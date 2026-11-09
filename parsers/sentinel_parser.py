"""
Microsoft Sentinel Rule Parser
==============================

Parses Microsoft Sentinel analytics rules from the formats found in the wild:

1. YAML detection templates (the Azure-Sentinel community repository layout), where
   tactics and techniques are ``tactics:`` and ``relevantTechniques:`` lists
2. ARM templates (JSON) containing one or more ``...alertRules`` resources. The rule kind
   (``Scheduled``, ``NRT``...) is on the resource, the rest under ``properties``
3. API-style JSON where the rule body sits under ``properties`` next to a ``kind``

Sentinel writes tactic names in CamelCase (``CredentialAccess``); normalization to ATT&CK
short names is done in ``DetectionRule.add_tactic``.

The ``tags`` field is deliberately NOT treated as an ATT&CK source: in real templates it
holds free-form labels (campaign names, schema versions), not tactics.
"""

import logging
import re
from typing import Any, Dict, Iterator, List, Set

from parsers.base_parser import BaseRuleParser, Records, parse_timestamp, to_bool
from models.detection_rule import DetectionRule
from config import TECHNIQUE_ID_PATTERN

logger = logging.getLogger(__name__)

SENTINEL_KINDS = {
    'Scheduled': 'Scheduled Analytics Rule',
    'NRT': 'Near Real-Time Analytics Rule',
    'MicrosoftSecurityIncidentCreation': 'Microsoft Security Incident Creation Rule',
    'Fusion': 'Fusion Advanced Multistage Attack Detection',
    'ThreatIntelligence': 'Threat Intelligence Indicator Rule',
    'MLBehaviorAnalytics': 'Machine Learning Behavior Analytics Rule',
}

# Keys that identify Sentinel content. Each present key adds to the format score.
_SENTINEL_KEYS = (
    'queryFrequency', 'queryPeriod', 'triggerOperator', 'triggerThreshold',
    'requiredDataConnectors', 'entityMappings', 'relevantTechniques',
    'alertRuleTemplateName', 'eventGroupingSettings', 'alertDetailsOverride',
    'customDetails', 'sentinelEntitiesMappings', 'displayName',
)

# Fields that hold ATT&CK data (NOT 'tags'; see module docstring)
ATTACK_FIELD_NAMES = (
    'tactics', 'techniques', 'subTechniques', 'relevantTechniques',
    'attackTactics', 'attackTechniques', 'mitreTactics', 'mitreTechniques',
)

_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')


class SentinelRuleParser(BaseRuleParser):
    """Parser for Microsoft Sentinel analytics rules and detection templates."""

    def __init__(self, fallback_text_extraction: bool = False):
        """
        Args:
            fallback_text_extraction: When a rule has no ATT&CK fields at all, search its
                description/query/notes text for technique IDs. Off by default because
                an ID mentioned in a comment is not evidence the rule detects it.
        """
        super().__init__("Sentinel")
        self.fallback_text_extraction = fallback_text_extraction
        logger.debug("Microsoft Sentinel parser initialized")

    def get_supported_extensions(self) -> List[str]:
        return ['.json', '.yaml', '.yml']

    # ------------------------------------------------------------------
    # Record normalization and format recognition
    # ------------------------------------------------------------------

    @staticmethod
    def _is_alert_rule_resource(resource: Any) -> bool:
        return (isinstance(resource, dict)
                and 'alertrules' in str(resource.get('type', '')).lower()
                and isinstance(resource.get('properties'), dict))

    def _rule_dicts(self, record: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
        """
        Yield flat rule dicts from a record, which may be:
        - an ARM template (yields one dict per alertRules resource)
        - an API-style object with the rule under ``properties``
        - a flat template (yielded as is)
        """
        resources = record.get('resources')
        if isinstance(resources, list):
            for resource in resources:
                if self._is_alert_rule_resource(resource):
                    yield self._flatten_resource(resource)
            return

        if self._is_alert_rule_resource(record) or (
                isinstance(record.get('properties'), dict) and 'kind' in record):
            yield self._flatten_resource(record)
            return

        yield record

    @staticmethod
    def _flatten_resource(resource: Dict[str, Any]) -> Dict[str, Any]:
        """Merge an ARM/API resource into one flat dict: properties plus resource-level kind/name."""
        flat = dict(resource.get('properties', {}))
        if resource.get('kind') and 'kind' not in flat:
            flat['kind'] = resource['kind']
        # The resource name is the rule GUID when it is literal (ARM expressions like
        # "[concat(...)]" are not usable identifiers)
        resource_name = str(resource.get('name', ''))
        if 'id' not in flat and _UUID_RE.match(resource_name):
            flat['id'] = resource_name
        return flat

    def _record_score(self, data: Dict[str, Any]) -> int:
        score = sum(1 for key in _SENTINEL_KEYS if key in data)
        if data.get('kind') in SENTINEL_KINDS:
            score += 2
        return score

    def score(self, records: Records, file_path: str) -> int:
        best = 0
        for record in records:
            if isinstance(record.get('resources'), list):
                if any(self._is_alert_rule_resource(r) for r in record['resources']):
                    best = max(best, 6)
                continue
            for data in self._rule_dicts(record):
                best = max(best, self._record_score(data))
        return best if best >= 2 else 0

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_records(self, records: Records, file_path: str) -> List[DetectionRule]:
        rules: List[DetectionRule] = []
        for record in records:
            for data in self._rule_dicts(record):
                if self._record_score(data) < 2:
                    logger.debug(f"Skipping non-Sentinel record in {file_path}")
                    continue
                if not self.validate_rule_structure(data):
                    logger.error(f"Invalid Sentinel rule structure in {file_path}")
                    self.update_statistics(False)
                    continue
                try:
                    rules.append(self._extract_sentinel_rule_data(data, file_path))
                except Exception as e:
                    logger.error(f"Unexpected error parsing Sentinel rule in {file_path}: {e}")
                    self.update_statistics(False)
        return rules

    def _extract_sentinel_rule_data(self, rule_data: Dict[str, Any], file_path: str) -> DetectionRule:
        rule = self.extract_basic_metadata(rule_data, file_path)
        self._extract_sentinel_metadata(rule, rule_data)
        techniques_found, tactics_found = self._extract_attack_mappings(rule, rule_data)
        self._extract_additional_sentinel_metadata(rule, rule_data)

        if not rule.techniques and not rule.tactics:
            logger.warning(f"No MITRE ATT&CK mappings found in Sentinel rule '{rule.name}' ({file_path})")
            if self.fallback_text_extraction:
                techniques_found += self._fallback_technique_extraction(rule, rule_data)

        logger.debug(f"Parsed Sentinel rule '{rule.name}': {len(rule.techniques)} techniques, {len(rule.tactics)} tactics")
        self.update_statistics(True, techniques_found, tactics_found)
        return rule

    def _extract_sentinel_metadata(self, rule: DetectionRule, rule_data: Dict[str, Any]) -> None:
        if rule_data.get('kind'):
            rule.rule_type = f"sentinel-{str(rule_data['kind']).lower()}"

        if 'severity' in rule_data:
            # Sentinel uses Informational, Low, Medium, High
            severity = str(rule_data['severity']).lower()
            rule.severity = {'informational': 'low'}.get(severity, severity)

        rule.enabled = to_bool(rule_data.get('enabled'), default=True)

        if rule_data.get('version') is not None:
            rule.source_version = str(rule_data['version'])

        if not rule.rule_id and rule_data.get('alertRuleTemplateName'):
            rule.rule_id = str(rule_data['alertRuleTemplateName'])

    # ------------------------------------------------------------------
    # ATT&CK extraction
    # ------------------------------------------------------------------

    def _extract_attack_mappings(self, rule: DetectionRule, rule_data: Dict[str, Any]):
        """
        Extract tactics and techniques from the known ATT&CK fields.

        Returns:
            (techniques_found, tactics_found) for statistics
        """
        techniques_found = 0
        tactics_found = 0

        for field_name in ATTACK_FIELD_NAMES:
            if field_name not in rule_data:
                continue

            field_data = rule_data[field_name]
            logger.debug(f"Processing ATT&CK field '{field_name}' in {rule.source_file}")

            if isinstance(field_data, list):
                for item in field_data:
                    if isinstance(item, str):
                        if self._looks_like_technique(item):
                            if rule.add_technique(item.strip(), f"{field_name} in {rule.source_file}"):
                                techniques_found += 1
                        elif rule.add_tactic(item):
                            tactics_found += 1
                    elif isinstance(item, dict):
                        techniques_found += self._extract_from_dict(rule, item, field_name)
                        tactics_found += self._extract_tactics_from_dict(rule, item)

            elif isinstance(field_data, dict):
                techniques_found += self._extract_from_dict(rule, field_data, field_name)
                tactics_found += self._extract_tactics_from_dict(rule, field_data)

            elif isinstance(field_data, str):
                for technique_id in sorted(self._extract_techniques_from_text(field_data)):
                    if rule.add_technique(technique_id, f"{field_name} text in {rule.source_file}"):
                        techniques_found += 1

        return techniques_found, tactics_found

    def _extract_from_dict(self, rule: DetectionRule, data: Dict[str, Any], source_field: str) -> int:
        found = 0
        for key in ('id', 'techniqueId', 'technique', 'name', 'value'):
            value = data.get(key)
            candidates = value if isinstance(value, list) else [value]
            for candidate in candidates:
                if isinstance(candidate, str) and self._looks_like_technique(candidate):
                    if rule.add_technique(candidate.strip(), f"{source_field}.{key} in {rule.source_file}"):
                        found += 1
        return found

    def _extract_tactics_from_dict(self, rule: DetectionRule, data: Dict[str, Any]) -> int:
        found = 0
        for key in ('name', 'tactic', 'tacticName', 'value'):
            value = data.get(key)
            candidates = value if isinstance(value, list) else [value]
            for candidate in candidates:
                if isinstance(candidate, str) and not self._looks_like_technique(candidate):
                    if rule.add_tactic(candidate):
                        found += 1
        return found

    @staticmethod
    def _extract_techniques_from_text(text: str) -> Set[str]:
        if not text or not isinstance(text, str):
            return set()
        return set(TECHNIQUE_ID_PATTERN.findall(text))

    @staticmethod
    def _looks_like_technique(text: str) -> bool:
        if not text or not isinstance(text, str):
            return False
        return bool(TECHNIQUE_ID_PATTERN.fullmatch(text.strip()))

    def _fallback_technique_extraction(self, rule: DetectionRule, rule_data: Dict[str, Any]) -> int:
        """
        Opt-in: find technique IDs mentioned in free text when no ATT&CK fields exist.
        Recorded in ``rule.notes`` so the inference is visible in reports.
        """
        found = 0
        for field_name in ('description', 'query', 'notes'):
            if field_name in rule_data:
                for technique_id in sorted(self._extract_techniques_from_text(str(rule_data[field_name]))):
                    if rule.add_technique(technique_id, f"text fallback from {field_name}"):
                        found += 1
        if found:
            rule.notes.append(f"{found} technique(s) inferred from rule text (not from ATT&CK fields)")
            logger.info(f"Text fallback found {found} techniques in {rule.source_file}")
        return found

    # ------------------------------------------------------------------
    # Other metadata
    # ------------------------------------------------------------------

    def _extract_additional_sentinel_metadata(self, rule: DetectionRule, rule_data: Dict[str, Any]) -> None:
        for source_field, attr in [
            ('createdTimeUtc', 'created_date'), ('created', 'created_date'),
            ('lastModifiedUtc', 'modified_date'), ('lastUpdated', 'modified_date'),
        ]:
            if source_field in rule_data and getattr(rule, attr) is None:
                parsed = parse_timestamp(rule_data[source_field])
                if parsed:
                    setattr(rule, attr, parsed)
                else:
                    logger.warning(f"Could not parse timestamp {source_field} in {rule.source_file}")
                    rule.parse_errors.append(f"Invalid {source_field} timestamp: {rule_data[source_field]}")

    def validate_rule_structure(self, rule_data: Dict[str, Any]) -> bool:
        if not super().validate_rule_structure(rule_data):
            return False
        kind = rule_data.get('kind')
        if kind and kind not in SENTINEL_KINDS:
            logger.warning(f"Unknown Sentinel rule kind: {kind}")
        return True
