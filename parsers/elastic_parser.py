"""
Elastic Security Rule Parser
============================

Parses Elastic Security detection rules from every format they are commonly stored in:

- YAML rule files
- JSON rule files (Kibana / Detections API responses)
- NDJSON exports from Kibana (many rules per file; the trailing export-summary line is skipped)
- TOML rule files as used by the ``elastic/detection-rules`` repository, where the rule sits
  under a ``[rule]`` table and metadata (creation/updated dates) under ``[metadata]``

MITRE ATT&CK mappings live in the ``threat`` array::

    threat:
      - framework: MITRE ATT&CK
        tactic:    {id: TA0005, name: Defense Evasion}
        technique:
          - id: T1562
            subtechnique:
              - id: T1562.001

The tactic a technique was declared under is preserved (``DetectionRule.technique_tactics``).
"""

import logging
from typing import Any, Dict, List

from parsers.base_parser import BaseRuleParser, Records, parse_timestamp, to_bool
from models.detection_rule import DetectionRule

logger = logging.getLogger(__name__)

ELASTIC_RULE_TYPES = {
    'query', 'eql', 'esql', 'machine_learning', 'threshold',
    'threat_match', 'new_terms', 'saved_query'
}

# Keys that only (or almost only) appear in Elastic rules. Used for format scoring.
_STRONG_KEYS = {'rule_id': 2, 'risk_score': 2}
_WEAK_KEYS = ('index', 'from', 'interval', 'language', 'max_signals', 'required_fields',
              'related_integrations', 'data_view_id', 'exceptions_list', 'license',
              'false_positives', 'building_block_type')


def risk_score_to_severity(score: int) -> str:
    """
    Map an Elastic risk score to a severity using Elastic's documented guideline bands:
    0-21 low, 22-47 medium, 48-73 high, 74-100 critical.

    Only used when a rule has a risk_score but no explicit severity; in Elastic the two
    fields are independent and an explicit severity always wins.
    """
    if score >= 74:
        return 'critical'
    if score >= 48:
        return 'high'
    if score >= 22:
        return 'medium'
    return 'low'


class ElasticRuleParser(BaseRuleParser):
    """Parser for Elastic Security Detection Engine rules (YAML, JSON, NDJSON, TOML)."""

    def __init__(self):
        super().__init__("Elastic")
        logger.debug("Elastic Security parser initialized")

    def get_supported_extensions(self) -> List[str]:
        return ['.yaml', '.yml', '.json', '.toml', '.ndjson', '.jsonl']

    # ------------------------------------------------------------------
    # Format recognition
    # ------------------------------------------------------------------

    @staticmethod
    def _unwrap(record: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten the TOML layout ({'metadata': {...}, 'rule': {...}}) into one dict."""
        inner = record.get('rule')
        if isinstance(inner, dict):
            merged: Dict[str, Any] = {}
            metadata = record.get('metadata')
            if isinstance(metadata, dict):
                merged.update(metadata)
            merged.update(inner)
            return merged
        return record

    def _record_score(self, data: Dict[str, Any]) -> int:
        if not (data.get('name') or data.get('title')):
            return 0
        score = sum(weight for key, weight in _STRONG_KEYS.items() if key in data)
        if isinstance(data.get('threat'), list):
            score += 1
        if str(data.get('type', '')).lower() in ELASTIC_RULE_TYPES:
            score += 1
        score += sum(1 for key in _WEAK_KEYS if key in data)
        return score

    def score(self, records: Records, file_path: str) -> int:
        best = 0
        for record in records:
            best = max(best, self._record_score(self._unwrap(record)))
        # Require at least two indicators, as before, to avoid claiming generic files
        return best if best >= 2 else 0

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_records(self, records: Records, file_path: str) -> List[DetectionRule]:
        rules: List[DetectionRule] = []
        for record in records:
            data = self._unwrap(record)
            if self._record_score(data) < 2:
                logger.debug(f"Skipping non-rule record in {file_path}")
                continue
            try:
                rule = self._parse_rule(data, file_path)
            except Exception as e:
                logger.error(f"Unexpected error parsing Elastic rule in {file_path}: {e}")
                self.update_statistics(False)
                continue
            if rule is not None:
                rules.append(rule)
        return rules

    def _parse_rule(self, rule_data: Dict[str, Any], file_path: str):
        if not self.validate_rule_structure(rule_data):
            logger.error(f"Invalid Elastic rule structure: {file_path}")
            self.update_statistics(False)
            return None

        rule = self.extract_basic_metadata(rule_data, file_path)
        self._extract_elastic_metadata(rule, rule_data)
        techniques_found, tactics_found = self._process_threat_taxonomy(rule, rule_data)
        self._extract_additional_metadata(rule, rule_data)

        if not rule.techniques and not rule.tactics:
            logger.warning(f"No MITRE ATT&CK mappings found in Elastic rule '{rule.name}' ({file_path})")

        logger.debug(f"Parsed Elastic rule '{rule.name}': {len(rule.techniques)} techniques, {len(rule.tactics)} tactics")
        self.update_statistics(True, techniques_found, tactics_found)
        return rule

    def _extract_elastic_metadata(self, rule: DetectionRule, rule_data: Dict[str, Any]) -> None:
        """Elastic-specific fields: rule_id, rule type, severity, version, enabled."""
        if rule_data.get('rule_id') is not None:
            rule.rule_id = str(rule_data['rule_id'])

        if rule_data.get('type'):
            rule.rule_type = f"elastic-{str(rule_data['type']).lower()}"

        # Severity: explicit severity wins (handled in extract_basic_metadata);
        # derive from risk_score only when the rule did not state one.
        if rule_data.get('severity') is None and rule.risk_score is not None:
            rule.severity = risk_score_to_severity(rule.risk_score)

        if rule_data.get('version') is not None:
            rule.source_version = str(rule_data['version'])

        rule.enabled = to_bool(rule_data.get('enabled'), default=True)

    def _process_threat_taxonomy(self, rule: DetectionRule, rule_data: Dict[str, Any]):
        """
        Extract tactics and techniques from the ``threat`` array, keeping the pairing
        between each technique and the tactic it was declared under.

        Returns:
            (techniques_found, tactics_found) for statistics
        """
        techniques_found = 0
        tactics_found = 0

        threat_data = rule_data.get('threat', [])
        if not isinstance(threat_data, list):
            logger.debug(f"Threat field is not a list in {rule.source_file}")
            return techniques_found, tactics_found

        for threat_item in threat_data:
            if not isinstance(threat_item, dict):
                continue

            tactic_name = None
            tactic_data = threat_item.get('tactic')
            if isinstance(tactic_data, dict):
                tactic_name = tactic_data.get('name')
                if tactic_name and rule.add_tactic(tactic_name):
                    tactics_found += 1

            techniques_data = threat_item.get('technique', [])
            if not isinstance(techniques_data, list):
                continue

            for technique in techniques_data:
                if not isinstance(technique, dict):
                    continue

                technique_id = technique.get('id')
                if technique_id and rule.add_technique(
                        technique_id, f"threat.technique.id in {rule.source_file}", tactic=tactic_name):
                    techniques_found += 1

                sub_techniques = technique.get('subtechnique', [])
                if isinstance(sub_techniques, list):
                    for sub_technique in sub_techniques:
                        sub_id = sub_technique.get('id') if isinstance(sub_technique, dict) else None
                        if sub_id and rule.add_technique(
                                sub_id, f"threat.technique.subtechnique.id in {rule.source_file}",
                                tactic=tactic_name):
                            techniques_found += 1

        return techniques_found, tactics_found

    def _extract_additional_metadata(self, rule: DetectionRule, rule_data: Dict[str, Any]) -> None:
        """Timestamps, false positives, references and authors."""
        for field_name, attr in [
            ('created', 'created_date'), ('created_at', 'created_date'), ('creation_date', 'created_date'),
            ('updated', 'modified_date'), ('updated_at', 'modified_date'), ('updated_date', 'modified_date'),
        ]:
            if field_name in rule_data and getattr(rule, attr) is None:
                parsed = parse_timestamp(rule_data[field_name])
                if parsed:
                    setattr(rule, attr, parsed)
                else:
                    logger.warning(f"Could not parse {field_name} in {rule.source_file}")
                    rule.parse_errors.append(f"Invalid {field_name} timestamp: {rule_data[field_name]}")

        for field_name, attr in (('false_positives', 'false_positives'), ('references', 'references')):
            value = rule_data.get(field_name)
            if isinstance(value, list):
                setattr(rule, attr, [str(v) for v in value])
            elif isinstance(value, str) and value:
                setattr(rule, attr, [value])

    def validate_rule_structure(self, rule_data: Dict[str, Any]) -> bool:
        """
        Structure check for Elastic rules. Only a name is mandatory; Elastic rules in
        the wild omit ``description`` and others, and format recognition has already
        decided this is an Elastic rule.
        """
        if not super().validate_rule_structure(rule_data):
            return False

        rule_type = str(rule_data.get('type', '')).lower()
        if rule_type and rule_type not in ELASTIC_RULE_TYPES:
            logger.warning(f"Unknown Elastic rule type: {rule_type}")

        if 'threat' in rule_data and not isinstance(rule_data['threat'], list):
            logger.warning("Elastic rule 'threat' field should be a list; ignoring it")

        return True
