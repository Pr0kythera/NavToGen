"""
Rule Repository Management
==========================

Coordinates rule discovery, parsing and analysis:

1. ``discover_rules``: secure directory walk that finds candidate rule files
2. ``parse_rules``: reads each file ONCE, decodes it, asks every parser how well the
   content matches its format, and parses with the best match (never by extension alone)
3. technique validation against ATT&CK data (when a validator is supplied), including a
   policy for revoked techniques
4. statistics and the coverage report

Worker threads only parse and validate; all statistics are aggregated on the calling
thread from the workers' return values, so no shared counters need locking.
"""

import copy
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from config import MAX_DIRECTORY_DEPTH, MAX_WORKERS
from models.detection_rule import DetectionRule
from parsers.base_parser import BaseRuleParser, decode_structured, read_rule_file
from parsers.elastic_parser import ElasticRuleParser
from parsers.sentinel_parser import SentinelRuleParser
from validators.mitre_validator import MitreAttackValidator
from validators.security_validator import SecurityValidator

logger = logging.getLogger(__name__)

REVOKED_POLICIES = ('remap', 'drop', 'keep')


@dataclass
class _FileResult:
    """Outcome of processing one file, returned from worker threads."""
    file_path: str
    rules: List[DetectionRule] = field(default_factory=list)
    unrecognized: bool = False
    error: Optional[str] = None
    invalid: List[Tuple[str, str]] = field(default_factory=list)       # (rule name, technique id)
    remapped: List[Tuple[str, str, str]] = field(default_factory=list)  # (rule name, old, new)
    dropped_revoked: List[Tuple[str, str]] = field(default_factory=list)
    validated: int = 0


def _new_statistics() -> Dict[str, Any]:
    return {
        'discovery': {
            'directories_scanned': 0,
            'files_discovered': 0,
            'files_skipped': 0,
            'discovery_time_seconds': 0.0
        },
        'parsing': {
            'total_files': 0,
            'successful_parses': 0,   # files that produced at least one rule
            'failed_parses': 0,
            'rules_parsed': 0,
            'parsing_time_seconds': 0.0,
            'files_per_second': 0.0
        },
        'by_platform': {
            'elastic_rules': 0,
            'sentinel_rules': 0,
            'unknown_format': 0       # files no parser recognized
        },
        'attack_analysis': {
            'total_techniques': 0,
            'unique_techniques': set(),
            'total_tactics': 0,
            'unique_tactics': set(),
            'techniques_validated': 0,
            'techniques_invalid': 0,
            'techniques_remapped': 0,
            'techniques_dropped_revoked': 0,
            'legacy_tactic_rules': 0
        },
        'errors': {
            'parse_errors': [],
            'validation_errors': [],
            'security_violations': [],
            'unrecognized_files': []
        },
        'performance': {
            'concurrent_processing': False,
            'worker_threads': 1,
            'memory_usage_mb': 0.0
        }
    }


def _json_safe(value: Any) -> Any:
    """Recursively convert sets to sorted lists so statistics serialize to real JSON arrays."""
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


class RuleRepository:
    """
    Manages discovery and parsing of detection rules.

    Args:
        mitre_validator: Optional validator; when it has ATT&CK data loaded, unknown
            techniques are removed and revoked techniques are handled per ``revoked_policy``.
        revoked_policy: What to do with techniques ATT&CK has revoked:
            ``remap`` replace with the technique that superseded it (default),
            ``drop`` remove it, ``keep`` leave it (it will not render in Navigator).
        fallback_text_extraction: Passed to the Sentinel parser (see its docs).
    """

    def __init__(self, mitre_validator: Optional[MitreAttackValidator] = None,
                 revoked_policy: str = 'remap', fallback_text_extraction: bool = False):
        if revoked_policy not in REVOKED_POLICIES:
            raise ValueError(f"revoked_policy must be one of {REVOKED_POLICIES}")

        self.mitre_validator = mitre_validator
        self.revoked_policy = revoked_policy
        self.rules: List[DetectionRule] = []
        self.parsing_stats = _new_statistics()

        # Parser order matters only as a tie-breaker when scores are equal
        self.parsers: Dict[str, BaseRuleParser] = {
            'elastic': ElasticRuleParser(),
            'sentinel': SentinelRuleParser(fallback_text_extraction=fallback_text_extraction),
        }

        logger.info(f"Rule repository initialized with {len(self.parsers)} parsers")
        if mitre_validator and mitre_validator.has_data():
            logger.info(f"ATT&CK validation enabled (version {mitre_validator.data_version or 'unknown'}, "
                        f"revoked technique policy: {revoked_policy})")
        else:
            logger.info("ATT&CK validation disabled - using format validation only")

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def supported_extensions(self) -> Set[str]:
        extensions: Set[str] = set()
        for parser in self.parsers.values():
            extensions.update(parser.get_supported_extensions())
        return extensions

    def discover_rules(self, directory_path: str, max_depth: int = None,
                       file_extensions: Set[str] = None) -> List[str]:
        """
        Find candidate rule files under a directory.

        Args:
            directory_path: Root directory to search
            max_depth: Number of subdirectory levels to descend (0 = only the root).
                Defaults to the configured maximum.
            file_extensions: Allowed extensions (defaults to everything any parser supports)

        Raises:
            ValueError: If the directory fails security validation
        """
        start_time = time.time()
        logger.info(f"Starting rule discovery in: {directory_path}")

        is_valid, error_msg = SecurityValidator.validate_directory_path(directory_path)
        if not is_valid:
            raise ValueError(f"Directory validation failed: {error_msg}")

        if max_depth is None:
            max_depth = MAX_DIRECTORY_DEPTH
        extensions = file_extensions if file_extensions is not None else self.supported_extensions()

        root_path = Path(directory_path).resolve()
        rule_files: List[str] = []
        directories_scanned = 0
        files_skipped = 0

        try:
            for current, dirs, files in os.walk(root_path):
                directories_scanned += 1
                depth = len(Path(current).relative_to(root_path).parts)

                # Hidden directories (.git, .venv...) never contain rules we want
                dirs[:] = sorted(d for d in dirs if not d.startswith('.'))
                if depth >= max_depth:
                    if dirs:
                        logger.debug(f"Maximum depth reached at {current}, not descending")
                    dirs[:] = []

                for name in sorted(files):
                    if not any(name.lower().endswith(ext) for ext in extensions):
                        continue

                    file_path = os.path.join(current, name)
                    is_valid, error_msg = SecurityValidator.validate_file_path(
                        file_path, extensions, allowed_root=str(root_path)
                    )
                    if is_valid:
                        rule_files.append(file_path)
                    else:
                        files_skipped += 1
                        logger.debug(f"Skipped file {file_path}: {error_msg}")
                        self.parsing_stats['errors']['security_violations'].append(
                            f"{file_path}: {error_msg}"
                        )

            discovery_time = time.time() - start_time
            self.parsing_stats['discovery'].update({
                'directories_scanned': directories_scanned,
                'files_discovered': len(rule_files),
                'files_skipped': files_skipped,
                'discovery_time_seconds': discovery_time
            })
            logger.info(f"Rule discovery completed in {discovery_time:.2f}s: "
                        f"{len(rule_files)} files in {directories_scanned} directories, "
                        f"{files_skipped} skipped")
            return rule_files

        except Exception as e:
            error_msg = f"Error during rule discovery in {directory_path}: {e}"
            logger.error(error_msg)
            self.parsing_stats['errors']['parse_errors'].append(error_msg)
            return []

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_rules(self, file_paths: List[str], use_concurrent: bool = True,
                    max_workers: int = None) -> List[DetectionRule]:
        """
        Parse rule files into DetectionRule objects (one file may yield several rules).

        Concurrency is used only when it can pay off (more than 10 files, more than one
        worker). Statistics are aggregated on this thread.
        """
        start_time = time.time()
        max_workers = max_workers or MAX_WORKERS
        logger.info(f"Starting parsing of {len(file_paths)} rule files")

        should_use_concurrent = use_concurrent and len(file_paths) > 10 and max_workers > 1

        results: List[_FileResult] = []
        if should_use_concurrent:
            logger.info(f"Using concurrent processing with {max_workers} workers")
            results = self._parse_concurrent(file_paths, max_workers)
        else:
            logger.info("Using sequential processing")
            for i, file_path in enumerate(file_paths, 1):
                if i % 50 == 0:
                    logger.info(f"Processing file {i}/{len(file_paths)}")
                results.append(self._process_file(file_path))

        self.parsing_stats['performance']['concurrent_processing'] = should_use_concurrent
        self.parsing_stats['performance']['worker_threads'] = max_workers if should_use_concurrent else 1

        self.rules = self._aggregate_results(results)

        self._update_parsing_statistics(len(file_paths), len(results), time.time() - start_time)
        self._analyze_parsed_rules()
        self._log_parsing_summary()
        return self.rules

    def _parse_concurrent(self, file_paths: List[str], max_workers: int) -> List[_FileResult]:
        # Results are re-sorted into input order so runs are deterministic
        indexed: Dict[int, _FileResult] = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index = {
                executor.submit(self._process_file, path): i for i, path in enumerate(file_paths)
            }
            for completed, future in enumerate(as_completed(future_to_index), 1):
                index = future_to_index[future]
                try:
                    indexed[index] = future.result()
                except Exception as e:
                    indexed[index] = _FileResult(file_paths[index], error=f"Concurrent parsing error: {e}")
                if completed % 100 == 0:
                    logger.info(f"Completed {completed}/{len(file_paths)} files")
        return [indexed[i] for i in sorted(indexed)]

    def _process_file(self, file_path: str) -> _FileResult:
        """Read, route, parse and validate one file. Safe to call from worker threads."""
        result = _FileResult(file_path)
        try:
            content = read_rule_file(file_path, self.supported_extensions())
            if content is None:
                result.error = f"Could not read {file_path}"
                return result

            records, decode_errors = decode_structured(content, file_path)
            if not records:
                result.error = (f"{file_path}: " + "; ".join(decode_errors)) if decode_errors \
                    else f"{file_path}: no rule records found"
                return result

            parser = self._select_parser(records, file_path)
            if parser is None:
                result.unrecognized = True
                logger.warning(f"No parser recognized the format of {file_path}")
                return result

            result.rules = parser.parse_records(records, file_path)

            if self.mitre_validator and self.mitre_validator.has_data():
                for rule in result.rules:
                    self._validate_rule(rule, result)

        except Exception as e:
            result.error = f"Error parsing {file_path}: {e}"
            logger.error(result.error)
        return result

    def _select_parser(self, records, file_path: str) -> Optional[BaseRuleParser]:
        """Pick the parser with the highest non-zero format score; None if nobody claims it."""
        best_parser, best_score = None, 0
        for name, parser in self.parsers.items():
            try:
                score = parser.score(records, file_path)
            except Exception as e:
                logger.debug(f"Parser {name} failed scoring {file_path}: {e}")
                continue
            logger.debug(f"Parser {name} scored {score} for {file_path}")
            if score > best_score:
                best_parser, best_score = parser, score
        return best_parser

    def _validate_rule(self, rule: DetectionRule, result: _FileResult) -> None:
        """
        Check a rule's techniques against ATT&CK data and apply the revoked-technique policy.

        Mutates only the rule and the per-file result, so it is safe in worker threads.
        """
        validator = self.mitre_validator
        for technique_id in sorted(rule.techniques):
            if validator.is_valid_technique(technique_id):
                result.validated += 1
                continue

            if validator.is_revoked(technique_id) and self.revoked_policy != 'keep':
                rule.techniques.discard(technique_id)
                rule.technique_tactics.pop(technique_id, None)
                replacement = validator.resolve_revoked(technique_id) if self.revoked_policy == 'remap' else None
                if replacement:
                    rule.techniques.add(replacement)
                    rule.remapped_techniques[technique_id] = replacement
                    rule.notes.append(f"{technique_id} is revoked in ATT&CK; remapped to {replacement}")
                    result.remapped.append((rule.name, technique_id, replacement))
                else:
                    rule.parse_errors.append(f"Revoked ATT&CK technique dropped: {technique_id}")
                    result.dropped_revoked.append((rule.name, technique_id))
                continue

            if validator.is_revoked(technique_id):  # policy 'keep'
                rule.notes.append(f"{technique_id} is revoked in ATT&CK (kept by policy)")
                result.validated += 1
                continue

            # Unknown or deprecated: not usable in a layer
            rule.techniques.discard(technique_id)
            rule.technique_tactics.pop(technique_id, None)
            reason = "deprecated" if validator.is_deprecated(technique_id) else "unknown"
            rule.parse_errors.append(f"Invalid MITRE ATT&CK technique ID ({reason}): {technique_id}")
            result.invalid.append((rule.name, technique_id))

        # Tactic names that ATT&CK no longer has (e.g. Defense Evasion after v19)
        legacy = sorted(t for t in rule.tactics if validator.valid_tactics and t not in validator.valid_tactics)
        if legacy:
            rule.notes.append(f"Tactic(s) not in ATT&CK {validator.data_version or 'data'}: {', '.join(legacy)}")

    def _aggregate_results(self, results: List[_FileResult]) -> List[DetectionRule]:
        """Fold per-file results into repository statistics (runs on the calling thread)."""
        stats = self.parsing_stats
        rules: List[DetectionRule] = []

        for result in results:
            if result.error:
                stats['errors']['parse_errors'].append(result.error)
            if result.unrecognized:
                stats['by_platform']['unknown_format'] += 1
                stats['errors']['unrecognized_files'].append(result.file_path)

            for rule in result.rules:
                rules.append(rule)
                if rule.rule_type.startswith('elastic'):
                    stats['by_platform']['elastic_rules'] += 1
                elif rule.rule_type.startswith('sentinel'):
                    stats['by_platform']['sentinel_rules'] += 1

            analysis = stats['attack_analysis']
            analysis['techniques_validated'] += result.validated
            analysis['techniques_invalid'] += len(result.invalid)
            analysis['techniques_remapped'] += len(result.remapped)
            analysis['techniques_dropped_revoked'] += len(result.dropped_revoked)

            for rule_name, technique_id in result.invalid:
                stats['errors']['validation_errors'].append(
                    f"{result.file_path}: '{rule_name}' has invalid/deprecated technique {technique_id}")
            for rule_name, old, new in result.remapped:
                logger.warning(f"'{rule_name}': revoked {old} remapped to {new}")
            for rule_name, technique_id in result.dropped_revoked:
                stats['errors']['validation_errors'].append(
                    f"{result.file_path}: '{rule_name}' revoked technique {technique_id} dropped (no replacement)")

            validator = self.mitre_validator
            if validator and validator.has_data() and validator.valid_tactics:
                analysis['legacy_tactic_rules'] += sum(
                    1 for r in result.rules if r.tactics - validator.valid_tactics)

        return rules

    def _update_parsing_statistics(self, total_files: int, processed: int, parsing_time: float) -> None:
        files_with_rules = len({r.source_file for r in self.rules})
        self.parsing_stats['parsing'].update({
            'total_files': total_files,
            'successful_parses': files_with_rules,
            'failed_parses': total_files - files_with_rules,
            'rules_parsed': len(self.rules),
            'parsing_time_seconds': parsing_time,
            'files_per_second': total_files / parsing_time if parsing_time > 0 else 0
        })

    def _analyze_parsed_rules(self) -> None:
        """Aggregate technique and tactic information across all parsed rules."""
        if not self.rules:
            return

        all_techniques: Set[str] = set()
        all_tactics: Set[str] = set()
        total_techniques = 0
        total_tactics = 0
        for rule in self.rules:
            all_techniques.update(rule.techniques)
            all_tactics.update(rule.tactics)
            total_techniques += len(rule.techniques)
            total_tactics += len(rule.tactics)

        self.parsing_stats['attack_analysis'].update({
            'total_techniques': total_techniques,
            'unique_techniques': all_techniques,
            'total_tactics': total_tactics,
            'unique_tactics': all_tactics
        })
        self.parsing_stats['performance']['memory_usage_mb'] = len(self.rules) * 0.01  # rough estimate

    def _log_parsing_summary(self) -> None:
        stats = self.parsing_stats
        parsing = stats['parsing']
        discovery = stats['discovery']
        platform = stats['by_platform']
        attack = stats['attack_analysis']

        logger.info("=" * 60)
        logger.info("RULE PARSING SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Discovery: {discovery['files_discovered']} files found in {discovery['discovery_time_seconds']:.2f}s")
        success_rate = (parsing['successful_parses'] / parsing['total_files'] * 100) if parsing['total_files'] else 0
        logger.info(f"Parsing: {parsing['rules_parsed']} rules from {parsing['successful_parses']}/{parsing['total_files']} "
                    f"files ({success_rate:.1f}%)")
        logger.info(f"Platforms: {platform['elastic_rules']} Elastic, {platform['sentinel_rules']} Sentinel, "
                    f"{platform['unknown_format']} unrecognized files")
        logger.info(f"Coverage: {len(attack['unique_techniques'])} unique techniques, {len(attack['unique_tactics'])} tactics")
        if attack['techniques_remapped'] or attack['techniques_dropped_revoked'] or attack['techniques_invalid']:
            logger.info(f"ATT&CK validation: {attack['techniques_remapped']} revoked techniques remapped, "
                        f"{attack['techniques_dropped_revoked']} revoked dropped, "
                        f"{attack['techniques_invalid']} invalid/deprecated removed")
        error_count = sum(len(v) for v in stats['errors'].values())
        if error_count:
            logger.warning(f"Errors: {error_count} total issues encountered")
        logger.info("=" * 60)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def get_coverage_report(self) -> Dict[str, Any]:
        """
        Build the detailed coverage report. The result is JSON-serializable (sets are
        emitted as sorted lists).
        """
        if not self.rules:
            return {"error": "No rules parsed - cannot generate coverage report"}

        validator = self.mitre_validator if (self.mitre_validator and self.mitre_validator.has_data()) else None

        technique_frequency: Dict[str, int] = {}
        rules_per_tactic: Dict[str, int] = {}
        tactic_techniques: Dict[str, Set[str]] = {}

        for rule in self.rules:
            for technique in rule.techniques:
                technique_frequency[technique] = technique_frequency.get(technique, 0) + 1
                if validator:
                    info = validator.get_technique_info(technique)
                    for tactic in (info or {}).get('tactics', []):
                        tactic_techniques.setdefault(tactic, set()).add(technique)
            for tactic in rule.tactics:
                rules_per_tactic[tactic] = rules_per_tactic.get(tactic, 0) + 1
            if not validator:
                # Without ATT&CK data only rule-declared tactic/technique pairs are known
                for technique, tactics in rule.technique_tactics.items():
                    for tactic in tactics:
                        tactic_techniques.setdefault(tactic, set()).add(technique)

        tactic_coverage_counts = {t: len(v) for t, v in sorted(tactic_techniques.items())}

        report = {
            'generation_timestamp': datetime.now().isoformat(),
            'attack_data': self._attack_data_summary(validator),
            'parsing_statistics': _json_safe(self.parsing_stats),
            'coverage_analysis': {
                'total_rules': len(self.rules),
                'rules_with_techniques': sum(1 for r in self.rules if r.techniques),
                'unique_techniques': len(self.parsing_stats['attack_analysis']['unique_techniques']),
                'technique_frequency': technique_frequency,
                'tactic_coverage_counts': tactic_coverage_counts,
                'rules_per_tactic': dict(sorted(rules_per_tactic.items())),
                'most_common_techniques': sorted(
                    technique_frequency.items(), key=lambda x: (-x[1], x[0]))[:20],
                'remapped_techniques': self._remapped_summary(),
                'coverage_gaps': self._identify_coverage_gaps(validator, tactic_techniques),
                'platform_analysis': self._analyze_platform_distribution()
            },
            'quality_metrics': {
                'average_techniques_per_rule': (
                    self.parsing_stats['attack_analysis']['total_techniques'] / len(self.rules)),
                'rules_without_techniques': sum(1 for r in self.rules if not r.techniques),
                'disabled_rules': sum(1 for r in self.rules if not r.enabled),
                'parsing_errors': len(self.parsing_stats['errors']['parse_errors']),
                'validation_errors': len(self.parsing_stats['errors']['validation_errors'])
            }
        }
        return report

    @staticmethod
    def _attack_data_summary(validator: Optional[MitreAttackValidator]) -> Dict[str, Any]:
        """ATT&CK data facts recorded in the report so later analysis can use real denominators."""
        if not validator:
            return {'loaded': False}
        summary = validator.get_validation_summary()
        return {
            'loaded': True,
            'version': summary['data_version'],
            'source': summary['data_source'],
            'active_technique_count': summary['technique_count'],
            'tactic_count': summary['tactic_count'],
            'revoked_technique_count': summary['revoked_techniques'],
        }

    def _remapped_summary(self) -> Dict[str, Dict[str, Any]]:
        summary: Dict[str, Dict[str, Any]] = {}
        for rule in self.rules:
            for old, new in rule.remapped_techniques.items():
                entry = summary.setdefault(old, {'replaced_by': new, 'rules': 0})
                entry['rules'] += 1
        return dict(sorted(summary.items()))

    def _identify_coverage_gaps(self, validator: Optional[MitreAttackValidator],
                                tactic_techniques: Dict[str, Set[str]]) -> Dict[str, Any]:
        """Per-tactic coverage against the loaded ATT&CK data."""
        gaps: Dict[str, Any] = {
            'tactics_without_coverage': [],
            'low_coverage_tactics': {},
            'recommendations': []
        }
        if not validator:
            gaps['note'] = "ATT&CK data not loaded - gap analysis unavailable (use --validate-online or --attack-data-file)"
            return gaps

        for tactic in sorted(validator.valid_tactics):
            total = len(validator.get_techniques_by_tactic(tactic))
            covered = len(tactic_techniques.get(tactic, set()))
            if covered == 0:
                gaps['tactics_without_coverage'].append(tactic)
            elif total and covered / total < 0.10:
                gaps['low_coverage_tactics'][tactic] = {
                    'covered': covered, 'total': total, 'percent': round(covered / total * 100, 1)}

        if gaps['tactics_without_coverage']:
            gaps['recommendations'].append(
                "No techniques covered for tactics: " + ", ".join(gaps['tactics_without_coverage']))
        if gaps['low_coverage_tactics']:
            gaps['recommendations'].append(
                "Under 10% of techniques covered for tactics: " + ", ".join(sorted(gaps['low_coverage_tactics'])))
        return gaps

    def _analyze_platform_distribution(self) -> Dict[str, Any]:
        platform_stats = self.parsing_stats['by_platform']
        rule_counts = {k: v for k, v in platform_stats.items() if k != 'unknown_format'}
        total_rules = sum(rule_counts.values())

        distribution: Dict[str, Any] = {
            'total_rules': total_rules,
            'by_platform': dict(platform_stats),
        }
        if total_rules > 0:
            distribution['percentages'] = {
                platform: round(count / total_rules * 100, 2) for platform, count in rule_counts.items()
            }
        return distribution

    def get_rules_by_platform(self, platform: str) -> List[DetectionRule]:
        """All rules for a platform ('elastic' or 'sentinel')."""
        return [rule for rule in self.rules if rule.rule_type.startswith(platform.lower())]

    def get_statistics(self) -> Dict[str, Any]:
        """A deep copy of the current statistics (safe to mutate)."""
        return copy.deepcopy(self.parsing_stats)

    def reset(self) -> None:
        """Clear parsed rules and statistics for a fresh run."""
        self.rules = []
        self.parsing_stats = _new_statistics()
        for parser in self.parsers.values():
            parser.reset_statistics()
        logger.info("Rule repository reset - ready for new analysis")
