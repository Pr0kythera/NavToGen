"""
Temporal Analysis and Comparison Module
=======================================

Compares coverage snapshots taken at different times to show trends: rule growth,
technique and tactic coverage growth, and development velocity.

Snapshot sources
----------------
- **Coverage reports** (``--report`` output): the preferred input. They contain exact rule
  counts, per-technique frequencies, tactic coverage and the ATT&CK data facts needed to
  compute coverage percentages against the real number of techniques.
- **Navigator layers**: accepted, but a layer does not record how many rules exist, so
  rule counts are reported as unknown (``None``) rather than guessed.

Files in a snapshot directory are classified by CONTENT. Anything that is neither a
coverage report nor a Navigator layer (for example this tool's own executive summaries
or time-series files) is skipped, so a directory can safely contain other JSON files.
"""

import csv
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MAX_SNAPSHOT_FILE_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 500 * 1024 * 1024

# Used only when a snapshot carries no ATT&CK data facts. ATT&CK v20 Enterprise has
# 706 active techniques (227 techniques + 479 sub-techniques) and 15 tactics.
FALLBACK_TOTAL_TECHNIQUES = 706
FALLBACK_TOTAL_TACTICS = 15


def _to_naive_utc(value: datetime) -> datetime:
    """Normalize timestamps so aware and naive values can be compared and sorted."""
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _delta(newer: Optional[float], older: Optional[float]) -> Optional[float]:
    """Difference that propagates 'unknown': None if either side is unknown."""
    if newer is None or older is None:
        return None
    return newer - older


@dataclass
class AnalysisSnapshot:
    """
    A single coverage snapshot.

    ``total_rules`` is None when the source (a Navigator layer) does not say how many
    rules exist. ``total_techniques_possible`` and ``total_tactics_possible`` are the
    ATT&CK denominators recorded with the snapshot, or the module fallbacks.
    """

    timestamp: datetime
    file_path: str
    total_rules: Optional[int] = 0
    unique_techniques: int = 0
    unique_tactics: int = 0
    technique_coverage: Dict[str, int] = field(default_factory=dict)
    tactic_coverage: Dict[str, int] = field(default_factory=dict)
    platform_distribution: Dict[str, int] = field(default_factory=dict)
    parsing_stats: Dict[str, Any] = field(default_factory=dict)
    total_techniques_possible: int = FALLBACK_TOTAL_TECHNIQUES
    total_tactics_possible: int = FALLBACK_TOTAL_TACTICS
    denominator_source: str = "fallback"
    attack_version: Optional[str] = None

    def get_coverage_percentage(self, total_possible_techniques: Optional[int] = None) -> float:
        total = total_possible_techniques or self.total_techniques_possible
        return (self.unique_techniques / total) * 100 if total > 0 else 0

    def get_tactic_coverage_percentage(self, total_tactics: Optional[int] = None) -> float:
        total = total_tactics or self.total_tactics_possible
        return (self.unique_tactics / total) * 100 if total > 0 else 0


@dataclass
class ComparisonResult:
    """Deltas between two snapshots. Rule-based fields are None when rule counts are unknown."""

    baseline: AnalysisSnapshot
    current: AnalysisSnapshot
    time_delta_days: float
    rules_added: Optional[int]
    techniques_added: int
    tactics_added: int
    coverage_growth_percent: float
    tactic_coverage_growth_percent: float
    new_techniques: List[str] = field(default_factory=list)
    new_tactics: List[str] = field(default_factory=list)
    rules_per_day: Optional[float] = None

    def __post_init__(self):
        if self.time_delta_days > 0 and self.rules_added is not None:
            self.rules_per_day = self.rules_added / self.time_delta_days


class TemporalAnalyzer:
    """Loads snapshots from a directory and produces time-series data and a summary."""

    def __init__(self):
        self.snapshots: List[AnalysisSnapshot] = []
        self.comparisons: List[ComparisonResult] = []
        self.skipped_files: List[str] = []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    @staticmethod
    def _read_json(file_path: Path) -> Any:
        if file_path.stat().st_size > MAX_SNAPSHOT_FILE_BYTES:
            raise ValueError(f"JSON file too large: {file_path.stat().st_size} bytes (max 50MB)")
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    @staticmethod
    def _is_coverage_report_data(data: Any) -> bool:
        return isinstance(data, dict) and all(
            key in data for key in ('parsing_statistics', 'coverage_analysis', 'generation_timestamp'))

    @staticmethod
    def _is_navigator_layer_data(data: Any) -> bool:
        return (isinstance(data, dict) and isinstance(data.get('techniques'), list)
                and isinstance(data.get('versions'), dict) and 'domain' in data)

    def _is_coverage_report(self, file_path: Path) -> bool:
        """True if the file is a coverage report (kept for backward compatibility)."""
        try:
            return self._is_coverage_report_data(self._read_json(file_path))
        except Exception:
            return False

    def load_snapshot_from_coverage_report(self, file_path: str) -> AnalysisSnapshot:
        """Load a snapshot from a coverage report. Raises ValueError on invalid input."""
        try:
            path = Path(file_path)
            return self._snapshot_from_report(self._read_json(path), path)
        except Exception as e:
            raise ValueError(f"Failed to load coverage report from {file_path}: {e}")

    def load_snapshot_from_navigator_layer(self, file_path: str) -> AnalysisSnapshot:
        """Load a snapshot from a Navigator layer. Raises ValueError on invalid input."""
        try:
            path = Path(file_path)
            return self._snapshot_from_layer(self._read_json(path), path)
        except Exception as e:
            raise ValueError(f"Failed to load Navigator layer from {file_path}: {e}")

    def _snapshot_from_report(self, data: Dict[str, Any], path: Path) -> AnalysisSnapshot:
        coverage = data.get('coverage_analysis')
        if not isinstance(coverage, dict) or 'total_rules' not in coverage or 'unique_techniques' not in coverage:
            raise ValueError("Invalid coverage report format: missing coverage data")

        timestamp_str = data.get('generation_timestamp')
        timestamp = None
        if timestamp_str:
            try:
                timestamp = _to_naive_utc(datetime.fromisoformat(str(timestamp_str).replace('Z', '+00:00')))
            except ValueError:
                timestamp = None
        if timestamp is None:
            timestamp = self._timestamp_for(path)

        parsing_stats = data.get('parsing_statistics', {})
        technique_coverage = coverage.get('technique_frequency', {})
        tactic_coverage = coverage.get('tactic_coverage_counts', {})

        # Tactics known from any source: validator-derived counts, rule-declared tactics,
        # or the parser's unique tactic list (older reports serialized sets as strings,
        # which are ignored)
        tactic_names = set(tactic_coverage) | set(coverage.get('rules_per_tactic', {}))
        listed = parsing_stats.get('attack_analysis', {}).get('unique_tactics')
        if isinstance(listed, list):
            tactic_names.update(listed)

        attack_data = data.get('attack_data') or {}
        technique_total = attack_data.get('active_technique_count')
        tactic_total = attack_data.get('tactic_count')

        return AnalysisSnapshot(
            timestamp=timestamp,
            file_path=str(path),
            total_rules=coverage.get('total_rules', 0),
            unique_techniques=coverage.get('unique_techniques', 0),
            unique_tactics=len(tactic_names),
            technique_coverage=technique_coverage,
            tactic_coverage=tactic_coverage,
            platform_distribution=coverage.get('platform_analysis', {}).get('by_platform', {}),
            parsing_stats=data,
            total_techniques_possible=technique_total or FALLBACK_TOTAL_TECHNIQUES,
            total_tactics_possible=tactic_total or FALLBACK_TOTAL_TACTICS,
            denominator_source=(f"ATT&CK {attack_data.get('version') or 'data'}" if technique_total else "fallback"),
            attack_version=attack_data.get('version'),
        )

    def _snapshot_from_layer(self, data: Dict[str, Any], path: Path) -> AnalysisSnapshot:
        technique_coverage: Dict[str, int] = {}
        tactics: Dict[str, set] = defaultdict(set)

        for entry in data.get('techniques', []):
            technique_id = entry.get('techniqueID')
            if not technique_id:
                continue
            rule_count = 1
            for meta in entry.get('metadata', []):
                name = str(meta.get('name', '')).lower()
                value = str(meta.get('value', ''))
                if name == 'rule count' and value.isdigit():
                    rule_count = int(value)
                elif 'tactic' in name:
                    for tactic in value.split(','):
                        if tactic.strip():
                            tactics[tactic.strip()].add(technique_id)
            if entry.get('tactic'):
                tactics[entry['tactic']].add(technique_id)
            technique_coverage[technique_id] = rule_count

        return AnalysisSnapshot(
            timestamp=self._timestamp_for(path),
            file_path=str(path),
            total_rules=None,  # A layer does not record how many rules exist
            unique_techniques=len(technique_coverage),
            unique_tactics=len(tactics),
            technique_coverage=technique_coverage,
            tactic_coverage={t: len(v) for t, v in tactics.items()},
            attack_version=str(data.get('versions', {}).get('attack') or '') or None,
        )

    def load_snapshots_from_directory(self, directory_path: str, file_pattern: str = "*.json") -> int:
        """
        Load every coverage report and Navigator layer in a directory.

        Files are classified by content; other JSON files are skipped. Returns the
        number of snapshots loaded.
        """
        directory = Path(directory_path)
        if not directory.is_dir():
            raise ValueError(f"Directory does not exist: {directory_path}")

        files = sorted(directory.glob(file_pattern))
        total_size = sum(f.stat().st_size for f in files if f.is_file())
        if total_size > MAX_TOTAL_BYTES:
            logger.warning(f"Total file size {total_size / (1024 * 1024):.1f}MB exceeds the safe limit")

        loaded_count = 0
        for file_path in files:
            if not file_path.is_file():
                continue
            try:
                data = self._read_json(file_path)
                if self._is_coverage_report_data(data):
                    snapshot = self._snapshot_from_report(data, file_path)
                elif self._is_navigator_layer_data(data):
                    snapshot = self._snapshot_from_layer(data, file_path)
                else:
                    self.skipped_files.append(str(file_path))
                    logger.info(f"Skipping {file_path.name}: not a coverage report or Navigator layer")
                    continue
                self.snapshots.append(snapshot)
                loaded_count += 1
                logger.info(f"Loaded snapshot {file_path.name}: {snapshot.timestamp.isoformat()}, "
                            f"{snapshot.unique_techniques} techniques, rules={snapshot.total_rules}")
            except Exception as e:
                self.skipped_files.append(str(file_path))
                logger.warning(f"Failed to load {file_path}: {e}")

        self.snapshots.sort(key=lambda s: s.timestamp)
        logger.info(f"Loaded {loaded_count} snapshots from {directory_path}")
        return loaded_count

    @staticmethod
    def _timestamp_from_name(name: str) -> Optional[datetime]:
        """Timestamp from a filename: *_YYYYMMDD_HHMMSS.json, then YYYY-MM-DD."""
        match = re.search(r'(\d{8}_\d{6})', name)
        if match:
            try:
                return datetime.strptime(match.group(1), '%Y%m%d_%H%M%S')
            except ValueError:
                pass
        match = re.search(r'(\d{4}-\d{2}-\d{2})', name)
        if match:
            try:
                return datetime.strptime(match.group(1), '%Y-%m-%d')
            except ValueError:
                pass
        return None

    def _timestamp_for(self, path: Path) -> datetime:
        return self._timestamp_from_name(path.name) or datetime.fromtimestamp(path.stat().st_mtime)

    def _extract_timestamp_from_path(self, file_path: str) -> Optional[datetime]:
        """Kept for backward compatibility: timestamp from a filename, or None."""
        return self._timestamp_from_name(Path(file_path).name)

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def compare_snapshots(self, baseline_idx: int, current_idx: int) -> ComparisonResult:
        """Compare two snapshots by index. Raises IndexError for invalid indices."""
        if not (0 <= baseline_idx < len(self.snapshots)) or not (0 <= current_idx < len(self.snapshots)):
            raise IndexError("Invalid snapshot indices")

        baseline = self.snapshots[baseline_idx]
        current = self.snapshots[current_idx]
        time_delta_days = (current.timestamp - baseline.timestamp).total_seconds() / 86400

        comparison = ComparisonResult(
            baseline=baseline,
            current=current,
            time_delta_days=time_delta_days,
            rules_added=_delta(current.total_rules, baseline.total_rules),
            techniques_added=current.unique_techniques - baseline.unique_techniques,
            tactics_added=current.unique_tactics - baseline.unique_tactics,
            coverage_growth_percent=current.get_coverage_percentage() - baseline.get_coverage_percentage(),
            tactic_coverage_growth_percent=(current.get_tactic_coverage_percentage()
                                            - baseline.get_tactic_coverage_percentage()),
            new_techniques=sorted(set(current.technique_coverage) - set(baseline.technique_coverage)),
            new_tactics=sorted(set(current.tactic_coverage) - set(baseline.tactic_coverage)),
        )
        self.comparisons.append(comparison)
        return comparison

    def generate_time_series_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """Time series for charting. Unknown values (None) are emitted as null / empty CSV cells."""
        if not self.snapshots:
            return {}

        series: Dict[str, List[Dict[str, Any]]] = {
            'coverage_trends': [], 'rule_growth': [], 'technique_growth': [],
            'tactic_growth': [], 'velocity_metrics': [], 'platform_distribution': []
        }
        baseline_date = self.snapshots[0].timestamp

        for i, snap in enumerate(self.snapshots):
            days = round((snap.timestamp - baseline_date).total_seconds() / 86400, 1)
            date = snap.timestamp.isoformat()

            series['coverage_trends'].append({
                'date': date, 'days_since_baseline': days,
                'total_coverage_percent': round(snap.get_coverage_percentage(), 2),
                'tactic_coverage_percent': round(snap.get_tactic_coverage_percentage(), 2),
                'unique_techniques': snap.unique_techniques,
                'unique_tactics': snap.unique_tactics,
                'coverage_basis': snap.denominator_source,
            })
            series['rule_growth'].append({
                'date': date, 'days_since_baseline': days, 'total_rules': snap.total_rules,
                'rules_with_techniques': snap.parsing_stats.get('coverage_analysis', {}).get('rules_with_techniques')
                if snap.parsing_stats else None,
            })
            series['technique_growth'].append({
                'date': date, 'days_since_baseline': days,
                'unique_techniques': snap.unique_techniques,
                'total_technique_mappings': sum(snap.technique_coverage.values()),
            })
            series['tactic_growth'].append({
                'date': date, 'days_since_baseline': days,
                'unique_tactics': snap.unique_tactics,
                'total_tactic_mappings': sum(snap.tactic_coverage.values()),
            })
            series['platform_distribution'].append({
                'date': date, 'days_since_baseline': days,
                'elastic_rules': snap.platform_distribution.get('elastic_rules'),
                'sentinel_rules': snap.platform_distribution.get('sentinel_rules'),
                'total_rules': snap.total_rules,
            })

            if i > 0:
                prev = self.snapshots[i - 1]
                period = (snap.timestamp - prev.timestamp).total_seconds() / 86400
                if period > 0:
                    rules_delta = _delta(snap.total_rules, prev.total_rules)
                    series['velocity_metrics'].append({
                        'date': date, 'days_since_baseline': days,
                        'rules_per_day': round(rules_delta / period, 2) if rules_delta is not None else None,
                        'techniques_per_day': round((snap.unique_techniques - prev.unique_techniques) / period, 2),
                        'period_days': round(period, 1),
                    })
        return series

    def generate_executive_summary(self) -> Dict[str, Any]:
        """Summary of growth, current status, velocity and trends."""
        if len(self.snapshots) < 2:
            return {'error': 'Need at least 2 snapshots for meaningful analysis'}

        first, latest = self.snapshots[0], self.snapshots[-1]
        timeframe_days = (latest.timestamp - first.timestamp).total_seconds() / 86400

        rules_growth = _delta(latest.total_rules, first.total_rules)
        techniques_growth = latest.unique_techniques - first.unique_techniques
        tactics_growth = latest.unique_tactics - first.unique_tactics

        coverage_improvement = latest.get_coverage_percentage() - first.get_coverage_percentage()
        tactic_improvement = latest.get_tactic_coverage_percentage() - first.get_tactic_coverage_percentage()

        avg_rules_per_day = (rules_growth / timeframe_days) if (rules_growth is not None and timeframe_days > 0) else None
        avg_techniques_per_day = techniques_growth / timeframe_days if timeframe_days > 0 else 0

        def monthly(value: Optional[float]) -> Optional[float]:
            return round(value * 30, 1) if value is not None else None

        return {
            'analysis_period': {
                'start_date': first.timestamp.isoformat(),
                'end_date': latest.timestamp.isoformat(),
                'total_days': round(timeframe_days, 1),
                'total_snapshots': len(self.snapshots),
            },
            'coverage_basis': (f"{latest.denominator_source}: {latest.total_techniques_possible} techniques, "
                               f"{latest.total_tactics_possible} tactics"),
            'overall_growth': {
                'rules_added': rules_growth,
                'techniques_added': techniques_growth,
                'tactics_added': tactics_growth,
                'coverage_improvement_percent': round(coverage_improvement, 2),
                'tactic_coverage_improvement_percent': round(tactic_improvement, 2),
            },
            'current_status': {
                'total_rules': latest.total_rules,
                'unique_techniques_covered': latest.unique_techniques,
                'unique_tactics_covered': latest.unique_tactics,
                'overall_coverage_percent': round(latest.get_coverage_percentage(), 2),
                'tactic_coverage_percent': round(latest.get_tactic_coverage_percentage(), 2),
            },
            'velocity_metrics': {
                'average_rules_per_day': round(avg_rules_per_day, 2) if avg_rules_per_day is not None else None,
                'average_techniques_per_day': round(avg_techniques_per_day, 3),
                'average_rules_per_month': monthly(avg_rules_per_day),
                'average_techniques_per_month': round(avg_techniques_per_day * 30, 2),
            },
            'trend_analysis': {
                'monthly_breakdown': self._group_snapshots(lambda t: t.strftime('%Y-%m'), 'month'),
                'quarterly_breakdown': self._group_snapshots(
                    lambda t: f"{t.year}-Q{(t.month - 1) // 3 + 1}", 'quarter'),
                'acceleration_indicators': self._calculate_acceleration_indicators(),
            },
            'skipped_files': list(self.skipped_files),
            'recommendations': self._generate_recommendations(
                coverage_improvement, tactic_improvement, avg_rules_per_day),
        }

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_to_csv(self, output_directory: str, suffix: Optional[str] = None) -> List[str]:
        """
        Export each time series to CSV.

        Args:
            output_directory: Directory for the files (created if missing)
            suffix: Optional text (e.g. a timestamp) appended to filenames so runs do not
                overwrite each other
        """
        output_dir = Path(output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)

        created_files = []
        for series_name, data in self.generate_time_series_data().items():
            if not data:
                continue
            name = f"temporal_analysis_{series_name}" + (f"_{suffix}" if suffix else "") + ".csv"
            file_path = output_dir / name
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=list(data[0].keys()))
                writer.writeheader()
                writer.writerows(data)
            created_files.append(str(file_path))
            logger.info(f"Exported {series_name} to {file_path}")
        return created_files

    # ------------------------------------------------------------------
    # Grouping and trends
    # ------------------------------------------------------------------

    def _group_snapshots(self, key_func, label: str) -> List[Dict[str, Any]]:
        groups: Dict[str, List[AnalysisSnapshot]] = defaultdict(list)
        for snap in self.snapshots:
            groups[key_func(snap.timestamp)].append(snap)

        summary = []
        for key, snaps in sorted(groups.items()):
            latest = max(snaps, key=lambda s: s.timestamp)
            summary.append({
                label: key,
                'total_rules': latest.total_rules,
                'unique_techniques': latest.unique_techniques,
                'unique_tactics': latest.unique_tactics,
                'coverage_percent': round(latest.get_coverage_percentage(), 2),
                'tactic_coverage_percent': round(latest.get_tactic_coverage_percentage(), 2),
                'snapshot_count': len(snaps),
            })
        return summary

    def _group_snapshots_by_month(self) -> List[Dict[str, Any]]:
        return self._group_snapshots(lambda t: t.strftime('%Y-%m'), 'month')

    def _group_snapshots_by_quarter(self) -> List[Dict[str, Any]]:
        return self._group_snapshots(lambda t: f"{t.year}-Q{(t.month - 1) // 3 + 1}", 'quarter')

    def _calculate_acceleration_indicators(self) -> Dict[str, Any]:
        """Compare first-half and second-half velocity (None-safe for unknown rule counts)."""
        if len(self.snapshots) < 3:
            return {'note': 'Need at least 3 snapshots for acceleration analysis'}

        midpoint = len(self.snapshots) // 2
        first_half = self.snapshots[:midpoint + 1]
        second_half = self.snapshots[midpoint:]

        def velocity(half: List[AnalysisSnapshot], attr: str) -> Optional[float]:
            days = (half[-1].timestamp - half[0].timestamp).total_seconds() / 86400
            change = _delta(getattr(half[-1], attr), getattr(half[0], attr))
            return change / days if (change is not None and days > 0) else None

        def trend(first: Optional[float], second: Optional[float]) -> str:
            if first is None or second is None:
                return 'unknown'
            return 'accelerating' if second > first else 'decelerating' if second < first else 'stable'

        r1, r2 = velocity(first_half, 'total_rules'), velocity(second_half, 'total_rules')
        t1, t2 = velocity(first_half, 'unique_techniques'), velocity(second_half, 'unique_techniques')

        def rounded(value: Optional[float], digits: int) -> Optional[float]:
            return round(value, digits) if value is not None else None

        return {
            'rules_acceleration': trend(r1, r2),
            'techniques_acceleration': trend(t1, t2),
            'first_half_rules_per_day': rounded(r1, 2),
            'second_half_rules_per_day': rounded(r2, 2),
            'first_half_techniques_per_day': rounded(t1, 3),
            'second_half_techniques_per_day': rounded(t2, 3),
        }

    def _generate_recommendations(self, coverage_improvement: float,
                                  tactic_coverage_improvement: float,
                                  rules_per_day: Optional[float]) -> List[str]:
        recommendations = []

        if coverage_improvement < 1.0:
            recommendations.append("Consider accelerating detection rule development to improve overall coverage")
        elif coverage_improvement > 5.0:
            recommendations.append("Strong coverage growth - maintain the current development velocity")

        if tactic_coverage_improvement < 0.5:
            recommendations.append("Focus on diversifying coverage across different MITRE ATT&CK tactics")

        if rules_per_day is None:
            recommendations.append("Rule counts are unavailable for these snapshots; use coverage reports "
                                   "(--report) rather than Navigator layers to track rule growth")
        elif rules_per_day < 0.1:
            recommendations.append("Consider increasing detection engineering resources for faster rule development")
        elif rules_per_day > 2.0:
            recommendations.append("High rule development velocity - ensure quality assurance keeps pace")

        recommendations.extend([
            "Continue regular snapshot collection for ongoing trend analysis",
            "Consider setting quarterly coverage improvement targets",
            "Monitor for gaps in specific tactics that may need focused development",
        ])
        return recommendations
