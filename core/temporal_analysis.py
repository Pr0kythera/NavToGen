"""
Temporal Analysis and Comparison Module
======================================

This module provides functionality for comparing multiple Navigator layer JSON files
and detailed coverage reports across different time periods. It enables tracking
detection coverage growth, rule development velocity, and overall security posture
improvement over time.

The module generates time-series data suitable for executive reporting to CISOs,
showing metrics such as:
- Detection rule growth trends
- MITRE ATT&CK coverage expansion
- Tactic-specific coverage improvements
- Platform-specific detection development

Key capabilities:
- Multi-file comparison analysis
- Time-series data extraction from snapshots
- Executive summary generation for leadership
- CSV/Excel-compatible tabular output for charting
- Statistical trend analysis and projections
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional, Union
from dataclasses import dataclass, field
from collections import defaultdict
import csv
import re

logger = logging.getLogger(__name__)


@dataclass
class AnalysisSnapshot:
    """
    Represents a single analysis snapshot in time.
    
    This captures all the key metrics from a Navigator layer or coverage report
    at a specific point in time, enabling temporal comparison and trend analysis.
    
    Attributes:
        timestamp: When this snapshot was taken
        file_path: Original file path for reference
        total_rules: Total number of detection rules
        unique_techniques: Number of unique MITRE ATT&CK techniques covered
        unique_tactics: Number of unique MITRE ATT&CK tactics covered
        technique_coverage: Dictionary mapping techniques to rule counts
        tactic_coverage: Dictionary mapping tactics to technique counts
        platform_distribution: Rules per platform (Elastic/Sentinel)
        parsing_stats: Raw parsing statistics from the analysis
    """
    
    timestamp: datetime
    file_path: str
    total_rules: int = 0
    unique_techniques: int = 0
    unique_tactics: int = 0
    technique_coverage: Dict[str, int] = field(default_factory=dict)
    tactic_coverage: Dict[str, int] = field(default_factory=dict)
    platform_distribution: Dict[str, int] = field(default_factory=dict)
    parsing_stats: Dict[str, Any] = field(default_factory=dict)
    
    def get_coverage_percentage(self, total_possible_techniques: int = 800) -> float:
        """Calculate overall coverage percentage based on total possible techniques."""
        return (self.unique_techniques / total_possible_techniques) * 100 if total_possible_techniques > 0 else 0
    
    def get_tactic_coverage_percentage(self, total_tactics: int = 14) -> float:
        """Calculate tactic coverage percentage based on standard MITRE tactics."""
        return (self.unique_tactics / total_tactics) * 100 if total_tactics > 0 else 0


@dataclass
class ComparisonResult:
    """
    Results from comparing two analysis snapshots.
    
    This captures the deltas and growth metrics between two points in time,
    providing the foundation for trend analysis and executive reporting.
    
    Attributes:
        baseline: Earlier snapshot for comparison
        current: Later snapshot for comparison
        time_delta_days: Number of days between snapshots
        rules_added: Net increase in rules
        techniques_added: Net increase in unique techniques
        tactics_added: Net increase in unique tactics
        coverage_growth_percent: Percentage point increase in overall coverage
        tactic_coverage_growth_percent: Percentage point increase in tactic coverage
        new_techniques: List of techniques added since baseline
        new_tactics: List of tactics added since baseline
        rules_per_day: Average rule development velocity
    """
    
    baseline: AnalysisSnapshot
    current: AnalysisSnapshot
    time_delta_days: float
    rules_added: int
    techniques_added: int
    tactics_added: int
    coverage_growth_percent: float
    tactic_coverage_growth_percent: float
    new_techniques: List[str] = field(default_factory=list)
    new_tactics: List[str] = field(default_factory=list)
    rules_per_day: float = 0.0
    
    def __post_init__(self):
        """Calculate derived metrics after object creation."""
        if self.time_delta_days > 0:
            self.rules_per_day = self.rules_added / self.time_delta_days


class TemporalAnalyzer:
    """
    Main class for performing temporal analysis on Navigator layers and coverage reports.
    
    This class orchestrates the comparison of multiple analysis snapshots, extracts
    time-series data, and generates executive reports suitable for CISO presentations.
    
    The analyzer can work with both Navigator layer JSON files and detailed coverage
    reports, automatically detecting the format and extracting relevant metrics.
    """
    
    def __init__(self):
        """Initialize the temporal analyzer."""
        self.snapshots: List[AnalysisSnapshot] = []
        self.comparisons: List[ComparisonResult] = []
        
    def load_snapshot_from_navigator_layer(self, file_path: str) -> AnalysisSnapshot:
        """
        Load analysis snapshot from Navigator layer JSON file.
        
        Args:
            file_path: Path to Navigator layer JSON file
            
        Returns:
            AnalysisSnapshot: Extracted snapshot data
            
        Raises:
            ValueError: If file cannot be parsed or required data is missing
        """
        try:
            # Check file size for security (prevent large file attacks)
            file_stat = Path(file_path).stat()
            if file_stat.st_size > 50 * 1024 * 1024:  # 50MB limit for JSON files
                raise ValueError(f"JSON file too large: {file_stat.st_size} bytes (max 50MB)")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract timestamp from filename or layer metadata
            timestamp = self._extract_timestamp_from_path(file_path)
            if not timestamp:
                # Fallback to file modification time
                timestamp = datetime.fromtimestamp(Path(file_path).stat().st_mtime)
            
            # Extract metrics from Navigator layer
            techniques = data.get('techniques', [])
            technique_coverage = {}
            tactic_coverage = defaultdict(set)
            
            for technique in techniques:
                technique_id = technique.get('techniqueID', '')
                if technique_id:
                    # Estimate rule count from score (reverse engineering)
                    score = technique.get('score', 1)
                    estimated_rules = max(1, score // 20)  # Rough estimation
                    technique_coverage[technique_id] = estimated_rules
                    
                    # Extract tactic information if available in metadata
                    metadata = technique.get('metadata', [])
                    for meta in metadata:
                        if meta.get('name', '').lower() == 'tactics':
                            tactics = meta.get('value', '').split(',')
                            for tactic in tactics:
                                tactic = tactic.strip()
                                if tactic:
                                    tactic_coverage[tactic].add(technique_id)
            
            # Convert tactic coverage to counts
            tactic_counts = {tactic: len(techniques) for tactic, techniques in tactic_coverage.items()}
            
            # Estimate total rules (this is approximate from Navigator data)
            estimated_total_rules = sum(technique_coverage.values())
            
            snapshot = AnalysisSnapshot(
                timestamp=timestamp,
                file_path=file_path,
                total_rules=estimated_total_rules,
                unique_techniques=len(technique_coverage),
                unique_tactics=len(tactic_counts),
                technique_coverage=technique_coverage,
                tactic_coverage=tactic_counts,
                platform_distribution={}  # Not available in Navigator format
            )
            
            logger.info(f"Loaded snapshot from Navigator layer: {file_path}")
            logger.info(f"  - Timestamp: {timestamp}")
            logger.info(f"  - Techniques: {snapshot.unique_techniques}")
            logger.info(f"  - Estimated rules: {estimated_total_rules}")
            
            return snapshot
            
        except Exception as e:
            raise ValueError(f"Failed to load Navigator layer from {file_path}: {str(e)}")
    
    def load_snapshot_from_coverage_report(self, file_path: str) -> AnalysisSnapshot:
        """
        Load analysis snapshot from detailed coverage report JSON file.
        
        Args:
            file_path: Path to coverage report JSON file
            
        Returns:
            AnalysisSnapshot: Extracted snapshot data
            
        Raises:
            ValueError: If file cannot be parsed or required data is missing
        """
        try:
            # Check file size for security (prevent large file attacks)
            file_stat = Path(file_path).stat()
            if file_stat.st_size > 50 * 1024 * 1024:  # 50MB limit for JSON files
                raise ValueError(f"JSON file too large: {file_stat.st_size} bytes (max 50MB)")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract timestamp
            timestamp_str = data.get('generation_timestamp')
            if timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = datetime.fromtimestamp(Path(file_path).stat().st_mtime)
            
            # Validate required data is present
            if not data or 'coverage_analysis' not in data:
                raise ValueError(f"Invalid coverage report format: missing required data")
            
            # Extract coverage analysis data
            coverage_analysis = data.get('coverage_analysis', {})
            parsing_stats = data.get('parsing_statistics', {})
            
            # Validate coverage analysis has required fields
            if 'total_rules' not in coverage_analysis or 'unique_techniques' not in coverage_analysis:
                raise ValueError(f"Invalid coverage report format: missing required coverage data")
            
            technique_coverage = coverage_analysis.get('technique_frequency', {})
            tactic_coverage = coverage_analysis.get('tactic_coverage_counts', {})
            platform_analysis = coverage_analysis.get('platform_analysis', {})
            platform_distribution = platform_analysis.get('by_platform', {})
            
            snapshot = AnalysisSnapshot(
                timestamp=timestamp,
                file_path=file_path,
                total_rules=coverage_analysis.get('total_rules', 0),
                unique_techniques=coverage_analysis.get('unique_techniques', 0),
                unique_tactics=len(tactic_coverage),
                technique_coverage=technique_coverage,
                tactic_coverage=tactic_coverage,
                platform_distribution=platform_distribution,
                parsing_stats=parsing_stats
            )
            
            logger.info(f"Loaded snapshot from coverage report: {file_path}")
            logger.info(f"  - Timestamp: {timestamp}")
            logger.info(f"  - Total rules: {snapshot.total_rules}")
            logger.info(f"  - Unique techniques: {snapshot.unique_techniques}")
            logger.info(f"  - Unique tactics: {snapshot.unique_tactics}")
            
            return snapshot
            
        except Exception as e:
            raise ValueError(f"Failed to load coverage report from {file_path}: {str(e)}")
    
    def load_snapshots_from_directory(self, directory_path: str, 
                                    file_pattern: str = "*.json") -> int:
        """
        Load all snapshots from a directory containing analysis files.
        
        Args:
            directory_path: Directory to scan for analysis files
            file_pattern: Glob pattern for matching files
            
        Returns:
            int: Number of snapshots successfully loaded
        """
        directory = Path(directory_path)
        if not directory.exists():
            raise ValueError(f"Directory does not exist: {directory_path}")
        
        loaded_count = 0
        files = sorted(directory.glob(file_pattern))
        total_size = 0
        
        # Check total size before loading to prevent memory exhaustion
        for file_path in files:
            total_size += file_path.stat().st_size
            
        if total_size > 500 * 1024 * 1024:  # 500MB total limit
            logger.warning(f"Total file size {total_size / (1024*1024):.1f}MB exceeds safe limit")
        
        for file_path in files:
            try:
                # Try to determine file type and load accordingly
                if self._is_coverage_report(file_path):
                    snapshot = self.load_snapshot_from_coverage_report(str(file_path))
                else:
                    snapshot = self.load_snapshot_from_navigator_layer(str(file_path))
                
                self.snapshots.append(snapshot)
                loaded_count += 1
                
            except Exception as e:
                logger.warning(f"Failed to load {file_path}: {str(e)}")
        
        # Sort snapshots by timestamp
        self.snapshots.sort(key=lambda s: s.timestamp)
        
        logger.info(f"Loaded {loaded_count} snapshots from {directory_path}")
        return loaded_count
    
    def compare_snapshots(self, baseline_idx: int, current_idx: int) -> ComparisonResult:
        """
        Compare two snapshots and calculate growth metrics.
        
        Args:
            baseline_idx: Index of baseline snapshot
            current_idx: Index of current snapshot
            
        Returns:
            ComparisonResult: Detailed comparison results
            
        Raises:
            IndexError: If indices are invalid
        """
        if baseline_idx >= len(self.snapshots) or current_idx >= len(self.snapshots):
            raise IndexError("Invalid snapshot indices")
        
        baseline = self.snapshots[baseline_idx]
        current = self.snapshots[current_idx]
        
        # Calculate time delta
        time_delta = current.timestamp - baseline.timestamp
        time_delta_days = time_delta.total_seconds() / (24 * 3600)
        
        # Calculate growth metrics
        rules_added = current.total_rules - baseline.total_rules
        techniques_added = current.unique_techniques - baseline.unique_techniques
        tactics_added = current.unique_tactics - baseline.unique_tactics
        
        # Calculate coverage growth (percentage points)
        baseline_coverage = baseline.get_coverage_percentage()
        current_coverage = current.get_coverage_percentage()
        coverage_growth = current_coverage - baseline_coverage
        
        baseline_tactic_coverage = baseline.get_tactic_coverage_percentage()
        current_tactic_coverage = current.get_tactic_coverage_percentage()
        tactic_coverage_growth = current_tactic_coverage - baseline_tactic_coverage
        
        # Find new techniques and tactics
        baseline_techniques = set(baseline.technique_coverage.keys())
        current_techniques = set(current.technique_coverage.keys())
        new_techniques = list(current_techniques - baseline_techniques)
        
        baseline_tactics = set(baseline.tactic_coverage.keys())
        current_tactics = set(current.tactic_coverage.keys())
        new_tactics = list(current_tactics - baseline_tactics)
        
        comparison = ComparisonResult(
            baseline=baseline,
            current=current,
            time_delta_days=time_delta_days,
            rules_added=rules_added,
            techniques_added=techniques_added,
            tactics_added=tactics_added,
            coverage_growth_percent=coverage_growth,
            tactic_coverage_growth_percent=tactic_coverage_growth,
            new_techniques=new_techniques,
            new_tactics=new_tactics
        )
        
        self.comparisons.append(comparison)
        return comparison
    
    def generate_time_series_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Generate time-series data suitable for charting and executive reporting.
        
        Returns:
            Dict containing multiple time series for different metrics
        """
        if not self.snapshots:
            return {}
        
        # Generate time series for key metrics
        time_series = {
            'coverage_trends': [],
            'rule_growth': [],
            'technique_growth': [],
            'tactic_growth': [],
            'velocity_metrics': [],
            'platform_distribution': []
        }
        
        # Calculate baseline date for relative time calculations
        baseline_date = self.snapshots[0].timestamp
        
        for i, snapshot in enumerate(self.snapshots):
            # Calculate days since baseline
            days_since_baseline = (snapshot.timestamp - baseline_date).total_seconds() / (24 * 3600)
            
            # Coverage trends
            time_series['coverage_trends'].append({
                'date': snapshot.timestamp.isoformat(),
                'days_since_baseline': round(days_since_baseline, 1),
                'total_coverage_percent': round(snapshot.get_coverage_percentage(), 2),
                'tactic_coverage_percent': round(snapshot.get_tactic_coverage_percentage(), 2),
                'unique_techniques': snapshot.unique_techniques,
                'unique_tactics': snapshot.unique_tactics
            })
            
            # Rule growth
            time_series['rule_growth'].append({
                'date': snapshot.timestamp.isoformat(),
                'days_since_baseline': round(days_since_baseline, 1),
                'total_rules': snapshot.total_rules,
                'rules_with_techniques': snapshot.parsing_stats.get('coverage_analysis', {}).get('rules_with_techniques', 0) if snapshot.parsing_stats else 0
            })
            
            # Technique growth
            time_series['technique_growth'].append({
                'date': snapshot.timestamp.isoformat(),
                'days_since_baseline': round(days_since_baseline, 1),
                'unique_techniques': snapshot.unique_techniques,
                'total_technique_mappings': sum(snapshot.technique_coverage.values())
            })
            
            # Tactic growth
            time_series['tactic_growth'].append({
                'date': snapshot.timestamp.isoformat(),
                'days_since_baseline': round(days_since_baseline, 1),
                'unique_tactics': snapshot.unique_tactics,
                'total_tactic_mappings': sum(snapshot.tactic_coverage.values())
            })
            
            # Platform distribution
            time_series['platform_distribution'].append({
                'date': snapshot.timestamp.isoformat(),
                'days_since_baseline': round(days_since_baseline, 1),
                'elastic_rules': snapshot.platform_distribution.get('elastic_rules', 0),
                'sentinel_rules': snapshot.platform_distribution.get('sentinel_rules', 0),
                'total_rules': snapshot.total_rules
            })
            
            # Velocity metrics (requires comparison with previous snapshot)
            if i > 0:
                prev_snapshot = self.snapshots[i - 1]
                time_delta = (snapshot.timestamp - prev_snapshot.timestamp).total_seconds() / (24 * 3600)
                
                if time_delta > 0:
                    rules_velocity = (snapshot.total_rules - prev_snapshot.total_rules) / time_delta
                    techniques_velocity = (snapshot.unique_techniques - prev_snapshot.unique_techniques) / time_delta
                    
                    time_series['velocity_metrics'].append({
                        'date': snapshot.timestamp.isoformat(),
                        'days_since_baseline': round(days_since_baseline, 1),
                        'rules_per_day': round(rules_velocity, 2),
                        'techniques_per_day': round(techniques_velocity, 2),
                        'period_days': round(time_delta, 1)
                    })
        
        return time_series
    
    def generate_executive_summary(self) -> Dict[str, Any]:
        """
        Generate executive summary suitable for CISO reporting.
        
        Returns:
            Dict containing executive-level metrics and insights
        """
        if len(self.snapshots) < 2:
            return {'error': 'Need at least 2 snapshots for meaningful analysis'}
        
        # Get overall timeframe and latest snapshot
        first_snapshot = self.snapshots[0]
        latest_snapshot = self.snapshots[-1]
        timeframe_days = (latest_snapshot.timestamp - first_snapshot.timestamp).total_seconds() / (24 * 3600)
        
        # Calculate overall growth metrics
        total_rules_growth = latest_snapshot.total_rules - first_snapshot.total_rules
        total_techniques_growth = latest_snapshot.unique_techniques - first_snapshot.unique_techniques
        total_tactics_growth = latest_snapshot.unique_tactics - first_snapshot.unique_tactics
        
        coverage_start = first_snapshot.get_coverage_percentage()
        coverage_end = latest_snapshot.get_coverage_percentage()
        coverage_improvement = coverage_end - coverage_start
        
        tactic_coverage_start = first_snapshot.get_tactic_coverage_percentage()
        tactic_coverage_end = latest_snapshot.get_tactic_coverage_percentage()
        tactic_coverage_improvement = tactic_coverage_end - tactic_coverage_start
        
        # Calculate velocity metrics
        avg_rules_per_day = total_rules_growth / timeframe_days if timeframe_days > 0 else 0
        avg_techniques_per_day = total_techniques_growth / timeframe_days if timeframe_days > 0 else 0
        
        # Generate trend analysis
        monthly_snapshots = self._group_snapshots_by_month()
        quarterly_snapshots = self._group_snapshots_by_quarter()
        
        summary = {
            'analysis_period': {
                'start_date': first_snapshot.timestamp.isoformat(),
                'end_date': latest_snapshot.timestamp.isoformat(),
                'total_days': round(timeframe_days, 1),
                'total_snapshots': len(self.snapshots)
            },
            'overall_growth': {
                'rules_added': total_rules_growth,
                'techniques_added': total_techniques_growth,
                'tactics_added': total_tactics_growth,
                'coverage_improvement_percent': round(coverage_improvement, 2),
                'tactic_coverage_improvement_percent': round(tactic_coverage_improvement, 2)
            },
            'current_status': {
                'total_rules': latest_snapshot.total_rules,
                'unique_techniques_covered': latest_snapshot.unique_techniques,
                'unique_tactics_covered': latest_snapshot.unique_tactics,
                'overall_coverage_percent': round(coverage_end, 2),
                'tactic_coverage_percent': round(tactic_coverage_end, 2)
            },
            'velocity_metrics': {
                'average_rules_per_day': round(avg_rules_per_day, 2),
                'average_techniques_per_day': round(avg_techniques_per_day, 3),
                'average_rules_per_month': round(avg_rules_per_day * 30, 1),
                'average_techniques_per_month': round(avg_techniques_per_day * 30, 2)
            },
            'trend_analysis': {
                'monthly_breakdown': monthly_snapshots,
                'quarterly_breakdown': quarterly_snapshots,
                'acceleration_indicators': self._calculate_acceleration_indicators()
            },
            'recommendations': self._generate_recommendations(
                coverage_improvement, tactic_coverage_improvement, avg_rules_per_day
            )
        }
        
        return summary
    
    def export_to_csv(self, output_directory: str) -> List[str]:
        """
        Export time-series data to CSV files for Excel/charting tools.
        
        Args:
            output_directory: Directory to save CSV files
            
        Returns:
            List of created file paths
        """
        output_dir = Path(output_directory)
        output_dir.mkdir(exist_ok=True)
        
        time_series = self.generate_time_series_data()
        created_files = []
        
        for series_name, data in time_series.items():
            if not data:  # Skip empty series
                continue
                
            file_path = output_dir / f"temporal_analysis_{series_name}.csv"
            
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                if data:
                    fieldnames = data[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(data)
            
            created_files.append(str(file_path))
            logger.info(f"Exported {series_name} to {file_path}")
        
        return created_files
    
    def _extract_timestamp_from_path(self, file_path: str) -> Optional[datetime]:
        """Extract timestamp from filename if it follows the standard naming convention."""
        from validators.security_validator import SecurityValidator
        
        # Validate file path for security
        is_valid, error_msg = SecurityValidator.validate_file_path(file_path, {'.json'})
        if not is_valid:
            logger.warning(f"Invalid file path in timestamp extraction: {error_msg}")
            return None
        
        filename = Path(file_path).name
        
        # Try to match our standard format: *_YYYYMMDD_HHMMSS.json
        timestamp_pattern = r'(\d{8}_\d{6})'
        match = re.search(timestamp_pattern, filename)
        
        if match:
            timestamp_str = match.group(1)
            try:
                return datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
            except ValueError:
                pass
        
        # Try alternative formats
        # ISO date format: YYYY-MM-DD
        iso_pattern = r'(\d{4}-\d{2}-\d{2})'
        match = re.search(iso_pattern, filename)
        
        if match:
            date_str = match.group(1)
            try:
                return datetime.strptime(date_str, '%Y-%m-%d')
            except ValueError:
                pass
        
        return None
    
    def _is_coverage_report(self, file_path: Path) -> bool:
        """Determine if a file is a coverage report based on content."""
        try:
            # Check file size for security (prevent large file attacks)
            file_stat = file_path.stat()
            if file_stat.st_size > 50 * 1024 * 1024:  # 50MB limit for JSON files
                logger.warning(f"File too large for format detection: {file_path}")
                return False
            
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Coverage reports have these keys at the top level
            required_keys = ['parsing_statistics', 'coverage_analysis', 'generation_timestamp']
            return all(key in data for key in required_keys)
        except Exception:
            return False
    
    def _group_snapshots_by_month(self) -> List[Dict[str, Any]]:
        """Group snapshots by month for trend analysis."""
        monthly_data = defaultdict(list)
        
        for snapshot in self.snapshots:
            month_key = snapshot.timestamp.strftime('%Y-%m')
            monthly_data[month_key].append(snapshot)
        
        monthly_summary = []
        for month, snapshots in sorted(monthly_data.items()):
            # Use the latest snapshot in each month
            latest_in_month = max(snapshots, key=lambda s: s.timestamp)
            
            monthly_summary.append({
                'month': month,
                'total_rules': latest_in_month.total_rules,
                'unique_techniques': latest_in_month.unique_techniques,
                'unique_tactics': latest_in_month.unique_tactics,
                'coverage_percent': round(latest_in_month.get_coverage_percentage(), 2),
                'tactic_coverage_percent': round(latest_in_month.get_tactic_coverage_percentage(), 2),
                'snapshot_count': len(snapshots)
            })
        
        return monthly_summary
    
    def _group_snapshots_by_quarter(self) -> List[Dict[str, Any]]:
        """Group snapshots by quarter for high-level trend analysis."""
        quarterly_data = defaultdict(list)
        
        for snapshot in self.snapshots:
            quarter = (snapshot.timestamp.month - 1) // 3 + 1
            quarter_key = f"{snapshot.timestamp.year}-Q{quarter}"
            quarterly_data[quarter_key].append(snapshot)
        
        quarterly_summary = []
        for quarter, snapshots in sorted(quarterly_data.items()):
            latest_in_quarter = max(snapshots, key=lambda s: s.timestamp)
            
            quarterly_summary.append({
                'quarter': quarter,
                'total_rules': latest_in_quarter.total_rules,
                'unique_techniques': latest_in_quarter.unique_techniques,
                'unique_tactics': latest_in_quarter.unique_tactics,
                'coverage_percent': round(latest_in_quarter.get_coverage_percentage(), 2),
                'tactic_coverage_percent': round(latest_in_quarter.get_tactic_coverage_percentage(), 2),
                'snapshot_count': len(snapshots)
            })
        
        return quarterly_summary
    
    def _calculate_acceleration_indicators(self) -> Dict[str, Any]:
        """Calculate whether development is accelerating or decelerating."""
        if len(self.snapshots) < 3:
            return {'note': 'Need at least 3 snapshots for acceleration analysis'}
        
        # Compare first half vs second half velocity
        midpoint = len(self.snapshots) // 2
        first_half = self.snapshots[:midpoint + 1]
        second_half = self.snapshots[midpoint:]
        
        # Calculate velocity for each half
        first_period_days = (first_half[-1].timestamp - first_half[0].timestamp).total_seconds() / (24 * 3600)
        second_period_days = (second_half[-1].timestamp - second_half[0].timestamp).total_seconds() / (24 * 3600)
        
        first_rules_velocity = (first_half[-1].total_rules - first_half[0].total_rules) / first_period_days if first_period_days > 0 else 0
        second_rules_velocity = (second_half[-1].total_rules - second_half[0].total_rules) / second_period_days if second_period_days > 0 else 0
        
        first_techniques_velocity = (first_half[-1].unique_techniques - first_half[0].unique_techniques) / first_period_days if first_period_days > 0 else 0
        second_techniques_velocity = (second_half[-1].unique_techniques - second_half[0].unique_techniques) / second_period_days if second_period_days > 0 else 0
        
        return {
            'rules_acceleration': 'accelerating' if second_rules_velocity > first_rules_velocity else 'decelerating' if second_rules_velocity < first_rules_velocity else 'stable',
            'techniques_acceleration': 'accelerating' if second_techniques_velocity > first_techniques_velocity else 'decelerating' if second_techniques_velocity < first_techniques_velocity else 'stable',
            'first_half_rules_per_day': round(first_rules_velocity, 2),
            'second_half_rules_per_day': round(second_rules_velocity, 2),
            'first_half_techniques_per_day': round(first_techniques_velocity, 3),
            'second_half_techniques_per_day': round(second_techniques_velocity, 3)
        }
    
    def _generate_recommendations(self, coverage_improvement: float, 
                                tactic_coverage_improvement: float, 
                                rules_per_day: float) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []
        
        # Coverage-based recommendations
        if coverage_improvement < 1.0:
            recommendations.append("Consider accelerating detection rule development to improve overall coverage")
        elif coverage_improvement > 5.0:
            recommendations.append("Excellent coverage growth - maintain current development velocity")
        
        # Tactic-based recommendations
        if tactic_coverage_improvement < 0.5:
            recommendations.append("Focus on diversifying coverage across different MITRE ATT&CK tactics")
        
        # Velocity-based recommendations
        if rules_per_day < 0.1:
            recommendations.append("Consider increasing detection engineering resources for faster rule development")
        elif rules_per_day > 2.0:
            recommendations.append("High rule development velocity - ensure quality assurance processes keep pace")
        
        # General recommendations
        recommendations.extend([
            "Continue regular snapshot collection for ongoing trend analysis",
            "Consider setting quarterly coverage improvement targets",
            "Monitor for gaps in specific tactics that may need focused development"
        ])
        
        return recommendations