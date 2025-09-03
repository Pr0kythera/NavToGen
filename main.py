#!/usr/bin/env python3
"""
Enterprise MITRE ATT&CK Coverage Analyzer - Main Application
============================================================

This is the main entry point for the Enterprise MITRE ATT&CK Coverage Analyzer.
It provides a comprehensive command-line interface for analyzing detection rule
repositories and generating Navigator layers for coverage gap analysis.

The application orchestrates all system components to provide:
- Secure rule discovery across directory structures
- Format-aware parsing of Elastic and Sentinel rules
- MITRE ATT&CK technique validation against official framework
- Multiple Navigator layer generation modes
- Comprehensive reporting and analytics
- Performance optimization for large rule repositories

Usage Examples:
    # Basic coverage analysis
    python main.py -p /path/to/rules -o coverage_layer.json
    
    # Platform comparison with online validation
    python main.py -p /path/to/rules -o comparison.json --comparison-mode --validate-online
    
    # Detailed analysis with reporting
    python main.py -p /path/to/rules -o coverage.json --report coverage_report.json --log-level DEBUG

Author: Enterprise Security Team
Version: 3.0.0
License: MIT
"""

import argparse
import json
import logging
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# Import our custom modules
import config
from models.detection_rule import DetectionRule
from validators.security_validator import SecurityValidator
from validators import mitre_validator as MitreAttackValidator
from core.RuleRepository import RuleRepository
from core.temporal_analysis import TemporalAnalyzer
from generators.layer_generator import NavigatorLayerGenerator
from utils import setup_logging, create_logger, log_function_timing

# Module logger (will be properly configured after argument parsing)
logger = create_logger(__name__)


class AnalysisSession:
    """
    Manages a complete analysis session from start to finish.
    
    This class encapsulates all the state and operations for a single
    analysis run, providing clean separation of concerns and making
    the main function more manageable.
    
    The session follows the Command pattern, where each analysis run
    is encapsulated as an executable command with all necessary context.
    """
    
    def __init__(self, args: argparse.Namespace):
        """
        Initialize analysis session with parsed command line arguments.
        
        Args:
            args: Parsed command line arguments
        """
        self.args = args
        self.start_time = datetime.now()
        self.mitre_validator: Optional[MitreAttackValidator] = None
        self.repository: Optional[RuleRepository] = None
        self.generator: Optional[NavigatorLayerGenerator] = None
        self.results: Dict[str, Any] = {}
        
        logger.info(f"Analysis session initialized at {self.start_time}")
    
    @log_function_timing
    def run(self) -> int:
        """
        Execute the complete analysis workflow.
        
        Returns:
            int: Exit code (0 for success, non-zero for error)
        """
        try:
            # Branch for temporal analysis mode
            if self.args.temporal_analysis:
                return self._run_temporal_analysis()
            
            logger.info("Starting enterprise MITRE ATT&CK coverage analysis")
            
            # Phase 1: Initialize validators and components
            self._initialize_components()
            
            # Phase 2: Discover and validate rule files
            rule_files = self._discover_rules()
            if not rule_files:
                logger.error("No valid rule files found - analysis cannot proceed")
                return 1
            
            # Phase 3: Parse rules and build internal representation
            rules = self._parse_rules(rule_files)
            if not rules:
                logger.error("No rules were successfully parsed - analysis cannot proceed") 
                return 1
            
            # Phase 4: Generate Navigator layer(s)
            layer = self._generate_layer(rules)
            if not layer:
                logger.error("Failed to generate Navigator layer")
                return 1
            
            # Phase 5: Save results and generate reports
            self._save_results(layer)
            
            # Phase 6: Display summary and completion
            self._display_completion_summary()
            
            logger.info("Analysis completed successfully")
            return 0
            
        except KeyboardInterrupt:
            logger.info("Analysis interrupted by user")
            return 130  # Standard exit code for SIGINT
            
        except Exception as e:
            logger.error(f"Unexpected error during analysis: {str(e)}")
            logger.debug(f"Full traceback:\n{traceback.format_exc()}")
            return 1
    
    def _initialize_components(self) -> None:
        """Initialize all required components based on configuration."""
        logger.info("Initializing analysis components...")
        
        # Initialize MITRE ATT&CK validator if requested
        if self.args.validate_online:
            logger.info("Initializing MITRE ATT&CK validator...")
            self.mitre_validator = MitreAttackValidator()
            
            if self.mitre_validator.fetch_mitre_data():
                logger.info("✓ MITRE ATT&CK data loaded successfully")
                validator_summary = self.mitre_validator.get_validation_summary()
                logger.info(f"  - {validator_summary['technique_count']} techniques loaded")
                logger.info(f"  - {validator_summary['tactic_count']} tactics loaded")
                logger.info(f"  - Data version: {validator_summary['data_version']}")
            else:
                logger.warning("⚠ Failed to load MITRE ATT&CK data - continuing without validation")
                self.mitre_validator = None
        
        # Initialize rule repository
        self.repository = RuleRepository(self.mitre_validator)
        
        # Initialize layer generator
        self.generator = NavigatorLayerGenerator(self.mitre_validator)
        
        logger.info("✓ Components initialized successfully")
    
    def _discover_rules(self) -> List[str]:
        """
        Discover rule files in the specified directory.
        
        Returns:
            List[str]: List of discovered rule file paths
        """
        logger.info(f"Discovering rule files in: {self.args.path}")
        
        # Validate the input path first
        is_valid, error_msg = SecurityValidator.validate_directory_path(self.args.path)
        if not is_valid:
            raise ValueError(f"Invalid input directory: {error_msg}")
        
        # Discover rules using the repository
        rule_files = self.repository.discover_rules(self.args.path)
        
        discovery_stats = self.repository.get_statistics()['discovery']
        logger.info(f"Discovery completed:")
        logger.info(f"  - Directories scanned: {discovery_stats['directories_scanned']}")
        logger.info(f"  - Files found: {discovery_stats['files_discovered']}")
        logger.info(f"  - Files skipped: {discovery_stats['files_skipped']}")
        logger.info(f"  - Time taken: {discovery_stats['discovery_time_seconds']:.2f}s")
        
        return rule_files
    
    def _parse_rules(self, rule_files: List[str]) -> List[DetectionRule]:
        """
        Parse rule files into internal DetectionRule objects.
        
        Args:
            rule_files: List of rule file paths to parse
            
        Returns:
            List[DetectionRule]: Successfully parsed rules
        """
        logger.info(f"Parsing {len(rule_files)} rule files...")
        
        # Configure concurrent processing based on arguments
        use_concurrent = not self.args.no_threading
        max_workers = self.args.max_workers
        
        # Parse rules using repository
        rules = self.repository.parse_rules(rule_files, use_concurrent, max_workers)
        
        # Log parsing results
        parsing_stats = self.repository.get_statistics()['parsing']
        logger.info(f"Parsing completed:")
        logger.info(f"  - Success rate: {parsing_stats['successful_parses']}/{parsing_stats['total_files']} "
                   f"({parsing_stats['successful_parses']/parsing_stats['total_files']*100:.1f}%)")
        logger.info(f"  - Processing speed: {parsing_stats['files_per_second']:.1f} files/second")
        logger.info(f"  - Time taken: {parsing_stats['parsing_time_seconds']:.2f}s")
        
        # Filter rules by platform if specified
        if self.args.rule_type != "both":
            original_count = len(rules)
            rules = [rule for rule in rules if rule.rule_type.startswith(self.args.rule_type)]
            logger.info(f"Filtered to {len(rules)} {self.args.rule_type} rules (from {original_count} total)")
        
        return rules
    
    def _generate_layer(self, rules: List[DetectionRule]) -> Optional[Dict[str, Any]]:
        """
        Generate appropriate Navigator layer based on analysis mode.
        
        Args:
            rules: Parsed detection rules
            
        Returns:
            Dict[str, Any]: Generated Navigator layer, or None if generation failed
        """
        logger.info("Generating Navigator layer...")
        
        try:
            if self.args.comparison_mode:
                return self._generate_comparison_layer(rules)
            elif self.args.frequency_mode:
                return self._generate_frequency_layer(rules)
            else:
                return self._generate_coverage_layer(rules)
                
        except Exception as e:
            logger.error(f"Layer generation failed: {str(e)}")
            return None
    
    def _generate_coverage_layer(self, rules: List[DetectionRule]) -> Dict[str, Any]:
        """Generate standard coverage analysis layer."""
        layer_name = self._build_layer_name("Coverage Analysis")
        description = self._build_layer_description(rules, "coverage")
        
        layer = self.generator.generate_coverage_layer(
            rules=rules,
            layer_name=layer_name,
            description=description,
            attack_version=self.args.attack_version,
            scoring_algorithm='threshold'
        )
        
        return layer.to_dict()
    
    def _generate_comparison_layer(self, rules: List[DetectionRule]) -> Dict[str, Any]:
        """Generate platform comparison layer."""
        # Split rules by platform
        elastic_rules = [rule for rule in rules if rule.rule_type.startswith("elastic")]
        sentinel_rules = [rule for rule in rules if rule.rule_type.startswith("sentinel")]
        
        if not elastic_rules or not sentinel_rules:
            logger.warning("Comparison mode requires both Elastic and Sentinel rules")
            if not elastic_rules:
                logger.warning("No Elastic rules found")
            if not sentinel_rules:
                logger.warning("No Sentinel rules found")
            
            # Fall back to coverage layer if comparison isn't possible
            logger.info("Falling back to coverage analysis layer")
            return self._generate_coverage_layer(rules)
        
        layer = self.generator.generate_comparison_layer(elastic_rules, sentinel_rules)
        return layer.to_dict()
    
    def _generate_frequency_layer(self, rules: List[DetectionRule]) -> Dict[str, Any]:
        """Generate technique frequency analysis layer."""
        layer_name = self._build_layer_name("Frequency Analysis")
        
        layer = self.generator.generate_frequency_layer(
            rules=rules,
            layer_name=layer_name
        )
        
        return layer.to_dict()
    
    def _save_results(self, layer: Dict[str, Any]) -> None:
        """
        Save Navigator layer and optional reports to disk.
        
        Args:
            layer: Generated Navigator layer dictionary
        """
        logger.info("Saving analysis results...")
        
        # Generate default output path if not provided
        if not self.args.output:
            self.args.output = self._generate_default_output_path()
        
        # Validate and sanitize output path
        output_path = SecurityValidator.sanitize_filename(self.args.output)
        is_valid, error_msg = SecurityValidator.validate_output_path(output_path)
        
        if not is_valid:
            raise ValueError(f"Invalid output path: {error_msg}")
        
        # Save Navigator layer
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(layer, f, indent=2, ensure_ascii=False)
            
            logger.info(f"✓ Navigator layer saved to: {output_path}")
            
            # Store results for summary
            self.results['layer_file'] = output_path
            self.results['technique_count'] = len(layer.get('techniques', []))
            
        except Exception as e:
            raise RuntimeError(f"Failed to save Navigator layer: {str(e)}")
        
        # Generate and save detailed report if requested
        if self.args.report:
            self._save_detailed_report()
    
    def _save_detailed_report(self) -> None:
        """Generate and save detailed coverage analysis report."""
        logger.info("Generating detailed coverage report...")
        
        # Get comprehensive coverage report from repository
        coverage_report = self.repository.get_coverage_report()
        
        # Add session-specific information
        coverage_report['session_info'] = {
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'arguments': vars(self.args),
            'analysis_duration_seconds': (datetime.now() - self.start_time).total_seconds()
        }
        
        # Add layer information
        coverage_report['output_info'] = self.results.copy()
        
        # Generate default report path if relative path provided
        report_path = self.args.report
        if not os.path.isabs(report_path):
            from pathlib import Path
            output_dir = Path("output")
            output_dir.mkdir(exist_ok=True)
            report_path = str(output_dir / report_path)
        
        # Save report
        report_path = SecurityValidator.sanitize_filename(report_path)
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(coverage_report, f, indent=2, default=str, ensure_ascii=False)
            
            logger.info(f"✓ Detailed report saved to: {report_path}")
            self.results['report_file'] = report_path
            
        except Exception as e:
            logger.warning(f"Failed to save detailed report: {str(e)}")
    
    def _display_completion_summary(self) -> None:
        """Display comprehensive completion summary."""
        duration = datetime.now() - self.start_time
        stats = self.repository.get_statistics()
        
        print("\n" + "="*70)
        print("ENTERPRISE MITRE ATT&CK COVERAGE ANALYSIS - RESULTS SUMMARY")
        print("="*70)
        
        # Analysis overview
        print(f"Analysis Duration: {duration.total_seconds():.1f} seconds")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Rule processing summary
        parsing = stats['parsing']
        platform = stats['by_platform']
        print("RULE PROCESSING SUMMARY:")
        print(f"  Total files processed: {parsing['total_files']}")
        print(f"  Successfully parsed: {parsing['successful_parses']} ({parsing['successful_parses']/parsing['total_files']*100:.1f}%)")
        print(f"  Platform distribution: {platform['elastic_rules']} Elastic, {platform['sentinel_rules']} Sentinel")
        print(f"  Processing rate: {parsing['files_per_second']:.1f} files/second")
        print()
        
        # Coverage analysis summary
        attack = stats['attack_analysis']
        print("MITRE ATT&CK COVERAGE SUMMARY:")
        print(f"  Unique techniques identified: {len(attack['unique_techniques'])}")
        print(f"  Unique tactics covered: {len(attack['unique_tactics'])}")
        print(f"  Total technique mappings: {attack['total_techniques']}")
        
        if self.mitre_validator:
            validation_summary = self.mitre_validator.get_validation_summary()
            print(f"  Techniques validated against ATT&CK: {attack['techniques_validated']}")
            print(f"  Invalid techniques removed: {attack['techniques_invalid']}")
            print(f"  ATT&CK data version: {validation_summary['data_version']}")
        print()
        
        # Output summary
        print("OUTPUT FILES:")
        print(f"  Navigator layer: {self.results['layer_file']}")
        print(f"  Layer contains: {self.results['technique_count']} technique entries")
        
        if 'report_file' in self.results:
            print(f"  Detailed report: {self.results['report_file']}")
        print()
        
        # Usage instructions
        print("NEXT STEPS:")
        print("1. Import the Navigator layer JSON file into MITRE ATT&CK Navigator:")
        print("   → https://mitre-attack.github.io/attack-navigator/")
        print("2. Click 'Open Existing Layer' → 'Upload from local'")
        print("3. Select your generated JSON file to visualize coverage")
        
        # Error summary if any
        error_count = sum(len(errors) for errors in stats['errors'].values())
        if error_count > 0:
            print(f"\n⚠ {error_count} errors encountered during analysis")
            print("  Run with --log-level DEBUG for detailed error information")
        
        print("\n✓ Analysis completed successfully!")
        print("="*70)
    
    def _build_layer_name(self, analysis_type: str) -> str:
        """Build a descriptive name for the generated layer."""
        base_name = f"{analysis_type}"
        
        if self.args.rule_type != "both":
            base_name += f" - {self.args.rule_type.title()}"
        
        timestamp = datetime.now().strftime("%Y-%m-%d")
        return f"{base_name} ({timestamp})"
    
    def _generate_default_output_path(self) -> str:
        """Generate a default output file path with timestamp."""
        from pathlib import Path
        import os
        
        # Create output directory if it doesn't exist
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        # Generate filename based on analysis mode
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if self.args.comparison_mode:
            filename = f"platform_comparison_{timestamp}.json"
        elif self.args.frequency_mode:
            filename = f"frequency_analysis_{timestamp}.json"
        else:
            filename = f"coverage_analysis_{timestamp}.json"
        
        return str(output_dir / filename)
    
    def _build_layer_description(self, rules: List[DetectionRule], analysis_type: str) -> str:
        """Build a descriptive description for the generated layer."""
        elastic_count = sum(1 for rule in rules if rule.rule_type.startswith('elastic'))
        sentinel_count = sum(1 for rule in rules if rule.rule_type.startswith('sentinel'))
        
        all_techniques = set()
        for rule in rules:
            all_techniques.update(rule.techniques)
        
        description_parts = [
            f"{analysis_type.title()} analysis generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Analyzed {len(rules)} detection rules ({elastic_count} Elastic, {sentinel_count} Sentinel)",
            f"Covering {len(all_techniques)} unique MITRE ATT&CK techniques"
        ]
        
        if self.mitre_validator:
            validation_summary = self.mitre_validator.get_validation_summary()
            description_parts.append(f"Validated against ATT&CK {validation_summary['data_version']}")
        
        return ". ".join(description_parts) + "."
    
    def _run_temporal_analysis(self) -> int:
        """
        Run temporal analysis comparing multiple snapshots over time.
        
        Returns:
            int: Exit code (0 for success, non-zero for error)
        """
        logger.info("Starting temporal analysis of detection coverage snapshots")
        
        try:
            # Initialize temporal analyzer
            analyzer = TemporalAnalyzer()
            
            # Load snapshots from directory
            snapshots_loaded = analyzer.load_snapshots_from_directory(
                self.args.snapshots_directory, "*.json"
            )
            
            if snapshots_loaded < 2:
                logger.error(f"Need at least 2 snapshots for temporal analysis, found {snapshots_loaded}")
                return 1
            
            logger.info(f"Loaded {snapshots_loaded} snapshots for analysis")
            
            # Generate time-series data
            time_series = analyzer.generate_time_series_data()
            
            # Generate executive summary
            executive_summary = analyzer.generate_executive_summary()
            
            # Create output directory if needed
            from pathlib import Path
            output_dir = Path("output")
            output_dir.mkdir(exist_ok=True)
            
            # Save time-series data as CSV files
            csv_files = analyzer.export_to_csv(str(output_dir))
            
            # Save executive summary
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            summary_path = output_dir / f"executive_summary_{timestamp}.json"
            
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(executive_summary, f, indent=2, default=str, ensure_ascii=False)
            
            # Save detailed time-series data
            timeseries_path = output_dir / f"time_series_data_{timestamp}.json"
            with open(timeseries_path, 'w', encoding='utf-8') as f:
                json.dump(time_series, f, indent=2, default=str, ensure_ascii=False)
            
            # Display results summary
            self._display_temporal_analysis_summary(
                executive_summary, csv_files, str(summary_path), str(timeseries_path)
            )
            
            logger.info("Temporal analysis completed successfully")
            return 0
            
        except Exception as e:
            logger.error(f"Temporal analysis failed: {str(e)}")
            logger.debug(f"Full traceback:\n{traceback.format_exc()}")
            return 1
    
    def _display_temporal_analysis_summary(self, executive_summary: Dict[str, Any], 
                                         csv_files: List[str], summary_path: str, 
                                         timeseries_path: str) -> None:
        """Display comprehensive temporal analysis results summary."""
        print("\n" + "="*70)
        print("TEMPORAL DETECTION COVERAGE ANALYSIS - EXECUTIVE SUMMARY")
        print("="*70)
        
        # Analysis period
        period = executive_summary.get('analysis_period', {})
        print(f"Analysis Period: {period.get('start_date', 'N/A')} to {period.get('end_date', 'N/A')}")
        print(f"Total Duration: {period.get('total_days', 0):.1f} days")
        print(f"Snapshots Analyzed: {period.get('total_snapshots', 0)}")
        print()
        
        # Overall growth metrics
        growth = executive_summary.get('overall_growth', {})
        print("OVERALL GROWTH METRICS:")
        print(f"  Rules Added: {growth.get('rules_added', 0)}")
        print(f"  New Techniques Covered: {growth.get('techniques_added', 0)}")
        print(f"  New Tactics Covered: {growth.get('tactics_added', 0)}")
        print(f"  Coverage Improvement: {growth.get('coverage_improvement_percent', 0):.2f} percentage points")
        print(f"  Tactic Coverage Improvement: {growth.get('tactic_coverage_improvement_percent', 0):.2f} percentage points")
        print()
        
        # Current status
        status = executive_summary.get('current_status', {})
        print("CURRENT DETECTION STATUS:")
        print(f"  Total Rules: {status.get('total_rules', 0)}")
        print(f"  Unique Techniques: {status.get('unique_techniques_covered', 0)}")
        print(f"  Unique Tactics: {status.get('unique_tactics_covered', 0)}")
        print(f"  Overall Coverage: {status.get('overall_coverage_percent', 0):.2f}%")
        print(f"  Tactic Coverage: {status.get('tactic_coverage_percent', 0):.2f}%")
        print()
        
        # Velocity metrics
        velocity = executive_summary.get('velocity_metrics', {})
        print("DEVELOPMENT VELOCITY:")
        print(f"  Rules Per Day: {velocity.get('average_rules_per_day', 0):.2f}")
        print(f"  Techniques Per Day: {velocity.get('average_techniques_per_day', 0):.3f}")
        print(f"  Rules Per Month: {velocity.get('average_rules_per_month', 0):.1f}")
        print(f"  Techniques Per Month: {velocity.get('average_techniques_per_month', 0):.2f}")
        print()
        
        # Trend analysis
        trends = executive_summary.get('trend_analysis', {})
        acceleration = trends.get('acceleration_indicators', {})
        if 'rules_acceleration' in acceleration:
            print("TREND INDICATORS:")
            print(f"  Rules Development: {acceleration.get('rules_acceleration', 'unknown').title()}")
            print(f"  Techniques Coverage: {acceleration.get('techniques_acceleration', 'unknown').title()}")
            print()
        
        # Output files
        print("OUTPUT FILES GENERATED:")
        print(f"  Executive Summary: {summary_path}")
        print(f"  Time-Series Data: {timeseries_path}")
        print("  CSV Files for Charting:")
        for csv_file in csv_files:
            print(f"    - {csv_file}")
        print()
        
        # Recommendations
        recommendations = executive_summary.get('recommendations', [])
        if recommendations:
            print("KEY RECOMMENDATIONS:")
            for i, rec in enumerate(recommendations[:5], 1):  # Show top 5
                print(f"  {i}. {rec}")
            print()
        
        print("NEXT STEPS FOR CISO REPORTING:")
        print("1. Use CSV files to create executive dashboards and trend charts")
        print("2. Import time-series data into BI tools for deeper analysis")
        print("3. Schedule regular snapshot collection for continuous monitoring")
        print("4. Set quarterly targets based on current velocity metrics")
        print()
        
        print("✓ Temporal analysis completed - ready for executive presentation")
        print("="*70)


def setup_argument_parser() -> argparse.ArgumentParser:
    """
    Configure comprehensive command-line argument parser.
    
    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description=f"{config.APPLICATION_NAME} v{config.VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic coverage analysis
  python main.py -p /path/to/rules -o coverage_layer.json
  
  # Platform comparison with online validation
  python main.py -p /path/to/rules -o comparison.json \\
                 --comparison-mode --validate-online
  
  # Comprehensive analysis with detailed reporting
  python main.py -p /path/to/rules -o coverage.json \\
                 --report coverage_report.json --log-level DEBUG
  
  # Frequency analysis for rule prioritization
  python main.py -p /path/to/rules -o frequency.json \\
                 --frequency-mode --validate-online
  
  # Temporal analysis for executive reporting
  python main.py --temporal-analysis --snapshots-directory output/

For more information and documentation:
https://github.com/your-org/enterprise-mitre-analyzer
        """
    )
    
    # Required arguments
    required = parser.add_argument_group('Required Arguments')
    required.add_argument(
        "-p", "--path",
        type=str,
        required=False,
        help="Path to directory containing detection rules (not required for temporal analysis)"
    )
    
    required.add_argument(
        "-o", "--output",
        type=str,
        required=False,
        help="Output path for Navigator layer JSON file (default: output/coverage_analysis_TIMESTAMP.json)"
    )
    
    # Analysis mode options
    analysis = parser.add_argument_group('Analysis Modes')
    analysis.add_argument(
        "--comparison-mode",
        action="store_true",
        help="Generate comparison layer between Elastic and Sentinel rules"
    )
    
    analysis.add_argument(
        "--frequency-mode",
        action="store_true",
        help="Generate frequency analysis layer showing technique occurrence rates"
    )
    
    analysis.add_argument(
        "--temporal-analysis",
        action="store_true",
        help="Perform temporal analysis comparing multiple snapshots over time"
    )
    
    analysis.add_argument(
        "--snapshots-directory",
        type=str,
        help="Directory containing historical analysis snapshots for temporal analysis"
    )
    
    # Filtering and configuration
    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument(
        "--attack-version",
        type=str,
        default=config.DEFAULT_ATTACK_VERSION,
        help=f"MITRE ATT&CK version to reference (default: {config.DEFAULT_ATTACK_VERSION})"
    )
    
    config_group.add_argument(
        "--rule-type",
        choices=["elastic", "sentinel", "both"],
        default="both",
        help="Type of rules to analyze (default: both)"
    )
    
    # Validation options
    validation = parser.add_argument_group('Validation Options')
    validation.add_argument(
        "--validate-online",
        action="store_true",
        help="Validate techniques against official MITRE ATT&CK data (requires internet)"
    )
    
    # Output and reporting
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        "--report",
        type=str,
        help="Path to save detailed coverage analysis report (JSON format)"
    )
    
    # Performance options
    performance = parser.add_argument_group('Performance Options')
    performance.add_argument(
        "--max-workers",
        type=int,
        default=config.MAX_WORKERS,
        help=f"Maximum worker threads for concurrent processing (default: {config.MAX_WORKERS})"
    )
    
    performance.add_argument(
        "--no-threading",
        action="store_true",
        help="Disable concurrent processing (useful for debugging)"
    )
    
    # Logging and debugging
    debug = parser.add_argument_group('Logging Options')
    debug.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity level (default: INFO)"
    )
    
    debug.add_argument(
        "--log-file",
        type=str,
        help="Path to save log output to file (in addition to console)"
    )
    
    debug.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress all output except errors and final results"
    )
    
    # Version information
    parser.add_argument(
        "--version",
        action="version",
        version=f"{config.APPLICATION_NAME} v{config.VERSION}"
    )
    
    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    """
    Validate command line arguments and check for conflicts.
    
    Args:
        args: Parsed command line arguments
        
    Raises:
        ValueError: If arguments are invalid or conflicting
    """
    # Check for mutually exclusive analysis modes
    mode_count = sum([
        args.comparison_mode,
        args.frequency_mode,
        args.temporal_analysis
    ])
    
    if mode_count > 1:
        raise ValueError("Only one analysis mode can be specified at a time")
    
    # Validate ATT&CK version format
    if not config.validate_attack_version(args.attack_version):
        raise ValueError(f"Invalid ATT&CK version format: {args.attack_version}")
    
    # Validate worker thread count
    if args.max_workers < 1 or args.max_workers > 16:
        raise ValueError("Max workers must be between 1 and 16")
    
    # Check for comparison mode requirements
    if args.comparison_mode and args.rule_type != "both":
        logger.warning("Comparison mode works best with --rule-type both")
    
    # Validate temporal analysis requirements
    if args.temporal_analysis:
        if not args.snapshots_directory:
            raise ValueError("Temporal analysis requires --snapshots-directory")
        if not Path(args.snapshots_directory).exists():
            raise ValueError(f"Snapshots directory does not exist: {args.snapshots_directory}")
    
    # Validate that path is provided for non-temporal analysis
    if not args.temporal_analysis and not args.path:
        raise ValueError("Path to detection rules directory is required for all analysis modes except temporal analysis")
    
    # Validate output file extension (only if output is provided)
    if args.output and not args.output.lower().endswith('.json'):
        logger.warning("Output file should have .json extension for Navigator compatibility")


def main() -> int:
    """
    Main application entry point.
    
    Returns:
        int: Exit code (0 for success, non-zero for error)
    """
    try:
        # Parse command line arguments
        parser = setup_argument_parser()
        args = parser.parse_args()
        
        # Set up logging based on arguments
        log_level = "ERROR" if args.quiet else args.log_level
        setup_logging(log_level, args.log_file, enable_colors=True)
        
        # Display banner
        if not args.quiet:
            print(config.get_banner())
        
        # Validate arguments
        validate_arguments(args)
        
        # Perform security startup checks
        if not SecurityValidator.perform_startup_security_check():
            logger.error("Security validation failed - cannot proceed safely")
            return 1
        
        # Create and run analysis session
        session = AnalysisSession(args)
        return session.run()
        
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user.")
        return 130
        
    except Exception as e:
        if logger.isEnabledFor(logging.DEBUG):
            logger.error(f"Unexpected error: {str(e)}\n{traceback.format_exc()}")
        else:
            print(f"\nError: {str(e)}")
            print("Run with --log-level DEBUG for detailed error information")
        return 1


if __name__ == "__main__":
    sys.exit(main())
