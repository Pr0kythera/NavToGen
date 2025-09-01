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
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# Import our custom modules
import config
from models import detection_rule as DetectionRule
from validators import security_validator as SecurityValidator, mitre_validator as MitreAttackValidator
from core import RuleRepository
from generators import NavigatorLayerGenerator
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
        
        # Save report
        report_path = SecurityValidator.sanitize_filename(self.args.report)
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

For more information and documentation:
https://github.com/your-org/enterprise-mitre-analyzer
        """
    )
    
    # Required arguments
    required = parser.add_argument_group('Required Arguments')
    required.add_argument(
        "-p", "--path",
        type=str,
        required=True,
        help="Path to directory containing detection rules"
    )
    
    required.add_argument(
        "-o", "--output",
        type=str,
        required=True,
        help="Output path for Navigator layer JSON file"
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
        args.frequency_mode
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
    
    # Validate output file extension
    if not args.output.lower().endswith('.json'):
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
        if logger.isEnabledFor(logger.DEBUG):
            logger.error(f"Unexpected error: {str(e)}\n{traceback.format_exc()}")
        else:
            print(f"\nError: {str(e)}")
            print("Run with --log-level DEBUG for detailed error information")
        return 1


if __name__ == "__main__":
    sys.exit(main())
