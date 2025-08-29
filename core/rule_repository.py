"""
Rule Repository Management
=========================

This module manages the discovery, parsing, and organization of detection rules from various sources.
It serves as the central orchestrator that coordinates rule discovery, parser selection, validation,
and analysis across the entire rule repository.

Think of this class as the "project manager" for rule processing - it knows about all the different
specialists (parsers, validators) and coordinates their work to accomplish the overall goal of
analyzing your detection rule repository for MITRE ATT&CK coverage.

Key responsibilities:
1. Secure rule discovery across directory structures
2. Automatic parser selection based on rule format detection
3. Concurrent processing for performance with large rule sets
4. Comprehensive error handling and progress tracking
5. Statistical analysis and reporting on parsing results
6. Integration with MITRE ATT&CK validation
"""

import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
import time
from datetime import datetime

from models.detection_rule import DetectionRule
from validators.security_validator import SecurityValidator
from validators.mitre_validator import MitreAttackValidator
from parsers.elastic_parser import ElasticRuleParser
from parsers.sentinel_parser import SentinelRuleParser
from config import MAX_WORKERS, MAX_DIRECTORY_DEPTH

logger = logging.getLogger(__name__)


class RuleRepository:
    """
    Manages discovery and parsing of detection rules from various sources.
    
    This class coordinates the complex process of finding, parsing, and validating
    detection rules across different platforms and formats. It implements intelligent
    parser selection, concurrent processing for performance, and comprehensive
    error handling to ensure robust operation with large rule repositories.
    
    The repository follows the Facade pattern, providing a simple interface that
    hides the complexity of coordinating multiple parsers, validators, and
    processing strategies.
    
    Design Principles:
    - Fail-fast for critical errors, graceful degradation for recoverable issues
    - Comprehensive logging and progress tracking for operational visibility  
    - Concurrent processing where beneficial, sequential when debugging is needed
    - Extensible architecture for adding new rule formats and parsers
    
    Attributes:
        rules: List of successfully parsed DetectionRule objects
        parsing_stats: Comprehensive statistics about parsing operations
        parsers: Dictionary of available rule parsers by name
        mitre_validator: Optional MITRE ATT&CK validator for technique validation
    """
    
    def __init__(self, mitre_validator: Optional[MitreAttackValidator] = None):
        """
        Initialize the rule repository with optional MITRE ATT&CK validation.
        
        Args:
            mitre_validator: Optional validator for checking techniques against official MITRE data
        """
        self.mitre_validator = mitre_validator
        self.rules: List[DetectionRule] = []
        
        # Initialize comprehensive parsing statistics
        self.parsing_stats = {
            'discovery': {
                'directories_scanned': 0,
                'files_discovered': 0,
                'files_skipped': 0,
                'discovery_time_seconds': 0.0
            },
            'parsing': {
                'total_files': 0,
                'successful_parses': 0,
                'failed_parses': 0,
                'parsing_time_seconds': 0.0,
                'files_per_second': 0.0
            },
            'by_platform': {
                'elastic_rules': 0,
                'sentinel_rules': 0,
                'unknown_format': 0
            },
            'attack_analysis': {
                'total_techniques': 0,
                'unique_techniques': set(),
                'total_tactics': 0,
                'unique_tactics': set(),
                'techniques_validated': 0,
                'techniques_invalid': 0
            },
            'errors': {
                'parse_errors': [],
                'validation_errors': [],
                'security_violations': []
            },
            'performance': {
                'concurrent_processing': False,
                'worker_threads': 1,
                'memory_usage_mb': 0.0
            }
        }
        
        # Initialize parsers - this makes adding new parsers straightforward
        self.parsers = {
            'elastic': ElasticRuleParser(),
            'sentinel': SentinelRuleParser()
        }
        
        logger.info(f"Rule repository initialized with {len(self.parsers)} parsers")
        if mitre_validator:
            logger.info("MITRE ATT&CK validator enabled for technique validation")
        else:
            logger.info("MITRE ATT&CK validator disabled - using format validation only")
    
    def discover_rules(self, directory_path: str, max_depth: int = None, 
                      file_extensions: Set[str] = None) -> List[str]:
        """
        Discover rule files in directory with comprehensive security validation.
        
        This method implements secure directory traversal with multiple safety checks
        to prevent common attack vectors while efficiently discovering rule files
        across complex directory structures.
        
        Security measures implemented:
        1. Path validation and resolution to prevent directory traversal
        2. Depth limiting to prevent DoS via deep directory structures
        3. Size and permission checking for each discovered file
        4. Hidden directory filtering to avoid system files
        5. Extension validation to ensure only expected file types are processed
        
        Args:
            directory_path: Root directory to search for rules
            max_depth: Maximum recursion depth (defaults to config value)
            file_extensions: Set of allowed file extensions (defaults to all supported)
            
        Returns:
            List[str]: List of validated file paths ready for parsing
            
        Raises:
            ValueError: If directory path fails security validation
        """
        start_time = time.time()
        logger.info(f"Starting rule discovery in: {directory_path}")
        
        # Security validation of the root directory
        is_valid, error_msg = SecurityValidator.validate_directory_path(directory_path)
        if not is_valid:
            raise ValueError(f"Directory validation failed: {error_msg}")
        
        # Set default values from configuration
        max_depth = max_depth or MAX_DIRECTORY_DEPTH
        if file_extensions is None:
            # Collect all supported extensions from all parsers
            file_extensions = set()
            for parser in self.parsers.values():
                file_extensions.update(parser.get_supported_extensions())
        
        rule_files = []
        directories_scanned = 0
        files_skipped = 0
        
        try:
            # Use os.walk for efficient directory traversal
            for root, dirs, files in os.walk(directory_path):
                directories_scanned += 1
                
                # Calculate current depth to prevent excessive recursion
                current_depth = root.replace(directory_path, '').count(os.sep)
                if current_depth >= max_depth:
                    dirs[:] = []  # Don't recurse into subdirectories
                    logger.debug(f"Maximum depth reached at {root}, stopping recursion")
                    continue
                
                # Filter out hidden directories to avoid system files
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                # Process files in current directory
                for file in files:
                    # Quick filter by extension before expensive validation
                    if not any(file.lower().endswith(ext) for ext in file_extensions):
                        continue
                    
                    file_path = os.path.join(root, file)
                    
                    # Comprehensive security validation for each file
                    is_valid, error_msg = SecurityValidator.validate_file_path(
                        file_path, file_extensions
                    )
                    
                    if is_valid:
                        rule_files.append(file_path)
                        logger.debug(f"Discovered rule file: {file_path}")
                    else:
                        files_skipped += 1
                        logger.debug(f"Skipped file {file_path}: {error_msg}")
                        self.parsing_stats['errors']['security_violations'].append(
                            f"{file_path}: {error_msg}"
                        )
            
            # Update discovery statistics
            discovery_time = time.time() - start_time
            self.parsing_stats['discovery'].update({
                'directories_scanned': directories_scanned,
                'files_discovered': len(rule_files),
                'files_skipped': files_skipped,
                'discovery_time_seconds': discovery_time
            })
            
            logger.info(f"Rule discovery completed in {discovery_time:.2f}s:")
            logger.info(f"  - Directories scanned: {directories_scanned}")
            logger.info(f"  - Files discovered: {len(rule_files)}")
            logger.info(f"  - Files skipped: {files_skipped}")
            
            return rule_files
            
        except Exception as e:
            error_msg = f"Error during rule discovery in {directory_path}: {str(e)}"
            logger.error(error_msg)
            self.parsing_stats['errors']['parse_errors'].append(error_msg)
            return []
    
    def parse_rules(self, file_paths: List[str], use_concurrent: bool = True, 
                   max_workers: int = None) -> List[DetectionRule]:
        """
        Parse multiple rule files with optional concurrent processing.
        
        This method orchestrates the parsing of multiple rule files, automatically
        selecting appropriate parsers and optionally using concurrent processing
        for improved performance with large rule sets.
        
        The method implements intelligent concurrency decisions - using threading
        for large rule sets where I/O bound operations benefit from parallelism,
        while using sequential processing for smaller sets or when debugging.
        
        Args:
            file_paths: List of file paths to parse
            use_concurrent: Whether to use concurrent processing (auto-decided if large set)
            max_workers: Maximum number of worker threads (defaults to config)
            
        Returns:
            List[DetectionRule]: Successfully parsed rules
        """
        start_time = time.time()
        max_workers = max_workers or MAX_WORKERS
        
        logger.info(f"Starting parsing of {len(file_paths)} rule files")
        
        # Intelligent concurrency decision
        should_use_concurrent = (
            use_concurrent and 
            len(file_paths) > 10 and  # Only worth it for larger sets
            max_workers > 1
        )
        
        if should_use_concurrent:
            logger.info(f"Using concurrent processing with {max_workers} workers")
            self.rules = self._parse_rules_concurrent(file_paths, max_workers)
            self.parsing_stats['performance']['concurrent_processing'] = True
            self.parsing_stats['performance']['worker_threads'] = max_workers
        else:
            logger.info("Using sequential processing")
            self.rules = self._parse_rules_sequential(file_paths)
            self.parsing_stats['performance']['concurrent_processing'] = False
            self.parsing_stats['performance']['worker_threads'] = 1
        
        # Update parsing statistics
        parsing_time = time.time() - start_time
        self._update_parsing_statistics(len(file_paths), parsing_time)
        
        # Perform post-processing analysis
        self._analyze_parsed_rules()
        
        # Log summary
        self._log_parsing_summary()
        
        return self.rules
    
    def _parse_rules_sequential(self, file_paths: List[str]) -> List[DetectionRule]:
        """
        Parse rules sequentially - better for debugging and smaller rule sets.
        
        Args:
            file_paths: List of file paths to parse
            
        Returns:
            List[DetectionRule]: Successfully parsed rules
        """
        rules = []
        
        for i, file_path in enumerate(file_paths, 1):
            if i % 50 == 0:  # Progress logging every 50 files
                logger.info(f"Processing file {i}/{len(file_paths)}")
            
            rule = self._parse_single_file(file_path)
            if rule:
                rules.append(rule)
        
        return rules
    
    def _parse_rules_concurrent(self, file_paths: List[str], max_workers: int) -> List[DetectionRule]:
        """
        Parse rules using thread pool for improved performance with large rule sets.
        
        Args:
            file_paths: List of file paths to parse
            max_workers: Maximum number of worker threads
            
        Returns:
            List[DetectionRule]: Successfully parsed rules
        """
        rules = []
        completed_count = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all parsing tasks
            future_to_path = {
                executor.submit(self._parse_single_file, path): path 
                for path in file_paths
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_path):
                file_path = future_to_path[future]
                completed_count += 1
                
                try:
                    rule = future.result()
                    if rule:
                        rules.append(rule)
                    
                    # Progress logging for long-running operations
                    if completed_count % 100 == 0:
                        logger.info(f"Completed {completed_count}/{len(file_paths)} files")
                        
                except Exception as e:
                    error_msg = f"Concurrent parsing error for {file_path}: {str(e)}"
                    logger.error(error_msg)
                    self.parsing_stats['errors']['parse_errors'].append(error_msg)
        
        return rules
    
    def _parse_single_file(self, file_path: str) -> Optional[DetectionRule]:
        """
        Parse a single rule file using automatic parser selection.
        
        This method implements the core logic for selecting the appropriate parser
        for each file based on content analysis and format detection.
        
        Args:
            file_path: Path to the rule file to parse
            
        Returns:
            DetectionRule: Parsed rule object, or None if parsing failed
        """
        try:
            # Select the most appropriate parser
            parser = self._select_parser(file_path)
            if not parser:
                logger.warning(f"No suitable parser found for {file_path}")
                self.parsing_stats['by_platform']['unknown_format'] += 1
                return None
            
            # Parse the rule using the selected parser
            rule = parser.parse(file_path)
            
            if rule:
                # Validate techniques against MITRE framework if validator available
                if self.mitre_validator:
                    self._validate_rule_techniques(rule)
                
                # Update platform statistics
                if rule.rule_type.startswith('elastic'):
                    self.parsing_stats['by_platform']['elastic_rules'] += 1
                elif rule.rule_type.startswith('sentinel'):
                    self.parsing_stats['by_platform']['sentinel_rules'] += 1
                
                return rule
            else:
                # Parser returned None, indicating parsing failure
                return None
                
        except Exception as e:
            error_msg = f"Error parsing {file_path}: {str(e)}"
            logger.error(error_msg)
            self.parsing_stats['errors']['parse_errors'].append(error_msg)
            return None
    
    def _select_parser(self, file_path: str) -> Optional[object]:
        """
        Select the most appropriate parser for a given file.
        
        This method uses content-based heuristics to determine which parser
        is most likely to successfully parse a given file. It tries parsers
        in order of confidence and returns the first one that indicates it
        can handle the file format.
        
        Args:
            file_path: Path to the file needing parsing
            
        Returns:
            Parser object, or None if no parser can handle the file
        """
        parser_scores = []
        
        # Test each parser's confidence in handling this file
        for name, parser in self.parsers.items():
            try:
                if parser.can_parse(file_path):
                    parser_scores.append((name, parser))
                    logger.debug(f"Parser {name} can handle {file_path}")
            except Exception as e:
                logger.debug(f"Parser {name} failed confidence check for {file_path}: {str(e)}")
        
        # Return the first parser that indicated it can handle the file
        # In the future, this could be enhanced with confidence scoring
        if parser_scores:
            selected_name, selected_parser = parser_scores[0]
            logger.debug(f"Selected {selected_name} parser for {file_path}")
            return selected_parser
        
        # If no parser can handle the file, try fallback based on extension
        file_extension = Path(file_path).suffix.lower()
        
        if file_extension in ['.yaml', '.yml']:
            # YAML files are more commonly Elastic rules
            logger.debug(f"Fallback: using Elastic parser for YAML file {file_path}")
            return self.parsers['elastic']
        elif file_extension == '.json':
            # JSON files are more commonly Sentinel rules
            logger.debug(f"Fallback: using Sentinel parser for JSON file {file_path}")
            return self.parsers['sentinel']
        
        # No suitable parser found
        logger.warning(f"No parser can handle file format: {file_path}")
        return None
    
    def _validate_rule_techniques(self, rule: DetectionRule) -> None:
        """
        Validate rule techniques against the MITRE ATT&CK framework.
        
        This method checks each technique in the rule against the official
        MITRE ATT&CK framework data, removing invalid techniques and tracking
        validation statistics.
        
        Args:
            rule: DetectionRule object to validate
        """
        if not self.mitre_validator:
            return
        
        original_technique_count = len(rule.techniques)
        invalid_techniques = []
        
        # Validate each technique
        for technique_id in rule.techniques.copy():
            if not self.mitre_validator.is_valid_technique(technique_id):
                invalid_techniques.append(technique_id)
                rule.techniques.remove(technique_id)
                rule.parse_errors.append(f"Invalid MITRE ATT&CK technique ID: {technique_id}")
        
        # Update validation statistics
        valid_count = original_technique_count - len(invalid_techniques)
        self.parsing_stats['attack_analysis']['techniques_validated'] += valid_count
        self.parsing_stats['attack_analysis']['techniques_invalid'] += len(invalid_techniques)
        
        # Log validation results
        if invalid_techniques:
            logger.warning(f"Removed {len(invalid_techniques)} invalid techniques from '{rule.name}': {invalid_techniques}")
            self.parsing_stats['errors']['validation_errors'].append(
                f"{rule.source_file}: Invalid techniques {invalid_techniques}"
            )
    
    def _update_parsing_statistics(self, total_files: int, parsing_time: float) -> None:
        """
        Update comprehensive parsing statistics.
        
        Args:
            total_files: Total number of files processed
            parsing_time: Time taken for parsing operation
        """
        successful_parses = len(self.rules)
        failed_parses = total_files - successful_parses
        files_per_second = total_files / parsing_time if parsing_time > 0 else 0
        
        self.parsing_stats['parsing'].update({
            'total_files': total_files,
            'successful_parses': successful_parses,
            'failed_parses': failed_parses,
            'parsing_time_seconds': parsing_time,
            'files_per_second': files_per_second
        })
    
    def _analyze_parsed_rules(self) -> None:
        """
        Perform comprehensive analysis of parsed rules for statistics and insights.
        
        This method aggregates information across all parsed rules to provide
        useful statistics about technique coverage, rule quality, and platform
        distribution.
        """
        if not self.rules:
            return
        
        all_techniques = set()
        all_tactics = set()
        total_techniques = 0
        total_tactics = 0
        
        # Aggregate technique and tactic information
        for rule in self.rules:
            all_techniques.update(rule.techniques)
            all_tactics.update(rule.tactics)
            total_techniques += len(rule.techniques)
            total_tactics += len(rule.tactics)
        
        # Update analysis statistics
        self.parsing_stats['attack_analysis'].update({
            'total_techniques': total_techniques,
            'unique_techniques': all_techniques,
            'total_tactics': total_tactics,
            'unique_tactics': all_tactics
        })
        
        # Calculate memory usage estimate
        estimated_memory_mb = len(self.rules) * 0.01  # Rough estimate: 10KB per rule
        self.parsing_stats['performance']['memory_usage_mb'] = estimated_memory_mb
    
    def _log_parsing_summary(self) -> None:
        """Log comprehensive parsing summary for operational visibility."""
        stats = self.parsing_stats
        
        logger.info("="*60)
        logger.info("RULE PARSING SUMMARY")
        logger.info("="*60)
        
        # Discovery summary
        discovery = stats['discovery']
        logger.info(f"Discovery: {discovery['files_discovered']} files found in {discovery['discovery_time_seconds']:.2f}s")
        
        # Parsing summary
        parsing = stats['parsing']
        success_rate = (parsing['successful_parses'] / parsing['total_files'] * 100) if parsing['total_files'] > 0 else 0
        logger.info(f"Parsing: {parsing['successful_parses']}/{parsing['total_files']} files ({success_rate:.1f}% success)")
        logger.info(f"Performance: {parsing['files_per_second']:.1f} files/second")
        
        # Platform distribution
        platform = stats['by_platform']
        logger.info(f"Platforms: {platform['elastic_rules']} Elastic, {platform['sentinel_rules']} Sentinel")
        
        # MITRE ATT&CK analysis
        attack = stats['attack_analysis']
        logger.info(f"Coverage: {len(attack['unique_techniques'])} unique techniques, {len(attack['unique_tactics'])} tactics")
        
        # Error summary
        error_count = sum(len(errors) for errors in stats['errors'].values())
        if error_count > 0:
            logger.warning(f"Errors: {error_count} total errors encountered")
        
        logger.info("="*60)
    
    def get_coverage_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive coverage analysis report.
        
        This method produces a detailed report suitable for management dashboards,
        security assessments, or integration with other tools.
        
        Returns:
            Dict[str, Any]: Comprehensive coverage report with statistics and analysis
        """
        if not self.rules:
            return {"error": "No rules parsed - cannot generate coverage report"}
        
        # Aggregate technique frequency analysis
        technique_frequency = {}
        tactic_coverage = {}
        
        for rule in self.rules:
            # Count technique occurrences across rules
            for technique in rule.techniques:
                technique_frequency[technique] = technique_frequency.get(technique, 0) + 1
            
            # Analyze tactic coverage if MITRE validator is available
            for technique in rule.techniques:
                if self.mitre_validator:
                    tech_info = self.mitre_validator.get_technique_info(technique)
                    if tech_info:
                        for tactic in tech_info.get('tactics', []):
                            if tactic not in tactic_coverage:
                                tactic_coverage[tactic] = set()
                            tactic_coverage[tactic].add(technique)
        
        # Convert sets to counts for JSON serialization
        tactic_coverage_counts = {
            tactic: len(techniques) 
            for tactic, techniques in tactic_coverage.items()
        }
        
        # Build comprehensive report
        report = {
            'generation_timestamp': datetime.now().isoformat(),
            'parsing_statistics': self.parsing_stats,
            'coverage_analysis': {
                'total_rules': len(self.rules),
                'rules_with_techniques': sum(1 for rule in self.rules if rule.techniques),
                'unique_techniques': len(self.parsing_stats['attack_analysis']['unique_techniques']),
                'technique_frequency': technique_frequency,
                'tactic_coverage_counts': tactic_coverage_counts,
                'most_common_techniques': sorted(
                    technique_frequency.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:20],  # Top 20 most common techniques
                'coverage_gaps': self._identify_coverage_gaps(),
                'platform_analysis': self._analyze_platform_distribution()
            },
            'quality_metrics': {
                'average_techniques_per_rule': (
                    self.parsing_stats['attack_analysis']['total_techniques'] / len(self.rules)
                    if self.rules else 0
                ),
                'rules_without_techniques': sum(1 for rule in self.rules if not rule.techniques),
                'parsing_errors': len(self.parsing_stats['errors']['parse_errors']),
                'validation_errors': len(self.parsing_stats['errors']['validation_errors'])
            }
        }
        
        return report
    
    def _identify_coverage_gaps(self) -> Dict[str, Any]:
        """
        Identify potential gaps in MITRE ATT&CK coverage.
        
        Returns:
            Dict[str, Any]: Analysis of coverage gaps and recommendations
        """
        gaps = {
            'tactics_without_coverage': [],
            'low_coverage_tactics': {},
            'recommendations': []
        }
        
        if not self.mitre_validator:
            gaps['note'] = "MITRE ATT&CK validator not available - gap analysis limited"
            return gaps
        
        # This would require more sophisticated analysis with full MITRE data
        # For now, provide basic analysis based on what we have
        covered_techniques = self.parsing_stats['attack_analysis']['unique_techniques']
        
        if len(covered_techniques) < 50:  # Arbitrary threshold for "low coverage"
            gaps['recommendations'].append(
                "Consider expanding detection coverage - fewer than 50 unique techniques covered"
            )
        
        return gaps
    
    def _analyze_platform_distribution(self) -> Dict[str, Any]:
        """
        Analyze distribution of rules across different platforms.
        
        Returns:
            Dict[str, Any]: Platform distribution analysis
        """
        platform_stats = self.parsing_stats['by_platform']
        total_rules = sum(platform_stats.values())
        
        distribution = {
            'total_rules': total_rules,
            'by_platform': platform_stats.copy()
        }
        
        if total_rules > 0:
            distribution['percentages'] = {
                platform: (count / total_rules * 100)
                for platform, count in platform_stats.items()
            }
        
        return distribution
    
    def get_rules_by_platform(self, platform: str) -> List[DetectionRule]:
        """
        Get all rules for a specific platform.
        
        Args:
            platform: Platform name ('elastic' or 'sentinel')
            
        Returns:
            List[DetectionRule]: Rules for the specified platform
        """
        return [rule for rule in self.rules if rule.rule_type.startswith(platform.lower())]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current parsing and analysis statistics.
        
        Returns:
            Dict[str, Any]: Current statistics
        """
        return self.parsing_stats.copy()
    
    def reset(self) -> None:
        """
        Reset the repository state for processing a new rule set.
        
        This method clears all parsed rules and statistics, preparing
        the repository for a fresh analysis run.
        """
        self.rules.clear()
        
        # Reset all statistics
        self.parsing_stats = {
            'discovery': {
                'directories_scanned': 0,
                'files_discovered': 0,
                'files_skipped': 0,
                'discovery_time_seconds': 0.0
            },
            'parsing': {
                'total_files': 0,
                'successful_parses': 0,
                'failed_parses': 0,
                'parsing_time_seconds': 0.0,
                'files_per_second': 0.0
            },
            'by_platform': {
                'elastic_rules': 0,
                'sentinel_rules': 0,
                'unknown_format': 0
            },
            'attack_analysis': {
                'total_techniques': 0,
                'unique_techniques': set(),
                'total_tactics': 0,
                'unique_tactics': set(),
                'techniques_validated': 0,
                'techniques_invalid': 0
            },
            'errors': {
                'parse_errors': [],
                'validation_errors': [],
                'security_violations': []
            },
            'performance': {
                'concurrent_processing': False,
                'worker_threads': 1,
                'memory_usage_mb': 0.0
            }
        }
        
        # Reset parser statistics
        for parser in self.parsers.values():
            parser.reset_statistics()
        
        logger.info("Rule repository reset - ready for new analysis")
