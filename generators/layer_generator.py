"""
Navigator Layer Generator
========================

This module generates MITRE ATT&CK Navigator layers from parsed detection rules.
It transforms our internal rule analysis into the specific JSON format required
by the MITRE ATT&CK Navigator visualization tool.

The generator supports multiple visualization modes:
1. Coverage Analysis: Shows which techniques are covered by detection rules
2. Platform Comparison: Compares coverage between different SIEM platforms  
3. Frequency Analysis: Visualizes how many rules cover each technique
4. Gap Analysis: Highlights techniques that lack sufficient coverage

Think of this module as the "presentation specialist" that takes our technical
analysis results and transforms them into compelling, actionable visualizations
that security teams can use to understand and improve their detection coverage.

Key features:
- Intelligent scoring algorithms that reflect coverage quality and quantity
- Customizable color schemes for different analysis types
- Rich metadata and tooltips for detailed technique information
- Support for both main techniques and sub-techniques
- Automatic parent technique expansion for better visualization
"""

import logging
from datetime import datetime
from typing import Dict, List, Set, Optional, Any, Tuple
import math

from models.detection_rule import DetectionRule
from models.navigator_layer_model import NavigatorLayer, TechniqueEntry
from validators.mitre_validator import MitreAttackValidator
from config import (
    COVERAGE_COLORS, 
    DEFAULT_ATTACK_VERSION,
    validate_attack_version
)

logger = logging.getLogger(__name__)


class NavigatorLayerGenerator:
    """
    Generates MITRE ATT&CK Navigator layers from parsed detection rules.
    
    This class implements sophisticated algorithms for converting rule analysis
    results into Navigator layer visualizations. It provides multiple generation
    modes to support different analysis scenarios and visualization needs.
    
    The generator follows the Builder pattern, allowing you to configure various
    aspects of layer generation before producing the final output. It also
    implements the Strategy pattern for different scoring algorithms.
    
    Key capabilities:
    - Multiple scoring strategies (linear, logarithmic, threshold-based)
    - Intelligent color coding based on coverage levels  
    - Rich metadata generation for enhanced tooltips
    - Support for technique frequency analysis
    - Platform comparison and gap analysis modes
    - Automatic handling of technique parent-child relationships
    
    Attributes:
        mitre_validator: Optional MITRE ATT&CK validator for enhanced metadata
        default_attack_version: Default ATT&CK version for generated layers
        scoring_algorithms: Available scoring algorithms for coverage visualization
    """
    
    def __init__(self, mitre_validator: Optional[MitreAttackValidator] = None):
        """
        Initialize the Navigator layer generator.
        
        Args:
            mitre_validator: Optional MITRE ATT&CK validator for enhanced technique metadata
        """
        self.mitre_validator = mitre_validator
        self.default_attack_version = DEFAULT_ATTACK_VERSION
        
        # Available scoring algorithms for different visualization needs
        self.scoring_algorithms = {
            'linear': self._linear_scoring,
            'logarithmic': self._logarithmic_scoring,
            'threshold': self._threshold_scoring,
            'frequency': self._frequency_scoring
        }
        
        logger.debug("Navigator layer generator initialized")
        if mitre_validator:
            logger.debug("Enhanced metadata generation enabled via MITRE ATT&CK validator")
    
    def generate_coverage_layer(self, rules: List[DetectionRule], 
                               layer_name: str = "Detection Coverage Analysis",
                               description: str = "",
                               attack_version: str = None,
                               scoring_algorithm: str = 'threshold') -> NavigatorLayer:
        """
        Generate a coverage analysis layer showing detection rule coverage across techniques.
        
        This method creates the most common type of Navigator layer, showing which
        MITRE ATT&CK techniques are covered by your detection rules and how well
        they're covered (based on the number of rules per technique).
        
        The visualization uses color coding to quickly identify:
        - High coverage areas (green): Multiple rules cover these techniques
        - Medium coverage areas (yellow): Some coverage but could be improved  
        - Low coverage areas (red): Minimal coverage, potential gaps
        
        Args:
            rules: List of detection rules to analyze
            layer_name: Name for the generated layer
            description: Description text for the layer
            attack_version: MITRE ATT&CK version to reference
            scoring_algorithm: Algorithm to use for coverage scoring
            
        Returns:
            NavigatorLayer: Complete Navigator layer ready for export
            
        Raises:
            ValueError: If no rules provided or invalid parameters
        """
        if not rules:
            raise ValueError("No rules provided for layer generation")
        
        # Validate and set attack version
        attack_version = self._validate_attack_version(attack_version)
        
        # Validate scoring algorithm
        if scoring_algorithm not in self.scoring_algorithms:
            logger.warning(f"Unknown scoring algorithm '{scoring_algorithm}', using 'threshold'")
            scoring_algorithm = 'threshold'
        
        logger.info(f"Generating coverage layer '{layer_name}' with {len(rules)} rules using {scoring_algorithm} scoring")
        
        # Aggregate technique data from all rules
        technique_data = self._aggregate_technique_data(rules)
        
        if not technique_data:
            raise ValueError("No MITRE ATT&CK techniques found in the provided rules")
        
        # Create the base layer
        layer = NavigatorLayer(
            name=layer_name,
            description=description or self._generate_default_description(rules, "coverage"),
            attack_version=attack_version
        )
        
        # Set up appropriate legend for coverage analysis
        layer.set_default_legend()
        
        # Generate technique entries with scoring
        scoring_func = self.scoring_algorithms[scoring_algorithm]
        
        for technique_id, data in technique_data.items():
            # Calculate score and color based on rule coverage
            score, color = scoring_func(data['rule_count'])
            
            # Create technique entry with rich metadata
            technique_entry = TechniqueEntry(
                technique_id=technique_id,
                score=score,
                color=color,
                comment=self._generate_technique_comment(technique_id, data, "coverage"),
                show_subtechniques=self._should_show_subtechniques(technique_id, technique_data)
            )
            
            # Add metadata for enhanced tooltips
            self._add_coverage_metadata(technique_entry, data)
            
            layer.add_technique_entry(technique_entry)
        
        # Sort techniques for consistent output
        layer.sort_techniques(by_score=False)  # Sort by technique ID for browsing
        
        logger.info(f"Generated coverage layer with {layer.get_technique_count()} techniques")
        return layer
    
    def generate_comparison_layer(self, elastic_rules: List[DetectionRule], 
                                sentinel_rules: List[DetectionRule],
                                layer_name: str = "Platform Coverage Comparison") -> NavigatorLayer:
        """
        Generate a comparison layer showing coverage differences between platforms.
        
        This specialized layer type helps organizations understand the differences
        in MITRE ATT&CK coverage between their Elastic SIEM and Microsoft Sentinel
        deployments, highlighting areas where coverage is shared, unique, or missing.
        
        Color coding:
        - Green: Techniques covered by both platforms (good redundancy)
        - Blue: Techniques covered only by Elastic (potential Sentinel gap)
        - Orange: Techniques covered only by Sentinel (potential Elastic gap)
        
        Args:
            elastic_rules: List of Elastic detection rules
            sentinel_rules: List of Sentinel detection rules  
            layer_name: Name for the comparison layer
            
        Returns:
            NavigatorLayer: Comparison layer showing platform differences
            
        Raises:
            ValueError: If both rule lists are empty
        """
        if not elastic_rules and not sentinel_rules:
            raise ValueError("No rules provided for either platform")
        
        logger.info(f"Generating comparison layer: {len(elastic_rules)} Elastic rules vs {len(sentinel_rules)} Sentinel rules")
        
        # Extract technique sets for each platform
        elastic_techniques = self._extract_technique_set(elastic_rules)
        sentinel_techniques = self._extract_technique_set(sentinel_rules)
        
        # Calculate comparison categories
        both_platforms = elastic_techniques & sentinel_techniques
        elastic_only = elastic_techniques - sentinel_techniques  
        sentinel_only = sentinel_techniques - elastic_techniques
        
        # Create the comparison layer
        layer = NavigatorLayer(
            name=layer_name,
            description=self._generate_comparison_description(
                len(elastic_rules), len(sentinel_rules),
                len(elastic_techniques), len(sentinel_techniques),
                len(both_platforms), len(elastic_only), len(sentinel_only)
            ),
            attack_version=self.default_attack_version
        )
        
        # Set up comparison legend
        layer.set_comparison_legend()
        
        # Add all techniques with appropriate coloring
        all_techniques = elastic_techniques | sentinel_techniques
        
        for technique_id in sorted(all_techniques):
            if technique_id in both_platforms:
                color = COVERAGE_COLORS['both_platforms']
                score = 2
                comment = "Covered by both Elastic and Sentinel"
                platforms = "Both"
            elif technique_id in elastic_only:
                color = COVERAGE_COLORS['elastic_only']
                score = 1
                comment = "Covered by Elastic only - potential Sentinel gap"
                platforms = "Elastic"
            else:  # sentinel_only
                color = COVERAGE_COLORS['sentinel_only']
                score = 0
                comment = "Covered by Sentinel only - potential Elastic gap"  
                platforms = "Sentinel"
            
            # Create technique entry
            technique_entry = TechniqueEntry(
                technique_id=technique_id,
                score=score,
                color=color,
                comment=comment,
                show_subtechniques=self._should_show_subtechniques(technique_id, {t: {} for t in all_techniques})
            )
            
            # Add comparison-specific metadata
            technique_entry.add_metadata("Platform Coverage", platforms)
            
            # Add rule counts for each platform
            elastic_count = sum(1 for rule in elastic_rules if technique_id in rule.techniques)
            sentinel_count = sum(1 for rule in sentinel_rules if technique_id in rule.techniques)
            
            technique_entry.add_metadata("Elastic Rules", str(elastic_count))
            technique_entry.add_metadata("Sentinel Rules", str(sentinel_count))
            
            # Add MITRE ATT&CK metadata if available
            self._add_mitre_metadata(technique_entry, technique_id)
            
            layer.add_technique_entry(technique_entry)
        
        logger.info(f"Generated comparison layer: {len(both_platforms)} shared, {len(elastic_only)} Elastic-only, {len(sentinel_only)} Sentinel-only")
        return layer
    
    def generate_frequency_layer(self, rules: List[DetectionRule], 
                               layer_name: str = "Technique Frequency Analysis",
                               max_frequency: Optional[int] = None) -> NavigatorLayer:
        """
        Generate a frequency analysis layer showing how often each technique appears.
        
        This layer type helps identify the most and least commonly detected techniques
        in your rule set, which can inform prioritization decisions for rule development
        and help identify over-represented or under-represented attack vectors.
        
        Args:
            rules: List of detection rules to analyze
            layer_name: Name for the frequency layer
            max_frequency: Maximum frequency for scoring normalization (auto-calculated if None)
            
        Returns:
            NavigatorLayer: Frequency analysis layer
        """
        if not rules:
            raise ValueError("No rules provided for frequency analysis")
        
        logger.info(f"Generating frequency analysis layer with {len(rules)} rules")
        
        # Count technique frequencies
        technique_frequency = {}
        for rule in rules:
            for technique in rule.techniques:
                technique_frequency[technique] = technique_frequency.get(technique, 0) + 1
        
        if not technique_frequency:
            raise ValueError("No techniques found in rules for frequency analysis")
        
        # Calculate max frequency for normalization
        if max_frequency is None:
            max_frequency = max(technique_frequency.values())
        
        # Create the frequency layer
        layer = NavigatorLayer(
            name=layer_name,
            description=f"Technique frequency analysis across {len(rules)} rules. "
                       f"Shows how often each technique appears (max: {max_frequency} occurrences).",
            attack_version=self.default_attack_version
        )
        
        # Set up frequency-based legend
        layer.add_legend_item("High Frequency (80-100%)", "#8ec843")
        layer.add_legend_item("Medium Frequency (40-80%)", "#ffe766") 
        layer.add_legend_item("Low Frequency (1-40%)", "#ff6666")
        
        # Generate technique entries based on frequency
        for technique_id, frequency in technique_frequency.items():
            # Normalize frequency to 0-100 scale
            normalized_score = int((frequency / max_frequency) * 100)
            
            # Color based on frequency percentile
            if normalized_score >= 80:
                color = "#8ec843"  # Green for high frequency
            elif normalized_score >= 40:
                color = "#ffe766"  # Yellow for medium frequency
            else:
                color = "#ff6666"  # Red for low frequency
            
            # Create technique entry
            technique_entry = TechniqueEntry(
                technique_id=technique_id,
                score=normalized_score,
                color=color,
                comment=f"Appears in {frequency} rules ({frequency/len(rules)*100:.1f}% of total)",
                show_subtechniques=self._should_show_subtechniques(technique_id, technique_frequency)
            )
            
            # Add frequency metadata
            technique_entry.add_metadata("Frequency", str(frequency))
            technique_entry.add_metadata("Percentage", f"{frequency/len(rules)*100:.1f}%")
            
            # Add MITRE ATT&CK metadata if available
            self._add_mitre_metadata(technique_entry, technique_id)
            
            layer.add_technique_entry(technique_entry)
        
        # Sort by frequency (highest first) for better visualization
        layer.sort_techniques(by_score=True)
        
        logger.info(f"Generated frequency layer with {len(technique_frequency)} techniques (max frequency: {max_frequency})")
        return layer
    
    def _aggregate_technique_data(self, rules: List[DetectionRule]) -> Dict[str, Dict[str, Any]]:
        """
        Aggregate technique information from all rules for comprehensive analysis.
        
        Args:
            rules: List of detection rules to analyze
            
        Returns:
            Dict[str, Dict[str, Any]]: Aggregated technique data with statistics
        """
        technique_data = {}
        
        for rule in rules:
            for technique_id in rule.techniques:
                if technique_id not in technique_data:
                    technique_data[technique_id] = {
                        'rule_count': 0,
                        'rules': [],
                        'platforms': set(),
                        'severities': set(),
                        'tactics': set(),
                        'rule_types': set()
                    }
                
                data = technique_data[technique_id]
                data['rule_count'] += 1
                data['rules'].append(rule.name)
                data['platforms'].add(rule.rule_type.split('-')[0])  # Extract platform (elastic/sentinel)
                data['severities'].add(rule.severity)
                data['tactics'].update(rule.tactics)
                
                # Extract rule type for additional context
                if '-' in rule.rule_type:
                    data['rule_types'].add(rule.rule_type.split('-', 1)[1])
        
        # Convert sets to lists for JSON serialization and easier handling
        for data in technique_data.values():
            data['platforms'] = list(data['platforms'])
            data['severities'] = list(data['severities'])
            data['tactics'] = list(data['tactics'])
            data['rule_types'] = list(data['rule_types'])
        
        return technique_data
    
    def _extract_technique_set(self, rules: List[DetectionRule]) -> Set[str]:
        """
        Extract the set of all techniques covered by a list of rules.
        
        Args:
            rules: List of detection rules
            
        Returns:
            Set[str]: Set of all technique IDs found in the rules
        """
        techniques = set()
        for rule in rules:
            techniques.update(rule.techniques)
        return techniques
    
    def _generate_technique_comment(self, technique_id: str, data: Dict[str, Any], 
                                  layer_type: str) -> str:
        """
        Generate an informative comment/tooltip for a technique entry.
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            data: Aggregated technique data
            layer_type: Type of layer being generated ('coverage', 'frequency', etc.)
            
        Returns:
            str: Formatted comment text for the technique
        """
        comment_parts = []
        
        if layer_type == "coverage":
            rule_count = data['rule_count']
            comment_parts.append(f"Coverage: {rule_count} rule{'s' if rule_count != 1 else ''}")
            
            # Add platform information
            platforms = data.get('platforms', [])
            if platforms:
                comment_parts.append(f"Platforms: {', '.join(platforms)}")
            
            # Add example rules (limit to 3 for readability)
            example_rules = data['rules'][:3]
            if example_rules:
                rules_text = ", ".join(example_rules)
                if len(data['rules']) > 3:
                    rules_text += f" (+{len(data['rules']) - 3} more)"
                comment_parts.append(f"Rules: {rules_text}")
        
        # Add MITRE ATT&CK information if available
        if self.mitre_validator:
            tech_info = self.mitre_validator.get_technique_info(technique_id)
            if tech_info:
                comment_parts.append(f"Name: {tech_info['name']}")
                
                # Add tactic information
                tactics = tech_info.get('tactics', [])
                if tactics:
                    comment_parts.append(f"Tactics: {', '.join(tactics[:3])}")  # Limit for space
        
        return " | ".join(comment_parts)
    
    def _add_coverage_metadata(self, technique_entry: TechniqueEntry, data: Dict[str, Any]) -> None:
        """
        Add coverage-specific metadata to a technique entry.
        
        Args:
            technique_entry: TechniqueEntry to enhance with metadata
            data: Aggregated technique data
        """
        technique_entry.add_metadata("Rule Count", str(data['rule_count']))
        
        platforms = data.get('platforms', [])
        if platforms:
            technique_entry.add_metadata("Platforms", ", ".join(platforms))
        
        severities = data.get('severities', [])
        if severities:
            # Show the highest severity for quick assessment
            severity_order = ['critical', 'high', 'medium', 'low']
            highest_severity = next((s for s in severity_order if s in severities), 'unknown')
            technique_entry.add_metadata("Highest Severity", highest_severity.title())
        
        # Add rule type diversity
        rule_types = data.get('rule_types', [])
        if rule_types:
            technique_entry.add_metadata("Rule Types", ", ".join(set(rule_types)[:3]))  # Limit for readability
    
    def _add_mitre_metadata(self, technique_entry: TechniqueEntry, technique_id: str) -> None:
        """
        Add MITRE ATT&CK metadata to a technique entry if validator is available.
        
        Args:
            technique_entry: TechniqueEntry to enhance
            technique_id: MITRE ATT&CK technique ID
        """
        if not self.mitre_validator:
            return
        
        tech_info = self.mitre_validator.get_technique_info(technique_id)
        if not tech_info:
            return
        
        # Add technique name
        if tech_info.get('name'):
            technique_entry.add_metadata("ATT&CK Name", tech_info['name'])
        
        # Add platform information from MITRE
        platforms = tech_info.get('platforms', [])
        if platforms:
            platform_list = ", ".join(platforms[:4])  # Limit for space
            if len(platforms) > 4:
                platform_list += f" (+{len(platforms)-4} more)"
            technique_entry.add_metadata("ATT&CK Platforms", platform_list)
        
        # Add tactic information
        tactics = tech_info.get('tactics', [])
        if tactics:
            tactic_list = ", ".join(tactics[:3])  # Limit for readability
            if len(tactics) > 3:
                tactic_list += f" (+{len(tactics)-3} more)"
            technique_entry.add_metadata("ATT&CK Tactics", tactic_list)
        
        # Add sub-technique indicator
        if tech_info.get('is_sub_technique'):
            technique_entry.add_metadata("Type", "Sub-technique")
    
    def _should_show_subtechniques(self, technique_id: str, technique_data: Dict[str, Any]) -> bool:
        """
        Determine if subtechniques should be expanded for a parent technique.
        
        Args:
            technique_id: Technique ID to check
            technique_data: Dictionary of all technique data
            
        Returns:
            bool: True if subtechniques should be shown expanded
        """
        if '.' in technique_id:
            return False  # This is already a subtechnique
        
        # Check if we have any subtechniques for this parent technique
        for other_id in technique_data.keys():
            if other_id.startswith(f"{technique_id}."):
                return True
        
        return False
    
    def _generate_default_description(self, rules: List[DetectionRule], layer_type: str) -> str:
        """
        Generate a default description for a layer based on the rules analyzed.
        
        Args:
            rules: List of rules analyzed
            layer_type: Type of layer ('coverage', 'comparison', 'frequency')
            
        Returns:
            str: Generated description text
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Count rules by platform
        elastic_count = sum(1 for rule in rules if rule.rule_type.startswith('elastic'))
        sentinel_count = sum(1 for rule in rules if rule.rule_type.startswith('sentinel'))
        
        # Count unique techniques
        all_techniques = set()
        for rule in rules:
            all_techniques.update(rule.techniques)
        
        description_parts = [
            f"{layer_type.title()} analysis generated on {timestamp}",
            f"Analyzed {len(rules)} detection rules ({elastic_count} Elastic, {sentinel_count} Sentinel)",
            f"Covering {len(all_techniques)} unique MITRE ATT&CK techniques"
        ]
        
        return ". ".join(description_parts) + "."
    
    def _generate_comparison_description(self, elastic_rule_count: int, sentinel_rule_count: int,
                                       elastic_tech_count: int, sentinel_tech_count: int,
                                       shared_count: int, elastic_only_count: int, 
                                       sentinel_only_count: int) -> str:
        """Generate description for comparison layer."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return (f"Platform comparison analysis generated on {timestamp}. "
                f"Elastic: {elastic_rule_count} rules covering {elastic_tech_count} techniques. "
                f"Sentinel: {sentinel_rule_count} rules covering {sentinel_tech_count} techniques. "
                f"Shared coverage: {shared_count} techniques. "
                f"Platform-specific: {elastic_only_count} Elastic-only, {sentinel_only_count} Sentinel-only.")
    
    def _validate_attack_version(self, attack_version: Optional[str]) -> str:
        """
        Validate and normalize ATT&CK version.
        
        Args:
            attack_version: Version string to validate
            
        Returns:
            str: Validated version string
        """
        if attack_version is None:
            return self.default_attack_version
        
        if validate_attack_version(attack_version):
            return attack_version
        else:
            logger.warning(f"Invalid ATT&CK version '{attack_version}', using default '{self.default_attack_version}'")
            return self.default_attack_version
    
    # Scoring algorithm implementations
    
    def _threshold_scoring(self, rule_count: int) -> Tuple[int, str]:
        """
        Threshold-based scoring algorithm with distinct coverage levels.
        
        Args:
            rule_count: Number of rules covering this technique
            
        Returns:
            Tuple[int, str]: (score, color) for the technique
        """
        if rule_count >= 5:
            return 100, COVERAGE_COLORS['high_coverage']
        elif rule_count >= 2:
            return 60, COVERAGE_COLORS['medium_coverage']
        else:
            return 30, COVERAGE_COLORS['low_coverage']
    
    def _linear_scoring(self, rule_count: int) -> Tuple[int, str]:
        """
        Linear scoring algorithm that scales smoothly with rule count.
        
        Args:
            rule_count: Number of rules covering this technique
            
        Returns:
            Tuple[int, str]: (score, color) for the technique
        """
        # Linear scaling with maximum at 10 rules
        score = min(rule_count * 10, 100)
        
        if score >= 70:
            color = COVERAGE_COLORS['high_coverage']
        elif score >= 40:
            color = COVERAGE_COLORS['medium_coverage']
        else:
            color = COVERAGE_COLORS['low_coverage']
        
        return score, color
    
    def _logarithmic_scoring(self, rule_count: int) -> Tuple[int, str]:
        """
        Logarithmic scoring algorithm that gives diminishing returns for many rules.
        
        Args:
            rule_count: Number of rules covering this technique
            
        Returns:
            Tuple[int, str]: (score, color) for the technique
        """
        # Logarithmic scaling - each additional rule has less impact
        if rule_count <= 0:
            score = 0
        else:
            score = min(int(math.log(rule_count + 1) * 25), 100)
        
        if score >= 75:
            color = COVERAGE_COLORS['high_coverage']
        elif score >= 45:
            color = COVERAGE_COLORS['medium_coverage']
        else:
            color = COVERAGE_COLORS['low_coverage']
        
        return score, color
    
    def _frequency_scoring(self, rule_count: int) -> Tuple[int, str]:
        """
        Frequency-based scoring for technique frequency analysis.
        
        Args:
            rule_count: Frequency of this technique
            
        Returns:
            Tuple[int, str]: (score, color) for the technique
        """
        # This method would typically be called with pre-normalized scores
        # but we provide a simple implementation for completeness
        score = min(rule_count * 20, 100)  # Scale factor of 20
        
        if score >= 80:
            color = "#8ec843"  # High frequency
        elif score >= 40:
            color = "#ffe766"  # Medium frequency
        else:
            color = "#ff6666"  # Low frequency
        
        return score, color
    
    def __str__(self) -> str:
        """Provide clean string representation for logging."""
        validator_status = "with MITRE validation" if self.mitre_validator else "format validation only"
        return f"NavigatorLayerGenerator({validator_status})"
