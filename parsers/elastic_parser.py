"""
Elastic Security Rule Parser
===========================

This module implements parsing logic specifically for Elastic Security Detection Engine rules.
Elastic rules use a structured YAML format with a specific schema for MITRE ATT&CK mappings
located in the 'threat' field hierarchy.

Elastic rules follow a well-defined structure where MITRE ATT&CK information is stored in
nested threat objects. Each threat object contains:
- tactic: The high-level adversary goal
- technique: Array of techniques used to achieve that tactic  
- subtechnique: Array of more specific sub-techniques

This parser understands this structure and extracts techniques from the appropriate fields,
ensuring we capture the full breadth of MITRE ATT&CK coverage represented in Elastic rules.

The parser also handles Elastic-specific metadata like risk scores, rule types (query, eql, etc.),
and timeline templates that are unique to the Elastic Security platform.
"""

import yaml
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from parsers.base_parser import BaseRuleParser
from models.detection_rule import DetectionRule
from config import ELASTIC_INDICATORS

logger = logging.getLogger(__name__)


class ElasticRuleParser(BaseRuleParser):
    """
    Specialized parser for Elastic Security Detection Engine rules.
    
    This parser handles the YAML-based format used by Elastic Security rules,
    with deep understanding of the threat taxonomy structure that maps rules
    to MITRE ATT&CK techniques and tactics.
    
    Key Features:
    - Parses structured threat taxonomy from Elastic rule format
    - Extracts techniques and sub-techniques from nested hierarchies
    - Handles Elastic-specific metadata (risk scores, rule types, etc.)
    - Supports both detection rules and machine learning rules
    - Validates rule structure according to Elastic schema expectations
    
    The parser is designed to be robust against variations in the Elastic
    rule format while maintaining strict validation of MITRE ATT&CK mappings.
    """
    
    def __init__(self):
        """Initialize the Elastic Security rule parser."""
        super().__init__("Elastic")
        
        # Elastic rule type mappings for better categorization
        self.rule_types = {
            'query': 'KQL Query Rule',
            'eql': 'EQL (Event Query Language) Rule', 
            'machine_learning': 'Machine Learning Rule',
            'threshold': 'Threshold Rule',
            'threat_match': 'Indicator Match Rule',
            'new_terms': 'New Terms Rule'
        }
        
        logger.debug("Elastic Security parser initialized")
    
    def can_parse(self, file_path: str) -> bool:
        """
        Determine if this file appears to be an Elastic Security rule.
        
        This method uses heuristics to identify Elastic rules without fully
        parsing them. It looks for characteristic fields and structures that
        are specific to the Elastic Detection Engine format.
        
        Args:
            file_path: Path to the potential Elastic rule file
            
        Returns:
            bool: True if this appears to be an Elastic rule, False otherwise
        """
        # Check file extension first (quick filter)
        if not file_path.lower().endswith(('.yaml', '.yml')):
            return False
        
        try:
            # Read a sample of the file to check for Elastic indicators
            content_sample = self.safe_file_read(file_path)
            if not content_sample:
                return False
            
            # Take first 2KB for analysis (sufficient for rule headers)
            sample = content_sample[:2048]
            
            # Count Elastic-specific indicators
            elastic_score = sum(1 for indicator in ELASTIC_INDICATORS if indicator in sample)
            
            # Look for the structured threat taxonomy that's characteristic of Elastic rules
            threat_indicators = ['threat:', 'tactic:', 'technique:', 'framework: MITRE ATT&CK']
            threat_score = sum(1 for indicator in threat_indicators if indicator in sample)
            
            # Elastic rules typically have multiple indicators
            total_score = elastic_score + threat_score
            
            logger.debug(f"Elastic detection score for {file_path}: {total_score} (elastic: {elastic_score}, threat: {threat_score})")
            
            # Require at least 2 indicators to confidently identify as Elastic
            return total_score >= 2
            
        except Exception as e:
            logger.debug(f"Error checking Elastic format for {file_path}: {str(e)}")
            return False
    
    def get_supported_extensions(self) -> List[str]:
        """Get file extensions supported by this parser."""
        return ['.yaml', '.yml']
    
    def parse(self, file_path: str) -> Optional[DetectionRule]:
        """
        Parse an Elastic Security Detection Engine rule file.
        
        This method handles the complete parsing process for Elastic rules,
        including YAML parsing, structure validation, metadata extraction,
        and MITRE ATT&CK technique identification.
        
        The parsing process follows these steps:
        1. Safely read and parse the YAML content
        2. Validate the basic rule structure
        3. Extract core rule metadata (name, description, etc.)
        4. Process the threat taxonomy for MITRE ATT&CK mappings
        5. Extract Elastic-specific metadata (risk scores, rule types, etc.)
        6. Handle timestamps and author information
        7. Build and return the complete DetectionRule object
        
        Args:
            file_path: Absolute path to the Elastic rule file
            
        Returns:
            DetectionRule: Parsed rule object with MITRE ATT&CK mappings, or None if parsing failed
        """
        try:
            logger.debug(f"Parsing Elastic rule: {file_path}")
            
            # Step 1: Read and parse YAML content
            content = self.safe_file_read(file_path)
            if not content:
                logger.error(f"Could not read Elastic rule file: {file_path}")
                self.update_statistics(False)
                return None
            
            try:
                # Use safe_load to prevent code execution vulnerabilities
                rule_data = yaml.safe_load(content)
            except yaml.YAMLError as e:
                logger.error(f"YAML parsing error in {file_path}: {str(e)}")
                self.update_statistics(False)
                return None
            
            # Step 2: Validate basic structure
            if not self.validate_rule_structure(rule_data):
                logger.error(f"Invalid Elastic rule structure: {file_path}")
                self.update_statistics(False)
                return None
            
            # Step 3: Extract basic metadata using parent class helper
            rule = self.extract_basic_metadata(rule_data, file_path)
            
            # Step 4: Extract Elastic-specific metadata
            self._extract_elastic_metadata(rule, rule_data)
            
            # Step 5: Process threat taxonomy for MITRE ATT&CK mappings
            techniques_found, tactics_found = self._process_threat_taxonomy(rule, rule_data)
            
            # Step 6: Extract additional Elastic-specific fields
            self._extract_additional_metadata(rule, rule_data)
            
            # Step 7: Validate that we extracted meaningful data
            if not rule.techniques and not rule.tactics:
                logger.warning(f"No MITRE ATT&CK mappings found in Elastic rule: {file_path}")
            
            logger.debug(f"Successfully parsed Elastic rule '{rule.name}' with {len(rule.techniques)} techniques and {len(rule.tactics)} tactics")
            
            # Update statistics and return the parsed rule
            self.update_statistics(True, techniques_found, tactics_found)
            return rule
            
        except Exception as e:
            logger.error(f"Unexpected error parsing Elastic rule {file_path}: {str(e)}")
            self.update_statistics(False)
            return None
    
    def _extract_elastic_metadata(self, rule: DetectionRule, rule_data: Dict[str, Any]) -> None:
        """
        Extract Elastic-specific metadata from the rule.
        
        This method handles fields that are unique to Elastic Security rules,
        such as rule types, risk scores, and Detection Engine specific settings.
        
        Args:
            rule: DetectionRule object to populate
            rule_data: Parsed YAML data from the rule file
        """
        # Extract rule ID (common in Elastic rules)
        if 'rule_id' in rule_data:
            rule.rule_id = str(rule_data['rule_id'])
        
        # Extract and normalize rule type
        if 'type' in rule_data:
            rule_type = str(rule_data['type']).lower()
            # Store both the raw type and a human-readable description
            rule.rule_type = f"elastic-{rule_type}"
            
            # Add rule type info to description if it's a specialized type
            if rule_type in self.rule_types:
                type_description = self.rule_types[rule_type]
                if rule.description and type_description not in rule.description:
                    rule.description += f" [{type_description}]"
        
        # Extract risk score and map to severity
        if 'risk_score' in rule_data:
            risk_score = rule_data['risk_score']
            try:
                score_value = int(risk_score)
                # Map Elastic risk scores to standard severity levels
                if score_value >= 75:
                    rule.severity = 'critical'
                elif score_value >= 50:
                    rule.severity = 'high'
                elif score_value >= 25:
                    rule.severity = 'medium'
                else:
                    rule.severity = 'low'
            except (ValueError, TypeError):
                # If risk_score isn't a valid integer, use it as-is
                rule.severity = str(risk_score).lower()
        
        # Extract enabled status (Elastic rules can be disabled)
        if 'enabled' in rule_data:
            rule.enabled = bool(rule_data['enabled'])
        else:
            # Default to enabled if not specified
            rule.enabled = True
    
    def _process_threat_taxonomy(self, rule: DetectionRule, rule_data: Dict[str, Any]) -> tuple[int, int]:
        """
        Process the threat taxonomy structure to extract MITRE ATT&CK mappings.
        
        Elastic rules use a structured approach to MITRE ATT&CK mapping within
        the 'threat' field. This method navigates that structure to extract
        both techniques and tactics accurately.
        
        The threat structure typically looks like:
        threat:
          - tactic:
              id: TA0001
              name: Initial Access
            technique:
              - id: T1566
                name: Phishing
                subtechnique:
                  - id: T1566.001
                    name: Spearphishing Attachment
        
        Args:
            rule: DetectionRule object to populate
            rule_data: Parsed rule data containing the threat structure
            
        Returns:
            tuple[int, int]: (techniques_found, tactics_found) for statistics
        """
        techniques_found = 0
        tactics_found = 0
        
        # Get the threat array from the rule
        threat_data = rule_data.get('threat', [])
        if not isinstance(threat_data, list):
            logger.debug(f"Threat field is not a list in {rule.source_file}")
            return techniques_found, tactics_found
        
        # Process each threat item (there can be multiple tactics per rule)
        for threat_item in threat_data:
            if not isinstance(threat_item, dict):
                continue
            
            # Extract tactic information
            tactic_data = threat_item.get('tactic', {})
            if isinstance(tactic_data, dict):
                tactic_name = tactic_data.get('name')
                if tactic_name:
                    success = rule.add_tactic(tactic_name)
                    if success:
                        tactics_found += 1
                        logger.debug(f"Extracted tactic '{tactic_name}' from {rule.source_file}")
            
            # Extract technique information
            techniques_data = threat_item.get('technique', [])
            if isinstance(techniques_data, list):
                for technique in techniques_data:
                    if not isinstance(technique, dict):
                        continue
                    
                    # Extract main technique ID
                    technique_id = technique.get('id')
                    if technique_id:
                        success = rule.add_technique(technique_id, f"threat.technique.id in {rule.source_file}")
                        if success:
                            techniques_found += 1
                            logger.debug(f"Extracted technique '{technique_id}' from {rule.source_file}")
                    
                    # Extract sub-techniques
                    sub_techniques = technique.get('subtechnique', [])
                    if isinstance(sub_techniques, list):
                        for sub_technique in sub_techniques:
                            if isinstance(sub_technique, dict):
                                sub_id = sub_technique.get('id')
                                if sub_id:
                                    success = rule.add_technique(sub_id, f"threat.technique.subtechnique.id in {rule.source_file}")
                                    if success:
                                        techniques_found += 1
                                        logger.debug(f"Extracted sub-technique '{sub_id}' from {rule.source_file}")
        
        return techniques_found, tactics_found
    
    def _extract_additional_metadata(self, rule: DetectionRule, rule_data: Dict[str, Any]) -> None:
        """
        Extract additional metadata fields that provide context for the rule.
        
        This method handles timestamps, references, false positives, and other
        metadata that helps with rule management and analysis.
        
        Args:
            rule: DetectionRule object to populate
            rule_data: Parsed rule data
        """
        # Handle creation and modification timestamps
        for date_field, attr_name in [('created', 'created_date'), ('updated', 'modified_date')]:
            if date_field in rule_data:
                try:
                    # Elastic typically uses ISO format timestamps
                    date_str = str(rule_data[date_field])
                    # Handle both with and without timezone info
                    if date_str.endswith('Z'):
                        date_str = date_str.replace('Z', '+00:00')
                    
                    parsed_date = datetime.fromisoformat(date_str)
                    setattr(rule, attr_name, parsed_date)
                    
                except (ValueError, TypeError) as e:
                    logger.warning(f"Could not parse {date_field} timestamp in {rule.source_file}: {str(e)}")
                    # Store the raw value in parse_errors for debugging
                    rule.parse_errors.append(f"Invalid {date_field} timestamp: {rule_data[date_field]}")
        
        # Extract false positive information
        if 'false_positives' in rule_data:
            fp_data = rule_data['false_positives']
            if isinstance(fp_data, list):
                rule.false_positives = [str(fp) for fp in fp_data]
            elif isinstance(fp_data, str):
                rule.false_positives = [fp_data]
        
        # Extract references
        if 'references' in rule_data:
            ref_data = rule_data['references']
            if isinstance(ref_data, list):
                rule.references = [str(ref) for ref in ref_data]
            elif isinstance(ref_data, str):
                rule.references = [ref_data]
        
        # Extract author information (Elastic rules often have multiple authors)
        if 'author' in rule_data:
            author_data = rule_data['author']
            if isinstance(author_data, list):
                # Join multiple authors with commas
                rule.author = ', '.join(str(author) for author in author_data)
            else:
                rule.author = str(author_data)
        
        # Extract version information if available
        if 'version' in rule_data:
            try:
                version = int(rule_data['version'])
                # Store version info in the description or as metadata
                if version > 1:
                    rule.description += f" [Version {version}]"
            except (ValueError, TypeError):
                rule.parse_errors.append(f"Invalid version format: {rule_data['version']}")
        
        # Handle license information (common in open source Elastic rules)
        if 'license' in rule_data:
            license_info = str(rule_data['license'])
            if license_info and 'license' not in rule.description.lower():
                rule.description += f" [License: {license_info}]"
    
    def validate_rule_structure(self, rule_data: Dict[str, Any]) -> bool:
        """
        Validate that the rule data has the expected Elastic rule structure.
        
        This method extends the base validation with Elastic-specific checks,
        ensuring the rule conforms to the Detection Engine schema expectations.
        
        Args:
            rule_data: Parsed rule data to validate
            
        Returns:
            bool: True if structure is valid for an Elastic rule
        """
        # First run the base validation
        if not super().validate_rule_structure(rule_data):
            return False
        
        # Elastic-specific validation checks
        
        # Check for required fields in Elastic rules
        required_fields = ['name', 'description', 'type']
        missing_fields = [field for field in required_fields if field not in rule_data]
        
        if missing_fields:
            logger.warning(f"Elastic rule missing required fields: {missing_fields}")
            return False
        
        # Validate rule type
        valid_types = ['query', 'eql', 'machine_learning', 'threshold', 'threat_match', 'new_terms']
        rule_type = rule_data.get('type', '').lower()
        
        if rule_type not in valid_types:
            logger.warning(f"Unknown Elastic rule type: {rule_type}")
            # Don't fail validation for unknown types, just warn
        
        # If there's a threat section, validate its structure
        if 'threat' in rule_data:
            threat_data = rule_data['threat']
            if not isinstance(threat_data, list):
                logger.warning("Elastic rule 'threat' field should be a list")
                return False
            
            # Validate each threat item has the expected structure
            for i, threat_item in enumerate(threat_data):
                if not isinstance(threat_item, dict):
                    logger.warning(f"Elastic rule threat[{i}] should be a dictionary")
                    continue
                
                # Check for either tactic or technique (one is required for meaningful mapping)
                has_tactic = 'tactic' in threat_item
                has_technique = 'technique' in threat_item
                
                if not (has_tactic or has_technique):
                    logger.warning(f"Elastic rule threat[{i}] missing both tactic and technique")
        
        return True
    
    def get_rule_complexity_score(self, rule_data: Dict[str, Any]) -> int:
        """
        Calculate a complexity score for the Elastic rule.
        
        This method analyzes various aspects of the rule to determine its complexity,
        which can be useful for prioritizing review efforts or understanding
        the sophistication of detection logic.
        
        Args:
            rule_data: Parsed rule data
            
        Returns:
            int: Complexity score (higher numbers indicate more complex rules)
        """
        complexity_score = 0
        
        # Rule type complexity (some types are inherently more complex)
        rule_type = rule_data.get('type', '').lower()
        type_complexity = {
            'query': 1,
            'eql': 3,        # EQL queries are typically more complex
            'threshold': 2,   # Threshold rules require statistical analysis
            'machine_learning': 4,  # ML rules are most complex
            'threat_match': 3,      # Indicator matching is moderately complex
            'new_terms': 2          # New terms detection has moderate complexity
        }
        complexity_score += type_complexity.get(rule_type, 1)
        
        # MITRE ATT&CK mapping complexity
        threat_data = rule_data.get('threat', [])
        if isinstance(threat_data, list):
            complexity_score += len(threat_data)  # Multiple tactics increase complexity
            
            # Count sub-techniques (more granular mapping = higher complexity)
            for threat_item in threat_data:
                if isinstance(threat_item, dict):
                    techniques = threat_item.get('technique', [])
                    if isinstance(techniques, list):
                        for technique in techniques:
                            if isinstance(technique, dict):
                                sub_techniques = technique.get('subtechnique', [])
                                if isinstance(sub_techniques, list):
                                    complexity_score += len(sub_techniques)
        
        # Query complexity (longer queries are typically more complex)
        if 'query' in rule_data:
            query = str(rule_data['query'])
            # Simple heuristic: longer queries with more conditions are more complex
            complexity_score += min(len(query.split()) // 10, 5)  # Cap at 5 points
        
        # False positive handling (rules with FP mitigation are more sophisticated)
        if 'false_positives' in rule_data and rule_data['false_positives']:
            complexity_score += 2
        
        return min(complexity_score, 20)  # Cap at reasonable maximum
