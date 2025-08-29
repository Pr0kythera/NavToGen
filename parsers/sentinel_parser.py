"""
Microsoft Sentinel Rule Parser
=============================

This module implements parsing logic for Microsoft Sentinel Analytics Rules and Detection Templates.
Unlike Elastic rules which have a standardized structure, Sentinel rules come in multiple formats:

1. Analytics Rules (JSON): ARM template format used by Azure Sentinel
2. Detection Templates (YAML): Community-contributed detection templates
3. Hunting Queries (various): KQL queries with metadata

Each format stores MITRE ATT&CK information differently, requiring flexible parsing logic
that can handle multiple field names and structures. This parser normalizes these different
approaches into our unified DetectionRule format.

Key challenges addressed by this parser:
- Multiple file formats (JSON ARM templates vs. YAML templates)
- Varying field names for MITRE ATT&CK data (tactics, techniques, relevantTechniques, etc.)
- Nested ARM template structures vs. flat template structures
- Different severity and metadata field conventions
"""

import json
import yaml
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Set

from parsers.base_parser import BaseRuleParser
from models.detection_rule import DetectionRule
from config import SENTINEL_INDICATORS, TECHNIQUE_ID_PATTERN

logger = logging.getLogger(__name__)


class SentinelRuleParser(BaseRuleParser):
    """
    Specialized parser for Microsoft Sentinel rules and detection templates.
    
    This parser handles the diverse formats used by Microsoft Sentinel, including
    ARM template-based Analytics Rules and community detection templates. It
    implements flexible parsing logic to extract MITRE ATT&CK information from
    various field structures and formats.
    
    Key Features:
    - Supports both JSON (ARM template) and YAML formats
    - Handles nested ARM template structures
    - Extracts techniques from multiple field name variations
    - Processes Sentinel-specific metadata (query frequency, trigger operators, etc.)
    - Supports both scheduled and near-real-time rule types
    - Handles community template format variations
    
    The parser uses content analysis to determine the specific Sentinel format
    and applies appropriate parsing logic for each variant.
    """
    
    def __init__(self):
        """Initialize the Microsoft Sentinel rule parser."""
        super().__init__("Sentinel")
        
        # Sentinel rule types and their characteristics
        self.rule_kinds = {
            'Scheduled': 'Scheduled Analytics Rule',
            'NRT': 'Near Real-Time Analytics Rule',
            'MicrosoftSecurityIncidentCreation': 'Microsoft Security Incident Creation Rule',
            'Fusion': 'Fusion Advanced Multistage Attack Detection',
            'ThreatIntelligence': 'Threat Intelligence Indicator Rule'
        }
        
        # Common field names where MITRE ATT&CK data might be stored in Sentinel rules
        self.attack_field_names = [
            'tactics',           # Standard field for tactics
            'techniques',        # Standard field for techniques  
            'relevantTechniques', # Alternative field name
            'attackTactics',     # Legacy field name
            'attackTechniques',  # Legacy field name
            'mitreTactics',      # Alternative naming
            'mitreTechniques',   # Alternative naming
            'tags'               # Sometimes techniques are stored in tags
        ]
        
        logger.debug("Microsoft Sentinel parser initialized")
    
    def can_parse(self, file_path: str) -> bool:
        """
        Determine if this file appears to be a Microsoft Sentinel rule.
        
        This method uses heuristics to identify Sentinel rules by looking for
        characteristic fields, structures, and content patterns specific to
        the various Sentinel rule formats.
        
        Args:
            file_path: Path to the potential Sentinel rule file
            
        Returns:
            bool: True if this appears to be a Sentinel rule, False otherwise
        """
        try:
            # Read a sample of the file for analysis
            content_sample = self.safe_file_read(file_path)
            if not content_sample:
                return False
            
            # Take first 3KB for analysis (Sentinel rules can have longer headers)
            sample = content_sample[:3072]
            
            # Count Sentinel-specific indicators
            sentinel_score = sum(1 for indicator in SENTINEL_INDICATORS if indicator in sample)
            
            # Look for ARM template structure (common in Sentinel Analytics Rules)
            arm_indicators = [
                '"$schema":', '"Microsoft.SecurityInsights"', '"resources":',
                '"alertRules"', '"parameters":', '"variables":'
            ]
            arm_score = sum(1 for indicator in arm_indicators if indicator in sample)
            
            # Look for Sentinel template structure (YAML detection templates)
            template_indicators = [
                'displayName:', 'description:', 'severity:', 'requiredDataConnectors:',
                'queryFrequency:', 'triggerOperator:', 'kind: Scheduled'
            ]
            template_score = sum(1 for indicator in template_indicators if indicator in sample)
            
            # Calculate total score
            total_score = sentinel_score + arm_score + template_score
            
            logger.debug(f"Sentinel detection score for {file_path}: {total_score} "
                        f"(sentinel: {sentinel_score}, arm: {arm_score}, template: {template_score})")
            
            # Require at least 2 indicators to confidently identify as Sentinel
            return total_score >= 2
            
        except Exception as e:
            logger.debug(f"Error checking Sentinel format for {file_path}: {str(e)}")
            return False
    
    def get_supported_extensions(self) -> List[str]:
        """Get file extensions supported by this parser."""
        return ['.json', '.yaml', '.yml']
    
    def parse(self, file_path: str) -> Optional[DetectionRule]:
        """
        Parse a Microsoft Sentinel rule file.
        
        This method handles the complete parsing process for Sentinel rules,
        automatically detecting the format (JSON ARM template vs YAML template)
        and applying appropriate parsing logic.
        
        Args:
            file_path: Absolute path to the Sentinel rule file
            
        Returns:
            DetectionRule: Parsed rule object, or None if parsing failed
        """
        try:
            logger.debug(f"Parsing Sentinel rule: {file_path}")
            
            # Determine format based on file extension
            file_extension = Path(file_path).suffix.lower()
            
            if file_extension == '.json':
                return self._parse_json_rule(file_path)
            elif file_extension in ['.yaml', '.yml']:
                return self._parse_yaml_rule(file_path)
            else:
                logger.error(f"Unsupported Sentinel rule format: {file_extension}")
                self.update_statistics(False)
                return None
                
        except Exception as e:
            logger.error(f"Unexpected error parsing Sentinel rule {file_path}: {str(e)}")
            self.update_statistics(False)
            return None
    
    def _parse_json_rule(self, file_path: str) -> Optional[DetectionRule]:
        """
        Parse JSON format Sentinel Analytics Rule (ARM template).
        
        Args:
            file_path: Path to the JSON rule file
            
        Returns:
            DetectionRule: Parsed rule object, or None if parsing failed
        """
        try:
            # Read and parse JSON content
            content = self.safe_file_read(file_path)
            if not content:
                return None
            
            try:
                rule_data = json.loads(content)
            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing error in {file_path}: {str(e)}")
                self.update_statistics(False)
                return None
            
            # Handle ARM template format vs. direct rule format
            if 'resources' in rule_data and isinstance(rule_data['resources'], list):
                # ARM template format - find the alertRule resource
                for resource in rule_data['resources']:
                    if (isinstance(resource, dict) and 
                        resource.get('type') == 'Microsoft.SecurityInsights/alertRules'):
                        properties = resource.get('properties', {})
                        if properties:
                            return self._extract_sentinel_rule_data(properties, file_path)
                
                logger.warning(f"No alertRule resource found in ARM template: {file_path}")
                self.update_statistics(False)
                return None
            else:
                # Direct rule format
                return self._extract_sentinel_rule_data(rule_data, file_path)
                
        except Exception as e:
            logger.error(f"Error parsing JSON Sentinel rule {file_path}: {str(e)}")
            self.update_statistics(False)
            return None
    
    def _parse_yaml_rule(self, file_path: str) -> Optional[DetectionRule]:
        """
        Parse YAML format Sentinel detection template.
        
        Args:
            file_path: Path to the YAML rule file
            
        Returns:
            DetectionRule: Parsed rule object, or None if parsing failed
        """
        try:
            # Read and parse YAML content
            content = self.safe_file_read(file_path)
            if not content:
                return None
            
            try:
                rule_data = yaml.safe_load(content)
            except yaml.YAMLError as e:
                logger.error(f"YAML parsing error in {file_path}: {str(e)}")
                self.update_statistics(False)
                return None
            
            if not self.validate_rule_structure(rule_data):
                logger.error(f"Invalid Sentinel YAML rule structure: {file_path}")
                self.update_statistics(False)
                return None
            
            return self._extract_sentinel_rule_data(rule_data, file_path)
            
        except Exception as e:
            logger.error(f"Error parsing YAML Sentinel rule {file_path}: {str(e)}")
            self.update_statistics(False)
            return None
    
    def _extract_sentinel_rule_data(self, rule_data: Dict[str, Any], file_path: str) -> DetectionRule:
        """
        Extract rule data from parsed Sentinel rule (works for both JSON and YAML).
        
        This method handles the core logic for extracting information from Sentinel
        rules regardless of their original format. It normalizes the various field
        names and structures used across different Sentinel rule types.
        
        Args:
            rule_data: Parsed rule data (from JSON or YAML)
            file_path: Source file path for reference
            
        Returns:
            DetectionRule: Populated DetectionRule object
        """
        # Extract basic metadata
        rule = self.extract_basic_metadata(rule_data, file_path)
        
        # Extract Sentinel-specific metadata
        self._extract_sentinel_metadata(rule, rule_data)
        
        # Process MITRE ATT&CK information from various possible fields
        techniques_found, tactics_found = self._extract_attack_mappings(rule, rule_data)
        
        # Extract additional Sentinel-specific fields
        self._extract_additional_sentinel_metadata(rule, rule_data)
        
        # Validate extraction results
        if not rule.techniques and not rule.tactics:
            logger.warning(f"No MITRE ATT&CK mappings found in Sentinel rule: {file_path}")
            # Try fallback extraction from rule text
            self._fallback_technique_extraction(rule, rule_data)
        
        logger.debug(f"Successfully parsed Sentinel rule '{rule.name}' with {len(rule.techniques)} techniques and {len(rule.tactics)} tactics")
        
        # Update statistics
        self.update_statistics(True, techniques_found, tactics_found)
        return rule
    
    def _extract_sentinel_metadata(self, rule: DetectionRule, rule_data: Dict[str, Any]) -> None:
        """
        Extract Sentinel-specific metadata fields.
        
        Args:
            rule: DetectionRule object to populate
            rule_data: Parsed rule data
        """
        # Map Sentinel display name to our name field
        if 'displayName' in rule_data and not rule.name:
            rule.name = str(rule_data['displayName'])
        
        # Handle Sentinel rule kinds
        if 'kind' in rule_data:
            rule_kind = str(rule_data['kind'])
            rule.rule_type = f"sentinel-{rule_kind.lower()}"
            
            # Add kind description if available
            if rule_kind in self.rule_kinds:
                kind_description = self.rule_kinds[rule_kind]
                if rule.description and kind_description not in rule.description:
                    rule.description += f" [{kind_description}]"
        
        # Handle Sentinel severity levels
        if 'severity' in rule_data:
            # Sentinel uses: Informational, Low, Medium, High
            # Map to our standard levels
            severity = str(rule_data['severity']).lower()
            severity_mapping = {
                'informational': 'low',
                'low': 'low',
                'medium': 'medium',
                'high': 'high'
            }
            rule.severity = severity_mapping.get(severity, severity)
        
        # Extract enabled status
        rule.enabled = rule_data.get('enabled', True)
        
        # Handle Sentinel-specific IDs
        for id_field in ['alertRuleTemplateName', 'id', 'name']:
            if id_field in rule_data and not rule.rule_id:
                rule.rule_id = str(rule_data[id_field])
                break
    
    def _extract_attack_mappings(self, rule: DetectionRule, rule_data: Dict[str, Any]) -> tuple[int, int]:
        """
        Extract MITRE ATT&CK mappings from various Sentinel field structures.
        
        Sentinel rules store ATT&CK information in multiple possible fields with
        different structures. This method tries all known variations to ensure
        comprehensive extraction.
        
        Args:
            rule: DetectionRule object to populate
            rule_data: Parsed rule data
            
        Returns:
            tuple[int, int]: (techniques_found, tactics_found) for statistics
        """
        techniques_found = 0
        tactics_found = 0
        
        # Try each possible field that might contain ATT&CK data
        for field_name in self.attack_field_names:
            if field_name not in rule_data:
                continue
            
            field_data = rule_data[field_name]
            logger.debug(f"Processing ATT&CK field '{field_name}' in {rule.source_file}")
            
            # Handle different data structures
            if isinstance(field_data, list):
                # List format: ["T1055", "T1566.001"] or [{"name": "Initial Access"}]
                for item in field_data:
                    if isinstance(item, str):
                        # Direct technique/tactic string
                        if self._looks_like_technique(item):
                            if rule.add_technique(item, f"{field_name} in {rule.source_file}"):
                                techniques_found += 1
                        else:
                            # Might be a tactic name
                            if rule.add_tactic(item):
                                tactics_found += 1
                    
                    elif isinstance(item, dict):
                        # Dictionary format with various possible structures
                        techniques_found += self._extract_from_dict(rule, item, field_name)
                        tactics_found += self._extract_tactics_from_dict(rule, item, field_name)
            
            elif isinstance(field_data, dict):
                # Single dictionary with ATT&CK data
                techniques_found += self._extract_from_dict(rule, field_data, field_name)
                tactics_found += self._extract_tactics_from_dict(rule, field_data, field_name)
            
            elif isinstance(field_data, str):
                # String that might contain technique IDs
                extracted_techniques = self._extract_techniques_from_text(field_data)
                for technique_id in extracted_techniques:
                    if rule.add_technique(technique_id, f"{field_name} text in {rule.source_file}"):
                        techniques_found += 1
        
        return techniques_found, tactics_found
    
    def _extract_from_dict(self, rule: DetectionRule, data: Dict[str, Any], source_field: str) -> int:
        """
        Extract technique information from a dictionary structure.
        
        Args:
            rule: DetectionRule to populate
            data: Dictionary containing technique data
            source_field: Name of the source field for logging
            
        Returns:
            int: Number of techniques found
        """
        techniques_found = 0
        
        # Try various field names that might contain technique IDs
        technique_fields = ['id', 'techniqueId', 'technique', 'name', 'value']
        
        for field in technique_fields:
            if field in data:
                value = data[field]
                if isinstance(value, str) and self._looks_like_technique(value):
                    if rule.add_technique(value, f"{source_field}.{field} in {rule.source_file}"):
                        techniques_found += 1
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and self._looks_like_technique(item):
                            if rule.add_technique(item, f"{source_field}.{field} in {rule.source_file}"):
                                techniques_found += 1
        
        return techniques_found
    
    def _extract_tactics_from_dict(self, rule: DetectionRule, data: Dict[str, Any], source_field: str) -> int:
        """
        Extract tactic information from a dictionary structure.
        
        Args:
            rule: DetectionRule to populate
            data: Dictionary containing tactic data
            source_field: Name of the source field for logging
            
        Returns:
            int: Number of tactics found
        """
        tactics_found = 0
        
        # Try various field names that might contain tactic information
        tactic_fields = ['name', 'tactic', 'tacticName', 'value']
        
        for field in tactic_fields:
            if field in data:
                value = data[field]
                if isinstance(value, str) and not self._looks_like_technique(value):
                    if rule.add_tactic(value):
                        tactics_found += 1
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and not self._looks_like_technique(item):
                            if rule.add_tactic(item):
                                tactics_found += 1
        
        return tactics_found
    
    def _extract_techniques_from_text(self, text: str) -> Set[str]:
        """
        Extract technique IDs from free-form text using regex pattern matching.
        
        Args:
            text: Text that might contain technique IDs
            
        Returns:
            Set[str]: Set of technique IDs found in the text
        """
        if not text or not isinstance(text, str):
            return set()
        
        # Use the global technique pattern to find technique IDs
        matches = TECHNIQUE_ID_PATTERN.findall(text)
        return set(matches)
    
    def _looks_like_technique(self, text: str) -> bool:
        """
        Check if a string looks like a MITRE ATT&CK technique ID.
        
        Args:
            text: String to check
            
        Returns:
            bool: True if text appears to be a technique ID
        """
        if not text or not isinstance(text, str):
            return False
        
        return bool(TECHNIQUE_ID_PATTERN.match(text.strip()))
    
    def _fallback_technique_extraction(self, rule: DetectionRule, rule_data: Dict[str, Any]) -> None:
        """
        Fallback method to extract techniques from rule content when standard fields are empty.
        
        This method searches through various text fields in the rule for technique IDs
        that might be mentioned in descriptions, queries, or comments.
        
        Args:
            rule: DetectionRule to populate
            rule_data: Parsed rule data
        """
        # Fields to search for technique IDs as fallback
        search_fields = ['description', 'query', 'queryFrequency', 'triggerOperator', 
                        'suppressionDuration', 'tactics', 'techniques', 'notes']
        
        techniques_found = 0
        
        for field in search_fields:
            if field in rule_data:
                field_content = str(rule_data[field])
                extracted_techniques = self._extract_techniques_from_text(field_content)
                
                for technique_id in extracted_techniques:
                    if rule.add_technique(technique_id, f"fallback extraction from {field}"):
                        techniques_found += 1
        
        if techniques_found > 0:
            logger.info(f"Fallback extraction found {techniques_found} techniques in {rule.source_file}")
    
    def _extract_additional_sentinel_metadata(self, rule: DetectionRule, rule_data: Dict[str, Any]) -> None:
        """
        Extract additional Sentinel-specific metadata fields.
        
        Args:
            rule: DetectionRule to populate
            rule_data: Parsed rule data
        """
        # Handle timestamps (Sentinel uses different field names)
        timestamp_mappings = [
            ('createdTimeUtc', 'created_date'),
            ('lastModifiedUtc', 'modified_date'),
            ('created', 'created_date'),
            ('lastUpdated', 'modified_date')
        ]
        
        for source_field, target_attr in timestamp_mappings:
            if source_field in rule_data:
                try:
                    timestamp_str = str(rule_data[source_field])
                    # Handle various timestamp formats
                    if timestamp_str.endswith('Z'):
                        timestamp_str = timestamp_str.replace('Z', '+00:00')
                    
                    parsed_timestamp = datetime.fromisoformat(timestamp_str)
                    setattr(rule, target_attr, parsed_timestamp)
                    
                except (ValueError, TypeError) as e:
                    logger.warning(f"Could not parse timestamp {source_field} in {rule.source_file}: {str(e)}")
                    rule.parse_errors.append(f"Invalid {source_field} timestamp: {rule_data[source_field]}")
        
        # Extract query frequency and related metadata
        sentinel_specific_fields = {
            'queryFrequency': 'Query Frequency',
            'queryPeriod': 'Query Period', 
            'triggerOperator': 'Trigger Operator',
            'triggerThreshold': 'Trigger Threshold',
            'suppressionDuration': 'Suppression Duration',
            'suppressionEnabled': 'Suppression Enabled'
        }
        
        metadata_extracted = []
        for field, display_name in sentinel_specific_fields.items():
            if field in rule_data:
                value = str(rule_data[field])
                metadata_extracted.append(f"{display_name}: {value}")
        
        # Add Sentinel-specific metadata to description if found
        if metadata_extracted and rule.description:
            metadata_str = " | ".join(metadata_extracted)
            if metadata_str not in rule.description:
                rule.description += f" [Sentinel Config: {metadata_str}]"
    
    def validate_rule_structure(self, rule_data: Dict[str, Any]) -> bool:
        """
        Validate Sentinel rule structure.
        
        Args:
            rule_data: Parsed rule data to validate
            
        Returns:
            bool: True if structure is valid for a Sentinel rule
        """
        # Run base validation first
        if not super().validate_rule_structure(rule_data):
            return False
        
        # Sentinel-specific validation
        # Check for at least one of the common Sentinel fields
        sentinel_fields = ['displayName', 'kind', 'severity', 'queryFrequency', 'query']
        has_sentinel_field = any(field in rule_data for field in sentinel_fields)
        
        if not has_sentinel_field:
            logger.warning("No recognizable Sentinel fields found in rule data")
            return False
        
        # If it has a kind field, validate it's a known Sentinel rule kind
        if 'kind' in rule_data:
            kind = rule_data['kind']
            if kind not in self.rule_kinds and kind not in ['Scheduled', 'NRT']:
                logger.warning(f"Unknown Sentinel rule kind: {kind}")
                # Don't fail validation, just warn
        
        return True
