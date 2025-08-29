"""
Detection Rule Data Model
========================

This module defines the DetectionRule class, which serves as our unified data structure
for representing detection rules regardless of their source platform (Elastic or Sentinel).

Think of this as a "universal translator" that takes the different formats and structures
used by various SIEM platforms and converts them into a common representation that our
analysis tools can work with consistently.

The dataclass decorator automatically generates __init__, __repr__, and other methods,
reducing boilerplate code while maintaining clean, readable class definitions.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Set, List, Optional

from config import VALID_TACTICS


@dataclass
class DetectionRule:
    """
    Unified representation of a detection rule from any supported platform.
    
    This class acts as a common interface for detection rules, whether they come
    from Elastic Security, Microsoft Sentinel, or any other platform we might
    add in the future. By standardizing on this format, the rest of our system
    can work with rules without caring about their original format.
    
    The design follows the "Adapter Pattern" - we adapt different rule formats
    into this common interface, making the rest of our code much simpler.
    
    Attributes:
        name: Human-readable name of the detection rule
        description: Detailed description of what the rule detects
        rule_type: Platform identifier ('elastic' or 'sentinel')
        source_file: Path to the original rule file for debugging/reference
        techniques: Set of MITRE ATT&CK technique IDs (e.g., {'T1055', 'T1055.001'})
        tactics: Set of MITRE ATT&CK tactics (normalized names)
        severity: Rule severity level (low, medium, high, critical)
        enabled: Whether the rule is currently active
        rule_id: Unique identifier from the source platform
        author: Rule author(s) information
        created_date: When the rule was originally created
        modified_date: When the rule was last modified
        false_positives: Known false positive scenarios
        references: External references and documentation
        parse_errors: Any errors encountered during parsing
    """
    
    # Required fields - every rule must have these
    name: str
    description: str = ""
    rule_type: str = ""  # 'elastic' or 'sentinel'
    source_file: str = ""
    
    # MITRE ATT&CK mappings - the core data we're analyzing
    techniques: Set[str] = field(default_factory=set)
    tactics: Set[str] = field(default_factory=set)
    
    # Metadata that helps with analysis and reporting
    severity: str = "medium"
    enabled: bool = True
    rule_id: str = ""
    author: str = ""
    created_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    false_positives: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    # Error tracking for debugging and quality assurance
    parse_errors: List[str] = field(default_factory=list)
    
    def add_technique(self, technique_id: str, context: str = "") -> bool:
        """
        Add a validated MITRE ATT&CK technique ID to this rule.
        
        This method doesn't just blindly add technique IDs - it validates them first
        to ensure they follow the correct format. This prevents invalid data from
        polluting our analysis results.
        
        The validation follows the official MITRE ATT&CK naming convention:
        - Main techniques: T#### (e.g., T1055)
        - Sub-techniques: T####.### (e.g., T1055.001)
        
        Args:
            technique_id: The technique ID to add (will be normalized to uppercase)
            context: Optional context about where this technique was found (for debugging)
            
        Returns:
            bool: True if technique was successfully added, False if invalid
            
        Example:
            rule.add_technique("t1055.001", "found in threat.technique.subtechnique.id")
            # This normalizes to "T1055.001" and returns True
        """
        if self._validate_technique_id(technique_id):
            # Normalize to uppercase for consistency
            normalized_id = technique_id.upper().strip()
            self.techniques.add(normalized_id)
            
            # Log successful addition for debugging (if context provided)
            if context:
                import logging
                logger = logging.getLogger(__name__)
                logger.debug(f"Added technique {normalized_id} from {context}")
            
            return True
        else:
            # Track invalid technique IDs for quality assurance
            error_msg = f"Invalid technique ID format: {technique_id}"
            self.parse_errors.append(error_msg)
            
            # Also log the error for immediate visibility during development
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"{error_msg} in {self.source_file}")
            
            return False
    
    def add_tactic(self, tactic: str) -> bool:
        """
        Add a normalized MITRE ATT&CK tactic to this rule.
        
        Tactics represent the high-level goals of an adversary (like "Initial Access"
        or "Defense Evasion"). Different platforms may format these differently,
        so we normalize them to match MITRE's standard format.
        
        Args:
            tactic: The tactic name to add (will be normalized)
            
        Returns:
            bool: True if tactic was successfully added, False if invalid
            
        Example:
            rule.add_tactic("Initial Access")  # becomes "initial-access"
            rule.add_tactic("Defense_Evasion") # becomes "defense-evasion"
        """
        if not tactic or not isinstance(tactic, str):
            return False
        
        # Normalize tactic name to match MITRE conventions
        # Convert to lowercase, replace spaces and underscores with hyphens
        normalized_tactic = tactic.lower().strip().replace(' ', '-').replace('_', '-')
        
        # Validate against known tactics to prevent typos and invalid entries
        if normalized_tactic in VALID_TACTICS:
            self.tactics.add(normalized_tactic)
            return True
        else:
            # Log unrecognized tactics for review - they might be valid but new
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Unrecognized tactic '{tactic}' (normalized to '{normalized_tactic}') in {self.source_file}")
            return False
    
    def get_parent_techniques(self) -> Set[str]:
        """
        Extract parent technique IDs from any sub-techniques in this rule.
        
        Sub-techniques in MITRE ATT&CK follow the format T####.### where the parent
        technique is T####. This method extracts all parent techniques, which is
        useful for ensuring proper visualization in Navigator layers.
        
        Returns:
            Set[str]: Set of parent technique IDs
            
        Example:
            If rule has techniques {'T1055.001', 'T1055.002', 'T1078'}
            This returns {'T1055'} because T1055.001 and T1055.002 are sub-techniques
            of T1055, while T1078 has no sub-techniques in this rule.
        """
        parents = set()
        for technique in self.techniques:
            if '.' in technique:  # This is a sub-technique
                parent = technique.split('.')[0]
                parents.add(parent)
        return parents
    
    def get_coverage_score(self) -> int:
        """
        Calculate a simple coverage score based on the number of techniques.
        
        This provides a quick way to assess how comprehensive a rule is in terms
        of MITRE ATT&CK coverage. Rules covering more techniques might indicate
        broader detection capabilities.
        
        Returns:
            int: Number of unique techniques covered by this rule
        """
        return len(self.techniques)
    
    def has_sub_techniques(self) -> bool:
        """
        Check if this rule covers any sub-techniques.
        
        Sub-techniques provide more granular coverage information and may indicate
        more sophisticated detection logic.
        
        Returns:
            bool: True if rule has any sub-techniques (format T####.###)
        """
        return any('.' in technique for technique in self.techniques)
    
    def get_rule_summary(self) -> str:
        """
        Generate a concise summary of this rule for reporting purposes.
        
        This creates a human-readable summary that's useful for reports and
        debugging output.
        
        Returns:
            str: Formatted summary of the rule
        """
        technique_count = len(self.techniques)
        tactic_count = len(self.tactics)
        sub_tech_count = sum(1 for t in self.techniques if '.' in t)
        
        summary_parts = [
            f"Rule: {self.name}",
            f"Type: {self.rule_type}",
            f"Techniques: {technique_count} ({sub_tech_count} sub-techniques)",
            f"Tactics: {tactic_count}",
            f"Severity: {self.severity}",
            f"Enabled: {self.enabled}"
        ]
        
        if self.parse_errors:
            summary_parts.append(f"Parse Errors: {len(self.parse_errors)}")
        
        return " | ".join(summary_parts)
    
    @staticmethod
    def _validate_technique_id(technique_id: str) -> bool:
        """
        Validate MITRE ATT&CK technique ID format using strict pattern matching.
        
        This validation ensures we only accept properly formatted technique IDs,
        preventing invalid data from contaminating our analysis.
        
        The validation pattern enforces the official MITRE ATT&CK format:
        - Must start with 'T' (case insensitive)
        - Followed by exactly 4 digits
        - Optionally followed by a period and exactly 3 digits for sub-techniques
        
        Args:
            technique_id: The technique ID string to validate
            
        Returns:
            bool: True if technique ID follows the correct format, False otherwise
            
        Examples:
            _validate_technique_id("T1055") -> True
            _validate_technique_id("T1055.001") -> True
            _validate_technique_id("T123") -> False (too few digits)
            _validate_technique_id("T1055.1") -> False (sub-technique needs 3 digits)
            _validate_technique_id("1055") -> False (missing 'T' prefix)
        """
        if not technique_id or not isinstance(technique_id, str):
            return False
        
        # Clean up the input and check format
        cleaned_id = technique_id.upper().strip()
        
        # Use regex pattern to enforce exact format requirements
        # ^T\d{4}(\.\d{3})?$ breaks down as:
        # ^ - start of string
        # T - literal 'T' character
        # \d{4} - exactly 4 digits
        # (\.\d{3})? - optional group containing period and exactly 3 digits
        # $ - end of string
        pattern = r'^T\d{4}(\.\d{3})?$'
        return bool(re.match(pattern, cleaned_id))
    
    def __post_init__(self):
        """
        Perform additional validation after object creation.
        
        This method runs automatically after the dataclass __init__ method,
        allowing us to perform validation and normalization on the data.
        This is particularly useful for ensuring data consistency.
        """
        # Normalize rule type to lowercase for consistency
        if self.rule_type:
            self.rule_type = self.rule_type.lower().strip()
        
        # Normalize severity to lowercase for consistency
        if self.severity:
            self.severity = self.severity.lower().strip()
        
        # Validate that rule_type is one of our supported values
        if self.rule_type and self.rule_type not in ['elastic', 'sentinel']:
            self.parse_errors.append(f"Unknown rule type: {self.rule_type}")
    
    def __str__(self) -> str:
        """
        Provide a clean string representation for printing and logging.
        
        Returns:
            str: Human-readable representation of the rule
        """
        return f"DetectionRule(name='{self.name}', type={self.rule_type}, techniques={len(self.techniques)})"
    
    def __repr__(self) -> str:
        """
        Provide a detailed string representation for debugging.
        
        Returns:
            str: Detailed representation showing all key attributes
        """
        return (f"DetectionRule(name='{self.name}', rule_type='{self.rule_type}', "
                f"techniques={self.techniques}, tactics={self.tactics}, "
                f"source_file='{self.source_file}')")
