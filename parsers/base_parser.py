"""
Base Parser Interface
====================

This module defines the abstract base class that all rule parsers must implement.
Using an abstract base class ensures consistency across different parser implementations
and makes it easy to add support for new rule formats in the future.

Think of this as a "contract" that all parsers must follow. Just like how different
translators must all be able to take input text and produce output text, all our
parsers must be able to take a file path and produce a DetectionRule object.

The abstract base class pattern provides several benefits:
1. Interface consistency - all parsers work the same way
2. Polymorphism - we can use any parser through the same interface
3. Extensibility - adding new parsers is straightforward
4. Documentation - the base class documents what parsers must do
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
import logging
import threading

from models.detection_rule import DetectionRule

logger = logging.getLogger(__name__)


class BaseRuleParser(ABC):
    """
    Abstract base class for all rule parsers.
    
    This class defines the interface that all rule parsers must implement.
    It provides common functionality while requiring subclasses to implement
    the platform-specific parsing logic.
    
    The design follows the Template Method pattern - we define the overall
    structure and common behavior here, while specific parsing steps are
    implemented by subclasses.
    
    Each parser is responsible for:
    1. Validating that it can handle the given file
    2. Safely loading and parsing the file content
    3. Extracting MITRE ATT&CK techniques and tactics
    4. Building a complete DetectionRule object
    5. Handling errors gracefully and providing useful feedback
    """
    
    def __init__(self, parser_name: str):
        """
        Initialize the base parser with identification information.
        
        Args:
            parser_name: Human-readable name for this parser (e.g., "Elastic", "Sentinel")
        """
        self.parser_name = parser_name
        self.parse_statistics = {
            'files_processed': 0,
            'successful_parses': 0,
            'failed_parses': 0,
            'techniques_extracted': 0,
            'tactics_extracted': 0
        }
        self._stats_lock = threading.Lock()  # Thread-safe statistics updates
        
        logger.debug(f"Initialized {parser_name} parser")
    
    @abstractmethod
    def parse(self, file_path: str) -> Optional[DetectionRule]:
        """
        Parse a rule file and return a DetectionRule object.
        
        This is the main interface method that all parsers must implement.
        Each parser should read the file, extract relevant information,
        and return a properly populated DetectionRule object.
        
        Args:
            file_path: Absolute path to the rule file to parse
            
        Returns:
            DetectionRule: Parsed rule object, or None if parsing failed
            
        Raises:
            Should not raise exceptions - all errors should be handled gracefully
            and logged appropriately. Return None on any parsing failure.
        """
        pass
    
    @abstractmethod
    def can_parse(self, file_path: str) -> bool:
        """
        Determine if this parser can handle the given file.
        
        This method allows the system to automatically select the appropriate
        parser for each file without trying to parse with every parser.
        Implementations should perform quick checks like file extension,
        content sampling, or structure detection.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            bool: True if this parser can handle the file, False otherwise
        """
        pass
    
    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        """
        Get the file extensions this parser supports.
        
        Returns:
            List[str]: List of file extensions (including the dot, e.g., ['.yaml', '.yml'])
        """
        pass
    
    def validate_rule_structure(self, rule_data: Dict[str, Any]) -> bool:
        """
        Validate that rule data has the minimum required structure.
        
        This method provides common validation logic that can be used by
        all parsers to ensure rule data meets basic requirements before
        attempting detailed parsing.
        
        Args:
            rule_data: Parsed rule data (from JSON/YAML)
            
        Returns:
            bool: True if structure is valid, False otherwise
        """
        if not isinstance(rule_data, dict):
            logger.warning("Rule data is not a dictionary")
            return False
        
        # Check for at least a name or title field
        name_fields = ['name', 'title', 'displayName']
        has_name = any(field in rule_data for field in name_fields)
        
        if not has_name:
            logger.warning("Rule data missing name/title field")
            return False
        
        return True
    
    def extract_basic_metadata(self, rule_data: Dict[str, Any], file_path: str) -> DetectionRule:
        """
        Extract basic metadata that's common across rule formats.
        
        This helper method handles the extraction of standard fields that
        appear in most rule formats, reducing code duplication in specific
        parsers and ensuring consistent handling of common fields.
        
        Args:
            rule_data: Parsed rule data dictionary
            file_path: Source file path for reference
            
        Returns:
            DetectionRule: Partially populated rule object with basic metadata
        """
        # Try various name fields in order of preference
        name = (rule_data.get('name') or 
                rule_data.get('title') or 
                rule_data.get('displayName') or 
                'Unknown Rule')
        
        # Try various description fields
        description = (rule_data.get('description') or 
                      rule_data.get('summary') or 
                      '')
        
        # Create the base rule object
        rule = DetectionRule(
            name=name,
            description=description,
            rule_type=self.parser_name.lower(),
            source_file=file_path
        )
        
        # Extract additional common metadata if present
        if 'id' in rule_data:
            rule.rule_id = str(rule_data['id'])
        
        if 'author' in rule_data:
            # Handle both string and list formats
            author_data = rule_data['author']
            if isinstance(author_data, list):
                rule.author = ', '.join(str(a) for a in author_data)
            else:
                rule.author = str(author_data)
        
        # Extract severity information
        severity_fields = ['severity', 'risk_score', 'priority']
        for field in severity_fields:
            if field in rule_data:
                rule.severity = str(rule_data[field]).lower()
                break
        
        # Extract enabled status
        if 'enabled' in rule_data:
            rule.enabled = bool(rule_data['enabled'])
        
        return rule
    
    def safe_file_read(self, file_path: str, max_size: int = None) -> Optional[str]:
        """
        Safely read file content with size limits and error handling.
        
        This method provides secure file reading with protection against
        oversized files and proper error handling. All parsers should use
        this method instead of opening files directly.
        
        Args:
            file_path: Path to file to read
            max_size: Maximum file size in bytes (uses config default if None)
            
        Returns:
            str: File content, or None if reading failed
        """
        from config import MAX_FILE_SIZE, ENCODING
        from validators.security_validator import SecurityValidator
        
        # Use provided max_size or fall back to config
        size_limit = max_size or MAX_FILE_SIZE
        
        # Validate file first
        is_valid, error_msg = SecurityValidator.validate_file_path(
            file_path, 
            self.get_supported_extensions()
        )
        
        if not is_valid:
            logger.error(f"File validation failed for {file_path}: {error_msg}")
            return None
        
        try:
            # Check file size before reading
            file_size = Path(file_path).stat().st_size
            if file_size > size_limit:
                logger.error(f"File too large: {file_size} bytes (limit: {size_limit})")
                return None
            
            # Read file content safely
            with open(file_path, 'r', encoding=ENCODING, errors='replace') as f:
                content = f.read()
            
            logger.debug(f"Successfully read {len(content)} characters from {file_path}")
            return content
            
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return None
        except PermissionError:
            logger.error(f"Permission denied reading: {file_path}")
            return None
        except UnicodeDecodeError as e:
            logger.error(f"Encoding error reading {file_path}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error reading {file_path}: {str(e)}")
            return None
    
    def update_statistics(self, success: bool, techniques_found: int = 0, tactics_found: int = 0):
        """
        Update parser statistics for monitoring and reporting (thread-safe).
        
        This method tracks parsing performance and success rates, which
        is valuable for monitoring system health and identifying issues
        with specific rule formats or files.
        
        Args:
            success: Whether the parsing operation was successful
            techniques_found: Number of techniques extracted from this rule
            tactics_found: Number of tactics extracted from this rule
        """
        with self._stats_lock:  # Thread-safe statistics updates
            self.parse_statistics['files_processed'] += 1
            
            if success:
                self.parse_statistics['successful_parses'] += 1
                self.parse_statistics['techniques_extracted'] += techniques_found
                self.parse_statistics['tactics_extracted'] += tactics_found
            else:
                self.parse_statistics['failed_parses'] += 1
            
            # Log statistics periodically for monitoring
            if self.parse_statistics['files_processed'] % 100 == 0:
                self.log_statistics()
    
    def log_statistics(self):
        """Log current parsing statistics for monitoring purposes."""
        stats = self.parse_statistics
        total = stats['files_processed']
        success_rate = (stats['successful_parses'] / total * 100) if total > 0 else 0
        
        logger.info(f"{self.parser_name} Parser Statistics:")
        logger.info(f"  Files processed: {total}")
        logger.info(f"  Success rate: {success_rate:.1f}% ({stats['successful_parses']}/{total})")
        logger.info(f"  Techniques extracted: {stats['techniques_extracted']}")
        logger.info(f"  Tactics extracted: {stats['tactics_extracted']}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current parser statistics as a dictionary (thread-safe).
        
        Returns:
            Dict[str, Any]: Current parsing statistics
        """
        with self._stats_lock:
            stats = self.parse_statistics.copy()
        stats['parser_name'] = self.parser_name
        stats['success_rate'] = (
            stats['successful_parses'] / stats['files_processed'] * 100 
            if stats['files_processed'] > 0 else 0
        )
        return stats
    
    def reset_statistics(self):
        """Reset all parsing statistics to zero."""
        self.parse_statistics = {
            'files_processed': 0,
            'successful_parses': 0,
            'failed_parses': 0,
            'techniques_extracted': 0,
            'tactics_extracted': 0
        }
        logger.debug(f"Reset statistics for {self.parser_name} parser")
    
    def __str__(self) -> str:
        """Provide a clean string representation for logging."""
        return f"{self.parser_name}Parser(files_processed={self.parse_statistics['files_processed']})"
    
    def __repr__(self) -> str:
        """Provide detailed representation for debugging."""
        return (f"{self.__class__.__name__}(parser_name='{self.parser_name}', "
                f"statistics={self.parse_statistics})")


# Import Path for the safe_file_read method
from pathlib import Path
