"""
MITRE ATT&CK Framework Validator
==============================

This module validates technique IDs against the official MITRE ATT&CK framework,
ensuring that our coverage analysis only includes legitimate, current techniques.

Think of this as the "fact checker" for our MITRE ATT&CK analysis. While the security
validator protects against malicious inputs, this validator ensures the accuracy and
relevance of our technique identifications.

The validator can operate in two modes:
1. Online mode: Fetches the latest ATT&CK data for real-time validation
2. Offline mode: Uses format validation only when network access isn't available

This dual approach ensures the system remains functional even in restricted network
environments while providing enhanced validation when possible.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Set, Optional, Any, Tuple
import re

from config import (
    MITRE_ATTACK_URL,
    MITRE_REQUEST_TIMEOUT,
    HTTP_RETRY_ATTEMPTS,
    HTTP_RETRY_BACKOFF_FACTOR,
    HTTP_RETRY_STATUS_CODES
)

# Optional imports with graceful degradation
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)


class MitreAttackValidator:
    """
    Validates technique IDs against the official MITRE ATT&CK framework.
    
    This class provides comprehensive validation of MITRE ATT&CK technique IDs,
    ensuring that only legitimate techniques are included in analysis results.
    It can fetch live data from the MITRE repository or fall back to format-only
    validation when network access is unavailable.
    
    The validator follows a caching strategy to minimize network requests while
    ensuring data freshness. It also provides detailed metadata about techniques
    for enhanced reporting capabilities.
    
    Design Pattern: This class implements the Singleton pattern for the technique
    data cache, ensuring consistent validation results across the application while
    minimizing memory usage and network requests.
    
    Attributes:
        valid_techniques: Set of all valid technique IDs from the framework
        valid_tactics: Set of all valid tactic names from the framework  
        technique_metadata: Detailed information about each technique
        data_version: Version of ATT&CK data currently loaded
        last_update: Timestamp of the last successful data fetch
        cache_duration: How long cached data remains valid
    """
    
    def __init__(self, cache_duration_hours: int = 24):
        """
        Initialize the MITRE ATT&CK validator.
        
        Args:
            cache_duration_hours: How long to keep cached ATT&CK data before refreshing
        """
        self.valid_techniques: Set[str] = set()
        self.valid_tactics: Set[str] = set()
        self.technique_metadata: Dict[str, Dict[str, Any]] = {}
        self.data_version: Optional[str] = None
        self.last_update: Optional[datetime] = None
        self.cache_duration = timedelta(hours=cache_duration_hours)
        
        # Network session configuration for robust HTTP requests
        self._session: Optional[requests.Session] = None
        if HAS_REQUESTS:
            self._configure_http_session()
        
        logger.debug(f"MITRE ATT&CK validator initialized with {cache_duration_hours}h cache duration")
    
    def _configure_http_session(self) -> None:
        """
        Configure HTTP session with retry strategy and proper headers.
        
        This method sets up a robust HTTP client that can handle temporary
        network issues and server problems gracefully. The retry strategy
        helps ensure we can fetch ATT&CK data even when the MITRE servers
        are experiencing high load or temporary outages.
        """
        if not HAS_REQUESTS:
            logger.warning("Requests library not available - HTTP session not configured")
            return
        
        self._session = requests.Session()
        
        # Configure retry strategy for resilient network requests
        # This handles temporary network issues and server overload gracefully
        retry_strategy = Retry(
            total=HTTP_RETRY_ATTEMPTS,
            status_forcelist=HTTP_RETRY_STATUS_CODES,
            method_whitelist=["HEAD", "GET", "OPTIONS"],
            backoff_factor=HTTP_RETRY_BACKOFF_FACTOR,
            raise_on_status=False
        )
        
        # Apply retry strategy to HTTP and HTTPS
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        
        # Set appropriate headers for the MITRE API
        self._session.headers.update({
            'User-Agent': 'Enterprise-MITRE-Analyzer/3.0.0 (Security Analysis Tool)',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate'
        })
        
        logger.debug("HTTP session configured with retry strategy")
    
    def fetch_mitre_data(self, force_refresh: bool = False) -> bool:
        """
        Fetch the latest MITRE ATT&CK data from the official repository.
        
        This method retrieves the complete ATT&CK framework data and processes it
        into a format optimized for fast validation lookups. It implements intelligent
        caching to minimize network requests while ensuring data freshness.
        
        The fetching process follows these steps:
        1. Check if cached data is still valid (unless force_refresh is True)
        2. Download the latest ATT&CK JSON data from MITRE's repository
        3. Parse and validate the JSON structure
        4. Extract techniques, tactics, and metadata
        5. Build optimized lookup structures for validation
        
        Args:
            force_refresh: If True, bypass cache and fetch fresh data
            
        Returns:
            bool: True if data was successfully fetched and processed, False otherwise
            
        Raises:
            None: All exceptions are caught and logged, allowing graceful degradation
        """
        # Check if we need to refresh the cache
        if not force_refresh and self._is_cache_valid():
            logger.debug("MITRE ATT&CK data cache is still valid, skipping fetch")
            return True
        
        if not HAS_REQUESTS:
            logger.warning("Requests library not available. Cannot fetch MITRE ATT&CK data.")
            return False
        
        if not self._session:
            logger.error("HTTP session not configured. Cannot fetch MITRE ATT&CK data.")
            return False
        
        try:
            logger.info("Fetching latest MITRE ATT&CK data from official repository...")
            start_time = datetime.now()
            
            # Make the HTTP request with timeout
            response = self._session.get(MITRE_ATTACK_URL, timeout=MITRE_REQUEST_TIMEOUT)
            
            # Check if request was successful
            if not response.ok:
                logger.error(f"Failed to fetch MITRE ATT&CK data: HTTP {response.status_code}")
                return False
            
            # Parse JSON response
            try:
                attack_data = response.json()
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in MITRE ATT&CK data: {str(e)}")
                return False
            
            # Validate basic structure
            if not isinstance(attack_data, dict) or 'objects' not in attack_data:
                logger.error("Invalid MITRE ATT&CK data structure: missing 'objects' field")
                return False
            
            # Process the data
            success = self._process_attack_data(attack_data)
            if success:
                self.last_update = datetime.now()
                fetch_time = (datetime.now() - start_time).total_seconds()
                
                logger.info(f"Successfully loaded MITRE ATT&CK data in {fetch_time:.2f} seconds:")
                logger.info(f"  - {len(self.valid_techniques)} techniques")
                logger.info(f"  - {len(self.valid_tactics)} tactics")
                logger.info(f"  - Data version: {self.data_version or 'Unknown'}")
                
                return True
            else:
                logger.error("Failed to process MITRE ATT&CK data")
                return False
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout fetching MITRE ATT&CK data (>{MITRE_REQUEST_TIMEOUT}s)")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error fetching MITRE ATT&CK data: {str(e)}")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error fetching MITRE ATT&CK data: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error fetching MITRE ATT&CK data: {str(e)}")
            return False
    
    def _is_cache_valid(self) -> bool:
        """
        Check if the cached ATT&CK data is still valid based on age.
        
        Returns:
            bool: True if cache is valid and doesn't need refresh
        """
        if not self.last_update or not self.valid_techniques:
            return False
        
        age = datetime.now() - self.last_update
        is_valid = age < self.cache_duration
        
        if not is_valid:
            logger.debug(f"Cache expired: {age.total_seconds():.0f}s old (limit: {self.cache_duration.total_seconds():.0f}s)")
        
        return is_valid
    
    def _process_attack_data(self, attack_data: Dict[str, Any]) -> bool:
        """
        Process the raw ATT&CK JSON data into optimized validation structures.
        
        This method extracts the relevant information from the complex ATT&CK JSON
        structure and organizes it for efficient validation lookups. The processing
        handles various ATT&CK object types and relationships.
        
        Args:
            attack_data: Raw ATT&CK JSON data from MITRE repository
            
        Returns:
            bool: True if processing was successful, False otherwise
        """
        try:
            # Clear existing data
            self.valid_techniques.clear()
            self.valid_tactics.clear()
            self.technique_metadata.clear()
            
            # Extract version information if available
            self.data_version = attack_data.get('spec_version', 'Unknown')
            
            # Process all objects in the ATT&CK bundle
            objects_processed = 0
            techniques_found = 0
            tactics_found = 0
            
            for obj in attack_data.get('objects', []):
                objects_processed += 1
                
                # Process attack patterns (techniques)
                if obj.get('type') == 'attack-pattern':
                    if self._process_technique(obj):
                        techniques_found += 1
                
                # Process kill chain phases (tactics) from x-mitre-matrix objects
                elif obj.get('type') == 'x-mitre-matrix':
                    tactics_found += self._process_matrix_tactics(obj)
            
            # Validate that we found reasonable amounts of data
            if techniques_found < 100:  # ATT&CK has hundreds of techniques
                logger.warning(f"Only found {techniques_found} techniques - data may be incomplete")
            
            if tactics_found < 10:  # ATT&CK has ~14 tactics
                logger.warning(f"Only found {tactics_found} tactics - data may be incomplete")
            
            logger.debug(f"Processed {objects_processed} ATT&CK objects: {techniques_found} techniques, {tactics_found} tactics")
            return techniques_found > 0 and tactics_found > 0
            
        except Exception as e:
            logger.error(f"Error processing MITRE ATT&CK data: {str(e)}")
            return False
    
    def _process_technique(self, technique_obj: Dict[str, Any]) -> bool:
        """
        Process a single technique object from the ATT&CK data.
        
        Args:
            technique_obj: Individual technique object from ATT&CK JSON
            
        Returns:
            bool: True if technique was successfully processed
        """
        try:
            # Extract technique ID from external references
            technique_id = None
            for ref in technique_obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id')
                    break
            
            if not technique_id or not technique_id.startswith('T'):
                return False
            
            # Add to valid techniques set
            self.valid_techniques.add(technique_id)
            
            # Extract metadata for this technique
            metadata = {
                'name': technique_obj.get('name', ''),
                'description': technique_obj.get('description', ''),
                'platforms': technique_obj.get('x_mitre_platforms', []),
                'data_sources': technique_obj.get('x_mitre_data_sources', []),
                'detection': technique_obj.get('x_mitre_detection', ''),
                'tactics': [],
                'is_sub_technique': '.' in technique_id,
                'deprecated': technique_obj.get('x_mitre_deprecated', False),
                'version': technique_obj.get('x_mitre_version', '1.0')
            }
            
            # Extract associated tactics from kill chain phases
            for phase in technique_obj.get('kill_chain_phases', []):
                tactic_name = phase.get('phase_name')
                if tactic_name:
                    # Normalize tactic name
                    normalized_tactic = tactic_name.replace('_', '-')
                    metadata['tactics'].append(normalized_tactic)
                    self.valid_tactics.add(normalized_tactic)
            
            # Store metadata
            self.technique_metadata[technique_id] = metadata
            
            return True
            
        except Exception as e:
            logger.warning(f"Error processing technique: {str(e)}")
            return False
    
    def _process_matrix_tactics(self, matrix_obj: Dict[str, Any]) -> int:
        """
        Process tactics from a matrix object.
        
        Args:
            matrix_obj: Matrix object containing tactic definitions
            
        Returns:
            int: Number of tactics processed
        """
        tactics_found = 0
        
        try:
            for tactic_list in matrix_obj.get('tactic_refs', []):
                if isinstance(tactic_list, list):
                    for tactic_ref in tactic_list:
                        # Extract tactic name from reference
                        if isinstance(tactic_ref, str):
                            # Tactic refs are usually in format like 'x-mitre-tactic--...'
                            # We'll extract the actual tactic name from kill chain phases elsewhere
                            pass
        except Exception as e:
            logger.warning(f"Error processing matrix tactics: {str(e)}")
        
        return tactics_found
    
    def is_valid_technique(self, technique_id: str) -> bool:
        """
        Check if a technique ID exists in the MITRE ATT&CK framework.
        
        This method provides the core validation functionality, checking whether
        a given technique ID represents a legitimate ATT&CK technique. It falls
        back to format validation if ATT&CK data hasn't been loaded.
        
        Args:
            technique_id: Technique ID to validate (e.g., 'T1055', 'T1055.001')
            
        Returns:
            bool: True if technique is valid, False otherwise
        """
        if not technique_id or not isinstance(technique_id, str):
            return False
        
        normalized_id = technique_id.upper().strip()
        
        # If we have loaded ATT&CK data, use it for validation
        if self.valid_techniques:
            is_valid = normalized_id in self.valid_techniques
            
            # Log validation results for debugging
            if is_valid:
                logger.debug(f"Technique validated against ATT&CK data: {normalized_id}")
            else:
                logger.debug(f"Technique not found in ATT&CK data: {normalized_id}")
            
            return is_valid
        
        else:
            # Fall back to format validation only
            logger.debug(f"No ATT&CK data loaded, using format validation for: {normalized_id}")
            return self._validate_technique_format(normalized_id)
    
    def is_valid_tactic(self, tactic: str) -> bool:
        """
        Check if a tactic name is valid in the MITRE ATT&CK framework.
        
        Args:
            tactic: Tactic name to validate (normalized format expected)
            
        Returns:
            bool: True if tactic is valid, False otherwise
        """
        if not tactic or not isinstance(tactic, str):
            return False
        
        normalized_tactic = tactic.lower().strip().replace(' ', '-').replace('_', '-')
        
        if self.valid_tactics:
            return normalized_tactic in self.valid_tactics
        else:
            # Fall back to basic format checking
            return len(normalized_tactic) > 0 and normalized_tactic.replace('-', '').isalpha()
    
    def get_technique_info(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed metadata for a specific technique.
        
        This method returns comprehensive information about a technique,
        including its name, description, associated tactics, platforms,
        and other metadata from the ATT&CK framework.
        
        Args:
            technique_id: Technique ID to look up
            
        Returns:
            Dict[str, Any]: Technique metadata, or None if not found
        """
        if not technique_id:
            return None
        
        normalized_id = technique_id.upper().strip()
        return self.technique_metadata.get(normalized_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> Set[str]:
        """
        Get all techniques associated with a specific tactic.
        
        Args:
            tactic: Tactic name (normalized format)
            
        Returns:
            Set[str]: Set of technique IDs associated with this tactic
        """
        if not self.technique_metadata:
            return set()
        
        normalized_tactic = tactic.lower().strip().replace(' ', '-').replace('_', '-')
        techniques = set()
        
        for technique_id, metadata in self.technique_metadata.items():
            if normalized_tactic in metadata.get('tactics', []):
                techniques.add(technique_id)
        
        return techniques
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current validation state.
        
        This method provides useful information about the validator's current
        state, including data freshness, coverage, and validation statistics.
        
        Returns:
            Dict[str, Any]: Summary information about the validator state
        """
        summary = {
            'has_attack_data': len(self.valid_techniques) > 0,
            'technique_count': len(self.valid_techniques),
            'tactic_count': len(self.valid_tactics),
            'data_version': self.data_version,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'cache_valid': self._is_cache_valid(),
            'validation_mode': 'online' if self.valid_techniques else 'format_only'
        }
        
        # Add cache age information
        if self.last_update:
            cache_age = datetime.now() - self.last_update
            summary['cache_age_hours'] = cache_age.total_seconds() / 3600
        
        # Add some statistics about the data
        if self.technique_metadata:
            deprecated_count = sum(1 for meta in self.technique_metadata.values() 
                                 if meta.get('deprecated', False))
            sub_technique_count = sum(1 for meta in self.technique_metadata.values()
                                    if meta.get('is_sub_technique', False))
            
            summary['deprecated_techniques'] = deprecated_count
            summary['sub_techniques'] = sub_technique_count
            summary['main_techniques'] = len(self.valid_techniques) - sub_technique_count
        
        return summary
    
    def validate_technique_list(self, technique_ids: Set[str]) -> Tuple[Set[str], Set[str]]:
        """
        Validate a list of technique IDs and separate valid from invalid.
        
        This method is useful for batch validation of techniques extracted
        from rules, allowing you to identify and handle invalid techniques
        appropriately.
        
        Args:
            technique_ids: Set of technique IDs to validate
            
        Returns:
            Tuple[Set[str], Set[str]]: (valid_techniques, invalid_techniques)
        """
        valid_techniques = set()
        invalid_techniques = set()
        
        for technique_id in technique_ids:
            if self.is_valid_technique(technique_id):
                valid_techniques.add(technique_id.upper().strip())
            else:
                invalid_techniques.add(technique_id)
        
        return valid_techniques, invalid_techniques
    
    @staticmethod
    def _validate_technique_format(technique_id: str) -> bool:
        """
        Validate technique ID format without requiring ATT&CK data.
        
        This static method provides format validation as a fallback when
        the full ATT&CK dataset isn't available.
        
        Args:
            technique_id: Technique ID to validate
            
        Returns:
            bool: True if format is correct, False otherwise
        """
        if not technique_id or not isinstance(technique_id, str):
            return False
        
        # Use the same pattern as in the DetectionRule class
        pattern = r'^T\d{4}(\.\d{3})?$'
        return bool(re.match(pattern, technique_id.upper().strip()))
    
    def __str__(self) -> str:
        """Provide a clean string representation for logging."""
        if self.valid_techniques:
            return f"MitreAttackValidator(techniques={len(self.valid_techniques)}, tactics={len(self.valid_tactics)})"
        else:
            return "MitreAttackValidator(no_data_loaded)"
