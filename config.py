"""
Configuration Constants and Settings
===================================

This module centralizes all configuration values used throughout the application.
By keeping constants here, we ensure consistency and make the application easier to maintain.

Think of this as the "control panel" for the entire system - when you need to adjust
behavior across the application, you can do it from this single location.
"""

import re
from typing import Set

# Version information - used for tracking and compatibility
VERSION = "3.0.0"
APPLICATION_NAME = "Enterprise MITRE ATT&CK Coverage Analyzer"

# Security constraints - these limits prevent various attack vectors
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB per file limit (prevents memory exhaustion)
MAX_DIRECTORY_DEPTH = 10          # Maximum recursion depth (prevents directory traversal DoS)
MAX_WORKERS = 4                   # Thread pool size for concurrent processing

# MITRE ATT&CK data source - official repository URL
MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_REQUEST_TIMEOUT = 30        # Timeout for HTTP requests in seconds

# File processing settings
SUPPORTED_EXTENSIONS = {'.yaml', '.yml', '.json'}  # File types we can process
ENCODING = 'utf-8'                # Standard encoding for all file operations

# Regular expressions for pattern matching
# The word boundaries (\b) ensure we match complete technique IDs, not partial strings
TECHNIQUE_ID_PATTERN = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

# Navigator layer format constants
NAVIGATOR_VERSION = "4.9.1"
LAYER_VERSION = "4.5"
DEFAULT_ATTACK_VERSION = "15"

# Valid MITRE ATT&CK tactics (normalized names)
# These represent the standard phases of a cyber attack lifecycle
VALID_TACTICS = {
    'reconnaissance',      # Gathering information about the target
    'resource-development', # Establishing resources for operations
    'initial-access',      # Getting into the network
    'execution',          # Running malicious code
    'persistence',        # Maintaining foothold
    'privilege-escalation', # Gaining higher-level permissions
    'defense-evasion',    # Avoiding detection
    'credential-access',  # Obtaining account credentials
    'discovery',          # Learning about the environment
    'lateral-movement',   # Moving through the network
    'collection',         # Gathering data of interest
    'command-and-control', # Communicating with compromised systems
    'exfiltration',       # Stealing data
    'impact'              # Manipulating, interrupting, or destroying systems
}

# Security validation patterns
# These help identify potentially dangerous file paths that should be blocked
FORBIDDEN_PATH_PATTERNS = [
    '/etc/',                    # Unix system configuration
    '/proc/',                   # Unix process information
    '/sys/',                    # Unix system information
    '\\Windows\\System32\\',    # Windows system directory
    '\\Windows\\SysWOW64\\',   # Windows 32-bit system directory
    '/root/',                   # Unix root user home
    '/var/log/',               # Unix system logs
]

# Logging configuration
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Navigator layer color schemes
# These color gradients help visualize coverage density in the Navigator interface
COVERAGE_COLORS = {
    'high_coverage': '#8ec843',    # Green for techniques covered by many rules
    'medium_coverage': '#ffe766',  # Yellow for moderate coverage
    'low_coverage': '#ff6666',     # Red for minimal coverage
    'elastic_only': '#0000ff',     # Blue for Elastic-specific coverage
    'sentinel_only': '#ff6600',    # Orange for Sentinel-specific coverage
    'both_platforms': '#00ff00'    # Bright green for shared coverage
}

# Platform detection indicators
# These strings help identify which SIEM platform a rule belongs to
ELASTIC_INDICATORS = [
    'rule_id:',
    'risk_score:',
    'threat:',
    'type: eql',
    'type: query',
    'from: now',
    'index:'
]

SENTINEL_INDICATORS = [
    'Microsoft.SecurityInsights',
    'displayName:',
    'alertRuleTemplateName:',
    'kind: Scheduled',
    'kind: NRT',
    'queryFrequency:',
    'triggerOperator:'
]

# HTTP request configuration for MITRE ATT&CK data fetching
HTTP_RETRY_ATTEMPTS = 3
HTTP_RETRY_BACKOFF_FACTOR = 1
HTTP_RETRY_STATUS_CODES = [429, 500, 502, 503, 504]

def get_banner() -> str:
    """
    Returns the application banner for CLI display.
    
    This creates a professional-looking header that identifies the tool
    and its version when users run it from the command line.
    """
    banner = f"""
{'='*60}
{APPLICATION_NAME} v{VERSION}
{'='*60}
Enterprise-grade MITRE ATT&CK coverage analysis for
Elastic SIEM and Microsoft Sentinel detection rules.
{'='*60}
"""
    return banner

def validate_attack_version(version: str) -> bool:
    """
    Validates that an ATT&CK version string is reasonable.
    
    Args:
        version: Version string to validate (e.g., "15", "14")
        
    Returns:
        bool: True if version appears valid, False otherwise
    """
    try:
        # ATT&CK versions are typically integers between 1 and 20 (reasonable range)
        version_num = int(version)
        return 1 <= version_num <= 50  # Allow some future-proofing
    except ValueError:
        return False

def get_file_size_limit_mb() -> int:
    """
    Returns the file size limit in megabytes for easy reading.
    
    Returns:
        int: Maximum file size in MB
    """
    return MAX_FILE_SIZE // (1024 * 1024)
