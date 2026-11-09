"""
Configuration Constants and Settings
===================================

This module centralizes all configuration values used throughout the application.
By keeping constants here, we ensure consistency and make the application easier to maintain.

Think of this as the "control panel" for the entire system - when you need to adjust
behavior across the application, you can do it from this single location.
"""

import re

# Version information - used for tracking and compatibility
VERSION = "3.0.0"
APPLICATION_NAME = "NavToGen - MITRE ATT&CK Coverage Analyzer"

# Security constraints - these limits prevent various attack vectors
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB per file limit (prevents memory exhaustion)
MAX_DIRECTORY_DEPTH = 10          # Maximum recursion depth (prevents directory traversal DoS)
MAX_WORKERS = 4                   # Thread pool size for concurrent processing

# MITRE ATT&CK data source.
# attack-stix-data (STIX 2.1) is used because it ships an x-mitre-collection object that
# carries the real ATT&CK version, plus an index.json listing every versioned release.
# (mitre/cti is STIX 2.0 and exposes no version, so it is only supported as a local file.)
MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
MITRE_ATTACK_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
MITRE_ENTERPRISE_COLLECTION_NAME = "Enterprise ATT&CK"
MITRE_REQUEST_TIMEOUT = 60        # Timeout for HTTP requests in seconds (file is ~50MB)
MAX_ATTACK_DATA_BYTES = 200 * 1024 * 1024  # Refuse to parse ATT&CK data larger than this
MITRE_CACHE_HOURS = 24            # Cached ATT&CK data is reused without a network round trip for this long
MITRE_CACHE_DIR_NAME = "navtogen"  # Subdirectory of the user cache dir (XDG_CACHE_HOME or ~/.cache)

# File processing settings
# File types we can process. Elastic detection-rules uses TOML; Kibana exports are NDJSON.
SUPPORTED_EXTENSIONS = {'.yaml', '.yml', '.json', '.toml', '.ndjson', '.jsonl'}
ENCODING = 'utf-8-sig'            # UTF-8, tolerating a leading byte-order mark

# Regular expressions for pattern matching
# The word boundaries (\b) ensure we match complete technique IDs, not partial strings
TECHNIQUE_ID_PATTERN = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

# Navigator layer format constants
NAVIGATOR_VERSION = "5.1.1"
LAYER_VERSION = "4.5"
DEFAULT_ATTACK_VERSION = "20"  # Used only when no ATT&CK data was loaded (major version, as a string)

# Valid MITRE ATT&CK tactics (normalized, hyphenated short names).
# ATT&CK v19 (April 2026) split Defense Evasion into Stealth and Defense Impairment.
# Defense Evasion is kept as a legacy name because rules written before v19 still use it.
# When ATT&CK data is loaded, the validator's tactic list (from x-mitre-tactic objects)
# takes precedence over this static fallback.
CURRENT_TACTICS = {
    'reconnaissance',
    'resource-development',
    'initial-access',
    'execution',
    'persistence',
    'privilege-escalation',
    'stealth',
    'defense-impairment',
    'credential-access',
    'discovery',
    'lateral-movement',
    'collection',
    'command-and-control',
    'exfiltration',
    'impact'
}
LEGACY_TACTICS = {'defense-evasion'}
VALID_TACTICS = CURRENT_TACTICS | LEGACY_TACTICS

# Security validation: system locations that are never read from or written to.
# These are matched as path PREFIXES of the fully resolved path (component-wise), so
# /home/me/etc/rules is fine while /etc/passwd is not. /root is intentionally not listed:
# the tool only reads rule files, and refusing the home directory of the account that
# runs it (common in containers) is a usability bug, not protection.
FORBIDDEN_PATH_PREFIXES = [
    '/etc',
    '/private/etc',      # macOS: /etc is a symlink to /private/etc
    '/proc',
    '/sys',
    '/dev',
    '/boot',
    '/var/log',
    '/private/var/log',
    'C:/Windows',
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
MITRE ATT&CK coverage analysis for Elastic Security
and Microsoft Sentinel detection rules.
{'='*60}
"""
    return banner

def validate_attack_version(version: str) -> bool:
    """
    Validate an ATT&CK version string: a major version ("20") or major.minor ("19.2").

    Args:
        version: Version string to validate

    Returns:
        bool: True if the format is valid and the major version is in a sane range
    """
    if not isinstance(version, str) or not re.fullmatch(r'\d{1,3}(\.\d{1,3})?', version.strip()):
        return False
    return 1 <= int(version.strip().split('.')[0]) <= 50  # Allow some future-proofing

def get_file_size_limit_mb() -> int:
    """
    Returns the file size limit in megabytes for easy reading.
    
    Returns:
        int: Maximum file size in MB
    """
    return MAX_FILE_SIZE // (1024 * 1024)
