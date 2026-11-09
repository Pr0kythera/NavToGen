"""
ATT&CK Name Normalization
=========================

Helpers that convert the many spellings of ATT&CK tactic names found in detection
rules into the hyphenated short names used by the ATT&CK data (``x_mitre_shortname``).

Examples seen in real rules:
    "Credential Access"   (Elastic, human readable)
    "CredentialAccess"    (Microsoft Sentinel templates, CamelCase)
    "credential_access"   (snake case)
    "credential-access"   (ATT&CK short name)

All of these normalize to ``credential-access``.
"""

import re
from typing import Optional

# Insert a separator between a lowercase letter/digit and an uppercase letter:
# "CommandAndControl" -> "Command-And-Control"
_CAMEL_BOUNDARY = re.compile(r'(?<=[a-z0-9])(?=[A-Z])')
_SEPARATORS = re.compile(r'[\s_\-]+')

# Names used by rule authors that do not match an ATT&CK short name directly.
# Only unambiguous renames belong here. "PreAttack" (the retired PRE-ATT&CK matrix) is
# deliberately NOT mapped: it covered what is now two tactics, so a guess would be wrong.
TACTIC_ALIASES = {
    'command-control': 'command-and-control',
    'priv-esc': 'privilege-escalation',
}


def normalize_tactic_name(name: Optional[str]) -> str:
    """
    Normalize a tactic name to ATT&CK short-name form.

    Returns an empty string when the input is empty or not a string. The result is
    NOT checked against the list of valid tactics; callers do that.
    """
    if not name or not isinstance(name, str):
        return ""

    spaced = _CAMEL_BOUNDARY.sub('-', name.strip())
    normalized = _SEPARATORS.sub('-', spaced).strip('-').lower()
    return TACTIC_ALIASES.get(normalized, normalized)
