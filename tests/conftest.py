"""Shared fixtures for the NavToGen test suite."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = Path(__file__).resolve().parent / "fixtures"

CURRENT_TACTICS = [
    ('reconnaissance', 'Reconnaissance'), ('resource-development', 'Resource Development'),
    ('initial-access', 'Initial Access'), ('execution', 'Execution'), ('persistence', 'Persistence'),
    ('privilege-escalation', 'Privilege Escalation'), ('stealth', 'Stealth'),
    ('defense-impairment', 'Defense Impairment'), ('credential-access', 'Credential Access'),
    ('discovery', 'Discovery'), ('lateral-movement', 'Lateral Movement'), ('collection', 'Collection'),
    ('command-and-control', 'Command and Control'), ('exfiltration', 'Exfiltration'), ('impact', 'Impact'),
]


def _stix_id(kind: str, n: int) -> str:
    return f"{kind}--00000000-0000-4000-8000-{n:012d}"


def make_attack_bundle(version: str = "20.1", include_collection: bool = True) -> dict:
    """
    A small STIX bundle shaped like the real ATT&CK Enterprise data.

    Contains the structures that exposed bugs in the original validator:
    - 15 tactics including the v19 'stealth' and 'defense-impairment' (no 'defense-evasion')
    - revoked techniques with revoked-by relationships, including a 2-step chain
    - a deprecated (not revoked) technique
    - sub-techniques and multi-tactic techniques
    """
    objects = []
    n = [0]

    def add(obj):
        n[0] += 1
        obj.setdefault('id', _stix_id(obj['type'], n[0]))
        objects.append(obj)
        return obj['id']

    if include_collection:
        add({'type': 'x-mitre-collection', 'name': 'Enterprise ATT&CK', 'x_mitre_version': version})

    for shortname, name in CURRENT_TACTICS:
        add({'type': 'x-mitre-tactic', 'name': name, 'x_mitre_shortname': shortname})

    def technique(tid, name, tactics, platforms=("Windows",), **extra):
        return add({
            'type': 'attack-pattern', 'name': name,
            'external_references': [{'source_name': 'mitre-attack', 'external_id': tid}],
            'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': t} for t in tactics],
            'x_mitre_platforms': list(platforms),
            'x_mitre_is_subtechnique': '.' in tid,
            **extra,
        })

    ids = {}
    ids['T1059'] = technique('T1059', 'Command and Scripting Interpreter', ['execution'])
    ids['T1059.001'] = technique('T1059.001', 'PowerShell', ['execution'])
    ids['T1003'] = technique('T1003', 'OS Credential Dumping', ['credential-access'])
    ids['T1003.001'] = technique('T1003.001', 'LSASS Memory', ['credential-access'])
    ids['T1078'] = technique('T1078', 'Valid Accounts',
                             ['initial-access', 'persistence', 'privilege-escalation', 'stealth'],
                             platforms=("Windows", "Identity Provider"))
    ids['T1110'] = technique('T1110', 'Brute Force', ['credential-access'])
    ids['T1110.003'] = technique('T1110.003', 'Password Spraying', ['credential-access'])
    ids['T1685'] = technique('T1685', 'Disable or Modify Tools', ['defense-impairment'])
    ids['T1685.005'] = technique('T1685.005', 'Clear Windows Event Logs', ['defense-impairment'])

    # Revoked in favour of an active technique (single step)
    ids['T1562'] = technique('T1562', 'Impair Defenses', ['stealth'], revoked=True)
    ids['T1562.001'] = technique('T1562.001', 'Disable or Modify Tools', ['stealth'], revoked=True)
    ids['T1070.001'] = technique('T1070.001', 'Clear Windows Event Logs', ['stealth'], revoked=True)
    # Revoked chain: T1900 -> T1901 -> T1902 (active)
    ids['T1900'] = technique('T1900', 'Chain start', ['execution'], revoked=True)
    ids['T1901'] = technique('T1901', 'Chain middle', ['execution'], revoked=True)
    ids['T1902'] = technique('T1902', 'Chain end', ['execution'])
    # Revoked with no replacement
    ids['T1950'] = technique('T1950', 'Orphan', ['execution'], revoked=True)
    # Deprecated, not revoked
    ids['T1153'] = technique('T1153', 'Source', ['execution'], x_mitre_deprecated=True)

    def revoked_by(old, new):
        add({'type': 'relationship', 'relationship_type': 'revoked-by',
             'source_ref': ids[old], 'target_ref': ids[new]})

    revoked_by('T1562', 'T1685')
    revoked_by('T1562.001', 'T1685')
    revoked_by('T1070.001', 'T1685.005')
    revoked_by('T1900', 'T1901')
    revoked_by('T1901', 'T1902')

    # Padding so the "incomplete data" warning logic is not triggered by the tiny fixture
    return {'type': 'bundle', 'id': 'bundle--test', 'objects': objects}


@pytest.fixture
def attack_bundle():
    return make_attack_bundle()


@pytest.fixture
def attack_file(tmp_path, attack_bundle):
    path = tmp_path / "enterprise-attack.json"
    path.write_text(json.dumps(attack_bundle), encoding='utf-8')
    return path


@pytest.fixture
def validator(attack_file, tmp_path):
    from validators.mitre_validator import MitreAttackValidator
    v = MitreAttackValidator(cache_dir=str(tmp_path / "cache"))
    assert v.load_from_file(str(attack_file))
    return v


@pytest.fixture
def sentinel_fixtures():
    return FIXTURES / "sentinel"


ELASTIC_YAML = """\
name: Elastic YAML Rule
description: Example rule
type: query
rule_id: 11111111-1111-1111-1111-111111111111
risk_score: 47
severity: medium
version: 4
threat:
  - framework: MITRE ATT&CK
    tactic: {id: TA0006, name: Credential Access}
    technique:
      - id: T1003
        name: OS Credential Dumping
        subtechnique:
          - {id: T1003.001, name: LSASS Memory}
"""

ELASTIC_TOML = """\
[metadata]
creation_date = "2020/02/18"
updated_date = "2024/05/01"

[rule]
name = "Elastic TOML Rule"
description = "Example"
type = "eql"
rule_id = "22222222-2222-2222-2222-222222222222"
risk_score = 73
severity = "high"
version = 3

[[rule.threat]]
framework = "MITRE ATT&CK"

[[rule.threat.technique]]
id = "T1059"
name = "Command and Scripting Interpreter"

[[rule.threat.technique.subtechnique]]
id = "T1059.001"
name = "PowerShell"

[rule.threat.tactic]
id = "TA0002"
name = "Execution"
"""


def elastic_json_rule(name="Kibana Rule", rule_id="33333333-3333-3333-3333-333333333333", **extra):
    rule = {
        "name": name, "description": "d", "type": "query", "rule_id": rule_id, "risk_score": 21,
        "threat": [{"framework": "MITRE ATT&CK", "tactic": {"name": "Defense Evasion"},
                    "technique": [{"id": "T1562", "subtechnique": [{"id": "T1562.001"}]}]}],
    }
    rule.update(extra)
    return rule


@pytest.fixture
def elastic_dir(tmp_path):
    """A directory with Elastic rules in every supported container format."""
    d = tmp_path / "elastic"
    d.mkdir()
    (d / "rule.yaml").write_text(ELASTIC_YAML, encoding='utf-8')
    (d / "rule.toml").write_text(ELASTIC_TOML, encoding='utf-8')
    (d / "single.json").write_text(json.dumps(elastic_json_rule()), encoding='utf-8')
    export = [elastic_json_rule("Export One", "44444444-4444-4444-4444-444444444444"),
              elastic_json_rule("Export Two", "55555555-5555-5555-5555-555555555555", enabled=False),
              {"exported_rules_count": 2, "missing_rules": [], "missing_rules_count": 0}]
    (d / "export.ndjson").write_text("\n".join(json.dumps(r) for r in export) + "\n", encoding='utf-8')
    return d
