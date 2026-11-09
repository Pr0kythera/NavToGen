"""Tactic normalization (C2, C3) and the DetectionRule model (H7, M6)."""

import pytest

from models.detection_rule import DetectionRule
from utils.attack_names import normalize_tactic_name


@pytest.mark.parametrize("raw,expected", [
    ("Credential Access", "credential-access"),
    ("CredentialAccess", "credential-access"),       # Sentinel CamelCase (was rejected)
    ("credential_access", "credential-access"),
    ("credential-access", "credential-access"),
    ("CommandAndControl", "command-and-control"),
    ("Command and Control", "command-and-control"),
    ("LateralMovement", "lateral-movement"),
    ("  Stealth  ", "stealth"),
    ("Defense Impairment", "defense-impairment"),
    ("", ""),
    (None, ""),
])
def test_normalize_tactic_name(raw, expected):
    assert normalize_tactic_name(raw) == expected


@pytest.mark.parametrize("name", [
    "CredentialAccess", "PrivilegeEscalation", "DefenseEvasion", "LateralMovement", "InitialAccess",
    "Stealth", "Defense Impairment",    # v19 tactics (were rejected)
    "Defense Evasion",                  # legacy name still accepted
])
def test_valid_tactics_accepted(name):
    assert DetectionRule(name="r").add_tactic(name) is True


@pytest.mark.parametrize("name", ["Solorigate", "NOBELIUM", "DEV-0537", "PreAttack", "", None, 5])
def test_non_tactics_rejected(name):
    assert DetectionRule(name="r").add_tactic(name) is False


def test_technique_ids_validated_and_normalized():
    rule = DetectionRule(name="r")
    assert rule.add_technique("t1055.001")
    assert rule.techniques == {"T1055.001"}
    assert not rule.add_technique("T123")
    assert not rule.add_technique("1055")
    assert any("Invalid technique ID" in e for e in rule.parse_errors)


def test_technique_tactic_pairing_recorded():
    rule = DetectionRule(name="r")
    rule.add_technique("T1078", tactic="Initial Access")
    rule.add_technique("T1078", tactic="Persistence")
    rule.add_technique("T1059")  # no pairing information
    assert rule.technique_tactics == {"T1078": {"initial-access", "persistence"}}


def test_pairing_ignores_unknown_tactic():
    rule = DetectionRule(name="r")
    rule.add_technique("T1078", tactic="Not A Tactic")
    assert rule.technique_tactics == {}
