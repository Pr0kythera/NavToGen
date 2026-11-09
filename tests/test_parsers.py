"""Parsers: C3, C5, M5, M6, M8, M9 and format routing."""

import json

import pytest

from parsers.base_parser import decode_structured, parse_timestamp, read_rule_file, to_bool
from parsers.elastic_parser import ElasticRuleParser, risk_score_to_severity
from parsers.sentinel_parser import SentinelRuleParser
from tests.conftest import ELASTIC_TOML, ELASTIC_YAML, elastic_json_rule


# --- Sentinel ---------------------------------------------------------------

def test_sentinel_fixtures_parse_with_tactics(sentinel_fixtures):
    """CamelCase tactics used to be rejected: only 2 tactics came out of these 7 rules."""
    parser = SentinelRuleParser()
    rules = []
    for path in sorted(sentinel_fixtures.glob("*.yaml")):
        rules.extend(parser.parse_all(str(path)))
    assert len(rules) == 7
    tactics = {t for r in rules for t in r.tactics}
    assert {"credential-access", "privilege-escalation", "discovery", "persistence", "defense-evasion"} <= tactics
    assert all(r.rule_type == "sentinel-scheduled" for r in rules)


def test_sentinel_tags_are_not_attack_data(tmp_path):
    f = tmp_path / "r.yaml"
    f.write_text(
        "id: a\nname: Rule\nkind: Scheduled\nseverity: High\nqueryFrequency: 1h\n"
        "tactics: [CredentialAccess]\nrelevantTechniques: [T1110]\n"
        "tags: [Solorigate, NOBELIUM, DEV-0537, T1999]\n")
    (rule,) = SentinelRuleParser().parse_all(str(f))
    assert rule.tactics == {"credential-access"}
    assert rule.techniques == {"T1110"}            # T1999 in tags must not be picked up


def test_sentinel_arm_template_multiple_rules_and_kind(tmp_path):
    arm = {"$schema": "x", "resources": [
        {"type": "Microsoft.OperationalInsights/workspaces/providers/alertRules", "kind": "Scheduled",
         "name": "6a2e2ff4-5568-475e-bef2-b95f12b9367b",
         "properties": {"displayName": "First", "severity": "Informational", "enabled": False,
                        "tactics": ["InitialAccess"], "techniques": ["T1078"], "query": "q"}},
        {"type": "Microsoft.SecurityInsights/alertRules", "kind": "NRT",
         "name": "[concat('x', parameters('y'))]",
         "properties": {"displayName": "Second", "severity": "High", "tactics": ["Execution"],
                        "techniques": ["T1059"], "subTechniques": ["T1059.001"]}},
        {"type": "Microsoft.Resources/other", "properties": {"displayName": "Ignored"}},
    ]}
    f = tmp_path / "arm.json"
    f.write_text(json.dumps(arm))
    rules = SentinelRuleParser().parse_all(str(f))
    assert [r.name for r in rules] == ["First", "Second"]               # old code returned only the first
    first, second = rules
    assert first.rule_type == "sentinel-scheduled" and second.rule_type == "sentinel-nrt"
    assert first.rule_id == "6a2e2ff4-5568-475e-bef2-b95f12b9367b"
    assert second.rule_id == ""                                          # ARM expression is not an id
    assert first.enabled is False and first.severity == "low"            # Informational -> low
    assert second.techniques == {"T1059", "T1059.001"}


def test_sentinel_api_style_json(tmp_path):
    f = tmp_path / "api.json"
    f.write_text(json.dumps({"id": "abc", "kind": "Scheduled",
                             "properties": {"displayName": "API Rule", "tactics": ["Impact"],
                                            "techniques": ["T1485"], "queryFrequency": "PT1H"}}))
    (rule,) = SentinelRuleParser().parse_all(str(f))
    assert rule.name == "API Rule" and rule.techniques == {"T1485"} and rule.tactics == {"impact"}


def test_sentinel_text_fallback_is_opt_in(tmp_path):
    f = tmp_path / "r.yaml"
    f.write_text("id: a\nname: R\nkind: Scheduled\nqueryFrequency: 1h\n"
                 "description: This relates to T1059 and T1566.001\nquery: x\n")
    (default,) = SentinelRuleParser().parse_all(str(f))
    assert default.techniques == set()
    (opted,) = SentinelRuleParser(fallback_text_extraction=True).parse_all(str(f))
    assert opted.techniques == {"T1059", "T1566.001"}
    assert any("inferred from rule text" in n for n in opted.notes)


def test_sentinel_version_kept_verbatim(sentinel_fixtures):
    (rule,) = SentinelRuleParser().parse_all(str(sentinel_fixtures / "AdFind_Usage.yaml"))
    assert rule.source_version == "1.0.3"


# --- Elastic ----------------------------------------------------------------

def test_elastic_yaml(tmp_path):
    f = tmp_path / "r.yaml"
    f.write_text(ELASTIC_YAML)
    (rule,) = ElasticRuleParser().parse_all(str(f))
    assert rule.rule_type == "elastic-query" and rule.rule_id.startswith("1111")
    assert rule.techniques == {"T1003", "T1003.001"}
    assert rule.technique_tactics["T1003.001"] == {"credential-access"}    # pairing kept (H7)
    assert rule.risk_score == 47 and rule.severity == "medium"
    assert rule.source_version == "4"
    # Descriptions are no longer mutated with bracketed metadata
    assert rule.description == "Example rule"


def test_elastic_toml(tmp_path):
    f = tmp_path / "r.toml"
    f.write_text(ELASTIC_TOML)
    (rule,) = ElasticRuleParser().parse_all(str(f))
    assert rule.name == "Elastic TOML Rule" and rule.rule_type == "elastic-eql"
    assert rule.techniques == {"T1059", "T1059.001"} and rule.tactics == {"execution"}
    assert rule.created_date.year == 2020 and rule.modified_date.year == 2024   # YYYY/MM/DD dates


def test_elastic_ndjson_many_rules_and_summary_line_skipped(elastic_dir):
    rules = ElasticRuleParser().parse_all(str(elastic_dir / "export.ndjson"))
    assert [r.name for r in rules] == ["Export One", "Export Two"]
    assert rules[1].enabled is False


def test_elastic_json(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(json.dumps(elastic_json_rule()))
    (rule,) = ElasticRuleParser().parse_all(str(f))
    assert rule.techniques == {"T1562", "T1562.001"} and rule.tactics == {"defense-evasion"}


def test_elastic_description_not_required(tmp_path):
    f = tmp_path / "r.yaml"
    f.write_text("name: No Description\nrule_id: x\nrisk_score: 10\nthreat: []\n")
    assert len(ElasticRuleParser().parse_all(str(f))) == 1


@pytest.mark.parametrize("score,expected", [
    (0, "low"), (21, "low"), (22, "medium"), (47, "medium"),
    (48, "high"), (73, "high"), (74, "critical"), (100, "critical"),
])
def test_risk_score_bands_match_elastic_docs(score, expected):
    assert risk_score_to_severity(score) == expected


def test_explicit_severity_wins_over_risk_score(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(json.dumps(elastic_json_rule(risk_score=99, severity="low")))
    (rule,) = ElasticRuleParser().parse_all(str(f))
    assert rule.severity == "low" and rule.risk_score == 99


def test_risk_score_stays_numeric_and_derives_severity(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(json.dumps(elastic_json_rule(risk_score=47)))
    (rule,) = ElasticRuleParser().parse_all(str(f))
    assert rule.risk_score == 47 and rule.severity == "medium"


# --- routing (C5) ------------------------------------------------------------

def test_scores_route_by_content_not_extension(tmp_path):
    """An Elastic-format .json file used to be handed to the Sentinel parser (0 techniques)."""
    f = tmp_path / "r.json"
    f.write_text(json.dumps(elastic_json_rule()))
    records, _ = decode_structured(f.read_text(), str(f))
    assert ElasticRuleParser().score(records, str(f)) > SentinelRuleParser().score(records, str(f))


def test_generic_json_is_claimed_by_nobody(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(json.dumps({"name": "x", "version": "1.0.0", "description": "d"}))
    records, _ = decode_structured(f.read_text(), str(f))
    assert ElasticRuleParser().score(records, str(f)) == 0
    assert SentinelRuleParser().score(records, str(f)) == 0


def test_can_parse_and_parse_compat_api(sentinel_fixtures, tmp_path):
    path = str(sentinel_fixtures / "AdFind_Usage.yaml")
    assert SentinelRuleParser().can_parse(path)
    assert not ElasticRuleParser().can_parse(path)
    assert SentinelRuleParser().parse(path).name.startswith("Probable AdFind")


# --- reading and decoding (M8) --------------------------------------------------

def test_utf8_bom_accepted(tmp_path):
    f = tmp_path / "r.yaml"
    f.write_bytes(b"\xef\xbb\xbf" + ELASTIC_YAML.encode())
    assert read_rule_file(str(f), {".yaml"}).startswith("name:")
    assert len(ElasticRuleParser().parse_all(str(f))) == 1


def test_invalid_utf8_rejected_not_altered(tmp_path):
    f = tmp_path / "r.yaml"
    f.write_bytes(b"name: caf\xe9\n")
    assert read_rule_file(str(f), {".yaml"}) is None


def test_oversized_file_rejected(tmp_path):
    f = tmp_path / "r.yaml"
    f.write_text("name: x\n")
    assert read_rule_file(str(f), {".yaml"}, max_size=3) is None


def test_decode_errors_are_reported_not_raised():
    records, errors = decode_structured("{broken", "x.json")
    assert records == [] and errors
    records, errors = decode_structured('{"a": 1}\nnot json\n{"b": 2}\n', "x.ndjson")
    assert len(records) == 2 and len(errors) == 1
    records, errors = decode_structured("a = ", "x.toml")
    assert records == [] and errors
    records, errors = decode_structured("- 1\n- {a: 1}\n", "x.yaml")
    assert records == [{"a": 1}]                                   # non-dict items dropped


def test_helpers():
    assert to_bool("false") is False and to_bool("Yes") is True and to_bool(None, default=False) is False
    assert to_bool("maybe", default=True) is True
    assert parse_timestamp("2020/02/18").year == 2020
    assert parse_timestamp("2024-05-01T10:00:00Z").year == 2024
    assert parse_timestamp("garbage") is None


def test_parser_statistics_thread_safe_copy():
    p = ElasticRuleParser()
    p.update_statistics(True, 2, 1)
    p.update_statistics(False)
    stats = p.get_statistics()
    stats["files_processed"] = 999
    assert p.get_statistics()["files_processed"] == 2
    assert p.get_statistics()["success_rate"] == 50.0
    p.reset_statistics()
    assert p.get_statistics()["files_processed"] == 0


# --- Sentinel ATT&CK field shapes ---------------------------------------------------

def parse_sentinel_dict(tmp_path, extra: dict):
    base = {"id": "x", "name": "Rule", "kind": "Scheduled", "queryFrequency": "1h"}
    f = tmp_path / "r.json"
    f.write_text(json.dumps({**base, **extra}))
    (rule,) = SentinelRuleParser().parse_all(str(f))
    return rule


def test_sentinel_field_as_comma_separated_string(tmp_path):
    rule = parse_sentinel_dict(tmp_path, {"techniques": "T1059, T1566.001 and T1078"})
    assert rule.techniques == {"T1059", "T1566.001", "T1078"}


def test_sentinel_list_of_dicts(tmp_path):
    rule = parse_sentinel_dict(tmp_path, {
        "techniques": [{"id": "T1003"}, {"techniqueId": "T1110"}, {"technique": ["T1059", "not-a-technique"]}],
        "tactics": [{"name": "CredentialAccess"}, {"tactic": "Impact"}]})
    assert rule.techniques == {"T1003", "T1110", "T1059"}
    assert rule.tactics == {"credential-access", "impact"}


def test_sentinel_single_dict_field(tmp_path):
    rule = parse_sentinel_dict(tmp_path, {"mitreTechniques": {"id": "T1486"}, "mitreTactics": {"name": "Impact"}})
    assert rule.techniques == {"T1486"} and rule.tactics == {"impact"}


def test_sentinel_technique_ids_must_match_fully(tmp_path):
    rule = parse_sentinel_dict(tmp_path, {"relevantTechniques": ["T1059 and more", "T1110"]})
    assert rule.techniques == {"T1110"}                          # "T1059 and more" is a tactic-ish string, rejected


def test_sentinel_bad_timestamp_recorded(tmp_path):
    rule = parse_sentinel_dict(tmp_path, {"createdTimeUtc": "not a date", "lastModifiedUtc": "2024-05-01T00:00:00Z"})
    assert rule.created_date is None and rule.modified_date.year == 2024
    assert any("Invalid createdTimeUtc" in e for e in rule.parse_errors)


def test_sentinel_unknown_kind_still_parsed(tmp_path):
    rule = parse_sentinel_dict(tmp_path, {"kind": "SomethingNew", "relevantTechniques": ["T1110"]})
    assert rule.rule_type == "sentinel-somethingnew" and rule.techniques == {"T1110"}


def test_elastic_bad_timestamp_and_scalar_lists(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(json.dumps(elastic_json_rule(created_at="never", false_positives="admins", references=["https://a"])))
    (rule,) = ElasticRuleParser().parse_all(str(f))
    assert rule.created_date is None and any("Invalid created_at" in e for e in rule.parse_errors)
    assert rule.false_positives == ["admins"] and rule.references == ["https://a"]


def test_elastic_threat_not_a_list_is_tolerated(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(json.dumps(elastic_json_rule(threat={"tactic": "x"})))
    (rule,) = ElasticRuleParser().parse_all(str(f))
    assert rule.techniques == set()
