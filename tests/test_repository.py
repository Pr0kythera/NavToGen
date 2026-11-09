"""RuleRepository: discovery (M4), routing (C5), revoked policy (C4), stats, report (C6)."""

import json
import os

import pytest

from core.RuleRepository import RuleRepository
from tests.conftest import elastic_json_rule


def sentinel_yaml(i, techniques="T1110"):
    return (f"id: 00000000-0000-0000-0000-{i:012d}\nname: Rule {i}\nkind: Scheduled\nseverity: Low\n"
            f"queryFrequency: 1h\ntactics: [CredentialAccess]\nrelevantTechniques: [{techniques}]\nquery: q\n")


# --- discovery -----------------------------------------------------------

def test_discovery_finds_all_supported_formats(elastic_dir):
    repo = RuleRepository()
    names = sorted(os.path.basename(f) for f in repo.discover_rules(str(elastic_dir)))
    assert names == ["export.ndjson", "rule.toml", "rule.yaml", "single.json"]   # toml/ndjson were never found


def test_discovery_depth_semantics(tmp_path):
    for depth in range(4):
        d = tmp_path.joinpath(*[f"d{i}" for i in range(depth)])
        d.mkdir(parents=True, exist_ok=True)
        (d / f"r{depth}.yaml").write_text(sentinel_yaml(depth))
    repo = RuleRepository()
    found = lambda depth: sorted(os.path.basename(p) for p in repo.discover_rules(str(tmp_path), max_depth=depth))
    assert found(0) == ["r0.yaml"]
    assert found(1) == ["r0.yaml", "r1.yaml"]
    assert found(3) == ["r0.yaml", "r1.yaml", "r2.yaml", "r3.yaml"]


def test_discovery_trailing_slash_same_result(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "r.yaml").write_text(sentinel_yaml(1))
    repo = RuleRepository()
    assert len(repo.discover_rules(str(tmp_path) + os.sep, max_depth=1)) == 1   # old code was off by one


def test_discovery_skips_hidden_dirs(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "r.yaml").write_text(sentinel_yaml(1))
    (tmp_path / "r.yaml").write_text(sentinel_yaml(2))
    assert len(RuleRepository().discover_rules(str(tmp_path))) == 1


def test_discovery_rejects_symlink_escaping_root(tmp_path):
    root = tmp_path / "rules"
    root.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text(sentinel_yaml(9))
    (root / "link.yaml").symlink_to(outside)
    (root / "ok.yaml").write_text(sentinel_yaml(1))
    repo = RuleRepository()
    files = repo.discover_rules(str(root))
    assert [os.path.basename(f) for f in files] == ["ok.yaml"]
    assert repo.get_statistics()['discovery']['files_skipped'] == 1


def test_discovery_invalid_directory_raises(tmp_path):
    with pytest.raises(ValueError):
        RuleRepository().discover_rules(str(tmp_path / "nope"))


# --- parsing and routing --------------------------------------------------------

def test_parse_mixed_directory(elastic_dir, sentinel_fixtures):
    repo = RuleRepository()
    rules = repo.parse_rules(repo.discover_rules(str(elastic_dir)) + repo.discover_rules(str(sentinel_fixtures)),
                             use_concurrent=False)
    stats = repo.get_statistics()
    assert stats['by_platform']['elastic_rules'] == 5      # yaml + toml + json + 2 ndjson
    assert stats['by_platform']['sentinel_rules'] == 7
    assert stats['parsing']['rules_parsed'] == 12
    assert stats['parsing']['successful_parses'] == 11     # files that yielded rules
    assert len(rules) == 12


def test_elastic_json_is_not_misrouted_to_sentinel(tmp_path):
    (tmp_path / "r.json").write_text(json.dumps(elastic_json_rule()))
    repo = RuleRepository()
    (rule,) = repo.parse_rules(repo.discover_rules(str(tmp_path)), use_concurrent=False)
    assert rule.rule_type.startswith("elastic") and rule.techniques


def test_unrecognized_files_are_reported_not_silently_parsed(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x", "version": "1"}))
    (tmp_path / "r.yaml").write_text(sentinel_yaml(1))
    repo = RuleRepository()
    rules = repo.parse_rules(repo.discover_rules(str(tmp_path)), use_concurrent=False)
    stats = repo.get_statistics()
    assert len(rules) == 1
    assert stats['by_platform']['unknown_format'] == 1
    assert [os.path.basename(p) for p in stats['errors']['unrecognized_files']] == ["package.json"]


def test_corrupt_files_do_not_stop_the_run(tmp_path):
    (tmp_path / "bad.yaml").write_text("name: [unclosed")
    (tmp_path / "ok.yaml").write_text(sentinel_yaml(1))
    repo = RuleRepository()
    rules = repo.parse_rules(repo.discover_rules(str(tmp_path)), use_concurrent=False)
    assert len(rules) == 1
    assert repo.get_statistics()['errors']['parse_errors']


def test_concurrent_equals_sequential_and_is_ordered(tmp_path):
    for i in range(25):
        (tmp_path / f"r{i:02d}.yaml").write_text(sentinel_yaml(i))
    files = sorted(RuleRepository().discover_rules(str(tmp_path)))

    seq_repo, par_repo = RuleRepository(), RuleRepository()
    seq = seq_repo.parse_rules(files, use_concurrent=False)
    par = par_repo.parse_rules(files, use_concurrent=True, max_workers=4)

    assert [r.name for r in seq] == [r.name for r in par]
    assert par_repo.get_statistics()['performance']['concurrent_processing'] is True
    assert par_repo.get_statistics()['by_platform'] == seq_repo.get_statistics()['by_platform']


def test_statistics_are_deep_copies(sentinel_fixtures):
    repo = RuleRepository()
    repo.parse_rules(repo.discover_rules(str(sentinel_fixtures)), use_concurrent=False)
    stats = repo.get_statistics()
    stats['attack_analysis']['unique_techniques'].add("TAMPERED")
    assert "TAMPERED" not in repo.parsing_stats['attack_analysis']['unique_techniques']


def test_reset(sentinel_fixtures):
    repo = RuleRepository()
    repo.parse_rules(repo.discover_rules(str(sentinel_fixtures)), use_concurrent=False)
    repo.reset()
    assert repo.rules == [] and repo.get_statistics()['parsing']['rules_parsed'] == 0


# --- ATT&CK validation and revoked policy (C4) -------------------------------------

def _revoked_dir(tmp_path):
    (tmp_path / "r.json").write_text(json.dumps(elastic_json_rule()))                   # T1562, T1562.001
    (tmp_path / "s.yaml").write_text(sentinel_yaml(1, "T1110, T9999, T1153, T1950"))   # unknown/deprecated/orphan
    return tmp_path


def parse_with(tmp_path, validator, policy):
    repo = RuleRepository(validator, revoked_policy=policy)
    rules = repo.parse_rules(repo.discover_rules(str(_revoked_dir(tmp_path))), use_concurrent=False)
    return repo, {r.name: r for r in rules}


def test_policy_remap(tmp_path, validator):
    repo, rules = parse_with(tmp_path, validator, "remap")
    elastic = rules["Kibana Rule"]
    assert elastic.techniques == {"T1685"}                        # both revoked IDs collapse to one
    assert elastic.remapped_techniques == {"T1562": "T1685", "T1562.001": "T1685"}
    assert elastic.technique_tactics == {}                        # stale pairing for revoked IDs dropped
    sentinel = rules["Rule 1"]
    assert sentinel.techniques == {"T1110"}                       # unknown, deprecated, orphan removed
    stats = repo.get_statistics()['attack_analysis']
    assert stats['techniques_remapped'] == 2
    assert stats['techniques_invalid'] == 2                       # T9999 unknown, T1153 deprecated
    assert stats['techniques_dropped_revoked'] == 1               # T1950 has no replacement


def test_policy_drop(tmp_path, validator):
    _, rules = parse_with(tmp_path, validator, "drop")
    assert rules["Kibana Rule"].techniques == set()
    assert rules["Kibana Rule"].remapped_techniques == {}


def test_policy_keep(tmp_path, validator):
    _, rules = parse_with(tmp_path, validator, "keep")
    assert rules["Kibana Rule"].techniques == {"T1562", "T1562.001"}
    assert any("kept by policy" in n for n in rules["Kibana Rule"].notes)


def test_invalid_policy_rejected():
    with pytest.raises(ValueError):
        RuleRepository(revoked_policy="bogus")


def test_legacy_tactic_noted(tmp_path, validator):
    _, rules = parse_with(tmp_path, validator, "remap")
    assert any("defense-evasion" in n for n in rules["Kibana Rule"].notes)


def test_no_validation_without_data(tmp_path):
    repo = RuleRepository()                                       # no validator: revoked IDs pass through
    rules = repo.parse_rules(repo.discover_rules(str(_revoked_dir(tmp_path))), use_concurrent=False)
    assert any("T1562" in r.techniques for r in rules)


# --- coverage report (C6) --------------------------------------------------------

def test_report_is_real_json_with_lists(tmp_path, validator):
    repo, _ = parse_with(tmp_path, validator, "remap")
    report = repo.get_coverage_report()
    text = json.dumps(report)                                     # must not need default=str
    parsed = json.loads(text)
    analysis = parsed['parsing_statistics']['attack_analysis']
    assert isinstance(analysis['unique_techniques'], list)        # was a Python repr string
    assert isinstance(analysis['unique_tactics'], list)
    assert parsed['attack_data']['version'] == '20.1'
    assert parsed['coverage_analysis']['remapped_techniques']['T1562']['replaced_by'] == 'T1685'


def test_report_tactic_gaps_use_attack_data(tmp_path, validator):
    repo, _ = parse_with(tmp_path, validator, "remap")
    gaps = repo.get_coverage_report()['coverage_analysis']['coverage_gaps']
    assert 'collection' in gaps['tactics_without_coverage']
    # The remapped T1685 is a defense-impairment technique, so that tactic is covered
    assert 'defense-impairment' not in gaps['tactics_without_coverage']
    assert 'credential-access' not in gaps['tactics_without_coverage']   # T1110 from the Sentinel rule


def test_report_without_validator_notes_limitation(sentinel_fixtures):
    repo = RuleRepository()
    repo.parse_rules(repo.discover_rules(str(sentinel_fixtures)), use_concurrent=False)
    report = repo.get_coverage_report()
    assert report['attack_data'] == {'loaded': False}
    assert 'note' in report['coverage_analysis']['coverage_gaps']
    assert report['coverage_analysis']['rules_per_tactic']        # tactic info available without ATT&CK data


def test_report_with_no_rules():
    assert 'error' in RuleRepository().get_coverage_report()
