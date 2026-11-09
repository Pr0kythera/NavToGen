"""End-to-end CLI behaviour: C1 (explicit validation failure), C6, H1, H4, M3, exit codes."""

import json
import sys
from pathlib import Path

import pytest

import main as cli
from validators.mitre_validator import MitreAttackValidator


def run_cli(monkeypatch, tmp_path, *argv):
    """Run main() with argv in tmp_path; returns the exit code."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["main.py", "--quiet", "--no-threading", *argv])
    return cli.main()


@pytest.fixture
def rules_dir(tmp_path, sentinel_fixtures):
    d = tmp_path / "rules"
    d.mkdir()
    for f in sentinel_fixtures.glob("*.yaml"):
        (d / f.name).write_text(f.read_text())
    return d


def test_basic_run_creates_nested_output_dir(monkeypatch, tmp_path, rules_dir):
    rc = run_cli(monkeypatch, tmp_path, "-p", str(rules_dir), "-o", "deep/er/cov.json")
    assert rc == 0
    layer = json.loads((tmp_path / "deep" / "er" / "cov.json").read_text())
    assert len(layer["techniques"]) == 13                               # M3: parent dirs created


def test_report_goes_where_asked_and_is_valid_json(monkeypatch, tmp_path, rules_dir, attack_file):
    rc = run_cli(monkeypatch, tmp_path, "-p", str(rules_dir), "-o", "l.json",
                 "--report", "reports/rep.json", "--attack-data-file", str(attack_file))
    assert rc == 0
    report = json.loads((tmp_path / "reports" / "rep.json").read_text())      # old code wrote output_reports_rep.json
    assert not (tmp_path / "reports_rep.json").exists()
    assert isinstance(report["parsing_statistics"]["attack_analysis"]["unique_techniques"], list)


def test_bare_report_name_goes_under_output(monkeypatch, tmp_path, rules_dir):
    assert run_cli(monkeypatch, tmp_path, "-p", str(rules_dir), "-o", "l.json", "--report", "rep.json") == 0
    assert (tmp_path / "output" / "rep.json").is_file()


def test_default_output_path(monkeypatch, tmp_path, rules_dir):
    assert run_cli(monkeypatch, tmp_path, "-p", str(rules_dir)) == 0
    files = list((tmp_path / "output").glob("coverage_analysis_*.json"))
    assert len(files) == 1


def test_offline_validation_stamps_real_version(monkeypatch, tmp_path, rules_dir, attack_file):
    rc = run_cli(monkeypatch, tmp_path, "-p", str(rules_dir), "-o", "l.json", "--attack-data-file", str(attack_file))
    assert rc == 0
    layer = json.loads((tmp_path / "l.json").read_text())
    assert layer["versions"]["attack"] == "20"
    assert "Validated against ATT&CK 20.1" in layer["description"]


def test_explicit_attack_version_overrides(monkeypatch, tmp_path, rules_dir, attack_file):
    run_cli(monkeypatch, tmp_path, "-p", str(rules_dir), "-o", "l.json",
            "--attack-data-file", str(attack_file), "--attack-version", "19")
    assert json.loads((tmp_path / "l.json").read_text())["versions"]["attack"] == "19"


def test_validate_online_failure_is_explicit(monkeypatch, tmp_path, rules_dir):
    """Old behaviour: warn and exit 0 with unvalidated results."""
    monkeypatch.setattr(MitreAttackValidator, "fetch_mitre_data", lambda self, **kw: False)
    rc = run_cli(monkeypatch, tmp_path, "-p", str(rules_dir), "-o", "l.json", "--validate-online")
    assert rc == cli.EXIT_BAD_ARGS
    assert not (tmp_path / "l.json").exists()


def test_validate_online_failure_can_be_allowed(monkeypatch, tmp_path, rules_dir):
    monkeypatch.setattr(MitreAttackValidator, "fetch_mitre_data", lambda self, **kw: False)
    rc = run_cli(monkeypatch, tmp_path, "-p", str(rules_dir), "-o", "l.json",
                 "--validate-online", "--allow-unvalidated")
    assert rc == 0 and (tmp_path / "l.json").exists()


def test_validate_online_passes_version_and_cache_options(monkeypatch, tmp_path, rules_dir, attack_file):
    seen = {}

    def fake_fetch(self, force_refresh=False, version=None):
        seen.update(force_refresh=force_refresh, version=version, cache_dir=str(self.cache_dir), use_cache=self.use_cache)
        return self.load_from_file(str(attack_file))

    monkeypatch.setattr(MitreAttackValidator, "fetch_mitre_data", fake_fetch)
    run_cli(monkeypatch, tmp_path, "-p", str(rules_dir), "-o", "l.json", "--validate-online",
            "--attack-version", "19", "--refresh-attack-data", "--cache-dir", str(tmp_path / "c"), "--no-cache")
    assert seen == {"force_refresh": True, "version": "19", "cache_dir": str(tmp_path / "c"), "use_cache": False}


def make_disabled_dir(tmp_path):
    d = tmp_path / "r"
    d.mkdir()
    base = "name: {n}\nkind: Scheduled\nqueryFrequency: 1h\ntactics: [Impact]\nrelevantTechniques: [{t}]\nenabled: {e}\n"
    (d / "on.yaml").write_text(base.format(n="Enabled rule", t="T1485", e="true"))
    (d / "off.yaml").write_text(base.format(n="Disabled rule", t="T1486", e="false"))
    return d


def test_disabled_rules_excluded_by_default(monkeypatch, tmp_path):
    d = make_disabled_dir(tmp_path)
    run_cli(monkeypatch, tmp_path, "-p", str(d), "-o", "l.json")
    assert [t["techniqueID"] for t in json.loads((tmp_path / "l.json").read_text())["techniques"]] == ["T1485"]


def test_disabled_rules_can_be_included(monkeypatch, tmp_path):
    d = make_disabled_dir(tmp_path)
    run_cli(monkeypatch, tmp_path, "-p", str(d), "-o", "l.json", "--include-disabled")
    ids = sorted(t["techniqueID"] for t in json.loads((tmp_path / "l.json").read_text())["techniques"])
    assert ids == ["T1485", "T1486"]


def test_attack_version_honoured_in_comparison_and_frequency(monkeypatch, tmp_path, rules_dir, elastic_dir):
    for flag in ("--comparison-mode", "--frequency-mode"):
        d = tmp_path / "mixed"
        d.mkdir(exist_ok=True)
        for src in list(rules_dir.glob("*.yaml")) + [elastic_dir / "rule.yaml"]:
            (d / src.name).write_text(src.read_text())
        assert run_cli(monkeypatch, tmp_path, "-p", str(d), "-o", f"{flag[2:]}.json", flag, "--attack-version", "18") == 0
        assert json.loads((tmp_path / f"{flag[2:]}.json").read_text())["versions"]["attack"] == "18"


def test_platform_filter_option(monkeypatch, tmp_path, rules_dir):
    run_cli(monkeypatch, tmp_path, "-p", str(rules_dir), "-o", "l.json", "--platforms", "Windows", "Identity Provider")
    assert json.loads((tmp_path / "l.json").read_text())["filters"]["platforms"] == ["Windows", "Identity Provider"]


def test_rule_type_filter(monkeypatch, tmp_path, rules_dir, elastic_dir):
    d = tmp_path / "mix"
    d.mkdir()
    (d / "e.yaml").write_text((elastic_dir / "rule.yaml").read_text())
    (d / "s.yaml").write_text(next(rules_dir.glob("*.yaml")).read_text())
    run_cli(monkeypatch, tmp_path, "-p", str(d), "-o", "l.json", "--rule-type", "elastic")
    layer = json.loads((tmp_path / "l.json").read_text())
    assert all("elastic" in t["comment"] for t in layer["techniques"] if t["comment"].startswith("Coverage"))


def test_no_rules_found_exit_code(monkeypatch, tmp_path):
    (tmp_path / "empty").mkdir()
    assert run_cli(monkeypatch, tmp_path, "-p", str(tmp_path / "empty"), "-o", "l.json") == cli.EXIT_FAILED


def test_rules_without_techniques_fail_cleanly(monkeypatch, tmp_path):
    d = tmp_path / "r"
    d.mkdir()
    (d / "x.yaml").write_text("name: n\nkind: Scheduled\nqueryFrequency: 1h\n")
    assert run_cli(monkeypatch, tmp_path, "-p", str(d), "-o", "l.json") == cli.EXIT_FAILED


@pytest.mark.parametrize("argv", [
    ["-p", "{rules}", "--comparison-mode", "--frequency-mode"],
    ["-p", "{rules}", "--attack-version", "abc"],
    ["-p", "{rules}", "--max-workers", "99"],
    ["-p", "{rules}", "--validate-online", "--attack-data-file", "{rules}/x"],
    ["-p", "/definitely/not/a/dir"],
    [],
    ["--temporal-analysis"],
])
def test_invalid_arguments_exit_2(monkeypatch, tmp_path, rules_dir, argv):
    argv = [a.replace("{rules}", str(rules_dir)) for a in argv]
    assert run_cli(monkeypatch, tmp_path, *argv) == cli.EXIT_BAD_ARGS


def test_output_to_system_path_rejected(monkeypatch, tmp_path, rules_dir):
    assert run_cli(monkeypatch, tmp_path, "-p", str(rules_dir), "-o", "/etc/navtogen/out.json") == cli.EXIT_FAILED
    assert not Path("/etc/navtogen").exists()
