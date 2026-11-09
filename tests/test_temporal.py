"""Temporal analysis: C7 (self-contamination), M10 (denominators, tz, CSV names)."""

import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

import main as cli
from core.RuleRepository import RuleRepository
from core.temporal_analysis import FALLBACK_TOTAL_TECHNIQUES, TemporalAnalyzer, _to_naive_utc

ROOT = Path(__file__).resolve().parent.parent


def make_report(ts, rules, techniques, tactics=None, attack_data=None):
    report = {
        "generation_timestamp": ts,
        "parsing_statistics": {"attack_analysis": {"unique_tactics": list(tactics or [])}},
        "coverage_analysis": {
            "total_rules": rules, "unique_techniques": len(techniques),
            "technique_frequency": {t: 1 for t in techniques},
            "tactic_coverage_counts": {}, "rules_per_tactic": {t: 1 for t in (tactics or [])},
            "platform_analysis": {"by_platform": {"elastic_rules": rules // 2, "sentinel_rules": rules - rules // 2}},
        },
    }
    if attack_data:
        report["attack_data"] = attack_data
    return report


def write(path, data):
    path.write_text(json.dumps(data))
    return path


@pytest.fixture
def snap_dir(tmp_path):
    write(tmp_path / "coverage_20260101_000000.json", make_report("2026-01-01T00:00:00", 100, ["T1059", "T1003"], ["execution"]))
    write(tmp_path / "coverage_20260301_000000.json", make_report("2026-03-01T00:00:00", 160, ["T1059", "T1003", "T1078"], ["execution", "persistence"]))
    return tmp_path


def test_loads_reports_and_computes_growth(snap_dir):
    a = TemporalAnalyzer()
    assert a.load_snapshots_from_directory(str(snap_dir)) == 2
    summary = a.generate_executive_summary()
    assert summary["overall_growth"]["rules_added"] == 60
    assert summary["overall_growth"]["techniques_added"] == 1
    assert summary["overall_growth"]["tactics_added"] == 1
    assert summary["analysis_period"]["total_snapshots"] == 2


def test_foreign_json_files_are_skipped_by_content(snap_dir):
    """The tool's own outputs in the directory used to be loaded as empty 'snapshots'."""
    write(snap_dir / "executive_summary_20261109_162707.json", {"analysis_period": {}, "overall_growth": {}})
    write(snap_dir / "time_series_data_20261109_162707.json", {"coverage_trends": []})
    write(snap_dir / "package.json", {"name": "x"})
    (snap_dir / "broken.json").write_text("{nope")
    a = TemporalAnalyzer()
    assert a.load_snapshots_from_directory(str(snap_dir)) == 2
    assert len(a.skipped_files) == 4
    assert a.generate_executive_summary()["current_status"]["total_rules"] == 160    # was 0


def test_navigator_layer_snapshots_have_unknown_rule_counts(tmp_path):
    layer = {"name": "x", "domain": "enterprise-attack", "versions": {"attack": "20"},
             "techniques": [
                 {"techniqueID": "T1059", "score": 60, "metadata": [{"name": "Rule Count", "value": "3"},
                                                                    {"name": "ATT&CK Tactics", "value": "execution, stealth"}]},
                 {"techniqueID": "T1003", "score": 30, "tactic": "credential-access", "metadata": []}]}
    write(tmp_path / "layer_20260101_000000.json", layer)
    write(tmp_path / "layer_20260201_000000.json", layer)
    write(tmp_path / "layer_20260301_000000.json", layer)
    a = TemporalAnalyzer()
    assert a.load_snapshots_from_directory(str(tmp_path)) == 3
    snap = a.snapshots[0]
    assert snap.total_rules is None                                          # not guessed from score // 20
    assert snap.technique_coverage["T1059"] == 3                             # exact, from 'Rule Count' metadata
    assert set(snap.tactic_coverage) == {"execution", "stealth", "credential-access"}
    summary = a.generate_executive_summary()                                  # must not raise on None
    assert summary["overall_growth"]["rules_added"] is None
    assert summary["velocity_metrics"]["average_rules_per_day"] is None
    assert summary["trend_analysis"]["acceleration_indicators"]["rules_acceleration"] == "unknown"
    assert any("Rule counts are unavailable" in r for r in summary["recommendations"])
    series = a.generate_time_series_data()
    assert series["velocity_metrics"][0]["rules_per_day"] is None


def test_denominator_from_attack_data_vs_fallback(tmp_path):
    facts = {"loaded": True, "version": "20.1", "active_technique_count": 100, "tactic_count": 15}
    write(tmp_path / "a_20260101_000000.json", make_report("2026-01-01T00:00:00", 10, [f"T{1000+i}" for i in range(10)], attack_data=facts))
    write(tmp_path / "b_20260201_000000.json", make_report("2026-02-01T00:00:00", 20, [f"T{1000+i}" for i in range(20)], attack_data=facts))
    a = TemporalAnalyzer()
    a.load_snapshots_from_directory(str(tmp_path))
    assert a.snapshots[-1].get_coverage_percentage() == 20.0                 # 20 / 100, not 20 / 800
    assert a.snapshots[-1].denominator_source == "ATT&CK 20.1"
    assert "ATT&CK 20.1" in a.generate_executive_summary()["coverage_basis"]

    legacy = TemporalAnalyzer()
    write(tmp_path / "c_20260301_000000.json", make_report("2026-03-01T00:00:00", 5, ["T1059"]))
    legacy.load_snapshot_from_coverage_report(str(tmp_path / "c_20260301_000000.json"))
    assert legacy.snapshots == []                                            # direct load does not register
    snap = legacy.load_snapshot_from_coverage_report(str(tmp_path / "c_20260301_000000.json"))
    assert snap.total_techniques_possible == FALLBACK_TOTAL_TECHNIQUES and snap.denominator_source == "fallback"


def test_timezone_aware_and_naive_timestamps_sort(tmp_path):
    write(tmp_path / "a.json", make_report("2026-02-01T00:00:00+00:00", 20, ["T1059"]))
    write(tmp_path / "b.json", make_report("2026-01-01T00:00:00", 10, ["T1059"]))
    write(tmp_path / "c.json", make_report("2026-03-01T00:00:00Z", 30, ["T1059"]))
    a = TemporalAnalyzer()
    assert a.load_snapshots_from_directory(str(tmp_path)) == 3                 # used to raise on sort
    assert [s.total_rules for s in a.snapshots] == [10, 20, 30]
    assert _to_naive_utc(datetime.fromisoformat("2026-01-01T02:00:00+02:00")) == datetime(2026, 1, 1, 0, 0)


def test_csv_export_uses_suffix_and_creates_dirs(snap_dir, tmp_path):
    a = TemporalAnalyzer()
    a.load_snapshots_from_directory(str(snap_dir))
    out = tmp_path / "x" / "y"
    first = a.export_to_csv(str(out), suffix="run1")
    second = a.export_to_csv(str(out), suffix="run2")
    assert all("run1" in f for f in first) and all("run2" in f for f in second)
    assert len(list(out.glob("*.csv"))) == len(first) * 2                      # nothing overwritten
    plain = a.export_to_csv(str(out))
    assert all(Path(f).name.endswith(".csv") and "run" not in f for f in plain)


def test_compare_snapshots_and_bounds(snap_dir):
    a = TemporalAnalyzer()
    a.load_snapshots_from_directory(str(snap_dir))
    result = a.compare_snapshots(0, 1)
    assert result.rules_added == 60 and result.new_techniques == ["T1078"] and result.new_tactics == []
    assert result.rules_per_day == pytest.approx(60 / 59)
    with pytest.raises(IndexError):
        a.compare_snapshots(0, 5)
    with pytest.raises(IndexError):
        a.compare_snapshots(-1, 1)


def test_needs_two_snapshots(tmp_path):
    write(tmp_path / "a.json", make_report("2026-01-01T00:00:00", 1, ["T1059"]))
    a = TemporalAnalyzer()
    a.load_snapshots_from_directory(str(tmp_path))
    assert "error" in a.generate_executive_summary()


def test_repo_sample_snapshots_still_load():
    a = TemporalAnalyzer()
    assert a.load_snapshots_from_directory(str(ROOT / "sample_snapshots")) == 3
    assert a.generate_executive_summary()["overall_growth"]["rules_added"] == 70


def test_real_report_round_trip(tmp_path, sentinel_fixtures, validator):
    repo = RuleRepository(validator)
    repo.parse_rules(repo.discover_rules(str(sentinel_fixtures)), use_concurrent=False)
    report = repo.get_coverage_report()
    write(tmp_path / "r1_20260101_000000.json", report)
    report2 = dict(report, generation_timestamp="2026-02-01T00:00:00")
    write(tmp_path / "r2_20260201_000000.json", report2)
    a = TemporalAnalyzer()
    assert a.load_snapshots_from_directory(str(tmp_path)) == 2
    snap = a.snapshots[0]
    assert snap.total_rules == 7 and snap.unique_tactics >= 5
    assert snap.total_techniques_possible == len(validator.valid_techniques)   # real denominator
    assert snap.attack_version == "20.1"


# --- through the CLI -------------------------------------------------------------

def run_temporal(monkeypatch, tmp_path, directory):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["main.py", "--quiet", "--temporal-analysis", "--snapshots-directory", str(directory)])
    return cli.main()


def test_cli_temporal_outputs_never_become_inputs(monkeypatch, tmp_path, snap_dir):
    assert run_temporal(monkeypatch, tmp_path, snap_dir) == 0
    out = tmp_path / "output" / "temporal"
    assert list(out.glob("executive_summary_*.json")) and list(out.glob("temporal_analysis_*_*.csv"))
    # Point the next run at the output directory used by earlier tool versions: nothing in
    # output/ (including the temporal subdirectory) may be mistaken for a snapshot
    shutil_target = tmp_path / "output"
    for f in snap_dir.glob("*.json"):
        (shutil_target / f.name).write_text(f.read_text())
    assert run_temporal(monkeypatch, tmp_path, shutil_target) == 0
    summary = json.loads(sorted((tmp_path / "output" / "temporal").glob("executive_summary_*.json"))[-1].read_text())
    assert summary["analysis_period"]["total_snapshots"] == 2
    assert summary["current_status"]["total_rules"] == 160


def test_cli_temporal_with_too_few_snapshots_fails(monkeypatch, tmp_path):
    d = tmp_path / "one"
    d.mkdir()
    write(d / "a.json", make_report("2026-01-01T00:00:00", 1, ["T1059"]))
    assert run_temporal(monkeypatch, tmp_path, d) == cli.EXIT_FAILED
