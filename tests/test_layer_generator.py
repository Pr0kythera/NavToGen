"""Layer generation: H2 (sub-technique visibility), H3 (filters), H4 (version), H7 (tactic scope)."""

import pytest

from generators.layer_generator import NavigatorLayerGenerator
from models.detection_rule import DetectionRule


def make_rule(name, rtype="sentinel-scheduled", techniques=(), pairs=None, severity="medium", tactics=()):
    rule = DetectionRule(name=name, rule_type=rtype, severity=severity)
    for t in techniques:
        rule.add_technique(t)
    for tid, tactic_list in (pairs or {}).items():
        for tactic in tactic_list:
            rule.add_technique(tid, tactic=tactic)
    for tactic in tactics:
        rule.add_tactic(tactic)
    return rule


def entries(layer):
    return {(t["techniqueID"], t.get("tactic")): t for t in layer.to_dict()["techniques"]}


def test_coverage_layer_basics():
    rules = [make_rule("a", techniques=["T1059", "T1059.001"]), make_rule("b", techniques=["T1059"])]
    layer = NavigatorLayerGenerator().generate_coverage_layer(rules, "L")
    e = entries(layer)
    assert e[("T1059", None)]["score"] == 60 and e[("T1059.001", None)]["score"] == 30
    assert e[("T1059", None)]["showSubtechniques"] is True
    assert e[("T1059.001", None)]["showSubtechniques"] is False
    assert "tactic" not in e[("T1059", None)]


def test_layer_expands_annotated_subtechniques_without_fabricating_parents():
    layer = NavigatorLayerGenerator().generate_coverage_layer([make_rule("a", techniques=["T1003.001"])], "L")
    d = layer.to_dict()
    assert d["layout"]["expandedSubtechniques"] == "annotated"
    assert [t["techniqueID"] for t in d["techniques"]] == ["T1003.001"]       # no invented T1003 entry


def test_no_platform_filter_by_default_and_opt_in():
    rules = [make_rule("a", techniques=["T1059"])]
    assert "filters" not in NavigatorLayerGenerator().generate_coverage_layer(rules, "L").to_dict()
    gen = NavigatorLayerGenerator(platforms=["Windows", "Identity Provider"])
    assert gen.generate_coverage_layer(rules, "L").to_dict()["filters"] == {
        "platforms": ["Windows", "Identity Provider"]}


def test_attack_version_in_every_mode():
    elastic = [make_rule("e", "elastic-query", ["T1059", "T1078"])]
    sentinel = [make_rule("s", "sentinel-scheduled", ["T1059", "T1110"])]
    gen = NavigatorLayerGenerator(attack_version="19.2")
    layers = [gen.generate_coverage_layer(elastic + sentinel, "c"),
              gen.generate_comparison_layer(elastic, sentinel),
              gen.generate_frequency_layer(elastic + sentinel)]
    assert [l.to_dict()["versions"]["attack"] for l in layers] == ["19", "19", "19"]   # comparison/frequency ignored it


def test_attack_version_defaults_from_loaded_data(validator):
    gen = NavigatorLayerGenerator(validator)
    assert gen.default_attack_version == "20"
    assert NavigatorLayerGenerator(validator, attack_version="18").default_attack_version == "18"
    assert NavigatorLayerGenerator().default_attack_version == "20"     # configured fallback


def test_invalid_version_falls_back():
    assert NavigatorLayerGenerator(attack_version="abc").default_attack_version == "20"


def test_tactic_scoped_entries():
    rule = make_rule("e", "elastic-query", pairs={"T1078": ["Initial Access", "Persistence"]})
    plain = NavigatorLayerGenerator().generate_coverage_layer([rule], "L")
    scoped = NavigatorLayerGenerator(tactic_scoped=True).generate_coverage_layer([rule], "L")
    assert set(entries(plain)) == {("T1078", None)}
    assert set(entries(scoped)) == {("T1078", "initial-access"), ("T1078", "persistence")}


def test_tactic_scoped_falls_back_to_unscoped_without_pairing():
    rules = [make_rule("e", "elastic-query", pairs={"T1078": ["Persistence"]}),
             make_rule("s", techniques=["T1110"])]
    e = entries(NavigatorLayerGenerator(tactic_scoped=True).generate_coverage_layer(rules, "L"))
    assert set(e) == {("T1078", "persistence"), ("T1110", None)}


def test_comparison_layer_categories():
    elastic = [make_rule("e", "elastic-query", ["T1059", "T1078"])]
    sentinel = [make_rule("s", "sentinel-scheduled", ["T1059", "T1110"])]
    e = entries(NavigatorLayerGenerator().generate_comparison_layer(elastic, sentinel))
    platform = lambda tid: {m["name"]: m["value"] for m in e[(tid, None)]["metadata"]}["Platform Coverage"]
    assert (platform("T1059"), platform("T1078"), platform("T1110")) == ("Both", "Elastic", "Sentinel")


def test_frequency_layer_scores():
    rules = [make_rule(str(i), techniques=["T1059"]) for i in range(5)] + [make_rule("x", techniques=["T1110"])]
    e = entries(NavigatorLayerGenerator().generate_frequency_layer(rules))
    assert e[("T1059", None)]["score"] == 100 and e[("T1110", None)]["score"] == 20


def test_highest_severity_metadata():
    rules = [make_rule("a", techniques=["T1059"], severity="low"), make_rule("b", techniques=["T1059"], severity="high")]
    meta = {m["name"]: m["value"] for m in entries(
        NavigatorLayerGenerator().generate_coverage_layer(rules, "L"))[("T1059", None)]["metadata"]}
    assert meta["Highest Severity"] == "High"


def test_validator_enriches_comments(validator):
    layer = NavigatorLayerGenerator(validator).generate_coverage_layer([make_rule("a", techniques=["T1059"])], "L")
    assert "Name: Command and Scripting Interpreter" in entries(layer)[("T1059", None)]["comment"]


def test_empty_inputs_raise():
    gen = NavigatorLayerGenerator()
    with pytest.raises(ValueError):
        gen.generate_coverage_layer([], "L")
    with pytest.raises(ValueError):
        gen.generate_coverage_layer([make_rule("a")], "L")        # rules but no techniques
    with pytest.raises(ValueError):
        gen.generate_frequency_layer([])


def test_scoring_algorithms_exposed():
    gen = NavigatorLayerGenerator()
    assert gen._threshold_scoring(5)[0] == 100 and gen._linear_scoring(3)[0] == 30
    assert gen._logarithmic_scoring(0)[0] == 0 and gen._frequency_scoring(10)[0] == 100
    layer = gen.generate_coverage_layer([make_rule("a", techniques=["T1059"])], "L", scoring_algorithm="linear")
    assert entries(layer)[("T1059", None)]["score"] == 10
