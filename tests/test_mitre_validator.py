"""ATT&CK validator: C1, C2, C4, H5, H6, M12."""

import json
from datetime import datetime, timedelta


import validators.mitre_validator as mv
from validators.mitre_validator import MitreAttackValidator
from tests.conftest import make_attack_bundle


class FakeResponse:
    def __init__(self, status=200, body=b"", headers=None):
        self.status_code = status
        self.content = body
        self.headers = headers or {}

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        return json.loads(self.content)


class FakeSession:
    """Stands in for requests.Session; records calls and replays queued responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, timeout=None, headers=None):
        self.calls.append((url, dict(headers or {})))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def bundle_bytes(**kw):
    return json.dumps(make_attack_bundle(**kw)).encode()


def make_validator(tmp_path, responses):
    v = MitreAttackValidator(cache_dir=str(tmp_path / "cache"))
    v._session = FakeSession(responses)
    return v


# --- C1: processing real-shaped data must succeed ---------------------------

def test_process_attack_data_succeeds(validator):
    assert validator.has_data()
    assert "T1059.001" in validator.valid_techniques


def test_tactics_come_from_tactic_objects(validator):
    """Old code derived tactics from an empty stub, so validation always failed."""
    assert len(validator.valid_tactics) == 15
    assert {"stealth", "defense-impairment"} <= validator.valid_tactics   # C2
    assert "defense-evasion" not in validator.valid_tactics


def test_invalid_structures_rejected():
    v = MitreAttackValidator()
    assert v._process_attack_data({"no": "objects"}) is False
    assert v._process_attack_data({"objects": []}) is False
    assert v._process_attack_data("not a dict") is False
    assert not v.has_data()


def test_failed_load_does_not_clobber_existing_data(validator):
    before = set(validator.valid_techniques)
    assert validator._process_attack_data({"objects": []}) is False
    assert validator.valid_techniques == before


# --- H5: real version ------------------------------------------------------

def test_version_from_collection(validator):
    assert validator.data_version == "20.1"
    assert validator.data_major_version == "20"


def test_version_unknown_without_collection(tmp_path):
    path = tmp_path / "cti.json"
    path.write_bytes(bundle_bytes(include_collection=False))
    v = MitreAttackValidator()
    assert v.load_from_file(str(path))
    assert v.data_version is None and v.data_major_version is None


# --- C4: revoked / deprecated ---------------------------------------------

def test_revoked_and_deprecated_are_not_valid(validator):
    assert validator.is_valid_technique("T1059")
    assert not validator.is_valid_technique("T1562")       # revoked
    assert not validator.is_valid_technique("T1153")       # deprecated
    assert not validator.is_valid_technique("T9999")       # unknown
    assert validator.is_revoked("T1562") and validator.is_deprecated("T1153")
    assert validator.is_known_technique("T1562") and not validator.is_known_technique("T9999")


def test_resolve_revoked(validator):
    assert validator.resolve_revoked("T1562") == "T1685"
    assert validator.resolve_revoked("T1562.001") == "T1685"
    assert validator.resolve_revoked("T1070.001") == "T1685.005"
    assert validator.resolve_revoked("T1900") == "T1902"    # follows the chain
    assert validator.resolve_revoked("T1950") is None       # revoked, no replacement
    assert validator.resolve_revoked("T1059") is None       # not revoked


def test_revoked_cycle_does_not_loop(validator):
    validator.revoked_by["T1900"] = "T1901"
    validator.revoked_by["T1901"] = "T1900"
    assert validator.resolve_revoked("T1900") is None


def test_format_only_fallback_without_data():
    v = MitreAttackValidator()
    assert v.is_valid_technique("T1055.001")
    assert not v.is_valid_technique("T10")
    assert v.is_valid_tactic("stealth")


def test_known_platforms_and_techniques_by_tactic(validator):
    assert {"Windows", "Identity Provider"} <= validator.known_platforms()
    assert "T1685" in validator.get_techniques_by_tactic("defense-impairment")
    assert "T1562" not in validator.get_techniques_by_tactic("stealth")   # revoked excluded


# --- H6: retry configuration -----------------------------------------------

def test_retry_uses_status_forcelist():
    adapter = MitreAttackValidator()._session.get_adapter("https://example.org")
    retries = adapter.max_retries
    assert {429, 500, 502, 503, 504} <= set(retries.status_forcelist)


# --- M12: caching, ETag, stale cache, offline -------------------------------

def test_download_then_cache_hit(tmp_path):
    v = make_validator(tmp_path, [FakeResponse(200, bundle_bytes(), {"ETag": '"abc"'})])
    assert v.fetch_mitre_data()
    assert len(v._session.calls) == 1

    # A new validator with a fresh cache needs no network at all
    v2 = make_validator(tmp_path, [])
    assert v2.fetch_mitre_data()
    assert v2._session.calls == []
    assert v2.data_version == "20.1"


def test_expired_cache_revalidates_with_etag_and_accepts_304(tmp_path):
    v = make_validator(tmp_path, [FakeResponse(200, bundle_bytes(), {"ETag": '"abc"'})])
    assert v.fetch_mitre_data()

    _, meta_path = v._cache_paths(mv.MITRE_ATTACK_URL)
    meta = json.loads(meta_path.read_text())
    meta["fetched_at"] = (datetime.now() - timedelta(days=3)).isoformat()
    meta_path.write_text(json.dumps(meta))

    v2 = make_validator(tmp_path, [FakeResponse(304)])
    assert v2.fetch_mitre_data()
    assert v2._session.calls[0][1].get("If-None-Match") == '"abc"'
    assert v2.has_data()


def test_stale_cache_used_when_download_fails(tmp_path):
    v = make_validator(tmp_path, [FakeResponse(200, bundle_bytes())])
    assert v.fetch_mitre_data()
    _, meta_path = v._cache_paths(mv.MITRE_ATTACK_URL)
    meta_path.write_text(json.dumps({"fetched_at": (datetime.now() - timedelta(days=9)).isoformat()}))

    v2 = make_validator(tmp_path, [FakeResponse(503)])
    assert v2.fetch_mitre_data()
    assert v2.using_stale_cache is True


def test_failure_without_cache_returns_false(tmp_path):
    v = make_validator(tmp_path, [FakeResponse(500)])
    assert v.fetch_mitre_data() is False
    assert not v.has_data()


def test_refresh_bypasses_fresh_cache(tmp_path):
    v = make_validator(tmp_path, [FakeResponse(200, bundle_bytes())])
    assert v.fetch_mitre_data()
    v2 = make_validator(tmp_path, [FakeResponse(200, bundle_bytes())])
    assert v2.fetch_mitre_data(force_refresh=True)
    assert len(v2._session.calls) == 1


def test_no_cache_option_writes_nothing(tmp_path):
    v = MitreAttackValidator(cache_dir=str(tmp_path / "cache"), use_cache=False)
    v._session = FakeSession([FakeResponse(200, bundle_bytes())])
    assert v.fetch_mitre_data()
    assert not (tmp_path / "cache").exists()


def test_oversized_download_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(mv, "MAX_ATTACK_DATA_BYTES", 10)
    v = make_validator(tmp_path, [FakeResponse(200, bundle_bytes())])
    assert v.fetch_mitre_data() is False


def test_versioned_download_resolves_through_index(tmp_path):
    index = {"collections": [{"name": "Enterprise ATT&CK", "versions": [
        {"version": "20.1", "url": "https://example.org/e-20.1.json"},
        {"version": "19.2", "url": "https://example.org/e-19.2.json"},
        {"version": "19.1", "url": "https://example.org/e-19.1.json"},
    ]}]}
    v = make_validator(tmp_path, [FakeResponse(200, json.dumps(index).encode()),
                                  FakeResponse(200, bundle_bytes(version="19.2"))])
    assert v.fetch_mitre_data(version="19")
    assert v._session.calls[1][0] == "https://example.org/e-19.2.json"   # newest 19.x
    assert v.data_version == "19.2"


def test_unknown_version_fails_cleanly(tmp_path):
    index = {"collections": [{"name": "Enterprise ATT&CK", "versions": [{"version": "20.1", "url": "u"}]}]}
    v = make_validator(tmp_path, [FakeResponse(200, json.dumps(index).encode())])
    assert v.fetch_mitre_data(version="3") is False


def test_load_from_missing_or_corrupt_file(tmp_path):
    v = MitreAttackValidator()
    assert v.load_from_file(str(tmp_path / "nope.json")) is False
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert v.load_from_file(str(bad)) is False


def test_default_cache_dir_respects_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert mv.default_cache_dir() == tmp_path / "navtogen"


def test_validate_technique_list(validator):
    valid, invalid = validator.validate_technique_list({"T1059", "t1003.001", "T1562", "T9999"})
    assert valid == {"T1059", "T1003.001"} and invalid == {"T1562", "T9999"}


def test_validation_summary(validator):
    summary = validator.get_validation_summary()
    assert summary["data_version"] == "20.1" and summary["validation_mode"] == "attack_data"
    assert summary["revoked_techniques"] == 6 and summary["deprecated_techniques"] == 1
    assert MitreAttackValidator().get_validation_summary()["validation_mode"] == "format_only"
