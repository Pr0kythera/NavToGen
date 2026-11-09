"""Path safety: M1 (prefix matching), M2 (symlinks), M3 (output dirs), C6 (filename sanitizing)."""

from pathlib import Path

import pytest

from validators.security_validator import SecurityValidator as SV


@pytest.mark.parametrize("path,blocked", [
    ("/etc/passwd", True),
    ("/etc", True),
    ("/var/log/syslog", True),
    ("/proc/1/environ", True),
    ("/private/etc/hosts", True),                  # macOS
    ("/home/me/proj/etc/rules/a.yaml", False),     # old substring check blocked this
    ("/data/sys/rules/a.yaml", False),
    ("/opt/var/log/archive/a.yaml", False),
    ("/etcetera/x.yaml", False),
    ("/root/rules/a.yaml", False),                 # running as root must work
])
def test_forbidden_prefix(path, blocked):
    assert (SV._forbidden_prefix(Path(path)) is not None) is blocked


def test_windows_prefix_case_insensitive():
    assert SV._forbidden_prefix(Path("c:/windows/system32/x")) is not None


def test_sanitize_output_path_keeps_directories():
    assert SV.sanitize_output_path("output/rep.json") == str(Path("output") / "rep.json")
    assert SV.sanitize_output_path("/tmp/x/a<b>.json") == "/tmp/x/a_b_.json"


def test_sanitize_filename_basics():
    assert SV.sanitize_filename("a:b*c?.json") == "a_b_c_.json"
    assert SV.sanitize_filename("") == "default_filename"
    assert len(SV.sanitize_filename("x" * 500 + ".json")) <= 200


def test_output_path_creates_parents_only_when_asked(tmp_path):
    target = tmp_path / "a" / "b" / "out.json"
    ok, msg = SV.validate_output_path(str(target))
    assert not ok and "does not exist" in msg
    ok, msg = SV.validate_output_path(str(target), create_parents=True)
    assert ok, msg
    assert target.parent.is_dir()


def test_output_path_rejects_system_location_without_creating_dirs():
    ok, msg = SV.validate_output_path("/etc/navtogen_new_dir/out.json", create_parents=True)
    assert not ok and "system location" in msg
    assert not Path("/etc/navtogen_new_dir").exists()


def test_file_validation_accepts_normal_rule(tmp_path):
    f = tmp_path / "r.yaml"
    f.write_text("name: x")
    assert SV.validate_file_path(str(f), {".yaml"})[0]
    assert not SV.validate_file_path(str(f), {".json"})[0]


def test_symlink_escaping_root_rejected(tmp_path):
    root = tmp_path / "rules"
    root.mkdir()
    outside = tmp_path / "secret.yaml"
    outside.write_text("name: secret")
    link = root / "link.yaml"
    link.symlink_to(outside)
    ok, msg = SV.validate_file_path(str(link), {".yaml"}, allowed_root=str(root))
    assert not ok and "outside the scanned directory" in msg


def test_symlink_inside_root_allowed(tmp_path):
    root = tmp_path / "rules"
    (root / "sub").mkdir(parents=True)
    real = root / "sub" / "real.yaml"
    real.write_text("name: x")
    link = root / "link.yaml"
    link.symlink_to(real)
    assert SV.validate_file_path(str(link), {".yaml"}, allowed_root=str(root))[0]


def test_directory_symlink_is_detected_and_logged(tmp_path, caplog):
    """The old check called resolve() first, so symlinks were never detected."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with caplog.at_level("WARNING"):
        ok, _ = SV.validate_directory_path(str(link))
    assert ok
    assert any("symbolic link" in r.message for r in caplog.records)


def test_directory_validation_errors(tmp_path):
    assert not SV.validate_directory_path(str(tmp_path / "missing"))[0]
    f = tmp_path / "f"
    f.write_text("x")
    assert not SV.validate_directory_path(str(f))[0]
    assert not SV.validate_directory_path("/etc")[0]


def test_startup_check_passes():
    assert SV.perform_startup_security_check() is True
