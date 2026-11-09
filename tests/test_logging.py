"""Logging configuration (NO_COLOR handling)."""

import logging

from utils.logging_config import ColoredFormatter, setup_logging


def test_no_color_wins_over_force_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert ColoredFormatter._supports_color() is False


def test_force_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert ColoredFormatter._supports_color() is True


def test_setup_logging_file_handler(tmp_path):
    log = tmp_path / "logs" / "run.log"
    summary = setup_logging("INFO", str(log), enable_colors=False)
    logging.getLogger("t").info("hello file")
    for handler in logging.getLogger().handlers:
        handler.flush()
    assert "hello file" in log.read_text()
    assert any(h.startswith("file(") for h in summary["handlers"])
