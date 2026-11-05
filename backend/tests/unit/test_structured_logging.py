"""Structured logging (Atta Prompt 10): JSON lines with the scan id, extras,
tracebacks, and a redaction pass over the final line."""

from __future__ import annotations

import json
import logging

from app.utils import logging as app_logging


def _record(msg, *args, exc=None, **extra):
    rec = logging.LogRecord("app.x", logging.INFO, __file__, 1, msg, args, exc)
    for k, v in extra.items():
        setattr(rec, k, v)
    app_logging._ScanIdFilter().filter(rec)
    return rec


def test_json_lines_carry_scan_id_and_extras():
    token = app_logging.scan_id_var.set("11111111-1111-4111-8111-111111111111")
    try:
        line = app_logging.JsonFormatter().format(
            _record("scan completed %s", "ok", findings=3, stage_seconds={"crawl": 1.5})
        )
    finally:
        app_logging.scan_id_var.reset(token)
    out = json.loads(line)
    assert out["msg"] == "scan completed ok" and out["level"] == "INFO"
    assert out["scan_id"] == "11111111-1111-4111-8111-111111111111"
    assert out["findings"] == 3 and out["stage_seconds"] == {"crawl": 1.5}
    assert "args" not in out and "pathname" not in out


def test_lines_outside_a_scan_have_no_scan_id():
    out = json.loads(app_logging.JsonFormatter().format(_record("startup")))
    assert "scan_id" not in out


def test_tracebacks_are_one_json_field():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        out = json.loads(app_logging.JsonFormatter().format(_record("failed", exc=sys.exc_info())))
    assert "ValueError: boom" in out["exc"]


def test_secrets_are_redacted_in_both_formats():
    for fmt in (app_logging.JsonFormatter(), app_logging.TextFormatter()):
        line = fmt.format(_record("got api_key=cawasma-fake-abcdef123456 from %s", "x"))
        assert "cawasma-fake-abcdef123456" not in line and "REDACTED" in line
