"""Application logging configuration.

One :func:`configure_logging` entry point and a :func:`get_logger` helper.

``LOG_FORMAT=json`` (the Docker default) writes one JSON object per line:
``ts``, ``level``, ``logger``, ``msg``, ``scan_id`` while a scan runs (from the
:data:`scan_id_var` context variable, so every module's lines inside a scan are
tagged without passing the id around), anything given as ``extra={...}``, and
``exc`` for tracebacks. ``LOG_FORMAT=text`` keeps the readable form for local
runs. Secrets must be redacted (``utils/redaction.py``) before they reach the
logger; both formatters also redact the final line as a last line of defence.
"""
from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar

from app.config import settings
from app.utils.redaction import redact_text

_CONFIGURED = False

_LEVEL = logging.DEBUG if settings.DEBUG else logging.INFO

# Set by the scan runner for the duration of a scan (asyncio tasks inherit it).
scan_id_var: ContextVar[str | None] = ContextVar("scan_id", default=None)

# LogRecord attributes that are not ``extra`` fields.
_STANDARD = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message", "asctime", "scan_id", "taskName"}


class _ScanIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.scan_id = scan_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, object] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if scan_id := getattr(record, "scan_id", None):
            out["scan_id"] = scan_id
        out.update({k: v for k, v in vars(record).items()
                    if k not in _STANDARD and not k.startswith("_")})
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return redact_text(json.dumps(out, default=str)) or ""


class TextFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__(fmt="%(asctime)s %(levelname)-8s %(name)s :: %(message)s",
                         datefmt="%Y-%m-%dT%H:%M:%S%z")

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        if scan_id := getattr(record, "scan_id", None):
            line += f" [scan={scan_id}]"
        return redact_text(line) or ""


def configure_logging() -> None:
    """Configure the root logger once, idempotently."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if settings.LOG_FORMAT == "json"
                         else TextFormatter())
    handler.addFilter(_ScanIdFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(_LEVEL)

    # Tame noisy third-party loggers.
    for noisy in ("httpx", "httpcore", "urllib3", "asyncio", "hpack", "h2"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a module-scoped logger, configuring logging on first use."""
    if not _CONFIGURED:
        configure_logging()
    return logging.getLogger(name)
