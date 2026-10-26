"""Redaction of secrets from evidence, headers, and logs (spec sections 20/31).

Nothing sensitive should ever be stored raw or written to a log: passwords,
API keys, JWTs, session cookies, and authorization headers are masked here
before persistence or logging. Detection is deliberately conservative -- when
in doubt, mask.
"""
from __future__ import annotations

import re

MASK = "***REDACTED***"

# Header names whose values are always sensitive.
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-csrf-token",
}

# Patterns for secret-like values inside response bodies / evidence.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{10,}")),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    # KEY=value, key: value and JSON "key": "value", whatever the value's
    # characters or length (SECRET_KEY=abc123, DB_PASSWORD=pw, "pwd": "P@ss!").
    ("api_key_assign", re.compile(
        r"(?i)(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)"
        r"[\w-]*['\"]?\s*[=:]\s*(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s'\",;&<>]+)"
    )),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]


def redact_text(text: str | None) -> str | None:
    """Mask secret-like substrings inside free text."""
    if not text:
        return text
    redacted = text
    for _name, pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(MASK, redacted)
    return redacted


def redact_header(name: str, value: str) -> str:
    """Return the header value, masked if the header name is sensitive."""
    if name.lower() in SENSITIVE_HEADERS:
        return MASK
    # Even non-sensitive headers may contain secrets in their value.
    return redact_text(value) or ""


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of a header mapping with sensitive values masked."""
    return {k: redact_header(k, v) for k, v in headers.items()}


def safe_evidence(text: str | None, *, max_len: int = 500) -> str | None:
    """Prepare response evidence for storage: redact, then truncate."""
    red = redact_text(text)
    if red is None:
        return None
    if len(red) > max_len:
        return red[:max_len] + "…"
    return red
