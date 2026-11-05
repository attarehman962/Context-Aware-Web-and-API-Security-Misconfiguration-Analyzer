"""Behaviour of the shipped checks in config/checks.yaml (review asim-p04).

These pin bugs found in review, not the security judgement behind each check.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import settings
from app.core.contracts import ResponseInfo
from app.core.specs import load_checks

CHECKS = {c.check_id: c for c in load_checks(Path(settings.CONFIG_DIR) / "checks.yaml").checks}


def _resp(headers: dict[str, str]) -> ResponseInfo:
    return ResponseInfo("https://shop.example.com/", 200, "text/html", headers)


@pytest.mark.parametrize(
    "value, fires",
    [
        (None, True),  # header absent
        ("DENY", False),
        ("SAMEORIGIN", False),
        ("sameorigin", False),  # case-insensitive
        (" DENY ", False),
        ("ALLOW-FROM https://x.example", True),
        ("DENY, SAMEORIGIN", True),  # invalid combined value
    ],
)
def test_hdr003_fires_only_without_deny_or_sameorigin(value, fires):
    headers = {} if value is None else {"X-Frame-Options": value}
    assert CHECKS["HDR-003"].http_condition.matches(_resp(headers)) is fires


# --------------------------------------------- review asim-p04 #1, #14, #15


@pytest.mark.parametrize(
    "check_id, words",
    [
        ("HDR-001", "hsts"),
        ("HDR-002", "content-security-policy"),
        ("HDR-004", "content-type"),
        ("HDR-007", "server"),
        ("CKI-001", "httponly"),
        ("CKI-002", "secure"),
        ("INF-002", "directory"),
        ("INF-003", ".env"),
        ("INF-004", ".git"),
        ("TLS-005", "redirect"),
    ],
)
def test_shared_ids_keep_the_catalog_meaning(check_id, words):
    # A check_id means the same check in checks.yaml, the catalog, chains and stored findings.
    from app.core.checks.catalog import CATALOG

    spec = CHECKS[check_id]
    assert words in (spec.title or "").lower() and words in CATALOG[check_id].name.lower()
    assert spec.category is CATALOG[check_id].category


def _body(text: str) -> ResponseInfo:
    return ResponseInfo("https://shop.example.com/x", 200, "text/plain", {}, text)


def test_env_exposure_needs_several_key_value_lines():
    env = CHECKS["INF-003"].http_condition
    assert env.matches(_body("APP_ENV=production\nDB_HOST=10.0.3.17\nDB_PASSWORD=x\n"))
    assert not env.matches(_body("<p>Set\nDEBUG=false in your config.</p>"))


def test_stack_trace_needs_a_real_trace():
    trace = CHECKS["API-004"].http_condition
    assert trace.matches(_body('Traceback (most recent call last):\n  File "app.py", line 3'))
    assert trace.matches(
        _body(
            "Error: boom\n    at handler (/srv/app.js:10:5)\n"
            "    at next (/srv/node_modules/express/lib/router.js:3:7)\n"
        )
    )
    assert not trace.matches(_body("function f(){ return init(config) } // look at init(config)"))
