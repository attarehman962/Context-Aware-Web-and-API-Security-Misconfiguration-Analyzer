"""http_condition evaluation semantics (docs/check-spec-format.md)."""

from __future__ import annotations

import pytest

from app.core.contracts import ResponseInfo
from app.core.specs import HttpCondition

XFO = "X-Frame-Options"


def _resp(headers=None, status=200, body=""):
    return ResponseInfo("https://x.example.com/", status, "text/html", headers or {}, body)


def _cond(*rules, match="all"):
    return HttpCondition.model_validate({"match": match, "rules": list(rules)})


@pytest.mark.parametrize(
    "rule, headers, fires",
    [
        ({"header": XFO, "op": "missing"}, {}, True),
        ({"header": XFO, "op": "missing"}, {XFO.lower(): "DENY"}, False),
        ({"header": XFO, "op": "present"}, {XFO.upper(): "DENY"}, True),
        ({"header": XFO, "op": "equals", "value": "deny"}, {XFO: " DENY "}, True),
        (
            {"header": XFO, "op": "equals", "value": "deny", "case_sensitive": True},
            {XFO: "DENY"},
            False,
        ),
        ({"header": XFO, "op": "not_equals", "value": "DENY"}, {}, False),  # missing
        ({"header": XFO, "op": "not_equals", "value": "DENY"}, {XFO: "x"}, True),
        (
            {"header": "CSP", "op": "contains", "value": "unsafe-inline"},
            {"CSP": "script-src 'UNSAFE-INLINE'"},
            True,
        ),
        (
            {"header": "CSP", "op": "not_contains", "value": "frame-ancestors"},
            {"CSP": "default-src"},
            True,
        ),
        ({"header": "Server", "op": "matches", "value": r"/\d"}, {"Server": "nginx/1.18.0"}, True),
        ({"header": "Server", "op": "matches", "value": r"/\d"}, {}, False),
    ],
)
def test_header_rules(rule, headers, fires):
    assert _cond(rule).matches(_resp(headers)) is fires


def test_status_and_body_rules():
    assert _cond({"status": "in", "value": [200]}).matches(_resp(status=200))
    assert not _cond({"status": "not_in", "value": [301, 302]}).matches(_resp(status=301))
    assert _cond({"body": "contains", "value": "Index of /"}).matches(
        _resp(body="<h1>Index of /</h1>")
    )
    assert _cond({"body": "not_contains", "value": "x"}).matches(_resp(body="abc"))
    assert _cond({"body": "matches", "value": r"Traceback \("}).matches(
        _resp(body="Traceback (most recent call last):")
    )


def test_all_and_any():
    rules = ({"header": "A", "op": "present"}, {"header": "B", "op": "present"})
    only_a = _resp({"A": "1"})
    assert not _cond(*rules, match="all").matches(only_a)
    assert _cond(*rules, match="any").matches(only_a)
