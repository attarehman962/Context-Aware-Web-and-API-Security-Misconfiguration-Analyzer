"""The test pattern every spec check follows (docs/adding-a-check.md).

    def test_hdr001_fires():
        assert_fires("HDR-001", response(headers={}))

    def test_hdr001_no_fire():
        hsts = {"Strict-Transport-Security": "max-age=31536000"}
        assert_no_fire("HDR-001", response(headers=hsts))

``tests/checks/test_check_tests.py`` fails if a registered check has no
``assert_fires`` or no ``assert_no_fire`` call, or a legacy ``@rule`` no
``assert_rule_fires`` or ``assert_rule_no_fire`` call.
"""

from __future__ import annotations

from typing import Any

from app.core.checks import REGISTRY, CheckContext, registry
from app.core.checks import RawFinding as LegacyFinding
from app.core.checks.base import DetectFn
from app.core.checks.registry import RawFinding
from app.core.contracts import EndpointInfo
from app.core.engine import ScanResponse

URL = "https://shop.example.com/account"


def response(
    url: str = URL,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    body: str = "",
    method: str = "GET",
    content_type: str = "text/html",
    cookies: list[str] | None = None,
    request_headers: dict[str, str] | None = None,
) -> ScanResponse:
    """A normalised response, as the engine returns it (headers lowercased).

    ``cookies`` are separate Set-Cookie headers (the engine keeps each one);
    ``request_headers`` are what the engine sent (e.g. the CORS probe Origin).
    """
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    if cookies:
        hdrs["set-cookie"] = cookies[-1]  # folded, as in a dict of headers
    return ScanResponse(
        requested_url=url,
        final_url=url,
        method=method,
        status_code=status,
        headers=hdrs,
        body=body,
        content_type=content_type,
        set_cookie_headers=list(cookies or []),
        request_headers=dict(request_headers or {}),
    )


def endpoint(url: str = URL) -> EndpointInfo:
    from urllib.parse import urlparse

    return EndpointInfo(url=url, path=urlparse(url).path or "/")


def _run(check_id: str, resp: ScanResponse, ep: EndpointInfo | None) -> list[RawFinding]:
    registry.load_implementations()
    assert check_id in registry.CHECKS, f"{check_id} is not registered"
    return registry.CHECKS[check_id](resp, ep or endpoint(resp.requested_url))


def assert_fires(
    check_id: str, resp: ScanResponse, ep: EndpointInfo | None = None
) -> list[RawFinding]:
    """The check fires on this (vulnerable) response, with well-formed findings."""
    found = _run(check_id, resp, ep)
    assert found, f"{check_id} did not fire"
    for f in found:
        assert f.check_id == check_id
        assert f.endpoint.url == (ep.url if ep else resp.requested_url)
        assert isinstance(f.evidence.get("text"), str) and f.evidence["text"], "evidence.text"
    return found


def assert_no_fire(check_id: str, resp: ScanResponse, ep: EndpointInfo | None = None) -> None:
    """The check stays silent on this (secure) response."""
    found = _run(check_id, resp, ep)
    assert not found, f"{check_id} fired unexpectedly: {found}"


# Legacy rules
# Legacy ``@rule`` checks read a CheckContext instead; same pattern:
#     assert_rule_fires("HDR-009", context(headers={}))


def context(
    url: str = URL,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    body: str = "",
    content_type: str = "text/html",
    cookies: list[str] | None = None,
    **signals: Any,
) -> CheckContext:
    """What the pipeline hands a legacy rule; ``signals`` are the probe fields
    (``allowed_methods``, ``cors_acao``, ``tls``, ``context_class``, ...)."""
    from urllib.parse import urlparse

    resp = response(
        url, status=status, headers=headers, body=body, content_type=content_type, cookies=cookies
    )
    return CheckContext(url=url, path=urlparse(url).path or "/", result=resp, **signals)


def legacy_rule_id(fn: DetectFn) -> str:
    """``api_001_rate_limit`` -> ``API-001``."""
    prefix, number = fn.__name__.split("_")[:2]
    return f"{prefix.upper()}-{number}"


def _legacy(rule_id: str) -> DetectFn:
    rules = [fn for fn in REGISTRY if legacy_rule_id(fn) == rule_id]
    assert len(rules) == 1, f"{rule_id} is not a legacy rule"
    return rules[0]


def assert_rule_fires(rule_id: str, ctx: CheckContext) -> LegacyFinding:
    found = _legacy(rule_id)(ctx)
    assert found is not None, f"{rule_id} did not fire"
    assert found.rule_id == rule_id and found.evidence, "rule id and evidence"
    return found


def assert_rule_no_fire(rule_id: str, ctx: CheckContext) -> None:
    found = _legacy(rule_id)(ctx)
    assert found is None, f"{rule_id} fired unexpectedly: {found.evidence}"
