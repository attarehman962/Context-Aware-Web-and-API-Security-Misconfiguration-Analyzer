"""The test pattern every spec check follows (docs/adding-a-check.md).

    def test_hdr001_fires():
        assert_fires("HDR-001", response(headers={}))

    def test_hdr001_no_fire():
        hsts = {"Strict-Transport-Security": "max-age=31536000"}
        assert_no_fire("HDR-001", response(headers=hsts))

``tests/checks/test_check_tests.py`` fails if a registered check has no
``assert_fires`` or no ``assert_no_fire`` call.
"""
from __future__ import annotations

from app.core.checks import registry
from app.core.checks.registry import RawFinding
from app.core.contracts import EndpointInfo
from app.core.engine import ScanResponse

URL = "https://shop.example.com/account"


def response(url: str = URL, *, status: int = 200, headers: dict[str, str] | None = None,
             body: str = "", method: str = "GET", content_type: str = "text/html",
             cookies: list[str] | None = None,
             request_headers: dict[str, str] | None = None) -> ScanResponse:
    """A normalised response, as the engine returns it (headers lowercased).

    ``cookies`` are separate Set-Cookie headers (the engine keeps each one);
    ``request_headers`` are what the engine sent (e.g. the CORS probe Origin).
    """
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    if cookies:
        hdrs["set-cookie"] = cookies[-1]          # folded, as in a dict of headers
    return ScanResponse(requested_url=url, final_url=url, method=method, status_code=status,
                        headers=hdrs, body=body, content_type=content_type,
                        set_cookie_headers=list(cookies or []),
                        request_headers=dict(request_headers or {}))


def endpoint(url: str = URL) -> EndpointInfo:
    from urllib.parse import urlparse

    return EndpointInfo(url=url, path=urlparse(url).path or "/")


def _run(check_id: str, resp: ScanResponse, ep: EndpointInfo | None) -> list[RawFinding]:
    registry.load_implementations()
    assert check_id in registry.CHECKS, f"{check_id} is not registered"
    return registry.CHECKS[check_id](resp, ep or endpoint(resp.requested_url))


def assert_fires(check_id: str, resp: ScanResponse,
                 ep: EndpointInfo | None = None) -> list[RawFinding]:
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
