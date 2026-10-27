"""Security-header checks (Mozilla Observatory-style, conditions from checks.yaml).

* ``HDR-002`` Missing Content-Security-Policy
* ``HDR-013`` Unsafe Content-Security-Policy ('unsafe-inline' / 'unsafe-eval')
* ``HDR-003`` Missing or weak X-Frame-Options
* ``HDR-014`` CSP without frame-ancestors
* ``HDR-004`` Missing or weak X-Content-Type-Options
* ``HDR-005`` Missing or weak Referrer-Policy
* ``HDR-006`` Missing Permissions-Policy
* ``HDR-007`` Server version banner
* ``HDR-008`` Framework version banner (X-Powered-By, X-AspNet[Mvc]-Version)

Like Observatory, each check judges the headers of a response the server
actually returned (no response, no finding); when it fires is exactly the
spec's ``http_condition``. Header names are case-insensitive and values are
compared case-insensitively unless a rule says otherwise (``NOSNIFF`` passes
HDR-004, as in Observatory). Evidence carries the header's value, redacted.
"""
from __future__ import annotations

from app.core.checks.registry import CheckFn, RawFinding, condition_matches, register_check
from app.core.contracts import EndpointInfo
from app.core.engine import ScanResponse
from app.utils.redaction import redact_header

# check_id -> (headers to show as evidence, summary)
_CHECKS: dict[str, tuple[tuple[str, ...], str]] = {
    "HDR-002": (("Content-Security-Policy",), "Missing Content-Security-Policy"),
    "HDR-013": (("Content-Security-Policy",), "Content-Security-Policy allows unsafe script"),
    "HDR-003": (("X-Frame-Options",), "Missing or weak X-Frame-Options"),
    "HDR-014": (("Content-Security-Policy",), "No CSP frame-ancestors directive"),
    "HDR-004": (("X-Content-Type-Options",), "Missing or weak X-Content-Type-Options"),
    "HDR-005": (("Referrer-Policy",), "Missing or weak Referrer-Policy"),
    "HDR-006": (("Permissions-Policy",), "Missing Permissions-Policy"),
    "HDR-007": (("Server",), "Server header discloses a version"),
    "HDR-008": (("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"),
                "Framework version disclosed"),
}


def _make(check_id: str, headers: tuple[str, ...], summary: str) -> CheckFn:
    def check(resp: ScanResponse, endpoint: EndpointInfo) -> list[RawFinding]:
        if not resp.ok or not condition_matches(check_id, resp):
            return []
        seen = {h: resp.headers.get(h.lower()) for h in headers}
        return [RawFinding(check_id, endpoint, {
            "text": f"{summary} on {endpoint.path}",
            "headers": {h: redact_header(h, v) if v is not None else None
                        for h, v in seen.items()},
        })]

    check.__name__ = f"{check_id.lower().replace('-', '_')}_header"
    return register_check(check_id)(check)


for _check_id, (_headers, _summary) in _CHECKS.items():
    _make(_check_id, _headers, _summary)
