"""CORS checks, judged on the scanner's CORS preflight (OPTIONS + Origin).

* ``COR-003`` Access-Control-Allow-Origin: * together with Allow-Credentials: true
* ``COR-002`` the server reflects the probe's Origin

COR-002's spec limitation: presence of the header is not evidence; the engine
sends a unique untrusted Origin and the check fires only when the response
names **exactly** that Origin. ``*`` is not a reflection (COR-003 covers the
credentialed wildcard).
"""
from __future__ import annotations

from app.core.checks.registry import RawFinding, condition_matches, register_check
from app.core.contracts import EndpointInfo
from app.core.engine import ScanResponse


def _acao(resp: ScanResponse) -> str | None:
    return resp.headers.get("access-control-allow-origin")


@register_check("COR-003")
def cors_wildcard_with_credentials(resp: ScanResponse, endpoint: EndpointInfo
                                   ) -> list[RawFinding]:
    if not resp.ok or not condition_matches("COR-003", resp):
        return []
    return [RawFinding("COR-003", endpoint, {
        "text": f"Allow-Origin * with Allow-Credentials: true on {endpoint.path}",
        "allow_origin": _acao(resp),
        "allow_credentials": resp.headers.get("access-control-allow-credentials"),
    })]


@register_check("COR-002")
def cors_reflected_origin(resp: ScanResponse, endpoint: EndpointInfo) -> list[RawFinding]:
    sent = next((v for k, v in resp.request_headers.items() if k.lower() == "origin"), None)
    if (not resp.ok or sent is None or not condition_matches("COR-002", resp)
            or (_acao(resp) or "").strip() != sent):
        return []
    return [RawFinding("COR-002", endpoint, {
        "text": f"Origin {sent} reflected in Access-Control-Allow-Origin on {endpoint.path}",
        "origin_sent": sent, "allow_origin": _acao(resp),
        "allow_credentials": resp.headers.get("access-control-allow-credentials"),
    })]
