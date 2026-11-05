"""HSTS checks (reference implementation; docs/adding-a-check.md).

* ``HDR-001`` Missing HSTS
* ``TLS-009`` Weak HSTS Policy (short max-age or no includeSubDomains)

Both fire exactly when their ``http_condition`` in config/checks.yaml holds;
the code only adds what the spec format can't say (HSTS is meaningful on
HTTPS responses only, as the spec descriptions state) and builds evidence.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from app.core.checks.registry import RawFinding, condition_matches, register_check
from app.core.contracts import EndpointInfo
from app.core.engine import ScanResponse

_HEADER = "strict-transport-security"
_MAX_AGE = re.compile(r"(?i)max-age\s*=\s*\"?(\d+)")


def _is_https(resp: ScanResponse) -> bool:
    return resp.ok and urlparse(resp.final_url).scheme == "https"


def _hsts_evidence(resp: ScanResponse) -> dict[str, Any]:
    value = resp.headers.get(_HEADER)
    if value is None:
        return {"header": "Strict-Transport-Security", "present": False}
    match = _MAX_AGE.search(value)
    return {
        "header": "Strict-Transport-Security",
        "value": value,
        "max_age": int(match.group(1)) if match else None,
        "include_subdomains": "includesubdomains" in value.lower(),
    }


@register_check("HDR-001")
def missing_hsts(resp: ScanResponse, endpoint: EndpointInfo) -> list[RawFinding]:
    if not _is_https(resp) or not condition_matches("HDR-001", resp):
        return []
    return [
        RawFinding(
            "HDR-001",
            endpoint,
            {
                "text": f"Missing Strict-Transport-Security on {endpoint.path}",
                **_hsts_evidence(resp),
            },
        )
    ]


@register_check("TLS-009")
def weak_hsts(resp: ScanResponse, endpoint: EndpointInfo) -> list[RawFinding]:
    if not _is_https(resp) or not condition_matches("TLS-009", resp):
        return []
    evidence = _hsts_evidence(resp)
    reasons = []
    if evidence.get("max_age") is not None and evidence["max_age"] < 1_000_000:
        reasons.append(f"max-age={evidence['max_age']} is short")
    if not evidence.get("include_subdomains"):
        reasons.append("includeSubDomains is missing")
    return [
        RawFinding(
            "TLS-009",
            endpoint,
            {
                "text": f"Weak Strict-Transport-Security on {endpoint.path}: {'; '.join(reasons)}",
                **evidence,
            },
        )
    ]
