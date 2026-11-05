"""Exposure checks whose specs use the applies_to / artifact blocks (checks.yaml).

* ``API-001`` authentication endpoint without rate-limit headers (indicator)
* ``API-003`` sensitive endpoint returns JSON data without credentials
* ``INF-003`` .env file, ``INF-004`` .git metadata, ``INF-005`` backup or archive

Which endpoints each one judges (sensitivity, auth endpoint, artifact path,
soft-404, passive mode) is decided by the registry from the spec before these
run; here only http_condition and the evidence. Evidence never holds a value
from the file: INF-003 lists variable names only.
"""

from __future__ import annotations

import json
import re

from app.core.checks.registry import RawFinding, condition_matches, register_check
from app.core.contracts import EndpointInfo
from app.core.engine import ScanResponse

_ENV_NAME = re.compile(r"(?m)^([A-Z][A-Z0-9_]*)=")


def _fires(check_id: str, resp: ScanResponse) -> bool:
    return resp.ok and condition_matches(check_id, resp)


@register_check("API-001")
def auth_without_rate_limit_headers(resp: ScanResponse, ep: EndpointInfo) -> list[RawFinding]:
    if not _fires("API-001", resp):
        return []
    text = f"No RateLimit-*, X-RateLimit-* or Retry-After header on {ep.path}"
    return [RawFinding("API-001", ep, {"text": text, "status": resp.status_code})]


@register_check("API-003")
def sensitive_data_without_credentials(resp: ScanResponse, ep: EndpointInfo) -> list[RawFinding]:
    if not _fires("API-003", resp):
        return []
    data = json.loads(resp.body)
    size = f"{len(data)} {'items' if isinstance(data, list) else 'fields'}"
    text = f"{ep.path} returned JSON ({size}) to a request without credentials"
    return [RawFinding("API-003", ep, {"text": text, "status": resp.status_code})]


@register_check("INF-003")
def env_file(resp: ScanResponse, ep: EndpointInfo) -> list[RawFinding]:
    if not _fires("INF-003", resp):
        return []
    names = list(dict.fromkeys(_ENV_NAME.findall(resp.body)))
    text = f"{ep.path} serves {len(names)} environment variable(s); values not stored"
    return [RawFinding("INF-003", ep, {"text": text, "variables": names[:20]})]


@register_check("INF-004")
def git_metadata(resp: ScanResponse, ep: EndpointInfo) -> list[RawFinding]:
    if not _fires("INF-004", resp):
        return []
    text = f"Git metadata readable at {ep.path}"
    return [RawFinding("INF-004", ep, {"text": text, "status": resp.status_code})]


@register_check("INF-005")
def backup_file(resp: ScanResponse, ep: EndpointInfo) -> list[RawFinding]:
    if not _fires("INF-005", resp):
        return []
    size = resp.content_length or len(resp.body)
    text = f"Backup or archive served at {ep.path} ({size} bytes)"
    return [
        RawFinding("INF-005", ep, {"text": text, "content_type": resp.content_type, "bytes": size})
    ]
