"""``TLS-005`` HTTP does not redirect to HTTPS (scope: target_root).

The spec's limitation: judge the explicitly issued plain-HTTP probe of the
target root, before any redirect is followed, and never an HTTPS response. The
pipeline sends that probe once per host (``fetch(http://host/,
follow_redirects=False)``) and runs the ``target_root`` checks on it.
"""
from __future__ import annotations

from urllib.parse import urlparse

from app.core.checks.registry import RawFinding, condition_matches, register_check
from app.core.contracts import EndpointInfo
from app.core.engine import ScanResponse


@register_check("TLS-005")
def http_does_not_redirect(resp: ScanResponse, endpoint: EndpointInfo) -> list[RawFinding]:
    if (urlparse(resp.requested_url).scheme != "http" or resp.status_code is None
            or not condition_matches("TLS-005", resp)):
        return []
    return [RawFinding("TLS-005", endpoint, {
        "text": f"HTTP request to {resp.requested_url} is not redirected (status "
                f"{resp.status_code})",
        "status": resp.status_code,
        "location": resp.headers.get("location"),
    })]
