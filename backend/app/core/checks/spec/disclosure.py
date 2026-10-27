"""Body-based disclosure checks (conditions from checks.yaml).

* ``API-004`` stack trace in the response body
* ``INF-002`` automatically generated directory listing
* ``INF-007`` verbose / development error page (or an X-Debug-Token header)

Evidence is a short excerpt around the first match, passed through
``utils/redaction.py`` (a trace or debug page may quote secrets).
"""
from __future__ import annotations

import re

from app.core.checks.registry import (
    CheckFn,
    RawFinding,
    condition_matches,
    register_check,
    spec_for,
)
from app.core.contracts import EndpointInfo
from app.core.engine import ScanResponse
from app.core.specs import BodyRule
from app.utils.redaction import redact_text

_CHECKS = {
    "API-004": "Stack trace in the response",
    "INF-002": "Directory listing",
    "INF-007": "Verbose error or debug output",
}
_EXCERPT = 160


def excerpt(check_id: str, body: str) -> str | None:
    """Redacted text around the first match of the spec's body regex."""
    for rule in spec_for(check_id).http_condition.rules:
        if isinstance(rule, BodyRule) and rule.body == "matches":
            m = re.search(rule.value, body)
            if m:
                start = max(0, m.start() - 40)
                text = " ".join(body[start:start + _EXCERPT].split())
                return redact_text(text)
    return None


def _make(check_id: str, summary: str) -> CheckFn:
    def check(resp: ScanResponse, endpoint: EndpointInfo) -> list[RawFinding]:
        if not resp.ok or not condition_matches(check_id, resp):
            return []
        evidence: dict[str, object] = {"text": f"{summary} on {endpoint.path}",
                                       "status": resp.status_code}
        snippet = excerpt(check_id, resp.body)
        if snippet:
            evidence["excerpt"] = snippet
        if resp.headers.get("x-debug-token") is not None:
            evidence["header"] = "X-Debug-Token"
        return [RawFinding(check_id, endpoint, evidence)]

    check.__name__ = f"{check_id.lower().replace('-', '_')}_body"
    return register_check(check_id)(check)


for _check_id, _summary in _CHECKS.items():
    _make(_check_id, _summary)
