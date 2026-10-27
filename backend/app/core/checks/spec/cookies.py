"""Session-cookie flag checks (conditions from checks.yaml).

* ``CKI-001`` session cookie without HttpOnly
* ``CKI-002`` session cookie without Secure
* ``CKI-003`` session cookie without SameSite

The spec conditions test one ``Set-Cookie`` header. The engine folds repeated
headers, so each cookie the response sets is evaluated on its own (one finding
per offending cookie, as Observatory reports per cookie). Evidence carries the
cookie's name and flags, never its value (CLAUDE.md: cookies store metadata).
"""
from __future__ import annotations

from app.core.checks.registry import CheckFn, RawFinding, condition_matches, register_check
from app.core.contracts import EndpointInfo
from app.core.engine import ScanResponse

_CHECKS = {
    "CKI-001": ("HttpOnly", "Session cookie without HttpOnly"),
    "CKI-002": ("Secure", "Session cookie without Secure"),
    "CKI-003": ("SameSite", "Session cookie without SameSite"),
}


def cookie_metadata(raw: str) -> dict[str, object]:
    """Name and attributes of a Set-Cookie value; the value itself is dropped."""
    first, *attrs = [p.strip() for p in raw.split(";")]
    flags = {a.split("=", 1)[0].strip().lower(): (a.split("=", 1)[1].strip() if "=" in a else True)
             for a in attrs if a}
    return {"name": first.split("=", 1)[0].strip(), "http_only": "httponly" in flags,
            "secure": "secure" in flags, "same_site": flags.get("samesite")}


def _make(check_id: str, flag: str, summary: str) -> CheckFn:
    def check(resp: ScanResponse, endpoint: EndpointInfo) -> list[RawFinding]:
        if not resp.ok:
            return []
        out = []
        for raw in resp.set_cookie_headers:
            if condition_matches(check_id, resp, headers={"set-cookie": raw}):
                meta = cookie_metadata(raw)
                out.append(RawFinding(check_id, endpoint, {
                    "text": f"{summary}: '{meta['name']}' on {endpoint.path}",
                    "cookie": meta, "missing": flag,
                }))
        return out

    check.__name__ = f"{check_id.lower().replace('-', '_')}_cookie"
    return register_check(check_id)(check)


for _check_id, (_flag, _summary) in _CHECKS.items():
    _make(_check_id, _flag, _summary)
