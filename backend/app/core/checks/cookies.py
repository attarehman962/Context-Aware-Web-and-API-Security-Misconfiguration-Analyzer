"""Cookie checks CKI-001..CKI-006 (spec section 13)."""
from __future__ import annotations

from app.core.checks.base import CheckContext, RawFinding, make, query_names, rule

_TOKEN_PARAMS = {"token", "sid", "session", "sessionid", "sessid", "jsessionid",
                 "phpsessid", "auth", "jwt", "access_token", "id_token", "auth_token"}


def _parse_cookie(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0] if parts and "=" in parts[0] else parts[0]
    value = parts[0].split("=", 1)[1] if parts and "=" in parts[0] else ""
    attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else True)
             for p in parts[1:]}
    return {"name": name, "value": value, "attrs": attrs}


@rule
def cki_001_httponly(ctx: CheckContext) -> RawFinding | None:
    for raw in ctx.result.set_cookie_headers:
        c = _parse_cookie(raw)
        if "httponly" not in c["attrs"]:
            return make("CKI-001", f"Cookie '{c['name']}' lacks HttpOnly.")
    return None


@rule
def cki_002_secure(ctx: CheckContext) -> RawFinding | None:
    for raw in ctx.result.set_cookie_headers:
        c = _parse_cookie(raw)
        if "secure" not in c["attrs"]:
            return make("CKI-002", f"Cookie '{c['name']}' lacks Secure.")
    return None


@rule
def cki_003_samesite(ctx: CheckContext) -> RawFinding | None:
    for raw in ctx.result.set_cookie_headers:
        c = _parse_cookie(raw)
        if "samesite" not in c["attrs"]:
            return make("CKI-003", f"Cookie '{c['name']}' lacks SameSite.")
    return None


@rule
def cki_004_token_in_url(ctx: CheckContext) -> RawFinding | None:
    # Whole parameter names: "author=" or "inside=" are not session tokens.
    for name in sorted(query_names(ctx.url)):
        if name in _TOKEN_PARAMS or name.endswith(("_token", "-token", "sessionid", "sessid")):
            return make("CKI-004", f"URL query appears to carry a session token ({name}).")
    return None


@rule
def cki_005_scope(ctx: CheckContext) -> RawFinding | None:
    for raw in ctx.result.set_cookie_headers:
        c = _parse_cookie(raw)
        domain = c["attrs"].get("domain")
        if isinstance(domain, str) and domain.startswith("."):
            return make("CKI-005", f"Cookie '{c['name']}' scoped broadly to {domain}.")
        if c["attrs"].get("path") == "/" and domain:
            return make("CKI-005", f"Cookie '{c['name']}' path='/' with explicit domain.")
    return None


@rule
def cki_006_entropy(ctx: CheckContext) -> RawFinding | None:
    for raw in ctx.result.set_cookie_headers:
        c = _parse_cookie(raw)
        name = c["name"].lower()
        if any(k in name for k in ("sess", "sid", "token", "auth")):
            if len(c["value"]) < 16:  # heuristic entropy floor
                return make("CKI-006", f"Session cookie '{c['name']}' value is short "
                                        f"({len(c['value'])} chars).")
    return None
