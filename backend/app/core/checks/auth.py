"""Authentication checks AUT-001..AUT-007 (spec section 13).

Most auth weaknesses require an authenticated session or business-logic flow
and are therefore not fully determinable in black-box mode; those fire only on a
surface indicator and carry a ``limitation`` (spec sections 47-48). CAWASMA
never submits credentials.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from app.core.checks.base import CheckContext, RawFinding, make, query_names, rule

_ADMIN_SEGMENT = re.compile(r"(?i)(?:^|/)admin")
_REDIRECT_PARAMS = {"redirect_uri", "returnurl", "next", "redirect", "return_to"}
_LOGIN_PATHS = ("login", "signin", "admin", "wp-login", "auth")
_DEFAULT_CRED_TECH = ("tomcat", "jenkins", "grafana", "phpmyadmin", "wp-admin")


@rule
def aut_001_basic(ctx: CheckContext) -> RawFinding | None:
    www = (ctx.header("WWW-Authenticate") or "").lower()
    if www.startswith("basic"):
        return make("AUT-001", "Server offers HTTP Basic authentication.")
    return None


@rule
def aut_002_function_level(ctx: CheckContext) -> RawFinding | None:
    # Surface indicator: an admin-ish path that returned 200 unauthenticated.
    # A path segment starting with "admin" (/admin, /administrator), not
    # "/badminton".
    if _ADMIN_SEGMENT.search(ctx.path) and ctx.result.status_code == 200:
        return make("AUT-002", f"Admin path reachable unauthenticated: {ctx.path}")
    return None


@rule
def aut_003_reset_token(ctx: CheckContext) -> RawFinding | None:
    query = (urlparse(ctx.url).query or "").lower()
    if "reset" in ctx.path.lower() and re.search(r"token=[a-z0-9]{1,12}(&|$)", query):
        return make("AUT-003", "Short reset token observed in URL.")
    return None


@rule
def aut_004_logout_invalidation(ctx: CheckContext) -> RawFinding | None:
    # Only a surface indicator: logout endpoint that doesn't clear the cookie.
    if "logout" in ctx.path.lower():
        cleared = any("max-age=0" in c.lower() or "expires=thu, 01 jan 1970" in c.lower()
                      for c in ctx.result.set_cookie_headers)
        if not cleared:
            return make("AUT-004", "Logout endpoint does not appear to clear session cookie.")
    return None


@rule
def aut_005_auth_handling(ctx: CheckContext) -> RawFinding | None:
    body = ctx.result.body.lower()
    if any(p in ctx.path.lower() for p in _LOGIN_PATHS):
        if "no such user" in body or "user not found" in body or "invalid username" in body:
            return make("AUT-005", "Auth response distinguishes users (enumeration risk).")
    return None


@rule
def aut_006_default_creds(ctx: CheckContext) -> RawFinding | None:
    haystack = (ctx.path + " " + (ctx.result.body[:2000] or "")).lower()
    for tech in _DEFAULT_CRED_TECH:
        if tech in haystack:
            return make("AUT-006", f"Login surface for '{tech}' (known default-credential risk).")
    return None


@rule
def aut_007_oauth_redirect(ctx: CheckContext) -> RawFinding | None:
    if query_names(ctx.url) & _REDIRECT_PARAMS:
        return make("AUT-007", "Redirect parameter present; verify allow-listing.")
    return None
