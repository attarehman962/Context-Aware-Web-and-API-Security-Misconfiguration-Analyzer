"""REST API checks API-001..API-014 (spec section 13).

Several of these cannot be confirmed in unauthenticated black-box mode (BOLA,
mass assignment, JWT internals). Those fire only on a genuine surface signal and
always carry a ``limitation`` note (spec section 47).

API-004 moved to ``checks/spec/disclosure.py``.
"""
from __future__ import annotations

import re

from app.core.checks.base import CheckContext, RawFinding, make, rule

_STACK_TRACE = re.compile(
    r"(Traceback \(most recent call last\)|Exception in thread|"
    r"at [a-zA-Z0-9_.]+\([A-Za-z0-9_]+\.java:\d+\)|"
    r"SQL syntax|ORA-\d{5}|System\.\w+Exception|stack trace)",
    re.IGNORECASE,
)
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


def _is_api(ctx: CheckContext) -> bool:
    return "/api" in ctx.path or "json" in (ctx.result.content_type or "").lower()


@rule
def api_001_rate_limit(ctx: CheckContext) -> RawFinding | None:
    # The pipeline records whether a bounded burst ever saw a 429/Retry-After.
    # Here we only flag API endpoints lacking any rate-limit headers.
    if _is_api(ctx) and ctx.result.status_code == 200:
        if not (ctx.has_header("RateLimit-Limit") or ctx.has_header("X-RateLimit-Limit")
                or ctx.has_header("Retry-After")):
            return make("API-001", "No rate-limit headers observed on API endpoint.")
    return None


@rule
def api_002_trace(ctx: CheckContext) -> RawFinding | None:
    if "TRACE" in {m.upper() for m in ctx.allowed_methods}:
        return make("API-002", "TRACE method is enabled (from Allow/OPTIONS).")
    return None


@rule
def api_003_unauth_data(ctx: CheckContext) -> RawFinding | None:
    if _is_api(ctx) and ctx.result.status_code == 200:
        body = ctx.result.body
        if re.search(r'"\w+"\s*:\s*\[', body) or '"data"' in body or '"users"' in body:
            return make("API-003", "API returned a data collection without authentication.")
    return None


@rule
def api_005_mass_assignment(ctx: CheckContext) -> RawFinding | None:
    # Surface signal only: a writable object endpoint exposing many fields.
    if _is_api(ctx) and ctx.result.status_code == 200 and (
        '"role"' in ctx.result.body or '"is_admin"' in ctx.result.body
        or '"isAdmin"' in ctx.result.body
    ):
        return make("API-005", "Object exposes privilege fields (role/is_admin).")
    return None


@rule
def api_006_bola(ctx: CheckContext) -> RawFinding | None:
    # Numeric object id in an API path is a BOLA/IDOR surface indicator.
    if _is_api(ctx) and re.search(r"/\d+(?:/|$)", ctx.path):
        return make("API-006", f"Numeric object identifier in path: {ctx.path}")
    return None


@rule
def api_007_versioning(ctx: CheckContext) -> RawFinding | None:
    if "/api" in ctx.path and not re.search(r"/v\d+", ctx.path):
        return make("API-007", f"API path is unversioned: {ctx.path}")
    return None


@rule
def api_008_deprecated(ctx: CheckContext) -> RawFinding | None:
    if ctx.has_header("Deprecation") or ctx.has_header("Sunset"):
        return make("API-008", "Endpoint advertises Deprecation/Sunset header.")
    return None


@rule
def api_009_options_methods(ctx: CheckContext) -> RawFinding | None:
    methods = {m.upper() for m in ctx.allowed_methods}
    if len(methods) >= 5:
        return make("API-009", f"OPTIONS exposes many methods: {sorted(methods)}")
    return None


@rule
def api_010_jwt(ctx: CheckContext) -> RawFinding | None:
    auth = ctx.header("Authorization") or ""
    if _JWT.search(auth) or _JWT.search(ctx.result.body):
        return make("API-010", "JWT observed; verify signing algorithm and validation.")
    return None


@rule
def api_011_overfetch(ctx: CheckContext) -> RawFinding | None:
    # Heuristic: very large JSON object counts many keys.
    if _is_api(ctx) and ctx.result.status_code == 200:
        if ctx.result.body.count('":') > 40:
            return make("API-011", "API response returns a large number of fields.")
    return None


@rule
def api_012_graphql(ctx: CheckContext) -> RawFinding | None:
    if ctx.graphql_introspection or "__schema" in ctx.result.body:
        return make("API-012", "GraphQL introspection appears enabled.")
    return None


@rule
def api_013_secrets(ctx: CheckContext) -> RawFinding | None:
    if ctx.body_class and ctx.body_class.credentials:
        return make("API-013", "Credential-like secret detected in response body.")
    return None


@rule
def api_014_injection(ctx: CheckContext) -> RawFinding | None:
    if ctx.injection_error_reflected:
        return make("API-014", "Benign probe caused an error to be reflected.")
    return None
