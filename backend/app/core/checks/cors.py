"""CORS checks COR-001..COR-005.

These read the CORS response to a probe request carrying a test Origin header;
the pipeline performs that probe and populates ``ctx.cors_*``.

COR-002 and COR-003 moved to ``checks/spec/cors.py``.
"""

from __future__ import annotations

from app.core.checks.base import CheckContext, RawFinding, make, rule


@rule
def cor_001_wildcard(ctx: CheckContext) -> RawFinding | None:
    """COR-001: CORS allows any origin (*)."""
    if ctx.cors_acao == "*":
        return make("COR-001", "Access-Control-Allow-Origin is '*'.")
    return None


@rule
def cor_004_unsafe_methods(ctx: CheckContext) -> RawFinding | None:
    """COR-004: unsafe methods allowed cross-origin."""
    methods = (ctx.cors_methods or "").upper()
    if any(m in methods for m in ("PUT", "DELETE", "PATCH")) and ctx.cors_acao:
        return make("COR-004", f"Cross-origin unsafe methods allowed: {methods}.")
    return None


@rule
def cor_005_max_age(ctx: CheckContext) -> RawFinding | None:
    # Max-Age only exists on preflight responses, so judge the preflight probe
    # (and only when it shows CORS in use), never the GET response.
    """COR-005: CORS preflight has no max-age."""
    if ctx.cors_preflight_acao and not ctx.cors_max_age:
        return make("COR-005", "CORS enabled without Access-Control-Max-Age.")
    return None
