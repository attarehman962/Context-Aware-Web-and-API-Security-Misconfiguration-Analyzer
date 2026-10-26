"""CORS checks COR-001..COR-005 (spec section 13).

These read the CORS response to a probe request carrying a test Origin header;
the pipeline performs that probe and populates ``ctx.cors_*``.
"""
from __future__ import annotations

from app.core.checks.base import CheckContext, RawFinding, make, rule


@rule
def cor_001_wildcard(ctx: CheckContext) -> RawFinding | None:
    if ctx.cors_acao == "*":
        return make("COR-001", "Access-Control-Allow-Origin is '*'.")
    return None


@rule
def cor_002_reflection(ctx: CheckContext) -> RawFinding | None:
    # Server echoed our probe origin back -> arbitrary origins allowed.
    if ctx.cors_acao and ctx.cors_acao == ctx.probe_origin:
        return make("COR-002", f"Origin reflected: ACAO echoed '{ctx.cors_acao}'.")
    return None


@rule
def cor_003_credentials(ctx: CheckContext) -> RawFinding | None:
    acac = (ctx.cors_acac or "").lower() == "true"
    weak_origin = ctx.cors_acao == "*" or ctx.cors_acao == ctx.probe_origin
    if acac and weak_origin:
        return make("COR-003", "Allow-Credentials: true combined with weak origin.")
    return None


@rule
def cor_004_unsafe_methods(ctx: CheckContext) -> RawFinding | None:
    methods = (ctx.cors_methods or "").upper()
    if any(m in methods for m in ("PUT", "DELETE", "PATCH")) and ctx.cors_acao:
        return make("COR-004", f"Cross-origin unsafe methods allowed: {methods}.")
    return None


@rule
def cor_005_max_age(ctx: CheckContext) -> RawFinding | None:
    # Max-Age only exists on preflight responses, so judge the preflight probe
    # (and only when it shows CORS in use), never the GET response.
    if ctx.cors_preflight_acao and not ctx.cors_max_age:
        return make("COR-005", "CORS enabled without Access-Control-Max-Age.")
    return None
