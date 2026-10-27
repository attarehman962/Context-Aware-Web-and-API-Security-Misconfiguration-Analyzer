"""Legacy header checks HDR-009..HDR-012 (spec section 13).

HDR-001..HDR-008 moved to the spec registry (``checks/spec/hsts.py``,
``checks/spec/security_headers.py``).
"""
from __future__ import annotations

from app.core.checks.base import CheckContext, RawFinding, make, rule
from app.db.models.enums import ContextClass


def _missing(ctx: CheckContext, header: str) -> bool:
    return not ctx.has_header(header)


@rule
def hdr_009_coop(ctx: CheckContext) -> RawFinding | None:
    if _missing(ctx, "Cross-Origin-Opener-Policy"):
        return make("HDR-009", "Response has no Cross-Origin-Opener-Policy header.")
    return None


@rule
def hdr_010_corp(ctx: CheckContext) -> RawFinding | None:
    if _missing(ctx, "Cross-Origin-Resource-Policy"):
        return make("HDR-010", "Response has no Cross-Origin-Resource-Policy header.")
    return None


@rule
def hdr_011_cache(ctx: CheckContext) -> RawFinding | None:
    # Only relevant for sensitive endpoints.
    if ctx.context_class in (ContextClass.HIGH, ContextClass.CRITICAL):
        cc = (ctx.header("Cache-Control") or "").lower()
        if "no-store" not in cc:
            return make("HDR-011", f"Sensitive endpoint Cache-Control: '{cc or 'absent'}'.")
    return None


@rule
def hdr_012_expect_ct(ctx: CheckContext) -> RawFinding | None:
    # Legacy/informational: only when HSTS present but no CT signalling.
    if ctx.has_header("Strict-Transport-Security") and _missing(ctx, "Expect-CT"):
        return make("HDR-012", "No Expect-CT header (legacy CT signalling absent).")
    return None
