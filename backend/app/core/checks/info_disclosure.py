"""Information-disclosure checks INF-001..INF-006 (spec section 13).

INF-002 moved to ``checks/spec/disclosure.py``.
"""
from __future__ import annotations

from app.core.checks.base import CheckContext, RawFinding, make, rule


@rule
def inf_001_internal_ip(ctx: CheckContext) -> RawFinding | None:
    if ctx.body_class and ctx.body_class.internal_ip:
        return make("INF-001", "Response body contains an internal/private IP address.")
    return None


@rule
def inf_003_env(ctx: CheckContext) -> RawFinding | None:
    if ctx.path.endswith("/.env") and ctx.result.status_code == 200:
        body = ctx.result.body
        if "=" in body and any(k in body.upper() for k in
                               ("SECRET", "KEY", "PASSWORD", "TOKEN", "DB_", "API")):
            return make("INF-003", "Exposed .env with environment variables (values redacted).")
    return None


@rule
def inf_004_git(ctx: CheckContext) -> RawFinding | None:
    if "/.git/" in ctx.path and ctx.result.status_code == 200:
        if ctx.result.body.startswith("ref:") or "[core]" in ctx.result.body:
            return make("INF-004", "Exposed .git repository metadata.")
    return None


@rule
def inf_005_backup(ctx: CheckContext) -> RawFinding | None:
    lowered = ctx.path.lower()
    # An HTML page at /backup.zip is the site's catch-all, not an archive.
    if "html" in (ctx.result.content_type or "").lower():
        return None
    if ctx.result.status_code == 200 and lowered.endswith(
        (".zip", ".tar", ".tar.gz", ".bak", ".sql", ".old", ".backup")
    ):
        return make("INF-005", f"Exposed backup/archive file: {ctx.path}")
    return None


@rule
def inf_006_swagger(ctx: CheckContext) -> RawFinding | None:
    body = ctx.result.body[:4000].lower()
    if ctx.result.status_code == 200 and (
        "swagger" in body or '"openapi"' in body or "swagger-ui" in ctx.path.lower()
    ):
        return make("INF-006", "Public API documentation (Swagger/OpenAPI) exposed.")
    return None
