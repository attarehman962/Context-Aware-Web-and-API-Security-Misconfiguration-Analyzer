"""Information-disclosure checks INF-001..INF-006.

INF-002 moved to ``checks/spec/disclosure.py``; INF-003..005 to
``checks/spec/exposure.py``.
"""

from __future__ import annotations

from app.core.checks.base import CheckContext, RawFinding, make, rule


@rule
def inf_001_internal_ip(ctx: CheckContext) -> RawFinding | None:
    if ctx.body_class and ctx.body_class.internal_ip:
        return make("INF-001", "Response body contains an internal/private IP address.")
    return None


@rule
def inf_006_swagger(ctx: CheckContext) -> RawFinding | None:
    body = ctx.result.body[:4000].lower()
    if ctx.result.status_code == 200 and (
        "swagger" in body or '"openapi"' in body or "swagger-ui" in ctx.path.lower()
    ):
        return make("INF-006", "Public API documentation (Swagger/OpenAPI) exposed.")
    return None
