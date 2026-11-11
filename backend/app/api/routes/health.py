"""Health and liveness endpoint.

Reports service metadata plus a best-effort liveness probe for PostgreSQL and
Redis. Dependency failures are reported per-dependency rather than crashing the
endpoint, so the frontend can show partial-availability states.
"""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app import __version__
from app.api.schemas.health import HealthResponse
from app.config import settings
from app.db.session import engine
from app.utils.logging import get_logger

router = APIRouter(tags=["health"])
logger = get_logger(__name__)


async def _check_database() -> str:
    """Return 'ok' if the database answers, else the error."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return "ok"
    except Exception as exc:  # noqa: BLE001 - liveness must not raise
        logger.warning("database healthcheck failed: %s", exc)
        return "unavailable"


async def _check_redis() -> str:
    """Return 'ok' if Redis answers, else the error."""
    try:
        # Imported lazily so the app still starts if redis isn't installed yet.
        from redis.asyncio import from_url

        client = from_url(settings.REDIS_URL)
        try:
            await client.ping()
            return "ok"
        finally:
            await client.aclose()
    except Exception as exc:  # noqa: BLE001
        logger.warning("redis healthcheck failed: %s", exc)
        return "unavailable"


# ``/health`` is the conventional probe path (Docker healthcheck, uptime
# monitors); ``/api/health`` is what the frontend calls. Same handler.
@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service health and dependency liveness",
)
@router.get(
    "/api/health",
    response_model=HealthResponse,
    summary="Service health and dependency liveness",
)
async def health() -> HealthResponse:
    """Return service status and dependency liveness."""
    deps = {
        "database": await _check_database(),
        "redis": await _check_redis(),
    }
    overall = "ok" if all(v == "ok" for v in deps.values()) else "degraded"
    return HealthResponse(
        status=overall,
        service="cawasma-backend",
        version=__version__,
        environment=settings.ENVIRONMENT,
        dependencies=deps,
    )
