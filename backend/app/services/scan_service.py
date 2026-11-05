"""Scan records: create, dispatch, cancel, fail.

The API layer calls these functions; they own the scan table's database access,
so routes stay thin and the scanner modules stay DB-free. Results are read
through ``contract_service``.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.models import (
    Scan,
    ScanStatus,
)
from app.utils.logging import get_logger
from app.utils.validators import validate_target_url

logger = get_logger(__name__)


def scan_options() -> dict[str, Any]:
    """Snapshot of the limits a new scan runs with (stored on ``scans.options``)."""
    return {
        "max_endpoints": settings.MAX_ENDPOINTS,
        "max_crawl_depth": settings.MAX_CRAWL_DEPTH,
        "max_redirects": settings.MAX_REDIRECTS,
        "max_concurrent_requests": settings.MAX_CONCURRENT_REQUESTS,
        "request_timeout": settings.REQUEST_TIMEOUT,
        "max_response_size": settings.MAX_RESPONSE_SIZE,
        "rate_limit_probe_count": settings.RATE_LIMIT_PROBE_COUNT,
        "llm_enabled": settings.LLM_ENABLED,
    }


async def create_scan(
    session: AsyncSession, target_url: str, *, authorization_confirmed: bool = False,
    options: dict[str, Any] | None = None, dispatch: bool = True,
) -> Scan:
    """Validate the target and create a QUEUED scan record.

    ``dispatch=False`` leaves starting the scan to the caller (the contract
    route runs it as a FastAPI background task).
    """
    parsed = validate_target_url(target_url)  # raises InvalidTargetError
    scan = Scan(
        target_url=parsed.url,
        status=ScanStatus.QUEUED,
        progress=0,
        options={**scan_options(), **(options or {})},
        authorization_confirmed=authorization_confirmed,
        authorization_confirmed_at=datetime.now(UTC) if authorization_confirmed else None,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    logger.info("scan created id=%s target=%s", scan.id, scan.target_url)
    if dispatch:
        _dispatch(scan.id)
    return scan


def _dispatch(scan_id) -> None:
    """Start the scan: inline background task, or enqueue on Celery.

    ``RUN_SCANS_INLINE`` runs the scan in-process as an asyncio background task,
    so the full product works without Celery/Redis (simple deployments, demos).
    Otherwise the scan is enqueued on Celery (the docker-compose default).
    Either path is best-effort and never blocks/raises during scan creation.
    """
    if settings.RUN_SCANS_INLINE:
        try:
            import asyncio

            from app.services.scan_runner import run_scan_async

            asyncio.get_running_loop().create_task(run_scan_async(scan_id))
        except Exception as exc:  # noqa: BLE001
            logger.error("failed to start inline scan %s: %s", scan_id, exc)
        return

    if not settings.AUTO_DISPATCH_SCANS:
        return
    try:
        from app.workers.celery_app import celery_app

        celery_app.send_task("cawasma.run_scan", args=[str(scan_id)])
    except Exception as exc:  # noqa: BLE001 - broker issues must not 500 the request
        logger.error("failed to dispatch scan %s to Celery: %s", scan_id, exc)


INTERRUPTED = "Scan interrupted: the server restarted before it finished. Start it again."


async def fail_interrupted_scans(session: AsyncSession) -> int:
    """Mark scans the API process was running (``options.runner == "api"``) as
    FAILED. They ran as background tasks in a process that no longer exists, so
    without this they would stay QUEUED/RUNNING forever and clients would poll
    for ever. Celery-dispatched scans are left alone: the worker still has them.
    Call once at API start-up.
    """
    rows = (await session.scalars(
        select(Scan).where(Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]))
    )).all()
    stale = [s for s in rows if (s.options or {}).get("runner") == "api"]
    for scan in stale:
        scan.status = ScanStatus.FAILED
        scan.error_message = INTERRUPTED
        scan.completed_at = datetime.now(UTC)
    await session.commit()
    return len(stale)


async def mark_failed(session: AsyncSession, scan: Scan, message: str) -> None:
    """End a scan as FAILED with a user-facing message (e.g. it could not be queued)."""
    scan.status = ScanStatus.FAILED
    scan.error_message = message
    scan.completed_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(scan)


async def request_cancel(session: AsyncSession, scan: Scan) -> None:
    """Cancel a scan. QUEUED: FAILED now. RUNNING: raise the flag the worker
    checks at its next progress step (scan_runner.ScanCancelled)."""
    from app.services.scan_runner import CANCELLED

    scan.cancel_requested = True
    if scan.status == ScanStatus.QUEUED:
        scan.status = ScanStatus.FAILED
        scan.error_message = CANCELLED
        scan.completed_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(scan)


async def get_scan(session: AsyncSession, scan_id: uuid.UUID) -> Scan | None:
    return await session.get(Scan, scan_id)
