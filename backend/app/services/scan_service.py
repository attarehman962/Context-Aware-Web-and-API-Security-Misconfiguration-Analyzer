"""Scan service -- persistence and orchestration for scans.

The API layer calls these functions; they own all database access so routes
stay thin and the scanner modules stay DB-free. Actual background execution is
wired to Celery in Phase 14; ``create_scan`` currently persists a QUEUED record
and returns immediately (spec section 23), which is the real, honest state.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas.scan import ScanSummary
from app.config import settings
from app.db.models import (
    AttackChain,
    Endpoint,
    Finding,
    Scan,
    ScanStatus,
    Severity,
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


async def get_scan(session: AsyncSession, scan_id: uuid.UUID) -> Scan | None:
    return await session.get(Scan, scan_id)


async def list_scans(
    session: AsyncSession, offset: int, limit: int
) -> tuple[list[Scan], int]:
    total = await session.scalar(select(func.count()).select_from(Scan)) or 0
    rows = (
        await session.scalars(
            select(Scan).order_by(Scan.created_at.desc(), Scan.id).offset(offset).limit(limit)
        )
    ).all()
    return list(rows), total


async def delete_scan(session: AsyncSession, scan_id: uuid.UUID) -> bool:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        return False
    await session.delete(scan)  # cascades to the whole graph
    await session.commit()
    return True


async def build_summary(session: AsyncSession, scan_id: uuid.UUID) -> ScanSummary:
    """Aggregate counts for a scan (endpoints, findings by severity)."""
    endpoint_count = await session.scalar(
        select(func.count()).select_from(Endpoint).where(Endpoint.scan_id == scan_id)
    ) or 0
    finding_count = await session.scalar(
        select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
    ) or 0

    rows = (
        await session.execute(
            select(Finding.severity_bucket, func.count())
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.severity_bucket)
        )
    ).all()
    by_sev: dict[Severity, int] = {sev: n for sev, n in rows}
    return ScanSummary(
        endpoints=endpoint_count,
        findings=finding_count,
        critical=by_sev.get(Severity.CRITICAL, 0),
        high=by_sev.get(Severity.HIGH, 0),
        medium=by_sev.get(Severity.MEDIUM, 0),
        low=by_sev.get(Severity.LOW, 0),
        info=by_sev.get(Severity.INFO, 0),
    )


async def list_findings(
    session: AsyncSession, scan_id: uuid.UUID, offset: int, limit: int
) -> tuple[list[Finding], int]:
    total = await session.scalar(
        select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
    ) or 0
    rows = (
        await session.scalars(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.final_score.desc(), Finding.id)   # stable pages on ties
            .offset(offset)
            .limit(limit)
        )
    ).all()
    return list(rows), total


async def list_endpoints(
    session: AsyncSession, scan_id: uuid.UUID, offset: int, limit: int
) -> tuple[list[Endpoint], int]:
    total = await session.scalar(
        select(func.count()).select_from(Endpoint).where(Endpoint.scan_id == scan_id)
    ) or 0
    rows = (
        await session.scalars(
            select(Endpoint)
            .where(Endpoint.scan_id == scan_id)
            .order_by(Endpoint.created_at.asc(), Endpoint.id)
            .offset(offset)
            .limit(limit)
        )
    ).all()
    return list(rows), total


async def list_chains(
    session: AsyncSession, scan_id: uuid.UUID
) -> list[AttackChain]:
    rows = (
        await session.scalars(
            select(AttackChain)
            .where(AttackChain.scan_id == scan_id)
            .order_by(AttackChain.template_composite_score.desc())
        )
    ).all()
    return list(rows)
