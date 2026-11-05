"""Async driver that runs one scan end-to-end (spec section 19/24).

Separated from the Celery task so it can be unit-tested directly (the Celery
task is a thin ``asyncio.run`` wrapper). Updates the Scan row's status, progress
and per-stage counts (``progress_detail``), publishes progress to Redis,
persists the result, and records failures honestly.

* **Cancellation**: ``POST /api/scan/{id}/cancel`` sets ``cancel_requested``;
  this checks it at every progress step and stops with FAILED "Cancelled".
* **Timeout**: the pipeline gets ``SCAN_TIMEOUT`` seconds (below the Celery
  limits), so an over-long scan ends FAILED with a message, not killed silently.
* **Retries**: loading the scan is left uncaught, so a database that is down
  when the task starts surfaces to Celery, which retries the task. Once a scan
  is RUNNING it is never retried (it would scan the target again); a repeated
  delivery of a finished scan is ignored.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from sqlalchemy import select

from app.config import settings
from app.core.pipeline import ScanError, run_pipeline
from app.db.models import Scan
from app.db.models.enums import ScanStatus
from app.db.session import session_scope
from app.services.result_service import persist_result
from app.utils.logging import get_logger, scan_id_var

logger = get_logger(__name__)

CANCELLED = "Cancelled by the user."


class ScanCancelled(ScanError):
    """Raised at a progress step after the user asked to cancel."""

    def __init__(self) -> None:
        super().__init__(CANCELLED)


async def run_scan_async(scan_id: str | uuid.UUID, *, probe: bool = True) -> None:
    """Run the scan identified by ``scan_id``; never raises."""
    sid = uuid.UUID(str(scan_id))
    scan_id_var.set(str(sid))           # tags every log line of this scan
    started = datetime.now(UTC)

    async with session_scope() as session:
        scan = (await session.execute(select(Scan).where(Scan.id == sid))).scalar_one_or_none()
        if scan is None:
            logger.warning("run_scan: scan %s not found", sid)
            return
        if scan.status in (ScanStatus.DONE, ScanStatus.FAILED):
            logger.info("run_scan: scan %s already %s, ignoring", sid, scan.status.value)
            return
        if scan.cancel_requested:
            scan.status = ScanStatus.FAILED
            scan.error_message = CANCELLED
            scan.completed_at = datetime.now(UTC)
            await session.commit()
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = started
        scan.progress = 0
        scan.current_stage = "initializing"
        await session.commit()

        active = scan  # narrowed to Scan for the closure below

        async def on_progress(stage: str, percent: int, message: str,
                              detail: dict[str, int]) -> None:
            # A fresh read (not the cached attribute): the API sets it from outside.
            if await session.scalar(select(Scan.cancel_requested).where(Scan.id == sid)):
                raise ScanCancelled
            active.progress = max(percent, active.progress)
            active.current_stage = stage
            active.progress_detail = {"stage": stage, **detail}
            await session.commit()            # one per endpoint at most (bounded)

        try:
            opts = scan.options or {}
            passive = bool(opts.get("passive_only", False))
            try:
                result = await asyncio.wait_for(run_pipeline(
                    scan.target_url, on_progress,
                    probe=probe and not passive,
                    passive_only=passive,
                    crawl_depth=opts.get("crawl_depth"),
                    use_wordlist=opts.get("use_wordlist", True),
                ), timeout=settings.SCAN_TIMEOUT)
            except TimeoutError:
                raise ScanError(f"Scan timed out after {settings.SCAN_TIMEOUT:.0f} s.") from None
            await persist_result(session, scan, result)
            scan.status = ScanStatus.DONE
            scan.progress = 100
            scan.current_stage = "completed"
            scan.completed_at = datetime.now(UTC)
            scan.duration_seconds = (scan.completed_at - started).total_seconds()
            await session.commit()
            logger.info("scan completed", extra={
                k: result.stats.get(k)
                for k in ("endpoints", "findings", "chains", "requests", "stage_seconds")})
        except Exception as exc:  # noqa: BLE001 - record failure, never propagate
            logger.exception("scan %s failed", sid)
            # Shown to the user: only ScanError messages are written for them.
            message = (str(exc) if isinstance(exc, ScanError)
                       else "Internal error while scanning; the server log has details.")
            await session.rollback()
            scan = (await session.execute(
                select(Scan).where(Scan.id == sid))).scalar_one_or_none()
            if scan is not None:
                scan.status = ScanStatus.FAILED
                scan.error_message = message[:500]
                scan.completed_at = datetime.now(UTC)
                await session.commit()
