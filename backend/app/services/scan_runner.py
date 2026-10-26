"""Async driver that runs one scan end-to-end (spec section 19/24).

Separated from the Celery task so it can be unit-tested directly (the Celery
task is a thin ``asyncio.run`` wrapper). Updates the Scan row's status/progress,
publishes progress to Redis, persists the result, and records failures honestly.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select

from app.core.pipeline import ScanError, run_pipeline
from app.db.models import Scan
from app.db.models.enums import ScanStatus
from app.db.session import session_scope
from app.services.progress import RedisProgressPublisher
from app.services.result_service import persist_result
from app.utils.logging import get_logger

logger = get_logger(__name__)


async def run_scan_async(scan_id: str | uuid.UUID, *, probe: bool = True) -> None:
    """Run the scan identified by ``scan_id``; never raises."""
    sid = uuid.UUID(str(scan_id))
    publisher = RedisProgressPublisher(sid)
    started = datetime.now(UTC)

    async with session_scope() as session:
        scan = (await session.execute(select(Scan).where(Scan.id == sid))).scalar_one_or_none()
        if scan is None:
            logger.warning("run_scan: scan %s not found", sid)
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = started
        scan.progress = 0
        scan.current_stage = "initializing"
        await session.commit()

        last_pct = -10
        active = scan  # narrowed to Scan for the closure below

        async def on_progress(stage: str, percent: int, message: str) -> None:
            nonlocal last_pct
            await publisher.publish(stage, percent, message)
            if percent - last_pct >= 5 or percent >= 100:
                active.progress = percent
                active.current_stage = stage
                await session.commit()
                last_pct = percent

        try:
            opts = scan.options or {}
            passive = bool(opts.get("passive_only", False))
            result = await run_pipeline(
                scan.target_url, on_progress,
                probe=probe and not passive,
                passive_only=passive,
                crawl_depth=opts.get("crawl_depth"),
                use_wordlist=opts.get("use_wordlist", True),
            )
            await persist_result(session, scan, result)
            scan.status = ScanStatus.DONE
            scan.progress = 100
            scan.current_stage = "completed"
            scan.completed_at = datetime.now(UTC)
            scan.duration_seconds = (scan.completed_at - started).total_seconds()
            await session.commit()
            logger.info("scan %s completed: %s", sid, result.stats)
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
            # Terminal event, so live listeners (WebSocket) stop waiting.
            await publisher.publish("failed", scan.progress if scan else 0, message)
        finally:
            await publisher.close()
