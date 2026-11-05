"""Celery task definitions (spec section 23).

The HTTP layer enqueues ``cawasma.run_scan`` (task id = scan id, so it can be
revoked) and returns immediately; the worker runs the async pipeline via
``asyncio.run`` in its own process.

Retry policy: only infrastructure errors raised *before* the scan starts (the
database or broker is unreachable) are retried, with exponential backoff and no
jitter, at most ``MAX_RETRIES`` times. A scan that has started is never
retried: scan_runner records its failure as FAILED, so a retry would scan the
target a second time. Time limits come from celery_app (hard 1800 s, soft
1500 s); the scan's own SCAN_TIMEOUT (1200 s) ends it cleanly before that.
"""

from __future__ import annotations

import asyncio

from sqlalchemy.exc import InterfaceError, OperationalError

from app.db.session import engine
from app.services.scan_runner import run_scan_async
from app.utils.logging import get_logger
from app.workers.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name="cawasma.ping")
def ping() -> str:
    """Trivial task used to verify the worker/broker wiring."""
    return "pong"


MAX_RETRIES = 3
RETRY_ON = (OperationalError, InterfaceError, ConnectionError, TimeoutError)


@celery_app.task(
    name="cawasma.run_scan",
    bind=True,
    autoretry_for=RETRY_ON,
    max_retries=MAX_RETRIES,
    retry_backoff=5,
    retry_backoff_max=60,
    retry_jitter=False,
)
def run_scan(self, scan_id: str) -> str:
    """Run a full scan in the worker process."""
    logger.info("worker received scan %s (task %s)", scan_id, self.request.id)
    asyncio.run(_run_and_dispose(scan_id))
    return scan_id


async def _run_and_dispose(scan_id: str) -> None:
    """Each task gets a fresh event loop (asyncio.run), but the engine's pooled
    asyncpg connections belong to the loop that opened them: reusing them in the
    next task fails ("attached to a different loop"). Close them every time."""
    try:
        await run_scan_async(scan_id)
    finally:
        await engine.dispose()
