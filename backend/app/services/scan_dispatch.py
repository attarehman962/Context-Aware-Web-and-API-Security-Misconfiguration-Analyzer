"""Queue and cancel scans on Celery (the worker runs ``cawasma.run_scan``).

The task id is the scan id, so a cancel can revoke a scan that is still
queued without storing anything extra. Publishing fails fast (two quick
retries) when the broker is down, so ``POST /api/scan`` can answer 503 instead
of hanging.
"""

from __future__ import annotations

import uuid

from app.utils.logging import get_logger

logger = get_logger(__name__)

_PUBLISH_RETRY = {"max_retries": 2, "interval_start": 0, "interval_step": 0.5, "interval_max": 1}


class QueueUnavailable(RuntimeError):
    """The broker could not take the task."""


def queue_scan(scan_id: uuid.UUID) -> None:
    from app.workers.tasks import run_scan

    try:
        run_scan.apply_async(
            args=[str(scan_id)], task_id=str(scan_id), retry=True, retry_policy=_PUBLISH_RETRY
        )
    except Exception as exc:
        logger.error("could not queue scan %s: %s", scan_id, exc)
        raise QueueUnavailable(str(exc)) from exc


def revoke_scan(scan_id: uuid.UUID) -> None:
    """Drop a still-queued task; a running one stops at its next progress step
    (scan_runner reads ``cancel_requested``). Best effort: never raises."""
    from app.workers.celery_app import celery_app

    try:
        celery_app.control.revoke(str(scan_id))
    except Exception as exc:  # noqa: BLE001 - the DB flag is the real cancel
        logger.warning("could not revoke scan %s: %s", scan_id, exc)
