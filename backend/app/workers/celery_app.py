"""Celery application.

Scans run as background tasks so the HTTP request that creates a scan returns
immediately (spec section 23). Redis is both broker and result backend. The
actual scan task is registered in ``tasks.py`` and implemented in a later phase.
"""

from __future__ import annotations

from celery import Celery
from celery.signals import worker_init

from app.config import settings

celery_app = Celery(
    "cawasma",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=1800,  # hard 30-min ceiling per scan
    task_soft_time_limit=1500,
    worker_max_tasks_per_child=50,
    result_expires=86_400,
    # Keep app.utils.logging's handler (JSON lines with the scan id) in the worker.
    worker_hijack_root_logger=False,
)


@worker_init.connect
def validate_checks_on_worker_start(**_: object) -> None:
    """Same check-registry validation as the API: a worker with an implemented
    check that has no spec in checks.yaml refuses to start."""
    from app.core.checks.registry import validate_registry_at_startup

    validate_registry_at_startup()
