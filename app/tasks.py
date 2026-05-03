"""Celery integration and background scan task."""

from __future__ import annotations

from celery import Celery
from flask import current_app
from redis import Redis
from redis.exceptions import RedisError

from app.extensions import db


celery_app = Celery("cawasma")


def init_celery(flask_app):
    celery = Celery(
        flask_app.import_name,
        broker=flask_app.config.get("CELERY_BROKER_URL"),
        backend=flask_app.config.get("CELERY_RESULT_BACKEND"),
    )
    celery.conf.update(flask_app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with flask_app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    celery_app.conf.update(celery.conf)
    celery_app.Task = celery.Task
    return celery


def _run_scan(scan_id: int):
    from app.models import Scan
    from app.scanner.engine import ScanEngine

    scan = Scan.query.get(scan_id)
    if scan is None:
        return {"status": "missing"}

    engine = ScanEngine(current_app)
    result = engine.run(scan)
    db.session.commit()
    return result


def _redis_is_available(broker_url: str | None) -> bool:
    if not broker_url:
        return False

    try:
        client = Redis.from_url(broker_url, socket_connect_timeout=1, socket_timeout=1)
        return bool(client.ping())
    except RedisError:
        return False
    except Exception:
        return False


@celery_app.task(name="app.tasks.run_scan_task")
def run_scan_task(scan_id: int):
    return _run_scan(scan_id)


def enqueue_scan(scan_id: int):
    broker_url = current_app.config.get("CELERY_BROKER_URL")
    if _redis_is_available(broker_url):
        return run_scan_task.delay(scan_id)

    current_app.logger.warning(
        "Redis broker is unavailable; running scan %s inline instead of queueing it.",
        scan_id,
    )
    return _run_scan(scan_id)
