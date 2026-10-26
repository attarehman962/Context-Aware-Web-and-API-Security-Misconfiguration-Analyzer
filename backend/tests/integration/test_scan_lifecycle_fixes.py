"""Scan lifecycle fixes from the code review: interrupted scans, the terminal
progress event for failures, and the Celery task's engine disposal."""
from __future__ import annotations

import contextlib
import uuid

import pytest

import app.services.scan_runner as runner
import app.workers.tasks as tasks
from app.db.models import Scan
from app.db.models.enums import ScanStatus
from app.services.scan_service import INTERRUPTED, fail_interrupted_scans

pytestmark = pytest.mark.asyncio


async def test_api_run_scans_left_running_are_failed_at_startup(sessionmaker_):
    async with sessionmaker_() as s:
        api_running = Scan(target_url="https://a.example", status=ScanStatus.RUNNING,
                           progress=40, options={"runner": "api"})
        api_queued = Scan(target_url="https://b.example", status=ScanStatus.QUEUED,
                          progress=0, options={"runner": "api"})
        celery_queued = Scan(target_url="https://c.example", status=ScanStatus.QUEUED,
                             progress=0, options={})
        done = Scan(target_url="https://d.example", status=ScanStatus.DONE, progress=100,
                    options={"runner": "api"})
        s.add_all([api_running, api_queued, celery_queued, done])
        await s.commit()
        ids = [x.id for x in (api_running, api_queued, celery_queued, done)]

    async with sessionmaker_() as s:
        assert await fail_interrupted_scans(s) == 2

    async with sessionmaker_() as s:
        status = {i: (await s.get(Scan, i)) for i in ids}
        assert [status[i].status for i in ids] == [
            ScanStatus.FAILED, ScanStatus.FAILED, ScanStatus.QUEUED, ScanStatus.DONE]
        assert status[ids[0]].error_message == INTERRUPTED
        assert status[ids[0]].completed_at is not None


async def test_failed_scans_publish_a_terminal_event(sessionmaker_, monkeypatch):
    events: list[tuple[str, int, str]] = []

    @contextlib.asynccontextmanager
    async def scope():
        async with sessionmaker_() as session:
            yield session

    async def publish(self, stage, percent, message):
        events.append((stage, percent, message))

    async def noop(self, *a, **k):
        return None

    async def boom(*a, **k):
        raise RuntimeError("internal detail")

    monkeypatch.setattr(runner, "session_scope", scope)
    monkeypatch.setattr(runner, "run_pipeline", boom)
    monkeypatch.setattr(runner.RedisProgressPublisher, "publish", publish)
    monkeypatch.setattr(runner.RedisProgressPublisher, "close", noop)
    async with sessionmaker_() as s:
        scan = Scan(target_url="https://a.example", status=ScanStatus.QUEUED, progress=0)
        s.add(scan)
        await s.commit()
    await runner.run_scan_async(scan.id)
    assert events[-1][0] == "failed" and "internal detail" not in events[-1][2]


async def test_worker_task_disposes_the_engine_even_when_the_scan_fails(monkeypatch):
    disposed: list[bool] = []

    class FakeEngine:
        async def dispose(self):
            disposed.append(True)

    async def boom(scan_id):
        raise RuntimeError("scan crashed")

    monkeypatch.setattr(tasks, "engine", FakeEngine())
    monkeypatch.setattr(tasks, "run_scan_async", boom)
    with pytest.raises(RuntimeError):
        await tasks._run_and_dispose("x")
    assert disposed == [True]


async def test_contract_scans_are_marked_as_run_by_the_api(client, sessionmaker_):
    r = await client.post("/api/scan", json={"url": "https://example.com",
                                             "authorisation_confirmed": True})
    assert r.status_code == 202, r.text
    async with sessionmaker_() as s:
        scan = await s.get(Scan, uuid.UUID(r.json()["scan_id"]))
    assert scan.options["runner"] == "api"
    assert r.json()["options"] == {"crawl_depth": 2, "use_wordlist": True,
                                   "passive_only": False}
