"""Celery dispatch (eager mode), retry policy, rate limit, cancel, timeout, SSE.

Atta Prompt 9. The Celery tests are synchronous: the task calls
``asyncio.run`` itself, exactly as in the worker, with ``task_always_eager`` so
no broker is needed. The scanner is replaced by a fake pipeline that reports
progress like the real one; the real pipeline is covered elsewhere.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.services.scan_runner as runner
from app.api.routes import contract
from app.config import settings
from app.db.models import Base, Scan
from app.db.models.enums import ScanStatus
from app.services import rate_limit, scan_dispatch
from app.workers import tasks
from app.workers.celery_app import celery_app

BODY = {"url": "https://example.com", "authorisation_confirmed": True}


# Helpers


class _FakeEngine:
    async def dispose(self) -> None:
        return None


def _fake_pipeline(steps=None, *, hook=None, sleep: float = 0.0):
    steps = steps or [
        ("crawling", 8, {"endpoints_found": 0}),
        ("checking", 40, {"endpoints_found": 4, "endpoints_checked": 2, "findings": 3}),
        ("scoring", 90, {"endpoints_found": 4, "endpoints_checked": 4, "findings": 6}),
        (
            "completed",
            100,
            {"endpoints_found": 4, "endpoints_checked": 4, "findings": 6, "chains": 1},
        ),
    ]

    async def pipeline(target, on_progress, **kw):
        for i, (stage, pct, detail) in enumerate(steps):
            if hook is not None:
                await hook(i)
            await on_progress(stage, pct, stage, detail)
        await asyncio.sleep(sleep)
        return SimpleNamespace(stats={})

    return pipeline


async def _no_persist(session, scan, result):
    return None


@pytest.fixture
def eager():
    # Not task_eager_propagates: retries run nested apply() calls, which would then
    # raise Retry; the tests read the result state instead.
    old = {"task_always_eager": celery_app.conf.task_always_eager}
    celery_app.conf.update(task_always_eager=True)
    yield
    celery_app.conf.update(old)


@pytest.fixture
def worker_db(tmp_path, monkeypatch):
    """A SQLite file the eager task can open from its own event loop."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'worker.db'}"

    async def setup() -> uuid.UUID:
        eng = create_async_engine(url)
        async with eng.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with async_sessionmaker(eng, expire_on_commit=False)() as s:
            scan = Scan(
                target_url="https://a.example",
                status=ScanStatus.QUEUED,
                progress=0,
                options={"passive_only": True},
            )
            s.add(scan)
            await s.commit()
        await eng.dispose()
        return scan.id

    @contextlib.asynccontextmanager
    async def scope():
        eng = create_async_engine(url)
        try:
            async with async_sessionmaker(eng, class_=AsyncSession, expire_on_commit=False)() as s:
                yield s
        finally:
            await eng.dispose()

    async def load(scan_id: uuid.UUID) -> Scan:
        async with scope() as s:
            return (await s.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()

    monkeypatch.setattr(runner, "session_scope", scope)
    monkeypatch.setattr(tasks, "engine", _FakeEngine())
    scan_id = asyncio.run(setup())
    return SimpleNamespace(scan_id=scan_id, load=lambda: asyncio.run(load(scan_id)))


# Celery


def test_queued_scan_runs_on_the_celery_task_and_stores_progress(eager, worker_db, monkeypatch):
    seen: dict = {}

    async def pipeline(target, on_progress, **kw):
        seen.update(kw)
        return await _fake_pipeline()(target, on_progress, **kw)

    monkeypatch.setattr(runner, "run_pipeline", pipeline)
    monkeypatch.setattr(runner, "persist_result", _no_persist)

    scan_dispatch.queue_scan(worker_db.scan_id)  # apply_async, eager

    scan = worker_db.load()
    assert scan.status == ScanStatus.DONE and scan.progress == 100
    assert scan.current_stage == "completed"
    assert scan.progress_detail == {
        "stage": "completed",
        "endpoints_found": 4,
        "endpoints_checked": 4,
        "findings": 6,
        "chains": 1,
    }
    assert seen["passive_only"] is True and seen["probe"] is False  # options reach it


def test_progress_detail_is_stored_at_every_stage(eager, worker_db, monkeypatch):
    snapshots: list[dict | None] = []

    async def hook(i):
        if i:  # after step i-1 was committed
            async with runner.session_scope() as s:
                snapshots.append(
                    await s.scalar(select(Scan.progress_detail).where(Scan.id == worker_db.scan_id))
                )

    monkeypatch.setattr(runner, "run_pipeline", _fake_pipeline(hook=hook))
    monkeypatch.setattr(runner, "persist_result", _no_persist)
    tasks.run_scan.apply(args=[str(worker_db.scan_id)])
    assert [s["stage"] for s in snapshots] == ["crawling", "checking", "scoring"]
    assert snapshots[1]["endpoints_checked"] == 2 and snapshots[1]["findings"] == 3


def test_task_id_is_the_scan_id_so_it_can_be_revoked(monkeypatch):
    sent: dict = {}

    def apply_async(**kw):
        sent.update(kw)

    monkeypatch.setattr(tasks.run_scan, "apply_async", apply_async)
    sid = uuid.uuid4()
    scan_dispatch.queue_scan(sid)
    assert sent["task_id"] == str(sid) and sent["args"] == [str(sid)]
    assert sent["retry"] is True and sent["retry_policy"]["max_retries"] == 2


def test_broker_down_raises_queue_unavailable(monkeypatch):
    from kombu.exceptions import OperationalError as KombuError

    def down(**kw):
        raise KombuError("Connection refused")

    monkeypatch.setattr(tasks.run_scan, "apply_async", down)
    with pytest.raises(scan_dispatch.QueueUnavailable):
        scan_dispatch.queue_scan(uuid.uuid4())


def test_infrastructure_errors_are_retried_with_backoff(eager, monkeypatch):
    calls: list[str] = []

    async def flaky(scan_id):
        calls.append(scan_id)
        if len(calls) < 3:
            raise OperationalError("SELECT 1", {}, Exception("db down"))

    monkeypatch.setattr(tasks, "run_scan_async", flaky)
    monkeypatch.setattr(tasks, "engine", _FakeEngine())
    # throw=False: in eager mode Celery would re-raise Retry to the caller after
    # running the retries in place; the worker never does that.
    result = tasks.run_scan.apply(args=["s-1"], throw=False)
    assert result.successful() and len(calls) == 3
    assert tasks.run_scan.max_retries == tasks.MAX_RETRIES == 3
    assert tasks.run_scan.retry_backoff == 5 and tasks.run_scan.retry_jitter is False


def test_retries_stop_after_max_retries(eager, monkeypatch):
    calls: list[str] = []

    async def down(scan_id):
        calls.append(scan_id)
        raise OperationalError("SELECT 1", {}, Exception("db down"))

    monkeypatch.setattr(tasks, "run_scan_async", down)
    monkeypatch.setattr(tasks, "engine", _FakeEngine())
    result = tasks.run_scan.apply(args=["s-1"], throw=False)
    assert result.failed() and isinstance(result.result, OperationalError)
    assert len(calls) == 1 + tasks.MAX_RETRIES


def test_other_errors_are_not_retried(eager, monkeypatch):
    calls: list[str] = []

    async def bug(scan_id):
        calls.append(scan_id)
        raise ValueError("bug")

    monkeypatch.setattr(tasks, "run_scan_async", bug)
    monkeypatch.setattr(tasks, "engine", _FakeEngine())
    result = tasks.run_scan.apply(args=["s-1"], throw=False)
    assert result.failed() and isinstance(result.result, ValueError) and len(calls) == 1


def test_scan_timeout_fails_the_scan(eager, worker_db, monkeypatch):
    monkeypatch.setattr(settings, "SCAN_TIMEOUT", 0.05)
    monkeypatch.setattr(runner, "run_pipeline", _fake_pipeline(sleep=5))
    tasks.run_scan.apply(args=[str(worker_db.scan_id)])
    scan = worker_db.load()
    assert scan.status == ScanStatus.FAILED and "timed out" in scan.error_message


def test_cancel_flag_stops_a_running_scan(eager, worker_db, monkeypatch):
    async def cancel_after_first_step(i):
        if i == 1:
            async with runner.session_scope() as s:
                scan = await s.get(Scan, worker_db.scan_id)
                scan.cancel_requested = True
                await s.commit()

    persisted: list[bool] = []

    async def persist(*a):
        persisted.append(True)

    monkeypatch.setattr(runner, "run_pipeline", _fake_pipeline(hook=cancel_after_first_step))
    monkeypatch.setattr(runner, "persist_result", persist)
    tasks.run_scan.apply(args=[str(worker_db.scan_id)])
    scan = worker_db.load()
    assert scan.status == ScanStatus.FAILED and scan.error_message == runner.CANCELLED
    assert scan.progress_detail["stage"] == "crawling" and not persisted


def test_a_scan_cancelled_while_queued_never_starts(eager, worker_db, monkeypatch):
    async def flag():
        async with runner.session_scope() as s:
            scan = await s.get(Scan, worker_db.scan_id)
            scan.cancel_requested = True
            await s.commit()

    async def must_not_run(*a, **k):
        raise AssertionError("pipeline started")

    asyncio.run(flag())
    monkeypatch.setattr(runner, "run_pipeline", must_not_run)
    tasks.run_scan.apply(args=[str(worker_db.scan_id)])
    scan = worker_db.load()
    assert scan.status == ScanStatus.FAILED and scan.error_message == runner.CANCELLED


# POST /api/scan


@pytest.fixture
def queued(monkeypatch):
    ids: list[uuid.UUID] = []
    monkeypatch.setattr(settings, "AUTO_DISPATCH_SCANS", True)
    monkeypatch.setattr(settings, "RUN_SCANS_INLINE", False)
    monkeypatch.setattr(scan_dispatch, "queue_scan", ids.append)
    return ids


@pytest.mark.asyncio
async def test_post_scan_queues_it_on_celery(client, queued, sessionmaker_):
    r = await client.post("/api/scan", json=BODY)
    assert r.status_code == 202, r.text
    assert queued == [uuid.UUID(r.json()["scan_id"])]
    async with sessionmaker_() as s:
        scan = await s.get(Scan, queued[0])
    assert scan.status == ScanStatus.QUEUED and scan.options["runner"] == "celery"


@pytest.mark.asyncio
async def test_post_scan_answers_503_when_the_queue_is_down(client, monkeypatch, sessionmaker_):
    def down(scan_id):
        raise scan_dispatch.QueueUnavailable("refused")

    monkeypatch.setattr(settings, "AUTO_DISPATCH_SCANS", True)
    monkeypatch.setattr(settings, "RUN_SCANS_INLINE", False)
    monkeypatch.setattr(scan_dispatch, "queue_scan", down)
    r = await client.post("/api/scan", json=BODY)
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "QUEUE_UNAVAILABLE"
    async with sessionmaker_() as s:
        scans = (await s.execute(select(Scan))).scalars().all()
    assert [x.status for x in scans] == [ScanStatus.FAILED]  # not left QUEUED forever


# Rate limit


@pytest.fixture
def local_limiter(monkeypatch):
    lim = rate_limit.ScanRateLimiter()

    async def no_redis(key, window):
        return None

    monkeypatch.setattr(lim, "_incr_redis", no_redis)
    monkeypatch.setattr(rate_limit, "limiter", lim)
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT", "2/minute")
    return lim


@pytest.mark.asyncio
async def test_post_scan_is_rate_limited(client, queued, local_limiter):
    codes = [(await client.post("/api/scan", json=BODY)).status_code for _ in range(2)]
    r = await client.post("/api/scan", json=BODY)
    assert codes == [202, 202] and r.status_code == 429
    assert r.json()["error"]["code"] == "RATE_LIMITED"
    assert 1 <= int(r.headers["Retry-After"]) <= 60
    assert len(queued) == 2  # the refused one was never created


@pytest.mark.asyncio
async def test_rate_limit_window_resets_and_is_per_client(local_limiter):
    assert (await local_limiter.hit("a", now=120.0)).allowed
    assert (await local_limiter.hit("a", now=121.0)).allowed
    third = await local_limiter.hit("a", now=150.0)
    assert not third.allowed and third.retry_after == 30
    assert (await local_limiter.hit("b", now=150.0)).allowed
    assert (await local_limiter.hit("a", now=180.0)).allowed  # next minute


@pytest.mark.parametrize(
    "rule, parsed", [("5/minute", (5, 60)), ("100/hour", (100, 3600)), ("", None), ("  ", None)]
)
def test_rate_limit_rule_parsing(rule, parsed):
    assert rate_limit.parse(rule) == parsed


@pytest.mark.parametrize("rule", ["five/minute", "5/week", "0/minute", "5"])
def test_bad_rate_limit_rules_are_rejected(rule):
    with pytest.raises(ValueError):
        rate_limit.parse(rule)


# Cancel


async def _add(sessionmaker_, status_: ScanStatus) -> uuid.UUID:
    async with sessionmaker_() as s:
        scan = Scan(target_url="https://a.example", status=status_, progress=0)
        s.add(scan)
        await s.commit()
        return scan.id


@pytest.fixture
def revoked(monkeypatch):
    ids: list[uuid.UUID] = []
    monkeypatch.setattr(scan_dispatch, "revoke_scan", ids.append)
    return ids


@pytest.mark.asyncio
async def test_cancel_a_queued_scan_fails_it_at_once(client, sessionmaker_, revoked):
    sid = await _add(sessionmaker_, ScanStatus.QUEUED)
    r = await client.post(f"/api/scan/{sid}/cancel")
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "FAILED" and r.json()["error"] == runner.CANCELLED
    assert revoked == [sid]
    again = await client.post(f"/api/scan/{sid}/cancel")
    assert again.status_code == 409 and again.json()["error"]["code"] == "SCAN_FINISHED"


@pytest.mark.asyncio
async def test_cancel_a_running_scan_raises_the_flag(client, sessionmaker_, revoked):
    sid = await _add(sessionmaker_, ScanStatus.RUNNING)
    r = await client.post(f"/api/scan/{sid}/cancel")
    assert r.status_code == 202 and r.json()["status"] == "RUNNING"
    async with sessionmaker_() as s:
        assert (await s.get(Scan, sid)).cancel_requested is True


@pytest.mark.asyncio
async def test_cancel_unknown_or_finished(client, sessionmaker_, revoked):
    assert (await client.post(f"/api/scan/{uuid.uuid4()}/cancel")).status_code == 404
    sid = await _add(sessionmaker_, ScanStatus.DONE)
    assert (await client.post(f"/api/scan/{sid}/cancel")).status_code == 409
    assert revoked == []


# SSE


def _events(text: str) -> list[dict]:
    out = []
    for block in text.split("\n\n"):
        lines = block.splitlines()
        if "event: status" in lines:
            data = next(ln for ln in lines if ln.startswith("data: "))
            out.append(json.loads(data[len("data: ") :]))
    return out


@pytest.fixture
def sse_db(monkeypatch, sessionmaker_):
    monkeypatch.setattr(contract, "AsyncSessionLocal", sessionmaker_)
    monkeypatch.setattr(settings, "SSE_POLL_SECONDS", 0.01)


@pytest.mark.asyncio
async def test_events_stream_every_change_and_end_after_done(client, sessionmaker_, sse_db):
    sid = await _add(sessionmaker_, ScanStatus.RUNNING)

    async def worker():
        steps = [
            (30, "crawling", {"endpoints_found": 3}),
            (60, "checking", {"endpoints_found": 3, "endpoints_checked": 1}),
        ]
        for pct, stage, detail in steps:
            await asyncio.sleep(0.05)
            async with sessionmaker_() as s:
                scan = await s.get(Scan, sid)
                scan.progress, scan.current_stage = pct, stage
                scan.progress_detail = {"stage": stage, **detail}
                await s.commit()
        await asyncio.sleep(0.05)
        async with sessionmaker_() as s:
            scan = await s.get(Scan, sid)
            scan.status, scan.progress, scan.current_stage = ScanStatus.DONE, 100, "completed"
            await s.commit()

    job = asyncio.create_task(worker())
    async with asyncio.timeout(10):
        r = await client.get(f"/api/scan/{sid}/events")
    await job
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    assert r.text.startswith("retry: 3000\n\n")
    events = _events(r.text)
    assert [e["progress"] for e in events] == [0, 30, 60, 100]  # one per change
    assert events[2]["progress_detail"] == {
        "stage": "checking",
        "endpoints_found": 3,
        "endpoints_checked": 1,
    }
    assert events[-1]["status"] == "DONE"


@pytest.mark.asyncio
async def test_events_streams_are_capped_per_client(client, sessionmaker_, sse_db, monkeypatch):
    """SEC-09: each open stream polls the DB, so one client can't hold many."""
    monkeypatch.setattr(settings, "SSE_MAX_STREAMS_PER_CLIENT", 1)
    sid = await _add(sessionmaker_, ScanStatus.RUNNING)
    first = asyncio.create_task(client.get(f"/api/scan/{sid}/events"))
    await asyncio.sleep(0.1)  # the first stream is open and polling

    second = await client.get(f"/api/scan/{sid}/events")
    assert second.status_code == 429 and second.json()["error"]["code"] == "RATE_LIMITED"

    async with sessionmaker_() as s:
        (await s.get(Scan, sid)).status = ScanStatus.DONE
        await s.commit()
    async with asyncio.timeout(10):
        assert (await first).status_code == 200
    third = await client.get(f"/api/scan/{sid}/events")  # the slot was given back
    assert third.status_code == 200


@pytest.mark.asyncio
async def test_events_for_a_finished_scan_send_one_event(client, sessionmaker_, sse_db):
    sid = await _add(sessionmaker_, ScanStatus.FAILED)
    r = await client.get(f"/api/scan/{sid}/events")
    assert [e["status"] for e in _events(r.text)] == ["FAILED"]


@pytest.mark.asyncio
async def test_events_for_an_unknown_scan_are_404_json(client, sse_db):
    r = await client.get(f"/api/scan/{uuid.uuid4()}/events")
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_events_in_mock_mode(client, monkeypatch):
    from app.api import mock

    monkeypatch.setattr(settings, "MOCK_API", True)
    r = await client.get(f"/api/scan/{mock.RUNNING_ID}/events")
    (event,) = _events(r.text)
    assert event["stage"] == "checking" and event["progress_detail"]["endpoints_found"] == 38
    cancel = await client.post(f"/api/scan/{mock.RUNNING_ID}/cancel")
    assert cancel.json()["status"] == "FAILED"
    done = await client.post(f"/api/scan/{mock.DONE_ID}/cancel")
    assert done.status_code == 409
