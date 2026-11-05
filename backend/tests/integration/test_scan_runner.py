"""Scan runner drives QUEUED -> RUNNING -> DONE and persists results."""
from __future__ import annotations

import contextlib

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

import app.services.scan_runner as runner
from app.core.pipeline import run_pipeline
from app.db.models import Finding, Scan
from app.db.models.enums import ScanStatus
from tests.fixtures.mock_server import mock_server

pytestmark = pytest.mark.asyncio


async def test_scan_runner_completes(engine, monkeypatch):
    async_session = async_sessionmaker(bind=engine, expire_on_commit=False)

    @contextlib.asynccontextmanager
    async def fake_scope():
        session = async_session()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    async def patched_pipeline(target, on_progress=None, *, probe=True, allow_private=False, **_):
        return await run_pipeline(target, on_progress, probe=False, allow_private=True)

    monkeypatch.setattr(runner, "session_scope", fake_scope)
    monkeypatch.setattr(runner, "run_pipeline", patched_pipeline)

    with mock_server() as base:
        async with async_session() as s:
            scan = Scan(target_url=base, status=ScanStatus.QUEUED, progress=0)
            s.add(scan)
            await s.commit()
            await s.refresh(scan)
            sid = scan.id
        await runner.run_scan_async(sid)

    async with async_session() as s:
        scan = await s.get(Scan, sid)
        assert scan.status == ScanStatus.DONE
        assert scan.progress == 100
        assert scan.duration_seconds is not None
        from sqlalchemy import func, select
        n = (await s.execute(
            select(func.count()).select_from(Finding).where(Finding.scan_id == sid)
        )).scalar_one()
        assert n > 0


async def _run_failing(engine, monkeypatch, exc):
    async_session = async_sessionmaker(bind=engine, expire_on_commit=False)

    @contextlib.asynccontextmanager
    async def fake_scope():
        async with async_session() as session:
            yield session

    async def failing_pipeline(*a, **k):
        raise exc

    monkeypatch.setattr(runner, "session_scope", fake_scope)
    monkeypatch.setattr(runner, "run_pipeline", failing_pipeline)
    async with async_session() as s:
        scan = Scan(target_url="https://unreachable.example", status=ScanStatus.QUEUED,
                    progress=0)
        s.add(scan)
        await s.commit()
        sid = scan.id
    await runner.run_scan_async(sid)
    async with async_session() as s:
        return await s.get(Scan, sid)


async def test_scan_error_message_is_shown_to_the_user(engine, monkeypatch):
    from app.core.pipeline import ScanError

    scan = await _run_failing(engine, monkeypatch,
                              ScanError("Target unreachable: connection refused"))
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message == "Target unreachable: connection refused"
    assert scan.completed_at is not None


async def test_internal_errors_are_not_shown_to_the_user(engine, monkeypatch):
    scan = await _run_failing(engine, monkeypatch,
                              RuntimeError("psycopg: password authentication failed"))
    assert scan.status == ScanStatus.FAILED
    assert "psycopg" not in scan.error_message and "Internal error" in scan.error_message
