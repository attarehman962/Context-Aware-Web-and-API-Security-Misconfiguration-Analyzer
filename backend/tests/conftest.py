"""Shared test fixtures.

Uses a file-based async SQLite database by default so the API can be tested
without a real PostgreSQL. Set ``TEST_DATABASE_URL`` (e.g.
``postgresql+asyncpg://cawasma:cawasma@localhost:5432/cawasma_test``) to run the
same suite against PostgreSQL, as CI does. The scanner modules are DB-free and
tested directly.
"""
from __future__ import annotations

import os
from collections.abc import AsyncGenerator

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import settings as _settings
from app.db.models import Base
from app.db.session import enable_sqlite_foreign_keys, get_session

_settings.AUTO_DISPATCH_SCANS = False  # no Celery broker in tests
_settings.SCAN_RATE_LIMIT = ""          # tests create many scans; test_rate_limit enables it
from app.main import app  # noqa: E402 - must follow the settings override

TEST_DB = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///./_test.db")
_SQLITE_FILE = "_test.db" if TEST_DB.startswith("sqlite") else None


@pytest_asyncio.fixture
async def engine():
    if _SQLITE_FILE and os.path.exists(_SQLITE_FILE):
        os.remove(_SQLITE_FILE)
    eng = create_async_engine(TEST_DB, echo=False)
    enable_sqlite_foreign_keys(eng)  # enforce ON DELETE rules like PostgreSQL
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()
    if _SQLITE_FILE and os.path.exists(_SQLITE_FILE):
        os.remove(_SQLITE_FILE)


@pytest_asyncio.fixture
async def sessionmaker_(engine):
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture
async def client(sessionmaker_) -> AsyncGenerator[AsyncClient, None]:
    async def _override() -> AsyncGenerator[AsyncSession, None]:
        async with sessionmaker_() as session:
            yield session

    app.dependency_overrides[get_session] = _override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()
