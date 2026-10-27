"""scripts/seed.py loads the documented sample data; scripts/reset.py rebuilds the DB."""
from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path

import pytest
from sqlalchemy import func, inspect, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import scripts.seed as seed_mod
from app.config import settings
from app.db.models import (
    AttackChain,
    Base,
    Endpoint,
    Feedback,
    Finding,
    Scan,
    Severity,
    TlsInfo,
)
from scripts import reset


@pytest.fixture
def seeded_scope(engine, monkeypatch):
    maker = async_sessionmaker(bind=engine, expire_on_commit=False)

    @contextlib.asynccontextmanager
    async def fake_scope():
        async with maker() as session:
            yield session
            await session.commit()

    monkeypatch.setattr(seed_mod, "session_scope", fake_scope)
    return maker


async def _count(session, model) -> int:
    return (await session.execute(select(func.count()).select_from(model))).scalar_one()


@pytest.mark.asyncio
async def test_seed_matches_the_documented_sample(seeded_scope):
    assert await seed_mod.seed() is True
    assert await seed_mod.seed() is False  # idempotent

    async with seeded_scope() as s:
        targets = (await s.execute(select(func.count(func.distinct(Scan.target_url))))).scalar_one()
        assert targets == 1
        assert await _count(s, Scan) == 2
        assert await _count(s, Endpoint) == 10
        assert await _count(s, Finding) == 16
        assert await _count(s, AttackChain) == 1
        assert await _count(s, Feedback) == 2

        buckets = set((await s.execute(select(Finding.severity_bucket))).scalars())
        # INFO is unreachable with the current catalog (docs/db-decisions.md).
        assert buckets == {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW}

        chain = (await s.execute(select(AttackChain))).scalar_one()
        await s.refresh(chain, ["findings"])
        assert chain.chain_code == "C005"
        assert {f.check_id for f in chain.findings} == {"INF-003"}   # chains.yaml C005
        assert chain.composite_vector and chain.evidence["context"] == {
            "body_signals": ["CREDENTIALS"]}

        issues = {tuple(t.issues) for t in (await s.execute(select(TlsInfo))).scalars()}
        assert issues == {(), ("TLS-001",)}   # only the rescan offered TLS 1.1

        env = (await s.execute(select(Finding).where(Finding.check_id == "INF-003"))).scalar_one()
        assert env.severity_bucket is Severity.CRITICAL
        assert "Sup3rS3cret" not in str(env.evidence)  # body evidence is redacted


def test_reset_refuses_without_confirmation_or_in_production(monkeypatch):
    assert reset.main([]) == 1
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    assert reset.main(["--yes"]) == 2


def test_reset_rebuilds_schema(tmp_path: Path, monkeypatch):
    url = f"sqlite+aiosqlite:///{tmp_path / 'reset.db'}"
    monkeypatch.setattr(settings, "DATABASE_URL", url)
    monkeypatch.setattr(reset, "configure_logging", lambda: None)

    assert reset.main(["--yes"]) == 0

    async def tables() -> set[str]:
        engine = create_async_engine(url)
        async with engine.connect() as conn:
            names = await conn.run_sync(lambda c: set(inspect(c).get_table_names()))
        await engine.dispose()
        return names

    assert asyncio.run(tables()) == set(Base.metadata.tables) | {"alembic_version"}
