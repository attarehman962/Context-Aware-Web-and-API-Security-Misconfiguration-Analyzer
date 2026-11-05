"""End-to-end pipeline + persistence tests against the mock server."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.core.pipeline import run_pipeline
from app.db.models import (
    AiInsight,
    Endpoint,
    Finding,
    Scan,
)
from app.db.models.enums import ScanStatus
from app.services.result_service import persist_result
from tests.fixtures.mock_server import mock_server

pytestmark = pytest.mark.asyncio


async def test_pipeline_discovers_and_scores():
    with mock_server() as base:
        result = await run_pipeline(base, probe=False, allow_private=True)

    paths = {e.path for e in result.endpoints}
    assert "/" in paths
    # The .env leak must be found and scored.
    env_findings = [f for f in result.findings if f.raw.rule_id == "INF-003"]
    assert env_findings, "expected INF-003 (.env exposed)"
    # Secrets in response -> API-013, forced CRITICAL.
    secret = [f for f in result.findings if f.raw.rule_id == "API-013"]
    assert secret and secret[0].severity.value == "CRITICAL"
    # Missing security headers fire somewhere (HDR-001 HSTS needs HTTPS).
    assert any(f.raw.rule_id == "HDR-002" for f in result.findings)
    # Stats populated.
    assert result.stats["findings"] > 0
    assert result.stats["endpoints"] == len(result.endpoints)


async def test_pipeline_persists_full_graph(engine):
    Session = __import__(
        "sqlalchemy.ext.asyncio", fromlist=["async_sessionmaker"]
    ).async_sessionmaker
    async_session = Session(bind=engine, expire_on_commit=False)

    with mock_server() as base:
        result = await run_pipeline(base, probe=False, allow_private=True)

    async with async_session() as session:
        scan = Scan(target_url=result.target, status=ScanStatus.RUNNING, progress=0)
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        await persist_result(session, scan, result)
        await session.commit()

        n_ep = (
            await session.execute(
                select(func.count()).select_from(Endpoint).where(Endpoint.scan_id == scan.id)
            )
        ).scalar_one()
        n_find = (
            await session.execute(
                select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id)
            )
        ).scalar_one()
        n_ins = (
            await session.execute(
                select(func.count()).select_from(AiInsight).where(AiInsight.scan_id == scan.id)
            )
        ).scalar_one()

        assert n_ep == len(result.endpoints)
        assert n_find == len(result.findings)
        assert n_ins == 1  # one built-in insight

        # Findings carry both the official base and the custom final score.
        f = (
            await session.execute(select(Finding).where(Finding.scan_id == scan.id).limit(1))
        ).scalar_one()
        assert f.base_score > 0
        assert f.final_score is not None
        assert f.cvss_vector.startswith("CVSS:3.1/")
        assert isinstance(f.evidence, dict)

        # Body signals are persisted per endpoint.
        ep_rows = (
            (await session.execute(select(Endpoint).where(Endpoint.scan_id == scan.id)))
            .scalars()
            .all()
        )
        assert any(e.body_signals.get("credentials") for e in ep_rows)

    await async_session().close()


async def test_passive_pipeline_never_probes_the_wordlist():
    # ScanRequest.passive_only: GET/HEAD only, so the wordlist (/.env) is skipped.
    with mock_server() as base:
        result = await run_pipeline(base, probe=False, allow_private=True, passive_only=True)
    assert all(e.discovered_by.value != "WORDLIST" for e in result.endpoints)
    assert not any(f.raw.rule_id == "INF-003" for f in result.findings)
