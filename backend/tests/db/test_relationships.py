"""Relationships, cascades and constraints of the data model.

Deletes use SQL ``DELETE`` statements (not ORM cascades) so the tests prove the
database's own ``ON DELETE`` rules, which is what protects data written by the
worker. Runs on SQLite (foreign keys enabled) and PostgreSQL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from app.db.models import (
    AiInsight,
    AttackChain,
    ContextClass,
    Cookie,
    DiscoveryMethod,
    Endpoint,
    Feedback,
    Finding,
    FindingCategory,
    Header,
    Scan,
    ScanStatus,
    Severity,
    TlsInfo,
    chain_findings,
)

pytestmark = pytest.mark.asyncio

CHILD_TABLES = [Endpoint, Finding, Header, Cookie, TlsInfo, AttackChain, AiInsight, Feedback]


def _finding(scan: Scan | None, endpoint: Endpoint | None, check_id: str) -> Finding:
    return Finding(
        scan=scan,
        endpoint=endpoint,
        check_id=check_id,
        title=check_id,
        category=FindingCategory.HEADERS,
        owasp_map=["API8:2023"],
        cwe_map=["CWE-693"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        base_score=6.1,
        final_score=9.2,
        severity_bucket=Severity.CRITICAL,
        evidence={"text": "header missing", "header": "X-Frame-Options"},
    )


async def _graph(session: AsyncSession) -> Scan:
    """One scan with a row in every table."""
    scan = Scan(
        target_url="https://shop.example.com",
        status=ScanStatus.DONE,
        options={"max_endpoints": 200},
        authorization_confirmed=True,
        authorization_confirmed_at=datetime.now(UTC),
    )
    ep = Endpoint(
        scan=scan,
        url="https://shop.example.com/api/payment",
        path="/api/payment",
        context_class=ContextClass.CRITICAL,
        discovered_by=DiscoveryMethod.JAVASCRIPT,
        body_signals={
            "credentials": False,
            "pii": True,
            "financial": True,
            "internal_ip": False,
            "bonus": 2.0,
            "reasons": ["card number"],
        },
    )
    ep.headers.append(Header(name="Server", value="nginx"))
    ep.cookies.append(Cookie(name="session"))
    on_ep = _finding(scan, ep, "HDR-003")
    host_level = _finding(scan, None, "TLS-001")
    scan.tls_info.append(TlsInfo(host="shop.example.com"))
    scan.attack_chains.append(
        AttackChain(
            chain_code="C001",
            name="chain",
            template_composite_score=9.4,
            severity=Severity.CRITICAL,
            findings=[on_ep, host_level],
        )
    )
    scan.ai_insights.append(AiInsight(provider="builtin", summary="summary"))
    scan.feedback.append(Feedback(finding=on_ep, is_false_positive=True))
    scan.feedback.append(Feedback(note="scan-level note"))
    session.add(scan)
    await session.commit()
    return scan


async def _count(session: AsyncSession, model) -> int:
    return (await session.execute(select(func.count()).select_from(model))).scalar_one()


@pytest.fixture
async def session(engine):
    async with async_sessionmaker(engine, expire_on_commit=False)() as s:
        yield s


async def test_relationships_navigate_both_ways(session):
    scan = await _graph(session)
    session.expunge_all()

    loaded = (
        await session.execute(
            select(Scan)
            .where(Scan.id == scan.id)
            .options(
                selectinload(Scan.endpoints).selectinload(Endpoint.headers),
                selectinload(Scan.endpoints).selectinload(Endpoint.cookies),
                selectinload(Scan.endpoints).selectinload(Endpoint.findings),
                selectinload(Scan.findings).selectinload(Finding.chains),
                selectinload(Scan.attack_chains).selectinload(AttackChain.findings),
                selectinload(Scan.feedback).selectinload(Feedback.finding),
                selectinload(Scan.tls_info),
                selectinload(Scan.ai_insights),
            )
        )
    ).scalar_one()

    [ep] = loaded.endpoints
    assert [h.name for h in ep.headers] == ["Server"]
    assert [c.name for c in ep.cookies] == ["session"]
    assert [f.check_id for f in ep.findings] == ["HDR-003"]
    assert {f.check_id for f in loaded.findings} == {"HDR-003", "TLS-001"}
    assert all(len(f.chains) == 1 for f in loaded.findings)
    assert {f.check_id for f in loaded.attack_chains[0].findings} == {"HDR-003", "TLS-001"}
    assert {fb.finding.check_id if fb.finding else None for fb in loaded.feedback} == {
        "HDR-003",
        None,
    }
    assert len(loaded.tls_info) == 1 and len(loaded.ai_insights) == 1


async def test_json_columns_round_trip(session):
    scan = await _graph(session)
    session.expunge_all()

    f = (
        await session.execute(
            select(Finding).where(Finding.scan_id == scan.id, Finding.check_id == "HDR-003")
        )
    ).scalar_one()
    assert f.evidence == {"text": "header missing", "header": "X-Frame-Options"}
    assert f.owasp_map == ["API8:2023"] and f.cwe_map == ["CWE-693"]
    ep = (await session.execute(select(Endpoint))).scalar_one()
    assert ep.body_signals["financial"] is True
    s = (await session.execute(select(Scan))).scalar_one()
    assert s.options == {"max_endpoints": 200}
    tls = (await session.execute(select(TlsInfo))).scalar_one()
    assert tls.weak_ciphers == [] and tls.issues == []  # data-model fields, default empty


async def test_deleting_scan_cascades_to_every_child_table(session):
    scan = await _graph(session)
    assert all([await _count(session, m) for m in CHILD_TABLES])

    await session.execute(delete(Scan).where(Scan.id == scan.id))
    await session.commit()

    for model in CHILD_TABLES:
        assert await _count(session, model) == 0, model.__tablename__
    assert await _count(session, chain_findings) == 0


async def test_deleting_endpoint_keeps_findings_but_unlinks_them(session):
    scan = await _graph(session)
    ep_id = (await session.execute(select(Endpoint.id))).scalar_one()

    await session.execute(delete(Endpoint).where(Endpoint.id == ep_id))
    await session.commit()
    session.expunge_all()

    assert await _count(session, Header) == 0
    assert await _count(session, Cookie) == 0
    findings = (
        (await session.execute(select(Finding).where(Finding.scan_id == scan.id))).scalars().all()
    )
    assert len(findings) == 2
    assert all(f.endpoint_id is None for f in findings)  # ON DELETE SET NULL


async def test_deleting_finding_removes_its_links_and_feedback_only(session):
    await _graph(session)
    fid = (
        await session.execute(select(Finding.id).where(Finding.check_id == "HDR-003"))
    ).scalar_one()

    await session.execute(delete(Finding).where(Finding.id == fid))
    await session.commit()

    assert await _count(session, chain_findings) == 1  # TLS-001 link remains
    assert await _count(session, AttackChain) == 1  # chain itself stays
    remaining = (await session.execute(select(Feedback))).scalars().all()
    assert [fb.note for fb in remaining] == ["scan-level note"]


async def test_finding_requires_existing_scan(session):
    orphan = _finding(None, None, "HDR-001")
    orphan.scan_id = uuid.uuid4()
    session.add(orphan)
    with pytest.raises(IntegrityError):
        await session.commit()


@pytest.mark.parametrize("confirmed, at", [(True, None), (False, datetime.now(UTC))])
async def test_authorization_flag_and_timestamp_go_together(session, confirmed, at):
    session.add(
        Scan(
            target_url="https://shop.example.com",
            authorization_confirmed=confirmed,
            authorization_confirmed_at=at,
        )
    )
    with pytest.raises(IntegrityError):
        await session.commit()


async def test_scan_defaults(session):
    scan = Scan(target_url="https://shop.example.com")
    session.add(scan)
    await session.commit()
    assert scan.status is ScanStatus.QUEUED
    assert scan.options == {}
    assert scan.authorization_confirmed is False
    assert {s.value for s in ScanStatus} == {"QUEUED", "RUNNING", "DONE", "FAILED"}
