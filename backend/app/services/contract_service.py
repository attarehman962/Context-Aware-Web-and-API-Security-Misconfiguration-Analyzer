"""Build API contract v1 responses (app/api/schemas/contract.py) from the database.

Reads only; scan creation goes through :mod:`app.services.scan_service`.
Export rendering reuses the DB-free renderers in :mod:`app.core.reports`.
"""
from __future__ import annotations

import csv
import io
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.schemas.contract import (
    Chain,
    ExportFormat,
    Finding,
    ScanOptions,
    ScanResults,
    ScanStatus,
    SeverityCounts,
)
from app.core.contracts import BodySignal
from app.core.reports import csv_safe, render_html, render_pdf
from app.db.models import AttackChain, Scan
from app.db.models import Finding as FindingRow

_SIGNAL_KEYS = {
    "credentials": BodySignal.CREDENTIALS,
    "pii": BodySignal.PII,
    "financial": BodySignal.FINANCIAL,
    "internal_ip": BodySignal.INTERNAL_IP,
}

CSV_COLUMNS = [
    "id", "check_id", "title", "category", "severity_bucket", "final_score", "base_score",
    "cvss_vector", "sensitivity_class", "body_signals", "owasp_map", "cwe_map",
    "endpoint_url", "chain_ids",
]


def _utc(value: datetime | None) -> datetime | None:
    """Contract timestamps are UTC; SQLite hands back naive values."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def scan_status(scan: Scan, counts: SeverityCounts | None = None) -> ScanStatus:
    opts = scan.options or {}
    return ScanStatus(
        scan_id=scan.id,
        url=scan.target_url,
        status=scan.status,
        progress=scan.progress,
        stage=scan.current_stage,
        options=ScanOptions(
            crawl_depth=opts.get("crawl_depth", 2),
            use_wordlist=opts.get("use_wordlist", True),
            passive_only=opts.get("passive_only", False),
        ),
        created_at=_utc(scan.created_at),
        started_at=_utc(scan.started_at),
        completed_at=_utc(scan.completed_at),
        error=scan.error_message,
        severity_counts=counts or SeverityCounts(),
    )


async def severity_counts(
    session: AsyncSession, scan_ids: list[uuid.UUID]
) -> dict[uuid.UUID, SeverityCounts]:
    rows = (await session.execute(
        select(FindingRow.scan_id, FindingRow.severity_bucket, func.count())
        .where(FindingRow.scan_id.in_(scan_ids))
        .group_by(FindingRow.scan_id, FindingRow.severity_bucket)
    )).all()
    out: dict[uuid.UUID, dict[str, int]] = defaultdict(dict)
    for scan_id, bucket, n in rows:
        out[scan_id][bucket.value.lower()] = n
    return {sid: SeverityCounts(**out.get(sid, {})) for sid in scan_ids}


async def list_scans(
    session: AsyncSession, offset: int, limit: int
) -> tuple[list[ScanStatus], int]:
    total = await session.scalar(select(func.count()).select_from(Scan)) or 0
    scans = list((await session.execute(
        select(Scan).order_by(Scan.created_at.desc(), Scan.id).offset(offset).limit(limit)
    )).scalars())
    counts = await severity_counts(session, [s.id for s in scans])
    return [scan_status(s, counts[s.id]) for s in scans], total


async def get_results(session: AsyncSession, scan_id: uuid.UUID) -> ScanResults | None:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        return None
    findings = list((await session.execute(
        select(FindingRow).where(FindingRow.scan_id == scan_id)
        .options(selectinload(FindingRow.endpoint), selectinload(FindingRow.chains))
    )).scalars())
    chains = list((await session.execute(
        select(AttackChain).where(AttackChain.scan_id == scan_id)
        .options(selectinload(AttackChain.findings))
        .order_by(AttackChain.template_composite_score.desc())
    )).scalars())
    counts = (await severity_counts(session, [scan_id]))[scan_id]
    return ScanResults(
        scan=scan_status(scan, counts),
        findings=[_finding(f) for f in findings],
        chains=[Chain(
            id=c.id, chain_code=c.chain_code, name=c.name, description=c.description,
            composite_score=c.template_composite_score, severity=c.severity,
            finding_ids=sorted(f.id for f in c.findings),
        ) for c in chains],
    )


def _finding(f: FindingRow) -> Finding:
    ep = f.endpoint
    signals = ep.body_signals if ep is not None else {}
    return Finding(
        id=f.id, check_id=f.check_id, title=f.title, category=f.category,
        endpoint_id=f.endpoint_id, endpoint_url=ep.url if ep is not None else None,
        owasp_map=f.owasp_map, cwe_map=f.cwe_map, cvss_vector=f.cvss_vector,
        base_score=f.base_score, final_score=f.final_score, final_vector=f.final_vector,
        score_reasons=f.score_reasons or [], severity_bucket=f.severity_bucket,
        evidence=f.evidence or {"text": f.title},
        sensitivity_class=ep.context_class if ep is not None else f.context_class,
        body_signals=sorted(sig for key, sig in _SIGNAL_KEYS.items() if signals.get(key)),
        chain_ids=sorted(c.id for c in f.chains),
        recommendation=f.recommendation, limitation=f.limitation,
    )


# ------------------------------------------------------------------- export

MEDIA_TYPES: dict[str, str] = {
    "json": "application/json",
    "csv": "text/csv; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
}


def export(results: ScanResults, fmt: ExportFormat) -> bytes:
    """Render results. ``json``/``csv`` are part of the frozen contract; ``html``/
    ``pdf`` are human-readable reports whose layout may change."""
    if fmt == "json":
        return results.model_dump_json(indent=2).encode()
    if fmt == "csv":
        return _csv(results).encode()
    html_data = report_data(results)
    if fmt == "html":
        return render_html(html_data).encode()
    return render_pdf(html_data)  # raises ReportFormatUnavailable without WeasyPrint libs


def _csv(results: ScanResults) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    for f in results.findings:
        writer.writerow([csv_safe(v) for v in (
            f.id, f.check_id, f.title, f.category.value, f.severity_bucket.value,
            f.final_score, f.base_score, f.cvss_vector,
            f.sensitivity_class.value if f.sensitivity_class else "",
            ";".join(s.value for s in f.body_signals), ";".join(f.owasp_map),
            ";".join(f.cwe_map), f.endpoint_url or "", ";".join(str(c) for c in f.chain_ids),
        )])
    return buf.getvalue()


def report_data(results: ScanResults) -> dict[str, Any]:
    """The dict the HTML/PDF template in core/reports.py expects."""
    s = results.scan
    by_sev = {k.upper(): v for k, v in s.severity_counts.model_dump().items()}
    code_of = {f.id: f.check_id for f in results.findings}
    endpoints = {f.endpoint_url: f for f in results.findings if f.endpoint_url}
    return {
        "scan": {
            "id": str(s.scan_id), "target_url": s.url, "status": s.status.value,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "duration_seconds": (s.completed_at - s.started_at).total_seconds()
            if s.completed_at and s.started_at else None,
        },
        "summary": {
            "total_findings": len(results.findings), "total_endpoints": len(endpoints),
            "total_chains": len(results.chains), "by_severity": by_sev,
            "max_score": max((f.final_score for f in results.findings), default=0),
        },
        "insight": None,
        "tls": [],
        "endpoints": [{
            "url": url, "path": urlparse(url).path or "/",
            "method": "GET", "status_code": None,
            "context_class": f.sensitivity_class.value if f.sensitivity_class else None,
            "context_confidence": None, "context_reason": None, "discovered_by": "-",
        } for url, f in endpoints.items()],
        "findings": [{
            "rule_id": f.check_id, "title": f.title, "category": f.category.value,
            "severity": f.severity_bucket.value, "cvss_vector": f.cvss_vector,
            "cvss_base_score": f.base_score,
            "context_class": f.sensitivity_class.value if f.sensitivity_class else None,
            "cawasma_context_multiplier": "", "response_bonus": None,
            "cawasma_final_score": f.final_score, "endpoint_url": f.endpoint_url,
            "evidence": f.evidence.get("text"), "impact": None,
            "recommendation": f.recommendation, "references": [],
            "limitation": f.limitation,
        } for f in results.findings],
        "chains": [{
            "code": c.chain_code, "name": c.name, "description": c.description,
            "composite_score": c.composite_score, "severity": c.severity.value,
            "member_findings": sorted({code_of[i] for i in c.finding_ids if i in code_of}),
        } for c in results.chains],
    }
