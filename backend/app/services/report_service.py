"""Report data assembly (spec sections 25-27).

Loads a scan graph from the database into the plain dict that the DB-free
renderers in :mod:`app.core.reports` consume. Re-exports the renderers so
callers can keep importing them from here.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.reports import (  # noqa: F401  (re-exported)
    ReportFormatUnavailable,
    render_csv,
    render_html,
    render_json,
    render_pdf,
)
from app.db.models import AttackChain, Endpoint, Finding, Scan
from app.db.models.enums import Severity
from app.utils.logging import get_logger

logger = get_logger(__name__)

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
              Severity.LOW, Severity.INFO]


def _dt(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


async def build_report_data(session, scan_id: uuid.UUID) -> dict | None:
    """Assemble the full report payload for a scan, or None if not found."""
    scan = (await session.execute(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(
            selectinload(Scan.ai_insights),
            selectinload(Scan.tls_info),
        )
    )).scalar_one_or_none()
    if scan is None:
        return None

    findings = list((await session.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .options(selectinload(Finding.endpoint))
        .order_by(Finding.final_score.desc())
    )).scalars())

    endpoints = list((await session.execute(
        select(Endpoint).where(Endpoint.scan_id == scan_id)
        .order_by(Endpoint.context_class)
    )).scalars())

    chains = list((await session.execute(
        select(AttackChain).where(AttackChain.scan_id == scan_id)
        .options(selectinload(AttackChain.findings))
    )).scalars())

    by_sev = {s.value: 0 for s in Severity}
    for f in findings:
        by_sev[f.severity_bucket.value] += 1

    return {
        "scan": {
            "id": str(scan.id),
            "target_url": scan.target_url,
            "status": scan.status.public_value,
            "started_at": _dt(scan.started_at),
            "completed_at": _dt(scan.completed_at),
            "duration_seconds": scan.duration_seconds,
        },
        "summary": {
            "total_findings": len(findings),
            "total_endpoints": len(endpoints),
            "total_chains": len(chains),
            "by_severity": by_sev,
            "max_score": max((f.final_score for f in findings), default=0),
        },
        "insight": scan.ai_insights[0].summary if scan.ai_insights else None,
        "tls": [{
            "host": t.host, "negotiated_protocol": t.negotiated_protocol,
            "negotiated_cipher": t.negotiated_cipher,
            "protocols_offered": t.protocols_offered,
            "cert_issuer": t.cert_issuer, "cert_not_after": _dt(t.cert_not_after),
            "is_self_signed": t.is_self_signed, "hostname_matches": t.hostname_matches,
        } for t in scan.tls_info],
        "endpoints": [{
            "url": e.url, "path": e.path, "method": e.method,
            "status_code": e.status_code,
            "context_class": e.context_class.value if e.context_class else None,
            "context_confidence": e.context_confidence,
            "context_reason": e.context_reason,
            "discovered_by": e.discovered_by.value,
        } for e in endpoints],
        "findings": [{
            "rule_id": f.check_id, "title": f.title,
            "category": f.category.value, "severity": f.severity_bucket.value,
            "owasp_map": f.owasp_map, "cwe_map": f.cwe_map,
            "cvss_vector": f.cvss_vector, "cvss_base_score": f.base_score,
            "final_vector": f.final_vector, "score_reasons": f.score_reasons or [],
            "context_class": f.context_class.value if f.context_class else None,
            "cawasma_context_multiplier": f.cawasma_context_multiplier,
            "response_bonus": f.response_bonus,
            "cawasma_final_score": f.final_score,
            "endpoint_url": f.endpoint.url if f.endpoint else None,
            "evidence": f.evidence.get("text"), "impact": f.impact,
            "recommendation": f.recommendation, "references": f.references,
            "limitation": f.limitation,
        } for f in findings],
        "chains": [{
            "code": c.chain_code, "name": c.name, "description": c.description,
            "composite_score": c.template_composite_score,
            "composite_vector": c.composite_vector,
            "severity": c.severity.value,
            "member_findings": sorted({m.check_id for m in c.findings}),
        } for c in chains],
    }
