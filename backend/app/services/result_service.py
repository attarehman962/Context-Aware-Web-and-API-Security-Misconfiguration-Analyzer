"""Persist a pipeline :class:`ScanResult` into the database (spec section 19).

Kept separate from the pipeline so the scanner stays database-free and unit-
testable. All writes happen inside the caller's transaction/session.
"""
from __future__ import annotations

from typing import Any

from app.core.body_classifier import BodyClassification
from app.core.checks.base import RawFinding
from app.core.pipeline import ScanResult
from app.core.tls import weak_ciphers
from app.db.models import (
    AiInsight,
    AttackChain,
    Cookie,
    Endpoint,
    Finding,
    Header,
    Scan,
    TlsInfo,
)
from app.db.models.enums import FindingCategory
from app.services.insights import generate_insight
from app.utils.logging import get_logger
from app.utils.redaction import redact_text

logger = get_logger(__name__)

# Only persist headers that carry security signal (keeps rows bounded).
_SECURITY_HEADERS = {
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-resource-policy",
    "cache-control", "server", "x-powered-by", "set-cookie",
    "access-control-allow-origin", "access-control-allow-credentials",
    "www-authenticate",
}


def _redacted(value: Any) -> Any:
    """Evidence goes through redaction before it is stored (checks may quote
    header values or body snippets); keys and non-strings are kept."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: _redacted(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redacted(v) for v in value]
    return value


def body_signals_json(body: BodyClassification | None) -> dict[str, Any]:
    """Endpoint ``body_signals`` JSON (evidence is already redacted)."""
    if body is None:
        return {}
    return {
        "credentials": body.credentials,
        "pii": body.pii,
        "financial": body.financial,
        "internal_ip": body.internal_ip,
        "bonus": body.bonus,
        "reasons": list(body.reasons),
    }


def tls_issues(findings: list[RawFinding]) -> list[str]:
    """``tls_info.issues``: the TLS check ids that fired for the host."""
    return sorted({f.rule_id for f in findings if f.category is FindingCategory.TLS})


async def persist_result(session, scan: Scan, result: ScanResult) -> None:
    """Write endpoints, findings, TLS, chains and an insight for ``scan``."""
    endpoint_rows: list[Endpoint] = []

    for ep in result.endpoints:
        row = Endpoint(
            scan_id=scan.id,
            url=ep.url,
            path=ep.path,
            method=ep.method,
            status_code=ep.status_code,
            content_type=ep.content_type,
            context_class=ep.context_class,
            context_confidence=ep.context_confidence,
            context_reason=ep.context_reason,
            body_signals=body_signals_json(ep.body_class),
            response_time=ep.response_time,
            discovered_by=ep.discovered_by,
        )
        session.add(row)
        endpoint_rows.append(row)

        for name, value in ep.headers.items():
            if name.lower() in _SECURITY_HEADERS:
                session.add(Header(endpoint=row, name=name, value=value))
        for ck in ep.cookies:
            session.add(Cookie(
                endpoint=row, name=ck.name, value_length=ck.value_length,
                http_only=ck.http_only, secure=ck.secure, same_site=ck.same_site,
                domain=ck.domain, path=ck.path,
            ))

    # Findings -- keep a rule_id -> [Finding] map for chain linking.
    finding_rows: list[Finding] = []
    by_rule: dict[str, list[Finding]] = {}
    for sf in result.findings:
        raw = sf.raw
        ep_row = (endpoint_rows[sf.endpoint_index]
                  if sf.endpoint_index is not None and sf.endpoint_index < len(endpoint_rows)
                  else None)
        frow = Finding(
            scan_id=scan.id,
            endpoint=ep_row,
            check_id=raw.rule_id,
            title=raw.title,
            category=raw.category,
            description=redact_text(raw.evidence),
            context_class=sf.context_class,
            context_confidence=sf.context_confidence,
            cvss_vector=raw.cvss_vector,
            base_score=sf.cvss_base_score,
            cawasma_context_multiplier=sf.context_multiplier,
            response_bonus=sf.response_bonus,
            final_score=sf.cawasma_final_score,
            final_vector=sf.final_vector,
            score_reasons=sf.score_reasons or None,
            severity_bucket=sf.severity,
            owasp_map=sf.owasp_map,
            cwe_map=sf.cwe_map,
            evidence=_redacted(sf.evidence or ({"text": raw.evidence} if raw.evidence else {})),
            impact=raw.impact,
            recommendation=raw.recommendation,
            references=raw.references,
            limitation=raw.limitation,
        )
        session.add(frow)
        finding_rows.append(frow)
        by_rule.setdefault(raw.rule_id, []).append(frow)

    # TLS info (host-level).
    if result.tls and result.tls.reachable:
        t = result.tls
        session.add(TlsInfo(
            scan_id=scan.id, host=t.host,
            protocols_offered=t.protocols_offered,
            weak_ciphers=weak_ciphers(t),
            issues=tls_issues([sf.raw for sf in result.findings]),
            negotiated_protocol=t.negotiated_protocol,
            negotiated_cipher=t.negotiated_cipher,
            cert_subject=t.cert_subject, cert_issuer=t.cert_issuer,
            cert_not_after=t.cert_not_after, is_self_signed=t.is_self_signed,
            hostname_matches=t.hostname_matches,
        ))

    # Attack chains + link member findings.
    for ch in result.chains:
        chain_row = AttackChain(
            scan_id=scan.id, chain_code=ch.code, name=ch.name,
            description=ch.description,
            template_composite_score=ch.composite_score, severity=ch.severity,
            composite_vector=ch.composite_vector, evidence=ch.evidence,
        )
        # Exactly the member findings of this unit (not every finding with a
        # matching check id elsewhere in the scan).
        for i in ch.member_indexes:
            chain_row.findings.append(finding_rows[i])
        session.add(chain_row)

    # Deterministic executive insight (built-in, not an external LLM).
    session.add(AiInsight(
        scan_id=scan.id, provider="builtin",
        summary=generate_insight(result),
    ))

    logger.info("persisted scan %s: %d endpoints, %d findings, %d chains",
                scan.id, len(endpoint_rows), len(finding_rows), len(result.chains))
