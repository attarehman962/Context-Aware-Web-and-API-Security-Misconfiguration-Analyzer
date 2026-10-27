"""Seed the database with realistic sample data.

One target (``https://shop.example.com``) scanned twice: a baseline a week ago
and a rescan today -- 10 endpoints, 16 findings spanning CRITICAL/HIGH/MEDIUM/
LOW, one attack chain, plus headers, cookies, TLS facts, insights and analyst
feedback, so every table has rows.

Nothing here is hand-scored: sensitivity classes come from the real endpoint
classifier, body signals from the real body classifier (so evidence is
redacted), scores from :func:`app.core.cvss.compute_score` with the catalog's
CVSS v3.1 base vectors, and the chains from :func:`app.core.chains.correlate`
over config/chains.yaml.
OWASP/CWE mappings are illustrative until the catalog carries them
(docs/db-decisions.md).

Idempotent: rows have fixed ids and the script skips if they already exist.

    python scripts/seed.py          # or: make seed
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select

from app.core.body_classifier import BodyClassification, classify_body
from app.core.chains import ChainEndpoint, ChainMember, correlate
from app.core.checks.catalog import CATALOG
from app.core.contracts import BodySignal
from app.core.cvss import compute_score
from app.core.cvss31 import base_score
from app.core.pipeline import _BONUS_RULES, _FORCE_CRIT_RULES  # same rules as live scans
from app.core.sensitivity import SensitivityClassifier
from app.db.models import (
    AiInsight,
    AttackChain,
    Cookie,
    DiscoveryMethod,
    Endpoint,
    Feedback,
    Finding,
    Header,
    SameSite,
    Scan,
    ScanStatus,
    TlsInfo,
)
from app.db.session import session_scope
from app.services.result_service import body_signals_json
from app.utils.logging import configure_logging, get_logger

logger = get_logger(__name__)

TARGET = "https://shop.example.com"
_NS = uuid.UUID("6f1c2a52-6c1e-4d0a-9b8e-2f1f5c0a0001")


def _id(name: str) -> uuid.UUID:
    """Stable id so re-running the seed is a no-op."""
    return uuid.uuid5(_NS, name)


BASELINE_SCAN_ID = _id("scan:baseline")
RESCAN_SCAN_ID = _id("scan:rescan")

# Illustrative OWASP API Top 10 (2023) / CWE mappings for the seeded checks.
_MAPPINGS: dict[str, tuple[list[str], list[str]]] = {
    "HDR-002": (["API8:2023"], ["CWE-693"]),
    "HDR-003": (["API8:2023"], ["CWE-1021"]),
    "HDR-005": (["API8:2023"], ["CWE-200"]),
    "HDR-007": (["API8:2023"], ["CWE-497"]),
    "HDR-012": (["API8:2023"], ["CWE-693"]),
    "API-003": (["API2:2023"], ["CWE-306"]),
    "CKI-002": (["API8:2023"], ["CWE-614"]),
    "CKI-003": (["API8:2023"], ["CWE-1275"]),
    "INF-003": (["API8:2023"], ["CWE-538"]),
    "TLS-001": (["API8:2023"], ["CWE-327"]),
}


@dataclass
class EndpointSpec:
    path: str
    discovered_by: DiscoveryMethod
    content_type: str
    status_code: int = 200
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    # (check id, check-specific evidence detail)
    findings: list[tuple[str, dict[str, Any]]] = field(default_factory=list)


_SERVER = {"Server": "nginx/1.18.0 (Ubuntu)"}

RESCAN: list[EndpointSpec] = [
    EndpointSpec(
        "/", DiscoveryMethod.SEED, "text/html", headers=_SERVER,
        findings=[
            ("HDR-007", {"header": "Server", "value": "nginx/1.18.0 (Ubuntu)"}),
            ("HDR-003", {"header": "X-Frame-Options", "present": False}),
        ],
    ),
    EndpointSpec(
        "/api/v1/users/42", DiscoveryMethod.JAVASCRIPT, "application/json",
        body='{"id": 42, "name": "Ayesha Khan", "email": "ayesha.khan@example.com", '
             '"phone": "+92 300 1234567", "role": "customer"}',
        findings=[
            ("API-003", {"auth_header_sent": False, "status": 200}),
            ("HDR-005", {"header": "Referrer-Policy", "present": False}),
        ],
    ),
    EndpointSpec(
        "/api/payment/checkout", DiscoveryMethod.JAVASCRIPT, "application/json",
        body='{"order": 1187, "card": "4111 1111 1111 1111", "amount": "4999.00", '
             '"currency": "PKR"}',
        findings=[("HDR-002", {"header": "Content-Security-Policy", "present": False})],
    ),
    EndpointSpec(
        "/admin/login", DiscoveryMethod.WORDLIST, "text/html",
        cookies=[{"name": "admin_session", "value_length": 32, "http_only": True,
                  "secure": False, "same_site": SameSite.UNSET, "path": "/admin"}],
        findings=[
            ("CKI-002", {"cookie": "admin_session", "secure": False}),
            ("CKI-003", {"cookie": "admin_session", "same_site": None}),
        ],
    ),
    EndpointSpec(
        "/.env", DiscoveryMethod.WORDLIST, "text/plain",
        body="APP_ENV=production\nDB_HOST=10.0.3.17\n"
             "DB_PASSWORD=Sup3rS3cret!2024\nSTRIPE_SECRET_KEY=sk_live_51Hx9aQ2eZvKYlo2C\n",
        findings=[("INF-003", {"path": "/.env", "status": 200})],
    ),
    EndpointSpec(
        "/static/js/app.3f9c1.js", DiscoveryMethod.HTML, "application/javascript",
        findings=[("HDR-012", {"header": "Expect-CT", "present": False})],
    ),
]

BASELINE: list[EndpointSpec] = [
    EndpointSpec(
        "/", DiscoveryMethod.SEED, "text/html", headers=_SERVER,
        findings=[
            ("HDR-007", {"header": "Server", "value": "nginx/1.18.0 (Ubuntu)"}),
            ("HDR-003", {"header": "X-Frame-Options", "present": False}),
        ],
    ),
    EndpointSpec(
        "/about", DiscoveryMethod.HTML, "text/html",
        findings=[("HDR-005", {"header": "Referrer-Policy", "present": False})],
    ),
    EndpointSpec(
        "/api/v1/products", DiscoveryMethod.JAVASCRIPT, "application/json",
        body='[{"sku": "TS-001", "name": "Cotton T-shirt", "price": "1299.00"}]',
        findings=[("HDR-002", {"header": "Content-Security-Policy", "present": False})],
    ),
    EndpointSpec(
        "/login", DiscoveryMethod.HTML, "text/html",
        cookies=[{"name": "session", "value_length": 32, "http_only": True,
                  "secure": True, "same_site": SameSite.UNSET, "path": "/"}],
        findings=[
            ("CKI-003", {"cookie": "session", "same_site": None}),
            ("HDR-005", {"header": "Referrer-Policy", "present": False}),
        ],
    ),
]


def _finding(
    scan: Scan, endpoint: Endpoint | None, check_id: str, detail: dict[str, Any],
    body: BodyClassification | None,
) -> Finding:
    meta = CATALOG[check_id]
    bonus = body.bonus if body is not None and check_id in _BONUS_RULES else 0.0
    force = bool(body and body.force_critical and check_id in _FORCE_CRIT_RULES)
    ctx = endpoint.context_class if endpoint is not None else None
    # Score of the vector, as live scans do (catalog base_score can disagree).
    score = compute_score(base_score(meta.cvss_vector), ctx, bonus, force_critical=force)
    owasp, cwe = _MAPPINGS.get(check_id, ([], []))
    text = f"{meta.name}" + (f" on {endpoint.path}" if endpoint is not None else "")
    if body is not None and body.evidence and check_id in _BONUS_RULES:
        detail = {**detail, "body_excerpt": body.evidence}
    return Finding(
        scan=scan,
        endpoint=endpoint,
        check_id=check_id,
        title=meta.name,
        category=meta.category,
        description=meta.impact,
        owasp_map=owasp,
        cwe_map=cwe,
        context_class=ctx,
        context_confidence=endpoint.context_confidence if endpoint is not None else None,
        cvss_vector=meta.cvss_vector,
        base_score=score.cvss_base_score,
        cawasma_context_multiplier=score.context_multiplier,
        response_bonus=score.response_bonus,
        final_score=score.cawasma_final_score,
        severity_bucket=score.severity,
        evidence={"text": text, **detail},
        impact=meta.impact,
        recommendation=meta.recommendation,
        references=list(meta.references),
        limitation=meta.limitation,
    )


def _build_scan(
    scan_id: uuid.UUID, specs: list[EndpointSpec], started: datetime, duration: float,
    classifier: SensitivityClassifier, *, legacy_tls: bool,
) -> tuple[Scan, list[Finding]]:
    finished = started + timedelta(seconds=duration)
    scan = Scan(
        id=scan_id,
        target_url=TARGET,
        status=ScanStatus.DONE,
        progress=100,
        current_stage="completed",
        options={"max_endpoints": 200, "max_crawl_depth": 2, "request_timeout": 15.0},
        authorization_confirmed=True,
        authorization_confirmed_at=started - timedelta(minutes=2),
        started_at=started,
        completed_at=finished,
        duration_seconds=duration,
        created_at=started - timedelta(minutes=2),
        updated_at=finished,
    )
    findings: list[Finding] = []
    for i, spec in enumerate(specs):
        cls = classifier.classify(spec.path)
        body = classify_body(spec.body, spec.content_type) if spec.body else None
        endpoint = Endpoint(
            id=_id(f"{scan_id}:endpoint:{spec.path}"),
            scan=scan,
            url=TARGET + spec.path,
            path=spec.path,
            status_code=spec.status_code,
            content_type=spec.content_type,
            context_class=cls.context_class,
            context_confidence=round(cls.confidence, 2),
            context_reason=cls.reason,
            body_signals=body_signals_json(body),
            response_time=round(0.08 + 0.03 * i, 3),
            discovered_by=spec.discovered_by,
        )
        for name, value in spec.headers.items():
            endpoint.headers.append(Header(name=name, value=value))
        for ck in spec.cookies:
            endpoint.cookies.append(Cookie(domain="shop.example.com", **ck))
        for check_id, detail in spec.findings:
            findings.append(_finding(scan, endpoint, check_id, detail, body))
    scan.tls_info.append(TlsInfo(
        host="shop.example.com",
        protocols_offered=(["TLSv1.1", "TLSv1.2", "TLSv1.3"] if legacy_tls
                           else ["TLSv1.2", "TLSv1.3"]),
        negotiated_protocol="TLSv1.3",
        negotiated_cipher="TLS_AES_256_GCM_SHA384",
        cert_subject="CN=shop.example.com",
        cert_issuer="CN=R11,O=Let's Encrypt,C=US",
        cert_not_after=started + timedelta(days=64),
        is_self_signed=False,
        hostname_matches=True,
        weak_ciphers=[],                            # TLS_AES_256_GCM_SHA384 is strong
        issues=["TLS-001"] if legacy_tls else [],   # matches the finding below
    ))
    if legacy_tls:  # host-level finding: no endpoint
        findings.append(_finding(scan, None, "TLS-001",
                                 {"protocols": ["TLSv1.1"]}, None))
    return scan, findings


# endpoints.body_signals JSON key -> contract signal (as result_service stores them)
_SIGNALS = {"credentials": BodySignal.CREDENTIALS, "pii": BodySignal.PII,
            "financial": BodySignal.FINANCIAL, "internal_ip": BodySignal.INTERNAL_IP}


def _add_chains(scan: Scan, findings: list[Finding]) -> int:
    """Correlate exactly as live scans do (core/chains.py over config/chains.yaml)."""
    endpoints = list(dict.fromkeys(f.endpoint for f in findings if f.endpoint is not None))
    index = {id(e): i for i, e in enumerate(endpoints)}
    host = urlparse(scan.target_url).netloc.lower()
    detected = correlate(
        [ChainMember(f.check_id, index.get(id(f.endpoint)) if f.endpoint else None, host)
         for f in findings],
        [ChainEndpoint(e.url, e.context_class, frozenset(
            sig for key, sig in _SIGNALS.items() if (e.body_signals or {}).get(key)))
         for e in endpoints])
    for ch in detected:
        scan.attack_chains.append(AttackChain(
            chain_code=ch.code, name=ch.name, description=ch.description,
            template_composite_score=ch.composite_score, severity=ch.severity,
            composite_vector=ch.composite_vector, evidence=ch.evidence,
            findings=[findings[i] for i in ch.member_indexes],
        ))
    return len(detected)


async def seed() -> bool:
    """Insert the sample data. Returns False if it was already present."""
    async with session_scope() as session:
        if await session.scalar(select(Scan.id).where(Scan.id == RESCAN_SCAN_ID)):
            logger.info("seed: sample data already present, skipping")
            return False

        classifier = SensitivityClassifier(use_embeddings=False)  # deterministic
        now = datetime.now(UTC).replace(microsecond=0)
        baseline, baseline_findings = _build_scan(
            BASELINE_SCAN_ID, BASELINE, now - timedelta(days=7, hours=3), 38.4,
            classifier, legacy_tls=False,
        )
        rescan, rescan_findings = _build_scan(
            RESCAN_SCAN_ID, RESCAN, now - timedelta(hours=1), 71.9,
            classifier, legacy_tls=True,
        )
        chains = _add_chains(baseline, baseline_findings) + _add_chains(rescan, rescan_findings)

        for scan, fs in ((baseline, baseline_findings), (rescan, rescan_findings)):
            worst = max(fs, key=lambda f: f.final_score)
            scan.ai_insights.append(AiInsight(
                provider="builtin",
                summary=(f"{len(fs)} findings on {TARGET}. Highest priority: "
                         f"{worst.check_id} {worst.title} (score {worst.final_score})."),
            ))

        hdr012 = next(f for f in rescan_findings if f.check_id == "HDR-012")
        rescan.feedback.append(Feedback(
            finding=hdr012, is_false_positive=True,
            note="Expect-CT is deprecated; browsers enforce CT by default.",
        ))
        rescan.feedback.append(Feedback(
            is_false_positive=False,
            note=".env exposure confirmed with the site owner; rotation in progress.",
        ))

        session.add_all([baseline, rescan])
    logger.info("seed: inserted 2 scans, %d endpoints, %d findings, %d chain(s)",
                len(BASELINE) + len(RESCAN),
                len(baseline_findings) + len(rescan_findings), chains)
    return True


def main() -> None:
    configure_logging()
    asyncio.run(seed())


if __name__ == "__main__":
    main()
