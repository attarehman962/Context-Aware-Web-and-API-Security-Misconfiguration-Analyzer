"""High-level scanning orchestration."""

from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db, socketio
from app.models import Endpoint, ExploitChain, Finding, Scan
from app.scanner.body_classifier import classify_body
from app.scanner.checks import build_findings, build_scan_context
from app.scanner.chains import correlate
from app.scanner.crawler import EndpointCrawler
from app.scanner.cvss import adjust_score
from app.scanner.sensitivity import classify_endpoint


class ScanEngine:
    def __init__(self, flask_app):
        self.app = flask_app
        self.crawler = EndpointCrawler(
            max_depth=flask_app.config.get("MAX_CRAWL_DEPTH", 2),
            max_endpoints=flask_app.config.get("MAX_ENDPOINTS", 100),
        )

    def _emit(self, event: str, payload: dict) -> None:
        socketio.emit(event, payload)

    def run(self, scan: Scan) -> dict:
        scan.status = "running"
        db.session.add(scan)
        db.session.flush()

        crawl_result = self.crawler.crawl(scan.target_url)
        endpoints = []
        body_signal_labels: list[str] = []

        for discovered in crawl_result.endpoints:
            endpoint_result = classify_endpoint(discovered.path)
            response_evidence = discovered.body or discovered.evidence
            endpoint = Endpoint(
                scan_id=scan.id,
                url=discovered.url,
                path=discovered.path,
                method=discovered.method,
                sensitivity=endpoint_result.label,
                evidence=discovered.evidence,
            )
            db.session.add(endpoint)
            db.session.flush()
            endpoints.append(endpoint)

            body_result = classify_body(response_evidence)
            body_signal_labels.extend(body_result.labels)

            scan_context = build_scan_context(
                discovered.url,
                discovered.path,
                discovered.method,
                endpoint_result.label,
                body_result.labels,
                evidence=discovered.evidence,
                response_headers=discovered.headers,
                response_body=response_evidence,
                status_code=discovered.status_code,
            )

            for draft in build_findings(scan_context):
                score = adjust_score(draft.base_cvss, endpoint_result.label, body_result.as_bonus())
                finding = Finding(
                    scan_id=scan.id,
                    endpoint_id=endpoint.id,
                    check_name=draft.check_name,
                    title=draft.title,
                    severity=score.severity,
                    cvss_base=score.base_score,
                    cvss_adjusted=score.adjusted_score,
                    evidence=draft.evidence,
                    details=f"{draft.details}. {score.explanation}",
                )
                db.session.add(finding)

            self._emit(
                "scan.progress",
                {
                    "scan_id": scan.id,
                    "endpoint": discovered.path,
                    "sensitivity": endpoint_result.label,
                    "status_code": discovered.status_code,
                },
            )

        db.session.flush()
        findings_payload = [{"check_name": finding.check_name, "severity": finding.severity} for finding in Finding.query.filter_by(scan_id=scan.id).all()]
        chain_matches = correlate(findings_payload, body_signal_labels)

        for chain in chain_matches:
            db.session.add(
                ExploitChain(
                    scan_id=scan.id,
                    name=chain.name,
                    summary=chain.summary,
                    composite_cvss=chain.composite_cvss,
                    evidence=", ".join(chain.matched_signals),
                )
            )

        scan.status = "complete"
        scan.completed_at = datetime.now(UTC)
        scan.summary = f"Discovered {len(endpoints)} endpoints, {len(findings_payload)} findings, and {len(chain_matches)} chains."
        db.session.add(scan)
        db.session.flush()

        return {
            "scan_id": scan.id,
            "endpoints": [{"id": endpoint.id, "path": endpoint.path, "url": endpoint.url, "method": endpoint.method, "sensitivity": endpoint.sensitivity} for endpoint in endpoints],
            "findings": len(findings_payload),
            "chains": [chain.name for chain in chain_matches],
        }
