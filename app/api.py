"""JSON API routes for scans and results."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.models import ExploitChain, Finding, Scan
from app.tasks import enqueue_scan


api_bp = Blueprint("api", __name__)


@api_bp.post("/scans")
def create_scan():
    payload = request.get_json(force=True, silent=True) or {}
    target_url = payload.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    scan = Scan(target_url=target_url, profile=payload.get("profile", "Standard"), auth_token=payload.get("auth_token"), status="queued")
    from app.extensions import db

    db.session.add(scan)
    db.session.commit()
    enqueue_scan(scan.id)
    return jsonify({"scan_id": scan.id, "status": scan.status}), 201


@api_bp.get("/scans/<int:scan_id>")
def get_scan(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(
        {
            "id": scan.id,
            "target_url": scan.target_url,
            "profile": scan.profile,
            "status": scan.status,
            "summary": scan.summary,
            "findings": [
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "cvss_adjusted": finding.cvss_adjusted,
                }
                for finding in scan.findings
            ],
            "chains": [
                {"id": chain.id, "name": chain.name, "composite_cvss": chain.composite_cvss}
                for chain in scan.chains
            ],
        }
    )


@api_bp.get("/scans/<int:scan_id>/export")
def export_scan(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    findings = [finding for finding in Finding.query.filter_by(scan_id=scan.id).order_by(Finding.cvss_adjusted.desc()).all()]
    chains = [chain for chain in ExploitChain.query.filter_by(scan_id=scan.id).all()]
    return jsonify(
        {
            "scan": scan.target_url,
            "findings": [finding.title for finding in findings],
            "chains": [chain.name for chain in chains],
        }
    )
