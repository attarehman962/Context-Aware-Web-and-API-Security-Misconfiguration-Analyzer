"""Dashboard routes."""

from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import selectinload

from flask import Blueprint, redirect, render_template, request, url_for

from app.extensions import db
from app.models import Endpoint, Finding, Scan
from app.tasks import enqueue_scan


main_bp = Blueprint("main", __name__)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SENSITIVITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _severity_counts(findings) -> dict[str, int]:
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        severity = (finding.severity or "info").lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _scan_view(scan: Scan) -> dict:
    counts = _severity_counts(scan.findings)
    highest_finding = max(
        scan.findings,
        key=lambda finding: (finding.cvss_adjusted, SEVERITY_ORDER.get((finding.severity or "").lower(), -1)),
        default=None,
    )
    return {
        "scan": scan,
        "severity_counts": counts,
        "finding_count": len(scan.findings),
        "endpoint_count": len(scan.endpoints),
        "chain_count": len(scan.chains),
        "top_score": highest_finding.cvss_adjusted if highest_finding else None,
        "top_severity": (highest_finding.severity or "info").lower() if highest_finding else None,
    }


@main_bp.get("/")
def index():
    scans = (
        Scan.query.options(
            selectinload(Scan.findings),
            selectinload(Scan.endpoints),
            selectinload(Scan.chains),
        )
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )
    recent_scans = [_scan_view(scan) for scan in scans]

    severity_totals = {
        (severity or "info").lower(): count
        for severity, count in db.session.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all()
    }
    dashboard_stats = {
        "total_scans": db.session.query(func.count(Scan.id)).scalar() or 0,
        "active_scans": db.session.query(func.count(Scan.id)).filter(Scan.status.in_(("queued", "running"))).scalar() or 0,
        "targets_analyzed": db.session.query(func.count(func.distinct(Scan.target_url))).scalar() or 0,
        "total_endpoints": db.session.query(func.count(Endpoint.id)).scalar() or 0,
        "critical_findings": severity_totals.get("critical", 0),
        "high_findings": severity_totals.get("high", 0),
        "medium_findings": severity_totals.get("medium", 0),
        "low_findings": severity_totals.get("low", 0),
        "total_findings": sum(severity_totals.values()),
        "top_score": db.session.query(func.max(Finding.cvss_adjusted)).scalar() or 0,
    }

    return render_template(
        "index.html",
        scans=scans,
        recent_scans=recent_scans,
        dashboard_stats=dashboard_stats,
    )


@main_bp.post("/launch")
def launch_scan():
    target_url = request.form.get("target_url", "").strip()
    profile = request.form.get("profile", "Standard")
    auth_token = request.form.get("auth_token", "").strip() or None

    if not target_url:
        return redirect(url_for("main.index"))

    scan = Scan(target_url=target_url, profile=profile, auth_token=auth_token, status="queued")
    db.session.add(scan)
    db.session.commit()

    enqueue_scan(scan.id)

    return redirect(url_for("main.scan_detail", scan_id=scan.id))


@main_bp.get("/scans/<int:scan_id>")
def scan_detail(scan_id: int):
    scan = (
        Scan.query.options(
            selectinload(Scan.findings).selectinload(Finding.endpoint),
            selectinload(Scan.chains),
            selectinload(Scan.endpoints),
        )
        .filter_by(id=scan_id)
        .first_or_404()
    )
    findings = sorted(
        scan.findings,
        key=lambda finding: (finding.cvss_adjusted, SEVERITY_ORDER.get((finding.severity or "").lower(), -1)),
        reverse=True,
    )
    chains = sorted(scan.chains, key=lambda chain: chain.composite_cvss, reverse=True)
    endpoints = sorted(
        scan.endpoints,
        key=lambda endpoint: (SENSITIVITY_ORDER.get((endpoint.sensitivity or "").upper(), 0), endpoint.path),
        reverse=True,
    )
    severity_counts = _severity_counts(findings)
    top_finding = findings[0] if findings else None

    return render_template(
        "scan.html",
        scan=scan,
        findings=findings,
        chains=chains,
        endpoints=endpoints,
        severity_counts=severity_counts,
        top_finding=top_finding,
    )
