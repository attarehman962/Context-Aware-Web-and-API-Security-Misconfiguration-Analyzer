"""Dashboard routes."""

from __future__ import annotations

from flask import Blueprint, current_app, redirect, render_template, request, url_for

from app.extensions import db
from app.models import Scan
from app.tasks import enqueue_scan


main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def index():
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    return render_template("index.html", scans=scans)


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
    scan = Scan.query.get_or_404(scan_id)
    return render_template("scan.html", scan=scan)
