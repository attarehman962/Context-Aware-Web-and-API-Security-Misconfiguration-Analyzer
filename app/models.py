"""Database models used by the scanner and dashboard."""

from __future__ import annotations

from datetime import datetime

from app.extensions import db


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(2048), nullable=False, index=True)
    profile = db.Column(db.String(32), nullable=False, default="Standard")
    auth_token = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(32), nullable=False, default="queued")
    summary = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    endpoints = db.relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    findings = db.relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    chains = db.relationship("ExploitChain", back_populates="scan", cascade="all, delete-orphan")


class Endpoint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False, index=True)
    url = db.Column(db.String(2048), nullable=False)
    method = db.Column(db.String(16), nullable=False, default="GET")
    path = db.Column(db.String(2048), nullable=False, index=True)
    sensitivity = db.Column(db.String(16), nullable=False, default="LOW")
    evidence = db.Column(db.Text, nullable=True)

    scan = db.relationship("Scan", back_populates="endpoints")
    findings = db.relationship("Finding", back_populates="endpoint")


class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False, index=True)
    endpoint_id = db.Column(db.Integer, db.ForeignKey("endpoint.id"), nullable=True, index=True)
    check_name = db.Column(db.String(128), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    cvss_base = db.Column(db.Float, nullable=False, default=0.0)
    cvss_adjusted = db.Column(db.Float, nullable=False, default=0.0)
    evidence = db.Column(db.Text, nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    scan = db.relationship("Scan", back_populates="findings")
    endpoint = db.relationship("Endpoint", back_populates="findings")


class ExploitChain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.Text, nullable=False)
    composite_cvss = db.Column(db.Float, nullable=False, default=0.0)
    evidence = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    scan = db.relationship("Scan", back_populates="chains")
