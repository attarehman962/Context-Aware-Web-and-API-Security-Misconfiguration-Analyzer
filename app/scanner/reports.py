"""Report export helpers."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, is_dataclass


def _serialize_record(record):
    if is_dataclass(record):
        return asdict(record)
    if hasattr(record, "__table__"):
        return {column.name: getattr(record, column.name) for column in record.__table__.columns}
    if hasattr(record, "__dict__"):
        return {
            key: value
            for key, value in vars(record).items()
            if not key.startswith("_")
        }
    return record


def export_json(scan, endpoints, findings, chains):
    payload = {
        "scan": {
            "id": scan.id,
            "target_url": scan.target_url,
            "profile": scan.profile,
            "status": scan.status,
            "summary": scan.summary,
        },
        "endpoints": [_serialize_record(endpoint) for endpoint in endpoints],
        "findings": [_serialize_record(finding) for finding in findings],
        "chains": [_serialize_record(chain) for chain in chains],
    }
    return json.dumps(payload, indent=2, default=str)


def export_csv(findings):
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=["title", "severity", "cvss_base", "cvss_adjusted", "check_name", "details"],
    )
    writer.writeheader()
    for finding in findings:
        writer.writerow(
            {
                "title": finding.title,
                "severity": finding.severity,
                "cvss_base": finding.cvss_base,
                "cvss_adjusted": finding.cvss_adjusted,
                "check_name": finding.check_name,
                "details": finding.details or "",
            }
        )
    return buffer.getvalue()
