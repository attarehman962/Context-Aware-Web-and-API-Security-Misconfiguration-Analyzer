"""Contract v1 schema rules (docs/api-contract.md)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.api.schemas import (
    Finding,
    ScanOptions,
    ScanRequest,
    ScanResults,
    ScanState,
    ScanStatus,
)

URL = "https://shop.example.com"


def test_scan_request_defaults():
    req = ScanRequest(url=URL, authorisation_confirmed=True)
    assert (req.crawl_depth, req.use_wordlist, req.passive_only) == (2, True, False)


@pytest.mark.parametrize("body", [
    {"url": URL},                                            # authorisation missing
    {"url": URL, "authorisation_confirmed": False},          # must be true
    {"url": URL, "authorisation_confirmed": True, "crawl_depth": 0},
    {"url": URL, "authorisation_confirmed": True, "crawl_depth": 3},
    {"url": URL, "authorisation_confirmed": True, "depth": 1},   # unknown field
    {"url": "", "authorisation_confirmed": True},
])
def test_scan_request_rejects(body):
    with pytest.raises(ValidationError):
        ScanRequest.model_validate(body)


def _finding(score: float, check_id: str) -> Finding:
    return Finding(
        id=uuid.uuid4(), check_id=check_id, title=check_id, category="HEADERS",
        owasp_map=[], cwe_map=[], cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        base_score=5.9, final_score=score, severity_bucket="MEDIUM", evidence={"text": "x"},
    )


def test_results_rank_findings_by_final_score_desc():
    status = ScanStatus(scan_id=uuid.uuid4(), url=URL, status=ScanState.DONE, progress=100,
                        options=ScanOptions(), created_at=datetime.now(UTC))
    results = ScanResults(scan=status, findings=[
        _finding(3.7, "HDR-003"), _finding(10.0, "INF-003"), _finding(3.7, "HDR-001"),
    ])
    assert [(f.final_score, f.check_id) for f in results.findings] == [
        (10.0, "INF-003"), (3.7, "HDR-001"), (3.7, "HDR-003"),
    ]
    assert results.contract_version == "1.2.0"
