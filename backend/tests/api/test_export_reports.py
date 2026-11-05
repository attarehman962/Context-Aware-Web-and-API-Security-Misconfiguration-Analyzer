"""GET /api/results/{id}/export in every format (Atta Prompt 9).

The seeded scan is changed so one finding's stored evidence holds a raw secret
(as an older, pre-redaction row could) and a target-controlled title with
HTML in it. No format may carry the secret; HTML must escape the title; the
report shows vectors, the score story and the chains.
"""

from __future__ import annotations

import contextlib
import csv
import io
import shutil
import subprocess

import pytest
from sqlalchemy import select

import scripts.seed as seed_mod
from app.core import reports
from app.db.models import Finding

pytestmark = pytest.mark.asyncio

SECRET = "cawasma-fake-9f8e7d6c5b4a3210"
RAW_EVIDENCE = f"config leak: api_key={SECRET} and Authorization: Bearer abcdefghijklmnop"
XSS = "<img src=x onerror=alert(1)>"


@pytest.fixture
async def scan_id(sessionmaker_, monkeypatch):
    @contextlib.asynccontextmanager
    async def scope():
        async with sessionmaker_() as s:
            yield s
            await s.commit()

    monkeypatch.setattr(seed_mod, "session_scope", scope)
    await seed_mod.seed()
    sid = seed_mod.RESCAN_SCAN_ID
    async with sessionmaker_() as s:
        top = (
            (
                await s.execute(
                    select(Finding)
                    .where(Finding.scan_id == sid)
                    .order_by(Finding.final_score.desc())
                )
            )
            .scalars()
            .first()
        )
        top.evidence = {"text": RAW_EVIDENCE, "headers": {"x-debug": f"token={SECRET}"}}
        top.title = f"Leaky endpoint {XSS}"
        await s.commit()
    return sid


async def _export(client, sid, fmt):
    r = await client.get(f"/api/results/{sid}/export", params={"format": fmt})
    assert r.status_code == 200, r.text
    return r


async def test_json_export_is_the_results_body_with_evidence_redacted(client, scan_id):
    r = await _export(client, scan_id, "json")
    body = r.json()
    assert body["scan"]["scan_id"] == str(scan_id) and body["findings"]
    assert SECRET not in r.text and "abcdefghijklmnop" not in r.text
    top = next(f for f in body["findings"] if f["title"].startswith("Leaky"))
    assert "***REDACTED***" in top["evidence"]["text"]
    assert "***REDACTED***" in top["evidence"]["headers"]["x-debug"]
    # Same ranking and scores as GET /api/results.
    live = (await client.get(f"/api/results/{scan_id}")).json()
    assert [f["id"] for f in body["findings"]] == [f["id"] for f in live["findings"]]


async def test_csv_export_is_ranked_and_formula_safe(client, scan_id):
    r = await _export(client, scan_id, "csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    scores = [float(x["final_score"]) for x in rows]
    assert scores == sorted(scores, reverse=True) and SECRET not in r.text
    assert all(not v.startswith(("=", "+", "@")) for row in rows for v in row.values())


async def test_html_report_has_summary_vectors_story_and_chains(client, scan_id):
    r = await _export(client, scan_id, "html")
    html = r.text
    assert r.headers["content-type"].startswith("text/html")
    assert "Summary by severity" in html and "Attack chains" in html
    live = (await client.get(f"/api/results/{scan_id}")).json()
    for f in live["findings"]:
        assert f["cvss_vector"] in html
        if f["final_vector"]:
            assert f["final_vector"] in html
    for c in live["chains"]:
        assert c["chain_code"] in html
        if c["composite_vector"]:
            assert c["composite_vector"] in html
    assert "Why it differs" in html and "→ final" in html
    assert SECRET not in html and "abcdefghijklmnop" not in html
    assert XSS not in html and "&lt;img src=x onerror=alert(1)&gt;" in html


def _pdf_text(pdf: bytes) -> str | None:
    """Text of the PDF via poppler's pdftotext, when installed (it is a test aid)."""
    tool = shutil.which("pdftotext")
    if tool is None:
        return None
    done = subprocess.run(  # noqa: S603 - fixed tool, our own PDF
        [tool, "-", "-"], input=pdf, capture_output=True, check=True
    )
    return done.stdout.decode()


async def test_pdf_report_is_rendered_from_the_same_html(client, scan_id):
    r = await _export(client, scan_id, "pdf")
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-" and len(r.content) > 5_000
    text = _pdf_text(r.content)
    if text is not None:
        assert "CAWASMA Security Report" in text and "Why it differs" in text
        assert SECRET not in text and "REDACTED" in text


async def test_every_format_refuses_an_unfinished_scan(client, sessionmaker_):
    from app.db.models import Scan
    from app.db.models.enums import ScanStatus

    async with sessionmaker_() as s:
        scan = Scan(target_url="https://a.example", status=ScanStatus.RUNNING, progress=40)
        s.add(scan)
        await s.commit()
    for fmt in ("json", "csv", "html", "pdf"):
        r = await client.get(f"/api/results/{scan.id}/export", params={"format": fmt})
        assert r.status_code == 409 and r.json()["error"]["code"] == "SCAN_NOT_FINISHED"


# ---------------------------------------------------------- renderer units


def _finding(**kw):
    base = {
        "rule_id": "HDR-002",
        "title": "t",
        "severity": "MEDIUM",
        "cvss_vector": "V",
        "cvss_base_score": 5.4,
        "cawasma_final_score": 6.4,
        "endpoint_url": None,
        "evidence": None,
        "recommendation": None,
        "limitation": None,
    }
    return {**base, **kw}


def test_score_story_explains_environmental_requirements():
    story = reports.score_story(
        _finding(
            final_vector="V/CR:H",
            score_reasons=[
                "sensitivity:CRITICAL",
                "signal:PII",
                "CR:H<-sensitivity:CRITICAL+signal:PII",
                "base:5.4",
                "environmental:6.4",
            ],
        )
    )
    assert (
        "Confidentiality requirement High because endpoint sensitivity is CRITICAL, "
        "the response contains PII."
    ) in story
    assert story[-1] == "Base 5.4 → final 6.4 (+1.0)."


def test_score_story_for_unchanged_and_legacy_scores():
    same = reports.score_story(
        _finding(cawasma_final_score=5.4, final_vector="V", score_reasons=["no-context-change"])
    )
    assert any("equals the base score" in s for s in same) and same[-1].endswith("(unchanged).")
    legacy = reports.score_story(
        _finding(
            cawasma_context_multiplier=1.2,
            response_bonus=0.5,
            context_class="HIGH",
            body_signals=["PII"],
        )
    )
    assert "interim formula" in legacy[0]
    assert "Context multiplier ×1.2 for a HIGH endpoint." in legacy
    assert "Response bonus +0.5 for sensitive data in the response (PII)." in legacy


def test_template_is_packaged_next_to_the_code():
    assert (reports._TEMPLATES / reports.TEMPLATE).is_file()
