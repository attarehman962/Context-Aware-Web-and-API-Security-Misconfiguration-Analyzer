"""Regression tests for the whole-code review (Atta, bug sweep).

One test (or parametrized group) per bug, named after what was wrong.
"""
from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from app.core import pipeline, reports
from app.core.body_classifier import classify_body
from app.core.checks import CheckContext, run_checks
from app.core.crawler import Crawler
from app.core.engine import HttpEngine, ScanResponse
from app.core.tls import TlsProbe, probe_tls
from app.utils import security
from app.utils.redaction import MASK, redact_text

SITE = "https://site.example"


@pytest.fixture
def fake_dns(monkeypatch):
    def getaddrinfo(host, port, *a, **k):
        ips = {"site.example": "93.184.215.14", "other.example": "93.184.215.99"}
        if host not in ips:
            raise socket.gaierror(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ips[host], port))]

    monkeypatch.setattr(security.socket, "getaddrinfo", getaddrinfo)


def _ctx(url: str = SITE + "/", *, headers=None, body="", status=200, ctype="text/html",
         **kw) -> CheckContext:
    from urllib.parse import urlparse

    resp = ScanResponse(requested_url=url, final_url=url, method="GET", status_code=status,
                        headers={k.lower(): v for k, v in (headers or {}).items()},
                        body=body, content_type=ctype)
    return CheckContext(url=url, path=urlparse(url).path or "/", result=resp, **kw)


def _ids(ctx: CheckContext) -> set[str]:
    return {f.rule_id for f in run_checks(ctx)}


# ------------------------------------------------------------- redaction

@pytest.mark.parametrize("text, secret", [
    ("SECRET_KEY=abc123", "abc123"),
    ("DB_PASSWORD=pw", "pw"),                       # short values
    ("password=P@ssw0rd!", "P@ssw0rd!"),            # symbols
    ('{"password": "hunter2 secret"}', "hunter2"),  # JSON, quote before the colon
    ('{"api_key":"sk_live_abcdef123"}', "sk_live"),
    ("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG", "wJalr"),
])
def test_redaction_masks_common_secret_forms(text, secret):
    out = redact_text(text)
    assert secret not in out and MASK in out


# ------------------------------------------------------- body classifier

@pytest.mark.parametrize("body", [
    '{"created": "2026-10-20 09:00:00", "total": 3}',   # ISO timestamp, pagination
    '{"ts": 1698765432123, "id": 8000000000002}',       # Luhn-valid ids, no card brand
    '{"ref": "ABCD12EFGHIJKLMNOP"}',                    # IBAN-shaped, bad checksum
])
def test_body_classifier_ignores_timestamps_counts_and_ids(body):
    c = classify_body(body, "application/json")
    assert not (c.pii or c.financial)


@pytest.mark.parametrize("body, signal", [
    ('{"password": "hunter2x"}', "credentials"),
    ("call +92 300 1234567", "pii"),
    ("(555) 123-4567", "pii"),
    ("card 4111 1111 1111 1111", "financial"),
    ("IBAN GB82WEST12345698765432", "financial"),
    ('{"total": "$19.99"}', "financial"),
])
def test_body_classifier_still_finds_real_signals(body, signal):
    assert getattr(classify_body(body, "application/json"), signal)


# ------------------------------------------------------ rule heuristics

@pytest.mark.parametrize("query, fires", [
    ("author=jane&side=left", False), ("inside=1", False),
    ("token=abc", True), ("PHPSESSID=x", True), ("csrf_token=y", True),
])
def test_cki004_matches_parameter_names_not_substrings(query, fires):
    assert ("CKI-004" in _ids(_ctx(f"{SITE}/page?{query}"))) is fires


@pytest.mark.parametrize("path, fires", [
    ("/badminton", False), ("/admin", True), ("/administrator/login", True),
])
def test_aut002_admin_is_a_path_segment(path, fires):
    assert ("AUT-002" in _ids(_ctx(SITE + path))) is fires


@pytest.mark.parametrize("query, fires", [("context=1", False), ("next=/home", True)])
def test_aut007_matches_parameter_names(query, fires):
    assert ("AUT-007" in _ids(_ctx(f"{SITE}/login?{query}"))) is fires


def test_inf005_ignores_an_html_catch_all_page():
    assert "INF-005" not in _ids(_ctx(SITE + "/backup.zip", body="<html>app</html>"))
    assert "INF-005" in _ids(_ctx(SITE + "/backup.zip", body="PK\x03\x04",
                                  ctype="application/zip"))


def test_cor005_judges_the_preflight_not_the_get_response():
    assert "COR-005" not in _ids(_ctx(cors_acao="*"))            # no preflight seen
    assert "COR-005" in _ids(_ctx(cors_preflight_acao="*"))
    assert "COR-005" not in _ids(_ctx(cors_preflight_acao="*", cors_max_age="600"))


# ------------------------------------------------------------ reports

def test_html_report_escapes_target_controlled_text():
    data = {"scan": {"id": "s", "target_url": "https://x/<script>alert(1)</script>",
                     "status": "DONE", "started_at": None, "completed_at": None,
                     "duration_seconds": None},
            "summary": {"total_findings": 0, "total_endpoints": 0, "total_chains": 0,
                        "by_severity": {}, "max_score": 0},
            "insight": None, "tls": [], "endpoints": [], "findings": [], "chains": []}
    html = reports.render_html(data)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


@pytest.mark.parametrize("value, safe", [
    ("=HYPERLINK(\"x\")", "'=HYPERLINK(\"x\")"), ("+1", "'+1"), ("@SUM(A1)", "'@SUM(A1)"),
    ("https://x/", "https://x/"), (5.3, 5.3),
])
def test_csv_cells_cannot_start_a_formula(value, safe):
    assert reports.csv_safe(value) == safe


# ------------------------------------------------------------- engine

@pytest.mark.asyncio
async def test_probes_stop_at_cross_origin_redirects(fake_dns):
    async with HttpEngine(retries=0) as engine:
        with respx.mock(assert_all_called=False) as mock:
            mock.get(SITE + "/go").respond(302, headers={"Location": "https://other.example/x"})
            elsewhere = mock.get("https://other.example/x").respond(200, text="other")
            stopped = await engine.fetch(SITE + "/go", same_origin_only=True)
            assert not elsewhere.called
            followed = await engine.fetch(SITE + "/go")
    assert stopped.status_code == 302 and stopped.headers["location"]
    assert followed.status_code == 200 and elsewhere.called


@pytest.mark.asyncio
async def test_redirect_without_location_keeps_its_headers(fake_dns):
    async with HttpEngine(retries=0) as engine:
        with respx.mock:
            respx.get(SITE + "/").respond(302, headers={"Server": "nginx/1.18.0"})
            resp = await engine.fetch(SITE + "/")
    assert resp.status_code == 302 and resp.headers["server"] == "nginx/1.18.0"


# ------------------------------------------------------------ crawler

@pytest.mark.asyncio
async def test_wordlist_skips_a_catch_all_site(fake_dns):
    shell = httpx.Response(200, text="<html>spa shell</html>",
                           headers={"Content-Type": "text/html"})
    async with HttpEngine(retries=0) as engine:
        crawler = Crawler(engine, use_wordlist=True)
        with respx.mock(assert_all_called=False) as mock:
            mock.route().mock(return_value=shell)     # every path: the same page
            found = await crawler.crawl(SITE + "/")
    assert [e.path for e in found] == ["/"]


@pytest.mark.asyncio
async def test_links_resolve_against_the_redirected_page(fake_dns):
    async with HttpEngine(retries=0) as engine:
        crawler = Crawler(engine, use_wordlist=False)
        with respx.mock(assert_all_called=False) as mock:
            mock.get(SITE + "/").respond(302, headers={"Location": "/en/"})
            mock.get(SITE + "/en/").respond(200, text='<a href="about">a</a>',
                                            headers={"Content-Type": "text/html"})
            mock.route().respond(404)
            found = await crawler.crawl(SITE + "/")
    assert "/en/about" in {e.path for e in found}


# ----------------------------------------------------- TLS + host rules

def test_tls_probe_goes_through_the_ssrf_guard():
    probe = probe_tls("127.0.0.1", 443)
    assert not probe.reachable and "loopback" in (probe.error or "")


def test_host_level_tls_findings_are_reported_once_without_an_endpoint():
    seed = ScanResponse(requested_url=SITE + "/", final_url=SITE + "/", method="GET",
                        status_code=200)
    tls = TlsProbe(host="site.example", reachable=True, protocols_offered=["TLSv1.1"],
                   cert_not_after=datetime.now(UTC) + timedelta(days=200))
    found = pipeline._host_findings(SITE + "/", seed, tls, http_redirects=False)
    assert sorted(f.raw.rule_id for f in found) == ["TLS-001", "TLS-005"]
    assert all(f.endpoint_index is None and f.context_class is None for f in found)
    assert pipeline._host_findings(SITE + "/", seed, None, None) == []


# --------------------------------------------------- legacy base scores

def test_legacy_findings_report_the_score_of_their_own_vector():
    from cvss import CVSS3

    from app.core.checks.base import make
    from app.core.checks.catalog import CATALOG

    for rule_id in CATALOG:
        f = make(rule_id)
        assert f.base_score == float(CVSS3(f.cvss_vector).base_score), rule_id
