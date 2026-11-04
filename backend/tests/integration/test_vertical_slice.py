"""End-to-end vertical slice (Atta Prompt 7): POST /api/scan -> poll -> results.

The target is ``scripts/demo_target.py``: HTTPS with a throwaway CA, every
security header except HSTS. It is bound to this machine's **private** address
rather than loopback, because loopback stays blocked even for
``ALLOWED_INTERNAL_HOSTS``; the test therefore goes through the real SSRF guard,
the pinned connection and certificate verification, with no test-only bypass.
"""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
from pathlib import Path

import pytest
from cvss import CVSS3

import app.services.scan_runner as runner
from app.config import settings
from app.core.checks.registry import spec_for
from app.utils.security import _ip_is_disallowed
from scripts import demo_target

pytestmark = pytest.mark.asyncio


def _private_address() -> str | None:
    """This host's outbound IPv4 address if the guard lets it through for an
    allowed internal host (private, not loopback/link-local). UDP connect sends
    nothing; it only picks the interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("10.255.255.255", 1))
            ip = ipaddress.ip_address(s.getsockname()[0])
        except OSError:
            return None
    return str(ip) if _ip_is_disallowed(ip, internal_ok=True) is None else None


@pytest.fixture
def hsts_target(tmp_path: Path):
    ip = _private_address()
    if ip is None:
        pytest.skip("no private, non-loopback IPv4 address to bind the target to")
    with demo_target.running(ip, ips=(ip,)) as (url, ca_pem):
        ca = tmp_path / "demo-ca.pem"
        ca.write_bytes(ca_pem)
        yield ip, url, ca


@pytest.fixture
def live_scans(monkeypatch, sessionmaker_):
    """Run POST /api/scan's background task against the test database."""
    @contextlib.asynccontextmanager
    async def scope():
        async with sessionmaker_() as session:
            yield session

    async def quiet(self, *a, **k):
        return None

    # In-process (BackgroundTasks) instead of the Celery worker: same runner code.
    monkeypatch.setattr(settings, "RUN_SCANS_INLINE", True)
    monkeypatch.setattr(runner, "session_scope", scope)
    monkeypatch.setattr(runner.RedisProgressPublisher, "publish", quiet)
    monkeypatch.setattr(runner.RedisProgressPublisher, "close", quiet)


async def _poll(client, scan_id: str) -> dict:
    async with asyncio.timeout(60):
        while True:
            r = await client.get(f"/api/results/{scan_id}")
            assert r.status_code == 200, r.text
            body = r.json()
            if body["scan"]["status"] in {"DONE", "FAILED"}:
                return body
            await asyncio.sleep(0.2)


async def test_scan_of_a_target_without_hsts_reports_one_recomputable_finding(
        client, hsts_target, live_scans, monkeypatch):
    ip, url, ca = hsts_target
    monkeypatch.setattr(settings, "ALLOWED_INTERNAL_HOSTS", ip)
    monkeypatch.setattr(settings, "SCAN_CA_BUNDLE", str(ca))

    r = await client.post("/api/scan", json={
        "url": url, "authorisation_confirmed": True,
        "crawl_depth": 1, "use_wordlist": False, "passive_only": True,
    })
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "QUEUED"
    results = await _poll(client, r.json()["scan_id"])

    assert results["scan"]["status"] == "DONE", results["scan"]["error"]
    assert results["scan"]["progress"] == 100
    hsts = [f for f in results["findings"] if f["check_id"] == "HDR-001"]
    assert len(hsts) == 1, [f["check_id"] for f in results["findings"]]
    assert not [f for f in results["findings"] if f["check_id"] == "TLS-009"]

    f = hsts[0]
    assert f["endpoint_url"] == url
    assert f["cvss_vector"] == spec_for("HDR-001").base_cvss_vector
    assert f["final_vector"].startswith(f["cvss_vector"] + "/CR:")
    recomputed = CVSS3(f["final_vector"])
    assert float(recomputed.base_score) == f["base_score"]
    assert float(recomputed.environmental_score) == f["final_score"]
    assert f["score_reasons"][-1] == f"environmental:{f['final_score']}"
    assert f["evidence"]["text"].startswith("Missing Strict-Transport-Security")

    # Ranked by final_score, highest first; the history lists the scan.
    scores = [x["final_score"] for x in results["findings"]]
    assert scores == sorted(scores, reverse=True)
    history = (await client.get("/api/scans")).json()["items"]
    assert history[0]["scan_id"] == results["scan"]["scan_id"]


async def test_private_target_is_refused_without_allowed_internal_hosts(
        client, hsts_target, live_scans, monkeypatch):
    _, url, ca = hsts_target
    monkeypatch.setattr(settings, "ALLOWED_INTERNAL_HOSTS", "")
    monkeypatch.setattr(settings, "SCAN_CA_BUNDLE", str(ca))
    r = await client.post("/api/scan", json={"url": url, "authorisation_confirmed": True})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_TARGET"


async def test_scan_is_refused_without_authorisation(client, live_scans):
    r = await client.post("/api/scan", json={"url": "https://a.example",
                                             "authorisation_confirmed": False})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"
    assert (await client.get("/api/scans")).json()["meta"]["total"] == 0
