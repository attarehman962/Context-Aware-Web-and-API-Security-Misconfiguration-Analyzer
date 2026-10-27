"""Contract v1 routes, against the database and in MOCK_API mode."""
from __future__ import annotations

import contextlib
import csv
import io
import uuid

import pytest

import scripts.seed as seed_mod
from app.api import mock
from app.api.schemas import CONTRACT_VERSION, ScanResults
from app.config import settings

pytestmark = pytest.mark.asyncio

BODY = {"url": "https://example.com", "authorisation_confirmed": True,
        "crawl_depth": 1, "use_wordlist": False, "passive_only": True}


@pytest.fixture
async def seeded(sessionmaker_, monkeypatch):
    @contextlib.asynccontextmanager
    async def scope():
        async with sessionmaker_() as s:
            yield s
            await s.commit()

    monkeypatch.setattr(seed_mod, "session_scope", scope)
    await seed_mod.seed()
    return seed_mod.RESCAN_SCAN_ID


@pytest.fixture(autouse=True)
def offline_dns(monkeypatch):
    """Public names resolve to a public IP without the network; literal IPs and
    localhost still go through the real SSRF checks."""
    from app.api.routes import contract
    from app.utils import security

    def fake(url, *, allow_private=False):
        if "example.com" in url:
            return security.ResolvedTarget(host="example.com", ips=("93.184.215.14",))
        return security.validate_url_ssrf(url, allow_private=allow_private)

    monkeypatch.setattr(contract, "validate_url_ssrf", fake)


@pytest.fixture
def mock_mode(monkeypatch):
    monkeypatch.setattr(settings, "MOCK_API", True)


# ------------------------------------------------------------- real mode

async def test_start_scan_queues_with_options(client):
    r = await client.post("/api/scan", json=BODY)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == "QUEUED"
    assert body["options"] == {"crawl_depth": 1, "use_wordlist": False, "passive_only": True}
    assert r.headers["Location"] == f"/api/results/{body['scan_id']}"
    assert r.headers["X-Contract-Version"] == CONTRACT_VERSION


@pytest.mark.parametrize("body, status, code", [
    ({**BODY, "authorisation_confirmed": False}, 422, "VALIDATION_ERROR"),
    ({"url": "https://example.com"}, 422, "VALIDATION_ERROR"),
    ({**BODY, "crawl_depth": 5}, 422, "VALIDATION_ERROR"),
    ({**BODY, "url": "http://example.com"}, 400, "INVALID_TARGET"),
    ({**BODY, "url": "https://127.0.0.1"}, 400, "INVALID_TARGET"),
    ({**BODY, "url": "https://localhost"}, 400, "INVALID_TARGET"),
    ({**BODY, "url": "https://10.0.0.5:8443"}, 400, "INVALID_TARGET"),
])
async def test_start_scan_rejects(client, body, status, code):
    r = await client.post("/api/scan", json=body)
    assert r.status_code == status, r.text
    assert r.json()["success"] is False and r.json()["error"]["code"] == code


async def test_results_are_ranked_with_drill_down_fields(client, seeded):
    r = await client.get(f"/api/results/{seeded}")
    assert r.status_code == 200
    results = ScanResults.model_validate(r.json())
    scores = [f.final_score for f in results.findings]
    assert scores == sorted(scores, reverse=True)
    assert results.scan.status.value == "DONE"
    assert results.scan.severity_counts.critical == 4

    [chain] = results.chains
    members = {f.id for f in results.findings if chain.id in f.chain_ids}
    # C005 (config/chains.yaml): the exposed .env that leaks credentials.
    assert members == set(chain.finding_ids) and len(members) == 1
    env = next(f for f in results.findings if f.check_id == "INF-003")
    assert {s.value for s in env.body_signals} == {"CREDENTIALS", "INTERNAL_IP"}
    assert env.sensitivity_class is not None and env.evidence["text"]
    tls = next(f for f in results.findings if f.check_id == "TLS-001")
    assert tls.endpoint_id is None and tls.body_signals == []


async def test_unknown_and_malformed_ids(client):
    r = await client.get(f"/api/results/{uuid.uuid4()}")
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"
    assert (await client.get("/api/results/not-a-uuid")).status_code == 422


@pytest.mark.parametrize("fmt, media", [
    ("json", "application/json"), ("csv", "text/csv"), ("html", "text/html"),
])
async def test_export_formats(client, seeded, fmt, media):
    r = await client.get(f"/api/results/{seeded}/export", params={"format": fmt})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith(media)
    assert f'filename="cawasma-{seeded}.{fmt}"' in r.headers["content-disposition"]
    if fmt == "json":
        assert ScanResults.model_validate_json(r.content).scan.scan_id == seeded
    if fmt == "csv":
        rows = list(csv.DictReader(io.StringIO(r.text)))
        assert len(rows) == 10 and rows[0]["final_score"] == "10.0"


async def test_export_errors(client, seeded):
    r = await client.get(f"/api/results/{seeded}/export", params={"format": "xml"})
    assert r.status_code == 422
    queued = (await client.post("/api/scan", json=BODY)).json()["scan_id"]
    r = await client.get(f"/api/results/{queued}/export")
    assert r.status_code == 409 and r.json()["error"]["code"] == "SCAN_NOT_FINISHED"


async def test_scan_history_newest_first(client, seeded):
    r = await client.get("/api/scans", params={"limit": 1})
    assert r.status_code == 200
    body = r.json()
    assert body["meta"] == {"page": 1, "limit": 1, "total": 2, "pages": 2}
    assert body["items"][0]["scan_id"] == str(seeded)  # the rescan is newer


# ------------------------------------------------------------- mock mode

async def test_mock_mode_serves_every_example_state(client, mock_mode):
    for scan_id, results in mock.RESULTS.items():
        r = await client.get(f"/api/results/{scan_id}")
        assert r.status_code == 200
        assert r.json() == results.model_dump(mode="json")
    assert (await client.get(f"/api/results/{uuid.uuid4()}")).status_code == 404

    r = await client.post("/api/scan", json={**BODY, "url": "https://anything.test"})
    assert r.status_code == 202
    assert r.json()["scan_id"] == str(mock.QUEUED_ID)
    assert r.json()["url"] == "https://anything.test"
    r = await client.post("/api/scan", json={**BODY, "url": "http://insecure.test"})
    assert r.status_code == 400

    r = await client.get("/api/scans")
    assert [i["status"] for i in r.json()["items"]] == ["QUEUED", "RUNNING", "DONE", "FAILED"]

    assert (await client.get(f"/api/results/{mock.DONE_ID}/export?format=csv")).status_code == 200
    assert (await client.get(f"/api/results/{mock.RUNNING_ID}/export")).status_code == 409
