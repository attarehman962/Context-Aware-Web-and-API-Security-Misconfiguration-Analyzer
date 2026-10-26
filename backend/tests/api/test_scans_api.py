"""API tests for the scan endpoints (async SQLite-backed)."""
from __future__ import annotations

import pytest


def _new(url: str) -> dict:
    return {"target_url": url, "authorization_confirmed": True}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/health", "/api/health"])
async def test_health(client, path):
    r = await client.get(path)
    assert r.status_code == 200
    assert r.json()["service"] == "cawasma-backend"


@pytest.mark.asyncio
async def test_create_scan_valid(client):
    r = await client.post("/api/scans", json=_new("https://example.com"))
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "QUEUED"
    assert "scan_id" in body


@pytest.mark.asyncio
async def test_create_scan_rejects_http(client):
    r = await client.post("/api/scans", json=_new("http://example.com"))
    assert r.status_code == 400
    err = r.json()
    assert err["success"] is False
    assert err["error"]["code"] == "BAD_REQUEST"


@pytest.mark.asyncio
async def test_create_scan_rejects_garbage(client):
    r = await client.post("/api/scans", json=_new("not a url"))
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_get_scan_and_status(client):
    created = (await client.post(
        "/api/scans", json=_new("https://example.com")
    )).json()
    sid = created["scan_id"]

    detail = await client.get(f"/api/scans/{sid}")
    assert detail.status_code == 200
    assert detail.json()["target_url"] == "https://example.com/"
    assert detail.json()["summary"]["endpoints"] == 0

    status = await client.get(f"/api/scans/{sid}/status")
    assert status.status_code == 200
    assert status.json()["status"] == "QUEUED"


@pytest.mark.asyncio
async def test_list_scans_pagination(client):
    for _ in range(3):
        await client.post("/api/scans", json=_new("https://example.com"))
    r = await client.get("/api/scans?page=1&limit=2")
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 2
    assert body["meta"]["total"] == 3
    assert body["meta"]["pages"] == 2


@pytest.mark.asyncio
async def test_findings_and_endpoints_empty(client):
    sid = (await client.post(
        "/api/scans", json=_new("https://example.com")
    )).json()["scan_id"]
    f = await client.get(f"/api/scans/{sid}/findings")
    assert f.status_code == 200
    assert f.json()["items"] == []
    e = await client.get(f"/api/scans/{sid}/endpoints")
    assert e.status_code == 200
    c = await client.get(f"/api/scans/{sid}/chains")
    assert c.status_code == 200
    assert c.json() == []


@pytest.mark.asyncio
async def test_delete_scan(client):
    sid = (await client.post(
        "/api/scans", json=_new("https://example.com")
    )).json()["scan_id"]
    d = await client.delete(f"/api/scans/{sid}")
    assert d.status_code == 204
    missing = await client.get(f"/api/scans/{sid}")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_unknown_scan_404(client):
    import uuid
    r = await client.get(f"/api/scans/{uuid.uuid4()}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_create_scan_requires_authorization(client):
    r = await client.post("/api/scans", json={"target_url": "https://example.com"})
    assert r.status_code == 400
    assert "authorization_confirmed" in r.json()["error"]["message"]
