"""CORS for the frontends and the contract error envelope (Atta Prompt 7)."""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import Settings, settings
from app.main import create_app

pytestmark = pytest.mark.asyncio


async def test_default_origin_is_the_frontend():
    assert Settings.model_fields["FRONTEND_ORIGIN"].default == "http://localhost:3000"


async def test_preflight_allows_the_frontend_origin(monkeypatch):
    origin = "http://localhost:3000"
    # A fresh app with the default origins: a developer's .env may override them.
    monkeypatch.setattr(settings, "FRONTEND_ORIGIN",
                        Settings.model_fields["FRONTEND_ORIGIN"].default)
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.options("/api/scan", headers={
            "Origin": origin, "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        })
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == origin


async def test_unknown_origins_get_no_cors_grant(client):
    r = await client.get("/api/scans", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


async def test_browser_code_can_read_location(client):
    r = await client.get("/api/scans", headers={"Origin": "http://localhost:3000"})
    exposed = r.headers["access-control-expose-headers"].lower()
    assert "location" in exposed and "x-contract-version" in exposed


async def test_validation_details_are_loc_msg_type_only(client):
    r = await client.post("/api/scan", json={"url": "https://a.example",
                                             "authorisation_confirmed": False, "extra": 1})
    body = r.json()
    assert r.status_code == 422 and body["error"]["code"] == "VALIDATION_ERROR"
    assert body["details"] and all(set(d) == {"loc", "msg", "type"} for d in body["details"])
    assert ["body", "authorisation_confirmed"] in [d["loc"] for d in body["details"]]


async def test_unhandled_errors_never_leak_a_stack_trace():
    app = create_app()

    @app.get("/boom")
    async def boom():
        raise RuntimeError("secret internal detail at /srv/app/db.py line 42")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/boom")
    assert r.status_code == 500
    assert r.json() == {"success": False, "error": {"code": "INTERNAL_ERROR",
                                                    "message": "An internal error occurred."}}
    assert "secret" not in r.text and "Traceback" not in r.text
