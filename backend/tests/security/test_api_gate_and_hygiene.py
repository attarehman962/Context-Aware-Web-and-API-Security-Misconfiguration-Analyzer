"""SEC review 3 and 6: the authorisation gate, and basic API hygiene.

Everything goes straight to the API, as an attacker bypassing the frontend
would: odd JSON types, alternative spellings, query strings, other content
types, and the deprecated pre-contract route.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from app.config import settings
from app.db.models import Scan
from app.services import rate_limit

pytestmark = pytest.mark.asyncio

URL = "https://example.com/"


@pytest.fixture(autouse=True)
def public_dns(dns):
    dns["example.com"] = ["93.184.216.34"]
    dns["xn--bcher-kva.example"] = ["93.184.216.34"]


async def _count(sessionmaker_) -> int:
    async with sessionmaker_() as s:
        return int(await s.scalar(select(func.count()).select_from(Scan)))


# ----------------------------------------------------------- authorisation

@pytest.mark.parametrize("flag", [
    "missing", False, None, "true", "True", "yes",
    1,                                  # SEC-06 (fixed): 1 == True in lax mode
    "1", 0, [True], {"ok": True}, "",
])
async def test_contract_route_needs_a_literal_true(client, sessionmaker_, flag):
    body: dict = {"url": URL}
    if flag != "missing":
        body["authorisation_confirmed"] = flag
    r = await client.post("/api/scan", json=body)
    assert r.status_code == 422, (flag, r.text)
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"
    assert await _count(sessionmaker_) == 0


@pytest.mark.parametrize("body, params", [
    ({"url": URL, "authorization_confirmed": True}, None),    # US spelling: not the field
    ({"url": URL, "AUTHORISATION_CONFIRMED": True}, None),
    ({"url": URL}, {"authorisation_confirmed": "true"}),       # flag in the query string
])
async def test_contract_route_cannot_be_satisfied_another_way(client, sessionmaker_, body,
                                                              params):
    r = await client.post("/api/scan", json=body, params=params)
    assert r.status_code == 422, r.text
    assert await _count(sessionmaker_) == 0


@pytest.mark.parametrize("content_type, data", [
    ("application/x-www-form-urlencoded", f"url={URL}&authorisation_confirmed=true"),
    ("text/plain", f'{{"url": "{URL}", "authorisation_confirmed": true}}'),
])
async def test_contract_route_accepts_only_json(client, sessionmaker_, content_type, data):
    r = await client.post("/api/scan", content=data, headers={"content-type": content_type})
    assert r.status_code == 422, r.text
    assert await _count(sessionmaker_) == 0


@pytest.mark.parametrize("flag", ["missing", False, "false", 0, None])
async def test_deprecated_route_also_refuses_without_confirmation(client, sessionmaker_,
                                                                  flag):
    body: dict = {"target_url": URL}
    if flag != "missing":
        body["authorization_confirmed"] = flag
    r = await client.post("/api/scans", json=body)
    assert r.status_code in (400, 422), (flag, r.text)
    assert await _count(sessionmaker_) == 0


async def test_mock_mode_applies_the_same_gate(client, monkeypatch):
    monkeypatch.setattr(settings, "MOCK_API", True)
    r = await client.post("/api/scan", json={"url": URL})
    assert r.status_code == 422


# --------------------------------------------------------- URL validation

@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "file:///etc/passwd", "ftp://example.com/", "gopher://example.com/",
    "http://example.com/", "https://", "https:///path", "//example.com/", "example.com",
    "https://exa mple.com/",
    "https://example.com:0/", "https://example.com:99999/",          # SEC-05 (fixed)
    "https://example.com/\r\nX-Injected: 1",                          # SEC-04 (fixed)
    "https://example.com/" + "a" * 3000, "", " ",
    "https://[::1",                                                     # SEC-05 (fixed)
    "https://example.com\\@169.254.169.254/",
])
async def test_bad_urls_are_refused_and_nothing_is_stored(client, sessionmaker_, url):
    r = await client.post("/api/scan", json={"url": url, "authorisation_confirmed": True})
    assert r.status_code in (400, 422), (url, r.status_code, r.text)
    assert await _count(sessionmaker_) == 0


async def test_credentials_in_the_url_are_refused_not_stored(client, sessionmaker_):
    """userinfo (https://user:password@host) would be stored in scans.target_url
    and shown in every report, history row and log line."""
    r = await client.post("/api/scan", json={
        "url": "https://admin:S3cretPassw0rd@example.com/", "authorisation_confirmed": True})
    if r.status_code == 202:
        async with sessionmaker_() as s:
            stored = (await s.execute(select(Scan.target_url))).scalar_one()
        assert "S3cretPassw0rd" not in stored, "password stored in scans.target_url"
    assert r.status_code == 400, r.text


async def test_idn_targets_are_accepted(client):
    r = await client.post("/api/scan", json={"url": "https://xn--bcher-kva.example/",
                                             "authorisation_confirmed": True})
    assert r.status_code == 202, r.text


# ------------------------------------------------------------ rate limit

@pytest.fixture
def limit_two(monkeypatch):
    lim = rate_limit.ScanRateLimiter()

    async def local_only(key, window):
        return None

    monkeypatch.setattr(lim, "_incr_redis", local_only)
    monkeypatch.setattr(rate_limit, "limiter", lim)
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT", "2/minute")


async def test_contract_scan_creation_is_rate_limited(client, limit_two):
    body = {"url": URL, "authorisation_confirmed": True}
    codes = [(await client.post("/api/scan", json=body)).status_code for _ in range(4)]
    assert codes == [202, 202, 429, 429]


async def test_deprecated_scan_creation_is_rate_limited_too(client, limit_two):
    """POST /api/scans creates and dispatches scans like POST /api/scan; without
    the limit it is an open way around it."""
    body = {"target_url": URL, "authorization_confirmed": True}
    codes = [(await client.post("/api/scans", json=body)).status_code for _ in range(4)]
    assert 429 in codes, codes


async def test_rate_limit_ignores_spoofed_forwarded_for(client, limit_two):
    body = {"url": URL, "authorisation_confirmed": True}
    codes = [(await client.post("/api/scan", json=body,
                                headers={"X-Forwarded-For": f"203.0.113.{i}"})).status_code
             for i in range(3)]
    assert codes[-1] == 429, codes


# ------------------------------------------------------- error responses

@pytest.fixture
async def raw_client(client):
    """A client that gets the 500 response instead of the re-raised exception."""
    from app.main import app

    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False),
                           base_url="http://test") as c:
        yield c


async def test_internal_errors_have_no_stack_trace_or_internals(raw_client, monkeypatch):
    from app.services import contract_service

    async def boom(*a, **k):
        raise RuntimeError("db password=hunter2 at /app/app/services/x.py line 9")

    monkeypatch.setattr(contract_service, "get_results", boom)
    r = await raw_client.get("/api/results/11111111-1111-4111-8111-111111111111")
    assert r.status_code == 500
    assert r.json() == {"success": False, "error": {"code": "INTERNAL_ERROR",
                                                    "message": "An internal error occurred."}}
    for leak in ("Traceback", "RuntimeError", "hunter2", "/app/", ".py"):
        assert leak not in r.text


@pytest.mark.parametrize("method, path, kw", [
    ("post", "/api/scan", {"content": "{not json", "headers": {"content-type":
                                                              "application/json"}}),
    ("get", "/api/results/not-a-uuid", {}),
    ("get", "/api/results/11111111-1111-4111-8111-111111111111/export", {"params": {
        "format": "exe"}}),
    ("get", "/api/scans", {"params": {"limit": "99999"}}),
    ("get", "/api/nope", {}),
    ("delete", "/api/scan", {}),
])
async def test_client_errors_use_the_envelope_without_internals(client, method, path, kw):
    r = await getattr(client, method)(path, **kw)
    assert 400 <= r.status_code < 500
    body = r.json()
    assert body["success"] is False and {"code", "message"} <= set(body["error"])
    assert "Traceback" not in r.text and "site-packages" not in r.text


async def test_validation_errors_do_not_echo_the_request_body(client):
    secret = "cawasma-echo-check-123456"
    r = await client.post("/api/scan", json={"url": URL, "authorisation_confirmed": False,
                                             "note": secret})
    assert r.status_code == 422 and secret not in r.text
