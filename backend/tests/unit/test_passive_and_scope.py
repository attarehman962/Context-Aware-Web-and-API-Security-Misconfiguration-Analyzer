"""Passive mode and host scope are enforced in the engine, for every request.

Engine level: a refused request never reaches the network. Pipeline level: a
whole scan of the local mock target sends only GET/HEAD in passive mode, and
never contacts a host other than the target's (the mock page links to
external.example.org).
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest
import respx

from app.core import engine as engine_mod
from app.core.engine import PASSIVE_METHODS, HttpEngine
from app.core.pipeline import run_pipeline
from tests.fixtures.mock_server import mock_server

pytestmark = pytest.mark.asyncio


@pytest.fixture
def public_dns(monkeypatch):
    import socket

    def getaddrinfo(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 443))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


# ------------------------------------------------------------------ engine


@pytest.mark.parametrize(
    "url",
    [
        "https://other.example/",
        "https://sub.site.example/",
        "https://site.example.evil/",
        "ftp://site.example/",
    ],
)
async def test_out_of_scope_urls_are_refused_before_any_request(public_dns, url):
    async with HttpEngine(scope_host="site.example") as eng:
        with respx.mock(assert_all_called=False) as mock:
            route = mock.route().respond(200)
            r = await eng.fetch(url)
    assert not route.called
    assert r.status_code is None and "outside the scan's scope" in (r.error or "")


async def test_scope_matches_the_host_case_insensitively(public_dns):
    async with HttpEngine(scope_host="Site.Example.") as eng:
        assert eng.in_scope("https://SITE.example/a")
        assert eng.in_scope("http://site.example:8080/")  # TLS-005 probes port 80
        assert not eng.in_scope("https://www.site.example/")


async def test_redirect_to_another_host_is_reported_not_followed(public_dns):
    async with HttpEngine(scope_host="site.example") as eng:
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://site.example/").respond(
                302, headers={"Location": "https://elsewhere.example/landing"}
            )
            other = mock.get("https://elsewhere.example/landing").respond(200)
            r = await eng.fetch("https://site.example/")
    assert not other.called
    assert r.status_code == 302 and r.final_url == "https://site.example/"
    assert r.redirect_chain == []


async def test_same_host_redirects_are_still_followed(public_dns):
    async with HttpEngine(scope_host="site.example") as eng:
        with respx.mock:
            respx.get("https://site.example/").respond(301, headers={"Location": "/home"})
            respx.get("https://site.example/home").respond(200, text="ok")
            r = await eng.fetch("https://site.example/")
    assert r.status_code == 200 and r.redirect_chain == ["https://site.example/home"]


@pytest.mark.parametrize("method", ["OPTIONS", "POST", "PUT", "DELETE", "PATCH", "TRACE"])
async def test_passive_engine_refuses_every_non_get_head_method(public_dns, method):
    async with HttpEngine(passive_only=True, scope_host="site.example") as eng:
        with respx.mock(assert_all_called=False) as mock:
            route = mock.route().respond(200)
            r = await eng.fetch("https://site.example/", method=method)
    assert not route.called and "passive mode" in (r.error or "")


# ---------------------------------------------------------------- pipeline


@pytest.fixture
def sent(monkeypatch):
    """Record every request that actually goes on the wire."""
    calls: list[tuple[str, str]] = []
    real = HttpEngine._send_with_retries

    async def spy(self, url, method, extra_headers):
        calls.append((method, url))
        return await real(self, url, method, extra_headers)

    monkeypatch.setattr(engine_mod.HttpEngine, "_send_with_retries", spy)
    return calls


async def test_passive_scan_sends_only_get_and_head(sent):
    with mock_server() as base:
        result = await run_pipeline(base, probe=True, allow_private=True, passive_only=True)
    assert sent, "the scan made no requests"
    assert {m for m, _ in sent} <= PASSIVE_METHODS
    assert result.endpoints


async def test_active_scan_uses_other_methods_but_only_on_the_target(sent):
    with mock_server() as base:
        await run_pipeline(base, probe=True, allow_private=True)
        host = urlsplit(base).hostname
    assert {m for m, _ in sent} - PASSIVE_METHODS, "active probes expected (e.g. OPTIONS)"
    assert {urlsplit(u).hostname for _, u in sent} == {host}


async def test_scan_never_requests_a_linked_external_host(sent):
    with mock_server() as base:
        result = await run_pipeline(base, probe=True, allow_private=True, passive_only=True)
    assert all("external.example.org" not in u for _, u in sent)
    assert all("external.example.org" not in e.url for e in result.endpoints)


async def test_engine_scope_is_the_target_host(monkeypatch):
    seen: list[str | None] = []
    real_init = HttpEngine.__init__

    def init(self, **kw):
        seen.append(kw.get("scope_host"))
        real_init(self, **kw)

    monkeypatch.setattr(engine_mod.HttpEngine, "__init__", init)
    with mock_server() as base:
        await run_pipeline(base, probe=False, allow_private=True)
    assert seen and seen[0] == urlsplit(base).hostname
