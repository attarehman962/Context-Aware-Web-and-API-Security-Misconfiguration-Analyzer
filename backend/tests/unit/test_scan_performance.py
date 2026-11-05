"""Performance work (Atta Prompt 10): request de-duplication, concurrency that
keeps results deterministic, stage timings; plus the discovery fixes for the
eval false negatives (API-003: /rest/ and relative JS routes, OpenAPI paths)."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx

from app.core import pipeline
from app.core.crawler import Crawler
from app.core.engine import HttpEngine
from app.core.pipeline import run_pipeline
from tests.fixtures.mock_server import mock_server

pytestmark = pytest.mark.asyncio


@pytest.fixture
def public_dns(monkeypatch):
    import socket

    def getaddrinfo(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 443))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


# ------------------------------------------------------------------ cache


async def test_plain_gets_are_sent_once_per_scan(public_dns):
    async with HttpEngine(scope_host="site.example") as eng:
        with respx.mock:
            route = respx.get("https://site.example/a").respond(200, text="hi")
            first = await eng.fetch("https://site.example/a")
            again = await eng.fetch("https://site.example/a")
    assert route.call_count == 1 and eng.cache_hits == 1
    assert again.body == "hi" and again is not first  # each caller gets a copy


async def test_concurrent_identical_gets_share_one_request(public_dns):
    async def slow(request):
        await asyncio.sleep(0.05)
        return httpx.Response(200, text="ok")

    async with HttpEngine(scope_host="site.example") as eng:
        with respx.mock:
            route = respx.get("https://site.example/s").mock(side_effect=slow)
            out = await asyncio.gather(*(eng.fetch("https://site.example/s") for _ in range(5)))
    assert route.call_count == 1 and {r.body for r in out} == {"ok"}


async def test_probes_with_headers_or_other_methods_are_never_cached(public_dns):
    async with HttpEngine(scope_host="site.example") as eng:
        with respx.mock:
            get = respx.get("https://site.example/").respond(200)
            opt = respx.options("https://site.example/").respond(204)
            for _ in range(2):
                await eng.fetch("https://site.example/", extra_headers={"Origin": "https://o"})
                await eng.fetch("https://site.example/", method="OPTIONS")
    assert get.call_count == 2 and opt.call_count == 2


async def test_cache_can_be_disabled(public_dns):
    async with HttpEngine(scope_host="site.example", cache=False) as eng:
        with respx.mock:
            route = respx.get("https://site.example/").respond(200)
            await eng.fetch("https://site.example/")
            await eng.fetch("https://site.example/")
    assert route.call_count == 2


# ---------------------------------------------------------------- crawler


async def test_js_routes_beyond_api_are_discovered(public_dns):
    js = (
        'const a = "/rest/user/login"; this.http.get(this.host + "/api/Products");'
        ' const b = "rest/basket"; const c = `/v1/books`; const d = "//cdn.example/x.js";'
    )
    page = f"<html><head><script>{js}</script></head><body></body></html>"
    async with HttpEngine(scope_host="site.example") as eng:
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://site.example/").respond(
                200, text=page, headers={"Content-Type": "text/html"}
            )
            mock.route().respond(404)
            found = await Crawler(eng, use_wordlist=False).crawl("https://site.example/")
    urls = {e.url for e in found}
    assert {
        "https://site.example/rest/user/login",
        "https://site.example/api/Products",
        "https://site.example/rest/basket",
        "https://site.example/v1/books",
    } <= urls
    assert not any("cdn.example" in u for u in urls)


async def test_openapi_documents_add_their_concrete_get_paths(public_dns):
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/users/v1": {"get": {}},
            "/users/v1/_debug": {"get": {}},
            "/users/v1/{username}": {"get": {}},  # templated: needs a value
            "/users/v1/register": {"post": {}},  # not a GET
            "/createdb": {"get": {}},  # GET that resets the database
            "/users/v1/logout": {"get": {}},
            "/books/v1": {"get": {}, "post": {}},
        },
    }
    async with HttpEngine(scope_host="site.example") as eng:
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://site.example/").respond(
                200, text="{}", headers={"Content-Type": "text/html"}
            )
            mock.get("https://site.example/openapi.json").respond(
                200, text=json.dumps(spec), headers={"Content-Type": "application/json"}
            )
            mock.route().respond(404)
            found = await Crawler(eng).crawl("https://site.example/")
    paths = {e.path for e in found}
    assert {"/users/v1", "/users/v1/_debug", "/books/v1"} <= paths
    assert "/users/v1/{username}" not in paths and "/users/v1/register" not in paths
    assert "/createdb" not in paths and "/users/v1/logout" not in paths


async def test_crawl_result_order_is_deterministic():
    with mock_server() as base:
        async with HttpEngine(allow_private=True) as eng:
            first = [e.url for e in await Crawler(eng).crawl(base)]
        async with HttpEngine(allow_private=True) as eng:
            second = [e.url for e in await Crawler(eng).crawl(base)]
    assert first == second and first[0].rstrip("/") == base.rstrip("/")


# --------------------------------------------------------------- pipeline


async def test_scan_reports_stage_timings_and_request_count():
    with mock_server() as base:
        result = await run_pipeline(base, probe=True, allow_private=True)
    t = result.stats["stage_seconds"]
    assert {"seed", "crawl", "tls", "http_probe", "endpoints", "scoring", "total"} <= set(t)
    assert all(v >= 0 for v in t.values()) and t["total"] >= t["crawl"]
    assert result.stats["requests"] > 0


async def test_crawled_pages_are_not_fetched_again_for_analysis(monkeypatch):
    sent: list[tuple[str, str]] = []
    real = HttpEngine._send_with_retries

    async def spy(self, url, method, extra_headers):
        if not extra_headers:
            sent.append((method, url))
        return await real(self, url, method, extra_headers)

    monkeypatch.setattr(HttpEngine, "_send_with_retries", spy)
    with mock_server() as base:
        await run_pipeline(base, probe=False, allow_private=True, use_wordlist=False)
    gets = [u for m, u in sent if m == "GET"]
    assert len(gets) == len(set(gets)), "a URL was GET twice"


async def test_concurrent_analysis_keeps_endpoint_order_and_indexes(monkeypatch):
    monkeypatch.setattr(pipeline.settings, "MAX_CONCURRENT_ENDPOINTS", 1)
    with mock_server() as base:
        serial = await run_pipeline(base, probe=True, allow_private=True)
    monkeypatch.setattr(pipeline.settings, "MAX_CONCURRENT_ENDPOINTS", 8)
    with mock_server() as base2:
        parallel = await run_pipeline(base2, probe=True, allow_private=True)

    def shape(r, b):
        eps = [e.url.replace(b, "") for e in r.endpoints]
        fs = sorted((f.raw.rule_id, f.endpoint_index, f.cawasma_final_score) for f in r.findings)
        return eps, fs

    assert shape(serial, base) == shape(parallel, base2)


async def test_progress_counts_only_go_up_under_concurrency():
    seen: list[dict] = []

    async def report(stage, pct, msg, detail):
        seen.append({"pct": pct, **detail})

    with mock_server() as base:
        await run_pipeline(base, report, probe=True, allow_private=True)
    checked = [d["endpoints_checked"] for d in seen if "endpoints_checked" in d]
    pcts = [d["pct"] for d in seen]
    assert checked == sorted(checked) and pcts == sorted(pcts)


@pytest.mark.parametrize(
    "path, changes",
    [
        ("/createdb", True),
        ("/api/reset", True),
        ("/rest/user/logout", True),
        ("/api/users/delete_all", True),
        ("/setup.php", True),
        ("/install/", True),
        ("/api/Products", False),
        ("/rest/user/login", False),
        ("/created-items", False),
        ("/users/v1/_debug", False),
        ("/settings", False),
    ],
)
def test_state_changing_routes_are_recognised(path, changes):
    from app.core.crawler import _state_changing

    assert _state_changing("https://site.example" + path) is changes
