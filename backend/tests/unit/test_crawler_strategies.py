"""Crawler strategies (Atta Prompt 4), against respx-mocked sites."""

from __future__ import annotations

import logging
import socket

import httpx
import pytest
import respx

from app.core.crawler import Crawler
from app.core.engine import HttpEngine
from app.core.wordlist import PROBE_PATHS
from app.db.models.enums import DiscoveryMethod
from app.utils import security

pytestmark = pytest.mark.asyncio
SITE = "https://site.example"


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    def getaddrinfo(host, port, *a, **k):
        ips = {"site.example": "93.184.215.14", "other.example": "93.184.215.99"}
        if host not in ips:
            raise socket.gaierror(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ips[host], port))]

    monkeypatch.setattr(security.socket, "getaddrinfo", getaddrinfo)


def html(*links: str) -> httpx.Response:
    return httpx.Response(
        200,
        text="<html><body>" + "".join(links) + "</body></html>",
        headers={"Content-Type": "text/html"},
    )


async def crawl(
    pages: dict[str, httpx.Response],
    *,
    passive=False,
    use_wordlist=False,
    max_pages=None,
    max_depth=None,
):
    async with HttpEngine(passive_only=passive, retries=0) as engine:
        crawler = Crawler(
            engine, use_wordlist=use_wordlist, max_pages=max_pages, max_depth=max_depth
        )
        with respx.mock(assert_all_called=False) as mock:
            routes = {
                path: mock.get(SITE + path).mock(return_value=resp) for path, resp in pages.items()
            }
            fallback = mock.route().respond(404)
            found = await crawler.crawl(SITE + "/")
    return crawler, {(e.path, e.method): e for e in found}, routes, fallback


async def test_html_strategy_reads_a_form_script_link_and_iframe():
    _, found, _, _ = await crawl(
        {
            "/": html(
                '<a href="/about">a</a>',
                '<form action="/login" method="post"></form>',
                '<script src="/static/app.js"></script>',
                '<link rel="stylesheet" href="/static/site.css">',
                '<iframe src="/embed/map"></iframe>',
            )
        }
    )
    for path, method in [
        ("/about", "GET"),
        ("/login", "POST"),
        ("/static/app.js", "GET"),
        ("/static/site.css", "GET"),
        ("/embed/map", "GET"),
    ]:
        assert found[(path, method)].discovered_by is DiscoveryMethod.HTML, path


async def test_js_strategy_finds_endpoints_in_scripts():
    _, found, _, _ = await crawl(
        {
            "/": html('<script src="/static/app.js"></script>'),
            "/static/app.js": httpx.Response(
                200,
                headers={"Content-Type": "application/javascript"},
                text="fetch('/api/v1/items'); const u = '/api/users';",
            ),
        }
    )
    assert found[("/api/v1/items", "GET")].discovered_by is DiscoveryMethod.JAVASCRIPT
    assert ("/api/users", "GET") in found


async def test_wordlist_probe_records_existing_paths_only():
    _, found, _, _ = await crawl(
        {"/": html(), "/admin": httpx.Response(200, text="admin")}, use_wordlist=True
    )
    assert found[("/admin", "GET")].discovered_by is DiscoveryMethod.WORDLIST
    assert ("/backup.zip", "GET") not in found  # 404 -> not recorded


async def test_passive_mode_sends_no_wordlist_probes():
    _, found, routes, fallback = await crawl(
        {"/": html('<a href="/about">a</a>'), "/about": html(), "/admin": html()},
        passive=True,
        use_wordlist=True,
    )
    assert not routes["/admin"].called and not fallback.called
    assert all(e.discovered_by is not DiscoveryMethod.WORDLIST for e in found.values())


async def test_recursive_crawl_stops_at_depth_two():
    _, found, routes, _ = await crawl(
        {
            "/": html('<a href="/d1">1</a>'),
            "/d1": html('<a href="/d2">2</a>'),
            "/d2": html('<a href="/d3">3</a>'),
            "/d3": html('<a href="/d4">4</a>'),
        },
        max_depth=2,
    )
    assert routes["/d2"].called and not routes["/d3"].called  # /d3 recorded, not fetched
    assert ("/d3", "GET") in found and ("/d4", "GET") not in found


async def test_off_host_links_are_logged_not_followed(caplog):
    caplog.set_level(logging.INFO)
    crawler, found, _, fallback = await crawl(
        {"/": html('<a href="https://other.example/x">x</a>')}
    )
    assert not fallback.called  # nothing outside the site was requested
    assert "https://other.example/x" in crawler.off_host
    assert all("other.example" not in e.url for e in found.values())
    assert "off-host" in caplog.text


async def test_max_pages_limits_fetches_and_urls_are_deduplicated():
    links = "".join(f'<a href="/p{i}">p</a>' for i in range(5)) + '<a href="/p0#frag">dup</a>'
    _, found, routes, _ = await crawl(
        {"/": html(links), **{f"/p{i}": html() for i in range(5)}}, max_pages=3
    )
    assert sum(1 for path in [f"/p{i}" for i in range(5)] if routes[path].called) == 2
    assert [p for p, _ in found].count("/p0") == 1  # fragment variant merged


async def test_wordlist_is_loaded_from_the_data_file():
    assert "/.env" in PROBE_PATHS and "/admin" in PROBE_PATHS
    assert all(p.startswith("/") for p in PROBE_PATHS)
