"""Tests for the four-strategy crawler (against the local mock server)."""

from __future__ import annotations

import pytest

from app.core.crawler import Crawler
from app.core.engine import HttpEngine
from app.db.models.enums import DiscoveryMethod
from tests.fixtures.mock_server import mock_server


@pytest.mark.asyncio
async def test_crawler_discovers_endpoints():
    with mock_server() as base:
        async with HttpEngine(allow_private=True) as engine:
            crawler = Crawler(engine)
            results = await crawler.crawl(base + "/")

    paths = {e.path for e in results}
    methods = {e.discovered_by for e in results}

    # Strategy 1 (HTML): links and forms.
    assert "/about" in paths
    assert "/page2" in paths
    assert "/search" in paths  # form action
    # Strategy 2 (JS): fetch()/axios/api paths from inline + external JS.
    assert "/api/users" in paths
    assert "/api/orders" in paths
    assert DiscoveryMethod.JAVASCRIPT in methods
    # Strategy 3 (wordlist): /.env exists on the mock and should be found.
    assert "/.env" in paths
    assert DiscoveryMethod.WORDLIST in methods


@pytest.mark.asyncio
async def test_crawler_stays_same_origin():
    with mock_server() as base:
        async with HttpEngine(allow_private=True) as engine:
            crawler = Crawler(engine)
            results = await crawler.crawl(base + "/")
    # The external link must not be crawled/added.
    assert all("external.example.org" not in e.url for e in results)


@pytest.mark.asyncio
async def test_crawler_dedup():
    with mock_server() as base:
        async with HttpEngine(allow_private=True) as engine:
            crawler = Crawler(engine)
            results = await crawler.crawl(base + "/")
    keys = [(e.url, e.method) for e in results]
    assert len(keys) == len(set(keys))  # no duplicates
