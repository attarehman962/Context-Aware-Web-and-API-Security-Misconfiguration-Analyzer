"""Tests for the safe HTTP engine (against the local mock server)."""

from __future__ import annotations

import pytest

from app.core.engine import HttpEngine
from tests.fixtures.mock_server import mock_server


@pytest.mark.asyncio
async def test_fetch_basic():
    with mock_server() as base:
        async with HttpEngine(allow_private=True) as engine:
            r = await engine.fetch(base + "/")
    assert r.ok
    assert r.status_code == 200
    assert "html" in (r.content_type or "")
    assert "About" in r.body
    assert r.response_time is not None


@pytest.mark.asyncio
async def test_fetch_json():
    with mock_server() as base:
        async with HttpEngine(allow_private=True) as engine:
            r = await engine.fetch(base + "/api/users")
    assert r.ok
    assert "json" in (r.content_type or "")


@pytest.mark.asyncio
async def test_redirect_followed_and_recorded():
    with mock_server() as base:
        async with HttpEngine(allow_private=True) as engine:
            r = await engine.fetch(base + "/redirect")
    assert r.ok
    assert r.final_url.endswith("/about")
    assert any(u.endswith("/about") for u in r.redirect_chain)


@pytest.mark.asyncio
async def test_response_size_capped():
    with mock_server() as base:
        async with HttpEngine(allow_private=True) as engine:
            r = await engine.fetch(base + "/big")
    # MAX_RESPONSE_SIZE default is 5,000,000; the 6MB body must be truncated.
    assert r.truncated is True
    assert (r.content_length or 0) <= 5_000_000


@pytest.mark.asyncio
async def test_ssrf_blocks_private_by_default():
    # Without allow_private, a localhost target is refused (no crash).
    async with HttpEngine() as engine:
        r = await engine.fetch("http://127.0.0.1:1/")
    assert not r.ok
    assert r.error and "SSRF" in r.error


@pytest.mark.asyncio
async def test_unreachable_target_does_not_crash():
    async with HttpEngine(allow_private=True) as engine:
        r = await engine.fetch("http://127.0.0.1:9/")  # nothing listening
    assert not r.ok
    assert r.error is not None
