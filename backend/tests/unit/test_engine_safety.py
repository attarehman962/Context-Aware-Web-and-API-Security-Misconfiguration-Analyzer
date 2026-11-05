"""HTTP engine safety (Atta Prompt 4): SSRF, redirects, passive mode, rebinding."""

from __future__ import annotations

import asyncio
import socket

import httpx
import pytest
import respx

from app.core.engine import HttpEngine, PinnedNetworkBackend, ScanResponse
from app.utils import security
from app.utils.security import SSRFError

pytestmark = pytest.mark.asyncio

PUBLIC = {"site.example": "93.184.215.14", "cdn.example": "93.184.215.15"}
PRIVATE = {"evil.example": "10.0.0.7", "meta.example": "169.254.169.254"}


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """Resolve our test names without the network; everything else fails."""

    def getaddrinfo(host, port, *a, **k):
        ip = {**PUBLIC, **PRIVATE}.get(host)
        if ip is None:
            raise socket.gaierror(f"unknown host {host}")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    monkeypatch.setattr(security.socket, "getaddrinfo", getaddrinfo)


@pytest.fixture
def engine():
    return HttpEngine(retries=1, max_concurrency=4)


# ------------------------------------------------------------------- SSRF


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/",
        "https://10.0.0.1/",
        "https://172.16.0.1/",
        "https://192.168.1.1/",
        "https://169.254.169.254/latest/meta-data/",
        "https://[fd00:ec2::254]/",
        "https://[::1]/",
        "https://[::ffff:127.0.0.1]/",
        "https://[::ffff:169.254.169.254]/",
        "https://0.0.0.0/",
        "https://224.0.0.1/",
        "https://100.64.0.1/",
        "https://2130706433/",
        "https://0x7f000001/",
        "https://0177.0.0.1/",
        "https://127.1/",
        "https://localhost/",
        "https://evil.example/",
        "https://meta.example/",
    ],
)
async def test_ssrf_targets_are_blocked_before_any_request(engine, url):
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route().respond(200)
        result = await engine.fetch(url)
    assert result.error and result.error.startswith("SSRF blocked"), result.error
    assert not route.called


@pytest.mark.parametrize(
    "location",
    [
        "https://127.0.0.1/admin",
        "http://0x7f000001/",
        "https://evil.example/x",
        "https://169.254.169.254/latest/meta-data/",
    ],
)
async def test_redirect_to_internal_address_is_blocked(engine, location):
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://site.example/").respond(302, headers={"Location": location})
        inner = mock.route().respond(200, text="secret")  # anything but the first hop
        result = await engine.fetch("https://site.example/")
    assert result.error and result.error.startswith("SSRF blocked")
    assert not inner.called
    assert result.redirect_chain[-1].startswith(location.split("/x")[0].rstrip("/"))


async def test_public_redirects_are_followed_and_recorded(engine):
    with respx.mock:
        respx.get("https://site.example/").respond(
            301, headers={"Location": "https://cdn.example/a"}
        )
        respx.get("https://cdn.example/a").respond(200, text="ok")
        result = await engine.fetch("https://site.example/")
    assert result.status == 200 and result.final_url == "https://cdn.example/a"
    assert result.redirect_chain == ["https://cdn.example/a"]


# ----------------------------------------------------------- passive mode


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"])
async def test_passive_mode_sends_only_get_and_head(method):
    engine = HttpEngine(passive_only=True)
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route().respond(200)
        result = await engine.fetch("https://site.example/", method=method)
    assert result.error and "passive" in result.error
    assert not route.called


async def test_passive_mode_allows_get_and_head():
    engine = HttpEngine(passive_only=True)
    with respx.mock:
        respx.get("https://site.example/").respond(200, text="hi")
        respx.head("https://site.example/").respond(200)
        assert (await engine.fetch("https://site.example/")).status == 200
        assert (await engine.fetch("https://site.example/", method="HEAD")).status == 200


# ---------------------------------------------------- normalised response


async def test_scan_response_is_normalised(engine, monkeypatch):
    monkeypatch.setattr(engine, "_max_response_size", 10)
    with respx.mock:
        respx.get("https://site.example/p").respond(
            200,
            text="0123456789ABCDEF",
            headers={"X-Frame-Options": "DENY", "Content-Type": "text/html; charset=utf-8"},
        )
        result = await engine.fetch("https://site.example/p")
    assert isinstance(result, ScanResponse)
    assert (result.url, result.final_url, result.status) == (
        "https://site.example/p",
        "https://site.example/p",
        200,
    )
    assert result.headers["x-frame-options"] == "DENY"
    assert all(k == k.lower() for k in result.headers)
    assert result.content_type.startswith("text/html")
    assert result.body == "0123456789" and result.truncated  # size cap
    assert result.response_time is not None and result.response_time >= 0
    assert result.redirect_chain == [] and result.tls is None  # TLS placeholder


# ------------------------------------------------- retries / concurrency


async def test_transient_errors_are_retried_for_get_only(engine):
    with respx.mock:
        route = respx.get("https://site.example/").mock(
            side_effect=[httpx.ConnectError("reset"), httpx.Response(200, text="ok")]
        )
        assert (await engine.fetch("https://site.example/")).status == 200
        assert route.call_count == 2
        post = respx.post("https://site.example/").mock(side_effect=httpx.ConnectError("reset"))
        result = await engine.fetch("https://site.example/", method="POST")
        assert result.error and post.call_count == 1  # not retried


async def test_concurrency_is_bounded_by_the_semaphore():
    engine = HttpEngine(max_concurrency=2)
    in_flight = peak = 0

    async def slow(request):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.02)
        in_flight -= 1
        return httpx.Response(200)

    with respx.mock:
        respx.get(url__regex=r"https://site\.example/\d").mock(side_effect=slow)
        await asyncio.gather(*(engine.fetch(f"https://site.example/{i}") for i in range(6)))
    assert peak == 2


async def test_http2_and_pinned_backend_are_configured(engine):
    pool = engine._transport._pool
    assert pool._http2 is True
    assert isinstance(pool._network_backend, PinnedNetworkBackend)


# ------------------------------------------------------- DNS rebinding


class _FakeBackend:
    def __init__(self):
        self.connected_to: list[str] = []

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,  # noqa: ASYNC109 - httpcore API
        local_address=None,
        socket_options=None,
    ):
        self.connected_to.append(host)
        return object()


async def test_connection_is_pinned_to_the_validated_ip(monkeypatch):
    inner = _FakeBackend()
    backend = PinnedNetworkBackend(inner=inner)
    await backend.connect_tcp("site.example", 443)
    assert inner.connected_to == ["93.184.215.14"]  # the IP, not the name

    # Rebinding: the name now resolves to a private address at connect time.
    PUBLIC["site.example"], saved = "10.0.0.9", PUBLIC["site.example"]
    try:
        with pytest.raises(SSRFError):
            await backend.connect_tcp("site.example", 443)
    finally:
        PUBLIC["site.example"] = saved
    assert inner.connected_to == ["93.184.215.14"]  # no second connection


async def test_http2_libraries_do_not_flood_the_logs():
    import logging

    from app.utils import logging as app_logging

    app_logging._CONFIGURED = False
    app_logging.configure_logging()
    # hpack/h2 log every header frame at DEBUG once HTTP/2 is on.
    assert logging.getLogger("hpack").level == logging.WARNING
    assert logging.getLogger("h2").level == logging.WARNING
