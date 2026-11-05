"""The engine must not carry cookies between requests, and must keep the
Set-Cookie headers of every redirect hop (eval: CKI-001/002/003 on DVWA).

DVWA sets PHPSESSID on the ``/`` -> ``/login.php`` redirect and again on
/login.php only when the request has no session cookie. With a shared jar the
second request sends it back and the insecure cookie is never seen.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from app.core.engine import HttpEngine

pytestmark = pytest.mark.asyncio

COOKIE = "PHPSESSID=abc123; path=/"


@pytest.fixture
def public_dns(monkeypatch):
    import socket

    def getaddrinfo(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 443))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


def _dvwa(request: httpx.Request) -> httpx.Response:
    has_session = "phpsessid" in request.headers.get("cookie", "").lower()
    headers = {} if has_session else {"Set-Cookie": COOKIE}
    if request.url.path == "/":
        return httpx.Response(302, headers={"Location": "/login.php", **headers})
    return httpx.Response(200, text="<form>login</form>", headers=headers)


async def test_no_cookie_is_sent_back_on_later_requests(public_dns):
    async with HttpEngine(scope_host="dvwa.example") as eng:
        with respx.mock:
            route = respx.route(host="dvwa.example").mock(side_effect=_dvwa)
            await eng.fetch("https://dvwa.example/login.php")
            second = await eng.fetch("https://dvwa.example/login.php?next=1")  # not cached
    assert all("cookie" not in c.request.headers for c in route.calls)
    assert second.set_cookie_headers == [COOKIE]


async def test_set_cookie_on_a_redirect_hop_is_kept(public_dns):
    async with HttpEngine(scope_host="dvwa.example") as eng:
        with respx.mock:
            respx.route(host="dvwa.example").mock(side_effect=_dvwa)
            r = await eng.fetch("https://dvwa.example/")
    assert r.status_code == 200 and r.final_url.endswith("/login.php")
    # Both hops set it (the redirect, and login.php since no cookie was sent).
    assert r.set_cookie_headers == [COOKIE, COOKIE]
    assert [c["name"] for c in r.cookies] == ["PHPSESSID", "PHPSESSID"]
    assert all("abc123" not in str(c) for c in r.cookies)  # metadata only
