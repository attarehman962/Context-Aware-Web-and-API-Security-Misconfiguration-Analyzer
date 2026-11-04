"""SEC review 1: the SSRF guard (utils/security.py, core/engine.py).

Every address form of loopback, private, link-local and metadata ranges must be
refused at three layers: the API (400 INVALID_TARGET, nothing stored), the
resolver check, and the engine's connect (the IP actually dialled). DNS is a
stub (conftest ``dns``); the engine's inner network backend is replaced by a
recorder, so nothing real is ever contacted.
"""
from __future__ import annotations

import httpcore
import pytest
from sqlalchemy import func, select

from app.core.engine import HttpEngine, PinnedNetworkBackend
from app.db.models import Scan
from app.utils.security import SSRFError, parse_ip_literal, resolve_and_validate

LOOPBACK_FORMS = [
    "127.0.0.1", "127.1", "127.0.1", "127.255.255.254",
    "2130706433",            # decimal
    "0x7f000001",            # hex, one part
    "0x7f.0.0.1",            # hex first octet
    "0177.0.0.1",            # octal
    "0177.0.0.01", "017700000001",
    "[::1]", "[0:0:0:0:0:0:0:1]",
    "[::ffff:127.0.0.1]", "[::ffff:7f00:1]",          # IPv4-mapped IPv6
    "[64:ff9b::7f00:1]",                             # NAT64 of 127.0.0.1
    "localhost", "LOCALHOST", "localhost.",
]
INTERNAL_FORMS = [
    "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "0x0a000001",
    "169.254.169.254", "0xa9fea9fe", "2852039166",   # AWS/GCP/Azure metadata, all forms
    "[fd00:ec2::254]",                               # AWS IPv6 metadata
    "100.100.100.200",                               # Alibaba metadata (CGNAT range)
    "0.0.0.0", "0", "[::]",
    "100.64.0.1",                                    # shared address space
    "198.18.0.1", "192.0.0.1", "192.0.2.1",          # benchmarking / IETF / docs
    "224.0.0.1", "[ff02::1]",                        # multicast
    "[fe80::1]", "[fc00::1]",                        # link-local, ULA
    "[fec0::1]",                                     # deprecated site-local (SEC-07)
    "[::ffff:10.0.0.1]", "[::ffff:169.254.169.254]",
    "240.0.0.1", "255.255.255.255",                  # reserved / broadcast
]


class Recorder:
    """Inner network backend: records the IP the engine dials, never connects."""

    def __init__(self) -> None:
        self.dialled: list[str] = []

    async def connect_tcp(self, host, port, **kwargs):
        self.dialled.append(host)
        raise httpcore.ConnectError("recorder: not connecting")

    async def sleep(self, seconds):
        return None


def _engine(recorder: Recorder) -> HttpEngine:
    eng = HttpEngine(retries=0)
    eng._transport._pool._network_backend = PinnedNetworkBackend(recorder)
    return eng


# ---------------------------------------------------------------- resolver

@pytest.mark.parametrize("host", LOOPBACK_FORMS + INTERNAL_FORMS)
def test_every_internal_address_form_is_refused_by_the_resolver_check(dns, host):
    with pytest.raises(SSRFError):
        resolve_and_validate(host.strip("[]"))


@pytest.mark.parametrize("literal, ip", [
    ("2130706433", "127.0.0.1"), ("0x7f.1", "127.0.0.1"), ("0177.0.0.1", "127.0.0.1"),
    ("127.1", "127.0.0.1"), ("0xa9fea9fe", "169.254.169.254"),
])
def test_inet_aton_forms_decode_like_browsers_do(literal, ip):
    assert str(parse_ip_literal(literal)) == ip


@pytest.mark.parametrize("ips", [
    ["10.1.2.3"], ["127.0.0.1"], ["169.254.169.254"], ["::1"], ["fd12:3456::1"],
    ["93.184.216.34", "10.0.0.5"],         # one bad answer among good ones
    ["::ffff:192.168.0.10"],
])
def test_dns_names_resolving_to_internal_addresses_are_refused(dns, ips):
    dns["intranet.example"] = ips
    with pytest.raises(SSRFError):
        resolve_and_validate("intranet.example")


def test_allowed_internal_hosts_never_open_loopback_or_metadata(dns, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "ALLOWED_INTERNAL_HOSTS", "lab.example")
    for ip in ("127.0.0.1", "169.254.169.254", "::1", "0.0.0.0"):
        dns["lab.example"] = [ip]
        with pytest.raises(SSRFError):
            resolve_and_validate("lab.example")
    dns["lab.example"] = ["10.9.8.7"]        # private is what the allow-list is for
    assert resolve_and_validate("lab.example").ips == ("10.9.8.7",)


# -------------------------------------------------------------- engine

@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["127.0.0.1", "2130706433", "0x7f.0.0.1", "[::1]",
                                  "[::ffff:127.0.0.1]", "169.254.169.254", "10.0.0.1",
                                  "localhost", "intranet.example"])
async def test_engine_never_dials_an_internal_address(dns, host):
    dns["intranet.example"] = ["192.168.10.10"]
    rec = Recorder()
    async with _engine(rec) as eng:
        r = await eng.fetch(f"https://{host}/")
    assert rec.dialled == [] and r.status_code is None and "SSRF" in (r.error or "")


@pytest.mark.asyncio
async def test_dns_rebinding_is_blocked_at_connect_time(dns):
    """First answer public (passes the URL check), every later one private: the
    engine must validate and dial the address of the lookup it connects with."""
    answers = iter([["93.184.216.34"]])

    import socket
    stub = socket.getaddrinfo

    def rebinding(host, port, *a, **k):
        if host == "rebind.example":
            dns["rebind.example"] = next(answers, ["127.0.0.1"])
        return stub(host, port, *a, **k)

    socket.getaddrinfo = rebinding
    try:
        rec = Recorder()
        async with _engine(rec) as eng:
            await eng.fetch("https://rebind.example/")
    finally:
        socket.getaddrinfo = stub
    assert "127.0.0.1" not in rec.dialled
    assert set(rec.dialled) <= {"93.184.216.34"}


@pytest.mark.asyncio
@pytest.mark.parametrize("location", [
    "http://127.0.0.1/", "http://2130706433/", "http://[::1]/", "http://169.254.169.254/",
    "http://metadata.google.internal/", "http://localhost:6379/", "http://intranet.example/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
])
async def test_redirects_to_internal_hosts_are_not_followed(dns, location):
    import respx

    dns["public.example"] = ["93.184.216.34"]
    dns["intranet.example"] = ["10.0.0.7"]
    dns["metadata.google.internal"] = ["169.254.169.254"]
    async with HttpEngine(retries=0) as eng:
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://public.example/").respond(302, headers={"Location": location})
            internal = mock.route(url__regex=r"^http://(?!public\.example).*").respond(200)
            r = await eng.fetch("https://public.example/")
    assert not internal.called
    assert r.final_url == "https://public.example/" or "SSRF" in (r.error or "")


# ------------------------------------------------------------------- API

@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["127.0.0.1", "2130706433", "0x7f.0.0.1", "0177.0.0.1",
                                  "[::1]", "[::ffff:127.0.0.1]", "169.254.169.254",
                                  "10.0.0.1", "localhost", "intranet.example",
                                  "[fd00:ec2::254]", "0.0.0.0"])
async def test_api_refuses_internal_targets_and_stores_nothing(client, sessionmaker_, dns,
                                                               host):
    dns["intranet.example"] = ["172.20.0.5"]
    r = await client.post("/api/scan", json={"url": f"https://{host}/",
                                             "authorisation_confirmed": True})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "INVALID_TARGET"
    async with sessionmaker_() as s:
        assert await s.scalar(select(func.count()).select_from(Scan)) == 0


@pytest.mark.asyncio
async def test_refusal_does_not_reveal_what_an_internal_name_resolves_to(client, dns):
    """An error that echoes the resolved address turns the API into an oracle for
    the server's internal DNS (which names exist inside, and their IPs)."""
    dns["db.corp.internal"] = ["10.44.55.66"]
    r = await client.post("/api/scan", json={"url": "https://db.corp.internal/",
                                             "authorisation_confirmed": True})
    assert r.status_code == 400
    assert "10.44.55.66" not in r.text
