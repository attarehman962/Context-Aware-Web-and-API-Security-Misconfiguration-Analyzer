"""SSRF guard (Atta Prompt 4): every block case, encoded IP forms, internal hosts."""
from __future__ import annotations

import socket

import pytest

from app.config import settings
from app.utils import security
from app.utils.security import SSRFError, parse_ip_literal, validate_ip, validate_url_ssrf


@pytest.mark.parametrize("ip, reason", [
    ("127.0.0.1", "loopback"), ("::1", "loopback"),
    ("10.1.2.3", "private"), ("172.16.0.1", "private"), ("192.168.0.1", "private"),
    ("fc00::1", "private"),
    ("169.254.10.10", "link-local"), ("fe80::1", "link-local"),
    ("169.254.169.254", "metadata"), ("fd00:ec2::254", "metadata"),
    ("240.0.0.1", "reserved"),
    ("224.0.0.1", "multicast"), ("ff02::1", "multicast"),
    ("0.0.0.0", "unspecified"), ("::", "unspecified"),
    ("100.64.0.1", "non-public"),            # carrier-grade NAT
    ("198.18.0.1", "private"),               # benchmarking (Python counts it as private)
    ("::ffff:127.0.0.1", "loopback"),        # IPv4-mapped IPv6
    ("::ffff:169.254.169.254", "metadata"),
    ("::ffff:10.0.0.1", "private"),
    ("64:ff9b::7f00:1", "loopback"),         # NAT64 of 127.0.0.1
])
def test_every_block_case(ip, reason):
    with pytest.raises(SSRFError, match=reason):
        validate_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"])
def test_public_ips_pass(ip):
    validate_ip(ip)


@pytest.mark.parametrize("host, ip", [
    ("2130706433", "127.0.0.1"),     # decimal
    ("0x7f000001", "127.0.0.1"),     # hex
    ("017700000001", "127.0.0.1"),   # octal
    ("0177.0.0.1", "127.0.0.1"),     # dotted octal
    ("0x7f.0.0.1", "127.0.0.1"),     # dotted hex
    ("127.1", "127.0.0.1"),          # short form
    ("0xa9.0xfe.0xa9.0xfe", "169.254.169.254"),
    ("[::1]", "::1"),
])
def test_encoded_ip_literals_are_decoded(host, ip):
    assert str(parse_ip_literal(host)) == ip


@pytest.mark.parametrize("url", [
    "https://2130706433/", "https://0x7f000001/", "https://0177.0.0.1/", "https://127.1/",
    "https://0xa9.0xfe.0xa9.0xfe/latest/meta-data", "https://[::ffff:127.0.0.1]/",
    "https://localhost/", "https://LOCALHOST./",
])
def test_encoded_forms_are_blocked_without_dns(url, monkeypatch):
    def no_dns(*a, **k):
        raise AssertionError("IP literals must not go to DNS")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    with pytest.raises(SSRFError):
        validate_url_ssrf(url)


def _resolves_to(monkeypatch, ip: str) -> None:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    monkeypatch.setattr(security.socket, "getaddrinfo",
                        lambda *a, **k: [(family, socket.SOCK_STREAM, 6, "", (ip, 443))])


def test_hostname_is_checked_by_resolved_ip(monkeypatch):
    _resolves_to(monkeypatch, "10.0.0.7")
    with pytest.raises(SSRFError, match="private"):
        validate_url_ssrf("https://innocent.example.com/")
    _resolves_to(monkeypatch, "93.184.215.14")
    assert validate_url_ssrf("https://innocent.example.com/").ips == ("93.184.215.14",)


def test_allowed_internal_hosts_permit_private_ranges_only(monkeypatch):
    monkeypatch.setattr(settings, "ALLOWED_INTERNAL_HOSTS", "juice-shop, dvwa")
    _resolves_to(monkeypatch, "172.18.0.5")
    assert validate_url_ssrf("https://juice-shop:3000/").ips == ("172.18.0.5",)
    assert validate_url_ssrf("https://DVWA/").ips == ("172.18.0.5",)
    with pytest.raises(SSRFError):                       # not on the list
        validate_url_ssrf("https://vampi:5000/")
    for ip in ("127.0.0.1", "169.254.169.254", "fd00:ec2::254"):
        _resolves_to(monkeypatch, ip)                    # never allowed, even if listed
        with pytest.raises(SSRFError):
            validate_url_ssrf("https://juice-shop:3000/")


def test_allowed_internal_hosts_is_empty_by_default():
    assert settings.ALLOWED_INTERNAL_HOSTS == ""
    assert settings.allowed_internal_hosts == frozenset()


def test_malformed_url_is_an_ssrf_error_not_a_crash():
    for url in ("https://example.com:99999/", "https://[::1"):
        with pytest.raises(SSRFError, match="malformed"):
            validate_url_ssrf(url)
