"""Tests for SSRF protection."""

from __future__ import annotations

import pytest

from app.utils.security import SSRFError, validate_ip, validate_url_ssrf


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",  # loopback
        "10.0.0.5",  # private
        "192.168.1.1",  # private
        "172.16.0.1",  # private
        "169.254.169.254",  # link-local / cloud metadata
        "0.0.0.0",  # unspecified
        "::1",  # IPv6 loopback
        "fe80::1",  # IPv6 link-local
        "fc00::1",  # IPv6 unique-local (private)
    ],
)
def test_blocked_ips(ip):
    with pytest.raises(SSRFError):
        validate_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_public_ips_allowed(ip):
    validate_ip(ip)  # should not raise


def test_localhost_hostname_blocked():
    with pytest.raises(SSRFError):
        validate_url_ssrf("https://localhost/admin")


def test_metadata_hostname_blocked_by_ip():
    # 169.254.169.254 is link-local; even via literal it is blocked.
    with pytest.raises(SSRFError):
        validate_url_ssrf("https://169.254.169.254/latest/meta-data")


def test_allow_private_override():
    # The test override lets us reach a local mock server.
    r = validate_url_ssrf("http://127.0.0.1:8000/", allow_private=True)
    assert "127.0.0.1" in r.ips
