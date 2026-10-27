"""HDR-002..HDR-008, HDR-013, HDR-014 (checks/spec/security_headers.py)."""
from __future__ import annotations

import pytest

from tests.checks.helpers import assert_fires, assert_no_fire, response

GOOD_CSP = "default-src 'self'; frame-ancestors 'none'"


def test_hdr002_fires_without_csp():
    assert_fires("HDR-002", response(headers={}))


def test_hdr002_no_fire_with_csp():
    assert_no_fire("HDR-002", response(headers={"Content-Security-Policy": GOOD_CSP}))


@pytest.mark.parametrize("csp", ["script-src 'self' 'unsafe-inline'",
                                 "default-src 'self' 'unsafe-eval'"])
def test_hdr013_fires_on_unsafe_csp(csp):
    assert_fires("HDR-013", response(headers={"Content-Security-Policy": csp}))


@pytest.mark.parametrize("headers", [{"Content-Security-Policy": GOOD_CSP}, {}])
def test_hdr013_no_fire_on_strict_or_absent_csp(headers):
    # Absent CSP is HDR-002's finding, not "unsafe CSP".
    assert_no_fire("HDR-013", response(headers=headers))


@pytest.mark.parametrize("xfo", [None, "ALLOW-FROM https://x.example", "DENY, SAMEORIGIN"])
def test_hdr003_fires_on_missing_or_weak_xfo(xfo):
    assert_fires("HDR-003", response(headers={} if xfo is None else {"X-Frame-Options": xfo}))


@pytest.mark.parametrize("xfo", ["DENY", "sameorigin", " SAMEORIGIN "])
def test_hdr003_no_fire_on_deny_or_sameorigin(xfo):
    assert_no_fire("HDR-003", response(headers={"X-Frame-Options": xfo}))


@pytest.mark.parametrize("headers", [{}, {"Content-Security-Policy": "default-src 'self'"}])
def test_hdr014_fires_without_frame_ancestors(headers):
    assert_fires("HDR-014", response(headers=headers))


def test_hdr014_no_fire_with_frame_ancestors():
    assert_no_fire("HDR-014", response(headers={"Content-Security-Policy": GOOD_CSP}))


@pytest.mark.parametrize("headers", [{}, {"X-Content-Type-Options": "sniff"}])
def test_hdr004_fires_on_missing_or_weak_nosniff(headers):
    assert_fires("HDR-004", response(headers=headers))


@pytest.mark.parametrize("value", ["nosniff", "NOSNIFF"])
def test_hdr004_no_fire_with_nosniff(value):
    assert_no_fire("HDR-004", response(headers={"X-Content-Type-Options": value}))


@pytest.mark.parametrize("policy", [None, "unsafe-url", "no-referrer-when-downgrade",
                                    "origin-when-cross-origin"])
def test_hdr005_fires_on_missing_or_leaky_referrer_policy(policy):
    assert_fires("HDR-005", response(headers={} if policy is None
                                     else {"Referrer-Policy": policy}))


@pytest.mark.parametrize("policy", ["strict-origin-when-cross-origin", "no-referrer",
                                    "same-origin"])
def test_hdr005_no_fire_on_strict_referrer_policy(policy):
    assert_no_fire("HDR-005", response(headers={"Referrer-Policy": policy}))


def test_hdr006_fires_without_permissions_policy():
    assert_fires("HDR-006", response(headers={}))


def test_hdr006_no_fire_with_permissions_policy():
    assert_no_fire("HDR-006", response(headers={"Permissions-Policy": "geolocation=()"}))


@pytest.mark.parametrize("server", ["Apache/2.4.25 (Debian)", "nginx/1.18.0",
                                    "Werkzeug/2.2.3 Python/3.11.15"])
def test_hdr007_fires_on_versioned_server_banner(server):
    [f] = assert_fires("HDR-007", response(headers={"Server": server}))
    assert f.evidence["headers"]["Server"] == server


@pytest.mark.parametrize("headers", [{}, {"Server": "nginx"}, {"Server": "cloudflare"}])
def test_hdr007_no_fire_without_a_version(headers):
    assert_no_fire("HDR-007", response(headers=headers))


@pytest.mark.parametrize("headers", [{"X-Powered-By": "PHP/7.4.3"}, {"X-AspNet-Version": "4.0"},
                                     {"X-AspNetMvc-Version": "5.2"}])
def test_hdr008_fires_on_framework_banner(headers):
    assert_fires("HDR-008", response(headers=headers))


@pytest.mark.parametrize("headers", [{}, {"X-Powered-By": "Express"}])
def test_hdr008_no_fire_without_a_version(headers):
    assert_no_fire("HDR-008", response(headers=headers))


def test_header_checks_need_a_response():
    unreachable = response(headers={})
    unreachable.status_code = None
    for check_id in ("HDR-002", "HDR-006", "HDR-004"):
        assert_no_fire(check_id, unreachable)
