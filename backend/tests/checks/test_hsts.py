"""HSTS checks (HDR-001 missing, TLS-009 weak): the reference fire/no-fire tests."""

from __future__ import annotations

import pytest

from tests.checks.helpers import assert_fires, assert_no_fire, response

STRONG = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}


# --------------------------------------------------------------- HDR-001


def test_hdr001_fires_when_hsts_is_missing():
    [finding] = assert_fires("HDR-001", response(headers={}))
    assert finding.evidence["present"] is False


def test_hdr001_no_fire_when_hsts_is_present():
    assert_no_fire("HDR-001", response(headers=STRONG))


def test_hdr001_no_fire_on_plain_http():
    assert_no_fire("HDR-001", response("http://shop.example.com/", headers={}))


# --------------------------------------------------------------- TLS-009


@pytest.mark.parametrize(
    "value, reason",
    [
        ("max-age=300; includeSubDomains", "max-age=300 is short"),
        ("max-age=0; includeSubDomains", "max-age=0 is short"),
        ("max-age=31536000", "includeSubDomains is missing"),
    ],
)
def test_tls009_fires_on_a_weak_policy(value, reason):
    [finding] = assert_fires("TLS-009", response(headers={"Strict-Transport-Security": value}))
    assert reason in finding.evidence["text"]
    assert finding.evidence["value"] == value


def test_tls009_no_fire_on_a_strong_policy():
    assert_no_fire("TLS-009", response(headers=STRONG))


def test_tls009_no_fire_when_hsts_is_missing():
    # Missing HSTS is HDR-001's finding, not a weak policy.
    assert_no_fire("TLS-009", response(headers={}))
