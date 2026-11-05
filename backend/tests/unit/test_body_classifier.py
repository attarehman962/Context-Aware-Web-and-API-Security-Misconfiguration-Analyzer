"""Tests for the response body classifier (Contribution 3)."""

from __future__ import annotations

from app.core.body_classifier import classify_body
from app.utils.redaction import MASK


def test_credentials_detected_and_force_critical():
    body = 'api_key = "cawasma-fake-abcdef123456"'
    r = classify_body(body)
    assert r.credentials is True
    assert r.bonus >= 3.5
    assert r.force_critical is True
    # Evidence must be redacted, not raw.
    assert r.evidence is not None and MASK in r.evidence


def test_pii_detected():
    r = classify_body("contact: john.doe@example.com")
    assert r.pii is True
    assert r.bonus >= 2.0


def test_financial_card_luhn():
    # 4111111111111111 is a valid Luhn test card.
    r = classify_body('{"card":"4111 1111 1111 1111"}')
    assert r.financial is True


def test_internal_ip_detected():
    r = classify_body("host is 10.0.12.5 internal")
    assert r.internal_ip is True
    assert r.bonus >= 2.0


def test_clean_body_no_signals():
    r = classify_body("welcome to our public homepage")
    assert not any([r.credentials, r.pii, r.financial, r.internal_ip])
    assert r.bonus == 0.0
