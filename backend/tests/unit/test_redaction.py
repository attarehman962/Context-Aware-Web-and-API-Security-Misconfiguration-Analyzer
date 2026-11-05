"""Tests for secret redaction."""

from __future__ import annotations

from app.utils.redaction import (
    MASK,
    redact_header,
    redact_headers,
    redact_text,
    safe_evidence,
)


def test_authorization_header_redacted():
    assert redact_header("Authorization", "Bearer abc123def456") == MASK
    assert redact_header("authorization", "x") == MASK


def test_cookie_headers_redacted():
    out = redact_headers({"Set-Cookie": "session=secret", "X-Frame-Options": "DENY"})
    assert out["Set-Cookie"] == MASK
    assert out["X-Frame-Options"] == "DENY"  # non-sensitive kept


def test_jwt_in_text_redacted():
    # Assembled at run time so no JWT-shaped literal sits in the repo.
    jwt = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKL"
    assert MASK in redact_text(f"token is {jwt}")


def test_api_key_assignment_redacted():
    assert MASK in redact_text('api_key = "cawasma-fake-abcdef123456"')
    assert MASK in redact_text("password: hunter2000")


def test_safe_evidence_truncates():
    long = "a" * 1000
    out = safe_evidence(long, max_len=100)
    assert out is not None and len(out) <= 101
