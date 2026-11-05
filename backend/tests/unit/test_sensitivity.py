"""Tests for the endpoint sensitivity classifier (keyword layer, no model)."""

from __future__ import annotations

from app.core.sensitivity import SensitivityClassifier
from app.db.models.enums import ContextClass

# Force keyword-only so tests are deterministic and model-independent.
clf = SensitivityClassifier(use_embeddings=False)


def test_spec_examples():
    assert clf.classify("/svc/iam/priv/escalate").context_class == ContextClass.CRITICAL
    assert clf.classify("/ms/billing/stripe/webhook").context_class == ContextClass.CRITICAL
    assert clf.classify("/api/v2/usr/auth/mfa/verify").context_class == ContextClass.HIGH
    assert clf.classify("/public/about").context_class == ContextClass.LOW


def test_result_is_explainable():
    r = clf.classify("/api/payment/checkout")
    assert r.context_class == ContextClass.CRITICAL
    assert isinstance(r.reason, list) and len(r.reason) >= 1
    assert 0.0 < r.confidence <= 1.0
    d = r.as_dict()
    assert set(d.keys()) == {"class", "confidence", "reason"}


def test_low_when_no_tokens():
    r = clf.classify("/xyz123")
    assert r.context_class == ContextClass.LOW
    assert r.reason  # still explains itself
