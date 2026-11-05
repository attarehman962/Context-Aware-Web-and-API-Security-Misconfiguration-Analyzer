"""Tests for the CVSS + CAWASMA scoring engine."""

from __future__ import annotations

from app.core.cvss import compute_score, severity_for
from app.db.models.enums import ContextClass, Severity


def test_severity_buckets():
    assert severity_for(9.5) == Severity.CRITICAL
    assert severity_for(7.0) == Severity.HIGH
    assert severity_for(4.0) == Severity.MEDIUM
    assert severity_for(0.5) == Severity.LOW
    assert severity_for(0.0) == Severity.INFO


def test_formula_critical_endpoint_caps_at_10():
    # Spec example: base 6.1 on CRITICAL endpoint (x2.0) + PII/financial bonus.
    r = compute_score(6.1, ContextClass.CRITICAL, response_bonus=2.0)
    assert r.context_multiplier == 2.0
    assert r.cawasma_final_score == 10.0  # capped
    assert r.severity == Severity.CRITICAL


def test_formula_low_endpoint():
    # Spec example: base 6.1 on LOW endpoint (x0.6) -> 3.66 -> 3.7 LOW.
    r = compute_score(6.1, ContextClass.LOW)
    assert r.context_multiplier == 0.6
    assert r.cawasma_final_score == 3.7
    assert r.severity == Severity.LOW


def test_base_and_final_are_distinct():
    r = compute_score(6.1, ContextClass.CRITICAL, response_bonus=0.0)
    assert r.cvss_base_score == 6.1  # official, unchanged
    assert r.cawasma_final_score != r.cvss_base_score  # custom, context-adjusted


def test_force_critical_for_credentials():
    r = compute_score(4.3, ContextClass.LOW, response_bonus=3.5, force_critical=True)
    assert r.severity == Severity.CRITICAL
    assert r.cawasma_final_score >= 9.0
