"""Check registry (Atta Prompt 5): registration and cross-validation with checks.yaml."""

from __future__ import annotations

import logging

import pytest

from app.core.checks import registry
from app.core.checks.registry import RegistryError, register_check, validate_registry
from tests.checks.helpers import endpoint, response


@pytest.fixture
def clean_registry(monkeypatch):
    monkeypatch.setattr(registry, "CHECKS", {})
    return registry.CHECKS


def test_register_check_adds_the_function(clean_registry):
    @register_check("HDR-001")
    def check(resp, ep):
        return []

    assert clean_registry == {"HDR-001": check}


def test_duplicate_or_malformed_ids_are_rejected(clean_registry):
    register_check("HDR-001")(lambda r, e: [])
    with pytest.raises(RegistryError, match="registered twice"):
        register_check("HDR-001")(lambda r, e: [])
    with pytest.raises(RegistryError, match="not a valid check_id"):
        register_check("hsts")


def test_implementation_without_spec_fails(clean_registry):
    register_check("XYZ-999")(lambda r, e: [])
    with pytest.raises(RegistryError, match="XYZ-999"):
        validate_registry(registry.load_specs())


def test_spec_without_implementation_only_warns(clean_registry, caplog):
    register_check("HDR-001")(lambda r, e: [])
    with caplog.at_level(logging.WARNING):
        missing = validate_registry(registry.load_specs())
    assert "HDR-001" not in missing and "TLS-005" in missing
    assert "no implementation" in caplog.text


def test_shipped_registry_matches_checks_yaml():
    registry.load_implementations()
    missing = validate_registry(registry.load_specs())  # must not raise
    assert {"HDR-001", "TLS-009"} <= set(registry.CHECKS)
    assert "HDR-001" not in missing


def test_a_failing_check_does_not_stop_the_others(clean_registry):
    @register_check("HDR-001")
    def broken(resp, ep):
        raise RuntimeError("boom")

    @register_check("HDR-002")
    def works(resp, ep):
        return [registry.RawFinding("HDR-002", ep, {"text": "x"})]

    found = registry.run_spec_checks(response(), endpoint())
    assert [f.check_id for f in found] == ["HDR-002"]


async def test_api_startup_fails_on_an_implementation_without_spec(clean_registry):
    from app.main import app, lifespan

    register_check("XYZ-999")(lambda r, e: [])
    with pytest.raises(RegistryError, match="XYZ-999"):
        async with lifespan(app):
            pass


def test_worker_startup_runs_the_same_validation(clean_registry):
    from app.workers import celery_app

    register_check("XYZ-999")(lambda r, e: [])
    with pytest.raises(RegistryError, match="XYZ-999"):
        celery_app.validate_checks_on_worker_start()
