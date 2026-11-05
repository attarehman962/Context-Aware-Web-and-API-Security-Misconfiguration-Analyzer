"""Spec files in config/ and the validator that guards them."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from app.config import settings
from app.core.checks.catalog import CATALOG
from app.core.contracts import (
    BodySignal,
    EndpointInfo,
    ResponseInfo,
    SensitivityClass,
    builtin_analyze,
    builtin_classify,
    check_conformance,
)
from app.core.specs import SpecError, load_chains, load_checks, load_cvss_mapping
from scripts import validate_specs

CONFIG = Path(settings.CONFIG_DIR)
VALID = yaml.safe_load((CONFIG / "checks.yaml").read_text())


def _write(tmp_path: Path, data: object, name: str = "checks.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data) if not isinstance(data, str) else data)
    return path


def _mutated(**changes: object) -> dict:
    data = copy.deepcopy(VALID)
    data["checks"][0].update(changes)
    return data


# Shipped files


def test_shipped_spec_files_are_valid():
    # The content is Asim's and changes over time: assert validity, not values.
    checks = load_checks(CONFIG / "checks.yaml")
    assert checks.checks
    assert all(0.0 <= c.base_score <= 10.0 for c in checks.checks)
    mapping = load_cvss_mapping(CONFIG / "cvss_mapping.yaml")
    assert set(mapping.sensitivity_classes) == set(SensitivityClass)
    load_chains(
        CONFIG / "chains.yaml", known_check_ids=set(CATALOG) | {c.check_id for c in checks.checks}
    )


# Invalid checks


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"base_cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}, "must start with"),
        ({"base_cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N"}, "missing base metric"),
        ({"base_cvss_vector": "CVSS:3.1/AV:Q/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}, "invalid value"),
        ({"check_id": "hsts-1"}, "check_id"),
        ({"category": "NETWORK"}, "category"),
        ({"owasp": ["API11:2023"]}, "owasp"),
        ({"owasp": []}, "owasp"),
        ({"cwe": ["319"]}, "cwe"),
        ({"description": "short"}, "description"),
        ({"severity": "HIGH"}, "Extra inputs are not permitted"),
        (
            {"http_condition": {"method": "POST", "rules": [{"header": "X", "op": "missing"}]}},
            "method",
        ),
        ({"http_condition": {"rules": []}}, "rules"),
        ({"http_condition": {"rules": [{"header": "X", "op": "equals"}]}}, "needs a value"),
        (
            {"http_condition": {"rules": [{"header": "X", "op": "missing", "value": "y"}]}},
            "takes no value",
        ),
        (
            {"http_condition": {"rules": [{"header": "X", "op": "matches", "value": "(["}]}},
            "invalid regex",
        ),
        ({"http_condition": {"rules": [{"status": "in", "value": [42]}]}}, "status"),
        (
            {"http_condition": {"rules": [{"header": "X", "body": "contains", "value": "a"}]}},
            "exactly one of header/header_names/status/body/url",
        ),
    ],
)
def test_invalid_check_specs_are_rejected(tmp_path, changes, message):
    with pytest.raises(SpecError) as err:
        load_checks(_write(tmp_path, _mutated(**changes)))
    assert any(message in p for p in err.value.problems), err.value.problems


def test_duplicate_check_ids_and_bad_files_are_rejected(tmp_path):
    data = copy.deepcopy(VALID)
    data["checks"][1]["check_id"] = data["checks"][0]["check_id"]
    with pytest.raises(SpecError, match="duplicate check_id"):
        load_checks(_write(tmp_path, data))
    with pytest.raises(SpecError, match="not valid YAML"):
        load_checks(_write(tmp_path, "checks: [unclosed"))
    with pytest.raises(SpecError, match="file not found"):
        load_checks(tmp_path / "missing.yaml")
    with pytest.raises(SpecError, match="spec_version"):
        load_checks(_write(tmp_path, {**VALID, "spec_version": 2}))


# Mapping and chains rules


def test_mapping_must_cover_every_class_and_signal(tmp_path):
    data = yaml.safe_load((CONFIG / "cvss_mapping.yaml").read_text())
    del data["body_signals"]["PII"]
    with pytest.raises(SpecError, match="missing: PII"):
        load_cvss_mapping(_write(tmp_path, data, "m.yaml"))
    data = yaml.safe_load((CONFIG / "cvss_mapping.yaml").read_text())
    data["sensitivity_classes"]["LOW"]["CR"] = "HIGH"
    with pytest.raises(SpecError, match="CR"):
        load_cvss_mapping(_write(tmp_path, data, "m.yaml"))


# The original requires/mandatory/min_matches style (format 1.0) stays valid.
LEGACY_CHAIN = {
    "chain_id": "C005",
    "name": ".env Exposure -> Version Leak -> Full Compromise",
    "description": "An exposed .env combined with version disclosure.",
    "requires": ["INF-003", "HDR-007", "INF-004"],
    "mandatory": ["INF-003"],
    "min_matches": 2,
    "composite_score": 9.8,
    "severity": "CRITICAL",
}


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"mandatory": ["INF-005"]}, "must also be in requires"),
        ({"min_matches": 5}, "min_matches"),
        ({"severity": "HIGH"}, "does not match the chain score"),
        ({"requires": ["INF-003", "XYZ-999"], "min_matches": 2}, "unknown check XYZ-999"),
    ],
)
def test_invalid_chains_are_rejected(tmp_path, changes, message):
    data = {"chains_version": 1, "chains": [{**LEGACY_CHAIN, **changes}]}
    with pytest.raises(SpecError) as err:
        load_chains(_write(tmp_path, data, "c.yaml"), known_check_ids=CATALOG)
    assert any(message in p for p in err.value.problems), err.value.problems


# ML contract


def test_builtin_classifiers_conform_to_the_ml_contract():
    assert check_conformance(builtin_classify, builtin_analyze) == []
    assert (
        builtin_classify(
            EndpointInfo("https://x.example.com/api/payment/checkout", "/api/payment/checkout")
        )
        is SensitivityClass.CRITICAL
    )
    signals = builtin_analyze(
        ResponseInfo(
            "https://x.example.com/u",
            200,
            "application/json",
            body='{"email": "a.khan@example.com"}',
        )
    )
    assert signals == {BodySignal.PII}


def test_conformance_catches_contract_violations():
    def bad_classify(endpoint):
        return "HIGH"  # a string, not SensitivityClass

    def bad_analyze(response):
        raise RuntimeError("boom")

    problems = check_conformance(bad_classify, bad_analyze)
    assert any("not SensitivityClass" in p for p in problems)
    assert any("raised" in p for p in problems)


# CLI


def test_validator_cli_exit_codes(tmp_path, capsys):
    assert validate_specs.main(["checks", "--config-dir", str(CONFIG)]) == 0
    _write(tmp_path, _mutated(base_cvss_vector="CVSS:3.1/AV:N"))
    assert validate_specs.main(["checks", "--config-dir", str(tmp_path)]) == 1
    assert "FAIL" in capsys.readouterr().out


# Per-person plan, Contract 1 (gaps)


def test_owasp_top10_2025_ids_are_accepted(tmp_path):
    # The plan's example uses A02:2025, and the SRS cites OWASP Top 10 (2025).
    spec = load_checks(_write(tmp_path, _mutated(owasp=["A02:2025", "API8:2023"])))
    assert spec.checks[0].owasp == ["A02:2025", "API8:2023"]


def test_severity_notes_is_an_optional_field(tmp_path):
    spec = load_checks(_write(tmp_path, _mutated(severity_notes="raise with endpoint sensitivity")))
    assert spec.checks[0].severity_notes == "raise with endpoint sensitivity"
    assert load_checks(CONFIG / "checks.yaml").checks[0].severity_notes is None


def test_spec_status_defaults_to_approved_and_only_takes_two_values():
    from app.core.specs import CheckSpec

    base = {
        "check_id": "HDR-001",
        "category": "HEADERS",
        "description": "missing HSTS header",
        "http_condition": {"rules": [{"header": "Strict-Transport-Security", "op": "missing"}]},
        "owasp": ["A05:2021"],
        "cwe": ["CWE-319"],
        "base_cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    }
    assert CheckSpec.model_validate(base).status == "approved"
    assert CheckSpec.model_validate({**base, "status": "proposed"}).status == "proposed"
    with pytest.raises(ValueError):
        CheckSpec.model_validate({**base, "status": "draft"})
