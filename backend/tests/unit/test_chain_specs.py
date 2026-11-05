"""chains.yaml format 1.1 (Asim's Prompt 4): groups, scope, context, CVSS vectors."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.config import settings
from app.core.checks.catalog import CATALOG
from app.core.contracts import BodySignal, SensitivityClass
from app.core.specs import SpecError, load_chains, load_checks

CONFIG = Path(settings.CONFIG_DIR)
CHECKS = load_checks(CONFIG / "checks.yaml").checks
SCORES = {c.check_id: c.base_score for c in CHECKS}
KNOWN = set(CATALOG) | set(SCORES)

BASE = {
    "chain_id": "C900",
    "name": "Example chain",
    "description": "Two findings that combine.",
    "groups": [["HDR-007", "HDR-008"], ["API-004"]],
    "scope": "same_host",
    "composite_cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "severity": "MEDIUM",
}


def _load(tmp_path, **changes):
    path = tmp_path / "chains.yaml"
    path.write_text(yaml.safe_dump({"chains_version": 1, "chains": [{**BASE, **changes}]}))
    return load_chains(path, known_check_ids=KNOWN, member_scores=SCORES)


def test_groups_scope_and_vector_derive_the_score(tmp_path):
    [chain] = _load(tmp_path).chains
    assert chain.score == 5.6 and chain.scope == "same_host"
    assert chain.member_ids == {"HDR-007", "HDR-008", "API-004"}


def test_context_conditions(tmp_path):
    [chain] = _load(
        tmp_path, endpoint_sensitivity=["HIGH", "CRITICAL"], body_signals=["CREDENTIALS"]
    ).chains
    assert chain.endpoint_sensitivity == [SensitivityClass.HIGH, SensitivityClass.CRITICAL]
    assert chain.body_signals == [BodySignal.CREDENTIALS]


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"composite_cvss_vector": "CVSS:3.1/AV:N"}, "invalid CVSS v3.1 base vector"),
        ({"composite_score": 9.0}, "does not match its vector"),
        ({"composite_cvss_vector": None}, "composite_cvss_vector or composite_score"),
        ({"requires": ["HDR-007", "API-004"], "min_matches": 2}, "either groups or requires"),
        ({"groups": [[]]}, "groups"),
        ({"scope": "same_page"}, "scope"),
        ({"severity": "HIGH"}, "does not match"),
        ({"groups": [["HDR-007"], ["XYZ-999"]]}, "unknown check XYZ-999"),
        # SRS objective O4: the chain must score above every member (API-004 is 5.3).
        ({"composite_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}, "must exceed"),
    ],
)
def test_invalid_chains_are_rejected(tmp_path, changes, message):
    with pytest.raises(SpecError) as err:
        _load(tmp_path, **changes)
    assert any(message in p for p in err.value.problems), err.value.problems


def test_legacy_requires_style_still_loads(tmp_path):
    [chain] = _load(
        tmp_path,
        groups=None,
        requires=["HDR-007", "API-004"],
        mandatory=[],
        min_matches=2,
        composite_cvss_vector=None,
        composite_score=5.6,
    ).chains
    assert chain.member_ids == {"HDR-007", "API-004"} and chain.score == 5.6


def test_shipped_chains_are_valid_and_beat_their_members():
    chains = load_chains(CONFIG / "chains.yaml", known_check_ids=KNOWN, member_scores=SCORES)
    assert [c.chain_id for c in chains.chains] == ["C001", "C002", "C003", "C004", "C005"]
    for chain in chains.chains:
        assert chain.composite_cvss_vector, chain.chain_id  # standards-valid score
        assert chain.score > max(SCORES[i] for i in chain.member_ids if i in SCORES)
