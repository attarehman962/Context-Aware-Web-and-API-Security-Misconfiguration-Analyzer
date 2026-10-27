"""eval/ground_truth/<target>.yaml: format and consistency (Asim Prompt 5)."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.config import settings
from app.core.specs import load_checks

ROOT = Path(__file__).resolve().parents[3] / "eval" / "ground_truth"
TARGETS = ["juice-shop", "dvwa", "vampi", "crapi"]
CHECK_IDS = {c.check_id for c in load_checks(Path(settings.CONFIG_DIR) / "checks.yaml").checks}
ENTRY_KEYS = {"endpoint", "check_id", "expected", "source", "notes", "verification"}


def _load(target: str) -> dict:
    return yaml.safe_load((ROOT / f"{target}.yaml").read_text())


@pytest.mark.parametrize("target", TARGETS)
def test_entries_use_the_agreed_format(target):
    doc = _load(target)
    assert doc["target"] == target
    assert doc["base_url"].startswith("http://") and "127.0.0.1" not in doc["base_url"]
    assert (ROOT / doc["evidence"]).exists()
    assert len(doc["known_issues"]) >= 5
    for entry in doc["known_issues"]:
        assert set(entry) == ENTRY_KEYS, entry
        assert entry["check_id"] in CHECK_IDS, entry["check_id"]
        assert entry["expected"] in {"present", "absent"}
        assert entry["verification"] in {"unverified", "verified"}
        assert entry["endpoint"].startswith("/")
        assert entry["source"].startswith("official docs: ")


@pytest.mark.parametrize("target", TARGETS)
def test_true_negatives_are_real_check_ids_and_never_expected_present(target):
    doc = _load(target)
    negatives = {n["check_id"] for n in doc["must_not_fire"]}
    assert negatives and negatives <= CHECK_IDS
    assert all(n["reason"] for n in doc["must_not_fire"])
    present = {e["check_id"] for e in doc["known_issues"] if e["expected"] == "present"}
    assert not negatives & present, negatives & present
