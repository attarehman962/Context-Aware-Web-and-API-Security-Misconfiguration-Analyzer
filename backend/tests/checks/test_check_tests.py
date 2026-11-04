"""Every check, spec-registry or legacy, has at least one fire and one no-fire test."""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

from app.core.checks import REGISTRY, registry
from tests.checks.helpers import legacy_rule_id

TESTS_DIR = Path(__file__).parent


def _calls(names: set[str]) -> dict[str, set[str]]:
    """check_id -> which of ``names`` the tests in tests/checks/ call with it."""
    used: dict[str, set[str]] = defaultdict(set)
    for path in TESTS_DIR.glob("test_*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in names and node.args
                    and isinstance(node.args[0], ast.Constant)):
                used[node.args[0].value].add(node.func.id)
    return used


def test_every_registered_check_has_fire_and_no_fire_tests():
    registry.load_implementations()
    want = {"assert_fires", "assert_no_fire"}
    used = _calls(want)
    missing = {cid: sorted(want - used[cid]) for cid in registry.CHECKS if used[cid] != want}
    assert not missing, f"checks without fire/no-fire tests: {missing}"


def test_every_legacy_rule_has_fire_and_no_fire_tests():
    want = {"assert_rule_fires", "assert_rule_no_fire"}
    used = _calls(want)
    ids = sorted(legacy_rule_id(fn) for fn in REGISTRY)
    assert len(ids) == 42
    missing = {cid: sorted(want - used[cid]) for cid in ids if used[cid] != want}
    assert not missing, f"legacy rules without fire/no-fire tests: {missing}"
