"""Write docs/check-coverage.md: every check id, how it is implemented, its tests.

    python scripts/check_coverage.py        # or: make check-coverage

For each check in config/checks.yaml and the legacy catalog: whether it is a
spec-registry check (and which module), a legacy ``@rule``, or not
implemented; whether it has fire and no-fire tests (``assert_fires`` /
``assert_no_fire`` with its id); and whether every test that names the id
passed in a fresh pytest run.
"""
from __future__ import annotations

import ast
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.core.checks import REGISTRY  # noqa: E402
from app.core.checks import registry as spec_registry  # noqa: E402
from app.core.checks.catalog import CATALOG  # noqa: E402

OUTPUT = BACKEND.parent / "docs" / "check-coverage.md"
TEST_FILES = sorted({*BACKEND.glob("tests/checks/test_*.py"),
                     BACKEND / "tests/unit/test_checks.py",
                     BACKEND / "tests/unit/test_review_fixes.py",
                     BACKEND / "tests/integration/test_tls_sslyze.py"})

# Specs that stay on their legacy rule until Asim answers (see the doc's questions).
BLOCKED = {
    "API-001": "Which endpoints are 'authentication endpoints'?",
    "API-003": "Which sensitivity classes count as 'sensitive' (HIGH, CRITICAL, both)?",
    "INF-003": "What is an 'artifact-like path' for .env, and must the status be 2xx?",
    "INF-004": "Same for .git (the regex matches .git/HEAD quoted in a 404 page).",
    "INF-005": "Same for backups/keys (path suffixes? status?).",
}


def _ids(node: ast.AST) -> set[str]:
    return {n.value for n in ast.walk(node) if isinstance(n, ast.Constant)
            and isinstance(n.value, str) and len(n.value) == 7 and n.value[3] == "-"
            and n.value[:3].isalpha() and n.value[4:].isdigit()}


def test_index() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """check id -> test node ids naming it; check id -> {"assert_fires", "assert_no_fire"}."""
    tests: dict[str, set[str]] = defaultdict(set)
    kinds: dict[str, set[str]] = defaultdict(set)
    for path in TEST_FILES:
        rel = path.relative_to(BACKEND).as_posix()
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and \
                    node.name.startswith("test_"):
                for cid in _ids(node):
                    tests[cid].add(f"{rel}::{node.name}")
                for call in ast.walk(node):
                    if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                            and call.func.id in {"assert_fires", "assert_no_fire"}
                            and call.args and isinstance(call.args[0], ast.Constant)):
                        kinds[call.args[0].value].add(call.func.id)
    return tests, kinds


def run_tests() -> dict[str, bool]:
    """test node id (without params) -> passed."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "junit.xml"
        subprocess.run([sys.executable, "-m", "pytest",  # noqa: S603 - fixed args, own tests "-q", "-p", "no:cacheprovider",
                        f"--junitxml={report}", *map(str, TEST_FILES)],
                       cwd=BACKEND, capture_output=True, check=False)
        passed: dict[str, bool] = {}
        root = ET.parse(report).getroot()  # noqa: S314 - the report pytest just wrote
        for case in root.iter("testcase"):
            module = case.get("classname", "").replace(".", "/") + ".py"
            node = f"{module}::{case.get('name', '').split('[')[0]}"
            ok = not any(child.tag in {"failure", "error"} for child in case)
            passed[node] = passed.get(node, True) and ok
        return passed


def main() -> int:
    spec_registry.load_implementations()
    specs = spec_registry.load_specs()
    legacy = {fn.__name__.split("_")[0].upper() + "-" + fn.__name__.split("_")[1]: fn
              for fn in REGISTRY}
    tests, kinds = test_index()
    passed = run_tests()

    rows: list[str] = []
    totals: defaultdict[str, int] = defaultdict(int)
    for cid in sorted(set(specs) | set(CATALOG)):
        title = (specs[cid].title if cid in specs else None) or CATALOG[cid].name
        if cid in spec_registry.CHECKS:
            impl = f"spec registry (`{spec_registry.CHECKS[cid].__module__.rsplit('.', 1)[-1]}`)"
            totals["spec"] += 1
        elif cid in legacy:
            impl = f"legacy `@rule` (`{legacy[cid].__module__.rsplit('.', 1)[-1]}`)"
            totals["legacy"] += 1
        else:
            impl = "**not implemented**"
            totals["missing"] += 1
        if cid in BLOCKED:
            impl += " - blocked, question for Asim"
        fire = "yes" if {"assert_fires", "assert_no_fire"} <= kinds[cid] else (
            "n/a (legacy)" if cid in legacy and cid not in spec_registry.CHECKS else "no")
        nodes = sorted(tests[cid])
        results = [passed.get(n) for n in nodes]
        status = ("no tests" if not nodes else
                  "pass" if all(results) else "**FAIL**" if any(r is False for r in results)
                  else "not run")
        totals[status] += 1
        rows.append(f"| {cid} | {title} | {'yes' if cid in specs else 'no'} | {impl} | "
                    f"{fire} | {len(nodes)} | {status} |")

    lines = [
        "# Check coverage",
        "",
        "Generated by `backend/scripts/check_coverage.py` (`make check-coverage`); do not",
        "edit by hand. \"Tests\" counts the test functions that name the check id; \"passing\"",
        "is from a fresh pytest run of those files.",
        "",
        f"**{len(rows)} check ids**: {totals['spec']} spec-registry checks (scored with CVSS",
        f"v3.1 environmental metrics), {totals['legacy']} legacy `@rule` checks (interim",
        f"formula), {totals['missing']} not implemented. Tests: {totals['pass']} pass,",
        f"{totals['**FAIL**']} fail, {totals['no tests']} without a test naming them.",
        "",
        "| check_id | title | in checks.yaml | implementation | fire/no-fire tests | tests "
        "| passing |",
        "|---|---|---|---|---|---|---|",
        *rows,
        "",
        "## Open questions for Asim (checks.yaml)",
        "",
        "These specs say *where* they apply in a `limitation` the condition format can't",
        "express; implementing them would mean guessing, so they stay on their legacy rule",
        "(which scans still report) until the spec says:",
        "",
        *[f"- **{cid}**: {q}" for cid, q in BLOCKED.items()],
        "",
    ]
    OUTPUT.write_text("\n".join(lines))
    print(f"wrote {OUTPUT}: {len(rows)} checks, {totals['pass']} passing, "
          f"{totals['**FAIL**']} failing")
    return 1 if totals["**FAIL**"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
