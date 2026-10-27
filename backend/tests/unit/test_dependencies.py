"""Dependency hygiene (review asim-p04 #8, #10)."""
from __future__ import annotations

import ast
import re
import sys
import tomllib
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
ROOT = BACKEND.parent
PYPROJECT = tomllib.loads((BACKEND / "pyproject.toml").read_text())

# Used only by eval/ scripts and notebooks; must not be baked into the api/worker image
# via requirements-ml.txt (cvss is a runtime dependency in pyproject instead).
EVAL_ONLY = {"scikit-learn", "pandas", "matplotlib"}
# import name -> distribution name, where they differ
DIST_FOR_IMPORT = {"yaml": "PyYAML", "sklearn": "scikit-learn", "bs4": "beautifulsoup4"}


def _name(requirement: str) -> str:
    return re.split(r"[<>=@\[ ;]", requirement.strip(), maxsplit=1)[0].lower()


def _image_requirements() -> set[str]:
    lines = (BACKEND / "requirements-ml.txt").read_text().splitlines()
    return {_name(line) for line in lines if line.strip() and not line.startswith(("#", "-"))}


def test_image_does_not_install_eval_only_packages():
    assert _image_requirements() & EVAL_ONLY == set()


def test_every_eval_script_import_is_declared():
    declared = {_name(r) for r in PYPROJECT["project"]["dependencies"]}
    for extra in PYPROJECT["project"]["optional-dependencies"].values():
        declared |= {_name(r) for r in extra}
    missing = set()
    generated = {".cache", ".run", "raw"}          # downloads and tool outputs, not our code
    for script in (ROOT / "eval").rglob("*.py"):
        if generated & set(script.relative_to(ROOT).parts):
            continue
        for node in ast.walk(ast.parse(script.read_text())):
            names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                     else [node.module] if isinstance(node, ast.ImportFrom) and node.module
                     else [])
            for name in names:
                top = name.split(".")[0]
                if top in sys.stdlib_module_names or top == "__future__":
                    continue
                # Local code: a sibling script, or the backend's own packages.
                if (script.parent / f"{top}.py").exists() or top in {"app", "scripts"}:
                    continue
                if DIST_FOR_IMPORT.get(top, top).lower() not in declared:
                    missing.add(f"{script.relative_to(ROOT)}: {top}")
    assert not missing, f"undeclared imports: {sorted(missing)}"
