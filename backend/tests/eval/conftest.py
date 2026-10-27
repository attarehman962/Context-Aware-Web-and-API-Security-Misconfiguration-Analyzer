"""Load the eval/ scripts (plain scripts, not a package) for testing."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

EVAL_DIR = Path(__file__).resolve().parents[3] / "eval"


def load_eval_script(relative: str) -> ModuleType:
    path = EVAL_DIR / relative
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module          # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module
