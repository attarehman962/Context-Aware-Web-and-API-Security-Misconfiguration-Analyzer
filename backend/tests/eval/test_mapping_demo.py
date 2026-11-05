"""eval/harness/mapping_demo.py uses the real check vectors (review asim-p04 #11)."""

from __future__ import annotations

from pathlib import Path

from app.config import settings
from app.core.specs import load_checks
from tests.eval.conftest import load_eval_script

demo = load_eval_script("harness/mapping_demo.py")


def test_demo_examples_come_from_checks_yaml():
    specs = {c.check_id: c for c in load_checks(Path(settings.CONFIG_DIR) / "checks.yaml").checks}
    rows = demo.examples()
    assert len(rows) == 5
    for check_id, title, vector in rows:
        assert vector == specs[check_id].base_cvss_vector, check_id
        assert title == specs[check_id].title
