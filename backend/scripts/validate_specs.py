"""Validate the spec files in config/ (owner of the files: Asim).

    python scripts/validate_specs.py checks   # config/checks.yaml (make validate-checks)
    python scripts/validate_specs.py all      # + cvss_mapping.yaml, chains.yaml and a
                                              #   catalog.py vector check (make validate-config)

Exit status 0 when every file is valid, 1 otherwise. Problems are printed one
per line as ``path: location: message``. Paths default to ``settings.CONFIG_DIR``;
override with ``--config-dir``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.config import settings
from app.core.checks.catalog import CATALOG
from app.core.cvss31 import CvssVectorError, base_score
from app.core.specs import SpecError, load_chains, load_checks, load_cvss_mapping


def catalog_vector_problems(spec_vectors: dict[str, str]) -> list[str]:
    """Catalog vectors that don't parse, or differ from the id's checks.yaml spec."""
    out = []
    for meta in CATALOG.values():
        try:
            base_score(meta.cvss_vector)
        except CvssVectorError as exc:
            out.append(f"{meta.rule_id}: invalid vector {meta.cvss_vector!r}: {exc}")
            continue
        spec = spec_vectors.get(meta.rule_id)
        if spec is not None and spec != meta.cvss_vector:
            out.append(f"{meta.rule_id}: {meta.cvss_vector} but checks.yaml has {spec}")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", choices=["checks", "all"], nargs="?", default="checks")
    parser.add_argument("--config-dir", type=Path, default=Path(settings.CONFIG_DIR))
    args = parser.parse_args(argv)
    cfg: Path = args.config_dir

    ok = True
    known_ids = set(CATALOG)
    scores: dict[str, float] = {}
    vectors: dict[str, str] = {}
    try:
        checks = load_checks(cfg / "checks.yaml")
        known_ids |= {c.check_id for c in checks.checks}
        scores = {c.check_id: c.base_score for c in checks.checks}
        vectors = {c.check_id: c.base_cvss_vector for c in checks.checks}
        summary = ", ".join(f"{c.check_id} ({c.base_score})" for c in checks.checks)
        print(f"OK   {cfg / 'checks.yaml'}: {len(checks.checks)} checks: {summary}")
    except SpecError as exc:
        ok = False
        _report(exc)

    if args.target == "all":
        try:
            load_cvss_mapping(cfg / "cvss_mapping.yaml")
            print(f"OK   {cfg / 'cvss_mapping.yaml'}")
        except SpecError as exc:
            ok = False
            _report(exc)
        try:
            chains = load_chains(cfg / "chains.yaml", known_ids, member_scores=scores)
            print(f"OK   {cfg / 'chains.yaml'}: {len(chains.chains)} chains")
        except SpecError as exc:
            ok = False
            _report(exc)
        problems = catalog_vector_problems(vectors)
        if problems:
            ok = False
            print(f"FAIL backend/app/core/checks/catalog.py: {len(problems)} vectors:")
            for line in problems:
                print(f"     {line}")
        else:
            print(
                "OK   backend/app/core/checks/catalog.py: every vector parses and "
                "matches checks.yaml"
            )
    return 0 if ok else 1


def _report(exc: SpecError) -> None:
    print(f"FAIL {exc.path}")
    for problem in exc.problems:
        print(f"     {problem}")


if __name__ == "__main__":
    sys.exit(main())
