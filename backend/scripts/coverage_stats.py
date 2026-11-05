"""The coverage numbers for the report, computed, never typed by hand.

    python scripts/coverage_stats.py            # or: make coverage-stats
    python scripts/coverage_stats.py --json

Per check id (catalog.py and config/checks.yaml together): whether it has a spec,
a ground-truth entry (eval/ground_truth/<target>.yaml, known_issues or
must_not_fire), and whether scans score it with CVSS environmental metrics (a
spec-registry check) or the interim legacy formula (a legacy @rule). With the
latest CAWASMA run per target in eval/results/raw/ (if any), also how many
stored findings carry each scoring method. The output names the branch and
commit it ran on: the report figure is taken once, on main, after every merge.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))

from app.core.checks import REGISTRY  # noqa: E402
from app.core.checks import registry as spec_registry  # noqa: E402
from app.core.checks.catalog import CATALOG  # noqa: E402

GROUND_TRUTH = ROOT / "eval" / "ground_truth"
RAW = ROOT / "eval" / "results" / "raw" / "cawasma"


def legacy_ids() -> set[str]:
    return {fn.__name__.split("_")[0].upper() + "-" + fn.__name__.split("_")[1] for fn in REGISTRY}


def ground_truth_ids(directory: Path = GROUND_TRUTH) -> set[str]:
    ids: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        if path.name.startswith("priority_"):
            continue
        doc = yaml.safe_load(path.read_text()) or {}
        for entry in (doc.get("known_issues") or []) + (doc.get("must_not_fire") or []):
            ids.add(entry["check_id"])
    return ids


def latest_findings(raw: Path = RAW) -> dict[str, list[dict[str, Any]]]:
    """target -> findings of its latest CAWASMA run (empty if none was kept)."""
    out: dict[str, list[dict[str, Any]]] = {}
    for target_dir in sorted(p for p in raw.glob("*") if p.is_dir()):
        runs = sorted(target_dir.glob("*/results.json"))
        if runs:
            out[target_dir.name] = json.loads(runs[-1].read_text()).get("findings", [])
    return out


def git_revision(root: Path = ROOT) -> dict[str, str]:
    """Branch and short commit of the checkout ("unknown" outside a git clone)."""

    exe = shutil.which("git")

    def git(*args: str) -> str:
        if exe is None:
            return "unknown"
        try:
            done = subprocess.run(  # noqa: S603 - fixed git arguments
                [exe, "-C", str(root), *args], capture_output=True, text=True, check=True
            )
        except (OSError, subprocess.CalledProcessError):
            return "unknown"
        return done.stdout.strip() or "unknown"

    dirty = git("status", "--porcelain", "--untracked-files=no") not in ("", "unknown")
    return {
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "commit": git("rev-parse", "--short", "HEAD") + (" (uncommitted changes)" if dirty else ""),
    }


def stats(raw: Path = RAW, ground_truth: Path = GROUND_TRUTH) -> dict[str, Any]:
    spec_registry.load_implementations()
    loaded = spec_registry.load_specs()
    specs = set(loaded)
    proposed = {cid for cid, spec in loaded.items() if spec.status == "proposed"}
    environmental = set(spec_registry.CHECKS)
    legacy = legacy_ids()
    all_ids = set(CATALOG) | specs
    truth = ground_truth_ids(ground_truth) & all_ids
    runs = latest_findings(raw)
    findings = [f for fs in runs.values() for f in fs]
    env_findings = sum(1 for f in findings if f.get("final_vector"))
    return {
        **git_revision(),
        "check_ids": len(all_ids),
        "with_spec": len(specs & all_ids),
        # The report counts approved specs only; proposed ones await Asim's review.
        "with_approved_spec": len((specs - proposed) & all_ids),
        "with_proposed_spec": len(proposed & all_ids),
        "proposed_ids": sorted(proposed),
        "with_ground_truth": len(truth),
        "scored_environmental": len(environmental & all_ids),
        "scored_environmental_approved": len((environmental - proposed) & all_ids),
        "scored_legacy": len(legacy & all_ids),
        "not_implemented": len(all_ids - environmental - legacy),
        "eval_targets": sorted(runs),
        "findings": len(findings),
        "findings_environmental": env_findings,
        "findings_legacy": len(findings) - env_findings,
    }


def report(s: dict[str, Any]) -> str:
    n = s["check_ids"]
    lines = [
        f"on {s['branch']} @ {s['commit']}",
        f"{n} check ids",
        f"  with an approved spec          {s['with_approved_spec']:>3} of {n}",
        f"  with a proposed spec           {s['with_proposed_spec']:>3} of {n}"
        + (f"  ({', '.join(s['proposed_ids'])})" if s["proposed_ids"] else ""),
        f"  with a ground-truth entry      {s['with_ground_truth']:>3} of {n}",
        f"  scored environmental (CVSS)    {s['scored_environmental']:>3} of {n}"
        f"  ({s['scored_environmental_approved']} with an approved spec)",
        f"  scored legacy (interim)        {s['scored_legacy']:>3} of {n}",
    ]
    if s["not_implemented"]:
        lines.append(f"  not implemented                {s['not_implemented']:>3} of {n}")
    if s["findings"]:
        share = 100 * s["findings_environmental"] / s["findings"]
        lines += [
            f"latest eval run ({', '.join(s['eval_targets'])}): {s['findings']} findings",
            f"  environmental {s['findings_environmental']} ({share:.0f} %), "
            f"legacy {s['findings_legacy']} ({100 - share:.0f} %)",
        ]
    lines.append(
        f"for the report (approved specs only): {s['with_approved_spec']} of {n} checks "
        f"specified, {s['scored_environmental_approved']} of {n} scored with CVSS "
        "environmental metrics"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    s = stats()
    print(json.dumps(s, indent=2) if args.json else report(s))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
