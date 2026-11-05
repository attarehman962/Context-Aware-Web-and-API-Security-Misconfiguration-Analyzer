"""Build the blind grading pools for the ranking experiment (Asim grades them).

    python eval/harness/pool.py --run 20261104T152231Z [--k 20] [--seed 13]
    python eval/harness/pool.py --run <new stamp> --refresh   # after a new evaluation

For each target, the environmental-scored CAWASMA findings (``final_vector`` set)
are reduced to (check_id, endpoint) pairs and ranked twice, by base score and by
the environmental final score (ties broken at random, fixed seed). The union of
both top-k lists is de-duplicated, shuffled and written to
``eval/ground_truth/priority_pool_<target>.csv`` with an empty ``grade`` column.

The file carries no score, rank or source ranking, so the grader can't tell which
ranking put a pair in the pool (pooling, as in TREC). Without ``--refresh`` an
existing pool is never overwritten. ``--refresh`` rebuilds it from a new run and
keeps every grade already entered, matched by (target, check_id, endpoint):
graded pairs stay even if the new rankings no longer pool them (a judged pair is
still judged), ungraded pairs that dropped out are removed, new pairs are added
ungraded, and the rows are shuffled again. Grading rules: ``GRADING.md``.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evaluate as ev  # noqa: E402 - sibling script

POOL = ev.GROUND_TRUTH / "priority_pool_{target}.csv"
COLUMNS = ["target", "check_id", "endpoint", "evidence_summary", "grade"]
SUMMARY_CHARS = 140


def pool_path(target: str) -> Path:
    return Path(str(POOL).format(target=target))


def _pairs(findings: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """(check_id, endpoint) -> the pair's scores (max over its findings) and the
    evidence of its highest-scoring finding."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for f in findings:
        key = (f["check_id"], ev.normalise_endpoint(f.get("endpoint_url")))
        cur = out.get(key)
        if cur is None or f["final_score"] > cur["final_score"]:
            text = str((f.get("evidence") or {}).get("text") or f.get("title") or "")
            out[key] = {
                "base_score": max(f["base_score"], cur["base_score"] if cur else 0.0),
                "final_score": f["final_score"],
                "summary": " ".join(text.split())[:SUMMARY_CHARS],
            }
    return out


def _top(pairs: dict[tuple[str, str], dict[str, Any]], key: str, k: int,
         rng: random.Random) -> list[tuple[str, str]]:
    keyed = sorted(pairs, key=lambda p: (-pairs[p][key], rng.random()))
    return keyed[:k]


def build_pool(target: str, run_stamp: str, k: int = 20, seed: int = 13) -> list[dict[str, str]]:
    run = ev.RESULTS / "raw" / "cawasma" / target / run_stamp / "results.json"
    findings = [f for f in json.loads(run.read_text())["findings"] if f.get("final_vector")]
    pairs = _pairs(findings)
    rng = random.Random(seed)
    chosen = dict.fromkeys(_top(pairs, "base_score", k, rng) + _top(pairs, "final_score", k, rng))
    rows = [
        {"target": target, "check_id": cid, "endpoint": endpoint,
         "evidence_summary": pairs[(cid, endpoint)]["summary"], "grade": ""}
        for cid, endpoint in chosen
    ]
    rng.shuffle(rows)
    return rows


def load_pool(target: str) -> dict[tuple[str, str], int | None] | None:
    """(check_id, endpoint) -> grade (None while ungraded); None if no pool file."""
    path = pool_path(target)
    if not path.exists():
        return None
    out: dict[tuple[str, str], int | None] = {}
    with path.open(newline="") as fh:
        for row in csv.DictReader(fh):
            g = (row.get("grade") or "").strip()
            if g and g not in {"0", "1", "2", "3"}:
                raise ValueError(f"{path}: grade must be 0-3, got {g!r}")
            out[(row["check_id"], row["endpoint"])] = int(g) if g else None
    return out


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def _write_rows(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def refresh_pool(target: str, run_stamp: str, k: int = 20, seed: int = 13
                 ) -> tuple[list[dict[str, str]], dict[str, int]]:
    """The rebuilt pool rows and what changed against the existing file."""
    new = build_pool(target, run_stamp, k, seed)
    path = pool_path(target)
    old = {(r["target"], r["check_id"], r["endpoint"]): r
           for r in (_read_rows(path) if path.exists() else [])}
    new_keys = {(r["target"], r["check_id"], r["endpoint"]) for r in new}
    rows, kept, added = [], 0, 0
    for r in new:
        prev = old.get((r["target"], r["check_id"], r["endpoint"]))
        if prev is not None:
            r = {**r, "grade": prev.get("grade", "")}
            kept += 1
        else:
            added += 1
        rows.append(r)
    graded_out = [r for key, r in old.items() if key not in new_keys and r["grade"].strip()]
    rows += graded_out
    removed = sum(1 for key, r in old.items() if key not in new_keys and not r["grade"].strip())
    random.Random(seed).shuffle(rows)
    stats = {"before": len(old), "after": len(rows), "kept": kept, "added": added,
             "removed": removed, "kept_graded_outside_pool": len(graded_out),
             "grades_kept": sum(1 for r in rows if r["grade"].strip())}
    return rows, stats


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--run", required=True, help="raw run stamp, e.g. 20261104T152231Z")
    p.add_argument("--k", type=int, default=20)
    p.add_argument("--seed", type=int, default=13)
    p.add_argument("--refresh", action="store_true",
                   help="rebuild existing pools from --run, keeping entered grades")
    args = p.parse_args(argv)
    for target in ev.TARGETS:
        path = pool_path(target)
        if args.refresh:
            rows, st = refresh_pool(target, args.run, args.k, args.seed)
            _write_rows(path, rows)
            print(f"{target}: {st['before']} -> {st['after']} rows; kept {st['kept']}, "
                  f"added {st['added']}, removed {st['removed']} (ungraded), "
                  f"grades kept {st['grades_kept']}")
            continue
        if path.exists():
            print(f"kept {path.relative_to(ev.ROOT)} (exists; may hold grades)")
            continue
        rows = build_pool(target, args.run, args.k, args.seed)
        _write_rows(path, rows)
        print(f"wrote {path.relative_to(ev.ROOT)}: {len(rows)} pairs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
