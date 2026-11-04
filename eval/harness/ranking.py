"""Before/after ranking experiment (Asim Prompt 10).

    python eval/harness/ranking.py [--init] [--seed 13] [--out eval/results/final]

For each target, CAWASMA's findings from the latest raw run are ranked two ways:

- **before**: by the official CVSS v3.1 base score (``base_score``);
- **after**: by the context-aware score (``final_score``).

Both rankings are compared with the ground-truth priority order in
``eval/ground_truth/priority_<target>.yaml`` using NDCG@10 and the rank of the
first critical (grade 3) finding. Base scores tie a lot, and any fixed
tie-break would decide the result, so every metric is the mean over
``TIE_SAMPLES`` random tie-breaks (fixed seed), the same for both rankings.

``--init`` writes a priority template for each target that has none, from the
target's ``expected: present`` ground-truth entries. Each item's grade comes from
two human judgements, never from CAWASMA's output: the issue type's impact tier
(``IMPACT``) and the endpoint's hand label (``eval/labels/endpoints_labelled.csv``).
Edit the grades and order by hand afterwards: the file is the ground truth, not
this rule.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evaluate as ev  # noqa: E402 - sibling script

PRIORITY = ev.GROUND_TRUTH / "priority_{target}.yaml"
LABELS = ev.ROOT / "eval" / "labels" / "endpoints_labelled.csv"
K = 10
TIE_SAMPLES = 1000

# Impact tier of each issue type (what an attacker gains), 1-3.
IMPACT = {
    3: ["INF-002", "INF-003", "INF-004", "INF-005", "INF-006", "API-003", "API-013",
        "AUT-006"],                                      # direct exposure of data/secrets
    2: ["CKI-001", "CKI-002", "CKI-003", "API-001", "API-004", "TLS-001", "TLS-002",
        "TLS-005", "TLS-009", "COR-002", "COR-003"],     # weakens auth/session/transport
    1: ["HDR-001", "HDR-002", "HDR-003", "HDR-004", "HDR-005", "HDR-006", "HDR-007",
        "HDR-008", "HDR-014"],                           # missing hardening
}
TIER = {cid: tier for tier, ids in IMPACT.items() for cid in ids}


def sensitivity_labels() -> dict[tuple[str, str], str]:
    rows = csv.DictReader(LABELS.open())
    return {(r["target"], ev.normalise_endpoint(r["path"])): r["sensitivity_class"]
            for r in rows if r["sensitivity_class"]}


def grade(target: str, check_id: str, endpoint: str, labels) -> int:
    tier = TIER.get(check_id, 1)
    sens = labels.get((target, ev.normalise_endpoint(endpoint) if endpoint != "*" else "/"),
                      "LOW")
    return min(3, tier + (1 if sens in ("HIGH", "CRITICAL") else 0))


def init_priority(target: str) -> Path | None:
    path = Path(str(PRIORITY).format(target=target))
    if path.exists():
        return None
    labels = sensitivity_labels()
    gt = ev.load_ground_truth(target)
    items = []
    for e in gt["known_issues"]:
        if e["expected"] != "present":
            continue
        items.append({"check_id": e["check_id"], "endpoint": e["endpoint"],
                      "grade": grade(target, e["check_id"], e["endpoint"], labels)})
    items.sort(key=lambda i: (-i["grade"], i["check_id"], i["endpoint"]))
    header = (f"# Ground-truth priority order for {target}: what a defender should fix first.\n"
              "# grade 3 = critical (fix first), 2 = high, 1 = medium, 0 = not a priority.\n"
              "# Drafted by eval/harness/ranking.py --init from the issue type's impact tier\n"
              "# and the endpoint's hand-labelled sensitivity; never from CAWASMA's scores.\n"
              "# Review the grades by hand, then set status: reviewed.\n")
    doc = {"target": target, "status": "draft", "items": items}
    path.write_text(header + yaml.safe_dump(doc, sort_keys=False, width=100))
    return path


def load_priority(target: str) -> list[dict[str, Any]]:
    return yaml.safe_load(Path(str(PRIORITY).format(target=target)).read_text())["items"]


def _relevances(ranked: list[ev.Finding], items: list[dict[str, Any]]) -> list[int]:
    """Relevance of each ranked finding: the grade of the priority item it is the
    first finding to match; 0 for duplicates and unmatched findings."""
    taken: set[int] = set()
    out = []
    for f in ranked:
        rel = 0
        for i, item in enumerate(items):
            if i not in taken and ev._hits(f, item["check_id"], item["endpoint"]):
                taken.add(i)
                rel = int(item["grade"])
                break
        out.append(rel)
    return out


def ndcg_at_k(rels: list[int], ideal: list[int], k: int = K) -> float:
    def dcg(xs: list[int]) -> float:
        return sum((2 ** r - 1) / math.log2(i + 2) for i, r in enumerate(xs[:k]))
    best = dcg(sorted(ideal, reverse=True))
    return dcg(rels) / best if best else 0.0


def first_critical(rels: list[int]) -> int | None:
    return next((i + 1 for i, r in enumerate(rels) if r == 3), None)


def rank(findings: list[tuple[ev.Finding, float]], rng: random.Random) -> list[ev.Finding]:
    keyed = [(-score, rng.random(), f) for f, score in findings]
    return [f for _, _, f in sorted(keyed, key=lambda x: (x[0], x[1]))]


def experiment(target: str, seed: int) -> dict[str, Any] | None:
    run = ev.latest("cawasma", target)
    if run is None:
        return None
    raw = json.loads((run / "results.json").read_text())
    findings = [(ev.Finding("cawasma", target, f["check_id"],
                            ev.normalise_endpoint(f.get("endpoint_url")), f["check_id"]), f)
                for f in raw["findings"]]
    items = load_priority(target)
    ideal = [int(i["grade"]) for i in items]
    out: dict[str, Any] = {"target": target, "run": run.name, "findings": len(findings),
                           "priority_items": len(items),
                           "critical_items": sum(1 for g in ideal if g == 3)}
    for name, key in (("before", "base_score"), ("after", "final_score")):
        rng = random.Random(seed)
        ndcgs, firsts = [], []
        for _ in range(TIE_SAMPLES):
            rels = _relevances(rank([(f, raw_f[key]) for f, raw_f in findings], rng), items)
            ndcgs.append(ndcg_at_k(rels, ideal))
            firsts.append(first_critical(rels))
        found = [x for x in firsts if x is not None]
        out[f"ndcg10_{name}"] = round(sum(ndcgs) / len(ndcgs), 3)
        out[f"first_critical_{name}"] = (round(sum(found) / len(found), 1)
                                         if len(found) == len(firsts) else None)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--init", action="store_true", help="write missing priority templates")
    p.add_argument("--seed", type=int, default=13)
    p.add_argument("--out", type=Path, help="write ranking.json here")
    args = p.parse_args(argv)
    if args.init:
        for t in ev.TARGETS:
            if (made := init_priority(t)) is not None:
                print(f"wrote {made.relative_to(ev.ROOT)}")
    rows = [r for t in ev.TARGETS if (r := experiment(t, args.seed)) is not None]
    mean = {"target": "mean"}
    for key in ("ndcg10_before", "ndcg10_after", "first_critical_before",
                "first_critical_after"):
        vals = [r[key] for r in rows if r[key] is not None]
        mean[key] = round(sum(vals) / len(vals), 3) if vals else None
    result = {"k": K, "tie_samples": TIE_SAMPLES, "seed": args.seed, "targets": rows,
              "mean": mean}
    text = json.dumps(result, indent=2)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "ranking.json").write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
