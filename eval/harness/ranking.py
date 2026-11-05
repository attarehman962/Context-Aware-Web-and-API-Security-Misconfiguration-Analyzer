"""Before/after ranking experiment (Asim Prompt 10).

    python eval/harness/ranking.py [--init] [--seed 13] [--out eval/results/final]
    python eval/harness/ranking.py --scoring environmental --run 20261104T152231Z \
        --out eval/results/final     # the reported experiment

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

``--scoring environmental`` runs the experiment on environmental-scored findings
only (``final_vector`` set), against the priority items whose check is scored
that way. Legacy findings' ``final_score`` comes from the interim formula, a
different scale, so mixing them in would not test the CVSS environmental method.
It writes ``ranking_environmental.json`` and ``.md`` instead of ``ranking.json``.
``--run`` picks a raw run by its stamp (default: each target's latest).

**Graded pools.** When ``eval/ground_truth/priority_pool_<target>.csv`` exists
and every row has a grade (``pool.py``, ``GRADING.md``), NDCG@10 is also computed
against it: a finding's relevance is the grade of its (check_id, endpoint) pair,
the first finding of a pair gets it and repeats get 0, and pairs outside the
pool count 0 (unjudged = not relevant, as in TREC pooling). Both versions are
reported (``ndcg10_*`` from the priority list, ``ndcg10_pool_*`` from the pool)
until every pool is graded; ``pool`` says which state each target is in.

**Secondary, diagnostic view** (``--group-by-check``, added after the first
results, not the headline): many findings are copies of one issue across
endpoints. Findings are grouped by check_id per target, each group keeps its
highest-``final_score`` finding, and the groups are ranked by base and by final
score. A group's relevance is the highest grade of the priority items with its
check_id (issue level: the endpoint is ignored). Writes
``ranking_grouped_environmental.{json,md}`` with the duplication counts.
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
from pool import load_pool  # noqa: E402 - sibling script

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


def _pool_relevances(ranked: list[ev.Finding], grades: dict[tuple[str, str], int]) -> list[int]:
    taken: set[tuple[str, str]] = set()
    out = []
    for f in ranked:
        key = (str(f.check_id), f.endpoint)
        out.append(grades.get(key, 0) if key not in taken else 0)
        taken.add(key)
    return out


def _load_run(target: str, run_stamp: str | None) -> list[dict[str, Any]] | None:
    run = (ev.RESULTS / "raw" / "cawasma" / target / run_stamp if run_stamp
           else ev.latest("cawasma", target))
    if run is None or not (run / "results.json").exists():
        return None
    return json.loads((run / "results.json").read_text())["findings"]


def duplication(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """How many findings are copies of the same check across endpoints."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["check_id"]] = counts.get(f["check_id"], 0) + 1
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
    return {"findings": len(findings), "distinct_checks": len(counts),
            "top5": [f"{cid} ({n})" for cid, n in top]}


def grouped_experiment(target: str, seed: int, *, run_stamp: str | None = None,
                       environmental_only: set[str] | None = None) -> dict[str, Any] | None:
    """Secondary view: one finding per check_id (its highest final_score)."""
    raw = _load_run(target, run_stamp)
    if raw is None:
        return None
    kept = [f for f in raw if environmental_only is None or f.get("final_vector")]
    best: dict[str, dict[str, Any]] = {}
    for f in kept:
        if f["check_id"] not in best or f["final_score"] > best[f["check_id"]]["final_score"]:
            best[f["check_id"]] = f
    items = load_priority(target)
    if environmental_only is not None:
        items = [i for i in items if i["check_id"] in environmental_only]
    grade_of: dict[str, int] = {}
    for i in items:
        grade_of[i["check_id"]] = max(grade_of.get(i["check_id"], 0), int(i["grade"]))
    ideal = sorted(grade_of.values(), reverse=True)
    out: dict[str, Any] = {"target": target, **duplication(kept), "groups": len(best),
                           "graded_checks": len(grade_of)}
    for name, key in (("before", "base_score"), ("after", "final_score")):
        rng = random.Random(seed)
        scores = []
        for _ in range(TIE_SAMPLES):
            order = sorted(best.values(), key=lambda f: (-f[key], rng.random()))
            scores.append(ndcg_at_k([grade_of.get(f["check_id"], 0) for f in order], ideal))
        out[f"ndcg10_{name}"] = round(sum(scores) / len(scores), 3)
    return out


def _grouped_table(rows: list[dict[str, Any]], mean: dict[str, Any], seed: int) -> str:
    cols = ["target", "findings", "distinct_checks", "top5", "graded_checks",
            "ndcg10_before", "ndcg10_after"]
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in [*rows, mean]:
        lines.append("| " + " | ".join(
            ", ".join(r[c]) if isinstance(r.get(c), list)
            else ("–" if r.get(c) is None else str(r.get(c, "–"))) for c in cols) + " |")
    return "\n".join([
        "SECONDARY, DIAGNOSTIC VIEW (added after the first results; not the headline). "
        "Environmental-scored findings grouped by check_id per target, each group keeping "
        "its highest-final_score finding; relevance = the highest priority grade of that "
        "check (endpoint ignored).", "", *lines, "",
        f"before = base_score, after = final_score. Mean over {TIE_SAMPLES} random "
        f"tie-breaks (seed {seed}); descriptive only.", ""])


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


def environmental_check_ids() -> set[str]:
    """Checks the scanner scores with CVSS environmental metrics (spec registry)."""
    sys.path.insert(0, str(ev.ROOT / "backend"))
    from app.core.checks import registry

    registry.load_implementations()
    return set(registry.CHECKS)


def experiment(target: str, seed: int, *, run_stamp: str | None = None,
               environmental_only: set[str] | None = None) -> dict[str, Any] | None:
    """``environmental_only``: keep only findings with a final_vector, and only the
    priority items whose check is in this set."""
    run = (ev.RESULTS / "raw" / "cawasma" / target / run_stamp if run_stamp
           else ev.latest("cawasma", target))
    if run is None or not (run / "results.json").exists():
        return None
    raw = json.loads((run / "results.json").read_text())
    kept = [f for f in raw["findings"]
            if environmental_only is None or f.get("final_vector")]
    findings = [(ev.Finding("cawasma", target, f["check_id"],
                            ev.normalise_endpoint(f.get("endpoint_url")), f["check_id"]), f)
                for f in kept]
    items = load_priority(target)
    if environmental_only is not None:
        items = [i for i in items if i["check_id"] in environmental_only]
    ideal = [int(i["grade"]) for i in items]
    out: dict[str, Any] = {"target": target, "run": run.name, "findings": len(findings),
                           "priority_items": len(items),
                           "critical_items": sum(1 for g in ideal if g == 3),
                           "items_matched": sum(
                               1 for i in items
                               if any(ev._hits(f, i["check_id"], i["endpoint"])
                                      for f, _ in findings))}
    pool = load_pool(target)
    graded = pool is not None and all(g is not None for g in pool.values())
    out["pool"] = ("none" if pool is None else "graded" if graded
                   else f"ungraded ({sum(g is not None for g in pool.values())}/{len(pool)})")
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
        out[f"ndcg10_pool_{name}"] = None
        if graded and pool is not None:
            grades = {k: int(v) for k, v in pool.items() if v is not None}
            pool_ideal = sorted(grades.values(), reverse=True)
            rng = random.Random(seed)
            scores = [ndcg_at_k(_pool_relevances(
                          rank([(f, raw_f[key]) for f, raw_f in findings], rng), grades),
                          pool_ideal) for _ in range(TIE_SAMPLES)]
            out[f"ndcg10_pool_{name}"] = round(sum(scores) / len(scores), 3)
    return out


def _table(result: dict[str, Any]) -> str:
    cols = ["target", "findings", "priority_items", "items_matched", "critical_items",
            "ndcg10_before", "ndcg10_after", "first_critical_before", "first_critical_after",
            "pool", "ndcg10_pool_before", "ndcg10_pool_after"]
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in [*result["targets"], result["mean"]]:
        lines.append("| " + " | ".join("–" if r.get(c) is None else str(r.get(c, "–"))
                                       for c in cols) + " |")
    return "\n".join([
        "Ranking experiment on environmental-scored findings only (final_vector set), "
        "against the priority items whose check is scored that way.", "",
        *lines, "",
        f"before = base_score, after = final_score (CVSS v3.1 environmental). Mean over "
        f"{result['tie_samples']} random tie-breaks (seed {result['seed']}); "
        "descriptive only, no significance claimed. ndcg10_* uses priority_<target>.yaml; "
        "ndcg10_pool_* the graded pool (priority_pool_<target>.csv), empty until graded.",
        ""])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--init", action="store_true", help="write missing priority templates")
    p.add_argument("--seed", type=int, default=13)
    p.add_argument("--out", type=Path, help="write ranking.json here")
    p.add_argument("--scoring", choices=["all", "environmental"], default="all")
    p.add_argument("--run", help="raw run stamp to use for every target (default: latest)")
    p.add_argument("--group-by-check", action="store_true",
                   help="secondary diagnostic view: one finding per check_id")
    args = p.parse_args(argv)
    env_ids = environmental_check_ids() if args.scoring == "environmental" else None
    if args.group_by_check:
        grows = [r for t in ev.TARGETS
                 if (r := grouped_experiment(t, args.seed, run_stamp=args.run,
                                             environmental_only=env_ids)) is not None]
        gmean: dict[str, Any] = {"target": "mean"}
        for key in ("ndcg10_before", "ndcg10_after"):
            gmean[key] = round(sum(r[key] for r in grows) / len(grows), 3) if grows else None
        gresult = {"view": "secondary: grouped by check_id", "scoring": args.scoring,
                   "seed": args.seed, "targets": grows, "mean": gmean}
        if args.out:
            args.out.mkdir(parents=True, exist_ok=True)
            name = f"ranking_grouped_{args.scoring}"
            (args.out / f"{name}.json").write_text(json.dumps(gresult, indent=2) + "\n")
            (args.out / f"{name}.md").write_text(_grouped_table(grows, gmean, args.seed))
        print(json.dumps(gresult, indent=2))
        return 0
    if args.init:
        for t in ev.TARGETS:
            if (made := init_priority(t)) is not None:
                print(f"wrote {made.relative_to(ev.ROOT)}")
    rows = [r for t in ev.TARGETS
            if (r := experiment(t, args.seed, run_stamp=args.run,
                                environmental_only=env_ids)) is not None]
    mean = {"target": "mean"}
    for key in ("ndcg10_before", "ndcg10_after", "first_critical_before",
                "first_critical_after", "ndcg10_pool_before", "ndcg10_pool_after"):
        vals = [r[key] for r in rows if r[key] is not None]
        mean[key] = round(sum(vals) / len(vals), 3) if vals else None
    result = {"k": K, "tie_samples": TIE_SAMPLES, "seed": args.seed, "scoring": args.scoring,
              "targets": rows, "mean": mean}
    text = json.dumps(result, indent=2)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        name = "ranking" if args.scoring == "all" else "ranking_environmental"
        (args.out / f"{name}.json").write_text(text + "\n")
        if args.scoring == "environmental":
            (args.out / f"{name}.md").write_text(_table(result))
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
