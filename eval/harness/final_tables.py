"""Final evaluation tables for the report (Asim Prompt 10).

    python eval/harness/final_tables.py --before-run 20261104T151453Z

Writes eval/results/final/<table>.{csv,md,png} for:

- ``tools``: CAWASMA vs ZAP vs Nuclei per target and in total (precision,
  recall, FPR, scan time), from the latest raw run of each tool;
- ``tuning``: CAWASMA before/after the tuning pass (``--before-run`` is the
  pre-tuning raw run stamp), both scored against the same ground truth, split
  into dev and test targets;
- ``classifier``: sensitivity-classifier accuracy and macro-F1 (shipped vs
  proposed keyword families, dev and test) and ``confusion`` (shipped, test);
  reads the ``classifier_*.json`` files written by classifier_eval.py;
- ``ranking``: NDCG@10 and rank of the first critical finding, base vs
  context-aware score (reads ``ranking.json`` from ranking.py);
- ``mapping``: the CVSS v3.1 environmental mapping examples (mapping_demo.py)
  for every sensitivity class.

Needs matplotlib and cvss (the backend's ``ml`` extra).
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evaluate as ev  # noqa: E402 - sibling script
import mapping_demo  # noqa: E402

FINAL = ev.RESULTS / "final"
DEV, TEST = ["dvwa", "vampi"], ["juice-shop", "crapi"]
CLASSES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
TOOL_COLOURS = {"cawasma": "#2f6db5", "zap": "#e08a2b", "nuclei": "#5a9e5a"}


# ------------------------------------------------------------------ output

def write(name: str, rows: list[dict[str, Any]], note: str = "") -> None:
    FINAL.mkdir(parents=True, exist_ok=True)
    cols = list(rows[0])
    with (FINAL / f"{name}.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    lines += ["| " + " | ".join(_fmt(r[c]) for c in cols) + " |" for r in rows]
    (FINAL / f"{name}.md").write_text("\n".join(lines) + ("\n\n" + note if note else "") + "\n")


def _fmt(v: Any) -> str:
    if v is None:
        return "–"
    if isinstance(v, float):
        return f"{v:.3f}".rstrip("0").rstrip(".") if v != int(v) else f"{v:.1f}"
    return str(v)


def _plt():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.size": 10, "axes.spines.top": False,
                         "axes.spines.right": False, "figure.dpi": 150})
    return plt


def _bars(ax, groups: list[str], series: dict[str, list[float | None]],
          colours: dict[str, str] | None = None, fmt: str = "{:.2f}") -> None:
    width = 0.8 / max(len(series), 1)
    for i, (name, vals) in enumerate(series.items()):
        xs = [g + (i - (len(series) - 1) / 2) * width for g in range(len(groups))]
        heights = [v if v is not None else 0 for v in vals]
        bars = ax.bar(xs, heights, width * 0.92, label=name,
                      color=(colours or {}).get(name))
        for b, v in zip(bars, vals, strict=True):
            ax.annotate("n/a" if v is None else fmt.format(v), (b.get_x() + b.get_width() / 2,
                        b.get_height()), ha="center", va="bottom", fontsize=7,
                        xytext=(0, 2), textcoords="offset points")
    ax.set_xticks(range(len(groups)), groups)


# ------------------------------------------------------------------ tables

def _results(tool: str, target: str, run: Path | None, mapping) -> ev.Result | None:
    if run is None:
        return None
    findings, seconds = ev.load_run(tool, target, run, mapping)
    covered = ev.coverage(tool, mapping)
    result = ev.score(tool, target, findings, ev.load_ground_truth(target), covered)
    result.scan_seconds = seconds
    return result


def _total(results: list[ev.Result], tool: str, label: str) -> dict[str, Any]:
    tp, fp, fn, tn = (sum(len(getattr(r, k)) for r in results) for k in ("tp", "fp", "fn", "tn"))
    secs = [r.scan_seconds for r in results if r.scan_seconds is not None]
    return {"tool": tool, "target": label, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": ev._ratio(tp, tp + fp), "recall": ev._ratio(tp, tp + fn),
            "fpr": ev._ratio(fp, fp + tn),
            "scan_seconds": round(sum(secs) / len(secs), 1) if secs else None}


def tools_table() -> None:
    mapping = ev.load_mapping()
    rows, by_tool = [], {}
    for tool in ev.TOOLS:
        results = [r for t in ev.TARGETS
                   if (r := _results(tool, t, ev.latest(tool, t), mapping)) is not None]
        by_tool[tool] = results
        for r in results:
            m = r.metrics()
            rows.append({k: m[k] for k in ("tool", "target", "tp", "fp", "fn", "tn",
                                            "precision", "recall", "fpr", "scan_seconds")})
        rows.append(_total(results, tool, "all (micro)"))
    write("tools", rows, "Each tool is scored only on the checks it can detect (tool_mapping.yaml);"
          " scan_seconds for 'all' is the mean per target. FPs count only findings that"
          " contradict a ground-truth `absent` entry or a `must_not_fire` check.")
    plt = _plt()
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.4))
    totals = {r["tool"]: r for r in rows if r["target"] == "all (micro)"}
    for ax, key, title in zip(axes, ("precision", "recall", "fpr", "scan_seconds"),
                              ("Precision", "Recall", "False-positive rate",
                               "Scan time per target (s)"), strict=True):
        vals = [totals[t][key] for t in ev.TOOLS]
        bars = ax.bar(ev.TOOLS, [v or 0 for v in vals],
                      color=[TOOL_COLOURS[t] for t in ev.TOOLS])
        for b, v in zip(bars, vals, strict=True):
            ax.annotate("n/a" if v is None else (f"{v:.0f}" if key == "scan_seconds"
                                                 else f"{v:.2f}"),
                        (b.get_x() + b.get_width() / 2, b.get_height()), ha="center",
                        va="bottom", fontsize=8, xytext=(0, 2), textcoords="offset points")
        ax.set_title(title)
        if key != "scan_seconds":
            ax.set_ylim(0, 1.1)
    fig.suptitle("CAWASMA vs ZAP vs Nuclei, all four targets (micro-averaged)")
    fig.tight_layout()
    fig.savefig(FINAL / "tools.png")
    plt.close(fig)


def tuning_table(before_stamp: str) -> None:
    mapping = ev.load_mapping()
    rows = []
    for label, stamp in (("before tuning", before_stamp), ("after tuning", None)):
        for split, targets in (("dev", DEV), ("test", TEST)):
            results = []
            for t in targets:
                run = (ev.RESULTS / "raw" / "cawasma" / t / stamp) if stamp else ev.latest(
                    "cawasma", t)
                if run is not None and run.exists():
                    results.append(_results("cawasma", t, run, mapping))
            total = _total([r for r in results if r], "cawasma", split)
            unlabelled = sum(len(r.unlabelled) for r in results if r)
            rows.append({"run": label, "split": split, "tp": total["tp"], "fp": total["fp"],
                         "fn": total["fn"], "tn": total["tn"],
                         "precision": total["precision"], "recall": total["recall"],
                         "fpr": total["fpr"], "unlabelled_findings": unlabelled})
    write("tuning", rows, "Both runs scored against the same ground truth (incl. the dev-split"
          " entries added from hand-checking the pre-tuning run). Tuning used the dev split"
          " only. The pass removed the two hand-checked dev false positives it targeted,"
          " HDR-011 on /dvwa/css/login.css (static asset classed sensitive) and API-013 on"
          " VAmPI's /openapi.json (example values read as leaked secrets). Both are legacy"
          " checks with no checks.yaml id, which ground truth cannot label, so they show as"
          " unlabelled_findings 149 -> 147 rather than in fp. The 4 labelled dev FPs"
          " (API-001 x3, API-003 x1 on VAmPI) need the spec scoping in core/specs.py"
          " (Atta) and are unchanged. Test findings are identical before and after.")
    plt = _plt()
    fig, axes = plt.subplots(1, 3, figsize=(10, 3.2))
    for ax, key in zip(axes, ("precision", "recall", "fpr"), strict=True):
        series = {label: [next(r[key] for r in rows if r["run"] == label and r["split"] == s)
                          for s in ("dev", "test")]
                  for label in ("before tuning", "after tuning")}
        _bars(ax, ["dev", "test"], series, {"before tuning": "#9aa5b1",
                                            "after tuning": "#2f6db5"})
        ax.set_title(key.upper() if key == "fpr" else key.capitalize())
        ax.set_ylim(0, 1.15)
    axes[0].legend(frameon=False, fontsize=8)
    fig.suptitle("CAWASMA before/after the tuning pass")
    fig.tight_layout()
    fig.savefig(FINAL / "tuning.png")
    plt.close(fig)


def classifier_tables() -> None:
    rows = []
    for variant in ("shipped", "proposed"):
        for split in ("dev", "test"):
            path = FINAL / f"classifier_{variant}_{split}.json"
            if not path.exists():
                continue
            d = json.loads(path.read_text())
            rows.append({"families": variant, "split": split, "n": d["n"],
                         "accuracy": d["accuracy"], "macro_f1": d["macro_f1"],
                         "off_by_two_or_more": d["off_by_two_or_more"],
                         **{f"recall_{c.lower()}": d["per_class"][c]["recall"]
                            for c in CLASSES}})
    write("classifier", rows, "shipped = keyword families in app/core/sensitivity.py (Atta);"
          " proposed = eval/harness/proposed_families.json, chosen on dev only and reported"
          " once on test. Embeddings on (all-MiniLM-L6-v2): they set the confidence, not the"
          " class.")
    shipped = json.loads((FINAL / "classifier_shipped_test.json").read_text())
    matrix = shipped["confusion"]
    write("confusion", [{"true \\ predicted": t, **{p: matrix[t][p] for p in CLASSES}}
                        for t in CLASSES],
          "Shipped classifier on the test split (Juice Shop + crAPI, n="
          f"{shipped['n']}). Rows: hand label; columns: classifier.")
    plt = _plt()
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.5, 3.8),
                                   gridspec_kw={"width_ratios": [1.1, 1]})
    series = {f"{r['families']} ({r['split']})": [r["accuracy"], r["macro_f1"]] for r in rows}
    colours = {"shipped (dev)": "#c3cad3", "shipped (test)": "#7d8a99",
               "proposed (dev)": "#9cc0e8", "proposed (test)": "#2f6db5"}
    _bars(ax1, ["accuracy", "macro-F1"], series, colours)
    ax1.set_ylim(0, 1)
    ax1.legend(frameon=False, fontsize=7, loc="upper right")
    ax1.set_title("Sensitivity classifier")
    data = [[matrix[t][p] for p in CLASSES] for t in CLASSES]
    im = ax2.imshow(data, cmap="Blues")
    for i in range(4):
        for j in range(4):
            ax2.text(j, i, data[i][j], ha="center", va="center",
                     color="white" if data[i][j] > max(map(max, data)) / 2 else "black")
    ax2.set_xticks(range(4), CLASSES, fontsize=8)
    ax2.set_yticks(range(4), CLASSES, fontsize=8)
    ax2.set_xlabel("predicted")
    ax2.set_ylabel("hand label")
    ax2.set_title("Confusion matrix (shipped, test)")
    fig.colorbar(im, ax=ax2, fraction=0.046)
    fig.tight_layout()
    fig.savefig(FINAL / "classifier.png")
    plt.close(fig)


def ranking_table() -> None:
    d = json.loads((FINAL / "ranking.json").read_text())
    rows = [{"target": r["target"], "priority_items": r.get("priority_items"),
             "critical_items": r.get("critical_items"),
             "ndcg10_base": r["ndcg10_before"], "ndcg10_context": r["ndcg10_after"],
             "first_critical_base": r["first_critical_before"],
             "first_critical_context": r["first_critical_after"]}
            for r in d["targets"]]
    m = d["mean"]
    rows.append({"target": "mean", "priority_items": None, "critical_items": None,
                 "ndcg10_base": m["ndcg10_before"], "ndcg10_context": m["ndcg10_after"],
                 "first_critical_base": m["first_critical_before"],
                 "first_critical_context": m["first_critical_after"]})
    write("ranking", rows, f"Mean over {d['tie_samples']} random tie-breaks (seed {d['seed']}). "
          "first_critical = rank of the first finding matching a grade-3 priority item "
          "(– if a tie-break left it unfound). 4 targets, 6-10 priority items each: "
          "descriptive only, no significance claimed.")
    plt = _plt()
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 3.4))
    targets = [r["target"] for r in rows]
    colours = {"base CVSS": "#9aa5b1", "context-aware": "#2f6db5"}
    _bars(ax1, targets, {"base CVSS": [r["ndcg10_base"] for r in rows],
                         "context-aware": [r["ndcg10_context"] for r in rows]}, colours)
    ax1.set_ylim(0, 1.1)
    ax1.set_title("NDCG@10 (higher is better)")
    ax1.legend(frameon=False, fontsize=8)
    _bars(ax2, targets, {"base CVSS": [r["first_critical_base"] for r in rows],
                         "context-aware": [r["first_critical_context"] for r in rows]},
          colours, fmt="{:.1f}")
    ax2.set_title("Rank of first critical finding (lower is better)")
    fig.tight_layout()
    fig.savefig(FINAL / "ranking.png")
    plt.close(fig)


def mapping_table() -> None:
    import yaml
    from cvss import CVSS3

    classes = yaml.safe_load(mapping_demo.MAPPING_PATH.read_text())["sensitivity_classes"]
    rows = []
    for cid, title, vector in mapping_demo.examples():
        row: dict[str, Any] = {"check_id": cid, "title": title, "base_vector": vector,
                               "base": CVSS3(vector).base_score}
        for c in CLASSES:
            row[c.lower()] = mapping_demo.environmental_score(vector, classes[c])
        rows.append(row)
    write("mapping", rows, "CVSS v3.1 environmental score of the same finding on an endpoint of"
          " each sensitivity class (CR/IR/AR from config/cvss_mapping.yaml; modified base"
          " metrics left undefined).")
    plt = _plt()
    fig, ax = plt.subplots(figsize=(9, 3.4))
    series = {c: [r[c.lower()] for r in rows] for c in CLASSES}
    _bars(ax, [r["check_id"] for r in rows],
          {"base": [r["base"] for r in rows], **series},
          {"base": "#9aa5b1", "LOW": "#cfe0f3", "MEDIUM": "#8fb7e3", "HIGH": "#4f8fd0",
           "CRITICAL": "#1f4f8f"}, fmt="{:.1f}")
    ax.set_ylim(0, 10.5)
    ax.set_ylabel("CVSS score")
    ax.set_title("Same finding, different endpoint sensitivity")
    ax.legend(frameon=False, fontsize=7, ncol=5, loc="upper left")
    fig.tight_layout()
    fig.savefig(FINAL / "mapping.png")
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--before-run", required=True, help="raw run stamp before tuning")
    args = p.parse_args(argv)
    tools_table()
    tuning_table(args.before_run)
    classifier_tables()
    ranking_table()
    mapping_table()
    print(f"wrote {FINAL.relative_to(ev.ROOT)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
