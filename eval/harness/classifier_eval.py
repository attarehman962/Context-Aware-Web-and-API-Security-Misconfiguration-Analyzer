"""Sensitivity-classifier accuracy on the labelled endpoints (Asim Prompt 10).

    python eval/harness/classifier_eval.py [--split dev|test|all] [--anchors FILE]
                                           [--errors] [--out FILE]

Runs the classifier CAWASMA ships (``app.ml.sensitivity.classify`` through the
contract: keyword families + embedding anchors when sentence-transformers is
installed, keyword-only otherwise) on every path in
``eval/labels/endpoints_labelled.csv`` and prints accuracy, macro-F1, per-class
precision/recall and the confusion matrix as JSON.

Split (docs/evaluation-method.md): **dev** = DVWA + VAmPI, **test** = Juice
Shop + crAPI. Tuning (``--anchors``, a JSON ``{"CRITICAL": "...", ...}`` that
replaces the anchor phrases for this run only) is judged on dev; test is
reported once, for the final table, and never used to choose a change.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

LABELS = ROOT / "eval" / "labels" / "endpoints_labelled.csv"
CLASSES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SPLITS = {"dev": {"dvwa", "vampi"}, "test": {"juice-shop", "crapi"}}


def load(split: str) -> list[dict[str, str]]:
    rows = list(csv.DictReader(LABELS.open()))
    keep = SPLITS.get(split, SPLITS["dev"] | SPLITS["test"])
    return [r for r in rows if r["target"] in keep and r["sensitivity_class"] in CLASSES]


def predict(rows: list[dict[str, str]], anchors: dict[str, str] | None,
            families: list[list] | None = None) -> list[str]:
    from app.core import sensitivity
    from app.core.contracts import EndpointInfo, SensitivityClass

    if anchors:
        # For this process only: the shipped anchors live in Atta's
        # app/core/sensitivity.py; a better set is proposed to him, not edited.
        sensitivity._ANCHORS = {sensitivity.ContextClass(k): v for k, v in anchors.items()}
        sensitivity._default = None             # rebuild with the new anchors
    if families:
        # Same: a proposal for Atta's keyword families, applied in this process.
        sensitivity._KEYWORD_RULES = [(sensitivity.ContextClass(c), why, set(tokens))
                                      for c, why, tokens in families]
    from app.ml.sensitivity import classify

    out = []
    for r in rows:
        cls = classify(EndpointInfo(url="https://t" + r["path"], path=r["path"],
                                    method=r["method"]))
        out.append(cls.value if isinstance(cls, SensitivityClass) else str(cls))
    return out


def metrics(truth: list[str], pred: list[str]) -> dict:
    n = len(truth)
    matrix = {t: {p: 0 for p in CLASSES} for t in CLASSES}
    for t, p in zip(truth, pred, strict=True):
        matrix[t][p] += 1
    per = {}
    for c in CLASSES:
        tp = matrix[c][c]
        fp = sum(matrix[t][c] for t in CLASSES) - tp
        fn = sum(matrix[c].values()) - tp
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        per[c] = {"precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
                  "support": sum(matrix[c].values())}
    acc = sum(matrix[c][c] for c in CLASSES) / n if n else 0.0
    # Off by more than one class (LOW <-> HIGH/CRITICAL, MEDIUM <-> CRITICAL).
    far = sum(1 for t, p in zip(truth, pred, strict=True)
              if abs(CLASSES.index(t) - CLASSES.index(p)) > 1)
    return {"n": n, "accuracy": round(acc, 3),
            "macro_f1": round(sum(v["f1"] for v in per.values()) / len(CLASSES), 3),
            "off_by_two_or_more": far, "per_class": per, "confusion": matrix,
            "predicted": dict(Counter(pred))}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--split", default="dev", choices=["dev", "test", "all"])
    p.add_argument("--anchors", type=Path, help="JSON anchor phrases to try (dev only)")
    p.add_argument("--families", type=Path,
                   help="JSON keyword families [[class, reason, [tokens]], ...] to try")
    p.add_argument("--errors", action="store_true", help="list the misclassified paths")
    p.add_argument("--out", type=Path, help="write the JSON here (stdout carries app logs)")
    args = p.parse_args(argv)
    anchors = json.loads(args.anchors.read_text()) if args.anchors else None
    families = json.loads(args.families.read_text()) if args.families else None
    if (anchors or families) and args.split == "all":
        raise SystemExit("judge proposals per split: dev to choose, test once to report")
    rows = load(args.split)
    pred = predict(rows, anchors, families)
    from app.core import sensitivity

    result = {"split": args.split,
              "embeddings": bool(sensitivity.get_classifier().embeddings_available),
              "anchors": "proposed" if anchors else "shipped",
              "families": "proposed" if families else "shipped",
              **metrics([r["sensitivity_class"] for r in rows], pred)}
    if args.errors:
        result["errors"] = [f"{r['target']} {r['method']} {r['path']}: "
                            f"{r['sensitivity_class']} -> {q}"
                            for r, q in zip(rows, pred, strict=True)
                            if r["sensitivity_class"] != q]
    text = json.dumps(result, indent=2)
    if args.out:
        args.out.write_text(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
