"""Anchor classifier vs keyword classifier on the labelled endpoints (Asim Prompt 6).

    python eval/harness/eval_sensitivity.py --split dev     # tune: anchors, threshold
    python eval/harness/eval_sensitivity.py --split test    # report once, never tune

Runs both classifiers on ``eval/labels/endpoints_labelled.csv``:

- **anchors**: ``app.ml.sensitivity.AnchorClassifier`` with
  ``config/sensitivity_anchors.yaml`` (whatever its ``enabled`` flag says);
- **keywords**: the built-in keyword/embedding classifier the scanner ships
  (``app.core.sensitivity``), the baseline.

Static assets are LOW for both (the shared rule in ``classify``). Prints accuracy,
macro-F1, per-class precision/recall/F1 and the confusion matrix for each, and
writes ``eval/results/sensitivity_<split>.json`` and a confusion-matrix PNG.

Split: the project's fixed split by target (dev = DVWA + VAmPI, test = Juice Shop
+ crAPI, ``classifier_eval.SPLITS``), not a random stratified one: a random split
would put paths of the same app on both sides, and the scanner metrics use the
same split (docs/evaluation-method.md).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "eval" / "harness"))

from classifier_eval import CLASSES, load, metrics  # noqa: E402

RESULTS = ROOT / "eval" / "results"


def predict_anchors(rows: list[dict[str, str]], anchors_file: Path | None) -> list[str]:
    from app.ml.sensitivity import AnchorClassifier, is_static_asset, load_config

    model = AnchorClassifier(load_config(anchors_file))
    return ["LOW" if is_static_asset(r["path"]) else model.classify(r["path"], r["method"]).value
            for r in rows]


def predict_keywords(rows: list[dict[str, str]]) -> list[str]:
    from app.core.contracts import EndpointInfo, builtin_classify
    from app.ml.sensitivity import is_static_asset

    return ["LOW" if is_static_asset(r["path"]) else
            builtin_classify(EndpointInfo(url="https://t" + r["path"], path=r["path"],
                                          method=r["method"])).value
            for r in rows]


def confusion_png(results: dict[str, dict], path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, len(results), figsize=(5 * len(results), 4.4))
    for ax, (name, res) in zip(axes, results.items(), strict=True):
        grid = [[res["confusion"][t][p] for p in CLASSES] for t in CLASSES]
        ax.imshow(grid, cmap="Blues")
        for i, row in enumerate(grid):
            for j, v in enumerate(row):
                ax.text(j, i, str(v), ha="center", va="center",
                        color="white" if v > max(map(max, grid)) / 2 else "black")
        ax.set_xticks(range(4), CLASSES)
        ax.set_yticks(range(4), CLASSES)
        ax.set_xlabel("predicted")
        ax.set_ylabel("labelled")
        ax.set_title(f"{name}: accuracy {res['accuracy']}, macro-F1 {res['macro_f1']}")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--split", default="dev", choices=["dev", "test"])
    p.add_argument("--anchors", type=Path, help="anchors YAML to try (default: config/)")
    p.add_argument("--errors", action="store_true", help="list the anchor classifier's misses")
    args = p.parse_args(argv)

    rows = load(args.split)
    truth = [r["sensitivity_class"] for r in rows]
    anchor_pred = predict_anchors(rows, args.anchors)
    results = {"anchors": metrics(truth, anchor_pred),
               "keywords": metrics(truth, predict_keywords(rows))}
    out = {"split": args.split, **results}
    if args.errors:
        out["errors"] = [f"{r['target']} {r['method']} {r['path']}: "
                         f"{r['sensitivity_class']} -> {q}"
                         for r, q in zip(rows, anchor_pred, strict=True)
                         if r["sensitivity_class"] != q]
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / f"sensitivity_{args.split}.json").write_text(json.dumps(out, indent=2) + "\n")
    confusion_png(results, RESULTS / f"sensitivity_{args.split}_confusion.png")
    for name, res in results.items():
        print(f"{args.split} {name:8} accuracy {res['accuracy']:.3f}  "
              f"macro-F1 {res['macro_f1']:.3f}  off-by-two {res['off_by_two_or_more']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
