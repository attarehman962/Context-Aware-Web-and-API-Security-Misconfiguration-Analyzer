"""Interactive sensitivity labeller for endpoints_raw.csv.

    python eval/labels/label.py                      # label everything, resumable
    python eval/labels/label.py --labeler neelam --sample 50 \
        --output eval/labels/endpoints_labelled_neelam.csv   # inter-rater sample

One key per path (1-4, s skip, q quit); a note can follow the key on the same
line. Labels are saved after every answer, so stopping loses nothing.
"""
from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / "eval" / "labels" / "endpoints_raw.csv"
OUTPUT = ROOT / "eval" / "labels" / "endpoints_labelled.csv"
CLASSES = {
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
    "4": "CRITICAL",
}


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise SystemExit(f"missing {path}; run collect_endpoints.py first")
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_labels(path: Path) -> dict[tuple[str, str, str], dict[str, str]]:
    if not path.exists():
        return {}
    with path.open(newline="", encoding="utf-8") as handle:
        return {
            (row["target"], row["method"], row["path"]): row
            for row in csv.DictReader(handle)
        }


def write_labels(path: Path, labels: dict[tuple[str, str, str], dict[str, str]]) -> None:
    fields = ["target", "method", "path", "sensitivity_class", "labeler", "notes"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(labels[key] for key in sorted(labels))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labeler", help="your name (asked once if not given)")
    parser.add_argument("--output", type=Path, default=None,
                        help="labels file (a second labeller uses their own, e.g. "
                             "endpoints_labelled_neelam.csv)")
    parser.add_argument("--sample", type=int, default=0,
                        help="label only N rows chosen with --seed (inter-rater sample)")
    parser.add_argument("--seed", type=int, default=13)
    args = parser.parse_args(argv)

    output = args.output or OUTPUT
    rows = read_rows(INPUT)
    if args.sample:
        # Same seed -> same rows for every labeller, so their labels can be compared.
        rows = random.Random(args.seed).sample(rows, min(args.sample, len(rows)))
    labels = read_labels(output)
    pending = [
        row for row in rows
        if (row["target"], row["method"], row["path"]) not in labels
    ]
    print(f"{len(labels)} labelled, {len(pending)} remaining -> {output}")
    try:
        labeler = args.labeler if args.labeler is not None else input("your name: ").strip()
        for row in pending:
            key = (row["target"], row["method"], row["path"])
            print(f"\n{len(labels) + 1}: [{row['target']}] {row['method']} {row['path']}")
            print("1 LOW  2 MEDIUM  3 HIGH  4 CRITICAL  s skip  q save and quit"
                  "   (a note may follow the key: 3 login form)")
            choice, _, note = input("> ").strip().partition(" ")
            choice = choice.lower()
            while choice not in CLASSES and choice not in {"s", "q"}:
                choice, _, note = input("Press 1-4, s or q: ").strip().partition(" ")
                choice = choice.lower()
            if choice == "q":
                break
            if choice == "s":
                continue
            labels[key] = {**row, "sensitivity_class": CLASSES[choice],
                           "labeler": labeler, "notes": note.strip()}
            write_labels(output, labels)
    except (EOFError, KeyboardInterrupt):
        print("\ninterrupted")  # labels so far are saved below
    write_labels(output, labels)
    print(f"saved {len(labels)} labels to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
