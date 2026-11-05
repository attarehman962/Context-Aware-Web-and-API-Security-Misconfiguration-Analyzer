"""Controlled wordlist for endpoint probing (spec section 18, strategy 3).

The paths live in ``app/data/wordlist.txt`` so they can be reviewed and edited
without touching code. Deliberately small and defensive: this is NOT a
brute-force enumeration list.
"""

from __future__ import annotations

from pathlib import Path

WORDLIST_FILE = Path(__file__).resolve().parents[1] / "data" / "wordlist.txt"


def load_wordlist(path: Path = WORDLIST_FILE) -> tuple[str, ...]:
    lines = (line.split("#", 1)[0].strip() for line in path.read_text().splitlines())
    paths = [line for line in lines if line]
    bad = [p for p in paths if not p.startswith("/")]
    if bad:
        raise ValueError(f"{path}: paths must start with '/': {bad}")
    return tuple(dict.fromkeys(paths))


PROBE_PATHS: tuple[str, ...] = load_wordlist()
