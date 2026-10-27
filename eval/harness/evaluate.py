"""Normalise tool outputs, match them to the ground truth, compute metrics (Asim).

Pure functions over the raw files in ``eval/results/raw/<tool>/<target>/`` so
the metrics can be recomputed from a saved run without scanning again:

    python eval/harness/evaluate.py            # re-score the latest raw outputs

Rules (also in eval/harness/README.md):

* **Endpoint rule.** A finding's URL is reduced to its path: scheme, host,
  port, query and fragment dropped; percent-decoding applied; a trailing slash
  removed (except for ``/``); ID-like segments (all digits, UUIDs, 24-hex Mongo
  ids, ``{param}``/``:param`` placeholders) become ``:id``. Case is kept (paths
  are case-sensitive). Host-level findings (no endpoint, e.g. TLS) become ``*``
  and match a ground-truth entry on ``/`` or ``*``.
* **True positive**: a tool finding with the same target, endpoint and
  ``check_id`` as a ground-truth ``present`` entry. A ``present`` entry no
  finding matches is a **false negative**.
* **False positive**: a finding that hits a ground-truth ``absent`` entry, or
  any finding of a check listed in the target's ``must_not_fire``.
* **True negative**: an ``absent`` entry, or a ``must_not_fire`` check, that no
  finding hits.
* Findings the ground truth says nothing about are **unlabelled** (reported,
  not counted), and findings whose tool rule has no ``check_id`` mapping are
  **out of scope** (reported, never dropped).
* **Coverage**: a tool is scored only on the check ids its mapping can produce
  (``tool_mapping.yaml``); CAWASMA can produce every check id. Entries for
  checks a tool cannot report are listed as "not covered", not as misses.
"""
from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import yaml

ROOT = Path(__file__).resolve().parents[2]
GROUND_TRUTH = ROOT / "eval" / "ground_truth"
RESULTS = ROOT / "eval" / "results"
MAPPING = Path(__file__).resolve().parent / "tool_mapping.yaml"
TARGETS = ["juice-shop", "dvwa", "vampi", "crapi"]
TOOLS = ["cawasma", "zap", "nuclei"]
HOST_LEVEL = "*"

_ID = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                 r"|[0-9a-f]{24}|\{[^}]*\}|:\w+|<[^>]*>)$", re.I)


def normalise_endpoint(url_or_path: str | None) -> str:
    """The endpoint rule (module docstring)."""
    if not url_or_path:
        return HOST_LEVEL
    path = unquote(urlparse(url_or_path).path or "/")
    parts = [":id" if _ID.match(p) else p for p in path.split("/") if p]
    return "/" + "/".join(parts)


@dataclass(frozen=True)
class Finding:
    tool: str
    target: str
    check_id: str | None          # None: out of scope (no mapping)
    endpoint: str                 # normalised; "*" for host-level
    rule: str                     # the tool's own rule id (pluginid, template-id, check_id)
    name: str = ""


@dataclass
class Result:
    """One tool on one target."""

    tool: str
    target: str
    tp: list[tuple[str, str]] = field(default_factory=list)       # (check_id, endpoint)
    fp: list[tuple[str, str]] = field(default_factory=list)
    fn: list[tuple[str, str]] = field(default_factory=list)
    tn: list[tuple[str, str]] = field(default_factory=list)
    not_covered: list[tuple[str, str]] = field(default_factory=list)
    unlabelled: list[tuple[str, str]] = field(default_factory=list)
    out_of_scope: list[tuple[str, str]] = field(default_factory=list)  # (rule, endpoint)
    scan_seconds: float | None = None
    seen: set[str] = field(default_factory=set)   # endpoints the tool reported anything on

    def metrics(self) -> dict[str, Any]:
        tp, fp, fn, tn = len(self.tp), len(self.fp), len(self.fn), len(self.tn)
        return {
            "tool": self.tool, "target": self.target, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn),
            "fpr": _ratio(fp, fp + tn), "not_covered": len(self.not_covered),
            "unlabelled": len(self.unlabelled), "out_of_scope": len(self.out_of_scope),
            "scan_seconds": round(self.scan_seconds, 1) if self.scan_seconds is not None else None,
        }


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 3) if b else None


# ------------------------------------------------------------ mapping

def load_mapping(path: Path = MAPPING) -> dict[str, dict[str, str | None]]:
    data = yaml.safe_load(path.read_text())
    return {tool: {str(k): v for k, v in (data.get(tool) or {}).items()} for tool in ("zap", "nuclei")}


def coverage(tool: str, mapping: dict[str, dict[str, str | None]]) -> set[str] | None:
    """Check ids the tool can report; None means all (CAWASMA)."""
    if tool == "cawasma":
        return None
    return {c for c in mapping[tool].values() if c}


# ------------------------------------------------------------ normalisers

def normalise_cawasma(target: str, raw: dict[str, Any]) -> list[Finding]:
    return [Finding("cawasma", target, f["check_id"], normalise_endpoint(f.get("endpoint_url")),
                    f["check_id"], f.get("title", "")) for f in raw.get("findings", [])]


def normalise_zap(target: str, raw: dict[str, Any], mapping: dict[str, str | None]) -> list[Finding]:
    """ZAP JSON report: one finding per alert instance (URL)."""
    out = []
    for site in raw.get("site", []):
        for alert in site.get("alerts", []):
            rule = str(alert.get("pluginid"))
            check = mapping.get(rule)
            for inst in alert.get("instances", []) or [{"uri": None}]:
                out.append(Finding("zap", target, check, normalise_endpoint(inst.get("uri")),
                                   rule, alert.get("alert") or alert.get("name", "")))
    return out


def normalise_nuclei(target: str, lines: Iterable[str], mapping: dict[str, str | None]
                     ) -> list[Finding]:
    """Nuclei JSONL. A rule is ``template-id:matcher-name`` when a matcher fired,
    else ``template-id``; the more specific key is tried first."""
    out = []
    for line in lines:
        if not line.strip():
            continue
        r = json.loads(line)
        tid, matcher = r.get("template-id", ""), r.get("matcher-name")
        rule = f"{tid}:{matcher}" if matcher else tid
        check = mapping[rule] if rule in mapping else mapping.get(tid)
        if check is None and rule not in mapping and tid not in mapping:
            check = _by_path(r.get("template-path", ""), mapping)
        url = r.get("matched-at") or r.get("url")
        out.append(Finding("nuclei", target, check, normalise_endpoint(url), rule,
                           (r.get("info") or {}).get("name", "")))
    return out


def _by_path(template_path: str, mapping: dict[str, str | None]) -> str | None:
    """``path:<glob>`` keys, matched on the template path from ``http/`` on."""
    rel = template_path[template_path.find("http/"):] if "http/" in template_path else ""
    for key, check in mapping.items():
        if key.startswith("path:") and rel and fnmatch(rel, key[5:]):
            return check
    return None


# ------------------------------------------------------------ ground truth

def load_ground_truth(target: str) -> dict[str, Any]:
    return yaml.safe_load((GROUND_TRUTH / f"{target}.yaml").read_text())


def _hits(finding: Finding, check_id: str, endpoint: str) -> bool:
    if finding.check_id != check_id:
        return False
    gt = normalise_endpoint(endpoint) if endpoint != HOST_LEVEL else HOST_LEVEL
    if finding.endpoint == HOST_LEVEL:
        return gt in ("/", HOST_LEVEL)
    return finding.endpoint == gt


def score(tool: str, target: str, findings: list[Finding], gt: dict[str, Any],
          covered: set[str] | None) -> Result:
    res = Result(tool, target, seen={f.endpoint for f in findings})
    in_scope = [f for f in findings if f.check_id]
    res.out_of_scope = sorted({(f.rule, f.endpoint) for f in findings if not f.check_id})
    labelled: set[int] = set()
    for entry in gt.get("known_issues", []):
        key = (entry["check_id"], normalise_endpoint(entry["endpoint"]))
        if covered is not None and entry["check_id"] not in covered:
            res.not_covered.append(key)
            continue
        hit = [i for i, f in enumerate(in_scope) if _hits(f, entry["check_id"], entry["endpoint"])]
        labelled.update(hit)
        if entry["expected"] == "present":
            (res.tp if hit else res.fn).append(key)
        else:
            (res.fp if hit else res.tn).append(key)
    for neg in gt.get("must_not_fire", []):
        cid = neg["check_id"]
        if covered is not None and cid not in covered:
            res.not_covered.append((cid, "*"))
            continue
        hit = [i for i, f in enumerate(in_scope) if f.check_id == cid]
        labelled.update(hit)
        if hit:
            res.fp.extend(sorted({(cid, in_scope[i].endpoint) for i in hit}))
        else:
            res.tn.append((cid, "*"))
    res.unlabelled = sorted({(f.check_id or "", f.endpoint) for i, f in enumerate(in_scope)
                             if i not in labelled})
    return res


# ------------------------------------------------------------ reports

def write_reports(results: list[Result], out: Path = RESULTS, run_info: dict | None = None) -> None:
    out.mkdir(parents=True, exist_ok=True)
    rows = [r.metrics() for r in results]
    with (out / "metrics.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (out / "comparison.md").write_text(_comparison(results, run_info or {}))
    (out / "errors.md").write_text(_errors([r for r in results if r.tool == "cawasma"],
                                           run_info or {}))


def _fmt(v: Any) -> str:
    return "-" if v is None else f"{v:.2f}" if isinstance(v, float) and v <= 1 else str(v)


def _totals(results: list[Result]) -> dict[str, Any]:
    tot = Result(results[0].tool, "all")
    for r in results:
        for name in ("tp", "fp", "fn", "tn", "not_covered", "unlabelled", "out_of_scope"):
            getattr(tot, name).extend(getattr(r, name))
    tot.scan_seconds = sum(r.scan_seconds or 0 for r in results)
    return tot.metrics()


def _comparison(results: list[Result], info: dict) -> str:
    head = ("| tool | target | TP | FP | FN | TN | precision | recall | FPR | not covered "
            "| unlabelled | out of scope | scan time (s) |")
    lines = ["# Tool comparison", "", _info_block(info), "", head,
             "|" + "---|" * 13]
    for tool in TOOLS:
        mine = [r for r in results if r.tool == tool]
        if not mine:
            continue
        for m in [r.metrics() for r in mine] + [_totals(mine)]:
            lines.append("| " + " | ".join(_fmt(m[k]) if k not in ("tool", "target") else
                                           (f"**{m[k]}**" if m["target"] == "all" else m[k])
                                           for k in ("tool", "target", "tp", "fp", "fn", "tn",
                                                     "precision", "recall", "fpr", "not_covered",
                                                     "unlabelled", "out_of_scope",
                                                     "scan_seconds")) + " |")
    lines += ["", "Precision = TP/(TP+FP), recall = TP/(TP+FN), FPR = FP/(FP+TN); `-` when "
              "undefined. Rules: eval/harness/README.md.", "",
              "Reading the table:", "",
              "- ZAP and Nuclei are scored only on the check ids their rules map to "
              "(*not covered* counts the rest); CAWASMA is scored on every entry. Their "
              "recall is over a smaller, mostly header-only set, so compare per check, "
              "not the totals.",
              "- The endpoint rule is strict: a missing header reported on `/` does not "
              "match an entry on `/login.php`, even if every page lacks it.",
              "- *Unlabelled* findings are neither right nor wrong: the ground truth says "
              "nothing about that check on that endpoint.", ""]
    return "\n".join(lines)


def _info_block(info: dict) -> str:
    if not info:
        return "_Recomputed from saved raw outputs._"
    return "\n".join(f"- **{k}**: {v}" for k, v in info.items())


NOTES = Path(__file__).resolve().parent / "error_notes.yaml"


def _errors(results: list[Result], info: dict) -> str:
    """CAWASMA FPs/FNs by check id. A false negative is marked *not crawled* when
    CAWASMA reported nothing at all at that endpoint (it never reached it), and
    each check gets its cause from error_notes.yaml (hand-written analysis)."""
    notes = yaml.safe_load(NOTES.read_text()) if NOTES.exists() else {}
    fps: dict[str, list[str]] = defaultdict(list)
    fns: dict[str, list[str]] = defaultdict(list)
    for r in results:
        for cid, ep in r.fp:
            fps[cid].append(f"{r.target} `{ep}`")
        for cid, ep in r.fn:
            crawled = ep == HOST_LEVEL or ep in r.seen
            fns[cid].append(f"{r.target} `{ep}`" + ("" if crawled else " (not crawled)"))
    lines = ["# CAWASMA errors", "", _info_block(info), "",
             "False positives go to Atta (detection code); false negatives may be the scanner",
             "or the ground truth: check the target's `observed/*.json` first.", "",
             f"## False positives ({sum(map(len, fps.values()))})", ""]
    lines += _grouped(fps, notes.get("false_positives") or {})
    lines += ["", f"## False negatives ({sum(map(len, fns.values()))})", ""]
    lines += _grouped(fns, notes.get("false_negatives") or {})
    lines.append("")
    return "\n".join(lines)


def _grouped(errors: dict[str, list[str]], notes: dict[str, str]) -> list[str]:
    if not errors:
        return ["None."]
    out = []
    for cid, eps in sorted(errors.items()):
        out.append(f"- **{cid}** ({len(eps)}): " + ", ".join(sorted(eps)))
        if cid in notes:
            out.append(f"  - *Cause:* {' '.join(str(notes[cid]).split())}")
    return out


# ------------------------------------------------------------ from raw files

def latest(tool: str, target: str, raw_root: Path = RESULTS / "raw") -> Path | None:
    runs = sorted((raw_root / tool / target).glob("*/")) if (raw_root / tool / target).exists() else []
    return runs[-1] if runs else None


def load_run(tool: str, target: str, run_dir: Path, mapping) -> tuple[list[Finding], float | None]:
    meta = json.loads((run_dir / "meta.json").read_text())
    if tool == "cawasma":
        findings = normalise_cawasma(target, json.loads((run_dir / "results.json").read_text()))
    elif tool == "zap":
        findings = normalise_zap(target, json.loads((run_dir / "zap.json").read_text()),
                                 mapping["zap"])
    else:
        findings = normalise_nuclei(target, (run_dir / "nuclei.jsonl").read_text().splitlines(),
                                    mapping["nuclei"])
    return findings, meta.get("seconds")


def evaluate_all(raw_root: Path = RESULTS / "raw", out: Path = RESULTS,
                 run_info: dict | None = None) -> list[Result]:
    mapping = load_mapping()
    results = []
    info = dict(run_info or {})
    for tool in TOOLS:
        for target in TARGETS:
            run_dir = latest(tool, target, raw_root)
            if run_dir is None:
                continue
            meta = json.loads((run_dir / "meta.json").read_text())
            label = {"cawasma": "CAWASMA", "zap": "ZAP", "nuclei": "Nuclei"}[tool]
            info.setdefault(label, " ".join(str(meta.get(k)) for k in ("version", "image",
                                                                       "templates")
                                            if meta.get(k)).replace("\n", " ")[:160])
            info.setdefault("raw outputs", f"eval/results/raw/<tool>/<target>/{run_dir.name}/")
            findings, seconds = load_run(tool, target, run_dir, mapping)
            res = score(tool, target, findings, load_ground_truth(target),
                        coverage(tool, mapping))
            res.scan_seconds = seconds
            results.append(res)
    if results:
        write_reports(results, out, info)
    return results


if __name__ == "__main__":
    for r in evaluate_all():
        print(r.metrics())
