"""Verify a finished scan through the public API (clean-machine check, Atta Prompt 10).

    python -m scripts.verify_scan --api http://localhost:8000 SCAN_ID [--expect HDR-001]

Checks, failing with exit code 1 and a reason per failed check:

- the scan is DONE and the API serves its findings ranked by final_score
  (highest first, ties by check_id);
- every finding's ``cvss_vector`` is a valid CVSS v3.1 vector whose base score
  is ``base_score``, and every ``final_vector`` recomputes to ``final_score``
  (environmental score), so no score is invented;
- every chain's composite vector recomputes to its composite score;
- every export format downloads (JSON = the results body, CSV rows = findings,
  HTML, PDF starting with %PDF) and none contains an unredacted secret pattern;
- the live-status stream (SSE) ends with the DONE event;
- ``--expect`` check ids are among the findings.

Standard library + the ``cvss`` package only, so it runs in the api image.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import urllib.request

from cvss import CVSS3

SECRET_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.|AKIA[0-9A-Z]{16}|"
                       r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def get(url: str, timeout: float = 60) -> tuple[int, str, bytes]:
    with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 - our own api
        return r.status, r.headers.get("content-type", ""), r.read()


def base_score(vector: str) -> float:
    return float(CVSS3(vector).scores()[0])


def env_score(vector: str) -> float:
    return float(CVSS3(vector).scores()[2])


def verify(api: str, scan_id: str, expect: list[str]) -> list[str]:
    errors: list[str] = []
    _, _, raw = get(f"{api}/api/results/{scan_id}?limit=500")
    results = json.loads(raw)
    scan, findings, chains = results["scan"], results["findings"], results["chains"]
    if scan["status"] != "DONE":
        return [f"scan is {scan['status']}: {scan.get('error')}"]
    if not findings:
        errors.append("no findings")
    order = [(-f["final_score"], f["check_id"]) for f in findings]
    if order != sorted(order):
        errors.append("findings are not ranked by final_score desc, check_id")
    for f in findings:
        where = f"{f['check_id']} {f.get('endpoint_url') or 'host'}"
        try:
            if abs(base_score(f["cvss_vector"]) - f["base_score"]) > 0.05:
                errors.append(f"{where}: base_score {f['base_score']} != vector "
                              f"{f['cvss_vector']} ({base_score(f['cvss_vector'])})")
            if f.get("final_vector") and abs(env_score(f["final_vector"])
                                             - f["final_score"]) > 0.05:
                errors.append(f"{where}: final_score {f['final_score']} != "
                              f"{f['final_vector']} ({env_score(f['final_vector'])})")
        except Exception as exc:  # noqa: BLE001 - report every bad vector
            errors.append(f"{where}: invalid CVSS vector: {exc}")
    for c in chains:
        if c.get("composite_vector") and abs(base_score(c["composite_vector"])
                                             - c["composite_score"]) > 0.05:
            errors.append(f"chain {c['chain_code']}: composite score does not recompute")
    ids = {f["check_id"] for f in findings}
    errors += [f"expected finding {cid} is missing" for cid in expect if cid not in ids]

    for fmt in ("json", "csv", "html", "pdf"):
        status, ctype, body = get(f"{api}/api/results/{scan_id}/export?format={fmt}")
        if status != 200:
            errors.append(f"export {fmt}: HTTP {status}")
            continue
        if fmt == "json" and len(json.loads(body)["findings"]) != len(findings):
            errors.append("export json: finding count differs from the API")
        if fmt == "csv" and len(list(csv.DictReader(io.StringIO(body.decode())))) != len(
                findings):
            errors.append("export csv: row count differs from the API")
        if fmt == "pdf" and not body.startswith(b"%PDF-"):
            errors.append(f"export pdf: not a PDF ({ctype})")
        if fmt != "pdf" and SECRET_RE.search(body.decode(errors="replace")):
            errors.append(f"export {fmt}: contains an unredacted secret pattern")

    _, _, stream = get(f"{api}/api/scan/{scan_id}/events", timeout=30)
    events = [json.loads(line[6:]) for line in stream.decode().splitlines()
              if line.startswith("data: ")]
    if not events or events[-1]["status"] != "DONE":
        errors.append("SSE stream did not end with the DONE event")
    return errors


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("scan_id")
    p.add_argument("--api", default="http://localhost:8000")
    p.add_argument("--expect", nargs="*", default=[])
    args = p.parse_args(argv)
    errors = verify(args.api.rstrip("/"), args.scan_id, args.expect)
    for e in errors:
        print(f"FAIL {e}")
    if not errors:
        print("OK scan verified: ranked results, recomputable CVSS vectors, all exports, SSE")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
