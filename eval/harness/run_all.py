"""Run the full evaluation: CAWASMA, OWASP ZAP and Nuclei on every target (Asim).

    make eval                                    # reset targets, scan, score, report
    python eval/harness/run_all.py --tools cawasma --targets vampi
    python eval/harness/run_all.py --evaluate-only   # re-score the saved raw outputs

Steps, all from fixed inputs (see eval/harness/README.md):

1. **Reset** the targets (``docker compose down -v`` + ``up --wait``) so each run
   starts from fresh images and data; VAmPI's database is created once
   (``GET /createdb``, as its README says). Skip with ``--no-reset``.
2. **TLS front**: a CA and a certificate for ``<target>-tls`` are generated
   per run (``eval/.run/tls``); nginx on the eval network terminates TLS so
   HTTPS-only CAWASMA can scan the plain-HTTP targets. CAWASMA trusts the CA via
   ``SCAN_CA_BUNDLE`` (docker-compose.eval-scan.yml); verification stays on.
3. **Scan** each target with each tool. Raw outputs go to
   ``eval/results/raw/<tool>/<target>/<UTC timestamp>/`` with ``meta.json``
   (tool version, image digest, command, start, duration).
4. **Score** (evaluate.py) and write ``metrics.csv``, ``comparison.md`` and
   ``errors.md`` in eval/results/.

Every tool sees the same targets: ZAP and Nuclei on ``http://<target>``, CAWASMA
on ``https://<target>-tls`` (same application behind the transparent proxy).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

HARNESS = Path(__file__).resolve().parent
ROOT = HARNESS.parents[1]
sys.path[:0] = [str(HARNESS), str(ROOT / "backend")]

import evaluate  # noqa: E402

RAW = ROOT / "eval" / "results" / "raw"
RUN_DIR = ROOT / "eval" / ".run"
TLS_DIR = RUN_DIR / "tls"
TEMPLATES = ROOT / "eval" / ".cache" / "nuclei-templates-10.1.1"

EVAL_COMPOSE = ["docker", "compose", "-f", str(ROOT / "docker-compose.eval.yml")]
SCAN_COMPOSE = ["docker", "compose", "-f", str(ROOT / "docker-compose.yml"),
                "-f", str(ROOT / "docker-compose.eval-scan.yml")]
API = os.environ.get("CAWASMA_API", "http://localhost:8000")

# target -> (plain-HTTP base for ZAP/Nuclei, HTTPS base for CAWASMA)
TARGETS = {
    "juice-shop": ("http://juice-shop:3000", "https://juice-shop-tls/"),
    "dvwa": ("http://dvwa:80", "https://dvwa-tls/"),
    "vampi": ("http://vampi:5000", "https://vampi-tls/"),
    "crapi": ("http://crapi-web:80", "https://crapi-tls/"),
}
TLS_NAMES = [base.split("//")[1].rstrip("/") for _, base in TARGETS.values()]

CAWASMA_OPTIONS = {"crawl_depth": 2, "use_wordlist": True, "passive_only": False}
CAWASMA_TIMEOUT = 20 * 60
ZAP_SPIDER_MINUTES = 2
NUCLEI_TEMPLATES = [
    "http/misconfiguration", "http/exposures",
    "http/miscellaneous/directory-listing.yaml", "http/miscellaneous/dir-listing.yaml",
    "http/miscellaneous/options-method.yaml", "http/miscellaneous/http-trace.yaml",
    "http/vulnerabilities/generic/generic-env.yaml",
    "http/vulnerabilities/generic/cors-misconfig.yaml",
]


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC):%H:%M:%S}] {msg}", flush=True)


def sh(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, **kw)  # noqa: S603 - fixed argv


def stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def run_dir(tool: str, target: str, when: str) -> Path:
    d = RAW / tool / target / when
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o777)          # the ZAP container writes as its own user
    return d


def write_meta(d: Path, **meta: Any) -> None:
    (d / "meta.json").write_text(json.dumps(meta, indent=2, default=str) + "\n")


# ------------------------------------------------------------- setup

def make_tls() -> None:
    """CA + one certificate for every <target>-tls name, valid for this run."""
    from scripts.demo_target import make_certificates

    TLS_DIR.mkdir(parents=True, exist_ok=True)
    ca, cert, key = make_certificates(TLS_NAMES, [])
    (TLS_DIR / "ca.pem").write_bytes(ca)
    (TLS_DIR / "front.pem").write_bytes(cert + ca)
    (TLS_DIR / "front.key").write_bytes(key)
    (TLS_DIR / "front.key").chmod(0o644)       # read by nginx in its container


def reset_targets(reset: bool) -> None:
    make_tls()
    if reset:
        log("resetting targets (down -v, up --wait)")
        sh([*EVAL_COMPOSE, "down", "--volumes", "--remove-orphans"], check=True)
    out = sh([*EVAL_COMPOSE, "up", "-d", "--wait"])
    if out.returncode:
        raise SystemExit(f"eval targets did not start:\n{out.stderr[-2000:]}")
    # Recreated every run so it serves this run's certificate.
    out = sh([*EVAL_COMPOSE, "--profile", "scan", "up", "-d", "--wait", "--force-recreate",
              "tls-front"])
    if out.returncode:
        raise SystemExit(f"TLS front did not start:\n{out.stderr[-2000:]}")
    created = sh([*EVAL_COMPOSE, "exec", "-T", "vampi", "wget", "-qO-",
                  "http://127.0.0.1:5000/createdb"])
    log(f"VAmPI /createdb: {'ok' if created.returncode == 0 else created.stderr.strip()}")


def start_cawasma() -> str:
    log("starting CAWASMA (api on the eval network, trusting this run's CA)")
    out = sh([*SCAN_COMPOSE, "up", "-d", "--build", "--wait", "api"], timeout=3600)
    if out.returncode:
        raise SystemExit(f"CAWASMA api did not start:\n{out.stderr[-2000:]}")
    health = httpx.get(f"{API}/health", timeout=10).json()
    return str(health.get("version"))


def image_digest(image: str) -> str:
    out = sh(["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", image])
    return out.stdout.strip() or image


# ------------------------------------------------------------- tools

def run_cawasma(target: str, when: str, version: str) -> None:
    d = run_dir("cawasma", target, when)
    url = TARGETS[target][1]
    start = time.monotonic()
    r = httpx.post(f"{API}/api/scan", json={"url": url, "authorisation_confirmed": True,
                                            **CAWASMA_OPTIONS}, timeout=30)
    r.raise_for_status()
    scan_id = r.json()["scan_id"]
    deadline = start + CAWASMA_TIMEOUT
    while True:
        results = httpx.get(f"{API}/api/results/{scan_id}", timeout=30).json()
        if results["scan"]["status"] in ("DONE", "FAILED") or time.monotonic() > deadline:
            break
        time.sleep(3)
    seconds = time.monotonic() - start
    (d / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    write_meta(d, tool="cawasma", version=version, contract=results.get("contract_version"),
               target=target, url=url, options=CAWASMA_OPTIONS, scan_id=scan_id,
               status=results["scan"]["status"], error=results["scan"]["error"],
               started=when, seconds=round(seconds, 1))
    log(f"cawasma {target}: {results['scan']['status']}, {len(results['findings'])} findings, "
        f"{seconds:.0f}s")


def run_zap(target: str, when: str) -> None:
    d = run_dir("zap", target, when)
    base = TARGETS[target][0]
    if target == "vampi":       # the API scan, in safe mode (-S: no active attacks)
        # VAmPI's spec says servers: [{url: ""}], so ZAP would build URLs under
        # /openapi.json/. Give it a copy that names the real base.
        spec = json.loads(sh([*EVAL_COMPOSE, "exec", "-T", "vampi", "wget", "-qO-",
                              "http://127.0.0.1:5000/openapi.json"], check=True).stdout)
        spec["servers"] = [{"url": base}]
        (d / "openapi.json").write_text(json.dumps(spec))
        args = ["zap-api-scan.py", "-t", "/zap/wrk/openapi.json", "-f", "openapi", "-S"]
    else:
        args = ["zap-baseline.py", "-t", base, "-m", str(ZAP_SPIDER_MINUTES)]
    cmd = [*EVAL_COMPOSE, "--profile", "tools", "run", "--rm", "-v", f"{d}:/zap/wrk:rw",
           "zap", *args, "-J", "zap.json", "-I", "-z", "-silent"]
    start = time.monotonic()
    out = sh(cmd, timeout=3600)
    seconds = time.monotonic() - start
    (d / "zap.log").write_text(out.stdout[-20000:] + out.stderr[-20000:])
    report = json.loads((d / "zap.json").read_text()) if (d / "zap.json").exists() else {}
    write_meta(d, tool="zap", version=report.get("@version"), image=image_digest(ZAP_IMAGE),
               target=target, command=args, started=when, seconds=round(seconds, 1),
               exit_code=out.returncode)
    alerts = sum(len(s.get("alerts", [])) for s in report.get("site", []))
    log(f"zap {target}: {alerts} alert types, {seconds:.0f}s (exit {out.returncode})")


def run_nuclei(target: str, when: str) -> None:
    d = run_dir("nuclei", target, when)
    templates = [x for t in NUCLEI_TEMPLATES for x in ("-t", f"/templates/{t}")]
    args = ["-u", TARGETS[target][0], *templates, "-jsonl", "-o", "/out/nuclei.jsonl",
            "-duc", "-ni", "-silent", "-rl", "50", "-c", "10", "-timeout", "5", "-retries", "1",
            # Some templates also call outside hosts; with no internet on the eval
            # network those fail, and Nuclei would then skip the *target* for the
            # rest of the run ("unresponsive"). Never skip hosts on errors.
            "-no-mhe"]
    cmd = [*EVAL_COMPOSE, "--profile", "tools", "run", "--rm", "-v", f"{d}:/out:rw", "nuclei",
           *args]
    start = time.monotonic()
    out = sh(cmd, timeout=3600)
    seconds = time.monotonic() - start
    if not (d / "nuclei.jsonl").exists():
        (d / "nuclei.jsonl").write_text("")
    (d / "nuclei.log").write_text(out.stdout[-20000:] + out.stderr[-20000:])
    version = sh([*EVAL_COMPOSE, "--profile", "tools", "run", "--rm", "nuclei", "-version"])
    found = re.search(r"Engine Version:\s*(v[\d.]+)", version.stdout + version.stderr)
    write_meta(d, tool="nuclei", version=found.group(1) if found else "unknown",
               image=image_digest(NUCLEI_IMAGE), templates="nuclei-templates v10.1.1",
               template_set=NUCLEI_TEMPLATES, target=target, command=args, started=when,
               seconds=round(seconds, 1), exit_code=out.returncode)
    n = len((d / "nuclei.jsonl").read_text().splitlines())
    log(f"nuclei {target}: {n} results, {seconds:.0f}s (exit {out.returncode})")


ZAP_IMAGE = "zaproxy/zap-stable:2.15.0"         # pinned by digest in docker-compose.eval.yml
NUCLEI_IMAGE = "projectdiscovery/nuclei:v3.9.0"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--targets", nargs="*", default=list(TARGETS), choices=list(TARGETS))
    p.add_argument("--tools", nargs="*", default=evaluate.TOOLS, choices=evaluate.TOOLS)
    p.add_argument("--no-reset", action="store_true", help="keep the running targets")
    p.add_argument("--evaluate-only", action="store_true", help="only re-score raw outputs")
    args = p.parse_args(argv)
    os.environ.setdefault("PYTHONHASHSEED", "0")

    when = stamp()
    info: dict[str, Any] = {"scored": when}
    if not args.evaluate_only:
        if not TEMPLATES.exists() and "nuclei" in args.tools:
            raise SystemExit(f"missing {TEMPLATES}: run `make eval-templates` first")
        reset_targets(reset=not args.no_reset)
        version = start_cawasma() if "cawasma" in args.tools else None
        for target in args.targets:
            for tool in args.tools:
                log(f"{tool} -> {target}")
                if tool == "cawasma":
                    run_cawasma(target, when, str(version))
                elif tool == "zap":
                    run_zap(target, when)
                else:
                    run_nuclei(target, when)
        git = sh(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"]).stdout.strip()
        info.update({"commit": git, "CAWASMA": f"api {version}, {CAWASMA_OPTIONS}",
                     "ZAP": f"{ZAP_IMAGE} (baseline; VAmPI: API scan, safe mode)",
                     "Nuclei": f"{NUCLEI_IMAGE}, nuclei-templates v10.1.1",
                     "targets": "reset before the run" if not args.no_reset else "not reset"})
    results = evaluate.evaluate_all(run_info=info)
    for r in results:
        m = r.metrics()
        log(f"{m['tool']:8} {m['target']:10} TP {m['tp']:3} FP {m['fp']:3} FN {m['fn']:3} "
            f"TN {m['tn']:3}  precision {m['precision']}  recall {m['recall']}")
    log("wrote eval/results/metrics.csv, comparison.md, errors.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
