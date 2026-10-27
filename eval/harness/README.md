# Evaluation harness

`make eval` runs everything: it resets the four targets, scans each one with
CAWASMA, OWASP ZAP and Nuclei, scores the results against
`eval/ground_truth/`, and writes `eval/results/metrics.csv`,
`comparison.md` and `errors.md`.

```bash
make eval                                              # full run (~20-40 min)
python eval/harness/run_all.py --tools cawasma --targets vampi --no-reset
python eval/harness/run_all.py --evaluate-only         # re-score saved raw outputs
```

| File | What |
|------|------|
| `run_all.py` | orchestration: reset, TLS front, the three tools, raw outputs |
| `evaluate.py` | normalisers, endpoint rule, matching, metrics, reports (pure; unit-tested in `backend/tests/eval/test_harness.py`) |
| `tool_mapping.yaml` | ZAP plugin ids and Nuclei templates -> CAWASMA check ids |
| `tls-front/nginx.conf` | the TLS front CAWASMA scans through |

## Reproducibility

- **Fixed versions**: target images, nginx, ZAP 2.15.0 and Nuclei 3.9.0 are
  pinned by digest in `docker-compose.eval.yml`; the Nuclei templates are the
  v10.1.1 release, sha256-checked (`make eval-templates`) and mounted
  read-only. The eval network has no internet access, so nothing updates
  during a run. CAWASMA is the commit you run from (recorded in the reports).
- **Fixed inputs**: CAWASMA runs with `crawl_depth=2, use_wordlist=true,
  passive_only=false`; ZAP baseline with a 2-minute spider (VAmPI: API scan of
  `/openapi.json` in safe mode, `-S`, so no active attacks); Nuclei with a fixed
  template set (`NUCLEI_TEMPLATES` in `run_all.py`), rate 50/s, 10 workers.
- **Seeds**: no tool samples randomly. CAWASMA's per-scan probe Origin and
  soft-404 path are random by design (unguessable) and don't change findings;
  `PYTHONHASHSEED=0` fixes ordering in the harness.
- **Targets reset before each run**: `docker compose down -v` + `up --wait`,
  then VAmPI's `GET /createdb`. ZAP's VAmPI API scan requests every GET in the spec,
  `/createdb` included, which re-creates the same sample data; the tools run
  per target in a fixed order (CAWASMA, ZAP, Nuclei), so each run sees the
  same state. VAmPI's spec declares `servers: [{url: ""}]`, so ZAP gets a copy
  naming `http://vampi:5000` (saved next to its report).

## The TLS front

CAWASMA scans HTTPS only; the targets speak HTTP. nginx on the eval network
serves each target as `https://<target>-tls/` with a certificate from a CA the
harness generates per run (`eval/.run/tls/`, never committed). CAWASMA trusts
that CA through `SCAN_CA_BUNDLE` and may reach the `*-tls` names through
`ALLOWED_INTERNAL_HOSTS` (both in `docker-compose.eval-scan.yml` only). The
front is transparent: it passes the target's `Server` header through and adds
no headers. The first run checked that every target returns identical
security headers directly and through the front. ZAP and Nuclei scan the
targets directly over HTTP.

## Matching rules

**Endpoint rule** (`normalise_endpoint`): a URL is reduced to its path: scheme,
host, port, query and fragment are dropped, percent-encoding is decoded, and a
trailing slash is removed (except on `/`). Path segments that are IDs become
`:id`: all digits, UUIDs, 24-hex Mongo ids, and the placeholders `{x}`, `:x`
and `<x>`. Case is kept, because paths are case-sensitive. Host-level findings
(no endpoint, e.g. TLS) become `*` and match a ground-truth entry on `/` or `*`.

| Outcome | When |
|---------|------|
| **TP** | a finding has the same target, endpoint and `check_id` as a ground-truth `present` entry |
| **FN** | a `present` entry no finding matches |
| **FP** | a finding hits an `absent` entry, or has a check in the target's `must_not_fire` |
| **TN** | an `absent` entry or `must_not_fire` check that no finding hits |
| unlabelled | an in-scope finding the ground truth says nothing about (reported, not scored) |
| out of scope | a tool rule with no `check_id` in `tool_mapping.yaml` (reported, never dropped) |
| not covered | a ground-truth entry for a check the tool can't produce (ZAP/Nuclei only) |

Precision = TP/(TP+FP), recall = TP/(TP+FN), false-positive rate =
FP/(FP+TN); each is shown as `-` when its denominator is 0. One finding can
match only its own endpoint; the same header missing on other pages is
unlabelled, so a tool isn't rewarded for repeating itself.
