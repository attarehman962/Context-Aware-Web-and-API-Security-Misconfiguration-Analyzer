# Code walkthrough

How each main part of CAWASMA works and why it is built that way, in the order a
scan passes through it. Owners as in CLAUDE.md. Details: `docs/02-architecture.md`,
`docs/06-scoring-model.md`, `docs/engine-security.md`.

## Engine: `backend/app/core/engine.py` (Atta)

An async httpx client (HTTP/2, a semaphore for concurrency, size and time limits)
that every request of a scan goes through. Its network backend dials only an IP
that has just passed the SSRF check (`utils/security.py`), so a DNS answer that
changes between check and connect (rebinding) can't reach an internal host.
Redirects are followed by hand, one hop at a time, each re-checked and kept on the
scan's host. Passive mode refuses anything but GET/HEAD. No cookies are kept
between requests, and plain GET/HEAD responses are cached for the scan.

## Crawler: `backend/app/core/crawler.py` (Atta)

Finds the endpoints to check with four strategies sharing one visited set: links
and forms in HTML, API routes in JavaScript and OpenAPI documents, a small
wordlist (`app/data/wordlist.txt`, skipped in passive mode), and breadth-first
recursion to depth 2. A random path is fetched first to detect sites that answer
everything with the same page (soft 404), so a catch-all page isn't reported as
`/.env`. Off-host links are recorded, never fetched; routes named like state
changes (`/logout`, `/createdb`) are never requested.

## Checks: `backend/app/core/checks/` (Atta; specs and vectors: Asim)

Each check is a pure function over one response and its endpoint; it reads
nothing else, so it is easy to test. Twenty-five run through the spec registry
(`registry.py`, `spec/`), driven by Asim's `config/checks.yaml`; 37 older ones are
`@rule` functions with metadata in `catalog.py`. Every check carries a fixed CVSS
v3.1 base vector, never one computed at scan time, and a check id with a spec uses
the spec's vector however it runs. Every check has a fire and a no-fire test, and
a guard test fails if one is missing.

## Scoring: `backend/app/core/cvss.py` (Atta; mapping: Asim)

The point of the project: the same misconfiguration scores differently depending
on where it is. The endpoint's sensitivity class and the response's body signals
are looked up in `config/cvss_mapping.yaml`, which gives the CVSS environmental
requirements CR, IR and AR (the highest wins). These are appended to the base
vector and scored with the `cvss` library, so the final vector can be recomputed in
the FIRST calculator. Base and final scores are kept in separate columns. Legacy
checks still use the interim formula (base × context multiplier + body bonus).

## Pipeline: `backend/app/core/pipeline.py` (Atta)

Runs one scan without touching the database: fetch the seed URL (an unreachable
target is a `ScanError`), crawl, probe the host's TLS (SSLyze, else `ssl`) and
HTTP→HTTPS redirect, then analyse the endpoints concurrently but return them in a
fixed order, so two scans of the same site give the same result. Per endpoint:
classify the path and the body, run the checks, score. Findings are then
correlated into attack chains (`core/chains.py`, `config/chains.yaml`). Stage
times go to `stats["stage_seconds"]`.

## Workers: `backend/app/workers/` (Atta)

`POST /api/scan` stores a QUEUED scan and queues the Celery task `cawasma.run_scan`
with the scan id as task id, so cancel can revoke it. The worker runs the pipeline
through `services/scan_runner.py`, which writes progress per stage to the scan
row, checks the cancel flag at every step, enforces `SCAN_TIMEOUT` and stores the
results. Live status is `GET /api/scan/{id}/events` (SSE), which re-reads that row:
no second channel between worker and API.

## Reports: `backend/app/core/reports.py` (Atta)

JSON, CSV, HTML and PDF exports of one scan (`GET /api/results/{id}/export`). The
data comes from `services/contract_service.py`; the renderers are pure functions.
HTML comes from one Jinja2 template, and PDF is the same HTML through WeasyPrint
(501 if its native libraries are missing). Evidence is redacted again on export,
and CSV cells starting with `=`, `+`, `-` or `@` are neutralised so a target can't
plant a spreadsheet formula. Each finding says why its final score differs from
its base score.

## Sensitivity classifier: `backend/app/ml/sensitivity.py` (Asim), `core/sensitivity.py` (Atta)

Gives each endpoint a class from its path: LOW, MEDIUM, HIGH or CRITICAL. The
built-in classifier matches path tokens against keyword families (identity,
payment, secrets → CRITICAL; login, session, account → HIGH), after expanding
abbreviations, and reports why. Embeddings (all-MiniLM-L6-v2) only adjust the
confidence. Asim's module makes static files LOW. An anchor-embedding classifier
(Prompt 6) is on his branch with `enabled: false`; it scored 0.52 accuracy on the
test split against 0.43.

## Body classifier: `backend/app/ml/body_classifier.py` (Asim), `core/body_classifier.py` (Atta)

Scans each response body for credentials and keys, personal data, financial data
and internal IPs, and returns the contract's four body signals. Card numbers must
pass Luhn and IBANs mod-97; generic tokens must pass an entropy check, and values
inside OpenAPI examples are skipped. Evidence is always redacted (`AKIA****WXYZ`),
never stored whole. Atta's built-in version is the fallback when the ML
dependencies are absent.

## Evaluation harness: `eval/harness/` (Asim)

`run_all.py` resets four deliberately vulnerable apps (DVWA, VAmPI, Juice Shop,
crAPI) on an isolated network, puts a TLS front in front of each so HTTPS-only
CAWASMA can scan them, and runs CAWASMA, ZAP and Nuclei. `evaluate.py` matches
findings to hand-written ground truth (path-normalised, tool rules mapped to check
ids) for precision and recall; `ranking.py` compares base-score and
context-aware ranking with NDCG@10. Tuning happens only on dev (DVWA, VAmPI); test
(Juice Shop, crAPI) is reported once.

## Frontend pages: `frontend/src/app/` (Neelam)

- `/`: the scan form (HTTPS URL, depth, wordlist, passive mode, the authorisation
  checkbox); it posts `POST /api/scan` and opens the scan page.
- `/scans/[id]`: live progress from the SSE stream (polling if it drops), then the
  ranked findings with a base/context-aware toggle, filters, severity counts and
  how many findings context moved, chains, a finding drill-down that explains the
  score, and the exports.
- `/history`: past scans, newest first. `/evaluation`: the final evaluation
  tables, synced from `eval/results/final/`.
- All data comes through the typed client in `src/lib/api.ts` (generated from
  `docs/openapi.json`); MSW mocks let the app run without a backend.
