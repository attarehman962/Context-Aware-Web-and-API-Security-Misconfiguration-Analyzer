# 11 — Viva Guide

Concise, honest answers to the questions most likely to come up. (A longer
Roman-Urdu explainer is in the project root guides.)

## The one-sentence pitch

> CAWASMA is a defensive, black-box web & REST-API misconfiguration scanner whose
> novelty is **context-aware risk prioritization** — the same finding is scored
> differently depending on how sensitive the endpoint is and what its response
> exposes.

## Technology justifications

**Why FastAPI (not Flask)?** Native async — essential for running many httpx
requests concurrently — plus automatic OpenAPI docs and built-in Pydantic
validation. Flask would need extra libraries for both.

**Why PostgreSQL (relational)?** The data is naturally relational: a scan has many
endpoints, which have many findings, which link to attack chains (many-to-many).
Foreign keys, cascades and constraints keep it consistent; the ORM parameterizes
queries, preventing SQL injection.

**Why Redis?** Two jobs: it is the Celery message broker, and it holds the shared
scan rate-limit counters. Live progress goes through PostgreSQL: the worker writes
it to the scan row and the SSE route reads it.

**Why Celery (async scanning)?** A scan takes seconds to minutes. Running it inside
the HTTP request would block the client; Celery moves it to a background worker so
the API returns a scan ID immediately.

**Why httpx?** Async HTTP with the control we need: manual redirect handling
(for per-hop SSRF re-checks), timeouts, and response streaming (to enforce a size
cap).

**Why sentence-transformers / `all-MiniLM-L6-v2`?** To add a semantic layer to
endpoint classification. It is optional — the keyword layer guarantees explainable
output and a working demo without the model.

**Why spaCy/regex for response sensitivity?** Fast, deterministic, explainable
detection of credentials/PII/financial/IP — and safe (we redact before storing).

## Core-concept questions

**How does the context multiplier work?** Each endpoint is classified
CRITICAL/HIGH/MEDIUM/LOW; that class maps to ×2.0 / ×1.5 / ×1.0 / ×0.6. A finding
on a sensitive endpoint is multiplied up; on a trivial page it is multiplied down.

**Why does response data change the risk?** A misconfiguration on an endpoint that
leaks credentials or PII is more dangerous than the same issue on a page that
returns nothing sensitive — so we add a response bonus (and credentials force
CRITICAL).

**Why can individual findings become an attack chain?** Because real breaches
usually combine weaknesses. E.g. missing framing/XSS protection + a JS-readable
session cookie = an XSS-to-account-takeover path (chain C001). The chain score
reflects the combined, higher impact.

**Is the final score a real CVSS score?** No — and the tool is explicit about it.
The official CVSS base score is stored separately; the CAWASMA final score is a
custom prioritization metric. Both are shown.

**Why is REST the primary API scope?** REST uses standard HTTP methods and JSON,
which black-box tooling can analyze safely with httpx. Full SOAP/GraphQL/gRPC
auditing is intentionally out of scope.

## Honesty / safety questions

**How do you avoid false certainty?** Checks that can't be confirmed black-box
(BOLA, mass assignment, broken auth, default creds) fire only on a surface signal
and carry an explicit limitation note. We never claim exploitability without
evidence.

**Is it safe to run against a target?** Yes — it is defensive. It prefers
GET/HEAD/OPTIONS, never brute-forces, never submits credentials, never performs
destructive or state-changing actions, and bounds every request (timeout, size,
count, depth, concurrency).

**How is the backend itself protected?** HTTPS-only target validation; SSRF guard
that resolves the hostname and validates the **IP** (blocking loopback, private,
link-local, reserved and cloud-metadata ranges) and re-checks every redirect;
CORS restricted to configured origins (never `*`); secrets redacted everywhere;
ORM-parameterized queries; `.env` for configuration with no hardcoded secrets.

## "Show me it works"

- **Tests:** `python -m pytest -q` → 88 passing (unit + API + end-to-end).
- **Live:** run the stack, open `http://localhost:5173`, scan an HTTPS target, and
  open a finding to show the score breakdown (base × context + bonus = final), the
  redacted evidence, and the limitation note.
- **Reports:** download the HTML/PDF report to show the professional output.

## If asked "what are the limitations?"

Point to [Limitations & OWASP Coverage](10-limitations-owasp.md): the black-box
checks, the OWASP mapping (API8 is the core; API6/7/10 are out of scope), and the
protocol scope. Framing these honestly is a strength, not a weakness.
