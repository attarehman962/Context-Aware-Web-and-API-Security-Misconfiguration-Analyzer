# CAWASMA: Atta's Claude Code prompts

Atta's ten prompts (backend and scanner engine), in run order, as they were
pasted into our Claude Code sessions. They match the branches `atta/p01`–`p10`.
Asim's and Neelam's prompts are in [`docs/project/`](../project/) (see the
[README](README.md)). Text in `[square brackets]` is a placeholder.

## Prompt 1: Repository setup

```text
I'm Atta, backend & scanner-engine developer on CAWASMA, a context-aware web
security scanner (final-year project, team of 3). Read docs/ first — it has
the team plan and data model.

Set up the shared repository:
1. Create CLAUDE.md at the repo root: project goal (context-aware CVSS v3.1
   scoring: base vector per check, recomputed through environmental metrics
   using the NLP endpoint-sensitivity class + response-body signals), the
   team split (Atta = backend/engine, Neelam = Next.js frontend in
   frontend/, Asim = check specs, CVSS mapping, ML in backend/app/ml/,
   evaluation in eval/), file ownership, the rule that nobody edits another
   person's files without asking, coding conventions, and how to run tests.
   Leave a section for me, plus empty sections for Neelam and Asim to fill.
2. Layout: backend/app/ with core/ (engine, crawler, checks, cvss, reports),
   api/, db/, workers/, ml/ (Asim's — stubs only), tests/; config/; docs/;
   eval/ (Asim's); frontend/ (Neelam's). Python 3.12, pyproject.toml,
   ruff + mypy + pytest + pytest-asyncio configured.
3. docker-compose.yml with services: api (FastAPI), worker (Celery),
   postgres, redis. Healthchecks, .env.example, one-command startup.
   Leave a clearly commented slot for Neelam's frontend service.
4. An empty docker-compose.eval.yml placeholder for Asim's targets, on a
   separate network.
5. GitHub Actions CI: lint, type-check, tests with a Postgres service
   container. Structure it so Neelam can add a frontend job alongside.
6. A Makefile: up, down, test, lint, migrate, seed, reset.
7. A pull request template and branch naming rule <name>/pNN-topic.

Make sure `docker compose up` starts and the API answers on /health.
```

## Prompt 2: Database layer

```text
Read CLAUDE.md and docs/ (especially the data model).

Implement the database layer:
1. SQLAlchemy 2.0 models (typed, Mapped[] style) for all 10 entities in the
   data model. If something is ambiguous, list your assumptions in
   docs/db-decisions.md rather than guessing silently. The Finding model must
   include: id, endpoint_id, check_id, owasp_map, cwe_map, cvss_vector,
   base_score, final_score, severity_bucket, evidence (JSONB).
   Endpoint must store its sensitivity class and body signals; Scan needs a
   status enum (queued, running, done, failed), the scan options and the
   authorisation confirmation flag + timestamp.
2. Async engine/session setup (asyncpg) with a FastAPI dependency.
3. Alembic configured for async; generate and check the first migration.
4. scripts/seed.py with realistic sample data (1 target, 2 scans, ~10
   endpoints, ~15 findings across all severities, one chain) and
   scripts/reset.py.
5. Tests: migrations apply cleanly on an empty DB; relationships and
   cascades work.
6. docs/schema.md: table list + ER diagram in Mermaid, to share with the team.
```

## Prompt 3: Shared contracts

```text
Read CLAUDE.md. Create the shared contracts the team will freeze at the end of
Sprint 1. Neelam and Asim build against these, so make them clear and versioned.

1. Pydantic schemas in app/api/schemas.py: ScanRequest (url,
   authorisation_confirmed: bool — required true, crawl_depth 1–2,
   use_wordlist, passive_only), ScanStatus, Finding (id, endpoint_id,
   check_id, owasp_map, cwe_map, cvss_vector, base_score, final_score,
   severity_bucket, evidence, plus sensitivity_class, body_signals and
   chain_ids for the frontend drill-down), ScanResults (findings ranked by
   final_score desc).
2. docs/api-contract.md for Neelam: POST /api/scan,
   GET /api/results/{id}, GET /api/results/{id}/export?format=json|csv|html|pdf,
   GET /api/scans (history). Request/response examples, status codes, error
   format, status values. Export the OpenAPI JSON to docs/openapi.json.
3. Mock mode: if MOCK_API=true, routes return the example JSON so Neelam can
   build before the real pipeline exists.
4. The check-spec format for Asim: a checks.yaml example with 2 sample checks
   (HSTS missing, X-Content-Type-Options missing), fields: check_id,
   category, description, http_condition, owasp, cwe, base_cvss_vector.
   A Pydantic validator that loads checks.yaml and rejects invalid specs or
   invalid CVSS vectors (runnable as `make validate-checks`), plus
   docs/check-spec-format.md.
5. docs/cvss-mapping-contract.md for Asim: the interfaces his code must
   provide — sensitivity.classify(endpoint) -> SensitivityClass and
   body_classifier.analyze(response) -> set[BodySignal] — and the file
   format of config/cvss_mapping.yaml (class/signal -> CR/IR/AR) and
   config/chains.yaml, which he will fill in.
```

## Prompt 4: Engine and crawler

```text
Read CLAUDE.md. Build app/core/engine.py and app/core/crawler.py.

engine.py:
- Async httpx client with HTTP/2 (h2), configurable concurrency (semaphore),
  timeout, retries, user agent, max response size.
- SSRF guard: resolve DNS and block private, loopback, link-local, reserved,
  multicast, unspecified, cloud-metadata (169.254.169.254, fd00:ec2::254)
  and IPv4-mapped IPv6 addresses, including decimal/octal/hex IP forms.
  Follow redirects manually and re-validate every hop. Defend against DNS
  rebinding (validate the resolved IP actually used; document the approach).
- ALLOWED_INTERNAL_HOSTS setting, empty by default, so Asim's eval targets
  can be scanned in the eval environment only.
- A passive_only flag enforced here: only GET/HEAD, no probing.
- Return a normalised ScanResponse dataclass (url, final_url, status,
  lowercased headers, body text with size cap, content type, timing,
  redirect chain, TLS info placeholder) — every check consumes this.

crawler.py, 4 strategies sharing one visited-set:
1. HTML links (a, form, script, link, iframe),
2. JS-source regex for paths/endpoints,
3. wordlist probe (small wordlist in data/; skipped in passive mode),
4. recursive crawl to depth 2.
Normalise URLs, stay in scope, log off-host links without following them,
respect a max-pages limit, return the discovered endpoints.

Tests with respx: every SSRF block case, redirect-to-private blocked,
passive mode sends no probes, each crawler strategy, off-host links
logged not followed.
```

## Prompt 5: Check registry

```text
Read CLAUDE.md and docs/check-spec-format.md. Build app/core/checks.py.

1. A check registry: a @register_check("check_id") decorator so adding a
   check is a one-file change. At startup, cross-validate against Asim's
   checks.yaml: warn on specs with no implementation, fail on
   implementations with no spec.
2. Each check takes (ScanResponse, Endpoint) and returns a list of
   RawFinding (check_id, endpoint, evidence). Scoring happens later in
   cvss.py, not here.
3. Implement the HSTS check (missing or weak Strict-Transport-Security on
   HTTPS responses, e.g. max-age too low) as the reference implementation,
   following the http_condition in checks.yaml exactly.
4. The test pattern every check must follow: one "fire" test (vulnerable
   response -> finding) and one "no-fire" test (secure response -> nothing).
   A reusable pytest helper, plus a test that fails if any registered check
   is missing its fire/no-fire tests.
5. docs/adding-a-check.md: step-by-step for adding a check from a spec.
```

## Prompt 6: CVSS scoring

```text
Read CLAUDE.md and docs/cvss-mapping-contract.md. Build app/core/cvss.py,
the technical heart of the project.

- Use the `cvss` PyPI library. Do NOT re-implement the CVSS formula.
- Input: a RawFinding, its check's base vector from checks.yaml, the
  endpoint's SensitivityClass and the response's BodySignals.
- Load the class/signal -> CR/IR/AR mapping from config/cvss_mapping.yaml
  (Asim owns this file; if it doesn't exist yet, create a clearly marked
  PLACEHOLDER version for him to replace). Rule: signals only raise a
  requirement, never lower it; take the max. Only Security Requirements
  change — no modified base metrics.
- Output: full CVSS v3.1 vector string with environmental metrics,
  base_score, final_score (environmental), severity_bucket
  (None/Low/Medium/High/Critical per the v3.1 ranges), and a short
  machine-readable "score_reasons" list Neelam can show in the drill-down.
- Every vector produced must re-parse and recompute to the same score.
- If Asim's modules aren't in yet, create stubs app/ml/sensitivity.py and
  app/ml/body_classifier.py matching the contract (simple keyword rules,
  e.g. /admin, /login -> high), with a note to Asim at the top of each.
- Tests: known vectors checked against the FIRST calculator values, higher
  sensitivity never lowers the score, round-trip recomputation.
```

## Prompt 7: Vertical slice

```text
Read CLAUDE.md and docs/api-contract.md. Build the end-to-end vertical slice.

1. app/core/pipeline.py: run_scan(scan_id) = engine fetch -> crawler ->
   for each endpoint: run registered checks -> sensitivity class + body
   signals -> cvss.py score -> persist Findings. Status queued -> running
   -> done (or failed with an error message).
2. FastAPI routes exactly per the contract: POST /api/scan (validate the URL,
   REJECT the request unless authorisation_confirmed is true, create the
   scan, dispatch with BackgroundTasks for now), GET /api/results/{id}
   (status + findings ranked by final_score), GET /api/scans (history).
   Keep MOCK_API mode working, and keep mock and real responses identical
   in shape.
3. CORS for Neelam's frontend origin. Errors return the contract's error
   format, never a stack trace.
4. An integration test: a local test server missing HSTS (allowed via
   ALLOWED_INTERNAL_HOSTS in test settings) -> POST /api/scan -> poll ->
   GET results shows one HSTS finding with a valid, recomputable vector.
5. README section "demo the vertical slice": exact docker compose + curl
   commands. Tell me the test target URL so I can give it to Neelam for
   her end-to-end test.
```

## Prompt 8: Full check set and integration

```text
Read CLAUDE.md, docs/adding-a-check.md and docs/chain-templates.md. Asim's
full checks.yaml, config/cvss_mapping.yaml, config/chains.yaml and his real
sensitivity.py / body_classifier.py are now in the repo [adjust if not yet].

1. Implement every check in checks.yaml not yet implemented, each with
   fire/no-fire tests. Use SSLyze for TLS checks (protocol versions, weak
   ciphers, certificate validity), run once per host, not per endpoint.
   Use Mozilla Observatory-style logic for security headers and cookies.
   If a spec's http_condition is ambiguous, stop and list the question for
   Asim instead of guessing.
2. Swap my ML stubs for Asim's real modules, keeping the contract
   interface. If his output doesn't match the contract, stop and tell me
   what's different — don't change his code.
3. Chains: implement the trigger logic from docs/chain-templates.md using
   config/chains.yaml. A chain produces its own scored finding with the
   composite vector, and its member findings carry the chain_id.
4. Complete the results API: filters (severity, category, OWASP, in-chain),
   pagination, per-finding detail. Update docs/api-contract.md and
   openapi.json, and list the changes so I can tell Neelam.
5. Coverage report: every check_id, implemented yes/no, tests passing.
```

## Prompt 9: Celery, live status and reports

```text
Read CLAUDE.md. Sprint 4 work:

1. Move scan execution from BackgroundTasks to Celery (Redis broker).
   Per-stage progress (crawling / checking / scoring, counts so far) stored
   on the Scan; timeouts, retry policy, cancellation. Add live status via
   SSE (preferred) or GET /api/scan/{id}/status — tell me which you chose
   and why, and update docs/api-contract.md for Neelam.
2. app/core/reports.py and the export route: JSON and CSV straight from
   the DB; an HTML report from a Jinja2 template (summary by severity,
   ranked findings, CVSS vector and why the final score differs from base,
   chains); PDF via WeasyPrint from the same HTML. Add WeasyPrint's system
   dependencies to the Dockerfile. Evidence stays redacted in every format.
3. Passive mode and scope: confirm both are enforced in the engine, so no
   check can send a non-GET/HEAD request in passive mode or any request
   outside the target's scope.
4. Rate-limit POST /api/scan.
5. Tests for each export format, passive mode, scope, and Celery tasks
   (eager mode in tests).
```

## Prompt 10: Final hardening

```text
Read CLAUDE.md, eval/results/errors.md and docs/security-review.md.
Final hardening.

1. False positives from Asim's evaluation: for each one in errors.md that
   is owned by a check implementation, reproduce it with a failing test
   first, then fix the check, then confirm. If the cause is the spec rather
   than my code, list it for Asim instead.
2. Security review: make every failing test in tests/security/ that is
   marked as mine pass, and update the status column in
   docs/security-review.md.
3. Performance: budget is a full scan under 10 minutes on a typical target.
   Add timing per stage, profile a scan against the eval targets, optimise
   (connection reuse, concurrency tuning, de-duplicating requests across
   checks, per-host caching like TLS). Show before/after numbers per stage.
4. Reproducibility with Neelam: scripts/clean_machine_check.sh does fresh
   clone -> docker compose up -> migrate -> seed -> demo scan -> verify
   results. Fix anything that depends on my machine; pin all dependency
   versions.
5. Polish: consistent errors, structured logging, no dead code, ruff/mypy
   clean, README + CLAUDE.md updated to the final state.
6. Final check against my definition of done: scan runs end to end, every
   finding has a valid recomputable CVSS vector, the API serves ranked
   results, one-command Docker startup, every check has passing
   fire/no-fire tests. Report pass/fail per item.
```

## Reviewing a partner's prompt

Run after each of Asim's or Neelam's prompts; the review goes to `reviews/`.

```text
Read CLAUDE.md and docs/. Review the branch [partner-branch-name] against
main. I'm Atta, the reviewer; this is [Asim's / Neelam's] Prompt [NN]:
[one line on what the prompt was meant to do].

Do NOT change any files. Check:
1. Does it do what the prompt asked, completely?
2. Does it match the shared contracts exactly (docs/api-contract.md,
   docs/openapi.json, docs/check-spec-format.md,
   docs/cvss-mapping-contract.md, the FINDING shape)?
3. Does it break anything I own? Run the full test suite, lint and
   type-check, and `docker compose up`.
4. Bugs, missing tests, security problems (secrets, SSRF, unredacted
   evidence), files changed outside the owner's folders.
5. For security or scoring judgement calls (CVSS vectors, mapping rows,
   chains), only list questions — don't propose overriding them.

Write the result to reviews/[partner]-p[NN].md as a table:
issue | file:line | severity (must fix / should fix / question) |
suggested fix. End with a verdict: approve, approve after fixes, or
changes needed.
```

## Fixing a review

```text
Read CLAUDE.md and reviews/[asim,neelam both patners]-p[NN].md.

1. Create a branch atta/fix-[partner]-p[NN]-[topic] from
   [partner-branch-name] (or from main if it is already merged).
2. Fix ONLY these items from the review: [list the issue rows].
   For each bug, write a failing test first, then fix it.
3. Don't change anything else and don't touch security or scoring
   judgement calls — leave those as questions for Asim.
4. Run the full test suite, lint, type-check and `docker compose up`.
5. One commit per fix, each message naming the review item.
6. Write the pull request description for [partner]: what was wrong, what
   you changed and why, and how to verify it. Keep it friendly and short.
```

## Final pass before submission

```text
Read CLAUDE.md, every file in docs/ and docs/prompts/ (the 30 prompts:
atta.md, asim.md, neelam.md). I'm Atta. This is the final pass before
submission of our final-year project. Work in four phases. After Phase 1,
STOP and wait for my go-ahead. Commit each phase separately on
atta/p11-final-audit; put any change in Asim's files (checks.yaml,
config/, backend/app/ml/, eval/) or Neelam's (frontend/) on a separate
atta/fix-<name>-p11-<topic> branch so they can review it.

PHASE 1 — AUDIT (change nothing)
1. Prompt coverage: go through all 30 prompts one by one. For each
   numbered item in each prompt, check whether it exists and works.
   Mark: done / partly done / missing / done differently (explain).
2. Run everything from a fresh clone:
   - scripts/clean_machine_check.sh, docker compose up, migrate, seed
   - backend: ruff, mypy, pytest (unit, integration, tests/security/)
   - frontend: lint, type-check, unit tests, build, Playwright e2e + axe
   - make validate-checks, make eval (or a short eval run if slow)
   Record every failure with the exact command and error.
3. Contract consistency — these must all agree:
   - docs/openapi.json vs FastAPI routes vs frontend generated types vs
     MSW mock fixtures (field names, types, status values)
   - checks.yaml vs registered checks vs fire/no-fire tests (1:1:1)
   - config/cvss_mapping.yaml and config/chains.yaml vs cvss.py; every
     stored vector re-parses and recomputes to the same score
   - the FINDING shape across DB model, API schema, frontend and reports
4. Definitions of done: check all three people's definition-of-done
   lists and report pass/fail for each item.
5. Security: scan the whole git history for secrets (gitleaks),
   committed .env files, real credentials in fixtures, unredacted
   evidence in DB/logs/exports, and confirm the SSRF, passive-mode,
   scope and authorisation-gate tests pass.
6. Originality: find any code copied from outside sources (Stack
   Overflow, GitHub, docs examples, tutorials). List each with its
   likely source. Check every dependency's licence (pip-licenses,
   license-checker) and the licence of the wordlist, datasets, images
   and fonts we ship. Flag anything with no licence or an incompatible one.
Write reviews/final-audit.md: one table per section, then a short list
of what you propose for Phases 2–4. STOP here.

PHASE 2 — FIX
Fix the failures and gaps from Phase 1 that I approve, each with a test
first where possible. For copied code: rewrite it in our own way, or
keep it with a source comment and a compatible licence.

PHASE 3 — REMOVE WHAT WE DON'T NEED
List every candidate before deleting, with the reason, then remove in
small commits:
- dead code and unused functions/exports (vulture, knip or ts-prune)
- unused dependencies (deptry, depcheck) and unpinned ones
- leftover TEMPORARY types, unused stubs, commented-out code, debug
  prints and console.logs, TODOs that are done
- scratch scripts, one-off experiments, duplicate configs, old
  migrations that were squashed (only if safe), stale docs
- generated or bulky files that belong in .gitignore: __pycache__,
  .DS_Store, coverage, build output, eval raw outputs, model caches;
  notebooks get their outputs cleared
Keep: everything the demo, tests, evaluation and README need.
MOCK_API mode stays if the frontend tests or demo use it.
reviews/ moves to docs/reviews/ (it shows our process).

PHASE 4 — MAKE THE CODE READ LIKE OURS
The code should read like it was written by a careful three-person
team, not generated. Without changing behaviour:
- Delete comments that only repeat what the code says. Keep comments
  that explain WHY (a decision, a CVSS rule, a security edge case).
- Shorten docstrings: one line unless the function is non-obvious.
  No "This function..." openers, no Args/Returns blocks on trivial
  functions.
- Remove banner/divider comments, emoji, and decorative log messages.
- Rename vague names (data, result, info, helper, handle_x, utils.py
  catch-alls) to names from our domain (finding, endpoint, vector,
  scan). Split catch-all utils files by purpose.
- Remove over-engineering: abstract classes or factories with one
  implementation, wrappers that only forward a call, config options
  nobody sets, try/except blocks that just re-raise or hide errors.
- One consistent style per language (ruff format, prettier), the same
  error format and logging style everywhere.
- Docs and README: plain, specific wording; no filler like "robust",
  "seamless", "comprehensive", "leverage"; say what it does and how
  to run it.
- Do NOT rewrite git history.

FINAL CHECK
Re-run everything from Phase 1 step 2 on a fresh clone. Then write
docs/walkthrough.md: for each main module (engine, crawler, checks,
cvss, pipeline, workers, reports, sensitivity, body_classifier,
eval harness, main frontend pages) 4–6 lines on how it works and why
it is built that way, with the owner's name — so each of us can explain
our part in the viva. Finish with a pass/fail table of all definition-
of-done items and a list of anything still open.
```
