# Final audit before submission (Phase 1)

Auditor: Atta. Date: 2026-11-05. Code audited: `upstream/main` at 6656090 (after
PR #51). Nothing was changed for this audit except this file.

Every run below used a **fresh clone** in a separate directory: its own venv
(`pip install -c backend/constraints.txt -e "backend[dev]"`), `npm ci`, and a
separate compose project for the clean-machine check. Logs are kept locally
(`~/.cache/cawasma-audit/logs/`).

**Where the prompts are.** `docs/prompts/` doesn't exist. Asim's and Neelam's
prompts are in `docs/project/prompts-asim.md` and `prompts-neelam.md`. Atta's ten
prompts were never committed. They're taken from the prompts as pasted into our
Claude Code sessions, and they match the branch history `atta/p01`–`p10`.
Proposal 2.1 below commits all three files.

Marks: **done**, **partly** (what is missing is said), **missing**, **differently**
(done another way; why).

## 1. Prompt coverage

### Atta (backend & engine)

| Prompt | Item | Mark | Evidence / note |
|---|---|---|---|
| 1 Repo setup | 1 CLAUDE.md | done | goal, team, ownership, conventions, commands |
| | 2 layout, pyproject, ruff/mypy/pytest | done | `backend/app/{core,api,db,workers,ml,services,utils}` |
| | 3 compose api/worker/postgres/redis, healthchecks, .env.example, frontend slot | done | images pinned by digest since p10 |
| | 4 docker-compose.eval.yml placeholder | done | now Asim's full eval stack |
| | 5 CI lint, types, tests + Postgres | done | `.github/workflows/ci.yml` (plus Neelam's frontend jobs) |
| | 6 Makefile up/down/test/lint/migrate/seed/reset | done | plus validate-*, openapi, lock, eval-* |
| 2 DB layer | 1 SQLAlchemy 2.0 models, 10 entities, Finding/Endpoint/Scan fields | done | `app/db/models/` (10 model files); `docs/db-decisions.md` |
| | 2 async engine/session dependency | done | `db/session.py` (`SessionDep`) |
| | 3 Alembic async + first migration | done | 5 migrations (0001–0005) |
| | 4 seed.py / reset.py | done | `make seed`, `make reset` |
| | 5 migration + cascade tests | done | `tests/db/`, CI runs upgrade/downgrade |
| | 6 docs/schema.md + Mermaid ER | done | |
| 3 Contracts | 1 Pydantic contract schemas | differently | `app/api/schemas/contract.py` (a package, not one `schemas.py`, because legacy schemas live beside it) |
| | 2 api-contract.md + openapi.json | done | contract now v1.3.0; drift test in CI |
| | 3 MOCK_API mode | done | `app/api/mock.py`; Neelam's MSW fixtures match `docs/examples/` |
| | 4 checks.yaml format + validator + check-spec-format.md | done | `make validate-checks` OK (25 specs) |
| | 5 cvss-mapping-contract.md | done | |
| 4 Engine & crawler | engine: HTTP/2, limits, SSRF on every hop, rebinding, ALLOWED_INTERNAL_HOSTS, passive, ScanResponse | done | 86 SSRF security cases pass |
| | crawler: 4 strategies, scope, max pages | done | plus OpenAPI/JS-route discovery (p10) |
| | tests with respx | done | |
| 5 Check registry | 1 `@register_check` + startup cross-check | done | `checks/registry.py` (`validate_registry_at_startup`) |
| | 2 `(ScanResponse, Endpoint) -> list[RawFinding]` | done | `CheckFn` |
| | 3 HSTS reference check | done | `checks/spec/hsts.py` |
| | 4 fire/no-fire helper + guard test | partly | guard (`tests/checks/test_check_tests.py`) covers the 25 spec-registry checks only; 28 legacy `@rule` checks have no test naming them |
| | 5 adding-a-check.md | done | |
| 6 cvss.py | library, mapping, max rule, vector + scores + bucket + reasons, stubs, tests | done | FIRST oracle tests; 1,248 stored eval findings re-parse and recompute (section 3) |
| 7 Vertical slice | 1 pipeline | done | |
| | 2 routes per contract, authorisation gate, BackgroundTasks | done | later Celery (p9) |
| | 3 CORS, error envelope | done | |
| | 4 HSTS integration test | done | `test_vertical_slice.py` |
| | 5 README demo section | done | |
| 8 Full check set | 1 implement every checks.yaml spec, SSLyze, Observatory-style | partly | 20 of 25 specs on the registry; API-001, API-003, INF-003/004/005 still legacy, blocked on Asim's spec questions (`docs/check-coverage.md`) |
| | 2 swap to Asim's real modules | partly | `app/ml/body_classifier.py` is Asim's real one; `app/ml/sensitivity.py` is still the stub (Asim Prompt 6 not done) |
| | 3 chains from chains.yaml | done | composite vectors recompute |
| | 4 results filters, pagination, detail | done | contract 1.2 |
| | 5 coverage report | done | `make check-coverage`: 62 checks, 34 passing, 0 failing, 28 untested |
| 9 Celery & reports | 1 Celery, progress, timeout, retry, cancel, SSE | done | SSE chosen; contract 1.3.0 |
| | 2 reports JSON/CSV/HTML(Jinja2)/PDF, redaction | done | |
| | 3 passive + scope in the engine | done | security suite confirms |
| | 4 rate limit POST /api/scan | done | (deprecated `POST /api/scans` not limited: SEC-03) |
| | 5 tests incl. Celery eager | done | |
| 10 Final hardening | 1 false positives from errors.md | differently | errors.md had 0 FPs then; fixed the Atta-owned false negatives instead (cookie jar, discovery) |
| | 2 make my failing tests/security pass | **missing** | all 9 Atta issues (SEC-01..07, 09) still open; tests still xfail |
| | 3 performance, stage timings, before/after | done | `docs/performance.md` (Juice Shop 191 s → 8 s) |
| | 4 clean_machine_check.sh, pinned deps | done | see section 2 |
| | 5 polish: errors, logging, dead code, lint | partly | ruff check passes, but `ruff format` would reformat 161 of 181 files; CLAUDE.md has stale lines (section 3) |
| | 6 definition-of-done report | done | reported 2026-11-04 (fire/no-fire item failed then and now) |

### Asim (specs, CVSS mapping, ML, evaluation)

| Prompt | Item | Mark | Evidence / note |
|---|---|---|---|
| 1 Workspace | 1 CLAUDE.md section | done | |
| | 2 eval/ subfolders + READMEs | done | targets/, notebooks/ hold only READMEs |
| | 3 ml extra, models cached in Docker | done | `HF_HUB_OFFLINE` in the image since p10 |
| | 4 docs/lit-review.md structure | done | headings and prompts only: the content (Asim to write) is still empty |
| | 5 ml install + smoke test | done | `tests/ml/test_ml_smoke.py` (skips without the extra) |
| 2 Check specs | full checks.yaml, rationale, validator, review doc, debatable flags | partly | 25 specs; the asked-for TLS 1.0/1.1, weak ciphers and invalid/expired certificate checks exist only as legacy catalog entries (TLS-001..004), with no spec |
| 3 CVSS mapping | 1–6 | done | `cvss_mapping.yaml`, `docs/cvss-mapping.md`, `mapping_demo.py` |
| 4 Chains | 5 templates, composite vectors, chain-templates.md, weak-chain list | done | |
| 5 Targets & labels | 1 eval compose, pinned, isolated | done | |
| | 2 ground truth + true negatives | done | starter lists, mostly `unverified` |
| | 3 endpoint collector (150–300 paths) | done | 164 paths |
| | 4 label.py | done | |
| | 5 labelling guide | done | |
| 6 Sensitivity classifier | 1–6 | **missing** | no PR; `app/ml/sensitivity.py` delegates to the built-in classifier; no `config/sensitivity_anchors.yaml`, no `eval_sensitivity.py`, no speed test. Partly covered later: `eval/harness/classifier_eval.py`, a dev/test split and a measured accuracy (Prompt 10) |
| 7 Body classifier | all | done | fire/near-miss fixtures in `tests/fixtures/bodies/` |
| 8 Eval harness | 1–6 | done | `make eval`; ZAP/Nuclei pinned |
| 9 Security review | 1–6 + report | done | `docs/security-review.md`, `tests/security/` |
| 10 Final evaluation | 1 ranking experiment | done | priority files are `status: draft` (one rater) |
| | 2 tuning pass | done | |
| | 3 final tables CSV/MD/PNG | done | `eval/results/final/` |
| | 4 evaluation-method.md | done | |
| | 5 security sign-off | done | |

### Neelam (frontend)

| Prompt | Item | Mark | Evidence / note |
|---|---|---|---|
| 1 Scaffold | Next.js/TS/Tailwind/shadcn, lint, tests, Dockerfile, compose service, CI job | done | fresh-clone lint/type-check/build pass |
| 2 API layer | generated types, typed client, MSW mock scan, TanStack Query, client tests | done | regenerated types are byte-identical to the committed `api-schema.ts` |
| 3 App shell | layout + API-mode footer, severity tokens, shared components, /dev/components, tests | done | |
| 4 New-scan page | validation, authorisation box, advanced options, submit flow, tests | done | |
| 5 Real API | types regenerated, /scans/[id] polling, 404/failed/unreachable, real-stack e2e | done | `e2e/real-stack.spec.ts` |
| 6 Results page | summary, base/final toggle, URL filters, 500+ findings, states, tests | done | 600-finding perf e2e passes |
| 7 Drill-down | score story, vector table, FIRST calculator link, context, standards, evidence, tests | done | |
| 8 Live status & history | SSE + polling fallback, cancel, /history, re-scan, tests | done | |
| 9 Export & polish | export menu, file names `cawasma-<target>-<date>`, axe, performance, full e2e in CI, rough-edges list | done | `frontend-e2e-eval` CI job |
| 10 Evaluation & demo | /evaluation from CSVs, README, demo recording, reproducibility check, DoD report | done | `e2e/definition-of-done.spec.ts` |

## 2. Fresh-clone runs

| Command (in the clone) | Result |
|---|---|
| `pip install -c backend/constraints.txt -e "backend[dev]"` | pass (37 s) |
| `ruff check .` | pass |
| `ruff format --check .` | **fail**: 161 of 181 files would be reformatted (no formatter was ever applied) |
| `mypy` | pass (100 files) |
| `pytest` (all: unit, integration, api, db, eval, ml, security) | pass: 899 passed, 2 skipped (ML extra not installed), 9 xfailed (open security issues) |
| `pytest tests/security` | pass: 155 passed, 9 xfailed |
| `make validate-checks` / `validate-config` | pass (validate-config lists 31 catalog `base_score` values that disagree with their vectors; informational) |
| `pytest tests/api/test_openapi_export.py` | pass |
| `npm ci` / `npm run lint` / `prettier --check` / `npm run typecheck` | pass |
| `npm test` | pass: 263 tests in 24 files |
| `npm run build` | pass |
| `npm run test:e2e` (Playwright + axe + 600-finding perf) | pass: 34 tests |
| `scripts/clean_machine_check.sh` (REPO=upstream, REF=main; no cache, then FAST=1) | **fail (this machine)**: `docker compose build` → `failed to extract layer … no space left on device`. The root filesystem holding containerd's snapshots is 100 % full (111 of 114 GB). Two repo issues make it worse: api, worker and demo-target each build and export the same ~4 GB `cawasma-backend` image (3× the layers, and a race on one tag), and the script doesn't print the failing command. To re-run once space is freed (`docker builder prune` reclaims 13.8 GB). The last passing run was 2026-11-04 on Atta's machine state |
| short eval (`run_all.py --tools cawasma`) | not re-run (same disk limit: it rebuilds the api image). Still valid: since PR #49, whose code the 2026-11-04 15:22 full CAWASMA run (4 targets, `eval/results/final/`) scanned, nothing changed in `backend/`, `config/`, `eval/` or the compose files |

## 3. Contract consistency

| What must agree | Result | Detail |
|---|---|---|
| openapi.json ↔ FastAPI routes | agree | `test_openapi_export.py` |
| openapi.json ↔ frontend generated types | agree | `openapi-typescript` regenerated in the clone: byte-identical |
| docs/examples ↔ MSW fixtures | agree | all 6 shared fixtures equal |
| Field names the frontend uses | agree, but CLAUDE.md is wrong | the frontend uses the contract names (`check_id`, `base_score`, `final_score`). CLAUDE.md's conventions tell it to use the legacy names (`rule_id`, `cvss_base_score`, `cawasma_final_score`), which exist only on the deprecated routes |
| checks.yaml ↔ registered checks ↔ fire/no-fire tests | **not 1:1:1** | 62 check ids in total: catalog 58, checks.yaml 25, 37 catalog-only (no spec), 4 spec-only. Spec registry: 20 specs implemented, all with fire/no-fire tests; 5 specs blocked (legacy rules). 28 legacy checks have no test |
| catalog vectors ↔ checks.yaml vectors (same id) | **disagree** | 16 of the 21 shared ids have different base vectors (e.g. CKI-001: catalog 4.3, spec 8.1; API-003: 7.5 vs 9.1). Spec checks use the spec vector; the 5 blocked ones (API-001, API-003, INF-003/004/005) store the catalog vector, so their base score isn't Asim's |
| catalog `base_score` ↔ its own vector | disagree (known) | 31 entries; scans use the vector, so stored scores are consistent |
| cvss_mapping.yaml / chains.yaml ↔ cvss.py | agree | `validate-config` passes; every class and signal has a row |
| Stored vectors re-parse and recompute | agree | all 1,248 findings and both chains in the latest eval run: base 0 mismatches, environmental 0, bucket 0. 501 findings (40 %) are legacy: their `final_score` comes from the interim formula, so it has no vector to recompute |
| FINDING shape: DB ↔ API ↔ frontend ↔ reports | agree | the 10 planned fields are in the DB model and the API schema. The API adds `endpoint_url`, `sensitivity_class`, `body_signals`, `chain_ids`; the frontend uses the generated type; CSV/HTML/PDF render from the API schema |
| CLAUDE.md ↔ repo | stale lines | "the current frontend is a React + Vite SPA"; "a commented frontend job is ready" (it's enabled); "one initial migration 0001" (there are 5); "ml/ stubs for now"; catalog count "58" while 62 ids exist |

## 4. Definitions of done

| Owner | Item | Result |
|---|---|---|
| Atta | scan runs end to end through the pipeline | pass (clean-machine demo scan; eval runs on 4 targets) |
| Atta | every finding carries a valid, recomputable CVSS vector | partly: every base vector is valid and recomputes; 40 % of findings (legacy checks) have no environmental vector |
| Atta | the API serves ranked results | pass |
| Atta | backend up with one Docker command | pass (`make up`; clean-machine check) |
| Atta | every implemented check has a passing fire/no-fire test | **fail**: 34 of 62 (all 25 spec checks yes; 28 legacy no) |
| Asim | every check has a spec and a ground-truth expectation | **fail**: 25 of 62 have a spec; 17 of 62 a ground-truth entry |
| Asim | the classifier has a measured accuracy | pass: 0.425 on test (the classifier itself is still the built-in one) |
| Asim | the scoring mapping is designed and validated | pass |
| Asim | chains are justified | pass (`docs/chain-templates.md`) |
| Asim | precision/recall/FPR vs ZAP and Nuclei | pass (`eval/results/final/tools.*`) |
| Asim | before/after ranking result | pass (`eval/results/final/ranking.*`, descriptive, n = 4) |
| Neelam | enter URL → authorise → watch → ranked report → drill-down → history → export, on the real backend, one Docker command | pass (`e2e/definition-of-done.spec.ts` and `eval-flow.spec.ts`) |

## 5. Security

| Check | Result | Detail |
|---|---|---|
| gitleaks over all history (v8.21.2) | 13 hits, **all fake test values** | 5 Stripe-shaped `sk_live_…` (Atta's tests: test_structured_logging, test_export_reports; old test_redaction/test_body_classifier), 3 JWTs, 3 generic api keys, 1 PEM header, 1 AWS-shaped key in a body_classifier docstring (`AKIA…`, made up). No real credential. The provider-shaped ones should be replaced (push protection blocked one before) and the rest allow-listed in `.gitleaks.toml` |
| .env / key files ever committed | none | only `.env.example` and `frontend/.env.example`; no `.pem`/`.key`/`.kdbx` |
| real credentials in fixtures | none | fixtures use AWS's documented example key and made-up values |
| unredacted evidence: live dev DB | none | `pg_dump` of the dev database (14 scans, 3,756 findings) searched for JWTs, AWS keys, PEM blocks, `secret=value` pairs, URL userinfo: 0 hits (the only 16-digit "card" matches are float digits) |
| unredacted evidence: logs and every export | none | `tests/security/test_secret_leakage.py` passes in the clone |
| SSRF, passive mode, scope, authorisation gate | pass | `tests/security/` 155 passed. Open, all low or medium: SEC-01..09 (`docs/security-review.md`) |

## 6. Originality and licences

**Code from outside sources.** No file carries copied code without saying so:
there's no Stack Overflow, gist or tutorial attribution anywhere, and no file
matches a known snippet. Things that look like outside code, with their likely
source:

| Code | Likely source | Assessment |
|---|---|---|
| `frontend/src/components/ui/{button,dropdown-menu,input,label,skeleton}.tsx` | generated by the shadcn/ui CLI (`components.json`) | copied by design, MIT; keep, add attribution in a NOTICE |
| `frontend/public/mockServiceWorker.js` | generated by MSW | MIT; generated file, keep |
| Next.js config and app scaffold | `create-next-app` template | MIT; boilerplate |
| `luhn_ok`, `iban_ok`, `shannon_entropy` (`app/ml/body_classifier.py`) | textbook algorithms (Luhn, ISO 13616 mod-97, Shannon) | own implementation of public algorithms; fine |
| CA and certificate builder in `scripts/demo_target.py` | the `cryptography` docs' X.509 tutorial pattern | API usage, own code; fine |
| Secret regexes (AWS `AKIA…`, JWT, PEM) in `utils/redaction.py` and the body classifier | the standard public formats (also used by gitleaks) | formats, not code; fine |
| Header and cookie logic "Observatory-style" | Mozilla HTTP Observatory (MPL-2.0) | logic modelled on it, no code taken; the comment says "style", which is accurate |
| `parse_ip_literal` (inet_aton forms) | glibc `inet_aton` semantics | own implementation; fine |

**Licences.**

| Item | Licence | Flag |
|---|---|---|
| CAWASMA itself | **none** (no LICENSE file; `cawasma-frontend` is `UNLICENSED`) | **must fix**: without a licence the code is all rights reserved, which conflicts with the AGPL dependency below |
| sslyze 6.1.0 + nassl 5.4.0 (Python, runtime) | **AGPL-3.0** | **must decide**: we import it in a networked service, so AGPL §13 applies. Either license CAWASMA under AGPL-3.0 (compatible, source already public), or drop SSLyze for the `ssl` fallback that `core/tls.py` already has |
| cvss 3.6 | LGPL-3.0+ | fine (imported unmodified) |
| pyphen (WeasyPrint dependency) | GPL-2+/LGPL-2+/MPL-1.1, our choice | fine under MPL/LGPL |
| certifi | MPL-2.0 | fine |
| 17 Python packages reported UNKNOWN | permissive (MarkupSafe, idna, click, anyio, pillow …: BSD/MIT/HPND) | metadata only (`License-Expression`); fine |
| 341 npm production packages | 288 MIT, 21 ISC, 12 Apache-2.0, BSD, BlueOak, 0BSD | fine |
| sharp's libvips (npm, Next image optimisation) | LGPL-3.0+ | fine (dynamically linked prebuilt library) |
| caniuse-lite (npm) | CC-BY-4.0 | fine (data; attribution in NOTICE) |
| all-MiniLM-L6-v2 (baked into the image) | Apache-2.0 | fine |
| en_core_web_sm 3.8.0 | MIT | fine |
| Geist / Geist Mono (next/font/google) | SIL OFL 1.1 | fine; note it's fetched from Google at build time |
| DejaVu fonts (fonts-dejavu-core, PDF reports) | Bitstream Vera / DejaVu licence (permissive) | fine |
| `backend/app/data/wordlist.txt` | our own (26 well-known paths) | fine |
| Eval targets (Juice Shop MIT, DVWA GPL-3.0, VAmPI MIT, crAPI Apache-2.0), ZAP Apache-2.0, Nuclei MIT, nuclei-templates MIT | pulled at run time, not shipped | fine |
| `eval/labels/*.csv`, ground truth, priority files | ours (paths are public facts about the targets) | fine |
| `docs/screenshots/*.png`, demo video | ours (recorded by Playwright) | fine |

**deptry** (unused or undeclared Python dependencies): 19 reports, nearly all
false positives:

- loaded indirectly: `asyncpg` by URL, `greenlet` by SQLAlchemy, `h2` by httpx,
  `python-dotenv` by pydantic-settings, `preshed` as a version pin for spaCy,
  and `en-core-web-sm`;
- dev tools: pytest, ruff, mypy, respx, aiosqlite;
- eval-only extras: scikit-learn, pandas, matplotlib.

The one real item is `scripts/reset.py`'s fallback `from seed import seed`,
which is dead when run as `python -m scripts.reset`.

## Proposals for Phases 2–4 (waiting for your go-ahead)

**Phase 2: fix.** Atta's files on `atta/p11-final-audit`; other owners'
files on `atta/fix-<name>-p11-<topic>`.

0. Free disk space (your decision) and re-run the clean-machine check. In
   `docker-compose.yml`, give only `api` a `build:` and let `worker` and
   `demo-target` use the image it builds, so one image is built once; make
   the script name the step that failed.

1. Commit the 30 prompts under `docs/prompts/` (`atta.md` from our sessions,
   `asim.md`, `neelam.md` moved from `docs/project/`).
2. Licence:
   - add `LICENSE` (AGPL-3.0 recommended, because of SSLyze) and a `NOTICE`
     listing shadcn/ui, MSW, caniuse-lite, the model and the fonts;
   - set `license` in `pyproject.toml` and `package.json` (frontend:
     `atta/fix-neelam-p11-license`).
   - Needs your decision: AGPL, or drop SSLyze.
3. Fix SEC-01..07 and SEC-09 with the existing failing tests, removing each
   `known_issue` marker as it passes.
4. Vector conflict:
   - make the catalog read the base vector from `checks.yaml` for the 21
     shared ids, so one id has one vector, with a test that fails on
     disagreement;
   - for the 31 catalog `base_score` values, drop the field and derive it
     from the vector.
5. Fire/no-fire tests for the 28 legacy checks, and extend the guard test to
   legacy rules.
6. Replace the Stripe-shaped and made-up AWS test values with `cawasma-fake-…`
   values, and add `.gitleaks.toml` allow-listing `backend/tests/fixtures/`.
7. Correct the stale CLAUDE.md lines (section 3).
8. Asim's side, for him to review: `atta/fix-asim-p11-sensitivity` with his
   Prompt 6 (anchor sets in `config/sensitivity_anchors.yaml`, `eval_sensitivity`
   on the existing split). Or record it as not done in the report, if he
   prefers to do it himself.

**Phase 3: remove.** Candidates (each listed in its commit message before deletion):

- the deprecated pre-contract routes and the WebSocket. Neelam's app doesn't
  call them: `frontend/src` has no reference outside the generated schema (to
  confirm with her);
- `docs/04-api-reference.md` (it documents only those routes);
- the `reset.py` fallback import;
- vulture results after (1);
- `eval/harness/proposed_anchors.json` (the experiment showed anchors don't
  change classes);
- `reviews/` moved to `docs/reviews/`;
- check `.gitignore` covers `__pycache__/`, `eval/results/raw/`,
  `eval/.cache/`, `eval/.run/`, `frontend/test-results/`, `playwright-report/`
  and `demo-output/`.

**Phase 4: read like ours.**

- Run `ruff format` once (161 files) in its own commit, so the diff is
  mechanical and easy to review.
- Then the comment, docstring and naming pass: the catch-all `utils/` split
  by purpose, banner comments removed.
- Then the docs wording pass.

## Phase 2 results (2026-11-05)

On `atta/p11-final-audit` (Atta's files):

| Proposal | Outcome | Commit |
|---|---|---|
| 0 disk, one image build, failing step named | done. Freed 17 GB of build cache; `api` builds the image and `worker`/`demo-target` reuse it. The re-run found two more bugs, both fixed: the fixed network name `cawasma-backend` let the check's stack join the dev stack's network (two `postgres` hosts), and `grep -q` + `pipefail` turned a found scan id into a failure. **The clean-machine check now passes from a fresh clone of this branch.** | 5aeb12e, 82cf2ba, 70f3ca3 |
| 1 prompts in `docs/prompts/` | done: `atta.md` (10 prompts + review, fix, final pass), README pointing to Asim's and Neelam's (they stay in `docs/project/`, which `import.sh` regenerates) | 2464655 |
| 2 licence | **deferred** at Atta's request until after the presentation | — |
| 3 SEC-01..07, SEC-09 | done, test first (the strict xfails). `tests/security`: 164 passed, 0 xfailed. New `api/limits.py` (shared scan rate limit, SSE cap) | 6d165bb |
| 4 vector conflict | done in two parts: legacy findings for an id with a spec use the spec's vector (here, 6e93e62); the catalog itself is aligned on Asim's branch | 6e93e62 |
| 5 fire/no-fire for legacy rules | done: 42 of 42 legacy rules, guard extended; `make check-coverage`: 62 of 62 checks with fire and no-fire tests, all passing | 2e61771 |
| 6 fake secrets, `.gitleaks.toml` | done: `gitleaks git` reports no leaks; one docstring in Asim's file is on his branch | c24f7ef |
| 7 stale CLAUDE.md lines | done (Neelam's line about `docs/04-api-reference.md` is left for Phase 3, with the deprecated routes) | b05dbb9 |

For the other owners (each on its own branch, pushed to origin, for review):

| Branch | Owner | What | Merge order |
|---|---|---|---|
| `atta/fix-asim-p11-catalog-vectors` | Asim | catalog.py takes the checks.yaml vector for the 16 conflicting ids; `base_score` computed from the vector; `validate-config` fails on disagreement | 1 |
| `atta/fix-neelam-p11-fixtures` | Neelam | the MSW fixture copy and 5 unit tests for the new example scores (based on the branch above) | 2, with 1 |
| `atta/fix-neelam-p11-security-headers` | Neelam | SEC-08: CSP (`frame-ancestors 'none'`, ...), nosniff, Referrer-Policy, X-Frame-Options | any |
| `atta/fix-asim-p11-sensitivity` | Asim | Prompt 6: anchor classifier, `config/sensitivity_anchors.yaml` (`enabled: false`), `eval_sensitivity.py`; test split accuracy 0.522 vs 0.425 | any |
| `atta/fix-asim-p11-fake-secrets` | Asim | the AWS-shaped docstring example | any |
