# CAWASMA — Context-Aware Web & API Security Misconfiguration Analyzer

Final-year project. Defensive, black-box, HTTPS-only scanner for web apps and
REST APIs. The point is **prioritisation, not detection**: the same
misconfiguration is scored differently depending on where it occurs and what
the endpoint returns. Background and design are in `docs/` (start with
`docs/README.md`); `docs/06-scoring-model.md` and `docs/08-database-schema.md`
are the data and scoring references.

## Project goal: context-aware CVSS v3.1 scoring

1. Each of the 58 checks carries a fixed **CVSS v3.1 base vector** and base score
   (`backend/app/core/checks/catalog.py`). These are never invented per scan.
2. Each endpoint gets a **sensitivity class** (CRITICAL/HIGH/MEDIUM/LOW) from NLP
   over its URL path (`core/sensitivity.py`, optional LLM abbreviation expansion
   in `services/llm.py`).
3. Each response body is scanned for **sensitive-data signals**: credentials, PII,
   financial data, internal IPs (`core/body_classifier.py`, redacted evidence).
4. The base score is **recomputed through CVSS v3.1 environmental metrics**
   (CR/IR/AR security requirements and modified base metrics), driven by (2) and
   (3), giving the context-aware score and severity.
5. Findings are correlated into attack chains (`core/chains.py`), which are stored
   as separate records with their own composite score.

> **Current state vs goal:** (4) is implemented in `core/cvss.py`
> (`environmental_score` / `score_finding`, using the `cvss` library and
> `config/cvss_mapping.yaml`). The pipeline scores spec-registry checks
> (`core/checks/spec/`, today HDR-001 and TLS-009) that way and stores
> `final_vector` + `score_reasons`; the legacy `@rule` checks still use the
> interim formula `min(10, base × context_multiplier + response_bonus)`
> (docs/06) until each moves to the registry. Keep the official base score and
> the context-aware score in separate columns, as the `findings` table does.

## Team and file ownership

| Who | Area | Owns |
|-----|------|------|
| **Atta** | Backend & scanner engine | `backend/` except the paths owned by Asim below; `config/`; root infra (`docker-compose.yml` except the frontend service, `Makefile`, `.github/`) |
| **Neelam** | Frontend (Next.js) | `frontend/`, the `frontend` service in `docker-compose.yml`, the `frontend` CI job |
| **Asim** | Check specs, CVSS mapping, ML, evaluation | `backend/app/ml/`, `backend/app/core/checks/catalog.py` (rule specs + CVSS v3.1 vectors), `config/checks.yaml`, `config/cvss_mapping.yaml`, `config/chains.yaml`, `docs/05-security-checks.md`, `eval/`, `docker-compose.eval.yml` |

**Rule: nobody edits another person's files without asking first.** That
includes Claude sessions. If a change needs to touch someone else's area, stop
and ask the owner (or leave a note in the PR) instead of editing. Ownership is
also declared in `.github/CODEOWNERS`, so the owner is requested as reviewer.

Adding a check spans two owners: Asim adds the catalog entry (spec + vector),
Atta adds the detection function and its unit test.

The current `frontend/` is a React + Vite SPA. Neelam's Next.js app replaces it
in the same compose slot.

## Branches and pull requests

- Branch names: `<name>/pNN-topic`, e.g. `atta/p01-repo-setup`,
  `neelam/p03-scan-dashboard`, `asim/p02-cvss-mapping`. `<name>` is one of
  `atta`, `neelam`, `asim`; `NN` is the two-digit phase number; `topic` is
  lowercase kebab-case. CI fails PRs from branches that don't match.
- No direct pushes to `main`; open a PR using `.github/pull_request_template.md`.
- One topic per PR. CI must be green before merging.

## Atta: backend & engine

Owned files:

- `backend/app/core/engine.py`: async httpx engine (limits, redirects, SSRF re-check per hop)
- `backend/app/core/crawler.py`: endpoint discovery (seed, HTML, JS, wordlist, recursive)
- `backend/app/core/checks/` (except `catalog.py`): detection functions, one module per category
- `backend/app/core/cvss.py`: scoring
- `backend/app/core/reports.py`: JSON/CSV/HTML/PDF renderers (DB-free); data assembly in `services/report_service.py`
- FastAPI app: `backend/app/main.py`, `backend/app/api/`
- Celery: `backend/app/workers/`
- DB: `backend/app/db/` (models, session), `backend/migrations/`, `backend/scripts/` (seed, reset).
  Schema reference: `docs/schema.md`; decisions: `docs/db-decisions.md`

Notes:

- Next up: move the remaining legacy `@rule` checks to the spec registry so
  every finding gets an environmental score (see "Current state vs goal").
- `POST /api/scan` runs scans as a FastAPI background task in the api process;
  the Celery worker only serves the deprecated `POST /api/scans` for now.
- An unreachable target raises `pipeline.ScanError` and the scan is FAILED; only
  `ScanError` messages are shown to users.
- Scans started by `POST /api/scan` carry `options.runner = "api"`; at start-up the
  api marks those still QUEUED/RUNNING as FAILED (they died with the old process).
- Legacy `@rule` findings take their base score from the catalog vector, not the
  catalog's `base_score` (31 entries disagree; `make validate-config` lists them).

## Neelam: frontend

Stack: Next.js 16 (App Router, `src/` dir), React 19, TypeScript strict,
Tailwind CSS v4, shadcn/ui (`base-nova` style on Base UI, `lucide-react` icons).
Node >= 22 (shadcn's `cn` package requires it). Next 16 differs from older
Next.js: check `frontend/node_modules/next/dist/docs/` before relying on
remembered APIs (see `frontend/AGENTS.md`).

Owned files:

- `frontend/` (all of it): app code in `src/app/`, shadcn components in
  `src/components/ui/` (add with `npx shadcn@latest add <name>`), helpers in `src/lib/`
- `frontend/Dockerfile`: multi-stage, `output: "standalone"`, runs as non-root uid 1001
- The `frontend` service in `docker-compose.yml`
- The `frontend` job in `.github/workflows/ci.yml`

Run (from `frontend/`):

```bash
npm ci                 # install (lockfile is npm 10-compatible; keep it that way)
cp .env.example .env.local
npm run dev            # dev server on http://localhost:3000
npm run build && npm start   # production build, standalone server (honours PORT)
```

Tests and checks (from `frontend/`):

```bash
npm test               # Vitest + React Testing Library (src/**/*.test.ts(x)), single run
npm run test:watch     # Vitest watch mode
npx playwright install chromium   # once, for e2e
npm run test:e2e       # Playwright (e2e/); builds and serves on :3100
E2E_BASE_URL=http://localhost:3000 npm run test:e2e   # against a running app
npm run lint           # ESLint (next core-web-vitals + typescript, prettier-compatible)
npm run format         # Prettier write (format:check in CI)
npm run typecheck      # next typegen && tsc --noEmit
npm run gen:api        # regenerate src/lib/api-schema.ts from docs/openapi.json
```

API layer (`src/lib/`): `api.ts` is the typed client (`createScan`,
`getResults`, `getExportUrl`); it returns `ApiResult`s and never throws
(errors are `network` / `client` 4xx / `server` 5xx). Contract types are in
`api-types.ts` over the generated `api-schema.ts` (never hand-edit that one).
Components fetch through the TanStack Query hooks in `queries.ts`. The MSW
mocks are in `src/mocks/`: fixtures copied from `docs/examples/` (a test
fails if they drift) and a simulated scan that goes QUEUED -> RUNNING -> DONE
in about 10 s.

Docker: `docker compose --profile frontend up -d --build` serves the app on
http://localhost:3000 (`FRONTEND_HOST_PORT`) alongside the api on :8000.

Env vars (read only through `src/lib/env.ts`):

- `NEXT_PUBLIC_API_URL`: api as the **browser** reaches it. Inlined at build
  time, so in Docker it is a build arg; changing it needs a rebuild.
- `API_INTERNAL_URL`: api as the Next.js **server** reaches it
  (`http://api:8000` in compose). Read at runtime.
- `NEXT_PUBLIC_USE_MOCK`: `true` serves every API call from the MSW fixtures
  (browser and server), so no backend is needed. Build-time like the URL.

The api's CORS allow-list (`FRONTEND_ORIGIN`, default `http://localhost:5173`)
must include `http://localhost:3000` for browser calls from this app.

Conventions:

- Server Components by default; add `"use client"` only where interactivity needs it.
- Consume the REST/report JSON with the field names in `docs/04-api-reference.md`
  (`rule_id`, `cvss_base_score`, `cawasma_final_score`, ...); don't rename on the client.
- Unit tests sit next to the code (`*.test.tsx`); e2e specs go in `e2e/`.
- Lockfile: if you install with npm 11, re-run `npx npm@10 install` before
  committing, or `npm ci` fails in Docker/CI (Node 22 ships npm 10).

## Asim: specs, CVSS mapping, ML, evaluation

Asim owns:

- `config/checks.yaml`
- `config/cvss_mapping.yaml`
- `config/chains.yaml`
- `backend/app/ml/sensitivity.py`
- `backend/app/ml/body_classifier.py`
- `eval/` (targets, ground truth, labelled data, harness, results)

## Layout

```
backend/app/
  core/      DB-free scanner logic: engine, crawler, checks/, cvss, reports,
             sensitivity + body classifiers, chains, tls, pipeline
  api/       routes/ + schemas/ (Pydantic). Never return ORM objects.
  db/        base (JSONType), session (engine, SessionDep), models/
  workers/   celery_app.py, tasks.py (cawasma.run_scan)
  ml/        sensitivity.classify + body_classifier.analyze (Asim; stubs for now)
  services/  orchestration + persistence (scan_runner, result_service, ...)
  utils/     validators, security (SSRF), redaction, logging
backend/migrations/   Alembic (async env; one initial migration 0001)
backend/scripts/      seed.py (sample data), reset.py (drop + migrate)
backend/tests/        unit/ integration/ api/ fixtures/
config/               shared service config (e.g. postgres init scripts)
docs/                 project documentation
eval/                 evaluation targets, datasets, scripts (Asim)
frontend/             web UI (Neelam)
```

## Conventions

- Python 3.12. Every module starts with a docstring and `from __future__ import annotations`.
- **`core/` stays database-free.** A check is a pure function
  `detect(ctx: CheckContext) -> RawFinding | None` registered with `@rule`. It
  reads only from `CheckContext`. Adding a check means a catalog entry, the
  function, and a unit test. Keep the catalog count check (58) in sync.
- Configuration comes only from `app.config.settings`; never read `os.environ` elsewhere.
- Safety rules are not negotiable: HTTPS-only targets; SSRF guard on the
  *resolved IP* for every hop (`utils/security.py`); bounded requests. Only
  GET/HEAD/OPTIONS unless a check needs a safe, non-destructive alternative.
  `allow_private` is for tests and the eval harness only.
- Redact secrets (`utils/redaction.py`) before anything is logged, stored or reported.
  Cookies store metadata, never values.
- Schema changes go through Alembic (`alembic revision --autogenerate`); never
  create tables by hand, never edit a migration that has been merged. Models must
  stay portable (SQLite tests, Postgres prod): JSON columns use `JSONType` (JSONB
  on Postgres), and cascades rely on DB `ON DELETE` rules (FKs are enforced on SQLite too).
- The REST/report JSON keeps its pre-rename field names (`rule_id`,
  `cvss_base_score`, `cawasma_final_score`, `severity`, status `COMPLETED`) for
  the frontend; map in `api/schemas/` rather than renaming (docs/db-decisions.md D2-D3).
- ML code plugs in through `app/ml/sensitivity.py` and `app/ml/body_classifier.py`
  with the types in `app/core/contracts.py`; the engine must keep working with the
  built-in classifiers when ML deps are absent.
- API errors use the envelope `{"success": false, "error": {"code", "message"}}`.
- Lint: ruff (config in `backend/pyproject.toml`, line length 100). Types: mypy must pass.
  Use a narrow `# noqa: <code> - reason` rather than disabling rules broadly.

## Commands

From the repo root:

```bash
make up        # build + start api, worker, postgres, redis; waits for healthchecks
make down      # stop (keeps DB volume)
make test      # pytest on the host (SQLite)
make lint      # ruff + mypy
make migrate   # alembic upgrade head in the api container
make seed      # sample data: 1 target, 2 scans, 10 endpoints, 16 findings, 1 chain
make reset     # drop everything in the DB, migrate, seed
make install   # pip install -e "backend[dev]" into .venv
make validate-checks   # config/checks.yaml (validate-config: + mapping, chains)
make openapi   # regenerate docs/openapi.json after any API change (CI checks it)
```

- Health: `curl localhost:8000/health` (also `/api/health`); Swagger at `/docs`.
- Contracts (frozen end of Sprint 1; changes follow their versioning rules):
  API v1 `app/api/schemas/contract.py` + `docs/api-contract.md`; ML/CVSS
  `app/core/contracts.py` + `docs/cvss-mapping-contract.md`; check specs
  `app/core/specs.py` + `docs/check-spec-format.md`. `MOCK_API=true` makes the
  contract routes return `app/api/mock.py` examples.
- Tests against Postgres (as CI does):
  `TEST_DATABASE_URL=postgresql+asyncpg://cawasma:cawasma@localhost:5446/cawasma_test make test`
  (`config/postgres/init/` creates `cawasma_test` on a fresh volume).
- Single test: `cd backend && ../.venv/bin/python -m pytest tests/unit/test_cvss.py -q`
- Faster image without the NLP stack: `INSTALL_ML=false make up`.
- Frontend: `docker compose --profile frontend up -d --build`.
- Eval targets: `docker compose -f docker-compose.eval.yml up -d` (isolated `cawasma-eval` network).
- Vertical-slice demo: `docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d --build --wait`,
  then scan `https://demo-target:8443/` (README "Demo the vertical slice").

CI (`.github/workflows/ci.yml`) has independent jobs: branch-name check (PRs),
backend lint (ruff + mypy), and backend tests (Alembic upgrade/downgrade + pytest
against a Postgres 16 service container). A commented `frontend` job is ready
for Neelam to enable.
