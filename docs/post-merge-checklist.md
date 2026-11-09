# Post-merge checklist (final pass, November 2026)

Steps to do on `main` after the final-pass branches are merged, so nothing is
forgotten. Tick each one in the PR that does it.

## Status (2026-11-06)

All final-pass branches are merged (#53–#74). Two web conflict resolutions had
broken `main`; #65 (backend: `validate-config` crashed, API-001 catalog vector,
formatting) and #66 (frontend fixture) repaired them, and #67 fixed the PostgreSQL
test job that had failed since 4 November. The five specs from #56 were approved
in #70.

**Rule from this:** don't resolve conflicts in generated files (`docs/openapi.json`,
`docs/examples/*.json`, `frontend/src/lib/api-schema.ts`, fixtures) in the GitHub
web editor. Merge locally, regenerate (`make openapi`, `npm run gen:api`, re-copy
the fixtures) and run the tests before pushing.

## Whenever docs/examples changes: Neelam's fixtures

Any change to scoring, vectors or the contract changes `docs/examples/*.json`.
The frontend's fixture copies must match, or `src/mocks/fixtures.test.ts` fails
(done for this pass in #64 and #66).

- [ ] Regenerate the examples and API types, then copy the examples:

  ```bash
  make openapi
  cd frontend && npm run gen:api
  for f in ../docs/examples/*.json; do b=$(basename "$f")
    [ -f "src/mocks/fixtures/$b" ] && cp "$f" "src/mocks/fixtures/$b"; done
  npx prettier --write src/mocks/fixtures src/lib/api-schema.ts
  npm test
  ```

- [x] Update the score tests that read the example values (done in #64 and #66;
  next time, the failures name them). This pass they were:
  - `src/lib/findings.test.ts`, "measures the severity shift from the base rating":
    the expected shift per check and the up/down counts;
  - `src/lib/score-story.test.ts`, "names the context and says it is the interim
    formula": API-003 is environmental now, so this test needs a legacy finding
    (TLS-001 is the only legacy finding left in `results-done.json`, and its
    score doesn't move; HDR-012 in `src/mocks/fixtures.ts` is legacy and lowered
    by context, or build one inline);
  - `src/components/results/findings-panel.test.tsx`, "shows each row's rank…" and
    "colours the band and badge…": ranks, and which row changes band;
  - `src/components/results/scan-summary.test.tsx`, "shows target, time, counts
    and the context shift": the critical count and "moved up / down" counts;
  - `findings-panel.test.tsx`, "badges every legacy-scored row…": API-003 is no
    longer legacy after #56.
- [ ] `npm run lint && npm run typecheck && npm test && npm run test:e2e`.

## After every merge

- [ ] `make lint` (includes `ruff format --check`), `make test`, `make validate-config`.
- [x] Run `ruff format` on Asim's files (`backend/app/ml/`,
  `backend/app/core/checks/catalog.py`) and remove the `[tool.ruff.format]`
  exclude from `backend/pyproject.toml` (#71).
- [ ] `make check-coverage` and commit `docs/check-coverage.md` if it changed.
- [ ] Clean-machine check from `main`: `REF=main bash scripts/clean_machine_check.sh`.

## The report figures (once, on `main`)

- [ ] `make coverage-stats` on a clean `main` checkout. Its first line must say
  `on main @ <commit>` with no "(uncommitted changes)"; put that commit next to
  the figure in the report.
- [ ] Ranking experiment: once Asim has graded
  `eval/ground_truth/priority_pool_<target>.csv` (`GRADING.md`), re-run

  ```bash
  python eval/harness/ranking.py --scoring environmental --run 20261105T050013Z --out eval/results/final
  ```

  and update the ranking section of `docs/evaluation-method.md` with the
  `ndcg10_pool_*` columns.
- [x] Evaluation re-run on `main` after #56 and #58 (run `20261105T050013Z`, #72);
  the pools were refreshed from it. If detection logic changes again, re-run
  (`make eval`, then `final_tables.py`) before quoting detection numbers.

## Open decisions, not code

- [ ] Dependency licences, **before submission**: SSLyze and nassl are AGPL-3.0
  (every other Python and npm package, ML stack included, is permissive or weak
  copyleft). Either license CAWASMA as AGPL-3.0 or drop SSLyze for the `ssl`
  fallback in `core/tls.py`. The project's own licence text can follow after the
  presentation.
- [ ] `docs/check-triage.md`: Asim and Atta confirm SPEC / MERGE / DROP before
  any spec is written or check deleted.
- [ ] API-003 base vector: 9.1, or 7.5 (C:H/I:N); see the note in `checks.yaml`.
- [ ] Branch protection on `main`, run by Asim (repo admin). With one owner per
  area, a PR touching only its author's files can't get a code-owner approval, so
  either add a second owner per area in `.github/CODEOWNERS` or set
  `enforce_admins` to `false` first.

  ```bash
  gh api -X PUT \
    repos/Asimshakeel13/Context-Aware-Web-and-API-Security-Misconfiguration-Analyzer/branches/main/protection \
    -H "Accept: application/vnd.github+json" --input - <<'JSON'
  {
    "required_status_checks": {"strict": true, "contexts": [
      "Branch name (<name>/pNN-topic or <name>/fix-<partner>-pNN-topic)",
      "Backend lint & type-check", "Backend tests (PostgreSQL)",
      "Frontend lint, type-check, test & build",
      "Frontend end-to-end on VAmPI (real stack)"]},
    "enforce_admins": true,
    "required_pull_request_reviews": {"required_approving_review_count": 1,
      "require_code_owner_reviews": true, "dismiss_stale_reviews": true},
    "restrictions": null, "allow_force_pushes": false, "allow_deletions": false
  }
  JSON
  ```
- [ ] The anchor sensitivity classifier stays `enabled: false` unless the
  evaluation is re-run with it.

## Clean-up

- [x] Delete the merged branches, local and on origin (2026-11-06).
