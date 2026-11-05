# Post-merge checklist (final pass, November 2026)

Steps to do on `main` after the final-pass branches are merged, so nothing is
forgotten. Tick each one in the PR that does it.

## Status (2026-11-05)

All final-pass branches are merged (#53–#64). Two web conflict resolutions broke
`main` and are repaired by **#65** (backend: `validate-config` crashed, API-001
catalog vector, formatting) and **#66** (frontend: the fixture from #59 came
back). Merge both, then do the rest of this list on `main`.

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
- [ ] Run `ruff format` on Asim's files (`backend/app/ml/`,
  `backend/app/core/checks/catalog.py`) and remove the `[tool.ruff.format]`
  exclude from `backend/pyproject.toml` (it was only there to avoid conflicts
  with his open branches).
- [ ] `make check-coverage` and commit `docs/check-coverage.md` if it changed.
- [ ] Clean-machine check from `main`: `REF=main bash scripts/clean_machine_check.sh`.

## The report figures (once, on `main`)

- [ ] `make coverage-stats` on a clean `main` checkout. Its first line must say
  `on main @ <commit>` with no "(uncommitted changes)"; put that commit next to
  the figure in the report.
- [ ] Ranking experiment: once Asim has graded
  `eval/ground_truth/priority_pool_<target>.csv` (`GRADING.md`), re-run

  ```bash
  python eval/harness/ranking.py --scoring environmental --run 20261104T152231Z --out eval/results/final
  ```

  and update the ranking section of `docs/evaluation-method.md` with the
  `ndcg10_pool_*` columns.
- [ ] If any detection logic changed after 2026-11-04 (it did: #56 and #58), re-run
  the evaluation before quoting detection numbers: `make eval-up`, then
  `PYTHONHASHSEED=0 python eval/harness/run_all.py --tools cawasma`, then
  `final_tables.py`.

## Open decisions, not code

- [ ] Licence (AGPL-3.0, or drop SSLyze): after the presentation (Atta).
- [ ] `docs/check-triage.md`: Asim and Atta confirm SPEC / MERGE / DROP before
  any spec is written or check deleted.
- [ ] API-003 base vector: 9.1, or 7.5 (C:H/I:N); see the note in `checks.yaml`.
- [ ] The anchor sensitivity classifier stays `enabled: false` unless the
  evaluation is re-run with it.

## Clean-up

- [ ] Delete the merged branches on origin.
