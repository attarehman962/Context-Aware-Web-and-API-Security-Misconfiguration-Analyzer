# Review: `asim/p04-ml-evaluation-setup` (Asim)

| | |
|---|---|
| Reviewer | Atta |
| Date | 2026-10-25 |
| Branch | `asim/p04-ml-evaluation-setup` (upstream) |
| Already merged | yes: PRs #8, #9, #10, #11, self-merged 09:27–10:58 without a reviewer |
| Reviewed range | `105fbeb..32c7380` (everything since `sprint-1`): 29 files, +1493 / −64 |
| Scope | The branch is named p04, but it contains Prompts **1** (workspace), **2** (check specs), **3** (CVSS mapping) and **5** (eval targets, ground truth, labelling) from *Asim's Claude Code Prompts*. **Prompt 4 (chain templates) is not done.** |

Because the work is already on `main`, the findings below are follow-up fixes,
not merge blockers.

## What I ran

| Check | Result |
|-------|--------|
| `ruff`, `mypy` | pass |
| `make validate-config` | pass: 23 checks, mapping, 1 chain (plus the existing catalog score warning) |
| `export_openapi.py --check` | pass: `docs/openapi.json` unchanged, so the API contract is untouched |
| pytest, SQLite and PostgreSQL | **1 failed, 185 passed**: `test_shipped_spec_files_are_valid` (row 5) |
| `docker compose up` (isolated project, branch code) | pass: api, worker, postgres, redis healthy; `/health` ok |
| Image size | 3.39 GB vs 3.05 GB before (+340 MB, row 8) |
| `docker compose -f docker-compose.eval.yml config` | valid |
| Eval host ports | **not reachable** (row 3), confirmed with a throwaway container |
| Mapping: can a score go *down* vs base? | no: 0 of 1,472 combinations (all 23 vectors × 4 classes × 16 signal sets) |
| `eval/harness/mapping_demo.py` | runs only after a manual `pip install cvss` (row 10); numbers match `docs/cvss-mapping.md` |

The eval targets themselves were not started (crAPI alone is 8 containers);
the reachability problem was confirmed independently.

## Findings

| # | Issue | File:line | Severity | Suggested fix |
|---|-------|-----------|----------|---------------|
| 1 | **Check IDs reuse catalog IDs with a different meaning.** 20 of 23 ids already exist in `catalog.py` for other checks: `HDR-001` is HSTS in the catalog but CSP here; `INF-003` is ".env exposed" but "stack trace" here; `INF-004` is ".git exposed" but "directory listing" here, and so on. The DB, seed data, mock API, API docs, `chains.py`, `chains.yaml` and stored findings all use the catalog meaning, so one `check_id` would mean two checks. | `config/checks.yaml:70` (HDR-001) … `:474` (API-002) | must fix | Keep each existing id for the *same* check (HSTS stays `HDR-001`, CSP stays `HDR-002`, …) and give new checks the next free number in their prefix (`TRN-001`/`HST-002` → e.g. `TLS-009`, `HDR-013`). If you want a renumbering, agree it with Atta first: it is a contract change plus a data migration. |
| 2 | **HDR-003 fires on every response, including `DENY`/`SAMEORIGIN`.** With `match: any`, "≠ DENY" or "≠ SAMEORIGIN" is always true. This would also distort the false-positive rate in the evaluation. | `config/checks.yaml:121-129` | must fix | `match: any` with two rules: `op: missing`, and `op: matches` with `value: "(?i)^(?!\\s*(deny\|sameorigin)\\s*$)"`. Add a ground-truth negative (a target that sends `DENY`). |
| 3 | **Eval targets are unreachable from the host.** Docker does not publish ports for containers whose only network is `internal: true` (verified), so `127.0.0.1:3001-3004` refuse connections. `collect_endpoints.py` therefore writes 0 rows, and `endpoints_raw.csv` is header-only: Prompt 5 item 3 (150–300 paths) is not delivered. | `docker-compose.eval.yml:255` (with `:22`, `:42`, `:59`, `:185`); `eval/labels/endpoints_raw.csv:1` | must fix | Keep the network internal (no egress) and run the collector **inside** it: a one-off service on `cawasma-eval` that uses service names (`http://juice-shop:3000`, …). Remove the dead `ports:` entries, or document that they don't work. |
| 4 | **Prompt 4 not done, and chain C005 is now semantically broken.** `chains.yaml` is unchanged; C005 requires `INF-003`, `HDR-007` and `INF-004`, which in `checks.yaml` now mean stack trace, Permissions-Policy and directory listing. | `config/chains.yaml:12-13` | must fix | Do Prompt 4 on its own branch (`asim/p04-chain-templates`) after row 1 is settled. |
| 5 | **The suite on `main` is red** (my test, not Asim's code). It hard-codes my two sample checks (`HDR-001`, `HDR-004`) and their catalog scores. | `backend/tests/unit/test_specs.py:44-47` | must fix (**Atta**) | Assert only that the shipped files validate and that every class and signal is mapped; don't pin sample ids or scores. |
| 6 | Collector hides failures: every connection error returns `None`, and the script exits 0 even with 0 rows. | `eval/labels/collect_endpoints.py:47`, `:120-131` | should fix | Print per-target counts; exit non-zero if a target yields nothing. Skip static assets (`.js`, `.css`, images) so the labelling set holds endpoints, not files. |
| 7 | Targets are plain HTTP, but CAWASMA only scans HTTPS targets, and its SSRF guard blocks their private IPs. Ground truth points at `http://127.0.0.1:300x`, so no eval scan can run yet. | `eval/ground_truth/juice-shop.yaml:2` (same in all 4); `docker-compose.eval.yml:11-15` | should fix | Put a TLS proxy on `cawasma-eval` (e.g. Caddy with an internal CA) and use `https://<service>` base URLs. Atta: wire `ALLOWED_INTERNAL_HOSTS` (Atta Prompt 4) for the eval profile only. |
| 8 | Eval-only libraries go into the production image: scikit-learn, pandas and matplotlib were added to `requirements-ml.txt`, which the Dockerfile installs for api and worker (+340 MB). Prompt 1 asked to keep the main image light. | `backend/requirements-ml.txt:20-22` | should fix | Move them to an `eval` extra (or `requirements-eval.txt`) that the Dockerfile doesn't install. |
| 9 | `pip install -e ".[ml]"` pulls the default CUDA build of torch (several GB) through sentence-transformers; the deleted comment explained why the CPU index is needed. The same dependencies are now listed in two places that can drift apart. | `backend/pyproject.toml:41-48` (comment removed at old `:32-33`) | should fix | Restore the comment and document `--extra-index-url https://download.pytorch.org/whl/cpu`, or keep `requirements-ml.txt` as the single source and drop the duplicates. |
| 10 | `mapping_demo.py` imports `cvss`, which no dependency file declares, so it fails on a fresh install. | `eval/harness/mapping_demo.py:12` | should fix | Add `cvss` (pinned) to the eval extra from row 8. |
| 11 | `mapping_demo.py` uses its own five vectors instead of those in `checks.yaml` (e.g. "Missing HSTS" 5.9 there vs `HST-001` 5.3), and all five are `S:U`, so the report's worked examples don't show your actual checks. | `eval/harness/mapping_demo.py:17-38` | should fix | Load the vectors from `config/checks.yaml` by `check_id`, and include at least one `S:C` example. |
| 12 | Prompt 1 item 5 (a smoke test that `.[ml]` installs and loads all-MiniLM-L6-v2 and spaCy) isn't committed. Importing the full ML stack inside the built image raised `OverflowError: Python int too large to convert to C ssize_t`; I couldn't isolate which import. | (missing test) | should fix | Commit the 3-line load test and run it in the image (`docker compose exec api python -m …`); find which library causes the error (likely a numpy ABI mismatch from the new pins). |
| 13 | Several conditions can't be coded from `http_condition` alone: the real rule lives in `limitation` prose. API-001 is "status 200/206 on every endpoint"; API-002 "auth endpoints only"; INF-005 "artifact paths only"; TRN-001 "the HTTP probe". Prompt 2 asked for conditions precise enough to code with no guessing. | `config/checks.yaml:463`, `:485`, `:421`, `:12` | should fix (joint) | Agree a format v2 with Atta: e.g. `scheme: http`, `applies_to: {sensitivity: [HIGH, CRITICAL]}`, `path_matches:`. Format changes follow the contract rules (all three agree). |
| 14 | INF-005's pattern `^[A-Z][A-Z0-9_]{2,}=` (multiline) matches any line like `FOO=bar` in any response, on every endpoint. | `config/checks.yaml:421` | should fix | Remove that alternative, or restrict INF-005 to artifact paths once row 13's `path_matches` exists. |
| 15 | INF-003's `at [A-Za-z0-9_.$]+\([^\n]+\)` matches ordinary JavaScript and prose ("at init(config)"). | `config/checks.yaml:383` | should fix | Require a frame shape, e.g. `\n\s+at \S+ \(\S+:\d+:\d+\)` repeated at least twice, or a language-specific trace header. |
| 16 | `ALLOWED_INTERNAL_HOSTS` is set on the crAPI containers, which never read it; the anchor comment says it is meant for a CAWASMA override. | `docker-compose.eval.yml:15`, `:72`, `:92`, `:113`, `:126`, `:147`, `:162`, `:187`, `:194` | should fix | Remove it from the target services; put it in a separate `docker-compose.eval-scan.yml` override for CAWASMA's api/worker. |
| 17 | Images are pinned by digest only, with no record of the version (Juice Shop, DVWA, VAmPI, crAPI 6×, postgres, mongo). | `docker-compose.eval.yml:19`, `:39`, `:56`, `:69`, … | should fix | Add the tag next to each digest (`# juice-shop:17.x.y`) so the report can cite versions. |
| 18 | Ground truth is thin: 12 entries across 4 targets, 8 of them `API-001`. Prompt 5 also asked which checks should **not** fire per target, for the false-positive rate. | `eval/ground_truth/*.yaml` | should fix | Add an entry or an explicit negative for each `checks.yaml` check on each target; keep `verification: unverified` until checked by hand. |
| 19 | Files outside Asim's area were changed without a recorded agreement: `Makefile`, `backend/Dockerfile`, `backend/pyproject.toml`, `backend/requirements-ml.txt`, `docs/03-installation.md` (Atta's). The changes themselves are reasonable (the Dockerfile cache `chown` is a real fix; the eval targets were requested), but the PRs were self-merged. | `Makefile:59-66`, `backend/Dockerfile:35`, `:56-57` | should fix (process) | Next time, ask Atta or note it in the PR. **Atta:** turn on branch protection on `main` (1 review, CODEOWNERS), since nothing enforces it today. |
| 20 | One branch carried four prompts across four PRs; team rule: one branch per prompt. | (branch) | should fix (process) | `asim/p02-check-specs`, `asim/p03-cvss-mapping`, … from now on. |
| 21 | `label.py`: an invalid key moves on instead of re-prompting, and Ctrl-D/Ctrl-C ends in a traceback. Saving after each label is good. Nothing in `eval/` has tests. | `eval/labels/label.py:55-62` | should fix | Loop until the key is valid; catch `EOFError`/`KeyboardInterrupt` and save. Add unit tests for `normalize_path` and label resume. |
| 22 | TLS 1.0/1.1, weak ciphers and invalid/expired certificates (Prompt 2) are missing: the format I wrote can't express TLS observations. You documented this correctly. | `docs/check-specs-review.md:65-72` | question (**Atta**) | Should format v2 get a `tls:` rule target, or do these stay as catalog/Python checks? |
| 23 | All 23 vectors are `S:U`. The catalog had CSP and CORS checks as `S:C`; Prompt 2 asked for "scope included". | `config/checks.yaml` (all) | question | Is `S:U` intended for HDR-001/002 (CSP) and COR-001/002? |
| 24 | `LOW = X` and `MEDIUM = M` give identical scores (CVSS treats X as M), so LOW and MEDIUM endpoints are indistinguishable; context only changes scores at HIGH and CRITICAL. | `config/cvss_mapping.yaml:10-12` | question | Intended? (I confirmed that nothing ever goes below base.) |
| 25 | `INTERNAL_IP` only raises CR to M, so it has no effect on MEDIUM-or-higher endpoints; `CREDENTIALS` and `FINANCIAL` also raise AR to M. | `config/cvss_mapping.yaml:20-26` | question | Intended? What is the justification for the AR rows? |
| 26 | CKI-002 (missing HttpOnly) scores 8.1, above CSP-missing (5.4); INF-005 and API-001 score 9.1 with `PR:N` from heuristic conditions. You already flag these as debatable. | `config/checks.yaml:259`, `:425`, `:468` | question | Keep, or adopt the alternatives listed in `docs/check-specs-review.md:50-59`? |
| 27 | API-002 has category `AUTH` but an `API-` prefix. | `config/checks.yaml:474-475` | question | Should it be `AUT-xxx`? This links to row 1. |
| 28 | The Juice Shop search endpoint is labelled `API-001` (unauthenticated sensitive data), but its cited source is the injection chapter. | `eval/ground_truth/juice-shop.yaml:6-9` | question | Is API-001 the right check for it? |
| 29 | The labelling guide puts `/users/me/profile` at MEDIUM, while the built-in classifier's HIGH anchor includes "profile". | `docs/labelling-guide.md:26` | question | Your labels become the ground truth for the classifier, so I'll align the built-in anchors to the guide unless you say otherwise. |

**Done well:** ruff, mypy, OpenAPI and the spec validators are clean, and
`docker compose up` is healthy. The mapping never lowers a score. The targets
use digest pins, loopback-only binds and an internal network with no egress.
`docs/check-specs-review.md` flags every debatable vector with an alternative
and is honest about what the format can't express. The labelling guide is
clear and consistent with the mapping. No real secrets were committed (the
crAPI credentials are the lab defaults on an isolated network). I found no
SSRF or redaction problems in the new code.

## Verdict

**Changes needed.** The work is already merged, so this means follow-up PRs:

1. Rows 1, 2 and 4: restore stable check ids, fix HDR-003, then do Prompt 4 (chains) on its own branch.
2. Row 3 (with 6, 7): make the targets reachable inside the eval network and collect the endpoint set.
3. Row 5: Atta fixes the failing test on `main` now.

The rest can follow in normal PRs. Questions 22–29 are Asim's calls, except
22, which is Atta's.
