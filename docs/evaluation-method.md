# Evaluation method

How CAWASMA was evaluated for the report: what was scanned, where the ground
truth comes from, how findings are matched and counted, what each metric means,
and what limits the conclusions. Owner: Asim. Final tables:
[`eval/results/final/`](../eval/results/final/) (each as `.csv`, `.md`, `.png`).

## Targets and tools

Four deliberately vulnerable applications, each pinned by image digest in
`docker-compose.eval.yml`. They run on the isolated `cawasma-eval` network (no
internet route, no published ports) and are reset (`down -v`, `up --wait`)
before every run.

| Target | Image (digest prefix) | Kind | Split |
|--------|-----------------------|------|-------|
| DVWA | `vulnerables/web-dvwa@sha256:dae203fe` | PHP web app | dev |
| VAmPI | `erev0s/vampi@sha256:7ba0b0a8` | Flask REST API (OpenAPI) | dev |
| OWASP Juice Shop | `bkimminich/juice-shop@sha256:31871440` | Angular + Node API | test |
| OWASP crAPI | `crapi/crapi-{web,identity,community,workshop}` (pinned) | microservice REST API | test |

| Tool | Version | Mode |
|------|---------|------|
| CAWASMA | `main` at e49dd83 + this branch's tuning | depth 2, wordlist on, active probes (`eval/harness/run_all.py`) |
| ZAP | 2.15.0 (`zaproxy/zap-stable@sha256:8dc78e39`) | baseline scan; VAmPI: API scan in safe mode |
| Nuclei | v3.9.0 (`projectdiscovery/nuclei@sha256:66b5f88c`), templates v10.1.1 | the template set in `run_all.py`, `-no-mhe` |

All three targets serve plain HTTP, and CAWASMA scans HTTPS only. The harness
therefore puts an nginx TLS front (`nginx:1.27.3-alpine`) with a CA generated per
run in front of each target, and CAWASMA trusts that CA (`SCAN_CA_BUNDLE`), so
certificate verification stays on. ZAP and Nuclei scan the targets directly.

Runs: CAWASMA 2026-11-04 15:14 (before tuning) and 15:22 (after tuning); ZAP and
Nuclei 2026-10-27 13:39. ZAP and Nuclei were not re-run: their versions,
templates and target digests are unchanged, so their raw outputs still describe
the same targets.

## Dev and test split

Decided before any tuning and kept fixed:

- **dev = DVWA + VAmPI**: errors here may be studied and used to choose changes.
- **test = Juice Shop + crAPI**: reported, never used to choose a change.

The split is by target, not by row, so a change can't learn a target's naming
style from one half of its endpoints and be scored on the other half. The same
split applies to the scanner metrics and the classifier labels.

## Ground truth

**Detection** (`eval/ground_truth/<target>.yaml`, format in its README):

- `known_issues` list what CAWASMA should find (`present`) and endpoint-level
  true negatives (`absent`).
- `must_not_fire` lists checks that must not fire anywhere on the target.
- Starter entries came from each project's official documentation, checked
  against a passive observation of the pinned image (`observe.py`: status,
  security headers, cookie attributes; never cookie values or bodies).
- Check ids come from `config/checks.yaml` only.
- During tuning, the pre-tuning CAWASMA findings on the **dev** targets were
  hand-checked. Four were clearly wrong and are labelled `absent` (VAmPI:
  API-001 on `/`, `/books/v1` and `/openapi.json`; API-003 on `/openapi.json`).
  The other two clear false positives are legacy-only checks with no
  `checks.yaml` id (HDR-011, API-013), so they can't be labelled. They are
  counted separately below.

**Priority order** (`eval/ground_truth/priority_<target>.yaml`, ranking experiment):

- Each `present` issue gets a grade: 3 = fix first (critical), 2 = high,
  1 = medium.
- The grade is the issue type's impact tier plus 1 when the endpoint's *hand
  label* is HIGH or CRITICAL, capped at 3. Impact tiers: 3 = direct exposure of
  data or secrets, 2 = weakens auth, session or transport, 1 = missing hardening
  (`IMPACT` in `eval/harness/ranking.py`).
- Neither input comes from CVSS or from CAWASMA, so the reference doesn't
  favour either ranking under test.
- The files are drafts (`status: draft`) for a human to re-order.

**Endpoint sensitivity** (`eval/labels/endpoints_labelled.csv`):

- 164 unique paths over the four targets, labelled LOW/MEDIUM/HIGH/CRITICAL by
  `docs/labelling-guide.md`, without looking at the classifier's output.
- One rule was added for a case the guide doesn't cover: operational and
  diagnostic exposure (phpinfo, `/metrics`, logs) is HIGH, while configuration,
  key management and admin with secrets are CRITICAL.
- Distribution: 52 LOW, 56 MEDIUM, 36 HIGH, 20 CRITICAL (dev 51, test 113).
- One rater, a first pass (`labeler: draft`). A second rater on the guide's
  50-path sample (Cohen's kappa) is still to do.

## Matching rules

Implemented in `eval/harness/evaluate.py`, unit-tested in
`backend/tests/eval/test_harness.py`.

- **Endpoint rule:** a URL becomes its path only (no scheme, host, query or
  fragment), percent-decoded, with ID-like segments (digits, UUIDs, Mongo ids,
  `{x}`, `:x`) replaced by `:id`.
- **Host-level findings** (`*`, e.g. TLS or HSTS) match a ground-truth entry
  on `/`.
- **ZAP and Nuclei** rules are mapped to CAWASMA check ids through
  `eval/harness/tool_mapping.yaml`; an unmapped rule is *out of scope*
  (reported, not scored).
- **Coverage:** a tool is scored only on the check ids its mapping can produce.
  Entries it can't detect are *not covered*: they count neither for nor against
  it.

## Metrics

- **TP:** a `present` entry some finding matches. **FN:** a `present` entry no
  finding matches.
- **FP:** a finding that matches an `absent` entry, or fires a `must_not_fire`
  check. **TN:** an `absent` entry or `must_not_fire` check with no finding.
- **precision** = TP / (TP + FP), **recall** = TP / (TP + FN),
  **FPR** = FP / (FP + TN). Totals are micro-averaged (counts summed over
  targets).
- **unlabelled:** findings matching no entry at all, neither right nor wrong
  by the ground truth. Most CAWASMA findings fall here (e.g. a missing header on
  every page): a label exists for one page per issue, not for every page.
- **scan time:** wall time from submitting the scan to the result, per target.
- **classifier:** accuracy, macro-F1 over the four classes, per-class recall,
  the confusion matrix, and *off by two or more* (e.g. LOW predicted for a HIGH
  path), the costly kind of error (`eval/harness/classifier_eval.py`).
- **NDCG@10:** findings ranked by `base_score` (before) or by `final_score`
  (after). Gain is (2^grade − 1) for the first finding matching each priority
  item; duplicates and unmatched findings get 0. The result is normalised by the
  ideal order of the priority items.
- **rank of the first critical finding:** the position of the first finding
  that matches a grade-3 item ("–" if no finding does).
- **ties:** base scores tie heavily, and a fixed tie-break would decide the
  result. Both rankings are therefore averaged over 1,000 random tie-breaks
  (seed 13) (`eval/harness/ranking.py`).

## Tuning pass

Studied on dev only:

1. **False positives:** on the pre-tuning run, the dev findings were
   hand-checked by check id. Two causes lay in code Asim owns, and both were
   fixed:
   - `app/ml/sensitivity.py`: static assets are LOW (`/dvwa/css/login.css` had
     been classed sensitive because of "login", which raised HDR-011).
   - `app/ml/body_classifier.py`: `example`/`examples`/`default` values inside
     an OpenAPI or Swagger document are not scanned (VAmPI's spec carries a
     sample JWT and sample emails, which raised API-013).

   Both have tests in `backend/tests/ml/test_tuning.py`.
2. **Anchors:** guide-aligned anchor phrases changed nothing on dev, because in
   `core/sensitivity.py` the keyword families decide the class and the
   embeddings only set the confidence.
3. **Keyword families:** a family set built from the dev errors and the
   guide's examples (`eval/harness/proposed_families.json`) was measured on
   dev, then reported **once** on test. It is a proposal for Atta, whose file
   holds the shipped families; it is not shipped.
4. **Not done, by design:**
   - Juice Shop's serve-index listing pattern for INF-002, and crAPI's
     `/identity/` prefix (which pushes every crAPI route to CRITICAL), were both
     seen on the test targets, so neither was tuned for.
   - The INF-003/004/005 specs could be tightened (2xx status, file content
     rather than names), but those checks still run as legacy rules, so a spec
     change wouldn't change a scan. They are proposed in `docs/check-coverage.md`
     terms instead.

## Results (summary)

The full numbers are in `eval/results/final/`.

- **Detection, all four targets:**

  | Tool | Precision | Recall | FPR | Mean scan time |
  |------|-----------|--------|-----|----------------|
  | CAWASMA | 0.857 | 0.727 | 0.085 | 5 s |
  | ZAP | 1.0 | 0.286 | 0 | 20 s |
  | Nuclei | 1.0 | 0.765 | 0 | 101 s |

  ZAP and Nuclei are scored on fewer, mostly header-level entries (coverage
  rule), so compare per check rather than across these totals. CAWASMA's 4 FPs
  are the newly labelled VAmPI API-001/API-003 cases, which need spec scoping
  in `core/specs.py`.
- **Tuning:**
  - dev: the two targeted FPs are gone (unlabelled findings 149 → 147);
    labelled dev metrics are unchanged (precision 0.8, recall 0.889, FPR 0.19).
  - test: every finding is identical before and after.
- **Classifier:**
  - shipped: accuracy 0.425 and macro-F1 0.362 on test (dev 0.392 / 0.297);
    MEDIUM and HIGH paths are often over-predicted as CRITICAL (22 and 13 of 40
    and 24 on test).
  - proposed families: test 0.487 / 0.454 (dev 0.569 / 0.577).
- **Ranking:** the context-aware score ranked better than the base score on
  every target where CAWASMA found a critical item:

  | | Base score | Context-aware |
  |-|-----------|---------------|
  | Mean NDCG@10 | 0.260 | 0.304 |
  | Mean rank of the first critical finding | 2.7 | 1.27 |

  On Juice Shop both are 0: none of its 6 critical priority items was found
  (recall), so ranking can't help there.

## Anchor classifier (Prompt 6, proposed, off by default)

Built on `atta/fix-asim-p11-sensitivity` for Asim to review. `app/ml/sensitivity.py`
has an embedding classifier: the path becomes text ("GET api user accounts
password reset"), all-MiniLM-L6-v2 compares it with each class's anchor phrases
in `config/sensitivity_anchors.yaml`, and the best class wins (below the
threshold: MEDIUM). `enabled: false` in that file keeps the keyword classifier
that every table above was produced with.

`eval/harness/eval_sensitivity.py`, same split by target. Tuned on dev only
(general changes: an empty path reads as "home page", a few abbreviations, anchors
for diagnostics, command execution and database control from the labelling
guide; nothing for DVWA's module names), then run once on test:

| | dev accuracy | dev macro-F1 | test accuracy | test macro-F1 | test off by two or more |
|-|-|-|-|-|-|
| keyword classifier (shipped) | 0.392 | 0.297 | 0.425 | 0.362 | 34 of 113 |
| keyword families proposal (above) | 0.569 | 0.577 | 0.487 | 0.454 | |
| anchor classifier | 0.627 | 0.643 | 0.522 | 0.518 | 9 of 113 |

Confusion matrices: `eval/results/sensitivity_{dev,test}_confusion.png`. On test
the anchors are weakest on LOW (recall 0.31: 25 of 39 LOW paths read as MEDIUM)
and CRITICAL (recall 0.3: 5 of 10 read as MEDIUM). HIGH is the strongest class
(recall 0.79, the keyword classifier 0.13). Turning it on changes every scan's sensitivity classes, so the detection
and ranking tables would have to be re-run before they could be reported with it.

## Threats to validity

- **Sample size:**
  - The ranking experiment rests on 4 targets with 6–10 priority items each,
    and one of the four has no critical item found at all. Every
    ranking-experiment number is descriptive: no significance test is meaningful
    at n = 3–4, and none is claimed. "Better on 3 of 3 targets" is the honest
    form of the result.
  - The classifier test set is 113 paths from two applications. A difference of
    about 0.06 in accuracy is within what a different pair of apps could move.
- **Ground truth:**
  - The ground truth was drafted by one person and is mostly `unverified`. The
    labels and priority grades are a single rater's first pass, with no
    inter-rater agreement yet.
  - The four dev `absent` entries were added after seeing CAWASMA's output, on
    dev only, and both runs are scored against them. This lowers CAWASMA's
    measured precision; it never raises it.
- **Coverage asymmetry:** ZAP and Nuclei are scored only where their mapping
  reaches, and CAWASMA on every entry. Their perfect precision is over a smaller,
  easier set.
- **Unlabelled findings:** most CAWASMA findings (about 1,200 of 1,250) are
  unlabelled, so precision covers labelled findings only. The dev hand-check
  found 6 clear FPs among 153 unlabelled dev findings; the rest were plausible.
  Test findings were not hand-checked (no tuning there).
- **Stale baselines:** ZAP and Nuclei outputs are a week older than CAWASMA's.
  The images, templates and targets are pinned and identical, but the runs were
  not simultaneous.
- **TLS front:** CAWASMA sees the targets through nginx, which adds its own
  `Server` header and may change redirects. The ground-truth header entries were
  observed on the targets directly.
- **Lab targets:** deliberately vulnerable apps exaggerate some issues (every
  header missing) and lack others (no real users, no production TLS). Results
  describe these four apps, not the web at large.
