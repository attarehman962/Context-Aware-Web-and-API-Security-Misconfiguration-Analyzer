# Output comparison: CAWASMA, ZAP and Nuclei

**Data:** the evaluation run `20261105T050013Z` (5 November 2026), on commit
`5f2d60e`, all targets reset, all three tools run together. The evaluation was not
repeated for this document: between `5f2d60e` and current `main` (`4051a16`) the
scanner's code differs only in formatting and an unused `status` field on specs, so
detection and scoring are unchanged.

**Tools:** CAWASMA 1.0.0 (depth 2, wordlist on, active probes); ZAP 2.15.0 baseline
scan (VAmPI: API scan, safe mode); Nuclei 3.9.0 with templates v10.1.1.

Every table is also saved as a CSV next to this file.

## How to read these numbers fairly

- **ZAP ran in baseline mode**, which by design "doesn't perform any actual
  'attacks'". These results don't represent a full active ZAP scan.
- **ZAP and Nuclei are scored only on checks their rules map to.** *Not covered*
  counts the ground-truth entries each could not be scored on. CAWASMA is scored on
  every entry, and the ground truth uses CAWASMA's check ids, so the benchmark
  favours CAWASMA's scope.
- **The endpoint rule is strict:** a missing header reported on `/` doesn't match an
  entry on `/login.php`, which lowers ZAP's and Nuclei's recall.
- **Finding counts aren't comparable.** CAWASMA reports each check once per endpoint;
  Nuclei reports mostly once per host. More findings doesn't mean better.
- **Precision covers labelled findings only.** Most findings match no ground-truth
  entry (CAWASMA: 1,184 of 1,230), so they are counted neither right nor wrong.
- The ground truth is a single rater's first pass. Four targets are too few for any
  significance claim.

## a. Per target and per tool

`comparison-per-target.csv`, `comparison-summary.csv`

| Target | Tool | Findings | TP | FP | FN | Not covered | Precision | Recall | FPR | Scan time (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Juice Shop | CAWASMA | 603 | 4 | 0 | 5 | 0 | 1.00 | 0.44 | 0.00 | 23.4 |
| Juice Shop | ZAP | 49 | 1 | 0 | 3 | 12 | 1.00 | 0.25 | 0.00 | 324.4 |
| Juice Shop | Nuclei | 11 | 3 | 0 | 2 | 11 | 1.00 | 0.60 | 0.00 | 198.8 |
| DVWA | CAWASMA | 115 | 10 | 0 | 0 | 0 | 1.00 | 1.00 | 0.00 | 4.3 |
| DVWA | ZAP | 12 | 0 | 0 | 9 | 7 | undefined | 0.00 | 0.00 | 36.5 |
| DVWA | Nuclei | 16 | 3 | 0 | 2 | 7 | 1.00 | 0.60 | 0.00 | 102.3 |
| VAmPI | CAWASMA | 68 | 6 | 0 | 2 | 0 | 1.00 | 0.75 | 0.00 | 6.8 |
| VAmPI | ZAP | 27 | 2 | 0 | 2 | 13 | 1.00 | 0.50 | 0.00 | 24.4 |
| VAmPI | Nuclei | 13 | 3 | 0 | 0 | 14 | 1.00 | 1.00 | 0.00 | 102.6 |
| crAPI | CAWASMA | 444 | 5 | 0 | 1 | 0 | 1.00 | 0.83 | 0.00 | 7.5 |
| crAPI | ZAP | 5 | 4 | 0 | 0 | 8 | 1.00 | 1.00 | 0.00 | 32.5 |
| crAPI | Nuclei | 14 | 4 | 0 | 0 | 9 | 1.00 | 1.00 | 0.00 | 101.3 |

Averaged across the four targets:

| Tool | Findings (mean) | TP / FP / FN (total) | Not covered (total) | Precision (mean) | Recall (mean) | Recall (pooled) | FPR (mean) | Scan time (mean, s) |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| CAWASMA | 307.5 | 25 / 0 / 8 | 0 | 1.00 | 0.76 | 0.76 | 0.00 | 10.5 |
| ZAP | 23.3 | 7 / 0 / 14 | 40 | 1.00* | 0.44 | 0.33 | 0.00 | 104.5 |
| Nuclei | 13.5 | 13 / 0 / 4 | 41 | 1.00 | 0.80 | 0.76 | 0.00 | 126.3 |

\* ZAP's mean precision is over three targets: on DVWA it had no true or false
positives, so precision is undefined there.

CAWASMA and Nuclei have about the same recall, but Nuclei's is measured on 17 entries
and CAWASMA's on 33. All three show zero false positives, because a false positive
is counted only against an explicit `absent` or `must_not_fire` entry.

## b. Coverage by check category

`comparison-coverage.csv`. A cell counts `present` ground-truth entries matched.
**detected** = all, **partly** = some, **not detected** = none.

| Category | Checks in ground truth | CAWASMA | ZAP | Nuclei |
|---|---|---|---|---|
| Security headers | HDR-002..007 | detected (15/15) | partly (7/15) | partly (12/15) |
| Cookies | CKI-001..003 | detected (3/3) | not detected (0/3) | not detected (0/3; no rule mapped) |
| Information disclosure | INF-002, INF-003 | partly (3/5) | not detected (0/5) | partly (1/5) |
| API auth / rate limit / data exposure | API-001, API-003 | partly (4/10) | not detected (0/10; no rule mapped) | not detected (0/10; no rule mapped) |
| TLS | none | not measured | not measured | not measured |
| CORS | none | not measured | not measured | not measured |

TLS and CORS have no `present` entries in the ground truth, so they cannot be scored.
What the run did output for them:

- **TLS:** no findings from any tool. CAWASMA reaches the targets through our own
  nginx TLS front, so its TLS checks see that front rather than the targets; ZAP and
  Nuclei scanned the targets over plain HTTP.
- **CORS:** on Juice Shop, CAWASMA reported 166 findings (COR-001, COR-004, COR-005)
  and ZAP 11 ("Cross-Domain Misconfiguration"). Nuclei reported none. No other target
  produced a CORS finding.

## c. Three side-by-side examples

`comparison-examples.csv`. In the 46 (check, endpoint) pairs that CAWASMA shares with
ZAP or Nuclei, CAWASMA **raised 11, kept 34 and lowered 1**. The one lowered pair is
INF-006 on VAmPI's `/openapi.json` (5.3 → 3.2), under the interim legacy formula.

| | 1. Raised: same issue, sensitive endpoint | 2. Kept: same issue, public page | 3. Raised by response data |
|---|---|---|---|
| Target, endpoint | VAmPI `/users/v1/_debug` | VAmPI `/` | crAPI `/.env` |
| Issue | HDR-004: missing X-Content-Type-Options | HDR-004: missing X-Content-Type-Options | INF-003: `.env` file exposed |
| ZAP risk (confidence) | Low (Medium) | Low (Medium) | no alert on this endpoint |
| Nuclei severity | no result on this endpoint | info | high |
| CAWASMA base score | 4.3 (Medium) | 4.3 (Medium) | 9.1 (Critical) |
| CAWASMA final score | **5.0** (Medium) | **4.3** (Medium) | **9.8** (Critical) |
| Endpoint class | HIGH | LOW | LOW |
| Body signals | CREDENTIALS, PII | none | CREDENTIALS |
| Requirements | CR:H / IR:H / AR:M | CR:X / IR:X / AR:X | CR:H / IR:H / AR:M |
| Why CAWASMA moved it | sensitive endpoint returning credentials and personal data | public page, no sensitive data: the base score stands | the response holds credentials, which raises the score even though the path class is LOW |

Examples 1 and 2 are the point of the project: ZAP gives the same rating on both
endpoints, while CAWASMA separates them. The change can be modest: in example 1 the
severity label stays Medium.

## d. Ranking result, as it stands

`comparison-ranking.csv`. NDCG@10 of each ranking against the hand-written priority
list; mean over 1,000 random tie-breaks.

| Target | Environmental-scored only: base → environmental | All findings mixed: base → context | Secondary, grouped by check: base → environmental |
|---|---|---|---|
| Juice Shop | 0.001 → 0.000 | 0.000 → 0.000 | 0.633 → 0.635 |
| DVWA | 0.147 → 0.261 | 0.146 → 0.261 | 0.843 → 0.834 |
| VAmPI | 0.607 → 0.591 | 0.602 → 0.410 | 0.667 → 0.653 |
| crAPI | 0.539 → 0.535 | 0.538 → 0.535 | 0.821 → 0.808 |
| **Mean** | **0.324 → 0.347** | **0.322 → 0.301** | **0.741 → 0.733** |

The grouped view was added after the first results, as a diagnostic, and is not the
headline. The graded pools (`eval/ground_truth/priority_pool_*.csv`) have no grades
yet, so there is no pool-based NDCG.

**What it means:** on four targets, the context-aware ranking is better than the base
score only on DVWA and is otherwise equal or slightly worse, so this evaluation does
not show that it ranks better overall.
