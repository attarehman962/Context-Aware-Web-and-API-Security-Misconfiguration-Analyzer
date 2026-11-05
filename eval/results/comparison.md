# Tool comparison

- **scored**: 20261105T050013Z
- **commit**: 5f2d60e
- **CAWASMA**: api 1.0.0, {'crawl_depth': 2, 'use_wordlist': True, 'passive_only': False}
- **ZAP**: zaproxy/zap-stable:2.15.0 (baseline; VAmPI: API scan, safe mode)
- **Nuclei**: projectdiscovery/nuclei:v3.9.0, nuclei-templates v10.1.1
- **targets**: reset before the run
- **raw outputs**: eval/results/raw/<tool>/<target>/20261105T050013Z/

| tool | target | TP | FP | FN | TN | precision | recall | FPR | not covered | unlabelled | out of scope | scan time (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cawasma | juice-shop | 4 | 0 | 5 | 14 | 1.00 | 0.44 | 0.00 | 0 | 599 | 0 | 23.4 |
| cawasma | dvwa | 10 | 0 | 0 | 7 | 1.00 | 1.00 | 0.00 | 0 | 84 | 0 | 4.3 |
| cawasma | vampi | 6 | 0 | 2 | 14 | 1.00 | 0.75 | 0.00 | 0 | 62 | 0 | 6.8 |
| cawasma | crapi | 5 | 0 | 1 | 12 | 1.00 | 0.83 | 0.00 | 0 | 439 | 0 | 7.5 |
| **cawasma** | **all** | 25 | 0 | 8 | 47 | 1.00 | 0.76 | 0.00 | 0 | 1184 | 0 | 42.0 |
| zap | juice-shop | 1 | 0 | 3 | 7 | 1.00 | 0.25 | 0.00 | 12 | 10 | 25 | 324.4 |
| zap | dvwa | 0 | 0 | 9 | 1 | - | 0.00 | 0.00 | 7 | 6 | 2 | 36.5 |
| zap | vampi | 2 | 0 | 2 | 5 | 1.00 | 0.50 | 0.00 | 13 | 16 | 7 | 24.4 |
| zap | crapi | 4 | 0 | 0 | 6 | 1.00 | 1.00 | 0.00 | 8 | 0 | 1 | 32.5 |
| **zap** | **all** | 7 | 0 | 14 | 19 | 1.00 | 0.33 | 0.00 | 40 | 32 | 35 | 417.8 |
| nuclei | juice-shop | 3 | 0 | 2 | 7 | 1.00 | 0.60 | 0.00 | 11 | 2 | 6 | 198.8 |
| nuclei | dvwa | 3 | 0 | 2 | 5 | 1.00 | 0.60 | 0.00 | 7 | 3 | 10 | 102.3 |
| nuclei | vampi | 3 | 0 | 0 | 5 | 1.00 | 1.00 | 0.00 | 14 | 4 | 6 | 102.6 |
| nuclei | crapi | 4 | 0 | 0 | 5 | 1.00 | 1.00 | 0.00 | 9 | 3 | 6 | 101.3 |
| **nuclei** | **all** | 13 | 0 | 4 | 22 | 1.00 | 0.77 | 0.00 | 41 | 12 | 28 | 505.0 |

Precision = TP/(TP+FP), recall = TP/(TP+FN), FPR = FP/(FP+TN); `-` when undefined. Rules: eval/harness/README.md.

Reading the table:

- ZAP and Nuclei are scored only on the check ids their rules map to (*not covered* counts the rest); CAWASMA is scored on every entry. Their recall is over a smaller, mostly header-only set, so compare per check, not the totals.
- The endpoint rule is strict: a missing header reported on `/` does not match an entry on `/login.php`, even if every page lacks it.
- *Unlabelled* findings are neither right nor wrong: the ground truth says nothing about that check on that endpoint.
