# Tool comparison

- **scored**: 20261111T015128Z
- **commit**: 3675280
- **CAWASMA**: api 1.0.0, {'crawl_depth': 2, 'use_wordlist': True, 'passive_only': False}
- **ZAP**: zaproxy/zap-stable:2.15.0 (baseline; VAmPI: API scan, safe mode)
- **Nuclei**: projectdiscovery/nuclei:v3.9.0, nuclei-templates v10.1.1
- **targets**: reset before the run
- **raw outputs**: eval/results/raw/<tool>/<target>/20261111T015128Z/

| tool | target | TP | FP | FN | TN | precision | recall | FPR | not covered | unlabelled | out of scope | scan time (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cawasma | juice-shop | 4 | 0 | 5 | 14 | 1.00 | 0.44 | 0.00 | 0 | 599 | 0 | 11.5 |
| cawasma | dvwa | 10 | 0 | 0 | 7 | 1.00 | 1.00 | 0.00 | 0 | 84 | 0 | 3.2 |
| cawasma | vampi | 6 | 0 | 2 | 14 | 1.00 | 0.75 | 0.00 | 0 | 62 | 0 | 6.2 |
| cawasma | crapi | 5 | 0 | 1 | 12 | 1.00 | 0.83 | 0.00 | 0 | 439 | 0 | 3.2 |
| **cawasma** | **all** | 25 | 0 | 8 | 47 | 1.00 | 0.76 | 0.00 | 0 | 1184 | 0 | 24.1 |
| zap | juice-shop | 1 | 0 | 3 | 7 | 1.00 | 0.25 | 0.00 | 12 | 9 | 25 | 302.6 |
| zap | dvwa | 0 | 0 | 9 | 1 | - | 0.00 | 0.00 | 7 | 6 | 2 | 24.6 |
| zap | vampi | 2 | 0 | 2 | 5 | 1.00 | 0.50 | 0.00 | 13 | 18 | 7 | 22.1 |
| zap | crapi | 4 | 0 | 0 | 6 | 1.00 | 1.00 | 0.00 | 8 | 0 | 1 | 16.1 |
| **zap** | **all** | 7 | 0 | 14 | 19 | 1.00 | 0.33 | 0.00 | 40 | 33 | 35 | 365.4 |
| nuclei | juice-shop | 3 | 0 | 2 | 7 | 1.00 | 0.60 | 0.00 | 11 | 2 | 6 | 390.9 |
| nuclei | dvwa | 3 | 0 | 2 | 5 | 1.00 | 0.60 | 0.00 | 7 | 3 | 10 | 283.8 |
| nuclei | vampi | 3 | 0 | 0 | 5 | 1.00 | 1.00 | 0.00 | 14 | 4 | 6 | 281.2 |
| nuclei | crapi | 4 | 0 | 0 | 5 | 1.00 | 1.00 | 0.00 | 9 | 3 | 6 | 283.9 |
| **nuclei** | **all** | 13 | 0 | 4 | 22 | 1.00 | 0.77 | 0.00 | 41 | 12 | 28 | 1239.8 |

Precision = TP/(TP+FP), recall = TP/(TP+FN), FPR = FP/(FP+TN); `-` when undefined. Rules: eval/harness/README.md.

Reading the table:

- ZAP and Nuclei are scored only on the check ids their rules map to (*not covered* counts the rest); CAWASMA is scored on every entry. Their recall is over a smaller, mostly header-only set, so compare per check, not the totals.
- The endpoint rule is strict: a missing header reported on `/` does not match an entry on `/login.php`, even if every page lacks it.
- *Unlabelled* findings are neither right nor wrong: the ground truth says nothing about that check on that endpoint.
