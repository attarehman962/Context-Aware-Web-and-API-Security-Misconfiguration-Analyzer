# Tool comparison

- **CAWASMA**: 1.0.0
- **raw outputs**: eval/results/raw/<tool>/<target>/20261104T152231Z/
- **ZAP**: 2.15.0 zaproxy/zap-stable@sha256:8dc78e39fafc3281ac2cf54eab05c3ea02721a1ea58f1c135f981a57f4e218b1
- **Nuclei**: v3.9.0 projectdiscovery/nuclei@sha256:66b5f88c9b98ad29c03343dd34e5e85bde0ad10428d72e0171b067efe1ed7811 nuclei-templates v10.1.1

| tool | target | TP | FP | FN | TN | precision | recall | FPR | not covered | unlabelled | out of scope | scan time (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cawasma | juice-shop | 3 | 0 | 6 | 14 | 1.00 | 0.33 | 0.00 | 0 | 620 | 0 | 11.1 |
| cawasma | dvwa | 9 | 0 | 1 | 7 | 1.00 | 0.90 | 0.00 | 0 | 83 | 0 | 3.1 |
| cawasma | vampi | 7 | 4 | 1 | 10 | 0.64 | 0.88 | 0.29 | 0 | 64 | 0 | 3.1 |
| cawasma | crapi | 5 | 0 | 1 | 12 | 1.00 | 0.83 | 0.00 | 0 | 432 | 0 | 3.1 |
| **cawasma** | **all** | 24 | 4 | 9 | 43 | 0.86 | 0.73 | 0.09 | 0 | 1199 | 0 | 20.4 |
| zap | juice-shop | 1 | 0 | 3 | 7 | 1.00 | 0.25 | 0.00 | 12 | 9 | 25 | 36.5 |
| zap | dvwa | 0 | 0 | 9 | 1 | - | 0.00 | 0.00 | 7 | 6 | 2 | 14.7 |
| zap | vampi | 1 | 0 | 3 | 5 | 1.00 | 0.25 | 0.00 | 13 | 16 | 7 | 16.4 |
| zap | crapi | 4 | 0 | 0 | 6 | 1.00 | 1.00 | 0.00 | 8 | 0 | 1 | 14.3 |
| **zap** | **all** | 6 | 0 | 15 | 19 | 1.00 | 0.29 | 0.00 | 40 | 31 | 35 | 81.9 |
| nuclei | juice-shop | 3 | 0 | 2 | 7 | 1.00 | 0.60 | 0.00 | 11 | 2 | 6 | 100.6 |
| nuclei | dvwa | 3 | 0 | 2 | 5 | 1.00 | 0.60 | 0.00 | 7 | 3 | 10 | 102.0 |
| nuclei | vampi | 3 | 0 | 0 | 5 | 1.00 | 1.00 | 0.00 | 14 | 4 | 6 | 100.6 |
| nuclei | crapi | 4 | 0 | 0 | 5 | 1.00 | 1.00 | 0.00 | 9 | 3 | 6 | 100.6 |
| **nuclei** | **all** | 13 | 0 | 4 | 22 | 1.00 | 0.77 | 0.00 | 41 | 12 | 28 | 403.8 |

Precision = TP/(TP+FP), recall = TP/(TP+FN), FPR = FP/(FP+TN); `-` when undefined. Rules: eval/harness/README.md.

Reading the table:

- ZAP and Nuclei are scored only on the check ids their rules map to (*not covered* counts the rest); CAWASMA is scored on every entry. Their recall is over a smaller, mostly header-only set, so compare per check, not the totals.
- The endpoint rule is strict: a missing header reported on `/` does not match an entry on `/login.php`, even if every page lacks it.
- *Unlabelled* findings are neither right nor wrong: the ground truth says nothing about that check on that endpoint.
