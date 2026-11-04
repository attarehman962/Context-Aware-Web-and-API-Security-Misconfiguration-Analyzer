| run | split | tp | fp | fn | tn | precision | recall | fpr | unlabelled_findings |
|---|---|---|---|---|---|---|---|---|---|
| before tuning | dev | 16 | 4 | 2 | 17 | 0.8 | 0.889 | 0.19 | 149 |
| before tuning | test | 8 | 0 | 7 | 26 | 1.0 | 0.533 | 0.0 | 1052 |
| after tuning | dev | 16 | 4 | 2 | 17 | 0.8 | 0.889 | 0.19 | 147 |
| after tuning | test | 8 | 0 | 7 | 26 | 1.0 | 0.533 | 0.0 | 1052 |

Both runs scored against the same ground truth (incl. the dev-split entries added from hand-checking the pre-tuning run). Tuning used the dev split only. The pass removed the two hand-checked dev false positives it targeted, HDR-011 on /dvwa/css/login.css (static asset classed sensitive) and API-013 on VAmPI's /openapi.json (example values read as leaked secrets). Both are legacy checks with no checks.yaml id, which ground truth cannot label, so they show as unlabelled_findings 149 -> 147 rather than in fp. The 4 labelled dev FPs (API-001 x3, API-003 x1 on VAmPI) need the spec scoping in core/specs.py (Atta) and are unchanged. Test findings are identical before and after.
