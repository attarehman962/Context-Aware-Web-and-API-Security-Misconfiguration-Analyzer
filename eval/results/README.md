# Results

Written by `make eval` (`eval/harness/run_all.py`):

| File | What |
|------|------|
| `metrics.csv` | per tool and target: TP, FP, FN, TN, precision, recall, FPR, scan time |
| `comparison.md` | the same as a table, with the run's versions |
| `errors.md` | every CAWASMA false positive and false negative, by check id |
| `raw/<tool>/<target>/<UTC time>/` | the tools' own outputs + `meta.json` (version, image digest, command, duration). **Not committed** (git-ignored): they contain the targets' full responses, including the demo apps' default credentials; `make eval` recreates them |

Re-score saved raw outputs without scanning: `python eval/harness/run_all.py --evaluate-only`.
