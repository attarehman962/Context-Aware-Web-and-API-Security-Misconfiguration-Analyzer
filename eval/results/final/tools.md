| tool | target | tp | fp | fn | tn | precision | recall | fpr | scan_seconds |
|---|---|---|---|---|---|---|---|---|---|
| cawasma | juice-shop | 3 | 0 | 6 | 14 | 1.0 | 0.333 | 0.0 | 11.1 |
| cawasma | dvwa | 9 | 0 | 1 | 7 | 1.0 | 0.9 | 0.0 | 3.1 |
| cawasma | vampi | 7 | 4 | 1 | 10 | 0.636 | 0.875 | 0.286 | 3.1 |
| cawasma | crapi | 5 | 0 | 1 | 12 | 1.0 | 0.833 | 0.0 | 3.1 |
| cawasma | all (micro) | 24 | 4 | 9 | 43 | 0.857 | 0.727 | 0.085 | 5.1 |
| zap | juice-shop | 1 | 0 | 3 | 7 | 1.0 | 0.25 | 0.0 | 36.5 |
| zap | dvwa | 0 | 0 | 9 | 1 | – | 0.0 | 0.0 | 14.7 |
| zap | vampi | 1 | 0 | 3 | 5 | 1.0 | 0.25 | 0.0 | 16.4 |
| zap | crapi | 4 | 0 | 0 | 6 | 1.0 | 1.0 | 0.0 | 14.3 |
| zap | all (micro) | 6 | 0 | 15 | 19 | 1.0 | 0.286 | 0.0 | 20.5 |
| nuclei | juice-shop | 3 | 0 | 2 | 7 | 1.0 | 0.6 | 0.0 | 100.6 |
| nuclei | dvwa | 3 | 0 | 2 | 5 | 1.0 | 0.6 | 0.0 | 102.0 |
| nuclei | vampi | 3 | 0 | 0 | 5 | 1.0 | 1.0 | 0.0 | 100.6 |
| nuclei | crapi | 4 | 0 | 0 | 5 | 1.0 | 1.0 | 0.0 | 100.6 |
| nuclei | all (micro) | 13 | 0 | 4 | 22 | 1.0 | 0.765 | 0.0 | 100.9 |

Each tool is scored only on the checks it can detect (tool_mapping.yaml); scan_seconds for 'all' is the mean per target. FPs count only findings that contradict a ground-truth `absent` entry or a `must_not_fire` check.
