| families | split | n | accuracy | macro_f1 | off_by_two_or_more | recall_low | recall_medium | recall_high | recall_critical |
|---|---|---|---|---|---|---|---|---|---|
| shipped | dev | 51 | 0.392 | 0.297 | 13 | 1.0 | 0.125 | 0.417 | 0.0 |
| shipped | test | 113 | 0.425 | 0.362 | 34 | 0.744 | 0.3 | 0.125 | 0.4 |
| proposed | dev | 51 | 0.569 | 0.577 | 8 | 1.0 | 0.25 | 0.583 | 0.5 |
| proposed | test | 113 | 0.487 | 0.454 | 32 | 0.769 | 0.325 | 0.333 | 0.4 |

shipped = keyword families in app/core/sensitivity.py (Atta); proposed = eval/harness/proposed_families.json, chosen on dev only and reported once on test. Embeddings on (all-MiniLM-L6-v2): they set the confidence, not the class.
