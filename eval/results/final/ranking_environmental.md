Ranking experiment on environmental-scored findings only (final_vector set), against the priority items whose check is scored that way.

| target | findings | priority_items | critical_items | ndcg10_before | ndcg10_after | first_critical_before | first_critical_after |
|---|---|---|---|---|---|---|---|
| juice-shop | 283 | 5 | 2 | 0.003 | 0.0 | – | – |
| dvwa | 96 | 9 | 5 | 0.163 | 0.285 | 3.6 | 1.0 |
| vampi | 48 | 4 | 0 | 0.207 | 0.0 | – | – |
| crapi | 320 | 4 | 0 | 0.029 | 0.0 | – | – |
| mean | – | – | – | 0.101 | 0.071 | 3.6 | 1.0 |

before = base_score, after = final_score (CVSS v3.1 environmental). Mean over 1000 random tie-breaks (seed 13); descriptive only, no significance claimed.
