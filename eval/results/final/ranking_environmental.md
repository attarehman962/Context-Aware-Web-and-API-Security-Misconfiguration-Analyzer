Ranking experiment on environmental-scored findings only (final_vector set), against the priority items whose check is scored that way.

| target | findings | priority_items | items_matched | critical_items | ndcg10_before | ndcg10_after | first_critical_before | first_critical_after | pool | ndcg10_pool_before | ndcg10_pool_after |
|---|---|---|---|---|---|---|---|---|---|---|---|
| juice-shop | 283 | 5 | 3 | 2 | 0.003 | 0.0 | – | – | ungraded (0/38) | – | – |
| dvwa | 96 | 9 | 9 | 5 | 0.163 | 0.285 | 3.6 | 1.0 | ungraded (0/26) | – | – |
| vampi | 48 | 4 | 4 | 0 | 0.207 | 0.0 | – | – | ungraded (0/22) | – | – |
| crapi | 320 | 4 | 4 | 0 | 0.029 | 0.0 | – | – | ungraded (0/40) | – | – |
| mean | – | – | – | – | 0.101 | 0.071 | 3.6 | 1.0 | – | – | – |

before = base_score, after = final_score (CVSS v3.1 environmental). Mean over 1000 random tie-breaks (seed 13); descriptive only, no significance claimed. ndcg10_* uses priority_<target>.yaml; ndcg10_pool_* the graded pool (priority_pool_<target>.csv), empty until graded.
