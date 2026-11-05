Ranking experiment on environmental-scored findings only (final_vector set), against the priority items whose check is scored that way.

| target | findings | priority_items | items_matched | critical_items | ndcg10_before | ndcg10_after | first_critical_before | first_critical_after | pool | ndcg10_pool_before | ndcg10_pool_after |
|---|---|---|---|---|---|---|---|---|---|---|---|
| juice-shop | 287 | 9 | 4 | 6 | 0.001 | 0.0 | 286.1 | 197.1 | ungraded (0/37) | – | – |
| dvwa | 98 | 10 | 10 | 6 | 0.147 | 0.261 | 3.7 | 1.0 | ungraded (0/27) | – | – |
| vampi | 50 | 8 | 6 | 4 | 0.607 | 0.591 | 1.0 | 1.0 | ungraded (0/24) | – | – |
| crapi | 330 | 6 | 5 | 2 | 0.539 | 0.535 | 1.0 | 1.0 | ungraded (0/39) | – | – |
| mean | – | – | – | – | 0.324 | 0.347 | 72.95 | 50.025 | – | – | – |

before = base_score, after = final_score (CVSS v3.1 environmental). Mean over 1000 random tie-breaks (seed 13); descriptive only, no significance claimed. ndcg10_* uses priority_<target>.yaml; ndcg10_pool_* the graded pool (priority_pool_<target>.csv), empty until graded.
