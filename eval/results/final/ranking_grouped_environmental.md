SECONDARY, DIAGNOSTIC VIEW (added after the first results; not the headline). Environmental-scored findings grouped by check_id per target, each group keeping its highest-final_score finding; relevance = the highest priority grade of that check (endpoint ignored).

| target | findings | distinct_checks | top5 | graded_checks | ndcg10_before | ndcg10_after |
|---|---|---|---|---|---|---|
| juice-shop | 287 | 10 | HDR-001 (56), HDR-002 (56), HDR-005 (56), HDR-006 (56), HDR-014 (56) | 6 | 0.633 | 0.635 |
| dvwa | 98 | 13 | CKI-001 (10), CKI-002 (10), CKI-003 (10), HDR-001 (8), HDR-002 (8) | 9 | 0.843 | 0.834 |
| vampi | 50 | 9 | HDR-001 (6), HDR-002 (6), HDR-003 (6), HDR-004 (6), HDR-005 (6) | 6 | 0.667 | 0.653 |
| crapi | 330 | 10 | HDR-001 (40), HDR-002 (40), HDR-003 (40), HDR-004 (40), HDR-005 (40) | 6 | 0.821 | 0.808 |
| mean | – | – | – | – | 0.741 | 0.733 |

before = base_score, after = final_score. Mean over 1000 random tie-breaks (seed 13); descriptive only.
