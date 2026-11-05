# Grading the priority pools (for Asim)

`priority_pool_<target>.csv` lists (check, endpoint) pairs CAWASMA reported on
that target. Fill in `grade` for every row: **how urgently a defender should fix
this issue at this endpoint**. The ranking experiment then measures how well each
ranking puts the most urgent pairs first (NDCG@10, `eval/harness/ranking.py`).

The pairs were pooled from two rankings and shuffled; the file holds no score,
rank or source on purpose. Grade from the check, the endpoint and the evidence
only, and don't look at CAWASMA's scores while grading. Same issue at two endpoints:
grade each on its own (that difference is what the experiment tests).

| Grade | Meaning |
|-------|---------|
| **0** | not important: no realistic harm at this endpoint (public static content, a hardening header with nothing to protect) |
| **1** | low: hardening gap, worth fixing in the normal cycle |
| **2** | high: weakens authentication, session, transport or data protection where it matters; fix soon |
| **3** | critical: direct exposure of secrets or sensitive data, or a gap on an admin, payment or credential surface; fix first |

Use the endpoint meaning the way `docs/labelling-guide.md` does (an admin or
token endpoint matters more than `/about`). Leave a row blank only if you can't
judge it, and say why in the commit message.

## Examples

```
target,check_id,endpoint,evidence_summary,grade
vampi,HDR-002,/,Missing Content-Security-Policy on /,1
vampi,HDR-002,/users/v1/_debug,Missing Content-Security-Policy on /users/v1/_debug,2
```

- `/` on VAmPI is an API index with no user data: a missing CSP is a hardening
  gap, **1**.
- `/users/v1/_debug` returns every user with their password: a missing CSP there
  makes any injected script worth far more, and the endpoint itself is
  sensitive, **2**. (The exposure of that data is a different check, which would
  be a **3**.)

When every row of a target has a grade, `ranking.py` uses the pool for that
target instead of `priority_<target>.yaml`. Re-run:

```bash
python eval/harness/ranking.py --scoring environmental --run 20261104T152231Z --out eval/results/final
```
