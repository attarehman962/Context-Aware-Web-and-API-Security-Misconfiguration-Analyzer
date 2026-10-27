# Labels

Endpoint paths of the four evaluation targets and their hand-assigned
sensitivity classes, for training and evaluating the sensitivity classifier.

| File | What |
|------|------|
| `endpoints_raw.csv` | `target, method, path`: 164 unique paths (2026-10-27), ID variants collapsed to `:id` |
| `endpoints_labelled.csv` | the same rows plus `sensitivity_class, labeler, notes` |
| `collect_endpoints.py` | builds `endpoints_raw.csv` |
| `label.py` | the labelling CLI (definitions: `docs/labelling-guide.md`) |

```bash
make eval-up && make eval-collect     # refresh endpoints_raw.csv
python eval/labels/label.py           # label, resumable
```

Where the paths come from (see the docstring of `collect_endpoints.py`):
OpenAPI specs (VAmPI), a same-origin crawl, API routes read from the
JavaScript bundles (Juice Shop, crAPI), and documented paths a logged-out crawl
cannot reach (DVWA modules, Juice Shop's challenge-guide paths). Every request
is a GET; static assets are not listed.
