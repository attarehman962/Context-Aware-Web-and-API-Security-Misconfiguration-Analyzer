# Adding a check

How a spec in `config/checks.yaml` becomes a tested check. Asim writes the
spec (security judgement: condition, OWASP/CWE, CVSS vector); Atta (or whoever
implements) writes the code and its two tests. No check is done without both.

The reference implementation is HSTS: `backend/app/core/checks/spec/hsts.py`
with its tests in `backend/tests/checks/test_hsts.py`.

## 1. Start from the spec

Find the entry in `config/checks.yaml` and check it validates:

```bash
make validate-checks
```

Read `http_condition` closely: it defines **exactly** when the check fires.
If it is ambiguous, or can't express what the description says, ask Asim to
change the spec rather than guessing in code (format:
[check-spec-format.md](check-spec-format.md)).

## 2. Write the two tests first

In `backend/tests/checks/test_<family>.py`, one test where the check must fire
(a vulnerable response) and one where it must not (a secure response):

```python
from tests.checks.helpers import assert_fires, assert_no_fire, response

def test_hdr004_fires_when_nosniff_is_missing():
    assert_fires("HDR-004", response(headers={}))

def test_hdr004_no_fire_with_nosniff():
    assert_no_fire("HDR-004", response(headers={"X-Content-Type-Options": "nosniff"}))
```

- `response(url=..., status=..., headers=..., body=..., method=...)` builds a
  `ScanResponse` the way the engine returns it (headers lowercased).
- `assert_fires` also checks each finding has the right `check_id`, the
  endpoint, and an `evidence["text"]`.
- Add more cases where the condition has edges (both sides of a threshold,
  header present but empty, plain HTTP...). A parametrized test counts.

Run them and watch them fail: `cd backend && ../.venv/bin/python -m pytest tests/checks -q`.

## 3. Implement it

Add a function to the family's module in `backend/app/core/checks/spec/` (or
create a new module there; every module is imported automatically):

```python
from app.core.checks.registry import RawFinding, condition_matches, register_check

@register_check("HDR-004")
def missing_nosniff(resp, endpoint):
    if not condition_matches("HDR-004", resp):     # the spec's http_condition
        return []
    return [RawFinding("HDR-004", endpoint, {
        "text": f"Missing X-Content-Type-Options on {endpoint.path}",
        "header": "X-Content-Type-Options",
        "value": resp.headers.get("x-content-type-options"),
    })]
```

Rules:

- **Use `condition_matches(check_id, resp)`.** It evaluates the spec's own
  `http_condition` (and its method), so code and spec cannot drift. Add code
  only for what the format can't say, and say why in a comment (HSTS: "only on
  HTTPS responses").
- **Return findings, never scores.** A finding is `check_id`, the endpoint, and
  evidence. The CVSS vector and the context-aware score come from the spec and
  `cvss.py` later.
- **Evidence is JSON with a `text` summary** plus the detail a reviewer needs
  (header name and value, matched snippet). Never put secrets in it: pass body
  excerpts through `app.utils.redaction` first.
- **Be safe:** checks only read the `ScanResponse`. Any extra request (a
  probe) goes through the engine, which enforces SSRF rules and passive mode.
- `scope: target_root` specs only run on the scan URL; the registry handles that.

## 4. Check it is wired up

```bash
make test        # includes the meta-test below
make lint
```

- `tests/checks/test_check_tests.py` fails if any registered check lacks an
  `assert_fires` or an `assert_no_fire` call.
- At startup, the API and the worker cross-check the registry with
  `checks.yaml`: an implementation whose `check_id` is not in the YAML stops
  the process; specs not implemented yet are logged as a warning.

## 5. Open the PR

Branch `atta/pNN-<check-name>`, one check family per PR, and note the
`check_id`s in the description. If you had to interpret the spec, say how, so
Asim can confirm.

## Legacy catalog

Of the 58 original rules (`backend/app/core/checks/catalog.py` plus the `@rule`
functions in `headers.py`, `cookies.py`, ...), 16 have moved to this registry and
42 still run in the pipeline (`docs/check-coverage.md` lists which). Moving
a check to this registry means: spec in `checks.yaml` (same `check_id`, see
`docs/check-specs-review.md`), implementation and tests here, then delete the
old `@rule` function. Until a check moves, both systems keep their own
`RawFinding` type (the legacy one carries the score inputs).
