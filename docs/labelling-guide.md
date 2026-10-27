# Endpoint sensitivity labelling guide

Label the endpoint's **business sensitivity**, not whether a vulnerability is
present. Use the path, HTTP method, response purpose, and available target
documentation. If the endpoint cannot be understood confidently, press `s` and
record why in a later review.

## LOW

Public content with no user-specific or operational data.

Examples:

- `/`
- `/api/products` (public catalogue)
- `/about`

## MEDIUM

Ordinary user data or user-facing functionality where compromise matters to one
user but does not control authentication, privileges, or high-impact money
movement.

Examples:

- `/users/me/profile`
- `/orders/history`
- `/community/posts`

## HIGH

Authentication, session, token, account-recovery, or account-control surfaces.
These endpoints can affect identity or access for a user.

Examples:

- `/auth/login`
- `/users/me/password`
- `/password-reset/request`

## CRITICAL

Administrative, privileged, payment, financial-transfer, or system-wide
management surfaces. Use this class when compromise could affect many users or
move/control high-value funds.

Examples:

- `/admin/users`
- `/payments/transfer`
- `/internal/tenant-management`

## Consistency rules

1. Prefer the most specific path meaning over generic words such as `api` or
   `v1`.
2. A public documentation endpoint is LOW unless it exposes sensitive data.
3. Login and token endpoints are HIGH even when they return an error.
4. Payment history is MEDIUM; payment execution or transfer is CRITICAL.
5. Do not infer sensitivity from a vulnerability finding.
6. Keep the same decision for normalized ID variants such as `/users/1` and
   `/users/:id`.

## Using the labeller

```bash
make eval-up && make eval-collect     # fills eval/labels/endpoints_raw.csv
python eval/labels/label.py           # asks your name once, then one key per path
```

Press `1`-`4` for the class (a note may follow on the same line: `3 login
form`), `s` to skip, `q` to stop. Every answer is saved at once, and the next
run resumes at the first unlabelled path; skipped rows come back then. Static
files (scripts, styles, images) are not in the list: they have no sensitivity.

## Inter-rater agreement

A second person labels the same random sample into their own file, without
looking at the first labels:

```bash
python eval/labels/label.py --sample 50 --seed 13          # first labeller
python eval/labels/label.py --labeler neelam --sample 50 --seed 13 \
    --output eval/labels/endpoints_labelled_neelam.csv     # second labeller
```

The same `--seed` gives both the same 50 paths. Compare the two files with
Cohen's kappa; below about 0.6, re-read the definitions above together,
settle the disagreements, and add a rule for each kind of disagreement to the
consistency rules.
