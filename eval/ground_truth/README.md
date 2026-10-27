# Ground truth

One file per evaluation target, `<target>.yaml`: what CAWASMA **should** find
there (true positives) and what it **must not** report (true negatives, for the
false-positive rate). Validated by `backend/tests/eval/test_ground_truth.py`.

```yaml
target: dvwa
base_url: http://dvwa:80          # as the scanner reaches it on the cawasma-eval network
status: starter-unverified
evidence: observed/dvwa.json      # what the target actually sent (observe.py)
known_issues:
  - endpoint: /login.php
    check_id: CKI-001             # from config/checks.yaml, nothing else
    expected: present             # present | absent (an endpoint-level true negative)
    source: "official docs: <url>; observed passive GET/OPTIONS, <date> (observed/dvwa.json)"
    notes: "PHPSESSID set without HttpOnly."
    verification: unverified      # unverified until checked by hand, then verified
must_not_fire:                    # checks that must not fire anywhere on this target
  - check_id: COR-003
    reason: "No CORS headers at all."
```

## How the starter lists were made

1. Each project's official docs (Juice Shop companion guide, DVWA, VAmPI and
   crAPI READMEs) gave the candidate issues.
2. `observe.py` recorded what the pinned images actually send to a passive GET
   and a CORS preflight per path: status, security headers, cookie attributes
   (never cookie values or bodies). Candidates the observation contradicts were
   dropped or turned into true negatives. Example: DVWA's `PHPSESSID` has no
   HttpOnly/SameSite, so CKI-001/003 are expected **present** there, not absent.
3. Everything is still `unverified`: confirm each entry by hand (browser dev
   tools or `curl` from the eval network), then set `verification: verified`.

Refresh the evidence after changing an image digest:

```bash
make eval-up
docker compose -f docker-compose.eval.yml run --rm collector python ground_truth/observe.py
```

## Setup the targets need before a scan

- **VAmPI**: `GET /createdb` once after start (its README); until then every data
  route answers 500. The observation was taken before that, so VAmPI's data-route
  entries are documented hypotheses (`observed` is not in their `source`).
- **DVWA**: logged out, everything except login and setup redirects to
  `login.php`. The database is created from `setup.php` (a POST, by hand).
- **All four** serve plain HTTP. CAWASMA scans HTTPS only, so a TLS front on the
  eval network is needed before a full scan (docs/engine-security.md, known
  gaps); HSTS and TLS checks are therefore not in the ground truth yet.
