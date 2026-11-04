# CAWASMA security review (the tool itself)

Reviewer: Asim. Date: 2026-11-04. Code reviewed: `main` at 5a95786 (contract
1.3.0, Celery scans, SSE). Scope: CAWASMA's own safety as a scanner people
point at real systems. The review didn't fix anything: each open issue has a
test under `backend/tests/security/` that fails today, for the owner to fix.

Run the review: `cd backend && ../.venv/bin/python -m pytest tests/security -rx -q`
(about 1 minute; no network, no Docker). Today: **155 passed, 9 xfailed**.

## How the tests work

- **No real internal hosts.** DNS is a monkeypatched `getaddrinfo` table, and the
  engine's inner network backend is swapped for a recorder that logs the IP it
  would dial and never connects.
- **The target's request log replaces a logging proxy.** `logging_target` is a
  local server that records every request it receives (method, `Host`, path,
  headers). It answers for `target.test` and `other.test`, so anything that
  leaves the target host shows up with `Host: other.test`. This is stricter than
  a forward proxy: the engine ignores proxy settings on purpose
  (`trust_env=False`, which keeps the SSRF pinning intact), and the target sees
  every request, including ones a proxy would never be asked to forward.
- **Fake secrets** (JWT, AWS key pair, `.env` passwords, a JSON password, an API
  key in a response header, a session cookie value, a private key in a script, a
  card number) are served by the target. After a full active scan through the
  real runner, the tests search every database table, the DEBUG logs, all 8
  exports (contract and deprecated, PDF via `pdftotext`) and every read route.
- **Open issues are strict `xfail`s** tagged with the issue id below. When an
  owner fixes one, its test passes (XPASS), which fails the run: remove the
  marker and set the status here to Fixed.

## Findings

| Issue | Severity | Evidence | Owner | Status |
|-------|----------|----------|-------|--------|
| **SEC-01** Credentials in the target URL are stored and shown | Medium | `POST /api/scan` with `https://admin:S3cretPassw0rd@example.com/` → 202. The password is returned in `url` and stored in `scans.target_url`, so it shows up in history, every report and the logs. Test: `test_api_gate_and_hygiene.py::test_credentials_in_the_url_are_refused_not_stored` | Atta | Open (test fails) |
| **SEC-02** Refusal message reveals what an internal name resolves to | Low | `https://db.corp.internal/` (stub → 10.44.55.66) → 400 `"Blocked 10.44.55.66: private address."`. Anyone can use the API as an oracle for the server's internal DNS: which names exist inside, and their IPs. Say "resolves to a private address" without the IP. Test: `test_ssrf.py::test_refusal_does_not_reveal_what_an_internal_name_resolves_to` | Atta | Open (test fails) |
| **SEC-03** Deprecated `POST /api/scans` is not rate-limited | Low | 4 calls in a row → all 201. It creates and dispatches scans like `POST /api/scan`, which is limited (`SCAN_RATE_LIMIT`), so it is an open way around the limit. Apply the same limiter, or remove the route once the frontend no longer uses it. Test: `test_deprecated_scan_creation_is_rate_limited_too` | Atta | Open (test fails) |
| **SEC-04** Control characters in the URL are silently dropped | Low | `https://example.com/\r\nX: 1` → 202, stored as `https://example.com/X: 1` (Python's `urlsplit` strips CR/LF/tab). There is no injection, but the scanned URL is not the one submitted. Reject control characters with 400 instead. Test: `test_bad_urls_are_refused_and_nothing_is_stored[...X-Injected...]` | Atta | Open (test fails) |
| **SEC-05** Port and IPv6 edge cases: 500s and a wrong port | Low | `https://example.com:99999/` and `https://[::1` → **500** `INTERNAL_ERROR` (`ValueError` from `urlparse` inside `validate_url_ssrf`, before `validate_target_url` runs). `https://example.com:0/` → 202, because `parsed.port or 443` treats 0 as "no port". Expected: 400 `INVALID_TARGET`. The 500 body is the safe envelope with no trace. Tests: `test_bad_urls_...[:0]`, `[:99999]`, `[https://[::1]` | Atta | Open (tests fail) |
| **SEC-06** `authorisation_confirmed: 1` counts as confirmation | Low | `{"authorisation_confirmed": 1}` → 202 (`Literal[True]` accepts `1 == True`). `"true"`, `"yes"`, `"1"`, `[true]` and every other case are refused (422), and no form, query-string or spelling bypass works. Make the field strict (`StrictBool` + `Literal[True]`) so only JSON `true` confirms. Test: `test_contract_route_needs_a_literal_true[1]` | Atta | Open (test fails) |
| **SEC-07** Deprecated IPv6 site-local range `fec0::/10` is not blocked | Low | `resolve_and_validate("fec0::1")` passes: Python's `ipaddress` doesn't count it as private. It's deprecated (RFC 3879) and rarely routed, but some networks still use it internally. Add it to the blocked ranges. Test: `test_ssrf.py::test_every_internal_address_form_is_refused_by_the_resolver_check[[fec0::1]]` | Atta | Open (test fails) |
| **SEC-08** Frontend sends no security headers | Low | `frontend/next.config.ts` has no `headers()`: no `Content-Security-Policy` (incl. `frame-ancestors`), `X-Content-Type-Options`, `Referrer-Policy`. The pages show target-controlled text (URLs, evidence); React escapes it and no `dangerouslySetInnerHTML` is used, so this is defence in depth. External links already use `rel="noopener noreferrer"`. Found by review (no Python test; Neelam's own test suite is the place for one) | Neelam | Open |
| **SEC-09** SSE streams have no per-client cap | Info | Each `GET /api/scan/{id}/events` keeps a connection and reads the DB every `SSE_POLL_SECONDS` until the scan ends. Many open streams on a long scan load the DB. Cap them per client or share one poll per scan. Found by review | Atta | Open |
| SSRF guard: every address form and DNS trick | — | Refused at the resolver, the engine's connect and the API (nothing stored): 127.0.0.1 in decimal, hex, octal and short forms; `::1`; IPv4-mapped and NAT64 IPv6; 169.254.169.254 in 3 encodings; AWS IPv6 metadata; private, CGNAT, benchmarking, documentation, multicast, link-local, ULA and reserved ranges; `localhost`; DNS names answering private IPs (also one bad answer among good ones). DNS rebinding: the IP dialled is the one validated at connect time. Redirects to internal hosts are not followed. `ALLOWED_INTERNAL_HOSTS` never opens loopback or metadata. `test_ssrf.py` (86 cases) | Atta | Pass |
| Passive-only mode | — | A full passive scan (direct, and through the runner with `options.passive_only` as `POST /api/scan` sets it): the target logged only GET/HEAD, no wordlist path that isn't linked, no soft-404 probe, no `cawasma_probe` payload, no `Origin` or preflight headers. `test_passive_and_scope.py` | Atta | Pass |
| Authorisation gate | — | No scan without the flag through either route, whatever the body: missing, `false`, `null`, strings, lists, objects, the US spelling, the flag in the query string, form or text bodies, mock mode. Nothing is stored on refusal. `test_api_gate_and_hygiene.py` (except SEC-06) | Atta | Pass |
| Secret leakage | — | After a full active scan of the fake-secrets target, no secret was found in any table (incl. `endpoints.headers`, `findings.evidence`, cookie metadata), the DEBUG logs, the 8 exports (JSON, CSV, HTML, PDF on contract and deprecated routes), or the read routes (results, finding details, deprecated scan, findings, endpoints and chains routes, SSE, history). Cookie values are never stored. `test_secret_leakage.py` | Atta | Pass |
| Scope | — | Active and passive scans: every request the target logged had `Host: target.test`. Links, a redirect, an iframe, an image, a script `fetch` and a form pointing at `other.test` were never requested, and none was reported as an endpoint. `test_passive_and_scope.py` | Atta | Pass |
| API hygiene: rate limit, errors | — | `POST /api/scan` → 202, 202, 429, 429 at 2/minute; a spoofed `X-Forwarded-For` doesn't reset it. An internal error returns only `{"code": "INTERNAL_ERROR", "message": "An internal error occurred."}`: no traceback, exception type, file path or exception text. Client errors (bad JSON, bad UUID, bad enum, out-of-range page, unknown route, wrong method) use the error envelope. 422 details don't echo the request body. `test_api_gate_and_hygiene.py` | Atta | Pass |

## Notes for the owners

- **Atta**: SEC-01 to SEC-07 and SEC-09 sit in `utils/validators.py`,
  `utils/security.py`, `api/schemas/contract.py` (strict flag), `api/routes/scans.py`
  (limit) and `api/routes/contract.py` (SSE). Fixing SEC-05 is mostly a matter of
  validating the URL (`validate_target_url`) before `validate_url_ssrf` touches
  `urlparse(...).port`, and catching `ValueError` there.
- **Neelam**: SEC-08. Add `headers()` in `next.config.ts` (CSP with
  `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy:
  no-referrer`). Your live-progress code still uses the deprecated WebSocket; the
  contract's live route is `GET /api/scan/{id}/events` (SSE).
- After each fix, run `pytest tests/security -rx`: the issue's test will XPASS
  and fail the run until its `known_issue(...)` marker is removed. Then update the
  status in this table.
