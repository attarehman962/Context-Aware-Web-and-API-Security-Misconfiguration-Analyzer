# Plan for what CAWASMA does not cover

CAWASMA currently runs safe, unauthenticated, read-only checks for
misconfigurations. It requires the user to confirm authorisation for every scan,
scans HTTPS only, sends no credentials, and never requests routes named like state
changes (`/logout`, `/reset`, `/create...`). The items below need more than that.

All of them would share two safety rules:

- **Opt-in active mode**, off by default and on top of the existing authorisation
  confirmation. Passive mode stays exactly as it is.
- **Bounded and non-destructive:** harmless inputs only, no attack payloads, nothing
  that changes data unless the target is one of our own test targets.

Effort is a rough estimate in working days, including tests and evaluation.

## XSS, injection, BOLA/IDOR, authenticated scanning

| Item | Why it is out of scope now | What a safe version looks like | Effort | Owner |
|---|---|---|---:|---|
| **XSS** | Confirming XSS normally means sending a script payload and proving it runs, which is exploitation | **Marker reflection:** send a random inert marker with `"'<>` in a query parameter and report only if it returns unescaped in the HTML, noting the context (text, attribute, script). No script is ever sent. It finds indicators, not proof, and sees only server-side reflection, so DOM-based XSS stays out | 2–3 | Atta (probe and check); Asim (spec, vector, ground truth) |
| **Injection** (SQL, command) | Real tests try to change a query or run a command, which can damage data. Today a single `'"<` probe on API endpoints only flags an error it caused (API-014) | **Error differential:** compare the response to a harmless syntax character against a normal request, and report new database or parser errors as an indicator. No time-based, boolean-extraction or stacked payloads | 6–8 | Atta (probes, rate limits); Asim (spec, ground truth on DVWA, VAmPI, crAPI) |
| **BOLA / IDOR** | Needs a logged-in session for two different users, and a positive test reads someone else's data, which is only acceptable on our own test targets | **Two-account differential:** the user supplies two test accounts; request one account's object with the other's token and compare. Allowed only on targets marked as test targets, read-only (GET), and depends on authenticated scanning | 8–10, after authenticated scanning | Asim (method, ground truth on VAmPI, crAPI); Atta (engine) |
| **Authenticated scanning** | The engine deliberately keeps no cookies and sends no credentials, so anything behind a login is unseen, and many DVWA and crAPI pages are | **User-supplied session token** (cookie or bearer header), sent only to the in-scope host, never stored or logged, redacted everywhere. CAWASMA would not log in itself. State-changing routes stay blocked, so the session isn't ended by the scan | 5–7 | Atta (engine, API); Neelam (form field, 1 day); Asim (re-label, re-run evaluation) |

## The checks marked DROP in `docs/check-triage.md`

The 14 DROP entries are a proposal that Asim and Atta have not yet confirmed; today
they still run as legacy checks. For several, the honest plan is to leave them out.

| Check | Why it is out of scope now | Safe version, if any | Effort | Owner |
|---|---|---|---:|---|
| API-005 mass assignment | Needs a write request to confirm | On test targets only, with a test account: send one harmless extra field to a throwaway resource and read it back | 3–4, after auth | Asim, Atta |
| API-006 BOLA surface | A numeric id alone proves nothing | Replaced by the BOLA/IDOR item above | included | Asim, Atta |
| API-008 Deprecation header | Informational, not a weakness | Show as an unscored note | 0.5 | Atta |
| API-011 too many fields | Unreliable: a field count says nothing about excess data | Compare response fields with the OpenAPI schema, where one exists | 3 | Asim, Atta |
| API-014 injection error | Injection detection rather than misconfiguration | Moves into the injection item above | included | Atta, Asim |
| AUT-001 Basic auth | Over HTTPS-only targets it is not a misconfiguration by itself | Show as an unscored note | 0.5 | Atta |
| AUT-003 short reset token | Needs a reset flow; `/reset` routes are never requested | Test targets only, with a test account and active mode | 3, after auth | Asim, Atta |
| AUT-004 logout keeps session | `/logout` is never requested | With a user-supplied test session: log out, then replay the token. Ends that session, so explicit opt-in | 2, after auth | Atta |
| AUT-005 user enumeration | Needs submitting credentials | Two dummy usernames, a strict request limit, compare the responses; active mode | 2 | Atta, Asim |
| AUT-006 default credentials | Trying default passwords is credential testing, a legal and safety line. The current check is unreliable | Never try passwords. At most report the product name as an unscored note | 1 | Asim |
| AUT-007 open redirect | Needs an active test | Set the parameter to a reserved domain and read the `Location` header without following it | 1.5 | Atta |
| CKI-006 short session cookie | Unreliable: length is not entropy | Sample many sessions and estimate entropy. It creates many sessions, so low value for the cost | 2 | Leave out |
| COR-005 missing max-age | Performance, not security | None needed | 0 | Stays dropped |
| HDR-012 Expect-CT | The header is deprecated | None needed | 0 | Stays dropped |

## Recommendation

**Add one item before final submission: the XSS marker-reflection check.**

- It's the smallest item (2–3 days) and fits what the scanner already is: a probe
  already exists, the check needs no login, and it sends nothing harmful.
- It answers the supervisor's most visible gap with a real, safe feature.
- **Limits to state:** it reports an indicator, not a proven exploit. No ground truth
  for XSS exists yet, so Asim would need to add it. The classic DVWA XSS pages sit
  behind a login, and Juice Shop's best-known XSS is DOM-based, so it may find little
  on these four targets and needs its own test fixture. Adding it also means
  re-running the evaluation.

**Future work:** authenticated scanning first, since BOLA/IDOR, mass assignment and
the session checks depend on it; then injection and BOLA/IDOR. Authenticated scanning
would add the most coverage, but it touches the engine, the API, the UI and every
ground-truth file, so it's too large and too risky to do just before submission.
