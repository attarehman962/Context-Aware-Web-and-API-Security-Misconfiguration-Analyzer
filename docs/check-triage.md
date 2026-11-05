# Triage of the 37 legacy-only checks (PROPOSED)

The 37 check ids that are in `backend/app/core/checks/catalog.py` but have no spec
in `config/checks.yaml`. They run as legacy `@rule` checks scored with the
interim formula. Before any spec is written or any check deleted, **Asim and
Atta confirm this table.** Drafted by Atta, 2026-11-05.

How the columns were filled:

- **Fired on an eval target**: CAWASMA findings per check in the latest run on
  the four targets (2026-11-05, `eval/results/raw/cawasma/<target>/20261105T011959Z/`):
  D = DVWA, V = VAmPI, J = Juice Shop, C = crAPI.
- **Scope**: CAWASMA is a passive or safe black-box scanner for
  misconfigurations: GET/HEAD/OPTIONS, no credentials, no exploitation, and
  never a state-changing route (`/logout`, `/reset`, `/create...` are not
  requested, `crawler._STATE_CHANGING`).
- **Recommendation**: **MERGE** when it duplicates a spec'd check; **DROP** when
  it is out of scope (needs exploitation or a login), unreliable, or never
  fired with no realistic ground truth; **SPEC** for the rest. SPEC rows are
  ordered by how often they fired.
- **TLS** checks never fire in the evaluation because CAWASMA reaches each target
  through our own nginx TLS front (docs/evaluation-method.md). They are in scope
  and deterministic, so they are SPEC, but their ground truth needs a TLS fixture
  (a local server with a legacy protocol, weak cipher, expired, self-signed or
  wrong-host certificate), not the four apps.

| check_id | what it detects | overlaps with (spec'd check) | fits our scope? | fired on an eval target? | recommendation |
|---|---|---|---|---|---|
| HDR-009 | no `Cross-Origin-Opener-Policy` header | — | yes (passive header) | 110 (D 8, V 6, J 56, C 40) | **SPEC** |
| HDR-010 | no `Cross-Origin-Resource-Policy` header | — | yes (passive header) | 110 (D 8, V 6, J 56, C 40) | **SPEC** |
| COR-001 | `Access-Control-Allow-Origin: *` | COR-003 covers `*` *with* credentials only | yes (CORS probe) | 55 (J) | **SPEC**, limited to MEDIUM+ endpoints (`*` on a public API is normal) |
| COR-004 | PUT/DELETE/PATCH allowed cross-origin in the preflight | — | yes (preflight) | 55 (J) | **SPEC** |
| API-007 | `/api` path without a `/vN` segment | — | yes, but hygiene rather than a misconfiguration | 33 (J 17, C 16) | **SPEC as low**, or DROP if we keep only security-relevant checks: *question for Asim* |
| HDR-011 | sensitive (HIGH/CRITICAL) endpoint without `Cache-Control: no-store` | — | yes (passive header + class) | 30 (D 1, V 2, J 11, C 16) | **SPEC** (uses the new `applies_to.sensitivity`) |
| API-013 | credential-like secret in the body (body classifier) | — | yes (passive body) | 3 (V 1, J 1, C 1) | **SPEC** |
| INF-006 | Swagger / OpenAPI document served publicly | — | yes (passive body) | 2 (V 1, J 1) | **SPEC as low** (the labelling guide calls public docs LOW) |
| API-012 | `__schema` in a response (GraphQL introspection) | — | yes (passive body) | 1 (C) | **SPEC** |
| INF-001 | internal IP address in the body (body classifier) | — | yes (passive body) | 0 (the signal feeds CR/IR; the check never fired) | **SPEC** (realistic: leaked `10.x`/`192.168.x` in errors and APIs) |
| CKI-004 | session token in a URL query parameter | — | yes (URL only) | 0 | **SPEC** (realistic: `;jsessionid=`, `?token=` links) |
| CKI-005 | cookie scoped to a parent domain (`Domain=.example.com`) | CKI-001..003 check other attributes | yes (passive `Set-Cookie`) | 0 | **SPEC** |
| API-002 | `TRACE` in the OPTIONS `Allow` header | — | yes (OPTIONS) | 0 | **SPEC**, merged with API-009 into one "risky methods advertised" check |
| TLS-001 | TLS 1.0/1.1 (or SSL) offered | — | yes (TLS handshake) | 0 (our TLS front) | **SPEC**, ground truth from a TLS fixture |
| TLS-002 | weak cipher suite accepted | — | yes | 0 (our TLS front) | **SPEC**, TLS fixture |
| TLS-003 | certificate expired or expiring within 15 days | — | yes | 0 (our TLS front) | **SPEC**, TLS fixture |
| TLS-004 | self-signed certificate | — | yes (SSLyze probe; the HTTP engine refuses an untrusted chain) | 0 (our TLS front) | **SPEC**, TLS fixture |
| TLS-006 | `src="http://` sub-resources on an HTTPS page | — | yes (passive body) | 0 | **SPEC** |
| TLS-008 | certificate does not match the hostname | — | yes (SSLyze probe) | 0 (our TLS front) | **SPEC**, TLS fixture |
| API-009 | 5 or more methods in the OPTIONS `Allow` header | API-002 (same source) | yes (OPTIONS) | 0 | **MERGE** into API-002 |
| API-010 | a JWT appears in a header or body | API-013 (a JWT in the body is a credential there) | indicator only: a JWT is not a misconfiguration | 1 (V) | **MERGE** into API-013 |
| AUT-002 | admin-looking path answers 200 unauthenticated | API-003 (sensitive endpoint without auth; admin paths are CRITICAL) | yes | 0 | **MERGE** into API-003 |
| TLS-007 | HSTS without `preload` | TLS-009 (weak HSTS policy) | preload is opt-in, not a misconfiguration | 0 | **MERGE** into TLS-009 (as a note, not a finding) |
| API-005 | `role` / `is_admin` fields in a JSON object | — | no: mass assignment needs a write request to confirm | 1 (J) | **DROP** |
| API-006 | numeric id in an API path (BOLA surface) | — | no: BOLA needs two users' sessions | 0 | **DROP** |
| API-008 | `Deprecation` / `Sunset` header | — | informational, not a weakness | 0 | **DROP** |
| API-011 | more than 40 fields in a JSON response | — | unreliable: field count says nothing about excess data | 8 (V 1, J 7) | **DROP** |
| API-014 | benign probe reflects an SQL or parser error | API-004 / INF-007 (error disclosure) | no: injection detection, not misconfiguration | 0 | **DROP** (error pages stay covered by API-004 and INF-007) |
| AUT-001 | `WWW-Authenticate: Basic` | — | over HTTPS-only targets, Basic is not a misconfiguration by itself | 0 | **DROP** |
| AUT-003 | short reset token in a `/reset` URL | — | no: needs a reset flow, and `/reset` routes are never requested | 0 (can't fire) | **DROP** |
| AUT-004 | logout response does not clear the cookie | — | no: `/logout` is never requested | 0 (can't fire) | **DROP** |
| AUT-005 | login page says "user not found" (enumeration) | — | no: needs submitting credentials | 0 | **DROP** |
| AUT-006 | page mentions Jenkins, Tomcat, phpMyAdmin... | — | unreliable: any page naming a product fires | 0 | **DROP** |
| AUT-007 | `next=` / `redirect_uri=` parameter present | — | no: an open redirect needs an active test | 0 | **DROP** |
| CKI-006 | session cookie value shorter than 16 characters | — | unreliable: length is not entropy | 0 | **DROP** |
| COR-005 | CORS preflight without `Access-Control-Max-Age` | — | performance, not security | 56 (J) | **DROP** |
| HDR-012 | HSTS present but no `Expect-CT` | — | `Expect-CT` is deprecated; browsers enforce CT | 0 | **DROP** |

## Totals (if confirmed)

| Recommendation | Checks | Effect |
|---|---|---|
| SPEC | 19 (API-002 absorbs API-009) | specs and ground truth to write; then moved to environmental scoring |
| MERGE | 4 | API-009 → API-002, API-010 → API-013, AUT-002 → API-003, TLS-007 → TLS-009 |
| DROP | 14 | removed from the catalog and the legacy rules |

That would leave 25 + 19 = 44 check ids, every one with a spec and scored with
environmental metrics, against 62 today (`make coverage-stats` gives the current
counts).

## Questions for Asim

1. API-007 (missing versioning): SPEC as low, or DROP as hygiene?
2. COR-001: is "MEDIUM or higher endpoints only" the right limit for `*`?
3. INF-006 and API-007 as low: is a base vector with `C:L` and `AC:H` acceptable,
   or should informational checks get no CVSS score at all?
4. The TLS fixture: a local server set up with weak protocols, ciphers and bad
   certificates (like badssl.com) as a fifth eval target, or only as unit-test
   fixtures?
