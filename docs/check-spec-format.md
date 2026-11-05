# Check specification format (`config/checks.yaml`), version 1

How a security check is specified, so the engine can run it and the CVSS
scoring can trust it. **Owner of the file: Asim.** The engine side (loading,
evaluating `http_condition`) is Atta's. Models and validation:
`backend/app/core/specs.py`.

```bash
make validate-checks    # checks.yaml only
make validate-config    # checks.yaml + cvss_mapping.yaml + chains.yaml (+ catalog report)
```

Both exit non-zero and print one line per problem when anything is invalid. CI
runs `validate-config` on every push.

## File layout

```yaml
spec_version: 1        # required; bumped only when this format changes
checks:                # at least one
  - check_id: HDR-001
    ...
```

## Fields of a check

| Field | Required | Type / rule | Example |
|-------|----------|-------------|---------|
| `check_id` | yes | `AAA-NNN`: 3 capital letters, dash, 3 digits; unique in the file | `HDR-001` |
| `category` | yes | one of `HEADERS`, `COOKIES`, `CORS`, `TLS`, `REST_API`, `AUTH`, `INFO_DISCLOSURE` | `HEADERS` |
| `title` | no | ≤ 255 chars; shown as the finding title | `Missing HSTS` |
| `description` | yes | ≥ 10 chars: what is wrong and why it matters | |
| `http_condition` | yes | when the check fires (below) | |
| `owasp` | yes | ≥ 1 of `API1:2023`…`API10:2023`, `A01:2021`…`A10:2021` or `A01:2025`…`A10:2025` (the SRS cites OWASP Top 10 2025) | `[API8:2023, A02:2025]` |
| `cwe` | yes | ≥ 1 of `CWE-<number>` | `[CWE-319]` |
| `base_cvss_vector` | yes | CVSS v3.1 **base** vector, rules below | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| `recommendation` | no | how to fix | |
| `references` | no | list of URLs | |
| `limitation` | no | set when black-box testing cannot confirm the issue; shown to users | |
| `severity_notes` | no | how context should move the severity (the plan's Contract 1 "severity notes"); guidance for the CVSS mapping, not used in scoring | `raise with endpoint sensitivity` |
| `status` | no | `approved` (default) or `proposed`: drafted for Asim and not yet approved. Scans run a proposed spec, but the report counts approved specs only (`make coverage-stats`) | `proposed` |
| `applies_to` | no | which endpoints the check judges (below); default: every endpoint | |
| `artifact` | no | the check is about a file at a path: which paths, what to probe, what not to fire on (below) | |

Any other key is an error, so typos (`descripton`) are caught.

There is **no `base_score` field**: the score is computed from
`base_cvss_vector` with the FIRST v3.1 equations (`backend/app/core/cvss31.py`),
so the two can never disagree. `make validate-checks` prints each computed score.

### `base_cvss_vector` rules

- starts with `CVSS:3.1/`;
- exactly the 8 base metrics, once each, **in this order**:
  `AV` (N/A/L/P), `AC` (L/H), `PR` (N/L/H), `UI` (N/R), `S` (U/C), `C`, `I`, `A` (H/L/N);
- no temporal or environmental metrics: the environmental part is computed by
  the engine from `config/cvss_mapping.yaml`
  ([cvss-mapping-contract.md](cvss-mapping-contract.md)).

## `http_condition`

Evaluated against each in-scope response. The check fires when the rules match.

| Key | Default | Values |
|-----|---------|--------|
| `method` | `GET` | `GET`, `HEAD`, `OPTIONS` only. The scanner never sends state-changing requests |
| `scope` | `every_endpoint` | `every_endpoint` (each crawled endpoint) or `target_root` (the scan URL only) |
| `match` | `all` | `all`: every rule must hold; `any`: one is enough |
| `rules` | | list, at least one; each rule has exactly one of `header`, `header_names`, `status`, `body`, `url` |

### Rule types

**Header** (name is case-insensitive; values compared case-insensitively unless
`case_sensitive: true`):

| `op` | `value` | Fires when |
|------|---------|------------|
| `missing` | none | header absent |
| `present` | none | header present |
| `equals` / `not_equals` | required | value is / is not exactly `value` |
| `contains` / `not_contains` | required | value does / does not contain `value` |
| `matches` | required regex | value matches the Python regex (validated when loading) |

```yaml
- header: Strict-Transport-Security
  op: missing
```

Value operations (`equals` … `matches`) on a header that is **absent** are
false: pair them with `op: missing` under `match: any` when absence should
also fire. `matches` uses `re.search`, so anchor with `^…$` when you mean the
whole value.

**Status code**:

```yaml
- status: in            # or not_in
  value: [200, 206]     # 100-599
```

**Body** (the truncated, decoded response body; comparisons are
case-sensitive, so use `(?i)` in a `matches` pattern when needed):

```yaml
- body: matches         # contains | not_contains | matches | not_empty | json
  value: "(?i)index of /"
```

`not_empty` (some non-whitespace text) and `json` (the body parses as a
non-empty JSON object or array) take no `value`.

**Header names** (regex, case-insensitive, over every response header name):

```yaml
- header_names: none_match      # or any_match
  value: "^(?:ratelimit-.+|x-ratelimit-.+|retry-after)$"
```

**Final URL** (after redirects):

```yaml
- url: not_matches              # or matches
  value: "(?i)/(?:login|signin)(?:[/?.#]|$)"
```

## `applies_to` (optional)

Which endpoints the check judges at all; `http_condition` then decides whether it
fires. Same `match: all | any` as `http_condition`. Each rule has exactly one of:

| Key | Holds when |
|-----|-----------|
| `sensitivity: [HIGH, CRITICAL]` | the endpoint's sensitivity class is in the list |
| `sensitivity_family: authentication` | the built-in path classifier matched that keyword family (`identity`, `payment`, `secrets`, `authentication`, `account`, `api`, `public`; `app/core/sensitivity.py`) |
| `path: <regex>` (+ optional `methods: [POST]`) | the endpoint path matches, and its method is listed (a POST form is judged on its GET response; the scanner never sends POST) |
| `credentials: absent` | the request carried no `Authorization` header and no cookie |

```yaml
applies_to:
  match: any
  rules:
    - sensitivity_family: authentication
    - path: "(?i)(?:login|token|password)"
      methods: [POST]
```

## `artifact` (optional)

For a check about a file at a path (`.env`, `.git/HEAD`, a backup). Such a check
**never runs in passive mode**, because it is about probed paths.

| Key | Default | Meaning |
|-----|---------|---------|
| `path` | required | regex on the endpoint path: only matching endpoints are judged |
| `probe` | `[]` | fixed paths (from `/`) requested with the wordlist, active mode only |
| `not_html` | `true` | an HTML body is the site's page, not the file: never fires |
| `not_soft_404` | `true` | never fires on a response like the host's soft-404 baseline (the crawler requests one random path per scan; a page that echoes the requested path still counts) |
| `require_body` | `false` | the response must have content (text, or bytes for binary files) |

```yaml
artifact:
  path: "(?:^|/)\\.git/(?:HEAD|config)$"
  probe: [/.git/HEAD, /.git/config]
```

## The two sample checks

From `config/checks.yaml`:

```yaml
spec_version: 1
checks:
  - check_id: HDR-001
    category: HEADERS
    title: Missing HSTS (Strict-Transport-Security)
    description: >-
      The HTTPS response does not send a Strict-Transport-Security header, so a
      browser can be downgraded to plain HTTP and the session intercepted (MITM).
    http_condition:
      method: GET
      scope: every_endpoint
      match: all
      rules:
        - header: Strict-Transport-Security
          op: missing
    owasp: [API8:2023, A05:2021]
    cwe: [CWE-319]
    base_cvss_vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N   # 5.9

  - check_id: HDR-004
    category: HEADERS
    title: Missing X-Content-Type-Options
    description: >-
      The response does not send 'X-Content-Type-Options: nosniff' (or sends
      another value), so browsers may MIME-sniff the content and execute it.
    http_condition:
      match: any            # absent OR not "nosniff"
      rules:
        - header: X-Content-Type-Options
          op: missing
        - header: X-Content-Type-Options
          op: not_equals
          value: nosniff
    owasp: [API8:2023, A05:2021]
    cwe: [CWE-693]
    base_cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N   # 4.3
```

## What the validator rejects

Examples of the messages you get (`make validate-checks`):

```
FAIL config/checks.yaml
     checks.0.base_cvss_vector: Value error, invalid CVSS v3.1 base vector: missing base metric(s): A
     checks.1.http_condition.rules.1.header: Value error, op 'not_equals' needs a value
     checks.1.owasp.0: String should match pattern '^(API([1-9]|10):2023|A(0[1-9]|10):(2021|2025))$'
```

Also rejected: duplicate `check_id`, unknown keys, unsafe `method`, empty
`rules`, a rule with two targets, invalid regexes, status codes outside 100–599,
invalid YAML, and a missing or different `spec_version`.

## Status and migration

- `checks.yaml` holds 25 specs, each implemented in the spec registry
  (`backend/app/core/checks/spec/`) and scored with environmental metrics. The
  37 other checks are still legacy rules defined in `catalog.py` and
  `backend/app/core/checks/*.py`; `docs/check-triage.md` proposes which to
  specify, merge or drop.
- **Known issue in the catalog (for Asim): 31 of the 58 rules have a
  `base_score` that disagrees with their own vector.** For example, `INF-003`
  records 9.1 but its vector scores 7.5, and `AUT-006` records 7.5 but its
  vector scores 9.1. Those numbers are stored as the official CVSS base score,
  so each one needs either the vector or the score fixed. `make validate-config`
  lists them all. The new format prevents this because the score is always
  computed from the vector.

## Changes

- **spec_version 1, 2026-11-05 (proposed):** optional `applies_to` and `artifact`
  blocks; rule kinds `header_names` and `url`; body ops `not_empty` and `json`.
  Backward compatible: all 25 existing specs stay valid unchanged. Used by
  API-001, API-003, INF-003, INF-004, INF-005. Optional `status`
  (`approved` | `proposed`); those five are `proposed` until Asim approves them.
- **spec_version 1, 2026-10-25:** accept OWASP Top 10 2025 ids; add optional
  `severity_notes` (both from the per-person plan's Contract 1). Backward
  compatible: every existing file stays valid.

## Changing this format

Bump `spec_version` and `CHECK_SPEC_VERSION` in `backend/app/core/specs.py`, keep
the loader accepting the previous version until every file is migrated, and
update this document. Agree it with Atta first, because the engine evaluates it.
