# Database layer: decisions and assumptions

Choices made while implementing the data model (docs/08, schema in
[schema.md](schema.md)) where the spec was ambiguous or conflicted with the
existing code. Each one says what to revisit. Owner: Atta. Items marked
**Neelam** or **Asim** need their input.

## D1. The ten entities

The ten entities are the ten tables in docs/08: `scans`, `endpoints`,
`findings`, `headers`, `cookies`, `tls_info`, `attack_chains`,
`chain_findings` (link table), `ai_insights`, `feedback`.

There is **no `targets` table**. A target is the `scans.target_url` value; the
seed's "1 target, 2 scans" is two scans of the same URL, and the
`(target_url, created_at)` index makes "scan history for a target" cheap.
*Revisit* if targets need their own data (owner, scope, an authorisation
document), then add `targets` and a `scans.target_id` foreign key.

## D2. Finding column names vs the API contract

The spec's names are used in the database: `check_id` (was `rule_id`),
`base_score` (was `cvss_base_score`), `final_score` (was
`cawasma_final_score`), `severity_bucket` (was `severity`).

The **REST/report JSON keeps the old names** (`rule_id`, `cvss_base_score`,
`cawasma_final_score`, `severity`), mapped in `api/schemas/endpoint.py` and
`services/report_service.py`. The frontend reads those names, and changing
them would mean editing Neelam's files. New fields are additive: `owasp_map`,
`cwe_map`, `evidence_details`. **Neelam:** say if you'd rather the API use
the new names. It's a one-file change on the backend side.

The scanner core (`core/`) keeps its own dataclass names (`RawFinding.rule_id`,
`ScoreResult.cvss_base_score`); it is DB-free, and only
`services/result_service.py` maps them to columns.

## D3. Scan status

Stored as `QUEUED`, `RUNNING`, `DONE`, `FAILED` (uppercase like every other
enum in the schema). The old `CANCELLED` value was dropped: there is no cancel
feature. The old `COMPLETED` is now `DONE`.

The API and reports publish `DONE`. (Until 2026-11-05 the pre-contract routes
published it as `"COMPLETED"` through `ScanStatus.public_value`; both were
removed with those routes.)

## D4. `owasp_map` and `cwe_map`

JSON arrays of strings, never null (default `[]`), e.g. `["API8:2023"]`,
`["CWE-1021"]`. The check catalog does not carry these mappings yet, so
**findings from live scans currently store `[]`**. The seed's values are
illustrative standard IDs. **Asim:** the authoritative mapping belongs in
`core/checks/catalog.py` (your file); once it is there, `result_service` will
copy it onto each finding.

## D5. JSON storage

All JSON columns use `JSONType` (`backend/app/db/base.py`): **JSONB on
PostgreSQL**, plain JSON on SQLite so the test suite stays portable.

`findings.evidence` is a JSON object, never null: `{"text": <redacted summary>,
...check-specific keys}`. Live scans currently write `{"text": ...}` only.
Everything in it is redacted before it is written.

## D6. Endpoint sensitivity and body signals

The sensitivity class is the existing `context_class` column (CRITICAL / HIGH /
MEDIUM / LOW) with `context_confidence` and `context_reason`. It was not renamed
because the classifier, scoring and checks all use "context class".

`body_signals` is JSONB with a fixed shape, `{}` when no body was analysed:

```json
{"credentials": false, "pii": true, "financial": false, "internal_ip": false,
 "bonus": 2.0, "reasons": ["email address", "phone number"]}
```

A JSON object rather than four boolean columns, because Asim's ML classifier
may add signals. Queryable with JSONB operators if needed.

## D7. Scan options

`scans.options` (JSONB, default `{}`) stores a snapshot of the limits the scan
ran with (max endpoints, crawl depth, timeouts, LLM on/off, ...), taken from
settings at creation, so a result can be reproduced. There are no per-scan
user options yet; when the API accepts them they go into the same column.

## D8. Authorisation confirmation

`authorization_confirmed` (bool, default false) and `authorization_confirmed_at`
(timestamptz). A CHECK constraint enforces that the timestamp is set exactly
when the flag is true. `POST /api/scans` accepts an optional
`authorization_confirmed` and stamps the time server-side, but **does not
require it yet**, because the current form has no checkbox. *Follow-up*
(Neelam + Atta): add the checkbox, then reject unconfirmed scans in the API.

## D9. Nullability of scores

`cvss_vector`, `base_score` and `final_score` are NOT NULL: every finding comes
from a catalog rule that has a vector and base score. `cawasma_context_multiplier`
and `response_bonus` are kept (nullable) for explainability. They will change
when scoring moves to CVSS environmental metrics (see CLAUDE.md, "Current state
vs goal").

## D10. Host-level findings

`findings.endpoint_id` is nullable with `ON DELETE SET NULL`. Host-wide
findings such as TLS have no endpoint, and deleting an endpoint must not delete
its findings. `findings.scan_id` is required (cascade).

## D11. Feedback scope

docs/08 links `feedback` to `scans`; the previous model linked it to
`findings`. It now has both: `scan_id` required (cascade) and `finding_id`
optional (cascade). Feedback is either about one finding or a scan-level note.

## D12. INFO severity is unreachable today

`severity_bucket` keeps `INFO` (score 0.0), but no catalog check can produce
it: the lowest base score is 3.1 and the lowest multiplier is 0.6, which gives
1.9 (LOW). The seed therefore covers CRITICAL, HIGH, MEDIUM and LOW only, rather
than inventing a row the scanner could never create.

## D13. One initial migration

The two earlier migrations were replaced by a single `0001_initial_schema`.
The project is pre-release and the databases held only demo data.
**Existing dev databases must be reset once: `make reset`** (the api container
fails at startup with "Can't locate revision" until then). From now on, schema
changes are new migrations on top of 0001; never edit 0001.

PostgreSQL enums are native types; the downgrade drops them so
`downgrade base` → `upgrade head` works.

## D14. Foreign keys on SQLite

SQLite ignores foreign keys, and therefore every `ON DELETE` rule, unless
`PRAGMA foreign_keys=ON` is set per connection.
`db.session.enable_sqlite_foreign_keys` sets it for the app engine (SQLite run
mode) and the test engine, so cascade tests mean the same thing on both
databases.

## D15. Keys and timestamps

UUID v4 primary keys. All timestamps are timezone-aware (`timestamptz`);
`created_at`/`updated_at` have a server default of `now()`.

## D16. Where the scripts live

`backend/scripts/seed.py` and `backend/scripts/reset.py` (not a root
`scripts/`), so they ship in the backend Docker image and run inside the
container (`make seed`, `make reset`).

## D17. Data-model names vs column names

The data model in `docs/project/project-summary.md` lists key fields by
meaning; a few columns use names that were already in the code before the
model was imported. They mean the same thing:

| Data model | Column | Notes |
|------------|--------|-------|
| `SCAN.finished_at` | `scans.completed_at` | |
| `SCAN.authorised` | `scans.authorization_confirmed` + `authorization_confirmed_at` | flag plus timestamp, as the DB prompt asked |
| `SCAN.settings` | `scans.options` | D7 |
| `ENDPOINT.sensitivity_class` | `endpoints.context_class` | D6 |
| `ENDPOINT.discovery_strategy` | `endpoints.discovered_by` | `SEED`, `HTML`, `JAVASCRIPT`, `WORDLIST`, `RECURSIVE` |
| `COOKIE.flags`, `scope` | `cookies.http_only`, `secure`, `same_site`; `domain`, `path` | one column per flag |
| `TLS_INFO.protocol_versions` | `tls_info.protocols_offered` | |
| `TLS_INFO.cert_expiry` | `tls_info.cert_not_after` | |
| `ATTACK_CHAIN.template_id` | `attack_chains.chain_code` | e.g. `C005` |
| `ATTACK_CHAIN.composite_score` | `attack_chains.template_composite_score` | |
| `AI_INSIGHT.summary_text` | `ai_insights.summary` | |

FINDING matches the model field for field. Renaming the others would change
the API and reports for no gain, so they stay; new columns use the data-model
names (D18).

## D18. TLS_INFO is per host, not per endpoint

The data model says "TLS handshake per endpoint", but a TLS handshake belongs
to a host and port: every endpoint on `shop.example.com` gets the same
certificate and protocols. So `tls_info` has one row per scanned host
(`scan_id`, `host`), and TLS findings are host-level (`endpoint_id` null, D10).
Migration 0002 added the model's `weak_ciphers` and `issues` fields:
`weak_ciphers` holds weak cipher suites seen (today, the negotiated one, if
weak), and `issues` the TLS check ids that fired. *Revisit* if one scan ever
covers several hosts or ports: the rows already carry `host`.

## D19. The environmental vector is stored next to the base vector

Spec-registry checks are scored with CVSS v3.1 environmental metrics
(`core/cvss.py`): the check's base vector plus `CR`/`IR`/`AR` from the
endpoint's sensitivity class and body signals. `findings.cvss_vector` keeps
the official **base** vector (its meaning in the API contract), and migration
0003 adds `final_vector` (base + requirements) and `score_reasons`, so anyone
can paste `final_vector` into a CVSS v3.1 calculator and get `final_score`.
Both are nullable: legacy `@rule` findings still use the interim multiplier
formula, which has no vector. *Revisit* once every rule has moved to the
registry: then both can become required.

## Noticed while seeding (for Asim)

The built-in sensitivity classifier puts `/.env` in the **LOW** class. The
finding is still CRITICAL (credential exposure forces it), but the endpoint
class looks wrong for a secrets file.
