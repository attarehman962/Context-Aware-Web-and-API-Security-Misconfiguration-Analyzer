# CAWASMA database schema

PostgreSQL 16 in Docker and CI; SQLite for the quick test runs. Defined by the
SQLAlchemy models in `backend/app/db/models/` and created by the Alembic
migrations in `backend/migrations/versions/` (`0001` initial schema, `0002`
TLS weak ciphers and issues). It implements the data model in
[project/project-summary.md](project/project-summary.md); where a column name
differs from that table, see [db-decisions.md](db-decisions.md) D17.

Conventions for every table: UUID primary key `id`; `created_at` and
`updated_at` (timestamptz, set by the database), omitted from the tables
below. "JSON" columns are JSONB on PostgreSQL.

## Tables

| Table | One row per | Parent (on delete) |
|-------|-------------|--------------------|
| `scans` | scan job of a target URL | (root) |
| `endpoints` | URL + method discovered in a scan | `scans` (cascade) |
| `findings` | security finding from a check | `scans` (cascade); `endpoints` (set null) |
| `headers` | security-relevant response header (redacted) | `endpoints` (cascade) |
| `cookies` | cookie **metadata**; the value is never stored | `endpoints` (cascade) |
| `tls_info` | TLS / certificate facts for the scanned host | `scans` (cascade) |
| `attack_chains` | correlated chain of findings | `scans` (cascade) |
| `chain_findings` | link: which findings form a chain | `attack_chains`, `findings` (cascade) |
| `ai_insights` | executive summary text | `scans` (cascade) |
| `feedback` | analyst note / false-positive flag | `scans` (cascade); `findings` (cascade, optional) |

Deleting a scan deletes everything under it. Deleting an endpoint keeps its
findings (their `endpoint_id` becomes null).

### scans

| Column | Type | Notes |
|--------|------|-------|
| `target_url` | string, required | HTTPS URL; a "target" is this value (no separate table) |
| `status` | enum, required | `QUEUED` → `RUNNING` → `DONE` / `FAILED` |
| `progress`, `current_stage` | int, string | 0–100 and a human-readable stage |
| `options` | JSON, required | limits the scan ran with, e.g. `{"max_endpoints": 200, "max_crawl_depth": 2}` |
| `authorization_confirmed` | bool, required | operator confirmed they may test the target |
| `authorization_confirmed_at` | timestamptz | set exactly when the flag is true (DB constraint) |
| `started_at`, `completed_at`, `duration_seconds` | timestamptz, float | |
| `error_message` | text | why a scan failed |

### endpoints

| Column | Type | Notes |
|--------|------|-------|
| `scan_id` | FK, required | |
| `url`, `path`, `method` | string, required | unique per scan (`scan_id`, `url`, `method`) |
| `status_code`, `content_type`, `response_time` | int, string, float | |
| `context_class` | enum | **sensitivity class** from the NLP classifier: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `context_confidence`, `context_reason` | float, JSON list | classifier confidence and human-readable reasons |
| `body_signals` | JSON, required | `{"credentials", "pii", "financial", "internal_ip": bool, "bonus": float, "reasons": [str]}`, or `{}` if no body was analysed |
| `discovered_by` | enum | `SEED`, `HTML`, `JAVASCRIPT`, `WORDLIST`, `RECURSIVE` |

### findings

| Column | Type | Notes |
|--------|------|-------|
| `scan_id` | FK, required | |
| `endpoint_id` | FK | null for host-level findings (e.g. TLS) |
| `check_id` | string, required | catalog rule, e.g. `HDR-003` |
| `title`, `category`, `description` | string, enum, text | category: `HEADERS`, `COOKIES`, `CORS`, `TLS`, `REST_API`, `AUTH`, `INFO_DISCLOSURE` |
| `owasp_map` | JSON list, required | e.g. `["API8:2023"]` (`[]` until the catalog has mappings) |
| `cwe_map` | JSON list, required | e.g. `["CWE-1021"]` |
| `cvss_vector` | string, required | official CVSS v3.1 base vector of the check |
| `base_score` | float, required | official CVSS v3.1 base score, never modified |
| `context_class`, `context_confidence` | enum, float | copied from the endpoint at scoring time |
| `cawasma_context_multiplier`, `response_bonus` | float | inputs to the context-aware score |
| `final_score` | float, required | CAWASMA context-aware score (not an official CVSS value) |
| `final_vector`, `score_reasons` | string, JSON list | CVSS v3.1 base vector + `CR/IR/AR` that `final_score` recomputes from, and why each requirement was set (D19). Null for findings scored by the interim formula |
| `severity_bucket` | enum, required | `CRITICAL` ≥ 9.0, `HIGH` ≥ 7.0, `MEDIUM` ≥ 4.0, `LOW` ≥ 0.1, `INFO` |
| `evidence` | JSON, required | redacted: `{"text": "summary", ...check-specific keys}` |
| `impact`, `recommendation`, `references`, `limitation` | text, text, JSON list, text | |

### Other tables

- **headers**: `endpoint_id`, `name`, `value` (redacted where sensitive).
- **cookies**: `endpoint_id`, `name`, `value_length`, `http_only`, `secure`,
  `same_site` (`STRICT` / `LAX` / `NONE` / `UNSET`), `domain`, `path`.
- **tls_info** (one row per scanned host, not per endpoint; D18): `scan_id`, `host`,
  `protocols_offered` (JSON list), `negotiated_protocol`, `negotiated_cipher`,
  `weak_ciphers` (JSON list of weak suites seen), `issues` (JSON list of the TLS
  check ids that fired, e.g. `["TLS-001"]`), `cert_subject`, `cert_issuer`,
  `cert_not_after`, `is_self_signed`, `hostname_matches`.
- **attack_chains**: `scan_id`, `chain_code` (e.g. `C005`), `name`,
  `description`, `template_composite_score` (documented template value, not a
  computed CVSS), `severity`.
- **chain_findings**: `chain_id`, `finding_id` (composite primary key).
- **ai_insights**: `scan_id`, `provider` (`builtin`, `openai`, `anthropic`), `summary`.
- **feedback**: `scan_id`, `finding_id` (optional), `is_false_positive`, `note`.

## ER diagram

```mermaid
erDiagram
    SCANS ||--o{ ENDPOINTS : discovers
    SCANS ||--o{ FINDINGS : produces
    ENDPOINTS |o--o{ FINDINGS : "located at"
    ENDPOINTS ||--o{ HEADERS : returns
    ENDPOINTS ||--o{ COOKIES : sets
    SCANS ||--o{ TLS_INFO : probes
    SCANS ||--o{ ATTACK_CHAINS : correlates
    ATTACK_CHAINS ||--|{ CHAIN_FINDINGS : groups
    FINDINGS ||--o{ CHAIN_FINDINGS : "member of"
    SCANS ||--o{ AI_INSIGHTS : summarised_by
    SCANS ||--o{ FEEDBACK : receives
    FINDINGS |o--o{ FEEDBACK : "about"

    SCANS {
        uuid id PK
        string target_url
        enum status "QUEUED RUNNING DONE FAILED"
        int progress
        jsonb options
        bool authorization_confirmed
        timestamptz authorization_confirmed_at
        timestamptz started_at
        timestamptz completed_at
    }
    ENDPOINTS {
        uuid id PK
        uuid scan_id FK
        string url
        string path
        string method
        enum context_class "sensitivity class"
        float context_confidence
        jsonb body_signals
        enum discovered_by
    }
    FINDINGS {
        uuid id PK
        uuid scan_id FK
        uuid endpoint_id FK "nullable"
        string check_id
        jsonb owasp_map
        jsonb cwe_map
        string cvss_vector
        float base_score "official CVSS"
        float final_score "context-aware"
        string final_vector "base + CR/IR/AR"
        enum severity_bucket
        jsonb evidence "redacted"
    }
    HEADERS {
        uuid id PK
        uuid endpoint_id FK
        string name
        text value
    }
    COOKIES {
        uuid id PK
        uuid endpoint_id FK
        string name
        bool http_only
        bool secure
        enum same_site
    }
    TLS_INFO {
        uuid id PK
        uuid scan_id FK
        string host
        jsonb protocols_offered
        jsonb weak_ciphers
        jsonb issues "TLS check ids"
        timestamptz cert_not_after
    }
    ATTACK_CHAINS {
        uuid id PK
        uuid scan_id FK
        string chain_code
        float template_composite_score
        enum severity
    }
    CHAIN_FINDINGS {
        uuid chain_id PK, FK
        uuid finding_id PK, FK
    }
    AI_INSIGHTS {
        uuid id PK
        uuid scan_id FK
        string provider
        text summary
    }
    FEEDBACK {
        uuid id PK
        uuid scan_id FK
        uuid finding_id FK "nullable"
        bool is_false_positive
        text note
    }
```

## Working with it

```bash
make reset     # drop everything, apply migrations, load sample data
make seed      # sample data only: 1 target, 2 scans, 10 endpoints, 16 findings, 1 chain
make migrate   # apply new migrations
cd backend && alembic revision --autogenerate -m "describe change"   # after changing a model
```

Schema changes always go through a new migration; CI fails if the models and
migrations drift (`alembic check`).
