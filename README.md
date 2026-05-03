# Context-Aware Web and API Security Misconfiguration Analyzer

CAWASMA is a Flask-based black-box scanner for web applications and REST APIs. It crawls a target, inspects response headers and bodies, creates security findings, adjusts severity using endpoint and body sensitivity, correlates related signals into exploit chains, and exposes the results through both a web dashboard and a JSON API.

This README documents the project as it exists in the current repository, so the setup and usage instructions here are meant to match the real code path rather than an older design document.

## What the project does

The current implementation provides:

- A Flask dashboard for launching scans and reviewing recent results
- A JSON API for creating scans and reading scan output
- Same-origin crawling with HTML link discovery and lightweight JavaScript route mining
- Heuristic endpoint sensitivity classification
- Response-body signal detection for PII, tokens, financial terms, and infrastructure hints
- Header, cookie, CORS, response-body, and exposure checks
- Context-adjusted CVSS scoring
- Exploit-chain correlation based on combinations of findings and body signals
- SQLite-backed persistence for scans, endpoints, findings, and chains

## Current architecture

At a high level, the scan flow is:

1. A scan is created from the dashboard or JSON API.
2. The scan is queued through Celery if Redis is available.
3. If Redis is unavailable, the scan runs inline inside the Flask app.
4. The crawler discovers same-origin endpoints from the seed page, common wordlist paths, and JavaScript route patterns.
5. Each discovered endpoint is classified for sensitivity.
6. Response content is checked for body signals and finding heuristics.
7. Findings receive adjusted CVSS scores based on endpoint sensitivity and body signals.
8. Related findings are correlated into exploit chains.
9. Results are stored in the database and shown in the UI/API.

## Tech stack

- Python 3
- Flask
- Flask-SQLAlchemy
- Flask-SocketIO
- Celery
- Redis
- HTTPX
- BeautifulSoup4
- SQLite by default

## Repository structure

- `app/`
  Flask application package.
- `app/__init__.py`
  Application factory, extension setup, blueprint registration, and database initialization.
- `app/routes.py`
  Dashboard routes.
- `app/api.py`
  JSON API routes.
- `app/models.py`
  SQLAlchemy models for scans, endpoints, findings, and exploit chains.
- `app/tasks.py`
  Celery integration and inline fallback behavior.
- `app/scanner/`
  Crawler, checks, CVSS adjustment, body classification, endpoint sensitivity, chain correlation, and report helpers.
- `app/templates/`
  Dashboard templates.
- `app/static/`
  Frontend assets for the dashboard.
- `tests/`
  Smoke, engine, finding, chain, and export tests.
- `config.py`
  Central configuration and environment variable loading.
- `run.py`
  Development entry point.
- `requirements.txt`
  Runtime dependencies required by the current code.
- `requirements-dev.txt`
  Runtime dependencies plus `pytest`.
- `.env.example`
  Example environment configuration.

## Requirements

Recommended:

- Python 3.11+ or 3.12+
- `venv`
- Internet access from the machine that will scan external targets

Tested in this workspace with:

- Python 3.13

## Quick start

From the project root:

```bash
python3 -m venv venv
./venv/bin/python -m pip install -r requirements-dev.txt
./venv/bin/python run.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Detailed setup

### 1. Create a virtual environment

```bash
python3 -m venv venv
```

### 2. Install dependencies

For normal runtime:

```bash
./venv/bin/python -m pip install -r requirements.txt
```

For development and tests:

```bash
./venv/bin/python -m pip install -r requirements-dev.txt
```

### 3. Optional environment configuration

If you want to override the defaults:

```bash
cp .env.example .env
```

Then edit `.env` as needed.

### 4. Start the application

```bash
./venv/bin/python run.py
```

The app binds to:

- `http://127.0.0.1:5000`
- `http://0.0.0.0:5000`

## Configuration

Environment variables are loaded from `.env` by `config.py`.

### Core Flask settings

- `FLASK_SECRET_KEY`
  Secret key for Flask sessions and security-related internals.
- `FLASK_DEBUG`
  Enables debug mode when set to `True`.
- `FLASK_TESTING`
  Enables testing mode when set to `True`.

### Database

- `DATABASE_URL`
  Defaults to a SQLite database under `instance/cawasma.db`.

Default:

```text
sqlite:///instance/cawasma.db
```

### Queue / Redis

- `REDIS_URL`
  Base Redis URL used as a fallback for broker/backend.
- `CELERY_BROKER_URL`
  Celery broker URL.
- `CELERY_RESULT_BACKEND`
  Celery result backend URL.

Important behavior:

- Redis is optional for local development.
- If Redis is unavailable, CAWASMA logs a warning and runs scans inline.
- You can use the app without setting up a separate Celery worker for basic local use.

### Scanner controls

- `SCAN_TIMEOUT`
  General timeout setting.
- `MAX_CRAWL_DEPTH`
  Maximum crawl depth for discovered links.
- `MAX_ENDPOINTS`
  Maximum number of endpoints to process in one scan.
- `RATE_LIMIT_BURST`
  Reserved configuration for rate-based checks.
- `TARGET_WORDLIST_SIZE`
  Config value exposed for scan tuning.

### Reporting / runtime

- `REPORT_OUTPUT_DIR`
  Directory used for generated report output.
- `SOCKETIO_ASYNC_MODE`
  Socket.IO async mode. The example config uses `threading`.

### External keys

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `NLP_MODEL_NAME`

Note:

- These values are present in config for future or extended functionality, but the current codebase does not import or require external LLM SDKs or transformer models in the base runtime path.

## Running the dashboard

After starting the server:

1. Open `http://127.0.0.1:5000`
2. Enter a target URL
3. Choose a profile
4. Optionally enter a bearer token
5. Launch the scan

The dashboard currently includes:

- A launch form on the home page
- A recent scans list
- A detail page for each scan
- Findings with severity and adjusted CVSS
- Correlated exploit chains with composite CVSS

### Current UI fields

The launch form accepts:

- `target_url`
- `profile`
- `auth_token`

Profiles available in the UI:

- `Quick`
- `Standard`
- `Deep`

Note:

- These profile values are stored with the scan and shown in the UI, but the current engine does not yet vary crawling or finding behavior based on profile selection.

## Running through the API

All API routes are mounted under `/api`.

### Create a scan

Endpoint:

```text
POST /api/scans
```

Example:

```bash
curl -X POST http://127.0.0.1:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "profile": "Standard",
    "auth_token": ""
  }'
```

Success response:

```json
{
  "scan_id": 1,
  "status": "queued"
}
```

Validation rule:

- `target_url` is required

### Get scan details

Endpoint:

```text
GET /api/scans/<scan_id>
```

Example:

```bash
curl http://127.0.0.1:5000/api/scans/1
```

Returns:

- scan metadata
- profile
- status
- summary
- finding list
- chain list

### Export scan summary

Endpoint:

```text
GET /api/scans/<scan_id>/export
```

Example:

```bash
curl http://127.0.0.1:5000/api/scans/1/export
```

Current behavior:

- Returns a JSON summary of the scan target, finding titles, and chain names
- It does not currently stream a PDF or CSV file directly from this endpoint

## Database behavior

The app automatically creates tables on startup through the Flask app factory.

Default entities:

- `Scan`
- `Endpoint`
- `Finding`
- `ExploitChain`

For local development, this means you usually do not need to run a separate migration step just to get started.

## How crawling works

The crawler is intentionally lightweight and same-origin focused.

Discovery sources include:

- the original seed URL
- HTML anchors
- form actions
- script sources
- image, link, and source tags
- JavaScript route-like strings
- a small built-in wordlist of common paths

Examples of common seeded paths:

- `/api`
- `/api/v1`
- `/api/v2`
- `/health`
- `/login`
- `/status`
- `/robots.txt`
- `/.well-known/security.txt`
- `/admin`
- `/users`
- `/auth`
- `/data`
- `/graphql`
- `/rest`

The crawler skips:

- non-HTTP(S) URLs
- different-origin URLs
- common static assets
- obvious archive/binary-style targets such as `.zip`, `.tar`, `.gz`, `.exe`, and `.dmg`

## How findings are produced

Each discovered endpoint is processed through:

1. endpoint sensitivity classification
2. body signal detection
3. finding heuristic checks
4. CVSS adjustment
5. exploit-chain correlation

The current checks focus on areas such as:

- missing security headers
- exposed server/framework headers
- insecure cookies
- permissive CORS
- inline scripts and risky body content
- stack traces and error leakage
- admin path exposure
- health endpoint exposure
- robots.txt hints
- sensitive-file indicators
- backup-file indicators

## Scoring model

Findings start from a base CVSS-like value and are adjusted using:

- endpoint sensitivity label
- response-body signal bonus

Endpoint sensitivity labels:

- `LOW`
- `MEDIUM`
- `HIGH`
- `CRITICAL`

Body signals can add extra weight when the response suggests:

- PII
- tokens or secrets
- financial information
- infrastructure identifiers

## Exploit chains

The project also correlates combinations of signals into higher-level chains, such as:

- XSS and insecure cookie combinations
- CORS and token leakage combinations
- debug exposure and secret leakage combinations
- admin-surface and transport-hardening combinations

These are stored separately from single findings so the scan can highlight combined attack paths, not just isolated issues.

## Authentication handling

The UI and API both accept an optional bearer token string when a scan is created.

Current state:

- The token is stored on the `Scan` record
- The current crawler/engine path does not yet inject that token into outbound target requests

That means:

- authenticated scan support is partially modeled in data and UI
- full authenticated request execution is not yet implemented in the current scanner path

## Reports and exports

The repository includes export helpers for:

- JSON
- CSV

Current note:

- Export helper functions exist in the scanner/report layer
- The public API currently exposes a simple JSON export summary endpoint
- Direct downloadable report workflows are not fully wired into the web routes yet

## Development workflow

### Run tests

```bash
./venv/bin/python -m pytest -q
```

### Byte-compile sanity check

```bash
./venv/bin/python -m py_compile app/*.py app/scanner/*.py tests/*.py run.py config.py
```

### Verify dependency health

```bash
./venv/bin/python -m pip check
```

## Example local workflow

```bash
python3 -m venv venv
./venv/bin/python -m pip install -r requirements-dev.txt
cp .env.example .env
./venv/bin/python run.py
```

Then in another terminal:

```bash
curl -X POST http://127.0.0.1:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url":"https://example.com","profile":"Standard"}'
```

## Troubleshooting

### The app does not start

Check:

- the virtual environment exists
- dependencies were installed
- you are running from the project root

Start command:

```bash
./venv/bin/python run.py
```

### Redis is not running

This is usually fine for local development.

Expected behavior:

- CAWASMA detects the broker is unavailable
- it runs the scan inline instead of queueing it

### The database file is missing

The application factory creates the `instance/` directory and initializes tables automatically on startup.

### A scan seems limited

Tune these settings in `.env`:

- `MAX_CRAWL_DEPTH`
- `MAX_ENDPOINTS`
- `SCAN_TIMEOUT`

### API request returns `400`

For scan creation, make sure your JSON includes:

- `target_url`

## Security and usage notes

- Use this tool only against systems you are authorized to assess.
- Crawling and heuristic probing can create logs on target systems.
- The current implementation is designed as a development-stage scanner and should be validated before relying on it for production security decisions.

## Known limitations

The current repository is functional, but there are some important boundaries to keep in mind:

- scan profiles are stored but do not yet change engine behavior
- auth tokens are stored but not yet injected into outbound requests
- report export helpers exist, but full downloadable reporting flows are not wired into the UI
- configuration exposes some future-oriented settings that the current runtime path does not use yet
- the scanner is heuristic and lightweight, not a full authenticated DAST platform

## Files most useful to read first

If you want to understand the code quickly, start here:

1. `run.py`
2. `app/__init__.py`
3. `app/routes.py`
4. `app/api.py`
5. `app/tasks.py`
6. `app/scanner/engine.py`
7. `app/scanner/crawler.py`
8. `app/scanner/checks.py`

## License

No license file is currently included in the repository. Add one if you intend to distribute or publish the project.
