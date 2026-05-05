# CAWASMA

## Context-Aware Web and API Security Misconfiguration Analyzer

CAWASMA is a web-based security analysis system designed to detect misconfigurations in web applications and APIs using a black-box scanning approach. The current implementation is built with Python and Flask and focuses on discovering reachable endpoints, inspecting responses, generating findings, adjusting severity using context, and correlating related issues into higher-level exploit chains.

This repository represents the current working implementation for the Final Year Project (FYP). It includes the backend engine, persistence layer, JSON API, and a server-rendered frontend for launching scans and reviewing results.

## Features

- Launch security scans from a web dashboard or JSON API
- Crawl same-origin web targets and discover reachable endpoints
- Extract routes from HTML and lightweight JavaScript patterns
- Classify endpoint sensitivity into `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`
- Detect response-body signals such as PII, tokens, financial hints, and infrastructure terms
- Apply heuristic checks for:
  - missing security headers
  - insecure cookie attributes
  - permissive CORS behavior
  - error leakage and debug traces
  - sensitive file exposure indicators
  - risky inline scripts and body content
- Adjust CVSS-style scores using endpoint sensitivity and body-signal bonuses
- Correlate related findings into exploit chains
- Persist scans, endpoints, findings, and chains in a relational database
- View recent scans and detailed findings through the browser UI
- Export a JSON summary of scan findings through the API
- Fall back to inline execution when Redis is unavailable

## Tech Stack

### Frontend

- Server-rendered HTML templates with Jinja2
- Custom CSS
- Vanilla JavaScript
- Bootstrap Icons via CDN

### Backend

- Python 3
- Flask
- Flask-SQLAlchemy
- Flask-SocketIO
- Celery
- Redis
- HTTPX
- BeautifulSoup4

### Database

- SQLite by default

### Development and Testing

- `venv`
- `pytest`
- `python-dotenv`

## Project Architecture

At a high level, the system works as follows:

1. A scan request is created from the dashboard form or the `/api/scans` endpoint.
2. A `Scan` record is stored in the database with status `queued`.
3. The task layer checks whether Redis is available.
4. If Redis is available, the scan can be queued through Celery.
5. If Redis is unavailable, the scan runs inline inside the Flask application.
6. The scan engine crawls the target, discovers endpoints, and fetches responses.
7. Each endpoint is classified for sensitivity.
8. Response content is analyzed for body signals.
9. The checks registry generates findings from headers, cookies, body content, and status signals.
10. Findings are rescored using context-aware CVSS adjustment.
11. Related findings and body signals are correlated into exploit chains.
12. All results are persisted and made available through the UI and API.

### Main Runtime Components

- `app/routes.py`
  Handles the web UI routes.
- `app/api.py`
  Exposes JSON endpoints for scan creation, retrieval, and export.
- `app/tasks.py`
  Manages Celery integration and inline fallback behavior.
- `app/scanner/engine.py`
  Orchestrates crawl, classification, finding generation, scoring, and persistence.
- `app/scanner/crawler.py`
  Performs same-origin endpoint discovery.
- `app/scanner/checks.py`
  Contains the heuristic finding registry.
- `app/scanner/sensitivity.py`
  Classifies endpoint sensitivity.
- `app/scanner/body_classifier.py`
  Detects data-sensitive signals in response bodies.
- `app/scanner/cvss.py`
  Applies context-aware score adjustment.
- `app/scanner/chains.py`
  Correlates multiple signals into exploit chains.

## Folder Structure

```text
Context-Aware-Web-and-API-Security-Misconfiguration-Analyzer/
├── app/
│   ├── __init__.py
│   ├── api.py
│   ├── extensions.py
│   ├── models.py
│   ├── routes.py
│   ├── tasks.py
│   ├── scanner/
│   │   ├── body_classifier.py
│   │   ├── chains.py
│   │   ├── checks.py
│   │   ├── crawler.py
│   │   ├── cvss.py
│   │   ├── engine.py
│   │   ├── reports.py
│   │   └── sensitivity.py
│   ├── static/
│   │   ├── css/
│   │   └── js/
│   └── templates/
├── docs/
│   └── use-case-diagram.puml
├── instance/
│   └── cawasma.db
├── reports/
├── tests/
│   ├── test_chains.py
│   ├── test_checks.py
│   ├── test_engine.py
│   ├── test_reports.py
│   └── test_smoke.py
├── .env.example
├── config.py
├── requirements.txt
├── requirements-dev.txt
├── requirements-ml.txt
├── run.py
└── README.md
```

### Key Files and Directories

- `app/__init__.py`
  Creates the Flask app, loads config, initializes extensions, registers blueprints, and creates database tables.
- `app/models.py`
  Defines the `Scan`, `Endpoint`, `Finding`, and `ExploitChain` entities.
- `app/routes.py`
  Renders the landing page, scan launcher, dashboard summaries, and scan detail report.
- `app/api.py`
  Exposes machine-consumable scan endpoints.
- `app/scanner/`
  Contains the core engine and analysis pipeline.
- `app/templates/`
  Contains the user-facing pages.
- `app/static/`
  Contains the frontend styling and interaction scripts.
- `tests/`
  Covers smoke tests, engine execution, checks, chains, and export helpers.
- `instance/cawasma.db`
  Default SQLite database file for local development.

## How It Works

### End-to-End Flow

1. The user submits a target URL from the dashboard or sends a JSON request to the API.
2. The application stores a new `Scan` record.
3. The scan engine updates the scan status to `running`.
4. The crawler starts from the seed URL and collects:
   - HTML links
   - form actions
   - script sources
   - other resource paths
   - route-like strings found in JavaScript
   - common built-in endpoint guesses such as `/api`, `/login`, `/admin`, and `/health`
5. Each discovered endpoint is fetched and stored.
6. Endpoint paths are classified by sensitivity using keyword and anchor-based matching.
7. Response bodies are analyzed for signals such as:
   - email addresses
   - phone numbers
   - JWT-like tokens
   - API key or secret patterns
   - financial terminology
   - infrastructure/environment hints
8. The checks registry evaluates the response and may produce one or more findings.
9. Each finding receives:
   - a base score
   - an adjusted score
   - a severity label
   - supporting evidence
   - detailed explanation
10. The engine aggregates body signals and findings to detect exploit chains.
11. The scan is marked `complete` and summarized.
12. Results become visible in the browser UI and through API retrieval endpoints.

## Installation and Setup

### Prerequisites

- Python 3.11+ recommended
- `venv`
- Internet access if scanning external targets
- Optional: Redis if you want queued execution instead of inline fallback

### 1. Clone and Enter the Project

```bash
git clone <repository-url>
cd Context-Aware-Web-and-API-Security-Misconfiguration-Analyzer
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
```

### 3. Activate the Environment

On Linux/macOS:

```bash
source venv/bin/activate
```

On Windows PowerShell:

```powershell
venv\Scripts\Activate.ps1
```

### 4. Install Dependencies

For runtime only:

```bash
pip install -r requirements.txt
```

For development and tests:

```bash
pip install -r requirements-dev.txt
```

### 5. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` as needed.

### 6. Run the Application

```bash
python run.py
```

The app runs at:

```text
http://127.0.0.1:5000
```

## Environment Variables

Environment values are loaded from `.env` through `config.py`.

### Core Application

| Variable | Purpose | Default |
| --- | --- | --- |
| `FLASK_SECRET_KEY` | Flask secret key | `dev-secret-change-this` |
| `FLASK_DEBUG` | Enables debug mode | `True` |
| `FLASK_TESTING` | Enables testing mode | `False` |

### Database

| Variable | Purpose | Default |
| --- | --- | --- |
| `DATABASE_URL` | SQLAlchemy connection string | `sqlite:///instance/cawasma.db` |

### Queue and Background Execution

| Variable | Purpose | Default |
| --- | --- | --- |
| `REDIS_URL` | Base Redis connection URL | `redis://localhost:6379/0` |
| `CELERY_BROKER_URL` | Celery broker | `redis://localhost:6379/0` |
| `CELERY_RESULT_BACKEND` | Celery result backend | `redis://localhost:6379/1` |

### Scanner Controls

| Variable | Purpose | Default |
| --- | --- | --- |
| `SCAN_TIMEOUT` | General scan timeout setting | `30` |
| `MAX_CRAWL_DEPTH` | Maximum discovery depth | `2` |
| `MAX_ENDPOINTS` | Maximum discovered endpoints per scan | `100` |
| `RATE_LIMIT_BURST` | Reserved rate control setting | `20` |
| `TARGET_WORDLIST_SIZE` | Exposed tuning value for target enumeration | `200` |

### Reporting and Runtime

| Variable | Purpose | Default |
| --- | --- | --- |
| `REPORT_OUTPUT_DIR` | Output directory for generated report artifacts | `reports` |
| `SOCKETIO_ASYNC_MODE` | SocketIO async mode | `threading` |

### Reserved / Future-Facing Keys

| Variable | Purpose | Default |
| --- | --- | --- |
| `OPENAI_API_KEY` | Reserved for future enhancement | empty |
| `ANTHROPIC_API_KEY` | Reserved for future enhancement | empty |
| `NLP_MODEL_NAME` | Reserved model name setting | `all-MiniLM-L6-v2` |

### Example `.env`

```env
FLASK_SECRET_KEY=change-this-to-a-random-secret
FLASK_DEBUG=True
FLASK_TESTING=False
DATABASE_URL=sqlite:///instance/cawasma.db
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1
SCAN_TIMEOUT=30
MAX_CRAWL_DEPTH=2
MAX_ENDPOINTS=100
RATE_LIMIT_BURST=20
REPORT_OUTPUT_DIR=reports
SOCKETIO_ASYNC_MODE=threading
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
NLP_MODEL_NAME=all-MiniLM-L6-v2
```

## Usage Guide

### Running the Web Interface

1. Start the application:

```bash
python run.py
```

2. Open:

```text
http://127.0.0.1:5000
```

3. Use the launch form to enter:
   - target URL
   - scan profile
   - optional bearer token
4. Submit the scan.
5. Review:
   - live dashboard statistics
   - recent scans
   - detailed findings
   - exploit chains
   - endpoint summaries

### Running Through the API

Create a scan:

```bash
curl -X POST http://127.0.0.1:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "profile": "Standard",
    "auth_token": ""
  }'
```

Get scan details:

```bash
curl http://127.0.0.1:5000/api/scans/1
```

Export scan summary:

```bash
curl http://127.0.0.1:5000/api/scans/1/export
```

### Running Tests

```bash
python -m pytest
```

## API Overview

All API routes are mounted under `/api`.

### `POST /api/scans`

Creates a new scan.

Request body:

```json
{
  "target_url": "https://example.com",
  "profile": "Standard",
  "auth_token": ""
}
```

Behavior:

- validates that `target_url` is present
- creates a `Scan` record
- starts execution through the task layer

Success response:

```json
{
  "scan_id": 1,
  "status": "queued"
}
```

### `GET /api/scans/<scan_id>`

Returns structured scan data.

Response includes:

- scan ID
- target URL
- profile
- status
- summary
- findings
- exploit chains

### `GET /api/scans/<scan_id>/export`

Returns a simplified JSON export summary.

Response includes:

- target URL
- finding titles
- chain names

## Screens / Pages Overview

### Home / Dashboard Page

The root page (`/`) serves as the main user entry point. It currently includes:

- project introduction and hero section
- scan launch form
- summary statistics
- recent scans list
- workflow overview

### Scan Detail / Findings Report Page

The scan detail page (`/scans/<scan_id>`) displays:

- scan metadata
- top score summary
- severity counts
- filterable findings
- evidence and details for each finding
- exploit chains
- discovered endpoint summary
- JSON export link

## Limitations / Current Scope

This repository demonstrates a solid working base for the FYP, but it does not yet represent a fully complete production-grade security platform.

### Current Scope

- same-origin black-box crawling
- heuristic response inspection
- context-aware scoring
- exploit-chain correlation
- dashboard and API-based interaction

### Current Limitations

- The implementation is Flask-based, not a full MERN stack.
- Scan profiles such as `Quick`, `Standard`, and `Deep` are stored and displayed, but they do not yet change engine behavior.
- The optional bearer token is stored with the scan record, but it is not currently injected into outbound crawler requests.
- Crawling is lightweight and heuristic-based; it is not a full browser automation engine.
- Export helpers exist for JSON and CSV, but the public API currently exposes only a simple JSON summary endpoint.
- There is no user authentication or role-based access control.
- The project uses automatic table creation and does not yet include a migration workflow.
- The checks are deterministic heuristics and may not cover every real-world misconfiguration pattern.
- Report generation and advanced analytics are still limited compared to a mature security product.

## Future Improvements

- Implement authenticated target scanning using the stored bearer token
- Make scan profiles control crawl depth, endpoint limits, and analysis intensity
- Add downloadable PDF, CSV, and full JSON report routes
- Introduce user authentication and project-level scan ownership
- Add richer real-time progress updates in the frontend using SocketIO
- Expand the findings registry with more advanced misconfiguration checks
- Add browser-based crawling for JavaScript-heavy applications
- Add database migrations and environment-specific deployment workflows
- Improve reporting with remediation guidance, trends, and historical comparisons
- Add containerization and deployment automation

## Contribution Guidelines

Contributions should remain aligned with the project goal of context-aware web and API misconfiguration analysis.

### Basic Guidelines

1. Fork the repository or create a feature branch.
2. Keep changes focused and well-scoped.
3. Follow the existing project structure and naming conventions.
4. Add or update tests when changing scanner logic, export behavior, or API behavior.
5. Verify the application starts successfully before submitting changes.
6. Run the test suite before opening a pull request:

```bash
python -m pytest
```

### Suggested Workflow

```bash
git checkout -b feature/your-change
python -m pytest
git commit -m "Describe your change"
```

## License

No license file is currently included in this repository.

If this project will be published publicly, add an appropriate license such as MIT, Apache-2.0, or another institution-approved license before release.

## Notes for FYP Review

For evaluation purposes, this implementation already demonstrates:

- a working scan lifecycle
- backend persistence
- endpoint discovery
- contextual severity scoring
- exploit-chain generation
- a functional UI
- API-driven interaction
- a tested codebase

At the same time, some advanced capabilities are intentionally still in-progress, which makes the project suitable to present as a meaningful partial milestone rather than a fully finalized security platform.
