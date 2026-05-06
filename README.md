# CAWASMA

## Context-Aware Web and API Security Misconfiguration Analyzer

CAWASMA is a Flask-based security analysis platform for detecting web and API misconfigurations using a black-box scanning approach. It accepts a target URL, discovers reachable endpoints, analyzes responses, generates findings, adjusts risk scores using contextual signals, and correlates related issues into exploit chains.

This repository is the working implementation for the Final Year Project (FYP). It includes:

- a server-rendered frontend for launching scans and viewing reports
- a Flask backend for routing, API access, and persistence
- a scanning engine for crawling, classification, detection, and scoring
- a relational database for storing scans, endpoints, findings, and chains

## What This Project Does

At a practical level, CAWASMA performs this workflow:

1. A user submits a target web application or API URL.
2. The crawler discovers reachable paths and endpoints from the target.
3. Each endpoint is classified by sensitivity.
4. Response headers, cookies, body content, and status signals are inspected.
5. The system generates security findings for detected misconfigurations.
6. Findings are rescored using context-aware severity adjustment.
7. Related findings are grouped into exploit-chain style correlations.
8. Results are stored and presented in the dashboard and API.

The project is designed for security analysis demonstrations, academic evaluation, and further extension in later FYP phases.

## Features

- Launch scans from a browser dashboard
- Launch scans programmatically through a JSON API
- Crawl same-origin targets and discover reachable endpoints
- Extract links, forms, scripts, and route-like paths
- Classify endpoint sensitivity as `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`
- Detect security misconfiguration indicators in:
  - response headers
  - cookies
  - response bodies
  - error and debug output
- Detect body-level signals such as:
  - email addresses
  - phone numbers
  - JWT-like tokens
  - API key or secret-like patterns
  - financial keywords
  - infrastructure/environment hints
- Adjust CVSS-style scores using sensitivity and body-signal context
- Correlate related findings into exploit chains
- Persist scans and results in SQLite by default
- Export scan data through the API
- Fall back to inline scan execution when Redis is unavailable

## Tech Stack

### Frontend

- HTML templates with Jinja2
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

CAWASMA is organized into four main layers:

### 1. Presentation Layer

The UI is server-rendered using Flask templates. Users can:

- launch a new scan
- view recent scan history
- open scan detail pages
- inspect findings and summaries

Main files:

- `app/templates/base.html`
- `app/templates/index.html`
- `app/templates/scan.html`
- `app/static/css/main.css`
- `app/static/js/app.js`

### 2. Application Layer

The Flask application handles routing, request processing, API responses, and app startup.

Main files:

- `app/__init__.py`
- `app/routes.py`
- `app/api.py`
- `run.py`

### 3. Scanning and Analysis Layer

This is the core engine. It performs crawling, endpoint classification, finding generation, score adjustment, and exploit-chain correlation.

Main files:

- `app/scanner/engine.py`
- `app/scanner/crawler.py`
- `app/scanner/checks.py`
- `app/scanner/sensitivity.py`
- `app/scanner/body_classifier.py`
- `app/scanner/cvss.py`
- `app/scanner/chains.py`
- `app/scanner/reports.py`

### 4. Persistence and Background Execution Layer

This layer stores results and manages scan execution either through Redis/Celery or inline fallback.

Main files:

- `app/models.py`
- `app/extensions.py`
- `app/tasks.py`
- `config.py`

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
│   │   ├── __init__.py
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
│   │   │   └── main.css
│   │   └── js/
│   │       └── app.js
│   └── templates/
│       ├── base.html
│       ├── index.html
│       └── scan.html
├── ai/
├── docs/
│   └── use-case-diagram.puml
├── instance/
│   └── cawasma.db
├── report/
├── reports/
├── scanner/
├── scoring/
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

## Key Files and What They Do

This section explains the most important files in the project and their role in the system.

### Root-Level Files

#### `run.py`

Development entry point. It creates the Flask app and starts it through SocketIO:

- creates the app using `create_app()`
- runs the server on `0.0.0.0:5000`
- respects the `DEBUG` setting from config

#### `config.py`

Central configuration file. It loads `.env` values and defines:

- development, production, and testing configs
- database URL
- Redis/Celery broker settings
- scanner limits such as timeout, crawl depth, and endpoint count
- report output path

#### `.env.example`

Template for environment configuration. Copy this to `.env` before running locally.

#### `requirements.txt`

Runtime dependencies required to launch the project.

#### `requirements-dev.txt`

Development dependencies. Currently extends runtime dependencies and adds `pytest`.

#### `requirements-ml.txt`

Placeholder for optional ML-related dependencies. The current codebase does not actively import extra ML packages from here.

## Application Package: `app/`

### `app/__init__.py`

Flask application factory.

Responsibilities:

- creates the Flask app instance
- loads configuration
- creates `instance/` and report output directories
- initializes SQLAlchemy and SocketIO
- initializes Celery integration
- registers UI and API blueprints
- creates database tables on startup

### `app/extensions.py`

Holds shared Flask extension instances:

- `db` for SQLAlchemy
- `socketio` for progress/event emission

### `app/models.py`

Defines the database schema.

Main models:

- `Scan`
  Stores the submitted target, profile, status, summary, and timestamps
- `Endpoint`
  Stores discovered endpoints and their sensitivity level
- `Finding`
  Stores generated issues, severity, scores, evidence, and details
- `ExploitChain`
  Stores correlated multi-signal or multi-finding attack chains

### `app/routes.py`

Web UI routes.

Responsibilities:

- render the homepage dashboard
- launch scans from the form
- show recent scans
- show detailed findings for a specific scan
- compute UI summaries such as severity totals and top scores

Important routes:

- `GET /`
- `POST /launch`
- `GET /scans/<scan_id>`

### `app/api.py`

JSON API routes.

Responsibilities:

- create scans through JSON
- fetch scan status and results
- export summary information

Important routes:

- `POST /api/scans`
- `GET /api/scans/<scan_id>`
- `GET /api/scans/<scan_id>/export`

### `app/tasks.py`

Background execution layer.

Responsibilities:

- initialize Celery with Flask config
- check Redis availability
- queue tasks when Redis is available
- run scans inline when Redis is unavailable

This is important because the current project supports both:

- asynchronous queue-backed execution
- synchronous fallback execution for simpler setups

## Scanner Package: `app/scanner/`

### `app/scanner/engine.py`

Core orchestration engine.

This file is the main execution pipeline for a scan:

1. marks the scan as `running`
2. calls the crawler
3. creates `Endpoint` records
4. classifies endpoint sensitivity
5. classifies response-body signals
6. builds findings from checks
7. adjusts scores
8. emits progress events
9. correlates exploit chains
10. marks the scan as `complete`
11. writes the summary

### `app/scanner/crawler.py`

Discovers reachable endpoints from a seed URL. It is responsible for collecting pages and route candidates from the target application.

### `app/scanner/checks.py`

Contains the heuristic rules for generating findings. This is where misconfiguration detection logic is assembled from the scan context.

### `app/scanner/sensitivity.py`

Classifies an endpoint path into a sensitivity level such as `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.

### `app/scanner/body_classifier.py`

Scans response content for important contextual signals, such as secrets, PII, or infrastructure-related terms.

### `app/scanner/cvss.py`

Adjusts base risk scores according to contextual information such as endpoint sensitivity and body-signal bonuses.

### `app/scanner/chains.py`

Correlates findings and signals into higher-level exploit chains.

### `app/scanner/reports.py`

Provides report-export helpers for:

- JSON export
- CSV export

## Frontend Files

### `app/templates/base.html`

Shared layout used by the application:

- header
- navigation
- theme switch
- footer

### `app/templates/index.html`

Homepage / dashboard page:

- launch scan form
- recent scans section
- workflow explanation

### `app/templates/scan.html`

Detailed report page for a specific scan:

- scan summary
- findings list
- chain information
- endpoint overview

### `app/static/css/main.css`

Main styling file for the integrated frontend. It controls layout, responsiveness, color themes, dashboard styling, and page-level presentation.

### `app/static/js/app.js`

Frontend behavior file. It handles UI interactions such as:

- theme toggling
- mobile navigation
- responsive scan row expansion
- interactive filtering behavior

## How the System Works

### End-to-End Request Flow

1. The user opens the homepage at `/`.
2. The user submits a target URL from the Launch Scan form.
3. `app/routes.py` receives the form submission at `POST /launch`.
4. A `Scan` row is created in the database with status `queued`.
5. `app/tasks.py` decides how to execute the scan:
   - queue with Celery if Redis is available
   - run inline if Redis is unavailable
6. `app/scanner/engine.py` starts the scan.
7. `app/scanner/crawler.py` discovers reachable endpoints.
8. `app/scanner/sensitivity.py` classifies each endpoint.
9. `app/scanner/body_classifier.py` extracts contextual body signals.
10. `app/scanner/checks.py` generates misconfiguration findings.
11. `app/scanner/cvss.py` adjusts finding severity scores.
12. `app/scanner/chains.py` correlates related issues into exploit chains.
13. Results are stored in `Scan`, `Endpoint`, `Finding`, and `ExploitChain` tables.
14. The browser is redirected to `GET /scans/<scan_id>`.
15. The scan detail page renders the final results.

### API Flow

1. A client sends `POST /api/scans` with a target URL.
2. A `Scan` row is created.
3. The scan is queued or executed inline.
4. The client polls `GET /api/scans/<scan_id>`.
5. The client can retrieve a simplified export from `GET /api/scans/<scan_id>/export`.

## Installation and Setup

### Prerequisites

- Python 3.11 or newer recommended
- `venv`
- `pip`
- Optional: Redis for background queue execution

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd Context-Aware-Web-and-API-Security-Misconfiguration-Analyzer
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
```

### 3. Activate the Virtual Environment

### Linux / macOS

```bash
source venv/bin/activate
```

### Windows PowerShell

```powershell
venv\Scripts\Activate.ps1
```

### 4. Install Dependencies

### Runtime Only

```bash
pip install -r requirements.txt
```

### Development and Testing

```bash
pip install -r requirements-dev.txt
```

### 5. Configure Environment Variables

Copy the sample environment file:

```bash
cp .env.example .env
```

Then edit `.env` as needed.

### Environment Variables

The most important environment variables are:

| Variable | Purpose | Default |
| --- | --- | --- |
| `FLASK_SECRET_KEY` | Flask secret key | `dev-secret-change-this` |
| `FLASK_DEBUG` | Enables debug mode | `True` |
| `FLASK_TESTING` | Enables testing mode | `False` |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///instance/cawasma.db` |
| `REDIS_URL` | Redis base URL | `redis://localhost:6379/0` |
| `CELERY_BROKER_URL` | Celery broker URL | `redis://localhost:6379/0` |
| `CELERY_RESULT_BACKEND` | Celery result backend | `redis://localhost:6379/1` |
| `SCAN_TIMEOUT` | Scan timeout value | `30` |
| `MAX_CRAWL_DEPTH` | Max crawl depth | `2` |
| `MAX_ENDPOINTS` | Max endpoints per scan | `100` |
| `RATE_LIMIT_BURST` | Rate limit burst setting | `20` |
| `REPORT_OUTPUT_DIR` | Directory for saved reports | `reports` |
| `SOCKETIO_ASYNC_MODE` | SocketIO async mode | `threading` |
| `OPENAI_API_KEY` | Optional key for future AI integration | empty |
| `ANTHROPIC_API_KEY` | Optional key for future AI integration | empty |
| `NLP_MODEL_NAME` | Optional NLP model identifier | `all-MiniLM-L6-v2` |

### 6. Run the Application

```bash
python run.py
```

The application will start on:

```text
http://127.0.0.1:5000
```

### Optional: Run with Redis and Celery

If you want scan jobs to run through a queue instead of inline fallback:

1. Start Redis
2. Keep your Flask app running
3. Start a Celery worker in another terminal

Example Celery worker command:

```bash
celery -A app.tasks.celery_app worker --loglevel=info
```

If Redis is not available, the application still works by executing scans inline.

## Usage Guide

### Using the Web Interface

1. Start the application with `python run.py`
2. Open `http://127.0.0.1:5000`
3. In the `Launch New Scan` section, enter a target URL
4. Choose a scan profile
5. Click `Scan`
6. Wait for the scan to complete
7. Review the results in the scan detail page
8. Return to the dashboard to view recent scans

### Using the JSON API

### Create a Scan

```bash
curl -X POST http://127.0.0.1:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "profile": "Standard"
  }'
```

Example response:

```json
{
  "scan_id": 1,
  "status": "queued"
}
```

### Get a Scan Result

```bash
curl http://127.0.0.1:5000/api/scans/1
```

### Export a Scan Summary

```bash
curl http://127.0.0.1:5000/api/scans/1/export
```

## API Overview

### `POST /api/scans`

Creates a new scan.

Request body:

```json
{
  "target_url": "https://example.com",
  "profile": "Standard",
  "auth_token": "optional-token"
}
```

### `GET /api/scans/<scan_id>`

Returns:

- scan metadata
- current status
- summary text
- findings list
- exploit chain list

### `GET /api/scans/<scan_id>/export`

Returns a simplified JSON export containing:

- target URL
- finding titles
- chain names

## Screens and Pages Overview

### Homepage: `/`

Purpose:

- entry point of the application
- launch new scans
- view recent scans
- understand the scan workflow

Main file:

- `app/templates/index.html`

### Scan Detail Page: `/scans/<scan_id>`

Purpose:

- inspect findings for a single scan
- review severity ordering
- view exploit chains
- review endpoint sensitivity information

Main file:

- `app/templates/scan.html`

## Database Output

By default, local data is stored in:

```text
instance/cawasma.db
```

The main stored entities are:

- `Scan`
- `Endpoint`
- `Finding`
- `ExploitChain`

## Testing

Run the test suite with:

```bash
pytest
```

The current tests cover:

- app creation
- scan engine behavior
- finding generation
- exploit-chain logic
- report export helpers

## Current Scope and Limitations

This repository represents the current implementation state of the FYP and should be understood within that scope.

Current limitations include:

- heuristic-based detection only
- no authenticated scan flow currently exposed in the UI
- no full distributed task monitoring dashboard
- simplified export endpoints
- same-origin crawling focus
- SQLite default storage for local development

The project is functional, but still suitable for expansion in later milestones.

## Future Improvements

- richer report export formats
- more advanced detection rules
- broader API testing coverage
- stronger progress reporting in the UI
- authentication-aware scanning workflows
- improved queue monitoring and job tracking
- optional AI-assisted result summarization

## Contribution Guidelines

If you want to contribute:

1. Fork the repository
2. Create a feature branch
3. Make focused changes
4. Run the tests
5. Open a pull request with a clear description

Recommended contribution areas:

- detection logic in `app/scanner/checks.py`
- crawl strategy in `app/scanner/crawler.py`
- reporting/export enhancements in `app/scanner/reports.py`
- UI improvements in `app/templates/` and `app/static/`

## License

No license file is currently included in this repository.

If you intend to publish or distribute the project, add a license such as:

- MIT
- Apache-2.0
- GPL-3.0

## Quick Start Summary

If you only need the minimum steps:

```bash
git clone <your-repository-url>
cd Context-Aware-Web-and-API-Security-Misconfiguration-Analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python run.py
```

Then open:

```text
http://127.0.0.1:5000
```
