# 03 — Installation & Running

> A fuller, Roman-Urdu walkthrough (with troubleshooting) lives in
> [`../HOW-TO-RUN.md`](../HOW-TO-RUN.md). This file is the concise reference.

## Requirements

- **Docker path:** Docker Desktop (with WSL2 integration on Windows).
- **Manual path:** Python 3.12, Node.js 18+, and optionally PostgreSQL + Redis.

## Option A — Docker (recommended, one command)

```bash
cd cawasma
make up                          # postgres + redis + api + worker (creates .env if missing)
docker compose --profile frontend up -d --build   # optional: the frontend too
```

| Service | URL |
|---------|-----|
| Frontend (UI) | http://localhost:5173 |
| API docs (Swagger) | http://localhost:8000/docs |
| Health | http://localhost:8000/health (also `/api/health`) |

Stop: `make down`. `make reset` wipes the database, then migrates and seeds a demo scan.

## Option B — Manual, no infrastructure (SQLite + inline)

The lightest way to run everything on a laptop — no PostgreSQL, Redis or Celery.

**Backend:**
```bash
cd cawasma
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e "backend[dev]"
cd backend
export DATABASE_URL="sqlite+aiosqlite:///./cawasma.db"
export ALEMBIC_SQLALCHEMY_URL="sqlite:///./cawasma.db"
export RUN_SCANS_INLINE=true
alembic upgrade head
uvicorn app.main:app --reload            # http://localhost:8000
```
> Windows PowerShell: use `$env:NAME="value"` instead of `export NAME=value`.

**Frontend:**
```bash
cd frontend
npm install
npm run dev                              # http://localhost:5173
```

## Option C — Manual, production-like (Postgres + Redis + Celery)

```bash
cp .env.example .env            # point DATABASE_URL / REDIS_URL at your services
cd backend
alembic upgrade head
uvicorn app.main:app --reload                                   # terminal 1
celery -A app.workers.celery_app.celery_app worker --loglevel=info   # terminal 2
cd ../frontend && npm install && npm run dev                     # terminal 3
```

## Configuration (`.env`)

Key settings (full list in `backend/app/config.py`, sample in `.env.example`):

| Variable | Purpose | Default |
|----------|---------|---------|
| `DATABASE_URL` | async DB URL | postgres (docker) |
| `REDIS_URL` | broker + pub/sub | `redis://redis:6379/0` |
| `FRONTEND_ORIGIN` | CORS allow-list (never `*`) | `http://localhost:3000` |
| `RUN_SCANS_INLINE` | run scans in-process (no Celery) | `false` |
| `REQUEST_TIMEOUT`, `MAX_RESPONSE_SIZE`, `MAX_ENDPOINTS`, `MAX_CRAWL_DEPTH`, `MAX_REDIRECTS`, `MAX_CONCURRENT_REQUESTS` | safety limits | see file |
| `LLM_ENABLED`, `LLM_PROVIDER`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` | optional LLM for URL expansion | off |

Optional AI keys are **never required** for the core scanner to run.

## Optional: NLP embedding layer

```bash
cd backend
# CPU-only torch first: without the extra index, sentence-transformers pulls the
# multi-GB CUDA build of torch from PyPI.
pip install torch==2.5.1 --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[ml]"                  # one time; includes spaCy's en_core_web_sm
```
The Docker image installs the CPU-only stack from `requirements-ml.txt` and
bakes both `en_core_web_sm` and `all-MiniLM-L6-v2` into its model cache during
the image build. Without the optional dependencies the classifier logs
`embeddings unavailable, keyword-only` and still works.

## Running the tests

```bash
make test        # SQLite; expected: 93 passed
make lint        # ruff + mypy
TEST_DATABASE_URL=postgresql+asyncpg://cawasma:cawasma@localhost:5446/cawasma_test make test   # against Postgres, as CI does
```

## Database migrations (Alembic)

Run from `backend/` (or `make migrate` to apply inside the api container).

```bash
alembic upgrade head                                   # apply
alembic revision --autogenerate -m "describe change"   # create a new migration
alembic downgrade -1                                   # roll back one
```
