# CAWASMA developer commands. Run from the repo root.
#   make up | down | test | lint | migrate | seed | reset

COMPOSE ?= docker compose
# Host-side Python for test/lint; defaults to the repo venv when present.
PYTHON ?= $(if $(wildcard .venv/bin/python),$(CURDIR)/.venv/bin/python,python3)
BACKEND := backend

.DEFAULT_GOAL := help
.PHONY: help up down test lint typecheck migrate seed reset logs install env \
	validate-checks validate-config openapi ml-smoke eval-up eval-down eval-reset eval-collect

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

env:
	@test -f .env || (cp .env.example .env && echo "created .env from .env.example")

up: env ## Build and start api, worker, postgres, redis (waits until healthy)
	$(COMPOSE) up -d --build --wait
	@echo "API: http://localhost:$${API_HOST_PORT:-8000}/health  docs: /docs"

down: ## Stop the stack (keeps the database volume)
	$(COMPOSE) down

logs: ## Follow logs of all services
	$(COMPOSE) logs -f

install: ## Install backend + dev tools into $(PYTHON)'s environment
	"$(PYTHON)" -m pip install -e "$(BACKEND)[dev]"

test: ## Run the test suite on the host (SQLite; set TEST_DATABASE_URL for Postgres)
	cd $(BACKEND) && "$(PYTHON)" -m pytest -q

lint: ## ruff + mypy
	cd $(BACKEND) && "$(PYTHON)" -m ruff check . && "$(PYTHON)" -m mypy

validate-checks: ## Validate config/checks.yaml (specs + CVSS vectors)
	cd $(BACKEND) && "$(PYTHON)" scripts/validate_specs.py checks

validate-config: ## Validate checks, cvss_mapping and chains YAML; report catalog score drift
	cd $(BACKEND) && "$(PYTHON)" scripts/validate_specs.py all

check-coverage: ## Write docs/check-coverage.md (every check id: implementation, tests, passing)
	cd $(BACKEND) && "$(PYTHON)" scripts/check_coverage.py

openapi: ## Regenerate docs/openapi.json and docs/examples/*.json from the code (commit them)
	cd $(BACKEND) && "$(PYTHON)" scripts/export_openapi.py

ml-smoke: ## Load all-MiniLM-L6-v2 and spaCy inside the api image (needs make up)
	$(COMPOSE) exec -T api python -c "from sentence_transformers import SentenceTransformer as S; import spacy; \
	print(S('all-MiniLM-L6-v2').encode('api login').shape, [t.text for t in spacy.load('en_core_web_sm')('Reset the admin password')][:2])"

typecheck: ## mypy only
	cd $(BACKEND) && "$(PYTHON)" -m mypy

migrate: ## Apply Alembic migrations inside the api container
	$(COMPOSE) run --rm --no-deps api alembic upgrade head

seed: ## Insert sample data: 1 target, 2 scans, 10 endpoints, 16 findings (idempotent)
	$(COMPOSE) run --rm --no-deps api python scripts/seed.py

reset: ## Drop everything in the database, re-run migrations, seed (ALL DATA LOST)
	$(COMPOSE) run --rm --no-deps api python scripts/reset.py --yes --seed

eval-up: ## Start pinned isolated evaluation targets and wait for healthchecks
	$(COMPOSE) -f docker-compose.eval.yml up -d --wait

eval-collect: ## Collect endpoint paths from the running targets into eval/labels/endpoints_raw.csv
	EVAL_UID=$$(id -u) EVAL_GID=$$(id -g) $(COMPOSE) -f docker-compose.eval.yml run --rm collector

eval-down: ## Stop and remove evaluation target containers
	$(COMPOSE) -f docker-compose.eval.yml down

eval-reset: ## Remove evaluation containers and their anonymous volumes
	$(COMPOSE) -f docker-compose.eval.yml down --volumes --remove-orphans
