# CAWASMA developer commands. Run from the repo root.
#   make up | down | test | lint | migrate | seed | reset

COMPOSE ?= docker compose
# The whole app: backend services plus the frontend (an opt-in compose profile).
APP := $(COMPOSE) --profile frontend
# The app plus the HTTPS demo target. That overlay lets the scanner reach one
# private host (ALLOWED_INTERNAL_HOSTS=demo-target), so it is never part of `up`.
DEMO := $(COMPOSE) -f docker-compose.yml -f docker-compose.demo.yml --profile frontend
# Host-side Python for test/lint; defaults to the repo venv when present.
PYTHON ?= $(if $(wildcard .venv/bin/python),$(CURDIR)/.venv/bin/python,python3)
BACKEND := backend

.DEFAULT_GOAL := help
.PHONY: help up up-backend demo down lock test lint typecheck migrate seed reset logs install env \
	validate-checks validate-config coverage-stats openapi ml-smoke eval-up eval-down eval-reset eval-collect

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

env:
	@test -f .env || (cp .env.example .env && echo "created .env from .env.example")

up: env ## Build and start the whole app: api, worker, postgres, redis, frontend
	$(APP) up -d --build --wait
	@echo "App: http://localhost:$${FRONTEND_HOST_PORT:-3000}  API: http://localhost:$${API_HOST_PORT:-8000}/docs"

up-backend: env ## Backend only: api, worker, postgres, redis (no frontend build)
	$(COMPOSE) up -d --build --wait
	@echo "API: http://localhost:$${API_HOST_PORT:-8000}/health  docs: /docs"

demo: env ## The whole app plus the HTTPS demo target (scan https://demo-target:8443/)
	$(DEMO) up -d --build --wait
	@echo "App: http://localhost:$${FRONTEND_HOST_PORT:-3000}  scan https://demo-target:8443/"

down: ## Stop everything up, up-backend or demo started (keeps the database volume)
	$(DEMO) down

logs: ## Follow logs of all services
	$(DEMO) logs -f

install: ## Install backend + dev tools into $(PYTHON)'s environment
	"$(PYTHON)" -m pip install -c "$(BACKEND)/constraints.txt" -e "$(BACKEND)[dev]"

lock: ## Regenerate backend/constraints.txt (every package, exact versions) from a dev+ML image
	docker build -q --build-arg INSTALL_DEV=true --build-arg INSTALL_ML=true \
		-t cawasma-backend:lock "$(BACKEND)" >/dev/null
	{ sed -n '/^#/p' "$(BACKEND)/constraints.txt"; \
	  docker run --rm --entrypoint pip cawasma-backend:lock freeze --all \
		--exclude cawasma-backend --exclude pip --exclude en-core-web-sm; } \
		> "$(BACKEND)/constraints.txt.new" && mv "$(BACKEND)/constraints.txt.new" "$(BACKEND)/constraints.txt"

test: ## Run the test suite on the host (SQLite; set TEST_DATABASE_URL for Postgres)
	cd $(BACKEND) && "$(PYTHON)" -m pytest -q

lint: ## ruff (lint + format check) + mypy
	cd $(BACKEND) && "$(PYTHON)" -m ruff check . && "$(PYTHON)" -m ruff format --check . \
		&& "$(PYTHON)" -m mypy

validate-checks: ## Validate config/checks.yaml (specs + CVSS vectors)
	cd $(BACKEND) && "$(PYTHON)" scripts/validate_specs.py checks

validate-config: ## Validate checks, cvss_mapping and chains YAML; report catalog score drift
	cd $(BACKEND) && "$(PYTHON)" scripts/validate_specs.py all

check-coverage: ## Write docs/check-coverage.md (every check id: implementation, tests, passing)
	cd $(BACKEND) && "$(PYTHON)" scripts/check_coverage.py

coverage-stats: ## Spec / ground truth / environmental vs legacy counts (for the report)
	cd $(BACKEND) && "$(PYTHON)" scripts/coverage_stats.py

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

NUCLEI_TEMPLATES_VERSION := 10.1.1
NUCLEI_TEMPLATES_SHA256 := 45f427f4b44facea80e4bbb5a400826222fd564006aa8423047abe65637cfc01

eval-templates: ## Download the pinned nuclei-templates release once (sha256-checked) into eval/.cache
	@mkdir -p eval/.cache
	@test -d eval/.cache/nuclei-templates-$(NUCLEI_TEMPLATES_VERSION) || ( \
	  curl -sSL -o eval/.cache/nt.tar.gz https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v$(NUCLEI_TEMPLATES_VERSION).tar.gz && \
	  echo "$(NUCLEI_TEMPLATES_SHA256)  eval/.cache/nt.tar.gz" | sha256sum -c - && \
	  tar -xzf eval/.cache/nt.tar.gz -C eval/.cache && rm eval/.cache/nt.tar.gz )

eval: eval-templates ## Full evaluation: reset targets, scan with CAWASMA/ZAP/Nuclei, write eval/results/
	PYTHONHASHSEED=0 "$(PYTHON)" eval/harness/run_all.py

eval-down: ## Stop and remove evaluation target containers
	$(COMPOSE) -f docker-compose.eval.yml down

eval-reset: ## Remove evaluation containers and their anonymous volumes
	$(COMPOSE) -f docker-compose.eval.yml down --volumes --remove-orphans
