# =============================================================================
# EdgeGuard — Makefile
# =============================================================================
# Common shortcuts for development, testing, and deployment.
# Airflow (docker compose): metadata DB is PostgreSQL (airflow_postgres), not SQLite.
# MISP→Neo4j: per-event sync + Python chunk EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE + rel batch EDGEGUARD_REL_BATCH_SIZE
# (defaults in code; 0/all on chunk size = single pass, OOM risk — see README / COLLECTION_AND_SYNC_LIMITS.md).
#
# Usage:
#   make help          — list all targets
#   make install       — Docker Compose full-stack install (recommended)
#   make update        — git pull + auto Docker or pip (./install.sh --update)
#   make install-py    — Python/pip install into .venv (no Docker)
#   make start         — start all Docker services
#   make stop          — stop all Docker services
#   make test          — run the full test suite
#   make lint          — lint + format check
#   make health        — run the health check script
# =============================================================================

.DEFAULT_GOAL := help
.PHONY: help install install-py install-dev install-uv update start stop restart logs \
        build test lint fmt type-check health doctor deploy-check clean

PYTHON      := python3
PIP         := pip
VENV        := .venv
VENV_PYTHON := $(VENV)/bin/python
COMPOSE     := docker compose
# uv — fast drop-in pip replacement (10-100x faster installs)
# Install: curl -LsSf https://astral.sh/uv/install.sh | sh
UV          := uv

# ─────────────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  EdgeGuard — available targets"
	@echo "  ─────────────────────────────────────────────────────"
	@echo ""
	@echo "  INSTALL"
	@echo "    make install         Fast Docker Compose install (recommended)"
	@echo "    make update          git pull (ff-only) + auto Docker or pip (install.sh --update)"
	@echo "    make install-py      Python/pip install into .venv (no Docker)"
	@echo "    make install-dev     Python install + dev/test extras"
	@echo "    make install-uv      Same as install-dev but uses uv (10-100x faster)"
	@echo ""
	@echo "  DOCKER STACK"
	@echo "    make start           docker compose up -d (all services)"
	@echo "    make stop            docker compose down"
	@echo "    make restart         stop + start"
	@echo "    make build           rebuild Docker image"
	@echo "    make logs            tail all service logs"
	@echo "    make logs-graphql    tail GraphQL API logs"
	@echo "    make logs-api        tail REST API logs"
	@echo "    make monitoring      start Prometheus + Grafana overlay"
	@echo ""
	@echo "  DEVELOPMENT"
	@echo "    make test            run pytest (all tests)"
	@echo "    make test-graphql    run GraphQL tests only"
	@echo "    make lint            ruff check + format check"
	@echo "    make fmt             ruff format (auto-fix)"
	@echo "    make type-check      mypy static analysis"
	@echo "    make ci              lint + type-check + test (mirrors CI)"
	@echo ""
	@echo "  OPERATIONS"
	@echo "    make health          python src/health_check.py"
	@echo "    make doctor          edgeguard doctor (diagnose issues)"
	@echo "    make deploy-check    ./scripts/deployment_wiring_check.sh (Layer 1; LIVE=1 for health)"
	@echo "    make clean           remove .venv, __pycache__, .pytest_cache"
	@echo ""
	@echo "  SERVICES (after 'make start')"
	@echo "    Neo4j Browser  →  http://localhost:7474"
	@echo "    Airflow UI     →  http://localhost:8082"
	@echo "    REST API       →  http://localhost:8000/health"
	@echo "    GraphQL API    →  http://localhost:4001/graphql"
	@echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Install
# ─────────────────────────────────────────────────────────────────────────────
install: .env
	@./install.sh

install-py: .env $(VENV)/bin/activate
	$(VENV_PYTHON) -m pip install -e ".[api,graphql,monitoring]"
	@echo ""
	@echo "  Install complete. Activate with: source $(VENV)/bin/activate"
	@echo "  Verify with: make health"

install-dev: .env $(VENV)/bin/activate
	$(VENV_PYTHON) -m pip install -e ".[api,graphql,monitoring,dev]"
	@echo ""
	@echo "  Dev install complete. Run tests with: make test"

# uv path — 10-100x faster than pip; same result
install-uv: .env
	@if ! command -v uv &>/dev/null; then \
		echo "  uv not found. Installing..."; \
		curl -LsSf https://astral.sh/uv/install.sh | sh; \
	fi
	$(UV) venv $(VENV)
	$(UV) pip install -e ".[api,graphql,monitoring,dev]"
	@echo ""
	@echo "  Dev install complete (via uv). Run tests with: make test"

# git pull + same path as install (Docker default, or add --python / --dev via install.sh)
update:
	@./install.sh --update

$(VENV)/bin/activate:
	$(PYTHON) -m venv $(VENV)

.env:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo ""; \
		echo "  .env created from .env.example."; \
		echo "  Edit .env and set NEO4J_PASSWORD, MISP_URL, MISP_API_KEY before starting."; \
		echo ""; \
	fi

# ─────────────────────────────────────────────────────────────────────────────
# Docker Compose
# ─────────────────────────────────────────────────────────────────────────────
start: .env
	$(COMPOSE) up -d
	@echo ""
	@echo "  ✓ Stack started"
	@echo "    Neo4j Browser  →  http://localhost:7474"
	@echo "    Airflow UI     →  http://localhost:8082"
	@echo "    REST API       →  http://localhost:8000/health"
	@echo "    GraphQL API    →  http://localhost:4001/graphql"
	@echo ""

stop:
	$(COMPOSE) down

restart: stop start

build:
	$(COMPOSE) build

logs:
	$(COMPOSE) logs -f

logs-graphql:
	$(COMPOSE) logs -f graphql

logs-api:
	$(COMPOSE) logs -f api

monitoring: .env
	$(COMPOSE) -f docker-compose.yml -f docker-compose.monitoring.yml up -d
	@echo "  ✓ Monitoring started"
	@echo "    Prometheus  →  http://localhost:9090"
	@echo "    Grafana     →  http://localhost:3000"

# ─────────────────────────────────────────────────────────────────────────────
# Development
# ─────────────────────────────────────────────────────────────────────────────
test:
	NEO4J_URI=bolt://localhost:7687 NEO4J_USER=neo4j NEO4J_PASSWORD=test \
	MISP_URL=https://misp.local MISP_API_KEY=test-key-12345678901234567890 \
	$(PYTHON) -m pytest tests/ -v --cov=src --cov-report=term-missing --cov-fail-under=30

test-graphql:
	NEO4J_URI=bolt://localhost:7687 NEO4J_USER=neo4j NEO4J_PASSWORD=test \
	MISP_URL=https://misp.local MISP_API_KEY=test-key-12345678901234567890 \
	$(PYTHON) -m pytest tests/test_graphql_api.py -v

lint:
	$(PYTHON) -m ruff check src/ dags/ tests/
	$(PYTHON) -m ruff format --check src/ dags/ tests/

fmt:
	$(PYTHON) -m ruff format src/ dags/ tests/
	$(PYTHON) -m ruff check --fix src/ dags/ tests/

type-check:
	$(PYTHON) -m mypy src/ --ignore-missing-imports --no-error-summary

ci: lint type-check test

# ─────────────────────────────────────────────────────────────────────────────
# Operations
# ─────────────────────────────────────────────────────────────────────────────
health:
	$(PYTHON) src/health_check.py

doctor:
	$(PYTHON) src/edgeguard.py doctor

# Layer 1: preflight_ci (compileall, pytest, DagBag). Layer 3+: EDGEGUARD_DEPLOY_CHECK_LIVE=1 make deploy-check
deploy-check:
	@chmod +x scripts/deployment_wiring_check.sh 2>/dev/null || true
	@./scripts/deployment_wiring_check.sh

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "  ✓ Cleaned"
