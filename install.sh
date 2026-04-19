#!/usr/bin/env bash
# =============================================================================
# EdgeGuard — Installation Script
# =============================================================================
#
# FAST PATH (Docker Compose — recommended):
#   ./install.sh
#
# PYTHON-ONLY PATH (no Docker):
#   ./install.sh --python
#
# Options:
#   --update      Git pull latest (ff-only), then refresh install (see Docker vs Python below)
#   --docker      With --update: require Docker Compose (no fallback to pip). First install: no-op (Docker is default)
#   --python      Skip Docker; install into a local .venv with pip (also forces pip path with --update)
#   --dev         Also install dev/test dependencies (ruff, mypy, pytest)
#   --no-venv     Install into current Python environment (not recommended)
#   --help        Show this help
#
# Update path (--update): picks Docker if docker+compose+docker-compose.yml are available; otherwise
# falls back to the Python/pip path. Use --python or --docker to force one side.
#
# After install, the following commands are available:
#   docker compose up -d             — start the full stack   (Docker path)
#   edgeguard doctor                 — verify connectivity     (Python path)
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}⚠${NC}  $*"; }
error()   { echo -e "${RED}✗${NC}  $*" >&2; }
section() { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }

# ── Defaults ─────────────────────────────────────────────────────────────────
USE_DOCKER=true
INSTALL_DEV=false
USE_VENV=true
DO_UPDATE=false
# With --update --docker: do not fall back to Python if Docker is missing (fail fast)
FORCE_DOCKER_UPDATE=false

for arg in "$@"; do
  case "$arg" in
    --update)   DO_UPDATE=true ;;
    --docker)   FORCE_DOCKER_UPDATE=true ;;
    --python)   USE_DOCKER=false ;;
    --dev)      INSTALL_DEV=true ;;
    --no-venv)  USE_VENV=false ;;
    --help|-h)
      # Portable on macOS (BSD sed) and Linux — print header comment body
      sed -n '6,25p' "$0" | sed 's/^# *//'
      exit 0 ;;
    *) warn "Unknown option: $arg (ignored)" ;;
  esac
done

# ── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║           EdgeGuard Installer            ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── .env setup (both paths need this) ────────────────────────────────────────
section "Environment configuration"
if [ ! -f ".env" ]; then
    cp .env.example .env
    warn ".env created from .env.example — fill in NEO4J_PASSWORD, MISP_URL, MISP_API_KEY before starting"

    # PR-A audit fix (Red Team CRITICAL C1): without an EDGEGUARD_API_KEY, the
    # api / graphql containers refuse to start (the security check at
    # src/query_api.py:96 rejects an unauthenticated bind on 0.0.0.0). Auto-
    # generate a strong key on first .env creation so ``./install.sh && docker
    # compose up`` does not crashloop. Operators who clone + ``docker compose
    # up`` without install.sh will see the actionable RuntimeError and can set
    # EDGEGUARD_API_KEY by hand. We do NOT silently set EDGEGUARD_ALLOW_UNAUTH
    # — that would defeat the safety check entirely.
    if grep -q "^EDGEGUARD_API_KEY=$" .env 2>/dev/null; then
        if command -v openssl &>/dev/null; then
            generated_key="$(openssl rand -hex 32)"
        elif command -v python3 &>/dev/null; then
            generated_key="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
        else
            generated_key=""
        fi
        if [ -n "$generated_key" ]; then
            # Portable in-place sed: explicit -i'' (BSD/mac) and -i (GNU) handled by tmp-file rewrite
            tmp_env="$(mktemp)"
            awk -v key="$generated_key" '
                /^EDGEGUARD_API_KEY=$/ { print "EDGEGUARD_API_KEY=" key; next }
                { print }
            ' .env > "$tmp_env" && mv "$tmp_env" .env
            info "Generated random EDGEGUARD_API_KEY (32 bytes hex) — stored in .env"
        else
            warn "Neither openssl nor python3 available — leaving EDGEGUARD_API_KEY blank."
            warn "  api / graphql containers will refuse to start; set EDGEGUARD_API_KEY in .env first."
        fi
    fi

    # Same logic for GRAFANA_ADMIN_PASSWORD — compose default is "changeme"
    # which is a credential-stuffing target. Auto-generate on first .env.
    if grep -q "^GRAFANA_ADMIN_PASSWORD=changeme$" .env 2>/dev/null; then
        if command -v openssl &>/dev/null; then
            generated_grafana="$(openssl rand -base64 24 | tr -d '=+/')"
        elif command -v python3 &>/dev/null; then
            generated_grafana="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
        else
            generated_grafana=""
        fi
        if [ -n "$generated_grafana" ]; then
            tmp_env="$(mktemp)"
            awk -v pw="$generated_grafana" '
                /^GRAFANA_ADMIN_PASSWORD=changeme$/ { print "GRAFANA_ADMIN_PASSWORD=" pw; next }
                { print }
            ' .env > "$tmp_env" && mv "$tmp_env" .env
            info "Generated random GRAFANA_ADMIN_PASSWORD — stored in .env (visible only in this file)"
        fi
    fi
else
    info ".env already exists"
fi

# ── Optional: pull latest from GitHub ───────────────────────────────────────
if [ "$DO_UPDATE" = true ]; then
    section "Updating repository"
    if ! command -v git &>/dev/null; then
        error "git is not installed or not in PATH"
        exit 1
    fi
    if [ -d .git ] && git rev-parse --git-dir >/dev/null 2>&1; then
        git pull --ff-only
        info "git pull --ff-only completed"
    else
        warn "No .git directory — skipped git pull (e.g. release tarball). Replace files manually."
    fi
fi

# ── After pull: auto-pick Docker vs Python for --update (unless --python or --docker forced) ──
if [ "$DO_UPDATE" = true ] && [ "$USE_DOCKER" = true ] && [ "$FORCE_DOCKER_UPDATE" != true ]; then
    if ! command -v docker &>/dev/null || ! docker compose version &>/dev/null 2>&1 || [ ! -f docker-compose.yml ]; then
        warn "Docker Compose stack not available (docker, compose v2, or docker-compose.yml) — using Python/pip update path"
        USE_DOCKER=false
    fi
fi

# ── Docker Compose path ───────────────────────────────────────────────────────
if [ "$USE_DOCKER" = true ]; then
    section "Checking Docker"

    if ! command -v docker &>/dev/null; then
        error "Docker not found. Run with --python to install without Docker, or install Docker first:"
        echo "    https://docs.docker.com/get-docker/"
        exit 1
    fi
    info "Docker $(docker --version | awk '{print $3}' | tr -d ',')"

    if ! docker compose version &>/dev/null 2>&1; then
        error "Docker Compose v2 not found (need 'docker compose', not 'docker-compose')."
        error "Update Docker Desktop or install the Compose plugin:"
        echo "    https://docs.docker.com/compose/install/"
        exit 1
    fi
    info "Docker Compose $(docker compose version --short)"

    section "Building EdgeGuard image"
    # NOTE: --dev flag is not used here; dev/test dependencies (ruff, mypy, pytest)
    # are installed inside the container via the Dockerfile's own extras configuration.
    if [ "$DO_UPDATE" = true ]; then
        docker compose build --pull --quiet
    else
        docker compose build --quiet
    fi
    info "Image built"

    section "Starting the full stack"
    docker compose up -d

    echo ""
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  EdgeGuard is running!${NC}"
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Neo4j Browser  →  ${BOLD}http://localhost:7474${NC}"
    echo -e "  Airflow UI     →  ${BOLD}http://localhost:8082${NC}  (port 8082 — avoids ResilMesh Temporal)"
    echo -e "  REST API       →  ${BOLD}http://localhost:8000/health${NC}"
    echo -e "  GraphQL API    →  ${BOLD}http://localhost:4001/graphql${NC}  (GraphiQL playground)"
    echo ""
    echo -e "Next steps:"
    echo -e "  1. Edit ${BOLD}.env${NC} and add your API keys (MISP_URL, MISP_API_KEY, collector keys)"
    echo -e "  2. ${BOLD}docker compose restart airflow${NC} after editing .env"
    echo -e "  3. Open Airflow UI → trigger ${BOLD}edgeguard_baseline${NC} DAG once for historical load"
    echo ""
    echo -e "Useful commands:"
    echo -e "  ${BOLD}docker compose logs -f graphql${NC}  — tail GraphQL API logs"
    echo -e "  ${BOLD}docker compose down${NC}             — stop all services"
    echo -e "  ${BOLD}make help${NC}                       — see all Makefile shortcuts"
    echo ""
    exit 0
fi

# ── Python / pip path ─────────────────────────────────────────────────────────
section "Checking Python"
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED="3.12"

if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,12) else 1)"; then
    error "Python $REQUIRED+ required (found $PYTHON_VERSION). Apache Airflow 2.11 supports 3.11+ upstream; EdgeGuard standardizes on 3.12+ (see pyproject.toml)."
    exit 1
fi
info "Python $PYTHON_VERSION"

section "Setting up virtual environment"
if [ "$USE_VENV" = true ]; then
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
        info "Created .venv"
    else
        info ".venv already exists"
    fi
    # shellcheck disable=SC1091
    source .venv/bin/activate
    info "Virtual environment activated"
fi

section "Upgrading pip"
pip install --upgrade pip --quiet

section "Installing EdgeGuard"
if [ "$INSTALL_DEV" = true ]; then
    echo "  Installing: core + api + graphql + monitoring + dev extras"
    pip install -e ".[api,graphql,monitoring,dev]"
else
    echo "  Installing: core + api + graphql + monitoring"
    pip install -e ".[api,graphql,monitoring]"
fi
info "EdgeGuard installed"

# Airflow is heavy — offer it separately
echo ""
warn "Airflow not installed by default (large dependency). To add it:"
echo "    pip install -e '.[airflow]'    # or: pip install apache-airflow~=2.11"
echo ""
warn "Airflow webserver must run on port 8082 (not 8080) alongside ResilMesh:"
echo "    export AIRFLOW__WEBSERVER__WEB_SERVER_PORT=8082"

section "Verifying installation"
if python3 -c "import edgeguard" 2>/dev/null; then
    info "edgeguard module importable"
else
    warn "edgeguard CLI module not importable — run from the project root or activate .venv"
fi

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  EdgeGuard installed!${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${NC}"
echo ""
echo -e "Next steps:"
echo -e "  1. Edit ${BOLD}.env${NC} and add NEO4J_PASSWORD, MISP_URL, MISP_API_KEY"
echo -e "  2. Start Neo4j and MISP (or point at existing instances)"
echo -e "  3. ${BOLD}python src/health_check.py${NC}   — verify connectivity"
echo -e "  4. ${BOLD}python src/run_misp_to_neo4j.py${NC} — run first sync"
echo -e "  5. ${BOLD}uvicorn src.graphql_api:app --port 4001${NC} — start GraphQL API"
echo ""
echo -e "Useful commands:"
echo -e "  ${BOLD}edgeguard doctor${NC}   — diagnose issues"
echo -e "  ${BOLD}edgeguard heal${NC}     — auto-fix common problems"
echo -e "  ${BOLD}make help${NC}          — see all Makefile shortcuts"
echo ""
