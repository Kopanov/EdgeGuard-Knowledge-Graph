#!/usr/bin/env bash
# Deployment wiring check: Layer 1 (always) + optional live Layer 3 HTTP probes.
#
# Usage:
#   ./scripts/deployment_wiring_check.sh
#     → runs preflight_ci.sh (compileall, pytest, Airflow DagBag).
#
#   EDGEGUARD_DEPLOY_CHECK_LIVE=1 ./scripts/deployment_wiring_check.sh
#     → after preflight, runs src/health_check.py (needs real .env / MISP / Neo4j).
#     → optional curls if URLs set (defaults below).
#
# Env (live mode only):
#   EDGEGUARD_REST_HEALTH_URL      default http://127.0.0.1:8000/health
#   EDGEGUARD_GRAPHQL_HEALTH_URL   default http://127.0.0.1:4001/health
#   EDGEGUARD_SKIP_HTTP_HEALTH     set to 1 to skip REST/GraphQL curls
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== EdgeGuard deployment_wiring_check ==="
echo ""

echo "== Layer 1: preflight (compileall, pytest, DagBag) =="
./scripts/preflight_ci.sh

if [[ "${EDGEGUARD_DEPLOY_CHECK_LIVE:-}" != "1" ]]; then
  echo ""
  echo "== Layer 3–4 (manual) =="
  echo "  Live checks skipped. To run health_check.py + optional /health curls:"
  echo "    EDGEGUARD_DEPLOY_CHECK_LIVE=1 ./scripts/deployment_wiring_check.sh"
  echo ""
  echo "  See docs/DEPLOYMENT_READINESS_CHECKLIST.md for full Layer 2–5 gates."
  echo ""
  echo "=== deployment_wiring_check.sh done (static only) ==="
  exit 0
fi

echo ""
echo "== Layer 3 (live): health_check.py =="
export PYTHONPATH="${ROOT}/src:${PYTHONPATH:-}"
python3 "${ROOT}/src/health_check.py"

if [[ "${EDGEGUARD_SKIP_HTTP_HEALTH:-}" == "1" ]]; then
  echo ""
  echo "== HTTP health curls skipped (EDGEGUARD_SKIP_HTTP_HEALTH=1) ==="
  echo "=== deployment_wiring_check.sh done ==="
  exit 0
fi

REST_URL="${EDGEGUARD_REST_HEALTH_URL:-http://127.0.0.1:8000/health}"
GQL_URL="${EDGEGUARD_GRAPHQL_HEALTH_URL:-http://127.0.0.1:4001/health}"

echo ""
echo "== Layer 3 (live): REST health =="
echo "    GET $REST_URL"
if curl -sfS --max-time 15 "$REST_URL" >/dev/null; then
  echo "    OK"
else
  echo "    FAILED (set EDGEGUARD_REST_HEALTH_URL or start API; or EDGEGUARD_SKIP_HTTP_HEALTH=1)"
  exit 1
fi

echo ""
echo "== Layer 3 (live): GraphQL health =="
echo "    GET $GQL_URL"
if curl -sfS --max-time 15 "$GQL_URL" >/dev/null; then
  echo "    OK"
else
  echo "    FAILED (set EDGEGUARD_GRAPHQL_HEALTH_URL or start GraphQL; or EDGEGUARD_SKIP_HTTP_HEALTH=1)"
  exit 1
fi

echo ""
echo "=== deployment_wiring_check.sh done (static + live) ==="
