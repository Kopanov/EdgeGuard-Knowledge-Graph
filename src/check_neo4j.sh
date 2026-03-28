#!/usr/bin/env bash
# EdgeGuard — quick Neo4j container check (Docker Compose stack).
# Loads NEO4J_PASSWORD (and optional NEO4J_USER) from repo-root .env if present.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

: "${NEO4J_PASSWORD:?Set NEO4J_PASSWORD in .env (repo root) or export it}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
CONTAINER="${NEO4J_DOCKER_CONTAINER:-edgeguard_neo4j}"

echo "🔍 Checking Neo4j container (${CONTAINER})..."
if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "✗ Container ${CONTAINER} is not running. Start the stack: docker compose up -d"
  docker ps -a --filter "name=neo4j" || true
  exit 1
fi

echo ""
echo "📋 Recent logs:"
docker logs "$CONTAINER" --tail 20

echo ""
echo "🧪 Testing Bolt (cypher-shell inside container)..."
docker exec "$CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" "RETURN 1 AS ok" || {
  echo "✗ Bolt test failed — wait for DB ready or check NEO4J_USER / NEO4J_PASSWORD"
  exit 1
}

echo "✓ Neo4j responded."
echo ""
echo "Tip: for MISP + Neo4j together, run: python src/health_check.py (with .env loaded)"
