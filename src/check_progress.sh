#!/bin/bash
# EdgeGuard Progress Checker - Runs every 6 hours

EDGEGUARD_ROOT="/Users/user/Documents/python-projects/EdgeGuard"
LOG_FILE="$EDGEGUARD_ROOT/logs/cron_progress_$(date +%Y-%m-%d).md"

echo "=========================================="
echo "EdgeGuard Progress Check - $(date)"
echo "=========================================="

# Check Docker containers
echo ""
echo "📦 Docker Containers:"
docker ps --filter "name=edgeguard" --filter "name=misp" --format "table {{.Names}}\t{{.Status}}"

# Check Neo4j
echo ""
echo "🧠 Neo4j Status:"
if curl -s -u "neo4j:${NEO4J_PASSWORD:-changeme}" http://localhost:7474 > /dev/null 2>&1; then
    echo "✅ Neo4j is running"
else
    echo "❌ Neo4j is NOT reachable"
fi

# Check MISP
echo ""
echo "� Threat Intel (MISP):"
if curl -sk "https://localhost:8443/users/login" > /dev/null 2>&1; then
    echo "✅ MISP is running"
else
    echo "⚠️ MISP may not be fully ready"
fi

# Check collectors
echo ""
echo "📂 Collectors Status:"
ls -la "$EDGEGUARD_ROOT/prototype/collectors/" 2>/dev/null | grep -E "\.py$" | wc -l | xargs -I {} echo "  {} collector scripts found"

# Quick pipeline test
echo ""
echo "🔄 Pipeline Test:"
cd "$EDGEGUARD_ROOT/prototype"
python3 -c "
from neo4j_client import Neo4jClient
client = Neo4jClient()
if client.connect():
    result = client.query('MATCH (n) RETURN count(n) as count')
    print(f'  ✅ Neo4j connected - {result[0][\"count\"]} nodes in graph')
    client.close()
else:
    print('  ❌ Neo4j connection failed')
" 2>/dev/null || echo "  ⚠️ Could not test pipeline"

echo ""
echo "=========================================="
echo "Check complete: $(date)"
echo "=========================================="
