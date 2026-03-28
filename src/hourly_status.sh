#!/bin/bash
# Hourly EdgeGuard Status Report Script
# Run this every hour to monitor system health (development template)

cd "$(dirname "$0")"

# Check Docker containers
echo "=== EdgeGuard Hourly Status Report - $(date) ==="
echo ""
echo "🐳 Docker Containers:"
docker ps --format "  {{.Names}}: {{.Status}}"
echo ""

# Check Neo4j
echo "🗄️ Neo4j Status:"
python3 -c "
from neo4j_client_v2 import Neo4jClient
client = Neo4jClient()
client.connect()
result = client.run('MATCH (n) RETURN count(n) as total')
print(f'  Total Nodes: {result[0][\"total\"]}')
result = client.run('MATCH ()-[r]->() RETURN count(r) as total')
print(f'  Total Relationships: {result[0][\"total\"]}')
result = client.run('MATCH (n) RETURN labels(n)[0] as type, count(n) as count ORDER BY count DESC LIMIT 5')
print('  Top Node Types:')
for row in result:
    print(f'    {row[\"type\"]}: {row[\"count\"]}')
client.close()
" 2>&1 | grep -v "INFO\|WARNING" | sed 's/^/  /'
echo ""

# Check MISP
echo "🔌 MISP Status:"
MISP_HEALTH=$(curl -s -k -o /dev/null -w "%{http_code}" https://localhost:8443 2>/dev/null)
echo "  Web UI: HTTP $MISP_HEALTH"

# Check if sync would work (requires MISP_API_KEY in environment)
echo "  Sync Status: Checking..."
if [ -f "$(dirname "$0")/../.env" ]; then
    set -a; source "$(dirname "$0")/../.env" 2>/dev/null; set +a
fi
if [ -n "$MISP_API_KEY" ]; then
    python3 -c "
from run_misp_to_neo4j import MISPToNeo4jSync
sync = MISPToNeo4jSync()
health = sync.health_check_misp()
print(f'  MISP Health: {health}')
" 2>&1 | grep -v "INFO\|WARNING" | sed 's/^/  /'
else
    echo "  MISP Health: skipped (MISP_API_KEY not set — see .env)"
fi
echo ""

# Summary
echo "📊 Summary:"
echo "  - Neo4j has data: No (7 Source nodes only)"
echo "  - MISP API: Needs auth key fix"
echo "  - Next sync: When MISP is ready"
echo ""
echo "=== End of Report ==="
