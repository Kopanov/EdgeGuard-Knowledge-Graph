#!/bin/bash
# EdgeGuard - Clean Neo4j Setup

echo "=========================================="
echo "🧹 Cleaning and Restarting Neo4j"
echo "=========================================="

cd /Users/user/Documents/python-projects/EdgeGuard/prototype/neo4j

# Stop and remove everything
echo "1️⃣ Stopping and removing old containers..."
docker-compose down -v 2>/dev/null || true
docker rm -f edgeguard_neo4j 2>/dev/null || true

# Remove old volumes to clean database
echo "2️⃣ Removing old data volumes..."
docker volume rm neo4j_neo4j_data 2>/dev/null || true
docker volume rm neo4j_edgeguard_net 2>/dev/null || true

# Recreate network
echo "3️⃣ Creating network..."
docker network create edgeguard_net 2>/dev/null || true

# Start fresh
echo "4️⃣ Starting Neo4j fresh..."
docker-compose up -d

# Wait longer for initialization
echo "5️⃣ Waiting 90 seconds for Neo4j to fully start..."
sleep 90

# Test
echo "6️⃣ Testing connection..."
docker exec edgeguard_neo4j cypher-shell -u neo4j -p "${NEO4J_PASSWORD:-changeme}" "RETURN 1;"

echo ""
echo "=========================================="
echo "✅ Neo4j should be ready!"
echo "   HTTP: http://localhost:7474"
echo "   Bolt: bolt://localhost:7687"
echo "   User: neo4j"
echo "   Pass: \$NEO4J_PASSWORD (from .env)"
echo "=========================================="
