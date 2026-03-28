#!/bin/bash
# EdgeGuard - Start Neo4j

echo "🚀 Starting Neo4j for EdgeGuard Prototype..."

cd /Users/user/Documents/python-projects/EdgeGuard/prototype/neo4j

# Check if already running
if docker ps | grep -q edgeguard_neo4j; then
    echo "✅ Neo4j is already running!"
    echo "   HTTP: http://localhost:7474"
    echo "   Bolt: bolt://localhost:7687"
    echo "   User: neo4j"
    echo "   Pass: \$NEO4J_PASSWORD (from .env)"
else
    docker-compose up -d
    echo "⏳ Waiting for Neo4j to start (30 seconds)..."
    sleep 30
    echo "✅ Neo4j started!"
    echo "   HTTP: http://localhost:7474"
    echo "   Bolt: bolt://localhost:7687"
    echo "   User: neo4j"
    echo "   Pass: \$NEO4J_PASSWORD (from .env)"
fi
