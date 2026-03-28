#!/bin/bash
# EdgeGuard Prototype - Complete Setup & Run

set -e

echo "=========================================="
echo "🚀 EdgeGuard Prototype - Full Setup"
echo "=========================================="

PROTOCOL_DIR="/Users/user/Documents/python-projects/EdgeGuard/prototype"

cd "$PROTOCOL_DIR"

# Step 1: Check and start Neo4j
echo ""
echo "1️⃣ Checking Neo4j..."

if docker ps | grep -q edgeguard_neo4j; then
    echo "   ✅ Neo4j container is running"
    
    # Check if it's actually accepting connections
    if docker exec edgeguard_neo4j cypher-shell -u neo4j -p "${NEO4J_PASSWORD:-changeme}" "RETURN 1" >/dev/null 2>&1; then
        echo "   ✅ Neo4j is ready for connections!"
    else
        echo "   ⚠️ Neo4j not ready, restarting..."
        cd neo4j
        docker-compose restart
        cd ..
        echo "   ⏳ Waiting 60 seconds for Neo4j..."
        sleep 60
    fi
else
    echo "   🔄 Starting Neo4j..."
    cd neo4j
    docker-compose down 2>/dev/null || true
    docker-compose up -d
    cd ..
    echo "   ⏳ Waiting 90 seconds for Neo4j to start..."
    sleep 90
fi

# Step 2: Install dependencies
echo ""
echo "2️⃣ Installing dependencies..."
cd "$PROTOCOL_DIR"

# Create venv if needed
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -q neo4j requests pandas 2>/dev/null || pip install neo4j requests pandas

# Step 3: Run pipeline
echo ""
echo "3️⃣ Running EdgeGuard Pipeline..."
echo "=========================================="

python run_pipeline.py

echo ""
echo "=========================================="
echo "✅ Complete! Check Neo4j Browser:"
echo "   http://localhost:7474"
echo "   User: neo4j / \$NEO4J_PASSWORD (from .env)"
echo "=========================================="
