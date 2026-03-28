#!/bin/bash
# EdgeGuard - Complete Setup and Run

echo "=========================================="
echo "🚀 EdgeGuard Prototype - Full Setup"
echo "=========================================="

cd /Users/user/Documents/python-projects/EdgeGuard/prototype

# Step 1: Clean and restart Neo4j
echo ""
echo "1️⃣ Cleaning and restarting Neo4j..."

cd neo4j
docker-compose down -v 2>/dev/null || true
docker volume rm neo4j_edgeguard_net 2>/dev/null || true
docker-compose up -d
cd ..

echo "   ⏳ Waiting 90 seconds for Neo4j to start..."
sleep 90

# Test Neo4j
echo "   🧪 Testing Neo4j connection..."
for i in {1..5}; do
    if docker exec edgeguard_neo4j cypher-shell -u neo4j -p "${NEO4J_PASSWORD:-changeme}" "RETURN 1" >/dev/null 2>&1; then
        echo "   ✅ Neo4j is ready!"
        break
    fi
    echo "   ⏳ Waiting... ($i)"
    sleep 10
done

# Step 2: Install dependencies
echo ""
echo "2️⃣ Installing dependencies..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q neo4j requests pandas 2>/dev/null

# Step 3: Run pipeline
echo ""
echo "3️⃣ Running EdgeGuard Pipeline..."
echo "=========================================="

python run_pipeline.py

echo ""
echo "=========================================="
echo "✅ Complete!"
echo "=========================================="
