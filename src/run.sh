#!/bin/bash
# EdgeGuard Prototype - Full Setup & Run Script

echo "=========================================="
echo "🚀 EdgeGuard Prototype Setup & Run"
echo "=========================================="

cd /Users/user/Documents/python-projects/EdgeGuard/prototype

# Check if Neo4j is running
echo ""
echo "1️⃣ Checking Neo4j..."
if docker ps | grep -q edgeguard_neo4j; then
    echo "   ✅ Neo4j is already running!"
else
    echo "   ⏳ Starting Neo4j..."
    cd neo4j
    docker-compose up -d
    cd ..
    echo "   ⏳ Waiting for Neo4j to start (30s)..."
    sleep 30
    echo "   ✅ Neo4j started!"
fi

# Install dependencies
echo ""
echo "2️⃣ Installing dependencies..."
if [ -d ".venv" ]; then
    source .venv/bin/activate
else
    python3 -m venv .venv
    source .venv/bin/activate
fi
pip install -q neo4j requests pandas

# Run pipeline
echo ""
echo "3️⃣ Running EdgeGuard Pipeline..."
echo "=========================================="
python run_pipeline.py

echo ""
echo "=========================================="
echo "✅ Done! Check Neo4j at: http://localhost:7474"
echo "   User: neo4j / \$NEO4J_PASSWORD (from .env)"
echo "=========================================="
