#!/bin/bash
# MISP Startup Script

echo "🚀 Starting MISP..."

cd /Users/user/Documents/python-projects/EdgeGuard/MISP

# Start MISP
docker-compose up -d

echo "⏳ Waiting for MISP to initialize (60 seconds)..."
sleep 60

echo "📋 Getting MISP API Key..."
echo "Run this command to get your API key:"
echo "docker exec -it misp_misp_1 cat /var/www/MISP/APP/Config/bootstrap.php | grep 'MISP' | head -20"
echo ""
echo "🌐 Access MISP at: https://localhost:8443"
echo "📧 Email: admin@admin.test"
echo "🔑 Password: admin"
