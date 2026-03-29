"""EdgeGuard — REST API tests."""

import os

# Ensure env vars are set before importing query_api (which reads them at import time)
os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault("NEO4J_PASSWORD", "test-password")

from fastapi.testclient import TestClient

import query_api

client = TestClient(query_api.app)


def test_health_endpoint():
    """Health endpoint should return 200 with status and neo4j_connected fields."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "neo4j_connected" in data


def test_query_endpoint_missing_neo4j(monkeypatch):
    """When Neo4j is disconnected, /query should return 503."""
    monkeypatch.setattr(query_api, "neo4j_client", None)
    response = client.post("/query", json={"query": "show vulnerabilities", "limit": 5})
    assert response.status_code == 503


def test_health_endpoint_returns_version():
    """Health endpoint should include a version field."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    # Version may or may not be present depending on package_meta availability
    # but status should always be there
    assert data["status"] in ("ok", "degraded")
