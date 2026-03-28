import os

from fastapi.testclient import TestClient

import query_api


def _setup_env():
    os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
    os.environ.setdefault("NEO4J_USER", "neo4j")
    os.environ.setdefault("NEO4J_PASSWORD", "test-password")


_setup_env()
client = TestClient(query_api.app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "neo4j_connected" in data


def test_query_endpoint_missing_neo4j(monkeypatch):
    # Force neo4j_client to None to simulate disconnected state
    monkeypatch.setattr(query_api, "neo4j_client", None)
    response = client.post("/query", json={"query": "show vulnerabilities", "limit": 5})
    assert response.status_code == 503
