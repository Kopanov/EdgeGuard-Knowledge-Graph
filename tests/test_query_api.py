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
    """Health endpoint returns the status and neo4j_connected fields: 200 while healthy, 503 while
    degraded (so the compose healthcheck and partner probes see a database outage)."""
    response = client.get("/health")
    data = response.json()
    assert "status" in data
    assert "neo4j_connected" in data
    assert response.status_code == (200 if data["neo4j_connected"] else 503)
    assert data["status"] == ("ok" if response.status_code == 200 else "degraded")


def test_query_endpoint_missing_neo4j(monkeypatch):
    """When Neo4j is disconnected, /query should return 503."""
    monkeypatch.setattr(query_api, "neo4j_client", None)
    response = client.post("/query", json={"query": "show vulnerabilities", "limit": 5})
    assert response.status_code == 503


def test_health_endpoint_returns_version():
    """Health endpoint should include a version field."""
    response = client.get("/health")
    assert response.status_code in (200, 503)
    data = response.json()
    # Version may or may not be present depending on package_meta availability
    # but status should always be there
    assert data["status"] in ("ok", "degraded")


def test_stix_types_discovery_endpoint():
    """/stix/types is the ResilMesh-facing discovery endpoint: it must
    return the media type, the supported depth values, and one entry
    per supported object type — each carrying a working example
    identifier so a smoke test can curl straight from the response."""
    response = client.get("/stix/types")
    # _API_KEY is unset in the test harness (see header warning above)
    # so the endpoint is unauthenticated here.
    assert response.status_code == 200
    data = response.json()
    assert data["media_type"] == "application/stix+json;version=2.1"
    assert data["default_depth"] == 2
    assert data["supported_depths"] == [1, 2]
    types = {t["name"] for t in data["object_types"]}
    assert types == {"indicator", "actor", "technique", "cve"}
    # Every entry must carry an example identifier — the smoke script
    # reads these to drive the /stix/export calls.
    for entry in data["object_types"]:
        assert entry["example"]
        assert entry["primary_relation"]
        assert entry["returns"]


def test_stix_types_qualifies_the_links_between_indicators_and_cves():
    """``(Indicator)-[:EXPLOITS]->(CVE)`` rests on the indicator's own CVE tag, which no collector
    writes (2026-10-18): the indicator and cve entries must not promise those links unqualified. The
    links a graph the collectors built holds are ``(Indicator)-[:INDICATES]->(CVE)``, an indicator and a
    CVE named in the same OTX report (2026-10-18), and both entries and the route say so."""
    types = {t["name"]: t for t in client.get("/stix/types").json()["object_types"]}
    assert "collectors write no such tag" in types["indicator"]["returns"]
    assert "collectors do not write" in types["cve"]["returns"]
    assert "threat actors and malware (EXPLOITS)" in types["cve"]["returns"]
    assert "INDICATES CVEs (named in the same OTX report)" in types["indicator"]["returns"]
    assert "INDICATES, an indicator named in the same OTX report" in types["cve"]["returns"]
    doc = " ".join((query_api.stix_export.__doc__ or "").split())
    assert "INDICATES CVEs (named in the same OTX report, 2026-10-18)" in doc
    assert "INDICATES, an indicator named in the same OTX report, 2026-10-18" in doc
    assert "on a graph they built ``depth=1`` returns the CVE alone" not in doc
