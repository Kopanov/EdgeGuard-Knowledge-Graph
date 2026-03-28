"""
Tests for the EdgeGuard GraphQL API (src/graphql_api.py).

Strategy: mock the Neo4jClient so no live database is required.
Tests cover:
  - Schema introspection (all expected types present)
  - /health liveness endpoint
  - CVE query — happy path and not-found
  - Vulnerability list — with and without filters
  - Indicator list — active-only filter
  - Threat-actor / malware / technique / campaign list queries
  - API-key enforcement when EDGEGUARD_API_KEY is set
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Put src/ on the path before importing the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault("NEO4J_PASSWORD", "test")

# ── Stub heavy transitive imports so tests run without a live environment ────
# neo4j, pymisp, apache-airflow etc. are not installed in the slim CI image
# used for unit tests.  We insert lightweight stubs into sys.modules BEFORE
# any src/ file is imported so that import-time side-effects are skipped.
_stub_modules = [
    "neo4j",
    "neo4j.exceptions",
    "neo4j.time",
    "pymisp",
    "pymisp.api",
    "airflow",
    "airflow.models",
    "airflow.operators",
    "airflow.operators.python",
    "airflow.utils",
    "airflow.utils.dates",
    "nats",
    "opentelemetry",
    "opentelemetry.trace",
    "opentelemetry.sdk",
    "opentelemetry.sdk.trace",
    "opentelemetry.instrumentation",
    "opentelemetry.instrumentation.fastapi",
    "opentelemetry.exporter",
    "opentelemetry.exporter.otlp",
    "opentelemetry.exporter.otlp.proto",
    "opentelemetry.exporter.otlp.proto.grpc",
]
for _mod in _stub_modules:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()  # type: ignore[assignment]

# Stub Neo4jClient so graphql_api can be imported without a real DB
_fake_neo4j_client_cls = MagicMock()
_fake_neo4j_module = MagicMock()
_fake_neo4j_module.Neo4jClient = _fake_neo4j_client_cls
_fake_neo4j_module.NEO4J_READ_TIMEOUT = 120
sys.modules["neo4j_client"] = _fake_neo4j_module  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Helpers — build fake Neo4j records
# ---------------------------------------------------------------------------


def _fake_record(props: dict):
    """Return a MagicMock that behaves like a Neo4j Record with one key 'n'."""
    node = MagicMock()
    node.__iter__ = MagicMock(return_value=iter(props.items()))
    node.items = MagicMock(return_value=props.items())
    node.get = MagicMock(side_effect=props.get)

    record = MagicMock()
    record.__getitem__ = MagicMock(side_effect=lambda k: node if k in ("n", "c") else None)
    record.single = MagicMock(return_value=record)
    return record


def _make_node(props: dict):
    """
    Return a MagicMock that behaves like a Neo4j Node:
    node.get(key, default) returns from props.
    """
    n = MagicMock()
    n.get = MagicMock(side_effect=lambda k, d=None: props.get(k, d))
    n.__getitem__ = MagicMock(side_effect=lambda k: props[k])
    return n


def _fake_cve_record(cve_id="CVE-2024-9999"):
    """Build a compound record as returned by the JOIN query in _resolve_cve."""
    cve_props = {
        "cve_id": cve_id,
        "description": "A critical test vulnerability",
        "published": "2024-01-01",
        "last_modified": "2024-06-01",
        "cpe_type": ["a"],
        "result_impacts": ["HIGH"],
        "ref_tags": ["Patch"],
        "cwe": ["CWE-79"],
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "edgeguard_managed": True,
        "source": ["nvd"],
        "zone": ["global"],
    }
    cv31_props = {
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "base_score": 9.8,
        "base_severity": "CRITICAL",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "scope": "UNCHANGED",
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH",
        "impact_score": 5.9,
        "exploitability_score": 3.9,
    }

    cve_node = _make_node(cve_props)
    cv31_node = _make_node(cv31_props)

    record = MagicMock()
    record.__getitem__ = MagicMock(
        side_effect=lambda k: {"c": cve_node, "cv40": None, "cv31": cv31_node, "cv30": None, "cv2": None}.get(k)
    )
    return record


def _fake_cve_record_v30_only(cve_id="CVE-2020-1234"):
    """CVE with only CVSS v3.0 linked (no v3.1) — exercises cvssV30 + score fallback."""
    cve_props = {
        "cve_id": cve_id,
        "description": "Legacy CVSS 3.0 only",
        "published": "2020-01-01",
        "last_modified": "2020-06-01",
        "cpe_type": [],
        "result_impacts": [],
        "ref_tags": [],
        "cwe": [],
        "cvss_score": None,
        "base_score": None,
        "severity": None,
        "base_severity": None,
        "edgeguard_managed": True,
        "source": ["nvd"],
        "zone": ["global"],
    }
    cv30_props = {
        "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "base_score": 9.8,
        "base_severity": "HIGH",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "scope": "UNCHANGED",
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH",
        "impact_score": 5.9,
        "exploitability_score": 3.9,
    }
    cve_node = _make_node(cve_props)
    cv30_node = _make_node(cv30_props)
    record = MagicMock()
    record.__getitem__ = MagicMock(
        side_effect=lambda k: {"c": cve_node, "cv40": None, "cv31": None, "cv30": cv30_node, "cv2": None}.get(k)
    )
    return record


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_client():
    """Return a Neo4jClient mock with a usable driver.session()."""
    client = MagicMock()
    client.driver = MagicMock()
    client.connect.return_value = True
    client.is_connected.return_value = True
    client.health_check.return_value = {"healthy": True}

    session_ctx = MagicMock()
    client.driver.session.return_value.__enter__ = MagicMock(return_value=session_ctx)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return client, session_ctx


@pytest.fixture()
def graphql_client(mock_client):
    """TestClient with Neo4jClient patched out."""
    client, session_ctx = mock_client

    import graphql_api as gapi  # noqa: E402 — after sys.modules stubs

    with patch("graphql_api.Neo4jClient", return_value=client):
        gapi._client = client
        test_client = TestClient(gapi.app, raise_server_exceptions=True)
        yield test_client, session_ctx


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_health_endpoint(graphql_client):
    client, _ = graphql_client
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


def test_schema_introspection_has_expected_types(graphql_client):
    """Introspection must expose all EdgeGuard types."""
    client, _ = graphql_client
    query = """
    { __schema { types { name } } }
    """
    resp = client.post("/graphql", json={"query": query})
    assert resp.status_code == 200
    type_names = {t["name"] for t in resp.json()["data"]["__schema"]["types"]}
    expected = {
        "CVE",
        "Vulnerability",
        "Indicator",
        "ThreatActor",
        "Malware",
        "Technique",
        "Tactic",
        "Campaign",
        "CVSSv2",
        "CVSSv30",
        "CVSSv31",
        "CVSSv40",
    }
    assert expected.issubset(type_names), f"Missing types: {expected - type_names}"


def test_cve_query_happy_path(graphql_client):
    client, session_ctx = graphql_client
    cve_record = _fake_cve_record("CVE-2024-9999")
    session_ctx.run.return_value.single.return_value = cve_record

    query = """
    query {
      cve(cveId: "CVE-2024-9999") {
        cveId
        description
        baseScore
        cvssV31 { baseScore baseSeverity attackVector }
      }
    }
    """
    resp = client.post("/graphql", json={"query": query})
    assert resp.status_code == 200
    data = resp.json()
    assert "errors" not in data, data.get("errors")
    cve = data["data"]["cve"]
    assert cve["cveId"] == "CVE-2024-9999"
    assert cve["baseScore"] == 9.8
    assert cve["cvssV31"]["attackVector"] == "NETWORK"


def test_cve_query_cvss_v30_and_score_fallback(graphql_client):
    client, session_ctx = graphql_client
    session_ctx.run.return_value.single.return_value = _fake_cve_record_v30_only()

    query = """
    query {
      cve(cveId: "CVE-2020-1234") {
        cveId
        baseScore
        baseSeverity
        cvssV30 { baseScore baseSeverity attackVector vectorString }
      }
    }
    """
    resp = client.post("/graphql", json={"query": query})
    assert resp.status_code == 200
    data = resp.json()
    assert "errors" not in data, data.get("errors")
    cve = data["data"]["cve"]
    assert cve["cveId"] == "CVE-2020-1234"
    assert cve["baseScore"] == 9.8
    assert cve["baseSeverity"] == "HIGH"
    assert cve["cvssV30"]["attackVector"] == "NETWORK"
    assert "CVSS:3.0/" in cve["cvssV30"]["vectorString"]


def test_cve_query_not_found(graphql_client):
    client, session_ctx = graphql_client
    session_ctx.run.return_value.single.return_value = None

    query = '{ cve(cveId: "CVE-9999-0000") { cveId } }'
    resp = client.post("/graphql", json={"query": query})
    assert resp.status_code == 200
    assert resp.json()["data"]["cve"] is None


def test_vulnerabilities_list(graphql_client):
    client, session_ctx = graphql_client
    vuln_props = {
        "cve_id": "CVE-2024-1111",
        "description": "Test vuln",
        "status": ["active"],
        "severity": "HIGH",
        "cvss_score": 7.5,
        "zone": ["healthcare"],
        "edgeguard_managed": True,
        "source": ["nvd"],
        "last_updated": None,
    }
    node = MagicMock()
    node.get = MagicMock(side_effect=lambda k, d=None: vuln_props.get(k, d))
    record = MagicMock()
    record.__getitem__ = MagicMock(side_effect=lambda k: node)
    session_ctx.run.return_value.__iter__ = MagicMock(return_value=iter([record]))

    query = """
    {
      vulnerabilities(filter: {zone: "healthcare", limit: 10}) {
        cveId status severity cvssScore zone
      }
    }
    """
    resp = client.post("/graphql", json={"query": query})
    assert resp.status_code == 200
    data = resp.json()
    assert "errors" not in data, data.get("errors")
    vulns = data["data"]["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["cveId"] == "CVE-2024-1111"
    assert vulns[0]["status"] == ["active"]


def test_indicators_active_only_filter(graphql_client):
    client, session_ctx = graphql_client
    ind_props = {
        "value": "192.168.1.100",
        "indicator_type": "ipv4-addr",
        "confidence_score": 0.85,
        "zone": ["energy"],
        "active": True,
        "source": ["alienvault_otx"],
        "last_updated": None,
        "edgeguard_managed": True,
    }
    node = MagicMock()
    node.get = MagicMock(side_effect=lambda k, d=None: ind_props.get(k, d))
    record = MagicMock()
    record.__getitem__ = MagicMock(side_effect=lambda k: node)
    session_ctx.run.return_value.__iter__ = MagicMock(return_value=iter([record]))

    query = """
    {
      indicators(filter: {zone: "energy", activeOnly: true, limit: 5}) {
        value indicatorType confidenceScore active
      }
    }
    """
    resp = client.post("/graphql", json={"query": query})
    assert resp.status_code == 200
    data = resp.json()
    assert "errors" not in data, data.get("errors")
    inds = data["data"]["indicators"]
    assert len(inds) == 1
    assert inds[0]["value"] == "192.168.1.100"
    assert inds[0]["active"] is True


def test_threat_actors_list(graphql_client):
    client, session_ctx = graphql_client
    actor_props = {
        "name": "APT29",
        "description": "Russian state-sponsored actor",
        "sophistication": "advanced",
        "primary_motivation": "espionage",
        "resource_level": "government",
        "zone": ["global"],
        "confidence_score": 0.9,
        "source": ["mitre"],
        "edgeguard_managed": True,
    }
    node = _make_node(actor_props)
    record = MagicMock()
    record.__getitem__ = MagicMock(side_effect=lambda k: node)
    session_ctx.run.return_value.__iter__ = MagicMock(return_value=iter([record]))

    query = "{ threatActors { name sophistication primaryMotivation } }"
    resp = client.post("/graphql", json={"query": query})
    assert resp.status_code == 200
    data = resp.json()
    assert "errors" not in data, data.get("errors")
    assert data["data"]["threatActors"][0]["name"] == "APT29"


def test_indicator_provenance_fields(graphql_client, monkeypatch):
    """Indicator must expose MISP back-references and import audit fields."""
    client, session_ctx = graphql_client
    import graphql_api as gapi  # noqa: E402

    monkeypatch.setattr(gapi, "MISP_URL", "https://misp.example.com")

    ind_props = {
        "value": "10.0.0.1",
        "indicator_type": "ipv4",
        "confidence_score": 0.9,
        "zone": ["finance"],
        "active": True,
        "source": ["alienvault_otx"],
        "last_updated": None,
        "edgeguard_managed": True,
        "misp_event_id": "42",
        "misp_attribute_id": "1337",
        "first_imported_at": "2025-01-15T10:00:00",
        "last_imported_from": "alienvault_otx",
    }
    node = MagicMock()
    node.get = MagicMock(side_effect=lambda k, d=None: ind_props.get(k, d))
    node.__getitem__ = MagicMock(side_effect=lambda k: ind_props[k])
    record = MagicMock()
    record.__getitem__ = MagicMock(side_effect=lambda k: node)
    session_ctx.run.return_value.__iter__ = MagicMock(return_value=iter([record]))

    query = """
    {
      indicators {
        value mispEventId mispAttributeId mispEventUrl
        firstImportedAt lastImportedFrom
      }
    }
    """
    resp = client.post("/graphql", json={"query": query})
    assert resp.status_code == 200
    data = resp.json()
    assert "errors" not in data, data.get("errors")
    ind = data["data"]["indicators"][0]
    assert ind["mispEventId"] == "42"
    assert ind["mispAttributeId"] == "1337"
    assert ind["mispEventUrl"] == "https://misp.example.com/events/view/42"
    assert ind["firstImportedAt"] == "2025-01-15T10:00:00"
    assert ind["lastImportedFrom"] == "alienvault_otx"


def test_indicator_misp_url_absent_when_no_misp_url_env(graphql_client, monkeypatch):
    """misp_event_url must be None when MISP_URL env var is not set."""
    client, session_ctx = graphql_client
    import graphql_api as gapi  # noqa: E402

    monkeypatch.setattr(gapi, "MISP_URL", "")  # explicitly unset

    ind_props = {
        "value": "evil.com",
        "indicator_type": "domain",
        "confidence_score": 0.7,
        "zone": ["global"],
        "active": True,
        "source": ["threatfox"],
        "last_updated": None,
        "edgeguard_managed": True,
        "misp_event_id": "99",
        "misp_attribute_id": None,
        "first_imported_at": None,
        "last_imported_from": None,
    }
    node = MagicMock()
    node.get = MagicMock(side_effect=lambda k, d=None: ind_props.get(k, d))
    node.__getitem__ = MagicMock(side_effect=lambda k: ind_props[k])
    record = MagicMock()
    record.__getitem__ = MagicMock(side_effect=lambda k: node)
    session_ctx.run.return_value.__iter__ = MagicMock(return_value=iter([record]))

    query = "{ indicators { value mispEventId mispEventUrl } }"
    resp = client.post("/graphql", json={"query": query})
    assert resp.status_code == 200
    data = resp.json()
    assert "errors" not in data, data.get("errors")
    ind = data["data"]["indicators"][0]
    assert ind["mispEventId"] == "99"
    assert ind["mispEventUrl"] is None  # no MISP_URL → no URL


def test_vulnerability_provenance_fields(graphql_client):
    """Vulnerability must expose misp_event_id and import audit timestamps."""
    client, session_ctx = graphql_client
    vuln_props = {
        "cve_id": "CVE-2025-0001",
        "description": "Provenance test vuln",
        "status": ["active"],
        "severity": "CRITICAL",
        "cvss_score": 9.0,
        "zone": ["energy"],
        "edgeguard_managed": True,
        "source": ["cisa_kev"],
        "last_updated": None,
        "misp_event_id": "77",
        "first_imported_at": "2025-03-01T08:00:00",
        "last_imported_from": "cisa_kev",
    }
    node = MagicMock()
    node.get = MagicMock(side_effect=lambda k, d=None: vuln_props.get(k, d))
    node.__getitem__ = MagicMock(side_effect=lambda k: vuln_props[k])
    record = MagicMock()
    record.__getitem__ = MagicMock(side_effect=lambda k: node)
    session_ctx.run.return_value.__iter__ = MagicMock(return_value=iter([record]))

    query = """
    {
      vulnerabilities {
        cveId mispEventId firstImportedAt lastImportedFrom
      }
    }
    """
    resp = client.post("/graphql", json={"query": query})
    assert resp.status_code == 200
    data = resp.json()
    assert "errors" not in data, data.get("errors")
    vuln = data["data"]["vulnerabilities"][0]
    assert vuln["cveId"] == "CVE-2025-0001"
    assert vuln["mispEventId"] == "77"
    assert vuln["firstImportedAt"] == "2025-03-01T08:00:00"
    assert vuln["lastImportedFrom"] == "cisa_kev"


def test_cve_provenance_fields(graphql_client):
    """CVE must expose first_imported_at, last_updated, and last_imported_from."""
    client, session_ctx = graphql_client

    # Re-use _fake_cve_record base and inject provenance props
    cve_props = {
        "cve_id": "CVE-2024-5555",
        "description": "CVE provenance test",
        "published": "2024-02-01",
        "last_modified": "2024-07-01",
        "cpe_type": ["a"],
        "result_impacts": ["HIGH"],
        "ref_tags": ["Patch"],
        "cwe": ["CWE-119"],
        "cvss_score": 8.0,
        "severity": "HIGH",
        "edgeguard_managed": True,
        "source": ["nvd"],
        "zone": ["global"],
        "first_imported_at": "2024-02-02T00:00:00",
        "last_updated": "2024-07-02T00:00:00",
        "last_imported_from": "nvd",
    }
    cve_node = _make_node(cve_props)
    record = MagicMock()
    record.__getitem__ = MagicMock(
        side_effect=lambda k: {"c": cve_node, "cv40": None, "cv31": None, "cv2": None}.get(k)
    )
    session_ctx.run.return_value.single.return_value = record

    query = """
    query {
      cve(cveId: "CVE-2024-5555") {
        cveId firstImportedAt lastUpdated lastImportedFrom
      }
    }
    """
    resp = client.post("/graphql", json={"query": query})
    assert resp.status_code == 200
    data = resp.json()
    assert "errors" not in data, data.get("errors")
    cve = data["data"]["cve"]
    assert cve["cveId"] == "CVE-2024-5555"
    assert cve["firstImportedAt"] == "2024-02-02T00:00:00"
    assert cve["lastUpdated"] == "2024-07-02T00:00:00"
    assert cve["lastImportedFrom"] == "nvd"


def test_empty_list_queries_return_arrays(graphql_client):
    """All list queries return [] — not null — when Neo4j returns no rows."""
    client, session_ctx = graphql_client
    session_ctx.run.return_value.__iter__ = MagicMock(return_value=iter([]))

    for field in ("malware", "techniques", "tactics", "campaigns"):
        query = f"{{ {field} {{ name }} }}"
        resp = client.post("/graphql", json={"query": query})
        assert resp.status_code == 200
        data = resp.json()
        assert "errors" not in data, f"{field}: {data.get('errors')}"
        assert data["data"][field] == []
