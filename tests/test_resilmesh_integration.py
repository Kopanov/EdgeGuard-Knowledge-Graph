#!/usr/bin/env python3
"""
Test ResilMesh Integration with Alert Nodes
Validates the Phase 1 integration between EdgeGuard and ResilMesh schemas.

These are integration tests — they skip automatically if Neo4j is unavailable.
"""

import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

# -- helpers --


def _neo4j_available():
    """Check if Neo4j is reachable AND modules are not mocked."""
    try:
        import config

        # If config module is a MagicMock (from test_graphql_api stubs), skip
        if not hasattr(config, "NEO4J_URI") or not isinstance(config.NEO4J_URI, str):
            return False

        from neo4j_client import Neo4jClient

        c = Neo4jClient()
        ok = c.connect()
        if ok:
            c.close()
        return ok
    except Exception:
        return False


_SKIP_MSG = "Neo4j not available (integration test)"


# -- tests --


def test_alert_node_creation():
    """Test that Alert nodes are created correctly (integration — needs Neo4j)."""
    if not _neo4j_available():
        pytest.skip(_SKIP_MSG)
    from alert_processor import AlertProcessor

    processor = AlertProcessor()
    test_alert = {
        "alert_id": "test-resilmesh-001",
        "source": "wazuh",
        "zone": "healthcare",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tags": ["healthcare", "finance"],
        "threat": {
            "indicator": "192.168.100.50",
            "type": "ip",
            "malware": "TrickBot",
            "cve": "CVE-2021-43297",
            "description": "Suspected TrickBot C2 communication detected",
            "severity": 9,
            "source_ip": "192.168.100.50",
            "dest_ip": "185.220.101.45",
            "hostname": "hospital-server-01",
            "user": "admin",
        },
    }

    try:
        result = processor.process_alert(test_alert)
        assert result.alert_id == "test-resilmesh-001"
        assert result.query_metadata is not None
    except TypeError as e:
        if "MagicMock" in str(e):
            pytest.skip("MagicMock pollution from test_graphql_api stubs — run in isolation")
        raise
    finally:
        processor.close()


def test_multi_zone_alert():
    """Test that multi-zone alerts are handled correctly."""
    if not _neo4j_available():
        pytest.skip(_SKIP_MSG)
    from alert_processor import AlertProcessor

    processor = AlertProcessor()
    test_alert = {
        "alert_id": "test-multizone-001",
        "source": "wazuh",
        "zone": "finance",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tags": ["finance", "healthcare"],
        "threat": {
            "indicator": "10.0.0.5",
            "type": "ip",
            "description": "Multi-zone alert test",
            "severity": 7,
        },
    }

    try:
        result = processor.process_alert(test_alert)
        assert result.alert_id == "test-multizone-001"
    except TypeError as e:
        if "MagicMock" in str(e):
            pytest.skip("MagicMock pollution from test_graphql_api stubs — run in isolation")
        raise
    finally:
        processor.close()


def test_alert_schema_structure():
    """Test the expected alert input schema (no Neo4j needed)."""
    required_keys = {"alert_id", "source", "zone", "timestamp", "threat"}
    required_threat_keys = {"indicator", "type"}

    sample_alert = {
        "alert_id": "test-001",
        "source": "wazuh",
        "zone": "global",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "1.2.3.4",
            "type": "ip",
        },
    }

    assert required_keys.issubset(sample_alert.keys())
    assert required_threat_keys.issubset(sample_alert["threat"].keys())
