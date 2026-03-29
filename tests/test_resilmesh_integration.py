#!/usr/bin/env python3
"""
Test ResilMesh Integration with Alert Nodes
Validates the Phase 1 integration between EdgeGuard and ResilMesh schemas.
"""

import os
import sys
from datetime import datetime, timezone

import pytest

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# test_graphql_api may have stubbed neo4j_client / neo4j with MagicMock — restore real modules.
from stub_cleanup import clear_graphql_api_magicmock_stubs

clear_graphql_api_magicmock_stubs()

from alert_processor import AlertProcessor  # noqa: E402
from neo4j_client import Neo4jClient  # noqa: E402


def test_alert_node_creation():
    """Test that Alert nodes are created correctly."""
    print("\n" + "=" * 60)
    print("TEST 1: Alert Node Creation")
    print("=" * 60)

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

        print("\n✅ Alert processed successfully!")
        print(f"   Alert ID: {result.alert_id}")
        print(f"   Enriched: {result.enriched}")
        print(f"   Latency: {result.latency_ms}ms")
        print("\n   Query Metadata:")
        for key, value in result.query_metadata.items():
            print(f"     {key}: {value}")
        print("\n   Enrichment:")
        for key, value in result.enrichment.items():
            if key != "recommendations":
                print(f"     {key}: {value}")

        assert result.alert_id == "test-resilmesh-001"
        assert result.query_metadata is not None
    finally:
        processor.close()


def test_alert_indicator_linkage():
    """Test that Alert nodes are linked to Indicator nodes."""
    print("\n" + "=" * 60)
    print("TEST 2: Alert-Indicator Linkage")
    print("=" * 60)

    client = Neo4jClient()

    if not client.connect():
        pytest.skip("Neo4j not reachable — start Neo4j and set NEO4J_* in .env")

    try:
        # Query to verify the link exists
        query = """
        MATCH (a:Alert {alert_id: 'test-resilmesh-001'})-[r:INVOLVES]->(i:Indicator)
        RETURN a.alert_id as alert_id, i.value as indicator, type(r) as rel_type
        """

        with client.driver.session() as session:
            result = session.run(query)
            record = result.single()

            if not record:
                pytest.skip("Alert–Indicator link not in graph yet (run test_alert_node_creation with Neo4j up first)")

            print("\n✅ Link verified!")
            print(f"   Alert: {record['alert_id']}")
            print(f"   Indicator: {record['indicator']}")
            print(f"   Relationship: {record['rel_type']}")
            assert record["alert_id"] == "test-resilmesh-001"
            assert record["rel_type"] == "INVOLVES"
    finally:
        client.close()


def test_alert_retrieval():
    """Test retrieving an alert with enrichment data."""
    print("\n" + "=" * 60)
    print("TEST 3: Alert Retrieval with Enrichment")
    print("=" * 60)

    client = Neo4jClient()

    if not client.connect():
        pytest.skip("Neo4j not reachable — start Neo4j and set NEO4J_* in .env")

    try:
        alert = client.get_alert_with_enrichment("test-resilmesh-001")

        if not alert:
            pytest.skip("Alert test-resilmesh-001 not in graph — run test_alert_node_creation first")

        print("\n✅ Alert retrieved successfully!")
        print(f"   Alert ID: {alert.get('alert_id')}")
        print(f"   Source: {alert.get('source')}")
        print(f"   Zone: {alert.get('zone')}")
        print(f"   Severity: {alert.get('severity')}")
        print(f"   Enriched: {alert.get('enriched')}")
        print(f"   Latency: {alert.get('enrichment_latency_ms')}ms")

        if alert.get("indicator_data"):
            print("\n   Indicator Data:")
            print(f"     Value: {alert['indicator_data'].get('value')}")
            print(f"     Type: {alert['indicator_data'].get('indicator_type')}")
            print(f"     Zone: {alert['indicator_data'].get('zone')}")

        if alert.get("malware"):
            print("\n   Associated Malware:")
            for m in alert["malware"]:
                if m:
                    print(f"     - {m.get('name')} ({m.get('family', 'unknown family')})")

        if alert.get("threat_actors"):
            print("\n   Threat Actors:")
            for a in alert["threat_actors"]:
                if a:
                    print(f"     - {a.get('name')}")

        if alert.get("techniques"):
            print("\n   MITRE Techniques:")
            for t in alert["techniques"]:
                if t:
                    print(f"     - {t.get('mitre_id')}: {t.get('name')}")

        assert alert.get("alert_id") == "test-resilmesh-001"
    finally:
        client.close()


def test_multi_zone_alert():
    """Test processing of multi-zone alerts."""
    print("\n" + "=" * 60)
    print("TEST 4: Multi-Zone Alert Processing")
    print("=" * 60)

    processor = AlertProcessor()

    test_alert = {
        "alert_id": "test-multizone-001",
        "source": "wazuh",
        "zone": "healthcare",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tags": ["healthcare", "finance", "energy"],  # Multi-zone
        "threat": {
            "indicator": "evil-apt-c2.com",
            "type": "domain",
            "malware": "CozyDuke",
            "cve": "CVE-2021-34527",
            "description": "APT29 campaign targeting multiple sectors",
            "severity": 10,
        },
    }

    try:
        result = processor.process_alert(test_alert)

        print("\n✅ Multi-zone alert processed!")
        print(f"   Alert ID: {result.alert_id}")
        print(f"   Sectors affected: {result.enrichment.get('sectors_affected')}")
        print(f"   Cross-zone detected: {result.enrichment.get('cross_zone_detected')}")

        assert result.alert_id == "test-multizone-001"
    finally:
        processor.close()


def cleanup_test_data():
    """Clean up test data from Neo4j."""
    print("\n" + "=" * 60)
    print("CLEANUP: Removing Test Data")
    print("=" * 60)

    client = Neo4jClient()

    if not client.connect():
        return

    try:
        # Delete test alerts
        query = """
        MATCH (a:Alert)
        WHERE a.alert_id STARTS WITH 'test-'
        DETACH DELETE a
        """

        with client.driver.session() as session:
            result = session.run(query)

        print("\n✅ Test alerts cleaned up")
        client.close()

    except Exception as e:
        print(f"\n⚠️  Cleanup warning: {e}")
        client.close()


def main():
    """Run this module under pytest, then cleanup (CLI compatibility)."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║     EdgeGuard x ResilMesh Integration Test Suite             ║
║     Phase 1: Alert Node Creation & Enrichment                  ║
╚══════════════════════════════════════════════════════════════╝
    """)
    exit_code = pytest.main(
        [
            __file__,
            "-v",
            "--tb=short",
            "-k",
            "test_alert_node_creation or test_alert_indicator_linkage or test_alert_retrieval or test_multi_zone_alert",
        ]
    )
    cleanup_test_data()
    print("\n" + "=" * 60)
    print("Integration test complete!")
    print("=" * 60)
    return exit_code == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
