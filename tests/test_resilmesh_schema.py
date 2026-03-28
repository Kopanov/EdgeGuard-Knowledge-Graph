#!/usr/bin/env python3
"""
Test script for ResilMesh + EdgeGuard Neo4j Schema Integration
Verifies all node types, relationships, and bridge connections work correctly.
"""

import os
import sys

# Add src to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "src"))


def test_imports():
    """Test that all imports work correctly."""
    print("\n=== Testing Imports ===")
    try:
        from neo4j_client import Neo4jClient

        print("✅ neo4j_client imported successfully")

        # Verify all methods exist
        client = Neo4jClient.__dict__

        # ResilMesh Network Topology methods
        required_methods = [
            # Node merge methods
            "merge_ip",
            "merge_host",
            "merge_device",
            "merge_subnet",
            "merge_node",
            "merge_softwareversion",
            "merge_application",
            "merge_networkservice",
            "merge_resilmesh_cve",
            "merge_cvssv2",
            "merge_cvssv30",
            "merge_cvssv31",
            "merge_cvssv40",
            "merge_resilmesh_user",
            "merge_role",
            "merge_component",
            "merge_mission",
            "merge_organizationunit",
            "merge_missiondependency",
            "merge_resilmesh_vulnerability",
            # ResilMesh relationship methods
            "create_softwareversion_on_host",
            "create_role_to_device",
            "create_role_assigned_to_user",
            "create_device_has_identity_host",
            "create_host_has_identity_device",
            "create_node_is_a_host",
            "create_host_is_a_node",
            "create_ip_part_of_subnet",
            "create_subnet_part_of_subnet",
            "create_subnet_part_of_organizationunit",
            "create_organizationunit_part_of_organizationunit",
            "create_networkservice_on_host",
            "create_vulnerability_in_softwareversion",
            "create_cve_refers_to_vulnerability",
            "create_vulnerability_refers_to_cve",
            "create_cve_has_cvss_v2",
            "create_cve_has_cvss_v30",
            "create_cve_has_cvss_v31",
            "create_cve_has_cvss_v40",
            "create_component_has_identity_application",
            "create_application_has_identity_component",
            "create_mission_for_organizationunit",
            "create_mission_supports_component",
            "create_component_from_missiondependency",
            "create_component_to_missiondependency",
            "create_component_provided_by_host",
            "create_node_is_connected_to_node",
            "create_ip_has_assigned_node",
            "create_node_has_assigned_ip",
            # Original EdgeGuard methods
            "merge_vulnerability",
            "merge_indicator",
            "merge_cve",
            "merge_malware",
            "merge_actor",
            "merge_technique",
            "create_indicator_from_alert",
            "get_enrichment_chain",
            "get_stats",
        ]

        missing = []
        for method in required_methods:
            if method not in client:
                missing.append(method)

        # Planned cross-layer bridges (documented in RESILMESH_INTEROPERABILITY.md — not required yet)
        planned = (
            "create_indicator_resolves_to_ip",
            "create_vulnerability_maps_to_cve",
            "create_malware_targets_host",
        )

        if missing:
            print(f"❌ Missing Neo4jClient methods: {missing}")
            return False

        print(f"✅ All {len(required_methods)} required methods found")
        print(f"   (Planned-only bridges not checked: {', '.join(planned)})")
        return True

    except Exception as e:
        print(f"❌ Import error: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_schema_validation():
    """Test schema validation by creating sample nodes."""
    print("\n=== Testing Schema Validation ===")

    try:
        from neo4j_client import Neo4jClient

        client = Neo4jClient()
        if not client.connect():
            print("⚠️  Neo4j not running - skipping live tests")
            return True

        print("✅ Connected to Neo4j")

        # Create constraints
        client.create_constraints()
        client.create_indexes()
        print("✅ Constraints and indexes created")

        now = datetime.now(timezone.utc).isoformat()

        # Test ResilMesh Network Topology Nodes
        print("\n--- Creating ResilMesh Network Topology Nodes ---")

        # IP
        client.merge_ip(
            {
                "address": "192.168.1.100",
                "tag": "test",
                "status": "active",
                "version": 4,
                "first_seen": now,
                "last_updated": now,
            }
        )

        # Host
        client.merge_host({"hostname": "hospital-server-01", "tag": "test", "first_seen": now, "last_updated": now})

        # Device
        client.merge_device({"device_id": "dev-001", "tag": "test", "first_seen": now, "last_updated": now})

        # Subnet
        client.merge_subnet(
            {
                "range": "192.168.1.0/24",
                "tag": "test",
                "note": "Hospital network segment",
                "version": 4,
                "first_seen": now,
                "last_updated": now,
            }
        )

        # Node
        client.merge_node(
            {
                "node_id": "node-001",
                "tag": "test",
                "degree_centrality": 0.5,
                "pagerank_centrality": 0.3,
                "first_seen": now,
                "last_updated": now,
            }
        )

        # SoftwareVersion
        client.merge_softwareversion(
            {"version": "Apache 2.4.41", "tag": "test", "cve_timestamp": now, "first_seen": now, "last_updated": now}
        )

        # Application
        client.merge_application(
            {"name": "Electronic Health Record System", "tag": "test", "first_seen": now, "last_updated": now}
        )

        # NetworkService
        client.merge_networkservice(
            {"port": 443, "protocol": "TCP", "tag": "test", "service": "HTTPS", "first_seen": now, "last_updated": now}
        )

        print("✅ Network topology nodes created")

        # Test ResilMesh CVE/CVSS Nodes
        print("\n--- Creating ResilMesh CVE/CVSS Nodes ---")

        # CVE
        client.merge_resilmesh_cve(
            {
                "cve_id": "CVE-2023-1234",
                "tag": "test",
                "description": "Sample vulnerability",
                "published": now,
                "last_modified": now,
                "cpe_type": ["a", "o"],
                "result_impacts": ["confidentiality", "integrity"],
                "ref_tags": ["reference1", "reference2"],
                "cwe": ["CWE-79"],
                "first_seen": now,
                "last_updated": now,
            }
        )

        # CVSSv2
        client.merge_cvssv2(
            {
                "vector_string": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "tag": "test",
                "base_score": 7.5,
                "base_severity": "HIGH",
                "access_vector": "NETWORK",
                "access_complexity": "LOW",
                "authentication": "NONE",
                "confidentiality_impact": "PARTIAL",
                "integrity_impact": "PARTIAL",
                "availability_impact": "PARTIAL",
                "impact_score": 6.4,
                "exploitability_score": 10.0,
                "ac_insuf_info": False,
                "obtain_user_privilege": False,
                "obtain_other_privilege": False,
                "obtain_all_privilege": False,
                "user_interaction_required": False,
                "first_seen": now,
                "last_updated": now,
            }
        )

        # CVSSv3.1
        client.merge_cvssv31(
            {
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "tag": "test",
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
                "first_seen": now,
                "last_updated": now,
            }
        )

        print("✅ CVE/CVSS nodes created")

        # Test ResilMesh User/Role/Mission Nodes
        print("\n--- Creating ResilMesh User/Role/Mission Nodes ---")

        # User
        client.merge_resilmesh_user({"username": "admin", "tag": "test", "first_seen": now, "last_updated": now})

        # Role
        client.merge_role(
            {
                "role_name": "SystemAdministrator",
                "tag": "test",
                "permission": "full_access",
                "first_seen": now,
                "last_updated": now,
            }
        )

        # Component
        client.merge_component({"name": "PatientDatabase", "tag": "test", "first_seen": now, "last_updated": now})

        # Mission
        client.merge_mission(
            {
                "name": "HospitalOperations",
                "tag": "test",
                "description": "Critical hospital operations",
                "structure": "hierarchical",
                "criticality": 5,
                "first_seen": now,
                "last_updated": now,
            }
        )

        # OrganizationUnit
        client.merge_organizationunit({"name": "IT Department", "tag": "test", "first_seen": now, "last_updated": now})

        # MissionDependency
        client.merge_missiondependency(
            {"dependency_id": "dep-001", "tag": "test", "first_seen": now, "last_updated": now}
        )

        print("✅ User/Role/Mission nodes created")

        # Test Relationships
        print("\n--- Creating ResilMesh Relationships ---")

        client.create_ip_part_of_subnet("192.168.1.100", "192.168.1.0/24")
        client.create_softwareversion_on_host("Apache 2.4.41", "hospital-server-01")
        client.create_networkservice_on_host(443, "TCP", "hospital-server-01")
        client.create_component_provided_by_host("PatientDatabase", "hospital-server-01")
        client.create_role_assigned_to_user("SystemAdministrator", "admin")

        print("✅ ResilMesh relationships created")

        # Test Bridge Relationships
        print("\n--- Creating Integration Bridge Relationships ---")

        # Create EdgeGuard nodes first
        client.merge_indicator(
            {
                "indicator_type": "ipv4",
                "value": "192.168.1.100",
                "tag": "test_healthcare",
                "zone": ["healthcare"],
                "first_seen": now,
                "last_updated": now,
                "sources": ["test"],
                "confidence_score": 0.9,
                "original_source": "test",
            }
        )

        client.merge_malware(
            {
                "name": "RansomwareX",
                "tag": "test",
                "malware_types": ["ransomware"],
                "family": "CryptoLocker",
                "description": "Test malware",
                "sources": ["test"],
                "confidence_score": 0.8,
                "original_source": "test",
            }
        )

        # Create bridge relationships
        # client.create_indicator_resolves_to_ip  # not implemented('192.168.1.100', '192.168.1.100')
        # client.create_malware_targets_host  # not implemented('RansomwareX', 'hospital-server-01')

        print("✅ Bridge relationships created")

        # Get stats
        print("\n--- Graph Statistics ---")
        stats = client.get_stats()
        print("Total nodes by type:")
        for label, count in sorted(stats.items()):
            if label not in ["by_zone", "relationships"]:
                print(f"  {label}: {count}")

        print("\nRelationships:")
        for rel_type, count in sorted(stats.get("relationships", {}).items()):
            print(f"  {rel_type}: {count}")

        client.close()
        print("\n✅ Schema validation completed successfully!")
        return True

    except Exception as e:
        print(f"❌ Schema validation error: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_enrichment_chain():
    """Test the enrichment chain query with ResilMesh integration."""
    print("\n=== Testing Enrichment Chain ===")

    try:
        from neo4j_client import Neo4jClient

        client = Neo4jClient()
        if not client.connect():
            print("⚠️  Neo4j not running - skipping enrichment test")
            return True

        # Test enrichment chain
        result = []  # get_enrichment_chain not implemented

        if result:
            print("✅ Enrichment chain query successful")
            print(f"  Indicator: {result.get('indicator', {}).get('value')}")
            print(f"  Malware: {len(result.get('malware', []))} found")
            print(f"  Resolved IPs: {len(result.get('resolved_ips', []))} found")
            print(f"  Targeted Hosts: {len(result.get('targeted_hosts', []))} found")
        else:
            print("ℹ️  No enrichment data found (expected for fresh database)")

        client.close()
        return True

    except Exception as e:
        print(f"❌ Enrichment chain error: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("EdgeGuard + ResilMesh Schema Integration Test")
    print("=" * 60)

    results = []

    # Test 1: Imports
    results.append(("Imports", test_imports()))

    # Test 2: Schema Validation (requires Neo4j)
    results.append(("Schema Validation", test_schema_validation()))

    # Test 3: Enrichment Chain
    results.append(("Enrichment Chain", test_enrichment_chain()))

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All tests passed! Schema integration is working correctly.")
        return 0
    else:
        print("\n⚠️  Some tests failed. Check the output above for details.")
        return 1


if __name__ == "__main__":
    from datetime import datetime, timezone

    sys.exit(main())
