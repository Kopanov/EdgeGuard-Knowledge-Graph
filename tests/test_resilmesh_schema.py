"""EdgeGuard — ResilMesh schema alignment tests (no live Neo4j required)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))


def test_neo4j_client_has_resilmesh_node_methods():
    """Neo4jClient must have all ResilMesh network topology merge methods."""
    from neo4j_client import Neo4jClient

    required_methods = [
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
    ]

    client_methods = set(dir(Neo4jClient))
    missing = [m for m in required_methods if m not in client_methods]
    assert not missing, f"Neo4jClient missing ResilMesh methods: {missing}"


def test_neo4j_client_has_resilmesh_relationship_methods():
    """Neo4jClient must have all ResilMesh relationship creation methods."""
    from neo4j_client import Neo4jClient

    required_methods = [
        "create_softwareversion_on_host",
        "create_role_to_device",
        "create_role_assigned_to_user",
        "create_device_has_identity_host",
        "create_host_is_a_node",
        "create_ip_part_of_subnet",
        "create_subnet_part_of_subnet",
        "create_networkservice_on_host",
        "create_vulnerability_in_softwareversion",
        "create_cve_refers_to_vulnerability",
        "create_cve_has_cvss_v2",
        "create_cve_has_cvss_v30",
        "create_cve_has_cvss_v31",
        "create_cve_has_cvss_v40",
    ]

    client_methods = set(dir(Neo4jClient))
    missing = [m for m in required_methods if m not in client_methods]
    assert not missing, f"Neo4jClient missing ResilMesh relationship methods: {missing}"


def test_neo4j_client_has_edgeguard_core_methods():
    """Neo4jClient must have all EdgeGuard core merge methods."""
    from neo4j_client import Neo4jClient

    required_methods = [
        "merge_indicator",
        "merge_vulnerability",
        "merge_cve",
        "merge_malware",
        "merge_actor",
        "merge_technique",
        "merge_tactic",
        "merge_tool",
        "merge_node_with_source",
        "merge_indicators_batch",
        "merge_vulnerabilities_batch",
        "get_stats",
        "health_check",
        "ensure_constraints",
        "apply_sector_labels",
    ]

    client_methods = set(dir(Neo4jClient))
    missing = [m for m in required_methods if m not in client_methods]
    assert not missing, f"Neo4jClient missing EdgeGuard core methods: {missing}"


def test_allowed_node_labels_include_resilmesh_types():
    """The _ALLOWED_NODE_LABELS set must include all ResilMesh node types."""
    from neo4j_client import _ALLOWED_NODE_LABELS

    resilmesh_labels = {
        "IP",
        "Host",
        "Device",
        "Subnet",
        "Node",
        "SoftwareVersion",
        "Application",
        "NetworkService",
        "User",
        "Role",
        "Component",
        "Mission",
        "OrganizationUnit",
        "MissionDependency",
    }
    edgeguard_labels = {
        "Indicator",
        "Vulnerability",
        "CVE",
        "Malware",
        "ThreatActor",
        "Technique",
        "Tactic",
        "Tool",
        "Campaign",
        "Sector",
        "Source",
        "Alert",
        "CVSSv2",
        "CVSSv30",
        "CVSSv31",
        "CVSSv40",
    }

    missing_resilmesh = resilmesh_labels - _ALLOWED_NODE_LABELS
    missing_edgeguard = edgeguard_labels - _ALLOWED_NODE_LABELS

    assert not missing_resilmesh, f"Missing ResilMesh labels: {missing_resilmesh}"
    assert not missing_edgeguard, f"Missing EdgeGuard labels: {missing_edgeguard}"
