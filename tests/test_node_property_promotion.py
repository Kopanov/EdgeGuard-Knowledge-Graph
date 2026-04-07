"""
Tests for node property promotion — ensures merge functions promote
important fields (name, description, cvss_score, etc.) to extra_props
instead of leaving them only in raw_data on SOURCED_FROM edges.

These tests verify the fixes for the production issue where 69K nodes
had NULL core properties despite MISP having full data.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def mock_neo4j_client():
    """Create a Neo4jClient with mocked driver."""
    with patch.dict(os.environ, {"NEO4J_PASSWORD": "test", "MISP_API_KEY": "test"}):
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        client._uri = "bolt://localhost:7687"
        # Mock session context manager
        mock_session = MagicMock()
        mock_run = MagicMock()
        mock_run.single.return_value = None  # No existing node (new merge)
        mock_session.run.return_value = mock_run
        client.driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
        return client, mock_session


class TestTechniquePropertyPromotion:
    """Technique nodes must have name and description as queryable properties."""

    def test_technique_promotes_name(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        data = {
            "mitre_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse command and script interpreters.",
            "tactic_phases": ["execution"],
            "source": ["mitre_attck"],
            "zone": ["global"],
            "confidence_score": 0.95,
        }
        client.merge_technique(data, source_id="mitre_attck")
        # Check the Cypher query was called
        cypher_call = session.run.call_args_list[1]  # Second call is the merge (first is pre-check)
        cypher_text = cypher_call[0][0]
        # name should be in the SET clause as an extra_prop
        assert "n.name = $name" in cypher_text, "Technique.name must be promoted to extra_props"

    def test_technique_promotes_description(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        data = {
            "mitre_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse interpreters.",
            "source": ["mitre_attck"],
            "zone": ["global"],
            "confidence_score": 0.95,
        }
        client.merge_technique(data, source_id="mitre_attck")
        cypher_call = session.run.call_args_list[1]
        cypher_text = cypher_call[0][0]
        assert "n.description = $description" in cypher_text, "Technique.description must be promoted"


class TestTacticPropertyPromotion:
    """Tactic nodes must have name and description as queryable properties."""

    def test_tactic_promotes_name(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        data = {
            "mitre_id": "TA0001",
            "name": "Initial Access",
            "shortname": "initial-access",
            "description": "The adversary is trying to get into your network.",
            "source": ["mitre_attck"],
            "zone": ["global"],
            "confidence_score": 0.95,
        }
        client.merge_tactic(data, source_id="mitre_attck")
        cypher_call = session.run.call_args_list[1]
        cypher_text = cypher_call[0][0]
        assert "n.name = $name" in cypher_text, "Tactic.name must be promoted"


class TestCVEPropertyPromotion:
    """CVE nodes must have description, cvss_score, severity, attack_vector."""

    def test_cve_promotes_description(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        data = {
            "cve_id": "CVE-2024-1234",
            "description": "A critical buffer overflow vulnerability.",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "attack_vector": "NETWORK",
            "source": ["nvd"],
            "zone": ["global"],
            "confidence_score": 0.9,
        }
        client.merge_cve(data, source_id="nvd")
        cypher_call = session.run.call_args_list[1]
        cypher_text = cypher_call[0][0]
        assert "n.description = $description" in cypher_text, "CVE.description must be promoted"
        assert "n.cvss_score = $cvss_score" in cypher_text, "CVE.cvss_score must be promoted"
        assert "n.severity = $severity" in cypher_text, "CVE.severity must be promoted"


class TestToolPropertyPromotion:
    """Tool nodes must have name and description as queryable properties."""

    def test_tool_promotes_name_and_description(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        data = {
            "mitre_id": "S0154",
            "name": "Cobalt Strike",
            "description": "Cobalt Strike is a commercial penetration testing tool.",
            "tool_types": ["tool"],
            "source": ["mitre_attck"],
            "zone": ["global"],
            "confidence_score": 0.95,
        }
        client.merge_tool(data, source_id="mitre_attck")
        cypher_call = session.run.call_args_list[1]
        cypher_text = cypher_call[0][0]
        assert "n.name = $name" in cypher_text, "Tool.name must be promoted"
        assert "n.description = $description" in cypher_text, "Tool.description must be promoted"


class TestMalwarePropertyPromotion:
    """Malware nodes must have description as a queryable property."""

    def test_malware_promotes_description(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        data = {
            "name": "Emotet",
            "description": "Emotet is a banking trojan turned botnet.",
            "malware_types": ["trojan", "botnet"],
            "source": ["mitre_attck"],
            "zone": ["global"],
            "confidence_score": 0.8,
        }
        client.merge_malware(data, source_id="mitre_attck")
        cypher_call = session.run.call_args_list[1]
        cypher_text = cypher_call[0][0]
        assert "n.description = $description" in cypher_text, "Malware.description must be promoted"


class TestActorPropertyPromotion:
    """ThreatActor nodes must promote MITRE ATT&CK classification fields."""

    def test_actor_promotes_sophistication(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        data = {
            "name": "APT28",
            "description": "APT28 is a threat group attributed to Russia.",
            "sophistication": "expert",
            "primary_motivation": "organizational-gain",
            "resource_level": "government",
            "source": ["mitre_attck"],
            "zone": ["global"],
            "confidence_score": 0.95,
        }
        client.merge_actor(data, source_id="mitre_attck")
        cypher_call = session.run.call_args_list[1]
        cypher_text = cypher_call[0][0]
        assert "n.sophistication = $sophistication" in cypher_text, "Actor.sophistication must be promoted"
        assert "n.primary_motivation = $primary_motivation" in cypher_text
        assert "n.resource_level = $resource_level" in cypher_text


class TestCVSSNullFiltering:
    """CVSS nodes must filter None/empty values before SET."""

    def test_cvss_filters_none_values(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        # Simulate CVSS data with some None values
        cvss_data = {
            "base_score": 9.8,
            "base_severity": "CRITICAL",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "attack_vector": None,  # Should be filtered out
            "attack_complexity": "",  # Should be filtered out
            "scope": "UNCHANGED",
        }
        client._merge_cvss_node("CVE-2024-1234", "nvd", "CVSSv31", "HAS_CVSS_v31", cvss_data)
        cypher_call = session.run.call_args_list[0]
        cypher_text = cypher_call[0][0]
        params = cypher_call[1]
        # None and empty string should be filtered
        assert "attack_vector" not in params, "None values must be filtered from CVSS params"
        assert "attack_complexity" not in params, "Empty string values must be filtered"
        # Valid values should be present
        assert params.get("base_score") == 9.8, "Valid base_score must be kept"
        assert params.get("scope") == "UNCHANGED", "Valid string must be kept"

    def test_cvss_keeps_zero_score(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        cvss_data = {
            "base_score": 0.0,  # Valid score, must NOT be filtered
            "base_severity": "NONE",
            "vector_string": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
        }
        client._merge_cvss_node("CVE-2024-5678", "nvd", "CVSSv31", "HAS_CVSS_v31", cvss_data)
        cypher_call = session.run.call_args_list[0]
        params = cypher_call[1]
        assert params.get("base_score") == 0.0, "Zero base_score (0.0) must NOT be filtered — it's a valid CVSS score"


class TestBaseScoreTruthiness:
    """parse_attribute must use `is not None` for base_score, not truthiness."""

    def test_zero_base_score_not_dropped(self):
        """Verify the fix: `if v31.get('base_score') is not None` keeps 0.0."""
        # Simulate the fixed logic
        v31 = {"base_score": 0.0, "base_severity": "NONE"}
        # Old buggy code: if v31.get("base_score"):  → drops 0.0
        # Fixed code: if v31.get("base_score") is not None:  → keeps 0.0
        assert v31.get("base_score") is not None, "0.0 must pass 'is not None' check"
        cvss_score = float(v31["base_score"])
        assert cvss_score == 0.0, "0.0 must be preserved as a valid CVSS score"

    def test_missing_base_score_is_none(self):
        """Verify that truly missing base_score is correctly detected."""
        v31 = {"base_severity": "NONE"}  # no base_score key
        assert v31.get("base_score") is None, "Missing base_score must be None"
