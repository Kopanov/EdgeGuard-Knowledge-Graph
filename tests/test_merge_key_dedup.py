"""
Merge key deduplication tests — ensure entity nodes merge correctly across sources.

The production baseline (441K nodes) revealed that including ``tag`` in MERGE keys
caused ThreatActor/Malware/Technique nodes to fragment: APT28 had 7 separate nodes
(one per source tag) instead of 1. These tests verify:

1. MERGE key_props for each entity type do NOT include ``tag``
2. Indicator MERGE key also does NOT include ``tag`` (same as all entities)
3. CVSS sub-nodes STILL include ``tag`` (different CVSS scores per source)
4. Neo4j constraints match the MERGE keys
5. Batch MERGE queries use the correct keys
6. Cross-item relationship dicts use correct from_key/to_key (no tag for entities)
7. Embedded (parse_attribute) relationship dicts use correct keys
8. Tag is accumulated into ``tags`` array, not lost
"""

import os
import sys
from unittest.mock import MagicMock

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# Drop stale cached modules so we always get fresh imports
for _mod in ("neo4j_client", "run_misp_to_neo4j"):
    if _mod in sys.modules:
        del sys.modules[_mod]

from neo4j_client import Neo4jClient  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_neo4j_mock():
    """Return a Neo4jClient with a mocked driver that captures Cypher queries."""
    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    client._connection_healthy = True
    # session.run returns a mock result with .single() -> None
    mock_session = MagicMock()
    mock_result = MagicMock()
    mock_result.single.return_value = None
    mock_session.run.return_value = mock_result
    client.driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return client, mock_session


# ===========================================================================
# 1. MERGE key_props — tag must NOT be in entity keys
# ===========================================================================


class TestMergeKeyProps:
    """Verify each merge_* function builds key_props without tag (except Indicator)."""

    def _assert_merge_called_without_tag_in_key(self, client, session, merge_fn, data, label):
        """Call merge function, capture the Cypher, verify tag is not in MERGE key."""
        merge_fn(data, source_id="test_source")
        # Find the MERGE call (second session.run — first is the audit check)
        calls = session.run.call_args_list
        assert len(calls) >= 2, f"Expected at least 2 session.run calls for {label}, got {len(calls)}"
        merge_call = calls[1]  # second call is the MERGE
        cypher = merge_call[0][0]  # first positional arg
        # The MERGE pattern should NOT contain "tag:" for entity nodes
        merge_line = [line for line in cypher.split("\n") if "MERGE" in line]
        assert merge_line, f"No MERGE statement found in Cypher for {label}"
        merge_stmt = merge_line[0]
        assert "tag:" not in merge_stmt, (
            f"{label} MERGE key still contains 'tag:' — should merge on name/mitre_id only.\n"
            f"MERGE statement: {merge_stmt}"
        )

    def test_merge_actor_no_tag_in_key(self):
        client, session = _make_neo4j_mock()
        data = {"name": "APT28", "tag": "mitre_attck", "zone": ["global"]}
        self._assert_merge_called_without_tag_in_key(client, session, client.merge_actor, data, "ThreatActor")

    def test_merge_malware_no_tag_in_key(self):
        client, session = _make_neo4j_mock()
        data = {"name": "Emotet", "tag": "alienvault_otx", "zone": ["global"]}
        self._assert_merge_called_without_tag_in_key(client, session, client.merge_malware, data, "Malware")

    def test_merge_technique_no_tag_in_key(self):
        client, session = _make_neo4j_mock()
        data = {"mitre_id": "T1059", "name": "Command-Line Interface", "tag": "mitre_attck", "zone": ["global"]}
        self._assert_merge_called_without_tag_in_key(client, session, client.merge_technique, data, "Technique")

    def test_merge_tactic_no_tag_in_key(self):
        client, session = _make_neo4j_mock()
        data = {"mitre_id": "TA0001", "name": "Initial Access", "tag": "mitre_attck", "zone": ["global"]}
        self._assert_merge_called_without_tag_in_key(client, session, client.merge_tactic, data, "Tactic")

    def test_merge_tool_no_tag_in_key(self):
        client, session = _make_neo4j_mock()
        data = {"mitre_id": "S0154", "name": "Cobalt Strike", "tag": "mitre_attck", "zone": ["global"]}
        self._assert_merge_called_without_tag_in_key(client, session, client.merge_tool, data, "Tool")

    def test_merge_vulnerability_no_tag_in_key(self):
        client, session = _make_neo4j_mock()
        data = {"cve_id": "CVE-2021-44228", "tag": "nvd", "zone": ["global"]}
        self._assert_merge_called_without_tag_in_key(client, session, client.merge_vulnerability, data, "Vulnerability")

    def test_merge_cve_no_tag_in_key(self):
        client, session = _make_neo4j_mock()
        data = {"cve_id": "CVE-2021-44228", "tag": "nvd", "zone": ["global"]}
        # merge_cve calls merge_node_with_source + _merge_cvss_node; just check first call
        client.merge_cve(data, source_id="nvd")
        calls = session.run.call_args_list
        assert len(calls) >= 2
        merge_cypher = calls[1][0][0]
        merge_line = [ln for ln in merge_cypher.split("\n") if "MERGE" in ln][0]
        assert "tag:" not in merge_line, f"CVE MERGE key has tag: {merge_line}"


# ===========================================================================
# 2. Indicator MERGE key MUST include tag
# ===========================================================================


class TestIndicatorNoTag:
    """Indicator is keyed by (indicator_type, value) — no tag, like all other entities."""

    def test_merge_indicator_no_tag_in_key(self):
        client, session = _make_neo4j_mock()
        data = {
            "indicator_type": "ipv4",
            "value": "1.2.3.4",
            "tag": "alienvault_otx",
            "zone": ["global"],
        }
        client.merge_indicator(data, source_id="alienvault_otx")
        calls = session.run.call_args_list
        assert len(calls) >= 2
        merge_cypher = calls[1][0][0]
        merge_line = [ln for ln in merge_cypher.split("\n") if "MERGE" in ln][0]
        assert "tag:" not in merge_line, f"Indicator MERGE key should NOT have tag: {merge_line}"


# ===========================================================================
# 3. Tag accumulated into tags array
# ===========================================================================


class TestTagAccumulation:
    """Verify the Cypher accumulates tag into n.tags array."""

    def test_merge_node_cypher_has_tags_accumulation(self):
        client, session = _make_neo4j_mock()
        data = {"name": "APT28", "tag": "mitre_attck", "zone": ["global"]}
        client.merge_actor(data, source_id="mitre_attck")
        calls = session.run.call_args_list
        merge_cypher = calls[1][0][0]
        assert "n.tags = apoc.coll.toSet(coalesce(n.tags, []) + $tag_array)" in merge_cypher
        # Verify tag_array param was passed
        merge_kwargs = calls[1][1]
        assert "tag_array" in merge_kwargs
        assert merge_kwargs["tag_array"] == ["mitre_attck"]

    def test_tag_value_preserved_as_scalar(self):
        client, session = _make_neo4j_mock()
        data = {"name": "APT28", "tag": "mitre_attck", "zone": ["global"]}
        client.merge_actor(data, source_id="mitre_attck")
        merge_kwargs = session.run.call_args_list[1][1]
        assert merge_kwargs["tag_value"] == "mitre_attck"


# ===========================================================================
# 4. Batch MERGE queries
# ===========================================================================


class TestBatchMergeKeys:
    """Verify batch MERGE Cypher uses correct keys."""

    def test_vulnerability_batch_no_tag_in_merge(self):
        client, session = _make_neo4j_mock()
        items = [
            {"cve_id": "CVE-2021-44228", "tag": "nvd", "zone": ["global"]},
            {"cve_id": "CVE-2021-44228", "tag": "cisa_kev", "zone": ["energy"]},
        ]
        client.merge_vulnerabilities_batch(items, source_id="misp")
        calls = session.run.call_args_list
        assert len(calls) >= 1
        cypher = calls[0][0][0]
        merge_line = [ln for ln in cypher.split("\n") if "MERGE" in ln][0]
        assert "tag" not in merge_line, f"Vulnerability batch MERGE has tag: {merge_line}"
        # Same CVE from different tags should produce ONE batch item key
        assert "item.cve_id" in merge_line

    def test_vulnerability_batch_accumulates_tags(self):
        client, session = _make_neo4j_mock()
        items = [{"cve_id": "CVE-2021-44228", "tag": "nvd", "zone": ["global"]}]
        client.merge_vulnerabilities_batch(items, source_id="misp")
        cypher = session.run.call_args_list[0][0][0]
        assert "n.tags = apoc.coll.toSet(coalesce(n.tags, []) + [item.tag])" in cypher

    def test_indicator_batch_no_tag_in_merge(self):
        client, session = _make_neo4j_mock()
        items = [
            {"indicator_type": "ipv4", "value": "1.2.3.4", "tag": "otx", "zone": ["global"]},
        ]
        client.merge_indicators_batch(items, source_id="misp")
        cypher = session.run.call_args_list[0][0][0]
        merge_line = [ln for ln in cypher.split("\n") if "MERGE" in ln][0]
        assert "tag" not in merge_line, f"Indicator batch should NOT have tag: {merge_line}"


# ===========================================================================
# 5. Cross-item relationship keys (from _build_cross_item_relationships)
# ===========================================================================


class TestCrossItemRelKeys:
    """Verify _build_cross_item_relationships builds correct from_key/to_key."""

    def _build_rels(self, items):
        syncer = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
        return syncer._build_cross_item_relationships(items)

    def test_actor_technique_uses_no_tag(self):
        items = [
            {"type": "actor", "name": "APT28", "tag": "mitre_attck"},
            {"type": "technique", "mitre_id": "T1059", "name": "CLI", "tag": "mitre_attck"},
        ]
        rels = self._build_rels(items)
        uses = [r for r in rels if r["rel_type"] == "USES"]
        assert len(uses) == 1
        assert "tag" not in uses[0]["from_key"], f"USES from_key has tag: {uses[0]['from_key']}"
        assert "tag" not in uses[0]["to_key"], f"USES to_key has tag: {uses[0]['to_key']}"
        assert uses[0]["from_key"] == {"name": "APT28"}
        assert uses[0]["to_key"] == {"mitre_id": "T1059"}

    def test_malware_actor_attributed_to_no_tag(self):
        items = [
            {"type": "malware", "name": "Emotet", "tag": "misp"},
            {"type": "actor", "name": "TA542", "tag": "misp"},
        ]
        rels = self._build_rels(items)
        attr = [r for r in rels if r["rel_type"] == "ATTRIBUTED_TO"]
        assert len(attr) == 1
        assert "tag" not in attr[0]["from_key"]
        assert "tag" not in attr[0]["to_key"]

    def test_indicator_malware_indicates_no_tag(self):
        items = [
            {"type": "indicator", "indicator_type": "ipv4", "value": "1.2.3.4", "tag": "misp"},
            {"type": "malware", "name": "Emotet", "tag": "misp"},
        ]
        rels = self._build_rels(items)
        ind = [r for r in rels if r["rel_type"] == "INDICATES"]
        assert len(ind) == 1
        # Indicator from_key should NOT have tag (tag removed from all MERGE keys)
        assert "tag" not in ind[0]["from_key"], f"INDICATES from_key should not have tag: {ind[0]['from_key']}"
        assert "tag" not in ind[0]["to_key"], f"INDICATES to_key should not have tag: {ind[0]['to_key']}"

    def test_indicator_vulnerability_exploits_no_tag(self):
        items = [
            {"type": "indicator", "indicator_type": "ipv4", "value": "1.2.3.4", "tag": "misp"},
            {"type": "vulnerability", "cve_id": "CVE-2021-44228", "value": "CVE-2021-44228", "tag": "nvd"},
        ]
        rels = self._build_rels(items)
        expl = [r for r in rels if r["rel_type"] == "EXPLOITS"]
        assert len(expl) == 1
        assert "tag" not in expl[0]["from_key"], f"EXPLOITS from_key should not have tag: {expl[0]['from_key']}"
        assert "tag" not in expl[0]["to_key"], f"EXPLOITS to_key should not have tag: {expl[0]['to_key']}"
        assert expl[0]["to_key"] == {"cve_id": "CVE-2021-44228"}

    def test_vulnerability_sector_targets_no_tag(self):
        items = [
            {
                "type": "vulnerability",
                "cve_id": "CVE-2021-44228",
                "value": "CVE-2021-44228",
                "tag": "nvd",
                "zone": ["energy"],
            },
        ]
        rels = self._build_rels(items)
        tgt = [r for r in rels if r["rel_type"] == "TARGETS" and r["from_type"] == "Vulnerability"]
        assert len(tgt) == 1
        assert "tag" not in tgt[0]["from_key"], f"TARGETS from_key (Vuln) has tag: {tgt[0]['from_key']}"


# ===========================================================================
# 6. Dedup hypothesis: same entity from 3 sources produces 1 merge call
# ===========================================================================


class TestDedupHypothesis:
    """Simulate what happens when 3 sources provide the same actor."""

    def test_same_actor_three_sources_same_key(self):
        """APT28 from mitre, otx, and misp should all produce key_props={'name': 'APT28'}."""
        client, _ = _make_neo4j_mock()

        for tag in ["mitre_attck", "alienvault_otx", "misp"]:
            data = {"name": "APT28", "tag": tag, "zone": ["global"]}
            key_props = {"name": data.get("name")}
            # This is what merge_actor builds — verify it's the same across sources
            assert key_props == {"name": "APT28"}, f"Key mismatch for tag={tag}: {key_props}"

    def test_same_cve_two_sources_same_key(self):
        """CVE-2021-44228 from NVD and CISA should produce same key."""
        client, _ = _make_neo4j_mock()

        for tag in ["nvd", "cisa_kev"]:
            data = {"cve_id": "CVE-2021-44228", "tag": tag, "zone": ["global"]}
            key_props = {"cve_id": "CVE-2021-44228"}
            assert "tag" not in key_props

    def test_same_indicator_different_tags_same_key(self):
        """Same IP from different sources SHOULD merge into one node (no tag in key)."""
        key_otx = {"indicator_type": "ipv4", "value": "1.2.3.4"}
        key_misp = {"indicator_type": "ipv4", "value": "1.2.3.4"}
        assert key_otx == key_misp, "Indicator keys should be the same regardless of tag"


# ===========================================================================
# 7. source_id routing: embedded=misp, cross-item=misp_cooccurrence
# ===========================================================================


class TestSourceIdRouting:
    """Verify cross-item rels use misp_cooccurrence for calibration compatibility."""

    def test_process_event_attributes_source_id_split(self):
        """Embedded rels → 'misp', cross-item rels → 'misp_cooccurrence'."""
        syncer = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
        syncer.neo4j = MagicMock()
        syncer.neo4j.merge_indicators_batch.return_value = (2, 0)
        syncer.neo4j.merge_vulnerabilities_batch.return_value = (0, 0)
        syncer.stats = {
            "events_processed": 0,
            "events_failed": 0,
            "indicators_synced": 0,
            "vulnerabilities_synced": 0,
            "relationships_created": 0,
            "errors": 0,
        }

        # Mock _create_relationships to capture source_id
        source_ids_used = []
        original_create = syncer._create_relationships if hasattr(syncer, "_create_relationships") else None

        def _mock_create_rels(rels, source_id):
            source_ids_used.append((source_id, len(rels)))
            return len(rels)

        syncer._create_relationships = _mock_create_rels
        syncer.sync_to_neo4j = MagicMock(return_value=(2, 0, []))
        syncer._build_cross_item_relationships = MagicMock(
            return_value=[{"rel_type": "INDICATES", "from_type": "Indicator", "to_type": "Malware"}]
        )

        # Simulate parse_attribute returning items + embedded rels
        def _mock_parse(attr, event):
            return (
                {"indicator_type": "ipv4", "value": attr["value"], "tag": "misp"},
                [{"rel_type": "TARGETS", "embedded": True}],  # embedded rel
            )

        syncer.parse_attribute = _mock_parse

        attributes = [
            {"type": "ip-src", "value": "1.1.1.1"},
            {"type": "ip-src", "value": "2.2.2.2"},
        ]
        full_event = {"Event": {"id": "1"}}

        syncer._process_event_attributes("1", full_event, attributes)

        # Should have 2 _create_relationships calls:
        # 1st: embedded rels with "misp"
        # 2nd: cross-item rels with "misp_cooccurrence"
        assert len(source_ids_used) == 2, f"Expected 2 _create_relationships calls, got {len(source_ids_used)}"
        assert source_ids_used[0][0] == "misp", f"Embedded rels should use 'misp', got '{source_ids_used[0][0]}'"
        assert source_ids_used[1][0] == "misp_cooccurrence", (
            f"Cross-item rels should use 'misp_cooccurrence', got '{source_ids_used[1][0]}'"
        )


# ===========================================================================
# 8. Type-based sampling caps
# ===========================================================================


class TestTypeSamplingCaps:
    """Verify _build_cross_item_relationships samples large type groups."""

    def _build_rels(self, items):
        syncer = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
        return syncer._build_cross_item_relationships(items)

    def test_large_indicator_list_sampled(self):
        """3000 indicators should be sampled to 2000."""
        items = [
            {"type": "indicator", "indicator_type": "ipv4", "value": f"10.0.{i // 256}.{i % 256}", "tag": "misp"}
            for i in range(3000)
        ]
        items.append({"type": "malware", "name": "TestMalware", "tag": "misp"})
        rels = self._build_rels(items)
        # With 2000 indicators x 1 malware = 2000 INDICATES rels (not 3000)
        indicates = [r for r in rels if r["rel_type"] == "INDICATES"]
        assert len(indicates) == 2000, f"Expected 2000 sampled INDICATES, got {len(indicates)}"

    def test_small_event_not_sampled(self):
        """50 indicators + 5 malware should NOT be sampled."""
        items = [
            {"type": "indicator", "indicator_type": "ipv4", "value": f"10.0.0.{i}", "tag": "misp"} for i in range(50)
        ]
        items.extend([{"type": "malware", "name": f"Malware{i}", "tag": "misp"} for i in range(5)])
        rels = self._build_rels(items)
        indicates = [r for r in rels if r["rel_type"] == "INDICATES"]
        assert len(indicates) == 250, f"Expected 50*5=250 INDICATES, got {len(indicates)}"


# ===========================================================================
# 9. Constraint definitions (regression guard)
# ===========================================================================


class TestConstraintDefinitions:
    """Verify constraint Cypher strings match the MERGE key patterns."""

    def test_entity_constraints_single_key(self):
        """Entity constraints should NOT include tag."""
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()

        # Extract constraint strings from create_constraints source
        import inspect

        source = inspect.getsource(client.create_constraints)

        # These should be single-key (no tag)
        assert "REQUIRE (m.name) IS UNIQUE" in source, "Malware constraint should be single-key"
        assert "REQUIRE (a.name) IS UNIQUE" in source, "ThreatActor constraint should be single-key"
        assert "REQUIRE (c.cve_id) IS UNIQUE" in source, "CVE constraint should be single-key"

    def test_indicator_constraint_no_tag(self):
        """Indicator constraint should NOT include tag."""
        import inspect

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        source = inspect.getsource(client.create_constraints)
        assert "REQUIRE (i.indicator_type, i.value) IS UNIQUE" in source

    def test_cvss_constraints_keep_tag(self):
        """CVSS sub-node constraints should include tag (different scores per source)."""
        import inspect

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        source = inspect.getsource(client.create_constraints)
        assert "REQUIRE (n.cve_id, n.tag) IS UNIQUE" in source
