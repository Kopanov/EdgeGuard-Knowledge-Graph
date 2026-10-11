"""2026-10 shared-database contract (standalone product, maximal ResilMesh coexistence).

``edgeguard_managed = true`` means EdgeGuard CREATED the node and is stamped on the MERGE create
path only; a node a partner created first that EdgeGuard writes to gets ``edgeguard_enriched``.
EdgeGuard declares no UNIQUE constraint on partner-owned labels, CVSS de-duplication never groups
on a null key or touches partner nodes, Alert / INVOLVES carry the marker, the readers expose
created-or-enriched nodes, and the acceptance script polices the same contract.
"""

from __future__ import annotations

import inspect
import os
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import neo4j_client as nc  # noqa: E402
import node_identity  # noqa: E402

_SRC = Path(__file__).resolve().parent.parent / "src"
_WRITERS = ("neo4j_client.py", "build_relationships.py", "enrichment_jobs.py")
_READERS = ("query_api.py", "graphql_api.py", "stix_exporter.py")
_NODE_MERGE = re.compile(r"MERGE \((?P<var>\w+):(?P<label>[\w{}]+)[ {)]")
# Clause keywords that can precede a property write; "SET" alone must not match the SET inside
# ON CREATE SET / ON MATCH SET.
_CLAUSE = re.compile(r"\bON CREATE SET\b|\bON MATCH SET\b|(?<!CREATE )(?<!MATCH )\bSET\b|\bWHERE\b")


def _node_merge_sites(text: str):
    """(var, label, line, window) for every node MERGE that is real Cypher (has a SET nearby)."""
    for m in _NODE_MERGE.finditer(text):
        nxt = text.find("MERGE (", m.end())
        window = text[m.start() : (nxt if nxt != -1 else len(text))][:3000]
        if "SET " not in window:
            continue  # a mention in prose
        yield m["var"], m["label"], text.count("\n", 0, m.start()) + 1, window


def _client() -> nc.Neo4jClient:
    client = nc.Neo4jClient.__new__(nc.Neo4jClient)
    client.driver = MagicMock()
    return client


def _queries(client: nc.Neo4jClient):
    session = client.driver.session.return_value.__enter__.return_value
    return [c.args[0] for c in session.run.call_args_list]


# ---------------------------------------------------------------------------
# Marker on the create path only, enrichment on the match path
# ---------------------------------------------------------------------------


class TestMarkerOnCreatePathOnly:
    def test_helper_is_the_single_definition(self):
        assert nc._enriched_on_match_clause("x") == (
            "ON MATCH SET x.edgeguard_enriched = CASE WHEN x.edgeguard_managed = true THEN x.edgeguard_enriched ELSE true END"
        )

    def test_every_node_merge_stamps_managed_on_create_and_enriched_on_match(self):
        sites = 0
        for name in _WRITERS:
            text = (_SRC / name).read_text()
            for var, label, line, window in _node_merge_sites(text):
                sites += 1
                where = f"{name}:{line} MERGE ({var}:{label})"
                assert f"{var}.edgeguard_managed = true" in window, f"{where} never stamps the ownership marker"
                assert nc._enriched_on_match_clause(var) in window, f"{where} lacks the ON MATCH enriched clause"
                for occ in re.finditer(re.escape(f"{var}.edgeguard_managed = true"), window):
                    if window[: occ.start()].endswith("CASE WHEN "):
                        continue  # the comparison inside the ON MATCH clause, not a write
                    last = None
                    for c in _CLAUSE.finditer(window, 0, occ.start()):
                        last = c.group(0)
                    assert last == "ON CREATE SET", f"{where} writes the marker outside ON CREATE (after {last!r})"
        # 29 in neo4j_client (threat-intel, CVSS, Source, 5× Sector, topology, identity, alert path, Alert),
        # 4 Sector MERGEs in build_relationships, 1 Campaign in enrichment_jobs.
        assert sites >= 34, f"expected at least 34 node MERGE sites, found {sites}"

    def test_edges_keep_the_unconditional_marker(self):
        """Edges are EdgeGuard's whenever EdgeGuard MERGEs them — including INVOLVES (2026-10)."""
        src = inspect.getsource(nc.Neo4jClient.link_alert_to_indicator)
        assert "r.edgeguard_managed = true" in src
        assert "ON CREATE SET r.src_uuid = a.uuid, r.trg_uuid = i.uuid, r.created_at = datetime()" in src
        assert "SET r.updated_at = datetime()" in src
        assert "SET r.created_at = datetime()" not in src, "created_at must not be rewritten on redelivery"

    def test_partner_label_merge_behaviour(self):
        """Behavioural: the Cypher a Host MERGE sends has the marker in ON CREATE and nowhere else."""
        client = _client()
        assert client.merge_host({"hostname": "db-01"}) is True
        (query,) = _queries(client)
        assert "ON CREATE SET h.uuid = $host_uuid, h.edgeguard_managed = true" in query
        assert nc._enriched_on_match_clause("h") in query
        plain_set = query.split(nc._enriched_on_match_clause("h"), 1)[1]
        assert "h.edgeguard_managed" not in plain_set

    def test_alert_node_marker_zone_list_and_first_delivery_time(self):
        client = _client()
        ok = client.create_alert_node({"alert_id": "a-1", "zone": "healthcare", "threat": {"indicator": "1.2.3.4"}})
        assert ok is True
        session = client.driver.session.return_value.__enter__.return_value
        query = session.run.call_args.args[0]
        params = session.run.call_args.kwargs
        assert "ON CREATE SET a.uuid = $node_uuid, a.edgeguard_managed = true" in query
        assert nc._enriched_on_match_clause("a") in query
        assert "a.received_at = coalesce(a.received_at, datetime())" in query
        assert params["zone"] == ["healthcare"], "Alert.zone is a list like every other zone property"

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("healthcare", ["healthcare"]),
            (["energy", " finance ", ""], ["energy", "finance"]),
            (None, ["global"]),
            ("  ", ["global"]),
            ([], ["global"]),
            (42, ["global"]),
            ("Healthcare", ["healthcare"]),
            (["Energy", "energy", "ENERGY"], ["energy"]),
            ("us-gov", ["global"]),
            (["finance", "us-gov", "lab"], ["finance"]),
        ],
    )
    def test_zone_normaliser(self, raw, expected):
        """Scalar or list in; lower-cased, de-duplicated, vocabulary-checked list out (Bugbot on #147)."""
        assert nc._normalise_zone_list(raw) == expected

    def test_indicator_from_alert_carries_the_same_validated_zones(self):
        """Bugbot on #147 round 2: the Indicator written for an alert must get the same normalised
        zone list as the Alert node, not the raw payload strings."""
        client = _client()
        client.create_indicator_from_alert(
            "1.2.3.4", "ipv4", "US-Gov", alert_data={"alert_id": "a-1"}, zones=["Energy", "us-gov"]
        )
        session = client.driver.session.return_value.__enter__.return_value
        kwargs = next(c.kwargs for c in session.run.call_args_list if "zone" in c.kwargs)
        assert kwargs["zone"] == ["energy"]
        assert kwargs["tag"] == "energy_ipv4"
        client2 = _client()
        client2.create_indicator_from_alert("1.2.3.4", "ipv4", "us-gov", alert_data={"alert_id": "a-2"})
        session2 = client2.driver.session.return_value.__enter__.return_value
        assert next(c.kwargs for c in session2.run.call_args_list if "zone" in c.kwargs)["zone"] == ["global"]

    def test_unknown_zones_are_logged_and_dropped(self, caplog):
        with caplog.at_level("WARNING", logger="neo4j_client"):
            assert nc._normalise_zone_list(["us-gov", "energy"]) == ["energy"]
        assert any("outside EdgeGuard's vocabulary" in r.message and "us-gov" in r.message for r in caplog.records)

    def test_clear_edgeguard_managed_deletes_created_nodes_only(self):
        src = inspect.getsource(nc.Neo4jClient.clear_edgeguard_managed)
        assert "MATCH (n) WHERE n.edgeguard_managed = true WITH n LIMIT" in src
        assert "edgeguard_enriched = true" in src, "enriched nodes are counted, not deleted"
        delete_stmt = [ln for ln in src.splitlines() if "DETACH DELETE n" in ln]
        assert delete_stmt and all("enriched" not in ln for ln in delete_stmt)


# ---------------------------------------------------------------------------
# Schema: no UNIQUE constraints on partner-owned labels; null-safe CVSS dedup
# ---------------------------------------------------------------------------


class TestSharedSchema:
    def test_six_partner_labels_are_not_constrained_and_old_ones_are_dropped(self):
        src = inspect.getsource(nc.Neo4jClient.create_constraints)
        created = dict(re.findall(r"CREATE CONSTRAINT (\w+) IF NOT EXISTS FOR \(\w+:(\w+)\)", src))
        dropped = set(re.findall(r"DROP CONSTRAINT (\w+) IF EXISTS", src))
        for label in nc.SHARED_LABELS_WITHOUT_UNIQUE_CONSTRAINT:
            assert label not in created.values(), f"{label} must not get a UNIQUE constraint from EdgeGuard"
        for name in (
            "device_key",
            "networkservice_key",
            "softwareversion_key",
            "application_key",
            "role_key",
            "user_key",
        ):
            assert name not in created, name
            assert name in dropped, (
                f"{name} must be dropped so a database created by an older build converges without manual DDL"
            )
        # the keys unique in CRUSOE's model too are still declared
        assert {"IP", "Host", "Subnet", "Alert"} <= set(created.values())

    def test_shared_labels_still_have_deterministic_uuid_keys(self):
        assert nc.SHARED_LABELS_WITHOUT_UNIQUE_CONSTRAINT <= set(node_identity._NATURAL_KEYS)

    def test_cvss_dedup_never_groups_on_null_key_or_partner_nodes(self):
        src = inspect.getsource(nc.Neo4jClient.create_constraints)
        assert "WHERE n.cve_id IS NOT NULL AND n.edgeguard_managed = true\n" in src
        guard = src.index("WHERE n.cve_id IS NOT NULL AND n.edgeguard_managed = true")
        group = src.index("WITH n.cve_id AS cid, collect(n) AS nodes")
        assert guard < group, "the guard must filter before the collect()"
        assert "Move any relationships" not in src, (
            "the previous comment described a relationship move that the statement does not perform"
        )
        assert 'record_destructive_op("cvss_dedup"' in src


# ---------------------------------------------------------------------------
# Readers expose created-or-enriched nodes
# ---------------------------------------------------------------------------


class TestReadersExposeCreatedOrEnriched:
    def test_every_read_filter_is_widened(self):
        for name in _READERS:
            for lineno, line in enumerate((_SRC / name).read_text().splitlines(), 1):
                if "``" in line or line.lstrip().startswith("#"):
                    continue
                for m in re.finditer(r"(\w+)\.edgeguard_managed = true", line):
                    var = m.group(1)
                    assert f"({var}.edgeguard_managed = true OR {var}.edgeguard_enriched = true)" in line, (
                        f"{name}:{lineno} filters on the create marker alone: {line.strip()}"
                    )

    def test_related_entities_lookup_is_scoped_too(self):
        """Bugbot on #147: the seed's neighbours must pass the same ownership filter, or
        ``/search/indicator`` would serialise partner topology EdgeGuard never touched."""
        src = (_SRC / "query_api.py").read_text()
        start = src.index("MATCH (n:Indicator {value: $value})--(related)")
        block = src[start : src.index("RETURN related", start)]
        assert "(related.edgeguard_managed = true OR related.edgeguard_enriched = true)" in block

    def test_writers_do_not_use_the_widened_form_for_ownership(self):
        """The wipe and the status counts are about nodes EdgeGuard created — never widened."""
        for name in ("neo4j_client.py", "baseline_clean.py", "edgeguard.py"):
            text = (_SRC / name).read_text()
            assert "edgeguard_managed = true OR" not in text, name


# ---------------------------------------------------------------------------
# Acceptance script polices the same contract
# ---------------------------------------------------------------------------


class TestAcceptanceScriptContract:
    def test_labels_types_and_marker_query(self):
        text = (Path(__file__).resolve().parent.parent / "scripts" / "verify_fresh_baseline.py").read_text()
        labels = text.split("EDGEGUARD_LABELS = (", 1)[1].split("\n)\n", 1)[0]
        rel_types = text.split("EDGEGUARD_REL_TYPES = (", 1)[1].split("\n)\n", 1)[0]
        assert '"Alert",' in labels and '"Host"' not in labels
        assert '"INVOLVES",' in rel_types
        assert "n.edgeguard_managed IS NULL AND n.edgeguard_enriched IS NULL" in text
