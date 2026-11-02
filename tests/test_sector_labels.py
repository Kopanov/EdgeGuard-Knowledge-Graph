"""The sector labels' shared definitions (2026-11-02, ``src/sector_labels.py``).

The sync (``apply_sector_labels``), the campaign builder and the acceptance check 10n name the same labels
for the same node kinds. Their Cypher runs on Neo4j in ``tests/test_campaign_sector_labels_neo4j.py``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import config
import neo4j_client
import sector_labels


def test_sector_labels_are_the_capitalised_sector_zones():
    assert sector_labels.SECTOR_LABELS == tuple(sorted(z.capitalize() for z in config.VALID_ZONES if z != "global"))


def test_apply_sector_labels_labels_the_shared_node_kinds():
    statements = []

    def run(query, *args, **kwargs):
        statements.append(query)
        result = MagicMock()
        result.single.return_value = {"labeled": 1}
        return result

    session = MagicMock()
    session.run = run
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *a: False
    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = MagicMock()
    client.driver.session.return_value = session
    assert client.apply_sector_labels() == len(sector_labels.SECTOR_LABELLED_NODE_LABELS)
    assert [q.split("MATCH (n:", 1)[1].split(")", 1)[0] for q in statements] == list(
        sector_labels.SECTOR_LABELLED_NODE_LABELS
    )
    assert "Campaign" in sector_labels.SECTOR_LABELLED_NODE_LABELS


def test_campaign_statement_removes_stale_labels_only_from_edgeguard_campaigns():
    statement = sector_labels.CAMPAIGN_SECTOR_LABELS_CYPHER
    assert "CASE WHEN c.edgeguard_managed = true" in statement
    assert "apoc.create.removeLabels(c, stale)" in statement and "apoc.create.addLabels(kept, missing)" in statement
    assert "'global'" in sector_labels.wanted_labels("c")


def test_check_parameters_and_verdict():
    assert sector_labels.check_params() == {
        "node_labels": list(sector_labels.SECTOR_LABELLED_NODE_LABELS),
        "sector_labels": ["Energy", "Finance", "Healthcare"],
    }
    assert sector_labels.check_verdict({"nodes": 0, "missing_label": 0, "stray_label": 0}) is None
    assert sector_labels.check_verdict({"nodes": 5, "missing_label": 0, "stray_label": 0}) is True
    assert sector_labels.check_verdict({"nodes": 5, "missing_label": 1, "stray_label": 0}) is False
    assert sector_labels.check_verdict({"nodes": 5, "missing_label": 0, "stray_label": 2}) is False
