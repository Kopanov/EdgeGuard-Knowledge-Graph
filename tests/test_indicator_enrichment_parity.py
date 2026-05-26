#!/usr/bin/env python3
"""
Regression test: ``merge_indicators_batch`` must promote the SAME enrichment
fields as the single-item ``merge_indicator``, so they land as queryable node
properties — not only inside the SOURCED_FROM edge's ``raw_data`` JSON.

Bug this guards against (found 2026-05 against the edgeguard.org baseline):
the bulk/batch path (used by the baseline + scheduled MISP→Neo4j sync) wrote
only a subset of enrichment fields and silently dropped the rest. As a result:

  * ``Indicator.attack_ids`` was 0/146,185  → build_relationships step 8
    (USES_TECHNIQUE, matches ``i.attack_ids`` → Technique.mitre_id) could never
    create an edge.
  * ``Indicator.malware_family`` was 0      → build_relationships step 9
    (INDICATES via malware-family name match) could never fire for
    batch-ingested indicators.

The single-item ``merge_indicator`` (neo4j_client.py ~L2329) promoted these all
along, so the two ingest paths had drifted. This test pins parity WITHOUT a live
Neo4j: it captures the Cypher ``merge_indicators_batch`` generates (by
monkeypatching the batch executor) and asserts every promoted field is SET on
the node.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import neo4j_client as nc  # noqa: E402
from neo4j_client import Neo4jClient  # noqa: E402

# Enrichment fields the single-item merge_indicator promotes (neo4j_client.py
# ~L2329). The batch path must keep parity with this list.
_PROMOTED_FIELDS = [
    "attack_ids",
    "targeted_countries",
    "malware_family",
    "malware_malpedia",
    "reference",
    "reporter",
    "domain",
    "hostnames",
]


def test_merge_indicators_batch_promotes_enrichment_fields(monkeypatch):
    """The generated batch Cypher must SET every promoted enrichment field."""
    import config

    # Guard against MagicMock pollution from other test modules (e.g. the
    # test_graphql_api stubs that replace config / neo4j_client in sys.modules).
    if not hasattr(config, "NEO4J_URI") or not isinstance(config.NEO4J_URI, str):
        pytest.skip("config stubbed by another test module — run this test in isolation")

    captured = {}

    def _fake_exec(driver, query, **kwargs):
        captured["query"] = query
        return True, len(kwargs.get("query_kwargs", {}).get("batch", []))

    monkeypatch.setattr(nc, "_execute_batch_with_retry", _fake_exec)

    client = Neo4jClient()
    client.driver = object()  # truthy sentinel so the method does real work

    item = {
        "indicator_type": "domain",
        "value": "enrichment-parity.test",
        "zone": ["global"],
        "source": ["alienvault_otx"],
        "attack_ids": ["T1059", "T1071"],
        "targeted_countries": ["US"],
        "malware_family": "emotet",
        "malware_malpedia": "win.emotet",
        "reference": "https://example.test/ref",
        "reporter": "tester",
        "domain": "enrichment-parity.test",
        "hostnames": ["host.enrichment-parity.test"],
    }
    client.merge_indicators_batch([item], source_id="alienvault_otx")

    query = captured.get("query", "")
    if not isinstance(query, str) or not query:
        pytest.skip("neo4j_client appears stubbed (MagicMock pollution) — run in isolation")
    # Sanity: we captured the Indicator MERGE (not some other query).
    assert "MERGE (n:Indicator" in query

    missing = [f for f in _PROMOTED_FIELDS if f"n.{f} =" not in query]
    assert not missing, (
        "merge_indicators_batch Cypher does not promote these enrichment fields "
        f"to node properties: {missing}. The batch path has drifted from "
        "single-item merge_indicator parity (see this module's docstring)."
    )
