"""Indicator -> INDICATES -> CVE from the same OTX report, on a real Neo4j with APOC (2026-10-18).

A mocked session shows the Cypher the relationship writer sends, not what it does: that the CVE node
is matched by ``cve_id`` and never created, that the link carries the same-report label, confidence
and provenance lists, and that a second write adds to the lists without repeating them. This module
runs the real chain on one realistic pulse (IPs, a domain, a hostname, a URL, two hashes, two CVEs as
indicators of type CVE and one in ``cve_references``): the OTX collector's items, MISPWriter's
attributes, the sync's items and report-scoped rows, and ``Neo4jClient.create_misp_relationships_batch``;
then it reads the links.

Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``,
writes only nodes labelled ``EdgeGuardIT`` (the Indicator and CVE nodes the links MATCH exist
beforehand with the label), refuses any other node.
"""

from __future__ import annotations

import copy
import os
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)
from test_indicator_cve_report_links import (  # noqa: E402  (the realistic pulses and the chain)
    EVENT,
    PULSE_A,
    PULSE_B,
    PULSE_OTHER,
    PULSE_WITH_CVES,
    _attributes,
    _collect,
)

import neo4j_client  # noqa: E402
from node_identity import canonicalize_merge_key  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

# CVE-2025-0282 (the pulse's cve_references entry) has no node: the link must not create one.
CVES_IN_GRAPH = ("CVE-2024-21887", "CVE-2023-46805", "CVE-2023-4966")


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


def _parsed(*pulses: Dict[str, Any]) -> List[Dict[str, Any]]:
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    items = []
    for attr in _attributes(_collect(*pulses)):
        item, _ = syncer.parse_attribute(attr, EVENT)
        if item:
            items.append(item)
    return items


def _rows(parsed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The sync's Indicator -> CVE rows for *parsed* (one event): the only rows this module writes."""
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    return [
        r
        for r in syncer._build_cross_item_relationships(parsed)
        if r["rel_type"] == "INDICATES" and r["to_type"] == "CVE"
    ]


@pytest.fixture
def client(raw_driver):
    parsed = _parsed(PULSE_WITH_CVES, PULSE_OTHER)
    indicators = [
        canonicalize_merge_key("Indicator", {"indicator_type": i["indicator_type"], "value": i["value"]})
        for i in parsed
        if i.get("indicator_type")
    ]
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(
            f"UNWIND $rows AS row CREATE (:Indicator:{LABEL} {{indicator_type: row.indicator_type, "
            "value: row.value, uuid: 'u-' + row.value, edgeguard_managed: true})",
            rows=indicators,
        )
        session.run(
            f"UNWIND $ids AS id CREATE (:CVE:{LABEL} {{cve_id: id, uuid: 'u-' + id, edgeguard_managed: true}})",
            ids=list(CVES_IN_GRAPH),
        )
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    c.parsed = parsed
    yield c
    c.close()
    with raw_driver.session() as session:
        foreign = session.run(f"MATCH (n) WHERE NOT n:{LABEL} RETURN count(n) AS c").single()["c"]
    assert foreign == 0, "the test wrote a node without the test label"


def _links(driver) -> Dict[tuple, Dict[str, Any]]:
    with driver.session() as session:
        rows = session.run(
            "MATCH (i:Indicator)-[r:INDICATES]->(c:CVE) "
            "RETURN i.value AS value, c.cve_id AS cve, r.match_type AS label, r.confidence_score AS confidence, "
            "r.sources AS sources, r.source_refs AS refs, r.misp_event_ids AS events, "
            "r.edgeguard_managed AS managed, r.imported_at IS NOT NULL AS imported, "
            "r.updated_at IS NOT NULL AS updated, r.src_uuid = i.uuid AS src_uuid, r.trg_uuid = c.uuid AS trg_uuid"
        )
        return {(r["value"], r["cve"]): dict(r) for r in rows}


def test_the_report_links_are_written_with_their_label_and_provenance(client, raw_driver):
    client.create_misp_relationships_batch(_rows(client.parsed), source_id="misp")
    links = _links(raw_driver)
    a_values = {
        "203.0.113.17",
        "198.51.100.44",
        "update-check.example.net",
        "vpn.portal-sync.example.org",
        "https://update-check.example.net/dana-na/auth/lastauthserverused.js",
        "4bc3f6c1d0a5a1c2b7e8f90123456789abcdef0123456789abcdef0123456789",
        "0123456789abcdef0123456789abcdef",  # the MD5 as its node stores it
    }
    expected = {(v, c) for v in a_values for c in ("CVE-2024-21887", "CVE-2023-46805")}
    expected.add(("192.0.2.99", "CVE-2023-4966"))
    assert set(links) == expected
    for (value, _cve), link in links.items():
        pulse = PULSE_B if value == "192.0.2.99" else PULSE_A
        assert link == {
            "value": link["value"],
            "cve": link["cve"],
            "label": "otx_pulse",
            "confidence": 0.6,
            "sources": ["alienvault_otx"],
            "refs": [f"alienvault_otx:{pulse}"],
            "events": [EVENT["id"]],
            "managed": True,
            "imported": True,
            "updated": True,
            "src_uuid": True,
            "trg_uuid": True,
        }


def test_a_cve_without_a_node_gets_no_node_and_no_link(client, raw_driver):
    rows = _rows(client.parsed)
    assert any(r["to_key"]["cve_id"] == "CVE-2025-0282" for r in rows), "the pulse's cve_references CVE has rows"
    client.create_misp_relationships_batch(rows, source_id="misp")
    with raw_driver.session() as session:
        assert session.run("MATCH (c:CVE {cve_id: 'CVE-2025-0282'}) RETURN count(c) AS c").single()["c"] == 0
        assert session.run("MATCH (c:CVE) RETURN count(c) AS c").single()["c"] == len(CVES_IN_GRAPH)


def test_a_second_write_and_a_second_report_add_to_the_lists(client, raw_driver):
    client.create_misp_relationships_batch(_rows(client.parsed), source_id="misp")
    before = _links(raw_driver)
    client.create_misp_relationships_batch(_rows(client.parsed), source_id="misp")
    assert _links(raw_driver) == before, "a second write repeats nothing"

    # A later pulse names the same indicator and CVE (another event): the link names both reports.
    later = copy.deepcopy(PULSE_OTHER)
    later["id"] = "6a2f5e4a9d3c6b7a80912345"
    later["indicators"] = [
        {"id": 31, "indicator": "203.0.113.17", "type": "IPv4"},
        {"id": 32, "indicator": "CVE-2024-21887", "type": "CVE"},
    ]
    later_rows = _rows([dict(i, misp_event_id="4200") for i in _parsed(later)])
    assert len(later_rows) == 1
    client.create_misp_relationships_batch(later_rows, source_id="misp")
    link = _links(raw_driver)[("203.0.113.17", "CVE-2024-21887")]
    assert sorted(link["refs"]) == sorted([f"alienvault_otx:{PULSE_A}", "alienvault_otx:6a2f5e4a9d3c6b7a80912345"])
    assert sorted(link["events"]) == sorted([EVENT["id"], "4200"])
    assert link["label"] == "otx_pulse" and link["confidence"] == 0.6 and link["sources"] == ["alienvault_otx"]


def test_no_exploits_link_is_written(client, raw_driver):
    client.create_misp_relationships_batch(_rows(client.parsed), source_id="misp")
    with raw_driver.session() as session:
        assert session.run("MATCH ()-[r:EXPLOITS]->() RETURN count(r) AS c").single()["c"] == 0


def test_the_stix_bundles_carry_the_links_as_related_to(client, raw_driver):
    """The export queries walk the link on the database (the indicator's CVE stage and the CVE's indicator
    stage), and the bundles parse strictly."""
    import stix2

    from stix_exporter import StixExporter

    client.create_misp_relationships_batch(_rows(client.parsed), source_id="misp")
    exporter = StixExporter(client)
    indicator_bundle = exporter.export_indicator("203.0.113.17")
    cve_bundle = exporter.export_cve("CVE-2024-21887", depth=1)
    for bundle in (indicator_bundle, cve_bundle):
        stix2.parse(bundle)  # strict: allow_custom defaults to False
    by_id = {o["id"]: o for o in indicator_bundle["objects"]}
    links = [o for o in indicator_bundle["objects"] if o["type"] == "relationship"]
    assert sorted(by_id[o["target_ref"]]["name"] for o in links) == ["CVE-2023-46805", "CVE-2024-21887"]
    for link in links:
        assert link["relationship_type"] == "related-to" and link["x_edgeguard_match_type"] == "otx_pulse"
        assert link["x_edgeguard_source_refs"] == [f"alienvault_otx:{PULSE_A}"] and link["confidence"] == 60
    cve_links = [o for o in cve_bundle["objects"] if o["type"] == "relationship"]
    assert len(cve_links) == 7, "the seven indicators of the pulse"
    assert {o["relationship_type"] for o in cve_links} == {"related-to"}
