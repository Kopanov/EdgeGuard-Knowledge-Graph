"""CISA KEV revisions on a real Neo4j with APOC (2026-10).

Every KEV run now edits the stored MISP copy of an entry CISA revised, and the incremental sync re-reads
it. Two rules of ``merge_cve`` decide what the CVE node then holds, whatever the order in which the sync
reads the records:

- the KEV record owns ``cisa_exploit_add``, ``cisa_action_due``, ``cisa_required_action`` and
  ``cisa_vulnerability_name``: it sets them, NVD's record only fills them (NVD did not move
  ``lastModified`` when CISA moved the due date of CVE-2022-0995, so NVD's copy keeps the old date);
- ``SOURCED_FROM.raw_data`` of a CVE is replaced on every write from a MISP attribute, so the edge holds
  the source's latest record; the edge of any other label keeps the record that created it, and so does a
  CVE edge against the reduced record of the opt-in STIX import (``run_pipeline``).

What ``CASE`` with ``NULL`` and ``''`` and the ``ON CREATE SET`` / ``SET`` order do cannot be shown with a
mocked session, so this module runs the real writers (the collector's item → MISPWriter's attribute → the
sync's item → ``merge_cve``) with the real catalogue entries of ``tests/fixtures/kev_revisions_2026_10_16.json``.

Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``, writes
only nodes labelled ``EdgeGuardIT`` (every node a writer MERGEs exists beforehand with the label), refuses
any other node.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import neo4j_client  # noqa: E402
from collectors.cisa_collector import CISACollector  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

FIXTURES = json.loads((TESTS / "fixtures" / "kev_revisions_2026_10_16.json").read_text())
SOURCES = ("nvd", "cisa_kev", "alienvault_otx")
KEV_EVENT = {"id": 135, "info": "EdgeGuard-cisa_kev-2026-10-16", "date": "2026-10-16", "Tag": []}
NVD_EVENT = {"id": 120, "info": "EdgeGuard-nvd-2026-10-13", "date": "2026-10-13", "Tag": []}
DUE = "CVE-2022-0995"
FLIP = "CVE-2026-63077"


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def client(raw_driver):
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(f"UNWIND $ids AS sid CREATE (:Source:{LABEL} {{source_id: sid}})", ids=list(SOURCES))
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()
    with raw_driver.session() as session:
        foreign = session.run(f"MATCH (n) WHERE NOT n:{LABEL} RETURN count(n) AS c").single()["c"]
    assert foreign == 0, "the test wrote a node without the test label"


def _cve_node(driver, cve_id: str) -> None:
    """The CVE node the writers MERGE into, created with the test label (a MERGE would create one without)."""
    with driver.session() as session:
        session.run(f"CREATE (:CVE:{LABEL} {{cve_id: $cve, uuid: 'u-' + $cve}})", cve=cve_id)


def _kev_item(day: str, cve_id: str) -> Dict[str, Any]:
    collector = CISACollector.__new__(CISACollector)
    collector.tag = "cisa_kev"
    (entry,) = [e for e in FIXTURES["catalogues"][day]["vulnerabilities"] if e["cveID"] == cve_id]
    return collector._kev_item(entry)


def _nvd_item() -> Dict[str, Any]:
    """NVD's record of CVE-2022-0995 as its MISP copy held it after 2026-10-08: CISA's KEV enrichment
    with the old due date (NVD did not move ``lastModified``), no CVSS (a sub-node would be a node the
    test did not label)."""
    kev = _kev_item("2026-09-16", DUE)
    return {
        "cve_id": DUE,
        "description": "In the Linux kernel, an out-of-bounds write in the watch_queue event notification subsystem.",
        "zone": ["global"],
        "tag": "nvd",
        "published": "2022-03-25T19:15:10.143000+00:00",
        "last_modified": "2026-08-27T04:16:39.223000+00:00",
        "cwe": ["CWE-787"],
        **{k: kev[k] for k in ("cisa_exploit_add", "cisa_action_due", "cisa_required_action")},
        "cisa_vulnerability_name": kev["cisa_vulnerability_name"],
    }


def _attribute(item: Dict[str, Any]) -> Dict[str, Any]:
    """The MISP attribute MISPWriter writes for the item."""
    attribute = MISPWriter.__new__(MISPWriter).create_vulnerability_attribute(item)
    attribute["uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"edgeguard-it:{item['cve_id']}:{item['tag']}"))
    return attribute


def _sync(client, item: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    """One item through MISP and the sync, as production writes it: MISPWriter's attribute, the sync's
    item, the CVE node with its SOURCED_FROM edge."""
    parsed, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(_attribute(item), event)
    assert parsed is not None
    assert client.merge_cve(parsed, source_id=parsed["tag"])
    return parsed


def _node(driver, cve_id: str) -> Dict[str, Any]:
    with driver.session() as session:
        (row,) = list(session.run("MATCH (c:CVE {cve_id: $cve}) RETURN properties(c) AS p", cve=cve_id))
    return row["p"]


def _raw_data(driver, cve_id: str, source_id: str) -> Dict[str, Any]:
    with driver.session() as session:
        (row,) = list(
            session.run(
                "MATCH (:CVE {cve_id: $cve})-[r:SOURCED_FROM]->(:Source {source_id: $src}) RETURN r.raw_data AS raw",
                cve=cve_id,
                src=source_id,
            )
        )
    return json.loads(row["raw"])


@pytest.mark.parametrize("order", ["nvd_then_kev", "kev_then_nvd"])
def test_the_kev_record_owns_its_fields_in_either_order(client, raw_driver, order):
    _cve_node(raw_driver, DUE)
    kev = _kev_item("2026-10-16", DUE)
    steps = [(_nvd_item(), NVD_EVENT), (kev, KEV_EVENT)]
    for item, event in steps if order == "nvd_then_kev" else reversed(steps):
        _sync(client, item, event)
    node = _node(raw_driver, DUE)
    assert node["cisa_action_due"] == "2026-08-29", "NVD's stale due date never replaces the KEV record's"
    assert node["cisa_exploit_add"] == "2026-08-26"
    assert node["cisa_vulnerability_name"] == kev["cisa_vulnerability_name"]
    assert sorted(node["source"]) == ["cisa_kev", "nvd"]


def test_nvd_alone_fills_the_kev_fields(client, raw_driver):
    _cve_node(raw_driver, DUE)
    _sync(client, _nvd_item(), NVD_EVENT)
    assert _node(raw_driver, DUE)["cisa_action_due"] == "2026-09-09"


def test_a_revised_kev_record_replaces_the_node_fields_and_the_edge_record(client, raw_driver):
    _cve_node(raw_driver, FLIP)
    _sync(client, _kev_item("2026-09-16", FLIP), KEV_EVENT)
    assert _raw_data(raw_driver, FLIP, "cisa_kev")["known_ransomware_use"] == "Unknown"
    assert _node(raw_driver, FLIP)["known_ransomware_use"] == "Unknown"
    _sync(client, _kev_item("2026-10-16", FLIP), KEV_EVENT)
    assert _raw_data(raw_driver, FLIP, "cisa_kev")["known_ransomware_use"] == "Known", (
        "the edge holds the latest record"
    )
    assert _node(raw_driver, FLIP)["known_ransomware_use"] == "Known"
    with raw_driver.session() as session:
        edges = session.run(
            "MATCH (:CVE {cve_id: $cve})-[r:SOURCED_FROM]->(:Source {source_id: 'cisa_kev'}) RETURN count(r) AS c",
            cve=FLIP,
        ).single()["c"]
    assert edges == 1


def test_a_stix_import_keeps_the_kev_record_on_the_edge(client, raw_driver):
    """The opt-in STIX flow (``run_pipeline --stix-flow``) merges a reduced record of the KEV event's
    attribute under ``cisa_kev``: the record the sync wrote on the edge stays."""
    from run_pipeline import EdgeGuardPipeline

    _cve_node(raw_driver, DUE)
    kev = _kev_item("2026-10-16", DUE)
    _sync(client, kev, KEV_EVENT)
    sdo = MISPToNeo4jSync(neo4j_client=MagicMock())._attribute_to_stix21(
        _attribute(kev), "00000000-0000-4000-8000-000000000135", ["global"]
    )
    sdo["x_edgeguard_source"] = "cisa_kev"
    pipeline = EdgeGuardPipeline.__new__(EdgeGuardPipeline)
    pipeline.neo4j = client
    assert pipeline.load_stix21_to_neo4j({"type": "bundle", "objects": [sdo]})["vulnerabilities"] == 1
    raw = _raw_data(raw_driver, DUE, "cisa_kev")
    assert (raw["cisa_action_due"], raw["known_ransomware_use"]) == ("2026-08-29", "Unknown")
    assert _node(raw_driver, DUE)["cisa_action_due"] == "2026-08-29"


def test_an_indicator_edge_keeps_the_record_that_created_it(client, raw_driver):
    with raw_driver.session() as session:
        session.run(f"CREATE (:Indicator:{LABEL} {{indicator_type: 'ipv4', value: '203.0.113.7', uuid: 'u-ioc'}})")
    base = {"indicator_type": "ipv4", "value": "203.0.113.7", "tag": "alienvault_otx", "zone": ["global"]}
    assert client.merge_indicator(dict(base, reference="https://otx.example/pulse/1"), source_id="alienvault_otx")
    assert client.merge_indicator(dict(base, reference="https://otx.example/pulse/2"), source_id="alienvault_otx")
    with raw_driver.session() as session:
        (row,) = list(
            session.run(
                "MATCH (:Indicator {value: '203.0.113.7'})-[r:SOURCED_FROM]->(:Source {source_id: 'alienvault_otx'}) "
                "RETURN r.raw_data AS raw"
            )
        )
    assert json.loads(row["raw"])["reference"] == "https://otx.example/pulse/1"
