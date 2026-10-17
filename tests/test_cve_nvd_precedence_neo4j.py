"""NVD's record before any other on a CVE's shared data, on a real Neo4j with APOC (2026-10).

Two rules of ``merge_cve`` decide what a CVE holds when NVD and CISA ICS both describe it, whatever the
order in which the sync reads their records:

- a CVSS sub-node NVD has asserted (``'nvd'`` in ``sources`` of the CVE's ``HAS_CVSS_*`` edge to it) holds
  NVD's payload: another feed's payload only fills a property it lacks, and the CVE's score follows. A
  sub-node only CISA ICS asserted follows CISA ICS's latest record, without the 0.0 impact and
  exploitability sub-scores the collector used to send for a CSAF score block (CSAF has none);
- NVD's record sets the list properties (``cwe``, ``ref_tags``, ``cpe_type``, ``result_impacts``,
  ``reference_urls``, ``affected_products``); any other record only fills a list the node does not have.

An NVD record without a CVSS version CISA ICS also gives takes NVD out of that sub-node's ``sources``, and
CISA ICS's next record sets its values and the CVE's score again. An edge written before ``sources`` existed
counts as asserted by the sub-node's ``tag`` and keeps that feed in ``sources`` when CISA ICS writes it, so
the sub-node stays NVD's on every later write (2026-10-17).

The ``EXISTS`` guard and the ``CASE`` per property cannot be shown with a mocked session, so this module
runs the real writers: the CISA ICS collector's item of a CSAF advisory (``SAMPLE_ADVISORY`` of
``tests/test_cisa_ics_collector.py``) or a real hosted MISP attribute (``tests/test_cvss_real_payloads.json``)
→ MISPWriter's attribute → the sync's item → ``merge_cve``. The statements: ``tests/test_cve_nvd_precedence.py``.

Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``, writes
only nodes labelled ``EdgeGuardIT`` (every node a writer MERGEs exists beforehand with the label), refuses
any other node.
"""

from __future__ import annotations

import copy
import math
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import neo4j_client  # noqa: E402
from collectors.cisa_ics_collector import CISAICSCollector  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

SOURCES = ("nvd", "cisa_ics")
NVD_EVENT = {"id": 120, "info": "EdgeGuard-nvd-2026-10-13", "date": "2026-10-13", "Tag": []}
ICS_EVENT = {"id": 140, "info": "EdgeGuard-cisa_ics-2026-10-16", "date": "2026-10-16", "Tag": []}
CVE = "CVE-2026-32645"  # the first CVE of SAMPLE_ADVISORY (ICSA-26-281-01, CISA: CVSS 3.1 6.0, AV:L)
LISTS = ("cwe", "ref_tags", "cpe_type", "result_impacts", "reference_urls", "affected_products")
CVSS_LABELS = ("CVSSv40", "CVSSv31", "CVSSv30", "CVSSv2")

# NVD's CVSS 3.1 for the CVE, other than CISA's (NVD and the CNA can rate one CVE differently).
NVD_V31 = {
    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "scope": "UNCHANGED",
    "confidentiality_impact": "HIGH",
    "integrity_impact": "HIGH",
    "availability_impact": "HIGH",
    "base_score": 9.8,
    "base_severity": "CRITICAL",
    "impact_score": 5.9,
    "exploitability_score": 3.9,
}


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


def _nodes(driver, cve_id: str) -> None:
    """The CVE node and its CVSS sub-nodes the writers MERGE into, created with the test label (a MERGE
    would create them without), as EdgeGuard creates them (``edgeguard_managed``)."""
    with driver.session() as session:
        session.run(f"CREATE (:CVE:{LABEL} {{cve_id: $cve, uuid: 'u-' + $cve, edgeguard_managed: true}})", cve=cve_id)
        for label in CVSS_LABELS:
            session.run(f"CREATE (:{label}:{LABEL} {{cve_id: $cve, edgeguard_managed: true}})", cve=cve_id)


def _ics_item(score: Optional[Dict[str, Any]] = None, product: Optional[str] = None) -> Dict[str, Any]:
    """The CISA ICS collector's item for ``CVE`` from ``SAMPLE_ADVISORY``; ``score`` revises the advisory's
    ``cvss_v3`` block, ``product`` its product name."""
    from test_cisa_ics_collector import SAMPLE_ADVISORY

    data = copy.deepcopy(SAMPLE_ADVISORY)
    if score:
        data["vulnerabilities"][0]["scores"][0]["cvss_v3"].update(score)
    if product:
        data["product_tree"]["branches"][0]["branches"][0]["name"] = product
    items, _ = CISAICSCollector(misp_writer=MagicMock()).parse_advisory(data, "2026/icsa-26-281-01.json")
    (item,) = [i for i in items if i["cve_id"] == CVE]
    return item


def _nvd_item() -> Dict[str, Any]:
    """NVD's record of ``CVE`` as the NVD collector shapes it."""
    return {
        "cve_id": CVE,
        "description": "Red Lion N-Tron 700 Series devices keep their default factory credentials.",
        "zone": ["global"],
        "tag": "nvd",
        "published": "2026-10-08T15:15:41.000000+00:00",
        "last_modified": "2026-10-14T18:47:12.000000+00:00",
        "cwe": ["CWE-1392"],
        "ref_tags": ["Vendor Advisory"],
        "cpe_type": ["o"],
        "result_impacts": ["HIGH", "HIGH", "HIGH"],
        "reference_urls": ["https://www.redlion.net/support/security-advisories"],
        "affected_products": ["cpe:2.3:o:redlion:n-tron_708m12_firmware:*:*:*:*:*:*:*:*"],
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "attack_vector": "NETWORK",
        "cvss_v31_data": dict(NVD_V31),
    }


def _sync(client, item: Dict[str, Any], event: Dict[str, Any], literal: Optional[str] = None) -> Dict[str, Any]:
    """One item through MISP and the sync, as production writes it: MISPWriter's attribute, the sync's
    item, ``merge_cve``. ``literal`` replaces every ``"__LITERAL__"`` value in the attribute's comment
    verbatim (a JSON number MISPWriter would not write, such as ``1e309``)."""
    attribute = MISPWriter.__new__(MISPWriter).create_vulnerability_attribute(item)
    if literal is not None:
        assert '"__LITERAL__"' in attribute["comment"]
        attribute["comment"] = attribute["comment"].replace('"__LITERAL__"', literal)
    attribute["uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"edgeguard-it:{item['cve_id']}:{item['tag']}"))
    parsed, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(attribute, event)
    assert parsed is not None
    assert client.merge_cve(parsed, source_id=parsed["tag"]) is True
    return parsed


def _merge_real(client, record: Dict[str, Any]) -> None:
    assert client.merge_cve(record, source_id=record["tag"]) is True


def _cve(driver, cve_id: str) -> Dict[str, Any]:
    with driver.session() as session:
        (row,) = list(session.run("MATCH (c:CVE {cve_id: $cve}) RETURN properties(c) AS p", cve=cve_id))
    return row["p"]


def _cvss31(driver, cve_id: str) -> Tuple[Dict[str, Any], List[str], List[str]]:
    """The CVSSv31 sub-node's properties, and ``sources`` / ``misp_event_ids`` of the CVE's edge to it."""
    with driver.session() as session:
        (row,) = list(
            session.run(
                "MATCH (:CVE {cve_id: $cve})-[r:HAS_CVSS_v31]->(n:CVSSv31) "
                "RETURN properties(n) AS p, r.sources AS sources, r.misp_event_ids AS events",
                cve=cve_id,
            )
        )
    return row["p"], sorted(row["sources"]), sorted(row["events"])


@pytest.mark.parametrize("order", ["nvd_then_ics", "ics_then_nvd"])
def test_nvd_payload_holds_the_shared_cvss_sub_node_in_either_order(client, raw_driver, order):
    _nodes(raw_driver, CVE)
    steps = [(_nvd_item(), NVD_EVENT), (_ics_item(), ICS_EVENT)]
    for item, event in steps if order == "nvd_then_ics" else reversed(steps):
        _sync(client, item, event)
    props, sources, events = _cvss31(raw_driver, CVE)
    assert {k: props.get(k) for k in NVD_V31} == NVD_V31, "the sub-node holds NVD's payload"
    assert (sources, events) == (["cisa_ics", "nvd"], ["120", "140"]), "the edge still names both feeds"
    node = _cve(raw_driver, CVE)
    assert (node["cvss_score"], node["severity"], node["cvss_version"], node["attack_vector"]) == (
        9.8,
        "CRITICAL",
        "3.1",
        "NETWORK",
    ), "the CVE's score follows the sub-node"


def _legacy_nvd_sub_node(driver, cve_id: str) -> None:
    """NVD's CVSSv31 sub-node of ``cve_id`` as a graph written before relationship provenance holds it: NVD's
    payload and ``tag`` on the sub-node, both ``HAS_CVSS_v31`` edges without ``sources`` or ``misp_event_ids``."""
    with driver.session() as session:
        session.run(
            f"MATCH (c:CVE:{LABEL} {{cve_id: $cve}}), (n:CVSSv31:{LABEL} {{cve_id: $cve}}) "
            "SET n += $payload, n.tag = 'nvd' "
            "CREATE (c)-[:HAS_CVSS_v31 {edgeguard_managed: true}]->(n), "
            "(n)-[:HAS_CVSS_v31 {edgeguard_managed: true}]->(c)",
            cve=cve_id,
            payload=NVD_V31,
        ).consume()


def _cvss31_edges(driver, cve_id: str) -> List[Tuple[List[str], List[str]]]:
    """``sources`` and ``misp_event_ids`` of both ``HAS_CVSS_v31`` edges (CVE to sub-node and back), sorted."""
    with driver.session() as session:
        rows = session.run(
            "MATCH (:CVE {cve_id: $cve})-[r:HAS_CVSS_v31]-(:CVSSv31) RETURN r.sources AS s, r.misp_event_ids AS e",
            cve=cve_id,
        )
        return [(sorted(row["s"] or []), sorted(row["e"] or [])) for row in rows]


def test_an_edge_without_sources_stays_nvds_through_cisa_ics_writes(client, raw_driver):
    """A sub-node NVD asserted on a graph written before ``sources`` existed (the guard reads the sub-node's
    ``tag``). CISA ICS's first write keeps NVD's payload and leaves NVD in ``sources`` of both edges beside
    CISA ICS; its second write still keeps NVD's payload. Until 2026-10-17 the first write set ``sources`` to
    ``['cisa_ics']`` alone, the tag was no longer read, and the second write replaced NVD's payload."""
    _nodes(raw_driver, CVE)
    _legacy_nvd_sub_node(raw_driver, CVE)
    assert _cvss31_edges(raw_driver, CVE) == [([], [])] * 2, "the edges predate sources"

    _sync(client, _ics_item(), ICS_EVENT)
    props, sources, events = _cvss31(raw_driver, CVE)
    assert {k: props.get(k) for k in NVD_V31} == NVD_V31, "the first CISA ICS write keeps NVD's payload"
    assert (sources, events) == (["cisa_ics", "nvd"], ["140"]), "NVD stays in sources beside CISA ICS"
    assert _cvss31_edges(raw_driver, CVE) == [(["cisa_ics", "nvd"], ["140"])] * 2, "both edges"

    revised = {
        "baseScore": 7.2,
        "baseSeverity": "HIGH",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
    }
    _sync(client, _ics_item(score=revised), ICS_EVENT)
    props, sources, events = _cvss31(raw_driver, CVE)
    assert {k: props.get(k) for k in NVD_V31} == NVD_V31, "the second CISA ICS write still keeps NVD's payload"
    assert (sources, events) == (["cisa_ics", "nvd"], ["140"])
    node = _cve(raw_driver, CVE)
    assert (node["cvss_score"], node["severity"], node["cvss_version"], node["attack_vector"]) == (
        9.8,
        "CRITICAL",
        "3.1",
        "NETWORK",
    ), "the CVE's score follows NVD's sub-node"


def test_a_sub_node_only_cisa_ics_asserted_follows_its_latest_record(client, raw_driver):
    _nodes(raw_driver, CVE)
    _sync(client, _ics_item(), ICS_EVENT)
    props, _, _ = _cvss31(raw_driver, CVE)
    assert (props["base_score"], props["attack_vector"]) == (6.0, "LOCAL")
    assert "impact_score" not in props and "exploitability_score" not in props, "CSAF gives no sub-score"

    revised = {
        "baseScore": 7.2,
        "baseSeverity": "HIGH",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
    }
    _sync(client, _ics_item(score=revised), ICS_EVENT)
    props, sources, _ = _cvss31(raw_driver, CVE)
    assert (props["base_score"], props["base_severity"], props["vector_string"], props["attack_vector"]) == (
        7.2,
        "HIGH",
        revised["vectorString"],
        "NETWORK",
    )
    assert "impact_score" not in props and sources == ["cisa_ics"]
    node = _cve(raw_driver, CVE)
    assert (node["cvss_score"], node["severity"], node["attack_vector"]) == (7.2, "HIGH", "NETWORK")
    # The trade-off of the list rule: ``result_impacts`` (C/I/A of the same CVSS block) only fills, so after
    # the revision it keeps the first record's impacts while the sub-node shows the revised A:H.
    assert props["availability_impact"] == "HIGH" and node["result_impacts"] == ["HIGH", "HIGH", "NONE"]


def test_a_cvss_version_nvd_withdrew_goes_back_to_cisa_ics(client, raw_driver):
    """NVD's record drops the CVSS 3.1 CISA ICS also gives (an NVD re-analysis edits the MISP copy in place):
    NVD leaves ``sources`` and its event leaves ``misp_event_ids`` of the sub-node's edges, and CISA ICS's
    next record sets its values and the CVE's score, as a rebuild from the same records gives. Until 2026-10
    NVD stayed in ``sources``, so CISA ICS only filled the sub-node and NVD's withdrawn 3.1 scored the CVE."""
    _nodes(raw_driver, CVE)
    _sync(client, _nvd_item(), NVD_EVENT)
    _sync(client, _ics_item(), ICS_EVENT)
    withdrawn = _nvd_item()
    del withdrawn["cvss_v31_data"]
    withdrawn["cvss_v40_data"] = {
        "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "base_score": 9.3,
        "base_severity": "CRITICAL",
    }
    _sync(client, withdrawn, NVD_EVENT)
    props, sources, events = _cvss31(raw_driver, CVE)
    assert (sources, events) == (["cisa_ics"], ["140"]), "NVD no longer asserts the sub-node"
    with raw_driver.session() as session:
        both = session.run(
            "MATCH (:CVE {cve_id: $cve})-[r:HAS_CVSS_v31]-(:CVSSv31) RETURN collect([r.sources, r.misp_event_ids]) AS e",
            cve=CVE,
        ).single()["e"]
    assert both == [[["cisa_ics"], ["140"]]] * 2, "both edges (CVE to sub-node and back)"
    assert props["base_score"] == 9.8, "the values stay until CISA ICS's next record"

    _sync(client, _ics_item(), ICS_EVENT)
    props, sources, events = _cvss31(raw_driver, CVE)
    assert (props["base_score"], props["base_severity"], props["attack_vector"], props["vector_string"]) == (
        6.0,
        "MEDIUM",
        "LOCAL",
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
    )
    assert (sources, events) == (["cisa_ics"], ["140"])
    # Known limit: CSAF gives no impact or exploitability sub-score, so NVD's stay on a graph that is kept
    # (a rebuild has none); the CVE's score does not read them.
    assert (props["impact_score"], props["exploitability_score"]) == (5.9, 3.9)
    node = _cve(raw_driver, CVE)
    assert (node["cvss_score"], node["severity"], node["cvss_version"], node["attack_vector"]) == (
        6.0,
        "MEDIUM",
        "3.1",
        "LOCAL",
    ), "the CVE's score follows CISA ICS's 3.1, which outranks NVD's 4.0"


@pytest.mark.parametrize("cve_id", ["CVE-2025-7223", "CVE-2025-14272"])
@pytest.mark.parametrize("order", ["nvd_then_ics", "ics_then_nvd"])
def test_nvd_record_sets_the_lists_and_cisa_ics_fills_the_rest(client, raw_driver, cve_id, order):
    """Real hosted MISP attributes of NVD and CISA ICS. CVE-2025-7223: NVD gives every list, the node shows
    NVD's (not the advisory's URL and product names). CVE-2025-14272: NVD gives no product and no CVSS 3.x
    impacts, so the advisory's product name and impacts fill them."""
    from test_cve_description_source import synced_key

    nvd, ics = synced_key(f"{cve_id}__source:NVD"), synced_key(f"{cve_id}__source:CISA-ICS")
    assert nvd["nvd_record"] is True and ics["tag"] == "cisa_ics"
    _nodes(raw_driver, cve_id)
    for record in (nvd, ics) if order == "nvd_then_ics" else (ics, nvd):
        _merge_real(client, record)
    expected = {prop: (nvd.get(prop) or ics.get(prop) or None) for prop in LISTS}
    if cve_id == "CVE-2025-7223":
        assert all(nvd[prop] for prop in LISTS) and expected == {prop: nvd[prop] for prop in LISTS}
    else:
        assert expected["affected_products"] == ics["affected_products"] and not nvd["affected_products"]
        assert expected["reference_urls"] == nvd["reference_urls"] != ics["reference_urls"]
    node = _cve(raw_driver, cve_id)
    assert {prop: node.get(prop) for prop in LISTS} == expected


def test_a_revised_cisa_ics_record_does_not_change_the_lists_it_filled(client, raw_driver):
    """The trade-off of the rule: CISA ICS only fills, so a revised advisory leaves the lists of a CVE only
    CISA ICS names as the first record set them (today MISPWriter keeps the first CISA ICS record of a CVE
    anyway: a revised advisory reaches neither MISP nor the graph)."""
    _nodes(raw_driver, CVE)
    _sync(client, _ics_item(), ICS_EVENT)
    _sync(client, _ics_item(product="700 Series Gen2"), ICS_EVENT)
    assert _cve(raw_driver, CVE)["affected_products"] == ["Red Lion Controls 700 Series"]


def _non_finite(props: Dict[str, Any]) -> List[str]:
    return sorted(k for k, v in props.items() if isinstance(v, float) and not math.isfinite(v))


@pytest.mark.parametrize("literal", ["Infinity", "-Infinity", "NaN", "1e309"])
def test_a_non_finite_cvss_number_in_nvd_meta_is_not_written(client, raw_driver, literal):
    """``json.loads`` reads these literals of ``NVD_META`` as floats that are not finite (2026-10-17). NVD's
    record with such a base score of CVSS 3.1 and such an impact sub-score of CVSS 3.0: the CVE syncs, the 3.1
    payload counts as absent (no sub-node edge), the 3.0 sub-node is written without the sub-score, the CVE is
    scored from CVSS 3.0, and no property of any node or relationship holds a number that is not finite."""
    _nodes(raw_driver, CVE)
    item = _nvd_item()
    item["cvss_v31_data"] = {**NVD_V31, "base_score": "__LITERAL__"}
    item["cvss_v30_data"] = {
        **NVD_V31,
        "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impact_score": "__LITERAL__",
    }
    parsed = _sync(client, item, NVD_EVENT, literal=literal)
    assert parsed["cvss_v31_data"] is None and "impact_score" not in parsed["cvss_v30_data"]

    with raw_driver.session() as session:
        v31_edges = session.run(
            "MATCH (:CVE {cve_id: $cve})-[r:HAS_CVSS_v31]-() RETURN count(r) AS c", cve=CVE
        ).single()["c"]
        (v30,) = [
            row["p"]
            for row in session.run(
                "MATCH (:CVE {cve_id: $cve})-[:HAS_CVSS_v30]->(n) RETURN properties(n) AS p", cve=CVE
            )
        ]
        nodes = [row["p"] for row in session.run(f"MATCH (n:{LABEL}) RETURN properties(n) AS p")]
        rels = [row["p"] for row in session.run(f"MATCH (:{LABEL})-[r]-(:{LABEL}) RETURN properties(r) AS p")]
    assert v31_edges == 0, "the CVSS 3.1 payload without a finite base score is absent"
    assert "impact_score" not in v30 and (v30["base_score"], v30["exploitability_score"]) == (9.8, 3.9)
    assert [k for p in nodes + rels for k in _non_finite(p)] == [], "a number that is not finite was written"
    node = _cve(raw_driver, CVE)
    assert (node["cvss_score"], node["severity"], node["cvss_version"]) == (9.8, "CRITICAL", "3.0")
