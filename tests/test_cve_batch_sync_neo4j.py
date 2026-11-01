"""The batched CVE write leaves the graph as the per-CVE write does, on a real Neo4j with APOC (2026-11).

Until 2026-11 the sync wrote each CVE with ``Neo4jClient.merge_cve``: five to nine auto-commit statements per
CVE, about 8 NVD CVEs per second in the 7-day baseline of 2026-11-01. ``Neo4jClient.merge_cves_batch`` writes
the CVEs of a sync chunk in batches, one UNWIND statement per write in one transaction, and must leave every
node, property, relationship and provenance list as ``merge_cve`` leaves it, with the same result per CVE (the
sync's ``[MERGE-RETURNED-FALSE]`` accounting).

Each test runs the same input twice on an emptied database: through the per-CVE path (``merge_cves_batch``
replaced by a loop of ``merge_cve``, which is what the sync did before) and through the batched path, and
compares the two graphs property by property. Only the write-time stamps ``first_imported_at``,
``last_updated``, ``imported_at``, ``updated_at`` and ``created_at`` are left out (their presence is
compared). The input is real: NVD CVE API 2.0 records (``tests/fixtures/nvd_cve_batch_2026_11_01.json``)
through ``NVDCollector`` and ``MISPWriter`` to the MISP attribute the sync reads, and CVE attributes of the
hosted EdgeGuard MISP (NVD, CISA KEV, CISA ICS and OTX copies of shared CVEs: ``test_cvss_real_payloads.json``,
``fixtures/nvd_incremental_2026_10_14.json``, ``fixtures/kev_revisions_2026_10_16.json``). The sync runs every
event twice, so the second pass writes onto existing nodes. A CVE node another system created and one whose
``confidence_score`` is not a number exist beforehand.

The statements and the unit-level behaviour: ``tests/test_cve_batch_writes.py``. Same guards as
``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``, refuses a database that
holds a node this suite did not write, and gives every node the sync creates the label ``EdgeGuardIT``.
"""

from __future__ import annotations

import collections
import copy
import json
import logging
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import neo4j_client  # noqa: E402
from collectors.cisa_ics_collector import merge_items_per_cve  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from collectors.nvd_collector import NVDCollector  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

NVD_FIXTURE = json.loads((TESTS / "fixtures" / "nvd_cve_batch_2026_11_01.json").read_text())["nvd"]
HOSTED_ATTRIBUTES = [
    attribute
    for path in (
        TESTS / "test_cvss_real_payloads.json",
        TESTS / "fixtures" / "nvd_incremental_2026_10_14.json",
        TESTS / "fixtures" / "kev_revisions_2026_10_16.json",
    )
    for attribute in json.loads(path.read_text())["misp"].values()
]
NVD_EVENT = {"id": "501", "info": "EdgeGuard-nvd-2026-11-01", "date": "2026-11-01", "Tag": []}
WRITE_TIME = {"first_imported_at", "last_updated", "imported_at", "updated_at", "created_at"}
SYNC_LABELS = ("CVE", "CVSSv40", "CVSSv31", "CVSSv30", "CVSSv2", "Sector")
# Both in the NVD fixture. The first exists beforehand as another system wrote it (no edgeguard_managed), with
# a CVSS 3.1 sub-node whose edge predates ``sources``; the second holds a confidence_score that
# merge_node_with_source cannot compare, so merge_cve refuses its record.
PARTNER_CVE = "CVE-2026-110447"
ODD_CONFIDENCE_CVE = "CVE-2013-0261"
# Also in the NVD fixture: an EdgeGuard node with a higher confidence than the records give and a manual
# retirement, on which merge_node_with_source logs its two AUDIT lines.
RETIRED_CVE = "CVE-2026-76418"


def _one_cve_at_a_time(self, records, *, refresh_raw_data=True, on_fallback=None):
    """The sync's CVE write before 2026-11: ``merge_cve`` per record, its result or the exception it raised.

    Takes ``merge_cves_batch``'s arguments, as the sync calls it with them (``on_fallback`` is never called: no batch
    falls back here). A missing one would make the sync's call raise and send the per-CVE pass down the sync's own
    fallback (``tests/test_cve_batch_writes.py`` checks this without a Neo4j)."""
    results: List[Any] = []
    for data, source_id in records:
        try:
            results.append(self.merge_cve(data, source_id=source_id, refresh_raw_data=refresh_raw_data))
        except Exception as exc:  # noqa: BLE001 - what the sync's loop caught
            results.append(exc)
    return results


# ---------------------------------------------------------------------------------------------- the input
def _nvd_attributes() -> List[Dict[str, Any]]:
    """The fixture's NVD records as the NVD collector makes items of them and MISPWriter writes them to MISP."""
    collector = NVDCollector.__new__(NVDCollector)
    collector.base_url, collector.api_key, collector._api_key_rejected = "http://fake", "k", False
    collector.tag = collector.source_name = "nvd"
    collector.misp_writer, collector.circuit_breaker = MagicMock(), MagicMock()
    with (
        patch.object(NVDCollector, "_fetch_modified_cves", return_value=(list(NVD_FIXTURE.values()), True)),
        patch.object(NVDCollector, "check_service_available", return_value=True),
    ):
        items = collector.collect(limit=None, push_to_misp=False, baseline=False)
    writer = MISPWriter.__new__(MISPWriter)
    attributes = []
    for i, item in enumerate(items):
        attribute = writer.create_vulnerability_attribute(item)
        attribute.update(
            uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, f"edgeguard-it:{item['cve_id']}:nvd")),
            event_id=NVD_EVENT["id"],
            timestamp=str(1793500000 + i),
            category="External analysis",
        )
        attributes.append(attribute)
    return attributes


def _events() -> List[Tuple[Dict[str, Any], List[Dict[str, Any]]]]:
    """The NVD event, then the hosted attributes grouped by their MISP event, in the order they are listed."""
    events: "collections.OrderedDict[str, Tuple[Dict[str, Any], List[Dict[str, Any]]]]" = collections.OrderedDict()
    for attribute in HOSTED_ATTRIBUTES:
        event = attribute.get("_event") or {}
        event_id = str(attribute.get("event_id") or event.get("id"))
        info = event.get("info") or f"EdgeGuard-fixture-{event_id}"
        events.setdefault(event_id, ({"id": event_id, "info": info, "date": "2026-10-14", "Tag": []}, []))[1].append(
            {k: v for k, v in attribute.items() if k != "_event"}
        )
    return [(NVD_EVENT, _nvd_attributes()), *events.values()]


# ---------------------------------------------------------------------------------------------- the database
@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def client(raw_driver):
    _reset(raw_driver)
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()
    with raw_driver.session() as session:
        foreign = session.run(f"MATCH (n) WHERE NOT n:{LABEL} RETURN count(n) AS c").single()["c"]
    assert foreign == 0, "the test wrote a node without the test label"


def _reset(driver) -> None:
    """An empty test graph with the Source nodes and the two CVE nodes that exist before the sync."""
    with driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n").consume()
        session.run(
            f"UNWIND $ids AS sid CREATE (:Source:{LABEL} {{source_id: sid}})", ids=sorted(neo4j_client.SOURCES)
        ).consume()
        session.run(
            f"CREATE (c:CVE:{LABEL} {{cve_id: $cve, description: 'Partner text', cvss_score: 7.5, source: ['crusoe']}})"
            f"-[:HAS_CVSS_v31]->(:CVSSv31:{LABEL} {{cve_id: $cve, base_score: 7.5, tag: 'nvd'}})",
            cve=PARTNER_CVE,
        ).consume()
        session.run(
            f"CREATE (:CVE:{LABEL} {{cve_id: $cve, uuid: 'u-odd', edgeguard_managed: true, confidence_score: 'high'}})",
            cve=ODD_CONFIDENCE_CVE,
        ).consume()
        session.run(
            f"CREATE (:CVE:{LABEL} {{cve_id: $cve, uuid: 'u-retired', edgeguard_managed: true, confidence_score: 0.95, "
            "retired_at: datetime('2026-09-01T00:00:00Z'), retired_by: 'manual'})",
            cve=RETIRED_CVE,
        ).consume()


def _label_new_nodes(driver) -> None:
    """The nodes the sync created get the suite's label, so the cleanup removes them."""
    where = " OR ".join(f"n:{label}" for label in SYNC_LABELS)
    with driver.session() as session:
        session.run(f"MATCH (n) WHERE ({where}) AND NOT n:{LABEL} SET n:{LABEL}").consume()


def _value(value: Any) -> Any:
    if hasattr(value, "iso_format"):
        return value.iso_format()
    if isinstance(value, list):
        return [_value(v) for v in value]
    return value


def _graph(driver) -> Dict[str, List[str]]:
    """Every test node and relationship with all its properties (lists in their stored order), the write-time
    stamps by name only; nodes keyed by labels and natural key, so the two runs can be compared."""

    def props(p: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        return {k: _value(v) for k, v in p.items() if k not in WRITE_TIME}, sorted(k for k in p if k in WRITE_TIME)

    keys: Dict[str, str] = {}
    nodes, rels = [], []
    with driver.session() as session:
        for r in session.run(f"MATCH (n:{LABEL}) RETURN elementId(n) AS id, labels(n) AS labels, properties(n) AS p"):
            labels = sorted(label for label in r["labels"] if label != LABEL)
            values, stamps = props(r["p"])
            key = json.dumps([labels, values.get("source_id") or values.get("cve_id") or values.get("name")])
            keys[r["id"]] = key
            nodes.append(json.dumps([key, values, stamps], sort_keys=True, default=str))
        for r in session.run(
            f"MATCH (a:{LABEL})-[r]->(b:{LABEL}) "
            "RETURN elementId(a) AS a, elementId(b) AS b, type(r) AS t, properties(r) AS p"
        ):
            values, stamps = props(r["p"])
            rels.append(json.dumps([r["t"], keys[r["a"]], keys[r["b"]], values, stamps], sort_keys=True, default=str))
    return {"nodes": sorted(nodes), "rels": sorted(rels)}


def _messages(caplog) -> "collections.Counter[str]":
    """The sync's and the client's own log lines at WARNING and above, and the AUDIT lines."""
    return collections.Counter(
        r.getMessage()
        for r in caplog.records
        if r.name in ("run_misp_to_neo4j", "neo4j_client")
        and (r.levelno >= logging.WARNING or r.getMessage().startswith("AUDIT:"))
    )


def _sync_twice(client, driver, events) -> Tuple[List[Tuple[int, int, int]], Dict[str, Any]]:
    syncer = MISPToNeo4jSync(neo4j_client=client)
    results = []
    for _pass in (1, 2):
        for event, attributes in copy.deepcopy(events):
            results.append(syncer._process_event_attributes(event["id"], dict(event, Attribute=attributes), attributes))
            _label_new_nodes(driver)
    return results, {k: v for k, v in syncer.stats.items() if isinstance(v, (int, float))}


# ---------------------------------------------------------------------------------------------- the tests
def test_the_sync_leaves_the_graph_the_per_cve_write_leaves(client, raw_driver, caplog, monkeypatch):
    events = _events()
    caplog.set_level(logging.INFO)
    with monkeypatch.context() as m:
        m.setattr(neo4j_client.Neo4jClient, "merge_cves_batch", _one_cve_at_a_time)
        per_cve_results, per_cve_stats = _sync_twice(client, raw_driver, events)
    per_cve_graph, per_cve_logs = _graph(raw_driver), _messages(caplog)

    caplog.clear()
    _reset(raw_driver)
    merge_cve = MagicMock(wraps=client.merge_cve)
    batches = MagicMock(wraps=client._write_cve_batch)
    monkeypatch.setattr(client, "merge_cve", merge_cve)
    monkeypatch.setattr(client, "_write_cve_batch", batches)
    batched_results, batched_stats = _sync_twice(client, raw_driver, events)
    batched_graph, batched_logs = _graph(raw_driver), _messages(caplog)

    # The batched path ran: one batch per event (the NVD event's 56 CVEs, each hosted event's CVEs), and
    # merge_cve wrote only the CVE whose node merge_node_with_source refuses (once per pass).
    assert batches.call_count >= 2 * len(events)
    assert [c.args[0].get("cve_id") for c in merge_cve.call_args_list] == [ODD_CONFIDENCE_CVE] * 2
    assert not any("[CVE-BATCH-FALLBACK]" in m for m in batched_logs)

    assert batched_results == per_cve_results
    assert per_cve_stats["cve_batch_fallbacks"] == batched_stats["cve_batch_fallbacks"] == 0, "neither pass fell back"
    assert batched_stats == per_cve_stats
    assert batched_logs == per_cve_logs
    assert batched_graph["nodes"] == per_cve_graph["nodes"]
    assert batched_graph["rels"] == per_cve_graph["rels"]

    # The comparison covers what the sync writes: every CVSS version, the NVD data, the sector links, the
    # provenance, the partner node and the refused one.
    rel_types = collections.Counter(json.loads(r)[0] for r in batched_graph["rels"])
    for rel_type in ("SOURCED_FROM", "AFFECTS", "HAS_CVSS_v40", "HAS_CVSS_v31", "HAS_CVSS_v30", "HAS_CVSS_v2"):
        assert rel_types[rel_type] > 0, rel_type
    cves = {
        json.loads(json.loads(n)[0])[1]: json.loads(n)[1]
        for n in batched_graph["nodes"]
        if json.loads(json.loads(n)[0])[0] == ["CVE"]
    }
    assert len(cves) >= len(NVD_FIXTURE)
    for prop in ("cwe", "affected_products", "ssvc_exploitation", "cisa_exploit_add", "misp_attribute_ids"):
        assert any(prop in node for node in cves.values()), prop
    assert any(node.get("status") == ["rejected"] for node in cves.values())
    assert any(len(node.get("source", [])) > 1 for node in cves.values()), "no CVE with records of two sources"
    assert cves[PARTNER_CVE]["edgeguard_enriched"] is True and "edgeguard_managed" not in cves[PARTNER_CVE]
    assert cves[ODD_CONFIDENCE_CVE] == {"cve_id": ODD_CONFIDENCE_CVE, "uuid": "u-odd", "edgeguard_managed": True,
                                        "confidence_score": "high"}  # fmt: skip
    assert sum(1 for m in batched_logs.elements() if "[MERGE-RETURNED-FALSE]" in m) == 2
    assert (
        sum(
            1
            for m in batched_logs.elements()
            if m.startswith(f"AUDIT: Keeping the higher confidence of CVE(cve_id={RETIRED_CVE})")
        )
        == 2
    )
    assert (
        sum(
            1
            for m in batched_logs.elements()
            if m.startswith(f"AUDIT: Re-imported retired node CVE(cve_id={RETIRED_CVE})")
        )
        == 2
    )


def _hosted_items() -> List[Tuple[Dict[str, Any], str]]:
    """The sync's items of the hosted attributes, in the listed order (several CVEs have a record of two or
    three sources), as ``(item, source)`` records."""
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    records = []
    for attribute in HOSTED_ATTRIBUTES:
        event = attribute.get("_event") or {}
        item, _ = syncer.parse_attribute(
            {k: v for k, v in attribute.items() if k != "_event"},
            {"id": attribute.get("event_id"), "info": event.get("info", ""), "Tag": []},
        )
        if item:
            records.append((item, item.get("tag", "misp")))
    return records


def test_records_of_one_cve_in_one_call_are_written_in_order(client, raw_driver, monkeypatch):
    """Records of one CVE from several sources in one call (CVE-2025-21042: OTX, NVD, CISA KEV): each is
    written after the one before it, as ``merge_cve`` writes them in turn."""
    records = _hosted_items()
    ids = [neo4j_client.resolve_vulnerability_cve_id(item) for item, _ in records]
    assert len(ids) > len(set(ids)), "the input holds no CVE twice"
    records[3][0]["confidence_score"] = 0.8  # a record with a confidence of its own (the others give none)
    # A caller other than the sync may pass a source list and a tag of its own (the sync's are the source id).
    records[0][0].update(source=["alienvault_otx", "nvd"], tag="otx")

    expected = _one_cve_at_a_time(client, copy.deepcopy(records))
    _label_new_nodes(raw_driver)
    expected_graph = _graph(raw_driver)

    _reset(raw_driver)
    batches = MagicMock(wraps=client._write_cve_batch)
    monkeypatch.setattr(client, "_write_cve_batch", batches)
    assert client.merge_cves_batch(copy.deepcopy(records)) == expected
    _label_new_nodes(raw_driver)
    assert _graph(raw_driver) == expected_graph
    assert batches.call_count > 1, "a CVE held twice must start a new batch"


def _parsed(item: Dict[str, Any], event: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """A collector item as the sync reads it back from MISP: MISPWriter's attribute, then the sync's item."""
    attribute = MISPWriter.__new__(MISPWriter).create_vulnerability_attribute(item)
    attribute["uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"edgeguard-it:{item['cve_id']}:{item['tag']}"))
    parsed, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(attribute, event)
    return parsed, parsed["tag"]


def test_revisions_withdrawn_cvss_and_stated_sectors(client, raw_driver):
    """Two calls, each through both paths: NVD records with CVSS sub-nodes, CISA ICS's record of a CVE whose
    advisory states its sectors, and a record whose CVSS 4.0 payload holds no value beside one with a payload;
    then NVD's revisions that withdraw CVSS 3.1 from a CVE only NVD scores (the sub-node is deleted and the
    score moves to CVSS 2) and from the CVE CISA ICS also scores (NVD leaves the edge's ``sources``)."""
    from test_cve_nvd_precedence_neo4j import CVE as ICS_CVE
    from test_cve_nvd_precedence_neo4j import ICS_EVENT, _ics_item, _nvd_item
    from test_cve_nvd_precedence_neo4j import NVD_EVENT as NVD_REVISION_EVENT

    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    nvd = {
        item["cve_id"]: item
        for item in (syncer.parse_attribute(a, NVD_EVENT)[0] for a in _nvd_attributes())
        if item["cve_id"] in ("CVE-2012-3427", "CVE-2023-22793", "CVE-2026-107238")
    }
    scored_by_nvd = (nvd["CVE-2012-3427"], "nvd")  # CVSS 3.1 and 2
    assert scored_by_nvd[0]["cvss_v31_data"] and scored_by_nvd[0]["cvss_v2_data"]
    # The collector merges the advisories of a CVE before the push (``merge_items_per_cve``), which records
    # the advisory behind each sector.
    ics = _parsed(merge_items_per_cve([_ics_item()])[0], ICS_EVENT)
    assert ics[0]["stated_zones"] and ics[0]["stated_refs"], "the advisory states no sector"
    nvd_of_ics_cve = _parsed(_nvd_item(), NVD_REVISION_EVENT)
    assert nvd_of_ics_cve[0]["cve_id"] == ICS_CVE and nvd_of_ics_cve[0]["cvss_v31_data"]
    empty_v40 = (dict(nvd["CVE-2023-22793"], cvss_v40_data={"vector_string": "", "base_score": None}), "nvd")
    with_v40 = (nvd["CVE-2026-107238"], "nvd")
    assert with_v40[0]["cvss_v40_data"]
    first = [scored_by_nvd, nvd_of_ics_cve, ics, empty_v40, with_v40]
    revisions = [
        ({k: v for k, v in record.items() if k != "cvss_v31_data"}, source)
        for record, source in (scored_by_nvd, nvd_of_ics_cve)
    ]

    def run(write) -> Tuple[List[Any], Dict[str, List[str]]]:
        _reset(raw_driver)
        results = write(copy.deepcopy(first)) + write(copy.deepcopy(revisions))
        _label_new_nodes(raw_driver)
        return results, _graph(raw_driver)

    expected = run(lambda records: _one_cve_at_a_time(client, records))
    assert expected[0] == [True] * 7
    assert run(client.merge_cves_batch) == expected

    with raw_driver.session() as session:
        rows = session.run(
            "MATCH (c:CVE) WHERE c.cve_id IN $ids "
            "OPTIONAL MATCH (c)-[r:HAS_CVSS_v31|HAS_CVSS_v40]->(s) "
            "RETURN c.cve_id AS cve, c.cvss_version AS version, type(r) AS rel, r.sources AS sources, "
            "s.created AS created",
            ids=["CVE-2012-3427", ICS_CVE, "CVE-2023-22793", "CVE-2026-107238"],
        )
        found = {(r["cve"], r["rel"]): (r["version"], r["sources"], r["created"]) for r in rows}
        stated = session.run(
            "MATCH (:CVE {cve_id: $cve})-[r:SOURCED_FROM]->(:Source {source_id: 'cisa_ics'}) RETURN r.stated_refs AS s",
            cve=ICS_CVE,
        ).single()["s"]
    assert found[("CVE-2012-3427", None)][0] == "2.0", "NVD's CVSS 3.1 sub-node is gone and CVSS 2 scores the CVE"
    assert found[(ICS_CVE, "HAS_CVSS_v31")][1] == ["cisa_ics"], "NVD left the sub-node CISA ICS also scores"
    assert (
        found[("CVE-2023-22793", "HAS_CVSS_v40")][2] is True and found[("CVE-2026-107238", "HAS_CVSS_v40")][2] is None
    )
    assert stated, "the CISA ICS edge records which advisory stated which sector"


def test_a_cvss_payload_without_a_property_leaves_it(client, raw_driver):
    """One batch writes the CVSS 3.1 sub-node of a CISA ICS record without ``impact_score`` and
    ``exploitability_score`` (the collector sends none for a CSAF score block since 2026-10) and NVD's CVSS 3.1
    of another CVE with both. The ICS sub-node keeps the 0.0 sub-scores the hosted MISP's earlier copy of the
    record wrote, as ``merge_cve`` leaves a property its payload does not have."""
    records = _hosted_items()
    earlier = next(r for r in records if r[1] == "cisa_ics" and r[0].get("cvss_v31_data"))
    nvd = next(
        r for r in records if r[1] == "nvd" and (r[0].get("cvss_v31_data") or {}).get("impact_score") is not None
    )
    assert earlier[0]["cvss_v31_data"]["impact_score"] == 0.0 and earlier[0]["cve_id"] != nvd[0]["cve_id"]
    ics = copy.deepcopy(earlier)
    for sub_score in ("impact_score", "exploitability_score"):
        del ics[0]["cvss_v31_data"][sub_score]

    def run(write) -> Dict[str, List[str]]:
        _reset(raw_driver)
        assert client.merge_cve(copy.deepcopy(earlier[0]), source_id="cisa_ics")
        assert write(copy.deepcopy([ics, nvd])) == [True, True]
        _label_new_nodes(raw_driver)
        return _graph(raw_driver)

    expected = run(lambda records: _one_cve_at_a_time(client, records))
    assert run(client.merge_cves_batch) == expected
    with raw_driver.session() as session:
        kept = session.run(
            "MATCH (:CVE {cve_id: $cve})-[:HAS_CVSS_v31]->(s:CVSSv31) RETURN s.impact_score AS v", cve=ics[0]["cve_id"]
        ).single()["v"]
    assert kept == 0.0


def test_a_failed_batch_is_written_one_cve_at_a_time(client, raw_driver, caplog):
    """A record whose ``SOURCED_FROM`` write fails on the server (a source date Neo4j cannot read): the batch's
    transaction writes nothing and ``merge_cve`` writes each record, so the failing CVE keeps its node without
    the edge and counts as False, as before, and every other CVE is written."""
    records = _hosted_items()[:6]
    records[2][0]["first_seen_at_source"] = "not a date"

    expected = _one_cve_at_a_time(client, copy.deepcopy(records))
    _label_new_nodes(raw_driver)
    expected_graph = _graph(raw_driver)
    assert expected[2] is False and expected.count(True) == 5

    _reset(raw_driver)
    caplog.set_level(logging.WARNING, logger="neo4j_client")
    assert client.merge_cves_batch(copy.deepcopy(records)) == expected
    _label_new_nodes(raw_driver)
    assert _graph(raw_driver) == expected_graph
    (line,) = [r.getMessage() for r in caplog.records if "[CVE-BATCH-FALLBACK]" in r.getMessage()]
    assert "nothing of it was written" in line
