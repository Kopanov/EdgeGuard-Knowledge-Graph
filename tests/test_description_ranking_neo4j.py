"""The source ranking of node descriptions on a real Neo4j (2026-10-16).

What Cypher decides cannot be shown with a mocked session: ``NULL`` and ``''`` in the stored-rank ``CASE``,
string order between two unregistered sources, a ``WITH`` that decides once before the ``SET`` of both
properties, and the ``reduce`` an alias or twin merge uses to pick the description it keeps. This module
holds the Cypher of ``description_ranking`` to its Python mirror, which the path tests use
(``tests/test_description_ranking.py``), on every stored state against every incoming source, and runs the
write paths with the real records of ``tests/test_cve_description_source.py`` and
``tests/test_entity_description_source.py`` in every order: ``merge_cve``, ``merge_vulnerabilities_batch``,
``merge_resilmesh_cve``, ``merge_malware`` and ``merge_technique``.

Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``, writes
only nodes labelled ``EdgeGuardIT``, refuses any other node.
"""

from __future__ import annotations

import itertools
import os
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import description_ranking as dr  # noqa: E402
import neo4j_client  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

CVE, ENTITY = dr.CVE_DESCRIPTIONS, dr.ENTITY_DESCRIPTIONS
SOURCES = ("nvd", "cisa_kev", "cisa_ics", "mitre_attck", "coreideas", "alienvault_otx", "misp", "stix_import")


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


def _reset(raw_driver, label: str, key: str, value: str, **props) -> None:
    """The node the merges write to, created with the test label (a MERGE would create one without)."""
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{label}:{LABEL} {{{key}: $value}}) DETACH DELETE n", value=value)
        session.run(f"CREATE (n:{label}:{LABEL} {{{key}: $value}}) SET n += $props", value=value, props=props)


def _described(raw_driver, label: str, key: str, value: str) -> dict:
    with raw_driver.session() as session:
        rows = list(session.run(f"MATCH (n:{label} {{{key}: $value}}) RETURN properties(n) AS p", value=value))
    assert len(rows) == 1, f"one {label} node expected, found {len(rows)}"
    return {k: v for k, v in rows[0]["p"].items() if k in ("description", "description_source")}


# ================================================================ the Cypher against its mirror
STORED_STATES = [
    {},
    {"description": ""},
    {"description": "", "description_source": "nvd"},
    {"description": "legacy text"},
    {"description": "partner text", "description_source": "resilmesh"},
    {"description": "bundle text", "description_source": "stix_import"},
] + [{"description": f"{sid} text", "description_source": sid} for sid in sorted(CVE.ranks)]
INCOMING = sorted(CVE.ranks) + ["resilmesh", "stix_import", "zz_unregistered"]


@pytest.mark.parametrize("ranking", [CVE, ENTITY], ids=["cve", "entity"])
def test_the_ranked_set_decides_as_its_python_mirror(client, raw_driver, ranking):
    rows, expected = [], {}
    for i, (stored, incoming) in enumerate(itertools.product(STORED_STATES, INCOMING)):
        record = ranking.record(f"{incoming} new text", incoming)
        rows.append(
            {"id": f"case-{i}", "stored": stored, "text": record.text, "source": record.source, "rank": record.rank}
        )
        node = dict(stored)
        if ranking.replaces(stored.get("description"), stored.get("description_source"), record):
            node.update(description=record.text, description_source=record.source)
        expected[f"case-{i}"] = node
    # A row without text never changes the node (the batch path's rows without a description).
    kept = {"description": "kept", "description_source": "misp"}
    rows.append({"id": "no-text", "stored": kept, "text": None, "source": None, "rank": None})
    expected["no-text"] = kept
    with raw_driver.session() as session:
        session.run(
            f"UNWIND $rows AS row CREATE (n:RankCase:{LABEL} {{case_id: row.id}}) SET n += row.stored", rows=rows
        )
        session.run(
            f"UNWIND $rows AS row MATCH (n:RankCase:{LABEL} {{case_id: row.id}})\n"
            + ranking.set_cypher("n", "n, row", "row.text", "row.source", "row.rank"),
            rows=rows,
        )
        got = {
            r["id"]: {k: v for k, v in r["p"].items() if k in ("description", "description_source")}
            for r in session.run(f"MATCH (n:RankCase:{LABEL}) RETURN n.case_id AS id, properties(n) AS p")
        }
    mismatches = {case: (got[case], expected[case]) for case in expected if got[case] != expected[case]}
    assert not mismatches, mismatches


def test_the_merge_choice_decides_as_its_python_mirror(client, raw_driver):
    canonical = {"name": "clop", "description": "MISP text", "description_source": "misp"}
    dups = [
        {"name": "cl0p", "description": "Core Ideas text", "description_source": "coreideas"},
        {"name": "clop gang", "description": "other Core Ideas text", "description_source": "coreideas"},
        {"name": "clop team", "description": "bundle text", "description_source": "stix_import"},
        {"name": "clop crew"},
        {"name": "clop ransomware group", "description": "legacy text"},
    ]
    with raw_driver.session() as session:
        session.run(f"UNWIND $nodes AS p CREATE (n:Pick:{LABEL}) SET n += p", nodes=[canonical] + dups)
        # The duplicates in the order given, so every permutation reaches the reduce in its own order.
        query = (
            f"MATCH (c:Pick:{LABEL} {{name: $first}}) "
            "UNWIND range(0, size($names) - 1) AS i "
            f"MATCH (x:Pick:{LABEL} {{name: $names[i]}}) "
            "WITH c, i, x ORDER BY i "
            "WITH c, collect(x) AS dups "
            f"RETURN {ENTITY.best_of_cypher('c', 'dups')}.name AS name"
        )
        for size in range(1, len(dups) + 1):
            for subset in itertools.permutations(dups, size):
                for first in (canonical, subset[0]):
                    others = [d for d in ((canonical,) + subset) if d is not first]
                    names = [d["name"] for d in others]
                    got = session.run(query, first=first["name"], names=names).single()["name"]
                    assert got == ENTITY.best_of(first, others)["name"], (first["name"], names)


# ================================================================ the write paths, every order
def _cve(key: str) -> dict:
    """A real hosted MISP attribute read by the sync, without CVSS payloads (CVSS sub-nodes would be
    nodes without the test label)."""
    from test_cve_description_source import synced_key

    item = synced_key(key)
    item.update(cvss_v40_data=None, cvss_v31_data=None, cvss_v30_data=None, cvss_v2_data=None)
    return item


def _cve_without_nvd() -> dict:
    from test_cve_description_source import _without_nvd

    records = _without_nvd("kev", "ics", "otx")
    for item in records.values():
        item.update(cvss_v40_data=None, cvss_v31_data=None, cvss_v30_data=None, cvss_v2_data=None)
    return records


def test_merge_cve_without_nvd_keeps_the_kev_text_in_every_order(client, raw_driver):
    records = _cve_without_nvd()
    for order in itertools.permutations(records):
        _reset(raw_driver, "CVE", "cve_id", "CVE-2025-21042")
        for name in order:
            assert client.merge_cve(records[name], records[name]["tag"])
        node = _described(raw_driver, "CVE", "cve_id", "CVE-2025-21042")
        assert node == {"description": records["kev"]["description"], "description_source": "cisa_kev"}, order


def test_merge_cve_with_nvd_keeps_nvds_text_in_every_order_and_a_partner_write_changes_nothing(client, raw_driver):
    records = dict(_cve_without_nvd(), nvd=_cve("CVE-2025-21042__source:NVD"))
    expected = {"description": records["nvd"]["description"], "description_source": "nvd"}
    for order in itertools.permutations(("nvd", "kev", "ics")):
        _reset(raw_driver, "CVE", "cve_id", "CVE-2025-21042")
        for name in order:
            assert client.merge_cve(records[name], records[name]["tag"])
        assert _described(raw_driver, "CVE", "cve_id", "CVE-2025-21042") == expected, order
    assert client.merge_resilmesh_cve({"cve_id": "CVE-2025-21042", "description": "partner text"})
    assert client.merge_resilmesh_cve({"cve_id": "CVE-2025-21042"})
    assert _described(raw_driver, "CVE", "cve_id", "CVE-2025-21042") == expected


def test_a_node_written_before_takes_nvds_text_only(client, raw_driver):
    records = dict(_cve_without_nvd(), nvd=_cve("CVE-2025-21042__source:NVD"))
    _reset(raw_driver, "CVE", "cve_id", "CVE-2025-21042", description="legacy text")
    for name in ("kev", "ics", "otx"):
        assert client.merge_cve(records[name], records[name]["tag"])
    assert client.merge_resilmesh_cve({"cve_id": "CVE-2025-21042", "description": "partner text"})
    assert _described(raw_driver, "CVE", "cve_id", "CVE-2025-21042") == {"description": "legacy text"}
    assert client.merge_cve(records["nvd"], "nvd")
    node = _described(raw_driver, "CVE", "cve_id", "CVE-2025-21042")
    assert node == {"description": records["nvd"]["description"], "description_source": "nvd"}


def test_a_partner_write_fills_an_empty_cve_and_yields_to_a_feed(client, raw_driver):
    _reset(raw_driver, "CVE", "cve_id", "CVE-2015-5477")
    assert client.merge_resilmesh_cve({"cve_id": "CVE-2015-5477", "description": "partner text"})
    node = _described(raw_driver, "CVE", "cve_id", "CVE-2015-5477")
    assert node == {"description": "partner text", "description_source": "resilmesh"}
    kev = _cve("CVE-2015-5477__source:CISA-KEV")
    assert client.merge_cve(kev, "cisa_kev")
    assert _described(raw_driver, "CVE", "cve_id", "CVE-2015-5477") == {
        "description": kev["description"],
        "description_source": "cisa_kev",
    }


@pytest.mark.parametrize("first", ["nvd", "cisa_kev"])
def test_the_batch_path_keeps_nvds_text_in_both_orders(client, raw_driver, first):
    _reset(raw_driver, "Vulnerability", "cve_id", "CVE-2025-21042")
    nvd, kev = _cve("CVE-2025-21042__source:NVD"), _cve("CVE-2025-21042__source:CISA-KEV")
    for item in (nvd, kev) if first == "nvd" else (kev, nvd):
        assert client.merge_vulnerabilities_batch([dict(item)], source_id=item["tag"]) == (1, 0)
    node = _described(raw_driver, "Vulnerability", "cve_id", "CVE-2025-21042")
    assert node == {"description": nvd["description"], "description_source": "nvd"}


def test_merge_malware_keeps_the_highest_ranked_text_in_every_order(client, raw_driver):
    from test_entity_description_source import mitre_items, synced, written

    records = {
        "mitre_attck": synced(written("malware", mitre_items()["malware"])),
        "coreideas": dict(mitre_items()["malware"], description="Core Ideas profile"),
        "misp": dict(mitre_items()["malware"], description="A MISP-native attribute's text"),
        "stix_import": dict(mitre_items()["malware"], description="An external bundle's text"),
    }
    for subset_size in (2, 3, 4):
        for order in itertools.permutations(records, subset_size):
            _reset(raw_driver, "Malware", "name", "cobalt strike")
            for source in order:
                assert client.merge_malware(records[source], source_id=source)
            best = max(order, key=ENTITY.rank)
            node = _described(raw_driver, "Malware", "name", "cobalt strike")
            assert node == {"description": records[best]["description"], "description_source": best}, order


@pytest.mark.parametrize("first", ["mitre_attck", "misp"])
def test_a_technique_keeps_attacks_text_in_both_orders(client, raw_driver, first):
    # Until 2026-10-16 any record set a Technique's description: the one merged last won.
    from test_entity_description_source import mitre_items, synced, written

    mitre = synced(written("technique", mitre_items()["technique"]))
    native = dict(mitre_items()["technique"], description="A MISP-native attribute's text")
    _reset(raw_driver, "Technique", "mitre_id", mitre["mitre_id"].upper())
    records = [(mitre, "mitre_attck"), (native, "misp")]
    for item, source in records if first == "mitre_attck" else records[::-1]:
        assert client.merge_technique(item, source_id=source)
    node = _described(raw_driver, "Technique", "mitre_id", mitre["mitre_id"].upper())
    assert node == {"description": mitre["description"], "description_source": "mitre_attck"}
