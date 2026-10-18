"""Sector evidence on a real Neo4j with APOC (2026-10-16).

``build_relationships`` steps 7a-7d link a node to the Sector of each of its zones. Until 2026-10-16 every
such link named every feed of the node and was reset to ``zone_classification`` at 0.5 on every run: on the
graph of 2026-10-16, 2,639 of 6,506 AFFECTS links named a feed that never gave their sector (an NVD energy
guess on a CVE whose CISA advisory named no tracked sector carried ``cisa_ics``), and the 4,126 sectors
CISA's ICS advisories state looked like keyword guesses. Now each link names only the feeds whose
``SOURCED_FROM`` zones give its sector, and its label and confidence follow the table of
``sector_evidence``. What the per-sector selection, the ``reduce`` over the stating feeds, the map lookups
by parameter and APOC's ``combine`` do cannot be shown with a mocked session, so this module runs the real
writers (MISPWriter attribute → sync item → ``merge_cve`` and the sync's relationship rows) and the
statements of steps 7b / 7c through ``_safe_run_batched`` and ``apoc.periodic.iterate``, as production runs
them, and reads the links afterwards.

Since 2026-10-18 an OTX report's own industries are a statement too (``otx_industries``, 0.6, TARGETS only):
the OTX indicator, family and adversary go through the same writers and steps 7a / 7c / 7d, a statement and
an inference of one link keep the statement whichever is written last, a full sync relabels a link written
before, AFFECTS from an OTX record stays an inference, and the alias merge keeps the statement.

Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``, writes
only nodes labelled ``EdgeGuardIT`` (every node a writer MERGEs exists beforehand with the label), refuses
any other node.
"""

from __future__ import annotations

import copy
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)
from test_cisa_ics_collector import SAMPLE_ADVISORY  # noqa: E402  (the real CSAF 2.0 shape)
from test_otx_industries_sector_label import (  # noqa: E402
    PULSE_REF,
    SECOND_REF,
    WRITER,
    _attribute,
    _kind,
    _pulse,
    _second_pulse,
)
from test_otx_industries_sector_label import otx_items as _otx_items  # noqa: E402

import build_relationships  # noqa: E402
import collectors.cisa_ics_collector as ics  # noqa: E402
import enrichment_jobs  # noqa: E402
import neo4j_client  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

SOURCES = ("cisa_ics", "nvd", "cisa_kev", "alienvault_otx", "mitre_attck", "misp", "threatfox")
SECTORS = ("energy", "finance", "healthcare")
CISA_EVENT = {"id": 161, "info": "EdgeGuard-cisa_ics-2026-10-16", "date": "2026-10-16", "Tag": []}
NVD_EVENT = {"id": 120, "info": "EdgeGuard-nvd-2026-10-16", "date": "2026-10-16", "Tag": []}


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def client(raw_driver):
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(f"UNWIND $ids AS sid CREATE (:Source:{LABEL} {{source_id: sid}})", ids=list(SOURCES))
        session.run(
            f"UNWIND $sectors AS s CREATE (:Sector:{LABEL} {{name: s, uuid: 'u-' + s, edgeguard_managed: true}})",
            sectors=list(SECTORS),
        )
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()
    with raw_driver.session() as session:
        foreign = session.run(f"MATCH (n) WHERE NOT n:{LABEL} RETURN count(n) AS c").single()["c"]
    assert foreign == 0, "the test wrote a node without the test label"


def _rows(driver, query: str, **params) -> List[Dict[str, Any]]:
    with driver.session() as session:
        return [dict(r) for r in session.run(query, **params)]


def _cve_node(driver, cve_id: str) -> None:
    """The CVE node the writers MERGE into, created with the test label (a MERGE would create one without)."""
    with driver.session() as session:
        session.run(f"CREATE (:CVE:{LABEL} {{cve_id: $cve, uuid: 'u-' + $cve}})", cve=cve_id)


def _advisory_item(cve_id: str, zone: List[str], advisory_id: str) -> Dict[str, Any]:
    """The collector's (advisory, CVE) item for ``cve_id`` (from the real CSAF sample), without its CVSS
    payload: a CVSS sub-node would be a node the test did not label."""
    collector = ics.CISAICSCollector(misp_writer=MagicMock())
    items, _ = collector.parse_advisory(copy.deepcopy(SAMPLE_ADVISORY), "2026/icsa-26-281-01.json")
    item = dict(items[0], cve_id=cve_id, zone=zone, advisory_id=advisory_id, advisory_ids=[advisory_id])
    for key in ("cvss_v31_data", "cvss_v30_data"):
        item[key] = None
    return item


def _cisa_item(cve_id: str, zone: List[str], advisory_id: str = "ICSA-26-281-01") -> Dict[str, Any]:
    """The collector's item for a CVE one advisory names."""
    return ics.merge_items_per_cve([_advisory_item(cve_id, zone, advisory_id)])[0]


def _nvd_item(cve_id: str, zone: List[str]) -> Dict[str, Any]:
    return {
        "cve_id": cve_id,
        "description": "Default credentials in an energy management controller.",
        "zone": zone,
        "tag": "nvd",
        "published": "2026-10-08T00:00:00+00:00",
        "cwe": ["CWE-798"],
    }


def _sync(client, item: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    """One collector item through MISP and the sync, as production writes it: MISPWriter's attribute, the
    sync's item, the CVE node with its SOURCED_FROM edge, and the sync's AFFECTS rows."""
    attribute = MISPWriter.__new__(MISPWriter).create_vulnerability_attribute(item)
    attribute["uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"edgeguard-it:{item['cve_id']}:{item['tag']}"))
    syncer = MISPToNeo4jSync(neo4j_client=client)
    parsed, _ = syncer.parse_attribute(attribute, event)
    assert parsed is not None
    assert client.merge_cve(parsed, source_id=parsed["tag"])
    rows = [r for r in syncer._build_cross_item_relationships([parsed]) if r["rel_type"] == "AFFECTS"]
    if rows:
        client.create_misp_relationships_batch(rows, source_id=parsed["tag"])
    return parsed


def _step(client, statements, stat_key: str) -> Dict[str, Any]:
    stats: Dict[str, Any] = {}
    ok = build_relationships._safe_run_batched(
        client,
        stat_key,
        statements.outer,
        statements.inner,
        stats,
        stat_key,
        skip_query=statements.skip,
        params=statements.params,
    )
    assert ok, f"{stat_key} failed"
    return stats


def _q7b(client) -> None:
    _step(client, build_relationships._Q7B_STATEMENTS, "vuln_affects_sector")


def _skipped(client, statements) -> int:
    rows = client.run(statements.skip, statements.params)
    return rows[0]["c"]


def _links(driver, cve_id: str, rel: str = "AFFECTS") -> Dict[str, Dict[str, Any]]:
    rows = _rows(
        driver,
        f"MATCH (:CVE {{cve_id: $cve}})-[r:{rel}]->(s:Sector) "
        "RETURN s.name AS sector, r.match_type AS label, r.confidence_score AS confidence, "
        "apoc.coll.sort(r.sources) AS sources, apoc.coll.sort(coalesce(r.source_refs, [])) AS refs, "
        "apoc.coll.sort(coalesce(r.misp_event_ids, [])) AS events",
        cve=cve_id,
    )
    return {r.pop("sector"): r for r in rows}


def _stated_refs(driver, cve_id: str) -> Optional[List[str]]:
    (row,) = _rows(
        driver,
        "MATCH (:CVE {cve_id: $cve})-[sf:SOURCED_FROM]->(:Source {source_id: 'cisa_ics'}) "
        "RETURN sf.stated_refs AS refs",
        cve=cve_id,
    )
    return row["refs"]


def _sourced_from(driver, cve_id: str) -> Dict[str, Dict[str, Optional[List[str]]]]:
    rows = _rows(
        driver,
        "MATCH (:CVE {cve_id: $cve})-[sf:SOURCED_FROM]->(s:Source) "
        "RETURN s.source_id AS source, sf.zones AS zones, sf.stated_zones AS stated",
        cve=cve_id,
    )
    return {r["source"]: {"zones": r["zones"], "stated": r["stated"]} for r in rows}


# ================================================================ the writers and step 7b
class TestCisaStatementsAndInferences:
    def test_a_sector_only_cisa_states_is_advisory_sector(self, client, raw_driver):
        _cve_node(raw_driver, "CVE-2026-32645")
        _sync(client, _cisa_item("CVE-2026-32645", ["energy"]), CISA_EVENT)
        assert _sourced_from(raw_driver, "CVE-2026-32645") == {"cisa_ics": {"zones": ["energy"], "stated": ["energy"]}}
        _q7b(client)
        assert _links(raw_driver, "CVE-2026-32645") == {
            "energy": {
                "label": "advisory_sector",
                "confidence": 0.9,
                "sources": ["cisa_ics"],
                "refs": ["cisa_ics:ICSA-26-281-01"],
                "events": ["161"],
            }
        }

    @pytest.mark.parametrize("cisa_first", [True, False])
    def test_a_sector_cisa_states_and_nvd_infers_is_one_stated_link(self, client, raw_driver, cisa_first):
        _cve_node(raw_driver, "CVE-2026-0002")
        writes = [
            (_cisa_item("CVE-2026-0002", ["energy"]), CISA_EVENT),
            (_nvd_item("CVE-2026-0002", ["energy"]), NVD_EVENT),
        ]
        for item, event in writes if cisa_first else reversed(writes):
            _sync(client, item, event)
        _q7b(client)
        assert _links(raw_driver, "CVE-2026-0002") == {
            "energy": {
                "label": "advisory_sector",
                "confidence": 0.9,
                "sources": ["cisa_ics", "nvd"],
                "refs": ["cisa_ics:ICSA-26-281-01"],
                "events": ["120", "161"],
            }
        }

    def test_an_nvd_guess_where_cisa_named_no_sector_names_nvd_only(self, client, raw_driver):
        """CVE-2025-7639 on the graph of 2026-10-16: NVD guessed energy, CISA's advisory named no tracked
        sector (global), and the energy link named both feeds."""
        _cve_node(raw_driver, "CVE-2025-7639")
        _sync(client, _cisa_item("CVE-2025-7639", ["global"]), CISA_EVENT)
        _sync(client, _nvd_item("CVE-2025-7639", ["energy"]), NVD_EVENT)
        assert _sourced_from(raw_driver, "CVE-2025-7639") == {
            "cisa_ics": {"zones": ["global"], "stated": None},
            "nvd": {"zones": ["energy"], "stated": None},
        }
        _q7b(client)
        assert _links(raw_driver, "CVE-2025-7639") == {
            "energy": {
                "label": "zone_classification",
                "confidence": 0.5,
                "sources": ["nvd"],
                "refs": [],
                "events": ["120"],
            }
        }

    def test_each_sector_cites_only_the_advisories_that_name_it(self, client, raw_driver):
        """CVE-2026-32645 as two advisories name it: ICSA-26-281-01 for Energy, ICSMA-26-283-01 for
        Healthcare. The node is named by both; each sector link (sync row and step 7b) cites only the
        advisory whose sector note names the sector, so its STIX reference leads to that advisory."""
        _cve_node(raw_driver, "CVE-2026-32645")
        item = ics.merge_items_per_cve(
            [
                _advisory_item("CVE-2026-32645", ["energy"], "ICSA-26-281-01"),
                _advisory_item("CVE-2026-32645", ["healthcare", "global"], "ICSMA-26-283-01"),
            ]
        )[0]
        _sync(client, item, CISA_EVENT)
        assert _stated_refs(raw_driver, "CVE-2026-32645") == [
            "energy|cisa_ics:ICSA-26-281-01",
            "healthcare|cisa_ics:ICSMA-26-283-01",
        ]
        synced = _links(raw_driver, "CVE-2026-32645")
        _q7b(client)
        built = _links(raw_driver, "CVE-2026-32645")
        assert built == synced
        assert {s: (v["label"], v["refs"]) for s, v in built.items()} == {
            "energy": ("advisory_sector", ["cisa_ics:ICSA-26-281-01"]),
            "healthcare": ("advisory_sector", ["cisa_ics:ICSMA-26-283-01"]),
        }

    def test_a_second_run_changes_nothing(self, client, raw_driver):
        _cve_node(raw_driver, "CVE-2026-0002")
        _sync(client, _cisa_item("CVE-2026-0002", ["energy", "healthcare"]), CISA_EVENT)
        _sync(client, _nvd_item("CVE-2026-0002", ["energy", "finance"]), NVD_EVENT)
        _q7b(client)
        first = _links(raw_driver, "CVE-2026-0002")
        _q7b(client)
        assert _links(raw_driver, "CVE-2026-0002") == first
        assert {s: (v["label"], v["sources"]) for s, v in first.items()} == {
            "energy": ("advisory_sector", ["cisa_ics", "nvd"]),
            "healthcare": ("advisory_sector", ["cisa_ics"]),
            "finance": ("zone_classification", ["nvd"]),
        }


# ================================================================ the legacy rule and stored links
def _graph(driver, cypher: str) -> None:
    with driver.session() as session:
        session.run(cypher)


class TestLegacyAndStoredLinks:
    def test_an_edge_without_zones_gives_every_zone_of_the_node(self, client, raw_driver):
        _graph(
            raw_driver,
            f"""
            MATCH (nvd:Source {{source_id: 'nvd'}}), (kev:Source {{source_id: 'cisa_kev'}})
            CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2024-0001', uuid: 'u-1', source: ['nvd', 'cisa_kev'], zone: ['energy']}})
            CREATE (c)-[:SOURCED_FROM {{source: 'nvd', misp_event_ids: ['5']}}]->(nvd)
            CREATE (c)-[:SOURCED_FROM {{source: 'cisa_kev', misp_event_ids: ['6']}}]->(kev)
            """,
        )
        _q7b(client)
        assert _links(raw_driver, "CVE-2024-0001") == {
            "energy": {
                "label": "zone_classification",
                "confidence": 0.5,
                "sources": ["cisa_kev", "nvd"],
                "refs": [],
                "events": ["5", "6"],
            }
        }

    def test_a_feed_without_a_sourced_from_edge_counts_for_every_zone(self, client, raw_driver):
        _graph(
            raw_driver,
            f"""
            MATCH (nvd:Source {{source_id: 'nvd'}})
            CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2024-0002', uuid: 'u-2', source: ['nvd', 'misp'],
                    zone: ['energy', 'finance']}})
            CREATE (c)-[:SOURCED_FROM {{source: 'nvd', zones: ['finance'], misp_event_ids: ['5']}}]->(nvd)
            """,
        )
        _q7b(client)
        links = _links(raw_driver, "CVE-2024-0002")
        assert {s: v["sources"] for s, v in links.items()} == {"energy": ["misp"], "finance": ["misp", "nvd"]}

    @pytest.mark.parametrize(
        "stated_refs, expected",
        [
            # an edge written before 2026-10-16 records no reference per sector: every link cites all
            (None, {"energy": ["cisa_ics:A", "cisa_ics:B"], "healthcare": ["cisa_ics:A", "cisa_ics:B"]}),
            (["energy|cisa_ics:A", "healthcare|cisa_ics:B"], {"energy": ["cisa_ics:A"], "healthcare": ["cisa_ics:B"]}),
            # a sector without a recorded reference cites all of the edge's references
            (["energy|cisa_ics:A"], {"energy": ["cisa_ics:A"], "healthcare": ["cisa_ics:A", "cisa_ics:B"]}),
        ],
    )
    def test_an_edge_cites_per_sector_what_it_recorded(self, client, raw_driver, stated_refs, expected):
        _graph(
            raw_driver,
            f"""
            MATCH (src:Source {{source_id: 'cisa_ics'}})
            CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2024-0005', uuid: 'u-5', source: ['cisa_ics'],
                    zone: ['energy', 'healthcare']}})
            CREATE (c)-[:SOURCED_FROM {{source: 'cisa_ics', zones: ['energy', 'healthcare'],
                    stated_zones: ['energy', 'healthcare'], source_refs: ['cisa_ics:A', 'cisa_ics:B']}}]->(src)
            """,
        )
        if stated_refs is not None:
            with raw_driver.session() as session:
                session.run(
                    "MATCH (:CVE {cve_id: 'CVE-2024-0005'})-[sf:SOURCED_FROM]->() SET sf.stated_refs = $refs",
                    refs=stated_refs,
                )
        _q7b(client)
        assert {s: v["refs"] for s, v in _links(raw_driver, "CVE-2024-0005").items()} == expected

    def test_a_node_sector_no_feed_gave_is_counted_not_linked(self, client, raw_driver):
        _graph(
            raw_driver,
            f"""
            MATCH (nvd:Source {{source_id: 'nvd'}})
            CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2024-0003', uuid: 'u-3', source: ['nvd'], zone: ['energy', 'healthcare']}})
            CREATE (c)-[:SOURCED_FROM {{source: 'nvd', zones: ['energy']}}]->(nvd)
            """,
        )
        assert _skipped(client, build_relationships._Q7B_STATEMENTS) == 1
        _q7b(client)
        assert set(_links(raw_driver, "CVE-2024-0003")) == {"energy"}

    @pytest.mark.parametrize(
        "stored, expected",
        [
            # the old graph: an inference at 1.0 comes back to the table's 0.5
            ({"match_type": "zone_classification", "confidence_score": 1.0}, ("zone_classification", 0.5)),
            # a link CISA stated, read with an edge written before stated_zones: the stronger label stays
            ({"match_type": "advisory_sector", "confidence_score": 0.9}, ("advisory_sector", 0.9)),
            # a label outside the table (a curated claim) is kept with its confidence
            ({"match_type": "coreideas_curated", "confidence_score": 0.85}, ("coreideas_curated", 0.85)),
            # a link written before every edge stated its evidence takes the computed label
            ({}, ("zone_classification", 0.5)),
        ],
    )
    def test_a_stored_link_keeps_or_takes_the_label(self, client, raw_driver, stored, expected):
        _graph(
            raw_driver,
            f"""
            MATCH (src:Source {{source_id: 'cisa_ics'}}), (s:Sector {{name: 'energy'}})
            CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2024-0004', uuid: 'u-4', source: ['cisa_ics'], zone: ['energy']}})
            CREATE (c)-[:SOURCED_FROM {{source: 'cisa_ics'}}]->(src)
            CREATE (c)-[:AFFECTS {{sources: ['coreideas']}}]->(s)
            """,
        )
        with raw_driver.session() as session:
            session.run("MATCH (:CVE {cve_id: 'CVE-2024-0004'})-[r:AFFECTS]->() SET r += $props", props=stored)
        _q7b(client)
        link = _links(raw_driver, "CVE-2024-0004")["energy"]
        assert (link["label"], link["confidence"]) == expected
        assert link["sources"] == ["cisa_ics", "coreideas"], "provenance accumulates; no feed erases another's"


# ================================================================ TARGETS and the alias merge
class TestActorTargetsAndTheAliasMerge:
    # ``stated_refs`` on the OTX edges stands for any source's per-sector references (only CISA ICS records
    # them today): the alias merge folds them the same way whatever the source.
    FIXTURE = f"""
    MATCH (otx:Source {{source_id: 'alienvault_otx'}}), (mitre:Source {{source_id: 'mitre_attck'}})
    CREATE (c:ThreatActor:{LABEL} {{name: 'conti', uuid: 'u-conti', source: ['alienvault_otx', 'mitre_attck'],
            zone: ['energy', 'finance']}})
    CREATE (d:ThreatActor:{LABEL} {{name: 'conti team', uuid: 'u-team', source: ['alienvault_otx'],
            zone: $team_zones}})
    CREATE (c)-[:SOURCED_FROM {{source: 'alienvault_otx', zones: ['finance'], source_refs: ['alienvault_otx:p1'],
            stated_refs: ['finance|alienvault_otx:p1']}}]->(otx)
    CREATE (c)-[:SOURCED_FROM {{source: 'mitre_attck', zones: ['energy'], source_refs: ['mitre_attck:G0102']}}]->(mitre)
    CREATE (d)-[:SOURCED_FROM {{source: 'alienvault_otx', zones: $team_zones, source_refs: ['alienvault_otx:p2'],
            stated_refs: [z IN $team_zones | z + '|alienvault_otx:p2']}}]->(otx)
    """

    def _actor_links(self, driver) -> Dict[str, Any]:
        rows = _rows(
            driver,
            "MATCH (:ThreatActor {name: 'conti'})-[r:TARGETS]->(s:Sector) "
            "RETURN s.name AS sector, r.match_type AS label, apoc.coll.sort(r.sources) AS sources",
        )
        return {r["sector"]: (r["label"], r["sources"]) for r in rows}

    def test_each_sector_names_only_its_feed(self, client, raw_driver):
        with raw_driver.session() as session:
            session.run(self.FIXTURE, team_zones=["healthcare"])
        _step(client, build_relationships._Q7C_STATEMENTS, "actor_targets_sector")
        assert self._actor_links(raw_driver) == {
            "energy": ("zone_classification", ["mitre_attck"]),
            "finance": ("zone_classification", ["alienvault_otx"]),
        }

    @pytest.mark.parametrize(
        "team_zones, expected",
        [(["healthcare"], ["finance", "healthcare"]), (["finance"], ["finance"])],
    )
    def test_a_folded_edge_keeps_the_union_of_the_zones_as_a_list(self, client, raw_driver, team_zones, expected):
        with raw_driver.session() as session:
            session.run(self.FIXTURE, team_zones=team_zones)
            results = {"merged": 0, "restamped_edges": 0, "errors": 0, "apoc_missing": 0}
            assert enrichment_jobs._run_alias_merge_batches(
                session,
                [("conti", "conti team")],
                statements=enrichment_jobs._ACTOR_ALIAS_MERGE_STATEMENTS,
                batch_size=200,
                apply_params={
                    "strategy": enrichment_jobs._ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY,
                    "mitre_source": "mitre_attck",
                    "reference_canonicals": ["conti"],
                },
                results=results,
                log_tag="IT",
                canonical_noun="actor(s)",
            )
        assert results["merged"] == 1 and results["errors"] == 0
        (edge,) = _rows(
            raw_driver,
            "MATCH (:ThreatActor {name: 'conti'})-[sf:SOURCED_FROM]->(:Source {source_id: 'alienvault_otx'}) "
            "RETURN sf.zones AS zones, apoc.meta.cypher.type(sf.zones) AS type, "
            "sf.stated_refs AS stated_refs, apoc.meta.cypher.type(sf.stated_refs) AS refs_type",
        )
        assert edge["type"].startswith("LIST"), "APOC's combine of equal values is wrapped back into a list"
        assert edge["zones"] == expected
        # which record gave which sector survives the fold, as a sorted list
        assert edge["refs_type"].startswith("LIST")
        assert edge["stated_refs"] == sorted({"finance|alienvault_otx:p1", f"{team_zones[0]}|alienvault_otx:p2"})
        _step(client, build_relationships._Q7C_STATEMENTS, "actor_targets_sector")
        links = self._actor_links(raw_driver)
        for zone in expected:
            assert "alienvault_otx" in links[zone][1]


# ================================================================ OTX industries (2026-10-18)
OTX_EVENT = {"id": 134, "info": "EdgeGuard-alienvault_otx-2026-10-18", "date": "2026-10-18", "Tag": []}
TF_EVENT = {"id": 135, "info": "EdgeGuard-threatfox-2026-10-18", "date": "2026-10-18", "Tag": []}
IOC = "198.51.100.23"


def _otx_nodes(driver) -> None:
    """The nodes the OTX writers MERGE into, created with the test label (a MERGE would create them without)."""
    with driver.session() as session:
        session.run(
            f"CREATE (:Indicator:{LABEL} {{indicator_type: 'ipv4', value: $ioc, uuid: 'u-ioc'}}) "
            f"CREATE (:Malware:{LABEL} {{name: 'examplelocker', uuid: 'u-examplelocker'}}) "
            f"CREATE (:ThreatActor:{LABEL} {{name: 'dragonfly', uuid: 'u-dragonfly'}})",
            ioc=IOC,
        )


def _sync_otx(client, pulse: Dict[str, Any], kinds=("indicator",), *more_pulses: Dict[str, Any]) -> None:
    """The collector's items of ``pulse`` (and ``more_pulses``, the same run) of the given kinds through
    MISPWriter and the sync, as production writes them: the node with its SOURCED_FROM edge and the sync's
    sector rows."""
    syncer = MISPToNeo4jSync(neo4j_client=client)
    for item in _otx_items(pulse, *more_pulses):
        kind = _kind(item)
        if kind not in kinds:
            continue
        parsed, _ = syncer.parse_attribute(_attribute(item), OTX_EVENT)
        assert parsed is not None
        if kind == "indicator":
            assert client.merge_indicators_batch([parsed], source_id="alienvault_otx") == (1, 0)
        elif kind == "malware":
            assert client.merge_malware(parsed, source_id="alienvault_otx")
        elif kind == "actor":
            assert client.merge_actor(parsed, source_id="alienvault_otx")
        rows = [r for r in syncer._build_cross_item_relationships([parsed]) if r["to_type"] == "Sector"]
        if rows:
            client.create_misp_relationships_batch(rows, source_id="alienvault_otx")


def _sync_threatfox(client) -> None:
    """A ThreatFox record of the same IOC whose energy zone is inferred (a feed's malware family)."""
    attribute = WRITER.create_attribute(
        {
            "indicator_type": "ipv4",
            "value": IOC,
            "zone": ["energy"],
            "tag": "threatfox",
            "source": ["threatfox"],
            "confidence_score": 0.5,
            "ioc_id": "1650000",
            "reference": "https://threatfox.abuse.ch/ioc/1650000/",
        }
    )
    attribute["uuid"] = "6a1f0000-0000-4000-8000-000000001650"
    syncer = MISPToNeo4jSync(neo4j_client=client)
    parsed, _ = syncer.parse_attribute(attribute, TF_EVENT)
    assert parsed is not None and parsed["tag"] == "threatfox"
    assert client.merge_indicators_batch([parsed], source_id="threatfox") == (1, 0)
    rows = [r for r in syncer._build_cross_item_relationships([parsed]) if r["to_type"] == "Sector"]
    client.create_misp_relationships_batch(rows, source_id="threatfox")


def _targets(driver, node: str) -> Dict[str, Dict[str, Any]]:
    rows = _rows(
        driver,
        f"MATCH {node}-[r:TARGETS]->(s:Sector) "
        "RETURN s.name AS sector, r.match_type AS label, r.confidence_score AS confidence, "
        "apoc.coll.sort(r.sources) AS sources, apoc.coll.sort(coalesce(r.source_refs, [])) AS refs",
    )
    return {r.pop("sector"): r for r in rows}


def _otx_edge(driver, node: str) -> Dict[str, Any]:
    (row,) = _rows(
        driver,
        f"MATCH {node}-[sf:SOURCED_FROM]->(:Source {{source_id: 'alienvault_otx'}}) "
        "RETURN sf.zones AS zones, sf.stated_zones AS stated, sf.stated_refs AS stated_refs",
    )
    return row


_IOC_NODE = f"(:Indicator {{value: '{IOC}'}})"
_STATED = {"label": "otx_industries", "confidence": 0.6, "sources": ["alienvault_otx"], "refs": [PULSE_REF]}
_INFERRED = {"label": "zone_classification", "confidence": 0.5, "sources": ["alienvault_otx"], "refs": [PULSE_REF]}


class TestOtxIndustriesStatements:
    def test_an_indicator_link_is_the_pulses_statement_where_its_industries_name_the_sector(self, client, raw_driver):
        """The pulse's industries name Energy, its text names hospitals: the sync writes TARGETS energy as
        ``otx_industries`` and healthcare as ``zone_classification``, and step 7a computes the same."""
        _otx_nodes(raw_driver)
        _sync_otx(client, _pulse())
        assert _otx_edge(raw_driver, _IOC_NODE) == {
            "zones": ["energy", "healthcare"],
            "stated": ["energy"],
            "stated_refs": [f"energy|{PULSE_REF}"],
        }
        synced = _targets(raw_driver, _IOC_NODE)
        assert synced == {"energy": _STATED, "healthcare": _INFERRED}
        _step(client, build_relationships._Q7A_STATEMENTS, "indicator_targets_sector")
        assert _targets(raw_driver, _IOC_NODE) == synced

    @pytest.mark.parametrize("industries", [[], ["Government"]])
    def test_a_pulse_that_states_no_tracked_sector_stays_an_inference(self, client, raw_driver, industries):
        _otx_nodes(raw_driver)
        _sync_otx(client, _pulse(industries=industries))
        _step(client, build_relationships._Q7A_STATEMENTS, "indicator_targets_sector")
        assert _otx_edge(raw_driver, _IOC_NODE)["stated"] is None
        assert _targets(raw_driver, _IOC_NODE) == {"healthcare": _INFERRED}

    @pytest.mark.parametrize("otx_first", [True, False])
    def test_a_statement_and_an_inference_of_one_link_keep_the_statement(self, client, raw_driver, otx_first):
        _otx_nodes(raw_driver)
        writes = [lambda: _sync_otx(client, _pulse()), lambda: _sync_threatfox(client)]
        for write in writes if otx_first else reversed(writes):
            write()
        _step(client, build_relationships._Q7A_STATEMENTS, "indicator_targets_sector")
        energy = _targets(raw_driver, _IOC_NODE)["energy"]
        assert (energy["label"], energy["confidence"]) == ("otx_industries", 0.6)
        assert energy["sources"] == ["alienvault_otx", "threatfox"]
        assert PULSE_REF in energy["refs"] and "threatfox:1650000" in energy["refs"]

    def test_a_full_sync_relabels_a_link_written_before(self, client, raw_driver):
        """A graph synced before 2026-10-18: the OTX edge records no statement and the link is an inference.
        Step 7a alone keeps it (nothing stated yet); reading the attribute again (a full sync) records the
        statement, and the batched writer takes the row's label (0.6 reaches the stored 0.5)."""
        _graph(
            raw_driver,
            f"""
            MATCH (otx:Source {{source_id: 'alienvault_otx'}}), (s:Sector {{name: 'energy'}})
            CREATE (i:Indicator:{LABEL} {{indicator_type: 'ipv4', value: '{IOC}', uuid: 'u-ioc',
                    source: ['alienvault_otx'], zone: ['energy', 'healthcare']}})
            CREATE (i)-[:SOURCED_FROM {{source: 'alienvault_otx', zones: ['energy', 'healthcare'],
                    source_refs: ['{PULSE_REF}'], misp_event_ids: ['134']}}]->(otx)
            CREATE (i)-[:TARGETS {{match_type: 'zone_classification', confidence_score: 0.5,
                    sources: ['alienvault_otx'], source_refs: ['{PULSE_REF}'], misp_event_ids: ['134'],
                    edgeguard_managed: true}}]->(s)
            """,
        )
        _step(client, build_relationships._Q7A_STATEMENTS, "indicator_targets_sector")
        assert _targets(raw_driver, _IOC_NODE)["energy"]["label"] == "zone_classification"
        _sync_otx(client, _pulse())
        assert _targets(raw_driver, _IOC_NODE)["energy"] == _STATED
        _step(client, build_relationships._Q7A_STATEMENTS, "indicator_targets_sector")
        assert _targets(raw_driver, _IOC_NODE) == {"energy": _STATED, "healthcare": _INFERRED}

    def test_family_and_adversary_links_follow_the_statement(self, client, raw_driver):
        """Malware and ThreatActor link to a Sector in steps 7c / 7d only: from the OTX edge the writers
        recorded with the industries that travelled in ``MITRE_USES_TECHNIQUES.ind``."""
        _otx_nodes(raw_driver)
        _sync_otx(client, _pulse(), kinds=("malware", "actor"))
        _step(client, build_relationships._Q7C_STATEMENTS, "actor_targets_sector")
        _step(client, build_relationships._Q7D_STATEMENTS, "malware_targets_sector")
        for node in ("(:Malware {name: 'examplelocker'})", "(:ThreatActor {name: 'dragonfly'})"):
            assert _otx_edge(raw_driver, node)["stated_refs"] == [f"energy|{PULSE_REF}"]
            assert _targets(raw_driver, node) == {"energy": _STATED, "healthcare": _INFERRED}, node

    def test_a_folded_pulses_statement_is_linked_whichever_pulse_came_first(self, client, raw_driver):
        """A pulse whose text names a power grid utility lists the IOC and the family first; the stating pulse
        (industries Energy) lists them later in the same run. The statement travels with the folded item, so
        the OTX edges record it with the stating pulse and the sync's indicator row, step 7a and step 7d link
        energy as ``otx_industries`` citing that pulse; the keyword pulse is cited only by an inferred sector."""
        _otx_nodes(raw_driver)
        _sync_otx(client, _second_pulse(), ("indicator", "malware"), _pulse())
        for node in (_IOC_NODE, "(:Malware {name: 'examplelocker'})"):
            edge = _otx_edge(raw_driver, node)
            assert edge["stated"] == ["energy"] and edge["stated_refs"] == [f"energy|{PULSE_REF}"], node
        assert _targets(raw_driver, _IOC_NODE)["energy"] == _STATED
        _step(client, build_relationships._Q7A_STATEMENTS, "indicator_targets_sector")
        _step(client, build_relationships._Q7D_STATEMENTS, "malware_targets_sector")
        for node in (_IOC_NODE, "(:Malware {name: 'examplelocker'})"):
            assert _targets(raw_driver, node) == {"energy": _STATED}, node
        assert SECOND_REF not in _targets(raw_driver, _IOC_NODE)["energy"]["refs"]

    def test_affects_from_an_otx_record_stays_an_inference(self, client, raw_driver):
        """Even an OTX edge that records the statement on a CVE gives AFFECTS no OTX label: a targeted industry
        is no statement about where the product is deployed."""
        _graph(
            raw_driver,
            f"""
            MATCH (otx:Source {{source_id: 'alienvault_otx'}})
            CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2026-11111', uuid: 'u-11111', source: ['alienvault_otx'],
                    zone: ['energy']}})
            CREATE (c)-[:SOURCED_FROM {{source: 'alienvault_otx', zones: ['energy'], stated_zones: ['energy'],
                    stated_refs: ['energy|{PULSE_REF}'], source_refs: ['{PULSE_REF}']}}]->(otx)
            """,
        )
        _q7b(client)
        link = _links(raw_driver, "CVE-2026-11111")["energy"]
        assert (link["label"], link["confidence"], link["refs"]) == ("zone_classification", 0.5, [PULSE_REF])

    def test_the_alias_merge_keeps_the_statement(self, client, raw_driver):
        """An OTX duplicate whose energy link is the pulse's statement folds into the canonical actor, whose
        energy link is an ATT&CK inference: the collapsed link keeps ``otx_industries`` and the folded OTX edge
        keeps the statement, so step 7c computes the same afterwards."""
        _graph(
            raw_driver,
            f"""
            MATCH (otx:Source {{source_id: 'alienvault_otx'}}), (mitre:Source {{source_id: 'mitre_attck'}}),
                  (s:Sector {{name: 'energy'}})
            CREATE (c:ThreatActor:{LABEL} {{name: 'dragonfly', uuid: 'u-c', source: ['mitre_attck'], zone: ['energy'],
                    aliases: ['Energetic Bear']}})
            CREATE (d:ThreatActor:{LABEL} {{name: 'energetic bear', uuid: 'u-d', source: ['alienvault_otx'],
                    zone: ['energy']}})
            CREATE (c)-[:SOURCED_FROM {{source: 'mitre_attck', zones: ['energy'], source_refs: ['mitre_attck:G0035']}}]->(mitre)
            CREATE (d)-[:SOURCED_FROM {{source: 'alienvault_otx', zones: ['energy'], stated_zones: ['energy'],
                    stated_refs: ['energy|{PULSE_REF}'], source_refs: ['{PULSE_REF}']}}]->(otx)
            CREATE (c)-[:TARGETS {{match_type: 'zone_classification', confidence_score: 0.5, sources: ['mitre_attck'],
                    source_refs: ['mitre_attck:G0035'], edgeguard_managed: true}}]->(s)
            CREATE (d)-[:TARGETS {{match_type: 'otx_industries', confidence_score: 0.6, sources: ['alienvault_otx'],
                    source_refs: ['{PULSE_REF}'], edgeguard_managed: true}}]->(s)
            """,
        )
        with raw_driver.session() as session:
            results = {"merged": 0, "restamped_edges": 0, "errors": 0, "apoc_missing": 0}
            assert enrichment_jobs._run_alias_merge_batches(
                session,
                [("dragonfly", "energetic bear")],
                statements=enrichment_jobs._ACTOR_ALIAS_MERGE_STATEMENTS,
                batch_size=200,
                apply_params={
                    "strategy": enrichment_jobs._ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY,
                    "mitre_source": "mitre_attck",
                    "reference_canonicals": [],
                },
                results=results,
                log_tag="IT",
                canonical_noun="actor(s)",
            )
        assert results["merged"] == 1 and results["errors"] == 0
        node = "(:ThreatActor {name: 'dragonfly'})"
        merged = _targets(raw_driver, node)["energy"]
        assert (merged["label"], merged["confidence"]) == ("otx_industries", 0.6)
        assert merged["sources"] == ["alienvault_otx", "mitre_attck"]
        assert _otx_edge(raw_driver, node)["stated"] == ["energy"]
        _step(client, build_relationships._Q7C_STATEMENTS, "actor_targets_sector")
        assert _targets(raw_driver, node)["energy"] == merged
