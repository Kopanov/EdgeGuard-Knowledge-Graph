"""Explainability on a real Neo4j (2026-10): ``r.cited_ids`` on links a revoked ATT&CK id led to.

A link that reaches a technique through the revoked-id map records the id the source cited
(``r.cited_ids``); a link every source made to the technique's own id carries none. Two writers
are run as production runs them: ``build_relationships`` step 8 (OTX ``attack_ids``) through
``_safe_run_batched`` and ``apoc.periodic.iterate``, and the sync's
``create_misp_relationships_batch``, whose shared ``SET`` clause now handles ``cited_ids`` for every
relationship type. Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with
``EDGEGUARD_IT_NEO4J_URI``, writes only nodes labelled ``EdgeGuardIT``, refuses any other node.

Campaign links (2026-10-15, 2026-10-16) state their evidence: ``campaign_grouping``, the confidence of
the links they rest on and the relationship types of those links (``r.evidence_types``). A campaign
rests on ATTRIBUTED_TO or USES_MALWARE links between its actor and a malware (``campaign_evidence``);
one without either is deleted, one with evidence whose indicators expired stays inactive, and the
baseline postcheck and the acceptance checks read the same definition. A campaign and its links
carry the most restrictive TLP of the links they rest on (2026-10: a curated claim's level), and the
STIX export marks them with it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from build_rel_queries import assigned_queries  # noqa: E402
from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import build_relationships  # noqa: E402
import campaign_evidence  # noqa: E402
import neo4j_client  # noqa: E402
from attack_revoked import technique_successors  # noqa: E402
from node_identity import compute_node_uuid  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


FIXTURE = f"""
CREATE (otx:Source:{LABEL} {{source_id: 'alienvault_otx'}})
CREATE (i:Indicator:{LABEL} {{indicator_type: 'domain', value: 'it.example', uuid: 'u-i',
        source: ['alienvault_otx'], attack_ids: ['T1086', 'T1059.001', 'T1566']}})
CREATE (i)-[:SOURCED_FROM {{source: 'alienvault_otx', source_refs: ['alienvault_otx:p1'], misp_event_ids: ['5']}}]->(otx)
CREATE (:Technique:{LABEL} {{mitre_id: 'T1059.001', uuid: 'u-t1'}})
CREATE (:Technique:{LABEL} {{mitre_id: 'T1566', uuid: 'u-t2'}})
CREATE (:ThreatActor:{LABEL} {{name: 'apt29', uuid: 'u-a', source: ['alienvault_otx']}})
CREATE (:Malware:{LABEL} {{name: 'cobalt strike', uuid: 'u-m', source: ['alienvault_otx']}})
"""


@pytest.fixture
def client(raw_driver):
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(FIXTURE)
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()


def _cited(raw_driver, query):
    with raw_driver.session() as session:
        return {r["target"]: r["cited"] for r in session.run(query)}


def test_build_relationships_records_the_cited_id_on_a_translated_link(client, raw_driver):
    assert technique_successors()["T1086"] == "T1059.001"
    (outer,) = assigned_queries("_q8_outer")
    (inner,) = assigned_queries("_q8_inner")
    query = (
        "MATCH (:Indicator {value: 'it.example'})-[r:USES_TECHNIQUE]->(t:Technique) "
        "RETURN t.mitre_id AS target, r.cited_ids AS cited"
    )
    for _ in range(2):  # a second run adds nothing twice
        ok = build_relationships._safe_run_batched(
            client, "it", outer, inner, {}, "indicator_uses_technique", params={"revoked": technique_successors()}
        )
        assert ok
        # T1086 (revoked into T1059.001) and T1059.001 itself make one link, which names T1086;
        # the link to T1566 was cited as itself and carries no property.
        assert _cited(raw_driver, query) == {"T1059.001": ["T1086"], "T1566": None}
    # The pulse's ATT&CK ids are one report's association: 0.6, as every other link from them, with
    # the step's own evidence label.
    with raw_driver.session() as session:
        evidence = {
            (r["label"], r["confidence"])
            for r in session.run(
                "MATCH (:Indicator {value: 'it.example'})-[r:USES_TECHNIQUE]->(:Technique) "
                "RETURN r.match_type AS label, r.confidence_score AS confidence"
            )
        }
    assert evidence == {("otx_attack_ids", 0.6)}


def test_the_sync_writer_records_cited_ids_on_technique_rows_only(client, raw_driver):
    base = {"confidence": 0.5, "misp_event_id": "5", "match_type": "misp_attribute_tag"}
    rows = [
        {
            **base,
            "rel_type": "EMPLOYS_TECHNIQUE",
            "from_type": "ThreatActor",
            "from_key": {"name": "apt29"},
            "to_type": "Technique",
            "to_key": {"mitre_id": "T1059.001"},
            "cited_ids": ["T1086"],
        },
        {
            **base,
            "rel_type": "EMPLOYS_TECHNIQUE",
            "from_type": "ThreatActor",
            "from_key": {"name": "apt29"},
            "to_type": "Technique",
            "to_key": {"mitre_id": "T1566"},
            "cited_ids": [],
        },
        {
            **base,
            "rel_type": "USES_MALWARE",
            "from_type": "ThreatActor",
            "from_key": {"name": "apt29"},
            "to_type": "Malware",
            "to_key": {"name": "cobalt strike"},
        },
    ]
    for _ in range(2):
        client.create_misp_relationships_batch(rows, source_id="alienvault_otx")
    techniques = _cited(
        raw_driver,
        "MATCH (:ThreatActor {name: 'apt29'})-[r:EMPLOYS_TECHNIQUE]->(t:Technique) "
        "RETURN t.mitre_id AS target, r.cited_ids AS cited",
    )
    assert techniques == {"T1059.001": ["T1086"], "T1566": None}
    malware = _cited(
        raw_driver,
        "MATCH (:ThreatActor {name: 'apt29'})-[r:USES_MALWARE]->(m:Malware) RETURN m.name AS target, r.cited_ids AS cited",
    )
    assert malware == {"cobalt strike": None}, "a row without cited_ids leaves the property absent"


CAMPAIGN_FIXTURE = f"""
CREATE (a:ThreatActor:{LABEL} {{name: 'fin7', uuid: 'u-fin7', source: ['mitre_attck'], tags: ['mitre']}})
CREATE (carbanak:Malware:{LABEL} {{name: 'carbanak', uuid: 'u-carbanak'}})
CREATE (griffon:Malware:{LABEL} {{name: 'griffon', uuid: 'u-griffon'}})
CREATE (carbanak)-[:ATTRIBUTED_TO {{match_type: 'otx_pulse', confidence_score: 0.6, sources: ['alienvault_otx']}}]->(a)
CREATE (griffon)-[:ATTRIBUTED_TO {{match_type: 'mitre_explicit', confidence_score: 0.95, sources: ['mitre_attck']}}]->(a)
CREATE (i:Indicator:{LABEL} {{indicator_type: 'domain', value: 'fin7.example', uuid: 'u-fin7-i', active: true,
        first_imported_at: datetime('2026-10-01T00:00:00Z')}})
CREATE (i)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(carbanak)
CREATE (i)-[:INDICATES {{match_type: 'otx_pulse', confidence_score: 0.5, sources: ['alienvault_otx']}}]->(griffon)
"""


def test_campaign_links_state_their_evidence_and_its_strength(client, raw_driver, monkeypatch):
    """``campaign_grouping`` on every campaign link, with the confidence of the evidence it rests on:
    RUNS the actor's strongest attribution (0.95); a malware link its ATTRIBUTED_TO (0.6, 0.95); the
    indicator its best path, each path as strong as its weaker link (max(min(0.8, 0.6), min(0.5, 0.95)) = 0.6)."""
    import enrichment_jobs

    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    with raw_driver.session() as session:
        session.run(CAMPAIGN_FIXTURE)
    for _ in range(2):  # recomputed on every run: the same answer
        enrichment_jobs.build_campaign_nodes(client)
        with raw_driver.session() as session:
            session.run(f"MATCH (c:Campaign) SET c:{LABEL}")  # removed with the fixture
            found = list(
                session.run(
                    "MATCH (n)-[r:RUNS|PART_OF_CAMPAIGN]->(:Campaign {actor_name: 'fin7'}) "
                    "RETURN coalesce(n.name, n.value) AS from, type(r) AS type, r.match_type AS label, "
                    "r.confidence_score AS confidence, r.sources AS sources, r.evidence_types AS types"
                )
            )
            rows = {(r["from"], r["type"]): (r["label"], r["confidence"]) for r in found}
            sources = {(r["from"], r["type"]): sorted(r["sources"] or []) for r in found}
            types = {(r["from"], r["type"]): r["types"] for r in found}
        assert rows == {
            ("fin7", "RUNS"): ("campaign_grouping", 0.95),
            ("carbanak", "PART_OF_CAMPAIGN"): ("campaign_grouping", 0.6),
            ("griffon", "PART_OF_CAMPAIGN"): ("campaign_grouping", 0.95),
            ("fin7.example", "PART_OF_CAMPAIGN"): ("campaign_grouping", 0.6),
        }
        # 2026-10-16: the relationship types each link rests on, sorted.
        assert types == {
            ("fin7", "RUNS"): ["ATTRIBUTED_TO"],
            ("carbanak", "PART_OF_CAMPAIGN"): ["ATTRIBUTED_TO"],
            ("griffon", "PART_OF_CAMPAIGN"): ["ATTRIBUTED_TO"],
            ("fin7.example", "PART_OF_CAMPAIGN"): ["ATTRIBUTED_TO", "INDICATES"],
        }
        # Provenance (2026-10): the indicator's link carries that of every path to the actor
        # (INDICATES and ATTRIBUTED_TO through carbanak and through griffon), not the last row's.
        assert sources == {
            ("fin7", "RUNS"): ["alienvault_otx", "mitre_attck"],
            ("carbanak", "PART_OF_CAMPAIGN"): ["alienvault_otx"],
            ("griffon", "PART_OF_CAMPAIGN"): ["mitre_attck"],
            ("fin7.example", "PART_OF_CAMPAIGN"): ["alienvault_otx", "mitre_attck", "threatfox"],
        }


# 2026-10-16: campaign evidence. ``apt-uses`` rests on MITRE's "uses" alone, ``apt-both`` on an OTX
# attribution and a curated "uses" claim of one malware, ``apt-gone`` on an attribution step 2d will
# remove, ``apt-quiet`` on a "uses" whose only indicator will expire, ``apt-folded`` on a "uses" of an
# actor the alias merge will fold into ``apt-both``.
EVIDENCE_FIXTURE = f"""
CREATE (uses:ThreatActor:{LABEL} {{name: 'apt-uses', uuid: 'u-apt-uses'}})
CREATE (both:ThreatActor:{LABEL} {{name: 'apt-both', uuid: 'u-apt-both'}})
CREATE (gone:ThreatActor:{LABEL} {{name: 'apt-gone', uuid: 'u-apt-gone'}})
CREATE (quiet:ThreatActor:{LABEL} {{name: 'apt-quiet', uuid: 'u-apt-quiet'}})
CREATE (folded:ThreatActor:{LABEL} {{name: 'apt-folded', uuid: 'u-apt-folded'}})
CREATE (usemal:Malware:{LABEL} {{name: 'usemal', uuid: 'u-usemal'}})
CREATE (bothmal:Malware:{LABEL} {{name: 'bothmal', uuid: 'u-bothmal'}})
CREATE (gonemal:Malware:{LABEL} {{name: 'gonemal', uuid: 'u-gonemal'}})
CREATE (quietmal:Malware:{LABEL} {{name: 'quietmal', uuid: 'u-quietmal'}})
CREATE (foldmal:Malware:{LABEL} {{name: 'foldmal', uuid: 'u-foldmal'}})
CREATE (uses)-[:USES_MALWARE {{match_type: 'mitre_explicit', confidence_score: 0.95, sources: ['mitre_attck'],
        source_refs: ['mitre_attck:G9001'], misp_event_ids: ['11'], edgeguard_managed: true}}]->(usemal)
CREATE (bothmal)-[:ATTRIBUTED_TO {{match_type: 'otx_pulse', confidence_score: 0.6, sources: ['alienvault_otx'],
        source_refs: ['alienvault_otx:p9'], misp_event_ids: ['12'], edgeguard_managed: true}}]->(both)
CREATE (both)-[:USES_MALWARE {{match_type: 'coreideas_curated', confidence_score: 0.85, sources: ['coreideas'],
        source_refs: ['coreideas:pkg1'], misp_event_ids: ['13'], edgeguard_managed: true}}]->(bothmal)
CREATE (gonemal)-[:ATTRIBUTED_TO {{match_type: 'otx_pulse', confidence_score: 0.6, sources: ['alienvault_otx'],
        edgeguard_managed: true}}]->(gone)
CREATE (quiet)-[:USES_MALWARE {{match_type: 'mitre_explicit', confidence_score: 0.95, sources: ['mitre_attck'],
        edgeguard_managed: true}}]->(quietmal)
CREATE (folded)-[:USES_MALWARE {{match_type: 'mitre_explicit', confidence_score: 0.95, sources: ['mitre_attck'],
        edgeguard_managed: true}}]->(foldmal)
CREATE (iu:Indicator:{LABEL} {{indicator_type: 'domain', value: 'uses.example', uuid: 'u-iu', active: true,
        first_imported_at: datetime('2026-10-01T00:00:00Z')}})
CREATE (ib:Indicator:{LABEL} {{indicator_type: 'domain', value: 'both.example', uuid: 'u-ib', active: true,
        first_imported_at: datetime('2026-10-02T00:00:00Z')}})
CREATE (ig:Indicator:{LABEL} {{indicator_type: 'domain', value: 'gone.example', uuid: 'u-ig', active: true,
        first_imported_at: datetime('2026-10-03T00:00:00Z')}})
CREATE (iq:Indicator:{LABEL} {{indicator_type: 'domain', value: 'quiet.example', uuid: 'u-iq', active: true,
        first_imported_at: datetime('2026-10-04T00:00:00Z')}})
CREATE (ifo:Indicator:{LABEL} {{indicator_type: 'domain', value: 'fold.example', uuid: 'u-ifo', active: true,
        first_imported_at: datetime('2026-10-05T00:00:00Z')}})
CREATE (iu)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(usemal)
CREATE (ib)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(bothmal)
CREATE (ig)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(gonemal)
CREATE (iq)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(quietmal)
CREATE (ifo)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(foldmal)
"""


def _build(client, raw_driver) -> dict:
    """``build_campaign_nodes`` as the enrichment run calls it; the campaigns it writes get the suite's
    label, so the module's cleanup removes them."""
    import enrichment_jobs

    results = enrichment_jobs.build_campaign_nodes(client)
    with raw_driver.session() as session:
        session.run(f"MATCH (c:Campaign) SET c:{LABEL}")
    return results


def _campaign_links(raw_driver) -> dict:
    """Every campaign link: (campaign actor, member or actor, type) -> (confidence, types, sources)."""
    with raw_driver.session() as session:
        return {
            (r["actor"], r["from"], r["type"]): (r["confidence"], r["types"], sorted(r["sources"] or []))
            for r in session.run(
                "MATCH (n)-[r:RUNS|PART_OF_CAMPAIGN]->(c:Campaign) "
                "RETURN c.actor_name AS actor, coalesce(n.name, n.value) AS from, type(r) AS type, "
                "r.confidence_score AS confidence, r.evidence_types AS types, r.sources AS sources"
            )
        }


def _snapshot(raw_driver) -> tuple:
    """The campaigns and their links, without the run's timestamps."""
    with raw_driver.session() as session:
        campaigns = sorted(
            (r["name"], r["uuid"], r["active"], r["malware_count"], r["indicator_count"])
            for r in session.run(
                "MATCH (c:Campaign) RETURN c.name AS name, c.uuid AS uuid, c.active AS active, "
                "c.malware_count AS malware_count, c.indicator_count AS indicator_count"
            )
        )
        links = sorted(
            (r["c"], r["n"], r["t"], r["label"], r["conf"], r["types"], r["src"], r["refs"], r["events"])
            for r in session.run(
                "MATCH (n)-[r:RUNS|PART_OF_CAMPAIGN]->(c:Campaign) "
                "RETURN c.name AS c, coalesce(n.name, n.value) AS n, type(r) AS t, r.match_type AS label, "
                "r.confidence_score AS conf, r.evidence_types AS types, apoc.coll.sort(r.sources) AS src, "
                "apoc.coll.sort(r.source_refs) AS refs, apoc.coll.sort(r.misp_event_ids) AS events"
            )
        )
    return campaigns, links


def _one(raw_driver, query: str) -> dict:
    with raw_driver.session() as session:
        return dict(session.run(query).single())


def test_an_actor_that_uses_malware_has_a_campaign_resting_on_that_link(client, raw_driver, monkeypatch):
    import enrichment_jobs

    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    with raw_driver.session() as session:
        session.run(EVIDENCE_FIXTURE)
    # The postcheck's count (INV-1) is the builder's: five actors, five campaigns.
    qualifying = _one(raw_driver, campaign_evidence.QUALIFYING_ACTORS_QUERY)["qualifying_actors"]
    results = _build(client, raw_driver)
    assert qualifying == results["campaigns_created"] == 5
    links = _campaign_links(raw_driver)
    # MITRE's "uses" alone: the actor, its malware and the malware's indicator.
    assert links[("apt-uses", "apt-uses", "RUNS")] == (0.95, ["USES_MALWARE"], ["mitre_attck"])
    assert links[("apt-uses", "usemal", "PART_OF_CAMPAIGN")] == (0.95, ["USES_MALWARE"], ["mitre_attck"])
    assert links[("apt-uses", "uses.example", "PART_OF_CAMPAIGN")] == (
        0.8,
        ["INDICATES", "USES_MALWARE"],
        ["mitre_attck", "threatfox"],
    )
    # Both links to one malware: the strongest for RUNS and the member; for the indicator the best
    # path, each as strong as its weaker link (max(min(0.8, 0.6), min(0.8, 0.85)) = 0.8).
    assert links[("apt-both", "apt-both", "RUNS")] == (
        0.85,
        ["ATTRIBUTED_TO", "USES_MALWARE"],
        ["alienvault_otx", "coreideas"],
    )
    assert links[("apt-both", "bothmal", "PART_OF_CAMPAIGN")] == (
        0.85,
        ["ATTRIBUTED_TO", "USES_MALWARE"],
        ["alienvault_otx", "coreideas"],
    )
    assert links[("apt-both", "both.example", "PART_OF_CAMPAIGN")] == (
        0.8,
        ["ATTRIBUTED_TO", "INDICATES", "USES_MALWARE"],
        ["alienvault_otx", "coreideas", "threatfox"],
    )
    # The malware reached through both links counts once, and so does its indicator.
    with raw_driver.session() as session:
        both = session.run(
            "MATCH (c:Campaign {actor_name: 'apt-both'}) RETURN c.malware_count AS m, c.indicator_count AS i"
        ).single()
    assert (both["m"], both["i"]) == (1, 1)
    # The acceptance checks pass on the graph the builder wrote.
    assert _one(raw_driver, campaign_evidence.MALWARE_MEMBERSHIP_CHECK_QUERY) == {
        "malware_links": 5,
        "without_evidence": 0,
    }
    assert _one(raw_driver, campaign_evidence.CAMPAIGN_EVIDENCE_CHECK_QUERY) == {
        "campaigns": 5,
        "without_evidence": 0,
        "without_runs": 0,
        "runs_without_evidence": 0,
    }


# 2026-10: ``apt-amber`` rests on an amber curated "uses" claim (``curmal``) and an OTX attribution
# without a level (``otxmal``); ``apt-red`` uses a malware by MITRE's "uses" and has a campaign node a
# partner created at TLP:RED.
TLP_FIXTURE = f"""
CREATE (amber:ThreatActor:{LABEL} {{name: 'apt-amber', uuid: 'u-apt-amber', edgeguard_managed: true}})
CREATE (red:ThreatActor:{LABEL} {{name: 'apt-red', uuid: 'u-apt-red', edgeguard_managed: true}})
CREATE (curmal:Malware:{LABEL} {{name: 'curmal', uuid: 'u-curmal', edgeguard_managed: true}})
CREATE (otxmal:Malware:{LABEL} {{name: 'otxmal', uuid: 'u-otxmal', edgeguard_managed: true}})
CREATE (redmal:Malware:{LABEL} {{name: 'redmal', uuid: 'u-redmal', edgeguard_managed: true}})
CREATE (amber)-[:USES_MALWARE {{match_type: 'coreideas_curated', confidence_score: 0.85, sources: ['coreideas'],
        source_refs: ['coreideas:claim:0123456789abcdef'], misp_event_ids: ['42'], tlp: 'amber',
        edgeguard_managed: true}}]->(curmal)
CREATE (otxmal)-[:ATTRIBUTED_TO {{match_type: 'otx_pulse', confidence_score: 0.6, sources: ['alienvault_otx'],
        edgeguard_managed: true}}]->(amber)
CREATE (red)-[:USES_MALWARE {{match_type: 'mitre_explicit', confidence_score: 0.95, sources: ['mitre_attck'],
        edgeguard_managed: true}}]->(redmal)
CREATE (:Campaign:{LABEL} {{name: 'apt-red Campaign', actor_name: 'apt-red', uuid: 'u-partner', tlp: 'red',
        edgeguard_managed: false}})
CREATE (ic:Indicator:{LABEL} {{indicator_type: 'domain', value: 'cur.example', uuid: 'u-ic', active: true,
        edgeguard_managed: true, first_imported_at: datetime('2026-10-01T00:00:00Z')}})
CREATE (io:Indicator:{LABEL} {{indicator_type: 'domain', value: 'otx.example', uuid: 'u-io', active: true,
        edgeguard_managed: true, first_imported_at: datetime('2026-10-02T00:00:00Z')}})
CREATE (ir:Indicator:{LABEL} {{indicator_type: 'domain', value: 'red.example', uuid: 'u-ir', active: true,
        edgeguard_managed: true, first_imported_at: datetime('2026-10-03T00:00:00Z')}})
CREATE (ic)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(curmal)
CREATE (io)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(otxmal)
CREATE (ir)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(redmal)
"""


def _tlp_levels(raw_driver) -> dict:
    """(campaign actor, member or actor, type) -> the link's ``tlp``, and (campaign actor, 'Campaign') ->
    the campaign's."""
    with raw_driver.session() as session:
        links = {
            (r["actor"], r["from"], r["type"]): r["tlp"]
            for r in session.run(
                "MATCH (n)-[r:RUNS|PART_OF_CAMPAIGN]->(c:Campaign) "
                "RETURN c.actor_name AS actor, coalesce(n.name, n.value) AS from, type(r) AS type, r.tlp AS tlp"
            )
        }
        campaigns = {
            (r["actor"], "Campaign"): r["tlp"]
            for r in session.run("MATCH (c:Campaign) RETURN c.actor_name AS actor, c.tlp AS tlp")
        }
    return {**links, **campaigns}


def test_a_campaign_resting_on_a_curated_claim_carries_its_tlp(client, raw_driver, monkeypatch):
    """The campaign, its RUNS and the links that rest on the amber claim are amber, the links that do
    not rest on it carry no level, a partner's campaign keeps its own higher level, the STIX export
    marks the Campaign SDO amber (and so every SRO to it), and when the claim is withdrawn the level
    goes with it."""
    import stix2

    import enrichment_jobs
    from stix_exporter import StixExporter

    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    with raw_driver.session() as session:
        session.run(TLP_FIXTURE)
    for _ in range(2):  # recomputed on every run: the same answer
        _build(client, raw_driver)
        assert _tlp_levels(raw_driver) == {
            ("apt-amber", "Campaign"): "amber",
            ("apt-amber", "apt-amber", "RUNS"): "amber",
            ("apt-amber", "curmal", "PART_OF_CAMPAIGN"): "amber",
            ("apt-amber", "otxmal", "PART_OF_CAMPAIGN"): None,
            ("apt-amber", "cur.example", "PART_OF_CAMPAIGN"): "amber",
            ("apt-amber", "otx.example", "PART_OF_CAMPAIGN"): None,
            ("apt-red", "Campaign"): "red",  # a partner's level is never lowered
            ("apt-red", "apt-red", "RUNS"): None,
            ("apt-red", "redmal", "PART_OF_CAMPAIGN"): None,
            ("apt-red", "red.example", "PART_OF_CAMPAIGN"): None,
        }
    bundle = StixExporter(client).export_threat_actor("apt-amber")
    (campaign,) = [o for o in bundle["objects"] if o["type"] == "campaign"]
    assert campaign["object_marking_refs"] == [stix2.TLP_AMBER.id]
    runs = [
        o
        for o in bundle["objects"]
        if o["type"] == "relationship" and campaign["id"] in (o["source_ref"], o["target_ref"])
    ]
    assert runs and all(o["object_marking_refs"] == [stix2.TLP_AMBER.id] for o in runs)
    # The claim is withdrawn: the campaign rests on the OTX attribution alone and carries no level.
    with raw_driver.session() as session:
        session.run("MATCH (:ThreatActor {name: 'apt-amber'})-[r:USES_MALWARE]->(:Malware {name: 'curmal'}) DELETE r")
    _build(client, raw_driver)
    levels = _tlp_levels(raw_driver)
    assert levels[("apt-amber", "Campaign")] is None and levels[("apt-amber", "apt-amber", "RUNS")] is None
    assert ("apt-amber", "curmal", "PART_OF_CAMPAIGN") not in levels


# 2026-10: ``apt-quiet`` has a campaign whose only indicator expires before a claim arrives (Step 1 no
# longer reaches it, Step 2c does); ``apt-partner`` and ``apt-odd`` have campaign nodes a partner created,
# at TLP:WHITE and at a level outside the ladder.
TLP_QUIET_FIXTURE = f"""
CREATE (quiet:ThreatActor:{LABEL} {{name: 'apt-quiet', uuid: 'u-apt-quiet', edgeguard_managed: true}})
CREATE (partner:ThreatActor:{LABEL} {{name: 'apt-partner', uuid: 'u-apt-partner', edgeguard_managed: true}})
CREATE (odd:ThreatActor:{LABEL} {{name: 'apt-odd', uuid: 'u-apt-odd', edgeguard_managed: true}})
CREATE (qmal:Malware:{LABEL} {{name: 'qmal', uuid: 'u-qmal', edgeguard_managed: true}})
CREATE (qcur:Malware:{LABEL} {{name: 'qcur', uuid: 'u-qcur', edgeguard_managed: true}})
CREATE (pmal:Malware:{LABEL} {{name: 'pmal', uuid: 'u-pmal', edgeguard_managed: true}})
CREATE (pcur:Malware:{LABEL} {{name: 'pcur', uuid: 'u-pcur', edgeguard_managed: true}})
CREATE (omal:Malware:{LABEL} {{name: 'omal', uuid: 'u-omal', edgeguard_managed: true}})
CREATE (quiet)-[:USES_MALWARE {{match_type: 'mitre_explicit', confidence_score: 0.95, sources: ['mitre_attck'],
        edgeguard_managed: true}}]->(qmal)
CREATE (partner)-[:USES_MALWARE {{match_type: 'mitre_explicit', confidence_score: 0.95, sources: ['mitre_attck'],
        edgeguard_managed: true}}]->(pmal)
CREATE (partner)-[:USES_MALWARE {{match_type: 'coreideas_curated', confidence_score: 0.85, sources: ['coreideas'],
        tlp: 'amber', edgeguard_managed: true}}]->(pcur)
CREATE (odd)-[:USES_MALWARE {{match_type: 'mitre_explicit', confidence_score: 0.95, sources: ['mitre_attck'],
        edgeguard_managed: true}}]->(omal)
CREATE (:Campaign:{LABEL} {{name: 'apt-partner Campaign', actor_name: 'apt-partner', uuid: 'u-partner-w', tlp: 'white',
        edgeguard_managed: false}})
CREATE (:Campaign:{LABEL} {{name: 'apt-odd Campaign', actor_name: 'apt-odd', uuid: 'u-partner-o', tlp: 'TLP:AMBER',
        edgeguard_managed: false}})
CREATE (iq:Indicator:{LABEL} {{indicator_type: 'domain', value: 'quiet.example', uuid: 'u-iq', active: true,
        edgeguard_managed: true, first_imported_at: datetime('2026-10-01T00:00:00Z')}})
CREATE (ip:Indicator:{LABEL} {{indicator_type: 'domain', value: 'partner.example', uuid: 'u-ip', active: true,
        edgeguard_managed: true, first_imported_at: datetime('2026-10-02T00:00:00Z')}})
CREATE (io:Indicator:{LABEL} {{indicator_type: 'domain', value: 'odd.example', uuid: 'u-io', active: true,
        edgeguard_managed: true, first_imported_at: datetime('2026-10-03T00:00:00Z')}})
CREATE (iq)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(qmal)
CREATE (ip)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(pmal)
CREATE (io)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(omal)
"""


def test_a_campaign_without_an_active_indicator_and_partner_campaigns_take_the_level(client, raw_driver, monkeypatch):
    """Step 2c sets the level of a campaign Step 1 does not reach (its indicators expired) and stamps the
    change; a partner's campaign is raised by a claim and keeps the raised level after the withdrawal;
    a partner's level outside the ladder is kept."""
    import enrichment_jobs

    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    with raw_driver.session() as session:
        session.run(TLP_QUIET_FIXTURE)
    _build(client, raw_driver)
    levels = _tlp_levels(raw_driver)
    assert levels[("apt-quiet", "Campaign")] is None and levels[("apt-quiet", "apt-quiet", "RUNS")] is None
    assert levels[("apt-partner", "Campaign")] == "amber"  # raised from the partner's white by the claim
    assert levels[("apt-odd", "Campaign")] == "TLP:AMBER"  # outside the ladder: kept
    # apt-quiet's only indicator expires, then an amber claim arrives on a malware without indicators.
    with raw_driver.session() as session:
        session.run("MATCH (i:Indicator {value: 'quiet.example'}) SET i.active = false")
        session.run(
            "MATCH (a:ThreatActor {name: 'apt-quiet'}), (m:Malware {name: 'qcur'}) "
            "CREATE (a)-[:USES_MALWARE {match_type: 'coreideas_curated', confidence_score: 0.85, sources: ['coreideas'], "
            "tlp: 'amber', edgeguard_managed: true}]->(m)"
        )
    before = _one(
        raw_driver,
        "MATCH (a:ThreatActor {name: 'apt-quiet'})-[r:RUNS]->(c:Campaign) RETURN c.last_updated AS c, r.updated_at AS r",
    )
    _build(client, raw_driver)
    after = _one(
        raw_driver,
        "MATCH (a:ThreatActor {name: 'apt-quiet'})-[r:RUNS]->(c:Campaign) "
        "RETURN c.last_updated AS c, r.updated_at AS r, c.tlp AS tlp, r.tlp AS rtlp, c.active AS active",
    )
    assert (after["tlp"], after["rtlp"], after["active"]) == ("amber", "amber", False)
    assert after["c"] > before["c"] and after["r"] > before["r"]  # the change is stamped
    # Both claims are withdrawn: EdgeGuard's campaign loses the level, the partner's keeps the raised one.
    with raw_driver.session() as session:
        session.run("MATCH ()-[r:USES_MALWARE {match_type: 'coreideas_curated'}]->(:Malware) DELETE r")
    _build(client, raw_driver)
    levels = _tlp_levels(raw_driver)
    assert levels[("apt-quiet", "Campaign")] is None and levels[("apt-quiet", "apt-quiet", "RUNS")] is None
    assert levels[("apt-partner", "Campaign")] == "amber" and levels[("apt-partner", "apt-partner", "RUNS")] is None
    assert levels[("apt-odd", "Campaign")] == "TLP:AMBER"


def test_a_campaign_takes_its_newest_100_indicators_once_each(client, raw_driver, monkeypatch):
    """Each indicator of ``bothmal`` has two paths to ``apt-both`` (ATTRIBUTED_TO and USES_MALWARE):
    the sample is 100 indicators, not 100 paths."""
    import enrichment_jobs

    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    with raw_driver.session() as session:
        session.run(EVIDENCE_FIXTURE)
        session.run(
            f"MATCH (m:Malware {{name: 'bothmal'}}) UNWIND range(1, 101) AS n "
            f"CREATE (i:Indicator:{LABEL} {{indicator_type: 'domain', value: 'b' + toString(n) + '.example', active: true, "
            "first_imported_at: datetime('2026-09-01T00:00:00Z') + duration({days: n})}) "
            "CREATE (i)-[:INDICATES {match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}]->(m)"
        )
    _build(client, raw_driver)
    with raw_driver.session() as session:
        linked = {
            r["v"]
            for r in session.run(
                "MATCH (i:Indicator)-[:PART_OF_CAMPAIGN]->(:Campaign {actor_name: 'apt-both'}) RETURN i.value AS v"
            )
        }
        count = session.run("MATCH (c:Campaign {actor_name: 'apt-both'}) RETURN c.indicator_count AS n").single()["n"]
    assert len(linked) == 100 and count == 102
    # The two oldest of the 102 active indicators fall out of the sample.
    assert "b1.example" not in linked and "b2.example" not in linked and "both.example" in linked


def test_a_campaign_without_evidence_is_deleted_and_one_without_active_indicators_stays(
    client, raw_driver, monkeypatch
):
    import enrichment_jobs

    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    with raw_driver.session() as session:
        session.run(EVIDENCE_FIXTURE)
    _build(client, raw_driver)
    with raw_driver.session() as session:
        gone_uuid = session.run("MATCH (c:Campaign {actor_name: 'apt-gone'}) RETURN c.uuid AS u").single()["u"]
        # The uuid is computed from the actor's name.
        assert gone_uuid == compute_node_uuid("Campaign", {"name": "apt-gone Campaign"})
        # build_relationships step 2d removes apt-gone's only attribution; the indicator of apt-quiet's
        # malware expires; the actor alias merge folds apt-folded into apt-both (its links, the RUNS of
        # its campaign among them, move to apt-both, and no actor of its name remains).
        session.run("MATCH (:Malware {name: 'gonemal'})-[r:ATTRIBUTED_TO]->(:ThreatActor {name: 'apt-gone'}) DELETE r")
        session.run("MATCH (i:Indicator {value: 'quiet.example'}) SET i.active = false")
        session.run(
            "MATCH (c:ThreatActor {name: 'apt-both'}), (d:ThreatActor {name: 'apt-folded'}) "
            "CALL apoc.refactor.mergeNodes([c, d], {properties: 'discard', mergeRels: true}) YIELD node "
            "RETURN node.name AS name"
        ).consume()
    # The acceptance checks see the defects the builder has not settled yet.
    assert _one(raw_driver, campaign_evidence.CAMPAIGN_EVIDENCE_CHECK_QUERY) == {
        "campaigns": 5,
        "without_evidence": 2,  # apt-gone (no link left), apt-folded (no actor of that name)
        "without_runs": 1,  # apt-folded's RUNS now comes from apt-both; apt-gone keeps its RUNS
        "runs_without_evidence": 2,  # apt-gone's RUNS, and apt-both's to apt-folded's campaign
    }
    assert _one(raw_driver, campaign_evidence.MALWARE_MEMBERSHIP_CHECK_QUERY)["without_evidence"] == 2

    results = _build(client, raw_driver)
    assert results["campaigns_deleted"] == 2
    with raw_driver.session() as session:
        campaigns = {
            r["actor"]: r["active"]
            for r in session.run("MATCH (c:Campaign) RETURN c.actor_name AS actor, c.active AS active")
        }
        orphans = session.run(
            "MATCH (n)-[:PART_OF_CAMPAIGN]->() WHERE n.name IN ['gonemal'] OR n.value IN ['gone.example'] "
            "RETURN count(n) AS n"
        ).single()["n"]
    assert campaigns == {"apt-uses": True, "apt-both": True, "apt-quiet": False}
    assert orphans == 0, "the deleted campaign's links went with it"
    links = _campaign_links(raw_driver)
    # Evidence without an active indicator: the campaign stays, inactive, with its actor and malware.
    assert ("apt-quiet", "apt-quiet", "RUNS") in links and ("apt-quiet", "quietmal", "PART_OF_CAMPAIGN") in links
    assert ("apt-quiet", "quiet.example", "PART_OF_CAMPAIGN") not in links
    # The folded actor's malware and its indicator now belong to apt-both's campaign.
    assert links[("apt-both", "foldmal", "PART_OF_CAMPAIGN")] == (0.95, ["USES_MALWARE"], ["mitre_attck"])
    assert ("apt-both", "fold.example", "PART_OF_CAMPAIGN") in links
    assert links[("apt-both", "apt-both", "RUNS")] == (
        0.95,
        ["ATTRIBUTED_TO", "USES_MALWARE"],
        ["alienvault_otx", "coreideas", "mitre_attck"],
    )
    assert not any(actor in ("apt-gone", "apt-folded") for actor, _n, _t in links)
    assert _one(raw_driver, campaign_evidence.CAMPAIGN_EVIDENCE_CHECK_QUERY) == {
        "campaigns": 3,
        "without_evidence": 0,
        "without_runs": 0,
        "runs_without_evidence": 0,
    }
    assert _one(raw_driver, campaign_evidence.MALWARE_MEMBERSHIP_CHECK_QUERY)["without_evidence"] == 0

    # A RUNS from an actor that is not the campaign's is removed (Step 2c).
    with raw_driver.session() as session:
        session.run(
            "MATCH (a:ThreatActor {name: 'apt-both'}), (c:Campaign {actor_name: 'apt-uses'}) "
            "CREATE (a)-[:RUNS {edgeguard_managed: true}]->(c)"
        )
    results = _build(client, raw_driver)
    assert (results["runs_removed"], results["campaigns_deleted"]) == (1, 0)

    # A second run changes nothing.
    before = _snapshot(raw_driver)
    results = _build(client, raw_driver)
    assert (results["campaigns_deleted"], results["runs_removed"], results["malware_links_pruned"]) == (0, 0, 0)
    assert _snapshot(raw_driver) == before

    # Evidence again: the campaign is built again, with the same uuid.
    with raw_driver.session() as session:
        session.run(
            "MATCH (m:Malware {name: 'gonemal'}), (a:ThreatActor {name: 'apt-gone'}) "
            "CREATE (m)-[:ATTRIBUTED_TO {match_type: 'otx_pulse', confidence_score: 0.6, "
            "sources: ['alienvault_otx'], edgeguard_managed: true}]->(a)"
        )
    _build(client, raw_driver)
    with raw_driver.session() as session:
        again = session.run("MATCH (c:Campaign {actor_name: 'apt-gone'}) RETURN c.uuid AS u").single()["u"]
    assert again == gone_uuid


def test_campaign_link_provenance_does_not_depend_on_the_order_links_were_created(client, raw_driver, monkeypatch):
    """2026-10-16: a campaign link's ``misp_event_ids`` were the first 200 of the unsorted union of its
    links' lists, in the order the links were created, so two graphs built from the same MISP data in a
    different order kept different events. Three evidence links of one actor hold 300 events together;
    created in either order they give the same lists, the newest 200 events by MISP id, sorted feeds and
    record ids."""
    import enrichment_jobs

    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    links = [
        ("ATTRIBUTED_TO", "many-a", "alienvault_otx", range(1, 101)),
        ("USES_MALWARE", "many-b", "mitre_attck", range(101, 201)),
        ("USES_MALWARE", "many-c", "coreideas", range(201, 301)),
    ]

    def build(order) -> dict:
        with raw_driver.session() as session:
            session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
            session.run(f"CREATE (:ThreatActor:{LABEL} {{name: 'apt-many', uuid: 'u-apt-many'}})")
            for rel, malware, feed, events in order:
                session.run(
                    f"MATCH (a:ThreatActor {{name: 'apt-many'}}) "
                    f"MERGE (m:Malware:{LABEL} {{name: $m}}) ON CREATE SET m.uuid = 'u-' + $m "
                    f"CREATE (i:Indicator:{LABEL} {{indicator_type: 'domain', value: $m + '.example', uuid: 'u-i-' + $m, "
                    "active: true, first_imported_at: datetime('2026-10-01T00:00:00Z')}) "
                    "CREATE (i)-[:INDICATES {match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox'], "
                    "source_refs: ['threatfox:' + $m], misp_event_ids: ['7']}]->(m) "
                    + (
                        "CREATE (m)-[:ATTRIBUTED_TO {props}]->(a)"
                        if rel == "ATTRIBUTED_TO"
                        else "CREATE (a)-[:USES_MALWARE {props}]->(m)"
                    ).replace(
                        "{props}",
                        "{match_type: 'otx_pulse', confidence_score: 0.6, sources: [$feed], "
                        "source_refs: [$feed + ':' + $m], misp_event_ids: $events, edgeguard_managed: true}",
                    ),
                    m=malware,
                    feed=feed,
                    events=[str(e) for e in events],
                )
        _build(client, raw_driver)
        with raw_driver.session() as session:
            return {
                (r["from"], r["type"]): (r["events"], r["sources"], r["refs"])
                for r in session.run(
                    "MATCH (n)-[r:RUNS|PART_OF_CAMPAIGN]->(:Campaign {actor_name: 'apt-many'}) "
                    "RETURN coalesce(n.name, n.value) AS from, type(r) AS type, r.misp_event_ids AS events, "
                    "r.sources AS sources, r.source_refs AS refs"
                )
            }

    forward, backward = build(links), build(list(reversed(links)))
    assert forward == backward, "the same MISP data gives the same lists, in the same order"
    events, sources, refs = forward[("apt-many", "RUNS")]
    assert events == [str(e) for e in range(300, 100, -1)], "the newest 200 events, by MISP id"
    assert sources == ["alienvault_otx", "coreideas", "mitre_attck"]
    assert refs == ["alienvault_otx:many-a", "coreideas:many-c", "mitre_attck:many-b"]
    assert forward[("many-c.example", "PART_OF_CAMPAIGN")][0] == [str(e) for e in range(300, 200, -1)] + ["7"]


def test_step5_counts_the_active_campaigns_stamped_since_the_run_started(client, raw_driver):
    """2026-10-16: Step 5 of ``build_campaign_nodes`` counts the active campaigns whose ``last_updated``
    (Step 1 stamps it with the database's clock) is at or after the run's start, read from that clock.
    The statement was ``duration.between(c.last_updated, datetime()).minutes < 5``: ``.minutes`` is a
    component of the duration, so it counted the campaigns stamped days before (0 minutes) and missed
    one stamped 6 minutes before (here 3, not 2)."""
    import enrichment_jobs

    with raw_driver.session() as session:
        run_start_at = session.run("RETURN toString(datetime() - duration('PT10M')) AS t").single()["t"]
        session.run(
            f"""
            CREATE (:Campaign:{LABEL} {{name: 'stamped 6 minutes ago', active: true,
                    last_updated: datetime() - duration('PT6M')}})
            CREATE (:Campaign:{LABEL} {{name: 'stamped 1 minute ago', active: true,
                    last_updated: datetime() - duration('PT1M')}})
            CREATE (:Campaign:{LABEL} {{name: 'inactive, stamped 1 minute ago', active: false,
                    last_updated: datetime() - duration('PT1M')}})
            CREATE (:Campaign:{LABEL} {{name: 'stamped 2 days ago', active: true,
                    last_updated: datetime() - duration('P2D')}})
            CREATE (:Campaign:{LABEL} {{name: 'stamped 3 days ago', active: true,
                    last_updated: datetime() - duration('P3D')}})
            """
        )
        record = session.run(enrichment_jobs._CAMPAIGNS_STAMPED_THIS_RUN_CYPHER, run_start_at=run_start_at).single()
    assert record["count"] == 2, "the active campaigns stamped 6 minutes and 1 minute ago"
