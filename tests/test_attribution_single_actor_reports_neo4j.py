"""Attribution from a source report on a real Neo4j (2026-10): ``build_relationships`` step 2d and
the campaign membership that rests on it.

A graph as an earlier run left it: same-pulse attributions from a pulse that names one actor
(``p1``), from one that names two groups (``p2``, Gamaredon and Turla) and from one that names two
names of one actor (``p3``, The Gentlemen and Storm-2697), in the current provenance form
(``r.source_refs``) and in the form of graphs built before 2026-10-14 (``r.sources = ['otx_pulse']``,
``r.report_ids``). The indicators carry pairs in both forms: ``family::adversary::pulse`` (the OTX
collector since 2026-10, which writes them only for a pulse naming one actor; ``p5`` is a later pulse
the nodes do not record, naming Turla as Venomous Bear, a name the actor alias merge folds into Turla)
and ``family::adversary`` (written before). ``snake`` is a name of Turla the alias merge has not
folded yet: a pair naming it is judged by that node's pulses, not by Turla's. ``p6`` (2026-10) named Turla
alone when its pair ``crutch::turla::p6`` was written and an earlier run linked ``tinyturla`` to Turla from
it; it was then edited to name several actors. MISP held those actors already, so no actor node records
``p6``: only the OTX collector's mark says so, on another indicator of the pulse (``four.it.example``,
``several_actor_pulses``; the MISP writer adds the mark to the stored copies of up to three held IOCs of
the pulse, so the indicator carrying the pair need not carry the mark). ``unc-it-test``
loses its only attribution, and with it its campaign's ``RUNS``. ``strmal`` / ``strmal2`` and ``unc-it-test`` hold
lists as plain strings, as the actor alias merge's APOC ``combine`` leaves them until its normalising
statement runs. Step 2d runs as production runs it (its statements, through
``_safe_run_batched``, with the pulses ``_reports_naming_several_actors`` reads from the actor nodes and
the indicator marks, the committed reference and ``_attribution_params``), twice; the acceptance check
runs before and after, on the same pulses. The campaign builder
then drops the malware membership whose attribution is gone, and its links name only the evidence
that remains.
Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``,
writes only nodes labelled ``EdgeGuardIT``, refuses any other node.
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

from build_rel_queries import assigned_query  # noqa: E402
from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import build_relationships  # noqa: E402
import canonical_threat_actors  # noqa: E402
import enrichment_jobs  # noqa: E402
import neo4j_client  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

OTX = "{match_type: 'otx_pulse', confidence_score: 0.6, edgeguard_managed: true"
FIXTURE = f"""
CREATE (otx:Source:{LABEL} {{source_id: 'alienvault_otx'}})
CREATE (turla:ThreatActor:{LABEL} {{name: 'turla', uuid: 'u-turla', source: ['alienvault_otx'], pulse_ids: ['p1', 'p2']}})
CREATE (gam:ThreatActor:{LABEL} {{name: 'gamaredon group', uuid: 'u-gam', source: ['alienvault_otx'], pulse_ids: ['p2']}})
CREATE (tg:ThreatActor:{LABEL} {{name: 'the gentlemen', uuid: 'u-tg', source: ['alienvault_otx'], pulse_ids: ['p3']}})
CREATE (st:ThreatActor:{LABEL} {{name: 'storm-2697', uuid: 'u-st', source: ['alienvault_otx'], pulse_ids: ['p3']}})
CREATE (unc:ThreatActor:{LABEL} {{name: 'unc-it-test', uuid: 'u-unc', source: ['alienvault_otx'], pulse_ids: 'p2'}})
CREATE (snake:ThreatActor:{LABEL} {{name: 'snake', uuid: 'u-snake', source: ['alienvault_otx'], pulse_ids: ['p2']}})
CREATE (kaz:Malware:{LABEL} {{name: 'kazuar', uuid: 'u-kaz', pulse_ids: ['p1', 'p2']}})
CREATE (ptero:Malware:{LABEL} {{name: 'pterolnk', uuid: 'u-ptero', pulse_ids: ['p2']}})
CREATE (lb:Malware:{LABEL} {{name: 'lockbit', uuid: 'u-lb', pulse_ids: ['p2']}})
CREATE (gent:Malware:{LABEL} {{name: 'gentlemen', uuid: 'u-gent', pulse_ids: ['p3']}})
CREATE (norefs:Malware:{LABEL} {{name: 'norefs', uuid: 'u-norefs'}})
CREATE (partner:Malware:{LABEL} {{name: 'partner tool', uuid: 'u-partner'}})
CREATE (carbon:Malware:{LABEL} {{name: 'carbon', uuid: 'u-carbon', pulse_ids: ['p1', 'p2']}})
CREATE (loader:Malware:{LABEL} {{name: 'loader', uuid: 'u-loader', pulse_ids: ['p1', 'p2']}})
CREATE (strmal:Malware:{LABEL} {{name: 'strmal', uuid: 'u-strmal', pulse_ids: 'p2'}})
CREATE (strmal2:Malware:{LABEL} {{name: 'strmal2', uuid: 'u-strmal2'}})
CREATE (tiny:Malware:{LABEL} {{name: 'tinyturla', uuid: 'u-tiny', pulse_ids: ['p6']}})
CREATE (crutch:Malware:{LABEL} {{name: 'crutch', uuid: 'u-crutch', pulse_ids: ['p6']}})
CREATE (turla)-[:SOURCED_FROM {{source_refs: ['alienvault_otx:p1', 'alienvault_otx:p2']}}]->(otx)
CREATE (kaz)-[:SOURCED_FROM {{source_refs: ['alienvault_otx:p1', 'alienvault_otx:p2']}}]->(otx)
CREATE (gam)-[:SOURCED_FROM {{source_refs: ['alienvault_otx:p2']}}]->(otx)
CREATE (ptero)-[:SOURCED_FROM {{source_refs: ['alienvault_otx:p2']}}]->(otx)
CREATE (kaz)-[:ATTRIBUTED_TO {OTX}, sources: ['alienvault_otx'], source_refs: ['alienvault_otx:p1', 'alienvault_otx:p2']}}]->(turla)
CREATE (kaz)-[:ATTRIBUTED_TO {OTX}, sources: ['alienvault_otx'], source_refs: ['alienvault_otx:p2']}}]->(gam)
CREATE (ptero)-[:ATTRIBUTED_TO {OTX}, sources: ['alienvault_otx'], source_refs: ['alienvault_otx:p2']}}]->(gam)
CREATE (ptero)-[:ATTRIBUTED_TO {OTX}, sources: ['otx_pulse'], report_ids: ['p2']}}]->(turla)
CREATE (lb)-[:ATTRIBUTED_TO {OTX}, sources: ['alienvault_otx', 'threatfox'],
        source_refs: ['alienvault_otx:p2', 'threatfox:1']}}]->(gam)
CREATE (gent)-[:ATTRIBUTED_TO {OTX}, sources: ['alienvault_otx'], source_refs: ['alienvault_otx:p3']}}]->(tg)
CREATE (gent)-[:ATTRIBUTED_TO {OTX}, sources: ['alienvault_otx'], source_refs: ['alienvault_otx:p3']}}]->(st)
CREATE (norefs)-[:ATTRIBUTED_TO {OTX}, sources: ['alienvault_otx'], source_refs: []}}]->(gam)
CREATE (partner)-[:ATTRIBUTED_TO {{match_type: 'otx_pulse', source_refs: ['alienvault_otx:p2']}}]->(gam)
CREATE (carbon)-[:ATTRIBUTED_TO {OTX}, sources: ['otx_pulse'], report_ids: ['p1', 'p2']}}]->(turla)
CREATE (ptero)-[:ATTRIBUTED_TO {OTX}, sources: ['alienvault_otx'], source_refs: ['alienvault_otx:p2']}}]->(unc)
CREATE (strmal)-[:ATTRIBUTED_TO {OTX}, sources: 'alienvault_otx', source_refs: 'alienvault_otx:p2'}}]->(gam)
CREATE (strmal2)-[:ATTRIBUTED_TO {OTX}, sources: ['alienvault_otx', 'threatfox'], source_refs: 'alienvault_otx:p2'}}]->(gam)
CREATE (tiny)-[:ATTRIBUTED_TO {OTX}, sources: ['alienvault_otx'], source_refs: ['alienvault_otx:p6']}}]->(turla)
CREATE (i1:Indicator:{LABEL} {{indicator_type: 'domain', value: 'one.it.example', uuid: 'u-i1', active: true,
        pulse_malware_actor_pairs: ['kazuar::turla::p1', 'loader::snake']}})
CREATE (i2:Indicator:{LABEL} {{indicator_type: 'domain', value: 'two.it.example', uuid: 'u-i2', active: true,
        pulse_malware_actor_pairs: ['kazuar::turla', 'kazuar::gamaredon group', 'pterolnk::turla',
                                    'pterolnk::gamaredon group', 'pterolnk::gamaredon group::p2']}})
CREATE (i3:Indicator:{LABEL} {{indicator_type: 'domain', value: 'three.it.example', uuid: 'u-i3', active: true,
        pulse_malware_actor_pairs: ['lockbit::venomous bear::p5']}})
CREATE (i4:Indicator:{LABEL} {{indicator_type: 'domain', value: 'four.it.example', uuid: 'u-i4', active: true,
        several_actor_pulses: ['p6']}})
CREATE (i5:Indicator:{LABEL} {{indicator_type: 'domain', value: 'five.it.example', uuid: 'u-i5', active: true,
        pulse_malware_actor_pairs: ['crutch::turla::p6']}})
CREATE (i4)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: 'threatfox',
        source_refs: 'threatfox:9'}}]->(strmal2)
CREATE (i1)-[:INDICATES {{match_type: 'otx_pulse', confidence_score: 0.6}}]->(kaz)
CREATE (i2)-[:INDICATES {{match_type: 'otx_pulse', confidence_score: 0.6}}]->(ptero)
CREATE (i3)-[:INDICATES {{match_type: 'otx_pulse', confidence_score: 0.6}}]->(lb)
"""


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def client(raw_driver, monkeypatch):
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(FIXTURE)
    monkeypatch.setattr(build_relationships, "query_pause", lambda: None)
    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()


def _step_2d(client) -> dict:
    """Step 2d as ``build_relationships`` runs it: link, remove, trim."""
    reference = canonical_threat_actors.load_canonical_reference()
    several = build_relationships._reports_naming_several_actors(client, reference)
    params = build_relationships._attribution_params(several, reference)
    # The link statement also takes the ATT&CK software id pattern and the folded Malware names.
    link_params = {**params, **build_relationships._software_id_params(client)}
    stats: dict = {}
    assert build_relationships._safe_run_batched(
        client,
        "linked",
        assigned_query("_q2d_outer"),
        assigned_query("_q2d_inner"),
        stats,
        "linked",
        params=link_params,
    )
    assert build_relationships._remove_several_actor_attributions(client, stats, params)
    return {
        "several": several,
        "removed": stats["attributed_to_several_actor_pulses_removed"],
        "trimmed": stats["attributed_to_several_actor_pulses_trimmed"],
    }


def _attributions(driver) -> dict:
    with driver.session() as session:
        return {
            (r["m"], r["a"]): (sorted(r["refs"]) if r["refs"] is not None else None, r["report_ids"])
            for r in session.run(
                "MATCH (m:Malware)-[r:ATTRIBUTED_TO]->(a:ThreatActor) "
                "RETURN m.name AS m, a.name AS a, r.source_refs AS refs, r.report_ids AS report_ids"
            )
        }


def _acceptance(driver, several) -> dict:
    """The acceptance check ``attribution_from_single_actor_reports``, as the script runs it."""
    with driver.session() as session:
        row = session.run(
            canonical_threat_actors.ATTRIBUTION_CHECK_QUERY,
            several=several,
            otx_ref_prefix=canonical_threat_actors.OTX_REPORT_REF_PREFIX,
            feeds=list(canonical_threat_actors.REPORT_ATTRIBUTION_FEEDS),
        ).single()
        return dict(row)


def _campaign_refs(driver, actor: str = "turla") -> dict:
    """``source_refs`` of the campaign links of an actor's campaign."""
    with driver.session() as session:
        return {
            (r["n"], r["t"]): sorted(r["refs"] or [])
            for r in session.run(
                "MATCH (n)-[r:RUNS|PART_OF_CAMPAIGN]->(:Campaign {actor_name: $actor}) "
                "RETURN coalesce(n.name, n.value) AS n, type(r) AS t, r.source_refs AS refs",
                actor=actor,
            )
        }


def _runs(driver) -> set:
    with driver.session() as session:
        return {r["a"] for r in session.run("MATCH (a:ThreatActor)-[:RUNS]->(:Campaign) RETURN a.name AS a")}


def _campaign_malware(client, driver) -> set:
    enrichment_jobs.build_campaign_nodes(client)
    with driver.session() as session:
        session.run(f"MATCH (c:Campaign) SET c:{LABEL}")  # the suite removes only its own label
        return {
            (r["m"], r["c"])
            for r in session.run(
                "MATCH (m:Malware)-[:PART_OF_CAMPAIGN]->(c:Campaign) RETURN m.name AS m, c.actor_name AS c"
            )
        }


def test_step_2d_links_removes_and_trims_by_the_pulses_naming_several_actors(client, raw_driver):
    reference = canonical_threat_actors.load_canonical_reference()
    # The pulses naming several actors: p2 from the actor nodes, p6 from the indicator mark only.
    several = build_relationships._reports_naming_several_actors(client, reference)
    assert several == ["p2", "p6"], "p3 names two names of one actor; p6 is on no actor node"
    before = _campaign_malware(client, raw_driver)
    assert ("pterolnk", "turla") in before and ("kazuar", "gamaredon group") in before
    assert ("tinyturla", "turla") in before
    assert "alienvault_otx:p2" in _campaign_refs(raw_driver)[("turla", "RUNS")]
    assert "unc-it-test" in _runs(raw_driver)
    # An indicator path whose two links both hold a list as a plain string: two entries, never one
    # concatenated value.
    assert _campaign_refs(raw_driver, "gamaredon group")[("four.it.example", "PART_OF_CAMPAIGN")] == [
        "alienvault_otx:p2",
        "threatfox:9",
    ]
    # The acceptance check, by hand from the fixture: thirteen same-pulse links (the partner's is not
    # EdgeGuard's); six rest only on p2 or p6 (kazuar, pterolnk and strmal to gamaredon, pterolnk to
    # turla and to unc-it-test, tinyturla to turla), ten name one of them (strmal2 too), norefs names no
    # pulse.
    assert _acceptance(raw_driver, several) == {
        "links": 13,
        "resting_on_several_actor_reports": 6,
        "naming_several_actor_reports": 10,
        "without_reports": 1,
    }

    first = _step_2d(client)
    assert first["several"] == several
    assert (first["removed"], first["trimmed"]) == (6, 4)
    links = _attributions(raw_driver)
    # p2 names two groups: its attributions go, in both provenance forms; so does the link resting on
    # p6, which only the indicator mark shows to name several actors ...
    for gone in (
        ("kazuar", "gamaredon group"),
        ("pterolnk", "gamaredon group"),
        ("pterolnk", "turla"),
        ("pterolnk", "unc-it-test"),
        ("strmal", "gamaredon group"),
        ("tinyturla", "turla"),
    ):
        assert gone not in links, gone
    # ... and p6's pair on the indicator is not linked.
    assert ("crutch", "turla") not in links
    # A list stored as a string is trimmed as a one-entry list and written back as a list.
    assert links[("strmal2", "gamaredon group")] == ([], None)
    # The unmerged alias: 'loader::snake' is judged by snake's pulses (p2 only), so nothing links;
    # judged by Turla's (p1 too), it would have linked loader to Turla with no provenance.
    assert not any(m == "loader" for m, _a in links)
    # ... and leave the provenance of the links a pulse naming one actor supports (p1).
    assert links[("kazuar", "turla")] == (["alienvault_otx:p1"], None)
    # A pair with its pulse: linked to the canonical actor, the pair's pulse as provenance.
    assert links[("lockbit", "turla")] == (["alienvault_otx:p5"], None)
    # The older provenance form is trimmed too.
    assert links[("carbon", "turla")] == (None, ["p1"])
    # Kept: another feed asserts it (p2 dropped from its provenance), two names of one actor, no
    # pulse recorded, a partner's link.
    assert links[("lockbit", "gamaredon group")] == (["threatfox:1"], None)
    assert links[("gentlemen", "the gentlemen")] == (["alienvault_otx:p3"], None)
    assert links[("gentlemen", "storm-2697")] == (["alienvault_otx:p3"], None)
    assert links[("norefs", "gamaredon group")] == ([], None)
    assert links[("partner tool", "gamaredon group")] == (["alienvault_otx:p2"], None)

    second = _step_2d(client)
    # Nothing to remove the second time: the pairs written before whose recorded pulses all name
    # several actors are not linked again, and the pair carrying p2 is skipped.
    assert (second["removed"], second["trimmed"]) == (0, 0), "a second run changes nothing"
    assert _attributions(raw_driver) == links, "the pairs on the indicators bring nothing back"
    assert _acceptance(raw_driver, several) == {
        "links": 8,
        "resting_on_several_actor_reports": 0,
        "naming_several_actor_reports": 0,
        "without_reports": 3,
    }, "lockbit and strmal2 to gamaredon now name no pulse (ThreatFox asserts them); norefs names none"

    # Campaign membership follows: malware no longer attributed to an actor leaves its campaign.
    after = _campaign_malware(client, raw_driver)
    assert ("pterolnk", "turla") not in after and ("kazuar", "gamaredon group") not in after
    assert ("tinyturla", "turla") not in after
    assert ("kazuar", "turla") in after and ("lockbit", "gamaredon group") in after and ("lockbit", "turla") in after
    assert ("carbon", "turla") in after
    # An actor with no attribution left keeps no RUNS (its campaign retires).
    assert "unc-it-test" not in _runs(raw_driver) and "turla" in _runs(raw_driver)
    # ... and the campaign links name only the evidence that remains (replaced, not added to).
    refs = _campaign_refs(raw_driver)
    assert refs[("turla", "RUNS")] == ["alienvault_otx:p1", "alienvault_otx:p5"]
    assert refs[("kazuar", "PART_OF_CAMPAIGN")] == ["alienvault_otx:p1"]
    assert refs[("one.it.example", "PART_OF_CAMPAIGN")] == ["alienvault_otx:p1"]
