"""Feed family labels on a real Neo4j with APOC (2026-11-02): ``build_relationships`` step 9 and the acceptance
checks ``family_indicates_complete`` and ``attack_tool_named_malware``.

Step 9 links an indicator to the Malware nodes its feed's family label names. The labels are resolved once per
run (``family_resolution.resolve_feed_families``) into ``$family_targets``, keyed by the label as stored, and
the step finds each node by its name. This module stores Malware nodes, Tool nodes and indicators as the 730-day
graph of 2026-11-01 holds them (``tests/fixtures/feed_family_labels_2026_11_01.json``: the nodes' names, aliases
and sources, the indicators' values and their feeds' raw records), runs the step as production runs it (through
``_safe_run_batched`` and ``apoc.periodic.iterate``) and checks every link:

* an exact name (``Cobalt Strike`` → ``cobalt strike``, not the OTX spelling ``cobaltstrike``) and an alias
  (``Formbook`` → ``formbook`` and the ATT&CK node ``xloader``; ``Geodo`` → ``emotet``);
* a label found without separators (``SalatStealer`` → ``salat stealer``, ``Venom RAT`` → ``venomrat``);
* a label several nodes carry without separators (``CobaltStrike-Beacon``), a label that names no node
  (``IClickFix``) and a placeholder label (``Unknown Loader``, also where a node of that name exists): no link,
  and the skip statement counts the first two.

Then the acceptance statements and the acceptance script (``run_checks``, its statements sent to this database)
judge the graph before and after the step.

Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``, writes only
nodes labelled ``EdgeGuardIT``, refuses any other node.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from build_rel_queries import assigned_query  # noqa: E402
from neo4j import READ_ACCESS  # noqa: E402
from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import build_relationships  # noqa: E402
import family_resolution as fr  # noqa: E402
import graph_shape_checks as gsc  # noqa: E402
import neo4j_client  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

FIXTURE = json.loads((TESTS / "fixtures" / "feed_family_labels_2026_11_01.json").read_text(encoding="utf-8"))
SCRIPT = TESTS.parent / "scripts" / "verify_fresh_baseline.py"

STORED_MALWARE = (
    "salat stealer",
    "formbook",
    "xloader",
    "cobalt strike",
    "cobaltstrike",
    "cobalt strike beacon",
    "cobaltstrike beacon",
    "venomrat",
    "emotet",
    "asyncrat",
    "async rat",
)


def _record(family: str, source_id: str) -> Dict[str, Any]:
    row = next(r for r in FIXTURE["records"] if r["family_on_indicator"] == family and r["source_id"] == source_id)
    return json.loads(row["raw_data"])


def _indicators() -> List[Dict[str, Any]]:
    """The indicators: those of the 730-day graph with the feed record it holds (value from the sample, label
    and provenance from the record), and three with a label of the shape the graph meets (TEST-NET addresses)."""
    real = {
        ("SalatStealer", "threatfox"): ("00d323dbef92f11a94a71350ebd1b92e4fd3c8b6", "hash"),
        ("Formbook", "malwarebazaar"): ("0f4bdea083137db9fb14b677d019c8dc6c87f40ab76e46512afbe05bd6a4f76b", "hash"),
        ("Cobalt Strike", "threatfox"): ("1.15.65.4", "ipv4"),
        ("Venom RAT", "threatfox"): ("0e825537dc98505984e647da4b5d9354804e36eb34fae4293d6166a7bcc11301", "hash"),
        ("Unknown Loader", "threatfox"): ("0090e6f375af7b7115e17fac059cf7babe9140126dd5f15fd452feb488051999", "hash"),
        ("IClickFix", "threatfox"): ("11eventz.com", "domain"),
        ("Emotet", "feodo_tracker"): ("1.234.2.232", "ipv4"),
    }
    rows = []
    for (family, source_id), (value, kind) in real.items():
        raw = _record(family, source_id)
        rows.append(
            {
                "value": value,
                "indicator_type": kind,
                "uuid": f"u-{value}",
                "malware_family": raw["malware_family"],
                "source": [source_id],
                "source_refs": raw.get("source_refs") or [f"{source_id}:{value}"],
                "misp_event_ids": [raw["misp_event_id"]],
            }
        )
    for value, family in (("198.51.100.20", "Geodo"), ("198.51.100.21", "CobaltStrike-Beacon")):
        rows.append(
            {
                "value": value,
                "indicator_type": "ipv4",
                "uuid": f"u-{value}",
                "malware_family": family,
                "source": ["threatfox"],
                "source_refs": [f"threatfox:{value}"],
                "misp_event_ids": ["64"],
            }
        )
    return rows


SETUP = f"""
UNWIND ['threatfox', 'malwarebazaar', 'feodo_tracker', 'alienvault_otx', 'mitre_attck'] AS sid
CREATE (:Source:{LABEL} {{source_id: sid}})
WITH count(*) AS sources
UNWIND $malware AS m
CREATE (x:Malware:{LABEL}) SET x = m, x.uuid = 'u-' + m.name
WITH count(*) AS malware
UNWIND $tools AS t
CREATE (x:Tool:{LABEL}) SET x = t, x.uuid = 'u-' + t.mitre_id
WITH count(*) AS tools
UNWIND $indicators AS r
CREATE (i:Indicator:{LABEL} {{value: r.value, indicator_type: r.indicator_type, uuid: r.uuid,
        malware_family: r.malware_family, source: r.source}})
WITH i, r
MATCH (s:Source:{LABEL} {{source_id: r.source[0]}})
CREATE (i)-[:SOURCED_FROM {{source: r.source[0], source_refs: r.source_refs, misp_event_ids: r.misp_event_ids}}]->(s)
"""
# A node of a placeholder name from before the placeholder list held it, the OTX links of three indicators to the
# Malware nodes named after the ATT&CK Tool AsyncRAT, and an actor that uses one of them (a link, not an indicator).
LEGACY = f"""
CREATE (:Malware:{LABEL} {{name: 'unknown loader', uuid: 'u-unknown-loader', source: ['alienvault_otx']}})
WITH 1 AS one
MATCH (a:Malware:{LABEL} {{name: 'asyncrat'}}), (b:Malware:{LABEL} {{name: 'async rat'}})
CREATE (:ThreatActor:{LABEL} {{name: 'ta-test'}})-[:USES_MALWARE {{match_type: 'otx_pulse'}}]->(a)
CREATE (a)<-[:INDICATES {{match_type: 'otx_pulse', confidence_score: 0.6}}]-(:Indicator:{LABEL} {{value: '203.0.113.30', indicator_type: 'ipv4'}})
CREATE (a)<-[:INDICATES {{match_type: 'otx_pulse', confidence_score: 0.6}}]-(:Indicator:{LABEL} {{value: '203.0.113.31', indicator_type: 'ipv4'}})
CREATE (b)<-[:INDICATES {{match_type: 'otx_pulse', confidence_score: 0.6}}]-(:Indicator:{LABEL} {{value: '203.0.113.32', indicator_type: 'ipv4'}})
"""

EXPECTED_LINKS = {
    ("00d323dbef92f11a94a71350ebd1b92e4fd3c8b6", "salat stealer"),
    ("0f4bdea083137db9fb14b677d019c8dc6c87f40ab76e46512afbe05bd6a4f76b", "formbook"),
    ("0f4bdea083137db9fb14b677d019c8dc6c87f40ab76e46512afbe05bd6a4f76b", "xloader"),
    ("1.15.65.4", "cobalt strike"),
    ("0e825537dc98505984e647da4b5d9354804e36eb34fae4293d6166a7bcc11301", "venomrat"),
    ("1.234.2.232", "emotet"),
    ("198.51.100.20", "emotet"),
}


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def graph(raw_driver):
    malware = [{k: v for k, v in m.items() if v is not None} for m in FIXTURE["malware"] if m["name"] in STORED_MALWARE]
    assert sorted(m["name"] for m in malware) == sorted(STORED_MALWARE)
    tools = [t for t in FIXTURE["tools"] if t["name"] == "AsyncRAT"]
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(SETUP, malware=malware, tools=tools, indicators=_indicators())
        session.run(LEGACY)
    yield raw_driver
    with raw_driver.session() as session:
        foreign = session.run(f"MATCH (n) WHERE NOT n:{LABEL} RETURN count(n) AS c").single()["c"]
    assert foreign == 0, "the test wrote a node without the test label"


@pytest.fixture
def client(graph):
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()


def _rows(driver, statement: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    with driver.session(default_access_mode=READ_ACCESS) as session:
        return session.execute_read(lambda tx: [r.data() for r in tx.run(statement, params or {})])


def _step_9(client) -> Dict[str, Any]:
    stats: Dict[str, Any] = {}
    params = build_relationships._family_target_params(client)
    assert params is not None
    ok = build_relationships._safe_run_batched(
        client,
        "Indicator → Malware (family match)",
        assigned_query("_q9_outer"),
        assigned_query("_q9_inner"),
        stats,
        "indicates_family",
        skip_query=assigned_query("_q9_skip"),
        params=params,
    )
    assert ok
    return {"stats": stats, "params": params, "skip": client.run(assigned_query("_q9_skip"), params)[0]["c"]}


def _family_links(driver) -> Dict[tuple, Dict[str, Any]]:
    rows = _rows(
        driver,
        f"MATCH (i:Indicator:{LABEL})-[r:INDICATES]->(m:Malware:{LABEL}) WHERE r.match_type = 'malware_family' "
        "RETURN i.value AS ioc, m.name AS malware, r.confidence_score AS confidence, r.sources AS sources, "
        "r.source_refs AS refs, r.misp_event_ids AS events, r.src_uuid AS src, r.trg_uuid AS trg",
    )
    return {(r["ioc"], r["malware"]): r for r in rows}


def test_step_9_links_each_label_to_the_nodes_it_names(client, graph):
    run = _step_9(client)
    links = _family_links(graph)
    assert set(links) == EXPECTED_LINKS
    salat = links[("00d323dbef92f11a94a71350ebd1b92e4fd3c8b6", "salat stealer")]
    raw = _record("SalatStealer", "threatfox")
    assert salat == {
        "ioc": "00d323dbef92f11a94a71350ebd1b92e4fd3c8b6",
        "malware": "salat stealer",
        "confidence": 0.8,
        "sources": ["threatfox"],
        "refs": raw["source_refs"],
        "events": [raw["misp_event_id"]],
        "src": "u-00d323dbef92f11a94a71350ebd1b92e4fd3c8b6",
        "trg": "u-salat stealer",
    }
    assert links[("1.234.2.232", "emotet")]["sources"] == ["feodo_tracker"]
    assert links[("0f4bdea083137db9fb14b677d019c8dc6c87f40ab76e46512afbe05bd6a4f76b", "xloader")]["sources"] == [
        "malwarebazaar"
    ]
    # the outer rows leave the placeholder label out; IClickFix and CobaltStrike-Beacon have no entry
    assert run["stats"]["indicates_family"] == 8
    assert run["skip"] == 2
    # no link of any kind to the OTX spelling, the ambiguous pair or the placeholder node
    others = _rows(
        graph,
        f"MATCH (:Indicator:{LABEL})-[r:INDICATES]->(m:Malware:{LABEL}) "
        "WHERE m.name IN ['cobaltstrike', 'cobalt strike beacon', 'cobaltstrike beacon', 'unknown loader'] "
        "RETURN count(r) AS c",
    )
    assert others == [{"c": 0}]
    # a second run changes nothing
    _step_9(client)
    assert _family_links(graph) == links


def test_the_acceptance_statement_counts_the_links_step_9_must_write(client, graph):
    labels = [r["family"] for r in _rows(graph, fr.CYPHER_FEED_FAMILIES_READ)]
    resolution = fr.resolve_feed_families(labels, _rows(graph, fr.CYPHER_MALWARE_NAMES_READ))
    params = {"family_targets": resolution.targets}

    def row() -> Dict[str, Any]:
        (r,) = _rows(graph, gsc.FAMILY_INDICATES_COMPLETE_QUERY, params)
        return dict(r, examples=sorted(r["examples"]))

    before = row()
    assert (before["mapped_families"], before["mapped_indicators"], before["claims_with_target"]) == (6, 6, 7)
    assert before["edge_missing"] == 7 and gsc.family_indicates_verdict(before) is False

    _step_9(client)
    after = row()
    assert after == dict(before, edge_missing=0, examples=[]) and gsc.family_indicates_verdict(after) is True

    # a link step 9 relabelled away, then a deleted one: each is a missing link
    with graph.session() as session:
        session.run(
            f"MATCH (:Indicator:{LABEL} {{value: '1.15.65.4'}})-[r:INDICATES]->() SET r.match_type = 'otx_pulse'"
        )
    assert row() == dict(before, edge_missing=1, examples=["1.15.65.4 -> cobalt strike"])
    with graph.session() as session:
        session.run(f"MATCH (:Indicator:{LABEL} {{value: '198.51.100.20'}})-[r:INDICATES]->() DELETE r")
    assert row() == dict(before, edge_missing=2, examples=["1.15.65.4 -> cobalt strike", "198.51.100.20 -> emotet"])

    # no label names a node: nothing judged
    (empty,) = _rows(graph, gsc.FAMILY_INDICATES_COMPLETE_QUERY, {"family_targets": {}})
    assert empty == {
        "mapped_families": 0,
        "mapped_indicators": 0,
        "claims_with_target": 0,
        "edge_missing": 0,
        "examples": [],
    }
    assert gsc.family_indicates_verdict(empty) is None


def test_the_tool_statements_count_the_indicators_of_the_malware_named_after_a_tool(graph):
    pairs = fr.tool_named_malware(_rows(graph, fr.CYPHER_MALWARE_NAMES_READ), _rows(graph, gsc.TOOL_NAMES_READ))
    assert pairs == [
        {"malware": "async rat", "tool": "AsyncRAT", "tool_id": "S1087", "exact_name": False},
        {"malware": "asyncrat", "tool": "AsyncRAT", "tool_id": "S1087", "exact_name": True},
    ]
    counts = _rows(graph, gsc.MALWARE_INDICATES_COUNTS_QUERY, {"names": ["async rat", "asyncrat", "no such node"]})
    assert sorted((r["name"], r["indicates"]) for r in counts) == [("async rat", 1), ("asyncrat", 2)]


def _script():
    spec = importlib.util.spec_from_file_location("verify_fresh_baseline_feed_family", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_acceptance_script_judges_step_9(client, graph, monkeypatch):
    vfb = _script()
    monkeypatch.setattr(vfb, "_post", lambda statement, params=None, timeout=180: _rows(graph, statement, params))

    def checks() -> Dict[str, Dict[str, Any]]:
        return {c["check"]: c for c in vfb.run_checks(False, False, False, False).checks}

    before = checks()["family_indicates_complete"]
    assert before["ok"] is False and before["detail"]["edge_missing"] == 7
    _step_9(client)
    result = checks()
    family = result["family_indicates_complete"]
    assert family["ok"] is True and family["mandatory"] is True
    detail = family["detail"]
    assert {k: detail[k] for k in ("claims", "target_missing", "placeholder_indicators", "claims_with_target")} == {
        "claims": 8,
        "target_missing": 2,
        "placeholder_indicators": 1,
        "claims_with_target": 7,
    }
    assert detail["unresolved"] == {"IClickFix": 1}
    assert detail["ambiguous"] == {
        "CobaltStrike-Beacon": {"indicators": 1, "nodes": ["cobalt strike beacon", "cobaltstrike beacon"]}
    }
    assert detail["separator_free_matches"] == {"SalatStealer": "salat stealer", "Venom RAT": "venomrat"}
    tools = result["attack_tool_named_malware"]
    assert tools["ok"] is None
    assert {k: tools["detail"][k] for k in ("nodes", "indicates", "exact_name_nodes", "exact_name_indicates")} == {
        "nodes": 2,
        "indicates": 3,
        "exact_name_nodes": 1,
        "exact_name_indicates": 2,
    }
