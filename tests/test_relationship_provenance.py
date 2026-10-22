"""Relationship provenance contract (2026-10): who asserts a link, which record, which MISP event.

Every relationship EdgeGuard builds from the sources carries ``r.sources`` (canonical
source ids), ``r.source_refs`` (``"<source>:<record id>"``) and ``r.misp_event_ids``; each
write adds to the lists and never replaces them. Before this change, relationships held a
single ``r.source_id`` (last writer wins) whose values were evidence names (``otx_pulse``,
``malware_family_match``, ``cve_tag_match``) or the hub ``misp``: on the 730-day graph of
2026-10-14 no relationship named ThreatFox, URLhaus, NVD or Feodo Tracker, and the
1.6 million technique, malware and tool links carried no source at all.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-relationship-provenance")
os.environ.setdefault("MISP_API_KEY", "test-key-relationship-provenance")

import build_relationships  # noqa: E402
import enrichment_jobs  # noqa: E402
import relationship_provenance as rp  # noqa: E402
import source_registry  # noqa: E402
from neo4j_client import Neo4jClient  # noqa: E402
from run_misp_to_neo4j import (  # noqa: E402
    _REPORT_SCOPED_SOURCE_ID,
    MISPToNeo4jSync,
    _dedupe_parsed_items,
    _item_source_refs,
)


# --------------------------------------------------------------------------- fakes
class _FakeSession:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, *args, **kwargs):
        params = dict(args[0]) if args and isinstance(args[0], dict) else {}
        params.update({k: v for k, v in kwargs.items() if k != "timeout"})
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = {"count": len(params.get("rows") or [])}
        return result


def _client_with_fake_driver():
    calls: list = []
    client = Neo4jClient.__new__(Neo4jClient)
    driver = MagicMock()
    driver.session.side_effect = lambda **kw: _FakeSession(calls)
    client.driver = driver
    return client, calls


def _render_build_steps(monkeypatch):
    """Every build_relationships step as (label, outer, inner), without a database."""
    captured = []

    class _Client:
        def connect(self):
            return True

        def close(self):
            pass

        def run(self, query, **kw):
            return [{"count": 0, "c": 0}]

    def _batched(client, label, outer, inner, stats, key, batch_size=5000, skip_query=None, params=None):
        captured.append((label, outer, inner))
        return True

    monkeypatch.setattr(build_relationships, "Neo4jClient", _Client)
    monkeypatch.setattr(build_relationships, "_safe_run_batched", _batched)
    monkeypatch.setattr(build_relationships, "query_pause", lambda: None)
    build_relationships.build_relationships()
    return captured


def _render_campaign_statements(monkeypatch):
    """Every statement ``build_campaign_nodes`` sends, rendered, without a database."""
    statements = []

    def run(query, *args, **kwargs):
        statements.append(query)
        result = MagicMock()
        result.single.return_value = {
            "campaigns": 0,
            "backfilled": 0,
            "deleted": 0,
            "names": [],
            "links": 0,
            "removed": 0,
            "pruned": 0,
            "count": 0,
        }
        result.__iter__ = lambda _self: iter([])
        return result

    session = MagicMock()
    session.run = run
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *a: False
    client = MagicMock()
    client.driver.session.return_value = session
    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    enrichment_jobs.build_campaign_nodes(client)
    return statements


# --------------------------------------------------------------------------- registry
class TestRegistry:
    def test_curated_sources_are_registered_without_a_cli_id(self):
        for sid, tag in (("coreideas", "source:CoreIdeas"), ("misp_galaxy", "source:MISP-Galaxy")):
            src = source_registry.get_source(sid)
            assert src is not None, sid
            assert src.source_type == "curated"
            assert src.cli_id is None, "a curated package is imported once, not polled by a collector"
            assert src.misp_tag == tag
            assert src.reliable_first_seen is False

    @pytest.mark.parametrize(
        "name, expected",
        [
            ("otx", "alienvault_otx"),
            ("feodo", "feodo_tracker"),
            ("SSLBL", "ssl_blacklist"),
            ("mitre_attck", "mitre_attck"),
            (" Some-New-Feed ", "some-new-feed"),  # unknown names are kept, normalised
            ("", None),
            (None, None),
        ],
    )
    def test_canonical_source_id(self, name, expected):
        assert source_registry.canonical_source_id(name) == expected

    def test_format_source_ref(self):
        assert source_registry.format_source_ref("otx", " 5f3c ") == "alienvault_otx:5f3c"
        assert source_registry.format_source_ref("mitre", "G0016") == "mitre_attck:G0016"
        assert source_registry.format_source_ref("threatfox", 1234567) == "threatfox:1234567"
        assert source_registry.format_source_ref("threatfox", "") is None
        assert source_registry.format_source_ref("threatfox", None) is None
        assert source_registry.format_source_ref("", "x") is None
        assert len(source_registry.format_source_ref("urlhaus", "9" * 500)) == len("urlhaus:") + 200

    def test_sync_tag_mapping_is_derived_from_the_registry(self):
        mapping = source_registry.misp_tag_to_canonical_map()
        assert MISPToNeo4jSync.SOURCE_MAPPING == mapping
        assert mapping["CoreIdeas"] == "coreideas"
        assert mapping["MISP-Galaxy"] == "misp_galaxy"
        assert mapping["ThreatFox"] == "threatfox"
        assert mapping["Feodo-Tracker"] == "feodo_tracker"


# --------------------------------------------------------------------------- sync rows
class TestSyncStampsFeedAndRecord:
    @pytest.mark.parametrize(
        "item, source, expected",
        [
            (
                {"pulse_id": "P1", "report_ids": ["P2", "P1"]},
                "alienvault_otx",
                ["alienvault_otx:P1", "alienvault_otx:P2"],
            ),
            ({"ioc_id": "1234567"}, "threatfox", ["threatfox:1234567"]),
            ({"reference": "https://urlhaus.abuse.ch/url/3374851/"}, "urlhaus", ["urlhaus:3374851"]),
            ({"reference": "https://example.org/other"}, "urlhaus", []),
            ({"mitre_id": "G0016"}, "mitre_attck", ["mitre_attck:G0016"]),
            ({"cve_id": "CVE-2024-1"}, "nvd", []),  # keyed by the value itself: the node is the record
            ({"value": "1.2.3.4"}, "feodo_tracker", []),
        ],
    )
    def test_item_source_refs(self, item, source, expected):
        assert _item_source_refs(item, source) == expected

    def test_parsed_attribute_rows_carry_the_attribute_feed_and_record(self):
        sync = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
        item = {"type": "indicator", "value": "1.2.3.4", "tag": "threatfox", "ioc_id": "77"}
        rows = [{"rel_type": "INDICATES"}, {"rel_type": "TARGETS", "source": "nvd"}]
        out_item, out_rows = sync._with_provenance(item, rows)
        assert out_item["source_refs"] == ["threatfox:77"]
        assert out_rows[0]["source"] == "threatfox" and out_rows[0]["source_refs"] == ["threatfox:77"]
        assert out_rows[1]["source"] == "nvd", "a row that already names its feed keeps it"

    def test_unknown_tag_falls_back_to_misp(self):
        sync = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
        _, rows = sync._with_provenance({"type": "indicator", "value": "x"}, [{"rel_type": "TARGETS"}])
        assert rows[0]["source"] == "misp"
        assert "source_refs" not in rows[0]

    def test_report_rows_name_otx_and_the_pulse_zone_rows_the_item_feed(self):
        assert _REPORT_SCOPED_SOURCE_ID == "alienvault_otx", "a feed, not the evidence label otx_pulse"
        sync = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
        items = [
            {
                "type": "indicator",
                "indicator_type": "ipv4",
                "value": "1.2.3.4",
                "pulse_id": "P1",
                "tag": "alienvault_otx",
                "misp_event_id": "9",
                "source_refs": ["alienvault_otx:P1"],
            },
            {"type": "malware", "name": "emotet", "pulse_id": "P1", "tag": "alienvault_otx", "misp_event_id": "9"},
            {
                "type": "indicator",
                "indicator_type": "url",
                "value": "http://x",
                "zone": ["energy"],
                "tag": "urlhaus",
                "misp_event_id": "9",
                "source_refs": ["urlhaus:55"],
            },
        ]
        rels = sync._build_cross_item_relationships(items)
        indicates = [r for r in rels if r["rel_type"] == "INDICATES"]
        assert indicates and all(r["source"] == "alienvault_otx" for r in indicates)
        assert all(r["source_refs"] == ["alienvault_otx:P1"] for r in indicates)
        targets = [r for r in rels if r["rel_type"] == "TARGETS"]
        assert targets and targets[0]["source"] == "urlhaus" and targets[0]["source_refs"] == ["urlhaus:55"]

    def test_dedupe_keeps_every_record_of_the_duplicates(self):
        items = [
            {
                "type": "indicator",
                "indicator_type": "ipv4",
                "value": "1.2.3.4",
                "tag": "alienvault_otx",
                "pulse_id": "P1",
                "source_refs": ["alienvault_otx:P1"],
            },
            {
                "type": "indicator",
                "indicator_type": "ipv4",
                "value": "1.2.3.4",
                "tag": "alienvault_otx",
                "pulse_id": "P2",
                "source_refs": ["alienvault_otx:P2"],
            },
        ]
        kept = _dedupe_parsed_items(items)
        assert len(kept) == 1
        assert kept[0]["source_refs"] == ["alienvault_otx:P1", "alienvault_otx:P2"]


# --------------------------------------------------------------------------- writers
class TestWriters:
    def test_batch_writer_accumulates_feed_refs_and_events_never_a_single_source_id(self):
        client, calls = _client_with_fake_driver()
        rows = [
            {
                "rel_type": "INDICATES",
                "from_type": "Indicator",
                "from_key": {"value": "1.2.3.4", "indicator_type": "ipv4"},
                "to_type": "Malware",
                "to_key": {"name": "emotet"},
                "source": "otx",
                "source_refs": ["alienvault_otx:P1"],
                "misp_event_id": "9",
                "match_type": "otx_pulse",
            },
            {
                "rel_type": "TARGETS",
                "from_type": "Indicator",
                "from_key": {"value": "1.2.3.4", "indicator_type": "ipv4"},
                "to_type": "Sector",
                "to_key": {"name": "energy"},
                "match_type": "zone_classification",
            },
        ]
        client.create_misp_relationships_batch(rows, source_id="misp")
        assert calls, "the batch writer ran no query"
        for query, _params in calls:
            assert "r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source])" in query
            assert (
                "r.source_refs = apoc.coll.toSet(coalesce(r.source_refs, []) + coalesce(row.source_refs, []))" in query
            )
            assert "r.misp_event_ids" in query
            assert "r.source_id" not in query and "r.report_ids" not in query
        sent = [row for _, params in calls for row in params.get("rows", [])]
        assert any(r["source"] == "alienvault_otx" and r["source_refs"] == ["alienvault_otx:P1"] for r in sent), sent
        assert any(r["source"] == "misp" and r["source_refs"] == [] for r in sent), (
            "a row without a feed uses the batch's"
        )

    def test_single_writers_canonicalise_the_feed_and_drop_source_id(self):
        client, calls = _client_with_fake_driver()
        client.create_actor_technique_relationship("apt29", "T1566", source_id="mitre")
        client.create_malware_actor_relationship("m", "a", source_id="mitre_derived")
        for query, params in calls:
            assert "r.source_id" not in query
            assert params["source_id"] == "mitre_attck", "mitre_derived names a method, the feed is MITRE ATT&CK"
        assert calls[1][1]["match_type"] == "mitre_derived"

    def test_sourced_from_edge_keeps_per_source_events_and_records(self):
        client, calls = _client_with_fake_driver()
        client._upsert_sourced_relationship(
            "Indicator",
            {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "threatfox",
            "{}",
            0.7,
            misp_event_id=12,
            source_refs=["threatfox:77", None],
        )
        query, params = calls[0]
        assert "r.misp_event_ids = apoc.coll.toSet(coalesce(r.misp_event_ids, [])" in query
        assert "r.source_refs = apoc.coll.toSet(coalesce(r.source_refs, []) + coalesce($source_refs, []))" in query
        assert params["misp_event_id"] == "12" and params["source_refs"] == ["threatfox:77"]

    def test_cvss_edges_name_the_feed(self):
        client, calls = _client_with_fake_driver()
        client._merge_cvss_node("CVE-2024-1", "nvd", "CVSSv31", "HAS_CVSS_v31", {"base_score": 9.8}, misp_event_id="13")
        query, params = calls[0]
        assert "r1.sources" in query and "r2.sources" in query and "r1.misp_event_ids" in query
        assert params["feed"] == "nvd" and params["misp_event_id"] == "13"


# --------------------------------------------------------------------------- build steps
class TestBuildSteps:
    def test_every_step_writes_all_three_lists(self, monkeypatch):
        steps = _render_build_steps(monkeypatch)
        assert len(steps) == 20
        for label, _outer, inner in steps:
            assert ".sources = apoc.coll.toSet(" in inner, label
            assert ".source_refs = apoc.coll.toSet(" in inner, label
            assert ".misp_event_ids = apoc.coll.toSet(" in inner, label
            assert "source_id =" not in inner and "source_ids" not in inner, label
            assert "'" not in inner, f"{label}: inner queries run inside single quotes in apoc.periodic.iterate"

    def test_steps_name_the_feed_that_asserts_them(self, monkeypatch):
        steps = {label: inner for label, _o, inner in _render_build_steps(monkeypatch)}
        mitre = [
            k
            for k in steps
            if "MITRE explicit" in k
            or "ATT&CK explicit" in k
            or "USES_MALWARE" in k
            or "USES_TOOL" in k
            or "SUBTECHNIQUE_OF" in k
            or k == "Technique → Tactic"
        ]
        otx = [k for k in steps if "reported" in k or "attack_ids" in k or "same pulse" in k]
        assert len(mitre) == 7 and len(otx) == 5, (mitre, otx)
        for k in mitre:
            assert '["mitre_attck"] AS _feeds' in steps[k], k
        for k in otx:
            assert '["alienvault_otx"]' in steps[k] and "AS _feeds" in steps[k], k
        assert rp.FAMILY_LABEL_FEEDS in steps["Indicator → Malware (family match)"]
        for k in ("Indicator → Vulnerability (EXPLOITS)", "Indicator → CVE (EXPLOITS)", "Malware → ThreatActor"):
            assert "i.source" in steps[k] or "m.source" in steps[k], k

    def test_event_cap_matches_the_build_constant(self):
        assert rp.MAX_EVENT_IDS_PER_EDGE == build_relationships.CRITICAL_MAX_EVENT_IDS_PER_EDGE

    def test_fragments_use_double_quotes_only(self):
        for fragment in (
            rp.prov_with("a", rp.MITRE_FEEDS),
            rp.prov_with("i", rp.family_feeds("i")),
            rp.prov_set("r"),
            rp.inherited_prov_set("r", ["_ind", "_at"]),
            rp.aggregated_prov_set("r_runs", "(a)<-[_at:ATTRIBUTED_TO]-(:Malware)", "_at"),
            rp.inherited_prov_set("r", ["_at"], replace=True),
            rp.aggregated_prov_set("r", "(i)-[_xi:INDICATES]->(:Malware)", ["_xi"], replace=True),
        ):
            assert "'" not in fragment

    def test_replace_assigns_the_source_links_provenance(self):
        # 2026-10: a derived link follows the removal and trimming of the links it rests on.
        added = rp.inherited_prov_set("r", ["_at"])
        assert (
            "r.source_refs = " + rp.sorted_set("coalesce(r.source_refs, []) + coalesce(_at.source_refs, [])") in added
        )
        replaced = rp.inherited_prov_set("r", ["_at"], replace=True)
        # ``[] +`` keeps a list when the source link holds a plain string
        assert "r.source_refs = " + rp.sorted_set("[] + coalesce(_at.source_refs, [])") in replaced
        assert "coalesce(r." not in replaced
        pattern = "(i)-[_xi:INDICATES]->(:Malware)-[_xa:ATTRIBUTED_TO]->(:ThreatActor)"
        agg = rp.aggregated_prov_set("r", pattern, ["_xi", "_xa"], max_events=7, replace=True)
        assert (
            "r.source_refs = "
            + rp.sorted_set(
                "reduce(_acc = [], _x IN "
                f"[{pattern} | [] + coalesce(_xi.source_refs, []) + coalesce(_xa.source_refs, [])] | _acc + _x)"
            )
        ) in agg, "every operand a list element: two plain strings never concatenate"
        assert agg.endswith("[0..7]][0]") and "coalesce(r." not in agg
        # the default keeps the accumulating form: the stored lists are part of the union
        union = "[(a)<-[_at:ATTRIBUTED_TO]-(:Malware) | coalesce(_at.{f}, [])] | _acc + _x)"
        assert rp.aggregated_prov_set("r_runs", "(a)<-[_at:ATTRIBUTED_TO]-(:Malware)", "_at") == (
            "r_runs.sources = "
            + rp.sorted_set("coalesce(r_runs.sources, []) + reduce(_acc = [], _x IN " + union.format(f="sources"))
            + ", r_runs.source_refs = "
            + rp.sorted_set(
                "coalesce(r_runs.source_refs, []) + reduce(_acc = [], _x IN " + union.format(f="source_refs")
            )
            + ", r_runs.misp_event_ids = "
            + rp.capped_event_ids(
                "coalesce(r_runs.misp_event_ids, []) + reduce(_acc = [], _x IN " + union.format(f="misp_event_ids"),
                rp.MAX_EVENT_IDS_PER_EDGE,
            )
        )

    def test_lists_and_the_event_cap_follow_a_fixed_order(self):
        """2026-10-16: the union of the links' lists was cut unsorted (``apoc.coll.toSet(...)[0..200]``),
        so which events a campaign link kept followed the order in which its links were created. The
        lists are now sorted and the events are the newest ``N`` by numeric id (checked on a real
        Neo4j in tests/test_explainability_neo4j.py)."""
        assert rp.sorted_set("x") == "apoc.coll.sort(apoc.coll.toSet([_sv IN x WHERE _sv IS NOT NULL | toString(_sv)]))"
        capped = rp.capped_event_ids("x", 5)
        assert capped.startswith("[_ids IN [apoc.coll.toSet([_ei IN x WHERE _ei IS NOT NULL | toString(_ei)])] | ")
        assert "reverse(apoc.coll.sort(apoc.coll.toSet([_ei IN _ids WHERE toInteger(_ei) IS NOT NULL" in capped
        assert "+ apoc.coll.sort([_ei IN _ids WHERE toInteger(_ei) IS NULL]))[0..5]][0]" in capped
        for fragment in (
            rp.inherited_prov_set("r", ["_at"], replace=True),
            rp.inherited_prov_set("r", ["_at"]),
            rp.aggregated_prov_set("r", "_e IN links", "_e", replace=True),
            rp.aggregated_prov_set("r", "_e IN links", "_e"),
        ):
            assert ".sources = apoc.coll.sort(" in fragment and ".source_refs = apoc.coll.sort(" in fragment
            assert ".misp_event_ids = [_ids IN " in fragment
            assert "[0..200]][0]" in fragment and "))[0..200]," not in fragment


# --------------------------------------------------------------------------- enrichment
class TestEnrichment:
    def test_campaign_and_bridge_links_inherit_provenance(self):
        src = Path(enrichment_jobs.__file__).read_text()
        # 2026-10: replaced on every run, so campaign links name no evidence step 2d removed or trimmed;
        # 2026-10-16: from the links the campaign rests on (ATTRIBUTED_TO and USES_MALWARE), collected
        # once per link (RUNS: the actor's; a malware member: its own; an indicator: every path's).
        assert 'aggregated_prov_set(rel_var, f"_e IN {links}", "_e", replace=True)' in src
        assert '_links_evidence("r_runs", "actor_evidence")' in src
        assert '_links_evidence("r", "member_evidence")' in src
        assert 'aggregated_prov_set("r", "_p IN _paths", ["_p[0]", "_p[1]"], replace=True)' in src
        assert 'prov_with("v", node_feeds("v"))' in src
        # The list form renders as a list comprehension over the collected links.
        rendered = rp.aggregated_prov_set("r", "_p IN _paths", ["_p[0]", "_p[1]"], replace=True)
        assert (
            "r.sources = "
            + rp.sorted_set(
                "reduce(_acc = [], _x IN [_p IN _paths | "
                "[] + coalesce(_p[0].sources, []) + coalesce(_p[1].sources, [])] | _acc + _x)"
            )
        ) in rendered

    def test_campaign_links_state_their_evidence(self):
        """2026-10-15: RUNS / PART_OF_CAMPAIGN say they are EdgeGuard's grouping and carry the
        confidence of the evidence they rest on; 2026-10-16: and the relationship types it is made of
        (run on a real Neo4j in tests/test_explainability_neo4j.py)."""
        import campaign_evidence

        assert enrichment_jobs.CAMPAIGN_MATCH_TYPE == "campaign_grouping"
        src = Path(enrichment_jobs.__file__).read_text()
        body = src.split("def build_campaign_nodes")[1].split("\ndef ")[0]
        assert "__CAMPAIGN_EVIDENCE__" in body and 'quote="\'"' in body
        weaker = enrichment_jobs._weaker("x", "y")
        assert weaker == "CASE WHEN x IS NULL THEN y WHEN y IS NULL THEN x WHEN x < y THEN x ELSE y END"
        strongest = enrichment_jobs._strongest("[1, null, 3]")
        assert strongest.startswith("reduce(_best = null, _v IN [1, null, 3] |")
        inner = enrichment_jobs._campaign_evidence("r", "0.5", "t", quote="'")
        assert inner == "r.match_type = 'campaign_grouping', r.confidence_score = 0.5, r.evidence_types = t"
        assert '"' not in inner
        links = enrichment_jobs._links_evidence("r_runs", "actor_evidence")
        assert links.startswith(
            'r_runs.match_type = "campaign_grouping", r_runs.confidence_score = '
            "reduce(_best = null, _v IN [_e IN actor_evidence | _e.confidence_score] |"
        )
        assert "r_runs.evidence_types = " + campaign_evidence.evidence_types("actor_evidence") in links
        assert (
            "r_runs.sources = apoc.coll.sort(apoc.coll.toSet([_sv IN reduce(_acc = [], _x IN [_e IN actor_evidence |"
            in links
        )
        assert campaign_evidence.evidence_types("x") == "apoc.coll.sort(apoc.coll.toSet([_et IN x | type(_et)]))"

    def test_campaigns_and_their_links_carry_the_evidence_tlp(self, monkeypatch):
        """2026-10: a campaign and its links are as restricted as the links they rest on. The builder
        copied a curated claim's provenance onto RUNS / PART_OF_CAMPAIGN but not its ``r.tlp``, and the
        STIX export marked them TLP:WHITE. The levels are checked on a real Neo4j
        (tests/test_explainability_neo4j.py); here, the statements the builder sends."""
        # The fragment also runs inside the double-quoted inner statement of apoc.periodic.iterate.
        assert '"' not in enrichment_jobs._links_tlp("L")
        # A campaign link's SET items carry its level with its provenance.
        assert "r_runs.tlp = " in enrichment_jobs._links_evidence("r_runs", "actor_evidence")
        statements = _render_campaign_statements(monkeypatch)

        def one(*markers):
            (found,) = [s for s in statements if all(m in s for m in markers)]
            return found

        create = one("MERGE (c:Campaign")  # Step 1
        members = one("MERGE (m)-[r:PART_OF_CAMPAIGN]->(c)")  # Step 2
        settle = one("MATCH (a:ThreatActor)-[r_runs:RUNS]->(c:Campaign)")  # Step 2c
        indicators = one("apoc.periodic.iterate", "MERGE (i)-[r:PART_OF_CAMPAIGN]->(c)")  # Step 3a
        # Step 1 and Step 2c (which also reaches a campaign without an active indicator) set the
        # campaign's and the RUNS level, Step 2 a malware's link, Step 3a an indicator's.
        for statement, items in (
            (create, ("c.tlp = ", "r_runs.tlp = ")),
            (settle, ("c.tlp = ", "r_runs.tlp = ")),
            (members, ("r.tlp = ",)),
            (indicators, ("r.tlp = ",)),
        ):
            for item in items:
                assert item in statement, item
        # Step 3a: every placeholder is filled, and the inner statement holds no double quote of its own
        # (the call's two statements are its only double-quoted strings).
        assert re.search(r"__[A-Z_]+__", indicators) is None
        assert indicators.count('"') == 4
        # Step 2c stamps a level it changes before the items that change it: the items of a SET apply in
        # order, so the stamps compare the levels from before the run.
        stamps = max(settle.index("r_runs.updated_at = CASE WHEN"), settle.index("c.last_updated = CASE WHEN"))
        assert stamps < settle.index("r_runs.tlp = ") and stamps < settle.index("c.tlp = ")

    def test_alias_merge_keeps_lists_as_lists(self):
        node_props = enrichment_jobs._ACTOR_ALIAS_MERGE_LIST_PROPS
        edge_props = enrichment_jobs._ACTOR_ALIAS_MERGE_EDGE_LIST_PROPS
        assert {"zone", "source", "misp_event_ids", "aliases"} <= set(node_props)
        # 2026-10 (explainability): ``cited_ids`` is an edge provenance list as well; 2026-10-16 (sector
        # evidence): so are the zone lists of a SOURCED_FROM edge
        assert set(edge_props) == {
            "sources",
            "source_refs",
            "misp_event_ids",
            "cited_ids",
            "zones",
            "stated_zones",
            "stated_refs",
        }
        assert "source_ids" not in enrichment_jobs._ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY
        cypher = enrichment_jobs._ACTOR_ALIAS_MERGE_NORMALISE_CYPHER
        node_part, edge_part = cypher.split("MATCH (c)-[r]-()")
        for p in node_props:
            assert f"c.{p} = CASE WHEN c.{p} IS NULL THEN NULL" in node_part
        for p in edge_props:
            assert f"r.{p} = CASE WHEN r.{p} IS NULL THEN NULL" in edge_part
        assert 'STARTS WITH "LIST"' in cypher and "ELSE [c.zone] END" in cypher

    def test_alias_merge_leaves_the_scalar_sourced_from_source_alone(self):
        # ``r.source`` on a SOURCED_FROM edge is the scalar source id; wrapping it into a list
        # would make every ``r.source = 'nvd'`` reader miss the edge (review finding on #175).
        edge_part = enrichment_jobs._ACTOR_ALIAS_MERGE_NORMALISE_CYPHER.split("MATCH (c)-[r]-()")[1]
        assert "r.source =" not in edge_part and "r.source IS" not in edge_part
        # the node's ``zone`` is not an edge property; the SOURCED_FROM edge's are ``zones`` / ``stated_zones``
        assert "r.zone " not in edge_part and "r.zone)" not in edge_part and "r.aliases" not in edge_part
        assert "r.zones = CASE WHEN r.zones IS NULL THEN NULL" in edge_part
        assert "r.stated_zones = CASE WHEN r.stated_zones IS NULL THEN NULL" in edge_part

    def test_family_label_feeds_are_the_feeds_that_set_malware_family(self):
        # ThreatFox, MalwareBazaar and Feodo Tracker write ``malware_family``; URLhaus, SSL Blacklist,
        # VirusTotal and OTX do not (2026-10: OTX was listed although its collector never writes one;
        # its pulse families are linked by step 9b), so crediting them would over-attribute the link.
        import ast as _ast

        feeds = set(_ast.literal_eval(rp.FAMILY_LABEL_FEEDS))
        assert feeds == {"threatfox", "malwarebazaar", "feodo_tracker"}
