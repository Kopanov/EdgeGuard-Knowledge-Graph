"""Attribution from a source report only when the report names one actor (2026-10).

An OTX pulse that names several actors does not say which of its malware families is whose. On the
hosted graph of 2026-10-15, 515 of 3,727 same-pulse ``ATTRIBUTED_TO`` links came from 29 pulses
naming 2 to 7 actors, e.g. the "Indonesian Banking Sector Threat Landscape" pulse below, whose 10
families (ValleyRAT, LOTUSLITE, ...) went to each of its 8 actors. The rule, with the aliases of one
actor counted as one (canonical threat-actor reference), is applied by:

* the OTX collector, on the pulse's whole adversary list: it writes ``family::adversary::pulse`` pairs
  only for a pulse naming one actor, and records a pulse naming several in ``several_actor_pulses`` on
  every item of it (``OTX_META.sap`` / ``MITRE_USES_TECHNIQUES.sap`` in MISP). MISP drops an actor it
  already holds, so after the baseline an event may carry only some of a pulse's actors;
* the sync, when it pairs the items of one pulse (``_build_cross_item_relationships``);
* ``build_relationships`` step 2d: it links the pairs carried on indicators only when a pulse naming
  one actor supports them, removes the links an earlier run made from pulses naming several actors,
  and drops such pulses from the provenance of the others;
* the acceptance script ``scripts/verify_fresh_baseline.py`` (its tests: ``tests/test_verify_fresh_baseline.py``).

The statements on a real Neo4j: ``tests/test_attribution_single_actor_reports_neo4j.py``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
_TESTS = Path(__file__).resolve().parent
for _p in (_SRC, _TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

os.environ.setdefault("NEO4J_PASSWORD", "test")
os.environ.setdefault("MISP_API_KEY", "test")

import json  # noqa: E402

import test_pulse_scoped_linking as _pulse_scoped  # noqa: E402  (its collector harness)
from build_rel_queries import assigned_query  # noqa: E402
from test_fresh_baseline_provenance import _bare_syncer  # noqa: E402

import build_relationships  # noqa: E402
import canonical_threat_actors as cta  # noqa: E402
import run_misp_to_neo4j  # noqa: E402
from collectors import otx_collector as oc  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync, _dedupe_parsed_items  # noqa: E402

# OTX pulse 6a4fdf500b5e6dffde939998, "Indonesian Banking Sector Threat Landscape" (public, read
# 2026-10-15): its adversary field and malware families.
LANDSCAPE_PULSE = "6a4fdf500b5e6dffde939998"
LANDSCAPE_ACTORS = [
    "SilverFox",
    "Mustang Panda",
    "Amaranth-Dragon",
    "Lotus Blossom",
    "Shadow Campaigns",
    "TripleX",
    "ICARUS",
    "The Gen",
]
LANDSCAPE_FAMILIES = [
    "ValleyRAT",
    "ABCDoor",
    "LOTUSLITE",
    "Cobalt Strike - S0154",
    "Chrysalis",
    "TGAmaranth RAT",
    "Amaranth Loader",
    "Havoc",
    "ShadowGuard",
    "RustSL",
]


@pytest.fixture(scope="module")
def reference():
    return cta.load_canonical_reference()


# --------------------------------------------------------------------------- shared helpers
class TestActorIdentities:
    def test_aliases_of_one_actor_are_one_actor(self, reference):
        assert cta.actor_identities(["The Gentlemen", "Storm-2697"], reference) == {"the gentlemen"}
        assert cta.actor_identities(["Nimbus Manticore", "TA455"], reference) == {"nimbus manticore"}

    def test_different_actors_and_names_the_reference_does_not_resolve(self, reference):
        assert len(cta.actor_identities(["Gamaredon", "Turla"], reference)) == 2
        assert len(cta.actor_identities(LANDSCAPE_ACTORS, reference)) == 8
        # never_merge in the reference: each name stays an actor of its own
        assert cta.actor_identities(["Famous Chollima", "Wagemole"], reference) == {"famous chollima", "wagemole"}

    def test_without_the_reference_every_name_is_an_actor(self):
        assert len(cta.actor_identities(["The Gentlemen", "Storm-2697"], None)) == 2

    def test_names_without_a_key_are_left_out(self, reference):
        assert cta.actor_identities(["", None, 7, " APT28 "], reference) == {"apt28"}

    def test_reports_naming_several_actors(self, reference):
        rows = [
            {"pid": "p-groups", "names": ["gamaredon", "turla"]},
            {"pid": "p-alias", "names": ["the gentlemen", "storm-2697"]},
            {"pid": "", "names": ["a", "b"]},
            {"pid": "p-empty", "names": []},
        ]
        assert cta.reports_naming_several_actors(rows, reference) == ["p-groups"]
        assert cta.reports_naming_several_actors(rows, None) == ["p-alias", "p-groups"]

    def test_the_report_ids_fragment_has_no_single_quote(self):
        # It is used inside statements apoc.periodic.iterate wraps in single quotes.
        fragment = cta.attribution_reports_cypher("r")
        assert "'" not in fragment
        assert "r.source_refs" in fragment and "r.report_ids" in fragment and "$otx_ref_prefix" in fragment

    def test_lists_stored_as_a_string_are_read_as_one_entry(self):
        # The actor alias merge's APOC combine stores two equal one-element lists as a string until
        # its normalising statement runs; step 2d and the acceptance check read them through as_list.
        from relationship_provenance import as_list

        fragment = cta.attribution_reports_cypher("r")
        assert as_list("r.source_refs") in fragment and as_list("r.report_ids") in fragment
        assert ("UNWIND " + as_list("a.pulse_ids") + " AS pid") in cta.REPORT_ACTORS_QUERY
        assert ("all(s IN " + as_list("r.sources") + " WHERE s IN $feeds)") in cta.ATTRIBUTION_CHECK_QUERY
        assert ("all(s IN " + as_list("r.sources") + " WHERE s IN $report_feeds)") in assigned_query(
            "_q2d_remove_outer"
        )
        trim = assigned_query("_q2d_trim_inner")
        assert ("[x IN " + as_list("r.source_refs") + " WHERE NOT x IN $several_actor_refs]") in trim
        assert ("[p IN " + as_list("r.report_ids") + " WHERE NOT p IN $several_actor_reports]") in trim


# --------------------------------------------------------------------------- the collector and MISP
_HARNESS = _pulse_scoped.TestCollectorStampsPulseFamiliesAndAdversariesOnIndicators()
_pulse = _HARNESS._pulse


class TestTheCollector:
    def test_a_pulse_naming_several_actors_writes_no_pair_and_marks_every_item(self):
        items = _HARNESS._collect(
            [_pulse(LANDSCAPE_PULSE, LANDSCAPE_FAMILIES[:3], ", ".join(LANDSCAPE_ACTORS), ["203.0.113.5"])]
        )
        ioc = next(i for i in items if i.get("value") == "203.0.113.5")
        assert ioc["pulse_malware_actor_pairs"] == [], "the pulse does not say which family is whose"
        assert ioc["pulse_malware_families"] == LANDSCAPE_FAMILIES[:3], "INDICATES is unaffected"
        marked = {(i.get("type") or "indicator"): i["several_actor_pulses"] for i in items}
        assert marked == {"indicator": [LANDSCAPE_PULSE], "malware": [LANDSCAPE_PULSE], "actor": [LANDSCAPE_PULSE]}

    def test_a_pulse_naming_one_actor_pairs_with_its_pulse_id(self):
        items = _HARNESS._collect([_pulse("p-alias", ["Gentlemen"], "The Gentlemen, Storm-2697", ["203.0.113.6"])])
        ioc = next(i for i in items if i.get("value") == "203.0.113.6")
        assert ioc["pulse_malware_actor_pairs"] == [
            "Gentlemen::The Gentlemen::p-alias",
            "Gentlemen::Storm-2697::p-alias",
        ], "two names of one actor (canonical reference)"
        assert all(i["several_actor_pulses"] == [] for i in items)

    def test_the_whole_adversary_list_is_judged_before_the_cap(self, monkeypatch):
        monkeypatch.setattr(oc, "_MAX_PULSE_ADVERSARIES", 1)
        items = _HARNESS._collect([_pulse("p-two", ["Kazuar"], "Gamaredon, Turla", ["203.0.113.7"])])
        ioc = next(i for i in items if i.get("value") == "203.0.113.7")
        assert ioc["pulse_malware_actor_pairs"] == [] and ioc["several_actor_pulses"] == ["p-two"]

    def test_an_ioc_in_two_pulses_keeps_the_pairs_of_one_and_the_mark_of_the_other(self):
        items = _HARNESS._collect(
            [
                _pulse("p-one", ["Emotet"], "TA542", ["203.0.113.8"]),
                _pulse("p-two", ["Kazuar"], "Gamaredon, Turla", ["203.0.113.8"]),
            ]
        )
        shared = [i for i in items if i.get("value") == "203.0.113.8"]
        assert len(shared) == 1
        assert shared[0]["pulse_malware_actor_pairs"] == ["Emotet::TA542::p-one"]
        assert shared[0]["several_actor_pulses"] == ["p-two"]
        assert shared[0]["pulse_malware_families"] == ["Emotet", "Kazuar"]

    def test_the_pair_encoder(self):
        assert oc._pulse_actor_pairs(["Emotet"], ["apt28"], "p1") == ["Emotet::apt28::p1"]
        assert oc._pulse_actor_pairs(["Emotet"], ["apt28"], " ") == ["Emotet::apt28"]
        assert oc._pulse_actor_pairs(["Emotet"], ["apt28"], "a::b") == ["Emotet::apt28"], "never four parts"
        assert oc._pulse_actor_pairs(["Emotet"], ["apt28"]) == ["Emotet::apt28"]


def _writer():
    return MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)


def _meta(comment, prefix):
    return json.loads(comment.split("\n", 1)[0][len(prefix) :])


_EVENT = {"id": 7, "info": "EdgeGuard-alienvault_otx-2026-10-15", "date": "2026-10-15", "Tag": []}
_OTX = {"tag": "alienvault_otx", "source": ["alienvault_otx"], "zone": ["global"], "confidence_score": 0.5}


class TestMispRoundTrip:
    def test_the_mark_travels_on_indicators_malware_and_actors(self):
        writer = _writer()
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        indicator = writer.create_attribute(
            {
                **_OTX,
                "indicator_type": "ipv4",
                "value": "203.0.113.5",
                "pulse_id": "p-two",
                "several_actor_pulses": ["p-two"],
            }
        )
        assert _meta(indicator["comment"], "OTX_META:")["sap"] == ["p-two"]
        malware = writer.create_malware_attribute(
            {**_OTX, "type": "malware", "name": "Kazuar", "pulse_id": "p-two", "several_actor_pulses": ["p-two"]}
        )
        actor = writer.create_actor_attribute(
            {**_OTX, "type": "actor", "name": "Turla", "pulse_id": "p-two", "several_actor_pulses": ["p-two"]}
        )
        for attr in (malware, actor):
            assert _meta(attr["comment"], "MITRE_USES_TECHNIQUES:")["sap"] == ["p-two"]
        for attr in (indicator, malware, actor):
            item, _ = syncer.parse_attribute({**attr, "uuid": "20000000-0000-0000-0000-00000000abcd"}, _EVENT)
            assert item["several_actor_pulses"] == ["p-two"], attr["type"]

    def test_a_pair_too_long_for_its_pulse_id_is_left_out_not_cut(self):
        pair = "Emotet::" + "x" * 320 + "::6a4fdf500b5e6dffde939998"
        ok = "Emotet::TA542::6a4fdf500b5e6dffde939998"
        attr = _writer().create_attribute(
            {
                **_OTX,
                "indicator_type": "ipv4",
                "value": "203.0.113.5",
                "pulse_id": "p1",
                "pulse_malware_actor_pairs": [pair, ok],
            }
        )
        assert _meta(attr["comment"], "OTX_META:")["pa"] == [ok], "a cut pair would name another actor or pulse"

    def test_a_pair_keeps_its_pulse_when_the_family_loses_its_attack_id(self):
        # Pairs written before the twin fix name "Cobalt Strike - S0154"; the sync reads them by the base
        # name, both forms, and a three-part pair keeps its pulse.
        from run_misp_to_neo4j import _pair_without_software_id

        assert _pair_without_software_id("Cobalt Strike - S0154::apt29::p1") == "Cobalt Strike::apt29::p1"
        assert _pair_without_software_id("Cobalt Strike - S0154::apt29") == "Cobalt Strike::apt29"
        assert _pair_without_software_id("no separator") == "no separator"

    def test_no_mark_no_key(self):
        writer = _writer()
        indicator = writer.create_attribute(
            {**_OTX, "indicator_type": "ipv4", "value": "203.0.113.5", "pulse_id": "p1"}
        )
        malware = writer.create_malware_attribute({**_OTX, "type": "malware", "name": "Emotet", "pulse_id": "p1"})
        assert "sap" not in _meta(indicator["comment"], "OTX_META:")
        assert "sap" not in _meta(malware["comment"], "MITRE_USES_TECHNIQUES:")

    def test_one_event_unions_the_marks_of_its_duplicates(self):
        items = _dedupe_parsed_items(
            [
                {"type": "indicator", "indicator_type": "ipv4", "value": "203.0.113.5", "pulse_id": "p-one"},
                {
                    "type": "indicator",
                    "indicator_type": "ipv4",
                    "value": "203.0.113.5",
                    "pulse_id": "p-two",
                    "several_actor_pulses": ["p-two"],
                },
            ]
        )
        assert len(items) == 1
        assert items[0]["report_ids"] == ["p-two"] and items[0]["several_actor_pulses"] == ["p-two"]


# --------------------------------------------------------------------------- the sync
def _items(pulse, actors, families, indicators=("203.0.113.5",)):
    items = [{"type": "indicator", "indicator_type": "ipv4", "value": v, "pulse_id": pulse} for v in indicators]
    items += [{"type": "malware", "name": f, "pulse_id": pulse} for f in families]
    items += [{"type": "actor", "name": a, "pulse_id": pulse} for a in actors]
    return items


def _rels(syncer, items):
    out: dict = {}
    for r in syncer._build_cross_item_relationships(items):
        out.setdefault(r["rel_type"], []).append(r)
    return out


class TestTheSync:
    def test_a_pulse_naming_several_actors_attributes_nothing(self, caplog):
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        with caplog.at_level("INFO", logger="run_misp_to_neo4j"):
            rels = _rels(syncer, _items(LANDSCAPE_PULSE, LANDSCAPE_ACTORS, LANDSCAPE_FAMILIES))
        assert "ATTRIBUTED_TO" not in rels
        assert len(rels["INDICATES"]) == len(LANDSCAPE_FAMILIES), "the indicator side is unchanged"
        assert syncer.stats["reports_with_several_actors"] == 1
        assert f"report {LANDSCAPE_PULSE} names several actors" in caplog.text

    def test_the_collector_mark_holds_when_the_event_carries_one_of_the_actors(self):
        # After the baseline MISP drops an actor it already holds: this event carries only Turla of
        # a pulse naming Gamaredon and Turla. Items written before the mark existed are judged by the
        # actors the event carries.
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        items = _items("p-two", ["Turla"], ["Kazuar"])
        assert len(_rels(syncer, items)["ATTRIBUTED_TO"]) == 1, "unmarked: one actor in the event"
        items[0]["several_actor_pulses"] = ["p-two"]
        assert "ATTRIBUTED_TO" not in _rels(syncer, items)
        malware_marked = _items("p-two", ["Turla"], ["Kazuar"], indicators=())
        malware_marked[0]["several_actor_pulses"] = ["p-two"]
        assert "ATTRIBUTED_TO" not in _rels(syncer, malware_marked)
        other_pulse = _items("p-one", ["Turla"], ["Kazuar"])
        other_pulse[0]["several_actor_pulses"] = ["p-two"]
        assert len(_rels(syncer, other_pulse)["ATTRIBUTED_TO"]) == 1, "the mark is per pulse"
        assert syncer.stats["reports_with_several_actors"] == 2

    @pytest.mark.parametrize("path", ["_process_event_attributes", "_process_large_event_paged"])
    def test_both_event_paths_keep_the_mark(self, monkeypatch, path):
        # An event with more changed attributes than _ATTR_PAGE_SIZE is synced page by page, and
        # its report-scoped links are built from slim copies of the items.
        monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 2)
        items = _items("p-two", ["Turla"], ["Kazuar"])
        attrs = [{"uuid": f"u{n}"} for n in range(len(items))]

        def attributions(marked):
            parsed = {
                a["uuid"]: dict(i, several_actor_pulses=["p-two"] if marked else [])
                for a, i in zip(attrs, items, strict=True)
            }
            syncer = _bare_syncer()
            syncer.stats["reports_with_several_actors"] = 0
            syncer.parse_attribute = lambda attr, event: (dict(parsed[attr["uuid"]], misp_event_id="99"), [])
            rows: list = []
            syncer._create_relationships = lambda rels, source_id: (rows.extend(rels), len(rels))[1]
            syncer._write_cross_item_relationships = lambda rels: (rows.extend(rels), len(rels))[1]
            getattr(syncer, path)("99", {"Event": {"id": "99"}}, attrs)
            return [r for r in rows if r["rel_type"] == "ATTRIBUTED_TO"]

        assert len(attributions(marked=False)) == 1, "unmarked: one actor in the event"
        assert attributions(marked=True) == [], "the collector's mark survives the path"

    def test_one_actor_and_the_aliases_of_one_actor_attribute(self):
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        one = _rels(syncer, _items("p-one", ["TA542"], ["Emotet"]))
        assert [(r["from_key"]["name"], r["to_key"]["name"]) for r in one["ATTRIBUTED_TO"]] == [("Emotet", "TA542")]
        aliases = _rels(syncer, _items("p-alias", ["The Gentlemen", "Storm-2697"], ["Gentlemen"]))
        assert {r["to_key"]["name"] for r in aliases["ATTRIBUTED_TO"]} == {"The Gentlemen", "Storm-2697"}
        assert syncer.stats["reports_with_several_actors"] == 0

    def test_the_whole_pulse_is_judged_before_the_cap(self, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_MAX_REPORT_ACTORS", 1)
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        rels = _rels(syncer, _items("p-two", ["Gamaredon", "Turla"], ["PteroLNK", "Kazuar"]))
        assert "ATTRIBUTED_TO" not in rels, "not the first actor's: the pulse names two"

    def test_without_the_reference_aliases_count_as_several_and_it_is_logged_once(self, monkeypatch, caplog):
        def unavailable(*_a, **_k):
            raise cta.ReferenceUnavailable("test: not found")

        monkeypatch.setattr(run_misp_to_neo4j, "load_canonical_reference", unavailable)
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        with caplog.at_level("WARNING", logger="run_misp_to_neo4j"):
            first = _rels(syncer, _items("p-alias", ["The Gentlemen", "Storm-2697"], ["Gentlemen"]))
            second = _rels(syncer, _items("p-one", ["TA542"], ["Emotet"]))
        assert "ATTRIBUTED_TO" not in first and len(second["ATTRIBUTED_TO"]) == 1
        assert caplog.text.count("canonical reference unavailable") == 1


# --------------------------------------------------------------------------- build_relationships step 2d
_APOC_ROW = {
    "count": 0,
    "batches": 1,
    "errorMessages": {},
    "failedBatches": 0,
    "failedOperations": 0,
    "wasTerminated": False,
    "batch": {"errors": {}},
    "operations": {"errors": {}},
    "updateStatistics": {},
}
_REPORT_ACTOR_ROWS = [
    {"pid": "p-groups", "names": ["gamaredon", "turla"]},
    {"pid": "p-alias", "names": ["the gentlemen", "storm-2697"]},
]


def _run_build(
    monkeypatch, *, report_rows=_REPORT_ACTOR_ROWS, reference_ok=True, read_fails=False, read_empty=False, failing=None
):
    calls: list = []

    class _Client:
        def connect(self):
            return True

        def close(self):
            pass

        def run(self, query, parameters=None):
            calls.append((query, parameters))
            if query == cta.REPORT_ACTORS_QUERY:
                if read_fails:
                    raise RuntimeError("graph not readable")
                if read_empty:
                    return []  # ``Neo4jClient.run`` on a terminal error
                return [{"reports": [dict(r) for r in report_rows], "pulses": 1530}]
            if "apoc.periodic.iterate" in query:
                names = (failing,) if isinstance(failing, str) else (failing or ())
                if any(assigned_query(n) in query for n in names):
                    return [dict(_APOC_ROW, errorMessages={"neo4j down": 1}, failedBatches=1)]
                return [dict(_APOC_ROW)]
            return [{"c": 0, "count": 0}]

    monkeypatch.setattr(build_relationships, "Neo4jClient", _Client)
    monkeypatch.setattr(build_relationships, "query_pause", lambda: None)
    if not reference_ok:

        def unavailable(*_a, **_k):
            raise cta.ReferenceUnavailable("test: not found")

        monkeypatch.setattr(build_relationships, "load_canonical_reference", unavailable)
    ok = build_relationships.build_relationships()
    iterate = [(q, p) for q, p in calls if "apoc.periodic.iterate" in q]
    return ok, iterate


def _step(iterate, outer_name):
    outer = assigned_query(outer_name)
    found = [p for q, p in iterate if outer in q]
    assert len(found) <= 1
    return found[0]["iterate_params"] if found else None


class TestStep2d:
    def test_links_removes_and_trims_with_the_pulses_naming_several_actors(self, monkeypatch):
        ok, iterate = _run_build(monkeypatch)
        assert ok is True
        expected = {
            "several_actor_reports": ["p-groups"],
            "several_actor_refs": ["alienvault_otx:p-groups"],
            "otx_ref_prefix": "alienvault_otx:",
            "report_feeds": ["alienvault_otx", "otx_pulse"],
            "canonical_actor_names": cta.canonical_actor_names(cta.load_canonical_reference()),
        }
        assert expected["canonical_actor_names"]["storm-2697"] == "the gentlemen"
        assert "the gentlemen" not in expected["canonical_actor_names"], "a canonical key is not a synonym"
        # The link statement also takes the ATT&CK software id pattern and the folded Malware names.
        from attack_software_names import CYPHER_SOFTWARE_ID_SUFFIX

        link = dict(expected, software_id_suffix=CYPHER_SOFTWARE_ID_SUFFIX, folded_families={})
        assert _step(iterate, "_q2d_outer") == link, "Storm-2697 is The Gentlemen: p-alias attributes"
        assert _step(iterate, "_q2d_remove_outer") == expected
        assert _step(iterate, "_q2d_trim_outer") == expected
        order = [
            next(i for i, (q, _p) in enumerate(iterate) if assigned_query(n) in q)
            for n in ("_q2d_outer", "_q2d_remove_outer", "_q2d_trim_outer")
        ]
        assert order == sorted(order), "link, then remove, then trim (trimming first would strand links)"

    def test_without_the_reference_nothing_is_removed(self, monkeypatch):
        ok, iterate = _run_build(monkeypatch, reference_ok=False)
        assert ok is True
        assert _step(iterate, "_q2d_outer")["several_actor_reports"] == ["p-alias", "p-groups"]
        assert _step(iterate, "_q2d_remove_outer") is None and _step(iterate, "_q2d_trim_outer") is None

    def test_no_pulse_naming_several_actors_means_no_cleanup(self, monkeypatch):
        ok, iterate = _run_build(monkeypatch, report_rows=[])
        assert ok is True and _step(iterate, "_q2d_outer")["several_actor_reports"] == []
        assert _step(iterate, "_q2d_remove_outer") is None

    @pytest.mark.parametrize("failure", ["read_fails", "read_empty"])
    def test_an_unreadable_graph_skips_the_step_and_fails_the_run(self, monkeypatch, failure):
        ok, iterate = _run_build(monkeypatch, **{failure: True})
        assert ok is False
        for name in ("_q2d_outer", "_q2d_remove_outer", "_q2d_trim_outer"):
            assert _step(iterate, name) is None

    def test_a_failed_removal_is_not_followed_by_the_trim(self, monkeypatch):
        # Trimmed after a partly failed removal, a link resting only on such pulses would keep no
        # pulse to be judged by; the next run repeats the removal, then trims.
        ok, iterate = _run_build(monkeypatch, failing="_q2d_remove_outer")
        assert ok is False
        assert _step(iterate, "_q2d_remove_outer") is not None and _step(iterate, "_q2d_trim_outer") is None

    def test_a_failed_link_statement_is_not_followed_by_the_removal(self, monkeypatch):
        # A pair in a failed batch could have given a link a pulse naming one actor.
        ok, iterate = _run_build(monkeypatch, failing="_q2d_outer")
        assert ok is False
        assert _step(iterate, "_q2d_remove_outer") is None and _step(iterate, "_q2d_trim_outer") is None

    def test_step_2d_counts_once_in_the_summary(self, monkeypatch, caplog):
        # The gating makes it structural: after a failed part, no later part of step 2d runs.
        with caplog.at_level("INFO", logger="build_relationships"):
            ok, _iterate = _run_build(monkeypatch, failing="_q2d_trim_outer")
        assert ok is False
        assert "failures=1/20" in caplog.text

    def test_the_statements(self):
        inner = assigned_query("_q2d_inner")
        for fragment in (
            'WITH $pair AS pair WITH split(pair, "::") AS parts WHERE size(parts) IN [2, 3] ',
            'CASE WHEN size(parts) = 3 AND trim(parts[2]) <> "" THEN trim(parts[2]) END AS pid ',
            "AND (pid IS NULL OR NOT pid IN $several_actor_reports) ",
            "OPTIONAL MATCH (_named:ThreatActor {name: aname}) ",
            "OPTIONAL MATCH (_canonical:ThreatActor {name: coalesce($canonical_actor_names[aname], aname)}) ",
            # one node: a pair is judged by the pulses of the node it links
            "WITH m, pid, coalesce(_named, _canonical) AS a WHERE a IS NOT NULL ",
            "WHERE p IN CASE WHEN a.pulse_ids IS NULL THEN [] ",
            "WHERE pid IS NOT NULL OR size(_shared) = 0 OR any(p IN _shared WHERE NOT p IN $several_actor_reports) ",
            "CASE WHEN pid IS NOT NULL THEN [$otx_ref_prefix + pid] ",
            "ELSE [_x IN _mrefs WHERE _x IN _arefs AND NOT _x IN $several_actor_refs] END AS _prov_refs",
        ):
            assert fragment in inner, fragment
        remove = assigned_query("_q2d_remove_outer")
        for fragment in (
            'r.match_type = "otx_pulse" AND r.edgeguard_managed = true',
            cta.attribution_reports_cypher("r") + " AS reports",
            "size(reports) > 0 AND all(p IN reports WHERE p IN $several_actor_reports)",
            "WHERE s IN $report_feeds)",
        ):
            assert fragment in remove
        assert assigned_query("_q2d_remove_inner") == "WITH $r AS r DELETE r"
        trim = assigned_query("_q2d_trim_inner")
        assert (
            "CASE WHEN r.source_refs IS NULL THEN null" in trim and "CASE WHEN r.report_ids IS NULL THEN null" in trim
        )
        for name in ("_q2d_inner", "_q2d_remove_outer", "_q2d_remove_inner", "_q2d_trim_outer", "_q2d_trim_inner"):
            assert "'" not in assigned_query(name), f"{name}: apoc.periodic.iterate wraps it in single quotes"
