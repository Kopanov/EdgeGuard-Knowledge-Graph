"""Attribution from a source report only when the report names one actor (2026-10).

An OTX pulse that names several actors does not say which of its malware families is whose. On the
hosted graph of 2026-10-15, 515 of 3,727 same-pulse ``ATTRIBUTED_TO`` links came from 29 pulses
naming 2 to 7 actors, e.g. the "Indonesian Banking Sector Threat Landscape" pulse below, whose 10
families (ValleyRAT, LOTUSLITE, ...) went to each of its 8 actors. The rule, with the aliases of one
actor counted as one (canonical threat-actor reference), is applied by:

* the sync, when it pairs the items of one pulse (``_build_cross_item_relationships``);
* ``build_relationships`` step 2d: it links the pairs carried on indicators only when a pulse naming
  one actor supports them, removes the links an earlier run made from pulses naming several actors,
  and drops such pulses from the provenance of the others;
* the acceptance script (``tests/test_verify_fresh_baseline.py``).

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

from build_rel_queries import assigned_query  # noqa: E402

import build_relationships  # noqa: E402
import canonical_threat_actors as cta  # noqa: E402
import run_misp_to_neo4j  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

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

    def test_the_report_ids_fragment_has_no_quote(self):
        # It is used inside statements apoc.periodic.iterate wraps in single quotes.
        fragment = cta.attribution_reports_cypher("r")
        assert "'" not in fragment and '"' not in fragment
        assert "r.source_refs" in fragment and "r.report_ids" in fragment and "$otx_ref_prefix" in fragment


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
        assert f"report {LANDSCAPE_PULSE} names 8 actors" in caplog.text

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


def _run_build(monkeypatch, *, report_rows=_REPORT_ACTOR_ROWS, reference_ok=True, read_fails=False):
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
                return [dict(r) for r in report_rows]
            if "apoc.periodic.iterate" in query:
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
        }
        assert _step(iterate, "_q2d_outer") == expected, "Storm-2697 is The Gentlemen: p-alias attributes"
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

    def test_an_unreadable_graph_skips_the_step_and_fails_the_run(self, monkeypatch):
        ok, iterate = _run_build(monkeypatch, read_fails=True)
        assert ok is False
        for name in ("_q2d_outer", "_q2d_remove_outer", "_q2d_trim_outer"):
            assert _step(iterate, name) is None

    def test_the_statements(self):
        inner = assigned_query("_q2d_inner")
        assert "[p IN coalesce(m.pulse_ids, []) WHERE p IN coalesce(a.pulse_ids, [])] AS _shared" in inner
        assert "WHERE size(_shared) = 0 OR any(p IN _shared WHERE NOT p IN $several_actor_reports)" in inner
        assert "[_x IN _mrefs WHERE _x IN _arefs AND NOT _x IN $several_actor_refs] AS _prov_refs" in inner
        remove = assigned_query("_q2d_remove_outer")
        for fragment in (
            'r.match_type = "otx_pulse" AND r.edgeguard_managed = true',
            cta.attribution_reports_cypher("r") + " AS reports",
            "size(reports) > 0 AND all(p IN reports WHERE p IN $several_actor_reports)",
            "all(s IN coalesce(r.sources, []) WHERE s IN $report_feeds)",
        ):
            assert fragment in remove
        assert assigned_query("_q2d_remove_inner") == "WITH $r AS r DELETE r"
        trim = assigned_query("_q2d_trim_inner")
        assert (
            "CASE WHEN r.source_refs IS NULL THEN null" in trim and "CASE WHEN r.report_ids IS NULL THEN null" in trim
        )
        for name in ("_q2d_inner", "_q2d_remove_outer", "_q2d_remove_inner", "_q2d_trim_outer", "_q2d_trim_inner"):
            assert "'" not in assigned_query(name), f"{name}: apoc.periodic.iterate wraps it in single quotes"
