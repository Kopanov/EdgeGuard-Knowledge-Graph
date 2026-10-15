"""
2026-10 fresh-baseline PR — report-scoped provenance, TLP tagging and the
``edgeguard_managed`` ownership marker (ResilMesh conformance findings F1/F2/F4).

What changed, and what this file pins:

* ``run_misp_to_neo4j.MISPToNeo4jSync._build_cross_item_relationships`` pairs
  items only within one OTX pulse (``item["pulse_id"]`` plus any extra
  ``report_ids`` collected by ``_dedupe_parsed_items``) and emits only
  Indicator→Malware INDICATES and Malware→ThreatActor ATTRIBUTED_TO, each
  stamped ``confidence 0.6`` / ``match_type "otx_pulse"`` / ``report_id`` /
  ``misp_event_id``. EMPLOYS_TECHNIQUE and EXPLOITS are never derived from
  co-membership any more; sector TARGETS / AFFECTS from ``zone`` are unchanged.
  Both call sites route those edges with ``source_id="otx_pulse"``, and the
  paged large-event path keeps ``pulse_id`` / ``report_ids`` / ``misp_event_id``
  in its slim accumulator.
* ``collectors.misp_writer``: ``_technique_meta`` round-trips ``uses_techniques``
  (``t``), ``reported_techniques`` (``rt``) and ``pulse_id`` (``pid``) through the
  ``MITRE_USES_TECHNIQUES:`` comment; ``_tlp_tag`` stamps exactly one
  ``tlp:<level>`` tag on every attribute the 7 creators build.
* ``run_misp_to_neo4j.parse_attribute`` reads ``rt`` / ``pid`` back, rehydrates
  the TLP tag into ``item["tlp"]`` (``_extract_tlp_tag``) and skips threat-actor
  attributes whose value is a composite or a generic phrase
  (``actor_name_hygiene.clean_actor_names``).
* ``collectors.otx_collector``: malware / actor items carry ``reported_techniques``
  (never ``uses_techniques``) and one actor item is emitted per cleaned
  adversary name.
* ``build_relationships``: whole-event co-occurrence Q4 removed; 5b / 6b build
  EMPLOYS_TECHNIQUE / IMPLEMENTS_TECHNIQUE from ``reported_techniques`` with
  ``otx_pulse`` at 0.6; every inner query sets ``r.edgeguard_managed = true``.
* ``neo4j_client``: batch relationship rows carry ``match_type`` / ``report_id``;
  ``_set_clause`` writes ``edgeguard_managed`` / ``match_type`` / ``report_ids``;
  ``merge_cve`` promotes the ResilMesh list props; ``merge_malware`` /
  ``merge_actor`` pass ``reported_techniques`` / ``pulse_ids``;
  ``merge_node_with_source`` promotes ``tlp``; the indicator batch stages ``tlp``;
  ``clear_edgeguard_managed`` deletes only marked nodes.
* ``edgeguard clear neo4j --edgeguard-only`` routes to ``clear_edgeguard_managed``
  and returns 1 when the clear reports failure.
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# test_graphql_api may register a MagicMock as sys.modules["neo4j_client"] — drop it.
for _mod in ("neo4j_client", "run_misp_to_neo4j"):
    if _mod in sys.modules:
        del sys.modules[_mod]

import config  # noqa: E402
import neo4j_client as neo4j_client_mod  # noqa: E402
from collectors.misp_writer import MISPWriter, _technique_meta, _tlp_tag  # noqa: E402
from neo4j_client import Neo4jClient  # noqa: E402
from run_misp_to_neo4j import (  # noqa: E402
    _REPORT_SCOPED_SOURCE_ID,
    MISPToNeo4jSync,
    _dedupe_parsed_items,
    _extract_tlp_tag,
)

_BUILD_REL = SRC / "build_relationships.py"
_RUN_MISP = SRC / "run_misp_to_neo4j.py"
_NEO4J_CLIENT = SRC / "neo4j_client.py"
_ENRICHMENT = SRC / "enrichment_jobs.py"
_OTX = SRC / "collectors" / "otx_collector.py"
_EDGEGUARD_CLI = SRC / "edgeguard.py"


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def syncer() -> MISPToNeo4jSync:
    return MISPToNeo4jSync(neo4j_client=MagicMock())


@pytest.fixture
def writer() -> MISPWriter:
    return MISPWriter(url="http://137.0.0.1:9", api_key="dummy", verify_ssl=False)


def _ind(value: str, pulse: str | None = "pulse-1", **extra):
    item = {"type": "indicator", "indicator_type": "ipv4", "value": value, "misp_event_id": "777"}
    if pulse is not None:
        item["pulse_id"] = pulse
    item.update(extra)
    return item


def _mal(name: str, pulse: str | None = "pulse-1", **extra):
    item = {"type": "malware", "name": name, "misp_event_id": "777"}
    if pulse is not None:
        item["pulse_id"] = pulse
    item.update(extra)
    return item


def _act(name: str, pulse: str | None = "pulse-1", **extra):
    item = {"type": "actor", "name": name, "misp_event_id": "777"}
    if pulse is not None:
        item["pulse_id"] = pulse
    item.update(extra)
    return item


def _by_type(rels):
    out: dict[str, list] = {}
    for r in rels:
        out.setdefault(r["rel_type"], []).append(r)
    return out


def _make_neo4j_mock():
    """Neo4jClient with a mocked driver whose session records every Cypher call."""
    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    client._connection_healthy = True
    mock_session = MagicMock()
    mock_result = MagicMock()
    mock_result.single.return_value = None
    mock_session.run.return_value = mock_result
    client.driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return client, mock_session


def _capturing_client():
    """Neo4jClient whose session captures ``rows=`` batches (create_misp_relationships_batch)."""
    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    client._connection_healthy = True
    captured: list[tuple[str, list]] = []

    def run(query, **kwargs):
        rows = kwargs.get("rows")
        if rows is not None:
            captured.append((query, list(rows)))
        result = MagicMock()
        result.consume.return_value.counters.relationships_created = 0
        return result

    session = MagicMock()
    session.run = run
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *a: False
    client.driver.session.return_value = session
    return client, captured


def _inner_queries() -> list[tuple[str, int, str]]:
    """``(target name, line, concatenated string constants)`` for every ``*_inner`` assignment."""
    tree = ast.parse(_BUILD_REL.read_text())
    out: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and tgt.id.endswith("_inner"):
                body = "".join(
                    c.value for c in ast.walk(node.value) if isinstance(c, ast.Constant) and isinstance(c.value, str)
                )
                out.append((tgt.id, node.lineno, body))
    return out


# ===========================================================================
# 1. _build_cross_item_relationships — report (pulse) scope
# ===========================================================================


class TestCrossItemBuilderReportScope:
    def test_class_constants_pin_the_stamp_values(self):
        assert MISPToNeo4jSync._REPORT_LINK_CONFIDENCE == 0.6
        assert MISPToNeo4jSync._REPORT_LINK_MATCH_TYPE == "otx_pulse"
        assert MISPToNeo4jSync._MAX_REPORT_INDICATORS == 2000
        assert MISPToNeo4jSync._MAX_REPORT_MALWARE == 50
        assert MISPToNeo4jSync._MAX_REPORT_ACTORS == 10
        # 2026-10 (relationship provenance): the feed, not the evidence label ``otx_pulse``.
        assert _REPORT_SCOPED_SOURCE_ID == "alienvault_otx"

    def test_same_pulse_emits_indicates_and_attributed_to_with_exact_stamps(self, syncer):
        rels = syncer._build_cross_item_relationships([_ind("203.0.113.5"), _mal("Emotet"), _act("TA542")])
        assert len(rels) == 2
        by_type = {r["rel_type"]: r for r in rels}
        assert by_type["INDICATES"] == {
            "rel_type": "INDICATES",
            "from_type": "Indicator",
            "from_key": {"value": "203.0.113.5", "indicator_type": "ipv4"},
            "to_type": "Malware",
            "to_key": {"name": "Emotet"},
            "confidence": 0.6,
            "match_type": "otx_pulse",
            "report_id": "pulse-1",
            "source": "alienvault_otx",
            "source_refs": ["alienvault_otx:pulse-1"],
            "misp_event_id": "777",
        }
        assert by_type["ATTRIBUTED_TO"] == {
            "rel_type": "ATTRIBUTED_TO",
            "from_type": "Malware",
            "from_key": {"name": "Emotet"},
            "to_type": "ThreatActor",
            "to_key": {"name": "TA542"},
            "confidence": 0.6,
            "match_type": "otx_pulse",
            "report_id": "pulse-1",
            "source": "alienvault_otx",
            "source_refs": ["alienvault_otx:pulse-1"],
            "misp_event_id": "777",
        }

    def test_two_pulses_never_pair_across(self, syncer):
        items = [
            _ind("1.1.1.1", "A"),
            _mal("MalA", "A"),
            _act("ActA", "A"),
            _ind("2.2.2.2", "B"),
            _mal("MalB", "B"),
            _act("ActB", "B"),
        ]
        rels = syncer._build_cross_item_relationships(items)
        assert len(rels) == 4
        indicates = {(r["from_key"]["value"], r["to_key"]["name"], r["report_id"]) for r in _by_type(rels)["INDICATES"]}
        assert indicates == {("1.1.1.1", "MalA", "A"), ("2.2.2.2", "MalB", "B")}
        attributed = {
            (r["from_key"]["name"], r["to_key"]["name"], r["report_id"]) for r in _by_type(rels)["ATTRIBUTED_TO"]
        }
        assert attributed == {("MalA", "ActA", "A"), ("MalB", "ActB", "B")}

    def test_items_without_pulse_id_are_never_paired(self, syncer):
        items = [_ind("1.1.1.1", None), _mal("Emotet", None), _act("TA542", None)]
        assert syncer._build_cross_item_relationships(items) == []

    @pytest.mark.parametrize("bad_pulse", ["", "   ", None, 123, ["pulse-1"], {"id": "pulse-1"}])
    def test_blank_or_non_string_pulse_id_is_ignored(self, syncer, bad_pulse):
        items = [_ind("1.1.1.1", None, pulse_id=bad_pulse), _mal("Emotet", None, pulse_id=bad_pulse)]
        assert syncer._build_cross_item_relationships(items) == []

    def test_pulse_id_is_stripped_before_grouping(self, syncer):
        rels = syncer._build_cross_item_relationships([_ind("1.1.1.1", " p1 "), _mal("Emotet", "p1")])
        assert len(rels) == 1
        assert rels[0]["report_id"] == "p1"

    def test_mixed_pulse_and_orphan_items_only_pair_the_pulse_ones(self, syncer):
        items = [
            _ind("1.1.1.1", "A"),
            _mal("MalA", "A"),
            _mal("OrphanMalware", None),
            _act("ActA", "A"),
            _act("OrphanActor", None),
        ]
        rels = syncer._build_cross_item_relationships(items)
        assert {r["to_key"]["name"] for r in _by_type(rels)["INDICATES"]} == {"MalA"}
        assert {r["to_key"]["name"] for r in _by_type(rels)["ATTRIBUTED_TO"]} == {"ActA"}
        assert len(rels) == 2

    def test_indicators_without_value_and_entities_without_name_are_skipped(self, syncer):
        items = [
            {"type": "indicator", "indicator_type": "ipv4", "value": "", "pulse_id": "A"},
            {"type": "indicator", "indicator_type": "ipv4", "pulse_id": "A"},
            {"type": "malware", "name": "", "pulse_id": "A"},
            {"type": "malware", "pulse_id": "A"},
            {"type": "actor", "name": "", "pulse_id": "A"},
            {"type": "actor", "pulse_id": "A"},
            _ind("1.1.1.1", "A"),
            _mal("Real", "A"),
            _act("RealActor", "A"),
        ]
        rels = syncer._build_cross_item_relationships(items)
        assert len(rels) == 2
        assert {r["rel_type"] for r in rels} == {"INDICATES", "ATTRIBUTED_TO"}
        assert all(r["from_key"] and r["to_key"] for r in rels)

    def test_indicator_type_defaults_to_unknown_in_from_key(self, syncer):
        items = [{"type": "indicator", "value": "evil.example", "pulse_id": "A"}, _mal("M", "A")]
        rels = syncer._build_cross_item_relationships(items)
        assert len(rels) == 1
        assert rels[0]["from_key"] == {"value": "evil.example", "indicator_type": "unknown"}

    def test_per_report_caps_are_honoured_and_keep_first_items(self, syncer, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_MAX_REPORT_INDICATORS", 3)
        monkeypatch.setattr(MISPToNeo4jSync, "_MAX_REPORT_MALWARE", 2)
        monkeypatch.setattr(MISPToNeo4jSync, "_MAX_REPORT_ACTORS", 1)
        # Two names of one actor (canonical reference): a pulse naming two different actors would
        # attribute nothing (2026-10, tests/test_attribution_single_actor_reports.py).
        items = (
            [_ind(f"10.0.0.{i}") for i in range(5)]
            + [_mal(f"M{i}") for i in range(3)]
            + [_act(name) for name in ("The Gentlemen", "Storm-2697")]
        )
        rels = _by_type(syncer._build_cross_item_relationships(items))
        assert len(rels["INDICATES"]) == 3 * 2
        assert len(rels["ATTRIBUTED_TO"]) == 2 * 1
        assert {r["from_key"]["value"] for r in rels["INDICATES"]} == {"10.0.0.0", "10.0.0.1", "10.0.0.2"}
        assert {r["to_key"]["name"] for r in rels["INDICATES"]} == {"M0", "M1"}
        assert {r["to_key"]["name"] for r in rels["ATTRIBUTED_TO"]} == {"The Gentlemen"}

    def test_caps_apply_per_report_not_across_reports(self, syncer, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_MAX_REPORT_MALWARE", 1)
        items = [
            _ind("1.1.1.1", "A"),
            _mal("A1", "A"),
            _mal("A2", "A"),
            _ind("2.2.2.2", "B"),
            _mal("B1", "B"),
            _mal("B2", "B"),
        ]
        indicates = _by_type(syncer._build_cross_item_relationships(items))["INDICATES"]
        assert {(r["to_key"]["name"], r["report_id"]) for r in indicates} == {("A1", "A"), ("B1", "B")}

    def test_default_indicator_cap_is_2000_per_pulse(self, syncer):
        items = [_ind(f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}") for i in range(2001)] + [_mal("M")]
        indicates = _by_type(syncer._build_cross_item_relationships(items))["INDICATES"]
        assert len(indicates) == 2000

    def test_employs_technique_and_exploits_are_never_emitted(self, syncer):
        items = [
            _act("APT28"),
            {"type": "technique", "mitre_id": "T1059", "name": "CLI", "pulse_id": "pulse-1"},
            _ind("1.1.1.1"),
            {"type": "vulnerability", "cve_id": "CVE-2021-44228", "value": "CVE-2021-44228", "pulse_id": "pulse-1"},
            _mal("Emotet"),
        ]
        rels = syncer._build_cross_item_relationships(items)
        types = {r["rel_type"] for r in rels}
        assert "EMPLOYS_TECHNIQUE" not in types
        assert "EXPLOITS" not in types
        assert types == {"INDICATES", "ATTRIBUTED_TO"}

    def test_zone_targets_and_affects_still_emitted_without_any_pulse(self, syncer):
        items = [
            {
                "type": "indicator",
                "indicator_type": "ipv4",
                "value": "1.1.1.1",
                "zone": ["energy"],
                "misp_event_id": "5",
            },
            {
                "type": "vulnerability",
                "cve_id": "CVE-2021-44228",
                "value": "CVE-2021-44228",
                "zone": ["Finance", "global"],
                "misp_event_id": "5",
            },
        ]
        rels = _by_type(syncer._build_cross_item_relationships(items))
        assert set(rels) == {"TARGETS", "AFFECTS"}
        (targets,) = rels["TARGETS"]
        (affects,) = rels["AFFECTS"]
        assert targets["from_type"] == "Indicator" and targets["to_key"] == {"name": "energy"}
        assert affects["from_type"] == "Vulnerability" and affects["from_key"] == {"cve_id": "CVE-2021-44228"}
        assert affects["to_key"] == {"name": "finance"}, "zone is lower-cased; 'global' is skipped"
        for r in rels["TARGETS"] + rels["AFFECTS"]:
            assert r["misp_event_id"] == "5"
            assert r["confidence"] == 0.5
            assert "report_id" not in r and r["match_type"] == "zone_classification"

    def test_misp_event_id_taken_from_first_item_that_has_one(self, syncer):
        items = [_mal("M", misp_event_id=""), _act("A", misp_event_id="42")]
        rels = syncer._build_cross_item_relationships(items)
        assert [r["misp_event_id"] for r in rels] == ["42"]

    def test_missing_event_id_everywhere_stamps_empty_string(self, syncer):
        items = [{"type": "malware", "name": "M", "pulse_id": "p"}, {"type": "actor", "name": "A", "pulse_id": "p"}]
        rels = syncer._build_cross_item_relationships(items)
        assert rels and all(r["misp_event_id"] == "" for r in rels)


# ===========================================================================
# 2. _dedupe_parsed_items collects extra report ids; builder links to all of them
# ===========================================================================


class TestDedupeCollectsReportIds:
    def test_duplicate_with_other_pulse_adds_report_id_once(self):
        kept = {"indicator_type": "ipv4", "value": "1.1.1.1", "pulse_id": "p1"}
        dup_other = {"indicator_type": "ipv4", "value": "1.1.1.1", "pulse_id": "p2"}
        dup_other_again = {"indicator_type": "ipv4", "value": "1.1.1.1", "pulse_id": "p2"}
        dup_same = {"indicator_type": "ipv4", "value": "1.1.1.1", "pulse_id": "p1"}
        unique = _dedupe_parsed_items([kept, dup_other, dup_other_again, dup_same])
        assert len(unique) == 1 and unique[0] is kept
        assert kept["report_ids"] == ["p2"]
        assert kept["pulse_id"] == "p1", "the kept item's own pulse id is untouched"

    def test_duplicate_without_pulse_adds_nothing(self):
        kept = {"indicator_type": "ipv4", "value": "1.1.1.1", "pulse_id": "p1"}
        unique = _dedupe_parsed_items([kept, {"indicator_type": "ipv4", "value": "1.1.1.1"}])
        assert len(unique) == 1
        assert "report_ids" not in kept

    def test_kept_item_without_pulse_still_collects_duplicates_pulse(self):
        kept = {"indicator_type": "ipv4", "value": "1.1.1.1"}
        _dedupe_parsed_items([kept, {"indicator_type": "ipv4", "value": "1.1.1.1", "pulse_id": "p2"}])
        assert kept["report_ids"] == ["p2"]

    def test_three_pulses_accumulate_in_order(self):
        kept = {"type": "malware", "name": "Emotet", "pulse_id": "p1"}
        _dedupe_parsed_items(
            [
                kept,
                {"type": "malware", "name": "Emotet", "pulse_id": "p2"},
                {"type": "malware", "name": "Emotet", "pulse_id": "p3"},
                {"type": "malware", "name": "Emotet", "pulse_id": "p2"},
            ]
        )
        assert kept["report_ids"] == ["p2", "p3"]

    def test_builder_links_deduped_item_to_every_report(self, syncer):
        items = _dedupe_parsed_items(
            [
                _ind("1.1.1.1", "p1"),
                _mal("MalA", "p1"),
                _ind("1.1.1.1", "p2"),  # same IOC, second pulse → report_ids ["p2"]
                _mal("MalB", "p2"),
            ]
        )
        assert len(items) == 3
        rels = syncer._build_cross_item_relationships(items)
        indicates = {(r["to_key"]["name"], r["report_id"]) for r in rels if r["rel_type"] == "INDICATES"}
        assert indicates == {("MalA", "p1"), ("MalB", "p2")}
        assert all(r["match_type"] == "otx_pulse" and r["confidence"] == 0.6 for r in rels)

    def test_report_ids_alone_without_pulse_id_still_pairs(self, syncer):
        items = [{"indicator_type": "ipv4", "value": "1.1.1.1", "report_ids": ["p2"]}, _mal("MalB", "p2")]
        rels = syncer._build_cross_item_relationships(items)
        assert [(r["rel_type"], r["report_id"]) for r in rels] == [("INDICATES", "p2")]

    def test_report_ids_entries_are_validated_like_pulse_id(self, syncer):
        items = [
            {"indicator_type": "ipv4", "value": "1.1.1.1", "report_ids": ["", "   ", None, 5, " p2 "]},
            _mal("MalB", "p2"),
        ]
        rels = syncer._build_cross_item_relationships(items)
        assert [(r["rel_type"], r["report_id"]) for r in rels] == [("INDICATES", "p2")]


# ===========================================================================
# 3. Routing + paged path keep report provenance
# ===========================================================================


def _bare_syncer() -> MISPToNeo4jSync:
    syncer = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    syncer.neo4j = MagicMock()
    syncer.stats = {
        "events_processed": 0,
        "events_failed": 0,
        "indicators_synced": 0,
        "vulnerabilities_synced": 0,
        "relationships_created": 0,
        "errors": 0,
    }
    syncer.sync_to_neo4j = MagicMock(return_value=(1, 0, []))
    return syncer


class TestCreateRelationshipsRouting:
    def test_process_event_attributes_routes_cross_rels_to_otx_pulse(self):
        syncer = _bare_syncer()
        source_ids_used: list[tuple[str, int]] = []
        syncer._create_relationships = lambda rels, source_id: (
            source_ids_used.append((source_id, len(rels))),
            len(rels),
        )[1]
        syncer._build_cross_item_relationships = MagicMock(
            return_value=[{"rel_type": "INDICATES", "report_id": "p1"}, {"rel_type": "TARGETS"}]
        )
        syncer.parse_attribute = lambda attr, event: (
            {"indicator_type": "ipv4", "value": attr["value"], "tag": "misp"},
            [{"rel_type": "TARGETS", "embedded": True}],
        )
        attributes = [{"type": "ip-src", "value": "1.1.1.1"}, {"type": "ip-src", "value": "2.2.2.2"}]
        parsed, cross, errors = syncer._process_event_attributes("1", {"Event": {"id": "1"}}, attributes)
        assert (parsed, cross, errors) == (2, 2, 0)
        # 2026-10 (relationship provenance): every row names its own feed (``source``), so the
        # cross-item rows go out in one call; ``misp`` is only the fallback for a row without one.
        assert source_ids_used == [("misp", 2), ("misp", 2)]
        assert syncer.stats["relationships_created"] == 4

    def test_no_call_site_uses_misp_cooccurrence_any_more(self):
        text = _RUN_MISP.read_text()
        assert '_create_relationships(cross_rels, "misp_cooccurrence")' not in text
        assert "_write_cross_item_relationships(cross_rels)" in text, (
            "report-scoped edges must be routed through the helper that writes the builder's rows"
        )
        # The report-scoped rows name the feed; ``otx_pulse`` is the evidence label (match_type).
        assert '_REPORT_SCOPED_SOURCE_ID = "alienvault_otx"' in text
        assert '"source": _REPORT_SCOPED_SOURCE_ID' in text


class TestPagedPathKeepsReportProvenance:
    """``_process_large_event_paged`` accumulates slim copies of each page's
    items for the cross-item build after the last page. The slim key list
    now carries ``pulse_id`` / ``report_ids`` / ``misp_event_id``; before the
    fix, large OTX events (which hold most of the data) produced no
    report-scoped links and no event stamp."""

    _PARSED = {
        "a1": {
            "type": "indicator",
            "indicator_type": "ipv4",
            "value": "1.1.1.1",
            "pulse_id": "p1",
            "misp_event_id": "99",
            "tag": "misp",
            "description": "x" * 400,
            "relationships": [],
        },
        "a2": {"type": "malware", "name": "MalA", "pulse_id": "p1", "misp_event_id": "99", "tag": "misp"},
        "a3": {
            "type": "indicator",
            "indicator_type": "ipv4",
            "value": "1.1.1.1",
            "pulse_id": "p2",
            "misp_event_id": "99",
            "tag": "misp",
        },
        "a4": {"type": "malware", "name": "MalB", "pulse_id": "p2", "misp_event_id": "99", "tag": "misp"},
    }

    def _syncer_with_parsed(self):
        syncer = _bare_syncer()
        syncer.parse_attribute = lambda attr, event: (dict(self._PARSED[attr["uuid"]]), [])
        return syncer

    def _attrs(self):
        return [{"uuid": k} for k in self._PARSED]

    def test_slim_copies_keep_pulse_id_and_event_id_across_pages(self, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 2)  # 4 attrs → 2 pages
        syncer = self._syncer_with_parsed()
        captured: dict = {}

        def fake_builder(items):
            captured["items"] = items
            return []

        syncer._build_cross_item_relationships = fake_builder
        syncer._create_relationships = MagicMock(return_value=0)

        parsed, cross, errors = syncer._process_large_event_paged("99", {"Event": {"id": "99"}}, self._attrs())
        assert (parsed, cross, errors) == (4, 0, 0)
        slim = captured["items"]
        assert len(slim) == 4, "per-page dedupe only: the IOC appears once per page"
        for s in slim:
            assert s["misp_event_id"] == "99"
            assert s["pulse_id"] in {"p1", "p2"}
            assert "description" not in s and "relationships" not in s, "accumulator stays slim"
        assert {s.get("value") or s.get("name") for s in slim} == {"1.1.1.1", "MalA", "MalB"}

    def test_slim_copies_keep_report_ids_collected_by_dedupe(self, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 10)  # single page → in-page dedupe
        syncer = self._syncer_with_parsed()
        captured: dict = {}
        syncer._build_cross_item_relationships = lambda items: captured.setdefault("items", items) and []
        syncer._create_relationships = MagicMock(return_value=0)

        syncer._process_large_event_paged("99", {"Event": {"id": "99"}}, self._attrs())
        slim = captured["items"]
        assert len(slim) == 3
        (ioc,) = [s for s in slim if s.get("value") == "1.1.1.1"]
        assert ioc["pulse_id"] == "p1"
        assert ioc["report_ids"] == ["p2"]

    def test_paged_path_links_ioc_to_malware_of_both_pulses_via_otx_pulse(self, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 2)
        syncer = self._syncer_with_parsed()
        calls: list[tuple[list, str]] = []
        syncer._create_relationships = lambda rels, source_id: (calls.append((rels, source_id)), len(rels))[1]

        parsed, cross, errors = syncer._process_large_event_paged("99", {"Event": {"id": "99"}}, self._attrs())
        assert (parsed, cross, errors) == (4, 2, 0)
        # 2026-10 (relationship provenance): the rows carry their own feed and pulse record;
        # the call-level source id is only the fallback for a row without one.
        assert [source_id for _, source_id in calls] == ["misp"]
        (rels, _) = calls[0]
        assert {
            (
                r["rel_type"],
                r["to_key"]["name"],
                r["report_id"],
                r["misp_event_id"],
                r["source"],
                tuple(r["source_refs"]),
            )
            for r in rels
        } == {
            ("INDICATES", "MalA", "p1", "99", "alienvault_otx", ("alienvault_otx:p1",)),
            ("INDICATES", "MalB", "p2", "99", "alienvault_otx", ("alienvault_otx:p2",)),
        }
        assert syncer.stats["events_processed"] == 1
        assert syncer.stats["relationships_created"] == 2


# ===========================================================================
# 4. MISP writer — MITRE_USES_TECHNIQUES meta + TLP tag
# ===========================================================================


def _mitre_comment_json(attr: dict) -> dict:
    comment = attr["comment"]
    assert comment.startswith("MITRE_USES_TECHNIQUES:"), comment
    return json.loads(comment.split("MITRE_USES_TECHNIQUES:", 1)[1].split("\n", 1)[0])


class TestTechniqueMeta:
    def test_empty_when_nothing_applies(self):
        assert _technique_meta({}) == {}
        assert _technique_meta({"uses_techniques": [], "reported_techniques": None, "pulse_id": ""}) == {}

    def test_only_t_for_mitre_style_item(self):
        assert _technique_meta({"uses_techniques": ["T1059", "T1566"]}) == {"t": ["T1059", "T1566"]}

    def test_rt_and_pid_for_otx_style_item(self):
        meta = _technique_meta({"reported_techniques": ["T1059"], "pulse_id": "abc123"})
        assert meta == {"rt": ["T1059"], "pid": "abc123"}

    def test_all_three_keys_coexist(self):
        meta = _technique_meta({"uses_techniques": ["T1"], "reported_techniques": ["T2"], "pulse_id": "p"})
        assert meta == {"t": ["T1"], "rt": ["T2"], "pid": "p"}

    def test_values_are_stringified(self):
        meta = _technique_meta({"uses_techniques": [1059], "reported_techniques": ("T1",), "pulse_id": 42})
        assert meta == {"t": ["1059"], "rt": ["T1"], "pid": "42"}

    def test_lists_capped_at_400_and_pid_at_64(self):
        meta = _technique_meta(
            {
                "uses_techniques": [f"T{i}" for i in range(401)],
                "reported_techniques": [f"R{i}" for i in range(500)],
                "pulse_id": "p" * 100,
            }
        )
        assert len(meta["t"]) == 400 and meta["t"][-1] == "T399"
        assert len(meta["rt"]) == 400 and meta["rt"][-1] == "R399"
        assert len(meta["pid"]) == 64


class TestWriterTechniqueComment:
    @pytest.mark.parametrize("creator", ["create_malware_attribute", "create_actor_attribute"])
    def test_otx_style_item_round_trips_rt_and_pid(self, writer, creator):
        item = {
            "name": "Emotet" if "malware" in creator else "TA542",
            "tag": "alienvault_otx",
            "reported_techniques": ["T1059"],
            "pulse_id": "abc123",
            "description": "pulse description",
        }
        attr = getattr(writer, creator)(item)
        assert attr is not None
        meta = _mitre_comment_json(attr)
        assert meta == {"rt": ["T1059"], "pid": "abc123"}
        assert "t" not in meta, "pulse-level ids must never masquerade as MITRE-explicit uses_techniques"
        assert "pulse description" in attr["comment"]

    @pytest.mark.parametrize("creator", ["create_malware_attribute", "create_actor_attribute"])
    def test_mitre_style_item_only_t(self, writer, creator):
        item = {"name": "APT28", "tag": "mitre_attck", "uses_techniques": ["T1059", "T1566"]}
        attr = getattr(writer, creator)(item)
        meta = _mitre_comment_json(attr)
        assert meta == {"t": ["T1059", "T1566"]}

    @pytest.mark.parametrize("creator", ["create_malware_attribute", "create_actor_attribute"])
    def test_item_without_technique_meta_has_plain_comment(self, writer, creator):
        attr = getattr(writer, creator)({"name": "Plain", "tag": "misp", "description": "just text"})
        assert not attr["comment"].startswith("MITRE_USES_TECHNIQUES:")
        assert "just text" in attr["comment"]


class TestTlpTag:
    def test_default_is_the_config_default(self, monkeypatch):
        monkeypatch.setattr(config, "EDGEGUARD_DEFAULT_TLP", "white")
        assert _tlp_tag({}) == "tlp:white"
        assert _tlp_tag({"tlp": None, "pulse_tlp": ""}) == "tlp:white"

    def test_default_follows_config_override(self, monkeypatch):
        # ``_tlp_tag`` does ``from config import EDGEGUARD_DEFAULT_TLP`` at call time, i.e. it reads
        # whatever object sys.modules["config"] holds *now*; patch that object, not the module
        # bound at collection time (other test files re-import config, which made this
        # order-dependent).
        monkeypatch.setattr(sys.modules["config"], "EDGEGUARD_DEFAULT_TLP", "green")
        assert _tlp_tag({}) == "tlp:green"

    def test_pulse_tlp_overrides_default(self):
        assert _tlp_tag({"pulse_tlp": "amber"}) == "tlp:amber"

    def test_item_tlp_wins_over_pulse_tlp(self):
        assert _tlp_tag({"tlp": "red", "pulse_tlp": "amber"}) == "tlp:red"

    @pytest.mark.parametrize("raw", ["TLP:GREEN", " Green ", "tlp:green", "GREEN"])
    def test_case_prefix_and_whitespace_normalised(self, raw):
        assert _tlp_tag({"pulse_tlp": raw}) == "tlp:green"

    @pytest.mark.parametrize("raw", ["purple", "tlp", "tlp:", "white;red", 42])
    def test_invalid_value_falls_back_to_default(self, raw, monkeypatch):
        monkeypatch.setattr(sys.modules["config"], "EDGEGUARD_DEFAULT_TLP", "white")
        assert _tlp_tag({"pulse_tlp": raw}) == "tlp:white"
        assert _tlp_tag({"tlp": raw}) == "tlp:white"

    @pytest.mark.parametrize("level", ["white", "clear", "green", "amber", "amber+strict", "red"])
    def test_tlp1_and_tlp2_labels_accepted(self, level):
        assert _tlp_tag({"tlp": level}) == f"tlp:{level}"


_MINIMAL_ITEMS = {
    "create_attribute": {"indicator_type": "ipv4", "value": "203.0.113.5", "tag": "alienvault_otx", "zone": ["global"]},
    "create_vulnerability_attribute": {"cve_id": "CVE-2021-44228", "tag": "nvd", "zone": ["global"]},
    "create_malware_attribute": {"name": "Emotet", "tag": "alienvault_otx", "zone": ["global"]},
    "create_actor_attribute": {"name": "APT28", "tag": "mitre_attck", "zone": ["global"]},
    "create_technique_attribute": {
        "mitre_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tag": "mitre_attck",
        "zone": ["global"],
    },
    "create_tactic_attribute": {
        "mitre_id": "TA0001",
        "name": "Initial Access",
        "shortname": "initial-access",
        "tag": "mitre_attck",
        "zone": ["global"],
    },
    "create_tool_attribute": {"mitre_id": "S0154", "name": "Cobalt Strike", "tag": "mitre_attck", "zone": ["global"]},
}


def _tlp_tags(attr: dict) -> list[str]:
    return [t["name"] for t in attr["Tag"] if t["name"].lower().startswith("tlp:")]


class TestEveryAttributeCarriesOneTlpTag:
    def test_creator_inventory_matches_writer(self):
        creators = {n for n in dir(MISPWriter) if n.startswith("create_") and n.endswith("_attribute")}
        assert creators == set(_MINIMAL_ITEMS), (
            "a MISPWriter.create_*_attribute creator was added or renamed — "
            "add a minimal item for it to _MINIMAL_ITEMS so the TLP contract covers it"
        )

    @pytest.mark.parametrize("creator", sorted(_MINIMAL_ITEMS))
    def test_exactly_one_tlp_tag_with_the_default_level(self, writer, creator, monkeypatch):
        monkeypatch.setattr(config, "EDGEGUARD_DEFAULT_TLP", "white")
        attr = getattr(writer, creator)(dict(_MINIMAL_ITEMS[creator]))
        assert attr is not None, f"{creator} rejected the minimal item"
        assert _tlp_tags(attr) == ["tlp:white"]

    @pytest.mark.parametrize("creator", sorted(_MINIMAL_ITEMS))
    def test_pulse_tlp_override_lands_on_every_creator(self, writer, creator):
        attr = getattr(writer, creator)({**_MINIMAL_ITEMS[creator], "pulse_tlp": "amber"})
        assert _tlp_tags(attr) == ["tlp:amber"]

    @pytest.mark.parametrize("creator", sorted(_MINIMAL_ITEMS))
    def test_invalid_tlp_falls_back_rather_than_dropping_the_tag(self, writer, creator, monkeypatch):
        monkeypatch.setattr(config, "EDGEGUARD_DEFAULT_TLP", "white")
        attr = getattr(writer, creator)({**_MINIMAL_ITEMS[creator], "tlp": "rainbow"})
        assert _tlp_tags(attr) == ["tlp:white"]


# ===========================================================================
# 5. Parser — rt / pid, TLP rehydration, actor-name hygiene
# ===========================================================================

_EVENT = {"id": 4242, "info": "EdgeGuard-alienvault_otx-2026-10-01", "date": "2026-10-01", "Tag": []}
_OTX_COMMENT = 'MITRE_USES_TECHNIQUES:{"rt":["T1059"],"pid":"abc123"}'
_MITRE_COMMENT = 'MITRE_USES_TECHNIQUES:{"t":["T1003","T1056"]}\nFree-form description'


def _attr(attr_type: str, value: str, comment: str = "", tags=()):
    return {
        "type": attr_type,
        "value": value,
        "uuid": "10000000-0000-0000-0000-00000000abcd",
        "comment": comment,
        "Tag": [{"name": t} for t in tags],
    }


def _kind(item: dict) -> str:
    return item.get("type") or ("indicator" if item.get("indicator_type") else "?")


class TestExtractTlpTag:
    def test_dict_tag(self):
        assert _extract_tlp_tag([{"name": "tlp:amber"}]) == "amber"

    def test_case_insensitive_and_stripped(self):
        assert _extract_tlp_tag([{"name": "TLP:Amber "}]) == "amber"

    def test_string_tags_accepted(self):
        assert _extract_tlp_tag(["source:otx", "tlp:red"]) == "red"

    def test_first_tlp_tag_wins(self):
        assert _extract_tlp_tag([{"name": "tlp:green"}, {"name": "tlp:red"}]) == "green"

    def test_no_tlp_tag_returns_the_configured_default(self):
        # 2026-10-12: an attribute whose tags were lost to an interrupted push synced without tlp.
        assert config.EDGEGUARD_DEFAULT_TLP
        assert _extract_tlp_tag([{"name": "source:otx"}, {"name": "zone:Energy"}]) == config.EDGEGUARD_DEFAULT_TLP
        assert _extract_tlp_tag([]) == config.EDGEGUARD_DEFAULT_TLP
        assert _extract_tlp_tag([]) == config.EDGEGUARD_DEFAULT_TLP

    def test_empty_level_is_skipped(self):
        assert _extract_tlp_tag([{"name": "tlp:"}, {"name": "tlp:white"}]) == "white"
        assert _extract_tlp_tag([{"name": "tlp:  "}]) == config.EDGEGUARD_DEFAULT_TLP

    def test_non_string_names_ignored(self):
        assert _extract_tlp_tag([{"name": None}, {}, {"name": "tlp:clear"}]) == "clear"

    def test_the_default_is_logged_with_the_attribute(self, caplog):
        # The node passes tlp_on_every_node with the default; the sync log names the attribute.
        with caplog.at_level(logging.WARNING, logger="run_misp_to_neo4j"):
            assert _extract_tlp_tag([], "5f0c1a2e-0000-4000-8000-000000000001") == config.EDGEGUARD_DEFAULT_TLP
            assert _extract_tlp_tag([{"name": "tlp:green"}], "5f0c1a2e-0000-4000-8000-000000000002") == "green"
        messages = [r.getMessage() for r in caplog.records if "[TLP]" in r.getMessage()]
        assert len(messages) == 1 and "5f0c1a2e-0000-4000-8000-000000000001" in messages[0]


class TestParseAttributeReportedTechniques:
    @pytest.mark.parametrize(
        "attr_type,value,item_type", [("threat-actor", "APT-Test", "actor"), ("malware-type", "Emotet", "malware")]
    )
    def test_otx_style_comment_yields_reported_techniques_and_pulse_id(self, syncer, attr_type, value, item_type):
        item, _rels = syncer.parse_attribute(_attr(attr_type, value, comment=_OTX_COMMENT), _EVENT)
        assert item is not None and item["type"] == item_type
        assert item["reported_techniques"] == ["T1059"]
        assert item["pulse_id"] == "abc123"
        assert item["uses_techniques"] == []

    @pytest.mark.parametrize(
        "attr_type,value,item_type", [("threat-actor", "APT-Test", "actor"), ("malware-type", "Emotet", "malware")]
    )
    def test_mitre_style_comment_yields_uses_techniques_only(self, syncer, attr_type, value, item_type):
        item, _rels = syncer.parse_attribute(_attr(attr_type, value, comment=_MITRE_COMMENT), _EVENT)
        assert item["type"] == item_type
        assert item["uses_techniques"] == ["T1003", "T1056"]
        assert item["reported_techniques"] == []
        assert item["pulse_id"] == ""
        assert "Free-form description" in item["description"]

    @pytest.mark.parametrize("attr_type,value", [("threat-actor", "APT-Test"), ("malware-type", "Emotet")])
    def test_plain_comment_yields_empty_defaults(self, syncer, attr_type, value):
        item, _rels = syncer.parse_attribute(_attr(attr_type, value, comment="just a description"), _EVENT)
        assert item["uses_techniques"] == []
        assert item["reported_techniques"] == []
        assert item["pulse_id"] == ""

    def test_all_three_keys_round_trip_together(self, syncer):
        comment = 'MITRE_USES_TECHNIQUES:{"t":["T1003"],"rt":["T1059"],"pid":"p-9"}\ntail'
        item, _ = syncer.parse_attribute(_attr("malware-type", "Emotet", comment=comment), _EVENT)
        assert item["uses_techniques"] == ["T1003"]
        assert item["reported_techniques"] == ["T1059"]
        assert item["pulse_id"] == "p-9"


_SEVEN_ATTRIBUTE_KINDS = [
    ("ip-dst", "203.0.113.5", "indicator"),
    ("vulnerability", "CVE-2025-99999", "vulnerability"),
    ("threat-actor", "APT-Test", "actor"),
    ("malware-type", "Emotet", "malware"),
    ("text", "T1059: Command and Scripting Interpreter", "technique"),
    ("text", "TA0001: Initial Access", "tactic"),
    ("text", "S0002: Mimikatz", "tool"),
]


class TestParseAttributeTlp:
    @pytest.mark.parametrize("attr_type,value,kind", _SEVEN_ATTRIBUTE_KINDS)
    def test_tlp_amber_tag_is_rehydrated_on_every_item_kind(self, syncer, attr_type, value, kind):
        item, _ = syncer.parse_attribute(_attr(attr_type, value, tags=["tlp:amber"]), _EVENT)
        assert item is not None, f"{attr_type}/{value} did not parse"
        assert _kind(item) == kind
        assert item["tlp"] == "amber"

    @pytest.mark.parametrize("attr_type,value,kind", _SEVEN_ATTRIBUTE_KINDS)
    def test_untagged_attribute_yields_the_default_tlp(self, syncer, attr_type, value, kind, monkeypatch):
        # 2026-10-12: an attribute whose tags were lost to an interrupted push must still carry a level.
        import config

        monkeypatch.setattr(config, "EDGEGUARD_DEFAULT_TLP", "white")
        item, _ = syncer.parse_attribute(_attr(attr_type, value), _EVENT)
        assert item is not None
        assert _kind(item) == kind
        assert item["tlp"] == "white"

    def test_tlp_tag_is_case_normalised_and_other_tags_do_not_interfere(self, syncer):
        item, _ = syncer.parse_attribute(
            _attr("ip-dst", "203.0.113.9", tags=["source:alienvault_otx", "TLP:Green", "zone:Energy"]), _EVENT
        )
        assert item["tlp"] == "green"


class TestParseAttributeActorNameHygiene:
    """``threat-actor`` attributes go through ``clean_actor_names``: a composite
    ("a, b" / "a and b") or a generic phrase ("russian hackers") must never
    become a ThreatActor node — the attribute is skipped with an INFO log."""

    @pytest.mark.parametrize(
        "value,reason",
        [
            ("lazarus group, kimsuky", "composite name — split at collection"),
            ("head mare and twelve", "composite name — split at collection"),
            ("APT28 and APT29", "composite name — split at collection"),
            ("russian hackers", "generic phrase, not a name"),
            ("Chinese state-backed groups", "generic phrase, not a name"),
        ],
    )
    def test_composite_or_generic_actor_attribute_is_skipped(self, syncer, caplog, value, reason):
        caplog.set_level(logging.INFO)
        item, rels = syncer.parse_attribute(_attr("threat-actor", value, comment=_OTX_COMMENT), _EVENT)
        assert (item, rels) == (None, [])
        assert reason in caplog.text

    def test_plain_name_parses_with_report_provenance_and_tlp(self, syncer):
        item, rels = syncer.parse_attribute(
            _attr("threat-actor", "Sandworm Team", comment=_OTX_COMMENT, tags=["tlp:amber"]), _EVENT
        )
        assert item is not None
        assert item["type"] == "actor"
        assert item["name"] == "Sandworm Team"
        assert item["reported_techniques"] == ["T1059"]
        assert item["pulse_id"] == "abc123"
        assert item["uses_techniques"] == []
        assert item["tlp"] == "amber"
        assert item["misp_event_id"] == "4242"
        assert isinstance(rels, list)

    @pytest.mark.parametrize("value", ["APT28", "TA542", "APT-X", "  Sandworm   Team "])
    def test_whitespace_variants_and_short_ids_still_parse(self, syncer, value):
        item, _ = syncer.parse_attribute(_attr("threat-actor", value), _EVENT)
        assert item is not None and item["type"] == "actor"


# ===========================================================================
# 6. OTX collector — reported_techniques + one actor per cleaned adversary name
# ===========================================================================


class TestOtxCollectorReportedTechniquesAndActorHygiene:
    def _collector(self):
        from collectors.otx_collector import OTXCollector

        collector = OTXCollector.__new__(OTXCollector)
        collector.api_key = "test-otx-key-64chars" + "a" * 44
        collector.tag = "alienvault_otx"
        collector.session = MagicMock()
        collector.rate_limiter = MagicMock()
        collector.rate_limiter.wait_if_needed = MagicMock()
        collector._last_http_status = 200
        collector.circuit_breaker = MagicMock()
        collector.circuit_breaker.can_execute.return_value = True
        collector.misp_writer = None
        collector.source_name = "otx"
        collector.health_check = MagicMock(return_value=True)
        return collector

    @staticmethod
    def _pulse(adversary: str, pulse_id: str = "pulse-actor-1") -> dict:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "id": pulse_id,
            "name": "Hygiene pulse",
            "created": now,
            "modified": now,
            "adversary": adversary,
            "TLP": "amber",
            "attack_ids": [{"id": "T1059"}, "T1105"],
            "malware_families": ["Emotet"],
            "indicators": [{"type": "IPv4", "indicator": "203.0.113.5", "description": "ioc"}],
        }

    def _collect(self, pulse: dict) -> list:
        collector = self._collector()
        # The incremental path pages until ``_fetch_pulses`` returns an empty
        # page (sleeping 2 s between pages), so serve the pulse once and then
        # an empty page; neutralise the sleep and the checkpoint read/write.
        pages = iter([[pulse]])
        with (
            patch.object(collector, "check_service_available", return_value=True),
            patch.object(collector, "_fetch_pulses", side_effect=lambda **kw: next(pages, [])),
            patch("collectors.otx_collector.time.sleep", lambda *_a, **_k: None),
            patch("collectors.otx_collector.get_source_incremental", return_value={}),
            patch("collectors.otx_collector.update_source_incremental", lambda *_a, **_k: None),
        ):
            result = collector.collect(limit=5, push_to_misp=False)
        assert isinstance(result, list), f"push_to_misp=False must return the item list, got {type(result)}"
        return result

    def test_composite_adversary_emits_one_actor_per_cleaned_name(self):
        actors = [i for i in self._collect(self._pulse("lazarus group, kimsuky")) if i.get("type") == "actor"]
        assert sorted(a["name"] for a in actors) == ["kimsuky", "lazarus group"]
        for actor in actors:
            assert actor["pulse_id"] == "pulse-actor-1"
            assert actor["reported_techniques"] == ["T1059", "T1105"]
            assert "uses_techniques" not in actor, "pulse attack_ids must not pose as MITRE-explicit uses"
            assert actor["pulse_tlp"] == "amber"
            assert actor["tag"] == "alienvault_otx"

    def test_and_joined_composite_splits(self):
        actors = [i for i in self._collect(self._pulse("head mare and twelve")) if i.get("type") == "actor"]
        assert sorted(a["name"] for a in actors) == ["head mare", "twelve"]

    def test_generic_phrase_emits_no_actor_but_keeps_the_rest_of_the_pulse(self):
        items = self._collect(self._pulse("russian hackers"))
        assert not [i for i in items if i.get("type") == "actor"]
        assert any(i.get("value") == "203.0.113.5" for i in items), "indicators are unaffected"

    def test_plain_name_emits_exactly_one_actor(self):
        actors = [i for i in self._collect(self._pulse("Sandworm Team")) if i.get("type") == "actor"]
        assert [a["name"] for a in actors] == ["Sandworm Team"]

    @pytest.mark.parametrize("adversary", ["", None])
    def test_missing_adversary_emits_no_actor(self, adversary):
        pulse = self._pulse("x")
        pulse["adversary"] = adversary
        assert not [i for i in self._collect(pulse) if i.get("type") == "actor"]

    def test_malware_items_carry_reported_techniques_not_uses_techniques(self):
        malware = [i for i in self._collect(self._pulse("Sandworm Team")) if i.get("type") == "malware"]
        assert malware, "pulse malware_families must yield malware items"
        for m in malware:
            assert m["reported_techniques"] == ["T1059", "T1105"]
            assert "uses_techniques" not in m
            assert m["pulse_id"] == "pulse-actor-1"

    def test_source_never_writes_pulse_attack_ids_into_uses_techniques(self):
        text = _OTX.read_text()
        assert '"uses_techniques": pulse_attack_ids' not in text, (
            "pulse ids must never masquerade as MITRE explicit uses"
        )


# ===========================================================================
# 7. build_relationships.py — Q4 gone, 5b/6b present, ownership marker everywhere
# ===========================================================================


class TestBuildRelationshipsSource:
    def test_q4_cooccurrence_block_is_absent(self):
        text = _BUILD_REL.read_text()
        names = {name for name, _, _ in _inner_queries()}
        assert "_q4_inner" not in names
        assert "4. Indicator → Malware (INDICATES)" not in text
        assert not re.search(r"\[LINK\] 4/\d+", text)
        for name, line, body in _inner_queries():
            assert "misp_cooccurrence" not in body, f"{name}@{line} stamps misp_cooccurrence"
            assert "eid IN i.misp_event_ids" not in body, f"{name}@{line} re-introduces the event-id join"

    def test_only_q9_merges_indicates(self):
        indicates = [name for name, _, body in _inner_queries() if "[r:INDICATES]" in body]
        # 2026-10 (regular-update linking): Q9b links an IOC to the families named by its pulse(s) from
        # the indicator side (otx_pulse 0.6, ON CREATE only); the sync still pairs same-run items.
        assert indicates == ["_q9_inner", "_q9b_inner"], "IOC-level family match (Q9) + pulse-scoped (Q9b) only"

    def test_5b_actor_reported_techniques(self):
        bodies = [body for _, _, body in _inner_queries() if "UNWIND a.reported_techniques AS tid" in body]
        assert len(bodies) == 1
        body = bodies[0]
        assert "MERGE (a)-[r:EMPLOYS_TECHNIQUE]->(t)" in body
        assert 'r.match_type = "otx_pulse"' in body
        assert "r.confidence_score = 0.6" in body
        assert "r.edgeguard_managed = true" in body
        assert "r.updated_at = datetime()" in body
        text = _BUILD_REL.read_text()
        assert '"employs_technique_reported"' in text
        assert re.search(r"\[LINK\] 5b/\d+", text)

    def test_6b_malware_reported_techniques(self):
        bodies = [body for _, _, body in _inner_queries() if "UNWIND m.reported_techniques AS tid" in body]
        assert len(bodies) == 1
        body = bodies[0]
        assert "MERGE (m)-[r:IMPLEMENTS_TECHNIQUE]->(t)" in body
        assert 'r.match_type = "otx_pulse"' in body
        assert "r.confidence_score = 0.6" in body
        assert "r.edgeguard_managed = true" in body
        text = _BUILD_REL.read_text()
        assert '"malware_implements_technique_reported"' in text
        assert re.search(r"\[LINK\] 6b/\d+", text)

    def test_reported_queries_run_after_their_mitre_explicit_sibling(self):
        """ON CREATE semantics: a pair MITRE also asserts must keep the
        ``mitre_explicit`` / 0.95 stamp, so Q5 must run before 5b and Q6 before 6b."""
        text = _BUILD_REL.read_text()
        order = [re.search(rf"\[LINK\] {re.escape(step)}/\d+ ", text) for step in ("5", "5b", "6", "6b", "7a")]
        assert all(order), order
        order = [m.start() for m in order]
        assert order == sorted(order)

    def test_5b_6b_skip_queries_count_missing_techniques(self):
        text = _BUILD_REL.read_text()
        for var, prop in (("_q5b_skip", "a.reported_techniques"), ("_q6b_skip", "m.reported_techniques")):
            idx = text.find(f"{var} = (")
            assert idx > 0, f"{var} missing"
            block = text[idx : idx + 400]
            assert f"UNWIND {prop} AS tid" in block
            assert "NOT EXISTS { MATCH (t:Technique {mitre_id: tid}) }" in block

    def test_every_link_inner_query_sets_edgeguard_managed(self):
        text = _BUILD_REL.read_text()
        steps = re.findall(r"\[LINK\] (\w+)/\d+", text)
        assert steps, "no [LINK] step banners found"
        assert "4" not in steps and {"5b", "6b"} <= set(steps)
        merges = [(n, ln, b) for n, ln, b in _inner_queries() if "MERGE (" in b and "-[r:" in b]
        assert len(merges) == len(steps), (
            f"{len(steps)} [LINK] steps but {len(merges)} MERGE inner queries — "
            "every link step must be an inner query (and vice versa) for this pin to hold"
        )
        missing = [f"{n}@{ln}" for n, ln, b in merges if "r.edgeguard_managed = true" not in b]
        assert not missing, f"inner queries without the ownership marker: {missing}"


# ===========================================================================
# 8. neo4j_client — batch rows / _set_clause / merge_* / tlp / clear
# ===========================================================================


def _indicates_rel(**overrides):
    rel = {
        "rel_type": "INDICATES",
        "from_type": "Indicator",
        "from_key": {"value": "203.0.113.5", "indicator_type": "ipv4"},
        "to_type": "Malware",
        "to_key": {"name": "emotet"},
        "confidence": 0.6,
        "match_type": "otx_pulse",
        "report_id": "pulse-1",
        "source": "alienvault_otx",
        "source_refs": ["alienvault_otx:pulse-1"],
        "misp_event_id": "777",
    }
    rel.update(overrides)
    return rel


def _attributed_rel(**overrides):
    rel = {
        "rel_type": "ATTRIBUTED_TO",
        "from_type": "Malware",
        "from_key": {"name": "emotet"},
        "to_type": "ThreatActor",
        "to_key": {"name": "ta542"},
        "confidence": 0.6,
        "match_type": "otx_pulse",
        "report_id": "pulse-1",
        "source": "alienvault_otx",
        "source_refs": ["alienvault_otx:pulse-1"],
        "misp_event_id": "777",
    }
    rel.update(overrides)
    return rel


class TestBatchRelationshipSetClause:
    def _run(self, rels, source_id="alienvault_otx"):
        client, captured = _capturing_client()
        client.create_misp_relationships_batch(rels, source_id=source_id)
        assert captured, "expected at least one UNWIND batch"
        return captured

    def test_set_clause_writes_ownership_match_type_and_provenance(self):
        for query, _rows in self._run([_indicates_rel(), _attributed_rel()]):
            assert "r.edgeguard_managed = true" in query
            assert "THEN coalesce(row.match_type, r.match_type) ELSE r.match_type END" in query, (
                "label follows the stronger evidence"
            )
            # 2026-10 (relationship provenance): feeds, their record ids and the MISP events
            # accumulate; the single last-writer-wins ``r.source_id`` and ``r.report_ids`` are gone.
            assert "r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source])" in query
            assert (
                "r.source_refs = apoc.coll.toSet(coalesce(r.source_refs, []) + coalesce(row.source_refs, []))" in query
            )
            assert "r.source_id" not in query and "r.report_ids" not in query

    def test_indicates_rows_carry_match_type_and_report_id(self):
        rows = [r for q, rows in self._run([_indicates_rel()]) if "[r:INDICATES]" in q for r in rows]
        assert len(rows) == 1
        row = rows[0]
        assert row["value"] == "203.0.113.5" and row["malware"] == "emotet"
        assert row["source"] == "alienvault_otx"
        assert row["source_refs"] == ["alienvault_otx:pulse-1"]
        assert row["confidence"] == 0.6
        assert row["misp_event_id"] == "777"
        assert row["match_type"] == "otx_pulse"
        assert "source_id" not in row and "report_id" not in row

    def test_attributed_to_rows_carry_match_type_and_report_id(self):
        rows = [r for q, rows in self._run([_attributed_rel()]) if "[r:ATTRIBUTED_TO]" in q for r in rows]
        assert len(rows) == 1
        row = rows[0]
        assert row["malware"] == "emotet" and row["actor"] == "ta542"
        assert row["match_type"] == "otx_pulse"
        assert row["source"] == "alienvault_otx" and row["source_refs"] == ["alienvault_otx:pulse-1"]

    def test_missing_match_type_and_blank_refs_are_dropped(self):
        rel = _indicates_rel()
        del rel["match_type"]
        del rel["source"]
        rel["source_refs"] = ["   ", None]
        rows = [r for q, rows in self._run([rel], source_id="misp") if "[r:INDICATES]" in q for r in rows]
        assert rows[0]["match_type"] is None, "coalesce(row.match_type, r.match_type) must then keep the old value"
        assert rows[0]["source_refs"] == [], "blank record ids must not be appended to r.source_refs"
        assert rows[0]["source"] == "misp", "a row without a feed falls back to the batch's source id"

    def test_exploits_constant_match_type_still_wins_over_row_match_type(self):
        rel = {
            "rel_type": "EXPLOITS",
            "from_type": "Indicator",
            "from_key": {"value": "203.0.113.5", "indicator_type": "ipv4"},
            "to_type": "CVE",
            "to_key": {"cve_id": "CVE-2021-44228"},
            "confidence": 0.9,
            "misp_event_id": "1",
        }
        queries = [q for q, _ in self._run([rel], source_id="misp") if "[r:EXPLOITS]" in q]
        assert queries
        for q in queries:
            coalesce_idx = q.find("THEN coalesce(row.match_type, r.match_type) ELSE r.match_type END")
            constant_idx = q.find("r.match_type = 'cve_tag'")
            assert 0 <= coalesce_idx < constant_idx, "the constant cve_tag SET must be applied after the coalesce"


class TestMergeCvePromotesResilmeshListProps:
    _LIST_PROPS = ("cwe", "ref_tags", "cpe_type", "result_impacts", "reference_urls", "affected_products")

    def _client(self):
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        client._connection_healthy = True
        return client

    def test_six_list_props_promoted_when_present(self):
        client = self._client()
        data = {
            "cve_id": "CVE-2021-44228",
            "tag": "nvd",
            "zone": ["global"],
            "cwe": ["CWE-502"],
            "ref_tags": ["Vendor Advisory", "Patch"],
            "cpe_type": ["a"],
            "result_impacts": ["RCE"],
            "reference_urls": ["https://example.test/advisory"],
            "affected_products": ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
        }
        with patch.object(client, "merge_node_with_source", return_value=True) as merge:
            assert client.merge_cve(data, source_id="nvd") is True
        merge.assert_called_once()
        args, kwargs = merge.call_args
        assert args[0] == "CVE" and args[1] == {"cve_id": "CVE-2021-44228"} and args[3] == "nvd"
        extra = kwargs["extra_props"]
        for prop in self._LIST_PROPS:
            assert extra[prop] == data[prop], prop

    def test_absent_empty_or_non_list_values_are_omitted(self):
        client = self._client()
        data = {
            "cve_id": "CVE-2021-44228",
            "tag": "nvd",
            "zone": ["global"],
            "cwe": [],
            "ref_tags": None,
            "cpe_type": "a",  # scalar, not a list → not promoted
            "description": "keep me",
        }
        with patch.object(client, "merge_node_with_source", return_value=True) as merge:
            client.merge_cve(data, source_id="nvd")
        extra = merge.call_args.kwargs["extra_props"] or {}
        for prop in self._LIST_PROPS:
            assert prop not in extra, prop
        assert extra["description"] == "keep me"

    def test_none_and_blank_entries_dropped_and_values_stringified(self):
        client = self._client()
        data = {"cve_id": "CVE-2021-44228", "tag": "nvd", "zone": ["global"], "cwe": ["CWE-79", None, "", 20]}
        with patch.object(client, "merge_node_with_source", return_value=True) as merge:
            client.merge_cve(data, source_id="nvd")
        assert merge.call_args.kwargs["extra_props"]["cwe"] == ["CWE-79", "20"]


class TestMergeMalwareAndActorReportedTechniques:
    @pytest.mark.parametrize("method,label", [("merge_malware", "Malware"), ("merge_actor", "ThreatActor")])
    def test_reported_techniques_and_pulse_ids_passed(self, method, label):
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        data = {
            "name": "Emotet",
            "tag": "alienvault_otx",
            "zone": ["global"],
            "reported_techniques": ["T1059", "T1105"],
            "pulse_id": "abc123",
        }
        with patch.object(client, "merge_node_with_source", return_value=True) as merge:
            assert getattr(client, method)(data, source_id="alienvault_otx") is True
        args, kwargs = merge.call_args
        assert args[0] == label
        extra = kwargs["extra_props"]
        assert extra["reported_techniques"] == ["T1059", "T1105"]
        assert extra["pulse_ids"] == ["abc123"]
        assert extra["uses_techniques"] == []

    @pytest.mark.parametrize("method", ["merge_malware", "merge_actor"])
    def test_without_pulse_id_no_pulse_ids_key_and_reported_defaults_empty(self, method):
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        with patch.object(client, "merge_node_with_source", return_value=True) as merge:
            getattr(client, method)({"name": "Emotet", "tag": "mitre_attck", "zone": ["global"]}, source_id="x")
        extra = merge.call_args.kwargs["extra_props"]
        assert extra["reported_techniques"] == []
        assert "pulse_ids" not in extra

    @pytest.mark.parametrize("method", ["merge_malware", "merge_actor"])
    def test_reported_techniques_and_pulse_ids_accumulate_as_arrays_in_cypher(self, method):
        client, session = _make_neo4j_mock()
        getattr(client, method)(
            {
                "name": "Emotet",
                "tag": "alienvault_otx",
                "zone": ["global"],
                "reported_techniques": ["T1059"],
                "pulse_id": "p1",
            },
            source_id="alienvault_otx",
        )
        calls = session.run.call_args_list
        assert len(calls) >= 2
        cypher, kwargs = calls[1][0][0], calls[1][1]
        assert (
            "n.reported_techniques = apoc.coll.toSet(coalesce(n.reported_techniques, []) + $reported_techniques)"
            in cypher
        )
        assert "n.pulse_ids = apoc.coll.toSet(coalesce(n.pulse_ids, []) + $pulse_ids)" in cypher
        assert kwargs["reported_techniques"] == ["T1059"]
        assert kwargs["pulse_ids"] == ["p1"]


class TestTlpPromotion:
    def test_merge_node_with_source_promotes_tlp(self):
        client, session = _make_neo4j_mock()
        client.merge_actor({"name": "APT28", "tag": "mitre_attck", "zone": ["global"], "tlp": "amber"}, source_id="x")
        cypher, kwargs = session.run.call_args_list[1][0][0], session.run.call_args_list[1][1]
        assert "n.tlp = CASE WHEN" in cypher and "$tlp" in cypher, "tlp keeps the most restrictive level"
        assert cypher.count("WHEN 'red' THEN 5") >= 1 and "WHEN 'clear' THEN 1" in cypher, "rank ladder missing"
        assert kwargs["tlp"] == "amber"

    def test_merge_node_with_source_skips_tlp_when_absent(self):
        client, session = _make_neo4j_mock()
        client.merge_actor({"name": "APT28", "tag": "mitre_attck", "zone": ["global"], "tlp": ""}, source_id="x")
        cypher, kwargs = session.run.call_args_list[1][0][0], session.run.call_args_list[1][1]
        assert "n.tlp" not in cypher
        assert "tlp" not in kwargs

    def test_explicit_extra_prop_tlp_wins_over_item_tlp(self):
        client, session = _make_neo4j_mock()
        client.merge_node_with_source(
            "Malware", {"name": "x"}, {"name": "x", "tlp": "amber"}, "src", extra_props={"tlp": "red"}
        )
        assert session.run.call_args_list[1][1]["tlp"] == "red"

    def test_indicator_batch_stages_and_sets_tlp(self):
        client, session = _make_neo4j_mock()
        client.merge_indicators_batch(
            [
                {"indicator_type": "ipv4", "value": "1.2.3.4", "tag": "otx", "zone": ["global"], "tlp": "green"},
                {"indicator_type": "ipv4", "value": "5.6.7.8", "tag": "otx", "zone": ["global"]},
            ],
            source_id="misp",
        )
        batch_calls = [c for c in session.run.call_args_list if "UNWIND $batch" in c[0][0]]
        assert batch_calls, "indicator batch MERGE not executed"
        cypher, kwargs = batch_calls[0][0][0], batch_calls[0][1]
        assert "n.tlp = CASE WHEN" in cypher and "item.tlp" in cypher, "tlp keeps the most restrictive level"
        by_value = {item["value"]: item for item in kwargs["batch"]}
        assert by_value["1.2.3.4"]["tlp"] == "green"
        assert "tlp" not in by_value["5.6.7.8"], "absent TLP must stay NULL so coalesce keeps the old value"


class TestClearEdgeguardManaged:
    def _client(self, managed: int, deleted_batches: list[int], rel_batches: list[int] | None = None):
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        client._connection_healthy = True
        queries: list[str] = []
        deletes = iter(deleted_batches)
        rel_deletes = iter(rel_batches or [])

        def run(query, **kwargs):
            queries.append(query)
            result = MagicMock()
            if "DETACH DELETE" in query:
                result.single.return_value = {"deleted": next(deletes, 0)}
            elif "DELETE r" in query:
                result.single.return_value = {"deleted": next(rel_deletes, 0)}
            elif "<> true" in query:
                result.single.return_value = {"count": 5}
            else:
                result.single.return_value = {"count": managed}
            return result

        session = MagicMock()
        session.run = run
        client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
        client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
        return client, queries

    def test_every_query_is_scoped_by_the_ownership_marker(self):
        client, queries = self._client(managed=3, deleted_batches=[3])
        assert client.clear_edgeguard_managed() is True
        assert queries
        for q in queries:
            assert "edgeguard_managed" in q, q
        deletes = [q for q in queries if "DETACH DELETE" in q]
        assert deletes
        for q in deletes:
            assert "MATCH (n) WHERE n.edgeguard_managed = true" in q
            assert "DETACH DELETE n" in q
        bare = re.compile(r"MATCH \(n\)\s+(WITH|DETACH|RETURN)")
        assert not any(bare.search(q) for q in queries), "a bare MATCH (n) would wipe ResilMesh's nodes too"
        assert not any("MATCH (s:Source) DETACH DELETE s" in q for q in queries), (
            "clear_all's unconditional Source wipe must not be part of the scoped clear"
        )

    def test_batches_until_the_marked_count_is_reached(self):
        client, queries = self._client(managed=25_000, deleted_batches=[10_000, 10_000, 5_000])
        assert client.clear_edgeguard_managed() is True
        assert len([q for q in queries if "DETACH DELETE" in q]) == 3
        assert "LIMIT 10000" in [q for q in queries if "DETACH DELETE" in q][0]

    def test_stops_when_a_batch_deletes_nothing(self):
        client, queries = self._client(managed=5, deleted_batches=[0])
        assert client.clear_edgeguard_managed() is True
        assert len([q for q in queries if "DETACH DELETE" in q]) == 1

    def test_nothing_marked_runs_no_delete(self):
        client, queries = self._client(managed=0, deleted_batches=[])
        assert client.clear_edgeguard_managed() is True
        assert not [q for q in queries if "DETACH DELETE" in q]

    def test_relationships_of_marked_nodes_go_first_in_bounded_batches(self):
        # 2026-10-12: DETACH DELETE on a 10,000-node batch that holds a hub ran a 2g heap out of
        # memory on the 478K-node / 2.66M-edge graph; relationships are deleted first, bounded.
        client, queries = self._client(managed=3, deleted_batches=[3], rel_batches=[50_000, 20, 0])
        assert client.clear_edgeguard_managed() is True
        rel_queries = [q for q in queries if "DELETE r" in q]
        assert len(rel_queries) == 3
        for q in rel_queries:
            assert "MATCH (n)-[r]-() WHERE n.edgeguard_managed = true" in q
            assert "WITH DISTINCT r LIMIT 50000 DELETE r" in q
        first_node_delete = next(i for i, q in enumerate(queries) if "DETACH DELETE" in q)
        assert all(i < first_node_delete for i, q in enumerate(queries) if "DELETE r" in q)

    def test_returns_false_without_driver(self):
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = None
        assert client.clear_edgeguard_managed() is False

    def test_returns_false_on_generic_error(self):
        client, _ = self._client(managed=1, deleted_batches=[1])
        client.driver.session.return_value.__enter__.return_value.run = MagicMock(side_effect=RuntimeError("boom"))
        assert client.clear_edgeguard_managed() is False

    def test_transient_errors_propagate_to_the_retry_decorator(self):
        assert hasattr(neo4j_client_mod.Neo4jClient.clear_edgeguard_managed, "__wrapped__"), (
            "clear_edgeguard_managed must be wrapped by @retry_with_backoff like clear_all"
        )
        client, _ = self._client(managed=1, deleted_batches=[1])
        run = MagicMock(side_effect=neo4j_client_mod.neo4j_exceptions.ServiceUnavailable("down"))
        client.driver.session.return_value.__enter__.return_value.run = run
        # 2026-10 audit: the decorator sleeps 2/4/8 s for real — patch it out and pin the retry count
        # (max_retries=3 → 4 attempts); the old test slept 14 s and passed with a non-retrying decorator.
        sleeps: list = []
        monkeypatch_sleep = neo4j_client_mod.time.sleep
        neo4j_client_mod.time.sleep = lambda s: sleeps.append(s)
        try:
            with pytest.raises(neo4j_client_mod.neo4j_exceptions.ServiceUnavailable):
                client.clear_edgeguard_managed()
        finally:
            neo4j_client_mod.time.sleep = monkeypatch_sleep
        assert run.call_count == 4, f"expected 4 attempts (1 + 3 retries), got {run.call_count}"
        assert len(sleeps) == 3 and all(sl > 0 for sl in sleeps)


class TestOwnershipMarkerOnOtherWriters:
    def test_source_node_merge_marks_edgeguard_managed(self):
        text = _NEO4J_CLIENT.read_text()
        idx = text.find("s.edgeguard_managed = true")
        assert idx > 0
        assert "MERGE (s:Source" in text[idx - 1500 : idx]

    def test_cvss_sub_node_edges_marked(self):
        import inspect

        src = inspect.getsource(Neo4jClient._merge_cvss_node)
        assert "r1.edgeguard_managed = true" in src
        assert "r2.edgeguard_managed = true" in src

    @pytest.mark.parametrize("method", ["create_vulnerability_refers_to_cve", "create_cve_refers_to_vulnerability"])
    def test_refers_to_bridges_marked(self, method):
        import inspect

        src = inspect.getsource(getattr(Neo4jClient, method))
        assert "[r:REFERS_TO]" in src
        assert "r.edgeguard_managed = true" in src

    def test_batch_indicator_sourced_from_edge_marked(self):
        client, session = _make_neo4j_mock()
        client.merge_indicators_batch(
            [{"indicator_type": "ipv4", "value": "1.2.3.4", "tag": "otx", "zone": ["global"]}], source_id="misp"
        )
        cypher = [c[0][0] for c in session.run.call_args_list if "UNWIND $batch" in c[0][0]][0]
        sourced_idx = cypher.find("MERGE (n)-[r:SOURCED_FROM]->(s)")
        assert sourced_idx > 0
        assert "r.edgeguard_managed = true" in cypher[sourced_idx:]

    def test_enrichment_campaign_nodes_and_edges_marked(self):
        text = _ENRICHMENT.read_text()
        start = text.find("def build_campaign_nodes")
        end = text.find("\ndef ", start + 1)
        body = text[start:end]
        assert "c.edgeguard_managed = true" in body, "Campaign node"
        assert "r_runs.edgeguard_managed = true" in body, "RUNS edge"
        assert body.count("r.edgeguard_managed = true") >= 2, "PART_OF (malware) + PART_OF (indicator) edges"

    def test_enrichment_refers_to_bridge_marked(self):
        text = _ENRICHMENT.read_text()
        start = text.find("def bridge_vulnerability_cve")
        end = text.find("\ndef ", start + 1)
        body = text[start:end]
        assert "r1.edgeguard_managed = true" in body
        assert "r2.edgeguard_managed = true" in body


# ===========================================================================
# 9. CLI — edgeguard clear neo4j --edgeguard-only
# ===========================================================================


class TestClearNeo4jCli:
    @staticmethod
    def _args(**overrides):
        base = {"force": True, "edgeguard_only": False}
        base.update(overrides)
        return argparse.Namespace(**base)

    def _run(self, args, *, connect=True, clear_all=True, clear_managed=True):
        import edgeguard

        with patch("neo4j_client.Neo4jClient") as client_cls:
            client = client_cls.return_value
            client.connect.return_value = connect
            client.clear_all.return_value = clear_all
            client.clear_edgeguard_managed.return_value = clear_managed
            rc = edgeguard.cmd_clear_neo4j(args)
        return rc, client

    def test_edgeguard_only_routes_to_clear_edgeguard_managed(self):
        rc, client = self._run(self._args(edgeguard_only=True))
        assert rc == 0
        client.clear_edgeguard_managed.assert_called_once_with()
        client.clear_all.assert_not_called()
        client.close.assert_called_once()

    def test_edgeguard_only_returns_1_when_clear_reports_failure(self):
        rc, client = self._run(self._args(edgeguard_only=True), clear_managed=False)
        assert rc == 1
        client.clear_edgeguard_managed.assert_called_once()
        client.clear_all.assert_not_called()
        client.close.assert_called_once(), "the connection is closed even on failure"

    def test_default_mode_still_uses_clear_all(self):
        rc, client = self._run(self._args())
        assert rc == 0
        client.clear_all.assert_called_once_with()
        client.clear_edgeguard_managed.assert_not_called()

    def test_default_mode_failure_now_returns_1(self):
        rc, client = self._run(self._args(), clear_all=False)
        assert rc == 1

    def test_connect_failure_returns_1_without_clearing(self):
        rc, client = self._run(self._args(edgeguard_only=True), connect=False)
        assert rc == 1
        client.clear_edgeguard_managed.assert_not_called()
        client.clear_all.assert_not_called()

    def test_missing_attribute_defaults_to_full_clear(self):
        rc, client = self._run(argparse.Namespace(force=True))
        assert rc == 0
        client.clear_all.assert_called_once()

    def test_without_force_the_prompt_names_the_scope_and_aborts_on_mismatch(self, monkeypatch):
        import edgeguard

        prompts: list[str] = []

        def fake_input(prompt):
            prompts.append(prompt)
            return "no"

        monkeypatch.setattr("builtins.input", fake_input)
        with patch("neo4j_client.Neo4jClient") as client_cls:
            rc = edgeguard.cmd_clear_neo4j(self._args(force=False, edgeguard_only=True))
        assert rc == 0
        client_cls.assert_not_called()
        assert len(prompts) == 1 and "EdgeGuard-managed" in prompts[0] and "edgeguard_managed = true" in prompts[0]

    def test_argparse_registers_edgeguard_only_flag(self):
        text = _EDGEGUARD_CLI.read_text()
        idx = text.find('clear_subparsers.add_parser("neo4j"')
        assert idx > 0
        block = text[idx : idx + 900]
        assert '"--edgeguard-only"' in block
        assert 'action="store_true"' in block


class TestTlpMostRestrictiveClause:
    """Direct tests for the Cypher fragment every TLP-carrying writer uses (2026-10)."""

    _LADDER = ["clear", "white", "green", "amber", "amber+strict", "red"]

    @staticmethod
    def _rank(level: str) -> int:
        case = neo4j_client_mod._tlp_rank_case("x")
        m = re.search(rf"WHEN '{re.escape(level)}' THEN (\d+)", case)
        assert m, f"{level!r} missing from the rank CASE: {case}"
        return int(m.group(1))

    def test_rank_ladder_is_strictly_increasing_from_clear_to_red(self):
        ranks = [self._rank(lvl) for lvl in self._LADDER]
        assert ranks[0] == ranks[1], "clear and white are the same level (TLP 2.0 rename)"
        assert ranks[1:] == sorted(ranks[1:]) and len(set(ranks[1:])) == len(ranks[1:]), ranks

    def test_unknown_level_ranks_below_clear(self):
        case = neo4j_client_mod._tlp_rank_case("x")
        assert re.search(r"ELSE 0\b", case), case
        assert self._rank("clear") > 0

    def test_clause_keeps_existing_when_incoming_is_less_restrictive(self):
        clause = neo4j_client_mod._tlp_most_restrictive_clause("n.tlp", "$tlp")
        assert clause.startswith("CASE WHEN ") and clause.endswith("THEN $tlp ELSE n.tlp END")
        inc, exist = clause.split(" > ", 1)
        assert "$tlp" in inc and "n.tlp" in exist.split(" THEN ")[0], (
            "comparison direction: incoming rank > existing rank → take incoming"
        )
