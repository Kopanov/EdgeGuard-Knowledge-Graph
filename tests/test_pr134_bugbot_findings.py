"""Regression pins for the three Cursor Bugbot findings on PR #134 (2026-10).

1. **Dedup drops extra pulse links** (High) — the OTX collector's same-run dedup kept only the
   first pulse per malware / actor / IOC, so report-scoped linking paired the entity with that one
   pulse. Later pulses now fold their id into ``report_ids`` (and their ATT&CK ids into
   ``reported_techniques``); the id list round-trips through MISP as
   ``MITRE_USES_TECHNIQUES.rids`` / ``OTX_META.report_ids`` and the sync groups on
   ``[pulse_id] + report_ids``.
2. **Zone and tag match_type never written** (Medium) — only the ``ATTRIBUTED_TO`` and ``INDICATES``
   row builders copied ``match_type`` into the batch rows; ``TARGETS`` / ``AFFECTS`` /
   ``EMPLOYS_TECHNIQUE`` / ``IMPLEMENTS_TECHNIQUE`` / ``EXPLOITS`` rows now carry it too, and
   ``build_relationships`` Q7a/Q7b stamp ``zone_classification`` on edges the sync created first.
3. **STIX path loses ATTRIBUTED_TO source** (Medium) — the in-process STIX loader attributes every
   object to its ``x_edgeguard_source`` (stamped per object by ``sync_misp_to_neo4j_via_stix``),
   falls back to ``stix_import`` (never ``"unknown"``), and labels the explicit ``attributed-to``
   relationship object ``stix_relationship``.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from collectors import otx_collector as otx  # noqa: E402
from collectors.misp_writer import _technique_meta  # noqa: E402
from neo4j_client import Neo4jClient  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync, _dedupe_parsed_items  # noqa: E402

_EVENT = {"id": 4242, "info": "EdgeGuard-alienvault_otx-2026-10-01", "date": "2026-10-01", "Tag": []}


def _attr(attr_type: str, value: str, comment: str = "", tags=()):
    return {
        "type": attr_type,
        "value": value,
        "uuid": "10000000-0000-0000-0000-00000000abcd",
        "comment": comment,
        "Tag": [{"name": t} for t in tags],
    }


def _pulse_item(kind: str, name: str, pid: str, rts=()):
    base = {"type": kind, "name": name, "pulse_id": pid, "reported_techniques": list(rts), "tag": "alienvault_otx"}
    return base


# --------------------------------------------------------------------------- 1. collector dedup
class TestCollectorDedupFoldsLaterPulses:
    def test_second_pulse_naming_the_same_malware_contributes_report_id_and_techniques(self):
        items = [
            _pulse_item("malware", "Emotet", "p1", ["T1566"]),
            _pulse_item("malware", "Emotet", "p2", ["T1059", "T1566"]),
        ]
        out = otx._dedupe_pulse_items(items)
        assert len(out) == 1
        kept = out[0]
        assert kept["pulse_id"] == "p1", "the first pulse stays the primary id"
        assert kept["report_ids"] == ["p2"]
        assert kept["reported_techniques"] == ["T1566", "T1059"], "union, first-seen order, no duplicates"

    def test_actor_and_indicator_duplicates_fold_the_same_way(self):
        ioc = {"indicator_type": "ipv4", "value": "1.2.3.4", "pulse_id": "p1"}
        ioc2 = {"indicator_type": "ipv4", "value": "1.2.3.4", "pulse_id": "p2"}
        out = otx._dedupe_pulse_items(
            [_pulse_item("actor", "APT28", "p1"), ioc, _pulse_item("actor", "APT28", "p3"), ioc2]
        )
        by = {(i.get("type") or "indicator", i.get("name") or i.get("value")): i for i in out}
        assert by[("actor", "APT28")]["report_ids"] == ["p3"]
        assert by[("indicator", "1.2.3.4")]["report_ids"] == ["p2"]
        assert "reported_techniques" not in by[("indicator", "1.2.3.4")], "indicators do not grow a techniques list"

    def test_same_pulse_twice_adds_nothing_and_distinct_items_are_untouched(self):
        out = otx._dedupe_pulse_items(
            [_pulse_item("malware", "A", "p1"), _pulse_item("malware", "A", "p1"), _pulse_item("malware", "B", "p1")]
        )
        assert [i["name"] for i in out] == ["A", "B"]
        assert "report_ids" not in out[0] and "report_ids" not in out[1]

    def test_fold_never_mutates_lists_shared_with_sibling_items(self):
        """Bugbot round 2: ``reported_techniques`` is the pulse's ``pulse_attack_ids`` object, shared
        with ``attack_ids`` in ``pulse_meta`` and with every sibling of that pulse. Folding a later
        pulse must not write its ATT&CK ids onto them."""
        shared = ["T1566"]  # one list object, as the collector builds it per pulse
        pulse_meta = {"pulse_id": "p1", "attack_ids": shared}
        emotet = {"type": "malware", "name": "Emotet", "reported_techniques": shared, **pulse_meta}
        trickbot = {"type": "malware", "name": "TrickBot", "reported_techniques": shared, **pulse_meta}
        ioc = {"indicator_type": "ipv4", "value": "1.2.3.4", **pulse_meta}
        later = {"type": "malware", "name": "Emotet", "pulse_id": "p2", "reported_techniques": ["T1059"]}
        out = otx._dedupe_pulse_items([emotet, trickbot, ioc, later])
        kept = next(i for i in out if i.get("name") == "Emotet")
        assert kept["reported_techniques"] == ["T1566", "T1059"] and kept["report_ids"] == ["p2"]
        assert shared == ["T1566"], "the shared pulse list must be untouched"
        assert trickbot["reported_techniques"] == ["T1566"] and ioc["attack_ids"] == ["T1566"]
        assert kept["reported_techniques"] is not shared, "copy-on-write: the kept item owns a new list"

    def test_items_without_an_identity_are_dropped_as_before(self):
        assert (
            otx._dedupe_pulse_items([{"type": "malware", "name": ""}, {"indicator_type": "ipv4", "value": None}]) == []
        )

    def test_collect_uses_the_helper(self):
        src = Path(otx.__file__).read_text()
        assert "unique = _dedupe_pulse_items(processed)" in src


class TestReportIdsRoundTripThroughMisp:
    def test_technique_meta_carries_rids(self):
        assert _technique_meta({"pulse_id": "p1", "report_ids": ["p2", "p3"]}) == {"pid": "p1", "rids": ["p2", "p3"]}
        assert _technique_meta({"pulse_id": "p1", "report_ids": []}) == {"pid": "p1"}, "no key when empty"
        meta = _technique_meta({"pulse_id": "p1", "report_ids": [f"p{i}" for i in range(50)]})
        assert len(meta["rids"]) == 32, "capped so the MISP comment stays within field limits"

    @pytest.fixture
    def syncer(self) -> MISPToNeo4jSync:
        return MISPToNeo4jSync(neo4j_client=MagicMock())

    def test_parser_rehydrates_rids_on_malware_and_actor(self, syncer):
        comment = 'MITRE_USES_TECHNIQUES:{"rt":["T1059"],"pid":"p1","rids":["p2"," p3 ",""]}'
        mal, _ = syncer.parse_attribute(_attr("malware-type", "Emotet", comment=comment), _EVENT)
        assert mal["pulse_id"] == "p1" and mal["report_ids"] == ["p2", "p3"]
        act, _ = syncer.parse_attribute(_attr("threat-actor", "APT28", comment=comment), _EVENT)
        assert act["pulse_id"] == "p1" and act["report_ids"] == ["p2", "p3"]

    def test_parser_rehydrates_report_ids_on_indicators(self, syncer):
        comment = 'OTX_META:{"pulse_id":"p1","report_ids":["p2"],"pulse_name":"x"}'
        ioc, _ = syncer.parse_attribute(_attr("ip-src", "1.2.3.4", comment=comment), _EVENT)
        assert ioc["pulse_id"] == "p1" and ioc["report_ids"] == ["p2"]
        ioc2, _ = syncer.parse_attribute(_attr("ip-src", "5.6.7.8", comment='OTX_META:{"pulse_id":"p1"}'), _EVENT)
        assert "report_ids" not in ioc2

    def test_sync_dedupe_merges_report_ids_the_duplicate_already_carried(self):
        items = [
            {"type": "malware", "name": "Emotet", "pulse_id": "p1", "report_ids": ["p2"]},
            {"type": "malware", "name": "Emotet", "pulse_id": "p3", "report_ids": ["p4", "p1"]},
        ]
        out = _dedupe_parsed_items(items)
        assert len(out) == 1 and out[0]["report_ids"] == ["p2", "p3", "p4"], (
            "p1 is the kept pulse id and is not repeated"
        )

    def test_cross_item_linking_pairs_on_every_report_id(self):
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        items = [
            {"type": "malware", "name": "Emotet", "pulse_id": "p1", "report_ids": ["p2"], "misp_event_id": "7"},
            {"indicator_type": "ipv4", "value": "1.1.1.1", "pulse_id": "p2", "misp_event_id": "7"},
            {"indicator_type": "ipv4", "value": "2.2.2.2", "pulse_id": "p9", "misp_event_id": "7"},
        ]
        rels = syncer._build_cross_item_relationships(items)
        pairs = {
            (r["from_key"]["value"], r["to_key"]["name"], r["report_id"]) for r in rels if r["rel_type"] == "INDICATES"
        }
        assert pairs == {("1.1.1.1", "Emotet", "p2")}, "the folded-in pulse links; the unrelated pulse does not"


# --------------------------------------------------------------------------- 2. evidence labels land
def _capturing_client():
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


class TestBatchRowsCarryMatchType:
    _RELS = [
        {
            "rel_type": "TARGETS",
            "from_type": "Indicator",
            "from_key": {"value": "1.1.1.1"},
            "to_type": "Sector",
            "to_key": {"name": "energy"},
            "confidence": 0.5,
            "match_type": "zone_classification",
        },
        {
            "rel_type": "AFFECTS",
            "from_type": "CVE",
            "from_key": {"cve_id": "CVE-2026-0001"},
            "to_type": "Sector",
            "to_key": {"name": "finance"},
            "confidence": 0.5,
            "match_type": "zone_classification",
        },
        {
            "rel_type": "EMPLOYS_TECHNIQUE",
            "from_type": "ThreatActor",
            "from_key": {"name": "APT28"},
            "to_type": "Technique",
            "to_key": {"mitre_id": "T1059"},
            "confidence": 0.7,
            "match_type": "misp_attribute_tag",
        },
        {
            "rel_type": "EMPLOYS_TECHNIQUE",
            "from_type": "Campaign",
            "from_key": {"name": "Op X"},
            "to_type": "Technique",
            "to_key": {"mitre_id": "T1059"},
            "confidence": 0.7,
            "match_type": "misp_attribute_tag",
        },
        {
            "rel_type": "IMPLEMENTS_TECHNIQUE",
            "from_type": "Malware",
            "from_key": {"name": "Emotet"},
            "to_type": "Technique",
            "to_key": {"mitre_id": "T1059"},
            "confidence": 0.7,
            "match_type": "misp_attribute_tag",
        },
        {
            "rel_type": "IMPLEMENTS_TECHNIQUE",
            "from_type": "Tool",
            "from_key": {"mitre_id": "S0005"},
            "to_type": "Technique",
            "to_key": {"mitre_id": "T1059"},
            "confidence": 0.7,
            "match_type": "misp_attribute_tag",
        },
        {
            "rel_type": "EXPLOITS",
            "from_type": "Indicator",
            "from_key": {"value": "1.1.1.1"},
            "to_type": "CVE",
            "to_key": {"cve_id": "CVE-2026-0001"},
            "confidence": 0.9,
            "match_type": "misp_attribute_tag",
        },
        {
            "rel_type": "ATTRIBUTED_TO",
            "from_type": "Malware",
            "from_key": {"name": "Emotet"},
            "to_type": "ThreatActor",
            "to_key": {"name": "APT28"},
            "confidence": 0.6,
            "match_type": "otx_pulse",
            "report_id": "p1",
        },
        {
            "rel_type": "INDICATES",
            "from_type": "Indicator",
            "from_key": {"value": "1.1.1.1"},
            "to_type": "Malware",
            "to_key": {"name": "Emotet"},
            "confidence": 0.6,
            "match_type": "otx_pulse",
            "report_id": "p1",
        },
    ]

    def test_every_row_of_every_type_carries_the_producers_match_type(self):
        client, captured = _capturing_client()
        client.create_misp_relationships_batch(self._RELS, source_id="misp")
        rows = [r for _, batch in captured for r in batch]
        # AFFECTS and EXPLOITS fan out to both the Vulnerability and the CVE target label,
        # so 9 definitions become 11 rows; every one of them must carry the label.
        assert len(rows) == 11, f"expected 9 rels → 11 rows, got {len(rows)}"
        missing = [r for r in rows if not r.get("match_type")]
        assert not missing, missing
        labels = sorted({r["match_type"] for r in rows})
        assert labels == ["misp_attribute_tag", "otx_pulse", "zone_classification"]

    def test_set_clause_reads_the_row_label(self):
        client, captured = _capturing_client()
        client.create_misp_relationships_batch(self._RELS, source_id="misp")
        for query, _ in captured:
            assert "r.match_type = coalesce(row.match_type, r.match_type)" in query, query[:200]

    def test_q7a_q7b_stamp_zone_classification_on_pre_existing_edges(self):
        text = (Path(_SRC) / "build_relationships.py").read_text()
        blocks = re.findall(
            r'ON CREATE SET r\.confidence_score = 1\.0, r\.match_type = "zone_classification".*?r\.edgeguard_managed = true',
            text,
            re.S,
        )
        assert len(blocks) == 2, "Q7a (TARGETS) and Q7b (AFFECTS)"
        for b in blocks:
            assert 'r.match_type = coalesce(r.match_type, "zone_classification")' in b, b


# --------------------------------------------------------------------------- 3. STIX loader provenance
class TestStixLoaderProvenance:
    @pytest.fixture
    def pipeline(self):
        from run_pipeline import EdgeGuardPipeline

        p = EdgeGuardPipeline()
        p.neo4j = MagicMock()
        return p

    @staticmethod
    def _bundle(with_source: bool):
        objs = [
            {"type": "malware", "id": "malware--1", "name": "Emotet"},
            {"type": "threat-actor", "id": "threat-actor--1", "name": "TA542"},
            {"type": "indicator", "id": "indicator--1", "pattern": "[ipv4-addr:value = '1.2.3.4']"},
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "attributed-to",
                "source_ref": "malware--1",
                "target_ref": "threat-actor--1",
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "relationship_type": "indicates",
                "source_ref": "indicator--1",
                "target_ref": "malware--1",
            },
        ]
        if with_source:
            for o in objs:
                o["x_edgeguard_source"] = "alienvault_otx"
        return {"type": "bundle", "objects": objs}

    def test_attributed_to_keeps_the_objects_source_and_gets_the_stix_label(self, pipeline):
        pipeline.load_stix21_to_neo4j(self._bundle(with_source=True))
        pipeline.neo4j.create_malware_actor_relationship.assert_called_once_with(
            "Emotet", "TA542", source_id="alienvault_otx", match_type="stix_relationship"
        )
        _, kw = pipeline.neo4j.create_indicator_malware_relationship.call_args
        assert kw["source_id"] == "alienvault_otx"

    def test_bundle_without_source_is_attributed_to_stix_import_never_unknown(self, pipeline):
        pipeline.load_stix21_to_neo4j(self._bundle(with_source=False))
        _, kw = pipeline.neo4j.create_malware_actor_relationship.call_args
        assert kw["source_id"] == "stix_import"
        for call in pipeline.neo4j.method_calls:
            assert "unknown" not in repr(call.kwargs.get("source_id", "")), call

    def test_legacy_writer_derives_label_from_source_and_stamps_marker(self):
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        session = MagicMock()
        client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
        client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
        assert client.create_malware_actor_relationship("Emotet", "TA542") is not None
        query, kwargs = session.run.call_args[0][0], session.run.call_args[1]
        assert "r.edgeguard_managed = true" in query and "r.match_type = coalesce(r.match_type, $match_type)" in query
        assert kwargs["match_type"] == "mitre_explicit", "default source mitre_attck → MITRE's own attributed-to"
        client.create_malware_actor_relationship("Emotet", "TA542", source_id="mitre_derived")
        assert session.run.call_args[1]["match_type"] == "mitre_derived"
        client.create_malware_actor_relationship("Emotet", "TA542", source_id="alienvault_otx")
        assert session.run.call_args[1]["match_type"] is None, "no invented label for an unknown evidence class"
