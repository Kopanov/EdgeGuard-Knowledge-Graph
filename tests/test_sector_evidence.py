"""The evidence behind a link to a Sector (2026-10-16).

CISA's ICS advisories state the critical-infrastructure sectors where the affected product is deployed
(the CSAF note "Critical infrastructure sectors"). On the graph of 2026-10-16 every sector link was
``zone_classification`` at 0.5, the label of a keyword guess, and ``build_relationships`` steps 7a-7d
named every feed of the node on every sector link: 2,639 of the 6,506 AFFECTS links named a feed that
never gave their sector. This module follows a CISA advisory from the collector to the sync rows:

* the table (``sector_evidence``): ``advisory_sector`` at 0.9 on AFFECTS only, above
  ``zone_classification``, checked at import;
* the collector merges the advisories that name one CVE into one item, whatever their order, and keeps
  the sectors of each advisory (``advisory_zones``);
* MISPWriter carries the advisory ids, CISA's own sector names and the zones of each advisory in
  ``NVD_META``, for CISA items only;
* the sync states the sectors on the item (``stated_zones``), labels the AFFECTS rows ``advisory_sector``,
  names on each row only the advisories that name its sector (``cisa_ics:<id>``, ``stated_refs``), in a
  paged event as in a small one, and keeps everything else ``zone_classification``;
* the ``SOURCED_FROM`` writers record each source's zones, stated zones and which record stated which;
* the STIX export links an advisory reference to cisa.gov, and the optional STIX flow states the sectors
  as the attribute flow does.

The rendered Cypher of steps 7a-7d runs against a real Neo4j in ``tests/test_sector_evidence_neo4j.py``.
"""

from __future__ import annotations

import copy
import json
import os
import sys
from itertools import permutations
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-sector-evidence")
os.environ.setdefault("MISP_API_KEY", "test-key-sector-evidence")

from test_cisa_ics_collector import SAMPLE_ADVISORY  # noqa: E402  (the real CSAF 2.0 shape)

import collectors.cisa_ics_collector as ics  # noqa: E402
import enrichment_jobs  # noqa: E402
import sector_evidence as se  # noqa: E402
import stix_exporter as sx  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from neo4j_client import Neo4jClient  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync, _item_source_refs, _item_zone_refs  # noqa: E402
from source_registry import cisa_ics_advisory_url  # noqa: E402

# A second advisory naming CVE-2026-32645: an ICS medical advisory (ICSMA), revised later, whose sector
# note names Healthcare and Water. With ICSA-26-281-01 (Energy among five sectors) the CVE is deployed in
# energy and healthcare; Water and the others are CISA sectors EdgeGuard has no zone for.
MEDICAL_ADVISORY: Dict[str, Any] = copy.deepcopy(SAMPLE_ADVISORY)
MEDICAL_ADVISORY["document"]["title"] = "Example Medical Infusion Pump Gateway"
MEDICAL_ADVISORY["document"]["tracking"] = {
    "id": "ICSMA-26-283-01",
    "initial_release_date": "2026-10-10T06:00:00.000000Z",
    "current_release_date": "2026-10-12T06:00:00.000000Z",
}
MEDICAL_ADVISORY["document"]["references"] = []
for _note in MEDICAL_ADVISORY["document"]["notes"]:
    if _note["title"] == "Critical infrastructure sectors":
        _note["text"] = "Healthcare and Public Health, Water and Wastewater Systems"
MEDICAL_ADVISORY["vulnerabilities"] = [copy.deepcopy(SAMPLE_ADVISORY["vulnerabilities"][0])]


# A second ICS advisory of the same day for CVE-2026-32645 (another vendor's product with the shared
# component): its release dates equal ICSA-26-281-01's, so only the advisory id orders the two.
SAME_DAY_ADVISORY: Dict[str, Any] = copy.deepcopy(SAMPLE_ADVISORY)
SAME_DAY_ADVISORY["document"]["title"] = "Example Second Vendor Gateway"
SAME_DAY_ADVISORY["document"]["tracking"] = dict(SAMPLE_ADVISORY["document"]["tracking"], id="ICSA-26-281-02")
SAME_DAY_ADVISORY["document"]["references"] = []
SAME_DAY_ADVISORY["vulnerabilities"] = [copy.deepcopy(SAMPLE_ADVISORY["vulnerabilities"][0])]


def _items(advisory: Dict[str, Any], path: str) -> List[Dict[str, Any]]:
    collector = ics.CISAICSCollector(misp_writer=MagicMock())
    items, _skipped = collector.parse_advisory(copy.deepcopy(advisory), path)
    return items


def _advisory_items() -> List[Dict[str, Any]]:
    """The (advisory, CVE) items of both advisories, newest advisory first as a baseline reads them."""
    return _items(MEDICAL_ADVISORY, "2026/icsma-26-283-01.json") + _items(SAMPLE_ADVISORY, "2026/icsa-26-281-01.json")


@pytest.fixture
def writer() -> MISPWriter:
    return MISPWriter.__new__(MISPWriter)  # the attribute builders need no MISP connection


@pytest.fixture
def syncer() -> MISPToNeo4jSync:
    return MISPToNeo4jSync(neo4j_client=MagicMock())


_EVENT = {"id": 161, "info": "EdgeGuard-cisa_ics-2026-10-16", "date": "2026-10-16", "Tag": []}


# --------------------------------------------------------------------------- the table
class TestTable:
    def test_labels_and_confidences(self):
        # 2026-10-18: OTX's industries statement on TARGETS (``tests/test_otx_industries_sector_label.py``)
        assert se.LABEL_CONFIDENCE == {"zone_classification": 0.5, "otx_industries": 0.6, "advisory_sector": 0.9}
        assert se.LABEL_CONFIDENCE["advisory_sector"] > se.LABEL_CONFIDENCE["zone_classification"], (
            "the sync keeps the label of the higher-confidence row: an equal value would let an inferred "
            "row take a stated link's label"
        )
        assert se.STATEMENT_LABELS == {
            "AFFECTS": {"cisa_ics": "advisory_sector"},
            "TARGETS": {"alienvault_otx": "otx_industries"},
        }

    @pytest.mark.parametrize(
        "source, zones, expected",
        [
            ("cisa_ics", ["healthcare", "energy"], ["energy", "healthcare"]),
            ("cisa_ics", ["global"], []),
            ("cisa_ics", "Energy", ["energy"]),
            ("cisa_ics", None, []),
            ("nvd", ["energy"], []),
            ("alienvault_otx", ["finance", "healthcare"], []),
            (None, ["energy"], []),
        ],
    )
    def test_stated_zones(self, source, zones, expected):
        assert se.stated_zones(source, zones) == expected

    @pytest.mark.parametrize(
        "source, zone, stated, rel_type, expected",
        [
            ("cisa_ics", "energy", ["energy"], "AFFECTS", ("advisory_sector", 0.9)),
            ("cisa_ics", "finance", ["energy"], "AFFECTS", ("zone_classification", 0.5)),
            ("cisa_ics", "energy", None, "AFFECTS", ("zone_classification", 0.5)),
            # a deployment statement never labels TARGETS
            ("cisa_ics", "energy", ["energy"], "TARGETS", ("zone_classification", 0.5)),
            ("nvd", "energy", ["energy"], "AFFECTS", ("zone_classification", 0.5)),
            ("alienvault_otx", "finance", [], "TARGETS", ("zone_classification", 0.5)),
        ],
    )
    def test_link_evidence(self, source, zone, stated, rel_type, expected):
        assert se.link_evidence(source, zone, stated, rel_type) == expected

    def test_stated_refs_say_which_record_stated_which_zone(self):
        refs_by_zone = {
            "energy": ["cisa_ics:ICSA-26-281-01"],
            "healthcare": ["cisa_ics:ICSMA-26-283-01", "cisa_ics:ICSA-26-281-01"],
            "finance": ["cisa_ics:ICSA-26-300-01"],  # not stated: left out
        }
        stated = se.stated_refs(["energy", "healthcare"], refs_by_zone)
        assert stated == [
            "energy|cisa_ics:ICSA-26-281-01",
            "healthcare|cisa_ics:ICSA-26-281-01",
            "healthcare|cisa_ics:ICSMA-26-283-01",
        ]
        assert se.stated_refs([], refs_by_zone) == [] and se.stated_refs(None, refs_by_zone) == []

    @pytest.mark.parametrize(
        "zone, expected",
        [
            ("energy", ["cisa_ics:ICSA-26-281-01"]),
            ("healthcare", ["cisa_ics:ICSA-26-281-01", "cisa_ics:ICSMA-26-283-01"]),
            # no reference recorded for the zone: all of the record's references
            ("finance", ["cisa_ics:ICSA-26-281-01", "cisa_ics:ICSMA-26-283-01", "cisa_ics:ICSA-26-300-01"]),
        ],
    )
    def test_zone_refs_reads_the_zone_back(self, zone, expected):
        stated = [
            "energy|cisa_ics:ICSA-26-281-01",
            "healthcare|cisa_ics:ICSA-26-281-01",
            "healthcare|cisa_ics:ICSMA-26-283-01",
        ]
        default = ["cisa_ics:ICSA-26-281-01", "cisa_ics:ICSMA-26-283-01", "cisa_ics:ICSA-26-300-01"]
        assert se.zone_refs(stated, zone, default) == expected
        assert se.zone_refs(None, zone, default) == default, "a record without per-zone references: all of them"

    def test_cypher_params_per_relationship_type(self):
        assert se.cypher_params("AFFECTS") == {
            "sector_statements": {"cisa_ics": "advisory_sector"},
            "sector_confidence": {"zone_classification": 0.5, "otx_industries": 0.6, "advisory_sector": 0.9},
        }
        assert se.cypher_params("TARGETS")["sector_statements"] == {"alienvault_otx": "otx_industries"}

    @pytest.mark.parametrize(
        "patch, message",
        [
            ({"LABEL_CONFIDENCE": {"zone_classification": 0.5, "advisory_sector": 0.5}}, "must be above"),
            ({"STATEMENT_LABELS": {"AFFECTS": {"cisa": "advisory_sector"}, "TARGETS": {}}}, "canonical"),
            ({"STATEMENT_LABELS": {"AFFECTS": {"cisa_ics": "deployed"}, "TARGETS": {}}}, "no confidence"),
            ({"STATEMENT_LABELS": {"AFFECTS": {}, "TARGETS": {"cisa_ics": "advisory_sector"}}}, "never labels TARGETS"),
            ({"STATING_FEEDS": frozenset({"no_such_feed"})}, "canonical"),
        ],
    )
    def test_the_import_check_refuses_a_broken_table(self, monkeypatch, patch, message):
        for name, value in patch.items():
            monkeypatch.setattr(se, name, value)
        with pytest.raises(ValueError, match=message):
            se._check_table()

    def test_cypher_fragments_use_double_quotes_only(self):
        assert "'" not in se.label_with("v") and "'" not in se.label_set("v, sec, r")


# --------------------------------------------------------------------------- collector
class TestCollectorMergesAdvisoriesPerCve:
    def test_one_item_per_cve_with_the_union_of_the_advisories(self):
        merged = ics.merge_items_per_cve(_advisory_items())
        assert [i["cve_id"] for i in merged] == ["CVE-2026-32645", "CVE-2026-39460"]
        both = merged[0]
        assert both["zone"] == ["energy", "healthcare"]
        assert both["advisory_ids"] == ["ICSA-26-281-01", "ICSMA-26-283-01"]
        assert both["ics_sectors"] == [
            "Commercial Facilities",
            "Communications",
            "Critical Manufacturing",
            "Energy",
            "Healthcare and Public Health",
            "Information Technology",
            "Water and Wastewater Systems",
        ]
        assert both["reference_urls"] == [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-01",
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-283-01",
        ]
        # the sectors of each advisory: a sector link cites only the advisories that name its sector
        assert both["advisory_zones"] == {"ICSA-26-281-01": ["energy"], "ICSMA-26-283-01": ["healthcare"]}
        # the newest advisory's text and identity; the earliest publication, the latest revision
        assert both["advisory_id"] == "ICSMA-26-283-01"
        assert both["description"].startswith("ICSMA-26-283-01: Example Medical Infusion Pump Gateway")
        assert both["published"] == both["first_seen"] == "2026-10-08T06:00:00+00:00"
        assert both["last_modified"] == both["last_seen"] == "2026-10-12T06:00:00+00:00"
        only = merged[1]
        assert only["zone"] == ["energy"] and only["advisory_ids"] == ["ICSA-26-281-01"]
        assert only["advisory_zones"] == {"ICSA-26-281-01": ["energy"]}

    def test_merging_a_merged_item_changes_nothing(self):
        merged = ics.merge_items_per_cve(_advisory_items())
        assert ics.merge_items_per_cve(copy.deepcopy(merged)) == merged

    def test_advisories_of_the_same_date_are_ordered_by_their_id(self):
        """CISA publishes at 06:00Z, so two advisories of one day that were never revised have the same
        ``current_release_date``: the larger advisory id is the newest, whatever the order of the input
        (newest first in a baseline, oldest first in an incremental run)."""
        items = _items(SAMPLE_ADVISORY, "2026/icsa-26-281-01.json")[:1] + _items(
            SAME_DAY_ADVISORY, "2026/icsa-26-281-02.json"
        )
        assert items[0]["last_modified"] == items[1]["last_modified"]
        for order in permutations(items):
            (merged,) = ics.merge_items_per_cve([copy.deepcopy(i) for i in order])
            assert merged["advisory_id"] == "ICSA-26-281-02"
            assert merged["description"].startswith("ICSA-26-281-02: Example Second Vendor Gateway")
            assert merged["advisory_ids"] == ["ICSA-26-281-01", "ICSA-26-281-02"]

    def test_the_result_does_not_depend_on_the_order(self):
        items = _advisory_items()
        results = [ics.merge_items_per_cve([copy.deepcopy(i) for i in order]) for order in permutations(items)]
        assert all(r == results[0] for r in results)

    def test_global_is_dropped_once_an_advisory_names_a_sector(self):
        unmapped = copy.deepcopy(MEDICAL_ADVISORY)
        for note in unmapped["document"]["notes"]:
            if note["title"] == "Critical infrastructure sectors":
                note["text"] = "Water and Wastewater Systems"
        global_only = _items(unmapped, "2026/icsma-26-283-01.json")
        assert global_only[0]["zone"] == ["global"]
        merged = ics.merge_items_per_cve(global_only + _items(SAMPLE_ADVISORY, "2026/icsa-26-281-01.json"))
        assert merged[0]["zone"] == ["energy"]
        # the advisory that maps to no tracked sector names the CVE but states none
        assert merged[0]["advisory_zones"] == {"ICSA-26-281-01": ["energy"], "ICSMA-26-283-01": []}
        assert ics.merge_items_per_cve(global_only)[0]["zone"] == ["global"]

    def test_collect_pushes_merged_items(self, monkeypatch):
        monkeypatch.setattr(ics.CISAICSCollector, "is_enabled", staticmethod(lambda: True))
        collector = ics.CISAICSCollector(misp_writer=MagicMock())
        monkeypatch.setattr(
            collector, "_select_incremental_paths", lambda: (["2026/icsa-26-281-01.json", "2026/icsma.json"], {})
        )
        payloads = {"2026/icsa-26-281-01.json": SAMPLE_ADVISORY, "2026/icsma.json": MEDICAL_ADVISORY}
        monkeypatch.setattr(
            collector,
            "_get",
            lambda url: MagicMock(json=lambda: copy.deepcopy(payloads[url[len(collector.base_url) :]])),
        )
        items = collector.collect(push_to_misp=False, baseline=False)
        assert [i["cve_id"] for i in items] == ["CVE-2026-32645", "CVE-2026-39460"]
        assert items[0]["advisory_ids"] == ["ICSA-26-281-01", "ICSMA-26-283-01"]


# --------------------------------------------------------------------------- MISPWriter
class TestWriterCarriesTheAdvisories:
    def test_cisa_item_carries_advisory_ids_and_cisa_sector_names(self, writer):
        item = ics.merge_items_per_cve(_advisory_items())[0]
        attr = writer.create_vulnerability_attribute(item)
        meta = json.loads(attr["comment"][len("NVD_META:") :])
        assert meta["advisory_ids"] == ["ICSA-26-281-01", "ICSMA-26-283-01"]
        assert "Water and Wastewater Systems" in meta["ics_sectors"] and len(meta["ics_sectors"]) == 7
        assert meta["advisory_zones"] == {"ICSA-26-281-01": ["energy"], "ICSMA-26-283-01": ["healthcare"]}
        tags = {t["name"] for t in attr["Tag"]}
        assert {"zone:Energy", "zone:Healthcare", "source:CISA-ICS"} <= tags

    def test_nvd_and_kev_items_get_no_new_key(self, writer):
        nvd = {
            "cve_id": "CVE-2025-7639",
            "description": "A flaw in an energy management system.",
            "zone": ["energy"],
            "tag": "nvd",
            "published": "2025-07-14T00:00:00+00:00",
            "cwe": ["CWE-79"],
        }
        meta = json.loads(writer.create_vulnerability_attribute(nvd)["comment"][len("NVD_META:") :])
        assert "advisory_ids" not in meta and "ics_sectors" not in meta and "advisory_zones" not in meta

    def test_advisories_alone_qualify_for_nvd_meta(self, writer):
        item = {"cve_id": "CVE-2026-32645", "tag": "cisa_ics", "zone": ["energy"], "advisory_ids": ["ICSA-26-281-01"]}
        attr = writer.create_vulnerability_attribute(item)
        assert attr["comment"].startswith("NVD_META:")
        assert json.loads(attr["comment"][len("NVD_META:") :])["advisory_ids"] == ["ICSA-26-281-01"]

    def test_the_lists_are_bounded(self, writer):
        item = {
            "cve_id": "CVE-2026-32645",
            "tag": "cisa_ics",
            "zone": ["energy"],
            "advisory_ids": [f"ICSA-26-{i:03d}-01" for i in range(80)] + ["", None, "x" * 100],
            "ics_sectors": [f"Sector {i}" for i in range(30)],
            "advisory_zones": {f"ICSA-26-{i:03d}-01": ["energy"] for i in range(80)} | {"odd": "energy"},
        }
        meta = json.loads(writer.create_vulnerability_attribute(item)["comment"][len("NVD_META:") :])
        assert len(meta["advisory_ids"]) == 50 and len(meta["ics_sectors"]) == 20
        # the zones of the advisories kept in advisory_ids only
        assert sorted(meta["advisory_zones"]) == meta["advisory_ids"]


# --------------------------------------------------------------------------- the sync
def _cisa_attribute(writer) -> Dict[str, Any]:
    item = ics.merge_items_per_cve(_advisory_items())[0]
    attr = writer.create_vulnerability_attribute(item)
    attr["uuid"] = "6a1f0000-0000-4000-8000-000000000161"
    return attr


def _nvd_attribute(writer) -> Dict[str, Any]:
    attr = writer.create_vulnerability_attribute(
        {
            "cve_id": "CVE-2026-32645",
            "description": "Default credentials in an energy controller.",
            "zone": ["energy", "finance"],
            "tag": "nvd",
            "published": "2026-10-08T00:00:00+00:00",
            "cwe": ["CWE-798"],
        }
    )
    attr["uuid"] = "6a1f0000-0000-4000-8000-000000000162"
    return attr


class TestSyncStatesTheSectors:
    def test_cisa_item_states_its_sectors_and_names_its_advisories(self, writer, syncer):
        item, _rels = syncer.parse_attribute(_cisa_attribute(writer), _EVENT)
        assert item["zone"] == ["energy", "healthcare"]
        assert item["stated_zones"] == ["energy", "healthcare"]
        assert item["advisory_ids"] == ["ICSA-26-281-01", "ICSMA-26-283-01"]
        assert "Water and Wastewater Systems" in item["ics_sectors"]
        # the node is named by both advisories; each sector by one of them
        assert item["source_refs"] == ["cisa_ics:ICSA-26-281-01", "cisa_ics:ICSMA-26-283-01"]
        assert item["advisory_zones"] == {"ICSA-26-281-01": ["energy"], "ICSMA-26-283-01": ["healthcare"]}
        assert item["stated_refs"] == ["energy|cisa_ics:ICSA-26-281-01", "healthcare|cisa_ics:ICSMA-26-283-01"]

    def test_cisa_rows_are_advisory_sector_at_0_9_citing_the_advisory_of_the_sector(self, writer, syncer):
        """ICSA-26-281-01 names Energy and not Healthcare; ICSMA-26-283-01 names Healthcare and not Energy.
        Each row cites only the advisory that names its sector: the STIX export links every reference
        to its cisa.gov page, and a reader must not land on an advisory that does not name the sector."""
        item, _rels = syncer.parse_attribute(_cisa_attribute(writer), _EVENT)
        rows = [r for r in syncer._build_cross_item_relationships([item]) if r["to_type"] == "Sector"]
        assert {(r["rel_type"], r["to_key"]["name"]): r["source_refs"] for r in rows} == {
            ("AFFECTS", "energy"): ["cisa_ics:ICSA-26-281-01"],
            ("AFFECTS", "healthcare"): ["cisa_ics:ICSMA-26-283-01"],
        }
        for r in rows:
            assert (r["match_type"], r["confidence"], r["source"]) == ("advisory_sector", 0.9, "cisa_ics")
            assert r["misp_event_id"] == "161"

    def test_an_advisory_naming_several_sectors_is_cited_on_each(self, writer, syncer):
        item = ics.merge_items_per_cve(_advisory_items())[0]
        item["advisory_zones"] = {"ICSA-26-281-01": ["energy", "healthcare"], "ICSMA-26-283-01": ["healthcare"]}
        parsed, _ = syncer.parse_attribute(writer.create_vulnerability_attribute(item), _EVENT)
        rows = {r["to_key"]["name"]: r["source_refs"] for r in syncer._build_cross_item_relationships([parsed])}
        assert rows == {
            "energy": ["cisa_ics:ICSA-26-281-01"],
            "healthcare": ["cisa_ics:ICSA-26-281-01", "cisa_ics:ICSMA-26-283-01"],
        }

    def test_a_record_without_the_zones_of_its_advisories_cites_all_of_them(self, writer, syncer):
        """An NVD_META without ``advisory_zones``: every row cites every advisory of the record (it cannot
        tell them apart), as an edge without ``stated_refs`` does in ``build_relationships``."""
        item = ics.merge_items_per_cve(_advisory_items())[0]
        del item["advisory_zones"]
        parsed, _ = syncer.parse_attribute(writer.create_vulnerability_attribute(item), _EVENT)
        assert "advisory_zones" not in parsed and "stated_refs" not in parsed
        for r in syncer._build_cross_item_relationships([parsed]):
            assert r["source_refs"] == ["cisa_ics:ICSA-26-281-01", "cisa_ics:ICSMA-26-283-01"]

    def test_a_paged_event_gives_the_rows_a_small_event_gives(self, writer, syncer, monkeypatch):
        """An event over ``_ATTR_PAGE_SIZE`` attributes builds its rows from a light copy of each item
        (``_REL_KEYS``). Without the statement keys in that copy a CISA statement became
        ``zone_classification`` at 0.5 citing every advisory; the CISA ICS event of a 730-day baseline
        held 4,164 attributes, under the 5,000 of a page by little."""
        attributes = [_cisa_attribute(writer), _nvd_attribute(writer)]
        attributes[1]["value"] = "CVE-2026-0002"
        written: Dict[str, List[Dict[str, Any]]] = {}

        def run(path: str, *args) -> None:
            rows: List[Dict[str, Any]] = []
            monkeypatch.setattr(syncer, "sync_to_neo4j", lambda items: (len(items), 0, 0))
            monkeypatch.setattr(syncer, "_create_relationships", lambda rels, source: 0)
            monkeypatch.setattr(syncer, "_write_cross_item_relationships", lambda rels: rows.extend(rels) or len(rels))
            getattr(syncer, path)("161", _EVENT, copy.deepcopy(attributes), *args)
            written[path] = sorted(
                (
                    (r["rel_type"], r["from_key"].get("cve_id"), r["to_key"]["name"]),
                    (r["match_type"], r["confidence"], r["source"], tuple(r["source_refs"])),
                )
                for r in rows
                if r["to_type"] == "Sector"
            )

        run("_process_event_attributes", [])
        monkeypatch.setattr(syncer, "_ATTR_PAGE_SIZE", 1)
        run("_process_large_event_paged", [])
        assert written["_process_large_event_paged"] == written["_process_event_attributes"]
        assert written["_process_event_attributes"] == [
            (("AFFECTS", "CVE-2026-0002", "energy"), ("zone_classification", 0.5, "nvd", ())),
            (("AFFECTS", "CVE-2026-0002", "finance"), ("zone_classification", 0.5, "nvd", ())),
            (
                ("AFFECTS", "CVE-2026-32645", "energy"),
                ("advisory_sector", 0.9, "cisa_ics", ("cisa_ics:ICSA-26-281-01",)),
            ),
            (
                ("AFFECTS", "CVE-2026-32645", "healthcare"),
                ("advisory_sector", 0.9, "cisa_ics", ("cisa_ics:ICSMA-26-283-01",)),
            ),
        ]

    def test_nvd_rows_stay_zone_classification(self, writer, syncer):
        item, _rels = syncer.parse_attribute(_nvd_attribute(writer), _EVENT)
        assert "stated_zones" not in item and "advisory_ids" not in item and "ics_sectors" not in item
        rows = [r for r in syncer._build_cross_item_relationships([item]) if r["to_type"] == "Sector"]
        assert sorted(r["to_key"]["name"] for r in rows) == ["energy", "finance"]
        assert {(r["match_type"], r["confidence"], r["source"]) for r in rows} == {("zone_classification", 0.5, "nvd")}

    def test_a_cisa_record_without_a_sector_states_none(self, writer, syncer):
        item = ics.merge_items_per_cve(_advisory_items())[0]
        item["zone"] = ["global"]
        attr = writer.create_vulnerability_attribute(item)
        parsed, _ = syncer.parse_attribute(attr, _EVENT)
        assert parsed["zone"] == ["global"] and "stated_zones" not in parsed
        assert not [r for r in syncer._build_cross_item_relationships([parsed]) if r["to_type"] == "Sector"]

    def test_indicator_targets_never_take_the_advisory_label(self, syncer):
        # A CISA ICS source tag on an indicator (not a record the collector writes): TARGETS has no CISA ICS label.
        item = {"type": "indicator", "indicator_type": "ipv4", "value": "203.0.113.7", "zone": ["energy"]}
        item["tag"] = "cisa_ics"
        item["stated_zones"] = ["energy"]
        (row,) = [r for r in syncer._build_cross_item_relationships([item]) if r["to_type"] == "Sector"]
        assert (row["rel_type"], row["match_type"], row["confidence"]) == ("TARGETS", "zone_classification", 0.5)

    def test_item_source_refs_for_cisa_ics(self):
        assert _item_source_refs({"advisory_ids": ["ICSA-24-123-01"]}, "cisa_ics") == ["cisa_ics:ICSA-24-123-01"]
        assert _item_source_refs({}, "cisa_ics") == []
        assert _item_source_refs({"advisory_ids": ["ICSA-24-123-01"]}, "nvd") == []

    def test_item_zone_refs_for_cisa_ics_only(self):
        item = {"advisory_zones": {"ICSMA-26-283-01": ["healthcare"], "ICSA-26-281-01": ["energy", "healthcare"]}}
        assert _item_zone_refs(item, "cisa_ics") == {
            "energy": ["cisa_ics:ICSA-26-281-01"],
            "healthcare": ["cisa_ics:ICSA-26-281-01", "cisa_ics:ICSMA-26-283-01"],
        }
        assert _item_zone_refs(item, "nvd") == {} and _item_zone_refs({}, "cisa_ics") == {}


# --------------------------------------------------------------------------- SOURCED_FROM writers
class _Session:
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
        result.single.return_value = None
        result.__iter__ = lambda _self: iter([])
        return result


def _recording_client():
    calls: list = []
    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    client.driver.session.side_effect = lambda **kw: _Session(calls)
    return client, calls


def _sourced_from(calls):
    return [(q, p) for q, p in calls if "MERGE (n)-[r:SOURCED_FROM]->(s)" in q]


class TestSourcedFromRecordsTheZones:
    ZONES_SET = "r.zones = CASE WHEN {z} IS NULL THEN r.zones ELSE CASE WHEN size("
    STATED_SET = "r.stated_zones = CASE WHEN size(coalesce({s}, [])) = 0 THEN r.stated_zones"
    REFS_SET = "r.stated_refs = CASE WHEN size(coalesce({s}, [])) = 0 THEN r.stated_refs"

    def test_merge_cve_sends_the_zones_and_the_stated_zones(self, writer, syncer):
        item, _ = syncer.parse_attribute(_cisa_attribute(writer), _EVENT)
        client, calls = _recording_client()
        client.merge_cve(item, source_id="cisa_ics")
        ((query, params),) = _sourced_from(calls)
        assert self.ZONES_SET.format(z="$zones") in query and self.STATED_SET.format(s="$stated_zones") in query
        assert self.REFS_SET.format(s="$stated_refs") in query
        assert params["zones"] == ["energy", "healthcare"] and params["stated_zones"] == ["energy", "healthcare"]
        assert params["source_refs"] == ["cisa_ics:ICSA-26-281-01", "cisa_ics:ICSMA-26-283-01"]
        assert params["stated_refs"] == [
            "energy|cisa_ics:ICSA-26-281-01",
            "healthcare|cisa_ics:ICSMA-26-283-01",
        ]
        raw = json.loads(params["raw_data"])
        assert raw["advisory_ids"] == ["ICSA-26-281-01", "ICSMA-26-283-01"]
        assert "Water and Wastewater Systems" in raw["ics_sectors"]
        assert raw["advisory_zones"] == {"ICSA-26-281-01": ["energy"], "ICSMA-26-283-01": ["healthcare"]}

    def test_an_inferring_feed_sends_its_zones_and_no_statement(self, writer, syncer):
        item, _ = syncer.parse_attribute(_nvd_attribute(writer), _EVENT)
        client, calls = _recording_client()
        client.merge_cve(item, source_id="nvd")
        ((_query, params),) = _sourced_from(calls)
        assert params["zones"] == ["energy", "finance"] and params["stated_zones"] == []
        assert params["stated_refs"] == []

    @pytest.mark.parametrize(
        "method, item",
        [
            (
                "merge_indicators_batch",
                {"indicator_type": "ipv4", "value": "203.0.113.7", "zone": ["energy"], "tag": "nvd"},
            ),
            (
                "merge_vulnerabilities_batch",
                {
                    "cve_id": "CVE-2026-32645",
                    "zone": ["energy"],
                    "tag": "cisa_ics",
                    "stated_zones": ["energy"],
                    "stated_refs": ["energy|cisa_ics:ICSA-26-281-01"],
                },
            ),
        ],
    )
    def test_batch_writers_send_the_zones_and_the_stated_zones(self, method, item):
        client, calls = _recording_client()
        getattr(client, method)([dict(item)], source_id=item["tag"])
        queries = [(q, p) for q, p in calls if "MERGE (n)-[r:SOURCED_FROM]->(s)" in q]
        assert queries, f"{method} wrote no SOURCED_FROM edge"
        query, params = queries[0]
        assert self.ZONES_SET.format(z="item.zone") in query
        assert self.STATED_SET.format(s="item.stated_zones") in query
        assert self.REFS_SET.format(s="item.stated_refs") in query
        (row,) = params["batch"] if "batch" in params else params["items"]
        assert row["zone"] == ["energy"]
        assert row["stated_zones"] == list(item.get("stated_zones", []))
        assert row["stated_refs"] == list(item.get("stated_refs", []))


# --------------------------------------------------------------------------- merges and STIX
class TestMergesKeepTheZones:
    def test_folded_sourced_from_edges_keep_the_union_as_lists(self):
        for prop in ("zones", "stated_zones", "stated_refs"):
            assert enrichment_jobs._ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY[prop] == "combine"
            assert enrichment_jobs._MALWARE_TWIN_MERGE_PROPERTY_STRATEGY[prop] == "combine"
            assert prop in enrichment_jobs._ACTOR_ALIAS_MERGE_EDGE_LIST_PROPS
            assert prop not in enrichment_jobs._ACTOR_ALIAS_MERGE_LIST_PROPS, "edge lists, not node lists"
        edges = enrichment_jobs._ACTOR_ALIAS_MERGE_NORMALISE_CYPHER.split("MATCH (c)-[r]-()")[1]
        assert "apoc.coll.sort([_z IN CASE WHEN r.zones IS NULL THEN NULL WHEN apoc.meta.cypher.type(r.zones)" in edges
        for prop in ("stated_zones", "stated_refs"):
            assert f"r.{prop} = CASE WHEN r.{prop} IS NULL THEN NULL ELSE apoc.coll.sort(CASE WHEN r.{prop}" in edges


class TestStixLinksTheAdvisory:
    @pytest.mark.parametrize(
        "record_id, url",
        [
            ("ICSA-24-123-01", "https://www.cisa.gov/news-events/ics-advisories/icsa-24-123-01"),
            ("ICSMA-26-283-01", "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-283-01"),
            ("not-an-advisory", None),
        ],
    )
    def test_record_url(self, record_id, url):
        assert sx._record_url("cisa_ics", record_id) == url
        assert cisa_ics_advisory_url(record_id) == url

    def test_the_stix_flow_states_the_sectors_as_the_attribute_flow(self, writer, syncer):
        """``run_pipeline.py --stix-flow`` loads the STIX objects of a CISA ICS event: the CVE's
        ``SOURCED_FROM`` edge gets the stated zones as in the attribute flow, so step 7b labels the link
        ``advisory_sector`` whichever flow loaded it."""
        from run_pipeline import EdgeGuardPipeline

        pipeline = EdgeGuardPipeline.__new__(EdgeGuardPipeline)
        pipeline.neo4j = MagicMock()
        attr = {k: v for k, v in _cisa_attribute(writer).items()}
        sdo = syncer._attribute_to_stix21(attr, "00000000-0000-4000-8000-000000000000", ["global"])
        sdo["x_edgeguard_source"] = "cisa_ics"  # as the STIX flow stamps the objects of a CISA ICS event
        nvd_sdo = dict(sdo, x_edgeguard_source="nvd", id=sdo["id"].replace("-0", "-1", 1))
        pipeline.load_stix21_to_neo4j({"type": "bundle", "objects": [sdo, nvd_sdo]})
        calls = pipeline.neo4j.merge_cve.call_args_list
        assert [c.kwargs["source_id"] for c in calls] == ["cisa_ics", "nvd"]
        cisa, nvd = (c.args[0] for c in calls)
        assert cisa["zone"] == ["energy", "healthcare"] and cisa["stated_zones"] == ["energy", "healthcare"]
        assert nvd["zone"] == ["energy", "healthcare"] and "stated_zones" not in nvd

    def test_the_collector_uses_the_same_rule(self):
        assert ics.advisory_url("ICSMA-26-283-01", {"references": []}, "raw") == cisa_ics_advisory_url(
            "ICSMA-26-283-01"
        )
        assert ics.advisory_url("odd", {"references": []}, "raw") == "raw"


# --------------------------------------------------------------------------- the build step's count
class TestSectorStepsCountTheSectorsNoFeedGave:
    def test_the_skip_line_says_what_was_not_linked(self, caplog):
        import build_relationships

        client = MagicMock()
        client.run.side_effect = lambda query, *a, **k: (
            [{"c": 3}] if "RETURN count(*) AS c" in query and "apoc.periodic.iterate" not in query else [{"count": 5}]
        )
        stmts = build_relationships._Q7B_STATEMENTS
        with caplog.at_level("INFO", logger="build_relationships"):
            assert build_relationships._safe_run_batched(
                client,
                "Vulnerability/CVE -> Sector (AFFECTS)",
                stmts.outer,
                stmts.inner,
                {},
                "vuln_affects_sector",
                skip_query=stmts.skip,
                params=stmts.params,
            )
        assert "[SKIP] Vulnerability/CVE -> Sector (AFFECTS): 3 (node, sector) pairs" in caplog.text
        assert "no matching target node" not in caplog.text
        assert "WHERE size(_feeds) = 0 RETURN count(*) AS c" in stmts.skip
