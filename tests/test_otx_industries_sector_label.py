"""An OTX report's own industries as the statement behind its TARGETS links to a Sector (2026-10-18).

An OTX pulse classifies itself into industries (its ``industries`` field): the report's author states which
sectors the campaign it describes targets. The collector merges the zones those industries map to
(``config.OTX_INDUSTRY_ZONE_ALIASES``) into the zones its keyword detection finds in the pulse text, and
until 2026-10-18 every OTX sector link carried the inference label ``zone_classification`` (0.5), the
report's statement included. This module follows a pulse from the collector through MISP to the sync:

* the table (``sector_evidence``): ``otx_industries`` at 0.6 on TARGETS only, above
  ``zone_classification`` and below CISA's ``advisory_sector``, checked at import;
* only the zones the pulse's industries map to are stated: a keyword hit, an industry the table does not
  map and a pulse without industries state nothing, and the mapping has one definition;
* the industries travel through MISP on every OTX item that links to a Sector by TARGETS (an indicator in
  ``OTX_META.otx_industries``, a malware family and an adversary in ``MITRE_USES_TECHNIQUES.ind``);
* the sync labels the Indicator TARGETS rows, records on each item the zones its pulse stated and the pulse
  that stated them (``stated_zones``, ``stated_refs``), in a paged event as in a small one, and the
  ``SOURCED_FROM`` writers keep them, so build_relationships steps 7a / 7c / 7d label the links alike;
* a CVE the pulse names keeps ``zone_classification`` on AFFECTS; CISA ICS is unchanged;
* a foreign ``sector:`` tag row and the single-link writers follow the table.

The rendered Cypher runs against a real Neo4j in ``tests/test_sector_evidence_neo4j.py``; the acceptance
checks are in ``tests/test_verify_fresh_baseline.py``.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-otx-industries")
os.environ.setdefault("MISP_API_KEY", "test-key-otx-industries")

from test_entity_description_source import otx_items  # noqa: E402  (the OTX collector over one run)

import build_relationships  # noqa: E402
import config  # noqa: E402
import sector_evidence as se  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from neo4j_client import Neo4jClient  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync, _item_zone_refs  # noqa: E402

PULSE_ID = "6ac84a155bb626a3710179b9"
PULSE_REF = f"alienvault_otx:{PULSE_ID}"

# A pulse whose text names hospitals and patient records (keyword detection: healthcare) and whose author
# classified it into the Energy industry (the pulse's statement: energy). The shape is the OTX API's.
PULSE: Dict[str, Any] = {
    "id": PULSE_ID,
    "name": "Ransomware intrusions at hospitals",
    "description": "The operators encrypted patient records at two hospitals and a clinic network.",
    "created": "2026-10-08T09:00:00",
    "modified": "2026-10-09T10:00:00",
    "TLP": "white",
    "adversary": "Dragonfly",
    "author_name": "AlienVault",
    "attack_ids": [{"id": "T1486"}],
    "tags": ["ransomware"],
    "references": [],
    "targeted_countries": [],
    "industries": ["Energy"],
    "malware_families": ["ExampleLocker"],
    "cve_references": ["CVE-2026-11111"],
    "indicators": [{"type": "IPv4", "indicator": "198.51.100.23", "description": ""}],
}

WRITER = MISPWriter.__new__(MISPWriter)  # the attribute builders need no MISP connection
_BUILDERS = {
    "malware": "create_malware_attribute",
    "actor": "create_actor_attribute",
    "vulnerability": "create_vulnerability_attribute",
}
_EVENT = {"id": 34, "info": "EdgeGuard-alienvault_otx-2026-10-18", "date": "2026-10-18", "Tag": []}


def _pulse(**changes: Any) -> Dict[str, Any]:
    return dict(copy.deepcopy(PULSE), **changes)


def _kind(item: Dict[str, Any]) -> str:
    return item.get("type") or "indicator"


def _attribute(item: Dict[str, Any]) -> Dict[str, Any]:
    """The MISP attribute MISPWriter writes for a collector item."""
    attr = getattr(WRITER, _BUILDERS.get(_kind(item), "create_attribute"))(copy.deepcopy(item))
    assert attr is not None
    attr["uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"edgeguard-test:{_kind(item)}:{attr['value']}"))
    return attr


def _synced(*pulses: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """The sync's items, by kind, for the collector's items of ``pulses`` (one run) read back from MISP."""
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    out: Dict[str, Dict[str, Any]] = {}
    for item in otx_items(*pulses):
        parsed, _rels = syncer.parse_attribute(_attribute(item), _EVENT)
        assert parsed is not None
        out[_kind(item)] = parsed
    return out


def _sector_rows(*items: Dict[str, Any]) -> Dict[tuple, tuple]:
    rows = MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships(list(items))
    return {
        (r["rel_type"], r["to_key"]["name"]): (r["match_type"], r["confidence"], r["source"], r["source_refs"])
        for r in rows
        if r["to_type"] == "Sector"
    }


# --------------------------------------------------------------------------- the table
class TestTable:
    def test_the_label_sits_between_the_inference_and_cisas_statement(self):
        conf = se.LABEL_CONFIDENCE
        assert conf["otx_industries"] == 0.6
        assert conf["zone_classification"] < conf["otx_industries"] < conf["advisory_sector"], (
            "the sync keeps the label of the higher-confidence row: equal to the inference, a keyword row "
            "could take the statement's label"
        )
        assert se.STATEMENT_LABELS == {
            "AFFECTS": {"cisa_ics": "advisory_sector"},
            "TARGETS": {"alienvault_otx": "otx_industries"},
        }

    @pytest.mark.parametrize(
        "source, zones, industries, expected",
        [
            ("alienvault_otx", ["healthcare", "energy"], ["Energy"], ["energy"]),
            # several industries of one zone, and a list in any case
            ("alienvault_otx", ["finance", "energy"], ["Banking", "financial", " Oil "], ["energy", "finance"]),
            # no industries, or none the table maps: the keyword hits stay inferred
            ("alienvault_otx", ["healthcare"], [], []),
            ("alienvault_otx", ["healthcare"], None, []),
            ("alienvault_otx", ["healthcare"], ["Government", "Telecommunications"], []),
            # a stated zone is a zone of the record
            ("alienvault_otx", ["healthcare"], ["Energy"], []),
            ("alienvault_otx", ["global"], ["Energy"], []),
            # not a list (as the sync reads OTX_META, ``_meta_list``): no industries
            ("alienvault_otx", ["energy"], "Energy", []),
            # only OTX records classify themselves; CISA ICS states every zone, as before
            ("threatfox", ["energy"], ["Energy"], []),
            ("cisa_ics", ["healthcare", "energy"], ["Finance"], ["energy", "healthcare"]),
            ("cisa_ics", ["healthcare", "energy"], None, ["energy", "healthcare"]),
        ],
    )
    def test_stated_zones(self, source, zones, industries, expected):
        assert se.stated_zones(source, zones, industries) == expected

    @pytest.mark.parametrize(
        "source, zone, stated, rel_type, expected",
        [
            ("alienvault_otx", "energy", ["energy"], "TARGETS", ("otx_industries", 0.6)),
            ("alienvault_otx", "healthcare", ["energy"], "TARGETS", ("zone_classification", 0.5)),
            ("alienvault_otx", "energy", None, "TARGETS", ("zone_classification", 0.5)),
            # a targeted industry says nothing about where a vulnerable product is deployed
            ("alienvault_otx", "energy", ["energy"], "AFFECTS", ("zone_classification", 0.5)),
            ("threatfox", "energy", ["energy"], "TARGETS", ("zone_classification", 0.5)),
            ("cisa_ics", "energy", ["energy"], "TARGETS", ("zone_classification", 0.5)),
        ],
    )
    def test_link_evidence(self, source, zone, stated, rel_type, expected):
        assert se.link_evidence(source, zone, stated, rel_type) == expected

    def test_the_mapping_has_one_definition(self, monkeypatch):
        """The statement reads the collector's table: an alias added to ``config.OTX_INDUSTRY_ZONE_ALIASES``
        is stated by the sync and merged into the zones by the collector, with no second copy to update."""
        assert config.otx_industry_zones(["Energy", "Utilities", "Banking", "Government", None, ""]) == [
            "energy",
            "finance",
        ]
        monkeypatch.setitem(config.OTX_INDUSTRY_ZONE_ALIASES, "maritime", "energy")
        assert se.stated_zones("alienvault_otx", ["energy"], ["Maritime"]) == ["energy"]
        (item,) = [i for i in otx_items(_pulse(industries=["Maritime"])) if "indicator_type" in i]
        assert "energy" in item["zone"]

    def test_cypher_params_per_relationship_type(self):
        assert se.cypher_params("TARGETS")["sector_statements"] == {"alienvault_otx": "otx_industries"}
        assert se.cypher_params("AFFECTS")["sector_statements"] == {"cisa_ics": "advisory_sector"}
        assert se.cypher_params("TARGETS")["sector_confidence"]["otx_industries"] == 0.6

    def test_the_build_steps_read_the_table(self):
        for stmts in (build_relationships._Q7A_STATEMENTS, build_relationships._Q7C_STATEMENTS):
            assert stmts.params["sector_statements"] == {"alienvault_otx": "otx_industries"}
        assert build_relationships._Q7D_STATEMENTS.params["sector_statements"] == {"alienvault_otx": "otx_industries"}
        assert build_relationships._Q7B_STATEMENTS.params["sector_statements"] == {"cisa_ics": "advisory_sector"}

    @pytest.mark.parametrize(
        "patch, message",
        [
            (
                {
                    "LABEL_CONFIDENCE": {
                        "zone_classification": 0.5,
                        "otx_industries": 0.5,
                        "advisory_sector": 0.9,
                    }
                },
                "must be above",
            ),
            (
                {"STATEMENT_LABELS": {"AFFECTS": {"alienvault_otx": "otx_industries"}, "TARGETS": {}}},
                "never labels AFFECTS",
            ),
            ({"INDUSTRY_STATING_FEEDS": frozenset({"otx"})}, "canonical"),
            ({"INDUSTRY_STATING_FEEDS": frozenset({"alienvault_otx", "cisa_ics"})}, "both"),
            ({"INDUSTRY_STATING_FEEDS": frozenset()}, "states no sector"),
        ],
    )
    def test_the_import_check_refuses_a_broken_table(self, monkeypatch, patch, message):
        for name, value in patch.items():
            monkeypatch.setattr(se, name, value)
        with pytest.raises(ValueError, match=message):
            se._check_table()


# --------------------------------------------------------------------------- collector and MISPWriter
class TestTheIndustriesTravelThroughMisp:
    def test_the_collector_keeps_its_zones_and_the_raw_industries(self):
        items = otx_items(_pulse())
        assert {_kind(i) for i in items} == {"indicator", "malware", "actor", "vulnerability"}
        for item in items:
            assert sorted(item["zone"]) == ["energy", "healthcare"]
            assert item["otx_industries"] == ["Energy"]

    def test_an_indicator_carries_them_in_otx_meta(self):
        (item,) = [i for i in otx_items(_pulse()) if _kind(i) == "indicator"]
        meta = json.loads(_attribute(item)["comment"][len("OTX_META:") :])
        assert meta["otx_industries"] == ["Energy"] and meta["pulse_id"] == PULSE_ID

    @pytest.mark.parametrize("kind", ["malware", "actor"])
    def test_a_family_and_an_adversary_carry_them_in_the_technique_block(self, kind):
        (item,) = [i for i in otx_items(_pulse()) if _kind(i) == kind]
        comment = _attribute(item)["comment"]
        assert comment.startswith("MITRE_USES_TECHNIQUES:")
        meta = json.loads(comment[len("MITRE_USES_TECHNIQUES:") :].split("\n", 1)[0])
        assert meta["ind"] == ["Energy"] and meta["pid"] == PULSE_ID

    def test_an_item_without_industries_writes_no_key(self):
        mitre = {
            "type": "actor",
            "name": "APT28",
            "tag": "mitre_attck",
            "zone": ["global"],
            "uses_techniques": ["T1566"],
        }
        meta = json.loads(WRITER.create_actor_attribute(mitre)["comment"][len("MITRE_USES_TECHNIQUES:") :])
        assert "ind" not in meta
        (item,) = [i for i in otx_items(_pulse(industries=[])) if _kind(i) == "malware"]
        assert "ind" not in json.loads(_attribute(item)["comment"][len("MITRE_USES_TECHNIQUES:") :].split("\n", 1)[0])

    def test_the_list_is_bounded(self):
        item = {
            "type": "malware",
            "name": "ExampleLocker",
            "tag": "alienvault_otx",
            "zone": ["energy"],
            "pulse_id": PULSE_ID,
            "otx_industries": [f"Industry {i} " + "x" * 100 for i in range(30)] + ["", None],
        }
        meta = json.loads(WRITER.create_malware_attribute(item)["comment"][len("MITRE_USES_TECHNIQUES:") :])
        assert len(meta["ind"]) == 20 and all(len(x) <= 64 for x in meta["ind"])


# --------------------------------------------------------------------------- the sync
class TestSyncStatesTheIndustries:
    def test_targets_energy_is_the_pulses_statement_and_healthcare_an_inference(self):
        """The pulse's industries name Energy and its text names hospitals: the Indicator's TARGETS energy
        row is ``otx_industries`` at 0.6 citing the pulse, healthcare stays ``zone_classification``."""
        indicator = _synced(_pulse())["indicator"]
        assert indicator["stated_zones"] == ["energy"]
        assert indicator["stated_refs"] == [f"energy|{PULSE_REF}"]
        assert _sector_rows(indicator) == {
            ("TARGETS", "energy"): ("otx_industries", 0.6, "alienvault_otx", [PULSE_REF]),
            ("TARGETS", "healthcare"): ("zone_classification", 0.5, "alienvault_otx", [PULSE_REF]),
        }

    @pytest.mark.parametrize("industries", [[], ["Government", "Telecommunications"]])
    def test_a_pulse_that_states_no_tracked_sector_gives_only_inferences(self, industries):
        indicator = _synced(_pulse(industries=industries))["indicator"]
        assert "stated_zones" not in indicator and "stated_refs" not in indicator
        assert _sector_rows(indicator) == {
            ("TARGETS", "healthcare"): ("zone_classification", 0.5, "alienvault_otx", [PULSE_REF]),
        }

    def test_the_cve_the_pulse_names_keeps_zone_classification(self):
        """A targeted industry is no statement about where a vulnerable product is deployed: the CVE of the
        same pulse is linked by AFFECTS as an inference, also when its item records the statement."""
        cve = _synced(_pulse())["vulnerability"]
        assert {k: v[:2] for k, v in _sector_rows(cve).items()} == {
            ("AFFECTS", "energy"): ("zone_classification", 0.5),
            ("AFFECTS", "healthcare"): ("zone_classification", 0.5),
        }
        stated = dict(cve, stated_zones=["energy"], stated_refs=[f"energy|{PULSE_REF}"])
        assert _sector_rows(stated)[("AFFECTS", "energy")][:2] == ("zone_classification", 0.5)

    @pytest.mark.parametrize("kind", ["malware", "actor"])
    def test_a_family_and_an_adversary_record_the_statement(self, kind):
        """Malware and ThreatActor link to a Sector in build_relationships steps 7c / 7d, which read the
        statement from the OTX ``SOURCED_FROM`` edge: the item carries what the writer records there."""
        item = _synced(_pulse())[kind]
        assert item["otx_industries"] == ["Energy"]
        assert item["stated_zones"] == ["energy"]
        assert item["stated_refs"] == [f"energy|{PULSE_REF}"]
        assert item["source_refs"] == [PULSE_REF]

    def test_a_mitre_entity_states_nothing(self):
        attr = WRITER.create_actor_attribute(
            {"type": "actor", "name": "APT28", "tag": "mitre_attck", "zone": ["energy"], "uses_techniques": ["T1566"]}
        )
        attr["uuid"] = "6a1f0000-0000-4000-8000-000000000999"
        event = {"id": 33, "info": "EdgeGuard-mitre_attck-2026-10-18", "date": "2026-10-18", "Tag": []}
        item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(attr, event)
        assert "otx_industries" not in item and "stated_zones" not in item

    def test_the_statement_cites_the_pulse_whose_industries_the_item_carries(self):
        """An IOC two pulses of one run list keeps the first pulse's zones and industries; the second pulse
        joins ``report_ids`` without either. The stated sector cites the first pulse only: the second one's
        industries never reached the item."""
        second = _pulse(id="6ac84a155bb626a3710179ba", industries=[], malware_families=[], cve_references=[])
        second["adversary"] = ""
        indicator = _synced(_pulse(), second)["indicator"]
        assert indicator["source_refs"] == [PULSE_REF, "alienvault_otx:6ac84a155bb626a3710179ba"]
        assert indicator["stated_refs"] == [f"energy|{PULSE_REF}"]
        rows = _sector_rows(indicator)
        assert rows[("TARGETS", "energy")] == ("otx_industries", 0.6, "alienvault_otx", [PULSE_REF])
        assert rows[("TARGETS", "healthcare")][3] == indicator["source_refs"]

    def test_item_zone_refs_name_the_items_pulse(self):
        item = {"pulse_id": PULSE_ID, "report_ids": ["other"], "zone": ["energy", "healthcare", "global"]}
        assert _item_zone_refs(item, "alienvault_otx") == {"energy": [PULSE_REF], "healthcare": [PULSE_REF]}
        assert _item_zone_refs({"zone": ["energy"]}, "alienvault_otx") == {}
        assert _item_zone_refs(item, "threatfox") == {}

    def test_a_paged_event_gives_the_rows_a_small_event_gives(self, monkeypatch):
        attributes = [_attribute(i) for i in otx_items(_pulse())]
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        written: Dict[str, List[Any]] = {}

        def run(path: str) -> None:
            rows: List[Dict[str, Any]] = []
            monkeypatch.setattr(syncer, "sync_to_neo4j", lambda items: (len(items), 0, 0))
            monkeypatch.setattr(syncer, "_create_relationships", lambda rels, source: 0)
            monkeypatch.setattr(syncer, "_write_cross_item_relationships", lambda rels: rows.extend(rels) or len(rels))
            getattr(syncer, path)("34", _EVENT, copy.deepcopy(attributes), [])
            written[path] = sorted(
                ((r["rel_type"], r["to_key"]["name"]), (r["match_type"], r["confidence"], tuple(r["source_refs"])))
                for r in rows
                if r["to_type"] == "Sector"
            )

        run("_process_event_attributes")
        monkeypatch.setattr(syncer, "_ATTR_PAGE_SIZE", 1)
        run("_process_large_event_paged")
        assert written["_process_large_event_paged"] == written["_process_event_attributes"]
        # the CVE attribute of a pulse carries no pulse id (only its description names the pulse)
        assert written["_process_event_attributes"] == [
            (("AFFECTS", "energy"), ("zone_classification", 0.5, ())),
            (("AFFECTS", "healthcare"), ("zone_classification", 0.5, ())),
            (("TARGETS", "energy"), ("otx_industries", 0.6, (PULSE_REF,))),
            (("TARGETS", "healthcare"), ("zone_classification", 0.5, (PULSE_REF,))),
        ]

    def test_a_statement_row_outweighs_an_inference_row_of_the_same_link(self):
        """The same IOC from the stating pulse and from a feed that infers energy: two rows for one link.
        The batched writer keeps the label of the row whose confidence reaches the stored one, so the
        statement's 0.6 keeps ``otx_industries`` whichever row is written last (run on a real Neo4j in
        ``tests/test_sector_evidence_neo4j.py``)."""
        indicator = _synced(_pulse())["indicator"]
        inferred = {
            "indicator_type": "ipv4",
            "value": "198.51.100.23",
            "zone": ["energy"],
            "tag": "threatfox",
            "source_refs": ["threatfox:1650000"],
        }
        rows = MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships([indicator, inferred])
        energy = sorted(
            (r["confidence"], r["match_type"], r["source"]) for r in rows if r["to_key"].get("name") == "energy"
        )
        assert energy == [(0.5, "zone_classification", "threatfox"), (0.6, "otx_industries", "alienvault_otx")]

    def test_a_foreign_sector_tag_row_follows_the_table(self):
        """A partner's ``target-sector:`` tag with ``confidence:high`` is no statement EdgeGuard tracks: its
        row is ``zone_classification`` at the table's 0.5, so it cannot take the label of a stated link
        (at 0.8 it outweighed ``otx_industries``) and the link's confidence follows its label."""
        attr = {
            "uuid": "6a1f0000-0000-4000-8000-000000000777",
            "type": "ip-dst",
            "value": "198.51.100.23",
            "comment": "",
            "Tag": [{"name": "target-sector:energy"}, {"name": "zone:energy"}, {"name": "confidence:high"}],
        }
        event = {"id": 77, "info": "Partner event", "date": "2026-10-18", "Tag": []}
        _item, rels = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(attr, event)
        (row,) = [r for r in rels if r["rel_type"] == "TARGETS"]
        assert (row["match_type"], row["confidence"]) == ("zone_classification", 0.5)


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


class TestSourcedFromRecordsTheStatement:
    def test_the_indicator_batch_writer(self):
        indicator = _synced(_pulse())["indicator"]
        client, calls = _recording_client()
        client.merge_indicators_batch([indicator], source_id="alienvault_otx")
        (params,) = [p for q, p in calls if "MERGE (n)-[r:SOURCED_FROM]->(s)" in q]
        (row,) = params["batch"]
        assert sorted(row["zone"]) == ["energy", "healthcare"]
        assert row["stated_zones"] == ["energy"] and row["stated_refs"] == [f"energy|{PULSE_REF}"]

    @pytest.mark.parametrize("kind, method", [("malware", "merge_malware"), ("actor", "merge_actor")])
    def test_the_family_and_adversary_writers(self, kind, method):
        item = _synced(_pulse())[kind]
        client, calls = _recording_client()
        getattr(client, method)(item, source_id="alienvault_otx")
        (params,) = [p for q, p in calls if "MERGE (n)-[r:SOURCED_FROM]->(s)" in q]
        assert params["stated_zones"] == ["energy"] and params["stated_refs"] == [f"energy|{PULSE_REF}"]
        assert sorted(params["zones"]) == ["energy", "healthcare"]


# --------------------------------------------------------------------------- the single-link writers
class TestSingleLinkWritersFollowTheTable:
    """``create_indicator_sector_relationship`` / ``create_vulnerability_sector_relationship`` (no caller in
    the pipeline) write a link without evidence of their own: an inference at the table's confidence that
    never lowers a stored link, as the batched writer's rule."""

    @pytest.mark.parametrize(
        "method, args",
        [
            ("create_indicator_sector_relationship", ("198.51.100.23", "energy", "alienvault_otx", "ipv4")),
            ("create_vulnerability_sector_relationship", ("CVE-2026-11111", "energy", "nvd")),
        ],
    )
    def test_no_reset_of_a_stated_link(self, method, args):
        client, calls = _recording_client()
        assert getattr(client, method)(*args)
        rel_queries = [(q, p) for q, p in calls if "MERGE (i)-[r:TARGETS]->(s)" in q or "-[r:AFFECTS]->(s)" in q]
        assert rel_queries
        for query, params in rel_queries:
            assert "r.confidence_score = 0.5" not in query
            assert "$confidence >= r.confidence_score THEN $label ELSE r.match_type END" in query
            assert "$confidence > r.confidence_score THEN $confidence ELSE r.confidence_score END" in query
            assert (params["label"], params["confidence"]) == ("zone_classification", 0.5)
