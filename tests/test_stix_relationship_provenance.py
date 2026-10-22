"""STIX export of every relationship, with its provenance (2026-10).

Every relationship EdgeGuard builds carries ``sources`` (who asserts it), ``source_refs``
(``"<source>:<record id>"``), ``misp_event_ids`` and ``match_type`` (relationship provenance).
The STIX bundles now export every relationship type that has a STIX form — curated-package
claims included — and each SRO carries that provenance: ``confidence``,
``external_references`` (with a link where the source record has a public page) and the
``x_edgeguard_match_type`` / ``x_edgeguard_sources`` / ``x_edgeguard_source_refs`` /
``x_edgeguard_misp_event_ids`` extension properties.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
import stix2

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-stix-provenance")
os.environ.setdefault("MISP_API_KEY", "test-key-stix-provenance")

import stix_exporter as sx  # noqa: E402

CURATED = {
    "match_type": "coreideas_curated",
    "confidence_score": 0.85,
    "sources": ["coreideas"],
    "source_refs": ["coreideas:claim:4b6d411b"],
    "misp_event_ids": ["412"],
}
MITRE = {
    "match_type": "mitre_explicit",
    "confidence_score": 0.95,
    "sources": ["mitre_attck", "alienvault_otx"],
    "source_refs": ["mitre_attck:G0016", "alienvault_otx:5f3c9e"],
    "misp_event_ids": ["135", "140"],
}


class _Session:
    def __init__(self, row: Dict[str, Any]):
        self.row = row
        self.calls: List[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher: str, **params: Any):
        self.calls.append(cypher)
        # the export query first; the SOURCED_FROM aggregate prefetch gets no rows
        return iter([] if "SOURCED_FROM" in cypher else [self.row])


def _exporter(row: Dict[str, Any]) -> sx.StixExporter:
    client = MagicMock()
    session = _Session(row)
    client.driver.session.return_value = session
    client.is_connected.return_value = True
    return sx.StixExporter(client)


def _sros(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [o for o in bundle["objects"] if o["type"] == "relationship"]


def _by_type(bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {o["id"]: o for o in bundle["objects"]}


def _pair(node: Dict[str, Any], rel: Dict[str, Any]) -> Dict[str, Any]:
    return {"n": node, "r": rel}


# --------------------------------------------------------------------------- helpers
class TestRecordLinks:
    @pytest.mark.parametrize(
        "source, record_id, url",
        [
            ("alienvault_otx", "5f3c9e", "https://otx.alienvault.com/pulse/5f3c9e"),
            ("threatfox", "1234567", "https://threatfox.abuse.ch/ioc/1234567/"),
            ("urlhaus", "3374851", "https://urlhaus.abuse.ch/url/3374851/"),
            ("mitre_attck", "G0016", "https://attack.mitre.org/groups/G0016/"),
            ("mitre_attck", "S0002", "https://attack.mitre.org/software/S0002/"),
            ("mitre_attck", "T1566.001", "https://attack.mitre.org/techniques/T1566/001/"),
            ("mitre_attck", "TA0001", "https://attack.mitre.org/tactics/TA0001/"),
            ("mitre_attck", "M1032", "https://attack.mitre.org/mitigations/M1032/"),
            ("mitre_attck", "C0047", "https://attack.mitre.org/campaigns/C0047/"),
            ("mitre_attck", "not-an-id", None),
            ("coreideas", "claim:4b6d411b", None),
            ("misp_galaxy", "u-1", None),
            ("threatfox", "a/b c", "https://threatfox.abuse.ch/ioc/a%2Fb%20c/"),
            # 2026-10-16: the CISA ICS advisory a sector statement rests on
            ("cisa_ics", "ICSA-24-123-01", "https://www.cisa.gov/news-events/ics-advisories/icsa-24-123-01"),
            ("cisa_ics", "ICSMA-26-283-01", "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-283-01"),
            ("cisa_ics", "not-an-advisory", None),
        ],
    )
    def test_record_url(self, source, record_id, url):
        assert sx._record_url(source, record_id) == url

    def test_external_references(self):
        refs = sx._external_references(
            ["coreideas:claim:9", "mitre_attck:G0016", "mitre_attck:G0016", "broken", ":x", 7, "threatfox:"]
        )
        assert refs == [
            {"source_name": "coreideas", "external_id": "claim:9"},
            {"source_name": "mitre_attck", "external_id": "G0016", "url": "https://attack.mitre.org/groups/G0016/"},
        ]
        many = sx._external_references([f"alienvault_otx:p{n}" for n in range(50)])
        assert len(many) == sx._MAX_EXTERNAL_REFERENCES

    def test_bounded_references_are_the_sorted_prefix_of_the_source_refs(self):
        refs = [f"alienvault_otx:p{n:03d}" for n in range(50)]
        cited = sx._external_references(list(reversed(refs)))
        assert [r["external_id"] for r in cited] == [f"p{n:03d}" for n in range(sx._MAX_EXTERNAL_REFERENCES)]
        actor = sx._deterministic_id("intrusion-set", "apt29")
        technique = sx._deterministic_id("attack-pattern", "T1566")
        sro = _exporter({})._edge_to_sro("EMPLOYS_TECHNIQUE", actor, technique, {"source_refs": refs[::-1]})
        cited_refs = [f"{r['source_name']}:{r['external_id']}" for r in sro["external_references"]]
        assert cited_refs == sro["x_edgeguard_source_refs"][: sx._MAX_EXTERNAL_REFERENCES]


# --------------------------------------------------------------------------- merging edges into one SRO
OTX_ATTRIBUTION = {
    "match_type": "otx_pulse",
    "confidence_score": 0.6,
    "sources": ["alienvault_otx"],
    "source_refs": ["alienvault_otx:77aa01"],
    "misp_event_ids": ["152"],
}


class TestMerge:
    def test_merge_is_independent_of_order(self):
        one = sx._merge_rel_props([CURATED, MITRE])
        assert one == sx._merge_rel_props([MITRE, CURATED])
        assert one == {
            "sources": ["alienvault_otx", "coreideas", "mitre_attck"],
            "source_refs": ["alienvault_otx:5f3c9e", "coreideas:claim:4b6d411b", "mitre_attck:G0016"],
            "misp_event_ids": ["135", "140", "412"],
            "confidence_score": 0.95,
            "match_type": "mitre_explicit",
        }

    def test_tie_takes_the_alphabetically_first_match_type(self):
        a = {"match_type": "zone_classification", "confidence_score": 0.6}
        b = {"match_type": "otx_pulse", "confidence_score": 0.6}
        assert sx._merge_rel_props([a, b])["match_type"] == "otx_pulse"
        assert sx._merge_rel_props([b, a])["match_type"] == "otx_pulse"

    def test_without_confidence_any_match_type_is_kept(self):
        merged = sx._merge_rel_props([{"sources": ["nvd"]}, {"match_type": "cve_tag", "sources": "misp"}])
        assert merged == {"sources": ["misp", "nvd"], "match_type": "cve_tag"}

    @pytest.mark.parametrize("value, expected", [(None, {}), ([], {}), ([None, {}], {}), ([MITRE], MITRE)])
    def test_single_or_empty(self, value, expected):
        assert sx._merge_rel_props(value) == expected

    def test_duplicate_sro_merges_in_either_order(self):
        actor = sx._deterministic_id("intrusion-set", "apt29")
        malware = sx._deterministic_id("malware", "cozycar")
        results = []
        for first, second in ((OTX_ATTRIBUTION, MITRE), (MITRE, OTX_ATTRIBUTION)):
            exporter = _exporter({})
            objects: Dict[str, Dict[str, Any]] = {}
            # (Malware)-[:ATTRIBUTED_TO]->(ThreatActor) and (ThreatActor)-[:USES_MALWARE]->(Malware)
            # are both ``intrusion-set uses malware``: one SRO id.
            sros = [
                exporter._edge_to_sro("ATTRIBUTED_TO", malware, actor, first),
                exporter._edge_to_sro("USES_MALWARE", actor, malware, second),
            ]
            assert sros[0]["id"] == sros[1]["id"]
            for sro in sros:
                exporter._add(objects, sro)
            (merged,) = objects.values()
            results.append({k: v for k, v in merged.items() if k not in ("created", "modified")})
        assert results[0] == results[1]
        merged = results[0]
        assert merged["confidence"] == 95 and merged["x_edgeguard_match_type"] == "mitre_explicit"
        assert merged["x_edgeguard_sources"] == ["alienvault_otx", "mitre_attck"]
        assert merged["x_edgeguard_source_refs"] == [
            "alienvault_otx:5f3c9e",
            "alienvault_otx:77aa01",
            "mitre_attck:G0016",
        ]
        assert merged["x_edgeguard_misp_event_ids"] == ["135", "140", "152"]
        assert [r["external_id"] for r in merged["external_references"]] == ["5f3c9e", "77aa01", "G0016"]

    def test_duplicate_sdo_keeps_the_first(self):
        exporter = _exporter({})
        objects: Dict[str, Dict[str, Any]] = {}
        exporter._add(objects, {"type": "malware", "id": "malware--1", "name": "first"})
        exporter._add(objects, {"type": "malware", "id": "malware--1", "name": "second"})
        assert objects["malware--1"]["name"] == "first"


# --------------------------------------------------------------------------- SRO
class TestSro:
    def test_provenance_on_the_sro(self):
        actor = sx._deterministic_id("intrusion-set", "apt29")
        technique = sx._deterministic_id("attack-pattern", "T1566")
        sro = _exporter({})._edge_to_sro("EMPLOYS_TECHNIQUE", actor, technique, MITRE)
        assert sro["relationship_type"] == "uses" and sro["confidence"] == 95
        assert sro["x_edgeguard_match_type"] == "mitre_explicit"
        assert sro["x_edgeguard_sources"] == ["alienvault_otx", "mitre_attck"]
        assert sro["x_edgeguard_source_refs"] == ["alienvault_otx:5f3c9e", "mitre_attck:G0016"]
        assert sro["x_edgeguard_misp_event_ids"] == ["135", "140"]
        assert {r["source_name"] for r in sro["external_references"]} == {"mitre_attck", "alienvault_otx"}

    def test_no_provenance_keeps_the_lean_sro(self):
        actor = sx._deterministic_id("intrusion-set", "apt29")
        technique = sx._deterministic_id("attack-pattern", "T1566")
        sro = _exporter({})._edge_to_sro("EMPLOYS_TECHNIQUE", actor, technique)
        assert not any(k.startswith("x_edgeguard_") for k in sro)
        assert "confidence" not in sro and "external_references" not in sro

    @pytest.mark.parametrize("bad", [None, "0.9", True, -0.1, 1.5])
    def test_confidence_only_from_a_unit_interval_number(self, bad):
        actor = sx._deterministic_id("intrusion-set", "apt29")
        technique = sx._deterministic_id("attack-pattern", "T1566")
        sro = _exporter({})._edge_to_sro("EMPLOYS_TECHNIQUE", actor, technique, {"confidence_score": bad})
        assert "confidence" not in sro

    def test_extension_declares_the_new_properties(self):
        for prop in (
            "x_edgeguard_match_type",
            "x_edgeguard_sources",
            "x_edgeguard_source_refs",
            "x_edgeguard_cited_ids",
            "x_edgeguard_merged_from",
            "x_edgeguard_evidence_types",
            "x_edgeguard_description_source",
        ):
            assert prop in sx.EDGEGUARD_EXTENSION_PROPERTIES
        definition = sx._extension_definition()
        # 1.1.0 (2026-10-14) added the provenance; 1.2.0 (2026-10-15) x_edgeguard_status on
        # vulnerabilities; 1.3.0 (2026-10-15) the explainability properties; 1.4.0 (2026-10-15) EPSS
        # and CISA's SSVC on vulnerabilities; 1.5.0 (2026-10-16) the evidence types of campaign links;
        # 1.6.0 (2026-10-16) the source of an SDO's description; 1.7.0 (2026-10-16) the aging of an
        # indicator.
        assert definition["version"] == "1.7.0"
        assert definition["modified"] == "2026-10-16T18:00:00.000Z"

    def test_a_campaign_link_carries_the_types_it_rests_on(self):
        """2026-10-16: a campaign link names the relationship types it rests on; the SRO carries them
        sorted, and another link carries none."""
        actor = sx._deterministic_id("intrusion-set", "fin7")
        campaign = sx._deterministic_id("campaign", "fin7 campaign")
        indicator = sx._deterministic_id("indicator", "fin7.example")
        runs = {
            "match_type": "campaign_grouping",
            "confidence_score": 0.95,
            "sources": ["mitre_attck"],
            "evidence_types": ["USES_MALWARE", "ATTRIBUTED_TO"],
        }
        sro = _exporter({})._edge_to_sro("RUNS", actor, campaign, runs)
        assert (sro["relationship_type"], sro["source_ref"], sro["target_ref"]) == ("attributed-to", campaign, actor)
        assert sro["x_edgeguard_evidence_types"] == ["ATTRIBUTED_TO", "USES_MALWARE"]
        member = {**runs, "evidence_types": ["INDICATES", "USES_MALWARE"]}
        sro = _exporter({})._edge_to_sro("PART_OF_CAMPAIGN", indicator, campaign, member)
        assert sro["relationship_type"] == "indicates" and sro["x_edgeguard_evidence_types"] == [
            "INDICATES",
            "USES_MALWARE",
        ]
        plain = _exporter({})._edge_to_sro(
            "EMPLOYS_TECHNIQUE", actor, sx._deterministic_id("attack-pattern", "T1566"), MITRE
        )
        assert "x_edgeguard_evidence_types" not in plain

    def test_a_link_a_revoked_id_led_to_carries_the_cited_ids(self):
        actor = sx._deterministic_id("intrusion-set", "apt29")
        technique = sx._deterministic_id("attack-pattern", "T1059.001")
        rel = {**MITRE, "cited_ids": ["T1086"]}
        sro = _exporter({})._edge_to_sro("EMPLOYS_TECHNIQUE", actor, technique, rel)
        assert sro["x_edgeguard_cited_ids"] == ["T1086"]
        plain = _exporter({})._edge_to_sro("EMPLOYS_TECHNIQUE", actor, technique, MITRE)
        assert "x_edgeguard_cited_ids" not in plain, "absent when every source cited the target itself"

    def test_an_actor_bundle_with_the_new_properties_parses_strictly(self):
        row = {
            "seed": {"name": "clop", "aliases": ["cl0p"], "merged_from": ["cl0p"]},
            "malware": [],
            "actor_tech": [_pair({"mitre_id": "T1059.001", "name": "PowerShell"}, {**MITRE, "cited_ids": ["T1086"]})],
            "mal_tech": [],
            "campaigns": [],
            "uses_malware": [],
            "tools": [],
            "exploits": [],
            "sectors": [],
        }
        bundle = _exporter(row).export_threat_actor("clop")
        parsed = stix2.parse(json.dumps(bundle))  # strict: every x_edgeguard_* property is declared
        (actor,) = [o for o in parsed.objects if o.type == "intrusion-set"]
        (link,) = [o for o in parsed.objects if o.type == "relationship"]
        assert actor["x_edgeguard_merged_from"] == ["cl0p"] and link["x_edgeguard_cited_ids"] == ["T1086"]

    def test_merged_sros_take_the_union_of_the_cited_ids(self):
        merged = sx._merge_rel_props([{**MITRE, "cited_ids": ["T1086"]}, {**CURATED, "cited_ids": ["T1064", "T1086"]}])
        assert merged["cited_ids"] == ["T1064", "T1086"]

    def test_an_intrusion_set_names_the_actor_nodes_folded_into_it(self):
        exporter = _exporter({})
        sdo = exporter._actor_sdo({"name": "clop", "aliases": ["cl0p"], "merged_from": ["cl0p", "cl0p"]})
        assert sdo["x_edgeguard_merged_from"] == ["cl0p"]
        assert "x_edgeguard_merged_from" not in exporter._actor_sdo({"name": "apt29"})

    @pytest.mark.parametrize(
        "edge, source_type, target_type, stix_type, reversed_",
        [
            ("USES_MALWARE", "intrusion-set", "malware", "uses", False),
            ("USES_TOOL", "intrusion-set", "tool", "uses", False),
            ("SUBTECHNIQUE_OF", "attack-pattern", "attack-pattern", "subtechnique-of", False),
            ("EXPLOITS", "malware", "vulnerability", "exploits", False),
            ("EXPLOITS", "intrusion-set", "vulnerability", "targets", False),
            ("TARGETS", "intrusion-set", "identity", "targets", False),
            ("TARGETS", "malware", "identity", "targets", False),
            ("PART_OF_CAMPAIGN", "malware", "campaign", "uses", True),
            ("PART_OF_CAMPAIGN", "indicator", "campaign", "indicates", False),
        ],
    )
    def test_every_relationship_has_a_stix_form(self, edge, source_type, target_type, stix_type, reversed_):
        assert sx._SRO_BY_EDGE[(edge, source_type, target_type)] == (stix_type, reversed_)


# --------------------------------------------------------------------------- bundles
class TestBundles:
    def test_actor_bundle_exports_software_cves_and_sectors_with_curated_claims(self):
        row = {
            "seed": {"name": "apt29", "aliases": ["APT29"]},
            "malware": [],
            "actor_tech": [_pair({"mitre_id": "T1566", "name": "Phishing"}, MITRE)],
            "mal_tech": [],
            "campaigns": [],
            "uses_malware": [_pair({"name": "cozycar"}, MITRE)],
            "tools": [_pair({"mitre_id": "S0002", "name": "mimikatz"}, MITRE)],
            "exploits": [_pair({"cve_id": "CVE-2023-42793"}, CURATED)],
            "sectors": [
                _pair({"name": "energy"}, {"match_type": "zone_classification", "sources": ["alienvault_otx"]})
            ],
        }
        bundle = _exporter(row).export_threat_actor("apt29")
        stix2.parse(json.dumps(bundle), allow_custom=True)
        objects = _by_type(bundle)
        kinds = sorted(
            (objects[s["source_ref"]]["type"], s["relationship_type"], objects[s["target_ref"]]["type"])
            for s in _sros(bundle)
        )
        assert kinds == [
            ("intrusion-set", "targets", "identity"),
            ("intrusion-set", "targets", "vulnerability"),
            ("intrusion-set", "uses", "attack-pattern"),
            ("intrusion-set", "uses", "malware"),
            ("intrusion-set", "uses", "tool"),
        ]
        curated = next(s for s in _sros(bundle) if objects[s["target_ref"]]["type"] == "vulnerability")
        assert curated["x_edgeguard_match_type"] == "coreideas_curated"
        assert curated["x_edgeguard_sources"] == ["coreideas"]
        assert curated["confidence"] == 85
        assert curated["external_references"] == [{"source_name": "coreideas", "external_id": "claim:4b6d411b"}]
        assert sx.EDGEGUARD_EXTENSION_ID in curated["extensions"]

    def test_cve_bundle_exports_the_actors_and_malware_that_exploit_it(self):
        row = {
            "seed": {"cve_id": "CVE-2023-4966"},
            "indicators": [],
            "threats": [
                {"n": {"name": "lockbit"}, "r": CURATED, "kind": "Malware"},
                {"n": {"name": "fin7"}, "r": CURATED, "kind": "ThreatActor"},
                {"n": None, "r": None, "kind": "Malware"},
            ],
            "sectors": [],
        }
        bundle = _exporter(row).export_cve("CVE-2023-4966")
        stix2.parse(json.dumps(bundle), allow_custom=True)
        objects = _by_type(bundle)
        kinds = sorted((objects[s["source_ref"]]["type"], s["relationship_type"]) for s in _sros(bundle))
        assert kinds == [("intrusion-set", "targets"), ("malware", "exploits")]
        assert all(s["x_edgeguard_sources"] == ["coreideas"] for s in _sros(bundle))

    def test_cve_bundle_exports_a_cisa_sector_statement_with_its_advisory(self):
        """2026-10-16: a sector CISA's ICS advisory states is ``advisory_sector`` at 0.9 on the AFFECTS link
        (the product is deployed in the sector); STIX keeps ``related-to`` and carries the label, the
        confidence 90 and the advisory with its cisa.gov page. NVD also inferred the sector here."""
        advisory = {
            "match_type": "advisory_sector",
            "confidence_score": 0.9,
            "sources": ["cisa_ics", "nvd"],
            "source_refs": ["cisa_ics:ICSA-26-281-01"],
            "misp_event_ids": ["161", "120"],
        }
        row = {
            "seed": {"cve_id": "CVE-2026-32645"},
            "indicators": [],
            "threats": [],
            "sectors": [_pair({"name": "energy"}, advisory)],
        }
        bundle = _exporter(row).export_cve("CVE-2026-32645")
        stix2.parse(json.dumps(bundle), allow_custom=True)
        (sro,) = _sros(bundle)
        assert sro["relationship_type"] == "related-to"
        assert sro["x_edgeguard_match_type"] == "advisory_sector" and sro["confidence"] == 90
        assert sro["x_edgeguard_sources"] == ["cisa_ics", "nvd"]
        assert sro["external_references"] == [
            {
                "source_name": "cisa_ics",
                "external_id": "ICSA-26-281-01",
                "url": "https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-01",
            }
        ]

    def test_actor_bundle_merges_attribution_and_mitre_uses_into_one_sro(self):
        row = {
            "seed": {"name": "apt29"},
            "malware": [_pair({"name": "cozycar"}, OTX_ATTRIBUTION)],
            "actor_tech": [],
            "mal_tech": [],
            "campaigns": [],
            "uses_malware": [_pair({"name": "cozycar"}, MITRE)],
            "tools": [],
            "exploits": [],
            "sectors": [],
        }
        bundle = _exporter(row).export_threat_actor("apt29")
        stix2.parse(json.dumps(bundle), allow_custom=True)
        (sro,) = _sros(bundle)
        assert sro["relationship_type"] == "uses"
        assert sro["confidence"] == 95 and sro["x_edgeguard_match_type"] == "mitre_explicit"
        assert sro["x_edgeguard_sources"] == ["alienvault_otx", "mitre_attck"]

    def test_cve_bundle_merges_the_edges_to_both_twins(self):
        tag_otx = {
            "match_type": "cve_tag",
            "confidence_score": 1.0,
            "sources": ["alienvault_otx"],
            "misp_event_ids": ["135"],
        }
        tag_nvd = {"match_type": "cve_tag", "confidence_score": 1.0, "sources": ["nvd"], "misp_event_ids": ["120"]}
        row = {
            "seed": {"cve_id": "CVE-2023-4966"},
            # one row per neighbour, with its edges to the CVE and the Vulnerability twin
            "indicators": [{"n": {"value": "evil.example", "indicator_type": "domain"}, "r": [tag_otx, tag_nvd]}],
            "threats": [{"n": {"name": "lockbit"}, "r": [CURATED, OTX_ATTRIBUTION], "kind": "Malware"}],
            "sectors": [{"n": {"name": "energy"}, "r": []}],
        }
        bundle = _exporter(row).export_cve("CVE-2023-4966")
        stix2.parse(json.dumps(bundle), allow_custom=True)
        objects = _by_type(bundle)
        by_source = {objects[s["source_ref"]]["type"]: s for s in _sros(bundle)}
        assert by_source["indicator"]["x_edgeguard_sources"] == ["alienvault_otx", "nvd"]
        assert by_source["indicator"]["x_edgeguard_misp_event_ids"] == ["120", "135"]
        assert by_source["malware"]["x_edgeguard_sources"] == ["alienvault_otx", "coreideas"]
        assert by_source["malware"]["x_edgeguard_match_type"] == "coreideas_curated"
        assert "x_edgeguard_sources" not in by_source["vulnerability"]  # AFFECTS without provenance

    def test_indicator_bundle_merges_the_edges_to_both_cve_twins(self):
        row = {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [],
            "vulns": [
                {"n": {"cve_id": "CVE-2021-44228"}, "r": [{"sources": ["alienvault_otx"]}, {"sources": ["misp"]}]}
            ],
            "techniques": [],
            "sectors": [],
        }
        (sro,) = _sros(_exporter(row).export_indicator("1.2.3.4"))
        assert sro["x_edgeguard_sources"] == ["alienvault_otx", "misp"]

    def test_cve_bundle_depth_1_keeps_only_the_indicators(self):
        row = {
            "seed": {"cve_id": "CVE-2023-4966"},
            "indicators": [],
            "threats": [{"n": {"name": "x"}, "r": {}, "kind": "Malware"}],
            "sectors": [],
        }
        assert _sros(_exporter(row).export_cve("CVE-2023-4966", depth=1)) == []

    def test_technique_bundle_exports_the_attack_hierarchy(self):
        row = {
            "seed": {"mitre_id": "T1566", "name": "Phishing"},
            "actors": [],
            "malware": [],
            "tools": [],
            "indicators": [],
            "parents": [],
            "subtechniques": [
                _pair(
                    {"mitre_id": "T1566.001", "name": "Spearphishing Attachment"},
                    {"match_type": "mitre_explicit", "sources": ["mitre_attck"]},
                )
            ],
        }
        bundle = _exporter(row).export_technique("T1566")
        stix2.parse(json.dumps(bundle), allow_custom=True)
        (sro,) = _sros(bundle)
        objects = _by_type(bundle)
        assert sro["relationship_type"] == "subtechnique-of"
        assert objects[sro["source_ref"]]["external_references"][0]["external_id"] == "T1566.001"
        assert objects[sro["target_ref"]]["external_references"][0]["external_id"] == "T1566"

    def test_indicator_bundle_exports_campaign_membership(self):
        row = {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [],
            "vulns": [],
            "techniques": [],
            "sectors": [],
            "campaigns": [_pair({"name": "apt29 Campaign", "actor_name": "apt29"}, {"sources": ["alienvault_otx"]})],
        }
        bundle = _exporter(row).export_indicator("1.2.3.4")
        stix2.parse(json.dumps(bundle), allow_custom=True)
        (sro,) = _sros(bundle)
        assert sro["relationship_type"] == "indicates" and sro["x_edgeguard_sources"] == ["alienvault_otx"]

    def test_rows_of_plain_nodes_still_export(self):
        """Backward compatible: a plain node list (no relationship map) exports without provenance."""
        row = {
            "seed": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "malware": [{"name": "emotet"}],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
        (sro,) = _sros(_exporter(row).export_indicator("1.2.3.4"))
        assert sro["relationship_type"] == "indicates" and "x_edgeguard_sources" not in sro


# --------------------------------------------------------------------------- indicator and CVE named in one report
# 2026-10-18: (Indicator)-[:INDICATES]->(CVE), a CVE named in the same OTX report as the indicator, with the
# properties the sync's relationship writer gives it.
SAME_REPORT = {
    "edge_type": "INDICATES",
    "match_type": "otx_pulse",
    "confidence_score": 0.6,
    "sources": ["alienvault_otx"],
    "source_refs": ["alienvault_otx:6a0f3c2e9b1d4e5f60718293"],
    "misp_event_ids": ["4127"],
    "edgeguard_managed": True,
    "imported_at": "2026-10-18T06:00:00+00:00",
    "updated_at": "2026-10-18T07:30:00+00:00",
}
OWN_CLAIM = {
    "edge_type": "EXPLOITS",
    "match_type": "cve_tag",
    "confidence_score": 1.0,
    "sources": ["misp"],
    "source_refs": [],
    "misp_event_ids": ["99"],
    "imported_at": "2026-10-17T06:00:00+00:00",
    "updated_at": "2026-10-17T06:00:00+00:00",
}


class TestIndicatorCveSameReport:
    def test_the_pair_is_related_to_explicitly(self, caplog):
        assert sx._SRO_BY_EDGE[("INDICATES", "indicator", "vulnerability")] == ("related-to", False)
        assert {
            "graph_relationship": "INDICATES",
            "graph_source": "indicator",
            "graph_target": "vulnerability",
            "relationship_type": "related-to",
            "source": "indicator",
            "target": "vulnerability",
        } in sx.stix_relationship_mappings()
        indicator = sx._deterministic_id("indicator", "1.2.3.4")
        cve = sx._deterministic_id("vulnerability", "CVE-2024-21887")
        with caplog.at_level("WARNING", logger="stix_exporter"):
            sro = _exporter({})._edge_to_sro("INDICATES", indicator, cve, SAME_REPORT)
        assert not [r for r in caplog.records if "No STIX 2.1 relationship mapping" in r.getMessage()]
        assert sro["relationship_type"] == "related-to"

    def test_an_indicator_bundle_carries_the_same_report_cve(self):
        row = {
            "seed": {"value": "203.0.113.17", "indicator_type": "ipv4"},
            "malware": [],
            "vulns": [_pair({"cve_id": "CVE-2024-21887"}, [SAME_REPORT])],
            "techniques": [],
            "sectors": [],
        }
        bundle = _exporter(row).export_indicator("203.0.113.17")
        parsed = stix2.parse(json.dumps(bundle))  # strict: every x_edgeguard_* property is declared
        (sro,) = [o for o in parsed.objects if o.type == "relationship"]
        objects = _by_type(bundle)
        assert objects[sro.source_ref]["type"] == "indicator" and objects[sro.target_ref]["type"] == "vulnerability"
        assert sro.relationship_type == "related-to"
        assert sro.confidence == 60
        assert sro["x_edgeguard_match_type"] == "otx_pulse"
        assert sro["x_edgeguard_sources"] == ["alienvault_otx"]
        assert sro["x_edgeguard_source_refs"] == ["alienvault_otx:6a0f3c2e9b1d4e5f60718293"]
        assert sro["x_edgeguard_misp_event_ids"] == ["4127"]
        assert sro.external_references[0].url == "https://otx.alienvault.com/pulse/6a0f3c2e9b1d4e5f60718293"
        # The link's own times, never the clock (``_relationship_created_modified``).
        assert str(sro.created).startswith("2026-10-18 06:00:00") and str(sro.modified).startswith("2026-10-18 07:30")
        assert "edge_type" not in json.dumps(bundle)

    def test_a_cve_the_indicator_claims_and_its_report_names_is_one_sro(self):
        row = {
            "seed": {"value": "203.0.113.17", "indicator_type": "ipv4"},
            "malware": [],
            "vulns": [_pair({"cve_id": "CVE-2024-21887"}, [SAME_REPORT, OWN_CLAIM])],
            "techniques": [],
            "sectors": [],
        }
        bundle = _exporter(row).export_indicator("203.0.113.17")
        stix2.parse(json.dumps(bundle))
        (sro,) = _sros(bundle)
        # The stronger link's label; the provenance of both.
        assert sro["x_edgeguard_match_type"] == "cve_tag" and sro["confidence"] == 100
        assert sro["x_edgeguard_sources"] == ["alienvault_otx", "misp"]
        assert sro["x_edgeguard_misp_event_ids"] == ["4127", "99"]
        assert sro["created"].startswith("2026-10-17T06:00:00") and sro["modified"].startswith("2026-10-18T07:30")

    def test_depth_1_of_an_indicator_bundle_leaves_the_cves_out(self):
        row = {
            "seed": {"value": "203.0.113.17", "indicator_type": "ipv4"},
            "malware": [],
            "vulns": [_pair({"cve_id": "CVE-2024-21887"}, [SAME_REPORT])],
            "techniques": [],
            "sectors": [],
        }
        assert _sros(_exporter(row).export_indicator("203.0.113.17", depth=1)) == []

    @pytest.mark.parametrize("depth", [1, 2])
    def test_a_cve_bundle_carries_the_indicators_its_report_names(self, depth):
        row = {
            "seed": {"cve_id": "CVE-2024-21887"},
            "indicators": [
                _pair({"value": "203.0.113.17", "indicator_type": "ipv4"}, [SAME_REPORT]),
                _pair({"value": "update-check.example.net", "indicator_type": "domain"}, [SAME_REPORT, OWN_CLAIM]),
            ],
            "threats": [],
            "sectors": [],
        }
        bundle = _exporter(row).export_cve("CVE-2024-21887", depth=depth)
        stix2.parse(json.dumps(bundle))
        objects = _by_type(bundle)
        # An indicator SDO is named "<type>:<value>".
        by_indicator = {objects[s["source_ref"]]["name"].split(":", 1)[1]: s for s in _sros(bundle)}
        assert set(by_indicator) == {"203.0.113.17", "update-check.example.net"}
        assert {s["relationship_type"] for s in by_indicator.values()} == {"related-to"}
        assert by_indicator["203.0.113.17"]["x_edgeguard_match_type"] == "otx_pulse"
        assert by_indicator["update-check.example.net"]["x_edgeguard_match_type"] == "cve_tag"

    def test_the_queries_walk_indicates_to_the_cve_node_only(self):
        session = _Session({"seed": None})
        client = MagicMock()
        client.driver.session.return_value = session
        exporter = sx.StixExporter(client)
        exporter.export_indicator("203.0.113.17")
        exporter.export_cve("CVE-2024-21887")
        indicator_q, cve_q = (" ".join(c.split()) for c in session.calls if "SOURCED_FROM" not in c)
        assert "OPTIONAL MATCH (i)-[r2:EXPLOITS|INDICATES]->(v)" in indicator_q
        assert '(type(r2) = "INDICATES" AND v:CVE)' in indicator_q
        assert "collect(r2 {.*, edge_type: type(r2)}) AS r2s" in indicator_q
        assert "OPTIONAL MATCH (i:Indicator)-[r1:EXPLOITS|INDICATES]->(tw)" in cve_q
        assert 'WHERE (type(r1) = "EXPLOITS" OR tw:CVE)' in cve_q
        assert "collect(r1 {.*, edge_type: type(r1)}) AS r1s" in cve_q


# --------------------------------------------------------------------------- the link's own TLP
AMBER_CURATED = dict(CURATED, tlp="amber")


class TestRelationshipTlp:
    """TLP fix (2026-10): an SRO is as restricted as the most restricted of its two endpoints and
    of the link's own ``tlp`` (curated-package links carry the package's level in ``r.tlp``).
    It used to take its endpoints' markings only, so a curated link between TLP:WHITE nodes was
    exported as TLP:WHITE."""

    ACTOR = sx._deterministic_id("intrusion-set", "apt29")
    MALWARE = sx._deterministic_id("malware", "cozycar")

    def _exporter_with_marked_ends(self, actor=stix2.TLP_WHITE, malware=stix2.TLP_WHITE):
        exporter = _exporter({})
        exporter._marking_by_id = {self.ACTOR: actor.id, self.MALWARE: malware.id}
        return exporter

    @pytest.mark.parametrize(
        "ends, rel_tlp, expected",
        [
            ((stix2.TLP_WHITE, stix2.TLP_WHITE), "amber", stix2.TLP_AMBER),
            ((stix2.TLP_WHITE, stix2.TLP_GREEN), "amber+strict", stix2.TLP_RED),
            ((stix2.TLP_RED, stix2.TLP_WHITE), "amber", stix2.TLP_RED),
            ((stix2.TLP_WHITE, stix2.TLP_GREEN), None, stix2.TLP_GREEN),
            ((stix2.TLP_WHITE, stix2.TLP_WHITE), "clear", stix2.TLP_WHITE),
            ((stix2.TLP_WHITE, stix2.TLP_WHITE), "not-a-level", stix2.TLP_AMBER),
        ],
    )
    def test_sro_takes_the_most_restrictive_of_its_ends_and_the_link(self, ends, rel_tlp, expected):
        exporter = self._exporter_with_marked_ends(*ends)
        rel = dict(CURATED, tlp=rel_tlp) if rel_tlp is not None else CURATED
        sro = exporter._edge_to_sro("USES_MALWARE", self.ACTOR, self.MALWARE, rel)
        assert sro["object_marking_refs"] == [expected.id]

    def test_merging_two_edges_keeps_the_more_restrictive_marking_in_either_order(self):
        markings = []
        for first, second in ((OTX_ATTRIBUTION, AMBER_CURATED), (AMBER_CURATED, OTX_ATTRIBUTION)):
            exporter = self._exporter_with_marked_ends()
            objects: Dict[str, Dict[str, Any]] = {}
            # ATTRIBUTED_TO (a feed edge) and USES_MALWARE (a curated claim) are one SRO
            exporter._add(objects, exporter._edge_to_sro("ATTRIBUTED_TO", self.MALWARE, self.ACTOR, first))
            exporter._add(objects, exporter._edge_to_sro("USES_MALWARE", self.ACTOR, self.MALWARE, second))
            (merged,) = objects.values()
            markings.append(merged["object_marking_refs"])
        assert markings == [[stix2.TLP_AMBER.id], [stix2.TLP_AMBER.id]]

    def test_edges_behind_one_sro_keep_the_most_restrictive_tlp(self):
        assert sx._merge_rel_props([AMBER_CURATED, OTX_ATTRIBUTION])["tlp"] == "amber"
        assert sx._merge_rel_props([OTX_ATTRIBUTION, AMBER_CURATED])["tlp"] == "amber"
        assert sx._merge_rel_props([dict(CURATED, tlp="RED"), AMBER_CURATED])["tlp"] == "red"
        assert "tlp" not in sx._merge_rel_props([CURATED, OTX_ATTRIBUTION])

    def test_actor_bundle_marks_the_curated_link_amber(self):
        white = {"tlp": "white"}
        row = {
            "seed": {"name": "apt29", **white},
            "malware": [],
            "actor_tech": [_pair({"mitre_id": "T1566", "name": "Phishing", **white}, MITRE)],
            "mal_tech": [],
            "campaigns": [],
            "uses_malware": [],
            "tools": [],
            "exploits": [_pair({"cve_id": "CVE-2023-42793", **white}, AMBER_CURATED)],
            "sectors": [],
        }
        bundle = _exporter(row).export_threat_actor("apt29")
        stix2.parse(json.dumps(bundle), allow_custom=True)
        objects = _by_type(bundle)
        marking = {objects[s["target_ref"]]["type"]: s["object_marking_refs"] for s in _sros(bundle)}
        assert marking == {"vulnerability": [stix2.TLP_AMBER.id], "attack-pattern": [stix2.TLP_WHITE.id]}
        assert stix2.TLP_AMBER.id in objects, "the bundle carries the marking definition it references"

    def test_cve_bundle_marks_a_curated_edge_to_one_twin(self):
        row = {
            "seed": {"cve_id": "CVE-2023-4966", "tlp": "white"},
            "indicators": [],
            "threats": [
                {"n": {"name": "lockbit", "tlp": "white"}, "r": [OTX_ATTRIBUTION, AMBER_CURATED], "kind": "Malware"}
            ],
            "sectors": [],
        }
        bundle = _exporter(row).export_cve("CVE-2023-4966")
        stix2.parse(json.dumps(bundle), allow_custom=True)
        (sro,) = _sros(bundle)
        assert sro["object_marking_refs"] == [stix2.TLP_AMBER.id]
