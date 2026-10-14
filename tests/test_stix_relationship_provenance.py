"""STIX export of every relationship, with its provenance (2026-10).

Every relationship EdgeGuard builds carries ``sources`` (who asserts it), ``source_refs``
(``"<source>:<record id>"``), ``misp_event_ids`` and ``match_type`` (relationship provenance).
The STIX bundles now export every relationship type that has a STIX form — curated-package
claims (Core Ideas) included — and each SRO carries that provenance: ``confidence``,
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
        for prop in ("x_edgeguard_match_type", "x_edgeguard_sources", "x_edgeguard_source_refs"):
            assert prop in sx.EDGEGUARD_EXTENSION_PROPERTIES
        definition = sx._extension_definition()
        assert definition["version"] == "1.1.0"
        assert definition["modified"].startswith("2026-10-14")

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
