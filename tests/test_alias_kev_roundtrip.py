"""Alias + KEV round-trip fixes (2026-06, Stage-2 GraphRAG readiness).

Three ingest-side data losses, all of which only heal at collection/sync
time (which is why they ship before the planned fresh baseline):

1. **Alias round-trip drop.** MISPWriter exported ThreatActor aliases as
   ``alias:`` tags (capped at 5), but ``parse_attribute`` hardcoded
   ``aliases: []`` on rehydration and the Malware path had no alias
   carrier at all — 0/917 actors and 0/3,409 malware on the 2026-04
   baseline carried aliases, silently disabling the alias-matching
   branches in build_relationships Q2/Q9 (built in c5a58ec, hardened in
   PR-N8/N9/N10/N14) and any "Cozy Bear" → APT29 lookup. Fixed: malware
   aliases extracted from ATT&CK ``x_mitre_aliases``, both writers emit
   ``alias:`` tags (cap raised 5 → 20), parser rehydrates them via
   ``_extract_alias_tags`` (PR-N14 sanitizer still enforced downstream).

2. **KEV marker gap.** Only NVD-sourced CVEs got a queryable
   ``cisa_exploit_add`` property (via NVD's cisaExploitAdd enrichment
   riding the NVD_META comment). CVEs known ONLY from the CISA collector
   (480 on the 2026-04 baseline) reached Neo4j with no KEV marker —
   invisible to the ``ti-cve-kev`` query family. Fixed: cisa_collector
   emits the four cisa_* fields and misp_writer's META-carrier gate now
   accepts ``cisa_exploit_add`` alone as qualification.

3. **Hash/bitcoin case canonicalization.** The sync pipeline's
   TYPE_MAPPING collapses md5/sha1/sha256/sha512 → "hash" and
   btc → "bitcoin" BEFORE merge, but _CASE_INSENSITIVE_INDICATOR_TYPES
   only listed the granular names — file hashes were stored with
   source-supplied case and an uppercase-pasted SHA256 lookup missed.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from collectors.misp_writer import MISPWriter  # noqa: E402
from node_identity import canonicalize_merge_key  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync, _extract_alias_tags  # noqa: E402


@pytest.fixture
def syncer() -> MISPToNeo4jSync:
    return MISPToNeo4jSync(neo4j_client=MagicMock())


@pytest.fixture
def writer() -> MISPWriter:
    w = MISPWriter.__new__(MISPWriter)  # no MISP connection needed for attribute builders
    return w


def _event(info: str = "EdgeGuard-MITRE-2026-06-11") -> dict:
    return {"id": 42, "info": info, "date": "2026-06-11", "Tag": [{"name": "source:mitre_attck"}]}


# ---------------------------------------------------------------------------
# 1a. _extract_alias_tags unit behavior
# ---------------------------------------------------------------------------


class TestExtractAliasTags:
    def test_extracts_and_strips(self):
        tags = [
            {"name": "alias:Cozy Bear "},
            {"name": "alias:APT29"},
            {"name": "zone:healthcare"},
            {"name": "source:mitre_attck"},
        ]
        assert _extract_alias_tags(tags) == ["Cozy Bear", "APT29"]

    def test_dedups_case_insensitively_order_preserving(self):
        tags = [{"name": "alias:APT29"}, {"name": "alias:apt29"}, {"name": "alias:The Dukes"}]
        assert _extract_alias_tags(tags) == ["APT29", "The Dukes"]

    def test_ignores_empty_and_malformed(self):
        tags = [{"name": "alias:"}, {"name": "alias:   "}, {}, {"name": None}, {"name": "aliases:nope"}]
        assert _extract_alias_tags(tags) == []


# ---------------------------------------------------------------------------
# 1b. Writer side — alias tags emitted for actors AND malware
# ---------------------------------------------------------------------------


class TestWriterAliasTags:
    def _tag_names(self, attribute: dict) -> list:
        return [t["name"] for t in attribute["Tag"]]

    def test_actor_alias_tags_emitted(self, writer):
        attr = writer.create_actor_attribute(
            {"name": "apt29", "aliases": ["Cozy Bear", "The Dukes"], "tag": "mitre_attck", "zone": ["global"]}
        )
        tags = self._tag_names(attr)
        assert "alias:Cozy Bear" in tags and "alias:The Dukes" in tags

    def test_actor_alias_cap_is_20_not_5(self, writer):
        """The old cap of 5 could drop the very alias an analyst searches
        by — MITRE intrusion-sets commonly carry 5-10 aliases."""
        aliases = [f"alias-{i}" for i in range(30)]
        attr = writer.create_actor_attribute(
            {"name": "apt29", "aliases": aliases, "tag": "mitre_attck", "zone": ["global"]}
        )
        alias_tags = [t for t in self._tag_names(attr) if t.startswith("alias:")]
        assert len(alias_tags) == 20, "cap must be 20 (was 5 pre-2026-06; >20 bounded against hostile feeds)"

    def test_malware_alias_tags_emitted(self, writer):
        """Malware had NO alias carrier at all pre-fix — Q2 branch 3 and Q9
        alias matching had nothing to match against after a MISP round-trip."""
        attr = writer.create_malware_attribute(
            {"name": "wellmess", "aliases": ["WellMess", "BOTLIB"], "tag": "mitre_attck", "zone": ["global"]}
        )
        tags = self._tag_names(attr)
        assert "alias:WellMess" in tags and "alias:BOTLIB" in tags


# ---------------------------------------------------------------------------
# 1c. Parser side — aliases rehydrate from MISP tags
# ---------------------------------------------------------------------------


class TestParserAliasRehydration:
    def test_actor_aliases_rehydrate(self, syncer):
        attr = {
            "type": "threat-actor",
            "value": "apt29",
            "comment": "Russian state-sponsored group",
            "Tag": [{"name": "alias:Cozy Bear"}, {"name": "alias:The Dukes"}, {"name": "zone:global"}],
        }
        item, _ = syncer.parse_attribute(attr, _event())
        assert item is not None and item["type"] == "actor"
        assert item["aliases"] == ["Cozy Bear", "The Dukes"], (
            "pre-fix this was hardcoded [] — the regression this file exists to prevent"
        )

    def test_malware_aliases_rehydrate(self, syncer):
        attr = {
            "type": "malware-type",
            "value": "wellmess",
            "comment": "",
            "Tag": [{"name": "alias:WellMess"}, {"name": "malware-type:backdoor"}],
        }
        item, _ = syncer.parse_attribute(attr, _event())
        assert item is not None and item["type"] == "malware"
        assert item["aliases"] == ["WellMess"]

    def test_actor_without_alias_tags_gets_empty_list(self, syncer):
        attr = {"type": "threat-actor", "value": "apt29", "comment": "", "Tag": [{"name": "zone:global"}]}
        item, _ = syncer.parse_attribute(attr, _event())
        assert item["aliases"] == []


# ---------------------------------------------------------------------------
# 1d. Full writer → parser round-trip (the actual contract)
# ---------------------------------------------------------------------------


class TestAliasFullRoundTrip:
    def test_actor_aliases_survive_misp_round_trip(self, writer, syncer):
        attribute = writer.create_actor_attribute(
            {"name": "apt29", "aliases": ["Cozy Bear", "The Dukes"], "tag": "mitre_attck", "zone": ["global"]}
        )
        item, _ = syncer.parse_attribute(attribute, _event())
        assert sorted(item["aliases"]) == ["Cozy Bear", "The Dukes"]

    def test_malware_aliases_survive_misp_round_trip(self, writer, syncer):
        attribute = writer.create_malware_attribute(
            {"name": "wellmess", "aliases": ["WellMess"], "tag": "mitre_attck", "zone": ["global"]}
        )
        item, _ = syncer.parse_attribute(attribute, _event())
        assert item["aliases"] == ["WellMess"]


# ---------------------------------------------------------------------------
# 2. KEV marker round-trip
# ---------------------------------------------------------------------------


class TestKevMarkerRoundTrip:
    CISA_VULN = {
        "type": "vulnerability",
        "cve_id": "CVE-2026-12345",
        "description": "Known exploited vulnerability",
        "zone": ["global"],
        "tag": "cisa",
        "source": ["cisa"],
        "confidence_score": 0.9,
        "severity": "CRITICAL",
        "cvss_score": 9.0,
        "vendor": "ExampleVendor",
        "product": "ExampleProduct",
        "known_ransomware_use": "Known",
        # The four fields cisa_collector now emits (no NVD enrichment present):
        "cisa_exploit_add": "2026-05-30",
        "cisa_action_due": "2026-06-20",
        "cisa_required_action": "Apply updates per vendor instructions.",
        "cisa_vulnerability_name": "Example RCE Vulnerability",
    }

    def test_cisa_only_cve_gets_meta_carrier(self, writer):
        """Pre-fix: has_nvd_meta ignored cisa_exploit_add, so CISA-collector
        CVEs (no NVD fields) skipped the META comment and the KEV marker
        was dropped between MISP and Neo4j."""
        attr = writer.create_vulnerability_attribute(dict(self.CISA_VULN))
        assert attr["comment"].startswith("NVD_META:"), "KEV date alone must qualify for the META carrier"
        assert "2026-05-30" in attr["comment"]
        tags = [t["name"] for t in attr["Tag"]]
        assert "CISA-KEV" in tags

    def test_kev_fields_rehydrate_onto_item(self, writer, syncer):
        attribute = writer.create_vulnerability_attribute(dict(self.CISA_VULN))
        item, _ = syncer.parse_attribute(attribute, _event("EdgeGuard-CISA-2026-06-11"))
        assert item is not None
        assert item.get("cisa_exploit_add") == "2026-05-30", (
            "the ti-cve-kev query family keys on cisa_exploit_add — every KEV CVE must carry it"
        )
        assert item.get("cisa_action_due") == "2026-06-20"
        assert item.get("cisa_vulnerability_name") == "Example RCE Vulnerability"

    def test_cisa_collector_emits_kev_fields(self, monkeypatch):
        from collectors.cisa_collector import CISACollector

        collector = CISACollector.__new__(CISACollector)
        collector.tag = "cisa"
        monkeypatch.setattr(
            collector,
            "_fetch_kev",
            lambda limit: [
                {
                    "cveID": "CVE-2026-12345",
                    "vendorProject": "ExampleVendor",
                    "product": "ExampleProduct",
                    "vulnerabilityName": "Example RCE Vulnerability",
                    "shortDescription": "RCE in example product",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "dateAdded": "2026-05-30",
                    "dueDate": "2026-06-20",
                    "knownRansomwareCampaignUse": "Known",
                    "cwes": ["CWE-94"],
                    "notes": "",
                }
            ],
        )
        result = collector.collect(limit=10, push_to_misp=False)
        items = result if isinstance(result, list) else (result.get("items") or [])
        assert items, f"expected processed items from collect(), got: {type(result).__name__}"
        item = items[0]
        assert item["cisa_exploit_add"] == "2026-05-30"
        assert item["cisa_action_due"] == "2026-06-20"
        assert item["cisa_required_action"] == "Apply updates per vendor instructions."
        assert item["cisa_vulnerability_name"] == "Example RCE Vulnerability"


# ---------------------------------------------------------------------------
# 3. Hash / bitcoin case canonicalization
# ---------------------------------------------------------------------------


class TestCollapsedTypeCaseCanonicalization:
    def test_hash_type_is_case_insensitive(self):
        upper = canonicalize_merge_key("Indicator", {"indicator_type": "hash", "value": "ABCDEF0123456789" * 4})
        lower = canonicalize_merge_key("Indicator", {"indicator_type": "hash", "value": "abcdef0123456789" * 4})
        assert upper == lower, (
            "TYPE_MAPPING stores file hashes as indicator_type='hash' — it must canonicalize like sha256"
        )

    def test_bitcoin_type_is_case_insensitive(self):
        upper = canonicalize_merge_key(
            "Indicator", {"indicator_type": "bitcoin", "value": "1A1ZP1EP5QGEFI2DMPTFTL5SLMV7DIVFNA"}
        )
        lower = canonicalize_merge_key(
            "Indicator", {"indicator_type": "bitcoin", "value": "1a1zp1ep5qgefi2dmptftl5slmv7divfna"}
        )
        assert upper == lower

    def test_url_stays_case_sensitive(self):
        a = canonicalize_merge_key("Indicator", {"indicator_type": "url", "value": "http://x/PATH"})
        b = canonicalize_merge_key("Indicator", {"indicator_type": "url", "value": "http://x/path"})
        assert a != b, "URL paths are case-sensitive — must NOT be folded"


# ---------------------------------------------------------------------------
# 4. MITRE collector — malware aliases extracted from x_mitre_aliases
# ---------------------------------------------------------------------------


class TestMitreMalwareAliasExtraction:
    def test_source_extracts_x_mitre_aliases(self):
        """Source pin: ATT&CK malware SDOs carry aliases ONLY in
        x_mitre_aliases (plain `aliases` exists on intrusion-sets) — the
        malware branch must read the extension field."""
        with open(os.path.join(_SRC, "collectors", "mitre_collector.py")) as fh:
            src = fh.read()
        assert "x_mitre_aliases" in src
        idx = src.find("malware.append(")
        assert idx > 0
        block = src[idx : idx + 800]
        assert '"aliases"' in block and "x_mitre_aliases" in block, (
            "the malware item dict must emit an aliases field (from x_mitre_aliases) for the MISP round-trip"
        )
