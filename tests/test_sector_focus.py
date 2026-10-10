"""Pins for the 2026-10 sector-focus build (energy / finance demo questions).

* L3 — ``build_relationships`` Q7c / Q7d write ``(ThreatActor|Malware)-[:TARGETS]->(Sector)`` from the
  nodes' ``zone[]`` with the ``zone_classification`` evidence label, skipping ``global``; the step
  count is 15 and every new inner query stamps the ownership marker.
* L1 — the CPE-driven zone detector tags ICS / energy vendors and product families (and payment /
  ATM vendors for finance) that the vocabulary previously missed; generic vendors stay ``global``.
* The acceptance script reports sector coverage (informational).
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from collectors.nvd_collector import configurations_to_zone_text  # noqa: E402
from config import SECTOR_KEYWORDS, VALID_ZONES, detect_zones_from_item  # noqa: E402

_BUILD_REL = _SRC / "build_relationships.py"


def _inner(name: str) -> str:
    """Concatenated string constants of the ``<name> = (...)`` assignment in build_relationships."""
    tree = ast.parse(_BUILD_REL.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            parts = []
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    parts.append(sub.value)
            return "".join(parts)
    raise AssertionError(f"{name} not found")


# --------------------------------------------------------------------------- L3: actor / malware → Sector
class TestActorAndMalwareTargetSector:
    @pytest.mark.parametrize("name, var, label", [("_q7c_inner", "a", "ThreatActor"), ("_q7d_inner", "m", "Malware")])
    def test_inner_query_shape(self, name, var, label):
        body = _inner(name)
        assert f"WITH ${var} AS {var} UNWIND {var}.zone AS zone_name" in body
        assert f"MERGE ({var})-[r:TARGETS]->(sec)" in body
        assert 'zone_name <> "global"' in body, "no (actor)-[:TARGETS]->(global) edges"
        assert (
            'r.match_type = "zone_classification"' in body and 'coalesce(r.match_type, "zone_classification")' in body
        )
        assert "r.edgeguard_managed = true" in body
        assert "MERGE (sec:Sector {name: zone_name})" in body and "sec.edgeguard_managed = true" in body
        assert f"r.src_uuid = coalesce(r.src_uuid, {var}.uuid)" in body

    def test_outer_queries_select_nodes_with_a_zone(self):
        text = _BUILD_REL.read_text()
        assert '_q7c_outer = "MATCH (a:ThreatActor) WHERE size(coalesce(a.zone, [])) > 0 RETURN a"' in text
        assert '_q7d_outer = "MATCH (m:Malware) WHERE size(coalesce(m.zone, [])) > 0 RETURN m"' in text

    def test_steps_are_wired_with_their_own_stats_keys(self):
        text = _BUILD_REL.read_text()
        assert '"actor_targets_sector"' in text and '"malware_targets_sector"' in text

    def test_step_count_is_eighteen_everywhere(self):
        text = _BUILD_REL.read_text()
        banners = re.findall(r"\[LINK\] (\w+)/(\d+) ", text)
        totals = {t for _, t in banners}
        assert totals == {"18"}, totals
        assert len(banners) == 18, [s for s, _ in banners]
        assert {"7a", "7b", "7c", "7d"} <= {s for s, _ in banners}
        assert "failures=%d/18" in text and "/13" not in text and "/15" not in text and "/16" not in text

    def test_new_steps_run_right_after_7b_and_before_8(self):
        text = _BUILD_REL.read_text()
        pos = [re.search(rf"\[LINK\] {s}/\d+ ", text).start() for s in ("7b", "7c", "7d", "8")]
        assert pos == sorted(pos)


# --------------------------------------------------------------------------- L1: CPE vocabulary
def _cfg(*criteria: str) -> list:
    return [{"nodes": [{"cpeMatch": [{"criteria": c} for c in criteria]}]}]


def _zones_for_cpe(*criteria: str, description: str = "A vulnerability was found.") -> list:
    item = {"description": description}
    cpe_text = configurations_to_zone_text(_cfg(*criteria))
    if cpe_text.strip():
        item["comment"] = cpe_text
    return detect_zones_from_item(item)


class TestCpeVendorVocabulary:
    @pytest.mark.parametrize(
        "cpe",
        [
            "cpe:2.3:o:siemens:simatic_s7-1500_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:rockwellautomation:factorytalk_view:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:abb:rtu500_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:schneider-electric:ecostruxure_control_expert:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:phoenixcontact:axc_f_2152_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:growatt:shinewifi-x_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:advantech:webaccess:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:hitachienergy:rtu500_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:fujielectric:tellus_lite_v-simulator:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:deltaww:diaenergie:*:*:*:*:*:*:*:*",
        ],
    )
    def test_ics_vendor_cpe_tags_energy(self, cpe):
        assert _zones_for_cpe(cpe) == ["energy"], cpe

    @pytest.mark.parametrize(
        "cpe",
        [
            "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:adobe:acrobat_reader:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:huawei:emui:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
        ],
    )
    def test_generic_vendors_stay_global(self, cpe):
        assert _zones_for_cpe(cpe) == ["global"], cpe

    @pytest.mark.parametrize(
        "cpe",
        [
            "cpe:2.3:a:dieboldnixdorf:vynamic_security:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:temenos:transact:*:*:*:*:*:*:*:*",
            "cpe:2.3:h:ingenico:telium_2:*:*:*:*:*:*:*:*",
        ],
    )
    def test_payment_and_banking_vendor_cpe_tags_finance(self, cpe):
        assert _zones_for_cpe(cpe) == ["finance"], cpe

    def test_vocabulary_hygiene(self):
        for zone, kws in SECTOR_KEYWORDS.items():
            assert zone in VALID_ZONES
            assert all(kw == kw.lower().strip() and kw for kw in kws), zone
            assert len(set(kws)) == len(kws), f"duplicate keywords in {zone}: {[k for k in kws if kws.count(k) > 1]}"
        assert "siemens" in SECTOR_KEYWORDS["energy"] and "diebold nixdorf" in SECTOR_KEYWORDS["finance"]
        for too_generic in ("ge", "sel", "oracle", "sap", "cisco", "huawei", "honeywell"):
            assert too_generic not in SECTOR_KEYWORDS["energy"] and too_generic not in SECTOR_KEYWORDS["finance"]

    @pytest.mark.parametrize(
        "cpe",
        [
            "cpe:2.3:a:siemens_healthineers:syngo:*:*:*:*:*:*:*:*",
            # Bugbot on #137: the common NVD form — vendor token "siemens", Healthineers only in prose
            "cpe:2.3:a:siemens:syngo:*:*:*:*:*:*:*:*",
        ],
    )
    def test_siemens_healthineers_is_not_energy(self, cpe):
        zones = _zones_for_cpe(
            cpe,
            description="Siemens Healthineers syngo medical imaging software allows an attacker to access patient data.",
        )
        assert zones == ["healthcare"], zones

    def test_negative_keywords_are_module_level_and_cross_field(self):
        from config import SECTOR_NEGATIVE_KEYWORDS, _excluded_sectors

        assert "healthineers" in SECTOR_NEGATIVE_KEYWORDS["energy"]
        assert _excluded_sectors("siemens healthineers syngo") == {"energy"}
        zones = detect_zones_from_item(
            {"description": "Healthineers patient data exposure", "comment": "siemens syngo"}
        )
        assert "energy" not in zones


# --------------------------------------------------------------------------- acceptance script
class TestAcceptanceSectorCoverage:
    def test_sector_coverage_is_informational(self):
        script = (_SRC.parent / "scripts" / "verify_fresh_baseline.py").read_text()
        assert 'rep.add("sector_coverage", None, cov)' in script
        assert "[r:TARGETS|AFFECTS]->(s:Sector)" in script
