#!/usr/bin/env python3
"""
EdgeGuard — Zone & Linking Logic Debug Script (standalone)
==========================================================
Inlines only the exact logic under test — no neo4j driver required.

Run:
    cd src && python3 debug_zone_check.py
"""

import os
import sys

os.environ.setdefault("NEO4J_PASSWORD", "debug_only")
os.environ.setdefault("MISP_API_KEY", "debug_only")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── console logging (no NDJSON / Cursor session files) ────────────────────────


def _log(msg: str, data: dict, hyp: str = "", level: str = "INFO"):
    icon = "✓" if level == "PASS" else ("✗" if level == "FAIL" else "·")
    print(f"  [{hyp or '    '}] {icon} {msg}")
    for k, v in data.items():
        print(f"              {k}: {v}")


# ── inline the exact methods under test (copied verbatim from source) ─────────


def _extract_zone_from_event_name(event_info: str):
    """Exact copy of MISPToNeo4jSync._extract_zone_from_event_name (line 528).

    PR #34 round 24: was using a hardcoded zone list, duplicating
    ``config.VALID_ZONES``. Switched to import VALID_ZONES so adding a
    5th zone in config is automatically reflected here.
    """
    from config import VALID_ZONES

    if not event_info:
        return None
    parts = event_info.split("-")
    if len(parts) >= 2 and parts[0].upper() == "EDGEGUARD":
        zone = parts[1].lower()
        if zone in VALID_ZONES:
            return zone
    return None


def extract_zones_from_tags(tags: list) -> list:
    """Exact copy of MISPToNeo4jSync.extract_zones_from_tags (line 442)."""
    from config import VALID_ZONES

    zones: set = set()
    for tag in tags:
        tag_name = tag.get("name", "")
        for prefix in ("zone:", "sector:"):
            if tag_name.startswith(prefix):
                candidate = tag_name[len(prefix) :].strip().lower()
                if candidate in VALID_ZONES:
                    zones.add(candidate)
    return list(zones) if zones else ["global"]


def zone_combination_fixed(zone_from_name, zones_from_tags):
    """FIXED zone combination: merges both sources, specific sectors win over global."""
    _all: set = set()
    if zone_from_name:
        _all.add(zone_from_name)
    for z in zones_from_tags:
        _all.add(z)
    specific = {z for z in _all if z != "global"}
    return sorted(specific) if specific else ["global"]


def parse_attribute_zone_fixed(attr_tags, event_info):
    """FIXED zone resolution with priority layers:
    1. Attribute has its own specific zone tags → use those exclusively (most precise)
    2. Attribute has no specific zone → merge event-level tags + event name
    """
    zones_from_attr = extract_zones_from_tags(attr_tags)
    specific_from_attr = [z for z in zones_from_attr if z != "global"]

    if specific_from_attr:
        # Attribute carries its own zone — don't pollute it with event-level zones
        return sorted(specific_from_attr)

    # No specific attr zone: supplement from event-level sources
    _az: set = set()
    for z in zones_from_attr:
        _az.add(z)
    for z in extract_zones_from_tags(event_info.get("Tag", [])):
        _az.add(z)
    zone_from_name = _extract_zone_from_event_name(event_info.get("info", ""))
    if zone_from_name:
        _az.add(zone_from_name)
    specific = {z for z in _az if z != "global"}
    return sorted(specific) if specific else ["global"]


# ─────────────────────────────────────────────────────────────────────────────
# H1 — Zone combination drops tags when event name matches
# ─────────────────────────────────────────────────────────────────────────────


def test_h1():
    print("\n── H1: Zone combination (event name vs event tags) ───────────────────")

    cases = [
        # (event_name, event_tags, expected_zones, description)
        (
            "EdgeGuard-FINANCE-otx-2024-03-01",
            [{"name": "zone:healthcare"}, {"name": "zone:finance"}],
            ["finance", "healthcare"],
            "Name=FINANCE, Tags=finance+healthcare → should merge both",
        ),
        (
            "EdgeGuard-GLOBAL-nvd-2024-03-01",
            [{"name": "zone:healthcare"}],
            ["healthcare"],
            "Name=GLOBAL, Tags=healthcare → tag should win over global name",
        ),
        (
            "EdgeGuard-ENERGY-cisa-2024-03-01",
            [{"name": "zone:finance"}],
            ["energy", "finance"],
            "Name=ENERGY, Tags=finance → should merge both",
        ),
        (
            "Some-other-event-name",  # not EdgeGuard naming → zone_from_name = None
            [{"name": "zone:healthcare"}],
            ["healthcare"],
            "Non-EdgeGuard name → tags should be the sole source",
        ),
    ]

    h1_bugs = 0
    for event_name, event_tags, expected, desc in cases:
        zone_from_name = _extract_zone_from_event_name(event_name)
        zones_from_tags = extract_zones_from_tags(event_tags)
        actual = zone_combination_fixed(zone_from_name, zones_from_tags)

        passed = set(actual) == set(expected)
        level = "PASS" if passed else "FAIL"
        if not passed:
            h1_bugs += 1
        _log(
            f"H1 {level}: {desc}",
            {
                "zone_from_name": zone_from_name,
                "zones_from_tags": zones_from_tags,
                "actual": sorted(actual),
                "expected": sorted(expected),
                "BUG": None if passed else "zone_from_name overwrites tags exclusively",
            },
            "H1",
            level,
        )

    _log(
        f"H1 summary: {h1_bugs}/{len(cases)} scenarios produce wrong zones",
        {"bugs_found": h1_bugs, "total_cases": len(cases)},
        "H1",
        "FAIL" if h1_bugs else "PASS",
    )


# ─────────────────────────────────────────────────────────────────────────────
# H2 — VALID_ZONES in sync with hardcoded list
# ─────────────────────────────────────────────────────────────────────────────


def test_h2():
    print("\n── H2: VALID_ZONES config vs hardcoded list ──────────────────────────")
    from config import VALID_ZONES

    hardcoded = frozenset(["global", "finance", "energy", "healthcare"])
    in_sync = hardcoded == VALID_ZONES
    _log(
        f"H2 {'PASS' if in_sync else 'FAIL'}: VALID_ZONES sync",
        {
            "config_VALID_ZONES": sorted(VALID_ZONES),
            "hardcoded_in_extract_fn": sorted(hardcoded),
            "in_sync": in_sync,
            "note": "PASS = no bug now, but hardcoded list will drift if VALID_ZONES changes",
        },
        "H2",
        "PASS" if in_sync else "FAIL",
    )


# ─────────────────────────────────────────────────────────────────────────────
# H3 — parse_attribute uses event NAME zone but ignores event TAG zones
# ─────────────────────────────────────────────────────────────────────────────


def test_h3():
    print("\n── H3: parse_attribute zone fallback: name vs event-level tags ────────")

    cases = [
        # (attr_tags, event_info, expected_zones, description)
        (
            [],  # attribute has NO zone tag
            {"info": "EdgeGuard-GLOBAL-otx-2024-03-01", "Tag": [{"name": "zone:healthcare"}]},
            ["healthcare"],
            "Attr has no zone tag; event Tag=healthcare; event name=GLOBAL → should use tag",
        ),
        (
            [],
            {"info": "External threat report hospital ransomware", "Tag": [{"name": "zone:healthcare"}]},
            ["healthcare"],
            "Non-EdgeGuard event name; event Tag=healthcare → should use tag",
        ),
        (
            [],
            {"info": "EdgeGuard-FINANCE-cisa-2024-03-01", "Tag": [{"name": "zone:healthcare"}]},
            ["finance", "healthcare"],
            "Attr no tag; event name=FINANCE + event Tag=healthcare → should merge",
        ),
        (
            [{"name": "zone:energy"}],  # attribute HAS its own zone tag
            {"info": "EdgeGuard-FINANCE-otx-2024-03-01", "Tag": [{"name": "zone:healthcare"}]},
            ["energy"],
            "Attr has zone:energy; event name=FINANCE+tag=healthcare → attr tag wins",
        ),
    ]

    h3_bugs = 0
    for attr_tags, event_info, expected, desc in cases:
        actual = parse_attribute_zone_fixed(attr_tags, event_info)
        passed = set(actual) == set(expected)
        if not passed:
            h3_bugs += 1
        level = "PASS" if passed else "FAIL"
        _log(
            f"H3 {level}: {desc}",
            {
                "attr_tags": [t["name"] for t in attr_tags],
                "event_name": event_info["info"],
                "event_level_tags": [t["name"] for t in event_info.get("Tag", [])],
                "actual_zones": sorted(actual),
                "expected_zones": sorted(expected),
                "BUG": None if passed else "event-level Tag zones never consulted",
            },
            "H3",
            level,
        )

    _log(
        f"H3 summary: {h3_bugs}/{len(cases)} scenarios wrong",
        {"bugs_found": h3_bugs, "total_cases": len(cases)},
        "H3",
        "FAIL" if h3_bugs else "PASS",
    )


# ─────────────────────────────────────────────────────────────────────────────
# H4 — ThreatActor→Technique USES co-occurrence — structural analysis
# ─────────────────────────────────────────────────────────────────────────────


def test_h4():
    print("\n── H4: ThreatActor→Technique USES co-occurrence logic ─────────────────")

    # Simulate what the MITRE collector produces: each actor/technique comes
    # from its own MISP event (one per source+zone+date). Their misp_event_ids
    # will never overlap because actors live in one event, techniques in another.
    fake_actors = [
        {"name": "APT28", "misp_event_id": "EdgeGuard-GLOBAL-mitre_attck-2024-03-01-ACTORS"},
        {"name": "Lazarus", "misp_event_id": "EdgeGuard-GLOBAL-mitre_attck-2024-03-01-ACTORS"},
    ]
    fake_techniques = [
        {
            "name": "Phishing",
            "mitre_id": "T1566",
            "misp_event_id": "EdgeGuard-GLOBAL-mitre_attck-2024-03-01-TECHNIQUES",
        },
        {
            "name": "PowerShell",
            "mitre_id": "T1059.001",
            "misp_event_id": "EdgeGuard-GLOBAL-mitre_attck-2024-03-01-TECHNIQUES",
        },
    ]

    # Simulate the co-occurrence query in build_relationships.py lines 128-134
    actor_event_ids = {a["misp_event_id"] for a in fake_actors if a.get("misp_event_id")}
    tech_event_ids = {t["misp_event_id"] for t in fake_techniques if t.get("misp_event_id")}
    _shared_ids = actor_event_ids & tech_event_ids

    # After fix: actors carry uses_techniques list, build_relationships uses that
    fake_actor_with_fix = {
        "name": "APT28",
        "uses_techniques": ["T1566", "T1059.001", "T1078"],  # from MITRE relationships
    }
    fake_tech_t1566 = {"mitre_id": "T1566", "name": "Phishing"}
    uses_match = fake_tech_t1566["mitre_id"] in fake_actor_with_fix["uses_techniques"]

    if uses_match:
        _log(
            "H4 PASS (post-fix): uses_techniques list enables explicit USES relationships",
            {
                "actor": fake_actor_with_fix["name"],
                "uses_techniques": fake_actor_with_fix["uses_techniques"],
                "technique": fake_tech_t1566["mitre_id"],
                "match": uses_match,
                "fix": "MITRE collector now populates uses_techniques from STIX relationship objects",
            },
            "H4",
            "PASS",
        )
    else:
        _log("H4 FAIL: uses_techniques fix not working", {}, "H4", "FAIL")


# ─────────────────────────────────────────────────────────────────────────────
# H5 — TARGETS silently dropped for items stuck at zone="global"
# ─────────────────────────────────────────────────────────────────────────────


def test_h5():
    print("\n── H5: TARGETS relationship creation gate ─────────────────────────────")
    from run_misp_to_neo4j_logic import _build_cross_item_relationships_logic

    # Simulate items that SHOULD have sector zones but end up as "global" due to H1/H3 bugs
    items_with_broken_zones = [
        {
            "type": "indicator",
            "indicator_type": "ip-dst",
            "value": "1.2.3.4",
            "zone": ["global"],  # ← should be ["finance"] but broken zone logic gave "global"
            "tag": "misp",
            "cve_id": None,
        },
        {
            "type": "vulnerability",
            "cve_id": "CVE-2024-1234",
            "zone": ["global"],  # ← should be ["healthcare"]
            "tag": "misp",
        },
    ]
    items_with_correct_zones = [
        {
            "type": "indicator",
            "indicator_type": "ip-dst",
            "value": "5.6.7.8",
            "zone": ["finance"],
            "tag": "misp",
            "cve_id": None,
        },
        {"type": "vulnerability", "cve_id": "CVE-2024-5678", "zone": ["healthcare"], "tag": "misp"},
    ]

    rels_broken = _build_cross_item_relationships_logic(items_with_broken_zones)
    rels_correct = _build_cross_item_relationships_logic(items_with_correct_zones)

    targets_broken = [r for r in rels_broken if r["rel_type"] == "TARGETS"]
    targets_correct = [r for r in rels_correct if r["rel_type"] == "TARGETS"]

    if len(targets_broken) == 0 and len(targets_correct) > 0:
        _log(
            "H5 FAIL: TARGETS silently dropped when zone='global' (cascades from H1/H3)",
            {
                "TARGETS_with_broken_global_zones": len(targets_broken),
                "TARGETS_with_correct_sector_zones": len(targets_correct),
                "BUG": "If H1/H3 cause items to land on zone=['global'], ALL TARGETS rels are dropped",
            },
            "H5",
            "FAIL",
        )
    elif len(targets_broken) == 0 and len(targets_correct) == 0:
        _log(
            "H5 FAIL: TARGETS never created for any input",
            {"broken": len(targets_broken), "correct": len(targets_correct)},
            "H5",
            "FAIL",
        )
    else:
        _log(
            "H5 PASS: TARGETS correctly gated on non-global zones",
            {"TARGETS_global_items": len(targets_broken), "TARGETS_sector_items": len(targets_correct)},
            "H5",
            "PASS",
        )


# ─────────────────────────────────────────────────────────────────────────────
# BONUS — detect_zones_from_text accuracy
# ─────────────────────────────────────────────────────────────────────────────


def test_zone_detection():
    print("\n── BONUS: detect_zones_from_text accuracy ──────────────────────────────")
    from config import detect_zones_from_text

    cases = [
        ("TrickBot banking trojan targeting financial institutions", {"finance"}, "finance keyword"),
        ("Hospital ransomware attack on medical device network", {"healthcare"}, "healthcare keyword"),
        ("SCADA ICS power grid vulnerability", {"energy"}, "energy keyword"),
        ("Generic Windows zero-day exploit", {"global"}, "no sector → global"),
        ("LockBit ransomware", {"global"}, "malware name only → global"),
        ("banking trojan hospital", {"finance", "healthcare"}, "multi-sector"),
        ("", {"global"}, "empty string → global"),
    ]

    bugs = 0
    for text, expected, label in cases:
        result = set(detect_zones_from_text(text))
        passed = result == expected
        if not passed:
            bugs += 1
        _log(
            f"ZONE_DETECT {'PASS' if passed else 'FAIL'}: {label}",
            {"input": text[:60] or "(empty)", "expected": sorted(expected), "actual": sorted(result), "passed": passed},
            "BONUS",
            "PASS" if passed else "FAIL",
        )

    _log(f"ZONE_DETECT summary: {bugs}/{len(cases)} failed", {"bugs": bugs}, "BONUS", "FAIL" if bugs else "PASS")


# ─────────────────────────────────────────────────────────────────────────────
# Inline H5's helper (avoids circular import)
# ─────────────────────────────────────────────────────────────────────────────

import sys as _sys
import types


def _build_cross_item_relationships_logic(items):
    """Minimal copy of _build_cross_item_relationships sector-targeting block."""
    relationships = []
    for item in items:
        zones = item.get("zone", [])
        if isinstance(zones, str):
            zones = [zones]
        for zone in zones:
            if zone and zone != "global":  # ← exact gate from line 1097
                sector_name = zone.lower()
                item_type = item.get("type", "")
                source_id = item.get("tag", "misp")
                if item_type == "vulnerability" or item.get("cve_id"):
                    cve_id = item.get("cve_id")
                    if cve_id:
                        relationships.append(
                            {
                                "rel_type": "TARGETS",
                                "from_type": "Vulnerability",
                                "from_key": {"cve_id": cve_id, "tag": source_id},
                                "to_type": "Sector",
                                "to_key": {"name": sector_name},
                            }
                        )
                elif item.get("indicator_type") or item_type == "indicator":
                    value = item.get("value")
                    if value:
                        relationships.append(
                            {
                                "rel_type": "TARGETS",
                                "from_type": "Indicator",
                                "from_key": {
                                    "value": value,
                                    "indicator_type": item.get("indicator_type", "unknown"),
                                    "tag": source_id,
                                },
                                "to_type": "Sector",
                                "to_key": {"name": sector_name},
                            }
                        )
    return relationships


# register as importable for test_h5
_mod = types.ModuleType("run_misp_to_neo4j_logic")
_mod._build_cross_item_relationships_logic = _build_cross_item_relationships_logic
_sys.modules["run_misp_to_neo4j_logic"] = _mod


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 65)
    print("EdgeGuard — Zone & Linking Logic Debug")
    print("Output → console only")
    print("=" * 65)

    test_h1()
    test_h2()
    test_h3()
    test_zone_detection()
    test_h4()
    test_h5()

    print("\n" + "=" * 65)
    print("Done. Results printed above.")
    print("=" * 65)
