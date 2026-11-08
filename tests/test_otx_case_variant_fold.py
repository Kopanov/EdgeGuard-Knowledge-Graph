"""The OTX same-run fold compares items the way MISP and the graph compare them (2026-11).

In one event MISP does not store an attribute whose type and value match, ignoring case, an attribute
an earlier request already stored; within one request it stores both spellings. The OTX collector keyed
its items case-exactly (``malware:DcRat`` beside ``malware:DCRAT``), so the 730-day baseline of
2026-11-01 pushed later pulses' spellings of a family or an adversary as items of their own, and MISP
dropped 170 of them with the ids of the pulses that named them (164 family and 6 adversary spellings of
the 174 attributes it did not store). The graph already folds those names (``node_identity``): only the
pulse provenance was lost. The collector now keys a malware family or adversary by its graph key
(``name_key``, whitespace runs as one space), an indicator value of a type MISP changes in case on save
(hashes, domains, IP and e-mail addresses, CVE ids) lower-cased, and a URL with its scheme and host
lower-cased (``node_identity.fold_url_scheme_and_host``); a variant folds into the first item, which keeps
the first pulse's spelling and gains the later pulses' ids, techniques, stated zones and TLP.

Fixture: ``tests/fixtures/otx_case_variants_2026_11_01.json``, real pulses of that run rebuilt from the
attributes MISP stored in the OTX event (its ``description`` says how).
"""

from __future__ import annotations

import copy
import json
import sys
import unicodedata
from pathlib import Path
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_indicator_cve_report_links import _attributes, _collect  # noqa: E402  (the collector -> writer chain)

from collectors import otx_collector as oc  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402

FIXTURE = json.loads((TESTS / "fixtures" / "otx_case_variants_2026_11_01.json").read_text(encoding="utf-8"))
EVENT = {"id": "55", "info": "EdgeGuard-alienvault_otx-2026-11-01", "date": "2026-11-01", "Tag": []}


def _pulses(*groups, tlp: str = "white"):
    """The fixture pulses with the fields the collector reads and the fixture cannot give (no dates, no
    ATT&CK ids, no industries; TLP ``tlp``)."""
    out = []
    for pulse in (p for group in groups for p in group):
        p = copy.deepcopy(pulse)
        p.setdefault("tlp", tlp)
        p.setdefault("attack_ids", [])
        p.setdefault("industries", [])
        p.setdefault("cve_references", [])
        out.append(p)
    return out


def _of(items, kind, name_lower):
    return [i for i in items if i.get("type") == kind and str(i.get("name")).lower() == name_lower]


def _urls(items):
    return [i["value"] for i in items if i.get("indicator_type") == "url"]


# --------------------------------------------------------------------------- the item key


class TestItemKey:
    @pytest.mark.parametrize(
        "first, later",
        [
            ("DcRat", "DCRAT"),
            ("DcRat", "dcrat"),
            ("Hydraq", "HydraQ"),
            ("Atomic macOS Stealer", "Atomic macOS stealer"),
            ("Atomic macOS Stealer", " Atomic  macOS\tStealer "),
        ],
    )
    def test_malware_spellings_share_a_key(self, first, later):
        assert oc._pulse_item_key({"type": "malware", "name": first}) == oc._pulse_item_key(
            {"type": "malware", "name": later}
        )

    @pytest.mark.parametrize("first, later", [("qilin", "Qilin"), ("Mustang Panda", "MUSTANG PANDA"), ("CL0P", "Cl0p")])
    def test_adversary_spellings_share_a_key(self, first, later):
        assert oc._pulse_item_key({"type": "actor", "name": first}) == oc._pulse_item_key(
            {"type": "actor", "name": later}
        )

    def test_a_family_and_an_adversary_of_one_name_stay_two_items(self):
        assert oc._pulse_item_key({"type": "malware", "name": "Qilin"}) != oc._pulse_item_key(
            {"type": "actor", "name": "qilin"}
        )

    def test_names_that_differ_in_letters_stay_apart(self):
        assert oc._pulse_item_key({"type": "malware", "name": "Hydraq"}) != oc._pulse_item_key(
            {"type": "malware", "name": "HidraQ"}
        )

    @pytest.mark.parametrize(
        "indicator_type, first, later",
        [
            # a real SHA-256 of pulse 6a5dec09c0c4b7d2a00d7b2c and its upper-case form
            (
                "hash",
                "09bedbf7a41e0f8dabe4f41d331db58373ce15b2e9204540873a1884f38bdde1",
                "09BEDBF7A41E0F8DABE4F41D331DB58373CE15B2E9204540873A1884F38BDDE1",
            ),
            ("domain", "gatuso.duckdns.org", "Gatuso.DuckDNS.org"),
            ("ipv4", "146.19.125.36", " 146.19.125.36 "),
            ("ipv6", "2001:db8::7", "2001:DB8::7"),
            ("email", "admin@example.org", "Admin@Example.org"),
            ("cve", "CVE-2026-48710", "cve-2026-48710"),
            ("url", "http://setseta.com/set.exe", "http://Setseta.com/set.exe"),
            ("url", "http://setseta.com/set.exe", "HTTP://SETSETA.COM/set.exe"),
        ],
    )
    def test_values_misp_holds_as_one_share_a_key(self, indicator_type, first, later):
        assert oc._pulse_item_key({"indicator_type": indicator_type, "value": first}) == oc._pulse_item_key(
            {"indicator_type": indicator_type, "value": later}
        )

    @pytest.mark.parametrize(
        "indicator_type, composed",
        [
            ("domain", "café-update.example"),
            ("url", "http://update.example/Café.exe"),
            ("url", "http://café-update.example/Install.exe"),
            ("unknown", "Global\\CaféMutex"),
        ],
    )
    def test_values_that_differ_only_in_unicode_composition_share_a_key(self, indicator_type, composed):
        """The graph keys a value NFC-normalised (``canonicalize_merge_key``), so the same-run key does too:
        'é' written as U+00E9 and as 'e' + U+0301 is one value, whatever the type's case rule."""
        decomposed = unicodedata.normalize("NFD", composed)
        assert decomposed != composed and "é" in decomposed
        assert oc._pulse_item_key({"indicator_type": indicator_type, "value": composed}) == oc._pulse_item_key(
            {"indicator_type": indicator_type, "value": decomposed}
        )

    @pytest.mark.parametrize(
        "indicator_type, first, later",
        [
            ("url", "http://twizt.net/Installed", "http://twizt.net/installed"),
            (
                "url",
                "http://31.41.244.11/files/5094364719/WClchuE.ps1",
                "http://31.41.244.11/files/5094364719/wclchue.ps1",
            ),
            ("url", "https://bashupload.com/uCiPm/SENT_Kill.zip", "https://bashupload.com/ucipm/sent_kill[.]zip"),
            ("unknown", "Global\\MutexName", "global\\mutexname"),
        ],
    )
    def test_values_that_differ_otherwise_stay_apart(self, indicator_type, first, later):
        assert oc._pulse_item_key({"indicator_type": indicator_type, "value": first}) != oc._pulse_item_key(
            {"indicator_type": indicator_type, "value": later}
        )

    @pytest.mark.parametrize(
        "item, key",
        [
            ({"indicator_type": "ipv4", "value": None}, "ipv4:None"),
            ({"indicator_type": "hash", "value": 7}, "hash:7"),
            ({"type": "malware", "name": None}, "malware:None"),
            ({"type": "actor", "name": 3}, "actor:3"),
        ],
    )
    def test_a_value_or_name_that_is_not_a_string_keeps_its_old_key(self, item, key):
        assert oc._pulse_item_key(item) == key

    def test_a_cve_reference_keeps_its_key(self):
        assert oc._pulse_item_key({"type": "vulnerability", "cve_id": "CVE-2026-48710"}) == "cve:CVE-2026-48710"

    @pytest.mark.parametrize("value", ["CVE-2026-48710", "cve-2026-48710", " CVE-2026-48710 "])
    def test_a_cve_indicator_shares_the_key_of_a_cve_reference(self, value):
        """MISP stores CVE ids upper-cased: an OTX CVE indicator and a pulse's CVE reference of the same id are
        one item (they shared ``cve:CVE-...`` before the case rule; a lower-cased indicator key split them)."""
        reference = oc._pulse_item_key({"type": "vulnerability", "cve_id": "CVE-2026-48710"})
        assert oc._pulse_item_key({"indicator_type": "cve", "value": value}) == reference == "cve:CVE-2026-48710"
        assert oc._pulse_item_key({"type": "vulnerability", "cve_id": value.upper()}) == reference


# --------------------------------------------------------------------------- the run's items


class TestRealPulses:
    def test_family_spellings_of_five_pulses_fold_into_the_first_pulse_s_item(self):
        pulses = _pulses(FIXTURE["dcrat_pulses"])
        items = _collect(*pulses)
        dcrat = _of(items, "malware", "dcrat")
        assert len(dcrat) == 1, [i["name"] for i in dcrat]
        assert dcrat[0]["name"] == FIXTURE["dcrat_stored"] == "DcRat", "the first pulse's spelling"
        assert dcrat[0]["pulse_id"] == pulses[0]["id"]
        assert dcrat[0]["report_ids"] == [p["id"] for p in pulses[1:]], "every later pulse that named it"

    def test_adversary_spellings_fold_into_the_first_pulse_s_item(self):
        pulses = _pulses(FIXTURE["qilin_pulses"])
        items = _collect(*pulses)
        actors = _of(items, "actor", "qilin")
        assert [(a["name"], a["pulse_id"], a.get("report_ids")) for a in actors] == [
            (FIXTURE["qilin_stored_actor"], pulses[0]["id"], [pulses[1]["id"]])
        ]
        assert len(_of(items, "malware", "qilin")) == 1, "the family of the same name stays a malware item"

    def test_two_spellings_one_pulse_lists_become_one_item(self):
        pulse = _pulses([FIXTURE["aurora_pulse"]])[0]
        assert {"Hydraq", "HydraQ"} <= set(pulse["malware_families"])
        items = _collect(pulse)
        assert [i["name"] for i in _of(items, "malware", "hydraq")] == ["Hydraq"]
        assert [i["name"] for i in _of(items, "malware", "hidraq")] == ["HidraQ"], "another spelling, another item"
        assert "report_ids" not in _of(items, "malware", "hydraq")[0], "the same pulse adds no report id"

    def test_url_spellings_fold_by_scheme_and_host_only(self):
        pulses = _pulses(FIXTURE["url_pulses"])
        listed = [ind["indicator"] for p in pulses for ind in p["indicators"]]
        urls = _urls(_collect(*pulses))
        # (spelling the pulse listed later, spelling it listed first): the pulse listed both
        host_variants = {
            "http://Icherryls.com/exec.exe": "http://icherryls.com/exec.exe",
            "http://Inewsmvo.com/set.exe": "http://inewsmvo.com/set.exe",
            "http://Setseta.com/set.exe": "http://setseta.com/set.exe",
            "http://D3f4.com.hk/OfJ3qDlVoGBRGjYK/conf.php": "http://d3f4.com.hk/OfJ3qDlVoGBRGjYK/conf.php",
            "http://K0j8h7f6d5s4.com/set.exe": "http://k0j8h7f6d5s4.com/set.exe",
        }
        for later, first in host_variants.items():
            assert listed.index(first) < listed.index(later)
            assert first in urls and later not in urls, "the later spelling folds into the first"
        assert len(urls) == len(listed) - len(host_variants)
        for kept in (
            "http://Kaiwachis.ug/NShnObEA4XwtlDCC/gate.php",  # host and path differ: the path keeps them apart
            "http://kaiwachis.ug/nshnobea4xwtldcc/gate.php",
            "http://31.41.244.11/files/5094364719/WClchuE.ps1",
            "http://31.41.244.11/files/5094364719/wclchue.ps1",
            "http://twizt.net/Installed",
            "http://twizt.net/installed",
        ):
            assert kept in urls

    def test_a_defanged_value_is_refanged_before_the_fold(self):
        """2026-11-08: a defanged value is refanged as MISP refangs it on save, then keyed
        (``_pulse_indicator_value``). The pulse's own spelling (``SENT_Kill[.]zip``, read from OTX on 2026-11-08,
        ``tests/fixtures/otx_pulse_values_and_lists_2026_11_08.json``) folds into the stored twin listed before it.
        This fixture's lower-cased spelling (the confirmation key of the 2026-11-01 run) differs from the twin in
        the case of its path, so it stays an item of its own, refanged."""
        real = json.loads((TESTS / "fixtures" / "otx_pulse_values_and_lists_2026_11_08.json").read_text("utf-8"))
        as_listed = real["pulses"][FIXTURE["defanged_url_pulse"]]["pulse"]["indicators"][6]["indicator"]
        assert as_listed == "https://bashupload.com/uCiPm/SENT_Kill[.]zip"
        pulse = {
            "id": FIXTURE["defanged_url_pulse"],
            "name": "BlackBasta ransomware",
            "malware_families": [],
            "adversary": "",
            "indicators": [
                {"type": "URL", "indicator": FIXTURE["defanged_url_twin"]},
                {"type": "URL", "indicator": as_listed},
                {"type": "URL", "indicator": FIXTURE["defanged_url"]},
            ],
        }
        assert _urls(_collect(*_pulses([pulse]))) == [
            FIXTURE["defanged_url_twin"],
            "https://bashupload.com/ucipm/sent_kill.zip",
        ]

    def test_a_hash_listed_in_two_cases_is_one_item(self):
        first = _pulses([FIXTURE["dcrat_pulses"][2]])[0]
        sha256 = first["indicators"][0]["indicator"]
        later = {
            "id": "6aa18179c7eb1a5f0426ed7a",
            "name": "a later pulse listing the same file in upper case",
            "malware_families": [],
            "adversary": "",
            "indicators": [{"type": "FileHash-SHA256", "indicator": sha256.upper()}],
        }
        items = _collect(first, *_pulses([later]))
        hashes = [i for i in items if i.get("indicator_type") == "hash" and i["value"].lower() == sha256]
        assert [(h["value"], h["pulse_id"], h.get("report_ids")) for h in hashes] == [
            (sha256, first["id"], ["6aa18179c7eb1a5f0426ed7a"])
        ]

    def test_a_variant_s_techniques_zones_and_tlp_join_the_kept_item(self):
        first, later = _pulses(FIXTURE["dcrat_pulses"][:2])
        later["tlp"] = "amber"
        later["attack_ids"] = [{"id": "T1059.001"}]
        later["industries"] = ["Healthcare"]
        items = _collect(first, later)
        kept = _of(items, "malware", "dcrat")[0]
        assert kept["name"] == "DcRat"
        assert kept["pulse_tlp"] == "amber", "the most restrictive TLP of the pulses"
        assert "T1059.001" in kept["reported_techniques"]
        assert "healthcare" in kept["zone"]
        assert f"healthcare|{later['id']}" in kept["report_stated_zones"]

    def test_the_writer_sends_one_attribute_naming_every_pulse(self):
        pulses = _pulses(FIXTURE["dcrat_pulses"])
        items = _collect(*pulses)
        attrs = [a for a in _attributes(items) if a["type"] == "malware-type" and a["value"].lower() == "dcrat"]
        assert [a["value"] for a in attrs] == ["DcRat"]
        meta = json.loads(attrs[0]["comment"].split("MITRE_USES_TECHNIQUES:", 1)[1].split("\n", 1)[0])
        assert meta["pid"] == pulses[0]["id"] and meta["rids"] == [p["id"] for p in pulses[1:]]

    def test_the_sync_reads_every_pulse_back_from_the_attribute(self):
        from run_misp_to_neo4j import MISPToNeo4jSync

        pulses = _pulses(FIXTURE["dcrat_pulses"])
        attr = next(a for a in _attributes(_collect(*pulses)) if a["type"] == "malware-type" and a["value"] == "DcRat")
        item, _rels = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(attr, EVENT)
        assert item["name"] == "DcRat"
        assert [item["pulse_id"], *item["report_ids"]] == [p["id"] for p in pulses]


# --------------------------------------------------------------------------- the confirmation stays exact


def test_a_family_spelling_pushed_after_its_stored_twin_is_still_reported_unconfirmed():
    """The fold prevents the drop inside one run; across runs MISP still keeps the spelling it stored, and
    the push confirmation keeps naming the attribute it did not store (``[UNCONFIRMED]``)."""
    from collectors import misp_writer as mw

    later = {"type": "malware", "name": "DCRAT", "tag": "alienvault_otx", "pulse_id": "6aa18179c7eb1a5f0426ed7a"}
    pushed = MISPWriter.__new__(MISPWriter).create_malware_attribute(later)
    stored = [{"type": "malware-type", "value": FIXTURE["dcrat_stored"]}]
    assert mw._confirm_pushed_attributes([pushed], stored) == (0, [("malware-type", "DCRAT")])


class TestCveIndicatorAndReference:
    def test_a_later_pulse_s_reference_folds_into_the_earlier_cve_indicator(self):
        """One pulse lists the CVE as an indicator, a later one names it among its CVE references: one item,
        the later pulse in its report ids."""
        first = {
            "id": "6900000000000000000000a1",
            "name": "Exploitation of CVE-2026-48710",
            "malware_families": [],
            "adversary": "",
            "indicators": [{"type": "CVE", "indicator": "CVE-2026-48710"}],
        }
        later = {
            "id": "6900000000000000000000a2",
            "name": "Campaign naming CVE-2026-48710",
            "malware_families": [],
            "adversary": "",
            "indicators": [],
            "cve_references": ["cve-2026-48710"],
        }
        items = _collect(*_pulses([first, later]))
        cves = [
            i
            for i in items
            if i.get("indicator_type") == "cve" or (i.get("type") == "vulnerability" and i.get("cve_id"))
        ]
        assert len(cves) == 1, cves
        assert cves[0]["pulse_id"] == first["id"]
        assert cves[0].get("report_ids") == [later["id"]]
