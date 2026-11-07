"""Report records, schema ``edgeguard.report.v1`` (``src/report_records.py``, 2026-11-07).

One MISP Event Report per OTX pulse and per CISA ICS advisory. The record holds the source's own facts, normalised
(types, caps, sorted lists, unstorable characters removed) and digested; the Event Report content is the
description in a fence longer than any backtick run it holds, then a sentinel line and exactly one fenced JSON
block (the meta block with a self-digest) to the end. The report uuid is the graph node's uuid.

Fixtures: the OTX pulse read by id on 2026-11-02 (``tests/fixtures/otx_pulse_by_id_2026_11_02.json``) and the key
lists of both OTX answers recorded on 2026-11-07 (``otx_pulse_keys_2026_11_07.json``); the CISA ICS facts are
those of the CSAF advisory ICSA-26-281-01 as ``tests/test_cisa_ics_collector.py`` (``SAMPLE_ADVISORY``, its shape
verified against cisagov/CSAF) holds them, with remediations in the CSAF 2.0 shape (``category``, ``details``).
"""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import report_records as rr  # noqa: E402
from node_identity import compute_node_uuid  # noqa: E402

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_BY_ID = json.loads((_FIXTURES / "otx_pulse_by_id_2026_11_02.json").read_text(encoding="utf-8"))["by_id"]["pulse"]
_KEYS = json.loads((_FIXTURES / "otx_pulse_keys_2026_11_07.json").read_text(encoding="utf-8"))
# The writer's MISP type of each OTX indicator type of the pulse (``MISPWriter.TYPE_MAPPING``: cve -> vulnerability,
# md5 -> md5).
_MISP_TYPE = {"CVE": "vulnerability", "FileHash-MD5": "md5"}
EMOJI = "\U0001f600"


def _pairs(pulse):
    return [(_MISP_TYPE[i["type"]], i["indicator"]) for i in pulse["indicators"]]


def _otx_record(pulse=None, **kw):
    pulse = pulse or _BY_ID
    return rr.otx_pulse_record(pulse, _pairs(pulse), **kw)


def _window_copy(by_id):
    """The pulse as ``/api/v1/pulses/subscribed`` answers it, made from the answer by id with the recorded key
    lists: the keys only the answer by id has are dropped, the TLP is under ``tlp``, ``extract_source`` and
    ``more_indicators`` are added; list orders differ, as nothing in either answer fixes them."""
    window = {k: copy.deepcopy(v) for k, v in by_id.items() if k in _KEYS["subscribed_keys"]}
    window["tlp"] = by_id["TLP"]
    window["extract_source"] = []
    window["more_indicators"] = False
    for key in ("tags", "attack_ids", "references", "indicators"):
        window[key] = list(reversed(window[key]))
    assert set(window) == set(_KEYS["subscribed_keys"])
    return window


ICS_FIELDS = {
    "record_id": "ICSA-26-281-01",
    "url": "https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-01",
    "title": "Red Lion Controls N-Tron 700 Series",
    "description": "Successful exploitation ...",
    "published": "2026-10-08T06:00:00.000000Z",
    "last_modified": "2026-10-09T06:00:00.000000Z",
    "revision": "2",
    "tlp": "WHITE",
    "kind": "ICSA",
    "csaf_url": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-281-01.json",
    "vendors": ["Red Lion Controls"],
    "products": ["Red Lion Controls 700 Series"],
    "deployment_sectors": [
        "Commercial Facilities",
        "Communications",
        "Critical Manufacturing",
        "Energy",
        "Information Technology",
    ],
    "deployment_countries": ["Worldwide"],
    "cve_ids": ["CVE-2026-32645", "cve-2026-39460"],
    "revision_count": 2,
    "vulnerabilities": [
        {
            "cve_id": "cve-2026-39460",
            "summary": "Plaintext passwords.",
            "remediations": [{"category": "no_fix_planned", "details": "Red Lion Controls does not plan a fix."}],
            "affected_products": ["Red Lion Controls 700 Series: <=Firmware_3.11.0"],
        },
        {
            "cve_id": "CVE-2026-32645",
            "summary": "Default factory credentials persist.",
            "remediations": [
                {"category": "vendor_fix", "details": "Update to firmware 3.12.0 or later."},
                {"category": "mitigation", "details": "Change the default credentials."},
            ],
            "affected_products": ["Red Lion Controls 700 Series: <=Firmware_3.11.0"],
        },
    ],
}


def _ics_record(**changes):
    return rr.build_record(rr.SOURCE_CISA_ICS, {**ICS_FIELDS, **changes})


# --------------------------------------------------------------------------- #
# Schema and normalisation
# --------------------------------------------------------------------------- #


class TestOtxRecord:
    def test_the_pulse_read_by_id_gives_its_source_facts_and_nothing_derived(self):
        record = _otx_record(indicator_count=15)
        assert record["schema"] == "edgeguard.report.v1" and record["source"] == "alienvault_otx"
        assert record["record_ref"] == "alienvault_otx:6abf0b86fb14812f2dc84fb2"
        assert record["url"] == "https://otx.alienvault.com/pulse/6abf0b86fb14812f2dc84fb2"
        assert record["title"] == "PSIRT" and record["description"] == _BY_ID["description"]
        assert record["published"] == "2026-10-02T01:40:22.647000+00:00"  # OTX writes UTC without a zone
        assert record["last_modified"] == "2026-11-01T01:03:15.864000+00:00"
        assert (record["revision"], record["tlp"], record["author"]) == (2, "white", "AlienVault")
        assert record["tags"] == sorted(_BY_ID["tags"]) and record["attack_ids"] == sorted(_BY_ID["attack_ids"])
        assert record["cve_ids"] == ["CVE-2026-104286"]
        assert record["indicators"][0] == ["md5", "49a7156a7d043cc8f9f680579db22f86"]
        assert ["vulnerability", "CVE-2026-104286"] in record["indicators"]
        # the recording kept 6 of the pulse's 15 indicators; the count is the pulse's total
        assert len(record["indicators"]) == 6 and record["indicator_count"] == 15
        assert set(record) == {"schema", "source", "record_ref", "digest", *rr.record_fields("alienvault_otx")}
        for derived in ("zone", "stated_zones", "inferred_zones", "actor_names", "targeted_country_codes"):
            assert derived not in record

    def test_the_count_is_at_least_the_distinct_pairs_given(self):
        assert _otx_record()["indicator_count"] == 6

    def test_the_indicator_list_is_capped_in_type_value_order_and_the_count_stays_exact(self, monkeypatch):
        pairs = [("ip-dst", f"198.51.100.{i % 250}.{i}") for i in range(2500)] + [("domain", "z.example")]
        record = rr.otx_pulse_record(_BY_ID, pairs)
        assert len(record["indicators"]) == 2000 and record["indicator_count"] == 2501
        assert record["indicators"] == sorted(record["indicators"])
        assert record["indicators"][0] == ["domain", "z.example"]  # (type, value) order, not the order given
        monkeypatch.setenv("EDGEGUARD_REPORT_MAX_INDICATORS", "10")
        assert len(rr.otx_pulse_record(_BY_ID, pairs)["indicators"]) == 10
        monkeypatch.setenv("EDGEGUARD_REPORT_MAX_INDICATORS", "999999")
        assert len(rr.otx_pulse_record(_BY_ID, pairs)["indicators"]) == 2501  # clamped to the hard bound 20,000

    def test_a_missing_id_or_an_unknown_field_is_refused(self):
        with pytest.raises(ValueError, match="without a record id"):
            rr.build_record("alienvault_otx", {"title": "x"})
        with pytest.raises(ValueError, match="unknown record fields"):
            rr.build_record("alienvault_otx", {"record_id": "a", "zone": ["energy"]})
        with pytest.raises(ValueError, match="no report records"):
            rr.build_record("nvd", {"record_id": "a"})


class TestIcsRecord:
    def test_the_advisory_facts_are_normalised(self):
        record = _ics_record()
        assert record["record_ref"] == "cisa_ics:ICSA-26-281-01"
        assert (record["tlp"], record["revision"], record["revision_count"]) == ("white", 2, 2)
        assert record["cve_ids"] == ["CVE-2026-32645", "CVE-2026-39460"]
        assert [v["cve_id"] for v in record["vulnerabilities"]] == ["CVE-2026-32645", "CVE-2026-39460"]
        first = record["vulnerabilities"][0]
        assert [r["category"] for r in first["remediations"]] == ["mitigation", "vendor_fix"]
        assert record["deployment_sectors"][3] == "Energy" and record["vendor_headquarters"] is None
        assert record["published"] == "2026-10-08T06:00:00+00:00"

    def test_a_vulnerability_entry_with_another_key_is_refused(self):
        with pytest.raises(ValueError, match="vulnerability entry"):
            _ics_record(vulnerabilities=[{"cve_id": "CVE-2026-32645", "zone": "energy"}])


class TestUnstorableCharacters:
    def test_characters_outside_the_bmp_are_removed_and_a_value_needing_them_is_left_out(self):
        pulse = {**_BY_ID, "name": f"Campaign {EMOJI} energy", "description": f"Text {EMOJI}\r\nline two"}
        pulse["tags"] = [f"tag{EMOJI}", "plain"]
        pairs = [("url", f"https://x.example/{EMOJI}"), ("domain", "ok.example")]
        record = rr.otx_pulse_record(pulse, pairs)
        assert record["title"] == "Campaign energy"
        assert record["description"] == "Text \nline two"
        assert record["tags"] == ["plain", "tag"]
        assert record["indicators"] == [["domain", "ok.example"]]  # the writer never stores a 4-byte value
        assert record["indicator_count"] == 1
        content = rr.render_content(record)
        assert all(ord(ch) <= 0xFFFF for ch in content)
        assert rr.record_from_content(content) == record

    def test_the_report_name_is_cut_at_a_word_end_within_255_characters(self):
        title = ("word " * 80).strip() + f" {EMOJI}"
        record = rr.otx_pulse_record({**_BY_ID, "name": title}, [])
        name = rr.report_name(record)
        assert len(name) <= 255 and name.endswith("word") and not name.endswith(" ")
        assert record["title"] == ("word " * 80).strip()  # the full title stays in the block
        assert rr.report_name({**record, "title": None}) == record["record_ref"]


# --------------------------------------------------------------------------- #
# Digest
# --------------------------------------------------------------------------- #


class TestDigest:
    def test_the_window_copy_and_the_copy_by_id_of_one_pulse_give_one_record(self):
        window = _window_copy(_BY_ID)
        assert "TLP" not in window and window["tlp"] == "white" and "author" not in window
        by_id_record = _otx_record(_BY_ID)
        window_record = _otx_record(window)
        assert window_record == by_id_record
        assert window_record["digest"] == by_id_record["digest"]

    def test_the_same_facts_in_another_order_give_the_same_digest(self):
        fields = {**ICS_FIELDS}
        reordered = {
            **{k: list(reversed(v)) if isinstance(v, list) else v for k, v in fields.items()},
            "cve_ids": ["CVE-2026-39460", "cve-2026-32645"],
        }
        assert rr.build_record("cisa_ics", reordered)["digest"] == _ics_record()["digest"]

    def test_a_changed_fact_changes_the_digest_and_derived_values_cannot_enter(self):
        base = _otx_record()
        assert _otx_record({**_BY_ID, "revision": 3})["digest"] != base["digest"]
        assert _otx_record({**_BY_ID, "description": _BY_ID["description"] + " More."})["digest"] != base["digest"]
        assert rr.compute_digest(base) == base["digest"]
        # the digest covers source facts only: not the schema name, not itself
        assert rr.compute_digest({**base, "schema": "other", "digest": "x"}) == base["digest"]

    def test_a_cap_applied_to_both_copies_keeps_the_digest(self, monkeypatch):
        pairs = [("ip-dst", f"203.0.113.{i}") for i in range(250)]
        monkeypatch.setenv("EDGEGUARD_REPORT_MAX_INDICATORS", "100")
        one = rr.otx_pulse_record(_BY_ID, pairs)
        two = rr.otx_pulse_record(_window_copy(_BY_ID), list(reversed(pairs)))
        assert one["digest"] == two["digest"] and one["indicators"] == two["indicators"]


# --------------------------------------------------------------------------- #
# Content: render and parse
# --------------------------------------------------------------------------- #


class TestContent:
    @pytest.mark.parametrize("make", [lambda: _otx_record(indicator_count=15), _ics_record], ids=["otx", "ics"])
    def test_round_trip(self, make):
        record = make()
        content = rr.render_content(record)
        description, meta = rr.parse_content(content)
        assert description == record["description"]
        assert meta["digest"] == record["digest"] and meta["schema"] == rr.SCHEMA
        assert rr.record_from_content(content) == record
        assert content.endswith("\n```\n") and content.count(rr.SENTINEL) == 1
        lines = content.split("\n")
        assert lines[0] == "```" and lines[lines.index(rr.SENTINEL) + 1] == "```json"
        assert rr.digest_matches(description, meta)

    def test_the_description_fence_is_longer_than_any_backtick_run_in_it(self):
        record = _otx_record({**_BY_ID, "description": "run ``````` of seven"})
        content = rr.render_content(record)
        assert content.startswith("````````\n")
        assert rr.record_from_content(content) == record

    def test_a_sentinel_and_a_fenced_block_inside_the_description_do_not_spoof_the_record(self):
        fake = rr.meta_block(_ics_record())  # a valid block of another record
        spoof = f"Real text.\n\n## EdgeGuard record\n\n{rr.SENTINEL}\n```json\n{json.dumps(fake, sort_keys=True)}\n```"
        record = _otx_record({**_BY_ID, "description": spoof})
        content = rr.render_content(record)
        assert content.count(rr.SENTINEL) == 2
        description, meta = rr.parse_content(content)
        assert description == spoof
        assert meta["record_ref"] == record["record_ref"] and meta["source"] == "alienvault_otx"
        assert rr.record_from_content(content) == record

    def test_text_misp_prepends_before_the_description_is_ignored(self):
        record = _otx_record()
        content = "# AI summary\n\n```\nsummary\n```\n\n" + rr.render_content(record)
        assert rr.record_from_content(content) == record

    @pytest.mark.parametrize(
        "change",
        [
            lambda c: c + "trailing text\n",
            lambda c: c + "```json\n{}\n```\n",
            lambda c: c.replace('"revision": 2', '"revision": 3'),  # self-digest no longer matches
            lambda c: c.replace(rr.SENTINEL, "<!-- edgeguard:report-meta v2 -->"),
            lambda c: c.replace("## EdgeGuard record", "## Record"),
            lambda c: c[: c.rindex("\n```")],  # the block's closing fence cut off
            lambda c: c.replace("```\n\n## EdgeGuard", "````\n\n## EdgeGuard"),  # fences do not pair
        ],
        ids=["trailing", "second-block", "tampered", "sentinel-v2", "heading", "truncated", "fence"],
    )
    def test_content_that_is_not_one_record_block_to_the_end_is_refused(self, change):
        content = rr.render_content(_otx_record())
        assert rr.parse_content(content) is not None
        assert rr.parse_content(change(content)) is None

    @pytest.mark.parametrize(
        "edit",
        [
            lambda m: m.update(tags=list(reversed(m["tags"]))),  # not in normal form (unsorted)
            lambda m: m.update(revision="2"),  # wrong type
            lambda m: m.update(zone=["energy"]),  # a derived field
            lambda m: m.pop("adversary"),  # a missing field
            lambda m: m.update(indicator_count=1),  # fewer than listed
            lambda m: m.update(digest="not-a-digest"),
        ],
        ids=["unsorted", "type", "extra", "missing", "count", "digest"],
    )
    def test_a_block_with_a_valid_self_digest_but_out_of_normal_form_is_refused(self, edit):
        record = _otx_record()
        meta = {k: v for k, v in rr.meta_block(record).items() if k != "self_digest"}
        edit(meta)
        meta["self_digest"] = rr._sha256(rr._canonical_json(meta))
        content = rr.render_content(record)
        start = content.index(f"{rr.SENTINEL}\n```json\n") + len(rr.SENTINEL) + 9
        forged = content[:start] + json.dumps(meta, sort_keys=True) + "\n```\n"
        assert rr.parse_content(forged) is None

    def test_a_description_edited_in_misp_still_parses_and_the_digest_tells(self):
        record = _otx_record()
        content = rr.render_content(record).replace("FortiMail versions", "FortiMail releases", 1)
        description, meta = rr.parse_content(content)
        assert "FortiMail releases" in description and not rr.digest_matches(description, meta)

    def test_render_takes_only_a_built_record(self):
        with pytest.raises(ValueError):
            rr.render_content({"source": "alienvault_otx", "description": "x"})


# --------------------------------------------------------------------------- #
# MISP-side values
# --------------------------------------------------------------------------- #


class TestUuidAndMispValues:
    def test_the_uuid_is_pinned_and_equals_the_node_and_stix_uuid(self):
        from stix_exporter import _deterministic_id

        otx = rr.report_uuid("alienvault_otx:6abf0b86fb14812f2dc84fb2", "ThreatReport")
        ics = rr.report_uuid("cisa_ics:ICSA-26-281-01", "VulnerabilityAdvisory")
        assert otx == "41646198-5449-5283-bf27-6f3813e5f708"
        assert ics == "17ff328c-07c3-5786-9cac-e09357433faa"
        assert otx == compute_node_uuid("ThreatReport", {"record_ref": "alienvault_otx:6abf0b86fb14812f2dc84fb2"})
        assert _deterministic_id("report", "cisa_ics:ICSA-26-281-01") == f"report--{ics}"
        assert rr.record_uuid(_otx_record()) == otx and otx == otx.lower()
        with pytest.raises(ValueError):
            rr.report_uuid("alienvault_otx:x", "Indicator")

    @pytest.mark.parametrize(
        "level, gate, distribution",
        [("white", "white", 5), ("clear", "clear", 5), ("green", "green", 5), ("amber", "amber", 0)]
        + [("amber+strict", "amber+strict", 0), ("red", "red", 0), (None, "amber", 0), ("purple", "amber", 0)],
    )
    def test_amber_red_and_an_unknown_tlp_are_restricted(self, level, gate, distribution):
        record = _otx_record({**_BY_ID, "TLP": level})
        assert rr.gating_tlp(record) == gate and rr.report_distribution(record) == distribution
        assert rr.report_tags(record, "source:AlienVault-OTX") == [
            {"name": "EdgeGuard"},
            {"name": "source:AlienVault-OTX"},
            {"name": f"tlp:{gate}"},
        ]

    def test_the_event_pattern_takes_the_sources_day_parts_and_companion_events_only(self):
        pattern = rr.report_event_info_pattern("alienvault_otx")
        for info in ("EdgeGuard-alienvault_otx-2026-11-07", "EdgeGuard-alienvault_otx-2026-11-07-part3"):
            assert pattern.match(info)
        assert pattern.match("EdgeGuard-alienvault_otx-2026-11-07-reports")
        for info in (
            "EdgeGuard-cisa_ics-2026-11-07",
            "EdgeGuard-alienvault_otx-2026-11-07-x",
            "livecheck-eventreports-20261107T174641Z",
            "EdgeGuard-alienvault_otx-2026-11-07-reports-part2",
        ):
            assert not pattern.match(info), info
