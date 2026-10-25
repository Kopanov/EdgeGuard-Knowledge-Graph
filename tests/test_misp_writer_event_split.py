"""H2 of docs/flow_audits/06_misp_aggregation.md: MISPWriter continues a source/date event in ``-partN`` (2026-10).

Drives the real ``MISPWriter.push_items`` against ``FakeMisp`` (an in-memory MISP).
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from misp_fakes import FakeMisp, Response  # noqa: E402

from collectors import misp_writer  # noqa: E402
from collectors.misp_writer import MISPWriter, _attribute_report_ids, _event_name, _split_for_parts  # noqa: E402

TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
BASE = f"EdgeGuard-urlhaus-{TODAY}"


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.delenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", raising=False)
    monkeypatch.delenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", raising=False)
    monkeypatch.setattr(misp_writer.time, "sleep", lambda _s: None)
    monkeypatch.setattr(misp_writer, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(misp_writer, "MISP_CROSS_EVENT_DEDUP", False)  # per-event prefetch spans the parts


def existing(n, event_id, offset=0):
    return [
        {
            "id": str(offset + i),
            "uuid": f"u{event_id}-{offset + i}",
            "event_id": event_id,
            "type": "ip-dst",
            "value": f"10.{(offset + i) // 65536}.{((offset + i) // 256) % 256}.{(offset + i) % 256}",
            "timestamp": "1",
            "Tag": [],
        }
        for i in range(n)
    ]


def items(n, offset=0, pulse=None):
    out = []
    for i in range(offset, offset + n):
        item = {
            "indicator_type": "ipv4",
            "value": f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}",
            "tag": "urlhaus",
            "zone": ["global"],
        }
        if pulse:
            item["pulse_id"] = pulse
        out.append(item)
    return out


def push(misp, batch, **kw):
    writer = MISPWriter(url="https://misp.test", api_key="test", verify_ssl=True)
    writer.session = misp
    return writer.push_items(batch, **kw)


def sizes(misp):
    by_name = {}
    for a in misp.attributes:
        by_name.setdefault(misp.events[a["event_id"]], []).append(a)
    return {n: len(v) for n, v in by_name.items()}


class TestSplit:
    def test_audit_regression_19999_plus_500_puts_the_overflow_in_part2(self):
        misp = FakeMisp(existing(19999, "200"), event_info=BASE)
        ok, failed = push(misp, items(500, offset=100000))
        assert (ok, failed) == (500, 0)
        assert sizes(misp) == {BASE: 20000, f"{BASE}-part2": 499}

    def test_a_batch_larger_than_the_cap_spans_several_parts(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "100")
        misp = FakeMisp(existing(30, "200"), event_info=BASE)
        ok, failed = push(misp, items(250, offset=1000))
        assert (ok, failed) == (250, 0)
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100, f"{BASE}-part3": 80}

    def test_parts_are_created_from_scratch_and_carry_the_event_fields(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "10")
        misp = FakeMisp([], event_info=BASE)
        push(misp, items(25))
        bodies = [b["Event"] for p, b in misp.posts if p == "/events"]
        assert [b["info"] for b in bodies] == [BASE, f"{BASE}-part2", f"{BASE}-part3"]
        for b in bodies:
            assert {k: b[k] for k in ("distribution", "threat_level_id", "analysis", "date", "Tag")} == {
                "distribution": 1,
                "threat_level_id": 3,
                "analysis": 0,
                "date": TODAY,
                "Tag": [{"name": "EdgeGuard"}],
            }

    def test_rerun_does_not_re_add_to_part2_what_part1_holds(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "100")
        misp = FakeMisp([], event_info=BASE)
        batch = items(150)
        assert push(misp, batch) == (150, 0)
        before = sizes(misp)
        assert push(misp, batch) == (0, 0)
        assert sizes(misp) == before == {BASE: 100, f"{BASE}-part2": 50}

    def test_rerun_with_one_new_item_goes_to_the_highest_part(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "100")
        misp = FakeMisp([], event_info=BASE)
        push(misp, items(150))
        push(misp, items(151))
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 51}

    def test_cap_zero_is_the_old_behaviour(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "0")
        misp = FakeMisp(existing(50, "200"), event_info=BASE)
        push(misp, items(200, offset=1000))
        assert sizes(misp) == {BASE: 250}
        # no probe for a part either
        assert not [p for p, b in misp.posts if p == "/events/restSearch" and "part" in (b or {}).get("eventinfo", "")]

    def test_invalid_value_falls_back_to_the_default(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "many")
        assert misp_writer._event_split_above() == 20000

    def test_part_is_created_before_any_overflow_is_written_to_it(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "100")
        misp = FakeMisp([], event_info=BASE)
        push(misp, items(150))
        paths = [(p, (b or {}).get("Event", {}).get("info")) for p, b in misp.posts if p != "/events/restSearch"]
        created = paths.index(("/events", f"{BASE}-part2"))
        # part 2 exists before the first attribute is added to any event
        assert all(not p.startswith("/events/") for p, _ in paths[:created])

    def test_failed_part_creation_counts_the_overflow_as_failed(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "100")
        misp = FakeMisp([], event_info=BASE)
        real_post = misp.post

        def post(url, json=None, **kw):
            if url.endswith("/events") and json["Event"]["info"].endswith("-part2"):
                return Response(403, {"errors": "no"})
            return real_post(url, json=json, **kw)

        misp.post = post
        assert push(misp, items(150)) == (100, 50)
        assert sizes(misp) == {BASE: 100}


class TestReportGroupsAreNotSplit:
    def test_report_ids_are_read_from_both_meta_blocks(self):
        def attr(kind, meta):
            return {"type": "ip-dst", "value": "a", "comment": kind + ":" + json.dumps(meta)}

        assert _attribute_report_ids(attr("OTX_META", {"pulse_id": "p1", "report_ids": ["p2"]})) == ["p1", "p2"]
        assert _attribute_report_ids(attr("MITRE_USES_TECHNIQUES", {"pid": "p2", "rids": ["p3"]})) == ["p2", "p3"]
        assert _attribute_report_ids({"comment": 'NVD_META:{"pulse_id": "x"}'}) == []
        assert _attribute_report_ids({"comment": "OTX_META:{broken"}) == []

    def test_group_with_report_ids_over_the_cap_sends_the_requests_of_cap_zero(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "0")
        off = FakeMisp(existing(120, "200"), event_info=BASE)
        push(off, items(60, 1000, "pA") + items(60, 2000, "pB"))
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "50")
        on = FakeMisp(existing(120, "200"), event_info=BASE)
        push(on, items(60, 1000, "pA") + items(60, 2000, "pB"))
        assert on.posts == off.posts
        assert sizes(on) == {BASE: 240}

    def test_one_report_attribute_keeps_the_whole_group_in_one_event(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "50")
        misp = FakeMisp([], event_info=BASE)
        push(misp, items(120) + items(1, 5000, "pA"))
        assert sizes(misp) == {BASE: 121}

    def test_mixed_push_splits_the_report_free_group_only(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "50")
        misp = FakeMisp([], event_info=BASE)
        otx = [dict(i, tag="alienvault_otx") for i in items(80, 0, "pA")]
        push(misp, otx + items(120, 1000))
        assert sizes(misp) == {
            BASE: 50,
            f"{BASE}-part2": 50,
            f"{BASE}-part3": 20,
            f"EdgeGuard-alienvault_otx-{TODAY}": 80,
        }

    def test_dedup_off_rerun_after_a_split_writes_nothing(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "50")
        misp = FakeMisp([], event_info=BASE)
        assert push(misp, items(120)) == (120, 0)
        assert push(misp, items(120)) == (0, 0)
        assert sizes(misp) == {BASE: 50, f"{BASE}-part2": 50, f"{BASE}-part3": 20}

    def test_no_part_is_created_empty(self):
        attrs = [{"value": str(i)} for i in range(10)]
        assert _split_for_parts(attrs, 0, 5) == [[], attrs[:5], attrs[5:]]
        assert _split_for_parts(attrs, 5, 5) == [attrs[:5], attrs[5:]]
        assert _split_for_parts(attrs, 3, 5) == [attrs[:3], attrs[3:8], attrs[8:]]


class TestNameParsing:
    def test_event_name(self):
        assert _event_name("nvd", "2026-10-22") == "EdgeGuard-nvd-2026-10-22"
        assert _event_name("nvd", "2026-10-22", 1) == "EdgeGuard-nvd-2026-10-22"
        assert _event_name("nvd", "2026-10-22", 3) == "EdgeGuard-nvd-2026-10-22-part3"

    def test_sync_source_id_accepts_the_suffix(self):
        from run_misp_to_neo4j import _event_source_id

        assert _event_source_id("EdgeGuard-alienvault_otx-2026-10-22-part2") == "alienvault_otx"

    def test_edgeguard_cli_and_stix_pipeline_parse_the_source_with_the_suffix(self):
        # both take the second "-" field (src/edgeguard.py source_map, src/run_pipeline.py STIX export)
        for info in ("EdgeGuard-nvd-2026-10-22", "EdgeGuard-nvd-2026-10-22-part2"):
            assert info.split("-", 2)[1] == "nvd"
        src = (_SRC / "edgeguard.py").read_text() + (_SRC / "run_pipeline.py").read_text()
        assert src.count('.split("-", 2)') >= 2 and "parts[1]" in src

    def test_own_event_prefix_check_accepts_the_suffix(self):
        assert "EdgeGuard-nvd-2026-10-22-part2".startswith(misp_writer._OWN_EVENT_PREFIX)


MIXED_PAYLOAD_SHA256_ON_MAIN = "b73a283bed4992e767086ebb6c705b2ad12ab8bffd16b7f9327a6110992d7cb1"


def mixed_payload():
    vulns = [
        {
            "type": "vulnerability",
            "cve_id": f"CVE-2026-000{i}",
            "tag": "nvd",
            "description": "d",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "published": "2026-10-01T00:00:00",
            "last_modified": "2026-10-02T00:00:00",
        }
        for i in range(3)
    ]
    iocs = [
        {
            "indicator_type": "ipv4",
            "value": f"10.0.0.{i}",
            "tag": "alienvault_otx",
            "pulse_id": "p1",
            "zone": ["global"],
            "first_seen": "2026-10-01T00:00:00+00:00",
        }
        for i in range(4)
    ]
    return (
        vulns
        + iocs
        + [{"type": "malware", "name": "Emotet", "tag": "alienvault_otx", "pulse_id": "p1", "zone": ["global"]}]
    )


def dump(misp):
    return json.dumps(misp.posts, sort_keys=True, default=str).replace(TODAY, "DATE")


class TestNothingElseChanges:
    def test_cap_zero_sends_the_requests_origin_main_sent(self, monkeypatch):
        """The digest was taken from the same payload pushed by the code before the split (origin/main 74cd79b)."""
        import hashlib

        monkeypatch.setattr(misp_writer, "MISP_CROSS_EVENT_DEDUP", True)  # the default
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "0")
        misp = FakeMisp([], event_info="x")
        assert push(misp, mixed_payload()) == (8, 0)
        # the digest is of the posts as ``[[path, body], ...]`` with the tuple rendered as a list
        assert hashlib.sha256(dump(misp).encode()).hexdigest() == MIXED_PAYLOAD_SHA256_ON_MAIN

    def test_under_the_cap_sends_the_same_requests_as_with_the_split_off(self, monkeypatch):
        monkeypatch.setattr(misp_writer, "MISP_CROSS_EVENT_DEDUP", True)
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "0")
        off = FakeMisp([], event_info="x")
        push(off, mixed_payload())
        monkeypatch.delenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE")
        on = FakeMisp([], event_info="x")
        push(on, mixed_payload())
        assert on.posts == off.posts
