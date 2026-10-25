"""H2 of docs/flow_audits/06_misp_aggregation.md: MISPWriter continues a source/date event in ``-partN`` (2026-10).

Drives the real ``MISPWriter.push_items`` against ``FakeMisp`` (an in-memory MISP whose event lookup answers
``attribute_count`` as MISP 2.5.45 does). Covers the default configuration (cross-event dedup on), the
complete and the incomplete cross-event listing, the part a push goes to, the size a part is read with, the
part created only right before its first batch, and every failure path's accounting.
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
from collectors.misp_writer import MISPWriter, _allot_to_parts, _attribute_report_ids, _event_name  # noqa: E402

TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
_REAL_SPLIT_MIN = misp_writer._EVENT_SPLIT_MIN  # read before the fixture lowers it
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
    monkeypatch.setattr(misp_writer, "_EVENT_SPLIT_MIN", 1)  # small limits keep the fakes small


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


def writer_for(misp):
    writer = MISPWriter(url="https://misp.test", api_key="test", verify_ssl=True)
    writer.session = misp
    return writer


def push(misp, batch, **kw):
    return writer_for(misp).push_items(batch, **kw)


def fail_when(misp, predicate, response):
    """Answer ``response`` (a Response, or an exception to raise) to every post ``predicate(path, body)`` matches."""
    real_post = misp.post

    def post(url, json=None, **kw):
        path = url.split(misp.url, 1)[1]
        if predicate(path, json or {}):
            misp.posts.append((path, json))
            if isinstance(response, Exception):
                raise response
            return response
        return real_post(url, json=json, **kw)

    misp.post = post


def no_duplicates(misp):
    keys = [(misp.events[a["event_id"]].split("-part")[0], a["type"], a["value"]) for a in misp.attributes]
    return len(keys) == len(set(keys))


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

    def test_a_new_part_is_created_right_before_its_first_batch(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "100")
        misp = FakeMisp([], event_info=BASE)
        push(misp, items(150))
        writes = [(p, (b or {}).get("Event", {}).get("info")) for p, b in misp.posts if p != "/events/restSearch"]
        writes = [w for w in writes if w[0] != "/attributes/restSearch"]
        created = writes.index(("/events", f"{BASE}-part2"))
        # part 1 receives its attributes first; part 2 is created after that and receives the rest
        assert any(p.startswith("/events/2") for p, _ in writes[:created])
        assert writes[created + 1][0] == f"/events/{misp.events_by_name(f'{BASE}-part2')}"

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


class TestDefaultConfiguration:
    """Cross-event dedup on, as deployed: with a complete source-tag listing and with an incomplete one."""

    @pytest.fixture(autouse=True)
    def dedup_on(self, monkeypatch):
        monkeypatch.setattr(misp_writer, "MISP_CROSS_EVENT_DEDUP", True)
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "100")

    def test_rerun_with_new_items_fills_the_last_part(self):
        misp = FakeMisp([], event_info=BASE)
        assert push(misp, items(250)) == (250, 0)
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100, f"{BASE}-part3": 50}
        assert push(misp, items(260)) == (10, 0)
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100, f"{BASE}-part3": 60}
        assert no_duplicates(misp)

    def test_incomplete_source_listing_lists_the_other_parts_instead(self):
        misp = FakeMisp([], event_info=BASE)
        assert push(misp, items(250)) == (250, 0)
        fail_when(misp, lambda p, b: p == "/attributes/restSearch" and "tags" in b, Response(500, {"errors": "x"}))
        assert push(misp, items(260)) == (10, 0)
        assert push(misp, items(260)) == (0, 0)
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100, f"{BASE}-part3": 60}
        assert no_duplicates(misp)

    def test_incomplete_listing_with_a_short_part1_adds_nothing_twice(self):
        misp = FakeMisp(existing(80, "200") + existing(100, "201", offset=500), event_info=BASE)
        misp.events["201"] = f"{BASE}-part2"
        fail_when(misp, lambda p, b: p == "/attributes/restSearch" and "tags" in b, Response(500, {"errors": "x"}))
        again = [
            {"indicator_type": "ipv4", "value": a["value"], "tag": "urlhaus", "zone": ["global"]}
            for a in existing(10, "201", 500)
        ]
        assert push(misp, again + items(5, offset=5000)) == (5, 0)
        assert sizes(misp) == {BASE: 85, f"{BASE}-part2": 100}

    def test_overflow_of_a_short_part1_skips_a_full_part2(self):
        # complete cross-event listing: the walk comes only from the overflow of part 1
        misp = FakeMisp(existing(90, "200") + existing(100, "201", offset=500), event_info=BASE)
        misp.events["201"] = f"{BASE}-part2"
        assert push(misp, items(30, offset=5000)) == (30, 0)
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100, f"{BASE}-part3": 20}

    def test_a_timeout_listing_a_later_part_does_not_abort_the_push(self):
        # MISP under load: the source-tag listing and part 2's listing time out; part 2 is sized by its count
        import requests

        misp = FakeMisp(existing(50, "200") + existing(10, "201", offset=500), event_info=BASE)
        misp.events["201"] = f"{BASE}-part2"
        fail_when(
            misp, lambda p, b: p == "/attributes/restSearch" and "tags" in b, requests.exceptions.ReadTimeout("t")
        )
        fail_when(
            misp,
            lambda p, b: p == "/attributes/restSearch" and b.get("eventid") == "201",
            requests.exceptions.ReadTimeout("t"),
        )
        threatfox = [dict(i, tag="threatfox") for i in items(5, offset=9000)]
        assert push(misp, threatfox + items(5, offset=5000)) == (10, 0)
        assert sizes(misp)[BASE] == 55

    def test_a_rerun_of_everything_present_looks_up_no_part(self):
        misp = FakeMisp([], event_info=BASE)
        push(misp, items(250))
        before = len(misp.posts)
        assert push(misp, items(250)) == (0, 0)
        assert not [b for p, b in misp.posts[before:] if p == "/events/restSearch"]


class TestPartSelection:
    @pytest.fixture(autouse=True)
    def cap(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "100")

    def test_new_items_go_to_part3_when_parts_1_and_2_are_full(self):
        misp = FakeMisp([], event_info=BASE)
        push(misp, items(200))
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100}
        assert push(misp, items(50, offset=1000)) == (50, 0)
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100, f"{BASE}-part3": 50}

    def test_overflow_skips_a_full_later_part_when_part1_has_room(self):
        # part 1 left short (a failed batch, attributes deleted), part 2 full: the overflow of part 1 goes to
        # a new part 3, never on top of part 2
        misp = FakeMisp(existing(90, "200") + existing(100, "201", offset=500), event_info=BASE)
        misp.events["201"] = f"{BASE}-part2"
        assert push(misp, items(30, offset=1000)) == (30, 0)
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100, f"{BASE}-part3": 20}

    def test_a_short_part_is_filled_before_a_new_one_is_opened(self):
        misp = FakeMisp(existing(100, "200") + existing(40, "201", offset=500), event_info=BASE)
        misp.events["201"] = f"{BASE}-part2"
        misp.events["202"] = f"{BASE}-part3"  # an empty part 3 left by an earlier version's aborted push
        assert push(misp, items(70, offset=1000)) == (70, 0)
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100, f"{BASE}-part3": 10}

    def test_size_comes_from_attribute_count_when_the_part_listing_fails(self):
        # part 1 holds 60; its attribute listing answers 500 (MISP under load), the lookup's count says 60:
        # it takes 40 more, not a whole limit, and not nothing
        misp = FakeMisp(existing(60, "200"), event_info=BASE)
        fail_when(misp, lambda p, b: p == "/attributes/restSearch" and b.get("eventid") == "200", Response(500, {}))
        assert push(misp, items(50, offset=1000)) == (50, 0)
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 10}

    def test_an_over_full_part_takes_nothing_when_its_listing_fails(self):
        misp = FakeMisp(existing(300, "200"), event_info=BASE)
        fail_when(misp, lambda p, b: p == "/attributes/restSearch" and b.get("eventid") == "200", Response(500, {}))
        assert push(misp, items(50, offset=1000)) == (50, 0)
        assert sizes(misp) == {BASE: 300, f"{BASE}-part2": 50}

    def test_size_is_the_larger_of_listed_keys_and_attribute_count(self):
        # 100 attributes with 80 distinct values: the count (100) fills part 1, not the 80 keys
        dupes = [dict(a, id=f"d{a['id']}", uuid=f"d{a['uuid']}") for a in existing(20, "200")]
        misp = FakeMisp(existing(80, "200") + dupes, event_info=BASE)
        assert push(misp, items(10, offset=1000)) == (10, 0)
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 10}

    def test_a_created_part_counts_as_empty_even_if_its_listing_fails(self):
        misp = FakeMisp([], event_info=BASE)
        fail_when(misp, lambda p, b: p == "/attributes/restSearch" and b.get("eventid") == "200", Response(500, {}))
        assert push(misp, items(50)) == (50, 0)
        assert sizes(misp) == {BASE: 50}

    def test_a_later_part_without_a_count_is_never_overfilled(self):
        # lookup rows without a usable attribute_count and a complete cross-event listing, so the later parts
        # are not listed: parts 2 and 3, whose sizes are unknown, count as full and take nothing (part 2 stays
        # short rather than risk an overfill); the push opens parts 4 and 5
        misp = FakeMisp(existing(100, "200") + existing(40, "201", 500) + existing(100, "202", 900), event_info=BASE)
        misp.events.update({"201": f"{BASE}-part2", "202": f"{BASE}-part3"})
        misp._count = lambda _event_id: "n/a"
        misp_writer_dedup = misp_writer.MISP_CROSS_EVENT_DEDUP
        try:
            misp_writer.MISP_CROSS_EVENT_DEDUP = True
            assert push(misp, items(150, offset=5000)) == (150, 0)
        finally:
            misp_writer.MISP_CROSS_EVENT_DEDUP = misp_writer_dedup
        assert sizes(misp) == {
            BASE: 100,
            f"{BASE}-part2": 40,
            f"{BASE}-part3": 100,
            f"{BASE}-part4": 100,
            f"{BASE}-part5": 50,
        }

    def test_a_reused_writer_does_not_keep_a_stale_size(self):
        misp = FakeMisp([], event_info=BASE)
        writer = writer_for(misp)
        assert writer.push_items(items(90)) == (90, 0)  # creates part 1 (noted as 0), then stores 90
        misp._count = lambda _event_id: "n/a"
        fail_when(misp, lambda p, b: p == "/attributes/restSearch" and b.get("eventid") == "200", Response(500, {}))
        assert writer.push_items(items(50, offset=1000)) == (50, 0)
        assert sizes(misp) == {BASE: 90, f"{BASE}-part2": 50}

    def test_items_already_in_a_later_part_are_not_added_to_a_short_part1(self):
        # cross-event dedup off (module default): part 1 is short, part 2 full; 10 values part 2 holds and
        # 5 new ones fit part 1 (no overflow), and only the 5 new ones are written
        misp = FakeMisp(existing(80, "200") + existing(100, "201", offset=500), event_info=BASE)
        misp.events["201"] = f"{BASE}-part2"
        again = [
            {"indicator_type": "ipv4", "value": a["value"], "tag": "urlhaus", "zone": ["global"]}
            for a in existing(10, "201", 500)
        ]
        assert push(misp, again + items(5, offset=5000)) == (5, 0)
        assert sizes(misp) == {BASE: 85, f"{BASE}-part2": 100}
        assert no_duplicates(misp)

    def test_unknown_size_counts_as_full(self):
        # neither the listing nor the lookup tells the size: the part is not given another full limit
        misp = FakeMisp(existing(300, "200"), event_info=BASE)
        misp._count = lambda _event_id: "n/a"  # a lookup row without a usable attribute_count
        fail_when(misp, lambda p, b: p == "/attributes/restSearch" and b.get("eventid") == "200", Response(500, {}))
        assert push(misp, items(50, offset=1000)) == (50, 0)
        assert sizes(misp)[f"{BASE}-part2"] == 50

    def test_prefetch_off_and_no_count_takes_up_to_one_more_limit(self, monkeypatch):
        # nothing tells part 1's size: it takes at most one more limit, the rest opens part 2, nothing fails
        monkeypatch.setattr(misp_writer, "MISP_PREFETCH_EXISTING_ATTRS", False)
        misp = FakeMisp(existing(30, "200"), event_info=BASE)
        misp._count = lambda _event_id: None
        assert push(misp, items(150, offset=1000)) == (150, 0)
        assert sizes(misp) == {BASE: 130, f"{BASE}-part2": 50}

    def test_prefetch_off_still_splits_by_attribute_count(self, monkeypatch):
        monkeypatch.setattr(misp_writer, "MISP_PREFETCH_EXISTING_ATTRS", False)
        misp = FakeMisp([], event_info=BASE)
        push(misp, items(150))
        push(misp, items(150, offset=1000))
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100, f"{BASE}-part3": 100}


class TestFailures:
    @pytest.fixture(autouse=True)
    def cap(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "100")

    def test_failed_part_lookup_creates_nothing_and_counts_the_overflow(self):
        misp = FakeMisp([], event_info=BASE)
        push(misp, items(200))
        fail_when(
            misp,
            lambda p, b: p == "/events/restSearch" and str(b.get("eventinfo", "")).endswith("-part3"),
            Response(500, {"errors": "x"}),
        )
        threatfox = [dict(i, tag="threatfox") for i in items(5, offset=9000)]
        writer = writer_for(misp)
        batch = items(50, offset=1000) + threatfox
        assert writer.push_items(batch) == (5, 50)
        assert f"{BASE}-part3" not in misp.events.values()
        assert writer.last_push_unstored_items == list(range(50))
        assert sizes(misp)[f"EdgeGuard-threatfox-{TODAY}"] == 5

    def test_a_part_the_walk_could_not_read_is_never_written_blind(self):
        # parts 1-3 are full; the lookup of part 3 fails during the walk and answers again later in the push
        # (a flaky MISP). The overflow must not be sent to whatever part 3 the creation lookup then finds.
        misp = FakeMisp([], event_info=BASE)
        push(misp, items(300))
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100, f"{BASE}-part3": 100}

        start = len(misp.posts)

        def part3_lookup_before_any_add(path, body):
            added = any(p.startswith("/events/") and p[len("/events/") :].isdigit() for p, _ in misp.posts[start:])
            return path == "/events/restSearch" and str(body.get("eventinfo", "")).endswith("-part3") and not added

        fail_when(misp, part3_lookup_before_any_add, Response(500, {"errors": "x"}))
        threatfox = [dict(i, tag="threatfox") for i in items(5, offset=9000)]
        assert push(misp, threatfox + items(50, offset=1000)) == (5, 50)
        assert sizes(misp)[f"{BASE}-part3"] == 100

    @pytest.mark.parametrize("dedup", [True, False], ids=["dedup-on", "dedup-off"])
    def test_a_failed_part_lookup_without_a_complete_listing_writes_nothing_of_the_group(
        self, monkeypatch, caplog, dedup
    ):
        # part 1 left short (a failed batch) with parts 2 and 3 present; the source-tag listing answers 500 and
        # the lookup of part 3 fails after its retries. The 10 values part 3 holds must not go to part 1 again.
        monkeypatch.setattr(misp_writer, "MISP_CROSS_EVENT_DEDUP", dedup)
        misp = FakeMisp(
            existing(80, "200") + existing(100, "201", offset=500) + existing(40, "202", offset=900), event_info=BASE
        )
        misp.events.update({"201": f"{BASE}-part2", "202": f"{BASE}-part3"})
        fail_when(misp, lambda p, b: p == "/attributes/restSearch" and "tags" in b, Response(500, {"errors": "x"}))
        fail_when(
            misp,
            lambda p, b: p == "/events/restSearch" and str(b.get("eventinfo", "")).endswith("-part3"),
            Response(500, {"errors": "x"}),
        )
        held_by_part3 = [
            {"indicator_type": "ipv4", "value": a["value"], "tag": "urlhaus", "zone": ["global"]}
            for a in existing(10, "202", 900)
        ]
        threatfox = [dict(i, tag="threatfox") for i in items(5, offset=9000)]
        writer = writer_for(misp)
        with caplog.at_level("ERROR", logger=misp_writer.logger.name):
            assert writer.push_items(held_by_part3 + threatfox) == (5, 10)
        assert writer.last_push_unstored_items == list(range(10))
        assert any(
            r.levelname == "ERROR" and "10 attribute(s) counted as failed, nothing written" in r.getMessage()
            for r in caplog.records
        )
        assert no_duplicates(misp)
        assert sizes(misp) == {
            BASE: 80,
            f"{BASE}-part2": 100,
            f"{BASE}-part3": 40,
            f"EdgeGuard-threatfox-{TODAY}": 5,
        }

    def test_a_failed_part_lookup_with_a_complete_listing_still_writes_to_the_parts_found(self, monkeypatch):
        # the complete cross-event listing names every attribute of every part, so the parts found take what fits
        # them; only the overflow, which would need the part the lookup missed, counts as failed
        monkeypatch.setattr(misp_writer, "MISP_CROSS_EVENT_DEDUP", True)
        misp = FakeMisp(
            existing(80, "200") + existing(100, "201", offset=500) + existing(40, "202", offset=900), event_info=BASE
        )
        misp.events.update({"201": f"{BASE}-part2", "202": f"{BASE}-part3"})
        fail_when(
            misp,
            lambda p, b: p == "/events/restSearch" and str(b.get("eventinfo", "")).endswith("-part3"),
            Response(500, {"errors": "x"}),
        )
        writer = writer_for(misp)
        assert writer.push_items(items(30, offset=5000)) == (20, 10)
        assert writer.last_push_unstored_items == list(range(20, 30))
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100, f"{BASE}-part3": 40}

    def test_failed_part_creation_fails_its_later_parts_too(self):
        misp = FakeMisp([], event_info=BASE)
        fail_when(
            misp,
            lambda p, b: p == "/events" and b["Event"]["info"].endswith("-part2"),
            Response(403, {"errors": "no"}),
        )
        writer = writer_for(misp)
        assert writer.push_items(items(350)) == (100, 250)
        assert sorted(misp.events.values()) == [BASE]  # no part 3 after the missing part 2
        assert writer.last_push_unstored_items == list(range(100, 350))

    def test_a_failed_part_creation_fails_only_its_own_group(self):
        misp = FakeMisp([], event_info=BASE)
        fail_when(
            misp,
            lambda p, b: p == "/events" and b["Event"]["info"] == f"{BASE}-part2",
            Response(403, {"errors": "no"}),
        )
        threatfox = [dict(i, tag="threatfox") for i in items(150, offset=9000)]
        assert push(misp, items(150) + threatfox) == (250, 50)
        assert sizes(misp)[f"EdgeGuard-threatfox-{TODAY}-part2"] == 50

    def test_a_failed_event_lookup_counts_the_group_and_creates_nothing(self):
        misp = FakeMisp([], event_info=BASE)
        misp.event_lookup_status = 500
        assert push(misp, items(30)) == (0, 30)
        assert misp.events == {}

    def test_transient_error_on_part_creation_is_counted_as_failed(self):
        import requests

        misp = FakeMisp([], event_info=BASE)
        fail_when(
            misp,
            lambda p, b: p == "/events" and b["Event"]["info"].endswith("-part2"),
            requests.exceptions.ConnectionError("reset"),
        )
        writer = writer_for(misp)
        assert writer.push_items(items(250)) == (100, 150)
        assert writer.last_push_unstored_items == list(range(100, 250))

    def test_an_abort_during_the_backoff_cooldown_leaves_no_empty_part(self, monkeypatch):
        # part 1's three batches fail with HTTP 500, which trips the back-off cooldown before part 2's first
        # batch; the parent DAG dies during the cooldown. Part 2 must not exist yet.
        class Aborted(Exception):
            pass

        misp = FakeMisp(existing(10, "200"), event_info=BASE)
        fail_when(misp, lambda p, b: p == "/events/200", Response(500, {"errors": "x"}))
        writer = writer_for(misp)
        calls = []

        def liveness():
            calls.append(1)
            if len(calls) == 5:  # the second 30 s chunk of the cooldown
                raise Aborted()

        writer.liveness_callback = liveness
        with pytest.raises(Aborted):
            writer.push_items(items(120, offset=1000), batch_size=30)
        assert sorted(misp.events.values()) == [BASE]

    def test_an_aborted_push_leaves_no_empty_part(self):
        class Aborted(Exception):
            pass

        misp = FakeMisp([], event_info=BASE)
        writer = writer_for(misp)
        calls = []

        def liveness():
            calls.append(1)
            if len(calls) > 1:
                raise Aborted()

        writer.liveness_callback = liveness
        with pytest.raises(Aborted):
            writer.push_items(items(350))
        assert sizes(misp) == {BASE: 100}
        assert sorted(misp.events.values()) == [BASE]
        assert push(misp, items(350)) == (250, 0)
        assert sizes(misp) == {BASE: 100, f"{BASE}-part2": 100, f"{BASE}-part3": 100, f"{BASE}-part4": 50}
        assert all(n in sizes(misp) for n in misp.events.values())  # every event holds attributes


class TestKnob:
    @pytest.mark.parametrize(
        "raw, expected, warns",
        [
            (None, 20000, False),
            ("", 20000, False),
            (" 1500 ", 1500, False),
            ("0", 0, False),
            ("-5", 0, False),
            ("20", 20000, True),
            ("999", 20000, True),
            ("1000", 1000, False),
            ("many", 20000, True),
            ("off", 20000, True),
            ("2.5e4", 20000, True),
        ],
    )
    def test_parsing(self, monkeypatch, caplog, raw, expected, warns):
        assert _REAL_SPLIT_MIN == 1000
        monkeypatch.setattr(misp_writer, "_EVENT_SPLIT_MIN", _REAL_SPLIT_MIN)
        if raw is None:
            monkeypatch.delenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", raising=False)
        else:
            monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", raw)
        with caplog.at_level("WARNING", logger=misp_writer.logger.name):
            assert misp_writer._event_split_above() == expected
        assert any("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE" in r.getMessage() for r in caplog.records) == warns


class TestKnobWarnsOncePerPush:
    def test_one_warning_for_a_push_of_several_sources(self, monkeypatch, caplog):
        monkeypatch.setattr(misp_writer, "_EVENT_SPLIT_MIN", _REAL_SPLIT_MIN)
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "20")
        misp = FakeMisp([], event_info=BASE)
        batch = (
            items(3) + [dict(i, tag="threatfox") for i in items(3, 100)] + [dict(i, tag="feodo") for i in items(3, 200)]
        )
        with caplog.at_level("WARNING", logger=misp_writer.logger.name):
            assert push(misp, batch) == (9, 0)
        assert sum("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE" in r.getMessage() for r in caplog.records) == 1


class TestCountParsing:
    def test_only_the_exact_row_is_read(self):
        rows = [
            {"Event": {"id": "9", "info": f"{BASE}-part2", "attribute_count": "5"}},
            {"Event": {"id": "8", "info": BASE, "attribute_count": "145261"}},
        ]
        assert misp_writer._event_attribute_count_from_restsearch_rows(rows, BASE) == 145261
        assert misp_writer._event_attribute_count_from_restsearch_rows(rows, f"{BASE}-part3") is None
        assert (
            misp_writer._event_attribute_count_from_restsearch_rows(
                [{"id": "8", "info": BASE, "attribute_count": 7}], BASE
            )
            == 7
        )
        assert (
            misp_writer._event_attribute_count_from_restsearch_rows([{"Event": {"id": "8", "info": BASE}}], BASE)
            is None
        )
        assert (
            misp_writer._event_attribute_count_from_restsearch_rows(
                [{"Event": {"id": "8", "info": BASE, "attribute_count": "n/a"}}], BASE
            )
            is None
        )


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

    def test_no_new_part_chunk_is_empty(self):
        attrs = [{"value": str(i)} for i in range(10)]
        assert _allot_to_parts(attrs, [0], 5) == ([[]], [attrs[:5], attrs[5:]])
        assert _allot_to_parts(attrs, [5], 5) == ([attrs[:5]], [attrs[5:]])
        assert _allot_to_parts(attrs, [3], 5) == ([attrs[:3]], [attrs[3:8], attrs[8:]])
        assert _allot_to_parts(attrs, [2, 0, 3], 5) == ([attrs[:2], [], attrs[2:5]], [attrs[5:]])
        assert _allot_to_parts(attrs, [20], 5) == ([attrs], [])
        assert _allot_to_parts(attrs, [-3], 5) == ([[]], [attrs[:5], attrs[5:]])


class TestNameParsing:
    def test_event_name(self):
        assert _event_name("nvd", "2026-10-22") == "EdgeGuard-nvd-2026-10-22"
        assert _event_name("nvd", "2026-10-22", 1) == "EdgeGuard-nvd-2026-10-22"
        assert _event_name("nvd", "2026-10-22", 3) == "EdgeGuard-nvd-2026-10-22-part3"

    def test_sync_source_id_accepts_the_suffix(self):
        from run_misp_to_neo4j import _event_source_id

        assert _event_source_id("EdgeGuard-alienvault_otx-2026-10-22-part2") == "alienvault_otx"

    def test_cli_summary_counts_parts_under_their_source(self, monkeypatch):
        import requests

        import edgeguard

        class _Resp:
            def __init__(self, payload):
                self._payload = payload

            def raise_for_status(self):
                return None

            def json(self):
                return self._payload

        rows = [
            {"info": "EdgeGuard-nvd-2026-10-22", "attribute_count": "20000"},
            {"info": "EdgeGuard-nvd-2026-10-22-part2", "attribute_count": "20000"},
            {"info": "EdgeGuard-nvd-2026-10-22-part3", "attribute_count": "5"},
            {"info": "EdgeGuard-urlhaus-2026-10-22-part2", "attribute_count": "7"},
        ]

        class _Session:
            def __init__(self):
                self.headers = {}

            def get(self, url, params, **kw):
                return _Resp(rows if params["page"] == 1 else [])

        monkeypatch.setattr(requests, "Session", _Session)
        monkeypatch.setattr(edgeguard, "MISP_URL", "https://misp.test", raising=False)
        monkeypatch.setattr(edgeguard, "MISP_API_KEY", "k", raising=False)
        monkeypatch.setattr(edgeguard, "SSL_VERIFY", True, raising=False)
        summary = edgeguard._fetch_misp_event_summary()
        assert summary["by_source"] == [
            {"source": "nvd", "events": 3, "attributes": 40005},
            {"source": "urlhaus", "events": 1, "attributes": 7},
        ]
        assert summary["total_events"] == 4 and summary["total_attributes"] == 40012

    def test_stix_flow_labels_part_objects_with_their_source(self, monkeypatch):
        import run_pipeline

        pipeline = run_pipeline.EdgeGuardPipeline.__new__(run_pipeline.EdgeGuardPipeline)

        class _Exporter:
            def fetch_edgeguard_events(self):
                return [{"id": "7", "info": "EdgeGuard-nvd-2026-10-22-part2"}]

            def fetch_event_details(self, _event_id):
                return {"Event": {"id": "7"}}

            def convert_to_stix21(self, _event):
                return {"objects": [{"type": "vulnerability", "id": "vulnerability--1"}]}

        class _Neo4j:
            def run(self, _q):
                return [{"ok": 1}]

        bundles = []
        pipeline.stix_exporter = _Exporter()
        pipeline.neo4j = _Neo4j()
        pipeline.load_stix21_to_neo4j = lambda bundle: bundles.append(bundle) or {"vulnerabilities": 1}
        pipeline._run_stix_flow()
        assert [o["x_edgeguard_source"] for o in bundles[0]["objects"]] == ["nvd"]

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
