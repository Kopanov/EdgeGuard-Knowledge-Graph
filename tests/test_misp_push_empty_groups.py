"""MISP push accounting: no event for a group without attributes; conversion drops (2026-10).

``MISPWriter.push_items`` groups the converted attributes by (source, date) and pushes each group
into the day's event ``EdgeGuard-{source}-{date}``. Before 2026-10:

* a group whose items all failed conversion (an unknown item type, a ``create_*_attribute`` that
  returned None, such as an empty value) still went through ``_get_or_create_event`` and could
  create an empty same-day event;
* a re-run whose items MISP already held looked up (and on a new day created) the day's event
  before the cross-event check dropped every item;
* items dropped in conversion were neither pushed nor counted: the push returned ``(0, 0)`` and
  logged "[DEDUP] All N items were already present in MISP" with N the number of items given, so
  the success-rate gate (``status_after_misp_push``) passed a source whose payload had stopped
  converting.

Now the items no attribute can be built from are reported by a ``[CONVERT]`` line (per source: how
many of its items, the reasons, whether they count as failed) and ``stats["items_not_converted"]``,
and count as failed only when the drop is systemic for the source in the push: all of its items,
or at least ``CONVERT_FAILED_MIN_SHARE`` of them. A few bad records therefore neither fail a run
nor hold a collector's cursor (the OTX case is run through ``OTXCollector.collect``). A group
without attributes reaches neither the event lookup nor MISP; with cross-event dedup on and a
complete listing of the source's attributes, the cross-event filter runs before the event lookup
(dedup off, or a listing that stopped early, keeps the old order); and the "[DEDUP]" line is logged
only when nothing failed or was dropped, with N the attributes found present.

The fake MISP answers the requests the writer sends (``/events/restSearch`` with ``eventinfo``,
``/events``, ``/attributes/restSearch`` with ``tags`` or ``eventid``) in the MISP 2.5 formats; the
stored rows are built from the attributes the writer itself converts from collector items.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from collectors import misp_writer as mw
from collectors.collector_utils import status_after_misp_push

TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
EARLIER_EVENT = ("41", "EdgeGuard-otx-2026-10-01")


def _otx_ioc(value: str) -> Dict[str, Any]:
    """An OTX indicator item as ``OTXCollector`` emits it (the fields the writer reads)."""
    return {
        "indicator_type": "ipv4",
        "value": value,
        "zone": ["global"],
        "tag": "otx",
        "source": ["otx"],
        "confidence_score": 0.5,
        "pulse_id": "6650a1b2c3d4e5f600000001",
    }


def _threatfox_ioc(value: str) -> Dict[str, Any]:
    return {
        "indicator_type": "domain",
        "value": value,
        "zone": ["global"],
        "tag": "threatfox",
        "source": ["threatfox"],
        "confidence_score": 0.6,
    }


class _FakeMisp:
    """Stands in for MISP behind ``MISPWriter.session``; ``calls`` records the requests in order."""

    def __init__(
        self,
        stored: Optional[List[dict]] = None,
        events: Optional[Dict[str, str]] = None,
        listing_status: int = 200,
    ):
        self.stored = stored or []
        self.events = dict(events or {})  # Event.info -> id
        self.listing_status = listing_status
        self.calls: List[tuple] = []

    def post(self, url: str, json: Optional[dict] = None, **_kwargs: Any) -> MagicMock:
        body = json or {}
        r = MagicMock()
        r.status_code = 200
        r.text = ""
        if url.endswith("/events/restSearch"):
            name = body["eventinfo"]
            self.calls.append(("lookup", name))
            eid = self.events.get(name)
            r.json.return_value = {"response": [{"Event": {"id": eid, "info": name}}] if eid else []}
        elif url.endswith("/events"):
            name = body["Event"]["info"]
            self.calls.append(("create", name))
            eid = str(100 + len(self.events))
            self.events[name] = eid
            r.json.return_value = {"Event": {"id": eid, "info": name}}
        elif url.endswith("/attributes/restSearch") and "tags" in body:
            tag = body["tags"][0]
            self.calls.append(("listing", tag))
            r.status_code = self.listing_status
            rows = [a for a in self.stored if tag in [t["name"] for t in a["Tag"]]]
            r.json.return_value = {"response": {"Attribute": rows}}
        elif url.endswith("/attributes/restSearch") and "eventid" in body:
            self.calls.append(("per_event", body["eventid"]))
            rows = [a for a in self.stored if a["event_id"] == body["eventid"]]
            r.json.return_value = {"response": {"Attribute": rows}}
        else:  # pragma: no cover - a request the writer must not send here
            raise AssertionError(f"unexpected MISP request {url}")
        return r


def _stored(writer: mw.MISPWriter, item: Dict[str, Any], event: tuple = EARLIER_EVENT) -> dict:
    """The MISP 2.5 ``attributes/restSearch`` row of ``item`` as the writer converts it."""
    attr = writer.create_attribute(item)
    assert attr is not None
    eid, info = event
    return {
        "id": "9001",
        "event_id": eid,
        "type": attr["type"],
        "value": attr["value"],
        "Event": {"id": eid, "info": info},
        "Tag": list(attr["Tag"]),
    }


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setattr(mw, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", True)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.delenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", raising=False)
    monkeypatch.setattr(mw.time, "sleep", lambda _s: None)
    yield


def _writer(misp: _FakeMisp, monkeypatch) -> tuple:
    writer = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
    writer.session = misp
    pushed: List[tuple] = []

    def push_batch(event_id, batch):
        pushed.append((event_id, [a["value"] for a in batch]))
        return len(batch), 0

    monkeypatch.setattr(writer, "_push_batch", push_batch)
    return writer, pushed


def _messages(caplog) -> List[str]:
    return [r.getMessage() for r in caplog.records]


def _otx_tag(writer: mw.MISPWriter) -> str:
    return writer.SOURCE_TAGS.get("otx", "source:otx")


# --------------------------------------------------------------------------- conversion drops


def _bad_cve(tag: str = "otx") -> Dict[str, Any]:
    """A CVE reference whose id is only whitespace: the collector keeps it, the writer cannot convert it."""
    return {"type": "vulnerability", "cve_id": " ", "zone": ["global"], "tag": tag, "source": [tag]}


def _convert_lines(caplog) -> List[logging.LogRecord]:
    return [r for r in caplog.records if r.getMessage().startswith("[CONVERT]")]


def test_the_threshold_is_half_of_a_source_s_items():
    # The docs, the status error ("at least half") and the tests below state this value.
    assert mw.CONVERT_FAILED_MIN_SHARE == 0.5


def test_a_single_dropped_item_among_good_ones_is_reported_not_failed(monkeypatch, caplog):
    writer, pushed = _writer(_FakeMisp(), monkeypatch)
    present = ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
    writer.session = misp = _FakeMisp(stored=[_stored(writer, _otx_ioc(v)) for v in present])
    items = [_otx_ioc(v) for v in present] + [_otx_ioc("198.51.100.7"), _bad_cve()]
    with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
        result = writer.push_items(items)

    assert result == (1, 0), "one new attribute pushed; the unconvertible item is no failure"
    assert pushed == [(misp.events[f"EdgeGuard-otx-{TODAY}"], ["198.51.100.7"])]
    assert writer.stats["items_not_converted"] == 1
    assert writer.stats["items_not_converted_failed"] == 0
    convert = _convert_lines(caplog)
    assert [r.levelno for r in convert] == [logging.WARNING]
    assert convert[0].getMessage() == (
        "[CONVERT] 1 item(s) could not be converted to a MISP attribute, 0 of them counted as failed "
        "(a source's items count as failed when all or at least 50% of them fail conversion): "
        "otx: 1 of 5 item(s), not counted as failed (1 vulnerability with an empty cve_id)"
    )
    assert any(
        m.startswith("[OK] MISP push complete: 1 succeeded, 0 failed; 1 item(s) not converted, not counted as failed")
        for m in _messages(caplog)
    )
    assert status_after_misp_push("otx", len(items), *result)["success"] is True


def test_a_dropped_item_among_items_misp_holds_neither_fails_nor_logs_all_present(monkeypatch, caplog):
    # The case that turned every run red: nothing new to push, and one record of the source that
    # never converts. The run passes, and the [DEDUP] line does not claim every item was present.
    writer, pushed = _writer(_FakeMisp(), monkeypatch)
    present = ["203.0.113.10", "203.0.113.11"]
    writer.session = misp = _FakeMisp(stored=[_stored(writer, _otx_ioc(v)) for v in present])
    items = [_otx_ioc(v) for v in present] + [{"type": "report", "name": "Weekly", "tag": "otx"}]
    with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
        result = writer.push_items(items)

    assert result == (0, 0)
    assert misp.calls == [("listing", _otx_tag(writer))], "no event looked up or created"
    assert pushed == []
    assert any(
        "otx: 1 of 3 item(s), not counted as failed (1 unknown item type 'report')" in m for m in _messages(caplog)
    )
    assert not any("[DEDUP]" in m for m in _messages(caplog)), "an item was dropped: not 'all already present'"
    assert any(
        "[SKIP] MISP push: 0 new attributes to push (2 items deduplicated; 1 item(s) not converted, "
        "not counted as failed ([CONVERT]))" in m
        for m in _messages(caplog)
    )
    assert status_after_misp_push("otx", len(items), *result)["success"] is True


def test_a_source_whose_items_all_fail_conversion_fails_and_creates_no_event(monkeypatch, caplog):
    misp = _FakeMisp()
    writer, pushed = _writer(misp, monkeypatch)
    items = [
        _otx_ioc(""),  # an empty value
        _bad_cve(),
        {"type": "campaign", "name": "Operation X", "tag": "otx"},
        {"type": "campaign", "name": "Operation Y", "tag": "otx"},
    ]
    with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
        result = writer.push_items(items)

    assert result == (0, 4), "a source none of whose items converts fails with every item"
    assert misp.calls == [], "no event lookup, no event creation, no listing for a group without attributes"
    assert pushed == []
    assert writer.stats["items_not_converted"] == 4
    assert writer.stats["items_not_converted_failed"] == 4
    assert writer.stats["events_created"] == 0
    convert = _convert_lines(caplog)
    assert [r.levelno for r in convert] == [logging.ERROR]
    assert convert[0].getMessage() == (
        "[CONVERT] 4 item(s) could not be converted to a MISP attribute, 4 of them counted as failed "
        "(a source's items count as failed when all or at least 50% of them fail conversion): "
        "otx: 4 of 4 item(s), counted as failed (1 indicator with an empty value, "
        "2 unknown item type 'campaign', 1 vulnerability with an empty cve_id)"
    )
    assert not any("[DEDUP]" in m for m in _messages(caplog)), "nothing was found present in MISP"
    # The caller's gate sees the failures: before 2026-10 the push returned (0, 0), a success.
    status = status_after_misp_push("otx", len(items), *result)
    assert status["success"] is False
    assert "[CONVERT]" in status["error"] and "at least half" in status["error"]


def test_every_item_failing_counts_whatever_the_share(monkeypatch):
    # "All of a source's items" is a rule of its own, not only a share of 1.0 above the threshold.
    monkeypatch.setattr(mw, "CONVERT_FAILED_MIN_SHARE", 1.5)
    writer, _pushed = _writer(_FakeMisp(), monkeypatch)
    assert writer.push_items([_bad_cve(), _bad_cve()]) == (0, 2)
    writer, _pushed = _writer(_FakeMisp(), monkeypatch)
    assert writer.push_items([_bad_cve(), _otx_ioc("198.51.100.7")]) == (1, 0)


@pytest.mark.parametrize(
    ("dropped", "good", "counted"),
    [
        (2, 2, True),  # 2 of 4: exactly the threshold counts
        (3, 1, True),  # 3 of 4: above it
        (1, 2, False),  # 1 of 3: below it
        (2, 3, False),  # 2 of 5: below it
    ],
)
def test_the_share_of_dropped_items_decides_at_and_below_the_threshold(monkeypatch, caplog, dropped, good, counted):
    writer, _pushed = _writer(_FakeMisp(), monkeypatch)
    values = [f"203.0.113.{10 + i}" for i in range(good)]
    writer.session = _FakeMisp(stored=[_stored(writer, _otx_ioc(v)) for v in values])
    items = [_otx_ioc(v) for v in values] + [_bad_cve() for _ in range(dropped)]
    with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
        result = writer.push_items(items)

    total = dropped + good
    verdict = "counted as failed" if counted else "not counted as failed"
    assert result == (0, dropped if counted else 0)
    assert writer.stats["items_not_converted"] == dropped
    assert writer.stats["items_not_converted_failed"] == (dropped if counted else 0)
    assert any(f"otx: {dropped} of {total} item(s), {verdict} (" in m for m in _messages(caplog))
    assert status_after_misp_push("otx", total, *result)["success"] is (not counted)


def test_the_rule_is_applied_per_source(monkeypatch, caplog):
    writer, pushed = _writer(_FakeMisp(), monkeypatch)
    items = [
        _otx_ioc("198.51.100.7"),
        _otx_ioc("198.51.100.8"),
        _otx_ioc("198.51.100.9"),
        _bad_cve(),  # OTX: 1 of 4, reported
        _bad_cve("threatfox"),
        {"type": "campaign", "name": "Operation X", "tag": "threatfox"},  # ThreatFox: 2 of 2, failed
    ]
    with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
        result = writer.push_items(items)

    assert result == (3, 2)
    assert [event for event, _values in pushed] == [writer.session.events[f"EdgeGuard-otx-{TODAY}"]]
    assert f"EdgeGuard-threatfox-{TODAY}" not in writer.session.events
    message = _convert_lines(caplog)[0].getMessage()
    assert message.startswith("[CONVERT] 3 item(s) could not be converted to a MISP attribute, 2 of them counted")
    assert message.endswith(
        "otx: 1 of 4 item(s), not counted as failed (1 vulnerability with an empty cve_id); "
        "threatfox: 2 of 2 item(s), counted as failed (1 unknown item type 'campaign', "
        "1 vulnerability with an empty cve_id)"
    )


# --------------------------------------------------------------------------- the OTX cursor


def _otx_pulse(pulse_id: str, modified: str, iocs: List[str], cve_references: List[str]) -> Dict[str, Any]:
    """A pulse with the fields of OTX's ``/api/v1/pulses/subscribed`` answer that the collector reads."""
    return {
        "id": pulse_id,
        "name": f"pulse {pulse_id}",
        "description": "",
        "created": "2026-10-13T11:11:02.458000",
        "modified": modified,
        "TLP": "white",
        "adversary": "",
        "tags": [],
        "references": [],
        "industries": [],
        "targeted_countries": [],
        "malware_families": [],
        "attack_ids": [],
        "cve_references": cve_references,
        "indicators": [
            {"id": 4526831400 + n, "indicator": v, "type": "IPv4", "created": modified, "description": ""}
            for n, v in enumerate(iocs)
        ],
    }


def test_an_otx_pulse_with_one_unconvertible_item_does_not_hold_the_cursor(monkeypatch, caplog):
    """The OTX collector advances its cursor to the newest pulse only after a push without failures;
    on a partial failure it advanced it to the pulses of the first ``success`` items, an
    approximation that the dropped item, listed before the second pulse's indicator, shifts. A
    malformed CVE reference in the older pulse is reported and the cursor reaches the newer one."""
    from unittest.mock import patch

    from collectors import otx_collector

    writer, pushed = _writer(_FakeMisp(), monkeypatch)
    older = _otx_pulse("6710e46581edfe9bba0da3f1", "2026-10-14T10:00:00.000000", ["198.51.100.7"], [" "])
    newer = _otx_pulse("6710e46581edfe9bba0da3f2", "2026-10-15T10:00:00.000000", ["198.51.100.8"], [])
    collector = otx_collector.OTXCollector.__new__(otx_collector.OTXCollector)
    collector.api_key = "a" * 64
    collector.tag = "alienvault_otx"
    collector.session = MagicMock()
    collector.rate_limiter = MagicMock()
    collector._last_http_status = 200
    collector.circuit_breaker = MagicMock()
    collector.misp_writer = writer
    collector.source_name = "otx"
    cursor: Dict[str, Any] = {}
    pages = iter([[older, newer]])
    with (
        patch.object(collector, "check_service_available", return_value=True),
        patch.object(collector, "_fetch_pulses", side_effect=lambda **_kw: next(pages, [])),
        patch.object(otx_collector.time, "sleep"),
        patch.object(otx_collector, "get_source_incremental", return_value={}),
        patch.object(otx_collector, "update_source_incremental", lambda _src, **kw: cursor.update(kw)),
        patch.object(otx_collector, "OTX_INCREMENTAL_MAX_PAGES", 10),
        caplog.at_level(logging.INFO, logger="collectors.misp_writer"),
    ):
        status = collector.collect(limit=10, push_to_misp=True, baseline=False)

    assert [values for _event, values in pushed] == [["198.51.100.7", "198.51.100.8"]]
    assert cursor == {"otx_last_pulse_modified": "2026-10-15T10:00:00"}, (
        "the cursor reaches the newer pulse; counted as failed, the item held it at the older one"
    )
    assert status["success"] is True and status["failed"] == 0
    assert any(
        "alienvault_otx: 1 of 3 item(s), not counted as failed (1 vulnerability with an empty cve_id)" in m
        for m in _messages(caplog)
    )


# --------------------------------------------------------------------------- re-runs


def test_an_all_present_rerun_creates_no_event_and_logs_dedup(monkeypatch, caplog):
    writer, pushed = _writer(_FakeMisp(), monkeypatch)
    values = ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
    writer.session = misp = _FakeMisp(stored=[_stored(writer, _otx_ioc(v)) for v in values])
    items = [_otx_ioc(v) for v in values] + [_otx_ioc("203.0.113.10")]  # one repeated in the push
    with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
        result = writer.push_items(items)

    assert result == (0, 0)
    assert misp.calls == [("listing", _otx_tag(writer))], "the day's event is neither looked up nor created"
    assert pushed == []
    assert writer.stats["events_created"] == 0
    assert writer.stats["attrs_skipped_existing"] == 3
    dedup = [m for m in _messages(caplog) if "[DEDUP]" in m]
    assert len(dedup) == 1 and dedup[0].startswith("[DEDUP] All 3 items were already present in MISP"), (
        "N is the number of attributes found present (3), not the number of items given (4)"
    )
    assert any("no event looked up or created" in m for m in _messages(caplog))
    assert status_after_misp_push("otx", len(items), *result)["success"] is True


def test_partial_push_looks_up_only_the_event_of_the_group_with_new_attributes(monkeypatch, caplog):
    writer, pushed = _writer(_FakeMisp(), monkeypatch)
    threatfox_event = ("42", "EdgeGuard-threatfox-2026-10-02")
    writer.session = misp = _FakeMisp(
        stored=[
            _stored(writer, _otx_ioc("203.0.113.10")),
            _stored(writer, _threatfox_ioc("bad.example"), event=threatfox_event),
        ]
    )
    items = [
        _otx_ioc("203.0.113.10"),  # present in an earlier OTX event
        _otx_ioc("198.51.100.7"),  # new
        {"type": "campaign", "name": "Operation X", "tag": "otx"},  # not convertible
        _threatfox_ioc("bad.example"),  # the whole ThreatFox group is present
    ]
    with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
        result = writer.push_items(items)

    otx_tag = _otx_tag(writer)
    tf_tag = writer.SOURCE_TAGS.get("threatfox", "source:threatfox")
    otx_event = f"EdgeGuard-otx-{TODAY}"
    assert result == (1, 0), "one new attribute pushed; one OTX item of three dropped in conversion is reported"
    assert misp.calls == [
        ("listing", otx_tag),
        ("lookup", otx_event),
        ("lookup", otx_event),  # the confirming lookup inside the creation lock
        ("create", otx_event),
        ("per_event", misp.events[otx_event]),
        ("listing", tf_tag),
    ], "the cross-event check runs before the event lookup; ThreatFox's day event is never touched"
    assert pushed == [(misp.events[otx_event], ["198.51.100.7"])]
    assert writer.stats["attrs_skipped_existing"] == 2, "one OTX and one ThreatFox attribute, each counted once"
    assert not any("[DEDUP]" in m for m in _messages(caplog))
    assert any(
        "skipping 1 attributes already present (0 per-event + 1 cross-event; "
        "cross-event PR-F7 active, checked before the event lookup)" in m
        for m in _messages(caplog)
    )
    assert any("threatfox" in m and "no event looked up or created" in m for m in _messages(caplog))


def test_a_failed_event_lookup_counts_only_the_attributes_not_found_present(monkeypatch, caplog):
    writer, pushed = _writer(_FakeMisp(), monkeypatch)
    writer.session = _FakeMisp(stored=[_stored(writer, _otx_ioc("203.0.113.10"))])

    def fail_lookup(*_a, **_k):
        raise mw.MispTransientError("MISP 502 on event lookup")

    monkeypatch.setattr(writer, "_get_or_create_event", fail_lookup)
    with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
        result = writer.push_items([_otx_ioc("203.0.113.10"), _otx_ioc("198.51.100.7")])
    assert result == (0, 1), "the attribute MISP already holds was never to be pushed, so it is no failure"
    assert writer.stats["attrs_skipped_existing"] == 1, "it is counted as present, before the lookup"
    assert not any("[DEDUP]" in m for m in _messages(caplog))


# --------------------------------------------------------------------------- the old order is kept


def test_dedup_off_keeps_the_event_lookup_before_the_filters(monkeypatch, caplog):
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", False)
    writer, pushed = _writer(_FakeMisp(), monkeypatch)
    today_event = ("55", f"EdgeGuard-otx-{TODAY}")
    misp = _FakeMisp(
        stored=[_stored(writer, _otx_ioc("203.0.113.10"), event=today_event)],
        events={today_event[1]: today_event[0]},
    )
    writer.session = misp
    with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
        result = writer.push_items([_otx_ioc("203.0.113.10")])

    assert result == (0, 0)
    assert misp.calls == [("lookup", today_event[1]), ("per_event", "55")], (
        "with cross-event dedup off there is no listing and the event is looked up first"
    )
    assert any("(1 per-event + 0 cross-event; cross-event DISABLED)" in m for m in _messages(caplog))
    assert any(m.startswith("[DEDUP] All 1 items were already present") for m in _messages(caplog))


def test_a_listing_that_failed_keeps_the_event_lookup_before_the_filters(monkeypatch, caplog):
    writer, pushed = _writer(_FakeMisp(), monkeypatch)
    today_event = ("55", f"EdgeGuard-otx-{TODAY}")
    misp = _FakeMisp(
        stored=[_stored(writer, _otx_ioc("203.0.113.10"), event=today_event)],
        events={today_event[1]: today_event[0]},
        listing_status=500,
    )
    writer.session = misp
    with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
        result = writer.push_items([_otx_ioc("203.0.113.10")])

    assert result == (0, 0)
    assert misp.calls == [("listing", _otx_tag(writer)), ("lookup", today_event[1]), ("per_event", "55")], (
        "keys from a failed listing are not trusted to skip the event lookup; the per-event check finds it"
    )
    assert any(m.startswith("[DEDUP] All 1 items were already present") for m in _messages(caplog))


def test_known_source_keys_skip_the_lookup_only_with_cross_event_dedup_on(monkeypatch):
    writer, pushed = _writer(_FakeMisp(), monkeypatch)
    item = _otx_ioc("203.0.113.10")
    attr = writer.create_attribute(item)
    known = {_otx_tag(writer): {(attr["type"], attr["value"])}}

    writer.session = misp = _FakeMisp()
    assert writer.push_items([item], known_source_keys=known) == (0, 0)
    assert misp.calls == [], "the caller's complete listing replaces both the listing and the event lookup"

    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", False)
    writer.session = misp = _FakeMisp(events={f"EdgeGuard-otx-{TODAY}": "56"})
    assert writer.push_items([item], known_source_keys=known) == (0, 0)
    assert misp.calls == [("lookup", f"EdgeGuard-otx-{TODAY}"), ("per_event", "56")], (
        "with dedup off the old order stays (the supplied keys still filter, after the event lookup)"
    )


# --------------------------------------------------------------------------- the listing's completeness


class _ListingSession:
    def __init__(self, pages: List[Any]):
        self.pages = pages
        self.posts = 0

    def post(self, url, json=None, **_kwargs):
        page = self.pages[min(self.posts, len(self.pages) - 1)]
        self.posts += 1
        if isinstance(page, Exception):
            raise page
        r = MagicMock()
        if isinstance(page, int):
            r.status_code = page
            r.json.return_value = {}
        else:
            r.status_code = 200
            r.json.return_value = {"response": {"Attribute": page}}
        return r


def _listing(pages: List[Any]) -> tuple:
    writer = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
    writer.session = _ListingSession(pages)
    complete: Dict[str, bool] = {}
    keys = writer._get_existing_source_attribute_keys("source:otx", listing_complete=complete)
    return keys, complete, writer.session.posts


def test_the_listing_is_complete_only_when_it_reached_a_short_page(caplog):
    full = [{"type": "ip-dst", "value": f"10.0.{i // 250}.{i % 250}"} for i in range(5000)]
    short = [{"type": "ip-dst", "value": "192.0.2.1"}]

    keys, complete, posts = _listing([full, short])
    assert complete == {"source:otx": True} and posts == 2 and len(keys) == 5001

    keys, complete, _posts = _listing([full, 500])
    assert complete == {} and len(keys) == 5000, "an HTTP error keeps the partial keys, marked incomplete"

    _keys, complete, _posts = _listing([mw.requests.exceptions.ConnectionError("reset")])
    assert complete == {}

    with caplog.at_level(logging.WARNING, logger="collectors.misp_writer"):
        _keys, complete, posts = _listing([full])  # every page full: the page cap ends the listing
    assert complete == {} and posts == 200
    assert any("stopped at the page cap" in r.getMessage() for r in caplog.records)
