"""OTX pulse fetch: one copy per pulse id, and counts that tell paging from item loss (2026-11-02).

``/api/v1/pulses/subscribed`` is paged by offset (``page`` and ``limit``) without a sort order. When the
order shifts between two page requests, a pulse comes back on a later page and another is passed over.
The baseline and the incremental fetch appended the pages as they came, and the baseline logged the rows
as ``N total pulses collected``: a repeated pulse was processed twice and counted twice, and in an
incremental run it took a slot of the per-run limit, so a pulse past the limit was not processed and the
cursor could pass it. The 730-day run of 2026-11-01 logged ``3011 total pulses collected of 3011 that OTX
reported for the window``, while its graph holds 2,991 distinct OTX pulse references; the log could not
tell repeated rows from pulses whose items were lost.

The collector now keeps the first copy of each pulse id in both fetch paths, logs the distinct pulses
beside the rows read and the ids of the repeated rows, logs the pulses that yielded no item, and returns
the counts in its status (``pulse_counts``).

The pulses have the layout of OTX's answer that the other OTX tests use. The pulse ids and indicator
values of the pulses with items are read from the 730-day graph of 2026-11-01 (``conferencefreckewl.shop``
is listed there by pulses 6723f395217b63c2bbdfc819 and 682e5bb94e2f4e75be640cb5, among others); the two
pulses without a collectable item carry the ids and indicator types of the existing OTX tests.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from collectors import otx_collector  # noqa: E402
from collectors.otx_collector import OTXCollector  # noqa: E402


def _indicator(n: int, ind_type: str, value: str) -> Dict[str, Any]:
    return {
        "id": 4526831400 + n,
        "indicator": value,
        "type": ind_type,
        "created": "2026-10-13T23:37:31",
        "content": "",
        "title": "",
        "description": "",
        "expiration": None,
        "is_active": 1,
    }


def _pulse(pid: str, name: str, modified: str, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "id": pid,
        "name": name,
        "description": "",
        "author_name": "example",
        "created": "2026-10-13T11:11:02.458000",
        "modified": modified,
        "revision": 1,
        "public": 1,
        "TLP": "white",
        "adversary": "",
        "tags": [],
        "references": [],
        "industries": [],
        "targeted_countries": [],
        "malware_families": [],
        "attack_ids": [],
        "cve_references": [],
        "indicators": indicators,
    }


P1 = "6723f395217b63c2bbdfc819"
P2 = "6aad3e7f8cc155ff864b444b"
P3 = "69e991a518634e661de0c8eb"
P4 = "682e5bb94e2f4e75be640cb5"  # lists only an IOC that P1 lists too
NON_FILE_HASHES_ONLY = "6710e46581edfe9bba0da3f1"
EMPTY = "6710e46581edfe9bba0da3f2"


def _p1() -> Dict[str, Any]:
    return _pulse(
        P1,
        "Stealer infrastructure",
        "2026-10-15T10:00:00",
        [
            _indicator(1, "domain", "conferencefreckewl.shop"),
            _indicator(2, "domain", "pleasurenarrowsdla.shop"),
            _indicator(3, "FileHash-SHA256", "bfa188194c91e509262d0924cfd0ae70d120d50e904982d54d1d5a58de72bde4"),
        ],
    )


def _p2() -> Dict[str, Any]:
    return _pulse(
        P2,
        "Interview lure payload staging",
        "2026-10-15T12:00:00",
        [
            _indicator(4, "URL", "https://api.npoint.io/933a731a5e97f4b45249"),
            _indicator(5, "URL", "http://103.170.217.184:8787"),
        ],
    )


def _p3() -> Dict[str, Any]:
    """The oldest pulse of the window."""
    return _pulse(P3, "Remote worker infiltration", "2026-10-15T08:00:00", [_indicator(6, "domain", "luckyguys.site")])


def _p4() -> Dict[str, Any]:
    return _pulse(P4, "Stealer domains", "2026-10-15T09:00:00", [_indicator(7, "domain", "conferencefreckewl.shop")])


def _non_file_hashes_only() -> Dict[str, Any]:
    return _pulse(
        NON_FILE_HASHES_ONLY,
        "Loader campaign",
        "2026-10-15T07:00:00",
        [
            _indicator(8, "FileHash-IMPHASH", "f34d5f2d4577ed6d9ceec516c1f5a744"),
            _indicator(9, "JA3", "e7d705a3286e19ea42f587b344ee6865"),
        ],
    )


def _empty() -> Dict[str, Any]:
    return _pulse(EMPTY, "Loader campaign", "2026-10-15T06:00:00", [])


def _collector() -> OTXCollector:
    c = OTXCollector.__new__(OTXCollector)
    c.api_key = "a" * 64
    c.base_url = "https://otx.example"
    c.tag = "alienvault_otx"
    c.session = MagicMock()
    c.rate_limiter = MagicMock()
    c._last_http_status = 200
    c.circuit_breaker = MagicMock()
    c.source_name = "otx"
    writer = MagicMock()
    writer.push_items.side_effect = lambda items: (len(items), 0)
    writer.last_push_unstored_items = []
    c.misp_writer = writer
    return c


def _run(caplog, pages: List[List[Dict[str, Any]]], *, baseline: bool, limit: Optional[int] = None, count=None):
    """``collect`` against an OTX double that answers ``pages`` in order (then empty pages), as OTX answers
    ``/api/v1/pulses/subscribed``: ``{"count": ..., "results": [...]}``. Returns the collector, its status,
    the items pushed, the pulse ids ``detect_sectors`` read (once per processed pulse), the cursor writes
    and the log records."""

    def answer(method, url, params=None, **_kw):
        response = MagicMock(status_code=200)
        page = params["page"]
        body: Dict[str, Any] = {"results": pages[page - 1] if page <= len(pages) else []}
        if count is not None:
            body["count"] = count
        response.json.return_value = body
        return response

    c = _collector()
    processed_pulses: List[str] = []
    real_detect = c.detect_sectors

    def detect(text: str) -> List[str]:
        processed_pulses.extend(pid for pid in (P1, P2, P3, P4, NON_FILE_HASHES_ONLY, EMPTY) if pid in text)
        return real_detect(text)

    cursor = MagicMock()
    with (
        patch.object(c, "check_service_available", return_value=True),
        patch.object(c, "detect_sectors", side_effect=detect),
        patch.object(otx_collector, "request_with_rate_limit_retries", side_effect=answer),
        patch.object(otx_collector.time, "sleep"),
        patch.object(otx_collector, "get_source_incremental", return_value={}),
        patch.object(otx_collector, "update_source_incremental", cursor),
        patch.object(otx_collector, "OTX_BASELINE_MAX_PAGES", 200),
        patch.object(otx_collector, "OTX_INCREMENTAL_MAX_PAGES", 25),
        caplog.at_level("INFO", logger=otx_collector.logger.name),
    ):
        status = c.collect(limit=limit, push_to_misp=True, baseline=baseline, baseline_days=730)
    pushed = c.misp_writer.push_items.call_args.args[0] if c.misp_writer.push_items.called else []
    records = [r for r in caplog.records if r.name == otx_collector.logger.name]
    return status, pushed, processed_pulses, cursor, records


def _values(items: List[Dict[str, Any]]) -> List[str]:
    return [i["value"] for i in items if i.get("value")]


def test_a_pulse_on_two_pages_is_processed_once_and_the_repeat_is_logged(caplog):
    """Pages 1 and 2 both return P2 (the order shifted between the two requests)."""
    status, pushed, processed, _cursor, records = _run(caplog, [[_p1(), _p2()], [_p2(), _p3()]], baseline=True, count=3)
    assert processed.count(P2) == 1
    assert sorted(processed) == sorted([P1, P2, P3])
    assert _values(pushed).count("https://api.npoint.io/933a731a5e97f4b45249") == 1
    assert status["pulse_counts"] == {
        "rows_read": 4,
        "distinct": 3,
        "repeated_rows": 1,
        "processed": 3,
        "without_item": 0,
        "deferred": 0,
    }
    messages = [r.getMessage() for r in records]
    assert any(
        m.endswith(
            "Baseline complete: 3 distinct pulses collected of 3 that OTX reported for the window "
            "(4 rows read, 1 of them repeating a pulse already read)"
        )
        for m in messages
    )
    repeats = [r.getMessage() for r in records if r.getMessage().startswith("[PULSES] OTX: 1 page row(s) repeated")]
    # The id is the repeated pulse, whose first copy was kept, not a pulse that was passed over.
    assert repeats == [
        f"[PULSES] OTX: 1 page row(s) repeated 1 pulse(s) already read (repeated ids: {P2}); the first copy of "
        "each is kept. If the page order shifted between requests, as many other pulses may have been passed over."
    ]
    assert "Interview lure" not in repeats[0]  # ids only, no pulse names
    assert [r.levelname for r in records if r.getMessage() == repeats[0]] == ["WARNING"]


def test_a_fetch_without_repeats_counts_zero_and_logs_no_repeat(caplog):
    status, pushed, processed, _cursor, records = _run(caplog, [[_p1(), _p2()], [_p3()]], baseline=True, count=3)
    assert sorted(processed) == sorted([P1, P2, P3])
    assert status["pulse_counts"] == {
        "rows_read": 3,
        "distinct": 3,
        "repeated_rows": 0,
        "processed": 3,
        "without_item": 0,
        "deferred": 0,
    }
    messages = [r.getMessage() for r in records]
    assert any(m.endswith("(3 rows read, 0 of them repeating a pulse already read)") for m in messages)
    assert not any("repeated" in m and m.startswith("[PULSES]") for m in messages)
    assert "[PULSES] OTX: 3 pulse(s) processed, 0 of them yielded no item" in messages


def test_the_pulses_that_yielded_no_item_are_counted_and_named(caplog):
    """A pulse with only non-file hash indicators and a pulse with nothing collectable yield no item. A
    pulse whose only IOC an earlier pulse already listed yields its id to that item (``report_ids``) and
    is not among them."""
    status, pushed, _processed, _cursor, records = _run(
        caplog, [[_p1(), _non_file_hashes_only()], [_p4(), _empty()]], baseline=True, count=4
    )
    shared = [i for i in pushed if i.get("value") == "conferencefreckewl.shop"]
    assert len(shared) == 1 and shared[0]["pulse_id"] == P1 and shared[0]["report_ids"] == [P4]
    assert status["pulse_counts"]["without_item"] == 2
    assert status["pulse_counts"]["processed"] == 4
    lines = [r.getMessage() for r in records if r.getMessage().startswith("[PULSES] OTX: 4 pulse(s) processed")]
    assert lines == [
        "[PULSES] OTX: 4 pulse(s) processed, 2 of them yielded no item (no collected indicator, malware family, "
        f"CVE or adversary): {NON_FILE_HASHES_ONLY}, {EMPTY}"
    ]


def test_a_run_whose_pulses_all_yielded_no_item_still_returns_the_counts(caplog):
    """Nothing to push: the status of the empty push carries the counts too."""
    status, pushed, _processed, _cursor, _records = _run(
        caplog, [[_non_file_hashes_only(), _empty()], [_empty()]], baseline=False, limit=10
    )
    assert pushed == []
    assert status["count"] == 0
    assert status["pulse_counts"] == {
        "rows_read": 3,
        "distinct": 2,
        "repeated_rows": 1,
        "processed": 2,
        "without_item": 2,
        "deferred": 0,
    }


def test_an_incremental_repeat_no_longer_takes_a_slot_of_the_limit(caplog):
    """With a limit of 3 pulses, the repeated P2 took the third slot: P3, the oldest pulse, was not
    processed, and the cursor moved to P2's ``modified``, past P3, so no later run read it."""
    status, pushed, processed, cursor, records = _run(
        caplog, [[_p1(), _p2()], [_p2(), _p3()]], baseline=False, limit=3, count=3
    )
    assert sorted(processed) == sorted([P1, P2, P3])
    assert "luckyguys.site" in _values(pushed)
    assert status["pulse_counts"] == {
        "rows_read": 4,
        "distinct": 3,
        "repeated_rows": 1,
        "processed": 3,
        "without_item": 0,
        "deferred": 0,
    }
    messages = [r.getMessage() for r in records]
    assert (
        "OTX incremental: 3 distinct pulses read of 3 that OTX reported for the window "
        "(4 rows read, 1 of them repeating a pulse already read)"
    ) in messages
    assert any(
        m.startswith(f"[PULSES] OTX: 1 page row(s) repeated 1 pulse(s) already read (repeated ids: {P2});")
        for m in messages
    )
    cursor.assert_called_once_with("otx", otx_last_pulse_modified="2026-10-15T12:00:00")


def test_rows_and_pulses_are_counted_apart_when_a_pulse_comes_back_twice(caplog):
    """P2 comes back on pages 2 and 3, P1 on page 3: three repeated rows of two pulses."""
    status, _pushed, processed, _cursor, records = _run(
        caplog, [[_p1(), _p2()], [_p2(), _p3()], [_p2(), _p1()]], baseline=True, count=3
    )
    assert sorted(processed) == sorted([P1, P2, P3])
    assert status["pulse_counts"] == {
        "rows_read": 6,
        "distinct": 3,
        "repeated_rows": 3,
        "processed": 3,
        "without_item": 0,
        "deferred": 0,
    }
    repeats = [r.getMessage() for r in records if r.levelname == "WARNING" and r.getMessage().startswith("[PULSES]")]
    assert len(repeats) == 1
    assert repeats[0].startswith(
        f"[PULSES] OTX: 3 page row(s) repeated 2 pulse(s) already read (repeated ids: {P2}, {P1});"
    )


def test_a_scheduled_run_counts_only_the_pulses_within_the_limit(caplog):
    """Three distinct pulses that all yield items, one repeated row, and a limit of 2: the limit takes the
    pulses oldest first (P3, then P1), so P2, the newest, is deferred to the next run and the cursor stops at
    P1, below it. It is counted neither as processed nor as a pulse that yielded no item, and the
    ``processed`` line names no pulse."""
    status, pushed, processed, cursor, records = _run(
        caplog, [[_p1(), _p2()], [_p2(), _p3()]], baseline=False, limit=2, count=3
    )
    assert sorted(processed) == sorted([P1, P3])
    assert "luckyguys.site" in _values(pushed)
    assert "https://api.npoint.io/933a731a5e97f4b45249" not in _values(pushed)
    cursor.assert_called_once_with("otx", otx_last_pulse_modified="2026-10-15T10:00:00")
    assert status["pulse_counts"] == {
        "rows_read": 4,
        "distinct": 3,
        "repeated_rows": 1,
        "processed": 2,
        "without_item": 0,
        "deferred": 1,
    }
    lines = [
        r.getMessage() for r in records if " processed, " in r.getMessage() and r.getMessage().startswith("[PULSES]")
    ]
    assert lines == ["[PULSES] OTX: 2 pulse(s) processed, 0 of them yielded no item"]
    assert not any(pid in lines[0] for pid in (P1, P2, P3))
    assert not any("yielded no item (" in r.getMessage() for r in records)
    deferral = [r.getMessage() for r in records if "deferred to the next run" in r.getMessage()]
    assert len(deferral) == 1
    assert deferral[0].startswith("[PULSES] OTX: 1 pulse(s) deferred to the next run: the run's limit of 2 ")


def test_a_pulse_without_an_id_is_not_named_among_the_pulses_without_an_item():
    """It has no id to match or to name; the processed count still includes it."""
    no_id = _pulse("", "no id", "2026-10-15T05:00:00", [])
    no_id_key = _p3()
    del no_id_key["id"]
    assert otx_collector._pulses_without_item([no_id, no_id_key, _p1(), _empty()], [{"pulse_id": P1}]) == [EMPTY]


def test_the_first_copy_is_kept_and_a_row_without_an_id_stays():
    first = _p2()
    second = _p2()
    second["name"] = "renamed between the two requests"
    no_id = _pulse("", "no id", "2026-10-15T05:00:00", [])
    kept, repeated = otx_collector._first_copy_of_each_pulse([first, no_id, second, _p3(), _p2(), no_id])
    assert kept == [first, no_id, _p3(), no_id]
    assert kept[0] is first
    assert repeated == [P2, P2]


def test_the_logged_ids_are_capped_at_20_distinct():
    ids = [f"6a00000000000000000000{n:02d}" for n in range(25)]
    text = otx_collector._pulse_ids_for_log(ids + ids[:3])
    assert text.split(", … ")[0].split(", ") == ids[:20]
    assert text.endswith(", … (5 more)")
    assert otx_collector._pulse_ids_for_log(ids[:20]) == ", ".join(ids[:20])
