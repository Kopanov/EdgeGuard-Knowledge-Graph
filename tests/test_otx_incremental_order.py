"""OTX scheduled run: the per-run limit takes the oldest pulses first, so the cursor passes no pulse it read (2026-11-02).

``/api/v1/pulses/subscribed`` returns the pulses newest-modified first. Three pages of 20 read on 2026-11-02
(``modified_since`` 60 days back; OTX reported 370 pulses) held 60 distinct pulses whose ``modified`` never
rose from one row to the next: 59 consecutive pairs, 5 of them equal (three values shared by 2, 3 and 3
pulses, the higher id first). The scheduled run cut the window at ``EDGEGUARD_INCREMENTAL_LIMIT`` (200) in
that order and moved the cursor (``otx_last_pulse_modified``) to the newest pulse processed: when the window
held more pulses than the limit, the run processed the newest and the cursor passed every older one, which
no later run read.

The run now counts toward the limit the pulses modified after the stored cursor, oldest first (by
``modified``, then id). The pulses modified at or before the cursor, which the run reads only because the
request starts ``EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC`` (300 s) before it, and the pulses without a readable
``modified`` are processed outside the limit. The pulses processed keep OTX's order.

The pulses are built from ``tests/fixtures/otx_subscribed_order_2026_11_02.json`` (id, modified and created
of the 60 pulses, in the order OTX returned them), one indicator each. The OTX double answers as the
measurement shows (``_Otx``; ``test_the_double_answers_in_the_measured_order`` checks it against the
fixture), and ``collect`` keeps its incremental state in a dict, so several runs follow each other.

A push of items MISP already holds returns (0, 0) (``push_items`` counts them as neither stored nor failed);
the cursor advances after it as after any push without failures, so the oldest-first limit does not take the
same pulses on every run (``_HoldingWriter``). After a push with failures in batches MISP answered, whatever
it stored, the cursor advances too and the pulses with an item the writer lists as unstored go on the retry
list, which later runs fetch by id (2026-11-02; ``test_otx_retry_list.py``); when every listed item failed at
its MISP event (MISP unreachable, the day's event failing), the cursor stops below the oldest pulse with one.
The guards (a baseline, a window read before the page ceiling, a short last page, a writer without a list of
unstored items, an unstored item of a pulse without an id) pass before the change too and say so in their
docstrings.
"""

from __future__ import annotations

import copy
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional
from unittest.mock import MagicMock, patch

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from collectors import otx_collector  # noqa: E402
from collectors.otx_collector import OTXCollector  # noqa: E402

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "otx_subscribed_order_2026_11_02.json"
_RECORDED = json.loads(_FIXTURE.read_text(encoding="utf-8"))
# The 60 rows in the order OTX returned them (newest-modified first).
ROWS: List[Dict[str, Any]] = [row for page in _RECORDED["pages"] for row in page["results"]]
IDS: List[str] = [row["id"] for row in ROWS]
LIMIT_LOG = "deferred to the next run"


def _utc(raw: Any) -> Optional[datetime]:
    if not raw or not isinstance(raw, str):
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _pulse(pid: str, modified: Any, created: str, n: int) -> Dict[str, Any]:
    """A pulse with the fields of OTX's answer that the collector reads, with one IPv4 indicator."""
    return {
        "id": pid,
        "name": f"pulse {n}",
        "description": "",
        "author_name": "example",
        "created": created,
        "modified": modified,
        "tlp": "white",
        "adversary": "",
        "tags": [],
        "references": [],
        "industries": [],
        "targeted_countries": [],
        "malware_families": [],
        "attack_ids": [],
        "cve_references": [],
        "indicators": [
            {
                "id": 4526831400 + n,
                "indicator": f"198.51.100.{n}",
                "type": "IPv4",
                "created": created,
                "description": "",
            }
        ],
    }


def _recorded(indexes: Iterable[int]) -> List[Dict[str, Any]]:
    """The fixture rows at *indexes* as pulses (indicator ``198.51.100.<index + 1>``)."""
    return [_pulse(ROWS[i]["id"], ROWS[i]["modified"], ROWS[i]["created"], i + 1) for i in indexes]


def _ids(indexes: Iterable[int]) -> List[str]:
    return [IDS[i] for i in indexes]


class _Otx:
    """``/api/v1/pulses/subscribed`` as measured on 2026-11-02: the pulses modified at or after
    ``modified_since``, newest-modified first and the higher id first among equal ``modified`` values,
    paged by offset (``page``, ``limit``), with the number of matching pulses as ``count``. A pulse without
    a readable ``modified`` matches every request and comes last.

    ``/api/v1/pulses/{id}`` (the retry list's fetch by id, 2026-11-02) answers the pulse with that id, or
    HTTP 404 with OTX's body ``{"detail": "Not Found"}`` (``tests/fixtures/otx_pulse_by_id_2026_11_02.json``);
    *fetch_errors* maps an id to the HTTP status to answer instead, to an exception to raise, or to another
    body to answer with HTTP 200, and
    *by_id_only* holds pulses answered by id but not listed as subscribed (a pulse modified again after the
    page requests of the run, for example)."""

    def __init__(self, pulses: List[Dict[str, Any]]):
        self.pulses = list(pulses)
        self.requests: List[Dict[str, Any]] = []
        self.by_id_requests: List[str] = []
        self.by_id_calls: List[Dict[str, Any]] = []
        self.fetch_errors: Dict[str, Any] = {}
        self.by_id_only: Dict[str, Dict[str, Any]] = {}

    def by_id(self, pid: str) -> MagicMock:
        self.by_id_requests.append(pid)
        error = self.fetch_errors.get(pid)
        if isinstance(error, Exception):
            raise error
        if isinstance(error, dict):
            response = MagicMock(status_code=200)
            response.json.return_value = copy.deepcopy(error)
            return response
        pulse = self.by_id_only.get(pid) or next((p for p in self.pulses if p.get("id") == pid), None)
        response = MagicMock(status_code=error or (200 if pulse else 404))
        response.json.return_value = copy.deepcopy(pulse) if response.status_code == 200 else {"detail": "Not Found"}
        return response

    def ordered(self, since: datetime) -> List[Dict[str, Any]]:
        dated = [p for p in self.pulses if (dt := _utc(p.get("modified"))) is not None and dt >= since]
        dated.sort(key=lambda p: (_utc(p["modified"]), p["id"]), reverse=True)
        return dated + [p for p in self.pulses if _utc(p.get("modified")) is None]

    def answer(self, method: str, url: str, params: Optional[Dict[str, Any]] = None, **_kw: Any) -> MagicMock:
        if not url.endswith("/api/v1/pulses/subscribed"):
            assert "/api/v1/pulses/" in url and params is None, url
            self.by_id_calls.append({"method": method, "url": url, **_kw})
            return self.by_id(url.rsplit("/", 1)[1])
        params = dict(params or {})
        self.requests.append(params)
        since = _utc(params["modified_since"])
        assert since is not None
        matching = self.ordered(since)
        size, page = int(params["limit"]), int(params["page"])
        response = MagicMock(status_code=200)
        response.json.return_value = {
            "count": len(matching),
            "results": copy.deepcopy(matching[(page - 1) * size : page * size]),
        }
        return response


class _RecordedPages:
    """OTX answering the recorded pages of 2026-11-02 as they came (page ``n`` of the fixture, then empty
    pages), each with the recorded ``count`` (none when *with_count* is false); *drop* leaves out rows by
    fixture index."""

    def __init__(self, drop: Iterable[int] = (), with_count: bool = True):
        dropped = {IDS[i] for i in drop}
        self.pages = [
            [p for p in _recorded(range(20 * k, 20 * k + 20)) if p["id"] not in dropped]
            for k in range(len(_RECORDED["pages"]))
        ]
        self.count = _RECORDED["pages"][0]["count"] if with_count else None

    def answer(self, method: str, url: str, params: Optional[Dict[str, Any]] = None, **_kw: Any) -> MagicMock:
        page = int((params or {})["page"])
        response = MagicMock(status_code=200)
        rows = self.pages[page - 1] if page <= len(self.pages) else []
        response.json.return_value = {"count": self.count, "results": copy.deepcopy(rows)}
        return response


class _Writer:
    """A MISP writer double: stores every item except those of the pulses in *failing*, which it lists in
    ``last_push_unstored_items`` (positions in the pushed list) as ``MISPWriter`` does; with *at_the_event* they
    failed at their MISP event (``last_push_event_failed_items``: MISP unreachable, the day's event failing),
    otherwise in batches MISP answered. The items of a run's pushes (the window's, then the retry list's,
    2026-11-02) are kept in ``pushed`` and their *batch_key* (``push_items``' argument; ``None`` without one) in
    ``batch_keys``, in push order; ``calls`` keeps each call's items and keyword arguments."""

    def __init__(self, failing: Iterable[str] = (), at_the_event: bool = False):
        self.failing = set(failing)
        self.at_the_event = at_the_event
        self.pushed: List[Dict[str, Any]] = []
        self.batch_keys: List[Any] = []
        self.calls: List[Dict[str, Any]] = []
        self.last_push_unstored_items: List[int] = []
        self.last_push_event_failed_items: List[int] = []

    def push_items(self, items: List[Dict[str, Any]], batch_key: Any = None, **kw: Any):
        self.calls.append({"items": list(items), "batch_key": batch_key, **kw})
        self.pushed += list(items)
        self.batch_keys += [batch_key(item) if batch_key is not None else None for item in items]
        self.last_push_unstored_items = [n for n, item in enumerate(items) if item.get("pulse_id") in self.failing]
        self.last_push_event_failed_items = list(self.last_push_unstored_items) if self.at_the_event else []
        return len(items) - len(self.last_push_unstored_items), len(self.last_push_unstored_items)


class _WriterWithoutList:
    """A writer that gives no list of unstored items: one item of the push failed (every item with
    *every_item_fails*), which one is unknown."""

    def __init__(self, every_item_fails: bool = False):
        self.every_item_fails = every_item_fails
        self.pushed: List[Dict[str, Any]] = []

    def push_items(self, items: List[Dict[str, Any]], **_kw: Any):
        self.pushed += list(items)
        failed = len(items) if self.every_item_fails else 1
        return len(items) - failed, failed


def _value(index: int) -> str:
    """The indicator of the fixture pulse at *index* (``_recorded``)."""
    return f"198.51.100.{index + 1}"


class _HoldingWriter:
    """A MISP writer double that counts a push as ``MISPWriter.push_items`` does when MISP already holds items:
    an item MISP holds is neither stored nor failed, so a push of such items only returns (0, 0)
    (``test_otx_partial_cursor.py`` checks that with the writer itself). MISP holds the values in *held* and
    every value a push stored; the items of the pulses in *failing* fail and are listed in
    ``last_push_unstored_items``, the others are stored."""

    def __init__(self, held: Iterable[str] = (), failing: Iterable[str] = ()):
        self.held = set(held)
        self.failing = set(failing)
        self.pushed: List[Dict[str, Any]] = []
        self.counts: List[tuple] = []
        self.last_push_unstored_items: List[int] = []

    def push_items(self, items: List[Dict[str, Any]], **_kw: Any):
        self.pushed += list(items)
        new = [(n, item) for n, item in enumerate(items) if item["value"] not in self.held]
        self.last_push_unstored_items = [n for n, item in new if item.get("pulse_id") in self.failing]
        stored = [item["value"] for n, item in new if n not in self.last_push_unstored_items]
        self.held.update(stored)
        self.counts.append((len(stored), len(self.last_push_unstored_items)))
        return self.counts[-1]


class _Result(NamedTuple):
    status: Dict[str, Any]
    processed: List[str]  # the pulse ids of the pushed items, in push order
    cursor: Optional[str]
    messages: List[str]
    warnings: List[str]
    retry: List[Dict[str, Any]]  # the retry list in the state after the run (2026-11-02)
    errors: List[str]


def _collect(
    otx: Any,
    state: Dict[str, Any],
    caplog,
    *,
    limit: Optional[int],
    baseline: bool = False,
    max_pages: int = 25,
    page_size: int = 100,
    writer: Any = None,
    sleeps: Optional[List[float]] = None,
    push_to_misp: bool = True,
    sleep: Optional[Callable[[float], None]] = None,
) -> _Result:
    """One ``collect`` run against *otx*, reading and writing the incremental state in *state*; *sleeps*
    collects the pauses the run takes, and *sleep*, when given, takes them (a virtual clock). Each write goes
    through JSON, as ``baseline_checkpoint`` writes the state file, so *state* never shares an object with the
    run: a change the run makes to an entry after writing it reaches *state* only through a later write."""
    collector = OTXCollector.__new__(OTXCollector)
    collector.api_key = "a" * 64
    collector.base_url = "https://otx.example"
    collector.tag = "alienvault_otx"
    collector.session = MagicMock()
    collector.rate_limiter = MagicMock()
    collector._last_http_status = 200
    collector.circuit_breaker = MagicMock()
    collector.source_name = "otx"
    collector.misp_writer = writer if writer is not None else _Writer()
    if isinstance(getattr(collector.misp_writer, "pushed", None), list):
        collector.misp_writer.pushed = []  # the items of this run's pushes
    if isinstance(getattr(collector.misp_writer, "batch_keys", None), list):
        collector.misp_writer.batch_keys = []
    caplog.clear()
    with (
        patch.object(collector, "check_service_available", return_value=True),
        patch.object(otx_collector, "request_with_rate_limit_retries", side_effect=otx.answer),
        patch.object(otx_collector.time, "sleep", side_effect=sleep or (sleeps.append if sleeps is not None else None)),
        patch.object(otx_collector, "get_source_incremental", side_effect=lambda _src: copy.deepcopy(state)),
        patch.object(
            otx_collector,
            "update_source_incremental",
            side_effect=lambda _src, **kw: state.update(json.loads(json.dumps(kw))),
        ),
        patch.object(otx_collector, "OTX_INCREMENTAL_MAX_PAGES", max_pages),
        patch.object(otx_collector, "OTX_INCREMENTAL_OVERLAP_SEC", 300),
        # The look-back reaches every fixture pulse whatever the date the tests run on.
        patch.object(otx_collector, "OTX_INCREMENTAL_LOOKBACK_DAYS", 100000),
        patch.object(otx_collector, "_OTX_INCREMENTAL_PAGE_SIZE", page_size, create=True),
        caplog.at_level("INFO", logger=otx_collector.logger.name),
    ):
        status = collector.collect(limit=limit, push_to_misp=push_to_misp, baseline=baseline, baseline_days=100000)
    pushed = getattr(collector.misp_writer, "pushed", [])
    records = [r for r in caplog.records if r.name == otx_collector.logger.name]
    return _Result(
        status=status,
        processed=[item["pulse_id"] for item in pushed],
        cursor=state.get("otx_last_pulse_modified"),
        messages=[r.getMessage() for r in records],
        warnings=[r.getMessage() for r in records if r.levelname == "WARNING"],
        retry=list(state.get("otx_retry_pulses") or []),
        errors=[r.getMessage() for r in records if r.levelname == "ERROR"],
    )


def _passed_by_the_cursor(read: Iterable[Dict[str, Any]], stored: Iterable[str], cursor: Optional[str]) -> List[str]:
    """The ids of the pulses *read* whose items were not stored and that are modified before *cursor*: the
    cursor has passed them. A pulse modified at the cursor is read again by the next run, whose request starts
    300 s before the cursor, and is not among them."""
    stored_ids = set(stored)
    at = _utc(cursor)
    if at is None:
        return []
    return [p["id"] for p in read if p["id"] not in stored_ids and (dt := _utc(p["modified"])) is not None and dt < at]


# The retry-list counts of a scheduled run that pushed and whose retry list stayed empty (2026-11-02), and the
# window pulses a stopped push held (``held_unsent``, 2026-11-03), none here.
NO_RETRY = {
    "retry_pending": 0,
    "retry_added": 0,
    "retry_fetched": 0,
    "retry_recovered": 0,
    "retry_given_up": 0,
    "retry_not_found": 0,
    "retry_fetch_failed": 0,
    "retry_not_pushed": 0,
    "held_unsent": 0,
}


def _listed(run: "_Result") -> List[str]:
    """The pulse ids on the retry list after *run*, sorted."""
    return sorted(entry["id"] for entry in run.retry)


# --------------------------------------------------------------------------- the double


def test_the_double_answers_in_the_measured_order():
    """Check of the double, not of the collector: it returns the 60 recorded pulses in the recorded order."""
    since = _utc(_RECORDED["request"]["modified_since"])
    assert since is not None
    ordered = _Otx(_recorded(range(60))).ordered(since)
    assert [p["id"] for p in ordered] == IDS
    modified = [row["modified"] for row in ROWS]
    pairs = list(zip(modified[:-1], modified[1:], strict=True))
    assert len(pairs) == 59 and all(a >= b for a, b in pairs)
    assert sum(a == b for a, b in pairs) == 5


# --------------------------------------------------------------------------- the limit


def test_without_a_stored_cursor_the_limit_takes_the_oldest_pulses_of_the_look_back(caplog):
    """No cursor: the look-back window holds 60 pulses and the limit is 20. Before the change the run
    processed the 20 newest and moved the cursor to the newest pulse, past the 40 older ones."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {}
    run = _collect(otx, state, caplog, limit=20)

    assert sorted(run.processed) == sorted(_ids(range(40, 60))), "the 20 oldest pulses"
    assert run.cursor == ROWS[40]["modified"] == "2026-10-28T10:37:12.029000"
    assert _passed_by_the_cursor(_recorded(range(60)), run.processed, run.cursor) == []
    assert run.status["pulse_counts"] == {
        "rows_read": 60,
        "distinct": 60,
        "repeated_rows": 0,
        "processed": 20,
        "without_item": 0,
        "deferred": 40,
        **NO_RETRY,
    }
    deferral = [m for m in run.messages if LIMIT_LOG in m]
    assert deferral == [
        "[PULSES] OTX: 40 pulse(s) deferred to the next run: the run's limit of 20 (EDGEGUARD_INCREMENTAL_LIMIT, "
        "or EDGEGUARD_MAX_ENTRIES when set) counts the pulses modified after the cursor, oldest first, and the "
        "run took those modified up to 2026-10-28T10:37:12.029000; 0 pulse(s) re-read inside the overlap window "
        "were processed outside the limit"
    ]


def test_the_pulses_processed_keep_otx_order(caplog):
    """The limit chooses oldest first; the chosen pulses are processed in OTX's order (newest first), so the
    same-run fold keeps the newest pulse's copy of an item, as a baseline does."""
    run = _collect(_Otx(_recorded(range(60))), {}, caplog, limit=20)
    assert run.processed == _ids(range(40, 60))


def test_with_a_stored_cursor_the_limit_takes_the_oldest_pulses_after_it(caplog):
    """Stored cursor at pulse 50 (2026-10-27T16:44:43.100): the request starts 300 s earlier and reads
    pulses 0-50; pulse 50 is a re-read, and the limit of 20 takes pulses 30-49, the oldest after the cursor.
    Before the change the run took pulses 0-19 and the cursor passed pulses 20-49."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[50]["modified"]}
    run = _collect(otx, state, caplog, limit=20)

    assert sorted(run.processed) == sorted(_ids(range(30, 51)))
    assert run.cursor == ROWS[30]["modified"] == "2026-10-29T00:04:28.370000"
    assert _passed_by_the_cursor(_recorded(range(51)), run.processed, run.cursor) == []
    assert run.status["pulse_counts"]["processed"] == 21
    assert run.status["pulse_counts"]["deferred"] == 30
    assert [m for m in run.messages if LIMIT_LOG in m][0].endswith(
        "; 1 pulse(s) re-read inside the overlap window were processed outside the limit"
    )


def test_the_next_runs_process_the_deferred_pulses(caplog):
    """Three runs with a limit of 20 process the 60 pulses: each takes the 20 oldest after its cursor, and the
    next one starts 300 s before the new cursor; a fourth run re-reads only the two pulses at the cursor.
    Before the change the first run took the 20 newest, the cursor reached the newest pulse, and the later
    runs read only the two pulses of its last 300 s."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {}
    processed: List[str] = []
    cursors: List[Optional[str]] = []
    deferred: List[int] = []
    counted: List[int] = []
    for _ in range(4):
        before = _utc(state.get("otx_last_pulse_modified"))
        run = _collect(otx, state, caplog, limit=20)
        counted.append(
            sum(1 for pid in run.processed if before is None or _utc(ROWS[IDS.index(pid)]["modified"]) > before)
        )
        processed += run.processed
        cursors.append(run.cursor)
        deferred.append(run.status["pulse_counts"].get("deferred"))

    assert set(processed[: 20 + 22 + 22]) == set(IDS), "every pulse by the third run"
    assert cursors == [ROWS[40]["modified"], ROWS[20]["modified"], ROWS[0]["modified"], ROWS[0]["modified"]]
    assert counted == [20, 20, 20, 0], "at most the limit of pulses modified after the cursor, per run"
    assert deferred == [40, 20, 0, 0]


def test_pulses_that_share_the_boundary_value_are_processed_by_the_next_run(caplog):
    """Pulses 5-10: three share 2026-10-31T04:05:01.792, three 2026-10-30T18:01:22.297. With a limit of 2
    the first run takes two of the older three (by id) and the cursor stops at their value; the third is
    read again inside the overlap. Before the change the runs took two of the newer three, the cursor
    stopped at the newer value, and the older three were never processed."""
    otx = _Otx(_recorded(range(5, 11)))
    state: Dict[str, Any] = {}
    older = sorted(_ids(range(8, 11)))
    newer = sorted(_ids(range(5, 8)))

    first = _collect(otx, state, caplog, limit=2)
    assert sorted(first.processed) == older[:2]
    assert first.cursor == "2026-10-30T18:01:22.297000"
    assert first.status["pulse_counts"]["deferred"] == 4

    second = _collect(otx, state, caplog, limit=2)
    assert sorted(second.processed) == sorted(older + newer[:2]), "the tied three re-read, two newer counted"
    assert second.cursor == "2026-10-31T04:05:01.792000"
    assert second.status["pulse_counts"]["deferred"] == 1

    third = _collect(otx, state, caplog, limit=2)
    assert sorted(third.processed) == newer
    assert third.cursor == "2026-10-31T04:05:01.792000"
    assert third.status["pulse_counts"]["deferred"] == 0
    assert set(first.processed + second.processed + third.processed) == set(older + newer)


def _tied(count: int, modified: str, first_n: int) -> List[Dict[str, Any]]:
    """*count* pulses with the ids of fixture rows ``first_n``… and one ``modified`` value."""
    return [
        _pulse(IDS[i], modified, ROWS[i]["created"], i + 1)  # ids and created of the fixture
        for i in range(first_n, first_n + count)
    ]


def test_more_pulses_than_the_limit_with_one_modified_value_do_not_stall_the_runs(caplog):
    """Seven pulses share one ``modified`` value and the limit is 3. The first run takes three (by id) and
    the cursor reaches the value; the next run reads the seven again inside the overlap and processes them
    outside the limit. Before the change every run took the same three (OTX's order) and the other four
    were never processed."""
    otx = _Otx(_tied(7, "2026-10-31T04:05:01.792000", 0))
    state: Dict[str, Any] = {}
    runs = [_collect(otx, state, caplog, limit=3) for _ in range(3)]

    assert sorted(runs[0].processed) == sorted(IDS[:7])[:3]
    assert set(runs[0].processed + runs[1].processed) == set(IDS[:7]), "all seven by the second run"
    assert [r.cursor for r in runs] == ["2026-10-31T04:05:01.792000"] * 3
    assert [r.status["pulse_counts"]["deferred"] for r in runs] == [4, 0, 0]
    assert [r.status["pulse_counts"]["processed"] for r in runs] == [3, 7, 7]


def test_the_cursor_moves_on_past_more_tied_pulses_than_the_limit(caplog):
    """Seven pulses share one value T and two are modified an hour later; the limit is 3. Each run with
    pulses modified after its cursor processes some of them and moves the cursor: None → T → T + 1 h.
    Before the change the first run took the two newer pulses and one of the seven, the cursor reached
    T + 1 h, and the other six were never processed."""
    tied = _tied(7, "2026-10-31T04:05:01.792000", 0)
    later = _tied(2, "2026-10-31T05:05:01.792000", 7)
    otx = _Otx(tied + later)
    state: Dict[str, Any] = {}
    runs = [_collect(otx, state, caplog, limit=3) for _ in range(3)]

    assert [r.cursor for r in runs] == [
        "2026-10-31T04:05:01.792000",
        "2026-10-31T05:05:01.792000",
        "2026-10-31T05:05:01.792000",
    ]
    assert set(runs[0].processed + runs[1].processed) == set(IDS[:9])
    assert [r.status["pulse_counts"]["deferred"] for r in runs] == [6, 0, 0]


def _spaced(count: int, first: str, step_sec: int) -> List[Dict[str, Any]]:
    """*count* pulses with the ids of fixture rows 0… and ``modified`` values *step_sec* apart from *first*."""
    start = datetime.fromisoformat(first)
    return [
        _pulse(IDS[i], (start + timedelta(seconds=step_sec * i)).isoformat(), ROWS[i]["created"], i + 1)
        for i in range(count)
    ]


def test_a_backlog_denser_than_the_limit_per_overlap_is_processed_again_while_it_drains(caplog):
    """The cost the documentation states: nine pulses modified 5 s apart (all inside one 300 s overlap) and a
    limit of 3. Each run counts the three oldest after its cursor and processes again every pulse the earlier
    runs took, because they are re-reads of its overlap: 3, 6, then 9 pulses, and 9 on every run while the
    cursor stays within 300 s of them. No pulse is passed over; the re-reads are the extra work."""
    otx = _Otx(_spaced(9, "2026-10-31T04:00:00.000000", 5))
    state: Dict[str, Any] = {}
    runs = [_collect(otx, state, caplog, limit=3) for _ in range(4)]

    assert [r.status["pulse_counts"]["processed"] for r in runs] == [3, 6, 9, 9]
    assert [r.status["pulse_counts"]["deferred"] for r in runs] == [6, 3, 0, 0]
    assert set(runs[0].processed + runs[1].processed + runs[2].processed) == set(IDS[:9])
    assert [r.cursor for r in runs] == [
        "2026-10-31T04:00:10",
        "2026-10-31T04:00:25",
        "2026-10-31T04:00:40",
        "2026-10-31T04:00:40",
    ]
    assert [m for m in runs[1].messages if LIMIT_LOG in m][0].endswith(
        "; 3 pulse(s) re-read inside the overlap window were processed outside the limit"
    )


def test_overlap_rereads_do_not_take_slots_of_the_limit(caplog):
    """Stored cursor at the three pulses that share 2026-10-31T04:05:01.792 (pulses 5-7): the request reads
    pulses 0-7, the three are re-reads and the limit of 2 takes pulses 4 and 3, the oldest after the cursor.
    Counted toward the limit, the three re-reads would take both slots on every run and the cursor would
    never move. Before the change the run took pulses 0 and 1 (OTX's order) and the cursor passed 2-4."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[5]["modified"]}
    run = _collect(otx, state, caplog, limit=2)

    assert sorted(run.processed) == sorted(_ids(range(3, 8)))
    assert run.cursor == ROWS[3]["modified"] == "2026-11-01T01:03:15.864000"
    assert run.status["pulse_counts"]["processed"] == 5, "two counted, three re-read"
    assert run.status["pulse_counts"]["deferred"] == 3
    assert [m for m in run.messages if LIMIT_LOG in m][0].endswith(
        "; 3 pulse(s) re-read inside the overlap window were processed outside the limit"
    )


def test_an_unreadable_stored_cursor_reads_the_look_back_oldest_first(caplog):
    """A stored cursor that does not parse: the run reads the look-back window and every pulse counts.
    Before the change it took the 20 newest and the cursor passed the 40 older pulses."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": "not-a-timestamp"}
    run = _collect(otx, state, caplog, limit=20)

    assert otx.requests[0]["modified_since"] < "1800", "the look-back window (patched to 100,000 days)"
    assert sorted(run.processed) == sorted(_ids(range(40, 60)))
    assert run.cursor == ROWS[40]["modified"]
    assert run.status["pulse_counts"]["deferred"] == 40


def test_a_pulse_without_a_readable_modified_is_processed_outside_the_limit(caplog):
    """Pulses 50-53 and two without a readable ``modified`` (missing, unparseable), limit 2: the limit takes
    pulses 53 and 52 and the two undated pulses are processed too; they cannot move the cursor. Before the
    change the run took pulses 50 and 51 and the cursor passed 52, 53 and the undated pulses."""
    undated = [
        _pulse("6a0000000000000000000001", None, "2026-10-27T12:00:00.000000", 61),
        _pulse("6a0000000000000000000002", "yesterday", "2026-10-27T12:00:00.000000", 62),
    ]
    otx = _Otx(_recorded(range(50, 54)) + undated)
    state: Dict[str, Any] = {}
    run = _collect(otx, state, caplog, limit=2)

    assert run.processed == [IDS[52], IDS[53], "6a0000000000000000000001", "6a0000000000000000000002"]
    assert run.cursor == ROWS[52]["modified"]
    assert run.status["pulse_counts"]["deferred"] == 2
    assert [m for m in run.messages if LIMIT_LOG in m][0].endswith(
        "; 0 pulse(s) re-read inside the overlap window were processed outside the limit"
    ), "the undated pulses are not re-reads"
    assert run.warnings == [
        "[PULSES] OTX: 2 pulse(s) without a readable 'modified' processed outside the limit; they cannot move "
        "the cursor, so every run that reads them processes them again (ids: 6a0000000000000000000001, "
        "6a0000000000000000000002)"
    ]


def test_pulses_without_a_readable_modified_leave_the_cursor_where_it_is(caplog):
    """Three undated pulses and a limit of 2: all three are processed and the cursor is not written. Before
    the change the run took two of them."""
    otx = _Otx([_pulse(f"6a000000000000000000000{n}", "", "2026-10-27T12:00:00.000000", 60 + n) for n in (1, 2, 3)])
    state: Dict[str, Any] = {"otx_last_pulse_modified": "2026-10-31T04:05:01.792000"}
    run = _collect(otx, state, caplog, limit=2)

    assert len(run.processed) == 3
    assert state == {"otx_last_pulse_modified": "2026-10-31T04:05:01.792000"}
    assert run.status["pulse_counts"]["deferred"] == 0
    assert len(run.warnings) == 1
    assert run.warnings[0].startswith("[PULSES] OTX: 3 pulse(s) without a readable 'modified' processed outside")


def test_one_pulse_without_a_readable_modified_is_logged(caplog):
    """A single undated pulse beside pulses 50-53 (limit 2) gets the WARNING too, with its id. Before the
    change it took one of the two slots and gave no warning."""
    otx = _Otx(_recorded(range(50, 54)) + [_pulse("6a0000000000000000000001", "", "2026-10-27T12:00:00", 61)])
    run = _collect(otx, {}, caplog, limit=2)

    assert run.processed == [IDS[52], IDS[53], "6a0000000000000000000001"]
    assert run.warnings == [
        "[PULSES] OTX: 1 pulse(s) without a readable 'modified' processed outside the limit; they cannot move "
        "the cursor, so every run that reads them processes them again (ids: 6a0000000000000000000001)"
    ]


def test_modified_values_with_and_without_a_zone_are_compared_as_utc(caplog):
    """Three pulses after a stored cursor of 10:50, the middle one written with a zone, and a limit of 1.
    The second run processes the zoned pulse and re-reads the first: its deferral line takes the newest
    ``modified`` of the two. Compared as written, a value with a zone and one without raised ``TypeError``
    before the push, and the run pushed nothing on every run while pulses were deferred."""
    pulses = [
        _pulse(IDS[0], "2026-10-31T11:00:00", ROWS[0]["created"], 1),
        _pulse(IDS[1], "2026-10-31T11:01:00+00:00", ROWS[1]["created"], 2),
        _pulse(IDS[2], "2026-10-31T11:02:00", ROWS[2]["created"], 3),
    ]
    otx = _Otx(pulses)
    state: Dict[str, Any] = {"otx_last_pulse_modified": "2026-10-31T10:50:00"}
    runs = [_collect(otx, state, caplog, limit=1) for _ in range(3)]

    assert [r.status["success"] for r in runs] == [True, True, True]
    assert [r.processed for r in runs] == [[IDS[0]], [IDS[1], IDS[0]], [IDS[2], IDS[1], IDS[0]]]
    assert [r.cursor for r in runs] == ["2026-10-31T11:00:00", "2026-10-31T11:01:00+00:00", "2026-10-31T11:02:00"]
    assert "took those modified up to 2026-10-31T11:01:00+00:00;" in [m for m in runs[1].messages if LIMIT_LOG in m][0]


def test_the_newest_modified_is_returned_as_its_own_value_reads():
    """``_max_pulse_modified_iso`` compares as UTC (a value without a zone is UTC) and returns the newest
    value as it reads, so the stored cursor keeps OTX's form; unreadable values are left out."""
    newest = OTXCollector._max_pulse_modified_iso
    assert newest([{"modified": "2026-10-31T11:00:00"}, {"modified": "2026-10-31T11:01:00+00:00"}]) == (
        "2026-10-31T11:01:00+00:00"
    )
    assert newest([{"modified": "2026-10-31T11:02:00"}, {"modified": "2026-10-31T13:01:00+02:00"}]) == (
        "2026-10-31T11:02:00"
    )
    assert newest([{"modified": "2026-10-31T11:00:00Z"}, {"modified": "later"}, {}]) == "2026-10-31T11:00:00+00:00"
    assert newest([{"modified": "2026-10-31T11:00:00"}, {"modified": "2026-10-31T11:00:00+00:00"}]) == (
        "2026-10-31T11:00:00"
    ), "of equal values, the first"
    assert newest([{"modified": None}]) is None


# --------------------------------------------------------------------------- partial failure


def test_a_partial_failure_advances_the_cursor_and_lists_the_pulse_with_an_unstored_item(caplog):
    """Pulses 50-55 and a limit of 3: the run takes 55, 54 and 53, and pulse 53's item is not stored (listed).
    The cursor advances to pulse 53, the newest processed, and pulse 53 goes on the retry list; the next run
    reads pulse 53 again inside the overlap (modified at the cursor), stores it and takes it off the list,
    without a request by id. Before the retry list the cursor stopped below pulse 53 (at 54)."""
    otx = _Otx(_recorded(range(50, 56)))
    state: Dict[str, Any] = {}
    run = _collect(otx, state, caplog, limit=3, writer=_Writer(failing=[IDS[53]]))

    assert sorted(run.processed) == sorted(_ids([53, 54, 55]))
    assert run.cursor == ROWS[53]["modified"] == "2026-10-27T16:30:12.295000"
    assert _listed(run) == [IDS[53]]
    assert all(_utc(ROWS[i]["modified"]) > _utc(run.cursor) for i in (50, 51, 52)), "the deferred pulses"
    assert run.status["pulse_counts"]["deferred"] == 3
    assert run.status["success"] is False

    later = _collect(otx, state, caplog, limit=3)
    assert IDS[53] in later.processed and otx.by_id_requests == []
    assert later.retry == [] and later.status["pulse_counts"]["retry_recovered"] == 1


@pytest.mark.parametrize("every_item_fails", [False, True], ids=["two pulses fail", "every item fails at the event"])
def test_an_undated_pulse_with_an_unstored_item(caplog, every_item_fails):
    """The stored cursor is at pulse 55, and the run processes pulses 50-55 and one pulse without a readable
    ``modified``. When the items of that pulse and of pulse 52 are not stored while the others are, the cursor
    advances to pulse 50 and both go on the retry list, the undated one by its id alone (no ``modified``).
    When every item fails at its MISP event (a whole-push failure), the cursor stays where it was (guard,
    unchanged rule): the undated held pulse cannot be placed against it (``_pulses_before_oldest``), and no
    pulse goes on the list."""
    undated = "6a0000000000000000000001"
    otx = _Otx(_recorded(range(50, 56)) + [_pulse(undated, None, "2026-10-27T12:00:00", 61)])
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[55]["modified"]}
    failing = [undated, *_ids(range(50, 56))] if every_item_fails else [undated, IDS[52]]
    run = _collect(otx, state, caplog, limit=10, writer=_Writer(failing=failing, at_the_event=every_item_fails))

    assert sorted(run.processed) == sorted(_ids(range(50, 56)) + [undated])
    if every_item_fails:
        assert run.status["failed"] == 7
        assert state == {"otx_last_pulse_modified": ROWS[55]["modified"]}
    else:
        assert run.status["failed"] == 2
        assert run.cursor == ROWS[50]["modified"]
        assert _listed(run) == sorted([undated, IDS[52]])
        assert "modified" not in next(e for e in run.retry if e["id"] == undated)


def test_while_an_item_fails_on_every_run_the_runs_move_on_and_retry_its_pulse_by_id(caplog):
    """The 60 pulses, a limit of 20, and pulse 45's item not stored on the first three runs. Run 1 takes pulses
    40-59, the cursor advances to pulse 40 and pulse 45 goes on the retry list; runs 2 and 3 take the newer
    pulses (20-39, then 0-19, each with its re-reads) and fetch pulse 45 by id, which fails again (attempts 2
    and 3, the first failure kept). Run 4, the item stored, fetches it once more and takes it off the list.
    Before the retry list the cursor stayed below pulse 45 and each run took the same 20 oldest pulses after it
    while 0-25 waited."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {}
    held = [_collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[45]])) for _ in range(3)]

    assert [sorted(set(r.processed) - {IDS[45]}) for r in held] == [
        sorted(set(_ids(range(40, 60))) - {IDS[45]}),
        sorted(_ids(range(20, 42))),
        sorted(_ids(range(0, 22))),
    ], "each window with its re-reads (41 and 21 lie within 300 s of the cursor)"
    assert [r.cursor for r in held] == [ROWS[40]["modified"], ROWS[20]["modified"], ROWS[0]["modified"]]
    assert otx.by_id_requests == [IDS[45], IDS[45]]
    assert [[(e["id"], e["attempts"]) for e in r.retry] for r in held] == [[(IDS[45], n)] for n in (1, 2, 3)]
    assert len({e["first_failed_at"] for r in held for e in r.retry}) == 1, "the first failure is kept"
    assert [r.status["pulse_counts"]["retry_fetched"] for r in held] == [0, 1, 1]

    cleared = _collect(otx, state, caplog, limit=20)
    assert otx.by_id_requests == [IDS[45]] * 3
    assert cleared.retry == [] and cleared.status["pulse_counts"]["retry_recovered"] == 1
    assert cleared.cursor == ROWS[0]["modified"], "a retried pulse never moves the cursor"


# --------------------------------------------------------------------------- items MISP already holds


def test_with_a_stored_cursor_a_push_of_items_misp_holds_advances_the_cursor(caplog):
    """Stored cursor at pulse 59, a limit of 20. MISP already holds the items of pulses 39-59 (an additive
    baseline stored them and kept the older cursor); pulses 0-38 are new. Run 1 takes pulses 39-58 (and pulse
    59 as a re-read), its push returns (0, 0), and the cursor advances to pulse 39; run 2 takes the new pulses
    19-38 and run 3 the rest. The cursor used to move only after a push that stored an item; with the limit
    taking the oldest pulses first, every run would then take pulses 39-58 again, each run passing, and pulses
    0-38 would never be processed."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"]}
    writer = _HoldingWriter(held=[_value(i) for i in range(39, 60)])
    runs = [_collect(otx, state, caplog, limit=20, writer=writer) for _ in range(3)]

    assert sorted(runs[0].processed) == sorted(_ids(range(39, 60)))
    assert writer.counts == [(0, 0), (20, 0), (19, 0)]
    assert [r.cursor for r in runs] == [ROWS[39]["modified"], ROWS[19]["modified"], ROWS[0]["modified"]]
    assert sorted(runs[1].processed) == sorted(_ids(range(19, 40))), "the new pulses 19-38, and 39 re-read"
    assert {_value(i) for i in range(39)} <= writer.held, "every new pulse stored by the third run"
    assert [r.status["success"] for r in runs] == [True, True, True]
    assert [r.status["pulse_counts"]["deferred"] for r in runs] == [39, 19, 0]


def test_without_a_stored_cursor_a_push_of_items_misp_holds_advances_the_cursor(caplog):
    """No stored cursor, the 60 pulses and a limit of 20. MISP already holds the items of the 20 oldest
    (pulses 40-59); pulses 0-39 are new. Run 1 takes pulses 40-59, its push returns (0, 0), and the cursor
    moves to pulse 40; run 2 takes the new pulses 20-39. Were the cursor to move only after a push that stored
    an item (the earlier rule), no cursor would be stored and every run would take pulses 40-59 again from the
    look-back."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {}
    writer = _HoldingWriter(held=[_value(i) for i in range(40, 60)])
    runs = [_collect(otx, state, caplog, limit=20, writer=writer) for _ in range(3)]

    assert sorted(runs[0].processed) == sorted(_ids(range(40, 60)))
    assert writer.counts == [(0, 0), (20, 0), (20, 0)]
    assert [r.cursor for r in runs] == [ROWS[40]["modified"], ROWS[20]["modified"], ROWS[0]["modified"]]
    assert sorted(runs[1].processed) == sorted(_ids(range(20, 42))), "the new pulses 20-39, and 40-41 re-read"
    assert {_value(i) for i in range(40)} <= writer.held


@pytest.mark.parametrize("stored", [0, 1, 5], ids=["stores nothing", "stores one item", "stores five items"])
def test_a_push_with_failures_advances_the_cursor_and_lists_the_failed_pulses_whatever_it_stored(caplog, stored):
    """Stored cursor at pulse 59, a limit of 20: the run takes pulses 39-58 (and pulse 59 as a re-read). MISP
    already holds the items of pulses 49-59, the items of pulses 44-48 fail (listed as unstored), and of pulses
    39-43 the push stores the first *stored* while MISP holds the others. Whatever the push stored, MISP stored
    or held items of the push, so the failure is one of items, not of the push: the cursor advances to pulse 39
    and pulses 44-48 go on the retry list. The next run, the items storable again, takes the newer pulses 19-38
    and fetches pulses 44-48 by id, stores them and empties the list.

    The case that stores nothing is the stall of the previous rule: its push returns (0, 5), and the cursor
    stopped below pulse 48 on every run while the newer pulses waited."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"]}
    held = [_value(i) for i in range(39 + stored, 44)] + [_value(i) for i in range(49, 60)]
    writer = _HoldingWriter(held=held, failing=_ids(range(44, 49)))
    run = _collect(otx, state, caplog, limit=20, writer=writer)

    assert sorted(run.processed) == sorted(_ids(range(39, 60)))
    assert writer.counts == [(stored, 5)]
    assert run.cursor == ROWS[39]["modified"]
    assert _listed(run) == sorted(_ids(range(44, 49)))
    assert {(e["attempts"], e["modified"]) for e in run.retry} == {(1, ROWS[i]["modified"]) for i in range(44, 49)}
    assert run.status["success"] is False, "the failures still fail the run"
    assert run.status["pulse_counts"]["retry_added"] == 5

    writer.failing = set()
    retried = _collect(otx, state, caplog, limit=20, writer=writer)
    assert sorted(otx.by_id_requests) == sorted(_ids(range(44, 49)))
    assert set(_ids(range(19, 40))) <= set(retried.processed)
    assert {_value(i) for i in range(19, 49)} <= writer.held
    assert retried.retry == [] and retried.cursor == ROWS[19]["modified"]


@pytest.mark.parametrize("stored", [False, True], ids=["stores nothing", "stores the other items"])
def test_an_unstored_item_that_names_no_pulse_leaves_the_cursor(caplog, stored):
    """Guard (unchanged rule, passes before the change too): the stored cursor is at pulse 55, and the run
    processes pulses 50-55 and a pulse without an id (OTX's rows without an id are kept), whose item is not
    stored and is listed. The item cannot be placed against the cursor or fetched by id, so the cursor stays
    where it is and no pulse goes on the retry list, whether the push stored the other items or MISP already
    held them; skipping the item instead, the cursor would move to pulse 50, past the pulse without an id."""
    nameless = _pulse(None, "2026-10-27T16:00:00", "2026-10-27T12:00:00", 61)
    otx = _Otx(_recorded(range(50, 56)) + [nameless])
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[55]["modified"]}
    held = [] if stored else [_value(i) for i in range(50, 56)]
    writer = _HoldingWriter(held=held, failing=[None])
    run = _collect(otx, state, caplog, limit=10, writer=writer)

    assert sorted(map(str, run.processed)) == sorted(_ids(range(50, 56)) + ["None"])
    assert writer.counts == [(6 if stored else 0, 1)]
    assert state == {"otx_last_pulse_modified": ROWS[55]["modified"]}


@pytest.mark.parametrize("every_item_fails", [False, True], ids=["one item fails", "every item fails"])
def test_a_writer_without_a_list_of_unstored_items_leaves_the_cursor(caplog, every_item_fails):
    """Guard (unchanged rule, passes before the change too): a push with failures whose writer lists no
    unstored items leaves the stored cursor where it is and puts no pulse on the retry list, also when the limit
    deferred pulses, whether the push stored items or none."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[50]["modified"]}
    run = _collect(otx, state, caplog, limit=20, writer=_WriterWithoutList(every_item_fails))

    assert state == {"otx_last_pulse_modified": ROWS[50]["modified"]}
    assert run.status["failed"] == (len(run.processed) if every_item_fails else 1)


# --------------------------------------------------------------------------- the page ceiling


def test_a_ceiling_with_a_full_last_page_warns_that_the_oldest_pulses_were_not_read(caplog):
    """The recorded answer of 2026-11-02 read with a ceiling of 3 pages of 20: the third page is full and
    OTX reported 370 pulses. Before the change the run gave no warning."""
    state: Dict[str, Any] = {}
    run = _collect(_RecordedPages(), state, caplog, limit=200, max_pages=3, page_size=20)

    assert run.warnings == [
        "OTX incremental stopped at its page ceiling (EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES=3, 20 per page): "
        "60 distinct pulses read of 370 that OTX reported for the window. OTX returns the newest-modified pulses "
        "first, so the pulses not read are the oldest of the window, and any advance of the cursor passes them; "
        "raise EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES or run a baseline to read them"
    ]
    assert run.cursor == ROWS[0]["modified"]
    assert run.status["pulse_counts"]["processed"] == 60
    assert not any(LIMIT_LOG in m for m in run.messages), "nothing deferred, no deferral line"


def test_a_ceiling_with_a_full_last_page_warns_without_a_reported_count(caplog):
    """The recorded pages without OTX's ``count``: the full third page alone tells that the window goes on.
    Before the change the run gave no warning."""
    run = _collect(_RecordedPages(with_count=False), {}, caplog, limit=200, max_pages=3, page_size=20)
    assert run.warnings == [
        "OTX incremental stopped at its page ceiling (EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES=3, 20 per page): "
        "60 distinct pulses read. OTX returns the newest-modified pulses first, so the pulses not read are the "
        "oldest of the window, and any advance of the cursor passes them; raise "
        "EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES or run a baseline to read them"
    ]


def test_a_ceiling_with_a_short_last_page_warns_when_otx_reports_more_pulses(caplog):
    """The third recorded page short of one row while OTX reports more pulses than were read: the window
    was not read to its end. Before the change the run gave no warning."""
    run = _collect(_RecordedPages(drop=[59]), {}, caplog, limit=200, max_pages=3, page_size=20)
    assert len(run.warnings) == 1
    assert run.warnings[0].startswith(
        "OTX incremental stopped at its page ceiling (EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES=3, 20 per page): "
        "59 distinct pulses read of 370 that OTX reported for the window."
    )


def test_a_ceiling_with_a_repeated_row_compares_otx_count_with_the_distinct_pulses(caplog):
    """The third recorded page short of pulses 58 and 59 and repeating the first row of page 2, with OTX
    reporting 59 pulses: 59 rows read, 58 distinct pulses. The count equals the rows read but not the
    distinct pulses, so one pulse of the window was not read, and the run warns. Before the change the run
    gave no warning."""
    otx = _RecordedPages(drop=[58, 59])
    otx.pages[2].append(copy.deepcopy(otx.pages[1][0]))
    otx.count = 59
    run = _collect(otx, {}, caplog, limit=200, max_pages=3, page_size=20)

    assert run.status["pulse_counts"]["rows_read"] == 59
    assert run.status["pulse_counts"]["distinct"] == 58
    ceiling = [w for w in run.warnings if w.startswith("OTX incremental stopped at its page ceiling")]
    assert len(ceiling) == 1
    assert "58 distinct pulses read of 59 that OTX reported for the window." in ceiling[0]


def test_a_ceiling_with_a_short_last_page_and_no_more_pulses_does_not_warn(caplog):
    """Guard (passes before the change too): 50 pulses in pages of 20 under a ceiling of 3 pages; the third
    page holds the last 10 and OTX reports 50. The window was read to its end."""
    run = _collect(_Otx(_recorded(range(50))), {}, caplog, limit=200, max_pages=3, page_size=20)
    assert run.warnings == []
    assert run.status["pulse_counts"]["distinct"] == 50


def test_a_window_read_before_the_ceiling_does_not_warn(caplog):
    """Guard (passes before the change too): 60 pulses in pages of 20 under a ceiling of 4 pages; the
    fourth page, the last the ceiling allows, is empty, so the run read the window to its end."""
    run = _collect(_Otx(_recorded(range(60))), {}, caplog, limit=200, max_pages=4, page_size=20)
    assert run.warnings == []
    assert run.status["pulse_counts"]["distinct"] == 60


def test_the_scheduled_fetch_asks_for_pages_of_the_page_size(caplog):
    """The page size of the fetch is the one the ceiling check compares the last page with. Before the
    change the fetch asked for 100 pulses per page whatever the setting (there was none)."""
    otx = _Otx(_recorded(range(60)))
    _collect(otx, {}, caplog, limit=200, max_pages=25, page_size=20)
    assert [(r["page"], r["limit"]) for r in otx.requests] == [(1, 20), (2, 20), (3, 20), (4, 20)]


def test_without_a_limit_a_scheduled_run_processes_every_pulse_read(caplog):
    """Guard (passes before the change too): ``EDGEGUARD_INCREMENTAL_LIMIT=0`` (no limit) processes all 60
    pulses in OTX's order, defers none and moves the cursor to the newest."""
    with patch.object(otx_collector, "resolve_collection_limit", return_value=None):
        run = _collect(_Otx(_recorded(range(60))), {}, caplog, limit=None)
    assert run.processed == IDS
    assert run.cursor == ROWS[0]["modified"]
    assert run.status["pulse_counts"].get("deferred", 0) == 0


# --------------------------------------------------------------------------- the baseline


def test_a_baseline_keeps_otx_order_and_leaves_the_cursor(caplog):
    """Guard (the baseline is unchanged; passes before the change too except for the new ``deferred`` key):
    a baseline with a limit of 20 processes the first 20 pulses in OTX's order and never writes the cursor."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": "2026-10-01T00:00:00"}
    run = _collect(otx, state, caplog, limit=20, baseline=True)

    assert run.processed == _ids(range(20))
    assert state == {"otx_last_pulse_modified": "2026-10-01T00:00:00"}
    assert not any(LIMIT_LOG in m for m in run.messages)
    assert run.status["pulse_counts"]["deferred"] == 0


def test_the_look_back_reaches_the_fixture_whatever_the_date():
    """Check of the test set-up: the patched look-back starts before the oldest fixture pulse."""
    oldest = _utc(ROWS[-1]["modified"])
    assert oldest is not None
    assert datetime.now(timezone.utc) - timedelta(days=100000) < oldest
