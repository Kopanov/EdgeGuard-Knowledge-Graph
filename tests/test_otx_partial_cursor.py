"""OTX incremental cursor after a partial MISP push failure (2026-10).

``OTXCollector.collect`` advanced the cursor, on a push with failures and successes, to the newest
``modified`` among the pulses of ``unique[:success]``: the first ``success`` items by position. The
writer pushes batches in order and counts only the attributes it stored, so when an earlier batch
failed (or items were already present) those first items included the failed batch's pulses, the
cursor passed them and the next run (``modified_since`` = cursor - 300 s) never read them again.

The writer lists the items MISP did not store (``MISPWriter.last_push_unstored_items``): their
batch failed (HTTP 4xx, or 429 / 5xx after the retries), their event lookup failed, or their source's
conversion drop is systemic (a payload the collector no longer reads, counted as failed). A value MISP can
never store (4-byte characters) and a single record no attribute can be built from are counted as failed or
reported but not listed. Among the listed items, ``last_push_event_failed_items`` names those that failed at
their MISP event, which no batch carried (2026-11-02).

A push of items MISP already holds returns (0, 0), and the cursor advances after it as after any push
without failures (2026-11-02). After a push with failures in batches MISP answered, the cursor advances too
and the pulses of the listed items go on the retry list (``otx_retry_pulses``), which later runs fetch by id;
the cursor stopped below the oldest such pulse before, and with the oldest-first limit a pulse whose item kept
failing held every newer pulse back. When every listed item failed at its event (MISP unreachable, the day's
event failing), the cursor stops below the oldest pulse with a listed item and no pulse goes on the list. A
batch whose event id is empty once sanitised sends no request and counts as failed, its items listed as failed
at the event; it returned (0, 0), the count of a batch MISP already held.

The scheduled-run tests at the end run ``MISPWriter`` against the OTX double and the fixture pulses of
``test_otx_incremental_order.py``, with a stored cursor and a limit, over several runs.

The clean push, the single bad record and the failed event lookup are guards for the bookkeeping:
before the change the cursor was already right on the clean push, the event lookup test reads the
writer only (its list of the failures at the event is new), and the single bad record guards the share
rule (``CONVERT_FAILED_MIN_SHARE``). Each guard says so in its docstring.

The MISP double answers as MISP 2.5 does: an empty attribute listing, event lookup and creation, and
the event edit returning the stored event (HTTP 200), a validation error (HTTP 400) or a server error
(HTTP 500).
"""

import os
import sys
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest  # noqa: E402
import requests  # noqa: E402
from test_otx_incremental_order import ROWS, _collect, _ids, _Otx, _recorded, _value  # noqa: E402  (its OTX harness)

from collectors import misp_writer as mw  # noqa: E402
from collectors import otx_collector  # noqa: E402


class _Misp:
    """Empty store; the batch pushes numbered in *failing_batches* answer HTTP 400, the others 200.

    *refused_values*: every attempt to push a batch holding one of these values answers HTTP 500.
    *event_errors*: ``{source tag: (endpoint, HTTP status)}``; the lookup (``"lookup"``) or the
    creation (``"create"``) of that source's event answers the status on every attempt.
    """

    def __init__(self, failing_batches=(), refused_values=(), event_errors=None):
        self.events: Dict[str, str] = {}
        self.batch_no = 0
        self.failing = set(failing_batches)
        self.refused = set(refused_values)
        self.event_errors: Dict[str, Any] = dict(event_errors or {})
        self.refused_attempts = 0
        self.stored: List[str] = []

    def _event_error(self, name: str, endpoint: str) -> Optional[int]:
        for tag, (where, status) in self.event_errors.items():
            if where == endpoint and name.startswith(f"EdgeGuard-{tag}-"):
                return status
        return None

    def post(self, url: str, json: Optional[dict] = None, **_kw: Any):
        body = json or {}
        r = MagicMock()
        r.status_code = 200
        r.text = ""
        r.headers = {}
        if url.endswith("/events/restSearch"):
            name = body["eventinfo"]
            status = self._event_error(name, "lookup")
            if status:
                r.status_code = status
                r.text = "Internal Server Error"
                return r
            eid = self.events.get(name)
            r.json.return_value = {"response": [{"Event": {"id": eid, "info": name}}] if eid else []}
        elif url.endswith("/events"):
            name = body["Event"]["info"]
            status = self._event_error(name, "create")
            if status:
                r.status_code = status
                r.text = '{"errors": "forbidden"}'
                return r
            eid = str(100 + len(self.events))
            self.events[name] = eid
            r.json.return_value = {"Event": {"id": eid, "info": name}}
        elif url.endswith("/attributes/restSearch"):
            r.json.return_value = {"response": {"Attribute": []}}
        elif "/events/" in url:
            attrs = body.get("Attribute") or []
            if self.refused & {a["value"] for a in attrs}:
                self.refused_attempts += 1
                r.status_code = 500
                r.text = "Internal Server Error"
                return r
            self.batch_no += 1
            if self.batch_no in self.failing:
                r.status_code = 400
                r.text = '{"errors": "validation"}'
                r.json.return_value = {"errors": "validation"}
            else:
                self.stored.extend(a["value"] for a in attrs)
                r.json.return_value = {"Event": {"id": url.rsplit("/", 1)[1], "Attribute": [dict(a) for a in attrs]}}
        else:  # pragma: no cover
            raise AssertionError(url)
        return r


def _pulse(pid: str, modified: str, iocs: List[str], ioc_type: str = "IPv4") -> Dict[str, Any]:
    """A pulse with the fields of OTX's ``/api/v1/pulses/subscribed`` answer that the collector reads."""
    return {
        "id": pid,
        "name": f"pulse {pid}",
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
        "cve_references": [],
        "indicators": [
            {"id": 4526831400 + n, "indicator": v, "type": ioc_type, "created": modified, "description": ""}
            for n, v in enumerate(iocs)
        ],
    }


P1 = ("6710e46581edfe9bba0da301", "2026-10-15T08:00:00")
P2 = ("6710e46581edfe9bba0da302", "2026-10-15T10:00:00")
P3 = ("6710e46581edfe9bba0da303", "2026-10-15T12:00:00")


def _unreadable(pulse: Dict[str, Any], *positions: int) -> Dict[str, Any]:
    """The pulse with the indicators at *positions* (all when none given) carrying an object value.

    The shape a payload change gives: ``indicator`` no longer a string, so no MISP attribute can be
    built from the item (``create_attribute`` returns None, the writer logs ``[CONVERT]``).
    """
    for n, ind in enumerate(pulse["indicators"]):
        if not positions or n in positions:
            ind["indicator"] = {"value": ind["indicator"]}
    return pulse


def _three(order: str) -> List[Dict[str, Any]]:
    p1 = _pulse(*P1, ["198.51.100.1", "198.51.100.2"])
    p2 = _pulse(*P2, ["198.51.100.3", "198.51.100.4"])
    p3 = _pulse(*P3, ["198.51.100.5", "198.51.100.6"])
    return [p1, p2, p3] if order == "oldest first" else [p3, p2, p1]


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setattr(mw, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", True)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", "2")  # one pulse per batch below
    monkeypatch.setattr(mw.time, "sleep", lambda _s: None)
    yield


def _collector(writer: Any) -> otx_collector.OTXCollector:
    collector = otx_collector.OTXCollector.__new__(otx_collector.OTXCollector)
    collector.api_key = "a" * 64
    collector.tag = "alienvault_otx"
    collector.session = MagicMock()
    collector.rate_limiter = MagicMock()
    collector._last_http_status = 200
    collector.circuit_breaker = MagicMock()
    collector.misp_writer = writer
    collector.source_name = "otx"
    return collector


def _run(pulses: List[Dict[str, Any]], writer: Any):
    collector = _collector(writer)
    cursor: Dict[str, Any] = {}
    pages = iter([pulses])
    with (
        patch.object(collector, "check_service_available", return_value=True),
        patch.object(collector, "_fetch_pulses", side_effect=lambda **_kw: next(pages, [])),
        patch.object(otx_collector.time, "sleep"),
        patch.object(otx_collector, "get_source_incremental", return_value={}),
        patch.object(otx_collector, "update_source_incremental", lambda _src, **kw: cursor.update(kw)),
        patch.object(otx_collector, "OTX_INCREMENTAL_MAX_PAGES", 10),
    ):
        status = collector.collect(limit=50, push_to_misp=True, baseline=False)
    return status, cursor


def _writer(misp: _Misp) -> mw.MISPWriter:
    writer = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
    writer.session = misp
    return writer


def _listed(state: Dict[str, Any]) -> List[str]:
    """The pulse ids on the retry list in *state* (2026-11-02), sorted."""
    return sorted(entry["id"] for entry in state.get("otx_retry_pulses") or [])


def test_a_failed_first_batch_puts_its_pulse_on_the_retry_list():
    # Oldest first: P1 (failed batch), P2, P3 (stored). Before the unstored list the cursor reached P2 (10:00)
    # by position; then it stayed below P1 until P1's batch was stored. Now the cursor moves on to P3 and P1 goes
    # on the retry list (2026-11-02): MISP stored P2's and P3's items, so the failure is P1's, not the push's.
    misp = _Misp(failing_batches=(1,))
    writer = _writer(misp)
    status, state = _run(_three("oldest first"), writer)

    assert "198.51.100.1" not in misp.stored and "198.51.100.2" not in misp.stored
    assert state["otx_last_pulse_modified"] == P3[1]
    assert _listed(state) == [P1[0]]
    assert status["success"] is False
    assert writer.last_push_unstored_items == [0, 1]  # P1's two items


def test_a_failed_middle_batch_puts_its_pulse_on_the_retry_list():
    # Newest first: P3 (stored), P2 (failed batch), P1 (stored). Before the unstored list the cursor reached
    # P3 (12:00) and nothing named P2 again; now the cursor reaches P3 and P2 goes on the retry list.
    misp = _Misp(failing_batches=(2,))
    writer = _writer(misp)
    _status, state = _run(_three("newest first"), writer)

    assert "198.51.100.3" not in misp.stored and "198.51.100.4" not in misp.stored
    assert state["otx_last_pulse_modified"] == P3[1]
    assert _listed(state) == [P2[0]]
    assert writer.last_push_unstored_items == [2, 3]


def test_a_clean_push_still_advances_the_cursor_to_the_newest_pulse():
    """Guard for the new bookkeeping, not a proof of the defect: the cursor was already right here.

    A push without failures lists no unstored item and the cursor reaches the newest pulse.
    """
    writer = _writer(_Misp())
    status, cursor = _run(_three("newest first"), writer)

    assert writer.last_push_unstored_items == []
    assert status["success"] is True
    assert cursor == {"otx_last_pulse_modified": P3[1]}


def test_a_value_misp_cannot_store_does_not_hold_the_cursor():
    """Values MISP can never store are not listed and do not hold the cursor.

    P1's two URLs hold 4-byte characters and form a batch of their own: the writer skips both and
    counts the batch as failed without a request (``_push_batch`` returns (0, 2)). A later run cannot
    store them either, so they are not listed and the cursor reaches P2. Listed, they would keep the
    cursor before P1 on every run; before the change it went to P1 (the first items by position).
    """
    p1 = _pulse(*P1, ["https://example.test/\U0001f600", "https://example.test/\U0001f601"], ioc_type="URL")
    p2 = _pulse(*P2, ["198.51.100.3", "198.51.100.4"])
    misp = _Misp()
    writer = _writer(misp)
    status, cursor = _run([p1, p2], writer)

    assert misp.stored == ["198.51.100.3", "198.51.100.4"]
    assert status["success"] is False and status["failed"] == 2
    assert writer.last_push_unstored_items == []
    assert cursor == {"otx_last_pulse_modified": P2[1]}


def test_a_batch_answering_5xx_after_the_retries_puts_its_pulse_on_the_retry_list():
    # Newest first: P3 (stored), P2 (HTTP 500 on every attempt, the hosted failure mode), P1 (stored).
    misp = _Misp(refused_values=("198.51.100.3",))
    writer = _writer(misp)
    with patch("collectors.collector_utils.time.sleep"):
        _status, cursor = _run(_three("newest first"), writer)

    assert misp.refused_attempts == 5, "the first attempt and four retries"
    assert "198.51.100.3" not in misp.stored and "198.51.100.4" not in misp.stored
    assert writer.last_push_unstored_items == [2, 3] and writer.last_push_event_failed_items == []
    assert cursor["otx_last_pulse_modified"] == P3[1] and _listed(cursor) == [P2[0]]


def test_a_systemic_conversion_drop_puts_its_pulses_on_the_retry_list():
    # Newest first: P3 and P2 carry indicators no attribute can be built from (4 of OTX's 6 items, a
    # systemic drop: counted as failed and listed), P1 is stored. P2 and P3 go on the retry list and are
    # fetched again until the collector reads the payload again or they are given up; listing nothing,
    # the cursor reached P3 and no run read P2 or P3 again. MISP stored P1's items, so the cursor moves on.
    p3 = _unreadable(_pulse(*P3, ["198.51.100.5", "198.51.100.6"]))
    p2 = _unreadable(_pulse(*P2, ["198.51.100.3", "198.51.100.4"]))
    p1 = _pulse(*P1, ["198.51.100.1", "198.51.100.2"])
    misp = _Misp()
    writer = _writer(misp)
    status, cursor = _run([p3, p2, p1], writer)

    assert misp.stored == ["198.51.100.1", "198.51.100.2"]
    assert status["success"] is False and status["failed"] == 4
    assert writer.stats["items_not_converted_failed"] == 4
    assert writer.last_push_unstored_items == [0, 1, 2, 3]
    assert writer.last_push_event_failed_items == []
    assert cursor["otx_last_pulse_modified"] == P3[1] and _listed(cursor) == sorted([P2[0], P3[0]])


def test_a_single_record_no_attribute_can_be_built_from_does_not_hold_the_cursor():
    """Guard for the bookkeeping: drops below ``CONVERT_FAILED_MIN_SHARE`` are not listed.

    Newest first: P3 (stored), P2 (failed batch), P1 with one stored indicator and one no attribute
    can be built from (1 of 6 items: reported, not counted as failed). Only P2's items are listed;
    P2 goes on the retry list and the cursor reaches P3; with the single bad record listed, P1 would go
    on the list too.
    """
    p3 = _pulse(*P3, ["198.51.100.5", "198.51.100.6"])
    p2 = _pulse(*P2, ["198.51.100.3", "198.51.100.4"])
    p1 = _unreadable(_pulse(*P1, ["198.51.100.1", "198.51.100.2"]), 1)
    misp = _Misp(failing_batches=(2,))
    writer = _writer(misp)
    status, cursor = _run([p3, p2, p1], writer)

    assert "198.51.100.1" in misp.stored
    assert status["failed"] == 2, "the failed batch only"
    assert writer.stats["items_not_converted"] == 1 and writer.stats["items_not_converted_failed"] == 0
    assert writer.last_push_unstored_items == [2, 3] and writer.last_push_event_failed_items == []
    assert cursor["otx_last_pulse_modified"] == P3[1] and _listed(cursor) == [P2[0]]


def _indicator(value: str, tag: str) -> Dict[str, Any]:
    return {"indicator_type": "ip", "value": value, "tag": tag, "zone": ["global"], "confidence_score": 0.5}


@pytest.mark.parametrize(
    "event_error",
    [("lookup", 503), ("create", 403)],
    ids=["lookup answers 503 after the retries", "creation refused (no event id)"],
)
def test_a_failed_event_lookup_lists_the_items_of_its_group(event_error):
    """The items of a group whose event lookup or creation failed are listed, and named as failed at the event.

    Two source groups, interleaved: the second source's event cannot be looked up (HTTP 503 on every
    attempt, raised after the retries) or created (HTTP 403, no event id). Its items are listed by
    their positions, in ``last_push_unstored_items`` and in ``last_push_event_failed_items`` (2026-11-02);
    the first source's items are stored. An OTX push is one group per UTC day, so such a failure stores
    none of the items MISP lacks and lists them all at the event; the cursor then stays below the oldest
    pulse with one of them (``test_a_failure_at_the_event_holds_the_cursor_and_lists_nothing``). The
    listing of the unstored items was a guard before (it passed then); the list of failures at the event
    is new.
    """
    misp = _Misp(event_errors={"threatfox": event_error})
    writer = _writer(misp)
    items = [
        _indicator("198.51.100.1", "alienvault_otx"),
        _indicator("198.51.100.2", "threatfox"),
        _indicator("198.51.100.3", "alienvault_otx"),
        _indicator("198.51.100.4", "threatfox"),
    ]
    with patch("collectors.collector_utils.time.sleep"):
        success, failed = writer.push_items(items)

    assert (success, failed) == (2, 2)
    assert misp.stored == ["198.51.100.1", "198.51.100.3"]
    assert writer.last_push_unstored_items == [1, 3]
    assert writer.last_push_event_failed_items == [1, 3]


def test_an_item_shared_by_two_pulses_puts_both_on_the_retry_list():
    # The newer pulse lists the failed batch's IOC too (folded into the kept item as ``report_ids``).
    p1 = _pulse(*P1, ["198.51.100.1", "198.51.100.2"])
    p2 = _pulse(*P2, ["198.51.100.3", "198.51.100.4"])
    p3 = _pulse(*P3, ["198.51.100.5", "198.51.100.3"])
    misp = _Misp(failing_batches=(2,))  # [.1, .2] stored, [.3, .4] failed, [.5] stored
    _status, state = _run([p1, p2, p3], _writer(misp))

    assert state["otx_last_pulse_modified"] == P3[1]
    assert _listed(state) == sorted([P2[0], P3[0]])


PA = ("6710e46581edfe9bba0da30a", "2026-10-15T11:00:00")


@pytest.mark.parametrize("stores", [False, True], ids=["stores nothing", "stores the other items"])
def test_in_otx_order_an_older_pulse_whose_only_item_a_newer_pulse_lists_goes_on_the_retry_list(monkeypatch, stores):
    """OTX's order, newest first: P3 (12:00) lists .5 and .3, PA (11:00) .7, P2 (10:00) only .3, P1 (08:00) .1.
    The same-run fold keeps P3's copy of .3 and names P2 only in its ``report_ids``. MISP refuses .3 (HTTP 500
    on every attempt), so the writer lists it. Whether the push stores the other items or MISP already holds
    them (a first run stored them), MISP stored or held items of the push, so the cursor advances to P3 and both
    pulses the listed item names go on the retry list, P2 through ``report_ids``. Taking the listed item's
    ``pulse_id`` alone, only P3 would go on the list: the cursor passes P2 by two hours, beyond the 300 s
    overlap, and P2's only item would never be read again unless P3 kept listing it. (Before the retry list
    the cursor stopped below P2, at P1, through the same ``report_ids``.)"""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", "1")  # .3 alone in its batch
    p3 = _pulse(*P3, ["198.51.100.5", "198.51.100.3"])
    pa = _pulse(*PA, ["198.51.100.7"])
    p2 = _pulse(*P2, ["198.51.100.3"])
    p1 = _pulse(*P1, ["198.51.100.1"])
    misp = _HoldingMisp(refused_values=("198.51.100.3",))
    if not stores:
        _run([_pulse(*P3, ["198.51.100.5"]), pa, p1], _writer(misp))
        assert sorted(misp.stored) == ["198.51.100.1", "198.51.100.5", "198.51.100.7"]
    writer = _writer(misp)
    counts = _counted(writer)
    with patch("collectors.collector_utils.time.sleep"):
        status, cursor = _run([p3, pa, p2, p1], writer)

    assert counts == [(3 if stores else 0, 1)]
    (listed,) = [writer.last_pushed[pos] for pos in writer.last_push_unstored_items]
    assert (listed["value"], listed["pulse_id"], listed["report_ids"]) == ("198.51.100.3", P3[0], [P2[0]])
    assert status["success"] is False
    assert cursor["otx_last_pulse_modified"] == P3[1]
    assert _listed(cursor) == sorted([P2[0], P3[0]]), "P2 named through the kept item's report_ids"


class _HoldingMisp(_Misp):
    """The double holding the attributes it stored: ``attributes/restSearch`` lists them (one short page,
    so the listing is complete) whatever the filter, so the writer's duplicate checks find them."""

    def __init__(self, **kw: Any):
        super().__init__(**kw)
        self.attributes: List[Dict[str, Any]] = []

    def post(self, url: str, json: Optional[dict] = None, **kw: Any):
        if url.endswith("/attributes/restSearch"):
            r = MagicMock()
            r.status_code = 200
            r.text = ""
            r.headers = {}
            r.json.return_value = {"response": {"Attribute": [dict(a) for a in self.attributes]}}
            return r
        r = super().post(url, json=json, **kw)
        if "/events/" in url and not url.endswith("/events/restSearch") and r.status_code == 200:
            self.attributes.extend(dict(a) for a in (json or {}).get("Attribute") or [])
        return r


def _counted(writer: mw.MISPWriter) -> List[Any]:
    """Record what each ``push_items`` call of *writer* returns. ``writer.pushed`` keeps the items of a run's
    calls (``_collect`` of ``test_otx_incremental_order.py`` empties it before each run and reports their pulses
    as processed); ``writer.last_pushed`` the items of the last call, which ``last_push_unstored_items`` indexes."""
    counts: List[Any] = []
    push = writer.push_items
    writer.pushed = []  # type: ignore[attr-defined]

    def spy(items, *args, **kwargs):
        writer.pushed = [*writer.pushed, *items]  # type: ignore[attr-defined]
        writer.last_pushed = list(items)  # type: ignore[attr-defined]
        counts.append(push(items, *args, **kwargs))
        return counts[-1]

    writer.push_items = spy  # type: ignore[method-assign]
    return counts


def test_a_push_of_items_misp_already_holds_returns_nothing_counted_and_advances_the_cursor():
    """The writer counts an item MISP already holds as neither stored nor failed, so a push of such items
    only returns (0, 0) (what the ``_HoldingWriter`` double of ``test_otx_incremental_order.py`` answers).

    A first run stores the three pulses' six indicators. A second run, without a stored cursor, reads the
    same pulses: the cross-event listing finds every attribute, nothing is looked up, sent or failed, and
    the cursor advances to P3. The cursor used to move only after a push that stored an item, so it stayed;
    with the limit taking the oldest pulses first, the next run would take the same pulses again.
    """
    misp = _HoldingMisp()
    _run(_three("newest first"), _writer(misp))
    assert len(misp.attributes) == 6

    writer = _writer(misp)
    counts = _counted(writer)
    status, cursor = _run(_three("newest first"), writer)

    assert counts == [(0, 0)]
    assert writer.last_push_unstored_items == []
    assert len(misp.attributes) == 6
    assert status["success"] is True
    assert cursor == {"otx_last_pulse_modified": P3[1]}


def test_an_event_id_empty_once_sanitised_counts_the_batch_as_failed_and_holds_the_cursor():
    """MISP answers the creation of the day's event with an id of only whitespace. ``_push_batch`` sanitises
    the id to nothing and sends no request; the batch counts as failed and its items are listed as failed at
    their event, so MISP failed the push as a whole and the cursor stays: the listed items hold it below P1,
    the oldest of the three pulses, and no pulse goes on the retry list.
    Before the change the batch returned (0, 0): the push read as one MISP
    already held, the run passed, and the cursor (now advancing after a push without failures) would pass
    items MISP never received."""

    class _BlankIdMisp(_Misp):
        def post(self, url: str, json: Optional[dict] = None, **kw: Any):
            r = super().post(url, json=json, **kw)
            if url.endswith("/events"):
                name = (json or {})["Event"]["info"]
                self.events[name] = " "
                r.json.return_value = {"Event": {"id": " ", "info": name}}
            return r

    misp = _BlankIdMisp()
    writer = _writer(misp)
    counts = _counted(writer)
    status, cursor = _run(_three("newest first"), writer)

    assert counts == [(0, 6)]
    assert writer.last_push_unstored_items == [0, 1, 2, 3, 4, 5]
    assert writer.last_push_event_failed_items == [0, 1, 2, 3, 4, 5]
    assert misp.stored == [] and misp.batch_no == 0, "no batch was sent"
    assert status["success"] is False
    assert cursor == {}


def test_a_writer_that_does_not_list_unstored_items_leaves_the_cursor():
    """A writer that gives no list of unstored items (here a double): the failed items are unknown."""
    writer = MagicMock()
    writer.push_items.return_value = (4, 2)
    _status, cursor = _run(_three("newest first"), writer)

    assert cursor == {}


# --------------------------------------------------------------------------- scheduled runs, with MISPWriter


class _UnreachableMisp(_HoldingMisp):
    """``_HoldingMisp`` that, while ``unreachable`` is set, answers no request (a connection error on each)."""

    def __init__(self, **kw: Any):
        super().__init__(**kw)
        self.unreachable = False

    def post(self, url: str, json: Optional[dict] = None, **kw: Any):
        if self.unreachable:
            raise requests.exceptions.ConnectionError("MISP unreachable")
        return super().post(url, json=json, **kw)


def _baseline(pulses: List[Dict[str, Any]], misp: _Misp, caplog) -> None:
    """A baseline run into *misp*: it stores the pulses' items and never moves the cursor."""
    state: Dict[str, Any] = {}
    _collect(_Otx(pulses), state, caplog, limit=None, baseline=True, writer=_writer(misp))
    assert state == {}


def _misp_values(misp: _HoldingMisp) -> set:
    return {a["value"] for a in misp.attributes}


def test_a_push_whose_only_failure_is_a_value_misp_cannot_store_advances_the_cursor(caplog):
    """A baseline stored pulses 40-59 and could not store pulse 39's only indicator, a URL with a 4-byte
    character. The scheduled runs start from a cursor at pulse 59 with a limit of 20. Run 1 takes pulses 39-58
    (and pulse 59 as a re-read): MISP holds every item but the URL, which the writer counts as failed and does
    not list, so the push returns (0, 1) and the run fails, but the cursor advances to pulse 39. Run 2 takes the
    new pulses 19-38 (pulse 39 as a re-read, its URL failing again) and run 3 pulses 0-18.

    The gate on main left the cursor after a push with failures that stored nothing, so with the oldest-first
    limit every run would take pulses 39-58 again and fail while pulses 0-38 waited. (On main the limit took the
    newest pulses, the push stored them, and the cursor passed pulses 20-58.)"""
    url = "https://example.test/\U0001f600"
    pulses = _recorded(range(60))
    pulses[39]["indicators"][0].update({"indicator": url, "type": "URL"})
    misp = _HoldingMisp()
    _baseline(pulses[39:], misp, caplog)
    assert _misp_values(misp) == {_value(i) for i in range(40, 60)}

    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"]}
    writer = _writer(misp)
    counts = _counted(writer)
    first = _collect(_Otx(pulses), state, caplog, limit=20, writer=writer)
    assert sorted(first.processed) == sorted(_ids(range(39, 60)))
    assert counts == [(0, 1)] and writer.last_push_unstored_items == []
    assert first.status["success"] is False
    assert first.cursor == ROWS[39]["modified"]

    later = [_collect(_Otx(pulses), state, caplog, limit=20, writer=writer) for _ in range(2)]
    assert counts == [(0, 1), (20, 1), (19, 0)]
    assert [r.cursor for r in later] == [ROWS[19]["modified"], ROWS[0]["modified"]]
    assert {_value(i) for i in range(39)} <= _misp_values(misp), "the new pulses 0-38 are stored"
    assert url not in _misp_values(misp)
    assert [r.status["pulse_counts"]["deferred"] for r in [first, *later]] == [39, 19, 0]


def test_a_failure_at_the_event_holds_the_cursor_whether_or_not_misp_held_items_of_the_push(caplog):
    """A baseline stored pulses 49-59; the scheduled runs start from a cursor at pulse 59 with a limit of 20 and
    take pulses 39-58 (and pulse 59 as a re-read). The first two pushes store nothing.

    Run 1, MISP unreachable: the cross-event listing finds nothing, so every item, those MISP holds included,
    goes to the event lookup, which fails; all 21 items are listed, at the event. MISP failed the push as a
    whole: no pulse goes on the retry list, and no pulse the run processed is older than the oldest pulse with a
    listed item (59, at the cursor), so the cursor stays where it was and the next run reads the window again.

    Run 2, MISP reachable but the lookup of the day's event answering HTTP 503 after the retries: the listing
    finds the items of pulses 49-59, and the items of pulses 39-48 fail at the event. No batch carried a new
    item, so this too is a failure of the push, not of its items: the cursor moves to pulse 49, below pulse 48,
    the oldest pulse with a listed item, and no pulse goes on the list. (The previous rule counted the items
    MISP held and read an item failure: the cursor went to pulse 39 and pulses 39-48 went on the list.)

    Run 3, MISP answering again, takes the oldest pulses after the cursor first, 29-48 (49 re-read), and stores
    them."""
    pulses = _recorded(range(60))
    misp = _UnreachableMisp()
    _baseline(pulses[49:], misp, caplog)
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"]}
    writer = _writer(misp)
    counts = _counted(writer)

    misp.unreachable = True
    with patch("collectors.collector_utils.time.sleep"):
        unreachable = _collect(_Otx(pulses), state, caplog, limit=20, writer=writer)
    assert sorted(unreachable.processed) == sorted(_ids(range(39, 60)))
    assert counts == [(0, 21)] and writer.last_push_unstored_items == list(range(21))
    assert writer.last_push_event_failed_items == list(range(21))
    assert unreachable.status["success"] is False
    assert unreachable.cursor == ROWS[59]["modified"]
    assert unreachable.retry == [] and "otx_retry_pulses" not in state

    misp.unreachable = False
    misp.event_errors = {"alienvault_otx": ("lookup", 503)}
    with patch("collectors.collector_utils.time.sleep"):
        lookup_failed = _collect(_Otx(pulses), state, caplog, limit=20, writer=writer)
    listed = {writer.last_pushed[pos]["pulse_id"] for pos in writer.last_push_unstored_items}
    assert counts[1] == (0, 10) and listed == set(_ids(range(39, 49)))
    assert writer.last_push_event_failed_items == writer.last_push_unstored_items
    assert lookup_failed.status["success"] is False
    assert lookup_failed.cursor == ROWS[49]["modified"]
    assert lookup_failed.retry == [] and "otx_retry_pulses" not in state

    misp.event_errors = {}
    otx = _Otx(pulses)
    answered = _collect(otx, state, caplog, limit=20, writer=writer)
    assert counts[2] == (20, 0) and otx.by_id_requests == []
    assert answered.cursor == ROWS[29]["modified"]
    assert {_value(i) for i in range(29, 49)} <= _misp_values(misp)
