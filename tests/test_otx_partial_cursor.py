"""OTX incremental cursor after a partial MISP push failure (2026-10).

``OTXCollector.collect`` advanced the cursor, on a push with failures and successes, to the newest
``modified`` among the pulses of ``unique[:success]``: the first ``success`` items by position. The
writer pushes batches in order and counts only the attributes it stored, so when an earlier batch
failed (or items were already present) those first items included the failed batch's pulses, the
cursor passed them and the next run (``modified_since`` = cursor - 300 s) never read them again.

The writer now lists the items MISP did not store (``MISPWriter.last_push_unstored_items``): their
batch failed (HTTP 4xx, or 429 / 5xx after the retries), their event lookup failed, or their source's
conversion drop is systemic (a payload the collector no longer reads, counted as failed). The cursor
stops below the oldest pulse holding one. A value MISP can never store (4-byte characters) and a
single record no attribute can be built from are counted as failed or reported but not listed.

The clean push, the single bad record and the failed event lookup are guards for the bookkeeping:
before the change the cursor was already right on the clean push, the event lookup test reads the
writer only, and the single bad record guards the share rule (``CONVERT_FAILED_MIN_SHARE``). Each
guard says so in its docstring.

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


def test_a_failed_first_batch_keeps_the_cursor_before_its_pulse():
    # Oldest first: P1 (failed batch), P2, P3 (stored). Before the fix the cursor reached P2 (10:00).
    misp = _Misp(failing_batches=(1,))
    writer = _writer(misp)
    status, cursor = _run(_three("oldest first"), writer)

    assert "198.51.100.1" not in misp.stored and "198.51.100.2" not in misp.stored
    assert cursor == {}, "no pulse is older than P1: the cursor stays and the next run reads P1 again"
    assert status["success"] is False
    assert writer.last_push_unstored_items == [0, 1]  # P1's two items


def test_a_failed_middle_batch_stops_the_cursor_at_the_older_pulse():
    # Newest first: P3 (stored), P2 (failed batch), P1 (stored). Before the fix the cursor reached P3 (12:00).
    misp = _Misp(failing_batches=(2,))
    writer = _writer(misp)
    _status, cursor = _run(_three("newest first"), writer)

    assert "198.51.100.3" not in misp.stored and "198.51.100.4" not in misp.stored
    assert cursor == {"otx_last_pulse_modified": P1[1]}, "below P2 (10:00): the next run reads P2 again"
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


def test_a_batch_answering_5xx_after_the_retries_stops_the_cursor_at_the_older_pulse():
    # Newest first: P3 (stored), P2 (HTTP 500 on every attempt, the hosted failure mode), P1 (stored).
    misp = _Misp(refused_values=("198.51.100.3",))
    writer = _writer(misp)
    with patch("collectors.collector_utils.time.sleep"):
        _status, cursor = _run(_three("newest first"), writer)

    assert misp.refused_attempts == 5, "the first attempt and four retries"
    assert "198.51.100.3" not in misp.stored and "198.51.100.4" not in misp.stored
    assert writer.last_push_unstored_items == [2, 3]
    assert cursor == {"otx_last_pulse_modified": P1[1]}


def test_a_systemic_conversion_drop_holds_the_cursor():
    # Newest first: P3 and P2 carry indicators no attribute can be built from (4 of OTX's 6 items, a
    # systemic drop: counted as failed), P1 is stored. The cursor stays below P2 until the collector
    # reads the payload again; listing nothing, it reached P3 and the next runs never read P2 or P3.
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
    assert cursor == {"otx_last_pulse_modified": P1[1]}


def test_a_single_record_no_attribute_can_be_built_from_does_not_hold_the_cursor():
    """Guard for the bookkeeping: drops below ``CONVERT_FAILED_MIN_SHARE`` are not listed.

    Newest first: P3 (stored), P2 (failed batch), P1 with one stored indicator and one no attribute
    can be built from (1 of 6 items: reported, not counted as failed). Only P2's items are listed and
    the cursor reaches P1; with the single bad record listed, it would stay before P1.
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
    assert writer.last_push_unstored_items == [2, 3]
    assert cursor == {"otx_last_pulse_modified": P1[1]}


def _indicator(value: str, tag: str) -> Dict[str, Any]:
    return {"indicator_type": "ip", "value": value, "tag": tag, "zone": ["global"], "confidence_score": 0.5}


@pytest.mark.parametrize(
    "event_error",
    [("lookup", 503), ("create", 403)],
    ids=["lookup answers 503 after the retries", "creation refused (no event id)"],
)
def test_a_failed_event_lookup_lists_the_items_of_its_group(event_error):
    """Guard for the bookkeeping: the items of a group whose event lookup or creation failed are listed.

    Two source groups, interleaved: the second source's event cannot be looked up (HTTP 503 on every
    attempt, raised after the retries) or created (HTTP 403, no event id). Its items are listed by
    their positions; the first source's items are stored. An OTX push is one group per UTC day, so
    such a failure stores nothing of it and the cursor stays (``success`` 0); a run that crosses
    midnight pushes two groups, and the listed positions then hold the cursor as in the batch tests.
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


def test_an_item_shared_by_two_pulses_holds_the_cursor_below_both():
    # The newer pulse lists the failed batch's IOC too (folded into the kept item as ``report_ids``).
    p1 = _pulse(*P1, ["198.51.100.1", "198.51.100.2"])
    p2 = _pulse(*P2, ["198.51.100.3", "198.51.100.4"])
    p3 = _pulse(*P3, ["198.51.100.5", "198.51.100.3"])
    misp = _Misp(failing_batches=(2,))  # [.1, .2] stored, [.3, .4] failed, [.5] stored
    _status, cursor = _run([p1, p2, p3], _writer(misp))

    assert cursor == {"otx_last_pulse_modified": P1[1]}


def test_a_writer_that_does_not_list_unstored_items_leaves_the_cursor():
    """A writer that gives no list of unstored items (here a double): the failed items are unknown."""
    writer = MagicMock()
    writer.push_items.return_value = (4, 2)
    _status, cursor = _run(_three("newest first"), writer)

    assert cursor == {}
