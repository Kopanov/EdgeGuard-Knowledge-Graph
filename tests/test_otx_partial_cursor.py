"""OTX incremental cursor after a partial MISP push failure (2026-10).

``OTXCollector.collect`` advanced the cursor, on a push with failures and successes, to the newest
``modified`` among the pulses of ``unique[:success]``: the first ``success`` items by position. The
writer pushes batches in order and counts only the attributes it stored, so when an earlier batch
failed (or items were already present) those first items included the failed batch's pulses, the
cursor passed them and the next run (``modified_since`` = cursor - 300 s) never read them again.

The writer now lists the items MISP did not store because their batch failed
(``MISPWriter.last_push_unstored_items``), and the cursor stops below the oldest pulse holding one.
A value MISP can never store (4-byte characters) is counted as failed but does not hold the cursor.
Two of the tests, the clean push and the 4-byte value, guard the new bookkeeping: on their inputs the
cursor was already right before the change, and they fail without it only on the missing attribute.

The MISP double answers as MISP 2.5 does: an empty attribute listing, event lookup and creation, and
the event edit returning the stored event (HTTP 200) or a validation error (HTTP 400).
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
    """Empty store; the batch pushes numbered in *failing_batches* answer HTTP 400, the others 200."""

    def __init__(self, failing_batches=()):
        self.events: Dict[str, str] = {}
        self.batch_no = 0
        self.failing = set(failing_batches)
        self.stored: List[str] = []

    def post(self, url: str, json: Optional[dict] = None, **_kw: Any):
        body = json or {}
        r = MagicMock()
        r.status_code = 200
        r.text = ""
        r.headers = {}
        if url.endswith("/events/restSearch"):
            name = body["eventinfo"]
            eid = self.events.get(name)
            r.json.return_value = {"response": [{"Event": {"id": eid, "info": name}}] if eid else []}
        elif url.endswith("/events"):
            name = body["Event"]["info"]
            eid = str(100 + len(self.events))
            self.events[name] = eid
            r.json.return_value = {"Event": {"id": eid, "info": name}}
        elif url.endswith("/attributes/restSearch"):
            r.json.return_value = {"response": {"Attribute": []}}
        elif "/events/" in url:
            self.batch_no += 1
            attrs = body.get("Attribute") or []
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
    """Guard for the new bookkeeping, not a proof of the defect: the cursor was already right here.

    A URL with a 4-byte character is skipped by the writer and counted as failed; a later run cannot
    store it either, so the writer does not list it and it does not hold the cursor at its pulse.
    """
    p1 = _pulse(*P1, ["https://example.test/\U0001f600", "https://example.test/ok-1"], ioc_type="URL")
    p2 = _pulse(*P2, ["198.51.100.3", "198.51.100.4"])
    misp = _Misp()
    writer = _writer(misp)
    _status, cursor = _run([p1, p2], writer)

    assert "https://example.test/ok-1" in misp.stored and "198.51.100.3" in misp.stored
    assert writer.last_push_unstored_items == []
    assert cursor == {"otx_last_pulse_modified": P2[1]}


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
