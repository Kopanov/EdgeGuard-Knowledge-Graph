"""OTX report records: one MISP Event Report per pulse, ``report_pending``, the cursor rule (2026-11-07).

Every pulse a run processes, and every pulse it fetches by id for the retry list or for ``report_pending``, gets
one report record (``report_records.otx_pulse_record``), which ``MISPWriter.push_reports`` writes after the push
that carries the pulse's items, whatever happened to them. The records are built and pushed 100 at a time; after
each batch ``report_records.note_report_push`` keeps the records whose push failed, or that a push did not try, on
``report_pending`` in the OTX incremental state, on baselines and scheduled runs alike. Each run fetches the
pulses of that list by id (the retry list's fetch path) and pushes their records again; a record still failing
``EDGEGUARD_REPORT_PENDING_MAX_DAYS`` after its first failure is given up with ``[REPORT-GAVE-UP]``.

The window's records are pushed before the cursor moves. The cursor passes a pulse whose record MISP does not
hold only once that record is on ``report_pending`` and the list is saved; when the list cannot be saved, the
cursor stops below the oldest such pulse.

The runs use the OTX double and the writer doubles of ``test_otx_incremental_order.py`` (pulses with the ids and
dates OTX answered on 2026-11-02), ``MISPWriter`` itself against the report double of
``tests/report_misp_double.py`` (MISP 2.5.50 answers recorded on 2026-11-07), and the pulse OTX answered by id on
2026-11-02 (``tests/fixtures/otx_pulse_by_id_2026_11_02.json``). Its subscribed copy and its amber variant are
constructed from that answer (``_subscribed_copy``, ``_amber_pulse``): every subscribed pulse recorded so far is
white (``tests/fixtures/otx_pulse_keys_2026_11_07.json``).
"""

from __future__ import annotations

import copy
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from misp_fakes import Response  # noqa: E402
from report_misp_double import URL, ReportMisp  # noqa: E402
from test_otx_incremental_order import ROWS, _collect, _Otx, _pulse, _recorded, _Writer  # noqa: E402

import baseline_checkpoint  # noqa: E402
import report_records as rr  # noqa: E402
from collectors import misp_writer as mw  # noqa: E402
from collectors import otx_collector  # noqa: E402
from collectors.otx_collector import OTXCollector  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_BY_ID = json.loads((_ROOT / "tests" / "fixtures" / "otx_pulse_by_id_2026_11_02.json").read_text(encoding="utf-8"))
SOURCE = "alienvault_otx"
REPORTS_LOGGER = rr.logger.name


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    """The writer's settings of ``test_otx_retry_list.py``, no pause between records, and the report settings
    unset."""
    monkeypatch.setattr(mw, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", True)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.setenv("EDGEGUARD_MISP_REPORT_THROTTLE_SEC", "0")
    for name in (
        "EDGEGUARD_MISP_PUSH_BATCH_SIZE",
        "EDGEGUARD_MISP_EVENT_SPLIT_ABOVE",
        "EDGEGUARD_REPORT_MAX_INDICATORS",
        "EDGEGUARD_REPORT_PENDING_MAX_DAYS",
        "EDGEGUARD_OTX_RETRY_PER_RUN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(mw.time, "sleep", lambda _s: None)


# --------------------------------------------------------------------------- pulses


def _recorded_by_id() -> Dict[str, Any]:
    """The pulse OTX answered by id on 2026-11-02 (its first 6 of 15 indicators, as recorded)."""
    return copy.deepcopy(_BY_ID["by_id"]["pulse"])


def _subscribed_copy(pulse: Dict[str, Any]) -> Dict[str, Any]:
    """*pulse* as the subscribed list answers it, constructed from the keys recorded on 2026-11-07: ``tlp`` for
    ``TLP``, ``extract_source`` and ``more_indicators`` added, the by-id-only keys removed."""
    row = {k: v for k, v in pulse.items() if k not in ("TLP", "author", "groups", "in_group", "is_subscribing")}
    row.update(tlp=pulse["TLP"], extract_source=[], more_indicators=False)
    return row


def _amber_pulse() -> Dict[str, Any]:
    """The amber fixture: the recorded pulse with ``TLP`` amber and two targeted countries (constructed values; no
    amber pulse has been recorded). Its name, tags and references are the recorded ones."""
    pulse = _recorded_by_id()
    pulse["TLP"] = "amber"
    pulse["targeted_countries"] = ["Germany", "France"]
    return pulse


def _pending() -> List[Dict[str, Any]]:
    return rr.load_report_pending(SOURCE)


def _pending_refs() -> List[str]:
    return sorted(e["record_ref"] for e in _pending())


def _ref(pid: str) -> str:
    return f"{SOURCE}:{pid}"


class _RecordWriter(_Writer):
    """The items double of ``test_otx_incremental_order.py`` whose ``push_reports`` fails the records of the pulses
    in *failing_records* (HTTP 500, tried twice) and, with *skip_all*, tries no record (its task's end is near). It
    keeps the records of each call in ``report_batches``, the call's keyword arguments in ``report_calls`` and, with
    *state*, the cursor in that state when each call starts in ``cursor_at_push``."""

    def __init__(self, failing_records=(), skip_all: bool = False, state: Optional[Dict[str, Any]] = None, **kw):
        super().__init__(**kw)
        self.failing_records = set(failing_records)
        self.skip_all = skip_all
        self.state = state
        self.report_batches: List[List[Dict[str, Any]]] = []
        self.report_calls: List[Dict[str, Any]] = []
        self.cursor_at_push: List[Any] = []
        self.liveness_callback = lambda: None

    def push_reports(self, source: str, records: List[Dict[str, Any]], **kw: Any) -> Dict[str, Any]:
        self.report_batches.append(list(records))
        self.report_calls.append({"source": source, **kw})
        if self.state is not None:
            self.cursor_at_push.append(self.state.get("otx_last_pulse_modified"))
        stats: Dict[str, Any] = {"settled": [], "failed": [], "skipped": [], "reports_added": 0, "reports_failed": 0}
        for record in records:
            ref = record["record_ref"]
            if self.skip_all:
                stats["skipped"].append({"record_ref": ref, "reason": "the task's end is near"})
            elif record["record_id"] in self.failing_records:
                stats["failed"].append({"record_ref": ref, "reason": "the add answered HTTP 500", "permanent": False})
                stats["reports_failed"] += 1
            else:
                stats["settled"].append(ref)
                stats["reports_added"] += 1
        stats["reports_skipped"] = len(stats["skipped"])
        return stats

    def pushed_records(self) -> List[Dict[str, Any]]:
        return [r for batch in self.report_batches for r in batch]


# --------------------------------------------------------------------------- the record of a pulse


def _collector() -> OTXCollector:
    collector = OTXCollector.__new__(OTXCollector)
    collector.tag = "alienvault_otx"
    return collector


def test_the_window_copy_and_the_answer_by_id_give_one_record_and_one_digest():
    by_id = _recorded_by_id()
    window = _subscribed_copy(by_id)
    collector = _collector()
    records = [
        rr.otx_pulse_record(p, otx_collector._record_pairs(p, collector.map_indicator_type)) for p in (window, by_id)
    ]
    assert records[0] == records[1]
    record = records[0]
    assert record["record_ref"] == _ref(by_id["id"]) and record["tlp"] == "white"
    assert record["description"] == by_id["description"] and record["title"] == "PSIRT"
    assert record["cve_ids"] == ["CVE-2026-104286"] and record["indicator_count"] == 6


def test_the_record_lists_the_indicators_as_the_writer_stores_the_items():
    """The pairs of the record are the (type, value) of the attributes ``MISPWriter`` makes of the collector's items:
    the recorded pulse with an IPv4, a domain, a URL, an e-mail address, a SHA-256, a lower-case CVE, a JA3 (a type
    the collector does not collect) and a CVE reference added (constructed values). A CVE is upper-cased, as MISP
    stores it, so the CVE indicator and the CVE reference of one id give one pair."""
    pulse = _recorded_by_id()
    pulse["indicators"] += [
        {"indicator": "198.51.100.7", "type": "IPv4"},
        {"indicator": "files.example.net", "type": "domain"},
        {"indicator": "https://files.example.net/a.php?x=1", "type": "URL"},
        {"indicator": "ops@example.net", "type": "email"},
        {"indicator": "a" * 64, "type": "FileHash-SHA256"},
        {"indicator": "cve-2026-0001", "type": "CVE"},
        {"indicator": "e7d705a3286e19ea42f587b344ee6865", "type": "JA3"},
        {"indicator": " bad\x07host.example.net", "type": "domain"},
    ]
    pulse["cve_references"] = ["cve-2026-0001", "CVE-2026-0002"]
    collector = _collector()
    record = rr.otx_pulse_record(pulse, otx_collector._record_pairs(pulse, collector.map_indicator_type))

    items = []
    with patch.object(collector, "_report_actor_reference", return_value=None):
        collector.misp_writer = None
        processed = _process(collector, [pulse])
    writer = mw.MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)
    for item in processed:
        if "indicator_type" in item:
            items.append(writer.create_attribute(item))
        elif item.get("type") == "vulnerability":
            items.append(writer.create_vulnerability_attribute(item))
    stored = sorted({(a["type"], a["value"].upper() if a["type"] == "vulnerability" else a["value"]) for a in items})
    assert [tuple(p) for p in record["indicators"]] == stored
    assert ["vulnerability", "CVE-2026-0002"] in record["indicators"] and record["indicator_count"] == len(stored)
    assert record["cve_ids"] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-104286"]
    assert not any(v == "e7d705a3286e19ea42f587b344ee6865" for _t, v in record["indicators"]), "not collected"
    assert ["domain", "badhost.example.net"] in record["indicators"], "the value the writer sends"


def _process(collector: OTXCollector, pulses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The items a run makes of *pulses* without pushing them (a baseline over their pages)."""
    pages = iter([pulses])
    with (
        patch.object(collector, "check_service_available", return_value=True),
        patch.object(collector, "_fetch_pulses", side_effect=lambda **kw: next(pages, [])),
        patch.object(otx_collector.time, "sleep", lambda *_a, **_k: None),
    ):
        collector.api_key = "a" * 64
        collector.source_name = "otx"
        collector.circuit_breaker = SimpleNamespace(state=SimpleNamespace(name="CLOSED"), record_success=lambda: None)
        return collector.collect(limit=None, push_to_misp=False, baseline=True, baseline_days=730)


# --------------------------------------------------------------------------- one record per pulse, whatever its items


def test_every_pulse_of_a_baseline_gets_one_record_after_the_items(caplog):
    otx = _Otx(_recorded(range(5)))
    state: Dict[str, Any] = {}
    writer = _RecordWriter()
    run = _collect(otx, state, caplog, limit=None, baseline=True, writer=writer)
    assert sorted(r["record_id"] for r in writer.pushed_records()) == sorted(p["id"] for p in otx.pulses)
    assert len(writer.calls) == 1 and len(writer.report_batches) == 1, "the items, then the records"
    assert run.status["report_counts"]["reports_added"] == 5 and run.status["report_counts"]["records"] == 5
    assert _pending() == []


def test_a_record_is_pushed_whatever_happened_to_its_items(caplog):
    """Every item of the window fails at the MISP event (the day's event could not be looked up): the records are
    pushed all the same."""
    pulses = _recorded(range(5))
    writer = _RecordWriter(failing=[p["id"] for p in pulses], at_the_event=True)
    run = _collect(_Otx(pulses), {}, caplog, limit=None, writer=writer)
    assert run.status["success"] is False
    assert sorted(r["record_id"] for r in writer.pushed_records()) == sorted(p["id"] for p in pulses)


def test_a_pulse_without_a_storable_item_still_gets_its_record(caplog):
    """A pulse whose only indicator is of a type the collector does not collect (JA3) yields no item; its record is
    written with an empty indicator list."""
    pulse = _recorded(range(1))[0]
    pulse["indicators"] = [{"indicator": "e7d705a3286e19ea42f587b344ee6865", "type": "JA3"}]
    writer = _RecordWriter()
    run = _collect(_Otx([pulse]), {}, caplog, limit=None, baseline=True, writer=writer)
    assert writer.calls == [] and run.status["pulse_counts"]["without_item"] == 1
    (record,) = writer.pushed_records()
    assert record["record_id"] == pulse["id"] and record["indicators"] == [] and record["indicator_count"] == 0


def test_the_same_pulse_from_the_window_and_a_fetch_by_id_gives_one_record(caplog):
    """Pulse 3 is read in the window and its record is on ``report_pending``: it is not fetched by id and gets one
    record. Pulse 7 is on the retry list and on ``report_pending``, outside the window: it is fetched once, for the
    retry list, and gets one record."""
    pulses = _recorded(range(10))
    otx = _Otx(pulses[:5])
    otx.by_id_only[pulses[7]["id"]] = pulses[7]
    rr.update_report_pending(SOURCE, failed=[(_ref(pulses[3]["id"]), "earlier"), (_ref(pulses[7]["id"]), "earlier")])
    state = {
        "otx_last_pulse_modified": ROWS[4]["modified"],
        "otx_retry_pulses": [
            {"id": pulses[7]["id"], "modified": ROWS[7]["modified"], "first_failed_at": "2026-11-06T00:00:00+00:00"}
        ],
    }
    writer = _RecordWriter()
    _collect(otx, state, caplog, limit=None, writer=writer)
    ids = [r["record_id"] for r in writer.pushed_records()]
    assert sorted(ids) == sorted(set(ids)) and {pulses[3]["id"], pulses[7]["id"]} <= set(ids)
    assert otx.by_id_requests == [pulses[7]["id"]]
    assert _pending() == []


def test_a_record_that_cannot_be_built_counts_as_failed_and_waits_on_report_pending():
    """A pulse id longer than a record id may be (200 characters; a constructed value) fails its record, not the
    run: the other records are pushed, and the failed one goes on ``report_pending``."""
    good, bad = _recorded(range(2))
    bad["id"] = "6a" * 101
    collector = _collector()
    collector.misp_writer = _RecordWriter()
    counts = otx_collector._new_report_counts()
    assert collector._push_report_records([bad, good], counts, set()) == set()
    assert [r["record_id"] for r in collector.misp_writer.pushed_records()] == [good["id"]]
    (entry,) = _pending()
    assert entry["record_ref"] == rr.format_record_ref(SOURCE, bad["id"])
    assert entry["last_reason"] == "the record could not be built (ValueError)"
    assert counts["reports_failed"] == 1 and counts["reports_added"] == 1


def test_a_pulse_listed_twice_in_one_push_gives_one_record():
    pulse = _recorded(range(1))[0]
    collector = _collector()
    collector.misp_writer = _RecordWriter()
    counts = otx_collector._new_report_counts()
    seen: set = set()
    held = collector._push_report_records([pulse, copy.deepcopy(pulse)], counts, seen)
    held |= collector._push_report_records([copy.deepcopy(pulse)], counts, seen)
    assert held == set() and [r["record_id"] for r in collector.misp_writer.pushed_records()] == [pulse["id"]]
    assert counts["records"] == 1


# --------------------------------------------------------------------------- report_pending


def test_a_record_that_fails_on_a_baseline_goes_on_report_pending(caplog):
    pulses = _recorded(range(4))
    writer = _RecordWriter(failing_records=[pulses[2]["id"]])
    run = _collect(_Otx(pulses), {}, caplog, limit=None, baseline=True, writer=writer)
    (entry,) = _pending()
    assert entry["record_ref"] == _ref(pulses[2]["id"]) and entry["attempts"] == 1
    assert entry["last_reason"] == "the add answered HTTP 500" and "last_tried_at" in entry
    assert run.status["report_counts"]["pending"] == 1 and run.status["report_counts"]["reports_failed"] == 1
    assert "otx_retry_pulses" not in baseline_checkpoint.get_source_incremental("otx"), "apart from the retry list"


def test_the_pending_gauges_follow_the_list():
    from prometheus_client import REGISTRY

    import metrics_server  # noqa: F401  (registers the metrics)

    pulses = _recorded(range(3))
    collector = _collector()
    collector.misp_writer = _RecordWriter(failing_records=[pulses[0]["id"], pulses[1]["id"]])
    collector._push_report_records(pulses, otx_collector._new_report_counts(), set())
    assert REGISTRY.get_sample_value("edgeguard_report_pending_records", {"source": SOURCE}) == 2
    collector.misp_writer = _RecordWriter()
    collector._push_report_records(pulses, otx_collector._new_report_counts(), set())
    assert REGISTRY.get_sample_value("edgeguard_report_pending_records", {"source": SOURCE}) == 0


def test_a_run_without_records_still_feeds_the_gauges():
    from prometheus_client import REGISTRY

    import metrics_server  # noqa: F401  (registers the metrics)

    rr.update_report_pending(SOURCE, failed=[(_ref("6ab0000000000000000000aa"), "earlier")])
    metrics_server.record_report_pending(SOURCE, 0, 0.0, 0)  # as after a restart of the metrics process
    collector = _collector()
    counts = otx_collector._new_report_counts()
    collector._settle_report_counts(counts)
    assert REGISTRY.get_sample_value("edgeguard_report_pending_records", {"source": SOURCE}) == 1
    assert counts["pending"] == 1


def test_a_pending_record_is_fetched_by_id_and_settled(caplog):
    pulses = _recorded(range(8))
    otx = _Otx(pulses[:3])
    otx.by_id_only[pulses[6]["id"]] = pulses[6]
    rr.update_report_pending(SOURCE, failed=[(_ref(pulses[6]["id"]), "earlier")])
    writer = _RecordWriter()
    run = _collect(otx, {"otx_last_pulse_modified": ROWS[2]["modified"]}, caplog, limit=None, writer=writer)
    assert otx.by_id_requests == [pulses[6]["id"]]
    assert pulses[6]["id"] in [r["record_id"] for r in writer.pushed_records()]
    assert not any(item["pulse_id"] == pulses[6]["id"] for item in writer.pushed), "its items are not pushed again"
    assert _pending() == [] and run.status["report_counts"]["pending_fetched"] == 1


def test_a_pending_record_whose_pulse_answers_404_leaves_the_list(caplog):
    rr.update_report_pending(SOURCE, failed=[(_ref("6ab0000000000000000000ff"), "earlier")])
    otx = _Otx(_recorded(range(2)))
    run = _collect(otx, {"otx_last_pulse_modified": ROWS[1]["modified"]}, caplog, limit=None, writer=_RecordWriter())
    assert otx.by_id_requests == ["6ab0000000000000000000ff"] and _pending() == []
    assert run.status["report_counts"]["pending_not_found"] == 1
    assert any("answered HTTP 404" in m and "leave report_pending" in m for m in run.warnings)


def test_a_pending_record_whose_fetch_fails_stays_untouched(caplog):
    rr.update_report_pending(SOURCE, failed=[(_ref("6ab0000000000000000000ee"), "earlier")])
    before = _pending()
    otx = _Otx(_recorded(range(2)))
    otx.fetch_errors["6ab0000000000000000000ee"] = 503
    _collect(otx, {"otx_last_pulse_modified": ROWS[1]["modified"]}, caplog, limit=None, writer=_RecordWriter())
    assert _pending() == before


def test_a_record_failing_past_the_limit_is_given_up(caplog):
    """The record of pulse 6 first failed 8 days ago (``EDGEGUARD_REPORT_PENDING_MAX_DAYS`` 7) and fails again when
    this run fetches it by id: it leaves the list with an ERROR ``[REPORT-GAVE-UP]`` and counts as given up."""
    from prometheus_client import REGISTRY

    import metrics_server  # noqa: F401  (registers the metrics)

    pulses = _recorded(range(8))
    ref = _ref(pulses[6]["id"])
    eight_days_ago = datetime.now(timezone.utc) - timedelta(days=8)
    rr.update_report_pending(SOURCE, failed=[(ref, "earlier")], now=eight_days_ago)
    otx = _Otx(pulses[:3])
    otx.by_id_only[pulses[6]["id"]] = pulses[6]
    before = REGISTRY.get_sample_value("edgeguard_report_pending_given_up_total", {"source": SOURCE}) or 0.0
    run = _collect(
        otx,
        {"otx_last_pulse_modified": ROWS[2]["modified"]},
        caplog,
        limit=None,
        writer=_RecordWriter(failing_records=[pulses[6]["id"]]),
    )
    assert _pending() == []
    gave_up = [r.getMessage() for r in caplog.records if r.name == REPORTS_LOGGER and r.levelname == "ERROR"]
    assert len(gave_up) == 1 and gave_up[0].startswith("[REPORT-GAVE-UP] alienvault_otx: 1 report record(s) given up")
    assert ref in gave_up[0]
    assert REGISTRY.get_sample_value("edgeguard_report_pending_given_up_total", {"source": SOURCE}) == before + 1
    assert run.status["report_counts"]["given_up"] == 1


# --------------------------------------------------------------------------- the cursor rule


CURSOR = ROWS[16]["modified"]


def _window(caplog, writer, state):
    """A scheduled run from a cursor at pulse 16 with a limit of 4: pulses 12-15 (16-18 re-read in the overlap)."""
    return _collect(_Otx(_recorded(range(20))), state, caplog, limit=4, writer=writer)


def test_the_window_s_records_are_pushed_before_the_cursor_moves(caplog):
    state: Dict[str, Any] = {"otx_last_pulse_modified": CURSOR}
    writer = _RecordWriter(state=state)
    run = _window(caplog, writer, state)
    assert writer.cursor_at_push == [CURSOR]
    assert run.cursor == ROWS[12]["modified"]


def test_the_cursor_passes_a_pulse_whose_record_failed_once_it_is_on_report_pending(caplog):
    state: Dict[str, Any] = {"otx_last_pulse_modified": CURSOR}
    pulse_14 = ROWS[14]["id"]
    run = _window(caplog, _RecordWriter(failing_records=[pulse_14]), state)
    assert run.cursor == ROWS[12]["modified"]
    assert _pending_refs() == [_ref(pulse_14)]


def test_the_cursor_holds_below_a_pulse_whose_record_could_not_be_saved_on_report_pending(caplog, monkeypatch):
    """The save of ``report_pending`` fails (the state file cannot be written): the record of pulse 14 is neither in
    MISP nor on the list, so the cursor stops below it, at pulse 15, and the next run reads pulse 14 again."""
    _failing_save(monkeypatch)
    state: Dict[str, Any] = {"otx_last_pulse_modified": CURSOR}
    pulse_14 = ROWS[14]["id"]
    run = _window(caplog, _RecordWriter(failing_records=[pulse_14]), state)
    assert run.cursor == ROWS[15]["modified"]
    assert any(m.startswith("[REPORT-PENDING] OTX: report_pending could not be saved") for m in run.errors)
    assert any(f"the cursor moves no further than {ROWS[15]['modified']}" in m for m in run.warnings)
    assert run.status["report_counts"]["pending_saved"] is False


def test_a_save_that_fails_before_any_record_failed_holds_nothing(caplog, monkeypatch):
    """Every record of the window is in MISP: a failed save of the list holds no pulse."""

    def failing(source, **kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(baseline_checkpoint, "update_source_incremental", failing)
    state: Dict[str, Any] = {"otx_last_pulse_modified": CURSOR}
    run = _window(caplog, _RecordWriter(), state)
    assert run.cursor == ROWS[12]["modified"]


def _failing_save(monkeypatch):
    real = baseline_checkpoint.update_source_incremental

    def failing(source, **kw):
        if rr.PENDING_STATE_KEY in kw:
            raise OSError(28, "No space left on device")
        return real(source, **kw)

    monkeypatch.setattr(baseline_checkpoint, "update_source_incremental", failing)


def test_after_a_failure_at_the_event_the_cursor_also_holds_below_an_unsaved_record(caplog, monkeypatch):
    """The items of pulse 12 fail at the MISP event (the cursor stops below pulse 12, at pulse 13) and the record of
    pulse 14 can be neither written nor saved on ``report_pending``: the cursor stops below pulse 14, at pulse 15."""
    _failing_save(monkeypatch)
    state: Dict[str, Any] = {"otx_last_pulse_modified": CURSOR}
    writer = _RecordWriter(failing=[ROWS[12]["id"]], at_the_event=True, failing_records=[ROWS[14]["id"]])
    assert _window(caplog, writer, state).cursor == ROWS[15]["modified"]


class _StoppedWriter(_RecordWriter):
    """The window's push stopped because MISP kept failing before it sent the items of the pulses in *unsent*."""

    def __init__(self, unsent=(), **kw):
        super().__init__(**kw)
        self.unsent = set(unsent)

    def push_items(self, items, batch_key=None, **kw):
        self.pushed += list(items)
        self.last_push_unsent_items = [n for n, item in enumerate(items) if item.get("pulse_id") in self.unsent]
        self.last_push_unstored_items = list(self.last_push_unsent_items)
        self.last_push_event_failed_items = []
        self.last_push_stopped = bool(self.last_push_unsent_items)
        return len(items) - len(self.last_push_unsent_items), len(self.last_push_unsent_items)


def test_after_a_stopped_push_the_cursor_also_holds_below_an_unsaved_record(caplog, monkeypatch):
    """The window's push stopped before the items of pulse 12 (the cursor stops below pulse 12, at pulse 13) and the
    record of pulse 14 can be neither written nor saved: the cursor stops below pulse 14, at pulse 15."""
    _failing_save(monkeypatch)
    state: Dict[str, Any] = {"otx_last_pulse_modified": CURSOR}
    writer = _StoppedWriter(unsent=[ROWS[12]["id"]], failing_records=[ROWS[14]["id"]])
    assert _window(caplog, writer, state).cursor == ROWS[15]["modified"]


def test_the_guards_of_the_two_branches_hold_below_the_items_alone_when_the_records_are_saved(caplog):
    """Without the unsaved record, the same failures hold the cursor below pulse 12 only, at pulse 13."""
    for writer in (
        _RecordWriter(failing=[ROWS[12]["id"]], at_the_event=True, failing_records=[ROWS[14]["id"]]),
        _StoppedWriter(unsent=[ROWS[12]["id"]], failing_records=[ROWS[14]["id"]]),
    ):
        rr.update_report_pending(SOURCE, settled=[_ref(ROWS[14]["id"])])
        state: Dict[str, Any] = {"otx_last_pulse_modified": CURSOR}
        assert _window(caplog, writer, state).cursor == ROWS[13]["modified"]
        assert _ref(ROWS[14]["id"]) in _pending_refs()


# --------------------------------------------------------------------------- batches, deadline and liveness


def _many(count: int) -> List[Dict[str, Any]]:
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    return [
        _pulse(f"6a{n:022x}", (start + timedelta(minutes=n)).isoformat(), start.isoformat(), n % 250)
        for n in range(count)
    ]


def test_the_records_are_pushed_in_batches_each_saved_on_report_pending(caplog, monkeypatch):
    saves: List[int] = []
    real = rr.note_report_push

    def counting(source, stats, **kw):
        saves.append(len(stats.get("settled") or []))
        return real(source, stats, **kw)

    monkeypatch.setattr(rr, "note_report_push", counting)
    writer = _RecordWriter()
    _collect(_Otx(_many(250)), {}, caplog, limit=None, baseline=True, writer=writer)
    assert [len(b) for b in writer.report_batches] == [100, 100, 50]
    assert saves == [100, 100, 50]


def test_after_a_push_that_tried_no_record_the_later_batches_wait_on_report_pending(caplog):
    writer = _RecordWriter(skip_all=True)
    run = _collect(_Otx(_many(250)), {}, caplog, limit=None, baseline=True, writer=writer)
    assert [len(b) for b in writer.report_batches] == [100], "no later batch is pushed"
    entries = _pending()
    assert len(entries) == 250 and not any("last_tried_at" in e for e in entries), "not tried, never given up"
    assert {e["last_reason"] for e in entries} == {"the task's end is near"}
    assert run.status["report_counts"]["reports_skipped"] == 250


def test_push_reports_gets_the_writer_s_liveness_callback(caplog):
    writer = _RecordWriter()
    _collect(_Otx(_recorded(range(3))), {}, caplog, limit=None, baseline=True, writer=writer)
    assert writer.report_calls == [{"source": SOURCE, "liveness_callback": writer.liveness_callback}]


class _Misp(ReportMisp):
    """The report double of ``tests/report_misp_double.py`` that also takes attribute batches (``POST
    /events/<id>``, stored as sent) and answers the cross-event listing with nothing."""

    def __init__(self):
        super().__init__()
        self.attributes: List[Dict[str, Any]] = []

    def _handle(self, method: str, url: str, body: Any):
        path = url.split(self.url, 1)[1]
        if method == "POST" and path == "/attributes/restSearch":
            self.requests.append((method, path, copy.deepcopy(body)))
            return Response(200, {"response": {"Attribute": []}})
        if method == "POST" and path.startswith("/events/") and path[len("/events/") :].isdigit():
            self.requests.append((method, path, copy.deepcopy(body)))
            attrs = copy.deepcopy(body.get("Attribute") or [])
            self.attributes.extend(attrs)
            return Response(200, {"Event": {"id": path.rsplit("/", 1)[1], "Attribute": attrs}})
        return super()._handle(method, url, body)


def _real_writer(misp: _Misp, **kw: Any) -> mw.MISPWriter:
    writer = mw.MISPWriter(url=URL, api_key="test", verify_ssl=True, **kw)
    writer.session = misp
    return writer


def test_the_real_writer_calls_the_liveness_callback_before_each_record(caplog):
    misp = _Misp()
    calls: List[int] = []
    writer = _real_writer(misp, liveness_callback=lambda: calls.append(len(misp.reports)))
    run = _collect(_Otx(_recorded(range(3))), {}, caplog, limit=None, baseline=True, writer=writer)
    assert len(misp.reports) == 3 and run.status["report_counts"]["reports_added"] == 3
    assert calls[-3:] == [0, 1, 2], "once before each record"


def test_near_its_task_s_end_the_writer_tries_no_record_and_report_pending_keeps_them(caplog):
    """The writer's task ends in 5 minutes, inside the 10 minutes ``push_reports`` keeps free: no record is tried,
    and the run keeps every record on ``report_pending``, untried."""
    misp = _Misp()
    writer = _real_writer(misp, task_ends_at=time.time() + 300)
    pulses = _recorded(range(3))
    run = _collect(_Otx(pulses), {}, caplog, limit=None, baseline=True, writer=writer)
    assert misp.reports == {} and len(misp.attributes) == 3
    assert _pending_refs() == sorted(_ref(p["id"]) for p in pulses)
    assert not any("last_tried_at" in e for e in _pending())
    assert run.status["report_counts"]["reports_skipped"] == 3


def test_the_scheduled_otx_task_gives_its_writer_the_task_s_end(monkeypatch):
    from test_misp_push_failing_cap import _import_dag_module

    ep = _import_dag_module()
    built: List[Dict[str, Any]] = []

    class _Built:
        def __init__(self, **kw: Any):
            built.append(kw)

    start = datetime(2026, 11, 7, 8, 0, tzinfo=timezone.utc)
    context = {"task": SimpleNamespace(execution_timeout=timedelta(hours=1)), "ti": SimpleNamespace(start_date=start)}
    monkeypatch.setattr("collectors.misp_writer.MISPWriter", _Built)
    monkeypatch.setattr(ep, "get_effective_limit", lambda _source: 200)
    with patch.object(ep, "run_collector_with_metrics", return_value={"success": True}) as run:
        ep.run_otx_collection(**context)
    assert built == [{"task_ends_at": start.timestamp() + 3600}]
    assert run.call_args.args[0] == "otx" and run.call_args.kwargs == {"limit": 200}


# --------------------------------------------------------------------------- amber and red pulses (Rob2)


def _otx_meta(attribute: Dict[str, Any]) -> Dict[str, Any]:
    comment = attribute["comment"]
    assert comment.startswith("OTX_META:"), comment
    return json.loads(comment[len("OTX_META:") :])


def _copies(meta: Dict[str, Any]) -> Dict[str, Any]:
    return {k: meta.get(k) for k in mw.PULSE_COPY_KEYS}


NO_COPIES = {"pulse_name": "", "pulse_tags": [], "pulse_references": [], "targeted_countries": []}


def test_an_amber_pulse_keeps_its_text_in_its_record_and_off_its_indicators(caplog):
    """End to end down to MISP: the amber pulse's attributes carry the pulse id and ``pulse_tlp`` for the sync's
    linking, the ``tlp:amber`` tag, and no copy of its name, tags, references or countries; its CVE attribute names
    no pulse. The pulse's text is in its Event Report, at distribution 0 (your organisation only)."""
    misp = _Misp()
    pulse = _amber_pulse()
    run = _collect(_Otx([pulse]), {}, caplog, limit=None, baseline=True, writer=_real_writer(misp))
    assert run.status["success"] is True and len(misp.attributes) == 6
    for attribute in misp.attributes:
        meta = _otx_meta(attribute)
        assert meta["pulse_id"] == pulse["id"] and meta["pulse_tlp"] == "amber"
        assert _copies(meta) == NO_COPIES, attribute["type"]
        assert {"name": "tlp:amber"} in attribute["Tag"]
        for text in [pulse["name"], *pulse["tags"], *pulse["references"], *pulse["targeted_countries"]]:
            assert text not in attribute["comment"]
    (report,) = misp.reports.values()
    (sent,) = misp.bodies("/eventReports/add/")
    assert report["distribution"] == str(rr.DISTRIBUTION_OWN_ORGANISATION)
    assert {"name": "tlp:amber"} in sent["EventReport"]["Tag"]
    assert report["content"].startswith("```\n" + pulse["description"])


def test_a_white_pulse_keeps_its_copies(caplog):
    """The guard of the amber test: the same pulse at white carries its copies on every attribute."""
    misp = _Misp()
    pulse = _recorded_by_id()
    pulse["targeted_countries"] = ["Germany", "France"]
    _collect(_Otx([pulse]), {}, caplog, limit=None, baseline=True, writer=_real_writer(misp))
    for attribute in misp.attributes:
        assert _copies(_otx_meta(attribute)) == {
            "pulse_name": "PSIRT",
            "pulse_tags": pulse["tags"],
            "pulse_references": pulse["references"],
            "targeted_countries": ["Germany", "France"],
        }


def test_an_item_of_a_pulse_without_a_tlp_that_a_green_pulse_also_lists_carries_no_copy(caplog):
    """Pulse A states no TLP (counted as amber) and lists an IOC first; green pulse B lists it too. The fold gives
    the item B's green level and keeps A's copies, which the collector therefore never put on it."""
    pulse_a, pulse_b = _recorded(range(2))
    pulse_a.pop("tlp")
    pulse_a.update(name="Pulse A, unknown level", tags=["a-tag"], references=["https://a.example/r"])
    pulse_a["targeted_countries"] = ["Austria"]
    pulse_b.update(tlp="green")
    pulse_b["indicators"] = copy.deepcopy(pulse_a["indicators"])
    misp = _Misp()
    _collect(_Otx([pulse_a, pulse_b]), {}, caplog, limit=None, baseline=True, writer=_real_writer(misp))
    (attribute,) = misp.attributes
    meta = _otx_meta(attribute)
    assert meta["pulse_id"] == pulse_a["id"] and meta["report_ids"] == [pulse_b["id"]]
    assert meta["pulse_tlp"] == "green" and _copies(meta) == NO_COPIES


def test_the_collector_puts_no_copy_of_an_amber_pulse_on_its_items():
    collector = _collector()
    with patch.object(collector, "_report_actor_reference", return_value=None):
        collector.misp_writer = None
        pulse = _amber_pulse()
        pulse["cve_references"] = ["CVE-2026-0002"]
        items = _process(collector, [pulse])
    assert items and all(_copies(item) == NO_COPIES for item in items if "pulse_id" in item)
    (reference,) = [i for i in items if i.get("cve_id") == "CVE-2026-0002"]
    assert reference["description"] == "Referenced in an OTX pulse"


@pytest.mark.parametrize("level", ["amber", "AMBER", "amber+strict", "red", "", None, "orange"])
def test_the_writer_leaves_the_copies_out_unless_the_pulse_is_white_clear_or_green(level):
    writer = mw.MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)
    item = {
        "indicator_type": "ipv4",
        "value": "198.51.100.9",
        "tag": "alienvault_otx",
        "pulse_id": "6abf0b86fb14812f2dc84fb2",
        "pulse_tlp": level,
        "pulse_name": "Victim name in the title",
        "pulse_tags": ["victim"],
        "pulse_references": ["https://victim.example/report"],
        "targeted_countries": ["Germany"],
        "attack_ids": ["T1190"],
    }
    meta = _otx_meta(writer.create_attribute(item))
    assert _copies(meta) == NO_COPIES and meta["pulse_id"] == item["pulse_id"] and meta["attack_ids"] == ["T1190"]
    assert meta["pulse_tlp"] == level
    cve = writer.create_vulnerability_attribute(
        {"type": "vulnerability", "cve_id": "CVE-2026-0002", "tag": "alienvault_otx", **item}
    )
    assert "pulse_name" not in _otx_meta(cve) and _otx_meta(cve)["pulse_id"] == item["pulse_id"]
    # An item that carries no pulse metadata gets a plain comment: the pulse's name is withheld there too.
    plain = {k: v for k, v in item.items() if k not in ("pulse_id", "attack_ids", "targeted_countries")}
    no_meta = writer.create_attribute(plain)
    assert not no_meta["comment"].startswith("OTX_META:") and "Victim" not in no_meta["comment"]


@pytest.mark.parametrize("level", ["white", "clear", "green", "TLP:GREEN"])
def test_the_writer_keeps_the_copies_of_a_white_clear_or_green_pulse(level):
    writer = mw.MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)
    item = {
        "indicator_type": "ipv4",
        "value": "198.51.100.9",
        "tag": "alienvault_otx",
        "pulse_id": "6abf0b86fb14812f2dc84fb2",
        "pulse_tlp": level,
        "pulse_name": "Campaign report",
        "pulse_tags": ["tag"],
        "pulse_references": ["https://research.example/report"],
        "targeted_countries": ["Germany"],
    }
    meta = _otx_meta(writer.create_attribute(item))
    assert _copies(meta) == {k: item[k] for k in mw.PULSE_COPY_KEYS}
    plain = {k: v for k, v in item.items() if k not in ("pulse_id", "targeted_countries")}
    assert writer.create_attribute(plain)["comment"] == "Campaign report", "the guard of the plain comment"
    cve = writer.create_vulnerability_attribute({"type": "vulnerability", "cve_id": "CVE-2026-0002", **item})
    assert _otx_meta(cve)["pulse_name"] == "Campaign report"
