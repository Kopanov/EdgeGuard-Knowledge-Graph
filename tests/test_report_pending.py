"""The ``report_pending`` list (``src/report_records.py``, 2026-11-07).

Per source, the records whose Event Report push failed or was not tried, kept in the incremental state of the
source's collector (``checkpoints[otx|cisa_ics]["incremental"]["report_pending"]``) on baselines and scheduled runs,
apart from the OTX item retry list. A record leaves the list when a push settles it, is never added when its failure
is permanent (a uuid in a foreign event), and is given up with an ERROR ``[REPORT-GAVE-UP]`` once it has failed for
``EDGEGUARD_REPORT_PENDING_MAX_DAYS`` and a push tried it after that. The end-to-end tests run
``MISPWriter.push_reports`` against the recorded-answer double and hand its stats to ``note_report_push``.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from report_misp_double import URL, ReportMisp  # noqa: E402

import baseline_checkpoint  # noqa: E402
import report_records as rr  # noqa: E402
from collectors import misp_writer as mw  # noqa: E402

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
OTX_A = "alienvault_otx:6abf0b86fb14812f2dc84f0a"
OTX_B = "alienvault_otx:6abf0b86fb14812f2dc84f0b"


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.setenv("EDGEGUARD_MISP_REPORT_THROTTLE_SEC", "0")
    monkeypatch.delenv("EDGEGUARD_REPORT_PENDING_MAX_DAYS", raising=False)
    monkeypatch.delenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", raising=False)


def _incremental(state_source: str) -> dict:
    return baseline_checkpoint.get_source_incremental(state_source)


def _record(n: int, **changes):
    fields = {"record_id": f"6abf0b86fb14812f2dc84f{n:02d}", "title": f"Pulse {n}", "tlp": "white"}
    fields.update(changes)
    return rr.build_record("alienvault_otx", fields)


class TestSettle:
    def test_a_failure_is_added_and_counted_again_and_a_settled_record_is_cleared(self):
        first = rr.update_report_pending(
            "alienvault_otx", failed=[(OTX_A, "the add answered HTTP 500 (tried twice)")], now=NOW
        )
        assert first.added == [OTX_A]
        (entry,) = _incremental("otx")["report_pending"]
        assert entry == {
            "record_ref": OTX_A,
            "first_failed_at": NOW.isoformat(),
            "attempts": 1,
            "last_tried_at": NOW.isoformat(),
            "last_reason": "the add answered HTTP 500 (tried twice)",
        }
        later = NOW + timedelta(hours=3)
        again = rr.update_report_pending("alienvault_otx", failed=[(OTX_A, "the edit answered HTTP 404")], now=later)
        assert again.still == [OTX_A] and again.added == []
        (entry,) = _incremental("otx")["report_pending"]
        assert (entry["attempts"], entry["first_failed_at"], entry["last_tried_at"]) == (
            2,
            NOW.isoformat(),
            later.isoformat(),
        )
        cleared = rr.update_report_pending("alienvault_otx", settled=[OTX_A], now=later)
        assert cleared.cleared == [OTX_A] and _incremental("otx")["report_pending"] == []

    def test_a_skipped_record_is_kept_without_a_try_and_an_entry_stays_as_it_was(self):
        rr.update_report_pending("alienvault_otx", skipped=[(OTX_A, "the push's deadline came")], now=NOW)
        (entry,) = _incremental("otx")["report_pending"]
        assert entry["attempts"] == 0 and "last_tried_at" not in entry
        rr.update_report_pending("alienvault_otx", failed=[(OTX_B, "x")], now=NOW)
        rr.update_report_pending(
            "alienvault_otx", skipped=[(OTX_B, "the push's deadline came")], now=NOW + timedelta(1)
        )
        entries = {e["record_ref"]: e for e in _incremental("otx")["report_pending"]}
        assert entries[OTX_B]["attempts"] == 1 and entries[OTX_B]["last_reason"] == "x"

    def test_a_permanent_failure_is_never_added_and_leaves_the_list(self):
        rr.update_report_pending("alienvault_otx", failed=[(OTX_A, "x")], now=NOW)
        result = rr.update_report_pending("alienvault_otx", permanent=[OTX_A, OTX_B], now=NOW)
        assert result.cleared == [OTX_A] and _incremental("otx")["report_pending"] == []

    def test_a_record_failing_past_the_limit_and_tried_since_is_given_up(self, monkeypatch, caplog):
        monkeypatch.setenv("EDGEGUARD_REPORT_PENDING_MAX_DAYS", "7")
        rr.update_report_pending("alienvault_otx", failed=[(OTX_A, "the add answered HTTP 500 (tried twice)")], now=NOW)
        rr.update_report_pending("alienvault_otx", skipped=[(OTX_B, "the push's deadline came")], now=NOW)
        late = NOW + timedelta(days=7, hours=1)
        with caplog.at_level(logging.ERROR, logger=rr.logger.name):
            result = rr.update_report_pending("alienvault_otx", failed=[(OTX_A, "again")], now=late)
        assert [e["record_ref"] for e in result.given_up] == [OTX_A]
        # never tried: kept, so a record waiting while no run tried it gets one try first
        assert [e["record_ref"] for e in _incremental("otx")["report_pending"]] == [OTX_B]
        (line,) = [r.getMessage() for r in caplog.records if r.getMessage().startswith("[REPORT-GAVE-UP]")]
        assert OTX_A in line and "EDGEGUARD_REPORT_PENDING_MAX_DAYS=7" in line and "attempts 2" in line

    def test_within_the_limit_nothing_is_given_up(self):
        rr.update_report_pending("alienvault_otx", failed=[(OTX_A, "x")], now=NOW)
        result = rr.update_report_pending("alienvault_otx", failed=[(OTX_A, "x")], now=NOW + timedelta(days=6))
        assert result.given_up == [] and result.still == [OTX_A]

    def test_the_reason_is_printable_ascii_of_at_most_300_characters(self):
        rr.update_report_pending("alienvault_otx", failed=[(OTX_A, "é\n" + "x" * 400)], now=NOW)
        (entry,) = _incremental("otx")["report_pending"]
        assert entry["last_reason"].startswith("??x") and len(entry["last_reason"]) == 300

    def test_a_stored_list_is_read_defensively(self):
        baseline_checkpoint.update_source_incremental(
            "otx",
            report_pending=[
                {"record_ref": OTX_A, "first_failed_at": "not a date", "attempts": True},
                {"record_ref": OTX_A, "first_failed_at": NOW.isoformat()},
                {"record_ref": "cisa_ics:ICSA-26-281-01"},
                "junk",
            ],
        )
        (entry,) = rr.load_report_pending("alienvault_otx", now=NOW)
        assert entry == {"record_ref": OTX_A, "first_failed_at": NOW.isoformat(), "attempts": 0, "last_reason": ""}

    def test_pending_refs_come_tried_longest_ago_first(self):
        rr.update_report_pending("alienvault_otx", failed=[(OTX_B, "x")], now=NOW)
        rr.update_report_pending("alienvault_otx", failed=[(OTX_A, "x")], now=NOW - timedelta(hours=1))
        rr.update_report_pending(
            "alienvault_otx", skipped=[("alienvault_otx:6abf0b86fb14812f2dc84f0c", "deadline")], now=NOW
        )
        assert rr.pending_record_refs("alienvault_otx") == ["alienvault_otx:6abf0b86fb14812f2dc84f0c", OTX_A, OTX_B]


class TestWhereTheListLives:
    def test_each_source_keeps_its_list_beside_its_collectors_state(self):
        baseline_checkpoint.update_source_incremental(
            "otx", otx_retry_pulses=[{"id": "p1"}], otx_last_pulse_modified="c"
        )
        rr.update_report_pending("alienvault_otx", failed=[(OTX_A, "x")], now=NOW)
        rr.update_report_pending("cisa_ics", failed=[("cisa_ics:ICSA-26-281-01", "y")], now=NOW)
        otx = _incremental("otx")
        assert otx["otx_retry_pulses"] == [{"id": "p1"}] and otx["otx_last_pulse_modified"] == "c"
        assert [e["record_ref"] for e in otx["report_pending"]] == [OTX_A]
        assert [e["record_ref"] for e in _incremental("cisa_ics")["report_pending"]] == ["cisa_ics:ICSA-26-281-01"]
        assert "alienvault_otx" not in baseline_checkpoint.load_checkpoint()

    def test_a_baseline_keeps_the_list(self):
        rr.update_report_pending("alienvault_otx", failed=[(OTX_A, "x")], now=NOW)
        baseline_checkpoint.update_source_checkpoint("otx", page=3, items_collected=10)
        baseline_checkpoint.clear_checkpoint()  # a baseline's clean-up of its pages
        baseline_checkpoint.clear_checkpoint("otx")
        assert [e["record_ref"] for e in _incremental("otx")["report_pending"]] == [OTX_A]

    def test_the_fresh_baseline_wipe_clears_it_with_misp_and_resets_the_gauges(self):
        import baseline_clean
        import metrics_server

        rr.update_report_pending("alienvault_otx", failed=[(OTX_A, "x")], now=NOW)
        assert metrics_server.REPORT_PENDING_RECORDS.labels(source="alienvault_otx")._value.get() == 1
        baseline_clean._wipe_checkpoints()
        assert _incremental("otx") == {}
        for source in rr.REPORT_SOURCES:
            assert metrics_server.REPORT_PENDING_RECORDS.labels(source=source)._value.get() == 0
            assert metrics_server.REPORT_PENDING_OLDEST_FAILURE.labels(source=source)._value.get() == 0


class TestMetrics:
    def test_the_gauges_follow_the_list_and_the_counter_counts_given_up_records(self):
        import metrics_server

        given_up = metrics_server.REPORT_PENDING_GIVEN_UP.labels(source="cisa_ics")
        before = given_up._value.get()
        rr.update_report_pending("cisa_ics", failed=[("cisa_ics:ICSA-26-281-01", "x")], now=NOW)
        rr.update_report_pending("cisa_ics", skipped=[("cisa_ics:ICSMA-26-281-02", "x")], now=NOW + timedelta(1))
        assert metrics_server.REPORT_PENDING_RECORDS.labels(source="cisa_ics")._value.get() == 2
        assert metrics_server.REPORT_PENDING_OLDEST_FAILURE.labels(source="cisa_ics")._value.get() == NOW.timestamp()
        rr.update_report_pending("cisa_ics", failed=[("cisa_ics:ICSA-26-281-01", "x")], now=NOW + timedelta(days=8))
        assert given_up._value.get() == before + 1
        assert metrics_server.REPORT_PENDING_RECORDS.labels(source="cisa_ics")._value.get() == 1


class TestEndToEndWithTheWriter:
    def test_a_failed_push_puts_records_on_the_list_and_the_next_push_clears_them(self):
        misp = ReportMisp()
        misp.add_event("150", f"EdgeGuard-alienvault_otx-{datetime.now(timezone.utc):%Y-%m-%d}")
        misp.add_event("122", "livecheck-eventreports-20261107T174641Z")
        writer = mw.MISPWriter(url=URL, api_key="test", verify_ssl=True)
        writer.session = misp
        ok, failing, foreign = _record(1), _record(2), _record(3)
        misp.store(rr.record_uuid(foreign), "122", name="x", content=rr.render_content(foreign))
        misp.script("POST", "/eventReports/add/", "add_name_300_chars", times=2)  # the first record's add: 500 twice
        stats = writer.push_reports("alienvault_otx", [failing, ok, foreign])
        result = rr.note_report_push("alienvault_otx", stats, now=NOW)
        assert (stats["reports_added"], stats["reports_failed"], stats["reports_foreign"]) == (1, 2, 1)
        assert result.added == [failing["record_ref"]]
        (entry,) = _incremental("otx")["report_pending"]
        assert (
            entry["record_ref"] == failing["record_ref"]
            and entry["last_reason"] == "the add answered HTTP 500 (tried twice)"
        )
        again = writer.push_reports("alienvault_otx", [failing])
        assert again["reports_added"] == 1
        assert rr.note_report_push("alienvault_otx", again, now=NOW).cleared == [failing["record_ref"]]
        assert _incremental("otx")["report_pending"] == []

    def test_records_skipped_at_the_deadline_wait_on_the_list_untried(self):
        import time

        misp = ReportMisp()
        writer = mw.MISPWriter(url=URL, api_key="test", verify_ssl=True)
        writer.session = misp
        stats = writer.push_reports("alienvault_otx", [_record(1)], deadline=time.monotonic() - 1)
        rr.note_report_push("alienvault_otx", stats, now=NOW)
        (entry,) = _incremental("otx")["report_pending"]
        assert entry["attempts"] == 0 and "last_tried_at" not in entry
