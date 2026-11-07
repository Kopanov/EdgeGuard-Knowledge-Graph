"""``MISPWriter.push_reports`` and ``report_preflight`` (report records, 2026-11-07).

The writer's flow per record follows the live checks on MISP 2.5.50 of 2026-11-07 (L1-L12): an add by
``/eventReports/add/<event>`` counts only when the answer shows the uuid, the content's SHA-256, the name and
``deleted`` false; any HTTP 403 leads to a view of the uuid, which decides between a foreign report (permanent),
a deletion in MISP (respected), an unchanged or newer stored record (left as it is) and an edit by
``/eventReports/edit/<uuid>`` (checked the same way); a TLP change swaps the ``tlp:`` tags by id. HTTP 4xx is never
tried again, HTTP 5xx once. The MISP double (``tests/report_misp_double.py``) answers with the recorded answers of
``tests/fixtures/misp_event_reports_2026_11_07/``.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, List

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from misp_fakes import Response  # noqa: E402
from report_misp_double import URL, ReportMisp, recorded  # noqa: E402

import report_records as rr  # noqa: E402
from collectors import misp_writer as mw  # noqa: E402

TODAY_EVENT = "EdgeGuard-alienvault_otx-{date}"


@pytest.fixture(autouse=True)
def _report_env(monkeypatch, tmp_path):
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.setenv("EDGEGUARD_MISP_REPORT_THROTTLE_SEC", "0")
    monkeypatch.delenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", raising=False)
    monkeypatch.delenv("EDGEGUARD_REPORT_MAX_INDICATORS", raising=False)


def _writer(misp: ReportMisp, **kw: Any) -> mw.MISPWriter:
    writer = mw.MISPWriter(url=URL, api_key="test", verify_ssl=True, **kw)
    writer.session = misp
    return writer


def _record(n: int = 1, **changes: Any) -> Dict[str, Any]:
    fields = {
        "record_id": f"6abf0b86fb14812f2dc84f{n:02d}",
        "title": f"Pulse {n}: energy campaign",
        "description": f"Description of pulse {n}, which names CVE-2026-104286.",
        "published": "2026-10-02T01:40:22.647000",
        "last_modified": "2026-11-01T01:03:15.864000",
        "revision": 2,
        "tlp": "white",
        "author": "AlienVault",
        "industries": ["Energy"],
        "indicators": [["md5", "49a7156a7d043cc8f9f680579db22f86"], ["vulnerability", "CVE-2026-104286"]],
        "cve_ids": ["CVE-2026-104286"],
    }
    fields.update(changes)
    return rr.build_record("alienvault_otx", fields)


def _day_event(misp: ReportMisp, attribute_count: int = 3) -> str:
    from datetime import datetime, timezone

    info = TODAY_EVENT.format(date=datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    misp.add_event("150", info, attribute_count=attribute_count)
    return "150"


def _stored(misp: ReportMisp, record: Dict[str, Any], event_id: str = "150", **kw: Any) -> Dict[str, Any]:
    return misp.store(
        rr.record_uuid(record),
        event_id,
        name=rr.report_name(record),
        content=rr.render_content(record),
        distribution=rr.report_distribution(record),
        **kw,
    )


def _counts(stats: Dict[str, Any]) -> Dict[str, int]:
    return {k: v for k, v in stats.items() if k.startswith("report")}


ZERO = {
    "reports_added": 0,
    "reports_updated": 0,
    "reports_unchanged": 0,
    "reports_failed": 0,
    "reports_deleted_in_misp": 0,
    "reports_foreign": 0,
    "report_tag_drift": 0,
    "reports_skipped": 0,
}


# --------------------------------------------------------------------------- #
# Add
# --------------------------------------------------------------------------- #


class TestAdd:
    def test_a_new_record_is_added_with_its_uuid_name_content_distribution_and_tags(self):
        misp = ReportMisp()
        _day_event(misp)
        record = _record()
        stats = _writer(misp).push_reports("alienvault_otx", [record])
        assert _counts(stats) == {**ZERO, "reports_added": 1}
        assert stats["settled"] == [record["record_ref"]] and stats["event_id"] == "150"
        (body,) = misp.bodies("/eventReports/add/150")
        sent = body["EventReport"]
        assert sent["uuid"] == rr.record_uuid(record) == sent["uuid"].lower()
        assert sent["content"] == rr.render_content(record) and sent["name"] == "Pulse 1: energy campaign"
        assert sent["distribution"] == 5
        assert sent["Tag"] == [{"name": "EdgeGuard"}, {"name": "source:AlienVault-OTX"}, {"name": "tlp:white"}]
        stored = misp.reports[sent["uuid"]]
        assert rr.record_from_content(stored["content"]) == record

    def test_an_amber_record_is_written_for_the_own_organisation_only(self):
        misp = ReportMisp()
        _day_event(misp)
        _writer(misp).push_reports("alienvault_otx", [_record(tlp="amber")])
        (body,) = misp.bodies("/eventReports/add/")
        assert body["EventReport"]["distribution"] == 0
        assert body["EventReport"]["Tag"][-1] == {"name": "tlp:amber"}

    def test_reports_never_travel_in_the_event_edit(self):
        misp = ReportMisp()
        _day_event(misp)
        _writer(misp).push_reports("alienvault_otx", [_record(1), _record(2)])
        assert [p for p in misp.writes() if p.startswith("/events/")] == []
        assert misp.writes() == ["/eventReports/add/150", "/eventReports/add/150"]

    def test_an_add_answered_200_without_the_content_sent_fails(self):
        """A database without strict SQL mode cuts a value and answers HTTP 200 (L8): the SHA-256 tells."""
        misp = ReportMisp()
        _day_event(misp)
        record = _record()
        status, answer = recorded("add_ok")
        answer["EventReport"].update(uuid=rr.record_uuid(record), name=rr.report_name(record))
        answer["EventReport"]["content"] = rr.render_content(record)[:200]  # cut by the database
        misp.script("POST", "/eventReports/add/", (status, answer))
        stats = _writer(misp).push_reports("alienvault_otx", [record])
        assert _counts(stats) == {**ZERO, "reports_failed": 1}
        assert stats["failed"] == [
            {
                "record_ref": record["record_ref"],
                "reason": "the add answered HTTP 200 but MISP holds other content",
                "permanent": False,
            }
        ]

    def test_a_record_given_twice_is_written_once_newest_first(self):
        misp = ReportMisp()
        _day_event(misp)
        older = _record(revision=1, last_modified="2026-10-20T00:00:00")
        newer = _record(revision=2)
        stats = _writer(misp).push_reports("alienvault_otx", [older, newer, older])
        assert stats["reports_added"] == 1
        (body,) = misp.bodies("/eventReports/add/")
        assert rr.record_from_content(body["EventReport"]["content"])["revision"] == 2

    def test_an_invalid_record_fails_permanently_and_sends_nothing(self):
        misp = ReportMisp()
        _day_event(misp)
        stats = _writer(misp).push_reports("alienvault_otx", [{"record_id": "x", "zone": ["energy"]}])
        assert stats["reports_failed"] == 1 and stats["failed"][0]["permanent"] is True
        assert misp.requests == []


# --------------------------------------------------------------------------- #
# HTTP 403: view, then skip, edit, respect a deletion, or refuse a foreign report
# --------------------------------------------------------------------------- #


class TestStoredReport:
    def test_an_unchanged_record_is_viewed_and_left_as_it_is(self):
        misp = ReportMisp()
        _day_event(misp)
        record = _record()
        _stored(misp, record)
        stats = _writer(misp).push_reports("alienvault_otx", [record])
        assert _counts(stats) == {**ZERO, "reports_unchanged": 1}
        uuid = rr.record_uuid(record)
        assert misp.paths() == [
            "/events/restSearch",
            "/eventReports/add/150",
            f"/eventReports/view/{uuid}",
            "/users/view/me",
        ]
        assert stats["settled"] == [record["record_ref"]]

    def test_a_revised_record_is_edited_in_place_in_its_own_event(self):
        misp = ReportMisp()
        _day_event(misp)
        misp.add_event("76", "EdgeGuard-alienvault_otx-2026-11-03", attribute_count=150756)  # the baseline's event
        first = _record(revision=1, last_modified="2026-10-20T00:00:00")
        _stored(misp, first, event_id="76")
        revised = _record(revision=2, description="Revised description.")
        stats = _writer(misp).push_reports("alienvault_otx", [revised])
        assert _counts(stats) == {**ZERO, "reports_updated": 1}
        uuid = rr.record_uuid(revised)
        (edit,) = misp.bodies(f"/eventReports/edit/{uuid}")
        assert set(edit["EventReport"]) == {"name", "content", "distribution"}  # no Tag, no uuid, no event
        assert misp.reports[uuid]["event_id"] == "76"
        assert rr.record_from_content(misp.reports[uuid]["content"]) == revised

    def test_a_stored_record_with_a_later_last_modified_is_left_as_it_is(self):
        misp = ReportMisp()
        _day_event(misp)
        newer = _record(revision=3, last_modified="2026-11-05T00:00:00")
        _stored(misp, newer)
        stats = _writer(misp).push_reports("alienvault_otx", [_record(revision=2)])
        assert _counts(stats) == {**ZERO, "reports_unchanged": 1}
        assert not [p for p in misp.writes() if "/edit/" in p]

    def test_a_record_deleted_in_misp_is_respected(self):
        misp = ReportMisp()
        _day_event(misp)
        record = _record()
        _stored(misp, _record(revision=1, last_modified="2026-10-01T00:00:00"), deleted=True)
        stats = _writer(misp).push_reports("alienvault_otx", [record])
        assert _counts(stats) == {**ZERO, "reports_deleted_in_misp": 1}
        assert misp.writes() == ["/eventReports/add/150"]  # no edit, no restore
        assert misp.reports[rr.record_uuid(record)]["deleted"] is True
        assert stats["settled"] == [record["record_ref"]]

    def test_a_report_in_a_foreign_event_is_a_permanent_failure(self, caplog):
        """The recorded view answer's event is a livecheck event of organisation ADMIN: not an EdgeGuard event."""
        misp = ReportMisp()
        _day_event(misp)
        misp.add_event("122", "livecheck-eventreports-20261107T174641Z")
        record = _record()
        _stored(misp, record, event_id="122")
        with caplog.at_level(logging.ERROR, logger=mw.logger.name):
            stats = _writer(misp).push_reports("alienvault_otx", [record])
        assert _counts(stats) == {**ZERO, "reports_failed": 1, "reports_foreign": 1}
        assert stats["failed"][0]["permanent"] is True and stats["settled"] == []
        assert misp.writes() == ["/eventReports/add/150"]
        assert any(r.getMessage().startswith("[REPORT-UUID-FOREIGN]") for r in caplog.records)

    def test_an_edgeguard_event_of_another_organisation_is_foreign_too(self):
        misp = ReportMisp()
        _day_event(misp)
        misp.add_event("90", "EdgeGuard-alienvault_otx-2026-11-01", orgc_id="7")
        record = _record()
        _stored(misp, _record(revision=1, last_modified="2026-10-01T00:00:00"), event_id="90")
        stats = _writer(misp).push_reports("alienvault_otx", [record])
        assert stats["reports_foreign"] == 1 and not [p for p in misp.writes() if "/edit/" in p]

    def test_an_event_of_another_source_is_foreign(self):
        misp = ReportMisp()
        _day_event(misp)
        misp.add_event("91", "EdgeGuard-cisa_ics-2026-11-01")
        record = _record()
        _stored(misp, _record(revision=1, last_modified="2026-10-01T00:00:00"), event_id="91")
        assert _writer(misp).push_reports("alienvault_otx", [record])["reports_foreign"] == 1

    def test_a_403_whose_uuid_view_answers_404_fails_without_retries(self):
        """The add refused for another reason (L2b: distribution) and no report holds the uuid (L2: 404)."""
        misp = ReportMisp()
        _day_event(misp)
        misp.script("POST", "/eventReports/add/", "add_invalid_distribution")
        record = _record()
        stats = _writer(misp).push_reports("alienvault_otx", [record])
        assert _counts(stats) == {**ZERO, "reports_failed": 1}
        assert misp.paths() == [
            "/events/restSearch",
            "/eventReports/add/150",
            f"/eventReports/view/{rr.record_uuid(record)}",
        ]
        assert stats["failed"][0]["reason"] == "the add answered HTTP 403 and the view of the uuid answered HTTP 404"

    def test_an_edit_answered_200_with_an_empty_list_fails(self):
        misp = ReportMisp()
        _day_event(misp)
        _stored(misp, _record(revision=1, last_modified="2026-10-01T00:00:00"))
        misp.script("POST", "/eventReports/edit/", "edit_invalid_distribution")
        record = _record()
        stats = _writer(misp).push_reports("alienvault_otx", [record])
        assert _counts(stats) == {**ZERO, "reports_failed": 1}
        assert stats["failed"][0] == {
            "record_ref": record["record_ref"],
            "reason": "the edit answered HTTP 200 but the answer holds no report",
            "permanent": False,
        }

    def test_a_stored_content_without_a_valid_block_is_overwritten(self):
        misp = ReportMisp()
        _day_event(misp)
        record = _record()
        misp.store(rr.record_uuid(record), "150", name="x", content="edited by hand")
        stats = _writer(misp).push_reports("alienvault_otx", [record])
        assert stats["reports_updated"] == 1


# --------------------------------------------------------------------------- #
# TLP change on a revised record
# --------------------------------------------------------------------------- #


class TestTlpChange:
    def test_the_tlp_tags_are_swapped_by_id_and_the_distribution_follows(self):
        misp = ReportMisp()
        misp.add_tag("tlp:amber", "80")
        _day_event(misp)
        stored = _stored(
            misp, _record(revision=1, last_modified="2026-10-01T00:00:00"), tags=("EdgeGuard", "tlp:white")
        )
        stats = _writer(misp).push_reports("alienvault_otx", [_record(tlp="amber")])
        assert _counts(stats) == {**ZERO, "reports_updated": 1}
        report_id = stored["id"]
        assert misp.writes()[-2:] == [f"/eventReports/removeTag/{report_id}/78", f"/eventReports/addTag/{report_id}/80"]
        assert misp.reports[stored["uuid"]]["tags"] == {"EdgeGuard", "tlp:amber"}
        assert misp.reports[stored["uuid"]]["distribution"] == "0"

    def test_a_tag_change_misp_does_not_save_is_drift_not_failure(self):
        """tlp:amber does not exist (as tlp:green on the recording MISP): addTag answers saved false (L1b)."""
        misp = ReportMisp()
        misp.add_tag("tlp:amber", "80")
        _day_event(misp)
        _stored(misp, _record(revision=1, last_modified="2026-10-01T00:00:00"), tags=("tlp:white",))
        misp.script("POST", "/eventReports/addTag/", "add_tag_unknown_name")
        stats = _writer(misp).push_reports("alienvault_otx", [_record(tlp="amber")])
        assert _counts(stats) == {**ZERO, "reports_updated": 1, "report_tag_drift": 1}
        assert stats["failed"] == []

    def test_a_missing_tlp_tag_is_drift_and_the_old_tag_is_still_removed(self):
        """tlp:red does not exist on this MISP: the less restrictive tlp:white goes, no tlp:red can be added; the
        meta block and the distribution carry the record's level."""
        misp = ReportMisp()
        _day_event(misp)
        stored = _stored(misp, _record(revision=1, last_modified="2026-10-01T00:00:00"), tags=("tlp:white",))
        stats = _writer(misp).push_reports("alienvault_otx", [_record(tlp="red")])
        assert stats["report_tag_drift"] == 1 and stats["reports_updated"] == 1
        assert [p for p in misp.writes() if "Tag/" in p] == [f"/eventReports/removeTag/{stored['id']}/78"]
        assert misp.reports[stored["uuid"]]["tags"] == set() and misp.reports[stored["uuid"]]["distribution"] == "0"

    def test_an_unchanged_tlp_sends_no_tag_change(self):
        misp = ReportMisp()
        _day_event(misp)
        _stored(misp, _record(revision=1, last_modified="2026-10-01T00:00:00"))
        _writer(misp).push_reports("alienvault_otx", [_record()])
        assert not [p for p in misp.paths() if "Tag" in p or p.startswith("/tags/")]


# --------------------------------------------------------------------------- #
# Retries, the deadline, the liveness callback, the throttle
# --------------------------------------------------------------------------- #


class TestRetriesAndLimits:
    def test_a_500_is_tried_once_more(self):
        misp = ReportMisp()
        _day_event(misp)
        misp.script("POST", "/eventReports/add/", "add_name_300_chars")
        stats = _writer(misp).push_reports("alienvault_otx", [_record()])
        assert stats["reports_added"] == 1
        assert misp.paths().count("/eventReports/add/150") == 2

    def test_a_500_twice_fails_the_record(self):
        misp = ReportMisp()
        _day_event(misp)
        misp.script("POST", "/eventReports/add/", "add_name_300_chars", times=2)
        stats = _writer(misp).push_reports("alienvault_otx", [_record()])
        assert _counts(stats) == {**ZERO, "reports_failed": 1}
        assert stats["failed"][0]["reason"] == "the add answered HTTP 500 (tried twice)"
        assert misp.paths().count("/eventReports/add/150") == 2

    def test_an_edit_answered_500_is_tried_once_more(self):
        misp = ReportMisp()
        _day_event(misp)
        _stored(misp, _record(revision=1, last_modified="2026-10-01T00:00:00"))
        misp.script("POST", "/eventReports/edit/", "edit_name_256_chars")
        stats = _writer(misp).push_reports("alienvault_otx", [_record()])
        assert stats["reports_updated"] == 1

    def test_a_4xx_is_never_tried_again(self):
        misp = ReportMisp()
        _day_event(misp)
        misp.script("POST", "/eventReports/add/", "edit_unknown_uuid")  # HTTP 404
        stats = _writer(misp).push_reports("alienvault_otx", [_record()])
        assert stats["failed"][0]["reason"] == "the add answered HTTP 404"
        assert misp.paths().count("/eventReports/add/150") == 1

    def test_the_report_requests_are_not_wrapped_in_the_retry_decorator(self):
        for name in ("push_reports", "_push_report", "_report_request", "_swap_report_tlp"):
            assert not hasattr(getattr(mw.MISPWriter, name), "__wrapped__"), name

    def test_after_five_records_failing_on_5xx_the_rest_is_skipped(self):
        misp = ReportMisp()
        _day_event(misp)
        misp.script("POST", "/eventReports/add/", "add_name_300_chars", times=100)
        records = [_record(n) for n in range(8)]
        stats = _writer(misp).push_reports("alienvault_otx", records)
        assert (stats["reports_failed"], stats["reports_skipped"]) == (5, 3)
        assert [s["record_ref"] for s in stats["skipped"]] == [r["record_ref"] for r in records[5:]]
        assert stats["skipped"][0]["reason"].startswith("MISP kept failing: 5 records in a row")
        assert misp.paths().count("/eventReports/add/150") == 10

    def test_a_deadline_in_the_past_sends_nothing(self):
        import time

        misp = ReportMisp()
        _day_event(misp)
        stats = _writer(misp).push_reports("alienvault_otx", [_record(1), _record(2)], deadline=time.monotonic() - 1)
        assert stats["reports_skipped"] == 2 and misp.requests == []

    def test_the_deadline_stops_before_the_next_record(self, monkeypatch):
        clock = {"now": 1000.0}
        monkeypatch.setattr(mw.time, "monotonic", lambda: clock["now"])
        misp = ReportMisp()
        _day_event(misp)
        original = misp._add

        def add_and_tick(event_id, sent):
            clock["now"] += 30.0
            return original(event_id, sent)

        misp._add = add_and_tick
        stats = _writer(misp).push_reports("alienvault_otx", [_record(n) for n in range(4)], deadline=1050.0)
        assert (stats["reports_added"], stats["reports_skipped"]) == (2, 2)
        assert stats["skipped"][0]["reason"] == "the push's deadline came"

    def test_the_liveness_callback_runs_before_each_record_and_its_exception_propagates(self):
        misp = ReportMisp()
        _day_event(misp)
        calls: List[int] = []

        def alive():
            calls.append(len(misp.bodies("/eventReports/add/")))
            if len(calls) == 2:
                raise RuntimeError("parent run failed")

        with pytest.raises(RuntimeError, match="parent run failed"):
            _writer(misp).push_reports("alienvault_otx", [_record(1), _record(2), _record(3)], liveness_callback=alive)
        assert calls == [0, 1] and len(misp.bodies("/eventReports/add/")) == 1

    def test_the_writers_own_liveness_callback_is_the_default(self):
        misp = ReportMisp()
        _day_event(misp)
        calls: List[int] = []
        _writer(misp, liveness_callback=lambda: calls.append(1)).push_reports(
            "alienvault_otx", [_record(1), _record(2)]
        )
        assert calls == [1, 1]

    def test_the_throttle_pauses_between_records(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_REPORT_THROTTLE_SEC", "0.25")
        sleeps: List[float] = []
        monkeypatch.setattr(mw.time, "sleep", sleeps.append)
        misp = ReportMisp()
        _day_event(misp)
        _writer(misp).push_reports("alienvault_otx", [_record(n) for n in range(3)])
        assert sleeps == [0.25, 0.25]


# --------------------------------------------------------------------------- #
# The event the records go to
# --------------------------------------------------------------------------- #


class TestEvent:
    def test_the_day_event_is_created_when_missing(self):
        misp = ReportMisp()
        stats = _writer(misp).push_reports("alienvault_otx", [_record()])
        (event_id,) = misp.events
        assert misp.events[event_id]["info"].startswith("EdgeGuard-alienvault_otx-") and stats["event_id"] == event_id
        assert misp.paths()[:3] == ["/events/restSearch", "/events/restSearch", "/events"]

    def test_a_day_event_above_the_split_limit_sends_new_records_to_the_reports_event(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "20000")
        misp = ReportMisp()
        day = _day_event(misp, attribute_count=150756)
        stats = _writer(misp).push_reports("alienvault_otx", [_record()])
        companion = stats["event_id"]
        assert companion != day
        assert misp.events[companion]["info"] == misp.events[day]["info"] + "-reports"
        assert misp.writes()[-1] == f"/eventReports/add/{companion}"

    def test_the_split_turned_off_keeps_the_day_event(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "0")
        misp = ReportMisp()
        day = _day_event(misp, attribute_count=150756)
        assert _writer(misp).push_reports("alienvault_otx", [_record()])["event_id"] == day

    def test_a_failed_event_lookup_skips_every_record(self):
        misp = ReportMisp()
        misp.script("POST", "/events/restSearch", (403, {"name": "Forbidden"}), times=10)
        stats = _writer(misp).push_reports("alienvault_otx", [_record(1), _record(2)])
        assert stats["reports_skipped"] == 2 and stats["event_id"] is None
        assert not [p for p in misp.paths() if p.startswith("/eventReports/")]


# --------------------------------------------------------------------------- #
# Logs and bookkeeping
# --------------------------------------------------------------------------- #


class TestLogsAndBookkeeping:
    def test_no_content_and_no_answer_body_reaches_the_logs(self, caplog):
        misp = ReportMisp()
        misp.add_tag("tlp:amber", "80")
        _day_event(misp)
        misp.add_event("122", "livecheck-eventreports-20261107T174641Z")
        added = _record(1, description="SECRET-DESCRIPTION-ONE")
        _stored(misp, _record(2, revision=1, last_modified="2026-10-01T00:00:00"), tags=("tlp:white",))
        revised = _record(2, tlp="amber", description="SECRET-DESCRIPTION-TWO", title="SECRET-TITLE")
        foreign = _record(3)
        _stored(misp, foreign, event_id="122")
        failing = _record(4, description="SECRET-DESCRIPTION-FOUR")
        with caplog.at_level(logging.DEBUG):
            writer = _writer(misp)
            original = misp._add

            def add(event_id, sent):
                if "SECRET-DESCRIPTION-FOUR" in sent["content"]:
                    return Response(403, {"saved": False, "errors": "SECRET-ANSWER-BODY"})
                return original(event_id, sent)

            misp._add = add
            stats = writer.push_reports("alienvault_otx", [added, revised, foreign, failing])
            writer.report_preflight()
        assert (stats["reports_added"], stats["reports_updated"], stats["reports_foreign"]) == (1, 1, 1)
        text = "\n".join(r.getMessage() for r in caplog.records)
        for secret in ("SECRET-DESCRIPTION", "SECRET-TITLE", "SECRET-ANSWER-BODY", "Could not add EventReport"):
            assert secret not in text, secret
        assert "Invalid report" not in text and "admin@" not in text and "livecheck-eventreports" not in text
        assert f"uuid={rr.record_uuid(added)}" in text and "sha256=" in text and "content_chars=" in text

    def test_the_item_push_bookkeeping_is_not_written(self):
        misp = ReportMisp()
        _day_event(misp)
        writer = _writer(misp)
        writer.last_push_unstored_items = [7]
        writer.last_push_event_failed_items = [7]
        writer.last_push_skipped_items = [8]
        writer.last_push_unsent_items = [9]
        writer.last_push_stopped = True
        misp.script("POST", "/eventReports/add/", "add_name_300_chars", times=10)
        writer.push_reports("alienvault_otx", [_record(1), _record(2)])
        assert (writer.last_push_unstored_items, writer.last_push_event_failed_items) == ([7], [7])
        assert (writer.last_push_skipped_items, writer.last_push_unsent_items, writer.last_push_stopped) == (
            [8],
            [9],
            True,
        )

    def test_an_ics_record_goes_to_the_cisa_ics_event_with_its_source_tag(self):
        misp = ReportMisp()
        record = rr.build_record("cisa_ics", {"record_id": "ICSA-26-281-01", "title": "Red Lion", "tlp": "WHITE"})
        stats = _writer(misp).push_reports("cisa_ics", [record])
        assert stats["reports_added"] == 1
        (event_id,) = misp.events
        assert misp.events[event_id]["info"].startswith("EdgeGuard-cisa_ics-")
        (body,) = misp.bodies("/eventReports/add/")
        assert body["EventReport"]["Tag"][1] == {"name": "source:CISA-ICS"}
        assert body["EventReport"]["uuid"] == rr.report_uuid("cisa_ics:ICSA-26-281-01", "VulnerabilityAdvisory")


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #


class TestPreflight:
    def test_a_tag_editor_passes_with_missing_tags_and_nothing_is_written(self):
        misp = ReportMisp()
        result = _writer(misp).report_preflight()
        assert result.ok and result.problems == ()
        assert (result.perm_tagger, result.perm_tag_editor, result.perm_sync_authoritative) == (True, True, False)
        assert result.org_id == "1"
        assert "tlp:green" in result.missing_tags and "tlp:white" not in result.missing_tags
        assert misp.writes() == []
        assert misp.paths() == ["/users/view/me", "/tags/search/x/1"]
        assert set(misp.bodies("/tags/search/x/1")[0]["tag"]) == set(mw.report_tag_names())

    def test_the_tags_checked_are_every_tag_the_writer_sets(self):
        names = mw.report_tag_names()
        assert names[:3] == ("EdgeGuard", "source:AlienVault-OTX", "source:CISA-ICS")
        assert {f"tlp:{level}" for level in rr.TLP_LEVELS} <= set(names)

    def test_missing_tags_without_tag_editor_are_a_problem(self):
        misp = ReportMisp()
        misp.me["Role"]["perm_tag_editor"] = False
        result = _writer(misp).report_preflight()
        assert not result.ok and "tlp:green" in result.problems[0] and "perm_tag_editor" in result.problems[0]

    def test_a_role_without_perm_tagger_is_a_problem(self):
        misp = ReportMisp()
        misp.me["Role"]["perm_tagger"] = False
        result = _writer(misp).report_preflight()
        assert not result.ok and any("perm_tagger" in p for p in result.problems)

    def test_a_role_with_perm_sync_authoritative_is_a_problem(self):
        misp = ReportMisp()
        misp.me["Role"]["perm_sync_authoritative"] = True
        result = _writer(misp).report_preflight()
        assert not result.ok and any("perm_sync_authoritative" in p for p in result.problems)

    def test_an_unreadable_role_is_a_problem(self):
        misp = ReportMisp()
        misp.script("GET", "/users/view/me", (403, {"name": "Forbidden"}))
        result = _writer(misp).report_preflight()
        assert not result.ok and result.perm_tagger is None and "HTTP 403" in result.problems[0]
