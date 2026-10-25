"""Every CISA KEV run compares the whole catalogue with EdgeGuard's MISP copies (2026-10).

CISA revises catalogue entries in place and gives no per-entry modification date: between 2026-05-22 and
2026-10-16, 26 entries went from ransomware use Unknown to Known, a due date moved and a description was
extended, every one of them on an entry added more than 30 days earlier. An incremental run took only the
entries added within the last 30 days, and MISPWriter dropped every entry MISP already held as a duplicate,
so no revision reached MISP or the graph. Now each run lists EdgeGuard's ``source:CISA-KEV`` copies once,
adds the CVEs MISP lacks and edits in place the copies that differ (``collectors.vulnerability_update``).

The tests drive the real ``CISACollector`` and the real ``MISPWriter`` against ``FakeMisp``
(``tests/misp_fakes.py``) with real catalogue entries (``tests/fixtures/kev_revisions_2026_10_16.json``,
see its ``_provenance``). The stored copies are the ones an earlier run of the same code wrote, except
where a test uses the copy the hosted baseline of 2026-10-13 wrote.
"""

from __future__ import annotations

import copy
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from misp_fakes import FakeMisp  # noqa: E402
from stub_cleanup import clear_graphql_api_magicmock_stubs  # noqa: E402

# tests/test_graphql_api.py replaces neo4j_client (and neo4j, pymisp) with MagicMocks when it is collected first.
if any(isinstance(m, MagicMock) for k, m in list(sys.modules.items()) if k == "neo4j_client" or k.startswith("neo4j")):
    clear_graphql_api_magicmock_stubs()

import config  # noqa: E402
from collectors import misp_writer, vulnerability_update  # noqa: E402
from collectors.cisa_collector import CISACollector  # noqa: E402
from collectors.misp_writer import KnownAttribute, MISPWriter  # noqa: E402
from collectors.vulnerability_update import (  # noqa: E402
    PlannedEdit,
    apply_vulnerability_edits,
    meta_changed_keys,
    plan_source_updates,
)

FIXTURES = json.loads((Path(__file__).resolve().parent / "fixtures" / "kev_revisions_2026_10_16.json").read_text())
T0 = datetime(2026, 10, 16, 6, 0, tzinfo=timezone.utc).timestamp()

FLIP = "CVE-2026-63077"  # ransomware use Unknown (2026-09-16) → Known (2026-10-16); added 2026-08-05
DUE = "CVE-2022-0995"  # dueDate 2026-09-09 → 2026-08-29; NVD did not move lastModified
OLD_FLIP = "CVE-2012-0158"  # added 2021-11-03; Unknown (2026-05-22) → Known (2026-09-16)
TEXT = "CVE-2025-24813"  # shortDescription extended between 2026-05-22 and 2026-09-16
NEW = ("CVE-2025-61624", "CVE-2025-21042")  # in the 2026-10-16 catalogue, not in the 2026-09-16 one
LOG4SHELL = "CVE-2021-44228"  # unchanged in all three


def catalogue(day: str, *only: str) -> list:
    entries = copy.deepcopy(FIXTURES["catalogues"][day]["vulnerabilities"])
    return [e for e in entries if not only or e["cveID"] in only]


def entry(day: str, cve_id: str) -> dict:
    (found,) = catalogue(day, cve_id)
    return found


def meta(attribute: dict) -> dict:
    return json.loads(attribute["comment"][len("NVD_META:") :])


def tags(attribute: dict) -> set:
    return {t["name"] for t in attribute["Tag"]}


class Clock:
    """The time MISP stamps writes with: each run is an hour later."""

    def __init__(self):
        self.now = T0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def env(monkeypatch, tmp_path):
    for name in (
        "EDGEGUARD_KEV_UPDATE_EXISTING",
        "EDGEGUARD_KEV_MAX_EDITS_PER_RUN",
        "EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE",
        "EDGEGUARD_MISP_REFRESH_MAX_SECONDS",
        "EDGEGUARD_MISP_PUSH_BATCH_SIZE",
        "EDGEGUARD_MISP_MIN_SUCCESS_RATE",
        "EDGEGUARD_BASELINE_DAYS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.setattr(misp_writer.time, "sleep", lambda _s: None)
    monkeypatch.setattr(misp_writer, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(misp_writer, "MISP_CROSS_EVENT_DEDUP", True)
    # Other test modules reload ``config`` with their own EDGEGUARD_MAX_ENTRIES; the global override
    # would become the run's limit here.
    monkeypatch.setattr(config, "MAX_ENTRIES_PER_SOURCE", 0)
    return monkeypatch


def new_misp(clock: Clock, attributes=()) -> FakeMisp:
    return FakeMisp(attributes, event_info="EdgeGuard-cisa_kev-2026-10-13", clock=clock)


def run(misp: FakeMisp, entries: list, *, limit=None, push_to_misp=True, baseline=False):
    writer = MISPWriter(url="https://misp.test", api_key="test", verify_ssl=True)
    writer.session = misp
    collector = CISACollector(misp_writer=writer)
    collector._fetch_kev = lambda limit=None: copy.deepcopy(entries)
    if isinstance(misp.clock, Clock):
        misp.clock.now += 3600
    return collector.collect(limit=limit, push_to_misp=push_to_misp, baseline=baseline)


def stored_after(entries: list, clock: Clock) -> FakeMisp:
    """MISP after a run of this code over ``entries`` into an empty MISP (the stored copies)."""
    misp = new_misp(clock)
    status = run(misp, entries, baseline=True)
    assert status["success"] and status["kev_update"]["added"] == len(entries)
    misp.posts.clear()
    return misp


def edits_by_cve(misp: FakeMisp) -> dict:
    by_uuid = {a["uuid"]: a["value"] for a in misp.attributes}
    return {by_uuid[uid]: changes for uid, changes in misp.edits()}


# --------------------------------------------------------------------------- revisions reach MISP
class TestRevisions:
    def test_a_ransomware_flip_on_an_entry_added_in_2021_is_one_edit(self, env, caplog):
        clock = Clock()
        misp = stored_after(catalogue("2026-05-22"), clock)
        assert "ransomware:known" not in tags(misp.by_value(OLD_FLIP))
        with caplog.at_level(logging.INFO, logger="collectors.vulnerability_update"):
            status = run(misp, catalogue("2026-09-16", OLD_FLIP, TEXT))
        edits = edits_by_cve(misp)
        assert set(edits) == {OLD_FLIP, TEXT}
        assert edits[OLD_FLIP]["Tag"] == [{"name": "ransomware:known"}]
        assert meta(edits[OLD_FLIP])["known_ransomware_use"] == "Known"
        assert "Tag" not in edits[TEXT], "the extended description changes NVD_META only"
        assert meta(misp.by_value(TEXT))["description"].endswith("chained with CVE‑2026‑34486.")
        assert "ransomware:known" in tags(misp.by_value(OLD_FLIP))
        assert status["success"] and status["failed"] == 0
        update = status["kev_update"]
        assert (update["updated"], update["added"], update["unchanged"], update["deferred"]) == (2, 0, 0, 0)
        assert update["changed_keys"] == {OLD_FLIP: ["known_ransomware_use"], TEXT: ["description"]}
        old = misp.by_value(OLD_FLIP)
        assert (
            f"[KEV-UPDATE] {OLD_FLIP} attribute {old['uuid']} event {old['event_id']}: known_ransomware_use; tags +ransomware:known"
            in caplog.text
        )

    def test_the_month_to_2026_10_16_two_revisions_and_two_new_entries(self, env):
        clock = Clock()
        misp = stored_after(catalogue("2026-09-16"), clock)
        status = run(misp, catalogue("2026-10-16"))
        edits = edits_by_cve(misp)
        assert set(edits) == {FLIP, DUE}
        assert edits[FLIP]["Tag"] == [{"name": "ransomware:known"}]
        assert meta(misp.by_value(DUE))["cisa_action_due"] == "2026-08-29"
        assert sorted(misp.added_values()) == sorted(NEW)
        assert len(misp.listings()) == 1, "the run's listing is passed to push_items, MISP is listed once"
        update = status["kev_update"]
        assert (update["catalogue"], update["scope"]) == (7, 7)
        assert (update["added"], update["updated"], update["unchanged"], update["failed"]) == (2, 2, 3, 0)
        assert update["changed_keys"] == {DUE: ["cisa_action_due"], FLIP: ["known_ransomware_use"]}
        assert update["catalogue_version"] is None, "set by the real download only"
        assert status["count"] == 4 and status["success"]

    def test_known_to_unknown_detaches_the_ransomware_tag(self, env):
        # The reverse of the real revision of CVE-2026-63077: none was seen in 5 months, but CISA can revert.
        clock = Clock()
        misp = stored_after(catalogue("2026-10-16", FLIP), clock)
        assert "ransomware:known" in tags(misp.by_value(FLIP))
        run(misp, catalogue("2026-09-16", FLIP))
        ((_uuid, changes),) = misp.edits()
        assert changes["Tag"] == [{"name": "ransomware:known", "deleted": True}]
        assert "ransomware:known" not in tags(misp.by_value(FLIP))
        assert meta(misp.by_value(FLIP))["known_ransomware_use"] == "Unknown"

    def test_an_analyst_ransomware_taxonomy_tag_is_left_alone(self, env):
        # Only ``ransomware:known`` is EdgeGuard's: a machine tag of MISP's ``ransomware`` taxonomy that an
        # analyst attached to the copy neither plans an edit nor is detached when CISA reverts to Unknown.
        analyst = 'ransomware:type="crypto-ransomware"'
        clock = Clock()
        misp = stored_after(catalogue("2026-10-16", FLIP), clock)
        misp.by_value(FLIP)["Tag"].append({"id": "0", "name": analyst})
        status = run(misp, catalogue("2026-10-16", FLIP))
        assert misp.writes() == [] and status["kev_update"]["unchanged"] == 1
        run(misp, catalogue("2026-09-16", FLIP))
        ((_uuid, changes),) = misp.edits()
        assert changes["Tag"] == [{"name": "ransomware:known", "deleted": True}]
        assert analyst in tags(misp.by_value(FLIP)) and "ransomware:known" not in tags(misp.by_value(FLIP))

    def test_an_unchanged_catalogue_writes_nothing_and_a_revised_run_converges(self, env):
        clock = Clock()
        misp = stored_after(catalogue("2026-10-16"), clock)
        status = run(misp, catalogue("2026-10-16"))
        assert misp.writes() == [] and status["kev_update"]["unchanged"] == 7 and status["success"]

        misp = stored_after(catalogue("2026-09-16"), clock)
        run(misp, catalogue("2026-10-16"))
        misp.posts.clear()
        again = run(misp, catalogue("2026-10-16"))
        assert misp.writes() == [], "the edits of the first run compare as unchanged"
        assert again["kev_update"]["unchanged"] == 7

    def test_a_copy_written_before_the_score_fix_is_edited_once(self, env):
        """The copy the hosted baseline wrote on 2026-10-13: ransomware-derived ``severity:high`` and
        ``cvss:high`` tags and ``cisa_known_ransomware_use`` in NVD_META (#185 changed both)."""
        clock = Clock()
        hosted = copy.deepcopy(FIXTURES["misp"]["CVE-2025-21042"])
        hosted.pop("Event")
        hosted["Tag"] = [dict(t, id="0") for t in hosted["Tag"]]
        misp = new_misp(clock, [hosted])
        status = run(misp, catalogue("2026-10-16", "CVE-2025-21042"))
        ((uid, changes),) = misp.edits()
        assert uid == hosted["uuid"]
        assert sorted((t["name"], bool(t.get("deleted"))) for t in changes["Tag"]) == [
            ("cvss:high", True),
            ("severity:high", True),
            ("severity:unknown", False),
        ]
        assert status["kev_update"]["changed_keys"] == {
            "CVE-2025-21042": ["cisa_known_ransomware_use", "known_ransomware_use"]
        }
        misp.posts.clear()
        run(misp, catalogue("2026-10-16", "CVE-2025-21042"))
        assert misp.writes() == []


# --------------------------------------------------------------------------- event parts
class TestEventParts:
    """The event split (``EDGEGUARD_MISP_EVENT_SPLIT_ABOVE``) on the KEV update path: the run's listing reaches
    ``push_items`` as ``known_source_keys``, and a copy held in a ``-partN`` event is EdgeGuard's own copy."""

    def test_a_copy_held_in_part2_is_edited_and_the_additions_open_new_parts(self, env):
        env.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "1")
        env.setattr(misp_writer, "_EVENT_SPLIT_MIN", 1)  # a limit of 1 puts each stored copy in its own part
        misp = stored_after(catalogue("2026-09-16"), Clock())
        base = f"EdgeGuard-cisa_kev-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        held_in = {a["value"]: misp.events[a["event_id"]] for a in misp.attributes}
        assert sorted(held_in.values()) == sorted([base] + [f"{base}-part{n}" for n in range(2, 6)])
        assert held_in[FLIP] == f"{base}-part2"

        status = run(misp, catalogue("2026-10-16"))
        edits = edits_by_cve(misp)
        assert set(edits) == {FLIP, DUE}
        assert edits[FLIP]["Tag"] == [{"name": "ransomware:known"}]
        assert misp.events[misp.by_value(FLIP)["event_id"]] == f"{base}-part2"
        assert "ransomware:known" in tags(misp.by_value(FLIP))
        assert sorted(misp.added_values()) == sorted(NEW)
        created = [body["Event"]["info"] for p, body in misp.posts if p == "/events"]
        assert sorted(created) == [f"{base}-part6", f"{base}-part7"]
        assert sorted(misp.events[misp.by_value(c)["event_id"]] for c in NEW) == sorted(created)
        assert len(misp.listings()) == 1, "push_items reuses the run's listing"
        update = status["kev_update"]
        assert (update["added"], update["updated"], update["foreign_only"], update["failed"]) == (2, 2, 0, 0)


# --------------------------------------------------------------------------- what is not written
class TestNotWritten:
    @pytest.mark.parametrize("http_status", [403, 503])
    def test_a_listing_failure_writes_nothing_and_fails_the_run(self, env, http_status):
        clock = Clock()
        misp = stored_after(catalogue("2026-09-16"), clock)
        misp.listing_status = http_status
        status = run(misp, catalogue("2026-10-16"))
        assert misp.writes() == []
        assert status["success"] is False and "could not be listed" in status["error"]

    def test_a_copy_in_another_event_is_neither_edited_nor_added(self, env, caplog):
        clock = Clock()
        misp = stored_after(catalogue("2026-09-16"), clock)
        misp.events["900"] = "Analyst triage: exploited CI/CD servers"
        misp.by_value(FLIP)["event_id"] = "900"
        with caplog.at_level(logging.WARNING, logger="collectors.cisa_collector"):
            status = run(misp, catalogue("2026-10-16"))
        assert set(edits_by_cve(misp)) == {DUE}
        assert FLIP not in misp.added_values()
        assert status["kev_update"]["foreign_only"] == 1
        assert f"only in events EdgeGuard did not create ({FLIP})" in caplog.text

    def test_a_cve_in_an_edgeguard_event_and_in_another_event_has_only_its_own_copy_edited(self, env):
        clock = Clock()
        misp = stored_after(catalogue("2026-09-16"), clock)
        own = misp.by_value(DUE)
        foreign = copy.deepcopy(own)
        foreign.update(uuid="9b6f4c1e-0000-4000-8000-000000000900", id="3999999", event_id="900")
        misp.events["900"] = "Analyst triage: exploited kernels"
        misp.attributes.append(foreign)
        status = run(misp, catalogue("2026-10-16"))
        edited = [uid for uid, _changes in misp.edits()]
        assert own["uuid"] in edited and foreign["uuid"] not in edited
        assert meta(foreign)["cisa_action_due"] == "2026-09-09" and meta(own)["cisa_action_due"] == "2026-08-29"
        assert status["kev_update"]["foreign_only"] == 0 and status["kev_update"]["updated"] == 2

    def test_an_addition_misp_does_not_store_fails_the_run(self, env):
        # MISP answers 200 for the batch without storing one CVE: the run asks MISP by value
        # (``push_additions``) and counts only what MISP then holds as added.
        clock = Clock()
        misp = stored_after(catalogue("2026-09-16"), clock)
        misp.adds_not_stored.add(NEW[0])
        status = run(misp, catalogue("2026-10-16"))
        update = status["kev_update"]
        assert (update["added"], update["failed"], update["not_written"]) == (1, 1, [NEW[0]])
        assert status["success"] is False and status["failed"] == 1

    def test_listing_rows_without_their_event_are_never_edited(self, env):
        # A MISP answer without ``Event.info`` cannot show that a copy is EdgeGuard's: nothing is
        # edited or added for it, and the run says so.
        clock = Clock()
        misp = stored_after(catalogue("2026-09-16"), clock)
        misp.rows_without_event = True
        status = run(misp, catalogue("2026-10-16"))
        assert misp.edits() == [] and sorted(misp.added_values()) == sorted(NEW)
        assert status["kev_update"]["foreign_only"] == 5

    def test_updates_switched_off_add_only(self, env):
        env.setenv("EDGEGUARD_KEV_UPDATE_EXISTING", "false")
        clock = Clock()
        misp = stored_after(catalogue("2026-09-16"), clock)
        status = run(misp, catalogue("2026-10-16"))
        assert misp.edits() == [] and sorted(misp.added_values()) == sorted(NEW)
        assert status["kev_update"]["stored_not_updated"] == 5

    def test_an_edit_misp_does_not_store_fails_the_run_and_is_planned_again(self, env):
        clock = Clock()
        misp = stored_after(catalogue("2026-09-16", FLIP, DUE), clock)
        misp.edits_not_stored.add(misp.by_value(FLIP)["uuid"])
        status = run(misp, catalogue("2026-10-16", FLIP, DUE))
        update = status["kev_update"]
        assert (update["updated"], update["failed"], update["not_written"]) == (1, 1, [FLIP])
        assert status["failed"] == 1 and status["success"] is False, "1 of 2 writes is below the 95% gate"
        misp.edits_not_stored.clear()
        misp.posts.clear()
        retry = run(misp, catalogue("2026-10-16", FLIP, DUE))
        assert set(edits_by_cve(misp)) == {FLIP} and retry["success"]

    def test_an_edit_whose_timestamp_misp_did_not_move_is_not_confirmed(self, env):
        # The incremental sync re-reads an attribute only when its timestamp moves: an edit MISP stored
        # without a newer timestamp would never reach the graph, so it counts as failed.
        clock = Clock()
        misp = stored_after(catalogue("2026-09-16", FLIP), clock)
        misp.edits_keep_timestamp.add(misp.by_value(FLIP)["uuid"])
        status = run(misp, catalogue("2026-10-16", FLIP))
        assert len(misp.edits()) == 1 and "ransomware:known" in tags(misp.by_value(FLIP)), "stored, not stamped"
        assert status["kev_update"]["failed"] == 1 and status["kev_update"]["updated"] == 0

    def test_removed_entries_are_counted_and_kept(self, env, caplog):
        clock = Clock()
        misp = stored_after(catalogue("2026-10-16"), clock)
        remaining = [e for e in catalogue("2026-10-16") if e["cveID"] != OLD_FLIP]
        with caplog.at_level(logging.WARNING, logger="collectors.cisa_collector"):
            status = run(misp, remaining)
        assert misp.writes() == []
        update = status["kev_update"]
        assert (update["stored_not_in_catalogue"], update["stored_not_in_catalogue_ids"]) == (1, [OLD_FLIP])
        assert "no longer in the catalogue (CVE-2012-0158)" in caplog.text and status["success"]

    def test_a_removed_entry_held_only_in_another_event_is_not_counted(self, env):
        clock = Clock()
        misp = stored_after(catalogue("2026-10-16"), clock)
        misp.events["900"] = "Analyst triage: Log4j"
        misp.by_value(LOG4SHELL)["event_id"] = "900"
        remaining = [e for e in catalogue("2026-10-16") if e["cveID"] not in (OLD_FLIP, LOG4SHELL)]
        status = run(misp, remaining)
        assert status["kev_update"]["stored_not_in_catalogue_ids"] == [OLD_FLIP]

    def test_an_empty_catalogue_compares_nothing(self, env):
        misp = new_misp(Clock())
        status = run(misp, [])
        assert misp.posts == []
        assert status["success"] and status["skipped"] and status["skip_reason_class"] == "cisa_empty_catalogue"


# --------------------------------------------------------------------------- caps and stop rules
def _revised(entries: list) -> list:
    """The same real entries, each with its due date one day later: a revision of every entry."""
    out = copy.deepcopy(entries)
    for e in out:
        e["dueDate"] = (datetime.fromisoformat(e["dueDate"]) + timedelta(days=1)).strftime("%Y-%m-%d")
    return out


class TestCapsAndStopRules:
    def test_the_edit_cap_defers_the_rest_and_the_next_run_finishes(self, env):
        env.setenv("EDGEGUARD_KEV_MAX_EDITS_PER_RUN", "2")
        clock = Clock()
        older = [entry("2026-05-22", OLD_FLIP), entry("2026-05-22", TEXT)] + catalogue("2026-09-16", FLIP, DUE)
        misp = stored_after(older, clock)
        first = run(misp, catalogue("2026-10-16", OLD_FLIP, TEXT, FLIP, DUE))
        # Newest dateAdded first: CVE-2022-0995 (2026-08-26), CVE-2026-63077 (2026-08-05).
        assert set(edits_by_cve(misp)) == {DUE, FLIP}
        assert (first["kev_update"]["updated"], first["kev_update"]["deferred"]) == (2, 2)
        assert first["success"] and first["failed"] == 0, "a deferred edit is no failure"
        misp.posts.clear()
        second = run(misp, catalogue("2026-10-16", OLD_FLIP, TEXT, FLIP, DUE))
        assert set(edits_by_cve(misp)) == {TEXT, OLD_FLIP} and second["kev_update"]["deferred"] == 0
        misp.posts.clear()
        run(misp, catalogue("2026-10-16", OLD_FLIP, TEXT, FLIP, DUE))
        assert misp.writes() == []

    def test_an_explicit_limit_lowers_the_cap_and_cuts_the_additions(self, env):
        clock = Clock()
        misp = stored_after(catalogue("2026-09-16"), clock)
        status = run(misp, catalogue("2026-10-16"), limit=1)
        assert len(misp.edits()) == 1 and len(misp.added_values()) == 1
        assert status["kev_update"]["deferred"] == 2

    def test_five_failed_edits_in_a_row_stop_the_loop(self, env):
        clock = Clock()
        misp = stored_after(catalogue("2026-10-16"), clock)
        for attribute in misp.attributes:
            misp.edit_status[attribute["uuid"]] = 403
        status = run(misp, _revised(catalogue("2026-10-16")))
        assert len(misp.edits()) == 5
        update = status["kev_update"]
        assert (update["failed"], update["deferred"], update["updated"]) == (5, 2, 0)
        assert update["stop_reasons"] == ["stopped after 5 failed edits in a row"]
        assert status["success"] is False

    def test_failures_that_are_not_five_in_a_row_do_not_stop_the_loop(self, env):
        # Six of seven edits fail, the fourth (CVE-2025-21042, newest dateAdded first) succeeds: never five
        # failures in a row, so every edit is attempted.
        clock = Clock()
        misp = stored_after(catalogue("2026-10-16"), clock)
        for attribute in misp.attributes:
            if attribute["value"] != "CVE-2025-21042":
                misp.edit_status[attribute["uuid"]] = 403
        status = run(misp, _revised(catalogue("2026-10-16")))
        assert len(misp.edits()) == 7
        update = status["kev_update"]
        assert (update["failed"], update["updated"], update["deferred"], update["stop_reasons"]) == (6, 1, 0, [])

    def test_the_time_budget_defers_the_rest(self, env):
        env.setenv("EDGEGUARD_MISP_REFRESH_MAX_SECONDS", "10")
        ticks = iter(range(0, 1000, 6))
        env.setattr(vulnerability_update, "time", SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _s: None))
        clock = Clock()
        misp = stored_after(catalogue("2026-10-16"), clock)
        status = run(misp, _revised(catalogue("2026-10-16")))
        update = status["kev_update"]
        assert (update["updated"], update["deferred"], update["failed"]) == (2, 5, 0)
        assert update["stop_reasons"] == ["EDGEGUARD_MISP_REFRESH_MAX_SECONDS=10 spent"]
        assert status["success"]


def test_edits_pause_every_50_and_check_the_parent_run():
    sleeps, checks = [], []
    writer = SimpleNamespace(update_attribute=lambda *_a, **_k: True, liveness_callback=lambda: checks.append(1))
    stored = KnownAttribute(uuid="u", event_id="1", meta_digest=None, tags=(), written=1.0)
    edits = [PlannedEdit(f"CVE-2026-{n:05d}", stored, {"comment": "x"}, ()) for n in range(120)]
    with (
        patch.dict("os.environ", {"EDGEGUARD_MISP_BATCH_THROTTLE_SEC": "5"}),
        patch.object(vulnerability_update.time, "sleep", side_effect=sleeps.append),
    ):
        outcome = apply_vulnerability_edits(writer, edits, label="KEV")
    assert outcome.updated == 120 and sleeps == [5.0, 5.0] and len(checks) == 2


def test_each_edit_is_confirmed_against_the_stored_timestamp():
    calls = []
    writer = SimpleNamespace(update_attribute=lambda uuid, changes, written_after=None: calls.append(written_after))
    stored = KnownAttribute(uuid="u", event_id="1", meta_digest=None, tags=(), written=1791887497.0)
    apply_vulnerability_edits(writer, [PlannedEdit("CVE-2025-21042", stored, {"comment": "x"}, ())], label="KEV")
    assert calls == [1791887497.0]


# --------------------------------------------------------------------------- scope
class TestScope:
    def test_preview_returns_the_whole_catalogue_newest_first(self, env):
        misp = new_misp(Clock())
        items = run(misp, catalogue("2026-10-16"), push_to_misp=False)
        assert [i["cve_id"] for i in items] == [
            "CVE-2025-61624",  # 2026-10-16
            DUE,  # 2026-08-26
            FLIP,  # 2026-08-05
            "CVE-2025-21042",  # 2025-11-10
            TEXT,  # 2025-04-01
            LOG4SHELL,  # 2021-12-10
            OLD_FLIP,  # 2021-11-03
        ]
        assert misp.posts == []

    def test_entries_added_on_the_same_day_follow_the_cve_id(self, env):
        # CISA adds several entries on one day; among them the order is the CVE id's, not the feed's.
        same_day = catalogue("2026-10-16")
        for e in same_day:
            e["dateAdded"] = "2026-10-16"
        feed_order = [e["cveID"] for e in same_day]
        assert feed_order != sorted(feed_order)
        items = run(new_misp(Clock()), same_day, push_to_misp=False)
        assert [i["cve_id"] for i in items] == sorted(feed_order)

    def test_an_incremental_run_is_not_cut_at_the_generic_limit(self, env):
        assert config.get_effective_limit("cisa") is None and config.get_effective_limit("cisa_kev") is None


# --------------------------------------------------------------------------- pieces
class TestPieces:
    def test_meta_changed_keys_normalises_like_the_digest(self):
        stored = meta(FIXTURES["misp"]["CVE-2025-21042"])
        assert meta_changed_keys(stored, dict(stored, last_modified="2026-10-16", attack_vector=None)) == []
        assert meta_changed_keys(stored, dict(stored, known_ransomware_use="")) == []
        assert meta_changed_keys(stored, dict(stored, cisa_action_due="2025-12-02")) == ["cisa_action_due"]
        assert meta_changed_keys(None, {"description": "x", "cwe": []}) == ["description"]

    def test_listing_rows_give_the_timestamp_the_event_and_with_keep_meta_the_meta(self, env):
        hosted = copy.deepcopy(FIXTURES["misp"]["CVE-2025-21042"])
        writer = MISPWriter(url="https://misp.test", api_key="test", verify_ssl=True)
        writer.session = MagicMock()
        writer.session.post.return_value = SimpleNamespace(
            status_code=200, json=lambda: {"response": {"Attribute": [hosted]}}, text=""
        )
        (kept,) = writer.index_source_attributes("source:CISA-KEV", "vulnerability", keep_meta=True)["CVE-2025-21042"]
        assert kept.written == 1791887497.0 and kept.own_event is True and kept.meta == meta(hosted)
        (plain,) = writer.index_source_attributes("source:CISA-KEV", "vulnerability")["CVE-2025-21042"]
        assert plain.meta is None and plain.meta_digest == kept.meta_digest
        hosted["Event"]["info"] = "Shared by a partner: KEV extract"
        (foreign,) = writer.index_source_attributes("source:CISA-KEV", "vulnerability")["CVE-2025-21042"]
        assert foreign.own_event is False

    def test_a_cve_listed_twice_is_planned_once(self):
        writer = MISPWriter.__new__(MISPWriter)
        collector = CISACollector.__new__(CISACollector)
        collector.tag = "cisa_kev"
        kev = collector._kev_item(entry("2026-10-16", FLIP))
        twice = [kev, dict(kev, cve_id=FLIP.lower())]
        assert len(plan_source_updates(writer, twice, {}, update_existing=True, max_edits=10).to_add) == 1
        stored = [KnownAttribute(uuid="u0", event_id="1", meta_digest=None, tags=("source:CISA-KEV",))]
        assert len(plan_source_updates(writer, twice, {FLIP: stored}, update_existing=True, max_edits=10).edits) == 1

    def test_a_cve_with_more_copies_than_the_cap_is_still_planned(self):
        writer = MISPWriter.__new__(MISPWriter)
        item = CISACollector.__new__(CISACollector)
        item.tag = "cisa_kev"
        kev = item._kev_item(entry("2026-10-16", FLIP))
        copies = [
            KnownAttribute(uuid=f"u{n}", event_id=str(n), meta_digest=None, tags=("source:CISA-KEV",)) for n in range(3)
        ]
        plan = plan_source_updates(writer, [kev], {FLIP: copies}, update_existing=True, max_edits=1)
        assert len(plan.edits) == 3 and plan.deferred_ids == []


# --------------------------------------------------------------------------- the edit reaches the graph
def test_a_kev_edit_reaches_the_cve_node(env):
    """The production path after the revision of 2026-10-16: the edited attribute passes the incremental
    sync's changed-attribute filter, ``parse_attribute`` reads the new ``NVD_META``, and ``merge_cve`` sets
    the KEV-owned fields from it and replaces the ``SOURCED_FROM`` edge's ``raw_data``."""
    import os

    from run_misp_to_neo4j import MISPToNeo4jSync, _attribute_changed_since

    clock = Clock()
    misp = stored_after(catalogue("2026-09-16", FLIP, DUE), clock)
    window_start = datetime.fromtimestamp(clock.now + 1800, tz=timezone.utc)
    assert not any(_attribute_changed_since(a, window_start) for a in misp.attributes)
    run(misp, catalogue("2026-10-16", FLIP, DUE))
    attr = misp.by_value(DUE)
    assert _attribute_changed_since(attr, window_start), "the edit moved the attribute's timestamp"

    event = {"id": attr["event_id"], "info": misp.events[attr["event_id"]], "date": "2026-10-16", "Tag": []}
    item, _relationships = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(copy.deepcopy(attr), event)
    assert (item["tag"], item["cisa_action_due"]) == ("cisa_kev", "2026-08-29")
    flipped = misp.by_value(FLIP)
    flipped_item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(copy.deepcopy(flipped), event)
    assert flipped_item["known_ransomware_use"] == "Known"

    with patch.dict(os.environ, {"NEO4J_PASSWORD": "test", "MISP_API_KEY": "test"}):
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        session = MagicMock()
        session.run.return_value.single.return_value = None
        client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
        client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
        assert client.merge_cve(item, source_id=item["tag"])
    calls = [(c[0][0], c[1]) for c in session.run.call_args_list]
    (merge_query, merge_params) = next((q, p) for q, p in calls if q.lstrip().startswith("MERGE (n:CVE"))
    assert "n.cisa_action_due = $cisa_action_due" in merge_query and merge_params["cisa_action_due"] == "2026-08-29"
    (edge_query, edge_params) = next((q, p) for q, p in calls if "MERGE (n)-[r:SOURCED_FROM]->(s)" in q)
    assert "r.raw_data = $raw_data" in edge_query.split("ON CREATE SET", 1)[1].split("SET r.confidence", 1)[1]
    assert json.loads(edge_params["raw_data"])["cisa_action_due"] == "2026-08-29"


# --------------------------------------------------------------------------- the CVE node's KEV fields
def _session_client():
    import os

    with patch.dict(os.environ, {"NEO4J_PASSWORD": "test", "MISP_API_KEY": "test"}):
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    session = MagicMock()
    session.run.return_value.single.return_value = None
    client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return client, session


def _merge_statement(session) -> tuple:
    return next((c[0][0], c[1]) for c in session.run.call_args_list if c[0][0].lstrip().startswith("MERGE (n:"))


_KEV_FIELDS = ("cisa_exploit_add", "cisa_action_due", "cisa_required_action", "cisa_vulnerability_name")


@pytest.mark.parametrize("source_id", ["cisa_kev", "cisa"])
def test_a_kev_record_sets_the_kev_fields(source_id):
    collector = CISACollector.__new__(CISACollector)
    collector.tag = "cisa_kev"
    item = collector._kev_item(entry("2026-10-16", DUE))
    client, session = _session_client()
    assert client.merge_cve(item, source_id=source_id)
    query, params = _merge_statement(session)
    for field in _KEV_FIELDS:
        assert f"n.{field} = ${field}" in query and params[field] == item[field]
    assert params["cisa_action_due"] == "2026-08-29"


def test_another_record_only_fills_the_kev_fields():
    """NVD's record of CVE-2022-0995 kept the due date CISA moved on 2026-10-08 (NVD did not move its
    lastModified): merged after the KEV record, it must not write the old date back."""
    nvd_item = {
        "cve_id": DUE,
        "tag": "nvd",
        "zone": ["global"],
        "nvd_record": True,
        "cisa_exploit_add": "2026-08-26",
        "cisa_action_due": "2026-09-09",
        "cisa_required_action": "Apply mitigations per vendor instructions.",
        "cisa_vulnerability_name": "Linux Kernel Out-of-Bounds Write Vulnerability",
    }
    client, session = _session_client()
    assert client.merge_cve(nvd_item, source_id="nvd")
    query, params = _merge_statement(session)
    for field in _KEV_FIELDS:
        assert f"n.{field} = ${field}" not in query
        assert (
            f"n.{field} = CASE WHEN n.{field} IS NULL OR n.{field} = '' THEN $fill_{field} ELSE n.{field} END" in query
        )
        assert params[f"fill_{field}"] == nvd_item[field]


def test_the_stix_import_keeps_the_record_on_the_edge(env):
    """The opt-in STIX flow (``run_pipeline --stix-flow``) writes a reduced record under the MISP event's
    source id (``cisa_kev`` for a KEV event): no NVD_META, CVSS or KEV fields. It is written only when it
    creates the edge, never over the source's record that the sync wrote there."""
    from run_misp_to_neo4j import MISPToNeo4jSync
    from run_pipeline import EdgeGuardPipeline

    clock = Clock()
    misp = stored_after(catalogue("2026-10-16", DUE), clock)
    sdo = MISPToNeo4jSync(neo4j_client=MagicMock())._attribute_to_stix21(
        copy.deepcopy(misp.by_value(DUE)), "00000000-0000-4000-8000-000000000000", ["global"]
    )
    sdo["x_edgeguard_source"] = "cisa_kev"  # as the STIX flow stamps the objects of a KEV event
    client, session = _session_client()
    pipeline = EdgeGuardPipeline.__new__(EdgeGuardPipeline)
    pipeline.neo4j = client
    assert pipeline.load_stix21_to_neo4j({"type": "bundle", "objects": [sdo]})["vulnerabilities"] == 1
    (edge_query,) = [c[0][0] for c in session.run.call_args_list if "MERGE (n)-[r:SOURCED_FROM]->(s)" in c[0][0]]
    assert edge_query.count("r.raw_data = $raw_data") == 1, "ON CREATE SET only"


def test_only_a_cve_write_refreshes_the_edge_record():
    client, session = _session_client()
    assert client.merge_indicator(
        {"indicator_type": "ipv4", "value": "203.0.113.7", "tag": "alienvault_otx", "zone": ["global"]},
        source_id="alienvault_otx",
    )
    (edge_query,) = [c[0][0] for c in session.run.call_args_list if "MERGE (n)-[r:SOURCED_FROM]->(s)" in c[0][0]]
    assert edge_query.count("r.raw_data = $raw_data") == 1, "an Indicator's edge keeps the record that created it"
