"""OTX scheduled runs: the retry list (2026-11-02).

With the per-run limit taking the oldest pulses after the cursor first, a pulse whose item MISP kept refusing
held the cursor below it, and every run took the same pulses again while the newer ones waited, each run red.
A scheduled run now tells two kinds of failed push apart:

- Items failed in batches MISP answered (HTTP 4xx, or 429 / 5xx after the retries), or in a systemic
  conversion drop: the cursor advances as after a push without failures, and every pulse a listed item names
  (``pulse_id`` and ``report_ids``) goes on a retry list in the incremental state (``otx_retry_pulses``). This
  holds whatever share of the push failed: one value MISP refuses fails its whole batch, which can hold every
  new item of the push. Each later run fetches up to ``EDGEGUARD_OTX_RETRY_PER_RUN`` of the listed pulses by id
  (``/api/v1/pulses/{id}``), processes them after its window's pulses (outside the limit, never moving the
  cursor) and pushes the items of every listed pulse in batches of their own (``push_items``' ``batch_key``),
  so a value MISP refuses fails only its own pulse. A pulse leaves the list when none of its items is listed
  and the items recorded as failed were pushed again. A pulse still failing ``EDGEGUARD_OTX_RETRY_MAX_DAYS``
  after its first failure, tried since that deadline, or beyond ``EDGEGUARD_OTX_RETRY_MAX_PULSES``, is given up
  with an ERROR (``[OTX-RETRY-GAVE-UP]``) and counted in ``edgeguard_otx_retry_given_up_total``.
- Every listed item failed at its MISP event (``last_push_event_failed_items``: MISP unreachable, the lookup or
  creation of the day's event failing), so none of them reached a batch: the cursor stops below the oldest pulse
  with a listed item, as before, and nothing goes on the list.

The runs use the OTX double, the fixture pulses and the writer doubles of ``test_otx_incremental_order.py``,
and ``MISPWriter`` itself against the MISP doubles of ``test_otx_partial_cursor.py``. The pulse fetched by id
in ``test_the_real_answer_by_id_is_processed_like_a_subscribed_pulse`` is OTX's answer of 2026-11-02
(``tests/fixtures/otx_pulse_by_id_2026_11_02.json``). Every test here fails without the retry list, except four
guards that say so: an expired pulse the limit defers, a last try later than the run, a run that does not push
(without a list nothing is fetched or given up), and the fresh baseline's wipe of the list. A test of a later fix
says what the earlier revision of the retry list did.
"""

from __future__ import annotations

import ast
import copy
import io
import json
import os
import sys
import tokenize
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

import pytest
import requests
import yaml

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from test_otx_incremental_order import (  # noqa: E402  (its OTX harness)
    IDS,
    NO_RETRY,
    ROWS,
    _collect,
    _ids,
    _listed,
    _Otx,
    _pulse,
    _recorded,
    _utc,
    _value,
    _Writer,
    _WriterWithoutList,
)
from test_otx_partial_cursor import (  # noqa: E402
    _baseline,
    _counted,
    _HoldingMisp,
    _indicator,
    _Misp,
    _misp_values,
    _UnreachableMisp,
    _unreadable,
    _writer,
)

import baseline_checkpoint  # noqa: E402
import baseline_clean  # noqa: E402
import config  # noqa: E402
from collectors import misp_writer as mw  # noqa: E402
from collectors import otx_collector  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_BY_ID = json.loads((_ROOT / "tests" / "fixtures" / "otx_pulse_by_id_2026_11_02.json").read_text(encoding="utf-8"))
_RULES = yaml.safe_load((_ROOT / "prometheus" / "alerts.yml").read_text())
_RUNBOOK_SECTION = "OTX retry backlog and given-up pulses"


@pytest.fixture(autouse=True)
def _misp_env(monkeypatch, tmp_path):
    """The settings ``test_otx_partial_cursor.py`` runs ``MISPWriter`` with, the default batch size of 500, and the
    retry settings unset."""
    monkeypatch.setattr(mw, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", True)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.delenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", raising=False)
    monkeypatch.setattr(mw.time, "sleep", lambda _s: None)
    for name in (
        "EDGEGUARD_OTX_RETRY_PER_RUN",
        "EDGEGUARD_OTX_RETRY_MAX_DAYS",
        "EDGEGUARD_OTX_RETRY_MAX_PULSES",
        "EDGEGUARD_OTX_RETRY_MAX_SECONDS",
        "EDGEGUARD_MISP_BACKOFF_THRESHOLD",
        "EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC",
    ):
        monkeypatch.delenv(name, raising=False)


def _ago(days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _entry(index: int, days: float, attempts: int = 1, tried_days: Optional[float] = None) -> Dict[str, Any]:
    """A retry-list entry for fixture pulse *index*, first failed *days* ago (last tried *tried_days* ago)."""
    return {
        "id": IDS[index],
        "modified": ROWS[index]["modified"],
        "first_failed_at": _ago(days),
        "last_tried_at": _ago(days if tried_days is None else tried_days),
        "attempts": attempts,
        "last_reason": "1 item(s) listed as unstored; MISP push of an earlier run",
    }


def _raw_key(index: int) -> str:
    """The identity key of fixture pulse *index*'s indicator (``_pulse_item_key``)."""
    return otx_collector._pulse_item_key({"indicator_type": "ipv4", "value": _value(index)})


def _key(index: int) -> str:
    """The reference ``failed_items`` keeps of fixture pulse *index*'s indicator (its type and 16 hex digits of
    the SHA-256 of its identity key)."""
    return otx_collector._item_ref({"indicator_type": "ipv4", "value": _value(index)})


def _sample(name: str) -> float:
    from prometheus_client import REGISTRY

    import metrics_server  # noqa: F401  (registers the metrics)

    return REGISTRY.get_sample_value(name) or 0.0


GIVEN_UP = "edgeguard_otx_retry_given_up_total"
PENDING = "edgeguard_otx_retry_pulses"
OLDEST = "edgeguard_otx_retry_oldest_failure_timestamp_seconds"


# --------------------------------------------------------------------------- an item failure


def test_an_item_failure_advances_the_cursor_and_puts_the_pulse_on_the_list(caplog):
    """Stored cursor at pulse 59, a limit of 20: the run takes pulses 39-58 (59 re-read) and pulse 44's item is
    not stored while the other 20 are. The cursor advances to pulse 39, the newest processed, and pulse 44 goes
    on the retry list with its ``modified``, the start of the run as its first failure, one attempt and its
    failed item. The previous rule stopped the cursor below pulse 44, at pulse 45, and listed nothing."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"]}
    before = datetime.now(timezone.utc)
    run = _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[44]]))

    assert run.cursor == ROWS[39]["modified"]
    assert [{k: v for k, v in e.items() if not k.endswith("_at")} for e in run.retry] == [
        {
            "id": IDS[44],
            "modified": ROWS[44]["modified"],
            "attempts": 1,
            "last_reason": run.retry[0]["last_reason"],
            "failed_items": [_key(44)],
        }
    ]
    entry = run.retry[0]
    assert entry["first_failed_at"] == entry["last_tried_at"]
    assert before <= _utc(entry["first_failed_at"]) <= datetime.now(timezone.utc)
    assert entry["last_reason"].startswith("1 item(s) listed as unstored; MISP push of ")
    assert entry["last_reason"].endswith(": 1 of 21 item(s) failed")
    assert run.status["pulse_counts"] == {
        "rows_read": 60,
        "distinct": 60,
        "repeated_rows": 0,
        "processed": 21,
        "without_item": 0,
        "deferred": 39,
        **NO_RETRY,
        "retry_pending": 1,
        "retry_added": 1,
    }
    assert any(
        m.startswith("[OTX-RETRY] OTX: 1 pulse(s) put on the retry list:") and m.endswith(f"(ids: {IDS[44]})")
        for m in run.warnings
    )
    assert any(m.startswith("[OTX-RETRY] OTX: 1 pulse(s) on the retry list after the run") for m in run.warnings)


def test_the_next_run_fetches_the_pulse_by_id_and_recovers_it(caplog):
    """After the run above, the next run takes the newer pulses 19-38 (39 re-read) and fetches pulse 44 by id:
    one ``GET /api/v1/pulses/<id>`` with the collector's timeouts and TLS setting, then a 2 s pause. Its item is
    stored, so it leaves the list (INFO ``recovered``). The previous rule read pulse 44 again in the window,
    with the 20 oldest pulses after the held cursor."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"]}
    _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[44]]))
    sleeps: List[float] = []
    writer = _Writer()
    run = _collect(otx, state, caplog, limit=20, sleeps=sleeps, writer=writer)

    assert otx.by_id_requests == [IDS[44]]
    (call,) = otx.by_id_calls
    assert call["method"] == "GET" and call["url"] == f"https://otx.example/api/v1/pulses/{IDS[44]}"
    assert call["timeout"] == (otx_collector.OTX_CONNECT_TIMEOUT, otx_collector.OTX_REQUEST_TIMEOUT)
    assert call["verify"] == otx_collector.SSL_VERIFY and call["session"] is not None
    assert sleeps.count(2) == 2, "one pause after the page request, one after the fetch by id"
    assert sorted(run.processed) == sorted(_ids(range(19, 40)) + [IDS[44]])
    assert [k for k, item in zip(writer.batch_keys, writer.pushed, strict=True) if item["pulse_id"] == IDS[44]] == [
        IDS[44]
    ], "the listed pulse's item is batched apart"
    assert set(writer.batch_keys) == {None, IDS[44]}
    assert run.cursor == ROWS[19]["modified"]
    assert run.retry == [] and state["otx_retry_pulses"] == []
    assert run.status["pulse_counts"]["retry_fetched"] == 1 and run.status["pulse_counts"]["retry_recovered"] == 1
    assert (
        "[OTX-RETRY] OTX: 1 pulse(s) recovered: none of their items is listed as unstored, and they leave the "
        f"retry list (ids: {IDS[44]})" in run.messages
    )


def test_a_retried_pulse_counts_toward_no_limit_and_never_moves_the_cursor(caplog):
    """Stored cursor at pulse 59, a limit of 20, and three pulses on the list that OTX answers by id with a
    ``modified`` newer than every pulse of the window (modified again after the page requests). The window still
    counts 20 pulses (39-58, 59 re-read, 39 deferred), the three are processed on top, and the cursor goes to
    pulse 39, not to their ``modified``: a cursor taken from them would pass the pulses modified between the
    window's request and theirs. Without the retry list no pulse was fetched by id."""
    otx = _Otx(_recorded(range(60)))
    extra = [
        _pulse(f"6a00000000000000000000a{n}", "2026-11-02T00:00:00", "2026-11-01T00:00:00", 70 + n) for n in range(3)
    ]
    otx.by_id_only = {p["id"]: p for p in extra}
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[59]["modified"],
        "otx_retry_pulses": [{"id": p["id"], "first_failed_at": _ago(1), "attempts": 1} for p in extra],
    }
    run = _collect(otx, state, caplog, limit=20)

    assert sorted(otx.by_id_requests) == sorted(p["id"] for p in extra)
    assert sorted(run.processed) == sorted(_ids(range(39, 60)) + [p["id"] for p in extra])
    assert run.status["pulse_counts"]["processed"] == 21 and run.status["pulse_counts"]["deferred"] == 39
    assert run.cursor == ROWS[39]["modified"]
    assert run.retry == [] and run.status["pulse_counts"]["retry_recovered"] == 3


def test_a_retried_pulse_comes_after_the_window_in_the_same_run_fold(caplog):
    """A pulse on the list, fetched by id, lists the value of pulse 0, which the window reads again. The pulses
    fetched by id are processed after the window's, so the same-run fold keeps pulse 0's copy (its id, name, TLP
    and ``last_seen``) and names the retried pulse in ``report_ids``; the item goes in the window's batch. The
    other order would push the item under the older retried pulse."""
    retried = _pulse("6a00000000000000000000d1", "2026-09-01T00:00:00", "2026-08-01T00:00:00", 1)
    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {retried["id"]: retried}
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[0]["modified"],
        "otx_retry_pulses": [{"id": retried["id"], "first_failed_at": _ago(1), "attempts": 1}],
    }
    writer = _Writer()
    run = _collect(otx, state, caplog, limit=20, writer=writer)

    (shared,) = [item for item in writer.pushed if item["value"] == _value(0)]
    assert shared["pulse_id"] == IDS[0] and shared["report_ids"] == [retried["id"]]
    assert shared["pulse_name"] == "pulse 1" and shared["last_seen"] == ROWS[0]["modified"]
    assert writer.batch_keys[writer.pushed.index(shared)] is None
    assert run.retry == []


@pytest.mark.parametrize("stores", [True, False], ids=["stores", "fails again"])
def test_a_pulse_of_the_list_read_again_in_the_window_is_processed_there(caplog, stores):
    """Pulse 50, on the list, was modified again and is in the run's window (cursor at 59, limit 20): it is not
    fetched by id, and its item is batched apart. When its item is stored it leaves the list; when it fails
    again it stays, with one more attempt, its first failure kept and its ``modified`` as the window read it."""
    otx = _Otx(_recorded(range(60)))
    old = _entry(50, days=2, attempts=4)
    old["modified"] = "2026-10-01T00:00:00"
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"], "otx_retry_pulses": [old]}
    writer = _Writer(failing=[] if stores else [IDS[50]])
    run = _collect(otx, state, caplog, limit=20, writer=writer)

    assert otx.by_id_requests == []
    assert IDS[50] in run.processed
    assert writer.batch_keys[run.processed.index(IDS[50])] == IDS[50]
    if stores:
        assert run.retry == [] and run.status["pulse_counts"]["retry_recovered"] == 1
    else:
        (entry,) = run.retry
        assert (entry["attempts"], entry["first_failed_at"], entry["modified"]) == (
            5,
            old["first_failed_at"],
            ROWS[50]["modified"],
        )


def test_an_expired_pulse_of_the_list_the_limit_defers_is_not_given_up(caplog):
    """Pulse 10, on the list, first failed 8 days ago and last tried 7.5 days ago, before its deadline (7 days).
    It is read in the run's window (cursor at pulse 59, so the run reads pulses 0-59) but the limit of 20 defers
    it: it is neither fetched by id nor changed, and not given up, since no run tried it after its deadline; a
    later run processes it in its window, where the cursor cannot pass it. Fetched by id as well, it would be
    pushed twice. The earlier revision gave it up for its age alone; without the retry list (guard) nothing is
    given up."""
    otx = _Otx(_recorded(range(60)))
    entry = _entry(10, days=8, tried_days=7.5)
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"], "otx_retry_pulses": [entry]}
    given_up = _sample(GIVEN_UP)
    run = _collect(otx, state, caplog, limit=20)

    assert otx.by_id_requests == [] and IDS[10] not in run.processed
    assert run.retry == [entry]
    assert _sample(GIVEN_UP) == given_up and not run.errors


# --------------------------------------------------------------------------- batches of their own


def test_a_value_misp_refuses_fails_its_batch_and_the_retries_in_batches_of_their_own_free_the_other_pulses(caplog):
    """``MISPWriter`` with its default batch of 500, the cursor at pulse 5 and MISP refusing pulse 2's value
    (HTTP 500 on every attempt, nothing of the batch stored). Run 1 pushes the items of pulses 0-7 in one batch,
    which fails as a whole: every item is listed, in a batch MISP answered, so the failure is one of items, not
    of the push. The cursor advances to pulse 0 and the eight pulses go on the list. Run 2 reads pulses 0 and 1
    again in its window and fetches 2-7 by id; each listed pulse is pushed in a batch of its own, so only pulse
    2's fails and the other seven leave the list.

    The earlier revision read run 1 as a failure of the whole push (every item listed): the cursor stayed at
    pulse 5, nothing went on the list, and every later run pushed the same batch and failed again."""
    misp = _HoldingMisp(refused_values=(_value(2),))
    writer = _writer(misp)
    counts = _counted(writer)
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[5]["modified"]}
    with patch("collectors.collector_utils.time.sleep"):
        first = _collect(otx, state, caplog, limit=20, writer=writer)
    assert sorted(first.processed) == sorted(_ids(range(8)))
    assert counts == [(0, 8)] and misp.refused_attempts == 4
    assert writer.last_push_unstored_items == list(range(8)) and writer.last_push_event_failed_items == []
    assert first.cursor == ROWS[0]["modified"]
    assert _listed(first) == sorted(_ids(range(8)))

    with patch("collectors.collector_utils.time.sleep"):
        second = _collect(otx, state, caplog, limit=20, writer=writer)
    assert sorted(otx.by_id_requests) == sorted(_ids(range(2, 8)))
    assert counts[1] == (7, 1) and misp.refused_attempts == 8
    assert misp.batch_no == 7, "seven batches stored, one per pulse"
    assert _misp_values(misp) == {_value(i) for i in range(8)} - {_value(2)}
    assert _listed(second) == [IDS[2]] and second.retry[0]["attempts"] == 2
    assert second.status["pulse_counts"]["retry_recovered"] == 7
    assert second.cursor == ROWS[0]["modified"]


def test_while_misp_refuses_a_listed_pulse_the_new_pulses_are_stored_and_the_cursor_moves_on(caplog):
    """The stall the earlier revision kept, with ``MISPWriter`` and its default batch of 500: a baseline stored
    pulses 40-59, the cursor is at pulse 59 with a limit of 20, and MISP refuses pulse 39's value on runs 1-3.

    Run 1 takes pulses 39-58 (59 re-read): MISP holds 20 of the 21 items and refuses pulse 39's, so the push
    returns (0, 1), the cursor advances to pulse 39 and pulse 39 goes on the list. Run 2 takes the new pulses
    19-38 and reads pulse 39 again at the cursor; the window's push stores the new pulses, the cursor goes to
    pulse 19, and pulse 39 is pushed after it, in a batch of its own. Run 3 takes pulses 0-18 and fetches pulse
    39 by id; the cursor goes to pulse 0. Run 4, MISP accepting the value, stores it and empties the list. Run 1
    fails (it stored nothing); runs 2 and 3 pass the success-rate gate, which is unchanged.

    The earlier revision pushed pulse 39's item in the batch of the new pulses on run 2: the batch failed, every
    item was listed, the push read as one MISP failed as a whole, and the cursor stayed at pulse 39 on every run
    while pulses 0-38 waited."""
    pulses = _recorded(range(60))
    misp = _HoldingMisp(refused_values=(_value(39),))
    _baseline(pulses[40:], misp, caplog)
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"]}
    writer = _writer(misp)
    counts = _counted(writer)
    otx = _Otx(pulses)
    with patch("collectors.collector_utils.time.sleep"):
        runs = [_collect(otx, state, caplog, limit=20, writer=writer) for _ in range(3)]

    assert counts == [(0, 1), (20, 0), (0, 1), (19, 0), (0, 1)] and misp.refused_attempts == 12
    assert [r.cursor for r in runs] == [ROWS[39]["modified"], ROWS[19]["modified"], ROWS[0]["modified"]]
    assert [[(e["id"], e["attempts"]) for e in r.retry] for r in runs] == [[(IDS[39], n)] for n in (1, 2, 3)]
    assert otx.by_id_requests == [IDS[39]], "read in the window on run 2, fetched by id on run 3"
    assert {_value(i) for i in range(39)} <= _misp_values(misp), "the new pulses 0-38 are stored"
    assert [r.status["success"] for r in runs] == [False, True, True], (
        "run 1 stored nothing; runs 2 and 3 stored 20 of 21 and 19 of 20 items, at or above "
        "EDGEGUARD_MISP_MIN_SUCCESS_RATE (0.95)"
    )

    misp.refused.clear()
    answered = _collect(otx, state, caplog, limit=20, writer=writer)
    assert counts[5:] == [(0, 0), (1, 0)] and _value(39) in _misp_values(misp)
    assert answered.retry == [] and answered.cursor == ROWS[0]["modified"]


def test_a_window_pulse_without_an_id_that_shares_an_item_with_a_listed_pulse(caplog):
    """Pulse 45 of the window has no id (the collector keeps such a row as it is) and lists the value of a pulse on
    the list, fetched by id and processed after the window. The same-run fold keeps pulse 45's copy, whose
    ``pulse_id`` is empty and whose ``report_ids`` name the listed pulse, so only that pulse names the item: it goes
    in the push of the list's pulses, in that pulse's batches, and the pulse leaves the list. The window's other
    items are stored and the cursor advances. The previous revision ordered that push by the items' ``pulse_id``
    and raised ``KeyError: 'None'`` before the window's push, so every run that read pulse 45 failed with the
    cursor where it was."""
    (older,) = _listed_pulses(1)
    pulses = _recorded(range(60))
    pulses[45]["id"] = None
    pulses[45]["indicators"][0]["indicator"] = older["indicators"][0]["indicator"]
    otx = _Otx(pulses)
    otx.by_id_only = {older["id"]: older}
    entry = {"id": older["id"], "first_failed_at": _ago(1), "last_tried_at": _ago(0.5), "attempts": 2}
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"], "otx_retry_pulses": [entry]}
    writer = _Writer()
    run = _collect(otx, state, caplog, limit=20, writer=writer)

    assert run.status["success"] is True and run.cursor == ROWS[39]["modified"]
    (shared,) = [item for item in writer.pushed if item["value"] == older["indicators"][0]["indicator"]]
    assert shared["pulse_id"] is None and shared["report_ids"] == [older["id"]]
    assert [len(call["items"]) for call in writer.calls] == [20, 1]
    assert writer.calls[1]["items"] == [shared] and writer.batch_keys[-1] == older["id"]
    assert run.retry == [] and run.status["pulse_counts"]["retry_recovered"] == 1


# --------------------------------------------------------------------------- giving up


def test_a_pulse_failing_past_the_deadline_is_given_up(caplog):
    """Cursor at pulse 0, so the window holds only the re-reads 0 and 1. On the list: pulse 10, first failed 7.5
    days ago (40 attempts), whose item fails again; pulse 11, also 7.5 days ago, whose item is stored now; pulse
    12, first failed 6.5 days ago, failing (the limit is 7 days). All three are fetched, so tried after pulse
    10's and 11's deadline. Pulse 11 leaves as recovered (its last attempt succeeded), pulse 12 stays, and pulse
    10 is given up: an ERROR ``[OTX-RETRY-GAVE-UP]`` naming it with its ``modified`` and attempts, the counter
    ``edgeguard_otx_retry_given_up_total`` one higher. Nothing was ever given up before the retry list."""
    otx = _Otx(_recorded(range(60)))
    expired = _entry(10, days=7.5, attempts=40)
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[0]["modified"],
        "otx_retry_pulses": [expired, _entry(11, days=7.5, attempts=40), _entry(12, days=6.5)],
    }
    given_up = _sample(GIVEN_UP)
    run = _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[10], IDS[12]]))

    assert sorted(otx.by_id_requests) == sorted(_ids([10, 11, 12]))
    assert _listed(run) == [IDS[12]] and run.retry[0]["attempts"] == 2
    assert _sample(GIVEN_UP) == given_up + 1
    assert run.status["pulse_counts"]["retry_given_up"] == 1
    assert run.status["pulse_counts"]["retry_recovered"] == 1
    (error,) = [m for m in run.errors if m.startswith("[OTX-RETRY-GAVE-UP]")]
    assert error.startswith(
        "[OTX-RETRY-GAVE-UP] OTX: 1 pulse(s) given up (EDGEGUARD_OTX_RETRY_MAX_DAYS=7, "
        "EDGEGUARD_OTX_RETRY_MAX_PULSES=1000):"
    )
    assert (
        f"{IDS[10]} (modified {ROWS[10]['modified']}, attempts 41, first failed {expired['first_failed_at']}, "
        "last reason: 1 item(s) listed" in error
    )
    assert IDS[11] not in error and IDS[12] not in error
    assert _sample(PENDING) == 1


def test_an_expired_pulse_is_given_up_only_after_a_try_past_its_deadline(caplog, monkeypatch):
    """``EDGEGUARD_OTX_RETRY_PER_RUN=1``, two pulses on the list past their deadline, neither tried since: pulse
    10 (first failed 9 days ago, last tried 8.5 days ago) and pulse 12 (8 days, 7.9 days ago), both failing. The
    run fetches pulse 10, the one tried longest ago; it fails again and is given up. Pulse 12, not fetched, stays
    unchanged for a try at a later run: after a pause of the scheduled runs, the pulses beyond the run's fetches
    are not given up untried. The earlier revision gave up both for their age."""
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_PER_RUN", "1")
    otx = _Otx(_recorded(range(60)))
    waiting = _entry(12, days=8, tried_days=7.9)
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[0]["modified"],
        "otx_retry_pulses": [_entry(10, days=9, tried_days=8.5), waiting],
    }
    given_up = _sample(GIVEN_UP)
    run = _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[10], IDS[12]]))

    assert otx.by_id_requests == [IDS[10]]
    assert run.retry == [waiting]
    assert _sample(GIVEN_UP) == given_up + 1
    (error,) = [m for m in run.errors if m.startswith("[OTX-RETRY-GAVE-UP]")]
    assert IDS[10] in error and IDS[12] not in error


def test_a_last_try_later_than_the_run_does_not_bring_the_deadline_forward(caplog, monkeypatch):
    """Pulse 12 first failed 6.5 days ago, and its stored ``last_tried_at`` lies a day after the run (written by a
    host whose clock is ahead, or by hand). No fetch (``EDGEGUARD_OTX_RETRY_PER_RUN=0``): the pulse is not given
    up, since its deadline (7 days) has not passed; the last try counts as the run's start. Guard of the deadline
    rule: it passes without the retry list and on the earlier revision, which did not read the last try."""
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_PER_RUN", "0")
    entry = _entry(12, days=6.5, tried_days=-1)
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[0]["modified"], "otx_retry_pulses": [entry]}
    run = _collect(otx, state, caplog, limit=20)

    assert run.retry == [entry] and not run.errors


def test_the_age_rule_waits_for_the_push_of_the_list_s_pulses(caplog, monkeypatch):
    """``EDGEGUARD_OTX_RETRY_MAX_DAYS`` lowered to 1. Pulse 10 first failed 3 days ago and was last pushed 12 hours
    ago, past its new deadline; pulse 11 likewise. The run writes the window's state before it pushes the pulses
    of the list, and that write gives up nothing by age: both are fetched and pushed, pulse 10 is stored and leaves
    as recovered, pulse 11 fails again and is given up after its push. Given up by age before that push, pulse 10
    would have left the list with an ERROR and its item unpushed."""
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_MAX_DAYS", "1")
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[0]["modified"],
        "otx_retry_pulses": [_entry(10, days=3, tried_days=0.5), _entry(11, days=3, tried_days=0.5)],
    }
    writer = _Writer(failing=[IDS[11]])
    run = _collect(otx, state, caplog, limit=20, writer=writer)

    assert sorted(otx.by_id_requests) == sorted(_ids([10, 11]))
    assert sorted(i for i in run.processed if i in _ids([10, 11])) == sorted(_ids([10, 11])), "both pushed"
    assert run.retry == [] and run.status["pulse_counts"]["retry_recovered"] == 1
    (error,) = [m for m in run.errors if m.startswith("[OTX-RETRY-GAVE-UP]")]
    assert IDS[11] in error and IDS[10] not in error


def test_beyond_the_cap_the_pulses_that_first_failed_longest_ago_are_given_up(caplog, monkeypatch):
    """``EDGEGUARD_OTX_RETRY_MAX_PULSES=3`` and ``EDGEGUARD_OTX_RETRY_PER_RUN=0`` (no fetch): pulses 10, 11 and 12
    are on the list (first failed 3, 2 and 1 days ago), and the run adds pulses 44 and 45. Five pulses exceed
    the cap of 3, so pulses 10 and 11, which first failed longest ago, are given up, untried; the entry of 12 is
    not tried (no attempt added)."""
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_MAX_PULSES", "3")
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_PER_RUN", "0")
    otx = _Otx(_recorded(range(60)))
    kept = _entry(12, days=1)
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[59]["modified"],
        "otx_retry_pulses": [_entry(10, days=3), _entry(11, days=2), kept],
    }
    given_up = _sample(GIVEN_UP)
    run = _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[44], IDS[45]]))

    assert otx.by_id_requests == []
    assert [e["id"] for e in run.retry] == [IDS[12], *sorted(_ids([44, 45]))]
    assert run.retry[0] == kept, "not tried: no attempt added"
    assert _sample(GIVEN_UP) == given_up + 2 and run.status["pulse_counts"]["retry_given_up"] == 2
    (error,) = [m for m in run.errors if m.startswith("[OTX-RETRY-GAVE-UP]")]
    assert "EDGEGUARD_OTX_RETRY_MAX_PULSES=3" in error and IDS[10] in error and IDS[11] in error


@pytest.mark.parametrize("answer_has_the_item", [False, True], ids=["answer lacks the item", "answer has it"])
def test_a_pulse_read_without_the_item_that_failed_stays_on_the_list(caplog, answer_has_the_item):
    """Pulse 12 is on the list with its failed item recorded (``failed_items``). OTX's answer by id carries its
    indicators, or none (an answer cut short, or the indicator removed from the pulse). With the item, it is
    pushed and stored and the pulse leaves the list. Without it, nothing is listed, but the failed item was not
    pushed: the pulse stays with one more attempt and a WARNING, to be given up loudly in the end rather than
    taken off silently. The earlier revision took it off as recovered."""
    otx = _Otx(_recorded(range(60)))
    if not answer_has_the_item:
        body = _recorded([12])[0]
        body["indicators"] = []
        otx.fetch_errors[IDS[12]] = body
    entry = {**_entry(12, days=1, attempts=2), "failed_items": [_key(12)]}
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[0]["modified"], "otx_retry_pulses": [entry]}
    run = _collect(otx, state, caplog, limit=20)

    assert otx.by_id_requests == [IDS[12]]
    if answer_has_the_item:
        assert run.retry == [] and run.status["pulse_counts"]["retry_recovered"] == 1
        return
    (kept,) = run.retry
    assert (kept["attempts"], kept["failed_items"]) == (3, [_key(12)])
    assert kept["last_reason"].startswith("1 item(s) that failed earlier are not in the pulse as read now; ")
    assert run.status["pulse_counts"]["retry_recovered"] == 0
    assert any(
        m.startswith("[OTX-RETRY] OTX: 1 pulse(s) of the retry list read without items of theirs that failed earlier")
        for m in run.warnings
    )


# --------------------------------------------------------------------------- fetching by id


def test_a_pulse_answered_404_leaves_the_list(caplog):
    """OTX answers HTTP 404 for a pulse deleted or no longer subscribed (the id and body of the 404 read on
    2026-11-02): the pulse leaves the list with a WARNING; it is not given up and fails nothing."""
    gone = "000000000000000000000000"
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[0]["modified"],
        "otx_retry_pulses": [{"id": gone, "first_failed_at": _ago(3), "attempts": 6, "last_reason": "earlier"}],
    }
    given_up = _sample(GIVEN_UP)
    run = _collect(otx, state, caplog, limit=20)

    assert otx.by_id_requests == [gone]
    assert run.retry == [] and run.status["success"] is True
    assert run.status["pulse_counts"]["retry_not_found"] == 1 and run.status["pulse_counts"]["retry_given_up"] == 0
    assert _sample(GIVEN_UP) == given_up
    assert any(
        m.startswith(f"[OTX-RETRY] OTX: pulse {gone} answered HTTP 404 (deleted, or no longer subscribed)")
        for m in run.warnings
    )


@pytest.mark.parametrize(
    "error, stops, reason",
    [
        (403, False, "HTTP 403"),
        ({"id": IDS[11], "indicators": []}, False, "an answer that is not the pulse"),
        (429, True, "HTTP 429"),
        (503, True, "HTTP 503"),
        (requests.exceptions.ConnectionError("OTX unreachable"), True, "ConnectionError"),
        (requests.exceptions.ReadTimeout("read timed out"), True, "ReadTimeout"),
        (requests.exceptions.ChunkedEncodingError("Connection broken: IncompleteRead"), True, "ChunkedEncodingError"),
    ],
    ids=[
        "HTTP 403",
        "another pulse answered",
        "HTTP 429",
        "HTTP 503",
        "connection error",
        "read timeout",
        "body cut off",
    ],
)
def test_a_fetch_error_keeps_the_pulse_without_counting_an_attempt(caplog, error, stops, reason):
    """Pulses 10 and 11 are on the list, 10 tried longer ago, so it is fetched first, and its fetch fails. It
    stays on the list with its attempts unchanged and the error as ``last_reason``. After HTTP 403, or an answer
    that is another pulse (not processed), the run goes on to pulse 11, stores it and takes it off; HTTP 429 or
    5xx, or any error of the request itself (connection, timeout, a body cut off), stops the fetches of the run,
    and pulse 11 waits. The next run fetches pulse 11 first, the one tried longest ago. The run itself goes on:
    the earlier revision let an error other than a timeout or a connection error (a body cut off) end the run
    before its push, on every run."""
    otx = _Otx(_recorded(range(60)))
    otx.fetch_errors[IDS[10]] = error
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[0]["modified"],
        "otx_retry_pulses": [_entry(10, days=3, attempts=2, tried_days=2), _entry(11, days=3, tried_days=1)],
    }
    run = _collect(otx, state, caplog, limit=20)

    assert run.status["success"] is True, "the window is pushed"
    first = next(e for e in run.retry if e["id"] == IDS[10])
    assert first["attempts"] == 2
    assert first["last_reason"].endswith(f": {reason}")
    assert run.processed.count(IDS[11]) == (0 if stops else 1), "the other pulse's answer is not processed for 10"
    assert run.status["pulse_counts"]["retry_fetch_failed"] == 1
    if stops:
        assert otx.by_id_requests == [IDS[10]] and _listed(run) == sorted(_ids([10, 11]))
        assert any(m.endswith("and the 1 other pulse(s) due wait for the next run") for m in run.warnings)
        otx.fetch_errors.clear()
        _collect(otx, state, caplog, limit=20)
        assert otx.by_id_requests == [IDS[10], IDS[11], IDS[10]]
    else:
        assert otx.by_id_requests == [IDS[10], IDS[11]] and _listed(run) == [IDS[10]]


@pytest.mark.parametrize(
    "field, value",
    [("indicators", None), ("indicators", "an indicator, then null"), ("tags", None)],
    ids=["indicators null", "an indicator null after a valid one", "tags null"],
)
def test_an_answer_by_id_that_cannot_be_processed_keeps_the_pulse_and_the_run_goes_on(caplog, field, value):
    """The cursor at pulse 5 (the window: pulses 0-4, and 5-7 re-read) and pulse 12 on the list, which OTX answers
    by id with a field of another type than a subscribed pulse carries. Processing it raises; the pulse is set
    aside like a failed fetch (kept, no attempt, the error as ``last_reason``, a WARNING), with the items it
    yielded before the error, and the window is pushed and the cursor advances. The earlier revision ended the
    run before its push, with the cursor and the list unchanged, on every run that fetched the pulse."""
    body = _recorded([12])[0]
    body[field] = [body["indicators"][0], None] if value == "an indicator, then null" else value
    otx = _Otx(_recorded(range(60)))
    otx.fetch_errors[IDS[12]] = body
    entry = _entry(12, days=2, attempts=3)
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[5]["modified"], "otx_retry_pulses": [entry]}
    run = _collect(otx, state, caplog, limit=20)

    assert run.status["success"] is True
    assert sorted(run.processed) == sorted(_ids(range(8)))
    assert run.cursor == ROWS[0]["modified"]
    (kept,) = run.retry
    assert kept["attempts"] == 3 and kept["last_tried_at"] == entry["last_tried_at"], "no try"
    assert _utc(kept["last_fetch_failed_at"]) > _utc(_ago(0.01)), "behind the pulses tried since"
    assert kept["last_reason"].startswith("the answer by id of the run started ")
    assert run.status["pulse_counts"]["retry_fetched"] == 0 and run.status["pulse_counts"]["retry_fetch_failed"] == 1
    assert any(
        m.startswith(f"[OTX-RETRY] OTX: the answer by id for pulse {IDS[12]} could not be read") for m in run.warnings
    )


def test_retries_per_run_take_the_pulses_tried_longest_ago(caplog, monkeypatch):
    """``EDGEGUARD_OTX_RETRY_PER_RUN=2`` with three pulses on the list: the two tried longest ago are fetched;
    with ``0`` none is, and the list is unchanged."""
    otx = _Otx(_recorded(range(60)))
    entries = [_entry(10, days=3, tried_days=1), _entry(11, days=2, tried_days=3), _entry(12, days=1, tried_days=2)]
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_PER_RUN", "2")
    _collect(
        otx,
        {"otx_last_pulse_modified": ROWS[0]["modified"], "otx_retry_pulses": copy.deepcopy(entries)},
        caplog,
        limit=20,
    )
    assert otx.by_id_requests == [IDS[11], IDS[12]]

    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_PER_RUN", "0")
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[0]["modified"], "otx_retry_pulses": copy.deepcopy(entries)}
    run = _collect(otx, state, caplog, limit=20)
    assert otx.by_id_requests == [IDS[11], IDS[12]]
    assert run.retry == entries


def test_a_run_that_does_not_push_neither_fetches_nor_changes_the_list(caplog):
    """A scheduled run with ``push_to_misp=False`` (it returns its items) leaves the retry list alone: it fetches
    nothing by id and settles nothing, since no push says what MISP stored. Guard: it passes without the retry
    list and on the earlier revision, which had the same check."""
    otx = _Otx(_recorded(range(60)))
    entry = _entry(12, days=1)
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[0]["modified"], "otx_retry_pulses": [entry]}
    run = _collect(otx, state, caplog, limit=20, push_to_misp=False)

    assert isinstance(run.status, list) and run.status
    assert otx.by_id_requests == []
    assert run.retry == [entry]


def test_the_real_answer_by_id_is_processed_like_a_subscribed_pulse(caplog):
    """OTX's answer to ``GET /api/v1/pulses/6abf0b86fb14812f2dc84fb2`` of 2026-11-02 (its first 6 indicators).
    Compared with what the collector reads of a subscribed pulse, it has no ``cve_references`` (its CVE comes as
    an indicator of type ``CVE``) and its indicators carry no ``role`` or ``modified``; the collector reads each
    with a default. Fetched by id, the pulse yields one item per indicator, with the pulse's id, name, TLP and
    ATT&CK ids, the indicator's ``created`` as ``first_seen`` and the pulse's ``modified`` as ``last_seen``."""
    pulse = _BY_ID["by_id"]["pulse"]
    keys = set(_BY_ID["by_id"]["keys"])
    assert _BY_ID["by_id"]["status"] == 200 and keys == set(pulse)
    assert "cve_references" not in keys and not {"role", "modified"} & {k for ind in pulse["indicators"] for k in ind}
    assert _BY_ID["not_found"] == {"status": 404, "body": {"detail": "Not Found"}}, "the body the double answers"

    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {pulse["id"]: pulse}
    writer = _Writer(failing=[])
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[0]["modified"],
        "otx_retry_pulses": [{"id": pulse["id"], "first_failed_at": _ago(1), "attempts": 1}],
    }
    run = _collect(otx, state, caplog, limit=20, writer=writer)

    assert otx.by_id_requests == [pulse["id"]], "row 3, modified before the window of a cursor at row 0"
    items = [item for item in writer.pushed if item["pulse_id"] == pulse["id"]]
    assert [(i["indicator_type"], i["value"]) for i in items] == [
        ("cve", "CVE-2026-104286"),
        *[("hash", ind["indicator"]) for ind in pulse["indicators"][1:]],
    ]
    assert {(i["pulse_name"], i["pulse_tlp"], len(i["attack_ids"])) for i in items} == {("PSIRT", "white", 15)}
    assert {(i["first_seen"], i["last_seen"]) for i in items} == {("2026-10-02T01:40:23", pulse["modified"])}
    assert run.retry == []


# --------------------------------------------------------------------------- what puts no pulse on the list


@pytest.mark.parametrize("never_stored", ["a 4-byte value", "a record no attribute is built from"])
def test_a_failure_at_the_event_holds_the_cursor_and_lists_nothing(caplog, never_stored):
    """MISP unreachable, with ``MISPWriter`` itself: the event lookup fails, so every item MISP lacks is listed
    as failed at the event, except pulse 45's, which no push can store: a URL with a 4-byte character (counted as
    failed, not listed) or an indicator no attribute can be built from (1 of 21: reported, not counted). No
    batch carried a new item: the cursor stays (no pulse of the window is older than the oldest with a listed
    item, 59 at the cursor), and no pulse goes on the list. An older pulse already on it, fetched by id, is not
    pushed after the window's failure at the event and keeps its entry as it was: the outage says nothing about
    it. Counting failed items against the push instead, the record no attribute is built from (not counted)
    would leave one item short of the whole: the cursor would pass the window and 20 pulses would go on the
    list."""
    pulses = _recorded(range(60))
    if never_stored == "a 4-byte value":
        pulses[45]["indicators"][0].update({"indicator": "https://example.test/\U0001f600", "type": "URL"})
    else:
        _unreadable(pulses[45])
    older = _pulse("6a00000000000000000000b1", "2026-09-01T00:00:00", "2026-08-01T00:00:00", 71)
    otx = _Otx(pulses)
    otx.by_id_only = {older["id"]: older}
    misp = _UnreachableMisp()
    misp.unreachable = True
    writer = _writer(misp)
    counts = _counted(writer)
    entry = {"id": older["id"], "first_failed_at": _ago(1), "attempts": 1}
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"], "otx_retry_pulses": [entry]}
    with patch("collectors.collector_utils.time.sleep"):
        run = _collect(otx, state, caplog, limit=20, writer=writer)

    assert otx.by_id_requests == [older["id"]]
    assert counts == [(0, 21 if never_stored == "a 4-byte value" else 20)], "the window's push only"
    assert len(writer.last_push_unstored_items) == 20
    assert writer.last_push_event_failed_items == writer.last_push_unstored_items
    assert run.cursor == ROWS[59]["modified"]
    assert run.retry == [entry]
    assert run.status["pulse_counts"]["retry_not_pushed"] == 1
    assert any(
        m.startswith("[OTX-RETRY] OTX: every unstored item of the push failed at its MISP event") for m in run.warnings
    )


def test_an_unknown_failure_keeps_the_cursor_and_the_list_and_adds_nothing(caplog):
    """A writer that gives no list of unstored items, each of the run's two pushes failing one item: pulse 10,
    on the list and fetched by id (the cursor at pulse 0 reads only pulses 0 and 1), stays with one more attempt,
    the cursor stays and no pulse of the window goes on the list."""
    otx = _Otx(_recorded(range(60)))
    entry = _entry(10, days=1)
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[0]["modified"], "otx_retry_pulses": [entry]}
    run = _collect(otx, state, caplog, limit=20, writer=_WriterWithoutList())

    assert otx.by_id_requests == [IDS[10]]
    assert run.cursor == ROWS[0]["modified"]
    assert [(e["id"], e["attempts"]) for e in run.retry] == [(IDS[10], 2)]
    assert run.retry[0]["last_reason"].endswith("failed 2 item(s) without naming them")


def test_an_unknown_failure_of_the_push_of_the_listed_pulses_keeps_them(caplog):
    """The window's push names its failures (none), and the push of pulse 10, on the list and fetched by id,
    fails an item without naming it: pulse 10 stays with one more attempt and the unknown failure as its reason,
    and the cursor advances with the window."""

    class _SecondWithoutList(_Writer):
        def push_items(self, items: List[Dict[str, Any]], batch_key: Any = None, **kw: Any):
            result = super().push_items(items, batch_key=batch_key, **kw)
            if batch_key is None:
                return result
            self.last_push_unstored_items = None  # type: ignore[assignment]
            return len(items) - 1, 1

    otx = _Otx(_recorded(range(60)))
    entry = _entry(10, days=1)
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[5]["modified"], "otx_retry_pulses": [entry]}
    run = _collect(otx, state, caplog, limit=20, writer=_SecondWithoutList())

    assert otx.by_id_requests == [IDS[10]] and run.cursor == ROWS[0]["modified"]
    assert [(e["id"], e["attempts"]) for e in run.retry] == [(IDS[10], 2)]
    assert run.retry[0]["last_reason"].endswith("failed 1 item(s) without naming them")


def test_a_failure_at_the_event_places_the_cursor_by_the_window_alone(caplog):
    """A failure at the event in which a pulse fetched by id is listed too: the cursor is placed by the window's
    pulses with listed items only. No stored cursor; the run reads pulses 50-55 (limit 10), whose items all fail
    at the event and are listed, except pulse 55's, the oldest, whose only indicator is of a non-file hash type
    (no item). The cursor goes to pulse 55, below pulse 54, the oldest pulse of the window with a listed item,
    and the retried pulse, not pushed after the window's failure at the event, keeps its entry as it was.
    Counted with the window's, the retried pulse (not among the window's pulses) would leave the cursor
    unwritten."""
    pulses = _recorded(range(50, 56))
    pulses[-1]["indicators"][0]["type"] = "JA3"
    older = _pulse("6a00000000000000000000c1", "2026-09-01T00:00:00", "2026-08-01T00:00:00", 72)
    otx = _Otx(pulses)
    otx.by_id_only = {older["id"]: older}
    entry = {"id": older["id"], "first_failed_at": _ago(1), "attempts": 1}
    state: Dict[str, Any] = {"otx_retry_pulses": [entry]}
    writer = _Writer(failing=[older["id"], *_ids(range(50, 56))], at_the_event=True)
    run = _collect(otx, state, caplog, limit=10, writer=writer)

    assert sorted(run.processed) == sorted(_ids(range(50, 55))), "the retried pulse is not pushed"
    assert run.status["success"] is False and run.status["pulse_counts"]["without_item"] == 1
    assert run.cursor == ROWS[55]["modified"], "below pulse 54, the oldest pulse of the window with a listed item"
    assert run.retry == [entry]


def test_a_failure_at_the_event_counts_no_attempt_and_gives_up_nothing_by_age(caplog):
    """Pulse 12 has been on the list for 8 days, past its deadline. The run that fetches it finds MISP failing at
    the day's event (every listed item failed at its event): the pulse is not pushed, not given up, and keeps its
    entry as it was, since the outage says nothing about it. The next run, MISP answering but refusing its value
    in its own batch, gives it up. The earlier revision gave it up during the outage; its revision after that
    counted no attempt but stamped the pulse as tried."""
    otx = _Otx(_recorded(range(60)))
    entry = _entry(12, days=8, attempts=5, tried_days=1.5)
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[0]["modified"], "otx_retry_pulses": [entry]}
    given_up = _sample(GIVEN_UP)
    outage = _collect(
        otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[0], IDS[1], IDS[12]], at_the_event=True)
    )

    assert otx.by_id_requests == [IDS[12]]
    assert outage.retry == [entry]
    assert _sample(GIVEN_UP) == given_up and not outage.errors

    answered = _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[12]]))
    assert answered.retry == [] and answered.status["pulse_counts"]["retry_given_up"] == 1
    assert _sample(GIVEN_UP) == given_up + 1


def test_a_failure_at_the_event_leaves_a_listed_pulse_whose_item_went_in_the_window_s_push_as_it_was(caplog):
    """Pulse 50 is on the list (first failed 8 days ago, last pushed 7.5 days ago, before its deadline) and read in
    the window (cursor at pulse 59, limit 20). Its only indicator is also pulse 51's, which is not on the list, so
    the item goes in the window's push and the push of the list's pulses has nothing to push: pulse 50 counts as
    pushed by the run. MISP fails the window's push at the event. Pulse 50 keeps its entry as it was and is not
    given up, since the outage says nothing about it; the cursor stops below pulse 51, the oldest pulse with a
    listed item. The final settlement reads the window's failure at the event for it: read as a failure of its
    item, the pulse would be stamped as tried during the outage and, past its deadline, given up."""
    pulses = _recorded(range(60))
    pulses[50]["indicators"][0]["indicator"] = _value(51)
    otx = _Otx(pulses)
    entry = _entry(50, days=8, attempts=3, tried_days=7.5)
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"], "otx_retry_pulses": [entry]}
    given_up = _sample(GIVEN_UP)
    writer = _Writer(failing=[IDS[50], IDS[51]], at_the_event=True)
    run = _collect(otx, state, caplog, limit=20, writer=writer)

    assert otx.by_id_requests == [] and len(writer.calls) == 1, "the window's push only"
    (shared,) = [item for item in writer.pushed if item["value"] == _value(51)]
    assert shared["pulse_id"] == IDS[50] and shared["report_ids"] == [IDS[51]]
    assert run.cursor == ROWS[52]["modified"], "below pulse 51"
    assert run.retry == [entry]
    assert _sample(GIVEN_UP) == given_up and not run.errors
    assert run.status["pulse_counts"]["retry_pending"] == 1 and run.status["pulse_counts"]["retry_not_pushed"] == 0


def test_a_failure_at_the_event_with_a_window_row_without_an_id_leaves_the_listed_pulse_as_it_was(caplog):
    """The case above, with a window row without an id (pulse 45): its failed items name no pulse, so the failed
    items are unknown, but every listed item failed at its event. The run is an outage all the same: the cursor
    stays (it cannot be placed below a pulse without an id), nothing goes on the list, the list's pulses are not
    pushed, and pulse 50 keeps its entry as it was and is not given up. Read as an unknown failure, the run gave
    pulse 50 an attempt and a ``last_tried_at`` during the outage and, past its deadline, gave it up."""
    pulses = _recorded(range(60))
    pulses[50]["indicators"][0]["indicator"] = _value(51)
    pulses[45]["id"] = None
    otx = _Otx(pulses)
    entry = _entry(50, days=8, attempts=3, tried_days=7.5)
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"], "otx_retry_pulses": [entry]}
    given_up = _sample(GIVEN_UP)
    writer = _Writer(failing=[*IDS, None], at_the_event=True)
    run = _collect(otx, state, caplog, limit=20, writer=writer)

    assert otx.by_id_requests == [] and len(writer.calls) == 1, "the window's push only"
    assert run.cursor == ROWS[59]["modified"], "the cursor stays"
    assert run.retry == [entry]
    assert _sample(GIVEN_UP) == given_up and not run.errors
    assert any("failed at its MISP event" in m and "stays where it was" in m for m in run.warnings)
    assert not any("did not name" in m for m in run.warnings)


def test_listed_pulses_and_the_rule_at_the_event_read_the_writer_lists_only():
    """The helpers of the rule, on their own: a listed item counts for its pulse and for the pulses of its
    ``report_ids``, with the reference of its identity key; a listed item of no pulse, or of a pulse the run did
    not process, or no list, makes the failed items unknown (``None``). A push failed at the event only when an
    item is listed and every listed item failed at its event, whatever MISP held or could never store."""
    items = [
        {"pulse_id": "a", "indicator_type": "ipv4", "value": "198.51.100.1"},
        {"pulse_id": "b", "report_ids": ["c"], "indicator_type": "ipv4", "value": "198.51.100.2"},
        {"pulse_id": "c", "indicator_type": "ipv4", "value": "198.51.100.3"},
    ]
    ref = [otx_collector._item_ref(item) for item in items]
    listed = otx_collector._pulses_with_listed_items
    assert listed(items, [1, 2], {"a", "b", "c"}) == {"b": [ref[1]], "c": [ref[1], ref[2]]}
    assert listed(items, [], {"a"}) == {}
    assert listed(items, [1], {"a", "b"}) is None, "a pulse the run did not process"
    assert listed(items, [5], {"a", "b", "c"}) is None, "a position that names no item"
    assert listed(items, None, {"a", "b", "c"}) is None, "no list"
    assert otx_collector._items_per_pulse(items) == {"a": {ref[0]}, "b": {ref[1]}, "c": {ref[1], ref[2]}}
    at_the_event = otx_collector._failed_at_the_event
    assert at_the_event([0, 2], [0, 1, 2]) and at_the_event([1], [1])
    assert not at_the_event([0, 1, 2], [0, 2]), "an item of a batch MISP answered"
    assert not at_the_event([0, 1, 2], []) and not at_the_event([0, 1, 2], None), "every item in failed batches"
    assert not at_the_event([], [0, 1]), "nothing listed: no failure"


def test_unusable_entries_of_the_stored_list_are_left_out(caplog):
    """A stored list edited by hand or written by another version: entries without a string id, and a second
    entry of one id, are left out with a WARNING; an entry whose first failure does not read starts its time on
    the list with the run (it is not given up at once), attempts that are not a whole number count as 0, and
    ``failed_items`` keeps the references of its first ten strings (an identity key stored whole is read as its
    reference)."""
    otx = _Otx(_recorded(range(60)))
    otx.fetch_errors[IDS[10]] = 403
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[0]["modified"],
        "otx_retry_pulses": [
            {
                "id": IDS[10],
                "first_failed_at": "yesterday",
                "attempts": "many",
                "failed_items": [_raw_key(10), 7, *(_key(n) for n in range(20, 32))],
            },
            {"id": IDS[10], "first_failed_at": _ago(30)},
            {"first_failed_at": _ago(1)},
            "6ae14ab2a51c8b2b96924ba2",
        ],
    }
    before = datetime.now(timezone.utc)
    run = _collect(otx, state, caplog, limit=20)

    assert "[OTX-RETRY] OTX: 3 entr(y/ies) of the stored retry list without a usable pulse id left out" in run.warnings
    (entry,) = run.retry
    assert entry["id"] == IDS[10] and entry["attempts"] == 0
    assert entry["failed_items"] == [_key(10), *(_key(n) for n in range(20, 29))], "the first ten strings"
    assert _utc(entry["first_failed_at"]) >= before - timedelta(seconds=1)
    assert run.status["pulse_counts"]["retry_given_up"] == 0


# --------------------------------------------------------------------------- state and metrics


def _real_state_run(caplog, writer: Any, limit: int = 20) -> Dict[str, Any]:
    """One ``collect`` run that reads and writes the incremental state file itself (``baseline_checkpoint``,
    in the per-test directory of ``conftest.py``)."""
    collector = otx_collector.OTXCollector.__new__(otx_collector.OTXCollector)
    collector.api_key = "a" * 64
    collector.base_url = "https://otx.example"
    collector.tag = "alienvault_otx"
    collector.session = MagicMock()
    collector.circuit_breaker = MagicMock()
    collector.source_name = "otx"
    collector.misp_writer = writer
    otx = _Otx(_recorded(range(60)))
    with (
        patch.object(collector, "check_service_available", return_value=True),
        patch.object(otx_collector, "request_with_rate_limit_retries", side_effect=otx.answer),
        patch.object(otx_collector.time, "sleep"),
        patch.object(otx_collector, "OTX_INCREMENTAL_OVERLAP_SEC", 300),
        patch.object(otx_collector, "OTX_INCREMENTAL_LOOKBACK_DAYS", 100000),
    ):
        collector.collect(limit=limit, push_to_misp=True, baseline=False)
    return baseline_checkpoint.get_source_incremental("otx")


def test_the_state_keeps_the_cursor_beside_the_list(caplog):
    """With the state file itself: the cursor and the list are written in one update, and a later update of the
    list alone (a run with an unknown failure, which keeps the cursor) keeps the cursor key."""
    baseline_checkpoint.update_source_incremental("otx", otx_last_pulse_modified=ROWS[59]["modified"])
    first = _real_state_run(caplog, _Writer(failing=[IDS[44]]))
    assert first["otx_last_pulse_modified"] == ROWS[39]["modified"]
    assert [e["id"] for e in first["otx_retry_pulses"]] == [IDS[44]]

    second = _real_state_run(caplog, _WriterWithoutList())
    assert second["otx_last_pulse_modified"] == ROWS[39]["modified"], "an update of the list keeps the cursor"
    assert [(e["id"], e["attempts"]) for e in second["otx_retry_pulses"]] == [(IDS[44], 2)]


def test_the_final_write_of_the_list_follows_the_write_after_the_window_s_push(caplog):
    """The window's push puts pulse 44 on the list, so the list is written before the push of the list's pulses;
    the pulse on the list, fetched by id, then fails again. The state, written through JSON as the state file is
    (``_collect``), holds that pulse with one more attempt, the run's ``last_tried_at`` and no
    ``last_push_started_at``: the final write. The final settlement changes the entries in place and writes the
    list when it differs from the list written after the window's push; that list is a copy, and compared with
    the entries themselves it would never differ, so the state would keep the first write (two attempts, the mark
    of the push)."""
    (older,) = _listed_pulses(1)
    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {older["id"]: older}
    entry = {"id": older["id"], "first_failed_at": _ago(1), "last_tried_at": _ago(0.5), "attempts": 2}
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"], "otx_retry_pulses": [entry]}
    before = datetime.now(timezone.utc)
    run = _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[44], older["id"]]))

    by_id = {e["id"]: e for e in run.retry}
    assert sorted(by_id) == sorted([older["id"], IDS[44]])
    assert by_id[older["id"]]["attempts"] == 3 and "last_push_started_at" not in by_id[older["id"]]
    assert _utc(by_id[older["id"]]["last_tried_at"]) >= before - timedelta(seconds=1)


def test_a_fresh_baseline_clears_the_list_and_an_additive_one_keeps_it():
    """Guard (passes without the retry list too: the wipe removes the whole state file): the fresh baseline's wipe
    (``baseline_clean._wipe_checkpoints``) removes the incremental state, the list with it; clearing the baseline
    checkpoints only (an additive baseline) keeps both keys."""
    entry = _entry(10, days=1)
    baseline_checkpoint.update_source_incremental(
        "otx", otx_last_pulse_modified=ROWS[0]["modified"], otx_retry_pulses=[entry]
    )
    baseline_checkpoint.clear_checkpoint()
    assert baseline_checkpoint.get_source_incremental("otx") == {
        "otx_last_pulse_modified": ROWS[0]["modified"],
        "otx_retry_pulses": [entry],
    }
    baseline_clean._wipe_checkpoints()
    assert baseline_checkpoint.get_source_incremental("otx") == {}


def test_the_fresh_baseline_wipe_sets_the_gauges_to_an_empty_list():
    """The fresh baseline's wipe removes the list, so it sets the gauges to an empty list at once; they kept the
    list until the first scheduled OTX run after the baseline, and the waiting alert could fire meanwhile."""
    import metrics_server

    metrics_server.record_otx_retry_list(3, datetime.now(timezone.utc).timestamp() - 2 * 86400, 0)
    assert _sample(PENDING) == 3
    baseline_clean._wipe_checkpoints()
    assert _sample(PENDING) == 0 and _sample(OLDEST) == 0


def test_the_gauges_follow_the_list_after_every_run(caplog):
    """``edgeguard_otx_retry_pulses`` and ``edgeguard_otx_retry_oldest_failure_timestamp_seconds`` after each run:
    1 and the first failure of the listed pulse, then 0 and 0 once it recovered."""
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"]}
    run = _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[44]]))
    assert _sample(PENDING) == 1
    assert _sample(OLDEST) == pytest.approx(_utc(run.retry[0]["first_failed_at"]).timestamp())
    _collect(otx, state, caplog, limit=20)
    assert _sample(PENDING) == 0
    assert _sample(OLDEST) == 0


def test_the_oldest_failure_gauge_is_the_first_failure_of_the_longest_waiting_pulse(caplog, monkeypatch):
    """Two pulses on the list, first failed 3 days and 1 hour ago, neither fetched (``EDGEGUARD_OTX_RETRY_PER_RUN=0``):
    the gauges read 2 and the first failure of the one that has waited 3 days, so the waiting alert tests that
    pulse's age, not the newest's."""
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_PER_RUN", "0")
    longest = _entry(10, days=3)
    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[0]["modified"],
        "otx_retry_pulses": [_entry(11, days=1 / 24), longest],
    }
    _collect(otx, state, caplog, limit=20)
    assert _sample(PENDING) == 2
    assert _sample(OLDEST) == pytest.approx(_utc(longest["first_failed_at"]).timestamp())


# --------------------------------------------------------------------------- the time budget of the retries


class _Clock:
    """A virtual clock: ``sleep`` advances it and ``monotonic`` reads it, so a run's pauses (the writer's
    throttle, its back-off after HTTP 5xx and its cooldown, the collector's pauses between requests) take no
    real time and are summed; the requests themselves take none."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def sleep(self, seconds: float) -> None:
        self.now += max(0.0, float(seconds))

    def monotonic(self) -> float:
        return self.now


def _on_the_clock(monkeypatch) -> _Clock:
    """A ``_Clock`` that ``time.sleep`` and ``time.monotonic`` follow for the test."""
    clock = _Clock()
    monkeypatch.setattr(mw.time, "sleep", clock.sleep)
    monkeypatch.setattr(mw.time, "monotonic", clock.monotonic)
    return clock


def _timed(writer: Any, clock: _Clock) -> List[Tuple[int, float, float]]:
    """Per ``push_items`` call of *writer*: the number of items and the clock at its start and at its end."""
    calls: List[Tuple[int, float, float]] = []
    push = writer.push_items

    def spy(items, *args, **kwargs):
        start = clock.now
        try:
            return push(items, *args, **kwargs)
        finally:
            calls.append((len(items), start, clock.now))

    writer.push_items = spy
    return calls


def _listed_pulses(count: int) -> List[Dict[str, Any]]:
    """*count* pulses outside the window (modified on 2026-09-01), indicators ``198.51.100.101`` and up."""
    return [
        _pulse(f"6a0000000000000000000{100 + n}", "2026-09-01T00:00:00", "2026-08-01T00:00:00", 101 + n)
        for n in range(count)
    ]


def test_the_push_of_the_listed_pulses_stops_at_its_time_budget_and_the_others_keep_their_entries(caplog, monkeypatch):
    """``MISPWriter`` at its defaults (batches of 500, 5 s throttle, a 300 s cooldown after 3 batches failing
    with HTTP 5xx in a row) and ``EDGEGUARD_OTX_RETRY_MAX_SECONDS`` at its default of 600. Twenty pulses outside
    the window are on the list, and pulse 50, read in the window and tried more recently; MISP answers HTTP 500
    to every batch holding one of their values. The cursor is at pulse 59 with a limit of 20, so the window holds
    the new pulses 39-58 (59 re-read).

    The window is pushed first and its 20 items (pulse 50's aside) are stored; the cursor advances to pulse 39.
    The twenty pulses fetched by id and pulse 50 are pushed after it, each in a batch of its own, those tried
    longest ago first, pulse 50 last. Each batch takes 70 s of back-off over its four attempts (the clock sums
    the pauses; the requests take no time here). The cooldown after the third ends after its first 30 s step,
    because MISP answers the light request the writer then sends (2026-11-03, ``_misp_answers``: MISP refuses
    the batches, not every request). Before the seventh batch the throttle and the next cooldown would end past
    the budget, so the push stops after six pulses, about 490 s after it began; the push's cap on failure time
    (900 s) is not reached. The six pulses pushed count an attempt; the fifteen others keep their entries
    unchanged and are pushed first by the next run.

    The earlier revision pushed the twenty pulses' batches one after another in the window's push: about 5,000 s
    of pauses (cooldowns every three batches), past the task's one-hour limit, so the run was killed before it
    saved the cursor or the list, and every later run did the same."""
    clock = _on_the_clock(monkeypatch)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "5")
    listed = _listed_pulses(20)
    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {p["id"]: p for p in listed}
    entries = [
        {
            "id": p["id"],
            "modified": p["modified"],
            "first_failed_at": _ago(3),
            "last_tried_at": _ago(2 - n / 100),
            "attempts": 4,
            "last_reason": "1 item(s) listed as unstored; an earlier run",
        }
        for n, p in enumerate(listed)
    ]
    entries.append({**_entry(50, days=3, attempts=4, tried_days=0.5)})
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[59]["modified"],
        "otx_retry_pulses": copy.deepcopy(entries),
    }
    misp = _HoldingMisp(refused_values=(*(p["indicators"][0]["indicator"] for p in listed), _value(50)))
    writer = _writer(misp)
    counts = _counted(writer)
    calls = _timed(writer, clock)
    started = clock.now
    run = _collect(otx, state, caplog, limit=20, writer=writer, sleep=clock.sleep)

    assert clock.now - started <= 600, "pauses of the whole run, against the task's 3,600 s"
    assert [n for n, _start, _end in calls] == [20, 21], "the window's push, then the listed pulses' push"
    assert counts[0] == (20, 0) and run.cursor == ROWS[39]["modified"]
    (_n, retry_start, retry_end) = calls[1]
    assert 475 <= retry_end - retry_start <= 500, (
        "six batches: 6 x 70 s + 5 x 5 s + 30 s of cooldown, and the rate limiter"
    )
    assert misp.refused_attempts == 24 and counts[1] == (0, 6)
    assert writer.last_push_stopped is False, "the time budget, not the cap on failure time, ended the push"

    by_id = {e["id"]: e for e in run.retry}
    pushed = [p["id"] for p in listed[:6]]
    assert all(by_id[pid]["attempts"] == 5 and _utc(by_id[pid]["last_tried_at"]) > _utc(_ago(0.01)) for pid in pushed)
    assert [by_id[e["id"]] for e in entries[6:]] == entries[6:], "the others keep their entries unchanged"
    assert run.status["pulse_counts"]["retry_fetched"] == 20 and run.status["pulse_counts"]["retry_not_pushed"] == 15
    (budget_line,) = [m for m in run.warnings if "reached its time budget" in m]
    assert budget_line.startswith(
        "[OTX-RETRY] OTX: the push of the retry list's pulses reached its time budget "
        "(EDGEGUARD_OTX_RETRY_MAX_SECONDS=600) after 4"
    )
    assert "15 pulse(s) were not pushed; they keep their entries and are pushed first by the next run" in budget_line

    nxt = _collect(otx, state, caplog, limit=20, writer=writer, sleep=clock.sleep)
    tried_again = sorted(e["id"] for e in nxt.retry if e["attempts"] == 5 and e["id"] not in pushed)
    assert tried_again == sorted(p["id"] for p in listed[6:12]), "the pulses not pushed go first"


# --------------------------------------------------------------------------- a push that stopped (2026-11-03)


def test_a_window_push_that_stopped_holds_the_pulses_of_the_items_it_did_not_send(caplog, monkeypatch):
    """``MISPWriter`` with one item a batch and its cap on failure time at the default (900 s). A baseline stored
    pulses 52-59; the cursor is at pulse 59 with a limit of 20, so the window holds pulses 39-58 (59 re-read).
    Pulse 50 is on the list (first failed 8 days ago, last tried 7.5 days ago) and shares its only value with
    pulse 51, so that item goes in the window's push; a pulse outside the window is on the list too. MISP answers
    HTTP 500 to every batch of pulses 39-51 and of the listed pulse, and answers light requests.

    The window's push sends nine batches (pulses 39-47), each failing after its four attempts, and stops before
    the tenth, when the cooldown due would take the failing streak past 900 s: the items of pulses 48-51 are not
    sent. Those pulses are held as after a failure at the MISP event: the cursor moves below the oldest of them
    (to pulse 52), and none goes on the list. Pulses 39-47, whose batches MISP answered with an error, go on it.
    The push of the list's pulses does not run, and both listed pulses keep their entries unchanged, pulse 50
    not given up. Before the change every batch was sent and failed: the cursor advanced to pulse 39 and pulses
    39-51 went on the list."""
    pulses = _recorded(range(60))
    pulses[50]["indicators"][0]["indicator"] = _value(51)
    (outside,) = _listed_pulses(1)
    misp = _HoldingMisp(refused_values=(*(_value(i) for i in range(39, 52)), outside["indicators"][0]["indicator"]))
    _baseline(pulses[52:], misp, caplog)
    clock = _on_the_clock(monkeypatch)
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", "1")
    otx = _Otx(pulses)
    otx.by_id_only = {outside["id"]: outside}
    entries = [
        _entry(50, days=8, attempts=3, tried_days=7.5),
        {
            "id": outside["id"],
            "modified": outside["modified"],
            "first_failed_at": _ago(3),
            "last_tried_at": _ago(2),
            "attempts": 4,
            "last_reason": "1 item(s) listed as unstored; an earlier run",
        },
    ]
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[59]["modified"],
        "otx_retry_pulses": copy.deepcopy(entries),
    }
    writer = _writer(misp)
    counts = _counted(writer)
    given_up = _sample(GIVEN_UP)
    run = _collect(otx, state, caplog, limit=20, writer=writer, sleep=clock.sleep)

    assert counts == [(0, 12)], "the window's push only: 9 items sent and failed, 3 not sent"
    assert misp.refused_attempts == 36 and writer.last_push_stopped is True
    assert run.cursor == ROWS[52]["modified"], "below pulse 51, the oldest pulse with an item not sent"
    by_id = {e["id"]: e for e in run.retry}
    assert sorted(by_id) == sorted([*_ids(range(39, 48)), IDS[50], outside["id"]])
    assert [by_id[e["id"]] for e in entries] == entries, "the listed pulses keep their entries"
    assert all(by_id[IDS[i]]["attempts"] == 1 for i in range(39, 48))
    assert _sample(GIVEN_UP) == given_up
    assert run.status["success"] is False and run.status["failed"] == 12
    counts_of_run = run.status["pulse_counts"]
    assert counts_of_run["held_unsent"] == 4 and counts_of_run["retry_added"] == 9
    assert counts_of_run["retry_not_pushed"] == 2
    (held,) = [m for m in run.warnings if "the MISP push stopped because MISP kept failing" in m]
    assert held.startswith(
        "[OTX-RETRY] OTX: the MISP push stopped because MISP kept failing ([MISP-PUSH-STOPPED]): the items of 4 "
        "pulse(s) of the window were not sent; those pulses do not go on the retry list, and the cursor moves to "
        f"{ROWS[52]['modified']}, below the oldest pulse of the window with an item not sent"
    )


def test_a_window_push_that_stopped_with_a_row_without_an_id_keeps_the_listed_pulse_it_did_not_send(
    caplog, monkeypatch
):
    """The test above with pulse 49 an OTX row without an id. Its item is not sent and names no pulse, so the
    push's failures are unknown: the cursor stays and no pulse goes on the list, as #302 rules. Pulse 50 is on the
    list, and its only item (shared with pulse 51) is not sent either: it keeps its entry unchanged, with no
    attempt and no ``last_tried_at``, and is not given up by age although it first failed eight days ago. Before
    the fix the unknown failures took the branch without the stop, and pulse 50 got an attempt and was given up
    with ``[OTX-RETRY-GAVE-UP]`` although none of its items reached MISP."""
    pulses = _recorded(range(60))
    pulses[50]["indicators"][0]["indicator"] = _value(51)
    pulses[49]["id"] = None
    (outside,) = _listed_pulses(1)
    misp = _HoldingMisp(refused_values=(*(_value(i) for i in range(39, 52)), outside["indicators"][0]["indicator"]))
    _baseline(pulses[52:], misp, caplog)
    clock = _on_the_clock(monkeypatch)
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", "1")
    otx = _Otx(pulses)
    otx.by_id_only = {outside["id"]: outside}
    entries = [_entry(50, days=8, attempts=3, tried_days=7.5)]
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[59]["modified"],
        "otx_retry_pulses": copy.deepcopy(entries),
    }
    writer = _writer(misp)
    counts = _counted(writer)
    given_up = _sample(GIVEN_UP)
    run = _collect(otx, state, caplog, limit=20, writer=writer, sleep=clock.sleep)

    assert counts == [(0, 12)] and writer.last_push_stopped is True
    assert writer.last_push_unsent_items == [9, 10, 11], "the items of pulses 48, 49 (no id) and 50/51"
    assert run.cursor == ROWS[59]["modified"], "unknown failures: the cursor stays"
    assert run.retry == entries, "pulse 50 keeps its entry; no pulse goes on the list"
    assert _sample(GIVEN_UP) == given_up and not [m for m in run.errors if "OTX-RETRY-GAVE-UP" in m]
    counts_of_run = run.status["pulse_counts"]
    assert counts_of_run["held_unsent"] == 3, "pulses 48, 50 and 51; pulse 49 has no id"
    assert counts_of_run["retry_not_pushed"] == 1 and counts_of_run["retry_given_up"] == 0
    (line,) = [m for m in run.warnings if "the writer did not name" in m]
    assert "the push stopped because MISP kept failing ([MISP-PUSH-STOPPED])" in line
    assert f"those an item not sent names keep their entries (ids: {IDS[50]})" in line


def test_a_window_push_that_stopped_without_a_list_of_the_items_it_did_not_send_holds_everything(caplog):
    """A writer that reports a stop but no list of the items it did not send (a writer double; ``MISPWriter``
    always gives one): which pulses those items name is unknown, so the cursor stays and no pulse goes on the
    list, not even the pulses whose items the writer lists as unstored."""

    class _StoppedWithoutList(_Writer):
        def push_items(self, items, batch_key=None, **kw):
            result = super().push_items(items, batch_key=batch_key, **kw)
            self.last_push_stopped = True
            self.last_push_unsent_items = None
            return result

    otx = _Otx(_recorded(range(60)))
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"]}
    run = _collect(otx, state, caplog, limit=20, writer=_StoppedWithoutList(failing=[IDS[44], IDS[45]]))
    assert run.cursor == ROWS[59]["modified"], "the cursor stays"
    assert run.retry == [], "no pulse goes on the list"
    assert run.status["pulse_counts"]["held_unsent"] == 2


def test_the_warning_of_a_stopped_window_push_says_which_listed_pulses_keep_their_entries(caplog, monkeypatch):
    """Pulse 50 is on the list and read in the window; its only value is pulse 51's, sent and stored. The window's
    push stops later (pulses 55-58 not sent). Pulse 50 leaves the list as recovered, as its items were stored: the
    WARNING says that the listed pulses an item not sent names keep their entries, not every listed pulse."""

    class _Stopping(_Writer):
        def push_items(self, items, batch_key=None, **kw):
            self.pushed += list(items)
            unsent = [n for n, item in enumerate(items) if item.get("pulse_id") in {IDS[i] for i in range(55, 59)}]
            self.last_push_unsent_items = unsent
            self.last_push_unstored_items = list(unsent)
            self.last_push_event_failed_items = []
            self.last_push_skipped_items = []
            self.last_push_stopped = bool(unsent)
            return len(items) - len(unsent), len(unsent)

    pulses = _recorded(range(60))
    pulses[50]["indicators"][0]["indicator"] = _value(51)
    otx = _Otx(pulses)
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[59]["modified"],
        "otx_retry_pulses": [_entry(50, days=2, attempts=3, tried_days=1)],
    }
    run = _collect(otx, state, caplog, limit=20, writer=_Stopping())
    assert run.retry == [] and run.status["pulse_counts"]["retry_recovered"] == 1
    (line,) = [m for m in run.warnings if "the MISP push stopped because MISP kept failing" in m]
    assert "those an item not sent names keep their entries, and those read in the window otherwise follow" in line


def test_a_push_of_the_listed_pulses_that_stopped_keeps_the_entries_of_the_pulses_it_did_not_send(caplog, monkeypatch):
    """The listed pulses of the time-budget test above, with ``EDGEGUARD_OTX_RETRY_MAX_SECONDS`` out of reach: the
    window is stored and the cursor advances to pulse 39; the twenty listed pulses fetched by id and pulse 50 are
    pushed, each in a batch of its own, and MISP answers HTTP 500 to each. After nine batches the cooldown due
    would take the failing streak past the cap of 900 s, so the push stops. The nine pulses pushed count an
    attempt; the twelve whose items were not sent keep their entries unchanged and go first at the next run, as
    after the time budget. Before the change all 21 were pushed, five attempts each, and each counted an
    attempt."""
    clock = _on_the_clock(monkeypatch)
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_MAX_SECONDS", "100000")
    listed = _listed_pulses(20)
    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {p["id"]: p for p in listed}
    entries = [
        {
            "id": p["id"],
            "modified": p["modified"],
            "first_failed_at": _ago(3),
            "last_tried_at": _ago(2 - n / 100),
            "attempts": 4,
            "last_reason": "1 item(s) listed as unstored; an earlier run",
        }
        for n, p in enumerate(listed)
    ]
    entries.append({**_entry(50, days=3, attempts=4, tried_days=0.5)})
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[59]["modified"],
        "otx_retry_pulses": copy.deepcopy(entries),
    }
    misp = _HoldingMisp(refused_values=(*(p["indicators"][0]["indicator"] for p in listed), _value(50)))
    writer = _writer(misp)
    counts = _counted(writer)
    run = _collect(otx, state, caplog, limit=20, writer=writer, sleep=clock.sleep)

    assert counts == [(20, 0), (0, 21)] and run.cursor == ROWS[39]["modified"]
    assert misp.refused_attempts == 36 and writer.last_push_stopped is True
    by_id = {e["id"]: e for e in run.retry}
    pushed = [p["id"] for p in listed[:9]]
    assert all(by_id[pid]["attempts"] == 5 and _utc(by_id[pid]["last_tried_at"]) > _utc(_ago(0.01)) for pid in pushed)
    assert [by_id[e["id"]] for e in entries[9:]] == entries[9:], "the others keep their entries unchanged"
    assert run.status["pulse_counts"]["retry_not_pushed"] == 12 and run.status["pulse_counts"]["held_unsent"] == 0
    assert not [m for m in run.warnings if "reached its time budget" in m]
    (stopped,) = [m for m in run.warnings if "the push of the retry list's pulses stopped" in m]
    assert stopped.startswith(
        "[OTX-RETRY] OTX: the push of the retry list's pulses stopped because MISP kept failing "
        "([MISP-PUSH-STOPPED]) after "
    )
    assert "12 pulse(s) were not pushed; they keep their entries and are pushed first by the next run" in stopped


class _OutOfTime(_Writer):
    """A writer double whose push of the retry list's pulses (the call with a deadline) reaches the deadline before
    its first batch: every item is listed in ``last_push_skipped_items``, none stored or failed."""

    def push_items(self, items: List[Dict[str, Any]], batch_key: Any = None, **kw: Any):
        result = super().push_items(items, batch_key=batch_key, **kw)
        self.last_push_skipped_items = list(range(len(items))) if kw.get("deadline") is not None else []
        if not self.last_push_skipped_items:
            return result
        self.last_push_unstored_items = []
        return 0, 0


def test_two_listed_pulses_sharing_an_item_the_time_budget_left_unsent_keep_their_entries(caplog):
    """Pulses A and B are on the list, fetched by id, and list one value, their only item. The same-run fold keeps
    A's copy (A was tried longest ago, so fetched and processed first), which names B in ``report_ids``, and the
    item goes in A's batches. The push of the list's pulses reaches its time budget before that batch: neither
    pulse was pushed, so both keep their entries as they were (the mark written on A before the push is replaced
    by the final write) and count in ``retry_not_pushed``. Taking the pulses not pushed from ``pulse_id`` alone,
    B would leave the list as recovered while its item was never sent."""
    a, b = _listed_pulses(2)
    b["indicators"][0]["indicator"] = a["indicators"][0]["indicator"]
    ref = otx_collector._item_ref({"indicator_type": "ipv4", "value": a["indicators"][0]["indicator"]})
    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {p["id"]: p for p in (a, b)}
    entries = [
        {"id": p["id"], "first_failed_at": _ago(2), "last_tried_at": _ago(tried), "attempts": 3, "failed_items": [ref]}
        for p, tried in ((a, 1.5), (b, 1))
    ]
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[0]["modified"], "otx_retry_pulses": copy.deepcopy(entries)}
    writer = _OutOfTime()
    run = _collect(otx, state, caplog, limit=20, writer=writer)

    assert otx.by_id_requests == [a["id"], b["id"]]
    (shared,) = writer.calls[1]["items"]
    assert shared["pulse_id"] == a["id"] and shared["report_ids"] == [b["id"]]
    assert writer.batch_keys[-1] == a["id"], "the batches of the pulse first in the order"
    assert sorted(run.retry, key=lambda e: e["id"]) == sorted(entries, key=lambda e: e["id"])
    assert run.status["pulse_counts"]["retry_not_pushed"] == 2 and run.status["pulse_counts"]["retry_recovered"] == 0
    assert any("reached its time budget" in m and "2 pulse(s) were not pushed" in m for m in run.warnings)


# --------------------------------------------------------------------------- a raise during the push of the list


class _RaisingAt(_Writer):
    """A writer double whose push of the retry list's pulses (the call with a batch key) sends the items in order,
    as its batches go, and raises a read timeout at the first item of a pulse in *raising*: MISP does not answer
    that pulse's batch, after the writer's attempts. ``sent`` keeps the values sent before, over the runs."""

    def __init__(self, raising: Any, **kw: Any):
        super().__init__(**kw)
        self.raising = set(raising)
        self.sent: List[str] = []

    def push_items(self, items: List[Dict[str, Any]], batch_key: Any = None, **kw: Any):
        if batch_key is not None:
            for item in items:
                if item.get("pulse_id") in self.raising:
                    raise requests.exceptions.ReadTimeout("MISP did not answer in 300 s")
                self.sent.append(item["value"])
        return super().push_items(items, batch_key=batch_key, **kw)


def _three_listed() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Three pulses outside the window and their entries: first failed 4 days ago, tried 3, 2 and 1 days ago."""
    listed = _listed_pulses(3)
    entries = [
        {"id": p["id"], "first_failed_at": _ago(4), "last_tried_at": _ago(3 - n), "attempts": 2}
        for n, p in enumerate(listed)
    ]
    return listed, entries


def test_a_raise_during_the_push_of_the_listed_pulses_leaves_the_list_within_its_cap(caplog, monkeypatch):
    """``EDGEGUARD_OTX_RETRY_MAX_PULSES=2``. Pulses A (first failed 3 days ago) and B (2 days ago) are on the
    list and fetched by id, the window's push puts pulse 44 on it, and the push of the list's pulses raises at B's
    batch. The cap is applied when the run writes the window's new pulses, before the list's pulses are pushed: A,
    which first failed longest ago, is given up then, with the ERROR and the counter, and its item is not pushed.
    The state holds B, marked as the pulse that push began with, and pulse 44: two pulses. The previous revision
    applied the cap only after that push, so the raise left three pulses on a list of at most two, and a pulse
    whose batch raised on every run let the list grow by every run's new pulses."""
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_MAX_PULSES", "2")
    a, b = _listed_pulses(2)
    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {p["id"]: p for p in (a, b)}
    entry_b = {"id": b["id"], "first_failed_at": _ago(2), "last_tried_at": _ago(1), "attempts": 2}
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[59]["modified"],
        "otx_retry_pulses": [
            {"id": a["id"], "first_failed_at": _ago(3), "last_tried_at": _ago(2), "attempts": 2},
            entry_b,
        ],
    }
    given_up = _sample(GIVEN_UP)
    writer = _RaisingAt([b["id"]], failing=[IDS[44]])
    run = _collect(otx, state, caplog, limit=20, writer=writer)

    assert run.status["success"] is False and "MISP did not answer" in run.status["error"]
    assert otx.by_id_requests == [a["id"], b["id"]] and writer.sent == []
    assert run.cursor == ROWS[39]["modified"]
    assert [e["id"] for e in run.retry] == [b["id"], IDS[44]]
    assert {k: v for k, v in run.retry[0].items() if k != "last_push_started_at"} == entry_b
    assert "last_push_started_at" in run.retry[0]
    assert _sample(GIVEN_UP) == given_up + 1
    (error,) = [m for m in run.errors if m.startswith("[OTX-RETRY-GAVE-UP]")]
    assert "EDGEGUARD_OTX_RETRY_MAX_PULSES=2" in error and a["id"] in error and b["id"] not in error


def test_an_item_a_pulse_given_up_at_the_cap_shares_goes_in_the_batches_of_a_pulse_still_on_the_list(
    caplog, monkeypatch
):
    """``EDGEGUARD_OTX_RETRY_MAX_PULSES=2``. Pulses A and B are on the list, fetched by id, and list one value,
    their only item; A first failed longest ago, and the window's push puts pulse 44 on the list. A is given up at
    the cap when the run writes the window's new pulses; the shared item, kept in A's copy with B in
    ``report_ids``, still goes in the push of the list's pulses, in B's batches. That push reaches its time budget
    before the batch: B keeps its entry and counts in ``retry_not_pushed``, A, given up, does not."""
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_MAX_PULSES", "2")
    a, b = _listed_pulses(2)
    b["indicators"][0]["indicator"] = a["indicators"][0]["indicator"]
    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {p["id"]: p for p in (a, b)}
    entry_b = {"id": b["id"], "first_failed_at": _ago(2), "last_tried_at": _ago(1), "attempts": 2}
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[59]["modified"],
        "otx_retry_pulses": [
            {"id": a["id"], "first_failed_at": _ago(3), "last_tried_at": _ago(2), "attempts": 2},
            entry_b,
        ],
    }
    writer = _OutOfTime(failing=[IDS[44]])
    run = _collect(otx, state, caplog, limit=20, writer=writer)

    (shared,) = writer.calls[1]["items"]
    assert shared["pulse_id"] == a["id"] and shared["report_ids"] == [b["id"]]
    assert writer.batch_keys[-1] == b["id"]
    assert run.retry == [entry_b, next(e for e in run.retry if e["id"] == IDS[44])]
    assert run.status["pulse_counts"]["retry_not_pushed"] == 1 and run.status["pulse_counts"]["retry_given_up"] == 1
    (error,) = [m for m in run.errors if m.startswith("[OTX-RETRY-GAVE-UP]")]
    assert a["id"] in error and b["id"] not in error


def test_a_pulse_whose_batch_raises_on_every_run_goes_behind_the_others(caplog, monkeypatch):
    """``EDGEGUARD_OTX_RETRY_PER_RUN=2``; pulses A, B and C are on the list, tried 3, 2 and 1 days ago, and MISP
    never answers A's batch. Run 1 fetches A and B; its push of the list's pulses begins with A and raises, so
    the run fails. The list written before that push marks A (``last_push_started_at``, the run's start); B and C
    keep their entries. Run 2 puts A behind the others: it fetches B and C, pushes both, and they leave the list;
    A keeps its entry and gets no try. Run 3 takes A again. Without the mark every run fetched A and B, began with
    A and raised, and C was never fetched."""
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_PER_RUN", "2")
    (a, b, c), entries = _three_listed()
    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {p["id"]: p for p in (a, b, c)}
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[0]["modified"], "otx_retry_pulses": copy.deepcopy(entries)}
    writer = _RaisingAt([a["id"]])

    first = _collect(otx, state, caplog, limit=20, writer=writer)
    assert first.status["success"] is False and otx.by_id_requests == [a["id"], b["id"]] and writer.sent == []
    marked = {e["id"]: e for e in first.retry}
    assert "last_push_started_at" in marked[a["id"]] and [marked[p["id"]] for p in (b, c)] == entries[1:]

    second = _collect(otx, state, caplog, limit=20, writer=writer)
    assert second.status["success"] is True and otx.by_id_requests[2:] == [b["id"], c["id"]]
    assert writer.sent == [b["indicators"][0]["indicator"], c["indicators"][0]["indicator"]]
    assert second.retry == [marked[a["id"]]] and second.status["pulse_counts"]["retry_recovered"] == 2

    third = _collect(otx, state, caplog, limit=20, writer=writer)
    assert third.status["success"] is False and otx.by_id_requests[4:] == [a["id"]]


def test_in_one_push_the_pulse_whose_batch_raised_goes_last_at_the_next_run(caplog):
    """Pulses A, B and C on the list, tried 3, 2 and 1 days ago, all fetched by each run, and MISP does not answer
    A's batch. Run 1's push of the list's pulses begins with A and raises before anything of the list is sent.
    Run 2 pushes B and C first, then A, and raises there: B's and C's items reached MISP; B, which run 2's push
    began with, now carries the mark, and A keeps run 1's. The mark is no try: run 3, MISP answering A's batch
    but refusing its value, pushes C, A and B, and they all count their try: A stays with one more attempt and
    the run's ``last_tried_at``, without the mark, and B and C leave the list. Without the mark run 2 began with
    A again and sent nothing, and so did every later run."""
    (a, b, c), entries = _three_listed()
    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {p["id"]: p for p in (a, b, c)}
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[0]["modified"], "otx_retry_pulses": copy.deepcopy(entries)}
    writer = _RaisingAt([a["id"]])

    first = _collect(otx, state, caplog, limit=20, writer=writer)
    assert first.status["success"] is False and writer.sent == []
    mark_a = next(e for e in first.retry if e["id"] == a["id"])["last_push_started_at"]

    second = _collect(otx, state, caplog, limit=20, writer=writer)
    assert second.status["success"] is False
    assert writer.sent == [b["indicators"][0]["indicator"], c["indicators"][0]["indicator"]]
    marks = {e["id"]: e.get("last_push_started_at") for e in second.retry}
    assert marks[a["id"]] == mark_a and marks[b["id"]] is not None and marks[c["id"]] is None
    assert _utc(marks[b["id"]]) > _utc(mark_a)

    writer.raising.clear()
    writer.failing = {a["id"]}
    before = datetime.now(timezone.utc)
    third = _collect(otx, state, caplog, limit=20, writer=writer)
    assert "MISP did not answer" not in str(third.status), "the push ends (the run fails on its success rate)"
    assert writer.sent[2:] == [p["indicators"][0]["indicator"] for p in (c, a, b)]
    (kept,) = third.retry
    assert kept["id"] == a["id"] and kept["attempts"] == entries[0]["attempts"] + 1
    assert _utc(kept["last_tried_at"]) >= before - timedelta(seconds=1) and "last_push_started_at" not in kept


def test_a_failure_during_the_push_of_the_listed_pulses_keeps_the_window_s_cursor_and_its_new_pulses(caplog):
    """The window's push (pulses 39-58, 59 re-read; pulse 44's item failing) ends, and the push of a pulse on
    the list, fetched by id, then raises (a task killed, MISP gone). The run fails, but the cursor advance to
    pulse 39 and pulse 44 on the list were saved after the window's push, in one update; the listed pulse keeps
    its entry, with the start of the run as ``last_push_started_at`` (the push began with it), and no try. The
    earlier revision pushed both in one call: the raise left the cursor at pulse 59 and pulse 44 off the list,
    and the next run did the same."""
    (older,) = _listed_pulses(1)

    class _Killed(Exception):
        pass

    class _DyingWriter(_Writer):
        def push_items(self, items: List[Dict[str, Any]], batch_key: Any = None, **kw: Any):
            if any(item.get("pulse_id") == older["id"] for item in items):
                raise _Killed("the task was killed")
            return super().push_items(items, batch_key=batch_key, **kw)

    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {older["id"]: older}
    entry = {"id": older["id"], "first_failed_at": _ago(1), "last_tried_at": _ago(0.5), "attempts": 2}
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"], "otx_retry_pulses": [entry]}
    before = datetime.now(timezone.utc)
    run = _collect(otx, state, caplog, limit=20, writer=_DyingWriter(failing=[IDS[44]]))

    assert run.status["success"] is False and "the task was killed" in run.status["error"]
    assert otx.by_id_requests == [older["id"]]
    assert run.cursor == ROWS[39]["modified"]
    assert _listed(run) == sorted([older["id"], IDS[44]])
    kept = dict(next(e for e in run.retry if e["id"] == older["id"]))
    assert before - timedelta(seconds=1) <= _utc(kept.pop("last_push_started_at")) <= datetime.now(timezone.utc)
    assert kept == entry


def test_a_push_of_the_listed_pulses_that_fails_at_the_event_leaves_their_entries(caplog):
    """The window's push stores its items, then the push of the pulse on the list, fetched by id, fails at the
    MISP event (MISP gone between the two pushes). The pulse first failed 8 days ago and was last pushed before
    its deadline: it keeps its entry as it was and is not given up, since the outage says nothing about it; a
    WARNING says so. The cursor advances with the window."""
    (older,) = _listed_pulses(1)
    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {older["id"]: older}
    entry = {"id": older["id"], "first_failed_at": _ago(8), "last_tried_at": _ago(7.5), "attempts": 9}
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[0]["modified"], "otx_retry_pulses": [entry]}
    given_up = _sample(GIVEN_UP)
    run = _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[older["id"]], at_the_event=True))

    assert run.cursor == ROWS[0]["modified"] and run.retry == [entry]
    assert _sample(GIVEN_UP) == given_up and not run.errors
    assert any(
        m.startswith("[OTX-RETRY] OTX: every unstored item of the push of the retry list's pulses failed at its MISP")
        for m in run.warnings
    )


def test_the_run_makes_two_pushes_whatever_the_number_of_listed_pulses(caplog):
    """Each ``push_items`` call looks up the day's event and lists MISP's attributes before its first batch
    (about 2 s a page of 5,000; the OTX event of a 730-day baseline held 150,683 attributes, 31 pages), so the
    pulses of the list share one push: the window's push and one push of the listed pulses, with a batch key
    and a deadline, whatever their number."""
    listed = _listed_pulses(12)
    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {p["id"]: p for p in listed}
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[59]["modified"],
        "otx_retry_pulses": [{"id": p["id"], "first_failed_at": _ago(1), "attempts": 1} for p in listed],
    }
    writer = _Writer()
    run = _collect(otx, state, caplog, limit=20, writer=writer)

    assert [len(call["items"]) for call in writer.calls] == [21, 12]
    assert writer.calls[0]["batch_key"] is None and "deadline" not in writer.calls[0]
    assert writer.calls[1]["batch_key"] is not None and isinstance(writer.calls[1]["deadline"], float)
    assert run.retry == [] and run.status["pulse_counts"]["retry_recovered"] == 12


def test_the_writer_starts_no_batch_at_or_after_its_deadline(monkeypatch, caplog):
    """``push_items(deadline=...)``: three keys, a 5 s throttle and a deadline 8 s after the push starts. The
    first two batches start before it; the third would start after its throttle pause, at 10 s or later, so it
    is not sent: its item is listed in ``last_push_skipped_items``, neither stored nor failed. A cooldown due
    before a batch counts toward the deadline too. Without a deadline every batch is sent."""
    clock = _on_the_clock(monkeypatch)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "5")
    items = [{**_indicator(f"198.51.100.{n}", "alienvault_otx"), "k": k} for n, k in ((1, "a"), (2, "b"), (3, "c"))]
    misp = _Misp()
    writer = _writer(misp)
    assert writer.push_items(items, batch_key=lambda item: item["k"], deadline=clock.now + 8) == (2, 0)
    assert writer.last_push_skipped_items == [2] and writer.last_push_unstored_items == []
    assert misp.stored == ["198.51.100.1", "198.51.100.2"]

    cooling = _writer(_Misp())
    cooling._misp_push_consecutive_failures = 3  # the 300 s cooldown is due before the first batch
    assert cooling.push_items(items, batch_key=lambda item: item["k"], deadline=clock.now + 100) == (0, 0)
    assert cooling.last_push_skipped_items == [0, 1, 2]

    unbounded = _Misp()
    assert _writer(unbounded).push_items(items, batch_key=lambda item: item["k"]) == (3, 0)
    assert len(unbounded.stored) == 3

    # Two (source, date) groups: the deadline comes during the first, and the second sends nothing either.
    groups = [_indicator("198.51.100.4", "alienvault_otx"), _indicator("198.51.100.5", "alienvault_otx")]
    groups += [_indicator("198.51.100.6", "threatfox"), _indicator("198.51.100.7", "threatfox")]
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", "1")
    two = _Misp()
    stopped = _writer(two)
    caplog.clear()
    with caplog.at_level("INFO", logger=mw.logger.name):
        assert stopped.push_items(groups, deadline=clock.now + 3) == (1, 0)
    assert two.stored == ["198.51.100.4"] and stopped.last_push_skipped_items == [1, 2, 3]
    (stop_line,) = [r.getMessage() for r in caplog.records if "the push's deadline came before" in r.getMessage()]
    assert stop_line.endswith("3 item(s) not sent, neither stored nor failed"), "one stop, for both groups"


def test_the_push_passes_its_deadline_to_the_refresh(monkeypatch):
    """A push with a deadline already past sends nothing, and the refresh of a re-reported indicator whose
    stored copy MISP last wrote 90 days ago (the refresh at its default of 30 days) starts no edit (deferred);
    without a deadline the copy is edited."""
    from test_misp_reobserved_indicator_refresh import NOW, _feodo_item, _stored
    from test_misp_reobserved_indicator_refresh import _Misp as _RefreshMisp

    monkeypatch.delenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS")

    for deadline, edits in ((mw.time.monotonic() - 1, 0), (None, 1)):
        misp = _RefreshMisp([_stored("203.0.113.10", "u-stale", last_seen=None, written=NOW - timedelta(days=90))])
        writer = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
        writer.session = MagicMock()
        writer.session.post.side_effect = misp.post
        with patch.object(mw.MISPWriter, "_get_or_create_event", return_value="50"):
            assert writer.push_items([_feodo_item("203.0.113.10")], deadline=deadline) == (0, 0)
        assert len(misp.edits) == edits
        assert writer.stats["attributes_refresh_deferred"] == 1 - edits


def test_the_refresh_starts_no_edit_after_the_push_s_deadline(monkeypatch):
    """The refresh of re-reported indicators after a push with a deadline starts no edit at or after it; the
    edits not made are deferred to a later run, as when ``EDGEGUARD_MISP_REFRESH_MAX_SECONDS`` is spent."""
    clock = _on_the_clock(monkeypatch)
    writer = _writer(_Misp())
    edits: List[str] = []
    monkeypatch.setattr(
        writer, "update_attribute", lambda uuid, changes, written_after=None: edits.append(uuid) or True
    )
    due = {("ip-dst", f"198.51.100.{n}"): (mw.StoredCopy(1.0, f"uuid-{n}", None, None), None) for n in range(3)}
    assert writer._refresh_stored_copies(due, 30, deadline=clock.now) == (0, 0)
    assert edits == [] and writer.stats["attributes_refresh_deferred"] == 3
    assert writer._refresh_stored_copies(due, 30, deadline=clock.now + 1) == (3, 0)
    assert len(edits) == 3


# --------------------------------------------------------------------------- what counts as a try


@pytest.mark.parametrize(
    "error",
    [503, 429, 403, requests.exceptions.ConnectionError("OTX unreachable")],
    ids=["HTTP 503", "HTTP 429", "HTTP 403", "connection error"],
)
def test_a_failed_fetch_by_id_is_no_try_and_gives_up_no_pulse(caplog, error):
    """Pulse 10 first failed 7.5 days ago (its deadline passed 12 hours ago) and was last pushed before that;
    pulse 11 is on the list too. The run's fetch of pulse 10 fails. Its items were not pushed, so it is no try:
    the pulse is not given up, and its attempts and ``last_tried_at`` stay; ``last_fetch_failed_at`` puts it
    behind pulse 11 for the next fetches. The next run, OTX answering, fetches pulse 11 first (when it is still
    on the list) and then pulse 10, whose push fails again: tried past its deadline, it is given up. The earlier
    revision counted the failed fetch as a try and gave pulse 10 up untried in the first run."""
    otx = _Otx(_recorded(range(60)))
    otx.fetch_errors[IDS[10]] = error
    expired = _entry(10, days=7.5, attempts=4, tried_days=0.6)
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[0]["modified"],
        "otx_retry_pulses": [expired, _entry(11, days=3, tried_days=0.4)],
    }
    given_up = _sample(GIVEN_UP)
    run = _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[10]]))

    kept = next(e for e in run.retry if e["id"] == IDS[10])
    assert {k: kept[k] for k in ("attempts", "last_tried_at", "first_failed_at")} == {
        k: expired[k] for k in ("attempts", "last_tried_at", "first_failed_at")
    }
    assert _utc(kept["last_fetch_failed_at"]) > _utc(_ago(0.01))
    assert kept["last_reason"].startswith("fetch by id failed in the run started ")
    assert _sample(GIVEN_UP) == given_up and not run.errors

    otx.fetch_errors.clear()
    requests_before = len(otx.by_id_requests)
    nxt = _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[10]]))
    assert otx.by_id_requests[requests_before:] == [*([IDS[11]] if IDS[11] in _listed(run) else []), IDS[10]]
    assert nxt.retry == [] and _sample(GIVEN_UP) == given_up + 1
    (error_line,) = [m for m in nxt.errors if m.startswith("[OTX-RETRY-GAVE-UP]")]
    assert IDS[10] in error_line


def test_a_run_that_fails_at_the_event_leaves_the_entries_of_the_list_as_they_were(caplog, monkeypatch):
    """``EDGEGUARD_OTX_RETRY_PER_RUN=1``; pulses 10 (first failed 8 days ago) and 12 (9 days ago, tried longest
    ago) are past their deadline, neither pushed since. Run 1 fails at the MISP event: it fetches pulse 12 but
    does not push it, and both entries stay exactly as they were, ``last_tried_at`` included. Run 2, MISP
    answering and refusing both values, fetches pulse 12 again, pushes it and gives it up; pulse 10, not pushed
    since its deadline, stays. The earlier revision stamped pulse 12 as tried during the outage, so run 2
    fetched pulse 10 and gave up both, pulse 12 without a push MISP answered."""
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_PER_RUN", "1")
    otx = _Otx(_recorded(range(60)))
    a, b = _entry(10, days=8, tried_days=7.5), _entry(12, days=9, tried_days=8.5)
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[0]["modified"], "otx_retry_pulses": [a, b]}
    given_up = _sample(GIVEN_UP)
    outage = _collect(
        otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[0], IDS[1], IDS[10], IDS[12]], at_the_event=True)
    )
    assert otx.by_id_requests == [IDS[12]]
    assert outage.retry == [b, a]
    assert _sample(GIVEN_UP) == given_up

    answered = _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[10], IDS[12]]))
    assert otx.by_id_requests == [IDS[12], IDS[12]]
    assert answered.retry == [a]
    assert _sample(GIVEN_UP) == given_up + 1
    (error_line,) = [m for m in answered.errors if m.startswith("[OTX-RETRY-GAVE-UP]")]
    assert IDS[12] in error_line and IDS[10] not in error_line


# --------------------------------------------------------------------------- the size of an entry


def test_failed_items_keep_a_bounded_reference_of_each_item(caplog):
    """Pulse 44's only indicator is a URL of 5,021 characters, and MISP does not store it. The entry records
    the item as ``url:`` and 16 hex digits of the SHA-256 of its identity key (49 characters at most), so the
    state file holds no value. The next run fetches the pulse by id, pushes the URL again and MISP stores it:
    the reference of the pushed item matches the one recorded, and the pulse leaves the list. The earlier
    revision kept the identity key itself, the whole URL."""
    url = "https://example.test/" + "a" * 5000
    pulses = _recorded(range(60))
    pulses[44]["indicators"][0].update({"indicator": url, "type": "URL"})
    otx = _Otx(pulses)
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[59]["modified"]}
    run = _collect(otx, state, caplog, limit=20, writer=_Writer(failing=[IDS[44]]))

    (entry,) = run.retry
    (ref,) = entry["failed_items"]
    assert ref.startswith("url:") and len(ref) == 20
    assert url not in json.dumps(state) and len(json.dumps(entry)) < 500

    nxt = _collect(otx, state, caplog, limit=20)
    assert otx.by_id_requests == [IDS[44]]
    assert nxt.retry == [] and nxt.status["pulse_counts"]["retry_recovered"] == 1


def _state_file_bytes(entries: List[Dict[str, Any]]) -> int:
    """The size of the state file after ``baseline_checkpoint`` wrote *entries* as the OTX retry list."""
    baseline_checkpoint.update_source_incremental("otx", otx_retry_pulses=entries)
    return baseline_checkpoint.CHECKPOINT_FILE.stat().st_size


@pytest.mark.parametrize(
    "reason",
    ['"' * 2000, "\\" * 2000, "é" * 2000, "\x01\t\n" * 700],
    ids=["quotes", "backslashes", "non-ASCII", "control characters"],
)
def test_an_entry_of_the_list_stays_within_its_bound(reason):
    """The largest entry this module writes for an OTX pulse id: twelve failed items of a type of 300 characters
    and values of 3,000 characters (ten recorded, 49 characters each), a reason of 2,000 characters (300 kept, as
    printable ASCII: JSON escapes a quote or a backslash to two bytes, and a control character becomes ``?``,
    which it would escape to six), all five timestamps and a million attempts. Written to the state file by
    ``baseline_checkpoint`` (``json.dump`` with ``indent=2``), a list of 1,000 such entries, the cap, takes at
    most ``_RETRY_ENTRY_MAX_BYTES`` (2,000) a pulse, so at most 2 MB. The earlier revisions kept the identity
    keys whole, then stated the bound for compact JSON (1,500 bytes) and kept control characters."""
    pid = "6abf0b86fb14812f2dc84fb2"
    items = [
        {"pulse_id": pid, "indicator_type": "x" * 300, "value": f"https://example.test/{n}/" + "a" * 3000}
        for n in range(12)
    ]
    failing = otx_collector._pulses_with_listed_items(items, list(range(12)), {pid})
    pulse = {"id": pid, "modified": "2026-10-31T11:01:00.123456+00:00"}
    settled = otx_collector._settle_retry_list(
        [],
        [pulse],
        failing,
        otx_collector._items_per_pulse(items),
        add=True,
        outage=False,
        reason=reason,
        now=datetime.now(timezone.utc),
        max_days=7,
        max_pulses=1000,
    )
    (entry,) = settled.entries
    entry.update(
        attempts=10**6,
        last_fetch_failed_at=entry["first_failed_at"],
        last_push_started_at=entry["first_failed_at"],
    )
    assert len(entry["failed_items"]) == 10 and all(len(ref) == 49 for ref in entry["failed_items"])
    assert len(entry["last_reason"]) == 300
    assert entry["last_reason"].isascii() and entry["last_reason"].isprintable()
    assert json.dumps(entry["last_reason"]).count("\\u") == 0, "no character escaped to six bytes"

    empty = _state_file_bytes([])
    full = _state_file_bytes([{**entry, "id": f"{n:024x}"} for n in range(1000)])
    assert full - empty <= 1000 * otx_collector._RETRY_ENTRY_MAX_BYTES == 2_000_000


def test_a_usual_entry_takes_about_490_bytes_of_the_state_file():
    """An entry with one failed item (a URL) and the reason of a failed push, written to the state file by
    ``baseline_checkpoint``: about 490 bytes, as the comment on ``_RETRY_ENTRY_MAX_BYTES`` and the docs state."""
    pid = "6abf0b86fb14812f2dc84fb2"
    item = {"pulse_id": pid, "indicator_type": "url", "value": "https://example.test/a/b.php"}
    now = datetime(2026, 11, 2, 10, 30, 0, 123456, tzinfo=timezone.utc)
    settled = otx_collector._settle_retry_list(
        [],
        [{"id": pid, "modified": "2026-10-31T11:01:00.123000"}],
        otx_collector._pulses_with_listed_items([item], [0], {pid}),
        otx_collector._items_per_pulse([item]),
        add=True,
        outage=False,
        reason=f"MISP push of the run started {now.isoformat()}: 1 of 21 item(s) failed",
        now=now,
        max_days=7,
        max_pulses=1000,
    )
    empty = _state_file_bytes([])
    full = _state_file_bytes([{**settled.entries[0], "id": f"{n:024x}"} for n in range(1000)])
    assert 480 <= (full - empty) / 1000 <= 500


# --------------------------------------------------------------------------- the source text


@pytest.mark.parametrize("path", ["src/collectors/otx_collector.py", "src/collectors/misp_writer.py"])
def test_the_docstrings_and_comments_stay_within_120_columns(path):
    """``ruff format`` wraps code at 120 columns but leaves docstrings and comments as written; the retry list
    joined some of theirs past it. Every docstring and comment line of the collector and of the writer fits."""
    source = (_ROOT / path).read_text(encoding="utf-8")
    lines = source.splitlines()
    too_long = {
        tok.start[0]
        for tok in tokenize.generate_tokens(io.StringIO(source).readline)
        if tok.type == tokenize.COMMENT and len(lines[tok.start[0] - 1]) > 120
    }
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                end = first.end_lineno or first.lineno
                too_long.update(n for n in range(first.lineno, end + 1) if len(lines[n - 1]) > 120)
    assert sorted(too_long) == []


# --------------------------------------------------------------------------- writer, settings, alerts, docs


def test_the_writer_names_the_items_that_failed_at_their_event():
    """``last_push_event_failed_items``: among the listed items, those whose MISP event could not be used (here
    the lookup of the second source's event, HTTP 503 after the retries), not those of a batch MISP refused
    (HTTP 400 for the first source's batch); an empty push clears the list."""
    misp = _Misp(failing_batches=(1,), event_errors={"threatfox": ("lookup", 503)})
    writer = _writer(misp)
    items = [
        _indicator("198.51.100.1", "alienvault_otx"),
        _indicator("198.51.100.2", "threatfox"),
        _indicator("198.51.100.3", "alienvault_otx"),
        _indicator("198.51.100.4", "threatfox"),
    ]
    with patch("collectors.collector_utils.time.sleep"):
        assert writer.push_items(items) == (0, 4)
    assert writer.last_push_unstored_items == [0, 1, 2, 3]
    assert writer.last_push_event_failed_items == [1, 3]
    assert writer.push_items([]) == (0, 0)
    assert writer.last_push_event_failed_items == []


def test_the_writer_batches_the_items_of_each_batch_key_apart(monkeypatch):
    """``push_items(batch_key=...)``: the attributes of items with different keys never share a batch; each key's
    are batched in their order, the keys in the order of their first item, and an attribute built from two items
    (the same value) takes the key of the first. Without ``batch_key`` the batches follow the items."""

    class _Batches(_Misp):
        def __init__(self) -> None:
            super().__init__()
            self.batches: List[List[str]] = []

        def post(self, url: str, json: Optional[dict] = None, **kw: Any):
            if "/events/" in url and not url.endswith("/events/restSearch"):
                self.batches.append([a["value"] for a in (json or {}).get("Attribute") or []])
            return super().post(url, json=json, **kw)

    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", "2")
    keys = ["a", "b", "a", None, "a", "b", "c"]
    values = ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5", "198.51.100.6"]
    items = [{**_indicator(v, "alienvault_otx"), "k": k} for v, k in zip(values, keys, strict=False)]
    items.append({**_indicator("198.51.100.2", "alienvault_otx"), "k": "c"})  # the value of the first "b" item

    misp = _Batches()
    assert _writer(misp).push_items(items, batch_key=lambda item: item["k"]) == (6, 0)
    assert misp.batches == [
        ["198.51.100.1", "198.51.100.3"],
        ["198.51.100.5"],
        ["198.51.100.2", "198.51.100.6"],
        ["198.51.100.4"],
    ]

    plain = _Batches()
    assert _writer(plain).push_items(items) == (6, 0)
    assert plain.batches == [
        ["198.51.100.1", "198.51.100.2"],
        ["198.51.100.3", "198.51.100.4"],
        ["198.51.100.5", "198.51.100.6"],
    ]


def _settings() -> tuple:
    return (
        config.otx_retry_per_run(),
        config.otx_retry_max_days(),
        config.otx_retry_max_pulses(),
        config.otx_retry_max_seconds(),
    )


def test_the_settings_and_their_bounds(monkeypatch):
    assert _settings() == (50, 7, 1000, 600)
    for name, value in (
        ("EDGEGUARD_OTX_RETRY_PER_RUN", "-3"),
        ("EDGEGUARD_OTX_RETRY_MAX_DAYS", "0"),
        ("EDGEGUARD_OTX_RETRY_MAX_PULSES", "0"),
        ("EDGEGUARD_OTX_RETRY_MAX_SECONDS", "0"),
    ):
        monkeypatch.setenv(name, value)
    assert _settings() == (0, 1, 1, 1)
    monkeypatch.setenv("EDGEGUARD_OTX_RETRY_MAX_SECONDS", "ten minutes")
    assert config.otx_retry_max_seconds() == 600


def _alert(name: str) -> Dict[str, Any]:
    found = [(g["name"], r) for g in _RULES["groups"] for r in g["rules"] if r.get("alert") == name]
    assert len(found) == 1, name
    group, rule = found[0]
    assert group == "edgeguard_collection"
    return rule


def _norm(expr: str) -> str:
    return " ".join(expr.split())


def test_the_alerts_read_the_retry_metrics_and_point_to_the_runbook():
    waiting = _alert("EdgeGuardOtxRetryPulsesWaiting")
    given_up = _alert("EdgeGuardOtxRetryPulsesGivenUp")
    assert _norm(waiting["expr"]) == (
        "edgeguard_otx_retry_pulses > 0 and on () "
        "(time() - edgeguard_otx_retry_oldest_failure_timestamp_seconds) > 86400"
    )
    assert waiting["for"] == "30m"
    assert _norm(given_up["expr"]) == (
        "sum(increase(edgeguard_otx_retry_given_up_total[24h])) > 0 or "
        "( sum(edgeguard_otx_retry_given_up_total) > 0 unless sum(edgeguard_otx_retry_given_up_total offset 24h) )"
    ), "the second clause: the first pulse ever given up, when the series appears"
    assert given_up["for"] == "0m"
    for rule in (waiting, given_up):
        assert rule["labels"] == {"severity": "warning", "component": "collector"}
        assert f'docs/RUNBOOK.md § "{_RUNBOOK_SECTION}"' in rule["annotations"]["description"]
    runbook = (_ROOT / "docs" / "RUNBOOK.md").read_text()
    section = runbook.split(f"## {_RUNBOOK_SECTION}", 1)[1].split("\n## ", 1)[0]
    for text in (
        "EdgeGuardOtxRetryPulsesWaiting",
        "EdgeGuardOtxRetryPulsesGivenUp",
        "EdgeGuardDAGRunFailures",
        "EdgeGuardSourceUnhealthy",
        "[OTX-RETRY-GAVE-UP]",
        "baseline_days",
    ):
        assert text in section, text
    table = (_ROOT / "docs" / "PROMETHEUS_SETUP.md").read_text().split("\n## History", 1)[0]
    for name in (
        "edgeguard_otx_retry_pulses",
        "edgeguard_otx_retry_oldest_failure_timestamp_seconds",
        "edgeguard_otx_retry_given_up_total",
        "EdgeGuardOtxRetryPulsesWaiting",
        "EdgeGuardOtxRetryPulsesGivenUp",
    ):
        assert f"| `{name}` |" in table, name
