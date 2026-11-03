"""A MISP push stops once MISP has kept failing for longer than its cap (2026-11-03).

Nothing stopped a push while MISP kept answering HTTP 5xx or 429: every failed batch cost five attempts (10, 20,
40 and 80 s of back-off, and the lookups after each 5xx), and a 300 s cooldown followed every three failed
batches, so a long push against a failing MISP ran until Airflow's ``execution_timeout`` killed the task, which
saves no state. Now:

* a batch gets three retries (four attempts, 10/20/40 s apart); the event lookups keep four;
* one ``push_items`` call goes on for at most ``EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC`` (900 s) of failure time, or
  ``EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE`` (3600 s) for the baseline's writer, which also stops a streak
  10 minutes before its task's end. The time is the wall time of the current failing streak: from the start of
  the first request that fails, through the waits, pauses and attempts that follow, until a batch MISP answers
  or the day's event lookup returns;
* a batch's retries stop when the next wait would reach the cap, a ``Retry-After`` wait is cut to the time left,
  the lookups after a 5xx get timeouts of at most the time left, and before a batch (and again after the pause,
  the cooldown and the liveness check) the push stops when the batch would start at or after the cap, the
  throttle pause and the cooldown due included; in a push of several sources it also stops before a group. The
  items not sent count as failed and are listed
  (``last_push_unstored_items``, ``last_push_unsent_items``), one ERROR ``[MISP-PUSH-STOPPED]`` and
  ``edgeguard_misp_push_stopped_total`` report it, and the run goes on;
* during a back-off cooldown, a light request after a 30 s step, while its 40 s of timeouts fit in what is left,
  ends the cooldown when MISP answers; its time counts toward the cooldown, so the light requests never make it
  longer than its length.

The tests drive ``MISPWriter.push_items`` against a MISP double on a virtual clock: ``time.sleep`` advances it,
``time.monotonic`` reads it, and a failing batch request takes ``push_seconds`` of it. ``rate_limited`` reads the
real ``time.time`` and sleeps at most 0.5 s per request on the virtual clock, which the expected times allow for.
Every behavioural test here fails on the code before the change; the guards say so.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Union
from unittest.mock import patch

import pytest
import requests

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
_DAGS = os.path.join(os.path.dirname(__file__), "..", "dags")
for _p in (_SRC, _DAGS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from misp_fakes import FakeMisp, Response  # noqa: E402
from stub_cleanup import dag_module_import  # noqa: E402

import config  # noqa: E402
from collectors import misp_writer as mw  # noqa: E402

EVENT = "100"
URL = "https://misp.test"
TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
CAP_SETTINGS = ("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE")


class _Clock:
    """A virtual clock: ``sleep`` advances it and ``monotonic`` reads it; ``log`` records each sleep and each
    request the MISP double answers, in order."""

    def __init__(self) -> None:
        self.now = 1_000.0
        self.log: List[Any] = []

    def sleep(self, seconds: float) -> None:
        self.log.append(("sleep", float(seconds)))
        self.now += max(0.0, float(seconds))

    def monotonic(self) -> float:
        return self.now

    def waits(self) -> List[float]:
        """The sleeps of a second or more (the rate limiter's are shorter)."""
        return [entry[1] for entry in self.log if isinstance(entry, tuple) and entry[1] >= 1.0]


class _Resp:
    def __init__(self, status: int, payload: Any = None, text: str = "", headers: Optional[dict] = None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text
        self.headers = headers or {}

    def json(self) -> Any:
        return self._payload


Outcome = Union[int, BaseException]


class _Misp:
    """MISP as the push meets it: the event lookup finds the day's event, the attribute listings and the lookups
    after a 5xx find nothing (or the source's ``stored`` rows), and each batch request takes ``push_seconds`` and
    answers ``push`` (an HTTP status, an exception to raise, or a function of the batch's values giving either);
    ``batch_times`` keeps the clock at the start of each. The light request of a cooldown (``_misp_answers``, told
    apart by its timeout) takes ``probe_seconds`` and answers ``probe`` (an HTTP status, or an exception to
    raise)."""

    def __init__(
        self,
        clock: _Clock,
        *,
        push: Union[Outcome, Callable[[List[str]], Outcome]] = 500,
        push_seconds: float = 0.0,
        probe: Outcome = 200,
        probe_seconds: float = 0.0,
        retry_after: Optional[str] = None,
        stored: Optional[List[dict]] = None,
    ):
        self.clock = clock
        self.push = push
        self.push_seconds = push_seconds
        self.probe = probe
        self.probe_seconds = probe_seconds
        self.retry_after = retry_after
        self.stored = stored or []
        self.batches: List[List[str]] = []
        self.batch_times: List[float] = []
        self.edits: List[str] = []

    def post(self, url: str, json: Optional[dict] = None, timeout: Any = None, **_kw: Any) -> _Resp:
        path = url.split(URL, 1)[1]
        body = json or {}
        if path == "/events/restSearch":
            if timeout is not None and timeout == getattr(mw.MISPWriter, "COOLDOWN_PROBE_TIMEOUT", None):
                self.clock.log.append("probe")
                self.clock.now += self.probe_seconds
                if isinstance(self.probe, BaseException):
                    raise self.probe
                return _Resp(self.probe, {"response": []}, text="probe")
            row = {"Event": {"id": EVENT, "info": body["eventinfo"], "attribute_count": "0"}}
            return _Resp(200, {"response": [row]})
        if path == "/attributes/restSearch":
            rows = list(self.stored) if "tags" in body else []
            return _Resp(200, {"response": {"Attribute": rows}})
        if path.startswith("/attributes/edit/"):
            self.edits.append(path.rsplit("/", 1)[1])
            return _Resp(200, {"Attribute": {"uuid": path.rsplit("/", 1)[1], "timestamp": str(2_000_000_000)}})
        if path == f"/events/{EVENT}":
            attrs = body.get("Attribute") or []
            values = [a["value"] for a in attrs]
            self.batches.append(values)
            self.batch_times.append(self.clock.now)
            self.clock.log.append("batch")
            self.clock.now += self.push_seconds
            outcome = self.push(values) if callable(self.push) else self.push
            if isinstance(outcome, BaseException):
                raise outcome
            if outcome == 200:
                return _Resp(200, {"Event": {"id": EVENT, "Attribute": [dict(a) for a in attrs]}})
            headers = {"Retry-After": self.retry_after} if outcome == 429 and self.retry_after else {}
            return _Resp(outcome, {"errors": "x"}, text="Internal Server Error", headers=headers)
        raise AssertionError(path)

    def probes(self) -> int:
        return self.clock.log.count("probe")


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setattr(mw, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", True)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", "1")  # one item a batch unless a test says otherwise
    for name in (
        *CAP_SETTINGS,
        "EDGEGUARD_MISP_BACKOFF_THRESHOLD",
        "EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC",
        "EDGEGUARD_MISP_EVENT_SPLIT_ABOVE",
        "EDGEGUARD_MISP_REFRESH_MAX_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def clock(monkeypatch) -> _Clock:
    c = _Clock()
    monkeypatch.setattr(mw.time, "sleep", c.sleep)
    monkeypatch.setattr(mw.time, "monotonic", c.monotonic)
    return c


def _writer(misp: Any, **kw: Any) -> mw.MISPWriter:
    writer = mw.MISPWriter(url=URL, api_key="test", verify_ssl=True, **kw)
    writer.session = misp
    return writer


def _items(n: int, source: str = "urlhaus", start: int = 0) -> List[Dict[str, Any]]:
    return [
        {"indicator_type": "ipv4", "value": f"198.51.100.{i}", "tag": source, "zone": ["global"]}
        for i in range(start, start + n)
    ]


def _count(name: str, source: str) -> float:
    """The value of the writer's counter *name* (``_MISP_PUSH_STOPPED``, ...) for *source*; 0 without it."""
    counter = getattr(mw, name, None)
    return counter.labels(source=source)._value.get() if counter is not None else 0.0


def _stops(caplog) -> List[str]:
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("[MISP-PUSH-STOPPED]")]


def _summary(caplog) -> str:
    (line,) = [r.getMessage() for r in caplog.records if r.getMessage().startswith("[OK] MISP push complete:")]
    return line


# --------------------------------------------------------------------------- the stop


def test_a_push_misp_keeps_failing_stops_before_the_cap_and_counts_the_items_not_sent_as_failed(
    clock, monkeypatch, caplog
):
    """MISP answers every batch with HTTP 500 at once and answers light requests (the event at its size limit,
    the case of 1 Nov 2026). With the 5 s throttle each batch takes 70 s of back-off over four attempts; the
    cooldown after every three failed batches ends after its first 30 s step, when MISP answers the probe.
    Before the tenth batch the streak has lasted about 730 s and the cooldown due would take it past 900 s: the
    push stops there. Nine batches were sent and failed; the eleven items not sent count as failed and are
    listed. Before the change the push sent all twenty batches, five attempts each, with no limit."""
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "5")
    misp = _Misp(clock)
    writer = _writer(misp)
    items = _items(20)
    stopped, permanent = _count("_MISP_PUSH_STOPPED", "urlhaus"), _count("_MISP_PUSH_PERMANENT_FAILURES", "urlhaus")
    started = clock.now
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        assert writer.push_items(items) == (0, 20)

    assert len(misp.batches) == 36, "nine batches of four attempts"
    assert {v for b in misp.batches for v in b} == {i["value"] for i in items[:9]}
    expected: List[float] = []
    for batch in range(1, 10):
        if batch > 1:
            expected.append(5.0)
        if batch in (4, 7):
            expected.append(30.0)
        expected += [10.0, 20.0, 40.0]
    assert clock.waits() == expected, "no wait after the stop: the cooldown due before batch 10 is not slept"
    assert 730 <= clock.now - started < 760, "the push stopped before the cap of 900 s"

    assert writer.last_push_stopped is True
    assert writer.last_push_unsent_items == list(range(9, 20))
    assert writer.last_push_unstored_items == list(range(20))
    assert writer.last_push_event_failed_items == [] and writer.last_push_skipped_items == []
    (stop,) = _stops(caplog)
    assert stop.startswith("[MISP-PUSH-STOPPED] MISP push urlhaus: MISP kept failing for 7")
    assert "(EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC=900), so the push stopped before batch 10 of 20" in stop
    assert stop.endswith(
        "11 batch(es) with 11 attribute(s) not sent, counted as failed; the push ends and the run goes on"
    )
    assert [r.levelno for r in caplog.records if r.getMessage() == stop] == [logging.ERROR]
    summary = _summary(caplog)
    assert summary.startswith("[OK] MISP push complete: 0 succeeded, 20 failed")
    assert "11 attribute(s) not sent ([MISP-PUSH-STOPPED])" in summary
    if mw._METRICS_AVAILABLE:
        assert _count("_MISP_PUSH_STOPPED", "urlhaus") == stopped + 1
        assert _count("_MISP_PUSH_PERMANENT_FAILURES", "urlhaus") == permanent + 9, "unsent batches are not counted"
    assert (
        sum(
            "failed after retries" in r.getMessage() and "counted as failed and continuing" in r.getMessage()
            for r in caplog.records
        )
        == 9
    )


def test_a_cooldown_that_would_reach_the_cap_is_not_slept_and_the_probe_fails_while_misp_is_down(clock, caplog):
    """MISP answers no light request either: the first cooldown runs its ten 30 s steps (a probe after each while
    at least the probe's 40 s of timeouts is left: the first eight), and before the seventh batch the next
    cooldown would pass the cap (about 720 s of failure plus 300 s): the push stops without sleeping it."""
    misp = _Misp(clock, probe=503)
    writer = _writer(misp)
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        assert writer.push_items(_items(20)) == (0, 20)
    assert len(misp.batches) == 24, "six batches of four attempts"
    assert clock.waits().count(30.0) == 10 and misp.probes() == 8
    assert writer.last_push_unsent_items == list(range(6, 20))
    assert len(_stops(caplog)) == 1


def test_a_batch_misp_answers_ends_the_streak_and_the_next_failure_has_the_whole_cap(clock, monkeypatch):
    """Each request takes 20 s, the cap is 100 s. A failing batch gives up after three attempts: before its third
    retry the 40 s wait would reach the cap (90 s + 40 s). Two stored batches follow each failing one, so the
    back-off counter never reaches the cooldown. Every failing batch starts a new streak and gets the same three
    attempts: the push is not stopped. Before the change each failing batch made five attempts."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "100")
    items = _items(9)
    failing = {items[i]["value"] for i in (0, 3, 6)}
    misp = _Misp(clock, push=lambda values: 500 if values[0] in failing else 200, push_seconds=20)
    writer = _writer(misp)
    assert writer.push_items(items) == (6, 3)
    assert [b[0] for b in misp.batches].count(items[0]["value"]) == 3
    assert len(misp.batches) == 3 * 3 + 6
    assert writer.last_push_stopped is False and writer.last_push_unsent_items == []
    assert writer.last_push_unstored_items == [0, 3, 6]


def test_time_alone_never_stops_a_push(monkeypatch):
    """Guard (passes before the change too): a push MISP answers is not stopped, whatever the clock reads, here
    100,000 s later at every reading."""
    readings = iter(range(0, 100_000_000, 100_000))
    monkeypatch.setattr(mw.time, "monotonic", lambda: float(next(readings)))
    monkeypatch.setattr(mw.time, "sleep", lambda _s: None)
    misp = _Misp(_Clock(), push=200)
    writer = _writer(misp)
    assert writer.push_items(_items(10)) == (10, 0)
    assert getattr(writer, "last_push_stopped", False) is False and len(misp.batches) == 10


def test_a_cap_of_zero_is_no_cap(clock, monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "0")
    misp = _Misp(clock)
    writer = _writer(misp)
    assert writer.push_items(_items(20)) == (0, 20)
    assert len(misp.batches) == 80, "every batch sent, four attempts each"
    assert writer.last_push_stopped is False and writer.last_push_unsent_items == []


def test_a_batch_refused_with_http_4xx_ends_the_streak(clock, monkeypatch):
    """Batches answered 500, 400, 500; each request takes 20 s and the cap is 100 s. The first batch gives up after
    three attempts (90 s); the second is refused with HTTP 400, which ``_push_batch`` returns from, so the streak
    ends and the third batch starts a new one with the whole cap: three attempts, no stop."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "100")
    items = _items(3)
    outcome = {items[0]["value"]: 500, items[1]["value"]: 400, items[2]["value"]: 500}
    misp = _Misp(clock, push=lambda values: outcome[values[0]], push_seconds=20)
    writer = _writer(misp)
    assert writer.push_items(items) == (0, 3)
    assert writer.last_push_stopped is False
    assert [b[0] for b in misp.batches].count(items[2]["value"]) == 3, "a new streak with the whole cap"


def test_the_stop_names_the_source_it_stopped_in_and_counts_it_there(clock, monkeypatch, caplog):
    """Three urlhaus items, then two threatfox items; 50 s requests and a cap of 40 s. The push stops in urlhaus,
    before its second batch: the ERROR and ``edgeguard_misp_push_stopped_total`` name urlhaus, not the later entry,
    and the four items not sent are listed."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "40")
    misp = _Misp(clock, push_seconds=50)
    writer = _writer(misp)
    before_u, before_t = _count("_MISP_PUSH_STOPPED", "urlhaus"), _count("_MISP_PUSH_STOPPED", "threatfox")
    items = _items(3) + _items(2, source="threatfox", start=100)
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        assert writer.push_items(items) == (0, 5)
    (stop,) = _stops(caplog)
    assert stop.startswith("[MISP-PUSH-STOPPED] MISP push urlhaus:"), stop
    assert "before batch 2 of 5: 4 batch(es) with 4 attribute(s)" in stop, stop
    assert writer.last_push_unsent_items == [1, 2, 3, 4]
    if mw._METRICS_AVAILABLE:
        assert _count("_MISP_PUSH_STOPPED", "urlhaus") == before_u + 1
        assert _count("_MISP_PUSH_STOPPED", "threatfox") == before_t


def test_an_empty_push_after_a_stopped_one_reports_no_stop(clock, monkeypatch):
    """``last_push_stopped`` and ``last_push_unsent_items`` belong to the last call, as the other lists do."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "40")
    misp = _Misp(clock, push_seconds=50)
    writer = _writer(misp)
    writer.push_items(_items(3))
    assert writer.last_push_stopped is True and writer.last_push_unsent_items
    assert writer.push_items([]) == (0, 0)
    assert writer.last_push_stopped is False and writer.last_push_unsent_items == []


def test_when_the_cap_and_the_deadline_end_the_push_before_the_same_batch_the_stop_is_reported(clock, monkeypatch):
    """The cap's check comes before the deadline's: a push on a failing MISP that reaches both before the same
    batch is a stop (its items failed, the alert's counter), not a time budget's skip."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "40")
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "5")
    misp = _Misp(clock, push_seconds=60)
    writer = _writer(misp)
    assert writer.push_items(_items(3), deadline=clock.now + 62) == (0, 3)
    assert writer.last_push_stopped is True
    assert writer.last_push_unsent_items == [1, 2] and writer.last_push_skipped_items == []


def test_the_throttle_pause_before_a_cooldown_counts_in_the_check_before_the_batch(clock, monkeypatch, caplog):
    """A 30 s throttle, a cap of 590 s, batches answered HTTP 500 at once, and a probe answered 503. Before the
    fourth batch the streak has lasted 270 s: the 30 s throttle and the 300 s cooldown due would end at 600 s,
    past the cap, so the push stops there and sleeps neither. Before the fix the check left out the throttle:
    both were slept and the fourth batch was sent at 600 s, after the streak had reached the cap."""
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "30")
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "590")
    misp = _Misp(clock, probe=503)
    writer = _writer(misp)
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        assert writer.push_items(_items(10)) == (0, 10)
    assert len(misp.batches) == 12, "three batches of four attempts"
    assert max(misp.batch_times) - misp.batch_times[0] < 590
    assert misp.probes() == 0 and writer.last_push_unsent_items == list(range(3, 10))
    (stop,) = _stops(caplog)
    assert "so the push stopped before batch 4 of 10" in stop


def test_a_batch_is_not_sent_once_the_streak_has_reached_the_cap_after_the_liveness_check(clock, monkeypatch):
    """The check before a batch runs again after the pause, the cooldown and the liveness check. Here each liveness
    check of the parent DAG takes 100 s; with a cap of 150 s the first batch fails after its four attempts (70 s),
    the check before the second passes, and the liveness check takes the streak to 170 s: the second batch is not
    sent. Before the fix it was sent once, after the cap."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "150")

    def liveness() -> None:
        clock.now += 100

    misp = _Misp(clock)
    writer = _writer(misp, liveness_callback=liveness)
    assert writer.push_items(_items(3)) == (0, 3)
    assert len(misp.batches) == 4 and writer.last_push_unsent_items == [1, 2]


def test_a_push_of_several_sources_stops_before_a_group_once_the_streak_has_reached_the_cap(clock, monkeypatch, caplog):
    """The day's event lookups wait out a 330 s timeout (MISP not answering), and the cap is 60 s. The urlhaus
    lookup fails once and its items fail at the event; the streak it began has then reached the cap, so the push
    stops before the feodo and sslbl groups: neither is listed nor looked up, and their items count as failed and
    are listed as not sent. The stop names the group it stopped before. Before the fix every group paid its
    listings and one lookup attempt, and no stop was reported."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "60")
    misp = _Misp(clock, push=200)
    real = misp.post
    lookups: List[str] = []

    def post(url: str, json: Optional[dict] = None, timeout: Any = None, **kw: Any) -> _Resp:
        if url.endswith("/events/restSearch") and timeout != mw.MISPWriter.COOLDOWN_PROBE_TIMEOUT:
            lookups.append((json or {}).get("eventinfo", ""))
            clock.now += 330
            raise requests.exceptions.ReadTimeout("read timed out")
        return real(url, json=json, timeout=timeout, **kw)

    misp.post = post  # type: ignore[method-assign]
    writer = _writer(misp)
    items = _items(2) + _items(2, source="feodo", start=10) + _items(2, source="sslbl", start=20)
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        assert writer.push_items(items) == (0, 6)
    assert lookups == [f"EdgeGuard-urlhaus-{TODAY}"]
    assert writer.last_push_event_failed_items == [0, 1]
    assert writer.last_push_unsent_items == [2, 3, 4, 5] and writer.last_push_stopped is True
    (stop,) = _stops(caplog)
    assert stop.startswith("[MISP-PUSH-STOPPED] MISP push feodo: MISP kept failing for 330s"), stop
    assert "before batch 1 of 4: 4 batch(es) with 4 attribute(s) not sent" in stop


# --------------------------------------------------------------------------- inside a batch


def test_a_retry_after_wait_is_cut_to_the_time_left(clock, caplog):
    """HTTP 429 with ``Retry-After: 600`` on every attempt. The first wait fits the cap of 900 s; the second is
    cut to what is left (about 290 s); then the retry's wait would pass the cap, so the batch fails, and the push
    stops before the next one. Before the change every attempt waited 600 s."""
    misp = _Misp(clock, push=429, retry_after="600")
    writer = _writer(misp)
    with caplog.at_level(logging.WARNING, logger=mw.logger.name):
        assert writer.push_items(_items(3)) == (0, 3)
    waits = clock.waits()
    assert waits[:2] == [600.0, 10.0] and len(waits) == 3
    assert waits[2] == pytest.approx(290.0, abs=1.5)
    assert len(misp.batches) == 2 and writer.last_push_unsent_items == [1, 2]
    assert any("the Retry-After wait is cut to" in r.getMessage() for r in caplog.records)


def test_a_rate_limit_with_no_time_left_raises_without_waiting(clock):
    """One attempt (``__wrapped__``) while the push's streak has already lasted its cap: no ``Retry-After`` wait."""
    misp = _Misp(clock, push=429, retry_after="50")
    writer = _writer(misp)
    writer._misp_push_failing_cap = 100.0
    writer._misp_push_failing_since = clock.now - 100.0
    attrs = [{"type": "ip-dst", "category": "Network activity", "value": "198.51.100.1", "to_ids": False}]
    with pytest.raises(mw.MispTransientError):
        mw.MISPWriter._push_batch.__wrapped__(writer, EVENT, attrs)
    assert clock.waits() == []


def test_a_timeout_after_the_retries_still_raises_out_of_the_push_sooner(clock, caplog):
    """MISP not answering: each attempt ends in a read timeout after 330 s. The third attempt ends after about
    1,020 s and its retry would wait past the cap, so the timeout raises out of ``push_items`` as before, after
    three attempts instead of five (about 1,800 s)."""
    misp = _Misp(clock, push=requests.exceptions.ReadTimeout("read timed out"), push_seconds=330)
    writer = _writer(misp)
    started = clock.now
    with caplog.at_level(logging.WARNING):
        with pytest.raises(requests.exceptions.ReadTimeout):
            writer.push_items(_items(5))
    assert len(misp.batches) == 3
    assert 1_020 <= clock.now - started < 1_025
    assert any("No retry: MISP has kept failing for" in r.getMessage() for r in caplog.records)
    assert writer.last_push_stopped is False and writer.last_push_unstored_items == []


def test_the_event_lookup_retries_stop_at_the_cap_and_its_items_fail_at_the_event(clock, monkeypatch):
    """The day's event lookup answers HTTP 503 on every attempt, each after 100 s; with a cap of 150 s its
    retries stop after the second attempt (210 s + 20 s), not the fifth, and the group's items fail at the event
    as after the last retry."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "150")
    misp = _Misp(clock)
    lookups: List[float] = []
    real = misp.post

    def post(url: str, json: Optional[dict] = None, timeout: Any = None, **kw: Any) -> _Resp:
        if url.endswith("/events/restSearch"):
            lookups.append(clock.now)
            clock.now += 100
            return _Resp(503, text="Service Unavailable")
        return real(url, json=json, timeout=timeout, **kw)

    misp.post = post  # type: ignore[method-assign]
    writer = _writer(misp)
    assert writer.push_items(_items(3)) == (0, 3)
    assert len(lookups) == 2 and misp.batches == []
    assert writer.last_push_event_failed_items == [0, 1, 2] and writer.last_push_stopped is False


def test_the_lookup_after_a_5xx_gets_only_the_time_left_of_the_cap(clock, caplog):
    """A batch request answers HTTP 500 after 500 s, and the lookup of the batch's values that follows (did MISP
    store it anyway?) waits out its timeouts. The lookup gets the 400 s left of the cap of 900 s as its read
    timeout and no retry; the batch then fails and the push stops about 930 s into the streak, one connect
    timeout past the cap. Before the fix the lookup made three attempts of 30 + 600 s, and the push stopped
    about 2,400 s into the streak."""
    misp = _Misp(clock, push_seconds=500)
    real = misp.post
    lookups: List[Any] = []

    def post(url: str, json: Optional[dict] = None, timeout: Any = None, **kw: Any) -> _Resp:
        if url.endswith("/attributes/restSearch") and "eventid" in (json or {}) and "value" in (json or {}):
            lookups.append(timeout)
            clock.now += sum(timeout)
            raise requests.exceptions.ReadTimeout("read timed out")
        return real(url, json=json, timeout=timeout, **kw)

    misp.post = post  # type: ignore[method-assign]
    writer = _writer(misp)
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        assert writer.push_items(_items(3)) == (0, 3)
    assert len(misp.batches) == 1 and len(lookups) == 1
    assert lookups[0][0] == 30 and lookups[0][1] == pytest.approx(400.0, abs=1.5)
    (stop,) = _stops(caplog)
    failing = float(re.search(r"kept failing for (\d+)s", stop).group(1))
    assert 900 <= failing <= 932


def test_no_lookup_after_a_5xx_is_made_once_the_cap_has_no_time_left(clock, caplog):
    """A batch request answers HTTP 500 after 950 s, past the cap of 900 s: the values are not looked up (the batch
    counts as not stored), and the push stops before the next batch."""
    misp = _Misp(clock, push_seconds=950)
    real = misp.post
    lookups: List[Any] = []

    def post(url: str, json: Optional[dict] = None, timeout: Any = None, **kw: Any) -> _Resp:
        if url.endswith("/attributes/restSearch") and "eventid" in (json or {}) and "value" in (json or {}):
            lookups.append(timeout)
        return real(url, json=json, timeout=timeout, **kw)

    misp.post = post  # type: ignore[method-assign]
    writer = _writer(misp)
    with caplog.at_level(logging.WARNING, logger=mw.logger.name):
        assert writer.push_items(_items(2)) == (0, 2)
    assert lookups == [] and len(misp.batches) == 1 and writer.last_push_unsent_items == [1]
    assert any("no lookup of the batch after the server error" in r.getMessage() for r in caplog.records)


def test_the_first_retry_after_wait_of_a_streak_is_cut_to_the_cap(clock, monkeypatch):
    """HTTP 429 with ``Retry-After: 600`` while no streak is on and the cap is 100 s: the 429 starts the streak at
    its attempt's start, so its wait is cut to the cap too."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "100")
    misp = _Misp(clock, push=429, retry_after="600")
    writer = _writer(misp)
    assert writer.push_items(_items(1)) == (0, 1)
    assert clock.waits() and clock.waits()[0] <= 100.0, clock.waits()


def _failing_event_lookups(misp: _Misp, clock: _Clock) -> List[float]:
    """Make the day's event lookups of *misp* answer HTTP 503; returns the clock at the start of each."""
    real = misp.post
    lookups: List[float] = []

    def post(url: str, json: Optional[dict] = None, timeout: Any = None, **kw: Any) -> _Resp:
        if url.endswith("/events/restSearch") and timeout != mw.MISPWriter.COOLDOWN_PROBE_TIMEOUT:
            lookups.append(clock.now)
            return _Resp(503, text="Service Unavailable")
        return real(url, json=json, timeout=timeout, **kw)

    misp.post = post  # type: ignore[method-assign]
    return lookups


def test_the_event_lookup_keeps_four_retries(clock, monkeypatch):
    """Without a cap the event lookup still makes five attempts (four retries); only ``_push_batch`` has three."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "0")
    misp = _Misp(clock)
    lookups = _failing_event_lookups(misp, clock)
    writer = _writer(misp)
    assert writer.push_items(_items(1)) == (0, 1)
    assert len(lookups) == 5


def test_an_event_lookup_that_returns_ends_the_streak_its_failed_attempt_began(clock, monkeypatch):
    """The day's event lookup fails once after 100 s and is answered at its retry; every batch then answers HTTP
    500 at once, and the cap is 150 s. The answered lookup ends the streak its failed attempt began, so the
    batches start a streak of their own: four, four and one attempts, then the cooldown due would pass the cap.
    Were the lookup's 110 s counted, the batches would get three, one and one."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "150")
    misp = _Misp(clock)
    real = misp.post
    lookups: List[float] = []

    def post(url: str, json: Optional[dict] = None, timeout: Any = None, **kw: Any) -> _Resp:
        if url.endswith("/events/restSearch") and timeout != mw.MISPWriter.COOLDOWN_PROBE_TIMEOUT and not lookups:
            lookups.append(clock.now)
            clock.now += 100
            return _Resp(503, text="Service Unavailable")
        return real(url, json=json, timeout=timeout, **kw)

    misp.post = post  # type: ignore[method-assign]
    writer = _writer(misp)
    assert writer.push_items(_items(5)) == (0, 5)
    assert len(misp.batches) == 9 and writer.last_push_stopped is True
    assert writer.last_push_unsent_items == [3, 4]


def test_a_push_after_one_a_timeout_ended_gives_its_lookup_the_whole_cap(clock):
    """The first push ends with a read timeout raised out of ``push_items``, its streak still on. The next push on
    the writer, two hours later, starts without it: its event lookup, failing, gets its four retries (150 s)
    within the new push's cap."""
    misp = _Misp(clock, push=requests.exceptions.ReadTimeout("read timed out"), push_seconds=330)
    writer = _writer(misp)
    with pytest.raises(requests.exceptions.ReadTimeout):
        writer.push_items(_items(1))
    clock.now += 7200
    lookups = _failing_event_lookups(misp, clock)
    assert writer.push_items(_items(1, start=50)) == (0, 1)
    assert len(lookups) == 5


def test_the_lookup_of_a_later_part_stops_its_retries_at_the_cap(clock, monkeypatch):
    """The event split (limit 10): the lookup of part 2 answers HTTP 503 after 100 s; with a cap of 150 s it gets
    two attempts (100 s + 10 s + 100 s), not five."""
    monkeypatch.setattr(mw, "_EVENT_SPLIT_MIN", 1)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", False)
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "10")
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", "5")
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "150")
    misp = FakeMisp([], event_info=f"EdgeGuard-urlhaus-{TODAY}", url="misp.test")
    real = misp.post
    part2: List[float] = []

    def post(url: str, json: Optional[dict] = None, **kw: Any) -> Response:
        if url.endswith("/events/restSearch") and (json or {}).get("eventinfo", "").endswith("-part2"):
            part2.append(clock.now)
            clock.now += 100
            return Response(503, {"errors": "x"})
        return real(url, json=json, **kw)

    misp.post = post  # type: ignore[method-assign]
    writer = _writer(misp)
    writer.push_items(_items(30))
    assert len(part2) == 2, part2


def test_a_lookup_after_a_5xx_with_no_time_left_sends_no_request(clock):
    """``_post_with_retries`` given an *until* already past makes no attempt and raises."""
    misp = _Misp(clock)
    writer = _writer(misp)
    with pytest.raises(mw.MispTransientError, match="no time left"):
        writer._post_with_retries(f"{URL}/attributes/restSearch", {}, context="lookup", until=clock.now - 1)
    assert clock.log == []


def test_the_decorator_without_a_hook_reads_no_clock(monkeypatch):
    """Guard (passes before the change too): ``retry_with_backoff``'s other callers pass no *give_up*, and their
    retries read no clock."""
    from collectors import collector_utils

    def no_clock() -> float:
        raise AssertionError("the clock was read")

    monkeypatch.setattr(collector_utils.time, "monotonic", no_clock)
    monkeypatch.setattr(collector_utils.time, "sleep", lambda _s: None)
    calls: List[int] = []

    @collector_utils.retry_with_backoff(max_retries=2, base_delay=1.0)
    def flaky() -> str:
        calls.append(1)
        if len(calls) < 2:
            raise requests.exceptions.ConnectionError("reset")
        return "ok"

    assert flaky() == "ok" and len(calls) == 2


# --------------------------------------------------------------------------- the items not sent


def test_with_a_batch_key_the_items_not_sent_are_those_of_the_batches_not_sent(clock, monkeypatch):
    """Items keyed A, B, A, C, B, C go in the batches [A A], [B B], [C C] (``_batches``), which are not slices of
    the push. A's batch fails and its retries reach the cap (100 s requests, cap 150 s); the push stops before
    B's: the items not sent are B's and C's (positions 1, 3, 4 and 5), not positions 2-5."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", "10")
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "150")
    items = _items(6)
    for item, key in zip(items, "ABACBC", strict=True):
        item["k"] = key
    misp = _Misp(clock, push_seconds=100)
    writer = _writer(misp)
    assert writer.push_items(items, batch_key=lambda item: item["k"]) == (0, 6)
    assert misp.batches == [[items[0]["value"], items[2]["value"]]] * 2
    assert writer.last_push_unsent_items == [1, 3, 4, 5]
    assert writer.last_push_unstored_items == list(range(6))


def test_after_a_stop_no_part_is_created_and_the_later_entries_count_as_failed(clock, monkeypatch, caplog):
    """The event split (limit 10, batches of 5): part 1 takes ten items, new parts 2 and 3 ten each. Part 1's
    first batch fails (a 50 s request, cap 40 s: no retry); the push stops before its second. Parts 2 and 3 are
    not created, and their items and those of part 1's second batch count as failed and are listed."""
    monkeypatch.setattr(mw, "_EVENT_SPLIT_MIN", 1)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", False)
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "10")
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", "5")
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "40")
    base = f"EdgeGuard-urlhaus-{TODAY}"
    misp = FakeMisp([], event_info=base, url="misp.test")
    real = misp.post

    def post(url: str, json: Optional[dict] = None, **kw: Any) -> Response:
        if url.endswith("/events/200"):
            misp.posts.append(("/events/200", json))
            clock.now += 50
            return Response(500, {"errors": "x"})
        return real(url, json=json, **kw)

    misp.post = post  # type: ignore[method-assign]
    writer = _writer(misp)
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        assert writer.push_items(_items(30)) == (0, 30)
    assert misp.events == {"200": base}, "no part created after the stop"
    assert writer.last_push_unsent_items == list(range(5, 30))
    assert writer.last_push_event_failed_items == []
    (stop,) = _stops(caplog)
    assert "5 batch(es) with 25 attribute(s) not sent" in stop


def test_a_group_whose_part_failed_is_counted_once_and_a_later_source_is_not_sent(clock, monkeypatch, caplog):
    """Part 1 (urlhaus) is stored; the creation of part 2 fails (a 50 s connection error, cap 40 s: no retry), so
    parts 2 and 3 fail at the event, each counted once. The streak that creation began has reached the cap when
    the threatfox entry comes: the push stops, and threatfox's items count as failed and are listed as not sent."""
    monkeypatch.setattr(mw, "_EVENT_SPLIT_MIN", 1)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", False)
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE", "10")
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_BATCH_SIZE", "5")
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "40")
    misp = FakeMisp([], event_info=f"EdgeGuard-urlhaus-{TODAY}", url="misp.test")
    real = misp.post

    def post(url: str, json: Optional[dict] = None, **kw: Any) -> Response:
        if url.endswith("/events") and (json or {}).get("Event", {}).get("info", "").endswith("-part2"):
            clock.now += 50
            raise requests.exceptions.ConnectionError("reset")
        return real(url, json=json, **kw)

    misp.post = post  # type: ignore[method-assign]
    writer = _writer(misp)
    items = _items(30) + _items(5, source="threatfox", start=100)
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        assert writer.push_items(items) == (10, 25)
    assert writer.last_push_event_failed_items == list(range(10, 30))
    assert writer.last_push_unsent_items == list(range(30, 35))
    assert writer.last_push_unstored_items == list(range(10, 35))
    (stop,) = _stops(caplog)
    assert stop.startswith("[MISP-PUSH-STOPPED] MISP push threatfox:")
    assert "1 batch(es) with 5 attribute(s) not sent" in stop


def test_a_value_that_cannot_be_stored_counts_as_failed_when_its_batch_is_not_sent(clock, monkeypatch):
    """A URL with a 4-byte character in a batch the stop did not send counts as failed, as ``_push_batch`` counts
    it in a batch it sends; it is not listed (no value of it can be stored)."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "40")
    misp = _Misp(clock, push_seconds=50)
    writer = _writer(misp)
    items = _items(2) + [
        {"indicator_type": "url", "value": "http://example.com/\U0001f600", "tag": "urlhaus", "zone": ["global"]}
    ]
    assert writer.push_items(items) == (0, 3)
    assert writer.last_push_unsent_items == [1]


# --------------------------------------------------------------------------- cooldown, counters, refresh


@pytest.mark.parametrize("probe, steps, probes", [(200, 1, 1), (503, 10, 8)], ids=["answers", "fails"])
def test_the_cooldown_ends_when_misp_answers_its_probe(clock, monkeypatch, probe, steps, probes):
    """No cap: three batches fail, the fourth and fifth are stored. The cooldown before the fourth asks MISP after
    each 30 s step while at least the probe's 40 s of timeouts is left (the first eight of ten), never before the
    first step: an answer ends it, a failed probe lets it run."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "0")
    items = _items(5)
    failing = {i["value"] for i in items[:3]}
    misp = _Misp(clock, push=lambda values: 500 if values[0] in failing else 200, probe=probe)
    writer = _writer(misp)
    assert writer.push_items(items) == (2, 3)
    assert clock.waits().count(30.0) == steps and misp.probes() == probes
    log = [entry for entry in clock.log if entry in ("probe", "batch") or entry == ("sleep", 30.0)]
    first = log.index(("sleep", 30.0))
    assert "probe" not in log[:first], "no probe before the first step"
    assert all(log[n - 1] == ("sleep", 30.0) for n, entry in enumerate(log) if entry == "probe")


def test_a_push_misp_answers_sends_no_probe(clock):
    """Guard: the probe belongs to a cooldown; a push without failures sends nothing more than before."""
    misp = _Misp(clock, push=200)
    _writer(misp).push_items(_items(5))
    assert misp.probes() == 0 and clock.waits() == []


def test_the_back_off_counters_are_reset_at_a_stop_only(clock, monkeypatch):
    """After a stop the next push on the writer starts without a cooldown. Without a stop the counters carry over
    as before: a push that ends with three failed batches makes the next one begin with a cooldown."""
    misp = _Misp(clock)
    writer = _writer(misp)
    writer.push_items(_items(20))
    assert writer.last_push_stopped is True
    assert writer._misp_push_consecutive_failures == 0 and writer._misp_push_consecutive_successes == 0
    misp.push = 200
    clock.log.clear()
    assert writer.push_items(_items(2, start=50)) == (2, 0)
    assert 30.0 not in clock.waits()

    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "0")
    misp.push = 500
    writer.push_items(_items(3, start=60))
    assert writer.last_push_stopped is False and writer._misp_push_consecutive_failures == 3
    misp.push = 200
    clock.log.clear()
    writer.push_items(_items(1, start=70))
    assert clock.waits()[:1] == [30.0], "the cooldown carried over"


def _stale_row(value: str, uuid: str) -> dict:
    """A copy of *value* in an earlier EdgeGuard event, last written 60 days ago (a refresh is due)."""
    return {
        "id": uuid,
        "uuid": uuid,
        "event_id": "41",
        "type": "ip-dst",
        "value": value,
        "timestamp": str(int((datetime.now(timezone.utc) - timedelta(days=60)).timestamp())),
        "first_seen": None,
        "last_seen": None,
        "Event": {"id": "41", "info": "EdgeGuard-urlhaus-2026-07-01"},
        "Tag": [{"name": "source:URLhaus"}],
    }


def test_after_a_stop_the_due_refreshes_are_left_for_a_later_run(clock, monkeypatch, caplog):
    """Three re-reported indicators are due a refresh; the three new ones fail (50 s requests, cap 40 s) and the
    push stops before its second batch. No edit is sent to the MISP that stopped the push: the three refreshes
    are counted as deferred. Before the change they were edited after the batches."""
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "30")
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "40")
    old = _items(3)
    misp = _Misp(clock, push_seconds=50, stored=[_stale_row(i["value"], f"u-{n}") for n, i in enumerate(old)])
    writer = _writer(misp)
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        assert writer.push_items(old + _items(3, start=10)) == (0, 3)
    assert writer.last_push_stopped is True and misp.edits == []
    assert writer.stats["attributes_refresh_deferred"] == 3 and writer.stats["attributes_refreshed"] == 0
    assert any(
        r.getMessage().startswith("[REFRESH] 3 re-reported indicator(s)")
        and r.getMessage().endswith("3 left for a later run (the push stopped: MISP kept failing)")
        for r in caplog.records
    )


def test_a_cooldown_whose_probes_wait_out_their_timeouts_lasts_no_longer_than_its_length(clock, caplog):
    """Every batch request takes 30 s and answers HTTP 500, and the light request of a cooldown waits out its 40 s
    of timeouts. A probe is sent only while the cooldown has those 40 s left and its time counts toward the
    cooldown, so the 300 s cooldown before the fourth batch holds four probes and ends about 870 s into the
    streak; the fourth batch, the last sent, starts before the cap of 900 s and ends at most its 30 s past it. Before the fix nine probes stretched that
    cooldown to 660 s, and the fourth batch was sent about 1,230 s into the streak."""
    misp = _Misp(clock, push_seconds=30, probe=requests.exceptions.ReadTimeout("read timed out"), probe_seconds=40)
    writer = _writer(misp)
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        assert writer.push_items(_items(20)) == (0, 20)
    assert len(misp.batches) == 13 and misp.probes() == 4
    assert max(misp.batch_times) - misp.batch_times[0] < 900
    assert misp.batch_times[12] - (misp.batch_times[11] + 30) == pytest.approx(300.0, abs=2.0), "the cooldown"
    (stop,) = _stops(caplog)
    assert int(re.search(r"kept failing for (\d+)s", stop).group(1)) < 900 + 30, "at most the request in flight"


def test_a_push_with_a_deadline_ends_one_batch_after_it_when_the_probes_wait_out_their_timeouts(clock, monkeypatch):
    """No cap, a deadline 600 s after the push starts (the OTX list push's time budget), batches answered HTTP 500
    at once (70 s each), and probes that wait out their 40 s. The cooldown before the fourth batch lasts its 300 s,
    so the push ends at most one batch after the deadline, as the deadline rules. Before the fix the probes made
    that cooldown 660 s long and the push ended about 940 s after it started."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "0")
    misp = _Misp(clock, probe=requests.exceptions.ReadTimeout("read timed out"), probe_seconds=40)
    writer = _writer(misp)
    started = clock.now
    writer.push_items(_items(20), deadline=started + 600)
    assert clock.now - started < 600 + 75
    assert len(misp.batches) == 20, "five batches of four attempts"


@pytest.mark.parametrize("probe", [503, 403])
def test_a_failed_probe_is_not_logged_as_a_failed_event_lookup(clock, monkeypatch, caplog, probe):
    """The probe reuses one page of the event lookup; an answer other than HTTP 200 is logged at DEBUG, not as a
    lookup the caller retries (WARNING) or after which no event is created (ERROR)."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "0")
    items = _items(4)
    failing = {i["value"] for i in items[:3]}
    misp = _Misp(clock, push=lambda values: 500 if values[0] in failing else 200, probe=probe)
    writer = _writer(misp)
    with caplog.at_level(logging.DEBUG, logger=mw.logger.name):
        assert writer.push_items(items) == (1, 3)
    assert misp.probes() == 8
    lines = [r for r in caplog.records if r.getMessage().startswith("MISP restSearch for event lookup")]
    assert len(lines) == 8 and {r.levelno for r in lines} == {logging.DEBUG}


def test_a_probe_that_meets_a_connection_error_lets_the_cooldown_run(clock, monkeypatch):
    """MISP refusing connections: the probe's error is a no, and the cooldown runs its ten steps."""
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "0")
    items = _items(4)
    failing = {i["value"] for i in items[:3]}
    misp = _Misp(
        clock,
        push=lambda values: 500 if values[0] in failing else 200,
        probe=requests.exceptions.ConnectionError("connection refused"),
    )
    writer = _writer(misp)
    assert writer.push_items(items) == (1, 3)
    assert clock.waits().count(30.0) == 10 and misp.probes() == 8


# --------------------------------------------------------------------------- settings


@pytest.mark.parametrize(
    "raw, regular, baseline, warns",
    [
        (None, 900.0, 3600.0, False),
        ("", 900.0, 3600.0, False),
        ("0", 0.0, 0.0, False),
        ("1200", 1200.0, 1200.0, False),
        ("86400", 86400.0, 86400.0, False),
        ("86401", 900.0, 3600.0, True),
        ("-1", 900.0, 3600.0, True),
        ("ten", 900.0, 3600.0, True),
        ("nan", 900.0, 3600.0, True),
        ("inf", 900.0, 3600.0, True),
    ],
)
def test_the_settings(monkeypatch, caplog, raw, regular, baseline, warns):
    """'' is unset (compose forwards ``${NAME:-}``), 0 is no cap, and a value that is not a number in [0, 86400]
    takes the default with a WARNING."""
    for name in CAP_SETTINGS:
        if raw is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, raw)
    with caplog.at_level(logging.WARNING, logger=config.logger.name):
        assert config.misp_push_max_failing_seconds() == regular
        assert config.misp_push_max_failing_seconds(baseline=True) == baseline
    assert bool([r for r in caplog.records if any(n in r.getMessage() for n in CAP_SETTINGS)]) is warns


def test_the_settings_are_forwarded_and_documented():
    """Both settings reach the Airflow service as ``${NAME:-}`` and ``.env.example`` names them with their
    defaults."""
    root = os.path.join(os.path.dirname(__file__), "..")
    with open(os.path.join(root, "docker-compose.yml"), encoding="utf-8") as fh:
        compose = fh.read()
    with open(os.path.join(root, ".env.example"), encoding="utf-8") as fh:
        env_example = fh.read()
    for name, default in zip(CAP_SETTINGS, ("900", "3600"), strict=True):
        assert f"{name}: ${{{name}:-}}" in compose
        assert re.search(rf"^#? ?{name}={default}$", env_example, re.M), name


def test_the_baseline_writer_reads_its_own_setting(clock, monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC", "100")
    monkeypatch.setenv("EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE", "200")
    scheduled, baseline = _writer(_Misp(clock)), _writer(_Misp(clock), baseline=True)
    scheduled._arm_push_cap()
    baseline._arm_push_cap()
    assert scheduled._misp_push_failing_cap == 100.0 and baseline._misp_push_failing_cap == 200.0
    assert getattr(mw.MISPWriter.__new__(mw.MISPWriter), "last_push_stopped", False) is False


@pytest.mark.parametrize(
    "ends_in, cap, batches",
    [(1_000.0, "(399|400)", 12), (-10.0, "60", 7), (100_000.0, None, 80)],
    ids=["task-ends-soon", "task-end-passed", "task-ends-late"],
)
def test_the_baseline_writer_stops_a_streak_before_its_task_ends(clock, caplog, ends_in, cap, batches):
    """The baseline's writer, its task ending *ends_in* seconds after the push starts: a streak that starts at
    once gets the time to 600 s before that end (at least 60 s), at most 3600 s. Ending in 1,000 s: 400 s, and
    the push stops before the fourth batch, where the cooldown would pass it. Already past: 60 s, which cuts the
    retries of the first three batches short (three, two and two attempts). Far off: the whole 3600 s, which
    twenty failing batches do not reach."""
    misp = _Misp(clock)
    writer = _writer(misp, baseline=True, task_ends_at=mw.time.time() + ends_in)
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        assert writer.push_items(_items(20)) == (0, 20)
    assert len(misp.batches) == batches
    stops = _stops(caplog)
    if cap is None:
        assert stops == [] and writer.last_push_stopped is False
    else:
        (stop,) = stops
        assert re.search(
            rf"\(EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE=3600; {cap}s to 600s before the task's end\)", stop
        )


# --------------------------------------------------------------------------- the DAG passes the task's end


def _import_dag_module():
    for key in list(sys.modules):
        if key in ("edgeguard_pipeline", "airflow", "opentelemetry") or key.startswith(("airflow.", "opentelemetry.")):
            del sys.modules[key]
    import importlib

    with dag_module_import():
        return importlib.import_module("edgeguard_pipeline")


def test_the_task_end_is_its_start_plus_its_execution_timeout():
    ep = _import_dag_module()
    start = datetime(2026, 11, 3, 8, 0, tzinfo=timezone.utc)
    task = SimpleNamespace(execution_timeout=timedelta(hours=5))
    assert ep._task_ends_at({"task": task, "ti": SimpleNamespace(start_date=start)}) == start.timestamp() + 18_000
    naive = {"task": task, "ti": SimpleNamespace(start_date=start.replace(tzinfo=None))}
    assert abs(ep._task_ends_at(naive) - (mw.time.time() + 18_000)) < 60, "now when the start has no zone"
    assert ep._task_ends_at({"task": SimpleNamespace(execution_timeout=None)}) is None
    assert ep._task_ends_at({"task": SimpleNamespace(execution_timeout=timedelta(0))}) is None, "no limit"
    assert ep._task_ends_at(None) is None and ep._task_ends_at({}) is None


def test_the_baseline_collector_builds_the_baseline_writer_with_its_task_end(monkeypatch):
    ep = _import_dag_module()
    built: List[Dict[str, Any]] = []

    class _Writer:
        def __init__(self, **kw: Any):
            built.append(kw)

    start = datetime(2026, 11, 3, 8, 0, tzinfo=timezone.utc)
    context = {
        "task": SimpleNamespace(execution_timeout=timedelta(hours=5)),
        "ti": SimpleNamespace(start_date=start),
        "dag_run": SimpleNamespace(conf={}, run_id="manual__x"),
    }
    monkeypatch.setattr(ep, "_require_baseline_start", lambda *_a, **_k: None)
    monkeypatch.setattr(ep, "_require_baseline_lock", lambda *_a, **_k: None)
    monkeypatch.setattr(ep, "get_baseline_config", lambda context=None: (None, 730))
    monkeypatch.setattr(ep, "_baseline_run_holder", lambda _ctx: None)
    monkeypatch.setattr("collectors.misp_writer.MISPWriter", _Writer)
    monkeypatch.setattr("parent_dag_liveness.make_liveness_callback", lambda *_a, **_k: None)
    with patch.object(ep, "run_collector_with_metrics", return_value={"success": True}) as run:
        ep.run_baseline_collector("otx", object, context=context)
    assert built == [{"liveness_callback": None, "baseline": True, "task_ends_at": start.timestamp() + 18_000}]
    assert run.call_args.kwargs["baseline"] is True


# --------------------------------------------------------------------------- the alert


def _norm(text: str) -> str:
    return " ".join(text.split())


def test_the_alert_fires_on_one_stop_and_points_to_the_runbook():
    """``EdgeGuardMispPushStopped`` fires on a single increment: ``increase()`` over an hour, and for a series that
    has just been created (``increase()`` is 0 for it) the clause the OTX given-up alert uses. It is critical, like
    ``EdgeGuardMispBatchPermanentFailure`` next to it, and labelled by source only."""
    import yaml

    root = os.path.join(os.path.dirname(__file__), "..")
    with open(os.path.join(root, "prometheus", "alerts.yml"), encoding="utf-8") as fh:
        rules = yaml.safe_load(fh)
    (group,) = [g for g in rules["groups"] if g["name"] == "edgeguard_pipeline_observability"]
    names = [r.get("alert") for r in group["rules"]]
    assert names.index("EdgeGuardMispPushStopped") == names.index("EdgeGuardMispBatchPermanentFailure") + 1
    rule = group["rules"][names.index("EdgeGuardMispPushStopped")]
    metric = "edgeguard_misp_push_stopped_total"
    assert _norm(rule["expr"]) == (
        f"sum by (source) (increase({metric}[1h])) > 0 or "
        f"( sum by (source) ({metric}) > 0 unless sum by (source) ({metric} offset 1h) )"
    )
    assert rule["for"] == "0m"
    assert rule["labels"] == {"severity": "critical", "component": "misp_writer"}
    assert 'docs/RUNBOOK.md § "MISP push stopped (MISP kept failing)"' in rule["annotations"]["description"]
    with open(os.path.join(root, "docs", "RUNBOOK.md"), encoding="utf-8") as fh:
        runbook = fh.read()
    assert "## MISP push stopped (MISP kept failing)" in runbook
    assert "| `EdgeGuardMispPushStopped` | critical |" in runbook
    with open(os.path.join(root, "docs", "PROMETHEUS_SETUP.md"), encoding="utf-8") as fh:
        assert "| `EdgeGuardMispPushStopped` |" in fh.read()
    if mw._METRICS_AVAILABLE:
        assert mw._MISP_PUSH_STOPPED._labelnames == ("source",)
