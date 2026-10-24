"""MISP event listing of the MISP → Neo4j sync (2026-10).

* MISP 2.5.45 ignores ``limit``, ``page`` and ``timestamp`` in the query string of
  ``GET /events/index`` and answers the whole listing on every page (measured read-only on the
  hosted MISP 2026-10-16: ``?limit=5&page=2`` and ``?limit=5&page=9`` both answered all 11 events;
  named ``limit:`` / ``page:`` and a POST body are honoured, while only a named
  ``searchtimestamp:`` or a POST-body ``timestamp`` narrows by time, a named ``timestamp:`` being
  ignored too). From 500 events every page repeated the listing up to the 100-page cap, and each
  event was processed once per page. The listing now de-duplicates rows by event id, stops when a
  page brings no new id, and stops when a page holds more rows than the requested limit.
* A failure on an index page after the first no longer ends the listing as if it were complete:
  transient ``requests`` errors re-run the listing (``@retry_with_backoff``), anything else raises
  ``_MispFallbackHardError``. A first-page answer that is not a listing (HTTP 200 with
  ``{"errors": ...}``) makes the path unusable instead of reading as "no events".
* A listing cut at the page cap fails the run, also when no EdgeGuard event was among the rows
  listed, so the DAG keeps its cursor.
* A non-JSON restSearch fallback page, a non-transient error in the restSearch fallback (recorded
  as ``rest_search`` / ``hard_error`` for the critical fallback alert), and any other error while
  listing raise instead of returning the rows read so far.
* The 3-strike connection bail-out counts the events it never reached, and failed events are not
  reported again as merge/load errors.

The DAG cases import ``dags/edgeguard_pipeline.py`` as Airflow does and run ``run_neo4j_sync``
with the real ``MISPToNeo4jSync.run()`` against a stand-in MISP session.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

import run_misp_to_neo4j as rm

REPO_ROOT = Path(__file__).resolve().parent.parent
DAG_PATH = REPO_ROOT / "dags" / "edgeguard_pipeline.py"


class _Resp:
    def __init__(self, status: int, payload=None, raise_json: bool = False):
        self.status_code = status
        self._payload = payload if payload is not None else []
        self._raise_json = raise_json
        self.text = ""

    def json(self):
        if self._raise_json:
            raise ValueError("Expecting value: line 1 column 1 (char 0)")
        return self._payload


def _row(event_id, info: str = "EdgeGuard-otx-2026-10-16", timestamp: str = "1700000000") -> dict:
    return {"Event": {"id": str(event_id), "info": info, "timestamp": timestamp}}


def _recent_ts() -> str:
    return str(int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()))


class _IgnoresQueryPaging:
    """``GET /events/index`` of MISP 2.5.45: every query parameter ignored, the whole listing on every page."""

    def __init__(self, n_events: int, timestamp: str):
        self.rows = [_row(i, f"EdgeGuard-src{i % 11}-day{i // 11}", timestamp) for i in range(1, n_events + 1)]
        self.gets = 0

    def get(self, url, params=None, **_kw):
        self.gets += 1
        return _Resp(200, list(self.rows))


class _PagedIndex:
    """An index that honours paging: ``pages`` full pages of ``page_size`` distinct rows, then an empty page.

    ``fail_page`` answers ``fail`` instead: ``500``, ``html`` (HTTP 200, not JSON), ``errors``
    (HTTP 200 with an error object) or a ``requests`` exception instance to raise.
    """

    def __init__(self, page_size: int, pages: int, fail_page=None, fail=None, info="EdgeGuard-otx", ts="1700000000"):
        self.page_size = page_size
        self.pages = pages
        self.fail_page = fail_page
        self.fail = fail
        self.info = info
        self.ts = ts
        self.calls: list = []

    def get(self, url, params=None, **_kw):
        page = params["page"]
        self.calls.append((url, page))
        if self.fail_page is not None and page == self.fail_page:
            if isinstance(self.fail, BaseException):
                raise self.fail
            if self.fail == "500":
                return _Resp(500, {"message": "Internal error"})
            if self.fail == "html":
                return _Resp(200, raise_json=True)
            if self.fail == "errors":
                return _Resp(200, {"errors": "Permission denied"})
        n = self.page_size if page <= self.pages else 0
        return _Resp(200, [_row(page * 1000 + i, self.info, self.ts) for i in range(n)])


def _no_pymisp(monkeypatch):
    import pymisp

    def _broken(*_a, **_k):
        raise RuntimeError("PyMISP unavailable")

    monkeypatch.setattr(pymisp, "PyMISP", _broken)


def _sync(monkeypatch, session) -> tuple:
    """Real ``run()`` and listing; ``session`` answers MISP; every event is processed as an empty event."""
    sync = rm.MISPToNeo4jSync(neo4j_client=MagicMock())
    sync.session = session
    sync.misp_url = "https://misp.test"
    monkeypatch.setattr(sync, "check_services_available", lambda: (True, "ok"))
    monkeypatch.setattr(sync, "connect", lambda: True)
    processed: list = []

    def _process(event_id, info, attribute_count=0):
        processed.append(event_id)
        sync.stats["events_processed"] += 1
        return 0, 0, 0

    monkeypatch.setattr(sync, "_process_single_event", _process)
    return sync, processed


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC", "0")
    monkeypatch.setattr(rm.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setattr(rm, "record_collection_success", lambda *a, **k: None)
    monkeypatch.setattr(rm, "record_collection_failure", lambda *a, **k: None)
    rm.INDEX_FETCH_STATE["truncated"] = False
    yield
    rm.INDEX_FETCH_STATE["truncated"] = False


# ---------------------------------------------------------------------------
# A server that ignores query-string paging (real page size 500 and cap 100)
# ---------------------------------------------------------------------------


class TestServerIgnoringQueryPaging:
    def test_defaults_are_the_ones_measured_against(self):
        assert rm.MISP_EVENTS_INDEX_PAGE_SIZE == 500 and rm.MISP_EVENTS_INDEX_MAX_PAGES == 100

    def test_more_rows_than_the_limit_is_the_whole_listing(self, monkeypatch):
        """600 events: page 1 answers all 600 (> limit 500), so no second request; each event once."""
        now = datetime.now(timezone.utc)
        session = _IgnoresQueryPaging(600, _recent_ts())
        sync, processed = _sync(monkeypatch, session)
        assert sync.run(incremental=True, since=now - timedelta(days=3)) is True
        stats = sync.get_stats()
        assert session.gets == 1, f"index requested {session.gets} page(s)"
        assert len(processed) == 600 and len(set(processed)) == 600, (
            f"_process_single_event called {len(processed)} times for {len(set(processed))} events; "
            f"events_index_total={stats.get('events_index_total')}"
        )
        assert not stats.get("events_index_truncated")

    def test_exactly_the_limit_stops_at_the_first_repeated_page(self, monkeypatch):
        """500 events: page 1 is full, page 2 repeats it and brings no new id, so the listing ends there."""
        session = _IgnoresQueryPaging(500, _recent_ts())
        sync, processed = _sync(monkeypatch, session)
        assert sync.run(incremental=False) is True
        assert session.gets == 2
        assert sorted(processed, key=int) == [str(i) for i in range(1, 501)]
        assert not sync.get_stats().get("events_index_truncated")

    def test_below_the_limit_one_request_lists_all(self, monkeypatch):
        """11 events (the hosted MISP on 2026-10-16): one request, nothing lost, nothing repeated."""
        now = datetime.now(timezone.utc)
        session = _IgnoresQueryPaging(11, _recent_ts())
        sync, processed = _sync(monkeypatch, session)
        assert sync.run(incremental=True, since=now - timedelta(days=3)) is True
        assert sorted(processed, key=int) == [str(i) for i in range(1, 12)] and session.gets == 1


class TestPagedIndex:
    @pytest.fixture(autouse=True)
    def _small_pages(self, monkeypatch):
        monkeypatch.setattr(rm, "MISP_EVENTS_INDEX_PAGE_SIZE", 3)
        monkeypatch.setattr(rm, "MISP_EVENTS_INDEX_MAX_PAGES", 10)

    def test_a_row_repeated_on_the_next_page_is_listed_once_and_paging_continues(self):
        """A server that honours paging can shift a row onto the next page; it is listed once."""

        class _Shifted:
            calls = 0

            def get(self, url, params=None, **_kw):
                _Shifted.calls += 1
                page = params["page"]
                pages = {1: [1, 2, 3], 2: [3, 4, 5], 3: [6]}
                return _Resp(200, [_row(i) for i in pages.get(page, [])])

        rows = rm._fetch_edgeguard_events_via_requests_index(_Shifted(), "https://misp.test", None)
        assert [r["id"] for r in rows] == ["1", "2", "3", "4", "5", "6"]
        assert _Shifted.calls == 3

    @pytest.mark.parametrize("fail", ["500", "html", "errors"])
    def test_a_later_page_failure_raises_the_hard_error(self, fail):
        session = _PagedIndex(page_size=3, pages=4, fail_page=2, fail=fail)
        with pytest.raises(rm._MispFallbackHardError, match="on page 2 after 1 good page"):
            rm._fetch_edgeguard_events_via_requests_index(session, "https://misp.test", None)
        assert session.calls == [("https://misp.test/events/index", 1), ("https://misp.test/events/index", 2)], (
            "an incomplete listing must not fall through to the next path either"
        )

    @pytest.mark.parametrize(
        "exc",
        [
            requests.exceptions.ReadTimeout("read timed out"),
            requests.exceptions.ConnectionError("Connection reset by peer"),
            requests.exceptions.ChunkedEncodingError("connection broken"),
        ],
        ids=["timeout", "connection", "chunked"],
    )
    def test_a_transient_later_page_failure_is_re_raised_for_the_retry(self, exc):
        session = _PagedIndex(page_size=3, pages=4, fail_page=2, fail=exc)
        with pytest.raises(type(exc)):
            rm._fetch_edgeguard_events_via_requests_index(session, "https://misp.test", None)

    def test_another_request_error_on_a_later_page_raises_the_hard_error(self):
        session = _PagedIndex(page_size=3, pages=4, fail_page=2, fail=requests.exceptions.TooManyRedirects("loop"))
        with pytest.raises(rm._MispFallbackHardError, match="page 2"):
            rm._fetch_edgeguard_events_via_requests_index(session, "https://misp.test", None)

    def test_a_first_page_error_object_makes_the_path_unusable(self):
        """``/events/index`` answers ``{"errors": ...}`` with HTTP 200: the listing comes from ``/events``."""

        class _S:
            def get(self, url, params=None, **_kw):
                if url.endswith("/events/index"):
                    return _Resp(200, {"errors": "Permission denied"})
                return _Resp(200, [_row(7)] if params["page"] == 1 else [])

        rows = rm._fetch_edgeguard_events_via_requests_index(_S(), "https://misp.test", None)
        assert [r["id"] for r in rows] == ["7"]

    def test_first_page_failures_on_both_paths_leave_the_fallback_to_the_caller(self):
        session = _PagedIndex(page_size=3, pages=4, fail_page=1, fail="errors")
        assert rm._fetch_edgeguard_events_via_requests_index(session, "https://misp.test", None) is None

    def test_is_misp_index_listing(self):
        assert rm._is_misp_index_listing([]) is True
        assert rm._is_misp_index_listing({"response": []}) is True
        assert rm._is_misp_index_listing({"events": [_row(1)]}) is True
        assert rm._is_misp_index_listing(_row(1)) is True
        assert rm._is_misp_index_listing({"errors": "Permission denied"}) is False
        assert rm._is_misp_index_listing(None) is False
        assert rm._is_misp_index_listing("<html>") is False


class TestRunVerdictOnAnIncompleteListing:
    @pytest.fixture(autouse=True)
    def _small_pages(self, monkeypatch):
        monkeypatch.setattr(rm, "MISP_EVENTS_INDEX_PAGE_SIZE", 3)
        monkeypatch.setattr(rm, "MISP_EVENTS_INDEX_MAX_PAGES", 10)

    def test_full_sync_fails_after_a_later_page_timeout_that_outlasts_the_retries(self, monkeypatch):
        session = _PagedIndex(page_size=3, pages=4, fail_page=2, fail=requests.exceptions.ReadTimeout("timed out"))
        sync, processed = _sync(monkeypatch, session)
        assert sync.run(incremental=False) is False
        assert processed == [], "nothing is processed from an incomplete listing"
        assert [p for _u, p in session.calls].count(2) == rm.MAX_RETRIES + 1, "the listing is re-run by the retry"
        assert "ReadTimeout" in sync.get_stats()["last_failure_reason"]

    def test_incremental_sync_fails_after_a_later_page_500(self, monkeypatch):
        session = _PagedIndex(page_size=3, pages=4, fail_page=2, fail="500", ts=_recent_ts())
        sync, processed = _sync(monkeypatch, session)
        ok = sync.run(incremental=True, since=datetime.now(timezone.utc) - timedelta(days=4))
        assert ok is False and processed == []
        assert "HTTP 500 on page 2" in sync.get_stats()["last_failure_reason"]

    def test_a_first_page_error_object_is_not_an_empty_success(self, monkeypatch):
        """Both index paths answer ``{"errors": ...}``; the fallback fails too: the run fails."""
        _no_pymisp(monkeypatch)

        class _S:
            def get(self, url, params=None, **_kw):
                return _Resp(200, {"errors": "Permission denied"})

            def post(self, url, json=None, **_kw):
                return _Resp(403, {"errors": "Permission denied"})

        sync, _processed = _sync(monkeypatch, _S())
        assert sync.run(incremental=False) is False
        assert not sync.get_stats().get("zero_events")

    def test_a_first_page_of_rows_without_an_id_is_not_an_empty_success(self, monkeypatch):
        """Rows without an id on page 1 are kept: ``run()`` counts each one as a failed event.

        The stop for a page that brings no new id applies only from page 2; on page 1 it would drop
        such rows and the run would report an empty window as a success.
        """

        class _S:
            def get(self, url, params=None, **_kw):
                return _Resp(200, [{"Event": {"info": "EdgeGuard-otx-2026-10-16", "timestamp": "1700000000"}}])

        sync, processed = _sync(monkeypatch, _S())
        assert sync.run(incremental=False) is False
        stats = sync.get_stats()
        assert processed == [] and stats["events_failed"] == 1
        assert not stats.get("zero_events")

    def test_a_listing_cut_at_the_page_cap_fails_the_run(self, monkeypatch):
        monkeypatch.setattr(rm, "MISP_EVENTS_INDEX_MAX_PAGES", 2)
        sync, processed = _sync(monkeypatch, _PagedIndex(page_size=3, pages=5))
        assert sync.run(incremental=False) is False
        stats = sync.get_stats()
        assert stats.get("events_index_truncated") is True and len(processed) == 6
        assert "stopped at the page cap" in stats["last_failure_reason"]
        assert "EDGEGUARD_MISP_MAX_PAGES=2" in stats["last_failure_reason"]

    def test_a_cut_listing_without_an_edgeguard_event_is_not_an_empty_success(self, monkeypatch):
        monkeypatch.setattr(rm, "MISP_EVENTS_INDEX_MAX_PAGES", 2)
        sync, processed = _sync(monkeypatch, _PagedIndex(page_size=3, pages=5, info="CIRCL OSINT feed"))
        assert sync.run(incremental=False) is False
        stats = sync.get_stats()
        assert processed == [] and not stats.get("zero_events")
        assert "with no EdgeGuard event listed" in stats["last_failure_reason"]


# ---------------------------------------------------------------------------
# restSearch fallback and the outer handler of fetch_edgeguard_events
# ---------------------------------------------------------------------------


class _FallbackSession:
    """Both index paths answer 404; ``POST /events/restSearch`` answers ``answers`` by page."""

    def __init__(self, answers):
        self.answers = answers
        self.posts: list = []

    def get(self, url, params=None, **_kw):
        return _Resp(404, {})

    def post(self, url, json=None, **_kw):
        page = json["page"]
        self.posts.append(page)
        answer = self.answers.get(page, _Resp(200, {"response": []}))
        if isinstance(answer, BaseException):
            raise answer
        return answer


class TestFallbackListing:
    @pytest.fixture()
    def metrics(self, monkeypatch):
        recorded: list = []
        monkeypatch.setattr(
            rm, "record_misp_fetch_fallback", lambda branch, outcome: recorded.append((branch, outcome))
        )
        _no_pymisp(monkeypatch)
        return recorded

    @staticmethod
    def _fetch(session):
        sync = rm.MISPToNeo4jSync(neo4j_client=MagicMock())
        sync.session = session
        sync.misp_url = "https://misp.test"
        return sync.fetch_edgeguard_events(since=None)

    def test_a_non_json_page_after_a_full_page_raises(self, metrics):
        session = _FallbackSession(
            {1: _Resp(200, {"response": [_row(i) for i in range(500)]}), 2: _Resp(200, raise_json=True)}
        )
        with pytest.raises(rm._MispFallbackHardError, match="non-JSON on page 2 after 1 good pages"):
            self._fetch(session)
        assert session.posts == [1, 2]
        assert ("rest_search", "hard_error") in metrics

    def test_a_non_json_first_page_raises_instead_of_listing_nothing(self, metrics):
        with pytest.raises(rm._MispFallbackHardError, match="non-JSON on page 1"):
            self._fetch(_FallbackSession({1: _Resp(200, raise_json=True)}))

    def test_a_non_transient_request_error_after_a_full_page_is_a_fallback_hard_error(self, metrics):
        """It used to return the first page as the listing; it must also record ``hard_error``.

        Without the record only the warning alert (``engaged``) fired for a fallback that failed
        mid-listing, unlike an HTTP 5xx on the same page.
        """
        session = _FallbackSession(
            {
                1: _Resp(200, {"response": [_row(i) for i in range(500)]}),
                2: requests.exceptions.TooManyRedirects("Exceeded 30 redirects."),
            }
        )
        with pytest.raises(rm._MispFallbackHardError, match="restSearch failed on page 2 .*TooManyRedirects"):
            self._fetch(session)
        assert session.posts == [1, 2]
        assert metrics == [("pymisp", "engaged"), ("rest_search", "engaged"), ("rest_search", "hard_error")]

    def test_a_non_transient_request_error_on_the_first_page_raises_instead_of_listing_nothing(self, metrics):
        """A non-transient request error is not retried and used to end in an empty listing."""
        session = _FallbackSession({1: requests.exceptions.InvalidURL("bad MISP_URL")})
        with pytest.raises(rm._MispFallbackHardError, match="restSearch failed on page 1 .*InvalidURL"):
            self._fetch(session)
        assert ("rest_search", "hard_error") in metrics

    def test_a_transient_fallback_error_is_left_to_the_retry(self, metrics):
        """A timeout in the fallback re-runs the listing and is not a fallback hard error."""
        session = _FallbackSession({1: requests.exceptions.ReadTimeout("read timed out")})
        with pytest.raises(requests.exceptions.ReadTimeout):
            self._fetch(session)
        assert session.posts == [1] * (rm.MAX_RETRIES + 1), "the listing is re-run by the retry"
        assert ("rest_search", "hard_error") not in metrics

    def test_an_unexpected_error_outside_the_fallback_raises_instead_of_listing_nothing(self, metrics):
        """The outer handler used to log the error and return an empty listing."""

        class _Broken:
            def get(self, url, params=None, **_kw):
                raise RuntimeError("session closed")

        with pytest.raises(rm._MispFallbackHardError, match="MISP event listing failed: RuntimeError"):
            self._fetch(_Broken())
        assert metrics == [], "no fallback branch was reached, so no fallback alert fires"


# ---------------------------------------------------------------------------
# Event accounting of run()
# ---------------------------------------------------------------------------


def _sync_with_events(monkeypatch, events, process):
    sync = rm.MISPToNeo4jSync(neo4j_client=MagicMock())
    monkeypatch.setattr(sync, "check_services_available", lambda: (True, "ok"))
    monkeypatch.setattr(sync, "connect", lambda: True)
    monkeypatch.setattr(sync, "fetch_edgeguard_events", lambda since=None, sector=None: list(events))
    monkeypatch.setattr(sync, "_process_single_event", process)
    return sync


class TestEventAccounting:
    def test_the_connection_bail_out_counts_every_event_of_the_window(self, monkeypatch):
        events = [{"id": str(i), "info": f"EdgeGuard-x-{i}"} for i in range(1, 7)]
        attempted: list = []

        def _refused(event_id, info, attribute_count=0):
            attempted.append(event_id)
            raise ConnectionError("Connection refused")

        sync = _sync_with_events(monkeypatch, events, _refused)
        assert sync.run(incremental=False) is False
        s = sync.stats
        assert attempted == ["1", "2", "3"], "the bail-out stops after three connection failures"
        assert s["events_processed"] + s["events_failed"] == s["events_index_total"] == 6, (
            f"processed={s['events_processed']} failed={s['events_failed']} of {s['events_index_total']}"
        )
        assert "6 event(s) failed or were skipped after retries" in sync._last_sync_failure_reason

    def test_a_failed_event_is_not_reported_as_a_merge_error(self, monkeypatch):
        def _unavailable(event_id, info, attribute_count=0):
            raise rm.MispTransientServerError("MISP 503 fetching event 1")

        sync = _sync_with_events(monkeypatch, [{"id": "1", "info": "EdgeGuard-nvd-2026-10-01"}], _unavailable)
        assert sync.run(incremental=False) is False
        reason = sync._last_sync_failure_reason
        assert "1 event(s) failed or were skipped after retries" in reason
        assert "merge/load" not in reason, f"no item was merged, yet the reason says: {reason!r}"

    def test_merge_errors_are_counted_apart_from_failed_events(self, monkeypatch):
        def _process(event_id, info, attribute_count=0):
            if event_id == "1":
                sync.stats["events_processed"] += 1
                return 2, 0, 1  # one item merge returned False
            raise rm.MispTransientServerError("MISP 503 fetching event 2")

        sync = _sync_with_events(
            monkeypatch, [{"id": "1", "info": "EdgeGuard-a"}, {"id": "2", "info": "EdgeGuard-b"}], _process
        )
        assert sync.run(incremental=False) is False
        reason = sync._last_sync_failure_reason
        assert "1 event(s) failed or were skipped after retries" in reason
        assert "sync_to_neo4j reported 1 merge/load error(s)" in reason


# ---------------------------------------------------------------------------
# The DAG keeps its cursor after an incomplete listing
# ---------------------------------------------------------------------------


def _load_dag_module():
    spec = importlib.util.spec_from_file_location("_dag_module_misp_event_listing_test", DAG_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"DAG module not importable in this environment: {e}")
    return module


@pytest.fixture(scope="module")
def dag_module():
    return _load_dag_module()


class _Variables:
    store: dict = {}

    @classmethod
    def get(cls, key, default=None):
        return cls.store.get(key, default)

    @classmethod
    def set(cls, key, value):
        cls.store[key] = value


@pytest.fixture()
def dag_env(tmp_path, monkeypatch, dag_module):
    """``run_neo4j_sync`` with the real sync; ``set_session`` chooses the MISP session it reads."""
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    monkeypatch.setenv("EDGEGUARD_STATE_DIR", str(state_dir))
    monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_PATH", str(tmp_path / "no_such.lock"))
    _Variables.store = {}
    monkeypatch.setattr(dag_module, "Variable", _Variables)
    for name in ("ensure_metrics_server", "record_neo4j_sync_duration", "record_dag_run", "record_error"):
        monkeypatch.setattr(dag_module, name, lambda *_a, **_k: None)
    monkeypatch.setattr(dag_module, "_record_successful_sync_metrics", lambda *_a, **_k: None)
    monkeypatch.setattr(dag_module, "METRICS_SERVER_AVAILABLE", False)
    monkeypatch.setattr(rm, "MISP_EVENTS_INDEX_PAGE_SIZE", 3)
    monkeypatch.setattr(rm, "MISP_EVENTS_INDEX_MAX_PAGES", 10)

    current: dict = {}
    processed: list = []

    class _Sync(rm.MISPToNeo4jSync):
        def __init__(self):
            super().__init__(neo4j_client=MagicMock())
            self.session = current["session"]
            self.misp_url = "https://misp.test"

        def check_services_available(self):
            return True, "ok"

        def connect(self):
            return True

        def _process_single_event(self, event_id, event_info, attribute_count=0):
            processed.append(event_id)
            self.stats["events_processed"] += 1
            return 1, 0, 0

    fake = ModuleType("run_misp_to_neo4j")
    fake.MISPToNeo4jSync = _Sync
    monkeypatch.setitem(sys.modules, "run_misp_to_neo4j", fake)
    return SimpleNamespace(
        state_file=state_dir / "edgeguard_last_neo4j_sync.json",
        processed=processed,
        set_session=lambda s: current.__setitem__("session", s),
    )


class TestDagCursor:
    def test_a_later_page_timeout_does_not_advance_last_sync(self, dag_module, dag_env):
        previous = datetime.now(timezone.utc) - timedelta(days=3)
        dag_env.state_file.write_text(json.dumps({"last_sync": previous.isoformat()}))
        dag_env.set_session(
            _PagedIndex(
                page_size=3, pages=4, fail_page=2, fail=requests.exceptions.ReadTimeout("timed out"), ts=_recent_ts()
            )
        )
        with pytest.raises(dag_module.AirflowException, match="Neo4j sync failed"):
            dag_module.run_neo4j_sync(ti=SimpleNamespace(try_number=1))
        stamped = datetime.fromisoformat(json.loads(dag_env.state_file.read_text())["last_sync"])
        assert stamped == previous, f"{len(dag_env.processed)} of 12 events synced, yet last_sync moved to {stamped}"

    def test_a_later_page_500_on_the_first_full_sync_writes_no_state(self, dag_module, dag_env):
        dag_env.set_session(_PagedIndex(page_size=3, pages=5, fail_page=2, fail="500"))
        with pytest.raises(dag_module.AirflowException, match="HTTP 500 on page 2"):
            dag_module.run_neo4j_sync(ti=SimpleNamespace(try_number=1))
        assert not dag_env.state_file.exists()

    def test_a_listing_cut_at_the_page_cap_writes_no_state(self, dag_module, dag_env, monkeypatch):
        monkeypatch.setattr(rm, "MISP_EVENTS_INDEX_MAX_PAGES", 2)
        dag_env.set_session(_PagedIndex(page_size=3, pages=5))
        with pytest.raises(dag_module.AirflowException, match="stopped at the page cap"):
            dag_module.run_neo4j_sync(ti=SimpleNamespace(try_number=1))
        assert len(dag_env.processed) == 6
        assert not dag_env.state_file.exists(), "the next run must be a full sync again, not an incremental one"
