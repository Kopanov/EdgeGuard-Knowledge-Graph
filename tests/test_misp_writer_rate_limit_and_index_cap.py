"""MISP writer resilience (2026-10 follow-up of the production-readiness check):

* HTTP 429 on a batch push or an event lookup is transient — the Retry-After header is honoured
  and the shared retry decorator retries — instead of a permanent failure;
* an event lookup that fails for a non-transient reason raises instead of returning "no event",
  so the writer never creates a duplicate same-day event after a failed lookup;
* the MISP event index listing reports when it stops at the page cap, in the log and in the sync
  statistics, instead of silently dropping the events beyond the cap;
* the event lookup filters with ``eventinfo``, asks for event headers only and pages on a MISP
  that ignores the filter, and the sync's restSearch fallback asks for EdgeGuard event headers only.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

import run_misp_to_neo4j as rm
from collectors import collector_utils
from collectors import misp_writer as mw


class _Resp:
    def __init__(self, status: int, payload=None, headers=None, text: str = ""):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.headers = headers or {}
        self.text = text

    def json(self):
        return self._payload


def _writer(monkeypatch, responses):
    """``MISPWriter`` whose session answers POSTs from ``responses`` in order (last one repeats)."""
    writer = mw.MISPWriter(url="https://misp.test", api_key="test-key", verify_ssl=True)
    posted: list = []
    queue = list(responses)

    class _Session:
        def post(self, url, json=None, **_kwargs):
            posted.append((url, json))
            return queue.pop(0) if len(queue) > 1 else queue[0]

    writer.session = _Session()
    sleeps: list = []
    # ``mw.time`` and ``collector_utils.time`` are the same module: one patch records every sleep
    # (Retry-After waits from the writer and backoff delays from the retry decorator).
    monkeypatch.setattr(mw.time, "sleep", lambda s: sleeps.append(float(s)))
    assert collector_utils.time is mw.time
    return writer, posted, sleeps


ATTRS = [{"type": "ip-dst", "value": "203.0.113.10", "category": "Network activity"}]


class TestEventLookup:
    def test_rate_limited_lookup_is_transient_and_does_not_sleep_under_the_lock(self, monkeypatch):
        """The confirming lookup runs inside the event-creation lock: the wait belongs to the
        retry decorator outside it, not to the lookup."""
        writer, _posted, sleeps = _writer(monkeypatch, [_Resp(429, headers={"Retry-After": "7"})])
        with pytest.raises(mw.MispTransientError):
            writer._restsearch_events_for_name("EdgeGuard-otx-2026-10-12")
        assert sleeps == []

    def test_server_error_on_lookup_is_transient(self, monkeypatch):
        writer, _posted, sleeps = _writer(monkeypatch, [_Resp(503, text="maintenance")])
        with pytest.raises(mw.MispTransientError):
            writer._restsearch_events_for_name("EdgeGuard-otx-2026-10-12")
        assert sleeps == [], "no Retry-After on a 503 without the header"

    def test_client_error_on_lookup_raises_instead_of_reporting_no_event(self, monkeypatch, caplog):
        writer, _posted, _sleeps = _writer(monkeypatch, [_Resp(403, text="forbidden")])
        with caplog.at_level(logging.ERROR, logger="collectors.misp_writer"):
            with pytest.raises(mw.MispLookupError):
                writer._restsearch_events_for_name("EdgeGuard-otx-2026-10-12")
        assert any("no event is created after a failed lookup" in r.getMessage() for r in caplog.records)

    def test_successful_lookup_returns_rows(self, monkeypatch):
        writer, _posted, _sleeps = _writer(
            monkeypatch, [_Resp(200, {"response": [{"Event": {"id": "5", "info": "x"}}]})]
        )
        assert writer._restsearch_events_for_name("x") == [{"Event": {"id": "5", "info": "x"}}]

    def test_lookup_request_filters_on_eventinfo_and_asks_for_headers_only(self, monkeypatch):
        """``eventinfo`` is MISP's Event.info filter (``info`` is not a restSearch parameter and was
        dropped); ``metadata``: only id/info are read, and a full event grew a php-fpm worker by GBs."""
        writer, posted, _sleeps = _writer(monkeypatch, [_Resp(200, {"response": []})])
        assert writer._restsearch_events_for_name("x") == []
        assert posted == [
            (
                "https://misp.test/events/restSearch",
                {"returnFormat": "json", "eventinfo": "x", "metadata": True, "limit": 500, "page": 1},
            )
        ]

    def test_failed_lookup_does_not_create_an_event(self, monkeypatch, caplog):
        """The event may exist; creating another one would duplicate the day's event."""
        writer, posted, _sleeps = _writer(monkeypatch, [_Resp(403, text="forbidden")])
        with caplog.at_level(logging.ERROR, logger="collectors.misp_writer"):
            assert mw.MISPWriter._get_or_create_event.__wrapped__(writer, "otx", "2026-10-12") is None
        assert all(not url.endswith("/events") for url, _ in posted), "POST /events must not happen"
        assert any("no event is created" in r.getMessage() for r in caplog.records)

    def test_transient_lookup_failure_after_retries_counts_the_group_and_continues(self, monkeypatch, caplog):
        """A MispTransientError escaping _get_or_create_event must not abort the whole push."""
        writer, _posted, _sleeps = _writer(monkeypatch, [_Resp(200, {})])
        calls: list = []

        def fake_get_or_create(source, date=None, **_k):
            calls.append(source)
            if source == "otx":
                raise mw.MispTransientError("MISP 503 on event lookup")
            return "9"

        monkeypatch.setattr(writer, "_get_or_create_event", fake_get_or_create)
        monkeypatch.setattr(writer, "_get_existing_attribute_keys", lambda *a, **k: set(), raising=False)
        monkeypatch.setattr(writer, "_get_existing_source_attribute_keys", lambda *a, **k: set(), raising=False)
        monkeypatch.setattr(writer, "_push_batch", lambda event_id, attrs: (len(attrs), 0))
        # push_items groups by the item's ``tag`` (the MISP source tag), one event per tag and day.
        items = [
            {"tag": "otx", "indicator_type": "ipv4", "value": "203.0.113.10", "zone": "energy"},
            {"tag": "nvd", "indicator_type": "ipv4", "value": "203.0.113.11", "zone": "energy"},
        ]
        with caplog.at_level(logging.ERROR, logger="collectors.misp_writer"):
            success, failed = writer.push_items(items)
        assert "otx" in calls and "nvd" in calls, "the remaining source groups are still pushed"
        assert failed >= 1 and success >= 1
        assert any("failed after retries" in r.getMessage() for r in caplog.records)

    def test_missing_event_id_counts_the_batch_as_failed(self, monkeypatch):
        writer, _posted, _sleeps = _writer(monkeypatch, [_Resp(403, text="forbidden")])
        monkeypatch.setattr(writer, "_get_or_create_event", lambda *a, **k: None)
        monkeypatch.setattr(writer, "_get_existing_attribute_keys", lambda *a, **k: set(), raising=False)
        monkeypatch.setattr(writer, "_get_existing_source_attribute_keys", lambda *a, **k: set(), raising=False)
        items = [{"tag": "otx", "indicator_type": "ipv4", "value": "203.0.113.10", "zone": "energy"}]
        success, failed = writer.push_items(items)
        assert success == 0 and failed >= 1

    def test_failed_lookup_does_not_log_the_all_already_present_message(self, monkeypatch, caplog):
        writer, _posted, _sleeps = _writer(monkeypatch, [_Resp(200, {})])

        def fail_lookup(*_a, **_k):
            raise mw.MispTransientError("MISP 502 on event lookup")

        monkeypatch.setattr(writer, "_get_or_create_event", fail_lookup)
        items = [{"tag": "otx", "indicator_type": "ipv4", "value": "203.0.113.10", "zone": "energy"}]
        with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
            success, failed = writer.push_items(items)
        assert success == 0 and failed == 1
        assert not any("[DEDUP] All" in r.getMessage() for r in caplog.records)

    def test_genuine_all_duplicates_batch_still_logs_the_dedup_message(self, monkeypatch, caplog):
        writer, _posted, _sleeps = _writer(monkeypatch, [_Resp(200, {})])
        monkeypatch.setattr(writer, "_get_or_create_event", lambda *a, **k: "9")
        monkeypatch.setattr(writer, "_get_existing_attribute_keys", lambda *a, **k: {("ip-dst", "203.0.113.10")})
        monkeypatch.setattr(writer, "_get_existing_source_attribute_keys", lambda *a, **k: set(), raising=False)
        items = [{"tag": "otx", "indicator_type": "ipv4", "value": "203.0.113.10", "zone": "energy"}]
        with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
            success, failed = writer.push_items(items)
        assert success == 0 and failed == 0
        assert any("[DEDUP] All" in r.getMessage() for r in caplog.records)


class _EventStore:
    """Fake MISP for the event lookup: ``/events/restSearch`` answers pages of event headers in id
    order and ``POST /events`` stores a new event.

    ``honours_eventinfo=False`` is a MISP older than 2.4.177: the ``eventinfo`` filter is dropped
    and every event of the store is answered, as it was for the ``info`` key on every version.
    """

    def __init__(self, infos, honours_eventinfo: bool):
        self.events = {str(i): info for i, info in enumerate(infos, start=1)}
        self.honours_eventinfo = honours_eventinfo
        self.posts: list = []

    def post(self, url, json=None, **_kwargs):
        self.posts.append((url, json))
        if url.endswith("/events/restSearch"):
            rows = [
                {"Event": {"id": eid, "info": info}}
                for eid, info in self.events.items()
                if not self.honours_eventinfo or info.lower() == json["eventinfo"].lower()
            ]
            start = (json["page"] - 1) * json["limit"]
            return _Resp(200, {"response": rows[start : start + json["limit"]]})
        if url.endswith("/events"):
            eid = str(len(self.events) + 1)
            self.events[eid] = json["Event"]["info"]
            return _Resp(200, {"Event": {"id": eid, "info": json["Event"]["info"]}})
        return _Resp(404)

    def lookup_pages(self) -> list:
        return [body["page"] for url, body in self.posts if url.endswith("/events/restSearch")]

    def creations(self) -> int:
        return sum(1 for url, _ in self.posts if url.endswith("/events"))


def _store_writer(monkeypatch, tmp_path, store: _EventStore, page_size: int = 3, max_pages: int = 40):
    writer = mw.MISPWriter(url="https://misp.test", api_key="test-key", verify_ssl=True)
    writer.session = store
    monkeypatch.setattr(mw, "EVENT_LOOKUP_PAGE_SIZE", page_size)
    monkeypatch.setattr(mw, "EVENT_LOOKUP_MAX_PAGES", max_pages)
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    return writer


def _get_or_create(writer, date: str):
    return mw.MISPWriter._get_or_create_event.__wrapped__(writer, "otx", date)


class TestEventLookupPaging:
    """2026-10: a MISP older than 2.4.177 ignores ``eventinfo``; the lookup pages until the exact
    name or a short page, so the same-day event is found wherever it sits in the store."""

    def test_match_only_on_page_two_is_found_and_no_event_is_created(self, monkeypatch, tmp_path):
        infos = [f"EdgeGuard-otx-2026-10-0{d}" for d in range(1, 6)]
        store = _EventStore(infos, honours_eventinfo=False)
        writer = _store_writer(monkeypatch, tmp_path, store)
        assert _get_or_create(writer, "2026-10-05") == "5"
        assert store.lookup_pages() == [1, 2]
        assert store.creations() == 0, "POST /events must not happen when the event exists"

    def test_short_page_without_match_creates_the_event_once(self, monkeypatch, tmp_path):
        infos = [f"EdgeGuard-otx-2026-10-0{d}" for d in range(1, 5)]
        store = _EventStore(infos, honours_eventinfo=False)
        writer = _store_writer(monkeypatch, tmp_path, store)
        assert _get_or_create(writer, "2026-10-09") == "5"
        # One lookup before the lock and the confirming one under it, each read to the short page 2.
        assert store.lookup_pages() == [1, 2, 1, 2]
        assert store.creations() == 1
        assert _get_or_create(writer, "2026-10-09") == "5", "the next push finds the event it created"
        assert store.creations() == 1

    def test_case_variant_is_not_taken_for_the_event(self, monkeypatch, tmp_path):
        """MISP's own match follows the database collation; only the exact name is the event."""
        store = _EventStore(["edgeguard-otx-2026-10-09"], honours_eventinfo=True)
        writer = _store_writer(monkeypatch, tmp_path, store)
        assert _get_or_create(writer, "2026-10-09") == "2"
        assert store.creations() == 1

    def test_misp_honouring_eventinfo_answers_on_the_first_page(self, monkeypatch, tmp_path):
        infos = [f"EdgeGuard-nvd-{n}" for n in range(1200)] + ["EdgeGuard-otx-2026-10-09"]
        store = _EventStore(infos, honours_eventinfo=True)
        writer = _store_writer(monkeypatch, tmp_path, store, page_size=500)
        assert _get_or_create(writer, "2026-10-09") == "1201"
        assert store.lookup_pages() == [1]
        assert store.creations() == 0

    def test_page_cap_fails_the_lookup_and_creates_no_event(self, monkeypatch, tmp_path, caplog):
        infos = [f"EdgeGuard-nvd-{n}" for n in range(20)]
        store = _EventStore(infos, honours_eventinfo=False)
        writer = _store_writer(monkeypatch, tmp_path, store, page_size=2, max_pages=3)
        with caplog.at_level(logging.ERROR, logger="collectors.misp_writer"):
            with pytest.raises(mw.MispLookupError):
                writer._restsearch_events_for_name("EdgeGuard-otx-2026-10-09")
        assert store.lookup_pages() == [1, 2, 3]
        assert any(
            "reached the page cap" in r.getMessage() and "EVENT_LOOKUP_MAX_PAGES" in r.getMessage()
            for r in caplog.records
        )
        store.posts.clear()
        assert _get_or_create(writer, "2026-10-09") is None
        assert store.creations() == 0, "the event may exist beyond the cap"


class TestBatchPushRateLimit:
    def test_429_sleeps_retry_after_and_raises_transient(self, monkeypatch, caplog):
        writer, _posted, sleeps = _writer(monkeypatch, [_Resp(429, headers={"Retry-After": "12"}, text="slow down")])
        with caplog.at_level(logging.WARNING, logger="collectors.misp_writer"):
            with pytest.raises(mw.MispTransientError):
                mw.MISPWriter._push_batch.__wrapped__(writer, "5", ATTRS)
        assert 12.0 in sleeps
        assert writer.stats["errors"] == 0, "a rate limit is not a permanent error"
        assert any("HTTP 429" in r.getMessage() for r in caplog.records)

    def test_429_is_retried_by_the_decorator_and_eventually_counted(self, monkeypatch):
        writer, posted, sleeps = _writer(monkeypatch, [_Resp(429, headers={"Retry-After": "1"})])
        with pytest.raises(mw.MispTransientError):
            writer._push_batch("5", ATTRS)
        assert len(posted) == 5, "first attempt + 4 retries"
        assert sleeps.count(1.0) == 5, "Retry-After honoured on every attempt"
        assert [s for s in sleeps if s >= 10.0] == [10.0, 20.0, 40.0, 80.0], "exponential backoff of the decorator"

    def test_500_is_still_transient_and_400_still_permanent(self, monkeypatch):
        writer, _posted, _sleeps = _writer(monkeypatch, [_Resp(500, text="boom")])
        with pytest.raises(mw.MispTransientError):
            mw.MISPWriter._push_batch.__wrapped__(writer, "5", ATTRS)
        writer, _posted, _sleeps = _writer(monkeypatch, [_Resp(400, text="invalid")])
        assert mw.MISPWriter._push_batch.__wrapped__(writer, "5", ATTRS) == (0, 1)
        assert writer.stats["errors"] == 1


class _IndexSession:
    """GET answers full pages of ``page_size`` rows for ``full_pages`` pages, then a short page."""

    def __init__(self, page_size: int, full_pages: int):
        self.page_size = page_size
        self.full_pages = full_pages
        self.calls = 0

    def get(self, url, params=None, **_kwargs):
        self.calls += 1
        page = params["page"]
        n = self.page_size if page <= self.full_pages else 0
        rows = [
            {"Event": {"id": str(page * 1000 + i), "info": "EdgeGuard-otx", "timestamp": "1700000000"}}
            for i in range(n)
        ]
        return _Resp(200, rows)


class TestIndexPageCap:
    @pytest.fixture(autouse=True)
    def _small_pages(self, monkeypatch):
        monkeypatch.setattr(rm, "MISP_EVENTS_INDEX_PAGE_SIZE", 3)
        monkeypatch.setattr(rm, "MISP_EVENTS_INDEX_MAX_PAGES", 2)
        rm.INDEX_FETCH_STATE["truncated"] = False

    def test_full_last_page_at_the_cap_is_reported(self, caplog):
        session = _IndexSession(page_size=3, full_pages=5)
        with caplog.at_level(logging.WARNING, logger=rm.__name__):
            rows = rm._fetch_edgeguard_events_via_requests_index(session, "https://misp.test", None)
        assert len(rows) == 6 and session.calls == 2
        assert rm.INDEX_FETCH_STATE["truncated"] is True
        assert any(
            "stopped at the page cap" in r.getMessage() and "EDGEGUARD_MISP_MAX_PAGES" in r.getMessage()
            for r in caplog.records
        )

    def test_short_last_page_is_not_truncated(self, caplog):
        session = _IndexSession(page_size=3, full_pages=1)
        with caplog.at_level(logging.WARNING, logger=rm.__name__):
            rows = rm._fetch_edgeguard_events_via_requests_index(session, "https://misp.test", None)
        assert len(rows) == 3
        assert rm.INDEX_FETCH_STATE["truncated"] is False
        assert not any("page cap" in r.getMessage() for r in caplog.records)

    def test_fetch_records_the_truncation_in_the_run_stats(self, monkeypatch):
        sync = rm.MISPToNeo4jSync(neo4j_client=MagicMock())
        sync.session = _IndexSession(page_size=3, full_pages=5)
        sync.misp_url = "https://misp.test"
        rows = sync.fetch_edgeguard_events(since=None)
        assert rows and sync.stats.get("events_index_truncated") is True
        assert "events_index_truncated" in sync.stats


_EG_ROW = {"Event": {"id": "7", "info": "EdgeGuard-otx-2026-10-07", "attribute_count": "12"}}
_OTHER_ROW = {"Event": {"id": "8", "info": "CIRCL OSINT feed", "attribute_count": "900"}}
_FALLBACK_FILTERS = {"metadata": True, "eventinfo": "%EdgeGuard%"}


class _FallbackSession:
    """Both index endpoints answer 404, so ``fetch_edgeguard_events`` takes its fallback;
    ``POST /events/restSearch`` answers ``pages`` in order (an empty page after the last)."""

    def __init__(self, pages):
        self.pages = pages
        self.posts: list = []

    def get(self, url, params=None, **_kwargs):
        return _Resp(404)

    def post(self, url, json=None, **_kwargs):
        self.posts.append((url, json))
        page = json["page"]
        return _Resp(200, {"response": self.pages[page - 1] if page <= len(self.pages) else []})


class TestFetchFallbackAsksForEdgeGuardHeaders:
    """2026-10: ``search`` is not a restSearch parameter, so the fallback's first page was the whole
    store with every attribute. It now asks for event headers (``metadata``) filtered with
    ``eventinfo`` and keeps only EdgeGuard rows, which a MISP older than 2.4.177 does not filter."""

    @staticmethod
    def _sync(session):
        sync = rm.MISPToNeo4jSync(neo4j_client=MagicMock())
        sync.session = session
        sync.misp_url = "https://misp.test"
        return sync

    def test_pymisp_branch_pages_on_every_row_and_keeps_edgeguard_rows(self, monkeypatch):
        import pymisp

        calls: list = []
        # A MISP older than 2.4.177: a full first page of other events, then the EdgeGuard event.
        pages = [[_OTHER_ROW] * 500, [_EG_ROW, _OTHER_ROW]]

        class _FakePyMISP:
            def __init__(self, *_args, **_kwargs):
                pass

            def search(self, **kwargs):
                calls.append(kwargs)
                return {"response": pages[kwargs["page"] - 1] if kwargs["page"] <= len(pages) else []}

        monkeypatch.setattr(pymisp, "PyMISP", _FakePyMISP)
        session = _FallbackSession([])
        rows = self._sync(session).fetch_edgeguard_events(since=None)
        assert calls == [{"controller": "events", "limit": 500, "page": page, **_FALLBACK_FILTERS} for page in (1, 2)]
        assert session.posts == [], "the requests branch runs only when PyMISP fails"
        assert rows == [_EG_ROW["Event"]], "the non-EdgeGuard event is dropped; id, info, attribute_count kept"

    def test_requests_branch_pages_on_every_row_and_keeps_edgeguard_rows(self, monkeypatch):
        import pymisp

        def _no_pymisp(*_args, **_kwargs):
            raise RuntimeError("PyMISP unavailable")

        monkeypatch.setattr(pymisp, "PyMISP", _no_pymisp)
        # A MISP older than 2.4.177: a full first page of other events, then the EdgeGuard event.
        session = _FallbackSession([[_OTHER_ROW] * 500, [_EG_ROW, _OTHER_ROW]])
        rows = self._sync(session).fetch_edgeguard_events(since=None)
        assert [body for _url, body in session.posts] == [
            {"returnFormat": "json", "limit": 500, "page": page, **_FALLBACK_FILTERS} for page in (1, 2)
        ]
        assert all(url == "https://misp.test/events/restSearch" for url, _body in session.posts)
        assert rows == [_EG_ROW["Event"]]
