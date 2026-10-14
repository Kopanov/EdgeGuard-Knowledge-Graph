"""NVD incremental runs read every CVE modified since a stored cursor and keep MISP in step (2026-10).

Before, an incremental run took the newest N records of the 14-day lastMod window by publication
date (N = ``EDGEGUARD_INCREMENTAL_LIMIT``, 200). Measured on 2026-10-14: a 30-day replay of the
8-hourly schedule missed 37% of new CVEs; on the hosted instance 1,930 of the 2,130 CVEs published
after the 730-day baseline were never collected; and MISPWriter dropped every update to a CVE MISP
already held (cross-event duplicate check), so all 1,500 baseline CVEs NVD changed afterwards kept
their old version in MISP and Neo4j.

The tests drive the real ``NVDCollector`` and the real ``MISPWriter`` against two fakes fed with
real payloads (``tests/fixtures/nvd_incremental_2026_10_14.json``, see its ``_provenance``):

- ``FakeNvd`` answers lastMod requests as NVD CVE API 2.0 does: zone-less timestamps, results in
  publication order and evaluated again for every page, the envelope of a real page;
- ``FakeMisp`` answers MISPWriter as MISP 2.5 does: the attribute listing by tag, event lookup and
  creation, the event edit that adds attributes, and the attribute edit
  (``AttributesController::edit``: new comment and timestamps; tags attached, or detached when
  marked ``deleted``).
"""

from __future__ import annotations

import copy
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from collectors import misp_writer, nvd_collector  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from collectors.nvd_collector import NVD_CURSOR_KEY, NVDCollector, iter_nvd_lastmod_spans  # noqa: E402

FIXTURES = json.loads((Path(__file__).resolve().parent / "fixtures" / "nvd_incremental_2026_10_14.json").read_text())
NOW = datetime(2026, 10, 14, 18, 30, tzinfo=timezone.utc)

# The real records (published, lastModified, status as NVD returned them on 2026-10-14).
REJECTED = "CVE-2026-22314"  # in MISP as active (high), rejected by NVD on 2026-10-13 14:17 UTC
ANALYSED = "CVE-2026-83540"  # in MISP with CVSS 4.0 only; NVD added CVSS 3.1 and CPE on 2026-10-13 17:33
UNCHANGED = ("CVE-2025-0237", "CVE-2025-0238")  # in MISP exactly as NVD has them now
NEW = "CVE-2026-93637"  # published 2026-10-14 17:20, not in MISP
OLD = "CVE-1999-0024"  # published 1997, modified 2026-10-09, not on KEV, not in MISP
KEV_OLD = "CVE-2021-44228"  # published 2021, on KEV, modified 2026-08-11, not in MISP


def _ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def nvd_record(cve_id: str, **cve_changes) -> dict:
    record = copy.deepcopy(FIXTURES["nvd"][cve_id])
    record["cve"].update(cve_changes)
    return record


def stored_attribute(cve_id: str) -> dict:
    return copy.deepcopy(FIXTURES["misp"][cve_id])


class _Response:
    def __init__(self, status_code: int, body):
        self.status_code = status_code
        self._body = body
        self.headers: dict = {}
        self.text = json.dumps(body)[:300]
        self.content = self.text.encode()

    def json(self):
        return copy.deepcopy(self._body)


class FakeNvd:
    """lastMod requests answered from a list of real NVD records (see the module docstring)."""

    def __init__(self, records):
        self.records = [copy.deepcopy(r) for r in records]
        self.requests: list = []
        self.before_request = None  # hook(request_number) to change ``records`` between requests
        self.status = 200  # HTTP status of every answer (503: NVD unavailable)
        self.empty_pages: set = set()  # startIndex values answered with no record before totalResults is reached
        self.overcount = 0  # added to totalResults (an answer that counts records it does not return)

    def __call__(self, method, url, *, params=None, **_kwargs):
        params = dict(params or {})
        self.requests.append(params)
        if self.before_request is not None:
            self.before_request(len(self.requests))
        if self.status != 200:
            return _Response(self.status, {"message": "Service unavailable"})
        start, end = _ts(params["lastModStartDate"]), _ts(params["lastModEndDate"])
        rows = sorted(
            (
                r
                for r in self.records
                if "lastModified" not in r["cve"] or start <= _ts(r["cve"]["lastModified"]) <= end
            ),
            key=lambda r: (
                _ts(r["cve"].get("published") or r["cve"].get("lastModified") or "1970-01-01T00:00:00"),
                r["cve"]["id"],
            ),
        )
        first, count = int(params.get("startIndex", 0)), int(params.get("resultsPerPage", 2000))
        page = rows[first : first + count]
        if first in self.empty_pages:
            page = []
        body = dict(FIXTURES["nvd_page_envelope"])
        body.update(
            resultsPerPage=len(page), startIndex=first, totalResults=len(rows) + self.overcount, vulnerabilities=page
        )
        return _Response(200, body)


class FakeMisp:
    """MISP 2.5 REST answers over an in-memory attribute store (see the module docstring)."""

    def __init__(self, attributes=()):
        self.attributes = [copy.deepcopy(a) for a in attributes]
        self.events = {a["event_id"]: "EdgeGuard-nvd-2026-10-13" for a in self.attributes}
        self.posts: list = []
        self.headers: dict = {}
        self.edit_status: dict = {}  # uuid -> HTTP status MISP answers to its edit
        self.edits_not_stored: set = set()  # uuids MISP answers 200 for without storing the edit
        self.adds_not_stored: set = set()  # values MISP answers 200 for without storing them
        self.adds_without_list = False  # answer additions without the event's attribute list
        self.listing_status = None  # HTTP status of every attribute listing request

    def post(self, url, json=None, **_kwargs):
        path = url.split("misp.test", 1)[1]
        self.posts.append((path, copy.deepcopy(json)))
        if path == "/attributes/restSearch":
            return self._rest_search(json or {})
        if path == "/events/restSearch":
            info = (json or {}).get("info")
            return _Response(
                200, {"response": [{"Event": {"id": i, "info": n}} for i, n in self.events.items() if n == info]}
            )
        if path == "/events":
            event_id = str(200 + len(self.events))
            self.events[event_id] = json["Event"]["info"]
            return _Response(200, {"Event": {"id": event_id, "info": json["Event"]["info"]}})
        if path.startswith("/attributes/edit/"):
            return self._edit(path.rsplit("/", 1)[1], (json or {}).get("Attribute") or {})
        if path.startswith("/events/"):
            return self._add(path.rsplit("/", 1)[1], (json or {}).get("Attribute") or [])
        return _Response(404, {})

    def get(self, url, **_kwargs):
        return _Response(404, {})

    def edits(self) -> list:
        return [(p.rsplit("/", 1)[1], body["Attribute"]) for p, body in self.posts if p.startswith("/attributes/edit/")]

    def added_values(self) -> list:
        return [
            a["value"]
            for p, body in self.posts
            if p.startswith("/events/") and p != "/events/restSearch"
            for a in (body or {}).get("Attribute", [])
        ]

    def by_value(self, value: str) -> dict:
        return next(a for a in self.attributes if a["value"] == value)

    def _rest_search(self, body: dict):
        if self.listing_status is not None:
            return _Response(self.listing_status, {"errors": "listing failed"})
        if "eventid" in body:
            rows = [a for a in self.attributes if a["event_id"] == str(body["eventid"])]
        else:
            rows = [
                a
                for a in self.attributes
                if set(body.get("tags") or []) <= {t["name"] for t in a.get("Tag", [])}
                and a["type"] == body.get("type", a["type"])
            ]
        if "value" in body:
            wanted = set(body["value"]) if isinstance(body["value"], list) else {body["value"]}
            rows = [a for a in rows if a["value"] in wanted]
        page, limit = int(body.get("page", 1)), int(body.get("limit", 5000))
        return _Response(200, {"response": {"Attribute": rows[(page - 1) * limit : page * limit]}})

    def _add(self, event_id: str, attributes: list):
        for attr in attributes:
            if attr["value"] in self.adds_not_stored:
                continue
            stored = copy.deepcopy(attr)
            stored.update(id=str(3000000 + len(self.attributes)), uuid=str(uuid.uuid4()), event_id=event_id)
            stored["Tag"] = [{"id": "0", "name": t["name"]} for t in attr.get("Tag", [])]
            self.attributes.append(stored)
        if self.adds_without_list:
            return _Response(200, {"Event": {"id": event_id}})
        return _Response(
            200, {"Event": {"id": event_id, "Attribute": [a for a in self.attributes if a["event_id"] == event_id]}}
        )

    def listings(self) -> list:
        return [body for p, body in self.posts if p == "/attributes/restSearch" and "tags" in (body or {})]

    def _edit(self, attr_uuid: str, changes: dict):
        if attr_uuid in self.edit_status:
            return _Response(self.edit_status[attr_uuid], {"name": "Could not edit Attribute", "errors": {}})
        attr = next((a for a in self.attributes if a["uuid"] == attr_uuid), None)
        if attr is None:
            return _Response(404, {"name": "Invalid attribute"})
        if attr_uuid not in self.edits_not_stored:
            for key in ("comment", "first_seen", "last_seen"):
                if key in changes:
                    attr[key] = changes[key]
            for tag in changes.get("Tag", []):
                names = [t["name"] for t in attr["Tag"]]
                if tag.get("deleted"):
                    attr["Tag"] = [t for t in attr["Tag"] if t["name"] != tag["name"]]
                elif tag["name"] not in names:
                    attr["Tag"].append({"id": "0", "name": tag["name"]})
            attr["timestamp"] = str(int(NOW.timestamp()))
        return _Response(200, {"Attribute": copy.deepcopy(attr)})


class CursorStore:
    """In-memory ``checkpoints[nvd].incremental``."""

    def __init__(self, cursor: str | None = None):
        self.data = {} if cursor is None else {NVD_CURSOR_KEY: cursor}
        self.writes: list = []

    def get(self, source: str) -> dict:
        assert source == "nvd"
        return dict(self.data)

    def update(self, source: str, **values) -> None:
        assert source == "nvd"
        self.writes.append(values)
        self.data.update(values)


@pytest.fixture
def env(monkeypatch, tmp_path):
    for name in (
        "EDGEGUARD_NVD_INCREMENTAL_DAYS",
        "EDGEGUARD_NVD_CURSOR_OVERLAP_SEC",
        "EDGEGUARD_NVD_MAX_PER_RUN",
        "EDGEGUARD_NVD_UPDATE_EXISTING",
        "EDGEGUARD_NVD_EXTRA_CVE_IDS",
        "EDGEGUARD_BASELINE_DAYS",
        "EDGEGUARD_MISP_PUSH_BATCH_SIZE",
        "EDGEGUARD_MAX_ENTRIES",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(tmp_path / "event.lock"))
    monkeypatch.setattr(nvd_collector, "_utc_now", lambda: NOW)
    monkeypatch.setattr(nvd_collector.time, "sleep", lambda _s: None)
    monkeypatch.setattr(misp_writer.time, "sleep", lambda _s: None)
    monkeypatch.setattr(misp_writer, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(misp_writer, "MISP_CROSS_EVENT_DEDUP", True)
    import config

    # Other test modules reload ``config`` with their own EDGEGUARD_MAX_ENTRIES; the global override
    # would lower NVD's per-run cap here.
    monkeypatch.setattr(config, "MAX_ENTRIES_PER_SOURCE", 0)
    return monkeypatch


def run(env, nvd: FakeNvd, misp: FakeMisp, store: CursorStore, *, limit=None, push_to_misp=True):
    env.setattr(nvd_collector, "request_with_rate_limit_retries", nvd)
    env.setattr(nvd_collector, "get_source_incremental", store.get)
    env.setattr(nvd_collector, "update_source_incremental", store.update)
    writer = MISPWriter(url="https://misp.test", api_key="test", verify_ssl=True)
    writer.session = misp
    collector = NVDCollector(misp_writer=writer)
    collector.check_service_available = lambda: True
    collector.circuit_breaker = MagicMock()
    return collector.collect(limit=limit, push_to_misp=push_to_misp, baseline=False)


ALL = (REJECTED, ANALYSED, *UNCHANGED, NEW, OLD, KEV_OLD)
KNOWN = (REJECTED, ANALYSED, *UNCHANGED)


# --------------------------------------------------------------------------- window and cursor
class TestWindow:
    def _start(self, env, cursor):
        store = CursorStore(cursor)
        env.setattr(nvd_collector, "get_source_incremental", store.get)
        c = NVDCollector.__new__(NVDCollector)
        return c._incremental_start(NOW)

    def test_cursor_minus_overlap(self, env):
        start, cursor = self._start(env, "2026-10-14T10:00:00+00:00")
        assert cursor == datetime(2026, 10, 14, 10, tzinfo=timezone.utc)
        assert start == cursor - timedelta(hours=1), "default overlap 3600 s"

    def test_without_cursor_reads_the_lookback(self, env):
        env.setenv("EDGEGUARD_NVD_INCREMENTAL_DAYS", "20")
        assert self._start(env, None) == (NOW - timedelta(days=20), None)

    @pytest.mark.parametrize("bad", ["not a time", "2026-10-15T00:00:00+00:00"], ids=["unreadable", "in-the-future"])
    def test_unusable_cursor_falls_back_to_the_lookback(self, env, bad):
        assert self._start(env, bad) == (NOW - timedelta(days=14), None)

    def test_zone_less_nvd_and_zoned_misp_times_are_the_same_instant(self):
        assert nvd_collector._parse_nvd_time("2026-10-13T17:33:17.707") == nvd_collector._parse_nvd_time(
            "2026-10-13T17:33:17.707000+00:00"
        )
        assert nvd_collector._parse_nvd_time("garbage") is None and nvd_collector._parse_nvd_time(None) is None

    def test_spans_are_contiguous_oldest_first_and_at_most_120_days(self):
        spans = iter_nvd_lastmod_spans(NOW - timedelta(days=250), NOW)
        assert spans[0][0] == NOW - timedelta(days=250) and spans[-1][1] == NOW
        assert all(a[1] == b[0] for a, b in zip(spans, spans[1:], strict=False))
        assert all(timedelta(0) < e - s <= timedelta(days=120) for s, e in spans)


# --------------------------------------------------------------------------- reading the window
def _many(count: int, *, same_second: bool = False) -> list:
    """*count* copies of the real new record, published one second apart (or within one second),
    all modified in the window."""
    base = FIXTURES["nvd"][NEW]
    out = []
    for n in range(count):
        record = copy.deepcopy(base)
        offset = timedelta(milliseconds=n % 1000) if same_second else timedelta(seconds=n)
        stamp = (datetime(2026, 10, 14, 6, tzinfo=timezone.utc) + offset).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        record["cve"].update(id=f"CVE-2026-{900000 + n}", published=stamp, lastModified=stamp)
        out.append(record)
    return out


class TestReadingTheWindow:
    def _read(self, env, nvd):
        env.setattr(nvd_collector, "request_with_rate_limit_retries", nvd)
        c = NVDCollector.__new__(NVDCollector)
        c.api_key = None
        c.base_url = "https://nvd.test"
        return c._fetch_modified_cves(NOW - timedelta(days=1), NOW)

    def test_a_window_larger_than_one_answer_is_read_in_slices_of_one_request_each(self, env):
        nvd = FakeNvd(_many(4100))
        records, complete = self._read(env, nvd)
        assert complete and len(records) == 4100
        assert {r["startIndex"] for r in nvd.requests} == {0}, "no paging: each slice is one answer"
        assert all(r["resultsPerPage"] == 2000 for r in nvd.requests)

    def test_records_modified_again_while_the_window_is_read_are_not_lost(self, env):
        # Between requests NVD modifies records again (their new lastModified is after the window):
        # they leave it, and every record that stays in it is still read.
        nvd = FakeNvd(_many(4100))

        def modify_again(request_number):
            for record in nvd.records[100 * request_number : 100 * request_number + 7]:
                record["cve"]["lastModified"] = "2026-10-14T19:00:00.000"

        nvd.before_request = modify_again
        records, complete = self._read(env, nvd)
        ids = {r["cve"]["id"] for r in records}
        still_in_window = {r["cve"]["id"] for r in nvd.records if _ts(r["cve"]["lastModified"]) <= NOW}
        assert complete and still_in_window <= ids

    def test_a_slice_too_narrow_to_split_is_paged_and_records_that_moved_down_are_read_again(self, env):
        # 2,500 records modified within one second cannot be split by time; that slice is paged.
        nvd = FakeNvd(_many(2500, same_second=True))
        moved_down = [r["cve"]["id"] for r in sorted(nvd.records, key=lambda r: r["cve"]["published"])[2000:2007]]

        def modify_again(request_number):
            if nvd.requests[-1].get("startIndex") == 2000:
                for record in nvd.records[100:107]:
                    record["cve"]["lastModified"] = "2026-10-14T19:00:00.000"

        nvd.before_request = modify_again
        records, complete = self._read(env, nvd)
        assert complete and set(moved_down) <= {r["cve"]["id"] for r in records}
        assert any(r.get("startIndex") == 1993 and r.get("resultsPerPage") == 7 for r in nvd.requests)

    def test_a_paged_slice_that_cannot_be_read_again_completely_is_incomplete(self, env):
        nvd = FakeNvd(_many(2500, same_second=True))

        def modify_again(request_number):
            if nvd.requests[-1].get("startIndex") in (2000, 1997):
                for record in nvd.records[100 + request_number : 103 + request_number]:
                    record["cve"]["lastModified"] = "2026-10-14T19:00:00.000"

        nvd.before_request = modify_again
        _records, complete = self._read(env, nvd)
        assert complete is False

    def test_an_answer_that_counts_records_it_does_not_return_is_not_split(self, env):
        # NVD says 5 more records than it returns although the answer had room: splitting would turn
        # this into thousands of requests (an empty answer counting records splits down to 2 s).
        nvd = FakeNvd(_many(30))
        nvd.overcount = 5
        records, complete = self._read(env, nvd)
        assert complete is False and len(records) == 30 and len(nvd.requests) == 1

    def test_a_record_read_twice_counts_once(self, env):
        c = NVDCollector.__new__(NVDCollector)
        c.api_key = None
        record = nvd_record(NEW)
        env.setattr(
            NVDCollector, "_iter_lastmod_slices", lambda self, s, e, b: iter([([record], True), ([record], True)])
        )
        records, _ = c._fetch_modified_cves(NOW - timedelta(days=1), NOW)
        assert [r["cve"]["id"] for r in records] == [NEW]

    def test_a_page_that_ends_early_makes_the_read_incomplete(self, env):
        nvd = FakeNvd(_many(2500, same_second=True))
        nvd.empty_pages = {2000}
        _records, complete = self._read(env, nvd)
        assert complete is False


# --------------------------------------------------------------------------- one run, end to end
class TestIncrementalRun:
    def _fakes(self, cursor=None):
        nvd = FakeNvd([nvd_record(c) for c in ALL])
        misp = FakeMisp([stored_attribute(c) for c in KNOWN])
        return nvd, misp, CursorStore(cursor)

    def test_new_changed_unchanged_and_out_of_scope_cves(self, env):
        env.setenv("EDGEGUARD_NVD_INCREMENTAL_DAYS", "70")  # first run without a cursor; reaches Log4Shell
        nvd, misp, store = self._fakes()
        status = run(env, nvd, misp, store)

        edits = dict(misp.edits())
        assert set(edits) == {stored_attribute(REJECTED)["uuid"], stored_attribute(ANALYSED)["uuid"]}
        assert sorted(misp.added_values()) == [KEV_OLD, NEW], "new in-scope CVEs added; 1997 non-KEV CVE left out"

        rejected = edits[stored_attribute(REJECTED)["uuid"]]
        meta = json.loads(rejected["comment"][len("NVD_META:") :])
        assert meta["status"] == ["rejected"] and meta["cvss_v31_data"] is None
        assert rejected["last_seen"] == "2026-10-13T14:17:38.270000+00:00", "NVD's zone-less lastModified, as UTC"
        assert {t["name"] for t in rejected["Tag"] if t.get("deleted")} == {"severity:high", "cvss:high"}
        assert {t["name"] for t in rejected["Tag"] if not t.get("deleted")} == {"severity:unknown"}, (
            "no CVSS, no cvss: tag"
        )

        analysed = json.loads(edits[stored_attribute(ANALYSED)["uuid"]]["comment"][len("NVD_META:") :])
        assert analysed["cvss_v31_data"]["base_score"] == 8.8, "NVD's CVSS 3.1 score from its analysis"
        assert analysed["affected_products"], "NVD's CPE configuration reaches MISP"

        stored = json.loads(misp.by_value(REJECTED)["comment"][len("NVD_META:") :])
        assert stored["status"] == ["rejected"], "MISP holds NVD's current record after the run"
        assert store.data[NVD_CURSOR_KEY] == NOW.isoformat()
        assert status["success"] is True
        assert {k: status["nvd_incremental"][k] for k in ("added", "updated", "unchanged", "out_of_scope")} == {
            "added": 2,
            "updated": 2,
            "unchanged": 2,
            "out_of_scope": 1,
        }

    def test_a_second_run_over_the_same_changes_writes_nothing(self, env):
        env.setenv("EDGEGUARD_NVD_INCREMENTAL_DAYS", "70")
        nvd, misp, store = self._fakes()
        run(env, nvd, misp, store)
        store.data.clear()  # read the same window again
        posts_before = len(misp.posts)
        status = run(env, nvd, misp, store)
        writes = [
            p for p, _ in misp.posts[posts_before:] if p.startswith("/attributes/edit/") or p.startswith("/events/2")
        ]
        assert writes == [] and status["nvd_incremental"]["unchanged"] == 6

    def test_a_failed_edit_keeps_the_cursor_and_the_next_run_repeats_only_that_edit(self, env):
        nvd, misp, store = self._fakes(cursor="2026-10-13T12:00:00+00:00")
        misp.edit_status[stored_attribute(ANALYSED)["uuid"]] = 403
        status = run(env, nvd, misp, store)
        assert status["success"] is False and status["nvd_incremental"]["failed"] == 1
        assert store.writes == [], "cursor kept after a failed write"

        del misp.edit_status[stored_attribute(ANALYSED)["uuid"]]
        posts_before = len(misp.posts)
        status = run(env, nvd, misp, store)
        edited = [p.rsplit("/", 1)[1] for p, _ in misp.posts[posts_before:] if p.startswith("/attributes/edit/")]
        assert edited == [stored_attribute(ANALYSED)["uuid"]], "the edit that succeeded is not repeated"
        assert status["success"] is True and store.data[NVD_CURSOR_KEY] == NOW.isoformat()

    def test_an_edit_misp_does_not_store_counts_as_failed(self, env):
        nvd, misp, store = self._fakes(cursor="2026-10-13T12:00:00+00:00")
        misp.edits_not_stored.add(stored_attribute(REJECTED)["uuid"])
        status = run(env, nvd, misp, store)
        assert status["nvd_incremental"]["failed"] == 1 and store.writes == []

    @pytest.mark.parametrize(
        "throttle, pauses", [("2.5", [2.5, 2.5]), ("0", []), ("not a number", [5.0, 5.0])], ids=["set", "off", "bad"]
    )
    def test_edits_pause_like_push_items_batches(self, env, throttle, pauses):
        # 120 stored CVEs NVD changed: EDGEGUARD_MISP_BATCH_THROTTLE_SEC after every 50 edits, not
        # after the last (Bugbot on #186: the edits had no pause, push_items' batches have one).
        env.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", throttle)
        sleeps: list = []
        env.setattr(nvd_collector.time, "sleep", sleeps.append)
        records, attributes = [], []
        for n in range(120):
            cve_id = f"CVE-2026-9{n:04d}"
            records.append(nvd_record(REJECTED, id=cve_id))
            attr = stored_attribute(REJECTED)
            attr.update(value=cve_id, uuid=str(uuid.UUID(int=n + 1)), id=str(4000000 + n))
            attributes.append(attr)
        status = run(env, FakeNvd(records), FakeMisp(attributes), CursorStore("2026-10-13T13:00:00+00:00"))
        assert status["nvd_incremental"]["updated"] == 120 and status["success"] is True
        assert sleeps == pauses

    def test_listing_failure_writes_nothing_and_keeps_the_cursor(self, env):
        nvd, misp, store = self._fakes(cursor="2026-10-13T12:00:00+00:00")
        misp.listing_status = 503
        status = run(env, nvd, misp, store)
        assert status["success"] is False
        assert [p for p, _ in misp.posts if p != "/attributes/restSearch"] == []
        assert store.writes == []

    def test_per_run_cap_stops_at_a_record_and_later_runs_continue_without_gaps(self, env):
        env.setenv("EDGEGUARD_NVD_INCREMENTAL_DAYS", "70")
        env.setenv("EDGEGUARD_NVD_MAX_PER_RUN", "1")
        nvd, misp, store = self._fakes()
        runs = 0
        while runs < 10:
            runs += 1
            status = run(env, nvd, misp, store)
            assert status["success"] is True
            if not status["nvd_incremental"]["stopped_at_cap"]:
                break
        assert runs == 4, "four writes, one per run; unchanged and out-of-scope records cost none"
        assert sorted(misp.added_values()) == [KEV_OLD, NEW]
        assert sorted(uid for uid, _ in misp.edits()) == sorted(
            {stored_attribute(REJECTED)["uuid"], stored_attribute(ANALYSED)["uuid"]}
        ), "each change written once"
        assert store.data[NVD_CURSOR_KEY] == NOW.isoformat()

    def test_update_switch_off_leaves_stored_cves(self, env):
        env.setenv("EDGEGUARD_NVD_UPDATE_EXISTING", "false")
        env.setenv("EDGEGUARD_NVD_INCREMENTAL_DAYS", "70")
        nvd, misp, store = self._fakes()
        status = run(env, nvd, misp, store)
        assert misp.edits() == [] and sorted(misp.added_values()) == [KEV_OLD, NEW]
        assert status["nvd_incremental"]["stored_not_updated"] == 4

    def test_named_ids_and_the_baseline_days_set_the_scope(self, env):
        env.setenv("EDGEGUARD_NVD_INCREMENTAL_DAYS", "70")
        env.setenv("EDGEGUARD_NVD_EXTRA_CVE_IDS", OLD)
        env.setenv("EDGEGUARD_BASELINE_DAYS", "7")
        week_old = nvd_record(NEW, id="CVE-2026-93638", published="2026-10-06T09:00:00.000")
        nvd = FakeNvd([nvd_record(c) for c in (NEW, OLD, KEV_OLD)] + [week_old])
        misp, store = FakeMisp(), CursorStore()
        run(env, nvd, misp, store)
        assert sorted(misp.added_values()) == sorted([NEW, OLD, KEV_OLD]), "8 days old with a 7-day scope: left out"

    def test_without_push_every_record_read_is_returned_and_the_cursor_stays(self, env):
        env.setenv("EDGEGUARD_NVD_INCREMENTAL_DAYS", "70")
        nvd, misp, store = self._fakes()
        items = run(env, nvd, misp, store, push_to_misp=False)
        assert sorted(i["cve_id"] for i in items) == sorted(ALL)
        assert misp.posts == [] and store.writes == []

    def test_a_burst_beyond_the_old_limit_is_taken_whole(self, env):
        # 1,465 CVEs were published in one hour on 2026-10-13; the old selection took 200 per run.
        nvd = FakeNvd(_many(2500))
        misp, store = FakeMisp(), CursorStore("2026-10-14T05:00:00+00:00")
        status = run(env, nvd, misp, store, limit=None)
        assert len(misp.added_values()) == 2500 and status["nvd_incremental"]["added"] == 2500

    def test_records_are_handled_in_order_of_modification_not_of_id(self, env):
        # Ids sort X < Z < Y < W; modification times W (07:00) < X (10:00) < Y (11:00) < Z (12:00).
        # Handled by id with a cap of two, a run would write X and Z, stop at Y and store 11:00; the
        # next run reads from 10:00 (one hour of overlap), so W would never be read again.
        env.setenv("EDGEGUARD_NVD_MAX_PER_RUN", "2")
        records = []
        for cve_id, hour in (
            ("CVE-2026-90001", 10),
            ("CVE-2026-90002", 12),
            ("CVE-2026-90003", 11),
            ("CVE-2026-90004", 7),
        ):
            stamp = f"2026-10-14T{hour:02d}:00:00.000"
            records.append(nvd_record(NEW, id=cve_id, published=stamp, lastModified=stamp))
        nvd, misp, store = FakeNvd(records), FakeMisp(), CursorStore("2026-10-14T06:30:00+00:00")
        for _ in range(4):
            if not run(env, nvd, misp, store)["nvd_incremental"]["stopped_at_cap"]:
                break
        assert sorted(misp.added_values()) == ["CVE-2026-90001", "CVE-2026-90002", "CVE-2026-90003", "CVE-2026-90004"]

    def test_an_incomplete_read_keeps_the_cursor(self, env):
        nvd = FakeNvd(_many(2500, same_second=True))
        nvd.empty_pages = {2000}
        misp, store = FakeMisp(), CursorStore("2026-10-14T05:00:00+00:00")
        status = run(env, nvd, misp, store)
        assert status["nvd_incremental"]["read_complete"] is False and store.writes == []
        assert status["success"] is False, "a cursor that cannot move fails the task"

    def test_the_run_limit_lowers_the_cap(self, env):
        nvd, misp, store = FakeNvd([nvd_record(NEW), nvd_record(KEV_OLD)]), FakeMisp(), CursorStore()
        env.setenv("EDGEGUARD_NVD_INCREMENTAL_DAYS", "70")
        status = run(env, nvd, misp, store, limit=1)
        assert misp.added_values() == [KEV_OLD] and status["nvd_incremental"]["stopped_at_cap"] is True

    def test_a_record_without_a_publication_date_is_added(self, env):
        undated = nvd_record(NEW, id="CVE-2026-93639")
        del undated["cve"]["published"]
        nvd, misp, store = FakeNvd([undated]), FakeMisp(), CursorStore("2026-10-14T12:00:00+00:00")
        run(env, nvd, misp, store)
        assert misp.added_values() == ["CVE-2026-93639"]

    def test_an_addition_misp_does_not_store_keeps_the_cursor_and_is_repeated(self, env):
        # MISP answers the batch with HTTP 200 and the event, which holds one of the two attributes.
        other = nvd_record(NEW, id="CVE-2026-93640")
        nvd, misp, store = FakeNvd([nvd_record(NEW), other]), FakeMisp(), CursorStore("2026-10-14T12:00:00+00:00")
        misp.adds_not_stored.add(NEW)
        status = run(env, nvd, misp, store)
        assert status["nvd_incremental"]["failed"] == 1 and status["nvd_incremental"]["added"] == 1
        assert store.writes == [], "MISP answered HTTP 200 but did not store it"
        misp.adds_not_stored.clear()
        run(env, nvd, misp, store)
        assert NEW in {a["value"] for a in misp.attributes} and store.data[NVD_CURSOR_KEY] == NOW.isoformat()

    def test_an_answer_without_a_list_is_confirmed_by_value(self, env):
        # MISP answered the batch without the event's attribute list but stored the attribute.
        nvd, misp, store = FakeNvd([nvd_record(NEW)]), FakeMisp(), CursorStore("2026-10-14T12:00:00+00:00")
        misp.adds_without_list = True
        status = run(env, nvd, misp, store)
        assert status["success"] is True and status["nvd_incremental"]["added"] == 1
        assert store.data[NVD_CURSOR_KEY] == NOW.isoformat()

    def test_additions_misp_drops_on_an_empty_event_fail_the_run_and_keep_the_cursor(self, env):
        # MISP 2.5 answers an event edit with HTTP 200 even when every attribute fails validation;
        # on the day's empty event the answer then has no attribute list to check against.
        other = nvd_record(NEW, id="CVE-2026-93640")
        nvd, misp, store = FakeNvd([nvd_record(NEW), other]), FakeMisp(), CursorStore("2026-10-14T12:00:00+00:00")
        misp.adds_not_stored.update({NEW, "CVE-2026-93640"})
        misp.adds_without_list = True
        status = run(env, nvd, misp, store)
        detail = status["nvd_incremental"]
        assert (detail["added"], detail["failed"]) == (0, 2)
        assert detail["not_written"] == ["CVE-2026-93637", "CVE-2026-93640"]
        assert status["success"] is False and "CVE-2026-93637" in status["error"]
        assert store.writes == []

    def test_slices_are_handled_oldest_first_so_the_cap_loses_nothing(self, env):
        # 3,000 records over three hours make several slices. Newest first, a run that stops at the
        # cap would store the cursor past the older slices it never handled.
        env.setenv("EDGEGUARD_NVD_MAX_PER_RUN", "1000")
        records = []
        for n in range(3000):
            stamp = (datetime(2026, 10, 14, 12, tzinfo=timezone.utc) + timedelta(seconds=3.6 * n)).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            )[:-3]
            records.append(nvd_record(NEW, id=f"CVE-2026-{800000 + n}", published=stamp, lastModified=stamp))
        nvd, misp, store = FakeNvd(records), FakeMisp(), CursorStore("2026-10-14T11:00:00+00:00")
        starts = []
        for _ in range(6):
            first_request = len(nvd.requests)
            status = run(env, nvd, misp, store)
            starts.append([r["lastModStartDate"] for r in nvd.requests[first_request:]])
            if not status["nvd_incremental"]["stopped_at_cap"]:
                break
        assert len(set(misp.added_values())) == 3000
        leaf_starts = starts[0][1:]
        assert leaf_starts == sorted(leaf_starts), "slices are requested oldest first"

    def test_spans_of_a_window_longer_than_120_days_are_handled_oldest_first(self, env):
        # A 250-day lookback is read in three spans. Newest first, a cap reached inside the newest span
        # would store a recent cursor and the record of an older span would never be read.
        env.setenv("EDGEGUARD_NVD_INCREMENTAL_DAYS", "250")
        env.setenv("EDGEGUARD_NVD_MAX_PER_RUN", "1")
        records = []
        for cve_id, days_ago in (("CVE-2026-70001", 200), ("CVE-2026-70002", 10), ("CVE-2026-70003", 9)):
            stamp = (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
            records.append(nvd_record(NEW, id=cve_id, published=stamp, lastModified=stamp))
        nvd, misp, store = FakeNvd(records), FakeMisp(), CursorStore()
        for _ in range(5):
            if not run(env, nvd, misp, store)["nvd_incremental"]["stopped_at_cap"]:
                break
        assert sorted(misp.added_values()) == ["CVE-2026-70001", "CVE-2026-70002", "CVE-2026-70003"]

    def test_a_cap_stop_on_a_record_without_last_modified_keeps_the_cursor_at_the_window_start(self, env):
        env.setenv("EDGEGUARD_NVD_MAX_PER_RUN", "1")
        undated = [nvd_record(NEW, id=f"CVE-2026-9365{n}") for n in (1, 2)]
        for record in undated:
            del record["cve"]["lastModified"]
        nvd, misp, store = FakeNvd(undated), FakeMisp(), CursorStore("2026-10-14T12:00:00+00:00")
        status = run(env, nvd, misp, store)
        assert status["nvd_incremental"]["stopped_at_cap"] is True
        assert store.data[NVD_CURSOR_KEY] == "2026-10-14T11:00:00+00:00", "the window start, not 1970"

    def test_a_record_in_two_slices_is_written_once(self, env):
        record = nvd_record(NEW)
        env.setattr(
            NVDCollector, "_iter_lastmod_slices", lambda self, s, e, b: iter([([record], True), ([record], True)])
        )
        nvd, misp, store = FakeNvd([]), FakeMisp(), CursorStore("2026-10-14T12:00:00+00:00")
        status = run(env, nvd, misp, store)
        assert misp.added_values() == [NEW] and status["nvd_incremental"]["records_read"] == 1

    def test_nvd_unavailable_is_transient_writes_nothing_and_keeps_the_cursor(self, env):
        from collector_failure_alerts import is_transient_external_error

        nvd, misp, store = FakeNvd([nvd_record(NEW)]), FakeMisp(), CursorStore("2026-10-14T12:00:00+00:00")
        nvd.status = 503
        with pytest.raises(nvd_collector.NvdIncrementalUnavailable) as raised:
            run(env, nvd, misp, store)
        assert is_transient_external_error(raised.value), "the DAG skips the task with an alert"
        assert misp.posts == [] and store.writes == []

    def test_an_empty_window_does_not_list_misp(self, env):
        nvd, misp, store = (
            FakeNvd([]),
            FakeMisp([stored_attribute(c) for c in KNOWN]),
            CursorStore("2026-10-14T17:00:00+00:00"),
        )
        status = run(env, nvd, misp, store)
        assert misp.listings() == [] and status["success"] is True and store.data[NVD_CURSOR_KEY] == NOW.isoformat()

    def test_the_listing_asks_for_every_tag(self, env):
        nvd, misp, store = FakeNvd([nvd_record(NEW)]), FakeMisp(), CursorStore("2026-10-14T12:00:00+00:00")
        run(env, nvd, misp, store)
        (listing,) = misp.listings()
        assert (
            listing["includeAllTags"] is True
            and listing["tags"] == ["source:NVD"]
            and listing["type"] == "vulnerability"
        )


# --------------------------------------------------------------------------- baseline and cursor
class TestBaselineSeedsTheCursor:
    def _baseline(self, env, misp, store, checkpoint=None):
        env.setenv("EDGEGUARD_NVD_BASELINE_KEV_SWEEP", "false")
        env.setattr(nvd_collector, "get_source_incremental", store.get)
        env.setattr(nvd_collector, "update_source_incremental", store.update)
        env.setattr(nvd_collector, "get_source_checkpoint", lambda _s: dict(checkpoint or {}))
        env.setattr(nvd_collector, "update_source_checkpoint", lambda *_a, **_k: None)

        def windows(self, pub_start_iso=None, pub_end_iso=None, start_index=0, limit=2000, extra_params=None):
            return (
                [nvd_record(NEW)] if start_index == 0 and pub_end_iso and pub_end_iso.startswith("2026-10-14") else []
            )

        env.setattr(NVDCollector, "_fetch_cves_batch", windows)
        writer = MISPWriter(url="https://misp.test", api_key="test", verify_ssl=True)
        writer.session = misp
        collector = NVDCollector(misp_writer=writer)
        collector.check_service_available = lambda: True
        collector.circuit_breaker = MagicMock()
        return collector.collect(push_to_misp=True, baseline=True, baseline_days=30)

    def test_a_clean_baseline_starts_the_cursor_at_its_own_start(self, env):
        store = CursorStore()
        status = self._baseline(env, FakeMisp(), store)
        assert status["success"] is True and store.data == {NVD_CURSOR_KEY: NOW.isoformat()}

    def test_a_resumed_baseline_starts_the_cursor_where_the_first_attempt_began(self, env):
        store = CursorStore()
        self._baseline(
            env, FakeMisp(), store, checkpoint={"completed": False, "started_at": "2026-10-13T09:00:00+00:00"}
        )
        assert store.data == {NVD_CURSOR_KEY: "2026-10-13T09:00:00+00:00"}

    def test_a_stored_cursor_is_kept(self, env):
        store = CursorStore("2026-10-01T00:00:00+00:00")
        self._baseline(env, FakeMisp(), store)
        assert store.writes == []

    def test_a_failed_push_seeds_nothing(self, env):
        misp, store = FakeMisp(), CursorStore()
        with patch.object(MISPWriter, "push_items", return_value=(0, 1)):
            self._baseline(env, misp, store)
        assert store.writes == []


def test_nvd_applies_its_own_per_run_cap_not_the_incremental_limit(monkeypatch):
    import config

    monkeypatch.setattr(config, "MAX_ENTRIES_PER_SOURCE", 0)
    assert config.get_effective_limit("nvd") is None
    monkeypatch.setattr(config, "MAX_ENTRIES_PER_SOURCE", 50)
    assert config.get_effective_limit("nvd") == 50, "EDGEGUARD_MAX_ENTRIES still applies"


@pytest.mark.parametrize(
    "name, raw, function, expected",
    [
        ("EDGEGUARD_NVD_INCREMENTAL_DAYS", "0", "nvd_incremental_days", 1),
        ("EDGEGUARD_NVD_INCREMENTAL_DAYS", "x", "nvd_incremental_days", 14),
        ("EDGEGUARD_NVD_CURSOR_OVERLAP_SEC", "0", "nvd_cursor_overlap_seconds", 60),
        ("EDGEGUARD_NVD_MAX_PER_RUN", "0", "nvd_max_per_run", 1),
        ("EDGEGUARD_NVD_UPDATE_EXISTING", "no", "nvd_update_existing", False),
    ],
)
def test_settings_are_bounded(monkeypatch, name, raw, function, expected):
    import config

    monkeypatch.setenv(name, raw)
    assert getattr(config, function)() == expected
