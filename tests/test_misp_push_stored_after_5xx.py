"""A batch MISP stored although it answered the push with HTTP 5xx is counted as pushed (2026-11-02).

MISP answers an event edit with the whole event. On the 730-day baseline of 1 Nov 2026 (MISP with a 2 GB PHP
``memory_limit``) every batch pushed to the OTX event past about 148,800 attributes was saved and then
answered HTTP 500 while MISP built that answer. The writer retried each batch four times and paused 300 s,
re-sending data MISP held, and counted 1,857 attributes as failed although MISP had stored 1,854 of them. A
slightly larger OTX window would have failed the collector's success gate.

After a 5xx the writer now looks the batch's values up in the event (``_stored_after_server_error``):

* all stored: the batch counts as pushed, with a ``[STORED-AFTER-5XX]`` warning, and is not sent again;
* some stored: the batch is retried as before, and if every retry fails only the attributes MISP does not
  hold count as failed;
* the lookup fails, or the answer was a 429 or a timeout: the batch is retried as before.

The lookup answer is a real one: ``tests/fixtures/misp_restsearch_by_value_event_2026_11_01.json``, a MISP 2.5
answer to ``attributes/restSearch`` by ``eventid`` and value on that baseline's OTX event, for attributes the
batches answered with 500 had stored. The 500 body is the one MISP sent (the collector's log of 1 Nov 2026).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from collectors import collector_utils
from collectors import misp_writer as mw

FIXTURE = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "misp_restsearch_by_value_event_2026_11_01.json").read_text()
)
EVENT = FIXTURE["event_id"]
BATCH = [dict(a) for a in FIXTURE["batch"]]
STORED_ROWS = FIXTURE["answer"]["response"]["Attribute"]

# MISP's answer to the push (the collector's log of 1 Nov 2026).
ERROR_BODY = (
    '{"name":"An Internal Error Has Occurred.","message":"An Internal Error Has Occurred.","url":"\\/events\\/55"}'
)


class _Resp:
    def __init__(self, status: int, payload=None, text: str = "", headers=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text
        self.headers = headers or {}

    def json(self):
        return self._payload


class _Misp:
    """Answers pushes with ``push_status`` and value lookups from ``rows`` (exact value match, as asked)."""

    def __init__(self, push_status: int = 500, rows=None, lookup_status: int = 200):
        self.push_status = push_status
        self.rows = list(STORED_ROWS if rows is None else rows)
        self.lookup_status = lookup_status
        self.posts: list = []

    def post(self, url, json=None, **_kwargs):
        self.posts.append((url, json))
        if url.endswith("/attributes/restSearch"):
            if self.lookup_status != 200:
                return _Resp(self.lookup_status, text="lookup failed")
            assert json["eventid"] == EVENT and json["returnFormat"] == "json"
            asked = set(json["value"])
            rows = [r for r in self.rows if r["event_id"] == json["eventid"] and r["value"] in asked]
            return _Resp(200, {"response": {"Attribute": rows}})
        if self.push_status == 200:
            return _Resp(200, {"Event": {"id": EVENT, "Attribute": list(self.rows)}})
        return _Resp(self.push_status, text=ERROR_BODY if self.push_status == 500 else "x")

    def pushes(self) -> int:
        return sum(1 for url, _ in self.posts if url.endswith(f"/events/{EVENT}"))

    def lookups(self) -> list:
        return [body for url, body in self.posts if url.endswith("/attributes/restSearch")]


@pytest.fixture
def sleeps(monkeypatch):
    calls: list = []
    # ``mw.time`` and ``collector_utils.time`` are the same module: one patch records every sleep.
    monkeypatch.setattr(mw.time, "sleep", lambda s: calls.append(float(s)))
    assert collector_utils.time is mw.time
    return calls


def _writer(misp: _Misp) -> mw.MISPWriter:
    writer = mw.MISPWriter(url="https://misp.test", api_key="test-key", verify_ssl=True)
    writer.session = misp
    return writer


def test_fixture_is_the_stored_batch():
    """The fixture holds every attribute of the batch, and nothing for the value no event holds."""
    assert len(BATCH) == 4 and len(STORED_ROWS) == 4
    assert {(a["type"], a["value"]) for a in BATCH} == {(r["type"], r["value"]) for r in STORED_ROWS}
    assert "0" * 64 in FIXTURE["request_values"]
    assert all(
        r["event_id"] == EVENT and r["Event"]["info"].startswith("EdgeGuard-alienvault_otx") for r in STORED_ROWS
    )


def test_batch_stored_despite_500_is_pushed_and_not_sent_again(sleeps, caplog):
    misp = _Misp()
    writer = _writer(misp)
    with caplog.at_level(logging.WARNING, logger="collectors.misp_writer"):
        assert writer._push_batch(EVENT, BATCH) == (4, 0)
    assert misp.pushes() == 1, "no retry of a batch MISP holds"
    (lookup,) = misp.lookups()
    assert lookup["eventid"] == EVENT
    assert {a["value"] for a in BATCH} <= set(lookup["value"])
    assert [s for s in sleeps if s >= 10.0] == [], "no backoff"
    assert writer.stats["batches_stored_after_5xx"] == 1
    assert writer.stats["attributes_added"] == 4 and writer.stats["batches_sent"] == 1
    assert writer.stats["errors"] == 0
    (warning,) = [r for r in caplog.records if "[STORED-AFTER-5XX]" in r.getMessage()]
    assert warning.levelno == logging.WARNING
    assert "HTTP 500" in warning.getMessage() and f"event {EVENT}" in warning.getMessage()


def test_upper_case_hashes_are_confirmed_by_their_stored_lower_case(sleeps):
    """MISP stores hashes in lower case; a batch that sent them in upper case is still found."""
    misp = _Misp()
    batch = [dict(a, value=a["value"].upper()) if a["type"] in ("md5", "sha256") else dict(a) for a in BATCH]
    assert batch != BATCH
    assert _writer(misp)._push_batch(EVENT, batch) == (4, 0)
    asked = set(misp.lookups()[0]["value"])
    assert {a["value"].lower() for a in batch if a["type"] != "threat-actor"} <= asked
    assert "Water Barghest" in asked and "water barghest" not in asked, "case kept for a type MISP keeps"


def test_partly_stored_batch_is_retried_and_reports_what_misp_holds(sleeps):
    md5 = next(r for r in STORED_ROWS if r["type"] == "md5")
    misp = _Misp(rows=[r for r in STORED_ROWS if r is not md5])
    writer = _writer(misp)
    with pytest.raises(mw.MispTransientError) as raised:
        writer._push_batch(EVENT, BATCH)
    assert misp.pushes() == 4, "first attempt + 3 retries"
    assert len(misp.lookups()) == 4, "each 5xx is looked up"
    assert [s for s in sleeps if s >= 10.0] == [10.0, 20.0, 40.0]
    stored, unstored = raised.value.stored_after_error
    assert stored == 3
    assert unstored == [a for a in BATCH if a["type"] == "md5"]
    assert writer.stats["batches_stored_after_5xx"] == 0


def test_value_misp_does_not_hold_is_unstored():
    misp = _Misp()
    absent = {"type": "sha256", "value": "0" * 64}
    stored, unstored = _writer(misp)._stored_after_server_error(EVENT, BATCH + [absent])
    assert stored == 4 and unstored == [absent]


def test_failed_lookup_retries_the_batch_as_before(sleeps, caplog):
    misp = _Misp(lookup_status=500)
    writer = _writer(misp)
    with caplog.at_level(logging.WARNING, logger="collectors.misp_writer"):
        with pytest.raises(mw.MispTransientError) as raised:
            mw.MISPWriter._push_batch.__wrapped__(writer, EVENT, BATCH)
    assert raised.value.stored_after_error is None, "nothing known about the batch"
    assert len(misp.lookups()) == 3, "the lookup's own three attempts"
    assert any("lookup of the batch after the server error failed" in r.getMessage() for r in caplog.records)


def test_rate_limit_is_not_looked_up(sleeps):
    misp = _Misp(push_status=429)
    with pytest.raises(mw.MispTransientError) as raised:
        mw.MISPWriter._push_batch.__wrapped__(_writer(misp), EVENT, BATCH)
    assert misp.lookups() == [], "a 429 stored nothing"
    assert raised.value.stored_after_error is None


def test_400_is_still_permanent_and_not_looked_up(sleeps):
    misp = _Misp(push_status=400)
    writer = _writer(misp)
    assert mw.MISPWriter._push_batch.__wrapped__(writer, EVENT, BATCH) == (0, 4)
    assert misp.lookups() == []


def _push_items(monkeypatch, misp: _Misp, caplog):
    writer = _writer(misp)
    monkeypatch.setattr(writer, "_get_or_create_event", lambda *a, **k: EVENT)
    monkeypatch.setattr(writer, "_get_existing_attribute_keys", lambda *a, **k: set())
    monkeypatch.setattr(writer, "_get_existing_source_attribute_keys", lambda *a, **k: set())
    monkeypatch.setattr(writer, "_find_event_id", lambda *a, **k: None)
    by_value = {a["value"]: a for a in BATCH}
    monkeypatch.setattr(writer, "create_attribute", lambda item: dict(by_value[item["value"]]))
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    items = [{"indicator_type": a["type"], "value": a["value"], "tag": "alienvault_otx"} for a in BATCH]
    with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
        result = writer.push_items(items, batch_size=10)
    return writer, result


def test_push_counts_a_batch_misp_stored_despite_500_as_pushed(monkeypatch, sleeps, caplog):
    misp = _Misp()
    writer, result = _push_items(monkeypatch, misp, caplog)
    assert result == (4, 0)
    assert misp.pushes() == 1
    assert writer.last_push_unstored_items == []
    assert writer.__dict__.get("_misp_push_consecutive_failures", 0) == 0, "no cooldown for a stored batch"
    (summary,) = [r.getMessage() for r in caplog.records if "MISP push complete" in r.getMessage()]
    assert "4 succeeded, 0 failed" in summary
    assert "1 batch(es) stored although MISP answered HTTP 5xx ([STORED-AFTER-5XX])" in summary


def test_push_counts_only_what_misp_lacks_after_the_retries(monkeypatch, sleeps, caplog):
    md5 = next(r for r in STORED_ROWS if r["type"] == "md5")
    misp = _Misp(rows=[r for r in STORED_ROWS if r is not md5])
    writer, result = _push_items(monkeypatch, misp, caplog)
    assert result == (3, 1)
    md5_position = next(i for i, a in enumerate(BATCH) if a["type"] == "md5")
    assert writer.last_push_unstored_items == [md5_position]
    assert writer.stats["attributes_added"] == 3
    assert writer.stats["errors"] == 1
    assert any("1 of 4 attribute(s) counted as failed" in r.getMessage() for r in caplog.records)
    (summary,) = [r.getMessage() for r in caplog.records if "MISP push complete" in r.getMessage()]
    assert "3 succeeded, 1 failed" in summary and "STORED-AFTER-5XX" not in summary


def test_push_counts_the_whole_batch_when_nothing_is_known(monkeypatch, sleeps, caplog):
    misp = _Misp(lookup_status=503)
    writer, result = _push_items(monkeypatch, misp, caplog)
    assert result == (0, 4)
    assert writer.last_push_unstored_items == [0, 1, 2, 3]
    assert writer.stats["attributes_added"] == 0
