"""Large MISP events are fetched in pages instead of one ``/events/view`` (2026-10).

On 2026-10-24 prod MISP answered HTTP 500 ("An Internal Error Has Occurred.") to every
``/events/view/203`` of a 145k-attribute NVD event, about 550 MB of JSON. The sync retried,
deferred the event, retried again and then failed the whole run, so ``build_relationships`` and
the enrichment jobs never ran. ``/attributes/restSearch`` with ``page`` / ``limit`` answered the
same event in 30 pages of 5000 in under three minutes.

Pinned here:

* ``fetch_event_details_paged`` builds the event from ``/events/restSearch`` metadata plus paged
  ``/attributes/restSearch``, keeps only top-level attributes (as ``/events/view`` lists them) and
  drops the ``Event`` copy restSearch adds to each attribute.
* Paging stops on a short page, and on a page with no new attribute (MISP ignored ``page``).
* ``_process_single_event`` pages events whose index ``attribute_count`` is over
  ``EDGEGUARD_MISP_PAGED_FETCH_ABOVE`` (default 20000, ``0`` = off), and falls back to pages when
  the whole-event fetch still answers 5xx after its retries.
* ``_misp_post_json`` retries 5xx and raises 4xx as permanent.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import run_misp_to_neo4j  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync, MispTransientServerError  # noqa: E402

_META = {"response": [{"Event": {"id": "203", "info": "EdgeGuard-nvd-2026-10-22", "Tag": [{"name": "EdgeGuard"}]}}]}


def _attr(n, object_id="0"):
    return {"uuid": f"u{n}", "value": f"CVE-2026-{n:05d}", "object_id": object_id, "Event": {"id": "203"}}


def _syncer(pages, page_size=2):
    """A sync whose ``_misp_post_json`` answers the metadata and then ``pages`` in order."""
    syncer = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    syncer._ATTR_PAGE_SIZE = page_size
    syncer.calls = []

    def post(path, body):
        syncer.calls.append((path, dict(body)))
        if path == "/events/restSearch":
            return _META
        page = body["page"]
        return {"response": {"Attribute": pages[page - 1] if page <= len(pages) else []}}

    syncer._misp_post_json = post
    return syncer


def test_paged_fetch_builds_the_event_from_metadata_and_attribute_pages():
    syncer = _syncer([[_attr(1), _attr(2)], [_attr(3), _attr(4, object_id="12")], [_attr(5)]])
    event = syncer.fetch_event_details_paged("203")
    assert event["info"] == "EdgeGuard-nvd-2026-10-22"
    assert [t["name"] for t in event["Tag"]] == ["EdgeGuard"]
    # Object attribute u4 is left out, as /events/view lists it under Object, not Attribute.
    assert [a["uuid"] for a in event["Attribute"]] == ["u1", "u2", "u3", "u5"]
    assert all("Event" not in a for a in event["Attribute"])
    assert syncer.calls[0] == ("/events/restSearch", {"eventid": "203", "metadata": True, "returnFormat": "json"})
    assert [body["page"] for path, body in syncer.calls[1:]] == [1, 2, 3]
    assert all(body["eventid"] == "203" and body["limit"] == 2 for _, body in syncer.calls[1:])


def test_paged_fetch_stops_when_misp_ignores_the_page_parameter():
    page = [_attr(1), _attr(2)]
    syncer = _syncer([page, page, page, page])
    event = syncer.fetch_event_details_paged("203")
    assert [a["uuid"] for a in event["Attribute"]] == ["u1", "u2"]
    assert len(syncer.calls) == 3  # metadata, page 1, page 2 (nothing new: stop)


def test_paged_fetch_returns_none_when_misp_lists_no_event():
    syncer = _syncer([])
    syncer._misp_post_json = lambda path, body: {"response": []}
    assert syncer.fetch_event_details_paged("999") is None


def _routing_syncer():
    syncer = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    syncer.stats = {"events_processed": 0, "events_failed": 0}
    syncer.fetched = []
    syncer.fetch_event_details = lambda event_id: syncer.fetched.append("whole")
    syncer.fetch_event_details_paged = lambda event_id: syncer.fetched.append("paged")
    return syncer


@pytest.mark.parametrize(
    "env, attribute_count, expected",
    [
        (None, 145261, ["paged"]),
        (None, 20000, ["whole"]),
        (None, 0, ["whole"]),
        ("1000", 1001, ["paged"]),
        ("0", 145261, ["whole"]),
    ],
)
def test_process_single_event_pages_events_over_the_threshold(monkeypatch, env, attribute_count, expected):
    if env is None:
        monkeypatch.delenv("EDGEGUARD_MISP_PAGED_FETCH_ABOVE", raising=False)
    else:
        monkeypatch.setenv("EDGEGUARD_MISP_PAGED_FETCH_ABOVE", env)
    syncer = _routing_syncer()
    # Both fakes return None: the event is counted as failed, which ends the call after the fetch.
    assert syncer._process_single_event("203", "EdgeGuard-nvd", attribute_count) == (0, 0, 1)
    assert syncer.fetched == expected


def test_process_single_event_falls_back_to_pages_after_a_5xx_whole_fetch(monkeypatch):
    monkeypatch.delenv("EDGEGUARD_MISP_PAGED_FETCH_ABOVE", raising=False)
    syncer = _routing_syncer()

    def whole(event_id):
        syncer.fetched.append("whole")
        raise MispTransientServerError("MISP 500 fetching event 203", response=MagicMock(status_code=500))

    syncer.fetch_event_details = whole
    syncer._process_single_event("203", "EdgeGuard-nvd", 100)
    assert syncer.fetched == ["whole", "paged"]


def test_every_call_site_passes_the_index_attribute_count():
    src = (SRC / "run_misp_to_neo4j.py").read_text()
    assert len(re.findall(r"self\._process_single_event\(", src)) == 3
    assert src.count("self._process_single_event(str(event_id), event_info, _event_sort_key(event))") == 3


def _response(status, payload=None):
    response = MagicMock(status_code=status)
    response.json.return_value = payload
    if status >= 400:
        response.raise_for_status.side_effect = requests.exceptions.HTTPError(f"{status}")
    return response


def test_post_json_retries_5xx_and_raises_4xx(monkeypatch):
    monkeypatch.setattr(run_misp_to_neo4j.time, "sleep", lambda s: None)
    syncer = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    syncer.misp_url = "https://misp.example"
    syncer.session = MagicMock()
    syncer.session.post.side_effect = [_response(502), _response(200, {"response": []})]
    assert syncer._misp_post_json("/events/restSearch", {"eventid": "1"}) == {"response": []}
    assert syncer.session.post.call_count == 2

    syncer.session.post.reset_mock()
    syncer.session.post.side_effect = [_response(403)]
    with pytest.raises(requests.exceptions.HTTPError):
        syncer._misp_post_json("/events/restSearch", {"eventid": "1"})
    assert syncer.session.post.call_count == 1
