"""Large MISP events are fetched in pages instead of one ``/events/view`` (2026-10).

On 2026-10-24 the hosted MISP answered HTTP 500 ("An Internal Error Has Occurred.") to every
``/events/view/203`` of a 145k-attribute NVD event, about 550 MB of JSON. The sync retried,
deferred the event, retried again and then failed the whole run, so ``build_relationships`` and
the enrichment jobs never ran. ``/attributes/restSearch`` with ``page`` / ``limit`` answered the
same event in 30 pages of 5000 in under three minutes.

Pinned here:

* The paged event reads as the ``/events/view`` form of the same event does: ``parse_attribute``
  returns the same items and the creator-organisation trust check (``Orgc``) decides the same. The
  fixtures are shaped like MISP's answers (``/events/view``; ``/events/restSearch`` with
  ``metadata``, ``Org``, ``Orgc`` and ``Tag``; ``/attributes/restSearch`` rows with their ``Event``
  sub-dict and ``Tag``) around real NVD attributes of the hosted MISP
  (``tests/test_cvss_real_payloads.json``, event 138).
* Only top-level attributes are kept (as ``/events/view`` lists them under ``Attribute``), and the
  ``Event`` copy restSearch adds to each attribute is dropped. The objects of the object rows are
  listed under ``Object`` by id, so an event holding its attributes only in objects is warned about
  on both fetch paths.
* Paging sends ``order: Attribute.id`` and stops only on an empty page or a page with nothing new
  (MISP ignored ``page``). MISP removes rows after applying the limit (Allowedlist entries, the
  account's default search filters), so a short page in the middle does not end the listing.
* Fewer rows (top-level and object rows) than the index ``attribute_count`` log a
  ``[PAGED-FETCH-INCOMPLETE]`` warning naming the event and both counts and are counted in the run
  summary once per event, also when the retry pass fetches the event again; the run does not fail
  for it.
* ``run()`` hands each event's index ``attribute_count`` to the fetch: an event over
  ``EDGEGUARD_MISP_PAGED_FETCH_ABOVE`` (default 20000, ``0`` = off) goes to the paged fetch with its
  count on the first pass, among the deferred large events and in the retry pass; a whole-event
  fetch that still answers 5xx after its retries falls back to pages.
* ``_misp_post_json`` retries 5xx and raises 4xx as permanent.
"""

from __future__ import annotations

import copy
import json
import logging
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
import source_trust  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync, MispTransientServerError, misp_event_object_to_event_dict  # noqa: E402

SYNC_LOGGER = run_misp_to_neo4j.logger.name

# ---------------------------------------------------------------------------
# One event in the three shapes MISP answers it in
# ---------------------------------------------------------------------------

_PAYLOADS = json.loads((Path(__file__).resolve().parent / "test_cvss_real_payloads.json").read_text())["misp"]
# The NVD attributes of event 138 ("EdgeGuard-nvd-2026-10-13") as the hosted MISP held them on 2026-10-14.
_NVD_138 = [
    {k: v for k, v in attr.items() if k != "_event"} for attr in _PAYLOADS.values() if attr["event_id"] == "138"
]

EVENT_ID = "138"
EVENT_UUID = "8c0f6a2e-4d1b-4e7a-b3c9-1f2e3d4c5b6a"
ORGC = {"id": "1", "name": "EdgeGuard", "uuid": "5f1c9a3e-2b7d-4c1e-9a8f-3d2e1b0c4a5f", "local": True}
OTHER_ORG_UUID = "99999999-9999-4999-8999-999999999999"

# The ``Event`` columns ``/events/view`` and ``/events/restSearch`` both return.
EVENT_FIELDS = {
    "id": EVENT_ID,
    "orgc_id": "1",
    "org_id": "1",
    "date": "2026-10-13",
    "threat_level_id": "3",
    "info": "EdgeGuard-nvd-2026-10-13",
    "published": False,
    "uuid": EVENT_UUID,
    "attribute_count": str(len(_NVD_138) + 1),
    "analysis": "0",
    "timestamp": "1791908321",
    "distribution": "1",
    "proposal_email_lock": False,
    "locked": False,
    "publish_timestamp": "0",
    "sharing_group_id": "0",
    "disable_correlation": False,
    "extends_uuid": "",
    "protected": None,
}

_TAG_IDS: dict = {}


def _full_tag(name: str) -> dict:
    """A tag as ``/events/view`` and the event metadata list it."""
    tag_id = _TAG_IDS.setdefault(name, str(len(_TAG_IDS) + 1))
    return {
        "id": tag_id,
        "name": name,
        "colour": "#0088cc",
        "exportable": True,
        "user_id": "0",
        "hide_tag": False,
        "numerical_value": None,
        "is_galaxy": False,
        "is_custom_galaxy": False,
        "local_only": False,
        "local": 0,
        "relationship_type": None,
    }


def _search_tag(name: str) -> dict:
    """A tag as ``/attributes/restSearch`` lists it (``Attribute::attachTagsToAttributes``)."""
    full = _full_tag(name)
    return {k: full[k] for k in ("id", "name", "colour", "numerical_value", "is_galaxy", "local")}


def _attribute_columns(n: int, attr: dict, object_id: str = "0", object_relation=None) -> dict:
    return {
        "id": str(5000 + n),
        "type": attr["type"],
        "category": attr["category"],
        "to_ids": attr["to_ids"],
        "uuid": attr["uuid"],
        "event_id": EVENT_ID,
        "distribution": "5",
        "timestamp": attr["timestamp"],
        "comment": attr["comment"],
        "sharing_group_id": "0",
        "deleted": False,
        "disable_correlation": False,
        "object_id": object_id,
        "object_relation": object_relation,
        "first_seen": attr["first_seen"],
        "last_seen": attr["last_seen"],
        "value": attr["value"],
    }


# A MISP object in the event: ``/events/view`` lists its attribute under ``Object``, not ``Attribute``.
_OBJECT_ATTR = {
    "type": "ip-dst",
    "category": "Network activity",
    "to_ids": True,
    "uuid": "3b1d2c4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e",
    "timestamp": "1791908400",
    "comment": "",
    "first_seen": None,
    "last_seen": None,
    "value": "203.0.113.7",
    "Tag": [],
}
_OBJECT_ID = "12"


def _view_body() -> dict:
    """``/events/view/138``: the event with its attributes, objects and tags."""
    attributes = [
        {
            **_attribute_columns(n, a),
            "Galaxy": [],
            "ShadowAttribute": [],
            "Tag": [_full_tag(t["name"]) for t in a["Tag"]],
        }
        for n, a in enumerate(_NVD_138)
    ]
    obj_attr = {
        **_attribute_columns(len(_NVD_138), _OBJECT_ATTR, _OBJECT_ID, "ip"),
        "Galaxy": [],
        "ShadowAttribute": [],
    }
    obj = {
        "id": _OBJECT_ID,
        "name": "domain-ip",
        "meta-category": "network",
        "template_version": "11",
        "event_id": EVENT_ID,
        "uuid": "7e6d5c4b-3a29-4817-9605-f4e3d2c1b0a9",
        "timestamp": "1791908400",
        "distribution": "5",
        "sharing_group_id": "0",
        "comment": "",
        "deleted": False,
        "first_seen": None,
        "last_seen": None,
        "ObjectReference": [],
        "Attribute": [obj_attr],
    }
    return {
        "Event": {
            **EVENT_FIELDS,
            "Org": dict(ORGC),
            "Orgc": dict(ORGC),
            "Attribute": attributes,
            "ShadowAttribute": [],
            "RelatedEvent": [],
            "Galaxy": [],
            "Object": [obj],
            "EventReport": [],
            "CryptographicKey": [],
            "Tag": [_full_tag("EdgeGuard")],
        }
    }


def _metadata_body() -> dict:
    """``/events/restSearch`` with ``metadata``: the event without ``Attribute`` / ``Object``."""
    return {
        "response": [
            {
                "Event": {
                    **EVENT_FIELDS,
                    "Org": dict(ORGC),
                    "Orgc": dict(ORGC),
                    "Tag": [_full_tag("EdgeGuard")],
                    "Galaxy": [],
                }
            }
        ]
    }


def _search_rows() -> list:
    """``/attributes/restSearch`` rows of event 138 in id order (``flatten``: object rows included)."""
    parent = {
        "org_id": "1",
        "distribution": "1",
        "publish_timestamp": "0",
        "id": EVENT_ID,
        "info": EVENT_FIELDS["info"],
        "orgc_id": "1",
        "uuid": EVENT_UUID,
        "user_id": "1",
    }
    rows = [
        {**_attribute_columns(n, a), "Event": dict(parent), "Tag": [_search_tag(t["name"]) for t in a["Tag"]]}
        for n, a in enumerate(_NVD_138)
    ]
    rows.append(
        {
            **_attribute_columns(len(_NVD_138), _OBJECT_ATTR, _OBJECT_ID, "ip"),
            "Event": dict(parent),
            "Object": {"id": _OBJECT_ID, "distribution": "5", "sharing_group_id": "0"},
        }
    )
    return rows


class _FakeMisp:
    """``_misp_post_json`` of a MISP holding ``rows`` for one event.

    ``/attributes/restSearch`` applies ``limit`` and ``page`` as MISP's ``__iteratedFetch`` does
    (LIMIT, OFFSET) and then removes the rows whose uuid is in ``removed`` from the page, as MISP's
    Allowedlist does after the LIMIT. ``ignores_page`` answers page 1 to every request.
    """

    def __init__(self, rows, meta=None, removed=(), ignores_page=False):
        self.rows = rows
        self.meta = meta if meta is not None else _metadata_body()
        self.removed = set(removed)
        self.ignores_page = ignores_page
        self.calls: list = []

    def __call__(self, path, body):
        self.calls.append((path, dict(body)))
        if path == "/events/restSearch":
            return copy.deepcopy(self.meta)
        assert path == "/attributes/restSearch", path
        limit = body["limit"]
        page = 1 if self.ignores_page else body["page"]
        chunk = self.rows[(page - 1) * limit : page * limit]
        return {"response": {"Attribute": [copy.deepcopy(r) for r in chunk if r["uuid"] not in self.removed]}}

    def attribute_bodies(self):
        return [body for path, body in self.calls if path == "/attributes/restSearch"]


def _paged_syncer(fake: _FakeMisp, page_size: int = 3) -> MISPToNeo4jSync:
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    syncer._ATTR_PAGE_SIZE = page_size
    syncer._misp_post_json = fake
    return syncer


def _synthetic_rows(n: int) -> list:
    return [
        {"uuid": f"u{i}", "value": f"CVE-2026-{i:05d}", "object_id": "0", "Event": {"id": EVENT_ID}}
        for i in range(1, n + 1)
    ]


# ---------------------------------------------------------------------------
# The paged event reads as the /events/view event does
# ---------------------------------------------------------------------------


def _parse_all(event: dict) -> list:
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    return [syncer.parse_attribute(attr, event) for attr in event["Attribute"]]


@pytest.mark.parametrize(
    "allowlist, expected",
    [
        (None, (True, source_trust.TRUST_REASON_DISABLED)),
        (ORGC["uuid"], (True, source_trust.TRUST_REASON_UUID_MATCH)),
        (OTHER_ORG_UUID, (False, source_trust.TRUST_REASON_NOT_ALLOWLISTED)),
    ],
)
def test_paged_event_parses_and_is_trusted_as_the_events_view_event(monkeypatch, allowlist, expected):
    if allowlist is None:
        monkeypatch.delenv("EDGEGUARD_TRUSTED_MISP_ORG_UUIDS", raising=False)
    else:
        monkeypatch.setenv("EDGEGUARD_TRUSTED_MISP_ORG_UUIDS", allowlist)
    monkeypatch.delenv("EDGEGUARD_TRUSTED_MISP_ORG_NAMES", raising=False)
    source_trust._reload_env()

    view_event = misp_event_object_to_event_dict(_view_body())
    fake = _FakeMisp(_search_rows())
    paged_event = _paged_syncer(fake).fetch_event_details_paged(EVENT_ID, len(_NVD_138) + 1)

    assert [a["uuid"] for a in paged_event["Attribute"]] == [a["uuid"] for a in view_event["Attribute"]]
    assert paged_event["Orgc"] == view_event["Orgc"] and paged_event["Tag"] == view_event["Tag"]
    assert source_trust.is_attribute_creator_trusted(paged_event) == expected
    assert source_trust.is_attribute_creator_trusted(view_event) == expected

    paged_items = _parse_all(paged_event)
    view_items = _parse_all(view_event)
    assert all(item is not None for item, _rels in view_items), "every NVD attribute of event 138 parses"
    assert paged_items == view_items


def test_trust_dates_differ_between_trusted_and_refused_creator(monkeypatch):
    """The parity above is not vacuous: the creator decision changes what ``parse_attribute`` returns."""
    monkeypatch.delenv("EDGEGUARD_TRUSTED_MISP_ORG_NAMES", raising=False)
    results = []
    for allowlist in (ORGC["uuid"], OTHER_ORG_UUID):
        monkeypatch.setenv("EDGEGUARD_TRUSTED_MISP_ORG_UUIDS", allowlist)
        source_trust._reload_env()
        event = _paged_syncer(_FakeMisp(_search_rows())).fetch_event_details_paged(EVENT_ID, len(_NVD_138) + 1)
        results.append(_parse_all(event))
    assert results[0] != results[1]


def test_paged_event_keeps_top_level_attributes_without_the_event_copy():
    fake = _FakeMisp(_search_rows())
    event = _paged_syncer(fake).fetch_event_details_paged(EVENT_ID, len(_NVD_138) + 1)
    assert event["info"] == "EdgeGuard-nvd-2026-10-13"
    assert [t["name"] for t in event["Tag"]] == ["EdgeGuard"]
    # The object attribute is left out, as /events/view lists it under Object, not Attribute.
    assert _OBJECT_ATTR["uuid"] not in {a["uuid"] for a in event["Attribute"]}
    assert len(event["Attribute"]) == len(_NVD_138)
    assert all("Event" not in a for a in event["Attribute"])
    assert fake.calls[0] == ("/events/restSearch", {"eventid": EVENT_ID, "metadata": True, "returnFormat": "json"})


def test_paged_event_lists_the_objects_of_its_object_rows():
    """``/events/restSearch`` metadata has no ``Object``; the object rows of the pages name them."""
    event = _paged_syncer(_FakeMisp(_search_rows())).fetch_event_details_paged(EVENT_ID, len(_NVD_138) + 1)
    view_event = misp_event_object_to_event_dict(_view_body())
    assert [o["id"] for o in event["Object"]] == [o["id"] for o in view_event["Object"]] == [_OBJECT_ID]


def test_paged_event_without_object_rows_lists_no_object():
    event = _paged_syncer(_FakeMisp(_synthetic_rows(3)), page_size=2).fetch_event_details_paged(EVENT_ID, 3)
    assert not event.get("Object")


@pytest.mark.parametrize("attribute_count, paged", [(1, False), (30000, True)])
def test_an_event_holding_only_object_attributes_is_warned_on_both_fetch_paths(
    monkeypatch, caplog, attribute_count, paged
):
    """The same event, fetched whole (``/events/view``) or in pages, logs the same MISP Object warning."""
    monkeypatch.delenv("EDGEGUARD_MISP_PAGED_FETCH_ABOVE", raising=False)
    fake = _FakeMisp([_search_rows()[-1]])
    syncer = _paged_syncer(fake)
    view = _view_body()
    view["Event"]["Attribute"] = []
    syncer.fetch_event_details = lambda event_id: misp_event_object_to_event_dict(copy.deepcopy(view))
    with caplog.at_level(logging.WARNING, logger=SYNC_LOGGER):
        assert syncer._process_single_event(EVENT_ID, EVENT_FIELDS["info"], attribute_count) == (0, 0, 0)
    assert bool(fake.calls) is paged
    warnings = [r.getMessage() for r in caplog.records if "but no top-level Attribute list" in r.getMessage()]
    assert len(warnings) == 1 and warnings[0].startswith(f"Event {EVENT_ID} has 1 MISP Object(s)"), warnings
    assert syncer.stats["events_processed"] == 1 and syncer.stats["events_failed"] == 0


# ---------------------------------------------------------------------------
# Paging: order, stop condition, completeness
# ---------------------------------------------------------------------------


def test_attribute_pages_are_requested_in_attribute_id_order():
    fake = _FakeMisp(_synthetic_rows(5))
    _paged_syncer(fake, page_size=2).fetch_event_details_paged(EVENT_ID, 5)
    bodies = fake.attribute_bodies()
    assert bodies and all(body["order"] == "Attribute.id" for body in bodies), bodies
    assert all(body["eventid"] == EVENT_ID and body["limit"] == 2 for body in bodies)
    assert all(body["returnFormat"] == "json" for body in bodies)


def test_paging_ends_on_the_first_empty_page():
    fake = _FakeMisp(_synthetic_rows(5))
    event = _paged_syncer(fake, page_size=2).fetch_event_details_paged(EVENT_ID, 5)
    assert [a["uuid"] for a in event["Attribute"]] == ["u1", "u2", "u3", "u4", "u5"]
    # Pages 1-2 are full, page 3 short (one row) and page 4 empty: a short page does not end the listing.
    assert [body["page"] for body in fake.attribute_bodies()] == [1, 2, 3, 4]


def test_a_short_page_in_the_middle_does_not_end_the_listing():
    """MISP removes an Allowedlisted row from page 1 after the LIMIT; pages 2 and 3 still hold rows."""
    rows = _synthetic_rows(7)
    fake = _FakeMisp(rows, removed={"u2"})
    event = _paged_syncer(fake, page_size=3).fetch_event_details_paged(EVENT_ID, 0)
    assert [a["uuid"] for a in event["Attribute"]] == ["u1", "u3", "u4", "u5", "u6", "u7"]
    assert [body["page"] for body in fake.attribute_bodies()] == [1, 2, 3, 4]


def test_paging_stops_when_misp_ignores_the_page_parameter():
    fake = _FakeMisp(_synthetic_rows(2), ignores_page=True)
    event = _paged_syncer(fake, page_size=2).fetch_event_details_paged(EVENT_ID, 2)
    assert [a["uuid"] for a in event["Attribute"]] == ["u1", "u2"]
    assert len(fake.calls) == 3  # metadata, page 1, page 2 (nothing new: stop)


def test_paged_fetch_returns_none_when_misp_lists_no_event():
    fake = _FakeMisp([], meta={"response": []})
    assert _paged_syncer(fake).fetch_event_details_paged("999", 10) is None


def _incomplete_records(caplog):
    """The per-event warnings (the run summary line names the tag too, but does not start with it)."""
    return [r for r in caplog.records if r.getMessage().startswith("[PAGED-FETCH-INCOMPLETE]")]


def test_fewer_rows_than_the_index_count_are_warned_and_counted(caplog):
    """Object rows count: the index ``attribute_count`` holds top-level and object attributes."""
    rows = _search_rows()  # 7 top-level rows and 1 object row, index attribute_count 8
    removed = rows[4]["uuid"]
    syncer = _paged_syncer(_FakeMisp(rows, removed={removed}), page_size=3)
    with caplog.at_level(logging.WARNING, logger=SYNC_LOGGER):
        event = syncer.fetch_event_details_paged(EVENT_ID, len(rows))
    assert len(event["Attribute"]) == len(_NVD_138) - 1
    records = _incomplete_records(caplog)
    assert len(records) == 1 and records[0].levelno == logging.WARNING
    message = records[0].getMessage()
    assert f"Event {EVENT_ID}" in message and f"{len(rows) - 1} attribute rows" in message
    assert f"index lists {len(rows)}" in message, message
    assert syncer.stats["events_paged_incomplete"] == 1


@pytest.mark.parametrize("attribute_count", [0, 8, 6])
def test_no_completeness_warning_when_every_listed_row_arrived(caplog, attribute_count):
    """All 8 rows (object row included) arrived; 0 is an unknown count, 6 an event that grew since the index."""
    syncer = _paged_syncer(_FakeMisp(_search_rows()), page_size=3)
    with caplog.at_level(logging.WARNING, logger=SYNC_LOGGER):
        syncer.fetch_event_details_paged(EVENT_ID, attribute_count)
    assert _incomplete_records(caplog) == []
    assert syncer.stats.get("events_paged_incomplete", 0) == 0


# ---------------------------------------------------------------------------
# run(): the index attribute_count reaches the fetch
# ---------------------------------------------------------------------------


@pytest.fixture
def run_env(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_RETRY_COOLDOWN_SEC", "0")
    monkeypatch.delenv("EDGEGUARD_MISP_PAGED_FETCH_ABOVE", raising=False)
    monkeypatch.delenv("EDGEGUARD_MAX_EVENT_ATTRIBUTES", raising=False)
    monkeypatch.setattr(run_misp_to_neo4j.time, "sleep", lambda *_a, **_k: None)
    outcomes: dict = {"success": 0, "failure": []}
    monkeypatch.setattr(
        run_misp_to_neo4j,
        "record_collection_success",
        lambda *_a, **_k: outcomes.__setitem__("success", outcomes["success"] + 1),
    )
    monkeypatch.setattr(
        run_misp_to_neo4j, "record_collection_failure", lambda _source, msg=None: outcomes["failure"].append(msg)
    )
    run_misp_to_neo4j.INDEX_FETCH_STATE["truncated"] = False
    yield outcomes
    run_misp_to_neo4j.INDEX_FETCH_STATE["truncated"] = False


def _run_sync(monkeypatch, events):
    """The real ``run()`` and ``_process_single_event`` over index rows ``events``; MISP is faked below them."""
    sync = MISPToNeo4jSync(neo4j_client=MagicMock())
    monkeypatch.setattr(sync, "check_services_available", lambda: (True, "ok"))
    monkeypatch.setattr(sync, "connect", lambda: True)
    monkeypatch.setattr(sync, "fetch_edgeguard_events", lambda since=None, sector=None: [dict(e) for e in events])
    return sync


# Index rows as ``/events/index`` lists them (``attribute_count`` is a string).
_INDEX = [
    {"id": "151", "info": "EdgeGuard-mitre_attck-2026-10-13", "attribute_count": "1200"},
    {"id": "150", "info": "EdgeGuard-alienvault_otx-2026-10-13", "attribute_count": "30000"},
    {"id": "203", "info": "EdgeGuard-nvd-2026-10-22", "attribute_count": "145261"},
]


def _recording_fetches(monkeypatch, sync, fail_paged_once=()):
    whole: list = []
    paged: list = []
    failed: set = set()

    def fetch_whole(event_id):
        whole.append(event_id)
        return {"id": event_id, "info": "x", "Attribute": []}

    def fetch_paged(event_id, attribute_count=None):
        paged.append((event_id, attribute_count))
        if event_id in fail_paged_once and event_id not in failed:
            failed.add(event_id)
            raise MispTransientServerError(f"MISP 502 on /attributes/restSearch for event {event_id}")
        return {"id": event_id, "info": "x", "Attribute": []}

    monkeypatch.setattr(sync, "fetch_event_details", fetch_whole)
    monkeypatch.setattr(sync, "fetch_event_details_paged", fetch_paged)
    return whole, paged


def test_run_pages_events_over_the_threshold_with_their_index_count(monkeypatch, run_env):
    """145261 attributes: deferred as a large event (> 50000), then fetched in pages with its count."""
    sync = _run_sync(monkeypatch, _INDEX)
    whole, paged = _recording_fetches(monkeypatch, sync)
    assert sync.run(incremental=False) is True
    assert whole == ["151"]
    assert paged == [("150", 30000), ("203", 145261)]
    assert sync.stats["events_processed"] == 3 and sync.stats["events_failed"] == 0


def test_the_retry_pass_pages_with_the_index_count_too(monkeypatch, run_env):
    sync = _run_sync(monkeypatch, _INDEX)
    whole, paged = _recording_fetches(monkeypatch, sync, fail_paged_once={"150", "203"})
    assert sync.run(incremental=False) is True
    assert whole == ["151"]
    assert paged == [("150", 30000), ("203", 145261), ("150", 30000), ("203", 145261)]
    assert sync.stats["events_processed"] == 3 and sync.stats["events_failed"] == 0


def test_an_incomplete_paged_event_is_summarised_without_failing_the_run(monkeypatch, run_env, caplog):
    """MISP answers one object row for an event the index lists with 30000 attributes."""
    object_row = _search_rows()[-1]
    sync = _run_sync(monkeypatch, [{"id": EVENT_ID, "info": EVENT_FIELDS["info"], "attribute_count": "30000"}])
    fake = _FakeMisp([object_row])
    monkeypatch.setattr(sync, "_misp_post_json", fake)
    with caplog.at_level(logging.WARNING, logger=SYNC_LOGGER):
        assert sync.run(incremental=False) is True
    assert fake.calls[0][0] == "/events/restSearch"
    assert sync.stats["events_paged_incomplete"] == 1
    assert sync.stats["events_processed"] == 1 and sync.stats["events_failed"] == 0
    assert run_env["success"] == 1 and run_env["failure"] == []
    assert "1 attribute rows" in _incomplete_records(caplog)[0].getMessage()
    summary = [r.getMessage() for r in caplog.records if "fewer attributes than the MISP index lists" in r.getMessage()]
    assert summary and summary[0].startswith(
        "Events fetched in pages with fewer attributes than the MISP index lists: 1"
    )


def _paged_incomplete_gauge():
    from prometheus_client import REGISTRY

    return REGISTRY.get_sample_value("edgeguard_sync_events_paged_incomplete")


def test_an_incomplete_paged_event_sets_the_gauge_the_alert_reads(monkeypatch, run_env):
    """End to end: the real paged fetch counts the event, run() exports the count through
    record_sync_event_accounting, and edgeguard_sync_events_paged_incomplete (EdgeGuardSyncPagedFetchIncomplete)
    holds it while the run stays green."""
    assert run_misp_to_neo4j._METRICS_AVAILABLE, "prometheus_client is a declared dependency"
    sync = _run_sync(monkeypatch, [{"id": EVENT_ID, "info": EVENT_FIELDS["info"], "attribute_count": "30000"}])
    monkeypatch.setattr(sync, "_misp_post_json", _FakeMisp([_search_rows()[-1]]))
    assert sync.run(incremental=False) is True
    assert sync.stats["events_paged_incomplete"] == 1
    assert _paged_incomplete_gauge() == 1


def test_a_complete_paged_event_sets_the_gauge_back_to_zero(monkeypatch, run_env):
    """Control: every listed row arrives through the paged fetch, so the next run clears the alert."""
    monkeypatch.setenv("EDGEGUARD_MISP_PAGED_FETCH_ABOVE", "5")
    rows = _search_rows()
    run_misp_to_neo4j.record_sync_event_accounting(
        events_index_total=1, events_processed=1, events_failed=0, events_paged_incomplete=3
    )
    assert _paged_incomplete_gauge() == 3
    sync = _run_sync(monkeypatch, [{"id": EVENT_ID, "info": EVENT_FIELDS["info"], "attribute_count": str(len(rows))}])
    fake = _FakeMisp(rows)
    monkeypatch.setattr(sync, "_misp_post_json", fake)
    assert sync.run(incremental=False) is True
    assert fake.attribute_bodies(), "the event went through the paged fetch"
    assert sync.stats["events_paged_incomplete"] == 0
    assert _paged_incomplete_gauge() == 0


def test_a_run_that_fails_after_an_incomplete_paged_event_still_exports_it(monkeypatch, run_env):
    """The finally block exports the count on the exception path too (here Neo4j fails after the events)."""
    sync = _run_sync(monkeypatch, [{"id": EVENT_ID, "info": EVENT_FIELDS["info"], "attribute_count": "30000"}])
    monkeypatch.setattr(sync, "_misp_post_json", _FakeMisp([_search_rows()[-1]]))
    sync.neo4j.apply_sector_labels.side_effect = RuntimeError("Neo4j connection lost")
    exported: list = []
    monkeypatch.setattr(run_misp_to_neo4j, "record_sync_event_accounting", lambda **kw: exported.append(kw))
    assert sync.run(incremental=False) is False
    assert "Neo4j connection lost" in sync.get_stats()["last_failure_reason"]
    assert exported and exported[-1]["events_paged_incomplete"] == 1
    assert exported[-1]["events_processed"] == 1


@pytest.mark.parametrize("attribute_count", ["30000", "145261"])
def test_an_incomplete_event_fetched_again_on_retry_is_counted_once(monkeypatch, run_env, caplog, attribute_count):
    """The Neo4j write fails after the fetch; the retry pass fetches the event again (first pass and deferred)."""
    sync = _run_sync(monkeypatch, [{"id": EVENT_ID, "info": EVENT_FIELDS["info"], "attribute_count": attribute_count}])
    fake = _FakeMisp(_search_rows())
    monkeypatch.setattr(sync, "_misp_post_json", fake)
    writes: list = []

    def sync_to_neo4j(items):
        writes.append(len(items))
        if len(writes) == 1:
            raise RuntimeError("Neo4j write rejected")
        return len(items), 0, 0

    monkeypatch.setattr(sync, "sync_to_neo4j", sync_to_neo4j)
    monkeypatch.setattr(sync, "_create_relationships", lambda *_a, **_k: 0)
    monkeypatch.setattr(sync, "_write_cross_item_relationships", lambda *_a, **_k: 0)
    with caplog.at_level(logging.WARNING, logger=SYNC_LOGGER):
        assert sync.run(incremental=False) is True
    assert writes == [len(_NVD_138), len(_NVD_138)]
    assert [path for path, _body in fake.calls].count("/events/restSearch") == 2
    assert len(_incomplete_records(caplog)) == 2  # one warning per fetch
    assert sync.stats["events_paged_incomplete"] == 1
    assert sync.stats["events_processed"] == 1 and sync.stats["events_failed"] == 0
    summary = [r.getMessage() for r in caplog.records if "fewer attributes than the MISP index lists" in r.getMessage()]
    assert summary and summary[0].startswith(
        "Events fetched in pages with fewer attributes than the MISP index lists: 1"
    )


# ---------------------------------------------------------------------------
# _process_single_event routing
# ---------------------------------------------------------------------------


def _routing_syncer():
    syncer = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    syncer.stats = {"events_processed": 0, "events_failed": 0}
    syncer.fetched = []
    syncer.fetch_event_details = lambda event_id: syncer.fetched.append("whole")
    syncer.fetch_event_details_paged = lambda event_id, attribute_count=0: syncer.fetched.append(
        ("paged", attribute_count)
    )
    return syncer


@pytest.mark.parametrize(
    "env, attribute_count, expected",
    [
        (None, 145261, [("paged", 145261)]),
        (None, 20000, ["whole"]),
        (None, 0, ["whole"]),
        ("1000", 1001, [("paged", 1001)]),
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
    assert syncer.fetched == ["whole", ("paged", 100)]


# ---------------------------------------------------------------------------
# _misp_post_json
# ---------------------------------------------------------------------------


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
