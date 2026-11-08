"""The MISP -> Neo4j sync reads OTX events that carry Event Reports as before (report records, 2026-11-07).

``MISPWriter.push_reports`` writes one Event Report per OTX pulse into the source's day event, or into the
companion event ``EdgeGuard-alienvault_otx-<date>-reports`` (no attributes) when the day event is above
``EDGEGUARD_MISP_EVENT_SPLIT_ABOVE``. Until the sync reads the reports (a later change), it must read these events as
it reads any EdgeGuard event and ignore the reports:

* the event index keeps both events, and the source of each is ``alienvault_otx``;
* the whole-event fetch (the view without galaxy clusters, and when MISP refuses it PyMISP ``get_event`` and
  the REST fallback) returns the event with its ``EventReport`` list and its attributes; PyMISP's ``MISPEvent``
  loads such an event;
* the paged fetch reads the event's metadata, which carries no reports;
* processing writes the same items with and without the reports, and an event with reports and no attributes is
  processed, counted and writes nothing; an incremental run in which only a report changed writes nothing;
* an indicator of an amber, red or unknown-TLP pulse, whose ``OTX_META`` block the writer leaves without the pulse
  name, gets an empty ``pulse_name``, not the block.

The answers are MISP 2.5.50's of 2026-11-07 (``tests/fixtures/misp_events_with_reports_2026_11_07.json``), with an
EdgeGuard event name in place of the throwaway event's. The companion event and its index row are constructed from
these answers (``_companion_event`` and the index test): the recorded event and index row with the attributes
removed, ``attribute_count`` ``"0"`` and the id ``123``; recorded answers of an event without attributes carry
``"Attribute": []`` the same way. Reading these events needed no change in the sync, so the
tests of the events pass without the report records too: they guard the sync against a change that would trip on the reports (a fetch
that dropped such an event, a count of the reports as failures, an index filter on the event name's date).
"""

from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from misp_fakes import Response  # noqa: E402
from stub_cleanup import clear_graphql_api_magicmock_stubs  # noqa: E402

# tests/test_graphql_api.py replaces neo4j_client (and neo4j, pymisp) with MagicMocks when it is collected first.
if any(isinstance(m, MagicMock) for k, m in list(sys.modules.items()) if k == "neo4j_client" or k.startswith("neo4j")):
    clear_graphql_api_magicmock_stubs()

import run_misp_to_neo4j  # noqa: E402
from run_misp_to_neo4j import (  # noqa: E402
    MISPToNeo4jSync,
    _event_source_id,
    _fetch_edgeguard_events_via_requests_index,
    _is_edgeguard_index_event,
    misp_event_object_to_event_dict,
    normalize_misp_event_index_payload,
)

_FIXTURE = json.loads(
    (REPO_ROOT / "tests" / "fixtures" / "misp_events_with_reports_2026_11_07.json").read_text(encoding="utf-8")
)
DAY = "EdgeGuard-alienvault_otx-2026-11-07"
COMPANION = f"{DAY}-reports"


def _named(answer: Any, info: str) -> Any:
    """*answer* with every event in it named *info*."""
    answer = copy.deepcopy(answer)
    events = [r["Event"] for r in answer["response"]] if "response" in answer else [answer.get("Event", answer)]
    for event in events:
        event["info"] = info
    return answer


def _day_event() -> Dict[str, Any]:
    """The day event as ``/events/view`` answers it: six attributes and three Event Reports."""
    return _named(_FIXTURE["event_with_reports"], DAY)


def _companion_event() -> Dict[str, Any]:
    """The companion event, constructed from the recorded day event: its reports, no attribute
    (``attribute_count`` ``"0"``) and the id ``123`` of its index row."""
    answer = _named(_FIXTURE["event_with_reports"], COMPANION)
    answer["Event"].update(id="123", Attribute=[], attribute_count="0")
    return answer


def test_the_recorded_answers_carry_the_reports():
    """The guard of this file: the event answers hold reports (and the metadata answer none), as recorded."""
    assert len(_FIXTURE["event_with_reports"]["Event"]["EventReport"]) == 3
    assert len(_FIXTURE["event_with_reports"]["Event"]["Attribute"]) == 6
    assert len(_FIXTURE["restsearch_json"]["response"][0]["Event"]["EventReport"]) == 1
    assert "EventReport" not in _FIXTURE["restsearch_metadata"]["response"][0]["Event"]


# --------------------------------------------------------------------------- the event index


def test_the_index_keeps_the_day_event_and_its_reports_companion():
    day = dict(_FIXTURE["index_row"], info=DAY)
    # constructed from the recorded index row: the companion's id, name and attribute count
    companion = dict(_FIXTURE["index_row"], id="123", info=COMPANION, attribute_count="0")
    session = MagicMock()
    session.get.side_effect = lambda url, params=None, **_kw: Response(
        200, [day, companion] if params["page"] == 1 else []
    )
    listed = normalize_misp_event_index_payload(_fetch_edgeguard_events_via_requests_index(session, "https://m", None))
    assert [(e["id"], e["info"]) for e in listed] == [("122", DAY), ("123", COMPANION)]
    assert all(_is_edgeguard_index_event(e) for e in listed)
    assert [_event_source_id(e["info"]) for e in listed] == ["alienvault_otx", "alienvault_otx"]


# --------------------------------------------------------------------------- the fetch paths

_VIEW_WITHOUT_GALAXIES = "/events/view/122/excludeGalaxy:1"


def _session(answers: Dict[str, Any]) -> MagicMock:
    """A requests session whose GET answers each path of ``answers`` (a URL path → a ``Response``)."""
    session = MagicMock()
    session.get.side_effect = lambda url, **_kw: answers[url.split("://m", 1)[1]]
    return session


def _syncer(answers: Dict[str, Any]) -> MISPToNeo4jSync:
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    syncer.misp_url = "https://m"
    syncer.session = _session(answers)
    return syncer


def test_the_whole_event_fetch_without_galaxies_returns_the_event_with_its_reports():
    syncer = _syncer({_VIEW_WITHOUT_GALAXIES: Response(200, _day_event())})
    event = syncer.fetch_event_details("122")
    assert event["info"] == DAY and len(event["Attribute"]) == 6 and len(event["EventReport"]) == 3


def test_the_whole_event_fetch_through_pymisp_returns_the_event_with_its_reports(monkeypatch):
    import pymisp

    class _PyMISP:
        def __init__(self, *_a: Any, **_kw: Any):
            pass

        def get_event(self, event_id: str) -> Dict[str, Any]:
            assert event_id == "122"
            return _day_event()

    monkeypatch.setattr(pymisp, "PyMISP", _PyMISP)
    # PyMISP is read when MISP refuses the view without galaxy clusters.
    syncer = _syncer({_VIEW_WITHOUT_GALAXIES: Response(404, {"message": "Not found"})})
    event = syncer.fetch_event_details("122")
    assert event["info"] == DAY and len(event["Attribute"]) == 6 and len(event["EventReport"]) == 3


def test_the_rest_fallback_returns_the_event_with_its_reports(monkeypatch):
    import pymisp

    class _Failing:
        def __init__(self, *_a: Any, **_kw: Any):
            raise RuntimeError("PyMISP unavailable")

    monkeypatch.setattr(pymisp, "PyMISP", _Failing)
    syncer = _syncer(
        {_VIEW_WITHOUT_GALAXIES: Response(404, {"message": "Not found"}), "/events/122": Response(200, _day_event())}
    )
    event = syncer.fetch_event_details("122")
    assert event["info"] == DAY and len(event["Attribute"]) == 6 and len(event["EventReport"]) == 3
    assert [c.args[0] for c in syncer.session.get.call_args_list] == [
        f"https://m{_VIEW_WITHOUT_GALAXIES}",
        "https://m/events/122",
    ]


def test_pymisp_loads_an_event_with_reports():
    from pymisp import MISPEvent

    assert not isinstance(MISPEvent, MagicMock), "the real PyMISP"
    loaded = MISPEvent()
    loaded.load(_day_event())
    assert len(loaded.event_reports) == 3 and len(loaded.attributes) == 6
    event = misp_event_object_to_event_dict(loaded)
    assert event["info"] == DAY and len(event["Attribute"]) == 6 and len(event["EventReport"]) == 3
    restsearch = MISPEvent()
    restsearch.load(_named(_FIXTURE["restsearch_json"], DAY)["response"][0])
    assert len(restsearch.event_reports) == 1


def test_the_paged_fetch_reads_the_metadata_without_reports():
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    rows = copy.deepcopy(_day_event()["Event"]["Attribute"])

    def post(path: str, body: Dict[str, Any]):
        if path == "/events/restSearch":
            assert body["metadata"] is True
            return _named(_FIXTURE["restsearch_metadata"], DAY)
        return {"response": {"Attribute": copy.deepcopy(rows) if body["page"] == 1 else []}}

    syncer._misp_post_json = post
    event = syncer.fetch_event_details_paged("122", 6)
    assert event["info"] == DAY and len(event["Attribute"]) == 6 and "EventReport" not in event


# --------------------------------------------------------------------------- processing


def _processing_syncer(event: Dict[str, Any]) -> MISPToNeo4jSync:
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    syncer.written: List[Dict[str, Any]] = []
    syncer.fetch_event_details = lambda _event_id: misp_event_object_to_event_dict(copy.deepcopy(event))
    syncer.sync_to_neo4j = lambda items: (syncer.written.extend(items), (len(items), 0, []))[1]
    syncer._write_cross_item_relationships = lambda rels: 0
    syncer._create_relationships = lambda rels, source: 0
    syncer._count_relationship_writes = lambda written: None
    return syncer


def test_the_day_event_writes_the_same_items_with_and_without_its_reports():
    with_reports = _processing_syncer(_day_event())
    without = _day_event()
    del without["Event"]["EventReport"]
    plain = _processing_syncer(without)
    assert with_reports._process_single_event("122", DAY, 6) == plain._process_single_event("122", DAY, 6)
    assert with_reports.written == plain.written and len(with_reports.written) > 0
    assert with_reports.stats["events_processed"] == 1 and with_reports.stats["events_failed"] == 0
    contents = {r["content"] for r in _day_event()["Event"]["EventReport"]}
    assert not any(item.get("description") in contents for item in with_reports.written)


def test_the_reports_event_without_attributes_is_processed_and_writes_nothing():
    syncer = _processing_syncer(_companion_event())
    syncer.sync_to_neo4j = MagicMock()
    assert syncer._process_single_event("123", COMPANION, 0) == (0, 0, 0)
    syncer.sync_to_neo4j.assert_not_called()
    assert syncer.stats["events_processed"] == 1 and syncer.stats["events_failed"] == 0


def test_an_incremental_run_after_a_change_of_a_report_only_writes_nothing():
    """A report change moves the event's timestamp (live check L5), so an incremental run selects the event; none of
    its attributes changed since the window start, so it writes nothing."""
    event = _day_event()
    newest = max(int(a["timestamp"]) for a in event["Event"]["Attribute"])
    syncer = _processing_syncer(event)
    syncer._attr_since = datetime.fromtimestamp(newest + 1, tz=timezone.utc)
    syncer.sync_to_neo4j = MagicMock()
    assert syncer._process_single_event("122", DAY, 6) == (0, 0, 0)
    syncer.sync_to_neo4j.assert_not_called()
    assert syncer.stats["events_processed"] == 1


def _otx_indicator(level: str) -> Dict[str, Any]:
    """An OTX indicator item as the collector hands it to the writer (constructed; the values are the writer's
    inputs, not a recorded pulse)."""
    return {
        "indicator_type": "ipv4",
        "value": "198.51.100.9",
        "tag": "alienvault_otx",
        "pulse_id": "6abf0b86fb14812f2dc84fb2",
        "pulse_tlp": level,
        "pulse_name": "Some pulse",
        "pulse_tags": ["t"],
        "pulse_references": ["https://r.example/x"],
        "targeted_countries": ["Germany"],
        "attack_ids": ["T1190"],
        "description": "ind desc",
    }


@pytest.mark.parametrize(("level", "expected"), [("white", "Some pulse"), ("amber", ""), ("red", ""), ("", "")])
def test_an_indicator_of_a_pulse_without_copies_gets_an_empty_pulse_name(level, expected):
    """The writer leaves ``OTX_META.pulse_name`` empty for an amber, red or unknown-TLP pulse; the sync then takes no
    fallback from the comment, which is the whole ``OTX_META`` block, so the indicator's ``pulse_name`` (and the
    edge's ``raw_data``) holds an empty name, not the block."""
    from collectors import misp_writer

    writer = misp_writer.MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)
    attr = writer.create_attribute(_otx_indicator(level))
    assert attr["comment"].startswith("OTX_META:")
    event = _day_event()
    stored = copy.deepcopy(event["Event"]["Attribute"][0])
    stored.update(type=attr["type"], value=attr["value"], comment=attr["comment"])
    stored["Tag"] = attr.get("Tag", stored.get("Tag", []))
    event["Event"]["Attribute"] = [stored]
    syncer = _processing_syncer(event)
    syncer._process_single_event("122", DAY, 1)
    items = [item for item in syncer.written if item.get("value") == "198.51.100.9"]
    assert len(items) == 1
    assert items[0]["pulse_name"] == expected
    assert "OTX_META" not in json.dumps(items[0], default=str)


@pytest.mark.parametrize("info", [DAY, COMPANION])
def test_the_event_source_of_both_events_is_otx(info):
    assert run_misp_to_neo4j._event_source_id(info) == "alienvault_otx"
