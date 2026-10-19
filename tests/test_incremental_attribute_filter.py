"""Incremental sync writes only the attributes that changed since the sync window.

Before this fix an incremental run kept every MISP event modified inside the window and
then re-merged **all** of that event's attributes. Right after a baseline the 140k-attribute
NVD and 149k-attribute OTX events are inside the window, so the "incremental" run re-synced
the whole baseline (~2.5 h on a workstation).

Pinned here:

* ``_process_single_event`` writes only attributes whose MISP ``timestamp`` is at or after
  the run's ``since``; an attribute without a usable timestamp counts as changed.
* An event with no changed attribute is counted as processed and makes no Neo4j call.
* Unchanged items that share an OTX pulse with a changed item still feed the report-scoped
  cross-item build (so new indicators link to older malware of the same pulse), but are
  not written again.
* The large-event paging decision uses the number of changed attributes.
* A full sync (``since`` is None) and ``EDGEGUARD_SYNC_ATTRIBUTE_FILTER=false`` keep the
  whole-event behaviour.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from run_misp_to_neo4j import MISPToNeo4jSync, _attribute_changed_since  # noqa: E402

SINCE = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
OLD = str(int(SINCE.timestamp()) - 3600)
NEW = str(int(SINCE.timestamp()) + 3600)

_PARSED = {
    "ioc-new": {"type": "indicator", "indicator_type": "ipv4", "value": "1.1.1.1", "pulse_id": "p1"},
    "mal-old": {"type": "malware", "name": "MalA", "pulse_id": "p1"},
    "mal-other-pulse": {"type": "malware", "name": "MalB", "pulse_id": "p9"},
    "ioc-old": {"type": "indicator", "indicator_type": "ipv4", "value": "9.9.9.9", "pulse_id": "p9"},
}


def _syncer(attributes, since=SINCE):
    syncer = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    syncer.neo4j = MagicMock()
    syncer.stats = {
        "events_processed": 0,
        "events_failed": 0,
        "relationships_created": 0,
        "errors": 0,
    }
    syncer._attr_since = since
    syncer.written = []
    syncer.sync_to_neo4j = lambda items: (syncer.written.extend(items), (len(items), 0, []))[1]
    syncer.parse_attribute = lambda attr, event: (dict(_PARSED[attr["uuid"]], misp_event_id="7"), [])
    syncer.fetch_event_details = lambda event_id: {"Attribute": attributes, "Event": {"id": event_id}}
    syncer.cross_input = []

    real_build = MISPToNeo4jSync._build_cross_item_relationships

    def build(items, reports=None):
        syncer.cross_input.extend(items)
        return real_build(syncer, items, reports=reports)

    syncer._build_cross_item_relationships = build
    syncer.rels = []
    syncer._create_relationships = lambda rels, source_id: (syncer.rels.extend(rels), len(rels))[1]
    return syncer


def _attr(uuid, ts):
    return {"uuid": uuid, "timestamp": ts}


def _written_keys(syncer):
    return sorted(i.get("value") or i.get("name") for i in syncer.written)


class TestAttributeChangedSince:
    def test_compares_epoch_timestamp_with_since(self):
        assert _attribute_changed_since({"timestamp": NEW}, SINCE)
        assert not _attribute_changed_since({"timestamp": OLD}, SINCE)
        assert _attribute_changed_since({"timestamp": str(int(SINCE.timestamp()))}, SINCE)

    def test_accepts_datetime_timestamps_from_pymisp(self):
        assert _attribute_changed_since({"timestamp": datetime(2026, 10, 14, tzinfo=timezone.utc)}, SINCE)
        assert not _attribute_changed_since({"timestamp": datetime(2026, 10, 12)}, SINCE)

    @pytest.mark.parametrize("attr", [{}, {"timestamp": ""}, {"timestamp": None}, {"timestamp": "n/a"}])
    def test_missing_or_bad_timestamp_counts_as_changed(self, attr):
        assert _attribute_changed_since(attr, SINCE)


class TestIncrementalWritesOnlyChangedAttributes:
    def test_only_changed_attributes_are_written(self):
        syncer = _syncer([_attr("ioc-new", NEW), _attr("mal-other-pulse", OLD)])
        parsed, _cross, errors = syncer._process_single_event("7", "EdgeGuard-test")
        assert (parsed, errors) == (1, 0)
        assert _written_keys(syncer) == ["1.1.1.1"]
        assert syncer.stats["events_processed"] == 1

    def test_event_without_changed_attributes_makes_no_neo4j_call(self):
        syncer = _syncer([_attr("mal-old", OLD), _attr("ioc-old", OLD)])
        syncer.sync_to_neo4j = MagicMock()
        assert syncer._process_single_event("7", "EdgeGuard-test") == (0, 0, 0)
        syncer.sync_to_neo4j.assert_not_called()
        assert syncer.stats["events_processed"] == 1

    def test_missing_timestamp_is_written(self):
        syncer = _syncer([{"uuid": "ioc-new"}, _attr("mal-other-pulse", OLD)])
        syncer._process_single_event("7", "EdgeGuard-test")
        assert _written_keys(syncer) == ["1.1.1.1"]

    def test_unchanged_item_of_the_same_pulse_links_but_is_not_rewritten(self):
        attrs = [_attr("ioc-new", NEW), _attr("mal-old", OLD), _attr("mal-other-pulse", OLD), _attr("ioc-old", OLD)]
        syncer = _syncer(attrs)
        syncer._process_single_event("7", "EdgeGuard-test")
        assert _written_keys(syncer) == ["1.1.1.1"]
        assert sorted(i.get("value") or i.get("name") for i in syncer.cross_input) == ["1.1.1.1", "MalA"]
        indicates = [(r["rel_type"], r["to_key"]["name"]) for r in syncer.rels if r["rel_type"] == "INDICATES"]
        assert indicates == [("INDICATES", "MalA")]

    def test_paging_decision_uses_the_changed_count(self, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 2)
        attrs = [_attr("ioc-new", NEW), _attr("mal-old", OLD), _attr("mal-other-pulse", OLD), _attr("ioc-old", OLD)]
        syncer = _syncer(attrs)
        syncer._process_large_event_paged = MagicMock(return_value=(0, 0, 0))
        syncer._process_single_event("7", "EdgeGuard-test")
        syncer._process_large_event_paged.assert_not_called()
        assert _written_keys(syncer) == ["1.1.1.1"]

    def test_large_changed_set_pages_and_writes_only_changed(self, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 1)
        attrs = [_attr("ioc-new", NEW), _attr("mal-old", NEW), _attr("mal-other-pulse", OLD), _attr("ioc-old", OLD)]
        syncer = _syncer(attrs)
        parsed, cross, errors = syncer._process_single_event("7", "EdgeGuard-test")
        assert (parsed, errors) == (2, 0)
        assert _written_keys(syncer) == ["1.1.1.1", "MalA"]
        assert sorted(i.get("value") or i.get("name") for i in syncer.cross_input) == ["1.1.1.1", "MalA"]
        assert cross == 1

    def test_paged_path_links_unchanged_item_of_the_same_pulse(self, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 1)
        attrs = [_attr("ioc-new", NEW), _attr("ioc-old", NEW), _attr("mal-old", OLD), _attr("mal-other-pulse", NEW)]
        syncer = _syncer(attrs)
        parsed, cross, errors = syncer._process_single_event("7", "EdgeGuard-test")
        assert (parsed, errors) == (3, 0)
        assert _written_keys(syncer) == ["1.1.1.1", "9.9.9.9", "MalB"], "unchanged MalA is not rewritten"
        indicates = sorted(r["to_key"]["name"] for r in syncer.rels if r["rel_type"] == "INDICATES")
        assert indicates == ["MalA", "MalB"], "new p1 IOC links to the unchanged p1 malware"


class TestWholeEventBehaviourKept:
    ATTRS = [_attr("ioc-new", NEW), _attr("mal-old", OLD), _attr("mal-other-pulse", OLD), _attr("ioc-old", OLD)]

    def test_full_sync_writes_every_attribute(self):
        syncer = _syncer(self.ATTRS, since=None)
        syncer._process_single_event("7", "EdgeGuard-test")
        assert _written_keys(syncer) == ["1.1.1.1", "9.9.9.9", "MalA", "MalB"]

    def test_env_opt_out_writes_every_attribute(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_SYNC_ATTRIBUTE_FILTER", "false")
        syncer = _syncer(self.ATTRS)
        syncer._process_single_event("7", "EdgeGuard-test")
        assert _written_keys(syncer) == ["1.1.1.1", "9.9.9.9", "MalA", "MalB"]


def test_run_stores_the_window_for_the_attribute_filter(monkeypatch):
    """``run()`` hands its effective ``since`` to the per-event filter."""
    syncer = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    syncer.stats = {}
    seen = {}

    def stop(*_a, **_kw):
        seen["since"] = syncer._attr_since
        return False, "stop here"

    syncer.check_services_available = stop
    syncer.run(incremental=True, since=SINCE)
    assert seen["since"] == SINCE
