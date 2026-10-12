"""Unknown ``source:*`` MISP tags must degrade gracefully in the sync path.

A MISP instance may still hold attributes tagged by a collector that has
since been removed from the framework (see "Removed sources" in
``docs/DATA_SOURCES.md``). ``run_misp_to_neo4j`` must keep ingesting such
attributes: the source falls back to ``misp``, the fallback is logged once
per distinct tag name and counted in
``edgeguard_misp_unmapped_source_tags_total``, and nothing raises.
``source_truthful_timestamps`` must likewise return ``(None, None)`` for a
source id it does not know, so no unverified first-seen claim reaches the
``SOURCED_FROM`` edge.
"""

from __future__ import annotations

import logging
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

os.environ.setdefault("NEO4J_PASSWORD", "x")
os.environ.setdefault("MISP_API_KEY", "x")

from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

_UNKNOWN_TAG = "source:Retired-Feed"
_UNKNOWN_NAME = "Retired-Feed"


@pytest.fixture
def syncer() -> MISPToNeo4jSync:
    return MISPToNeo4jSync(neo4j_client=MagicMock())


# ---------------------------------------------------------------------------
# extract_source_from_tags
# ---------------------------------------------------------------------------


def test_unknown_source_tag_falls_back_to_misp(syncer: MISPToNeo4jSync):
    assert syncer.extract_source_from_tags([{"name": _UNKNOWN_TAG}]) == "misp"


def test_known_source_tag_still_maps(syncer: MISPToNeo4jSync):
    assert syncer.extract_source_from_tags([{"name": "source:URLhaus"}]) == "urlhaus"
    assert syncer.extract_source_from_tags([{"name": "source:Feodo-Tracker"}]) == "feodo_tracker"


def test_unknown_source_tag_is_logged_once_per_distinct_name(syncer: MISPToNeo4jSync, caplog):
    caplog.set_level(logging.WARNING)
    for _ in range(3):
        syncer.extract_source_from_tags([{"name": _UNKNOWN_TAG}])
    syncer.extract_source_from_tags([{"name": "source:Another-Retired-Feed"}])

    warnings = [r for r in caplog.records if "not in SOURCE_MAPPING" in r.getMessage()]
    assert len(warnings) == 2, [r.getMessage() for r in warnings]
    assert _UNKNOWN_TAG in warnings[0].getMessage()
    assert "source:Another-Retired-Feed" in warnings[1].getMessage()


def test_unknown_source_tag_is_counted_on_every_occurrence(syncer: MISPToNeo4jSync):
    with patch("metrics_server.record_misp_unmapped_source_tag") as rec:
        syncer.extract_source_from_tags([{"name": _UNKNOWN_TAG}])
        syncer.extract_source_from_tags([{"name": _UNKNOWN_TAG}])
    assert rec.call_count == 2
    assert all(call.args == (_UNKNOWN_NAME,) for call in rec.call_args_list)


def test_unknown_source_tag_increments_the_prometheus_counter(syncer: MISPToNeo4jSync):
    from metrics_server import MISP_UNMAPPED_SOURCE_TAGS

    child = MISP_UNMAPPED_SOURCE_TAGS.labels(source_tag=_UNKNOWN_NAME)
    before = child._value.get()
    syncer.extract_source_from_tags([{"name": _UNKNOWN_TAG}])
    assert child._value.get() == before + 1


def test_unmapped_source_tag_label_values_are_bounded(syncer: MISPToNeo4jSync):
    cap = MISPToNeo4jSync._UNMAPPED_SOURCE_TAG_LABEL_CAP
    with patch("metrics_server.record_misp_unmapped_source_tag") as rec:
        for i in range(cap + 5):
            syncer.extract_source_from_tags([{"name": f"source:Feed-{i}"}])
    labels = [call.args[0] for call in rec.call_args_list]
    assert len(labels) == cap + 5
    assert labels[:cap] == [f"Feed-{i}" for i in range(cap)]
    assert set(labels[cap:]) == {"<other>"}


def test_metric_failure_does_not_break_source_extraction(syncer: MISPToNeo4jSync):
    with patch("metrics_server.record_misp_unmapped_source_tag", side_effect=RuntimeError("registry down")):
        assert syncer.extract_source_from_tags([{"name": _UNKNOWN_TAG}]) == "misp"


def test_tracking_state_does_not_depend_on_the_constructor():
    """Several test modules build the sync object via ``__new__``; the
    unmapped-tag tracker must work on such instances as well."""
    sync = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    assert sync.extract_source_from_tags([{"name": _UNKNOWN_TAG}]) == "misp"
    assert sync.extract_source_from_tags([{"name": _UNKNOWN_TAG}]) == "misp"


# ---------------------------------------------------------------------------
# parse_attribute end to end
# ---------------------------------------------------------------------------


def test_parse_attribute_with_unknown_source_tag_ingests_under_misp(syncer: MISPToNeo4jSync):
    attr = {
        "type": "ip-dst",
        "value": "203.0.113.77",
        "uuid": "33333333-aaaa-bbbb-cccc-444444444444",
        "first_seen": "2026-01-01T00:00:00.000000+00:00",
        "Tag": [{"name": _UNKNOWN_TAG}],
    }
    event = {"id": 7, "info": "report", "date": "2026-10-01", "Tag": []}

    item, _rels = syncer.parse_attribute(attr, event)

    assert item is not None
    assert item["value"] == "203.0.113.77"
    assert item["tag"] == "misp"
    assert item["source"] == ["misp"]
    # An unmapped source carries no source-truthful first-seen claim.
    assert item["first_seen_at_source"] is None
    assert item["last_seen_at_source"] is None


# ---------------------------------------------------------------------------
# source_truthful_timestamps
# ---------------------------------------------------------------------------


def test_source_truthful_timestamps_reject_an_unknown_source_id():
    from source_truthful_timestamps import extract_source_truthful_timestamps, is_reliable_first_seen_source

    assert not is_reliable_first_seen_source("retired_feed")
    attr = {
        "first_seen": "2026-01-01T00:00:00.000000+00:00",
        "last_seen": "2026-02-01T00:00:00.000000+00:00",
        "comment": "",
    }
    assert extract_source_truthful_timestamps(attr, "retired_feed") == (None, None)
