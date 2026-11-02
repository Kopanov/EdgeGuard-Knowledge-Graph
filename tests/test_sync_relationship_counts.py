"""What the MISP→Neo4j sync counts for relationships (2026-11-02).

* ``create_misp_relationships_batch`` replays the AFFECTS rows (and an indicator's EXPLOITS rows)
  against ``Vulnerability`` and ``CVE`` and counted them once per label, in the rows written and in
  the failed rows. The 730-day baseline of 2026-11-01 logged ``Relationships created: 394534`` for
  384,931 definitions (9,603 AFFECTS rows twice). Each replayed row now counts once; ``created`` is
  what Neo4j's counters report the statements created (the graph had 0 ``Vulnerability`` nodes).
* The sync reports ``Relationship rows written`` and ``Relationships created`` apart.
* ``run()``'s "Sync totals" counts definitions on both event paths; the paged path returned rows
  written (388,051 logged for 384,931 definitions).
* The sector-label count is logged once, by ``apply_sector_labels``, under what it counts.

The AFFECTS rows are three CISA ICS links of the 730-day graph (event 69, ``advisory_sector``); the
INDICATES rows two OTX same-pulse links of it (event 55) and one to a family the graph lacks. The
EXPLOITS row is an indicator's own CVE tag (``cve_tag``) in the shape ``_build_cross_item_relationships``
builds it; its values are illustrative (the count does not depend on them).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Dict, List
from unittest.mock import MagicMock

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import neo4j_client as nc  # noqa: E402
import run_misp_to_neo4j  # noqa: E402
from neo4j_client import RelationshipBatchResult  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

# (cve_id, sector, source_refs) of three AFFECTS links of the 730-day graph, all from CISA ICS event 69.
_AFFECTS = [
    ("CVE-2023-35827", "energy", "cisa_ics:ICSA-25-226-15"),
    ("CVE-2026-8479", "energy", "cisa_ics:ICSA-26-155-04"),
    ("CVE-2026-53148", "energy", "cisa_ics:ICSA-26-295-16"),
]
# (indicator, family, pulse ref) of two INDICATES links of the 730-day graph (OTX event 55), and one row
# whose family is not in the graph.
_INDICATES = [
    ("252670701fa2aecc8361a82e4b3fa8da", "trickbot", "alienvault_otx:67502c40a650db434a39ed47"),
    ("8d5b3a0512744efc132afa6fc75c64d8", "trickbot", "alienvault_otx:6a6120390f602b6ee56739c3"),
    ("8d5b3a0512744efc132afa6fc75c64d8", "no such family", "alienvault_otx:6a6120390f602b6ee56739c3"),
]


def _definitions() -> List[Dict]:
    affects = [
        {
            "rel_type": "AFFECTS",
            "from_type": "Vulnerability",
            "from_key": {"cve_id": cve},
            "to_type": "Sector",
            "to_key": {"name": sector},
            "confidence": 0.9,
            "match_type": "advisory_sector",
            "source": "cisa_ics",
            "source_refs": [ref],
            "misp_event_id": "69",
        }
        for cve, sector, ref in _AFFECTS
    ]
    indicates = [
        {
            "rel_type": "INDICATES",
            "from_type": "Indicator",
            "from_key": {"value": value, "indicator_type": "hash"},
            "to_type": "Malware",
            "to_key": {"name": family},
            "confidence": 0.6,
            "match_type": "otx_pulse",
            "source": "alienvault_otx",
            "source_refs": [ref],
            "misp_event_id": "55",
        }
        for value, family, ref in _INDICATES
    ]
    return affects + indicates


# An indicator's CVE tag, as ``_build_cross_item_relationships`` builds it: replayed against
# ``Vulnerability`` and ``CVE`` like the AFFECTS rows.
_EXPLOITS = {
    "rel_type": "EXPLOITS",
    "from_type": "Indicator",
    "from_key": {"value": "203.0.113.17", "indicator_type": "ipv4"},
    "to_type": "Vulnerability",
    "to_key": {"cve_id": "CVE-2024-21887"},
    "confidence": 0.7,
    "misp_event_id": "55",
    "match_type": "cve_tag",
}


def _with_exploits() -> List[Dict]:
    return _definitions() + [dict(_EXPLOITS)]


def _group(query: str) -> str:
    if "[r:AFFECTS]" in query:
        return "AFFECTS_vulnerability" if "MATCH (v:Vulnerability" in query else "AFFECTS_cve"
    if "MATCH (i:Indicator" in query and "[r:EXPLOITS]" in query:
        return "EXPLOITS_vulnerability" if "MATCH (v:Vulnerability" in query else "EXPLOITS_cve"
    if "[r:INDICATES]->(m)" in query:
        return "INDICATES_malware"
    return "other"


# What Neo4j reports each statement created on the 730-day graph: no Vulnerability node, three CVE
# links, two of the three INDICATES rows (the third family is missing); the EXPLOITS row links its CVE.
_CREATED = {
    "AFFECTS_vulnerability": 0,
    "AFFECTS_cve": 3,
    "INDICATES_malware": 2,
    "EXPLOITS_vulnerability": 0,
    "EXPLOITS_cve": 1,
}


class _Session:
    def __init__(self, fail=()):
        self.fail = set(fail)
        self.groups: List[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, rows=None, **kwargs):
        group = _group(query)
        self.groups.append(group)
        if group in self.fail:
            raise RuntimeError("Neo.ClientError.Statement.TypeError")
        result = MagicMock()
        result.consume.return_value.counters.relationships_created = _CREATED.get(group, 0)
        return result


def _client(session: _Session):
    client = nc.Neo4jClient.__new__(nc.Neo4jClient)
    client.driver = MagicMock()
    client.driver.session.return_value = session
    return client


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch):
    monkeypatch.setattr(nc, "query_pause", lambda *a, **k: None)
    monkeypatch.setattr(run_misp_to_neo4j, "query_pause", lambda *a, **k: None)


def test_replayed_rows_count_once_and_created_comes_from_the_counters():
    session = _Session()
    result = _client(session).create_misp_relationships_batch(_definitions(), source_id="misp")
    assert session.groups == ["INDICATES_malware", "AFFECTS_vulnerability", "AFFECTS_cve"]
    # 3 AFFECTS rows once (they counted 6) and 3 INDICATES rows; 5 relationships created.
    assert (int(result), result.failed, result.created) == (6, 0, 5)


def test_a_replay_that_fails_counts_its_rows_once_as_failed(caplog):
    session = _Session(fail={"AFFECTS_vulnerability", "AFFECTS_cve"})
    with caplog.at_level(logging.WARNING, logger="neo4j_client"):
        result = _client(session).create_misp_relationships_batch(_definitions(), source_id="misp")
    # Both replays failed: the 3 AFFECTS rows are 3 failed rows (they counted 6), 3 INDICATES rows written.
    assert (int(result), result.failed, result.created) == (3, 3, 2)
    (line,) = [r.getMessage() for r in caplog.records if r.getMessage().startswith("Relationship batch: ")]
    assert "3 of 6 rows not written" in line


def test_one_failed_replay_fails_the_rows():
    result = _client(_Session(fail={"AFFECTS_vulnerability"})).create_misp_relationships_batch(
        _definitions(), source_id="misp"
    )
    assert (int(result), result.failed, result.created) == (3, 3, 5)


def test_an_indicator_exploits_row_counts_once():
    session = _Session()
    result = _client(session).create_misp_relationships_batch(_with_exploits(), source_id="misp")
    assert session.groups == [
        "INDICATES_malware",
        "AFFECTS_vulnerability",
        "AFFECTS_cve",
        "EXPLOITS_vulnerability",
        "EXPLOITS_cve",
    ]
    # 3 AFFECTS rows, 3 INDICATES rows and the EXPLOITS row once each; 6 relationships created.
    assert (int(result), result.failed, result.created) == (7, 0, 6)


@pytest.mark.parametrize(("failing", "created"), [("EXPLOITS_vulnerability", 6), ("EXPLOITS_cve", 5)])
def test_one_failed_exploits_replay_fails_the_row(failing, created):
    """The EXPLOITS row counts as written only when both statements succeed."""
    result = _client(_Session(fail={failing})).create_misp_relationships_batch(_with_exploits(), source_id="misp")
    assert (int(result), result.failed, result.created) == (6, 1, created)


def test_a_failed_exploits_replay_counts_its_row_once_as_failed(caplog):
    session = _Session(fail={"EXPLOITS_vulnerability", "EXPLOITS_cve"})
    with caplog.at_level(logging.WARNING, logger="neo4j_client"):
        result = _client(session).create_misp_relationships_batch(_with_exploits(), source_id="misp")
    assert (int(result), result.failed, result.created) == (6, 1, 5)
    (line,) = [r.getMessage() for r in caplog.records if r.getMessage().startswith("Relationship batch: ")]
    assert "1 of 7 rows not written" in line


def _sync(session: _Session) -> MISPToNeo4jSync:
    return MISPToNeo4jSync(neo4j_client=_client(session))


def test_the_sync_counts_rows_written_and_relationships_created(caplog):
    sync = _sync(_Session())
    sync._count_relationship_writes(sync._create_relationships(_definitions(), "misp"))
    assert (sync.stats["relationship_rows_written"], sync.stats["relationships_created"]) == (6, 5)


def test_rows_not_written_never_exceed_the_rows_sent(caplog):
    """``[REL-ROWS-FAILED] X of Y``: X counted the failed AFFECTS replays twice (6 of 6 here)."""
    sync = _sync(_Session(fail={"AFFECTS_vulnerability", "AFFECTS_cve"}))
    with caplog.at_level(logging.WARNING, logger="run_misp_to_neo4j"):
        written = sync._create_relationships(_definitions(), "misp")
    assert (int(written), written.failed) == (3, 3)
    assert sync.stats["relationships_failed"] == 3
    (line,) = [r.getMessage() for r in caplog.records if r.getMessage().startswith("[REL-ROWS-FAILED]")]
    assert line.startswith("[REL-ROWS-FAILED] 3 of 6 relationship rows were not written")


def test_chunks_add_up(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_REL_BATCH_SIZE", "3")
    sync = _sync(_Session())
    written = sync._create_relationships(_definitions(), "misp")
    # chunk 1: the 3 AFFECTS rows (3 created); chunk 2: the 3 INDICATES rows (2 created)
    assert (int(written), written.created) == (6, 5)


def test_the_early_paths_return_a_batch_result():
    """No definitions, or a client without the batch writer: a ``RelationshipBatchResult`` of 0 rows."""
    empty = _sync(_Session())._create_relationships([], "misp")
    no_writer = MISPToNeo4jSync(neo4j_client=MagicMock(spec=[]))._create_relationships(_definitions(), "misp")
    for result in (empty, no_writer):
        assert isinstance(result, RelationshipBatchResult)
        assert (int(result), result.failed, result.created) == (0, 0, 0)


def test_a_plain_int_result_adds_rows_only():
    sync = MISPToNeo4jSync(neo4j_client=MagicMock())
    sync._count_relationship_writes(4)
    assert (sync.stats["relationship_rows_written"], sync.stats["relationships_created"]) == (4, 0)


# --------------------------------------------------------------------------- the paged path


def _syncer() -> MISPToNeo4jSync:
    syncer = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    syncer.neo4j = MagicMock()
    syncer.stats = {"events_processed": 0, "events_failed": 0, "errors": 0}
    syncer.sync_to_neo4j = lambda items: (len(items), 0, [])
    syncer.parse_attribute = lambda attr, event: ({"type": "vulnerability", "cve_id": attr["value"]}, [])
    syncer._same_report_context = lambda *a, **k: []
    return syncer


def _defs(n: int) -> List[Dict]:
    return [dict(_definitions()[0], from_key={"cve_id": f"CVE-2026-{k:05d}"}) for k in range(n)]


def test_the_paged_path_returns_definitions_and_logs_rows_apart(monkeypatch, caplog):
    """NVD part 8 of the 730-day run: 179 definitions, logged as 358 cross rels and returned as such."""
    monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 2)
    syncer = _syncer()
    syncer._build_cross_item_relationships = lambda items, reports=None: _defs(179)
    # a writer that reports more rows than definitions (as the replay did: 358 for 179)
    syncer._create_relationships = lambda rels, source_id: RelationshipBatchResult(2 * len(rels), created=len(rels))
    attributes = [{"value": f"CVE-2026-{k:05d}"} for k in range(5)]
    with caplog.at_level(logging.INFO, logger="run_misp_to_neo4j"):
        parsed, cross, errors = syncer._process_large_event_paged("63", {"Event": {"id": "63"}}, attributes)
    assert (parsed, cross, errors) == (5, 179, 0)
    (line,) = [r.getMessage() for r in caplog.records if "large-event streaming complete" in r.getMessage()]
    assert line == (
        "Event 63: large-event streaming complete — 5 total items, 179 cross-item rel defs "
        "(358 relationship rows written), 0 errors"
    )
    assert (syncer.stats["relationship_rows_written"], syncer.stats["relationships_created"]) == (358, 179)


def test_the_small_event_path_returns_definitions():
    syncer = _syncer()
    syncer._build_cross_item_relationships = lambda items, reports=None: _defs(7)
    syncer._create_relationships = lambda rels, source_id: RelationshipBatchResult(2 * len(rels), created=len(rels))
    attributes = [{"value": f"CVE-2026-{k:05d}"} for k in range(3)]
    assert syncer._process_event_attributes("7", {"Event": {"id": "7"}}, attributes) == (3, 7, 0)
    assert (syncer.stats["relationship_rows_written"], syncer.stats["relationships_created"]) == (14, 7)


# --------------------------------------------------------------------------- the run summary


def test_the_run_reports_definitions_rows_and_created_and_the_sector_labels_once(monkeypatch, caplog):
    """A small event (7 definitions, as the KEV event) and a paged one (179, as NVD part 8)."""
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC", "0")
    monkeypatch.setenv("EDGEGUARD_MISP_RETRY_COOLDOWN_SEC", "0")
    monkeypatch.delenv("EDGEGUARD_MISP_PAGED_FETCH_ABOVE", raising=False)
    monkeypatch.delenv("EDGEGUARD_MAX_EVENT_ATTRIBUTES", raising=False)
    monkeypatch.setattr(run_misp_to_neo4j.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setattr(run_misp_to_neo4j, "record_collection_success", lambda *_a, **_k: None)
    monkeypatch.setattr(run_misp_to_neo4j, "record_collection_failure", lambda *_a, **_k: None)
    monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 3)
    run_misp_to_neo4j.INDEX_FETCH_STATE["truncated"] = False
    index = [
        {"id": "53", "info": "EdgeGuard-cisa_kev-2026-11-01", "attribute_count": "2"},
        {"id": "63", "info": "EdgeGuard-nvd-2026-11-01-part8", "attribute_count": "5"},
    ]
    attributes = {"53": 2, "63": 5}
    defs = {2: 7, 5: 179}
    neo4j = MagicMock()
    neo4j.create_misp_relationships_batch.side_effect = lambda rows, source_id="misp": RelationshipBatchResult(
        2 * len(rows), created=len(rows)
    )
    sync = MISPToNeo4jSync(neo4j_client=neo4j)
    monkeypatch.setattr(sync, "check_services_available", lambda: (True, "ok"))
    monkeypatch.setattr(sync, "connect", lambda: True)
    monkeypatch.setattr(sync, "fetch_edgeguard_events", lambda since=None, sector=None: [dict(e) for e in index])
    monkeypatch.setattr(
        sync,
        "fetch_event_details",
        lambda event_id: {
            "id": event_id,
            "info": "x",
            "Attribute": [{"value": f"CVE-2026-{k:05d}"} for k in range(attributes[event_id])],
        },
    )
    monkeypatch.setattr(
        sync, "parse_attribute", lambda attr, event: ({"type": "vulnerability", "cve_id": attr["value"]}, [])
    )
    monkeypatch.setattr(sync, "sync_to_neo4j", lambda items: (len(items), 0, []))
    monkeypatch.setattr(sync, "_build_cross_item_relationships", lambda items, reports=None: _defs(defs[len(items)]))
    try:
        with caplog.at_level(logging.INFO, logger="run_misp_to_neo4j"):
            assert sync.run(incremental=False) is True
    finally:
        run_misp_to_neo4j.INDEX_FETCH_STATE["truncated"] = False
    messages = [r.getMessage() for r in caplog.records if r.name == "run_misp_to_neo4j"]
    assert "Sync totals: 7 parsed items across events; 186 cross-item rel defs built (pre-Neo4j)" in messages
    assert any(m.startswith("Relationship rows written: 372 ") for m in messages), messages
    assert any(m.startswith("Relationships created: 186 ") for m in messages), messages
    assert not [m for m in messages if "sector labels" in m.lower()], "the client logs the count, once"
    neo4j.apply_sector_labels.assert_called_once_with()


def test_apply_sector_labels_logs_what_it_counts(caplog):
    session = MagicMock()
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *a: False
    session.run.return_value.single.return_value = {"labeled": 3}
    client = nc.Neo4jClient.__new__(nc.Neo4jClient)
    client.driver = MagicMock()
    client.driver.session.return_value = session
    with caplog.at_level(logging.INFO, logger="neo4j_client"):
        total = client.apply_sector_labels()
    lines = [r.getMessage() for r in caplog.records if "ector labels" in r.getMessage()]
    assert lines == [
        f"Sector labels applied to {total} nodes with a sector zone (labels they already carried included)"
    ]
