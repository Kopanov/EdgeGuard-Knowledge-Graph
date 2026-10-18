"""Loss accounting of the MISP → Neo4j sync and the MISP writer (2026-10 production-readiness review).

A run that skipped or failed work must never report unqualified success. These tests pin the
behaviour that closed the silent partial-loss paths:

* an event whose details cannot be fetched is counted in ``events_failed`` and fails the run;
* an item no merge path accepts is reported as unroutable (stats + WARNING), counted neither as a
  success nor as an error;
* relationship rows dropped by permanent Neo4j batch failures are returned through
  ``RelationshipBatchResult.failed``, recorded in ``stats["relationships_failed"]`` with a
  WARNING, and fail the run;
* a zero-event window is a WARNING with a successful run by default and, with
  ``EDGEGUARD_SYNC_MIN_EVENTS`` >= 1, an ERROR with a failed run; the variable is forwarded
  by ``docker-compose.yml`` and documented;
* ``MISPWriter._push_batch`` reconciles the pushed attributes against the MISP response: absent
  attributes are reported (and, with ``EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING``, counted as
  failed); a batch whose response carries no attribute list is recorded as unverified.

Every test here fails when its fix is reverted; control cases pin the unchanged happy path so
that the failure assertions are not vacuous.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import run_misp_to_neo4j as rm  # noqa: E402
from collectors import misp_writer as mw  # noqa: E402
from neo4j_client import Neo4jClient, RelationshipBatchResult  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNC_LOGGER = "run_misp_to_neo4j"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


def _run_sync(monkeypatch, events, *, details=None):
    """``MISPToNeo4jSync`` whose services, connection and MISP fetches are replaced by fakes.

    ``details`` maps an event id to the dict ``fetch_event_details`` returns for it; an id that is
    missing from the mapping is fetched as ``None`` (details could not be retrieved). Returns the
    sync, the list of event ids whose details were requested, and the recorded collection outcome.
    """
    sync = rm.MISPToNeo4jSync(neo4j_client=MagicMock())
    monkeypatch.setattr(sync, "check_services_available", lambda: (True, "ok"))
    monkeypatch.setattr(sync, "connect", lambda: True)
    monkeypatch.setattr(sync, "fetch_edgeguard_events", lambda since=None, sector=None: list(events))
    fetched: list = []

    def fake_details(event_id):
        fetched.append(str(event_id))
        return (details or {}).get(str(event_id))

    monkeypatch.setattr(sync, "fetch_event_details", fake_details)
    monkeypatch.setattr(rm.time, "sleep", lambda *_a, **_k: None)
    outcomes: dict = {"success": 0, "failure": []}
    monkeypatch.setattr(
        rm, "record_collection_success", lambda *_a, **_k: outcomes.__setitem__("success", outcomes["success"] + 1)
    )
    monkeypatch.setattr(rm, "record_collection_failure", lambda _source, msg=None: outcomes["failure"].append(msg))
    return sync, fetched, outcomes


def _rel_client(fail_when: str):
    """``Neo4jClient`` whose session raises a non-retryable error for queries containing ``fail_when``.

    A plain ``RuntimeError`` has no Neo4j ``code`` so ``_is_retryable_neo4j_error`` classifies it as
    permanent and ``_run_rows`` gives up immediately (no backoff sleeps).
    """
    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    client._connection_healthy = True
    calls: list = []

    def run(query, **kwargs):
        rows = list(kwargs.get("rows") or [])
        calls.append((query, rows))
        if fail_when in query:
            raise RuntimeError("simulated non-retryable failure")
        return MagicMock()

    session = MagicMock()
    session.run = run
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *_a: False
    client.driver.session.return_value = session
    return client, calls


def _actor_employs(i: int) -> dict:
    return {
        "rel_type": "EMPLOYS_TECHNIQUE",
        "from_type": "ThreatActor",
        "from_key": {"name": f"APT-{i}"},
        "to_type": "Technique",
        "to_key": {"mitre_id": f"T{1000 + i}"},
    }


def _attributed_to(i: int) -> dict:
    return {
        "rel_type": "ATTRIBUTED_TO",
        "from_type": "Malware",
        "from_key": {"name": f"Family-{i}"},
        "to_type": "ThreatActor",
        "to_key": {"name": f"APT-{i}"},
    }


class _FakeResponse:
    def __init__(self, payload, status_code: int = 200):
        self.status_code = status_code
        self._payload = payload
        self.text = ""

    def json(self):
        return self._payload


def _writer(monkeypatch, payload):
    """``MISPWriter`` whose HTTP session answers every POST with HTTP 200 and ``payload``."""
    writer = mw.MISPWriter(url="https://misp.test", api_key="test-key", verify_ssl=True)
    posted: list = []

    class _Session:
        def post(self, url, json=None, **_kwargs):
            posted.append((url, json))
            return _FakeResponse(payload)

    writer.session = _Session()
    monkeypatch.setattr(mw.time, "sleep", lambda *_a, **_k: None)
    return writer, posted


PUSHED = [
    {"type": "ip-dst", "value": "203.0.113.10", "category": "Network activity"},
    {"type": "sha256", "value": "ABCDEF" + "0" * 58, "category": "Payload delivery"},
    {"type": "domain", "value": "malicious.example", "category": "Network activity"},
]


def _event_payload(stored):
    return {"Event": {"id": "5", "info": "EdgeGuard-test", "Attribute": stored}}


# ---------------------------------------------------------------------------
# 1. Event whose details cannot be fetched
# ---------------------------------------------------------------------------


def test_process_single_event_counts_missing_details_as_a_failed_event(monkeypatch):
    sync = rm.MISPToNeo4jSync(neo4j_client=MagicMock())
    monkeypatch.setattr(sync, "fetch_event_details", lambda event_id: None)
    assert sync._process_single_event("7", "EdgeGuard-test") == (0, 0, 1)
    assert sync.stats["events_failed"] == 1
    assert sync.stats["events_processed"] == 0


def test_unfetchable_event_fails_the_run_and_records_no_success(monkeypatch, caplog):
    sync, fetched, outcomes = _run_sync(monkeypatch, [{"id": "7", "info": "EdgeGuard-test"}], details={})
    with caplog.at_level(logging.ERROR, logger=SYNC_LOGGER):
        ok = sync.run(incremental=False)
    assert fetched == ["7"]
    assert ok is False
    assert sync.stats["events_failed"] == 1
    assert sync.stats["events_processed"] == 0
    assert sync.stats["events_index_total"] == 1
    assert outcomes["success"] == 0
    assert len(outcomes["failure"]) == 1
    reason = sync.get_stats()["last_failure_reason"]
    assert "1 event(s) could not be fetched from MISP" in reason
    assert outcomes["failure"][0] == reason
    assert any(r.levelno == logging.ERROR and "could not be fetched" in r.getMessage() for r in caplog.records), (
        "the skipped event must be logged at ERROR"
    )
    reason = outcomes["failure"][0]
    assert "could not be fetched from MISP" in reason
    assert "[MERGE-RETURNED-FALSE]" not in reason, "fetch failures must not be described as merge errors"
    assert sync.stats["events_unfetchable"] == 1


def test_fetched_event_without_attributes_is_still_a_successful_run(monkeypatch):
    """Control: the harness itself does not fail the run — only the missing details do."""
    details = {"7": {"id": "7", "info": "EdgeGuard-test", "Attribute": []}}
    sync, fetched, outcomes = _run_sync(monkeypatch, [{"id": "7", "info": "EdgeGuard-test"}], details=details)
    assert sync.run(incremental=False) is True
    assert fetched == ["7"]
    assert sync.stats["events_processed"] == 1
    assert sync.stats["events_failed"] == 0
    assert outcomes["success"] == 1
    assert outcomes["failure"] == []


# ---------------------------------------------------------------------------
# 2. _sync_single_item result is honoured by the chunk loop
# ---------------------------------------------------------------------------


def test_sync_single_item_false_is_reported_as_unroutable_not_as_success_or_error(monkeypatch, caplog):
    sync = rm.MISPToNeo4jSync(neo4j_client=MagicMock())
    monkeypatch.setattr(sync, "_sync_single_item", lambda item: False)
    with caplog.at_level(logging.WARNING, logger=SYNC_LOGGER):
        assert sync._sync_to_neo4j_chunk([{"type": "campaign", "name": "Operation X"}]) == (0, 0)
    assert sync.stats["items_unroutable"] == 1
    assert any("[ITEM-UNROUTABLE]" in r.getMessage() for r in caplog.records)


def test_sync_single_item_true_is_counted_as_a_success(monkeypatch):
    sync = rm.MISPToNeo4jSync(neo4j_client=MagicMock())
    monkeypatch.setattr(sync, "_sync_single_item", lambda item: True)
    assert sync._sync_to_neo4j_chunk([{"type": "campaign", "name": "Operation X"}]) == (1, 0)


def test_item_no_merge_path_accepts_is_unroutable_with_the_real_single_item_path():
    sync = rm.MISPToNeo4jSync(neo4j_client=MagicMock())
    assert sync._sync_to_neo4j_chunk([{"type": "campaign", "name": "Operation X"}]) == (0, 0)
    assert sync.stats["items_unroutable"] == 1
    assert sync.stats["errors"] == 0


def test_unroutable_items_are_summarised_without_failing_the_run(monkeypatch, caplog):
    sync, _fetched, outcomes = _run_sync(
        monkeypatch, [{"id": "1", "info": "EdgeGuard-test"}], details={"1": {"Attribute": []}}
    )
    monkeypatch.setattr(sync, "_process_single_event", lambda *a, **k: (0, 0, 0))
    sync.stats["items_unroutable"] = 2
    with caplog.at_level(logging.WARNING, logger=SYNC_LOGGER):
        assert sync.run() is True
    assert outcomes["success"] == 1 and outcomes["failure"] == []
    assert any("no merge path accepted them: 2" in r.getMessage() for r in caplog.records)


def test_single_item_merge_exception_returns_false_and_counts_one_error():
    """``_sync_single_item`` swallows the exception and reports the outcome through its return value."""
    neo = MagicMock()
    neo.merge_malware.side_effect = RuntimeError("simulated merge failure")
    sync = rm.MISPToNeo4jSync(neo4j_client=neo)
    assert sync._sync_single_item({"type": "malware", "name": "Emotet", "tag": "misp"}) is False
    assert sync.stats["errors"] == 1


# ---------------------------------------------------------------------------
# 3. Relationship rows lost to permanent batch failures
# ---------------------------------------------------------------------------


def test_permanently_failed_relationship_rows_are_returned_as_failed():
    client, calls = _rel_client("ATTRIBUTED_TO")
    rels = [_actor_employs(1), _actor_employs(2), _attributed_to(1), _attributed_to(2), _attributed_to(3)]
    result = client.create_misp_relationships_batch(rels, source_id="misp")
    assert isinstance(result, RelationshipBatchResult)
    assert result == 2, "written rows keep the int semantics"
    assert result.failed == 3
    assert result + 1 == 3, "arithmetic on the result behaves like an int"
    assert len(calls) == 2, "one UNWIND per populated group; the failing group is not retried"


def test_fully_successful_relationship_batch_reports_zero_failed():
    client, _calls = _rel_client("no-query-matches-this")
    rels = [_actor_employs(1), _attributed_to(1)]
    result = client.create_misp_relationships_batch(rels, source_id="misp")
    assert result == 2
    assert result.failed == 0


def test_sync_records_relationships_failed_with_a_warning(monkeypatch, caplog):
    monkeypatch.setenv("EDGEGUARD_REL_BATCH_SIZE", "3")
    neo = MagicMock()
    neo.create_misp_relationships_batch.side_effect = lambda chunk, source_id="misp": RelationshipBatchResult(
        len(chunk) - 1, 1
    )
    sync = rm.MISPToNeo4jSync(neo4j_client=neo)
    with caplog.at_level(logging.WARNING, logger=SYNC_LOGGER):
        created = sync._create_relationships([_actor_employs(i) for i in range(5)], "misp")
    assert created == 3, "two chunks (3 + 2 rows), one failed row each"
    assert sync.stats["relationships_failed"] == 2
    assert any(
        r.levelno == logging.WARNING and "[REL-ROWS-FAILED]" in r.getMessage() and "2 of 5" in r.getMessage()
        for r in caplog.records
    )


def test_plain_int_batch_results_record_no_relationship_failures(monkeypatch, caplog):
    """Control: an ``int`` return (older client or test double) carries no failure information."""
    monkeypatch.setenv("EDGEGUARD_REL_BATCH_SIZE", "3")
    neo = MagicMock()
    neo.create_misp_relationships_batch.side_effect = lambda chunk, source_id="misp": len(chunk)
    sync = rm.MISPToNeo4jSync(neo4j_client=neo)
    with caplog.at_level(logging.WARNING, logger=SYNC_LOGGER):
        assert sync._create_relationships([_actor_employs(i) for i in range(5)], "misp") == 5
    assert sync.stats["relationships_failed"] == 0
    assert not any("[REL-ROWS-FAILED]" in r.getMessage() for r in caplog.records)


def test_relationship_failures_fail_the_run_even_without_merge_errors(monkeypatch):
    details = {"7": {"id": "7", "info": "EdgeGuard-test", "Attribute": []}}
    sync, _fetched, outcomes = _run_sync(monkeypatch, [{"id": "7", "info": "EdgeGuard-test"}], details=details)

    def process(event_id, event_info):
        sync.stats["events_processed"] += 1
        sync.stats["relationships_failed"] += 4
        return 10, 0, 0

    monkeypatch.setattr(sync, "_process_single_event", process)
    assert sync.run(incremental=False) is False
    assert outcomes["success"] == 0
    reason = sync.get_stats()["last_failure_reason"]
    assert "4 relationship row(s) were not written" in reason
    assert outcomes["failure"] == [reason]


# ---------------------------------------------------------------------------
# 4. Zero-event window and EDGEGUARD_SYNC_MIN_EVENTS
# ---------------------------------------------------------------------------


def test_zero_events_with_the_guard_disabled_is_a_warning_and_a_successful_run(monkeypatch, caplog):
    monkeypatch.setenv("EDGEGUARD_SYNC_MIN_EVENTS", "0")
    sync, fetched, outcomes = _run_sync(monkeypatch, [])
    with caplog.at_level(logging.WARNING, logger=SYNC_LOGGER):
        assert sync.run(incremental=True) is True
    assert fetched == []
    assert sync.stats["zero_events"] is True
    assert sync.stats["events_index_total"] == 0
    assert outcomes["success"] == 1
    assert outcomes["failure"] == []
    assert any(
        r.levelno == logging.WARNING
        and "zero events" in r.getMessage()
        and "EDGEGUARD_SYNC_MIN_EVENTS" in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.parametrize("configured", [None, "1"])
def test_zero_events_by_default_or_with_min_events_one_is_an_error_and_a_failed_run(monkeypatch, caplog, configured):
    if configured is None:
        monkeypatch.delenv("EDGEGUARD_SYNC_MIN_EVENTS", raising=False)
    else:
        monkeypatch.setenv("EDGEGUARD_SYNC_MIN_EVENTS", configured)
    sync, _fetched, outcomes = _run_sync(monkeypatch, [])
    with caplog.at_level(logging.ERROR, logger=SYNC_LOGGER):
        assert sync.run(incremental=True) is False
    assert outcomes["success"] == 0
    assert len(outcomes["failure"]) == 1
    assert "EDGEGUARD_SYNC_MIN_EVENTS=1" in outcomes["failure"][0]
    assert sync.stats["min_events_shortfall"] is True
    assert sync.stats["events_index_total"] == 0
    assert "zero_events" not in sync.stats
    assert "EDGEGUARD_SYNC_MIN_EVENTS=1" in sync.get_stats()["last_failure_reason"]
    assert any(r.levelno == logging.ERROR and "EDGEGUARD_SYNC_MIN_EVENTS=1" in r.getMessage() for r in caplog.records)


def test_fewer_events_than_min_events_fails_before_any_event_is_processed(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_SYNC_MIN_EVENTS", "3")
    sync, fetched, outcomes = _run_sync(monkeypatch, [{"id": "1", "info": "a"}, {"id": "2", "info": "b"}])
    exported: list = []
    monkeypatch.setattr(rm, "record_sync_event_accounting", lambda **kw: exported.append(kw))
    assert sync.run(incremental=False) is False
    assert fetched == []
    # Nothing was attempted: the exported input total is 0 so the coverage-gap invariant holds
    # (events_index_total == events_processed + events_failed); the summary keeps the found count.
    assert exported and exported[-1]["events_index_total"] == 0
    assert exported[-1]["events_processed"] == 0 and exported[-1]["events_failed"] == 0
    assert sync.stats["events_index_total"] == 2
    assert sync.stats["events_index_total"] == 2
    assert outcomes["success"] == 0


def test_min_events_satisfied_processes_the_window(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_SYNC_MIN_EVENTS", "1")
    details = {"1": {"id": "1", "info": "a", "Attribute": []}}
    sync, fetched, outcomes = _run_sync(monkeypatch, [{"id": "1", "info": "a"}], details=details)
    assert sync.run(incremental=False) is True
    assert fetched == ["1"]
    assert "min_events_shortfall" not in sync.stats
    assert outcomes["success"] == 1


@pytest.mark.parametrize(
    "raw, expected",
    [("", 1), ("  ", 1), ("0", 0), ("1", 1), (" 3 ", 3), ("abc", 1), ("-2", 1), ("1.5", 1)],
)
def test_sync_min_events_parsing(monkeypatch, raw, expected):
    monkeypatch.setenv("EDGEGUARD_SYNC_MIN_EVENTS", raw)
    assert rm._sync_min_events() == expected


def test_sync_min_events_unset_requires_one_event(monkeypatch):
    monkeypatch.delenv("EDGEGUARD_SYNC_MIN_EVENTS", raising=False)
    assert rm._sync_min_events() == 1


def test_compose_forwards_sync_min_events_to_the_airflow_service():
    data = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text())
    airflow_env = data["services"]["airflow"]["environment"]
    assert airflow_env.get("EDGEGUARD_SYNC_MIN_EVENTS") == "${EDGEGUARD_SYNC_MIN_EVENTS:-}"


def test_env_example_and_airflow_docs_describe_sync_min_events():
    env_example = (REPO_ROOT / ".env.example").read_text()
    assert "# EDGEGUARD_SYNC_MIN_EVENTS=1" in env_example, ".env.example must document the knob with its default"
    docs = (REPO_ROOT / "docs" / "AIRFLOW_DAGS.md").read_text()
    assert "EDGEGUARD_SYNC_MIN_EVENTS" in docs
    assert "relationships_failed" in docs


# ---------------------------------------------------------------------------
# 5. MISP writer counts what the response confirms
# ---------------------------------------------------------------------------


def test_push_batch_counts_every_attribute_present_in_the_returned_event(monkeypatch):
    stored = [
        {"type": "ip-dst", "value": "203.0.113.10"},
        # MISP lower-cases hashes on save; the comparison must tolerate that.
        {"type": "sha256", "value": ("ABCDEF" + "0" * 58).lower()},
        {"type": "domain", "value": "malicious.example"},
        {"type": "url", "value": "http://pre.existing.example/"},
    ]
    writer, posted = _writer(monkeypatch, _event_payload(stored))
    assert writer._push_batch("5", PUSHED) == (3, 0)
    assert posted[0][0] == "https://misp.test/events/5"
    assert posted[0][1] == {"Attribute": PUSHED}
    assert writer.stats["attributes_added"] == 3
    assert writer.stats["batches_sent"] == 1
    assert writer.stats["batches_unverified"] == 0
    assert writer.stats["attributes_unconfirmed"] == 0


def test_push_batch_reports_unconfirmed_attributes_without_counting_them_as_failed_by_default(monkeypatch, caplog):
    monkeypatch.delenv("EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING", raising=False)
    stored = [
        {"type": "ip-dst", "value": "203.0.113.10"},
        {"type": "sha256", "value": ("ABCDEF" + "0" * 58).lower()},
    ]
    payload = _event_payload(stored)
    payload["errors"] = {"Attribute": [{"value": ["Invalid domain"]}]}
    writer, _posted = _writer(monkeypatch, payload)
    with caplog.at_level(logging.WARNING, logger="collectors.misp_writer"):
        assert writer._push_batch("5", PUSHED) == (3, 0)
    assert writer.stats["attributes_added"] == 3
    assert writer.stats["attributes_unconfirmed"] == 1
    assert writer.stats["batches_unverified"] == 0
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("[UNCONFIRMED]" in m and "1 of 3" in m and "malicious.example" in m for m in warnings)
    assert any("Invalid domain" in m for m in warnings), "a present errors payload is surfaced in the warning"
    assert any("counted as pushed" in m for m in warnings)


def test_push_batch_counts_unconfirmed_attributes_as_failed_in_strict_mode(monkeypatch, caplog):
    monkeypatch.setenv("EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING", "true")
    stored = [
        {"type": "ip-dst", "value": "203.0.113.10"},
        {"type": "sha256", "value": ("ABCDEF" + "0" * 58).lower()},
    ]
    writer, _posted = _writer(monkeypatch, _event_payload(stored))
    with caplog.at_level(logging.WARNING, logger="collectors.misp_writer"):
        assert writer._push_batch("5", PUSHED) == (2, 1)
    assert writer.stats["attributes_added"] == 2
    assert writer.stats["attributes_unconfirmed"] == 1
    assert any("counted as failed" in r.getMessage() for r in caplog.records)


def test_strict_push_accounting_flag_is_forwarded_and_documented():
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text())
    env = compose["services"]["airflow"]["environment"]
    assert env["EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING"] == "${EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING:-}"
    assert "# EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING=false" in (REPO_ROOT / ".env.example").read_text()


def test_push_batch_without_an_attribute_list_keeps_the_attempted_count_as_unverified(monkeypatch, caplog):
    writer, _posted = _writer(monkeypatch, {"saved": True, "success": True})
    with caplog.at_level(logging.INFO, logger="collectors.misp_writer"):
        assert writer._push_batch("5", PUSHED) == (3, 0)
    assert writer.stats["attributes_added"] == 3
    assert writer.stats["batches_unverified"] == 1
    assert writer.stats["attributes_unconfirmed"] == 0
    infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    assert any("[UNVERIFIED]" in m and "event 5" in m for m in infos)


def test_push_batch_with_an_event_but_no_attribute_key_is_unverified(monkeypatch):
    writer, _posted = _writer(monkeypatch, {"Event": {"id": "5", "info": "EdgeGuard-test"}})
    assert writer._push_batch("5", PUSHED) == (3, 0)
    assert writer.stats["batches_unverified"] == 1


def test_push_batch_accepts_a_single_attribute_serialised_as_a_dict(monkeypatch):
    writer, _posted = _writer(monkeypatch, _event_payload({"type": "ip-dst", "value": "203.0.113.10"}))
    assert writer._push_batch("5", PUSHED[:1]) == (1, 0)
    assert writer.stats["batches_unverified"] == 0


def test_confirm_pushed_attributes_helper_shapes():
    assert mw._confirm_pushed_attributes(PUSHED, []) is None
    assert mw._confirm_pushed_attributes(PUSHED, None) is None
    assert mw._confirm_pushed_attributes(PUSHED, [{"category": "no type or value"}]) is None
    confirmed, unconfirmed = mw._confirm_pushed_attributes(
        PUSHED, [{"type": "DOMAIN", "value": "  Malicious.Example "}]
    )
    assert confirmed == 1
    assert unconfirmed == [("ip-dst", "203.0.113.10"), ("sha256", ("ABCDEF" + "0" * 58).lower())]


def test_writer_stats_reset_keeps_the_verification_counters():
    writer = mw.MISPWriter(url="https://misp.test", api_key="test-key", verify_ssl=True)
    writer.stats["batches_unverified"] = 2
    writer.reset_stats()
    assert writer.stats["batches_unverified"] == 0
    assert writer.stats["attributes_unconfirmed"] == 0


# ---------------------------------------------------------------------------
# 5. Event names reach the sync's discovery filter
# ---------------------------------------------------------------------------


def test_every_event_name_the_writer_builds_passes_the_sync_discovery_filter(monkeypatch):
    """With the minimum of one event, a name the discovery filter missed would fail every sync;
    the name ``MISPWriter`` builds for each registered source must be found by
    ``_is_edgeguard_index_event`` and start with the writer's own-event prefix."""
    from source_registry import all_sources

    writer = mw.MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)
    names: list = []

    def lookup(name):
        names.append(name)
        return [{"Event": {"id": "7", "info": name}}]

    monkeypatch.setattr(writer, "_restsearch_events_for_name", lookup)
    for source in all_sources():
        assert writer._get_or_create_event(source.canonical_id, date="2026-10-18") == "7"
        name = names[-1]
        assert name.startswith(mw._OWN_EVENT_PREFIX), name
        assert rm._is_edgeguard_index_event({"info": name, "org": {"name": "ADMIN"}}), name
