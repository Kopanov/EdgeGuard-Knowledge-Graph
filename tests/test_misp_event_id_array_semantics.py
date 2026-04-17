"""Cypher-template assertions for MISP event-id array semantics.

PR #33 round 10 dropped the legacy scalar ``misp_event_id`` (and
``misp_attribute_id``). All MISP provenance now lives in the array fields
``misp_event_ids[]`` / ``misp_attribute_ids[]``. These tests intercept the
Cypher strings sent to Neo4j (via a fake driver) and pin that the readers
use array-only predicates — guarding against regressions where a future
refactor accidentally re-introduces the scalar.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Capturing fake Neo4j driver — records every Cypher session.run() call.
# ---------------------------------------------------------------------------


class _CapSession:
    def __init__(self, captured: List[Tuple[str, Dict[str, Any]]]):
        self._captured = captured
        # Records returned by .single(); empty unless the test populates them.
        self.next_records: List[Dict[str, Any]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def run(self, cypher: str, **params: Any):
        self._captured.append((cypher, params))
        # Mirror neo4j Result enough for the production code to consume.
        result = MagicMock()
        # event_sizes pre-compute iterates — yield records eagerly via __iter__.
        records = self.next_records or []
        result.__iter__ = lambda self_: iter(records)
        result.single = lambda: records[0] if records else None
        return result


class _CapDriver:
    def __init__(self):
        self.captured: List[Tuple[str, Dict[str, Any]]] = []

    def session(self, **_kwargs: Any):
        return _CapSession(self.captured)

    def close(self) -> None:  # for retry decorators that may close
        pass


# ---------------------------------------------------------------------------
# mark_inactive_nodes — array-only Cypher (PR #33 round 10)
# ---------------------------------------------------------------------------


def test_mark_inactive_nodes_uses_array_only_for_indicators():
    from neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)  # bypass __init__/connection
    client.driver = _CapDriver()

    client.mark_inactive_nodes(["77", "88"])

    queries = [c for c, _ in client.driver.captured]
    assert queries, "expected at least one Cypher query"
    blob = "\n".join(queries)

    # Array field is present; legacy scalar field name must NOT appear in any
    # WHERE / SET / coalesce form (we still allow the substring ``misp_event_ids``,
    # so we explicitly grep for the bare scalar pattern).
    assert "misp_event_ids" in blob, "array field missing from mark_inactive_nodes Cypher"
    assert "n.misp_event_id " not in blob and "n.misp_event_id\n" not in blob, (
        "legacy scalar n.misp_event_id leaked back into mark_inactive_nodes Cypher"
    )
    assert "n.misp_event_id IS" not in blob, "legacy scalar IS NULL/NOT NULL check leaked back in"
    assert "n.misp_event_id <>" not in blob, "legacy scalar <> '' check leaked back in"

    # The any/none semantics must still be present.
    assert "any(eid IN" in blob, "expected any(...) re-activation gate"
    assert "none(eid IN" in blob, "expected none(...) deactivation gate"


def test_mark_inactive_nodes_handles_vulnerabilities_with_same_semantics():
    """Both Indicator and Vulnerability must have re-activation (any) AND
    deactivation (none) gates against the array."""
    from neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = _CapDriver()
    client.mark_inactive_nodes(["1"])

    queries = [c for c, _ in client.driver.captured]
    vuln_queries = [q for q in queries if ":Vulnerability" in q]
    assert len(vuln_queries) >= 2, (
        f"expected ≥2 Vulnerability queries (re-activation + deactivation), got {len(vuln_queries)}"
    )
    vuln_blob = "\n".join(vuln_queries)
    assert "any(eid IN" in vuln_blob, "Vulnerability re-activation gate (any()) is missing"
    assert "none(eid IN" in vuln_blob, "Vulnerability deactivation gate (none()) is missing"
    assert "misp_event_ids" in vuln_blob, "Vulnerability queries must use the array"
    assert "retired_at" in vuln_blob, "Vulnerability re-activation must respect retired_at"


# ---------------------------------------------------------------------------
# calibrate_cooccurrence_confidence — array-only event sizing
# ---------------------------------------------------------------------------


def test_calibrate_event_sizes_query_is_array_only():
    """The pre-compute query must count an Indicator against EVERY MISP event
    in its misp_event_ids[] array. The legacy scalar fallback was removed in
    PR #33 round 10."""
    import enrichment_jobs

    client = MagicMock()
    client.driver = _CapDriver()

    # No indicators → function exits after first query; that's all we need.
    enrichment_jobs.calibrate_cooccurrence_confidence(client)

    queries = [c for c, _ in client.driver.captured]
    assert queries, "expected the event-sizes pre-compute query to run"
    pre = queries[0]
    assert "misp_event_ids" in pre, "event_sizes_query must include the array"
    assert "i.misp_event_id " not in pre and "i.misp_event_id\n" not in pre, (
        "legacy scalar i.misp_event_id leaked back into event_sizes_query"
    )
    assert "UNWIND" in pre, "event_sizes_query must UNWIND the array"
    assert "count(DISTINCT i)" in pre, "must count distinct indicators per event"


def test_calibrate_large_event_query_is_parameterized_array_only():
    """Large-event path uses apoc.periodic.iterate with parameter binding.
    PR #33 round 10: scalar leg dropped, only the array IN-membership."""
    import enrichment_jobs

    client = MagicMock()
    client.driver = _CapDriver()

    real_session = client.driver.session
    call_count = {"n": 0}

    def _sess(**_kw):
        s = real_session()
        if call_count["n"] == 0:
            s.next_records = [{"eid": "9001", "sz": 5000}]
        call_count["n"] += 1
        return s

    client.driver.session = _sess

    with patch.object(enrichment_jobs.time, "sleep", lambda *_: None):
        enrichment_jobs.calibrate_cooccurrence_confidence(client)

    large_queries = [c for c, _ in client.driver.captured if "apoc.periodic.iterate" in c and "$eid" in c]
    assert large_queries, "expected at least one parameterized apoc.periodic.iterate (large event path)"

    big = large_queries[0]
    assert "$eid" in big and "$conf" in big, "params must be bound, not interpolated"
    assert "params: {eid: $eid, conf: $conf}" in big, "apoc.periodic.iterate must forward params to inner queries"
    assert "misp_event_ids" in big and "i.misp_event_id " not in big, (
        "large-event query must be array-only (no scalar leg)"
    )

    # Negative: no f-string interpolation residue.
    captured_with_params = [(c, p) for c, p in client.driver.captured if "apoc.periodic.iterate" in c and "$eid" in c]
    for cypher, params in captured_with_params:
        assert "9001" not in cypher, "event id must be a parameter, not interpolated into the Cypher string"
        assert params.get("eid") == "9001", "eid must be passed as a session.run param"


# ---------------------------------------------------------------------------
# build_relationships INDICATES co-occurrence — array-only on both ends
# ---------------------------------------------------------------------------


def test_build_relationships_indicates_cooccurrence_is_array_only():
    """PR #33 round 10: the INDICATES co-occurrence query is array-only on
    both the Indicator outer and the Malware inner. Pre-cleanup it had a
    scalar+array union; now only the array."""
    import build_relationships

    src_path = build_relationships.__file__
    with open(src_path) as fh:
        source = fh.read()

    block_start = source.find("4. Indicator → Malware (INDICATES)")
    block_end = source.find("5. ThreatActor → Technique", block_start)
    assert block_start > 0 and block_end > block_start, "could not locate the INDICATES co-occurrence block"
    block = source[block_start:block_end]

    # Outer: array filter only.
    assert "i.misp_event_ids IS NOT NULL AND size(i.misp_event_ids) > 0" in block, (
        "outer query must filter Indicators by misp_event_ids[]"
    )
    # No leftover scalar leg.
    assert "i.misp_event_id IS NOT NULL" not in block, "outer scalar leg must be removed"
    assert "i.misp_event_id <> " not in block, "outer scalar empty-check must be removed"

    # Inner Malware match: array IN-membership only.
    assert "eid IN m.misp_event_ids" in block, "inner Malware match must use array IN membership"
    assert "m.misp_event_id = eid" not in block, "inner scalar match must be removed"
    assert "MATCH (m:Malware {misp_event_id: eid})" not in block, "legacy scalar property match must be removed"
