"""Cypher-template assertions for the 2026-04 scalar→array consumer fixes.

These tests intercept the Cypher strings sent to Neo4j (via a fake driver) and
assert on the structure of the queries — not on a live Neo4j run. They guard
against regressions where a future refactor accidentally drops the array union
and reverts to the legacy scalar-only behaviour that flipped multi-event nodes
inactive whenever their first-seen event rotated out of the incremental window.
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
# mark_inactive_nodes — Cypher must coalesce array + scalar
# ---------------------------------------------------------------------------


def test_mark_inactive_nodes_uses_array_union_for_indicators():
    from neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)  # bypass __init__/connection
    client.driver = _CapDriver()

    client.mark_inactive_nodes(["77", "88"])

    queries = [c for c, _ in client.driver.captured]
    assert queries, "expected at least one Cypher query"
    blob = "\n".join(queries)

    # The array AND the scalar must both feature in every gate so a multi-event
    # Indicator stays active whenever ANY of its events is in the active list.
    assert "misp_event_ids" in blob, "array field missing from mark_inactive_nodes Cypher"
    assert "misp_event_id" in blob, "scalar field missing from mark_inactive_nodes Cypher"

    # The any/none semantics must be present — not the legacy scalar-only IN check.
    assert "any(eid IN" in blob, "expected any(...) re-activation gate"
    assert "none(eid IN" in blob, "expected none(...) deactivation gate"


def test_mark_inactive_nodes_handles_vulnerabilities_with_same_semantics():
    from neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = _CapDriver()
    client.mark_inactive_nodes(["1"])

    queries = [c for c, _ in client.driver.captured]
    # One of the queries must target Vulnerability — and use the same array union.
    vuln_queries = [q for q in queries if ":Vulnerability" in q]
    assert vuln_queries, "expected a Vulnerability query in mark_inactive_nodes"
    assert "misp_event_ids" in "\n".join(vuln_queries)
    assert "none(eid IN" in "\n".join(vuln_queries)


# ---------------------------------------------------------------------------
# calibrate_cooccurrence_confidence — array union + parameterized large path
# ---------------------------------------------------------------------------


def test_calibrate_event_sizes_query_unions_array_and_scalar():
    """The pre-compute query must count an Indicator against EVERY MISP event in
    its array, not just the first-seen scalar."""
    import enrichment_jobs

    client = MagicMock()
    client.driver = _CapDriver()

    # No indicators → function exits after first query; that's all we need to
    # assert on the event_sizes_query shape.
    enrichment_jobs.calibrate_cooccurrence_confidence(client)

    queries = [c for c, _ in client.driver.captured]
    assert queries, "expected the event-sizes pre-compute query to run"
    pre = queries[0]
    assert "misp_event_ids" in pre, "event_sizes_query must include the array"
    assert "misp_event_id" in pre, "event_sizes_query must include the scalar fallback"
    assert "UNWIND" in pre, "event_sizes_query must UNWIND the union"
    assert "count(DISTINCT i)" in pre, "must count distinct indicators per event"


def test_calibrate_large_event_query_is_parameterized_not_fstring():
    """The 2026-04 fix replaced f-string interpolation of `eid` with apoc.periodic.iterate's
    ``params`` config. Regression test: assert the parameterized form ($eid / $conf) and
    that the literal-quote injection pattern (\"{eid}\" inside the inner cypher) is gone."""
    import enrichment_jobs

    client = MagicMock()
    client.driver = _CapDriver()

    # Wire up the pre-compute to return one large event so the large-event path runs.
    # We do this by patching session.run so the FIRST call (event_sizes_query) returns
    # one >1000-indicator event, and subsequent calls just record.
    real_session = client.driver.session

    call_count = {"n": 0}

    def _sess(**_kw):
        s = real_session()
        if call_count["n"] == 0:
            # event_sizes_query — yield one big event
            s.next_records = [{"eid": "9001", "sz": 5000}]
        call_count["n"] += 1
        return s

    client.driver.session = _sess

    with patch.object(enrichment_jobs.time, "sleep", lambda *_: None):
        enrichment_jobs.calibrate_cooccurrence_confidence(client)

    # Find the large-event apoc.periodic.iterate query among captured cyphers.
    large_queries = [
        c for c, _ in client.driver.captured if "apoc.periodic.iterate" in c and "$eid" in c
    ]
    assert large_queries, (
        "expected at least one parameterized apoc.periodic.iterate (large event path)"
    )

    big = large_queries[0]
    # Must use parameter binding both inside the matcher and the action.
    assert "$eid" in big and "$conf" in big, "params must be bound, not interpolated"
    # Must declare them in the iterate config so APOC propagates them.
    assert "params: {eid: $eid, conf: $conf}" in big, (
        "apoc.periodic.iterate must forward params to inner queries"
    )
    # And the array-union semantics from the small-event path must also be here.
    assert "misp_event_ids" in big and "misp_event_id" in big

    # Negative assertion: no f-string interpolation residue (the legacy bug).
    # We can't grep for {eid} reliably inside a raw string, but the eid value
    # should NOT appear as a literal in the query string itself.
    captured_with_params = [
        (c, p) for c, p in client.driver.captured if "apoc.periodic.iterate" in c and "$eid" in c
    ]
    for cypher, params in captured_with_params:
        assert "9001" not in cypher, (
            "event id must be a parameter, not interpolated into the Cypher string"
        )
        assert params.get("eid") == "9001", "eid must be passed as a session.run param"


# ---------------------------------------------------------------------------
# build_relationships.py:138 INDICATES co-occurrence — scalar+array on both ends
# ---------------------------------------------------------------------------


def test_build_relationships_indicates_cooccurrence_uses_array_on_both_ends():
    """The 2026-04 fix made the INDICATES co-occurrence query symmetric: both the
    Indicator outer and the Malware inner now check scalar OR array. Pre-fix the
    Malware match was scalar-only, dropping co-occurrence edges to Malware whose
    contribution to the event was a re-occurrence."""
    import build_relationships

    # The query strings are constructed inline; rather than execute the function
    # against a fake driver (which would also exercise the rest of the module),
    # we read the source file and grep the relevant block. Cheaper and tighter
    # against future refactors that move the strings around.
    src_path = build_relationships.__file__
    with open(src_path) as fh:
        source = fh.read()

    # The INDICATES (co-occurrence) block lives in a comment block labeled
    # "4. Indicator → Malware (INDICATES)".
    block_start = source.find("4. Indicator → Malware (INDICATES)")
    block_end = source.find("5. ThreatActor → Technique", block_start)
    assert block_start > 0 and block_end > block_start, (
        "could not locate the INDICATES co-occurrence block"
    )
    block = source[block_start:block_end]

    # Outer must include the array OR-clause.
    assert "i.misp_event_ids IS NOT NULL AND size(i.misp_event_ids) > 0" in block, (
        "outer query must include Indicators with array-only event references"
    )

    # Inner Malware match must accept either scalar OR array membership.
    assert "m.misp_event_id = eid" in block and "eid IN m.misp_event_ids" in block, (
        "inner Malware match must accept either scalar or array"
    )

    # Negative assertion: the legacy scalar-only Malware property match must be gone.
    assert "MATCH (m:Malware {misp_event_id: eid})" not in block, (
        "legacy scalar-only property match must be removed"
    )
