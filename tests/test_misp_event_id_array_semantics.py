"""Cypher-template assertions for MISP event-id array semantics.

PR #33 round 10 dropped the legacy scalar ``misp_event_id`` (and
``misp_attribute_id``). All MISP provenance now lives in the array fields
``misp_event_ids[]`` / ``misp_attribute_ids[]``. These tests read the
Cypher templates and pin that the readers use array-only predicates —
guarding against regressions where a future refactor accidentally
re-introduces the scalar.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# mark_inactive_nodes — removed 2026-10-16
# ---------------------------------------------------------------------------


def test_mark_inactive_nodes_is_removed():
    """2026-10-16 (``indicator_aging``): ``mark_inactive_nodes`` (no caller) set ``active`` from
    whether a node's MISP events were listed, on Indicator and Vulnerability alike: a rule beside
    the one aging rule, and a lifecycle write on a label that does not age. It is gone."""
    from neo4j_client import Neo4jClient

    assert not hasattr(Neo4jClient, "mark_inactive_nodes")


# ---------------------------------------------------------------------------
# build_relationships INDICATES co-occurrence — array-only on both ends
# ---------------------------------------------------------------------------


def test_build_relationships_indicates_cooccurrence_is_gone_and_no_scalar_leg_remains():
    """PR #33 round 10 + PR-N7 pinned the INDICATES co-occurrence query
    (#4) as array-only on both sides. 2026-10 (fresh-baseline PR, ResilMesh
    conformance finding F1) removed that query outright — a shared
    per-source, per-day MISP event id never meant the source asserted a
    link. The invariant this test now pins is twofold:

    * the co-occurrence block (and any event-id join between Indicator and
      Malware) is absent, and
    * no inner query anywhere in build_relationships.py reintroduces a
      scalar ``misp_event_id`` leg — the array-only contract from PR #33
      still holds for the queries that remain (Q3a/Q3b/Q7a/Q7b/Q9 all
      propagate ``misp_event_ids[]``)."""
    import ast

    import build_relationships

    src_path = build_relationships.__file__
    with open(src_path) as fh:
        source = fh.read()

    assert "4. Indicator → Malware (INDICATES)" not in source, "the INDICATES co-occurrence block must stay removed"
    assert "eid IN i.misp_event_ids" not in source, "no event-id co-occurrence join may remain"
    assert "eid IN m.misp_event_ids" not in source, "no event-id co-occurrence join may remain"

    # Array-only contract on every remaining inner query: no scalar leg, and
    # no query may stamp misp_cooccurrence any more (report-scoped edges
    # use otx_pulse and are written by the MISP→Neo4j sync).
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not (isinstance(target, ast.Name) and target.id.endswith("_inner")):
                continue
            value = "".join(
                sub.value
                for sub in ast.walk(node.value)
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str)
            )
            assert "misp_cooccurrence" not in value, f"{target.id} re-introduces the misp_cooccurrence stamp"
            for scalar_leg in (
                "i.misp_event_id IS NOT NULL",
                "i.misp_event_id <> ",
                "m.misp_event_id IS NOT NULL",
                "m.misp_event_id <> ",
                "i.misp_event_id = eid",
                "MATCH (i:Indicator {misp_event_id: eid})",
            ):
                assert scalar_leg not in value, f"{target.id} re-introduces a scalar misp_event_id leg: {scalar_leg}"
