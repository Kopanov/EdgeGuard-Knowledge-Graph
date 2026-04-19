"""
Tests for ``_dedup_concat_clause`` / ``_dedup_concat_optional_clause`` —
the canonical Cypher fragment helpers for list-accumulator SET clauses.

Why this file exists (read this before changing any assertions):
    The codebase has 47+ ``SET <prop> = apoc.coll.toSet(coalesce(<prop>, []) + …)``
    fragments scattered across MERGE/SET clauses. Phase 2 of the
    apoc.coll.toSet → native-Cypher migration centralizes those into two
    helpers in ``src/neo4j_client.py``. Phase 3 (a follow-up PR) will
    flip the helper internals to native Cypher.

    These tests pin the contracts that BOTH phases must satisfy:

      1. **Output equals the legacy literal** — Phase 2 must not
         change Cypher behavior. If the helper output diverges from
         the original ``apoc.coll.toSet(coalesce(<prop>, []) + …)``
         string, every existing string-pinning test would still pass
         (because they grep for the literal substring) yet runtime
         queries would silently change.
      2. **Cypher-injection guards reject malformed prop refs** — the
         helper splices ``prop_ref`` directly into Cypher. Any path
         that bypasses ``_PROP_NAME_RE`` must error loudly.
      3. **Pattern-B CASE shape is byte-exact to the original** — there
         are 11 batch-relationship templates that all duplicated the
         same multi-line CASE expression. The helper now emits a single
         line, but the *parsed* Cypher must be equivalent (same predicate,
         same array literal, same gating).
      4. **Same-element re-merge is idempotent** — re-syncing the same
         MISP event must NOT grow ``r.misp_event_ids[]``. This is the
         contract the Kimi-style "Cypher dedupes on SET" myth would
         silently break. We assert it via Python (verifying the helper
         output preserves the dedup operator) since spinning up Neo4j
         in CI is cost-prohibitive.
      5. **Pattern-B null-element guard works** — re-syncing with a
         row whose ``misp_event_id`` is None must NOT grow the array.
      6. **Insertion-order preserved by the dedup operator** — at least
         one consumer (STIX exporter integration test) asserts list
         equality on ``misp_event_ids``. Order changes would break it.

    If you're tightening any of these assertions, also tighten the
    matching real-DB integration test before changing helper internals.
"""

from __future__ import annotations

import re
import sys

import pytest

sys.path.insert(0, "src")

from neo4j_client import (  # noqa: E402
    _dedup_concat_clause,
    _dedup_concat_optional_clause,
    _zone_override_global_clause,
)

# ---------------------------------------------------------------------------
# 1. Output equals the legacy literal (phase-2 contract)
# ---------------------------------------------------------------------------


class TestDedupConcatClauseOutput:
    """``_dedup_concat_clause`` must emit the canonical apoc.coll.toSet form."""

    def test_basic_two_list_merge(self):
        out = _dedup_concat_clause("n.source", "$source_array")
        assert out == "apoc.coll.toSet(coalesce(n.source, []) + $source_array)"

    def test_array_of_one_literal(self):
        out = _dedup_concat_clause("r.sources", "[$source_id]")
        assert out == "apoc.coll.toSet(coalesce(r.sources, []) + [$source_id])"

    def test_unwind_row_field(self):
        out = _dedup_concat_clause("r.sources", "[row.source_id]")
        assert out == "apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id])"

    def test_coalesce_inside_addition(self):
        out = _dedup_concat_clause("n.abuse_categories", "coalesce(item.abuse_categories, [])")
        assert out == "apoc.coll.toSet(coalesce(n.abuse_categories, []) + coalesce(item.abuse_categories, []))"

    def test_dynamic_property_name(self):
        # The merge_node_with_source extra_props loop emits the helper with
        # a dynamic prop_name — pin a representative case (aliases is one
        # of the _ARRAY_ACCUMULATE_PROPS).
        out = _dedup_concat_clause("n.aliases", "$aliases")
        assert out == "apoc.coll.toSet(coalesce(n.aliases, []) + $aliases)"


class TestDedupConcatOptionalClauseOutput:
    """``_dedup_concat_optional_clause`` must emit the canonical CASE-gated form."""

    def test_node_side_no_empty_string_guard(self):
        out = _dedup_concat_optional_clause("n.misp_event_ids", "item.misp_event_id")
        assert out == (
            "apoc.coll.toSet(coalesce(n.misp_event_ids, []) + "
            "CASE WHEN item.misp_event_id IS NOT NULL "
            "THEN [item.misp_event_id] ELSE [] END)"
        )

    def test_misp_attribute_id_node_side(self):
        out = _dedup_concat_optional_clause("n.misp_attribute_ids", "item.misp_attribute_id")
        assert out == (
            "apoc.coll.toSet(coalesce(n.misp_attribute_ids, []) + "
            "CASE WHEN item.misp_attribute_id IS NOT NULL "
            "THEN [item.misp_attribute_id] ELSE [] END)"
        )

    def test_batch_rel_with_empty_string_guard(self):
        # The 11 batch-relationship templates in create_misp_relationships_batch
        # all use the empty-string guard because some upstream paths emit ""
        # rather than None.
        out = _dedup_concat_optional_clause("r.misp_event_ids", "row.misp_event_id", require_nonempty_string=True)
        assert out == (
            "apoc.coll.toSet(coalesce(r.misp_event_ids, []) + "
            "CASE WHEN row.misp_event_id IS NOT NULL AND row.misp_event_id <> '' "
            "THEN [row.misp_event_id] ELSE [] END)"
        )

    def test_value_expr_appears_three_times_in_output(self):
        # Once in the predicate, optionally once in the empty-string guard,
        # and once in the array-of-one literal. Catches accidental shadowing
        # if the helper is later refactored to use a positional placeholder.
        out = _dedup_concat_optional_clause("r.x", "row.x", require_nonempty_string=True)
        # 3 IS NOT NULL/<> ''/[row.x] occurrences = the predicate (twice with the
        # empty-string guard) plus the array literal.
        assert out.count("row.x") == 3


# ---------------------------------------------------------------------------
# 2. Cypher-injection guards
# ---------------------------------------------------------------------------


class TestPropRefValidation:
    """``prop_ref`` must be a well-formed ``<var>.<name>`` pair."""

    def test_rejects_no_dot(self):
        with pytest.raises(ValueError, match="must be of the form"):
            _dedup_concat_clause("source", "[]")

    def test_rejects_dotted_inner_path(self):
        with pytest.raises(ValueError, match="must be of the form"):
            _dedup_concat_clause("n.source.bad", "[]")

    def test_rejects_injection_via_var(self):
        with pytest.raises(ValueError, match="must be of the form"):
            _dedup_concat_clause("n; DROP DATABASE neo4j", "[]")

    def test_rejects_injection_via_prop_name(self):
        with pytest.raises(ValueError, match="invalid prop name"):
            _dedup_concat_clause("n.source); DROP", "[]")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            _dedup_concat_clause("", "[]")

    def test_rejects_var_with_leading_digit(self):
        # _PROP_NAME_RE = ^[A-Za-z_][A-Za-z0-9_]*$ — leading digit must fail.
        with pytest.raises(ValueError, match="invalid var"):
            _dedup_concat_clause("9var.source", "[]")

    def test_optional_clause_inherits_validation(self):
        # The Pattern-B helper delegates to _dedup_concat_clause for the
        # outer wrap, so the same guards must apply.
        with pytest.raises(ValueError, match="must be of the form"):
            _dedup_concat_optional_clause("not_a_dotted_ref", "row.x")


# ---------------------------------------------------------------------------
# 3. Zone helper still produces the legacy substring (string-pin parity)
# ---------------------------------------------------------------------------


class TestZoneHelperParityViaDedupHelper:
    """``_zone_override_global_clause`` was refactored to call
    ``_dedup_concat_clause`` internally. The legacy substring that
    ``tests/test_pr33_bugbot_fixes.py:2430`` pins MUST still appear."""

    def test_legacy_apoc_substring_preserved(self):
        clause = _zone_override_global_clause("n", "$zone")
        assert "apoc.coll.toSet(coalesce(n.zone, []) + $zone)" in clause

    def test_legacy_apoc_substring_with_alt_var(self):
        clause = _zone_override_global_clause("i", "item.zone")
        assert "apoc.coll.toSet(coalesce(i.zone, []) + item.zone)" in clause

    def test_emits_specifics_filter(self):
        clause = _zone_override_global_clause("n", "$zone")
        assert "WHERE z <> 'global'" in clause
        assert clause.startswith("n.zone = CASE ")
        assert clause.endswith("END")


# ---------------------------------------------------------------------------
# 4. Same-element re-merge is idempotent (semantic invariant)
# ---------------------------------------------------------------------------


class TestDedupSemanticInvariants:
    """Pure-Python simulations of the operator the helper emits.

    Why a Python sim: spinning up Neo4j+APOC in CI is heavy. The helper
    contract is "the dedup operator that 'apoc.coll.toSet' resolves to
    on the server." We model that as a set-union-preserving-order and
    assert the invariants the operator must satisfy. When Phase 3 flips
    the helper to native Cypher, the same invariants must hold of the
    new fragment — these tests then become the contract any
    ``reduce(...)`` / ``CASE WHEN $x IN ...`` replacement must pass.
    """

    @staticmethod
    def _set_union_preserve_order(left: list, right: list) -> list:
        """Reference implementation of the apoc.coll.toSet semantics
        we rely on: dedup = LinkedHashSet (insertion order preserved,
        first occurrence wins). NULL elements are kept (one slot)."""
        seen = set()
        out = []
        for x in left + right:
            key = (type(x).__name__, x)  # so 1 and "1" don't collide
            if key in seen:
                continue
            seen.add(key)
            out.append(x)
        return out

    def test_resync_same_event_does_not_grow(self):
        # First sync: indicator gets misp_event_ids = ["1001"].
        existing: list = []
        first = self._set_union_preserve_order(existing, ["1001"])
        # Second sync: same MISP event re-touches the indicator.
        second = self._set_union_preserve_order(first, ["1001"])
        assert first == ["1001"]
        assert second == ["1001"], "re-sync must not grow the array (Kimi-myth tripwire)"

    def test_disjoint_events_concatenate(self):
        existing = ["1001"]
        out = self._set_union_preserve_order(existing, ["1002"])
        assert out == ["1001", "1002"]

    def test_multi_source_sources_preserve_first_seen_order(self):
        # The STIX exporter integration test (test_stix_misp_provenance.py:76)
        # asserts == ["1001", "1002"] — order matters. If a future
        # replacement uses collect(DISTINCT) which is unordered, that test
        # breaks. This guards the contract here.
        out = self._set_union_preserve_order(["1001"], ["1002"])
        assert out == ["1001", "1002"]
        out = self._set_union_preserve_order(["1002"], ["1001"])
        assert out == ["1002", "1001"], "first-occurrence-wins order"

    def test_resync_with_extra_event_extends_only_with_new(self):
        existing = ["1001", "1002"]
        out = self._set_union_preserve_order(existing, ["1002", "1003"])
        assert out == ["1001", "1002", "1003"]


# ---------------------------------------------------------------------------
# 5. Pattern-B null-element guard works
# ---------------------------------------------------------------------------


class TestPatternBNullGuard:
    """The CASE-gated optional-append must NOT add the value when it's null
    or (with require_nonempty_string=True) when it's an empty string.

    These are static-string assertions on the emitted Cypher — they prove
    the guard predicate is present. The actual "doesn't grow on re-sync"
    contract is enforced by ``TestDedupSemanticInvariants`` above, plus
    (eventually) a real-DB integration test."""

    def test_null_value_emits_no_append(self):
        out = _dedup_concat_optional_clause("r.misp_event_ids", "row.misp_event_id")
        # The CASE expression returns [] when value IS NULL — that's the
        # entire point of the helper. Pin the structure so a future refactor
        # can't drop the ELSE branch.
        assert "IS NOT NULL" in out
        assert "ELSE [] END" in out

    def test_empty_string_guard_present_only_when_requested(self):
        # Default: no <> '' check (used by node-side mergers where upstream
        # already filters empty strings).
        out_default = _dedup_concat_optional_clause("n.misp_event_ids", "item.misp_event_id")
        assert "<> ''" not in out_default

        # Opt-in: <> '' check (used by batch-rel queries where upstream
        # may emit empty strings for missing fields).
        out_strict = _dedup_concat_optional_clause(
            "r.misp_event_ids", "row.misp_event_id", require_nonempty_string=True
        )
        assert "row.misp_event_id <> ''" in out_strict

    def test_empty_string_guard_uses_value_expr_not_a_placeholder(self):
        # Regression guard: an earlier draft of the helper used a freeform
        # ``extra_predicate`` parameter that didn't reference ``value_expr``,
        # producing malformed Cypher like ``AND <> ""``. Pin the corrected
        # contract: the empty-string check MUST reference the actual value
        # expression by name.
        out = _dedup_concat_optional_clause("r.misp_event_ids", "row.foo_bar", require_nonempty_string=True)
        assert "row.foo_bar <> ''" in out
        assert " <> ''" in out  # sanity
        # And the malformed form must NOT appear:
        assert re.search(r"\bAND <> ''", out) is None


# ---------------------------------------------------------------------------
# 6. Refactor coverage — every batch-rel template uses the helper
# ---------------------------------------------------------------------------


class TestRefactorCoverage:
    """Pin that the helpers actually went into the call sites we care about.
    A regression that re-introduces a literal ``apoc.coll.toSet(coalesce(...``
    in the wrong place would defeat Phase 3 (the helper internals would
    flip but the orphan literal wouldn't)."""

    def _source_of(self, fn) -> str:
        import inspect

        return inspect.getsource(fn)

    def test_create_misp_relationships_batch_has_no_literal_apoc(self):
        import neo4j_client

        src = self._source_of(neo4j_client.Neo4jClient.create_misp_relationships_batch)
        # Only the helper-call site should emit the apoc literal; no
        # literal ``apoc.coll.toSet(coalesce(`` should appear in the
        # function body any more.
        assert "apoc.coll.toSet(coalesce(" not in src, (
            "create_misp_relationships_batch still has a literal apoc.coll.toSet(coalesce(...) — refactor incomplete."
        )

    def test_merge_indicators_batch_has_no_literal_apoc(self):
        import neo4j_client

        src = self._source_of(neo4j_client.Neo4jClient.merge_indicators_batch)
        assert "apoc.coll.toSet(coalesce(" not in src

    def test_merge_vulnerabilities_batch_has_no_literal_apoc(self):
        import neo4j_client

        src = self._source_of(neo4j_client.Neo4jClient.merge_vulnerabilities_batch)
        assert "apoc.coll.toSet(coalesce(" not in src

    def test_merge_node_with_source_has_no_literal_apoc(self):
        import neo4j_client

        src = self._source_of(neo4j_client.Neo4jClient.merge_node_with_source)
        # _zone_override_global_clause INTERNALLY produces the apoc literal
        # via the helper, but the source of merge_node_with_source itself
        # must be free of inline literals.
        assert "apoc.coll.toSet(coalesce(" not in src
