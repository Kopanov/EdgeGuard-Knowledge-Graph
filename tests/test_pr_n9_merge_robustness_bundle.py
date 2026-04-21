"""
PR-N9 — merge robustness bundle (NULL/empty filter + B6 observability).

Two independent themes, both "merge logic robustness":

## Fix A — NULL/empty filter in Q2/Q9 alias list comprehensions

Follow-up to PR-N8's R1 Bugbot fix. PR-N8 R1 dropped the
``coalesce(x, '')`` wrapper and hardened outer filters to
``size(trim(x)) > 0``. That closed the whitespace-only-LHS false-
match vector. BUT a separate remaining hazard existed in Q2:

  - m.attributed_to = "  "  (whitespace-only)
  - m.aliases = ["SomeAlias"]  (non-empty)
  - a.aliases = ["foo", "  ", "bar"]  (contains a whitespace entry)

Q2's outer ORs through the ``m.aliases non-empty`` leg even when
m.attributed_to is whitespace-only → inner runs. Branch 2's
comprehension ``[x IN a.aliases | toLower(trim(x))]`` yields
``["foo", "", "bar"]``. Then ``"" IN ["foo", "", "bar"]`` →
TRUE → spurious ATTRIBUTED_TO edge to every ThreatActor with a
malformed alias entry.

Fix: filter the list comprehensions to ``[x IN coalesce(..., [])
WHERE x IS NOT NULL AND size(trim(x)) > 0 | toLower(trim(x))]``,
so NULL and whitespace-only aliases are removed BEFORE the IN
comparison.

## Fix B — MERGE observability (audit finding B6)

The 7-agent audit (PR-N0) flagged Prod Readiness #2: ``merge_
indicators_batch`` / ``merge_vulnerabilities_batch`` use
``len(batch)`` as the success_count regardless of what Neo4j
actually wrote. If the write path silently fails (missing Source
node, constraint violation, schema drift), the caller thinks
every item succeeded.

Fix: inspect ``result.consume().counters`` after every batch. If
``nodes_created + nodes_updated + properties_set + rels_created +
rels_updated == 0`` on a non-empty batch, emit ERROR log + increment
``edgeguard_neo4j_merge_ineffective_batch_total{label, source}``.

Analog of the PR-N4 ``edgeguard_misp_push_permanent_failure_total``
on the MISPWriter side — now Neo4j has the same silent-data-loss
signal.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n9")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n9")


# ===========================================================================
# Fix A — Q2 / Q9 alias list-comprehension filters NULL/empty entries
# ===========================================================================


class TestFixANullEmptyAliasFilter:
    """List comprehensions over ``m.aliases`` / ``a.aliases`` must
    filter out NULL and whitespace-only entries before the IN
    comparison, so a single malformed alias can't produce a
    spurious match via ``"" IN ["foo", "", "bar"]``."""

    def _src(self) -> str:
        return (SRC / "build_relationships.py").read_text()

    def test_q2_inner_list_comprehensions_filter_null_and_whitespace(self):
        """Q2 inner has two list comprehensions (a.aliases + m.aliases).
        Both must carry the ``WHERE x IS NOT NULL AND size(trim(x)) > 0``
        filter."""
        src = self._src()
        # Find Q2 block
        step2_idx = src.find("[LINK] 2/12 Malware → ThreatActor")
        step3_idx = src.find("[LINK] 3a/12", step2_idx)
        block = src[step2_idx:step3_idx]

        # Must have filter in both a.aliases and m.aliases comprehensions
        a_alias_filter = "x IN coalesce(a.aliases, []) WHERE x IS NOT NULL AND size(trim(x)) > 0"
        m_alias_filter = "x IN coalesce(m.aliases, []) WHERE x IS NOT NULL AND size(trim(x)) > 0"
        assert a_alias_filter in block, "Q2 a.aliases comprehension must filter NULL/whitespace entries"
        assert m_alias_filter in block, "Q2 m.aliases comprehension must filter NULL/whitespace entries"

    def test_q9_inner_list_comprehension_filters_null_and_whitespace(self):
        """Q9 inner has one list comprehension (m.aliases). Must carry
        the same filter."""
        src = self._src()
        # Find Q9 inner
        q9_idx = src.find("_q9_inner")
        next_assignment = src.find("_q9_skip", q9_idx)
        block = src[q9_idx:next_assignment]
        m_alias_filter = "x IN coalesce(m.aliases, []) WHERE x IS NOT NULL AND size(trim(x)) > 0"
        assert m_alias_filter in block, "Q9 inner m.aliases comprehension must filter NULL/whitespace entries"

    def test_q9_skip_list_comprehension_filters_null_and_whitespace(self):
        """Q9's skip-query mirrors the inner's shape — must also filter."""
        src = self._src()
        q9_skip_idx = src.find("_q9_skip")
        next_assignment = src.find("if not _safe_run_batched", q9_skip_idx)
        block = src[q9_skip_idx:next_assignment]
        m_alias_filter = "x IN coalesce(m.aliases, []) WHERE x IS NOT NULL AND size(trim(x)) > 0"
        assert m_alias_filter in block, "Q9 skip m.aliases comprehension must filter NULL/whitespace entries"

    def test_no_bare_list_comprehension_without_filter(self):
        """Regression pin: any ``[x IN coalesce(..., []) | toLower(...)]``
        form WITHOUT the WHERE filter must NOT appear in build_relationships.py
        for the alias-comprehension pattern.

        Uses a targeted substring search rather than AST because we're
        looking at Cypher embedded in Python strings."""
        src = self._src()
        # The specific unsafe forms (Q2 a.aliases / m.aliases, Q9 m.aliases)
        unsafe_patterns = [
            "[x IN coalesce(a.aliases, []) | toLower",
            "[x IN coalesce(m.aliases, []) | toLower",
        ]
        for pat in unsafe_patterns:
            assert pat not in src, (
                f"Regression: unsafe bare comprehension {pat!r} must not "
                "appear — wrap with `WHERE x IS NOT NULL AND size(trim(x)) > 0`"
            )


# ===========================================================================
# Fix B — MERGE observability (B6)
# ===========================================================================


class TestFixBMergeObservability:
    """``_record_batch_counters`` must exist, be called from both batch
    methods, and the Prometheus metric must be declared."""

    def _src(self) -> str:
        return (SRC / "neo4j_client.py").read_text()

    def _metrics(self) -> str:
        return (SRC / "metrics_server.py").read_text()

    def test_metric_declared_with_bounded_labels(self):
        m = self._metrics()
        assert "NEO4J_MERGE_INEFFECTIVE_BATCH = Counter(" in m
        assert '"edgeguard_neo4j_merge_ineffective_batch_total"' in m
        # Bounded cardinality: label + source, no event_id or other unbounded axes
        assert '["label", "source"]' in m, (
            "metric must use bounded label set [label, source] — no cardinality explosion"
        )

    def test_helper_function_defined(self):
        src = self._src()
        assert "def _record_batch_counters(" in src
        # Must inspect the canonical counter fields
        for counter_field in (
            "nodes_created",
            "nodes_updated",
            "properties_set",
            "relationships_created",
        ):
            assert counter_field in src, f"_record_batch_counters must inspect counters.{counter_field}"

    def test_helper_emits_error_log_on_zero_effect(self):
        """The ERROR log must fire when total_touched == 0 and
        batch_len > 0."""
        src = self._src()
        fn_idx = src.find("def _record_batch_counters(")
        assert fn_idx != -1
        next_def = src.find("\ndef ", fn_idx + 1)
        body = src[fn_idx : next_def if next_def != -1 else fn_idx + 5000]
        assert "logger.error" in body, "must emit ERROR log on ineffective batch"
        assert "batch_len > 0 and total_touched == 0" in body, "zero-effect detection must use the exact condition"

    def test_helper_never_raises(self):
        """Counter-inspection failures must NOT propagate — observability
        code must not break production writes."""
        src = self._src()
        fn_idx = src.find("def _record_batch_counters(")
        next_def = src.find("\ndef ", fn_idx + 1)
        body = src[fn_idx : next_def if next_def != -1 else fn_idx + 5000]
        # Outer try/except wrapping the entire body
        assert "except Exception as _inspect_err:" in body, "must catch inspection exceptions to avoid breaking writes"

    def test_helper_guards_metric_on_none(self):
        """Uses the PR-N5 R1 pattern — explicit is-not-None check so the
        nested-import fallback (older metrics_server) doesn't AttributeError."""
        src = self._src()
        fn_idx = src.find("def _record_batch_counters(")
        next_def = src.find("\ndef ", fn_idx + 1)
        body = src[fn_idx : next_def if next_def != -1 else fn_idx + 5000]
        assert "_NEO4J_MERGE_INEFFECTIVE_BATCH is not None" in body, (
            "metric increment must be guarded by explicit is-not-None check"
        )

    def test_merge_indicators_batch_calls_helper(self):
        """The Indicator batch must invoke the helper after session.run."""
        src = self._src()
        fn_idx = src.find("def merge_indicators_batch(")
        next_def = src.find("\n    def ", fn_idx + 1)
        body = src[fn_idx : next_def if next_def != -1 else fn_idx + 5000]
        assert "_record_batch_counters(" in body, "merge_indicators_batch must call _record_batch_counters"
        # Specifically with label="Indicator"
        assert 'label="Indicator"' in body

    def test_merge_vulnerabilities_batch_calls_helper(self):
        src = self._src()
        fn_idx = src.find("def merge_vulnerabilities_batch(")
        next_def = src.find("\n    def ", fn_idx + 1)
        body = src[fn_idx : next_def if next_def != -1 else fn_idx + 5000]
        assert "_record_batch_counters(" in body
        assert 'label="Vulnerability"' in body

    def test_optional_import_graceful_degradation(self):
        """The nested counter import must be inside a try/except so older
        metrics_server deploys don't break the PR-N4/N5 counters."""
        src = self._src()
        assert "NEO4J_MERGE_INEFFECTIVE_BATCH as _NEO4J_MERGE_INEFFECTIVE_BATCH" in src
        assert "_NEO4J_MERGE_INEFFECTIVE_BATCH = None" in src, (
            "must set to None on nested ImportError (graceful degradation)"
        )

    # --- Behavioural ---

    def test_behaviour_zero_counters_triggers_error(self, caplog):
        """Given a mocked result whose consume().counters show
        everything at 0 on a non-empty batch, the helper must emit an
        ERROR log."""
        import importlib
        import logging

        if "neo4j_client" in sys.modules:
            del sys.modules["neo4j_client"]
        neo4j_client = importlib.import_module("neo4j_client")

        # Build a mock result with all-zero counters
        counters = MagicMock()
        counters.nodes_created = 0
        counters.nodes_updated = 0
        counters.properties_set = 0
        counters.relationships_created = 0
        counters.relationships_updated = 0
        # Make hasattr() work for nodes_updated / relationships_updated
        # (otherwise getattr returns the MagicMock auto-attr, not 0).
        # The MagicMock above already satisfies hasattr.

        result = MagicMock()
        result.consume.return_value.counters = counters

        with caplog.at_level(logging.ERROR, logger="neo4j_client"):
            neo4j_client._record_batch_counters(
                label="Indicator",
                source_id="otx",
                batch_len=100,
                result=result,
            )

        assert any("MERGE-INEFFECTIVE" in rec.message for rec in caplog.records), (
            f"expected ineffective-batch ERROR; got: {[r.message for r in caplog.records]}"
        )

    def test_behaviour_nonzero_counters_no_error(self, caplog):
        """Given a mocked result with ANY non-zero counter, the helper
        must NOT emit the ineffective-batch ERROR."""
        import importlib
        import logging

        if "neo4j_client" in sys.modules:
            del sys.modules["neo4j_client"]
        neo4j_client = importlib.import_module("neo4j_client")

        counters = MagicMock()
        counters.nodes_created = 5
        counters.nodes_updated = 0
        counters.properties_set = 20
        counters.relationships_created = 5
        counters.relationships_updated = 0

        result = MagicMock()
        result.consume.return_value.counters = counters

        with caplog.at_level(logging.ERROR, logger="neo4j_client"):
            neo4j_client._record_batch_counters(
                label="Indicator",
                source_id="otx",
                batch_len=100,
                result=result,
            )

        ineffective = [r for r in caplog.records if "MERGE-INEFFECTIVE" in r.message]
        assert not ineffective, (
            f"ineffective-batch ERROR must NOT fire when writes happened; got: {[r.message for r in ineffective]}"
        )

    def test_behaviour_empty_batch_no_error(self, caplog):
        """batch_len == 0 is not ineffective (nothing to do). No ERROR."""
        import importlib
        import logging

        if "neo4j_client" in sys.modules:
            del sys.modules["neo4j_client"]
        neo4j_client = importlib.import_module("neo4j_client")

        counters = MagicMock()
        counters.nodes_created = 0
        counters.nodes_updated = 0
        counters.properties_set = 0
        counters.relationships_created = 0
        counters.relationships_updated = 0

        result = MagicMock()
        result.consume.return_value.counters = counters

        with caplog.at_level(logging.ERROR, logger="neo4j_client"):
            neo4j_client._record_batch_counters(
                label="Indicator",
                source_id="otx",
                batch_len=0,  # empty batch — legitimately no writes
                result=result,
            )

        ineffective = [r for r in caplog.records if "MERGE-INEFFECTIVE" in r.message]
        assert not ineffective, "empty batch must not trigger ineffective-batch ERROR"

    def test_behaviour_consume_exception_swallowed(self, caplog):
        """If result.consume() itself raises, the helper must not
        propagate — observability code never breaks production writes."""
        import importlib
        import logging

        if "neo4j_client" in sys.modules:
            del sys.modules["neo4j_client"]
        neo4j_client = importlib.import_module("neo4j_client")

        result = MagicMock()
        result.consume.side_effect = RuntimeError("simulated driver error")

        with caplog.at_level(logging.DEBUG, logger="neo4j_client"):
            # Must not raise
            neo4j_client._record_batch_counters(
                label="Indicator",
                source_id="otx",
                batch_len=100,
                result=result,
            )

        # DEBUG log captured (the inspection-failure breadcrumb)
        assert any("result-counter inspection failed" in rec.message for rec in caplog.records)


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_build_relationships_imports(self):
        import build_relationships  # noqa: F401

    def test_neo4j_client_imports(self):
        import neo4j_client  # noqa: F401
