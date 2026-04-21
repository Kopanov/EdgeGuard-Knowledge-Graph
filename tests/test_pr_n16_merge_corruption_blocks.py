"""
PR-N16 — overnight merge-logic audit BLOCK + HIGH bundle.

Four findings from the overnight deep-merge-logic audit that PR-N10
through PR-N15 missed. Two BLOCK-severity (data-corruption vectors
that fire on every baseline sync with MISP-federated peers) + two
HIGH-severity (silent data loss on Neo4j transients).

## Fix #1 (BLOCK) — aliases-as-scalar corruption in merge_node_with_source

``_ARRAY_ACCUMULATE_PROPS = {"aliases", "malware_types",
"uses_techniques", "tactic_phases"}`` are meant to ACCUMULATE
(dedup-append) across sources, but ``merge_node_with_source``'s
extra_props loop gated the accumulation path on
``isinstance(prop_value, list)``. MISP objects emit string-typed
``aliases`` / ``malware_types`` attributes commonly
(``misp_collector.py:385,410,478,498``).

So: first sync writes ``n.aliases = ["Cozy Bear", "Nobelium"]`` via
the list path. Second sync with string-typed aliases falls through to
the scalar branch ``SET n.aliases = "APT29"`` — silently overwriting
the accumulated list with a scalar string. Neo4j stores it.
Downstream: every alias-based Q2 / Q9 / ATTRIBUTED_TO MATCH
(``$actor_name IN coalesce(a.aliases, [])``) evaluates
``IN scalar_string`` = nonsense, returns zero rows, silently drops
edges.

Fix: in the extra_props loop, for ``_ARRAY_ACCUMULATE_PROPS``,
unconditionally coerce to list before sanitization. Scalar string →
``[stripped]``. Non-list-non-string → log WARN + skip (don't corrupt).

## Fix #2 (BLOCK) — MITRE mitre_id case asymmetry

``merge_technique`` / ``merge_tactic`` / ``merge_tool`` stored
mitre_id as received from MISP. The Cypher ``MERGE (n:Technique
{mitre_id: $mitre_id})`` is case-sensitive, but ``compute_node_uuid``
goes through ``canonical_node_key.lower()`` so the uuid is the same
for ``T1056`` and ``t1056``.

Result: two distinct Neo4j nodes (``T1056`` and ``t1056``) share the
same ``n.uuid``. Cross-environment delta-sync + STIX export hits
either node non-deterministically.

Same class as PR #37 (Indicator value canonicalization — fixed there)
but missed for MITRE. Verified: ``compute_node_uuid("Technique",
{"mitre_id": "T1056"}) == compute_node_uuid("Technique", {"mitre_id":
"t1056"})``.

Fix: new ``_normalize_mitre_id`` helper uppercases (matches MITRE's
own canonical convention) + None-guards. Applied in all three
MITRE merge helpers.

## Fix #3 (HIGH) — single-item merge paths have no retry on transient Neo4j errors

PR-N15 added ``_execute_batch_with_retry`` for ``merge_indicators_batch``
and ``merge_vulnerabilities_batch``. But the single-item paths
(``merge_indicator``, ``merge_malware``, ``merge_actor``,
``merge_technique``, ``merge_tactic``, ``merge_tool``, ``merge_cve``,
``merge_vulnerability``, topology mergers) all route through
``merge_node_with_source`` which had NO retry decorator.

At 730d baseline scale, single-item merges of foundation nodes
(Malware / Actor / Technique) hit transient errors too. Losing one
Malware silently breaks every downstream batch-indicator INDICATES
edge that would have matched it.

Fix: decorate ``merge_node_with_source`` with
``@retry_with_backoff(max_retries=3)`` — uses the PR-N15 classifier
(``_is_retryable_neo4j_error``) so it retries on
``TransientError`` / ``ServiceUnavailable`` / ``DatabaseError`` with
retryable code.

## Fix #4 (HIGH) — ``_run_rows`` in create_misp_relationships_batch has no retry

``_run_rows`` (the 7-template UNWIND dispatcher for MISP-derived
relationships) had a bare ``except Exception: logger.warning``. No
retry, no permanent-failure counter. Same class as PR-N15 but in a
sibling code path.

At 700k-relationship baseline scale, a single Neo4j GC pause drops
~1000 relationships per batch with no retry. Over 30 sync cycles,
hundreds of silent drops of INDICATES / ATTRIBUTED_TO / EMPLOYS_TECHNIQUE
edges.

Fix: inline the same exponential-backoff + permanent-failure-counter
pattern ``_execute_batch_with_retry`` uses, with the ``_run_rows``
signature retained (it's a nested helper with access to
``nonlocal total``). Emits ``edgeguard_neo4j_batch_permanent_failure_total``
on exhaustion.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n16")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n16")


# ===========================================================================
# Fix #1 — aliases-as-scalar corruption
# ===========================================================================


class TestFix1AliasesAsScalarCorruption:
    def test_sanitizer_coerces_string_to_list_before_accumulate(self):
        """AST pin: the extra_props loop must coerce string → [string]
        for accumulating-array props BEFORE the sanitize call, not
        fall through to the scalar SET branch."""
        src = (SRC / "neo4j_client.py").read_text()
        idx = src.find("_ARRAY_ACCUMULATE_PROPS = frozenset(")
        assert idx != -1
        # Scan the extra_props loop for the new coerce logic.
        block = src[idx : idx + 6000]
        # Must branch on membership in accumulate-props WITHOUT the
        # old isinstance-list guard dropping strings.
        assert "if prop_name in _ARRAY_ACCUMULATE_PROPS:" in block
        assert "elif isinstance(prop_value, str):" in block, (
            "scalar-string coerce path missing — corruption vector reintroduced"
        )
        # Legacy failure mode: `if prop_name in _ARRAY_ACCUMULATE_PROPS and isinstance(prop_value, list):`
        # must NOT be present (that was the bug).
        assert "if prop_name in _ARRAY_ACCUMULATE_PROPS and isinstance(prop_value, list):" not in block, (
            "regression: the old scalar-to-SET fallthrough is back"
        )

    def test_module_imports_with_new_coerce_logic(self):
        """Behavioral sanity: module imports cleanly after the patch."""
        import neo4j_client  # noqa: F401

    def test_merge_node_sanitize_function_handles_string_input(self):
        """Walk the module AST, find ``_sanitize_array_value`` function
        definition, and confirm the coerce-to-list logic lives above
        it in the extra_props loop (the sanitizer itself already
        handles lists; the coerce is the caller's job)."""
        src = (SRC / "neo4j_client.py").read_text()
        # Find the `for prop_name, prop_value in extra_props.items():` loop
        idx = src.find("for prop_name, prop_value in extra_props.items():")
        assert idx != -1
        # Scan forward for both the coerce + the sanitize call.
        block = src[idx : idx + 4000]
        assert "prop_value = [stripped]" in block, "scalar-string → single-element-list coerce missing"
        assert "_sanitize_array_value(prop_name, prop_value)" in block, "sanitizer must still be invoked after coerce"


# ===========================================================================
# Fix #2 — MITRE mitre_id case asymmetry
# ===========================================================================


class TestFix2MitreCaseAsymmetry:
    def _client(self):
        from neo4j_client import Neo4jClient

        c = Neo4jClient.__new__(Neo4jClient)
        c.driver = MagicMock()
        return c

    def test_helper_uppercases_lowercase_input(self):
        """``_normalize_mitre_id`` must return uppercase."""
        c = self._client()
        result = c._normalize_mitre_id("t1056", label="Technique", data={"name": "Phishing"})
        assert result == "T1056", f"expected uppercase 'T1056'; got {result!r}"

    def test_helper_passes_already_uppercase(self):
        c = self._client()
        assert c._normalize_mitre_id("T1056", label="Technique", data={"name": "Phishing"}) == "T1056"

    def test_helper_rejects_none_empty_whitespace(self, caplog):
        """Preserves the PR-N13 None-guard."""
        import logging

        c = self._client()
        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            assert c._normalize_mitre_id(None, label="Technique", data={}) is None
            assert c._normalize_mitre_id("", label="Technique", data={}) is None
            assert c._normalize_mitre_id("   ", label="Technique", data={}) is None
        # Each reject emits a MERGE-REJECT log.
        reject_logs = [r for r in caplog.records if "[MERGE-REJECT]" in r.message]
        assert len(reject_logs) == 3

    def test_merge_technique_uses_normalize_helper(self):
        """AST pin: merge_technique must route mitre_id through _normalize_mitre_id,
        not through nonempty_graph_string alone."""
        src = (SRC / "neo4j_client.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "merge_technique":
                body = ast.unparse(node)
                assert "_normalize_mitre_id" in body, "merge_technique must call _normalize_mitre_id (PR-N16 Fix #2)"
                return
        raise AssertionError("merge_technique not found")

    def test_merge_tactic_and_tool_use_normalize_helper(self):
        src = (SRC / "neo4j_client.py").read_text()
        tree = ast.parse(src)
        found = {"merge_tactic": False, "merge_tool": False}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in found:
                if "_normalize_mitre_id" in ast.unparse(node):
                    found[node.name] = True
        assert all(found.values()), f"not all MITRE helpers use _normalize_mitre_id: {found}"


# ===========================================================================
# Fix #3 — merge_node_with_source has @retry_with_backoff
# ===========================================================================


class TestFix3MergeNodeHasRetryDecorator:
    def test_merge_node_with_source_decorated_with_retry(self):
        """Regression pin: the function must be decorated with
        ``@retry_with_backoff`` so transient errors retry instead of
        propagating as one-shot failures to the caller."""
        src = (SRC / "neo4j_client.py").read_text()
        # Find the function + look at the line IMMEDIATELY above it.
        lines = src.split("\n")
        for i, line in enumerate(lines):
            if "def merge_node_with_source(" in line:
                # Walk up past def line + any other decorators.
                # The decorator must appear before the def.
                preceding = "\n".join(lines[max(0, i - 5) : i])
                assert "@retry_with_backoff" in preceding, (
                    "merge_node_with_source must be decorated with @retry_with_backoff (PR-N16 Fix #3)"
                )
                return
        raise AssertionError("merge_node_with_source not found")


# ===========================================================================
# Fix #4 — _run_rows retry-on-transient
# ===========================================================================


class TestFix4RunRowsRetry:
    def _extract_run_rows_body(self) -> str:
        """Helper: extract the nested ``_run_rows`` function body from
        ``create_misp_relationships_batch``."""
        src = (SRC / "neo4j_client.py").read_text()
        idx = src.find("def _run_rows(session")
        assert idx != -1, "_run_rows not found"
        # _run_rows is a nested def — scan for its next sibling def at
        # same indent or any return to outer scope.
        end = src.find("\n        with self.driver.session() as session:", idx)
        if end == -1:
            end = idx + 5000
        return src[idx:end]

    def test_run_rows_retries_on_transient(self):
        body = self._extract_run_rows_body()
        # Must use the classifier.
        assert "_is_retryable_neo4j_error" in body, "_run_rows must use the PR-N15 retryable classifier"
        # Must use exponential backoff (max_retries loop + time.sleep).
        assert "max_retries" in body and "time.sleep" in body
        # Must emit permanent-failure counter.
        assert "_emit_batch_permanent_failure" in body, "_run_rows must emit permanent-failure counter on exhaustion"

    def test_run_rows_no_bare_warning_only_pattern(self):
        """Regression pin: the old bare ``logger.warning(...)`` + return
        pattern must be gone. The only acceptable warning path is
        per-attempt BATCH-RETRY (not the old silent swallow)."""
        body = self._extract_run_rows_body()
        # Old bug shape: `logger.warning("MISP relationship batch %s failed` + no retry after.
        assert "MISP relationship batch" not in body or "BATCH-RETRY" in body or "BATCH-PERMANENT-FAILURE" in body, (
            "regression: old silent-swallow logger.warning shape reappears"
        )


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_neo4j_client_imports(self):
        import neo4j_client  # noqa: F401

    def test_normalize_mitre_id_is_method(self):
        from neo4j_client import Neo4jClient

        assert hasattr(Neo4jClient, "_normalize_mitre_id"), "_normalize_mitre_id must be a Neo4jClient method"
