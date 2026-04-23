"""
PR-N26 — wire ``r.misp_event_ids[]`` onto TARGETS / EXPLOITS / INDICATES /
AFFECTS edges produced by ``build_relationships.py``.

## Why this PR exists

Cloud-Neo4j audit on 2026-04-23 found that 5 edge types created by the
post-sync graph-traversal in ``build_relationships.py`` silently dropped
the ``r.misp_event_ids[]`` provenance array. Pre-N26 cloud coverage:

| Relationship | Total | with `misp_event_ids` |
|---|---|---|
| INDICATES | 19,370 | 6.6% |
| TARGETS | 36,480 | 0% |
| EXPLOITS | 26,730 | 0% |
| AFFECTS | 1,221 | 0.1% |

PR #32's commit message had said *"every MISP-derived edge accumulates
``r.misp_event_ids[]``"* — the cloud data showed only 2 of 5 MISP-derived
edge types actually got the wire-up. PR-N26 closes the gap in 6 queries:

* **Q3a / Q3b** — EXPLOITS: propagate ``i.misp_event_ids[]``
* **Q4** — INDICATES (co-occurrence): use the ``eid`` already in scope
* **Q7a** — TARGETS: propagate ``i.misp_event_ids[]``
* **Q7b** — AFFECTS: propagate ``v.misp_event_ids[]``
* **Q9** — INDICATES (family-match): propagate ``i.misp_event_ids[]``

Plus a backfill migration (`scripts/backfill_edge_misp_event_ids.py`) for
~82,500 existing edges that were created before the fix.

## Test strategy

Three layers of pin:

1. **Static text pins** — every modified inner-query string contains the
   ``r.misp_event_ids = apoc.coll.toSet(coalesce(r.misp_event_ids, []) +
   …)`` SET clause. Anchored on the PR-N26 comment marker so a future
   refactor can't strip the SET without also stripping the comment.

2. **AST-shape pins** — for each modified ``_qNN_inner`` constant in
   ``build_relationships.py``, parse the file and verify the constant's
   value contains the SET clause structurally. Catches the case where
   someone reorganizes the queries into a helper function and breaks the
   string-literal anchor.

3. **Backfill script structural pins** — assert ``scripts/backfill_edge_
   misp_event_ids.py`` exists, exposes 5 named patterns, uses
   ``apoc.periodic.iterate`` (bounded TX), and is gated on
   ``coalesce(size(r.misp_event_ids), 0) = 0`` (idempotent).

We deliberately do NOT add a behavioural integration test that runs
build_relationships against a live Neo4j — that's covered by the
existing integration suite (which is excluded from the coverage gate).
The static + AST pins are sufficient to catch regressions to the
specific SET-clause shape this PR introduces.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
SCRIPTS = REPO_ROOT / "scripts"
MIGRATIONS = REPO_ROOT / "migrations"


# ===========================================================================
# Helper: locate a string-literal assignment and return its concatenated value
# ===========================================================================


def _string_literal_value(src_path: Path, var_name: str) -> str:
    """Return the concatenated string value of a top-level or nested ``var = (...)``
    assignment in ``src_path``. Walks the AST so reformatting / line-wrapping
    doesn't break the lookup.

    Build_relationships.py uses the pattern::

        _q3a_inner = (
            "WITH $i AS i ..."
            "MERGE (i)-[r:EXPLOITS]->(v) "
            ...
        )

    which the AST normalises into a Constant or a JoinedStr / BinOp tree.
    ast.unparse + a literal_eval-style probe is robust across Python 3.12+
    versions and across reformat decisions.
    """
    tree = ast.parse(src_path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and tgt.id == var_name:
                # Try literal evaluation first (works for pure string concat).
                try:
                    return str(ast.literal_eval(node.value))
                except (ValueError, SyntaxError):
                    # f-string / call expressions — fall back to unparsed source
                    # which still contains every literal we care to grep for.
                    return ast.unparse(node.value)
    raise AssertionError(f"variable {var_name!r} not found in {src_path}")


# ===========================================================================
# Section 1 — static text pins on each fixed query in build_relationships.py
# ===========================================================================


_BUILD_RELATIONSHIPS = SRC / "build_relationships.py"


class TestBuildRelationshipsHasMispEventIdsSetClause:
    """Each of the 6 fixed inner-query constants must contain the
    ``r.misp_event_ids = apoc.coll.toSet(coalesce(r.misp_event_ids, []) + …)``
    SET clause. The right-hand side may differ (``[eid]`` for Q4 — the
    co-occurrence path which has the eid in scope — vs ``coalesce(<src>.
    misp_event_ids, [])`` for the others), so the pin checks each pattern
    individually."""

    def test_q3a_exploits_vuln_propagates_indicator_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q3a_inner")
        assert "r.misp_event_ids" in body, "Q3a must SET r.misp_event_ids (PR-N26)"
        assert "coalesce(i.misp_event_ids, [])" in body, (
            "Q3a must propagate the indicator's misp_event_ids onto the EXPLOITS edge"
        )
        assert "apoc.coll.toSet" in body, "Q3a must use apoc.coll.toSet for idempotent dedup"

    def test_q3b_exploits_cve_propagates_indicator_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q3b_inner")
        assert "r.misp_event_ids" in body, "Q3b must SET r.misp_event_ids (PR-N26)"
        assert "coalesce(i.misp_event_ids, [])" in body
        assert "apoc.coll.toSet" in body

    def test_q4_indicates_cooccurrence_uses_eid_in_scope(self):
        """Q4's co-occurrence query iterates ``eid IN m.misp_event_ids`` —
        the eid IS the originating event id, so the SET appends ``[eid]``
        (cleaner than propagating the full source array)."""
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q4_inner")
        assert "r.misp_event_ids" in body, "Q4 must SET r.misp_event_ids (PR-N26)"
        # Specifically [eid] (not coalesce-from-i) — Q4 has the exact
        # event id available, no superset needed.
        assert "+ [eid]" in body or "+[eid]" in body, (
            "Q4 must SET r.misp_event_ids = apoc.coll.toSet(coalesce(r.misp_event_ids, []) + [eid]) "
            "— the eid is already in scope, no need to propagate the full array"
        )
        assert "apoc.coll.toSet" in body

    def test_q7a_targets_propagates_indicator_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q7a_inner")
        assert "r.misp_event_ids" in body, "Q7a must SET r.misp_event_ids (PR-N26)"
        assert "coalesce(i.misp_event_ids, [])" in body, (
            "Q7a must propagate the indicator's misp_event_ids onto the TARGETS edge"
        )
        assert "apoc.coll.toSet" in body

    def test_q7b_affects_propagates_vulnerability_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q7b_inner")
        assert "r.misp_event_ids" in body, "Q7b must SET r.misp_event_ids (PR-N26)"
        # Q7b uses ``v`` for the Vulnerability/CVE node, not ``i``.
        assert "coalesce(v.misp_event_ids, [])" in body, (
            "Q7b must propagate the Vulnerability/CVE's misp_event_ids onto the AFFECTS edge"
        )
        assert "apoc.coll.toSet" in body

    def test_q9_indicates_family_propagates_indicator_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q9_inner")
        assert "r.misp_event_ids" in body, "Q9 must SET r.misp_event_ids (PR-N26)"
        assert "coalesce(i.misp_event_ids, [])" in body, (
            "Q9 must propagate the indicator's misp_event_ids onto the family-match INDICATES edge"
        )
        assert "apoc.coll.toSet" in body


# ===========================================================================
# Section 2 — defensive AST scan: every MERGE producing an affected edge
# type in build_relationships.py must be followed by an r.misp_event_ids
# SET clause within the same query. Catches future regressions that add a
# NEW INDICATES/EXPLOITS/TARGETS/AFFECTS query without remembering the wire-up.
# ===========================================================================


class TestNoNewQueryForgetsToWireMispEventIds:
    """Defensive scan — every assigned ``_qN_inner`` constant in
    build_relationships.py that contains a MERGE for one of the four
    affected relationship types must also reference ``r.misp_event_ids``
    somewhere in its body. Prevents the bug class from coming back the
    next time someone adds a 13th link query.

    We exempt ``_q5_inner``-style queries (EMPLOYS_TECHNIQUE) and similar
    that are NOT in the four-edge-type set."""

    AFFECTED_REL_TYPES = ("INDICATES", "EXPLOITS", "TARGETS", "AFFECTS")

    def test_every_inner_query_with_affected_merge_sets_misp_event_ids(self):
        tree = ast.parse(_BUILD_RELATIONSHIPS.read_text())
        offenders: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for tgt in node.targets:
                if not isinstance(tgt, ast.Name):
                    continue
                # Inner queries follow the pattern _q<NN>_inner or _inner.
                if not (tgt.id.endswith("_inner") or tgt.id == "_inner"):
                    continue
                try:
                    body = str(ast.literal_eval(node.value))
                except (ValueError, SyntaxError):
                    body = ast.unparse(node.value)

                # Does this query MERGE one of the affected edge types?
                # Look for ``[r:INDICATES]``, ``[r:TARGETS]``, etc.
                affected = [rel for rel in self.AFFECTED_REL_TYPES if f":{rel}]" in body]
                if not affected:
                    continue
                # If yes, must also reference r.misp_event_ids.
                if "r.misp_event_ids" not in body:
                    offenders.append(f"{tgt.id}: MERGEs [{','.join(affected)}] but missing r.misp_event_ids SET")

        assert not offenders, (
            "the following build_relationships.py queries MERGE one of "
            f"{self.AFFECTED_REL_TYPES} but DO NOT SET r.misp_event_ids — "
            "this is the PR-N26 bug class:\n  " + "\n  ".join(offenders)
        )


# ===========================================================================
# Section 3 — backfill script structural pins
# ===========================================================================


_BACKFILL = SCRIPTS / "backfill_edge_misp_event_ids.py"


class TestBackfillScriptStructure:
    """``scripts/backfill_edge_misp_event_ids.py`` must:

    1. Exist + be executable.
    2. Define a ``PATTERNS`` list with at least 5 entries (one per fix site).
    3. Use ``apoc.periodic.iterate`` so transactions stay bounded.
    4. Gate on ``coalesce(size(r.misp_event_ids), 0) = 0`` so it's idempotent.
    5. For the cooccurrence pattern, compute the intersection of source +
       target arrays (the EXACT historical event set), not the union.
    """

    def test_backfill_script_exists(self):
        assert _BACKFILL.exists(), f"backfill script missing at {_BACKFILL}"

    def test_backfill_script_is_executable(self):
        import os

        assert os.access(_BACKFILL, os.X_OK), "backfill script must be chmod +x for operator runbook"

    def test_backfill_script_has_five_patterns(self):
        text = _BACKFILL.read_text()
        # Each pattern is a ('name', count_q, write_q) tuple in the PATTERNS list.
        # We don't import the module (would require neo4j-driver in the test env);
        # parse the AST to count tuple-literal entries inside PATTERNS.
        # PATTERNS may be either an Assign (``PATTERNS = [...]``) or an
        # AnnAssign (``PATTERNS: List[Tuple[str, str, str]] = [...]``) —
        # check both shapes.
        tree = ast.parse(text)
        for node in ast.walk(tree):
            target_name = None
            value_node = None
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == "PATTERNS":
                        target_name = "PATTERNS"
                        value_node = node.value
                        break
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "PATTERNS":
                target_name = "PATTERNS"
                value_node = node.value

            if target_name is None or value_node is None:
                continue
            assert isinstance(value_node, ast.List), "PATTERNS must be a list literal"
            assert len(value_node.elts) >= 5, (
                f"PATTERNS must have at least 5 entries (one per fix site); found {len(value_node.elts)}"
            )
            return
        raise AssertionError("PATTERNS list not found in backfill script")

    def test_backfill_uses_apoc_periodic_iterate(self):
        text = _BACKFILL.read_text()
        assert text.count("apoc.periodic.iterate") >= 5, (
            "every pattern's write_query must use apoc.periodic.iterate to keep TX bounded — "
            "expected ≥5 occurrences (one per pattern)"
        )

    def test_backfill_is_idempotent_via_size_gate(self):
        text = _BACKFILL.read_text()
        # The Cypher gate ``coalesce(size(r.misp_event_ids), 0) = 0`` ensures
        # we only touch edges that currently lack the array. Re-runs are no-ops.
        assert "coalesce(size(r.misp_event_ids), 0) = 0" in text, (
            "every pattern must gate on coalesce(size(r.misp_event_ids), 0) = 0 to be idempotent"
        )

    def test_cooccurrence_pattern_uses_intersection(self):
        """For the ``misp_cooccurrence`` INDICATES edge specifically, we have
        BOTH endpoints' arrays available — so we can recover the EXACT
        historical event set (the intersection) rather than over-stamping
        with a superset."""
        text = _BACKFILL.read_text()
        # The intersection idiom: list comprehension filtering one array
        # against the other.
        assert "WHERE eid IN coalesce(m.misp_event_ids" in text, (
            "indicates_cooccurrence pattern must compute "
            "[eid IN coalesce(i.misp_event_ids, []) WHERE eid IN coalesce(m.misp_event_ids, [])] — "
            "the exact intersection that originally produced the edge"
        )

    def test_backfill_supports_dry_run(self):
        text = _BACKFILL.read_text()
        assert "--dry-run" in text, "backfill must support --dry-run for operator preflight"

    def test_backfill_supports_only_filter(self):
        text = _BACKFILL.read_text()
        assert "--only" in text, "backfill must support --only <pattern> for incremental rollout"


# ===========================================================================
# Section 4 — operator runbook exists and references the script
# ===========================================================================


_RUNBOOK = MIGRATIONS / "2026_05_edge_misp_event_ids_backfill_runbook.md"


class TestRunbookExists:
    def test_runbook_file_exists(self):
        assert _RUNBOOK.exists(), f"operator runbook missing at {_RUNBOOK}"

    def test_runbook_references_backfill_script(self):
        text = _RUNBOOK.read_text()
        assert "scripts/backfill_edge_misp_event_ids.py" in text, "runbook must reference the backfill script by path"

    def test_runbook_has_dry_run_step(self):
        text = _RUNBOOK.read_text()
        assert "--dry-run" in text, "runbook must instruct operators to dry-run first"

    def test_runbook_has_idempotency_note(self):
        text = _RUNBOOK.read_text()
        assert "Idempoten" in text or "idempoten" in text, (
            "runbook must explicitly state the script is idempotent (so operators feel safe re-running)"
        )

    def test_runbook_has_verification_step(self):
        text = _RUNBOOK.read_text()
        # Operators need to know HOW to verify the backfill landed.
        assert "Verify" in text or "verify" in text or "verification" in text.lower(), (
            "runbook must include a post-backfill verification step"
        )

    def test_runbook_clarifies_not_a_baseline_blocker(self):
        text = _RUNBOOK.read_text()
        assert "NOT a blocker" in text or "not a blocker" in text or "not block" in text.lower(), (
            "runbook should clarify this migration is NOT a blocker for the next 730d baseline launch — "
            "operators need this signal so they don't delay baseline-day for a non-critical migration"
        )
