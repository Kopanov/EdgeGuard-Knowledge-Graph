"""
PR-N1 — Tier-A audit hotfix:
  A1. alert_processor.py:440 Query 5 ignored ``alert_id`` parameter,
      cross-contaminating ResilMesh enrichment payloads with assets +
      users from every Alert in the graph.
  A2. alert_processor.py:386 query alternation ``EMPLOYS_TECHNIQUE|USES``
      kept the legacy ``USES`` edge type alive after the 2026-04
      PR #41 refactor; backward-compat shim in
      ``neo4j_client.create_misp_relationships_batch`` was dead code
      that masked schema drift.

Both surfaced by the 7-agent comprehensive audit (Logic Tracker F4
and Cross-Checker F1, see ``docs/flow_audits/09_comprehensive_audit.md``
Tier A).

This PR removes the legacy ``USES`` edge type **fully** — not just from
the alert-enrichment query, but also the backward-compat read shim in
``neo4j_client.py`` and the misleading historical comments in
``mitre_collector.py`` / ``query_api.py``.

The current valid technique edge types (per
``docs/KNOWLEDGE_GRAPH.md``) are:
  * ``EMPLOYS_TECHNIQUE``  — ThreatActor / Campaign → Technique (attribution)
  * ``IMPLEMENTS_TECHNIQUE`` — Malware / Tool → Technique (capability)
  * ``USES_TECHNIQUE`` — Indicator → Technique (observation, OTX)

The bare ``USES`` edge type (no suffix) was retired and must not appear
in any active Cypher fragment, query, MERGE site, or backward-compat
shim. ``USES_TECHNIQUE`` is fine — distinct edge type with the
``_TECHNIQUE`` suffix.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ===========================================================================
# A1 — alert_id binding in Query 5
# ===========================================================================


class TestAlertEnrichmentBindsAlertId:
    """The Cypher in ``_enrich_alert``'s Query 5 must bind on
    ``Alert {alert_id: $alert_id}`` so the asset/user enrichment is
    scoped to the current alert. Pre-PR-N1 the parameter was bound but
    not used in the query → cross-contamination across all alerts."""

    def _read(self) -> str:
        return (SRC / "alert_processor.py").read_text()

    def test_query_5_matches_alert_by_alert_id(self) -> None:
        src = self._read()
        # Positive pin: the new MATCH form is present
        assert "MATCH (a:Alert {alert_id: $alert_id})" in src, (
            "Query 5 in alert_processor must bind ``Alert`` on its natural "
            "key ``alert_id`` (constraint at neo4j_client.py:794). Without "
            "this, the query matches ALL :Alert nodes in the graph and "
            "returns the cartesian product of every alert's assets + users."
        )

    def test_query_5_uses_optional_match_for_assets_and_users(self) -> None:
        """An alert with no associated assets / users must still return
        a single row with empty lists — preserving the original return
        shape."""
        src = self._read()
        assert "OPTIONAL MATCH (a)-[:TARGETS]->(asset:Asset)" in src
        assert "OPTIONAL MATCH (a)-[:INVOLVES_USER]->(u:User)" in src

    def test_query_5_no_unbound_alert_match(self) -> None:
        """Negative pin: the buggy form ``MATCH (a:Alert)-[:TARGETS]->...``
        with no key binding must NOT reappear. Strip comment-only lines
        before scanning so historical breadcrumbs explaining the bug
        are allowed."""
        src = self._read()
        # Active code only
        active = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        # The bare un-bound form
        assert "MATCH (a:Alert)-[:TARGETS]->(asset:Asset)" not in active, (
            "Regression: the un-bound ``MATCH (a:Alert)-[:TARGETS]->...`` "
            "form (no alert_id filter) silently cross-contaminates "
            "enrichment payloads. PR-N1 fixed this — must not return."
        )
        assert "MATCH (a:Alert)-[:INVOLVES_USER]->(u:User)" not in active, (
            "Same regression for the INVOLVES_USER half of the query."
        )

    def test_query_5_passes_alert_id_kwarg(self) -> None:
        """The Python call site must still pass ``alert_id`` as a
        kwarg to ``session.run``."""
        src = self._read()
        # Find the context_result block
        assert "context_result = session.run(" in src
        cr_idx = src.find("context_result = session.run(")
        block = src[cr_idx : cr_idx + 1000]
        assert "alert_id=alert.alert_id" in block, "context_result must pass alert_id=alert.alert_id as kwarg"


# ===========================================================================
# A2 — legacy USES edge type fully removed
# ===========================================================================


class TestLegacyUsesEdgeTypeFullyRemoved:
    """The bare ``USES`` edge type was retired in 2026-04 (PR #41).
    The fresh-start model writes only the specialized forms
    ``EMPLOYS_TECHNIQUE`` / ``IMPLEMENTS_TECHNIQUE`` / ``USES_TECHNIQUE``.
    PR-N1 removes ALL remaining traces:
      * the alternation ``[:EMPLOYS_TECHNIQUE|USES]`` in alert_processor
      * the ``rt == "USES" and to_type == "Technique"`` backward-compat
        shim in neo4j_client.create_misp_relationships_batch (verified
        no caller emits this)
      * misleading historical comments referencing ``USES``
    """

    @staticmethod
    def _strip_comments(src: str) -> str:
        """Strip whole-line ``#`` Python comments so historical
        breadcrumbs explaining what was removed don't false-match."""
        return "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))

    def test_alert_processor_no_uses_alternation(self) -> None:
        src = (SRC / "alert_processor.py").read_text()
        active = self._strip_comments(src)
        assert "EMPLOYS_TECHNIQUE|USES" not in active, (
            "Regression: the legacy ``EMPLOYS_TECHNIQUE|USES`` Cypher "
            "alternation in alert_processor.py:386 was removed in PR-N1. "
            "It was dead defensive code that masked schema drift."
        )
        # Positive pin: the bare specialized form
        assert "OPTIONAL MATCH (a)-[:EMPLOYS_TECHNIQUE]->(t:Technique)" in src

    def test_neo4j_client_no_legacy_uses_routing_shim(self) -> None:
        src = (SRC / "neo4j_client.py").read_text()
        active = self._strip_comments(src)
        # The dead shim form
        assert 'rt == "USES" and rel.get("to_type") == "Technique"' not in active, (
            "Regression: the backward-compat ``rt == 'USES' and to_type == "
            "'Technique'`` routing shim was removed in PR-N1. Verified no "
            "caller anywhere emits ``rel_type='USES'``."
        )

    def test_no_bare_uses_edge_in_active_cypher_anywhere(self) -> None:
        """Sweep all Python source under ``src/`` for any active Cypher
        fragment that uses the bare ``[:USES]`` or ``[:USES|`` /
        ``|USES]`` / ``|USES->`` shape. ``USES_TECHNIQUE`` is allowed
        (it's a distinct current edge type with the ``_TECHNIQUE``
        suffix)."""
        # Exclude collector pyc + test files
        py_files = [p for p in SRC.rglob("*.py") if "__pycache__" not in str(p)]
        # Build a regex that matches the bare USES edge type but NOT
        # USES_TECHNIQUE. Word-boundary guard ensures we don't match
        # the longer suffix.
        bad = re.compile(r":USES(?!_)|\|USES(?!_)|USES(?!_)\|")
        offenders = []
        for p in py_files:
            text = p.read_text()
            # Strip comment-only lines
            active_lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
            active = "\n".join(active_lines)
            for m in bad.finditer(active):
                # Find the source line for the offender
                line_no = active[: m.start()].count("\n") + 1
                line = active.splitlines()[line_no - 1] if line_no <= len(active.splitlines()) else ""
                offenders.append(f"{p.relative_to(REPO_ROOT)}:{line_no}: {line.strip()!r}")
        assert not offenders, (
            "Legacy bare ``USES`` edge type found in active code. "
            "Use one of the specialized types instead "
            "(EMPLOYS_TECHNIQUE / IMPLEMENTS_TECHNIQUE / USES_TECHNIQUE):\n" + "\n".join(f"  - {o}" for o in offenders)
        )


# ===========================================================================
# Cross-check: $alert_id parameter is referenced inside the Cypher text
# ===========================================================================


class TestAlertEnrichmentParameterIsActuallyUsed:
    """A subtle source-level check: verify that the ``alert_id`` kwarg
    passed to ``session.run`` is ACTUALLY referenced as ``$alert_id``
    inside the Cypher block immediately preceding the kwarg.

    This catches the original PR-N0 audit finding: the parameter was
    bound (``alert_id=alert.alert_id``) but the Cypher had no
    ``$alert_id`` reference. A future regression that reverts the
    Cypher would re-introduce the cross-contamination silently because
    the kwarg binding looks correct.
    """

    def test_alert_id_kwarg_paired_with_dollar_alert_id_in_cypher(self) -> None:
        src = (SRC / "alert_processor.py").read_text()
        # Find the context_result block (Query 5)
        cr_idx = src.find("context_result = session.run(")
        assert cr_idx != -1, "context_result session.run call missing"
        # The whole call expression up to its matching close-paren —
        # use a generous slice; bounded by the next blank line.
        call_block = src[cr_idx : cr_idx + 1500]
        # The Cypher itself is delimited by triple quotes
        first_quote = call_block.find('"""')
        second_quote = call_block.find('"""', first_quote + 3)
        cypher = call_block[first_quote + 3 : second_quote]
        # The cypher MUST contain ``$alert_id`` since the wrapper
        # passes ``alert_id=alert.alert_id`` as kwarg
        assert "$alert_id" in cypher, (
            "Cypher in Query 5 must reference ``$alert_id`` — without this, "
            "the kwarg is silently unused and the query matches ALL Alerts "
            "(the cross-contamination bug PR-N1 fixes)."
        )
        # And the kwarg call site is present
        assert "alert_id=alert.alert_id" in call_block
