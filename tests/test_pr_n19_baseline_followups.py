"""
PR-N19 — post-baseline follow-up bundle from Bravo's baseline-run audit.

The 2026-04-22 baseline (ran before PR #100/#101/#102 merged) surfaced
three bugs that none of the overnight PRs covered. Bravo ran sample
Cypher queries and noticed:

1. **CVE dates missing.** Every CVE in Neo4j had ``first_imported_at``
   set but ``published`` and ``last_modified`` were NULL — even for
   recent NVD-sourced CVEs that clearly had these fields upstream.

2. **Zone array duplicate combos.** ``MATCH (n) RETURN n.zone, count(n)``
   returned fragmented stats: ``["healthcare","energy"]`` and
   ``["energy","healthcare"]`` showed as different groups because
   Cypher groups by exact array equality.

3. **"4 merge/load error(s)" with no per-entity detail.** When
   ``_sync_single_item``'s merge_* calls returned False (not threw),
   only the count was incremented — no log line naming which CVE /
   Malware / Actor / MITRE id was rejected. The "see logs above"
   hint in the summary pointed at nothing.

## Fix #1 — merge_cve promotes published + last_modified

``merge_cve`` (the MISP-sourced CVE path used for 99,664 CVEs in the
baseline) built its ``extra_props`` dict with description, cvss_score,
severity, attack_vector, cisa_*... but NEVER included the NVD date
fields. The data flowed: NVD collector → NVD_META → MISP comment →
run_misp_to_neo4j rehydration into ``item["published"]`` /
``item["last_modified"]`` — then was dropped on the floor by the
extra_props builder. The ResilMesh-native ``merge_resilmesh_cve``
correctly wrote both; the MISP path didn't.

Fix: 4 lines in ``merge_cve`` extra_props builder to promote both
fields when present.

## Fix #2 — canonical sort on zone arrays

``_zone_override_global_clause`` built the accumulator via
``apoc.coll.toSet(coalesce(n.zone, []) + new_zone)`` which dedupes
exact-string entries but does NOT sort. Two nodes seeing the same
zones in different ingest order ended up with different arrays:

  Node A: n.zone = ["healthcare", "energy"]  (count=1)
  Node B: n.zone = ["energy", "healthcare"]  (count=448)

Cypher grouping by exact array equality treated them as different,
fragmenting sector stats. Also broke any STIX-export consumer that
hashed the zone array — same logical zones produced different hashes.

Fix: wrap the union + specifics in ``apoc.coll.sort(...)`` so all
writes produce canonical alphabetic ordering. One-shot Cypher
migration for pre-PR-N19 legacy data (documented in PR body).

## Fix #3 — per-entity logging on merge-returned-False

Six call sites in ``_sync_single_item`` incremented ``errors`` on
merge_* returning False with no log line:
  - merge_cve (rich_vulns + plain_vulns)
  - merge_tactic / merge_technique / merge_tool
  - merge_malware / merge_actor

Now each site emits ``[MERGE-RETURNED-FALSE]`` WARN with the entity
identifier (cve_id / mitre_id / name). The summary error message at
the end of ``run()`` points operators at the new grep token.

Bonus: the ``rich_vulns`` loop used to discard merge_cve's return
value entirely — CVEs that silently failed were counted as success.
Fixed to match the ``plain_vulns`` shape.
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

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n19")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n19")


# ===========================================================================
# Fix #1 — merge_cve promotes published + last_modified
# ===========================================================================


class TestFix1CvePublishedLastModified:
    def test_merge_cve_extra_props_includes_published(self):
        """AST pin: merge_cve must conditionally add 'published' to extra_props."""
        src = (SRC / "neo4j_client.py").read_text()
        tree = ast.parse(src)
        for cls in ast.walk(tree):
            if isinstance(cls, ast.ClassDef):
                for node in cls.body:
                    if isinstance(node, ast.FunctionDef) and node.name == "merge_cve":
                        body = ast.unparse(node)
                        assert 'extra_props["published"]' in body or "extra_props['published']" in body, (
                            "merge_cve must promote data['published'] to extra_props "
                            "(PR-N19 Fix #1; Bravo caught NULL c.published on 99K CVEs)"
                        )
                        return
        raise AssertionError("merge_cve not found")

    def test_merge_cve_extra_props_includes_last_modified(self):
        src = (SRC / "neo4j_client.py").read_text()
        tree = ast.parse(src)
        for cls in ast.walk(tree):
            if isinstance(cls, ast.ClassDef):
                for node in cls.body:
                    if isinstance(node, ast.FunctionDef) and node.name == "merge_cve":
                        body = ast.unparse(node)
                        assert 'extra_props["last_modified"]' in body or "extra_props['last_modified']" in body, (
                            "merge_cve must promote data['last_modified'] to extra_props (PR-N19 Fix #1)"
                        )
                        return
        raise AssertionError("merge_cve not found")

    def test_merge_cve_behavior_promotes_both_fields(self):
        """Behavioral pin: invoke merge_cve with data containing
        published + last_modified; confirm both reach extra_props via
        merge_node_with_source mock."""
        from neo4j_client import Neo4jClient

        c = Neo4jClient.__new__(Neo4jClient)
        c.driver = MagicMock()
        c.merge_node_with_source = MagicMock(return_value=True)

        data = {
            "cve_id": "CVE-2021-44228",
            "description": "Log4Shell",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "published": "2021-12-10T10:15:09.143",
            "last_modified": "2024-04-03T17:02:49.887",
        }
        assert c.merge_cve(data) is True
        # Inspect the extra_props passed to merge_node_with_source.
        call_kwargs = c.merge_node_with_source.call_args.kwargs
        extra_props = call_kwargs.get("extra_props", {})
        assert extra_props.get("published") == "2021-12-10T10:15:09.143", (
            f"merge_cve must pass published to extra_props; got {extra_props.get('published')!r}"
        )
        assert extra_props.get("last_modified") == "2024-04-03T17:02:49.887"


# ===========================================================================
# Fix #2 — zone array canonical sort
# ===========================================================================


class TestFix2ZoneCanonicalSort:
    def test_zone_clause_wraps_in_apoc_coll_sort(self):
        """The generated Cypher must wrap the zone expression in
        apoc.coll.sort() for canonical ordering across writes."""
        from neo4j_client import _zone_override_global_clause

        clause = _zone_override_global_clause("n", "$zone")
        assert "apoc.coll.sort(" in clause, (
            "_zone_override_global_clause must canonicalize zone ordering "
            "via apoc.coll.sort to eliminate duplicate-combo bug "
            "(['healthcare','energy'] vs ['energy','healthcare']). PR-N19 Fix #2."
        )
        # Both branches of the CASE (specifics + union-only) must sort.
        # Count: we expect at least 2 apoc.coll.sort calls in the clause
        # (one for the specifics-branch, one for the else-union-branch).
        assert clause.count("apoc.coll.sort(") >= 2, (
            "both CASE branches (specifics-branch + else-union-branch) must be sorted"
        )

    def test_zone_clause_preserves_drop_global_semantics(self):
        """Regression pin: the specifics-override-global rule (PR-N6/N8
        behaviour) must be preserved under the new sort wrapping."""
        from neo4j_client import _zone_override_global_clause

        clause = _zone_override_global_clause("n", "$zone")
        assert "z <> 'global'" in clause, "specifics filter must still exclude 'global' when other sectors are present"
        assert "CASE WHEN size(" in clause


# ===========================================================================
# Fix #3 — per-entity logging on merge-returned-False
# ===========================================================================


class TestFix3PerEntityMergeFalseLogging:
    def _src(self) -> str:
        return (REPO_ROOT / "src" / "run_misp_to_neo4j.py").read_text()

    def test_plain_cve_logs_cve_id_on_false(self):
        src = self._src()
        assert "[MERGE-RETURNED-FALSE] plain CVE" in src, (
            "plain CVE branch must emit [MERGE-RETURNED-FALSE] on return-False"
        )

    def test_rich_cve_checks_return_value_and_logs(self):
        """Regression pin: pre-PR-N19 the rich_vulns loop did NOT check
        merge_cve's return — silent failures counted as success."""
        src = self._src()
        assert "[MERGE-RETURNED-FALSE] rich CVE" in src, (
            "rich CVE branch must now check merge_cve return + emit "
            "[MERGE-RETURNED-FALSE] on false (PR-N19 Fix #3 follow-up)"
        )
        # Confirm it uses if-check (the specific fix shape).
        assert "if self.neo4j.merge_cve(vuln, source_id=src):" in src

    def test_tactic_technique_tool_log_on_false(self):
        src = self._src()
        for label in ["Tactic", "Technique", "Tool"]:
            assert f"[MERGE-RETURNED-FALSE] {label} " in src, (
                f"{label} branch must emit [MERGE-RETURNED-FALSE] on return-False"
            )

    def test_malware_actor_log_on_false(self):
        src = self._src()
        assert "[MERGE-RETURNED-FALSE] Malware " in src
        assert "[MERGE-RETURNED-FALSE] ThreatActor " in src

    def test_sync_summary_points_at_new_grep_token(self):
        """The ``_last_sync_failure_reason`` message must point operators
        at the new [MERGE-RETURNED-FALSE] / [MERGE-REJECT] tokens so
        the error count becomes traceable."""
        src = self._src()
        assert "[MERGE-RETURNED-FALSE]" in src and "grep" in src and "MERGE-REJECT" in src, (
            "sync failure-reason message must reference the grep tokens operators need to trace errors"
        )


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_neo4j_client_imports(self):
        import neo4j_client  # noqa: F401

    def test_run_misp_to_neo4j_imports(self):
        import run_misp_to_neo4j  # noqa: F401
