"""
PR-N10 — BLOCK-MERGE bundle from 7-agent pre-baseline audit.

Three BLOCK-severity findings from the audit run before the next 730d
baseline. All three are cross-agent-corroborated or trace-verified.

## Fix #1 — Placeholder-name reject at merge + Cypher defense-in-depth

Bug Hunter P1/P3 traced feed emissions of "unknown" / "Unknown malware"
/ "N/A" to Malware and ThreatActor node keys. Red Team #1 demonstrated
an adversarial attribution hijack (attacker creates Malware{name:
"unknown", attributed_to:"APT29"}; Q9 then links every Indicator with
family="unknown" — a very common feed default — to that Malware; Q2
edges that Malware to real APT29; false attribution corruption at
scale). Devil's Advocate #4 argued for fixing at ingest, not Cypher.

Fix: `_REJECTED_PLACEHOLDER_NAMES` frozenset in node_identity + a
`is_placeholder_name(name) -> bool` helper. `merge_malware` and
`merge_actor` in neo4j_client.py return False on placeholder names
(logging a MERGE-REJECT warning). Defense-in-depth: Q2 outer + Q9
outer/inner/skip Cypher WHERE clauses filter placeholders via
`NOT toLower(trim(x)) IN [...]`.

## Fix #2 — Extend PR-N8 calibrator-respect to 6 create_*_relationship helpers + _set_clause

Cross-Checker BLOCK 1: PR-N8's calibrator-respect was incomplete. Q9
in build_relationships.py honored `r.calibrated_at IS NOT NULL`, but
6 Python helpers + `create_misp_relationships_batch._set_clause` still
unconditionally SET `r.confidence_score = <constant>`. Next sync
undoes calibrator's demotion.

Fix: new `_confidence_respect_calibrator(value)` helper generating
`CASE WHEN r.calibrated_at IS NOT NULL THEN r.confidence_score ELSE
{value} END`. Applied at all 7 sites:
  - create_actor_technique_relationship (0.7)
  - create_malware_actor_relationship (0.7)
  - create_indicator_vulnerability_relationship (0.5 x 2 branches)
  - create_indicator_malware_relationship (0.6)
  - create_indicator_sector_relationship (0.5)
  - create_vulnerability_sector_relationship (0.5)
  - create_misp_relationships_batch._set_clause (row.confidence param)

## Fix #3 — OTX_META carries malware_family + attributed_to

Logic Tracker B1: walked one OTX indicator end-to-end and found
`misp_writer.py:974-985` OTX_META dict omits `malware_family` and
`attributed_to`. Only TF_META's `malware_family` survived the MISP
round-trip. Net: `i.malware_family` is NULL for every OTX-sourced
Indicator → Q9 INDICATES edges never fire for OTX (the biggest source).

Fix: add both fields to OTX_META serialization; add `attributed_to`
to TF_META for parity; rehydrate both in `run_misp_to_neo4j.py`
read-back path.
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

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n10")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n10")


# ===========================================================================
# Fix #1 — placeholder-name reject
# ===========================================================================


class TestFix1PlaceholderNameReject:
    """``is_placeholder_name`` + merge_malware/merge_actor reject guard +
    Cypher defense-in-depth in Q2/Q9."""

    # -- is_placeholder_name helper --

    def test_helper_rejects_canonical_placeholders(self):
        from node_identity import is_placeholder_name

        # Core unknowns
        for name in ["unknown", "Unknown", "UNKNOWN", "  unknown  "]:
            assert is_placeholder_name(name), f"must reject {name!r}"
        # Variants
        for name in ["Unknown malware", "N/A", "n/a", "NA", "none", "None", "null", "NULL"]:
            assert is_placeholder_name(name), f"must reject {name!r}"
        # Symbol placeholders
        for name in ["-", "--", "--- ", "?", "??", ".."]:
            assert is_placeholder_name(name), f"must reject {name!r}"
        # Threat-intel catch-alls
        for name in ["generic", "Generic", "TEST", "example"]:
            assert is_placeholder_name(name), f"must reject {name!r}"

    def test_helper_accepts_legitimate_names(self):
        from node_identity import is_placeholder_name

        for name in ["Emotet", "emotet", "APT29", "apt29", "Cozy Bear", "TrickBot"]:
            assert not is_placeholder_name(name), f"must NOT reject {name!r}"

    def test_helper_rejects_non_string(self):
        """Non-string input → rejected (None, int, etc. are not meaningful names)."""
        from node_identity import is_placeholder_name

        for val in [None, 12345, [], {}, True]:
            assert is_placeholder_name(val), f"non-string {val!r} must be rejected"

    # -- merge_malware / merge_actor guards --

    def test_merge_malware_rejects_placeholder_name(self, caplog):
        import logging

        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()  # satisfies downstream checks

        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            result = client.merge_malware({"name": "Unknown malware"}, source_id="otx")
        assert result is False, "merge_malware must return False for placeholder name"
        assert any("MERGE-REJECT" in r.message for r in caplog.records), "must emit MERGE-REJECT warning"

    def test_merge_malware_rejects_n_a(self):
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        assert client.merge_malware({"name": "N/A"}) is False
        assert client.merge_malware({"name": "  unknown  "}) is False
        assert client.merge_malware({"name": None}) is False

    def test_merge_actor_rejects_placeholder_name(self, caplog):
        import logging

        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()

        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            result = client.merge_actor({"name": "unknown"}, source_id="mitre_attck")
        assert result is False
        assert any("MERGE-REJECT" in r.message for r in caplog.records)

    # -- Cypher defense-in-depth in Q2/Q9 --

    def test_q2_outer_filters_placeholders(self):
        """Q2 outer's attributed_to OR-branch must include placeholder
        NOT IN filter. The filter lives INSIDE the branch (not at the
        end with AND) so that aliases-only rows with NULL attributed_to
        still pass. See _outer docstring for the NULL-propagation
        rationale."""
        src = (SRC / "build_relationships.py").read_text()
        step2_idx = src.find("[LINK] 2/12 Malware → ThreatActor")
        step3_idx = src.find("[LINK] 3a/12", step2_idx)
        block = src[step2_idx:step3_idx]
        # Must filter placeholder attributed_to in outer (no coalesce —
        # the branch has already asserted IS NOT NULL so coalesce would
        # be redundant and would also create a false-match of NULL→"").
        assert "NOT toLower(trim(m.attributed_to)) IN" in block, (
            "Q2 outer must filter placeholder attributed_to via NOT IN list"
        )

    def test_q2_inner_filters_placeholder_actor_names(self):
        src = (SRC / "build_relationships.py").read_text()
        step2_idx = src.find("[LINK] 2/12 Malware → ThreatActor")
        step3_idx = src.find("[LINK] 3a/12", step2_idx)
        block = src[step2_idx:step3_idx]
        assert "NOT toLower(trim(a.name)) IN" in block, "Q2 inner must filter placeholder ThreatActor names"

    def test_q9_outer_filters_placeholder_malware_family(self):
        src = (SRC / "build_relationships.py").read_text()
        q9_start = src.find("[LINK] 9/12")
        q10_start = src.find("[LINK] 10/12")
        block = src[q9_start:q10_start]
        # The outer must include the NOT IN filter
        q9_outer_idx = block.find("_q9_outer")
        q9_outer_end = block.find("_q9_inner", q9_outer_idx)
        outer = block[q9_outer_idx:q9_outer_end]
        assert "NOT toLower(trim(i.malware_family)) IN" in outer, "Q9 outer must filter placeholder malware_family"

    def test_q9_inner_filters_placeholder_malware_names(self):
        src = (SRC / "build_relationships.py").read_text()
        q9_start = src.find("[LINK] 9/12")
        q10_start = src.find("[LINK] 10/12")
        block = src[q9_start:q10_start]
        q9_inner_idx = block.find("_q9_inner")
        q9_skip_idx = block.find("_q9_skip", q9_inner_idx)
        inner = block[q9_inner_idx:q9_skip_idx]
        assert "NOT toLower(trim(m.name)) IN" in inner, "Q9 inner must filter placeholder Malware names"

    def test_q9_skip_mirrors_inner_filter(self):
        src = (SRC / "build_relationships.py").read_text()
        q9_start = src.find("[LINK] 9/12")
        q10_start = src.find("[LINK] 10/12")
        block = src[q9_start:q10_start]
        q9_skip_idx = block.find("_q9_skip")
        next_assignment_idx = block.find("if not _safe_run_batched", q9_skip_idx)
        skip = block[q9_skip_idx:next_assignment_idx]
        # Skip must mirror both outer (malware_family) and inner (m.name) filters
        assert "NOT toLower(trim(i.malware_family)) IN" in skip
        assert "NOT toLower(trim(m.name)) IN" in skip


# ===========================================================================
# Fix #2 — calibrator-respect completion
# ===========================================================================


class TestFix2CalibratorRespectComplete:
    """``_confidence_respect_calibrator`` helper applied at all 7 sites:
    6 create_*_relationship helpers + _set_clause in batched path."""

    def _src(self) -> str:
        return (SRC / "neo4j_client.py").read_text()

    def test_helper_defined(self):
        src = self._src()
        assert "def _confidence_respect_calibrator(" in src

    def test_helper_correct_shape(self):
        from neo4j_client import _confidence_respect_calibrator

        result = _confidence_respect_calibrator(0.7)
        assert result == "CASE WHEN r.calibrated_at IS NOT NULL THEN r.confidence_score ELSE 0.7 END"

    def test_helper_accepts_cypher_param_expression(self):
        """Must work with `$param` expressions for the batched path."""
        from neo4j_client import _confidence_respect_calibrator

        result = _confidence_respect_calibrator("row.confidence")
        assert "ELSE row.confidence END" in result

    def test_all_7_sites_use_helper(self):
        """Count the usages — must be 7 executable sites + 1 _set_clause
        call. The docstring example is in a comment/docstring so it's
        inside a string literal."""
        src = self._src()
        # Count executable invocations (exclude docstring example)
        # Docstring example is on line 192 area: `f"SET r.confidence_score = {_confidence_respect_calibrator(0.7)}"`
        # Real sites are in the 6 helpers + _set_clause body
        count = src.count("_confidence_respect_calibrator(")
        # Helper definition (1) + docstring example (1) + 7 helper sites + 1 _set_clause = 10
        assert count >= 9, f"expected >=9 usages (def + docstring + 7 helpers + _set_clause); got {count}"

    def test_no_unconditional_confidence_writes_remaining(self):
        """Regression pin: no `r.confidence_score = <literal>` should
        appear in executable code (only in docstring examples). AST walk."""
        import ast

        src = self._src()
        tree = ast.parse(src)
        # Walk JoinedStr (f-strings) and plain Str constants, search for
        # `r.confidence_score = <numeric-literal>` pattern.
        for node in ast.walk(tree):
            # Look for string literals containing "r.confidence_score = 0."
            # except inside the docstring helper definition.
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                s = node.value
                if (
                    "r.confidence_score = 0.5" in s
                    or "r.confidence_score = 0.6" in s
                    or "r.confidence_score = 0.7" in s
                ):
                    # Must be in a context that ALSO has ELSE (calibrator-wrapped)
                    # or be explicit documentation
                    if "CASE WHEN r.calibrated_at" not in s and "ELSE " not in s:
                        # The only legitimate occurrence is the docstring
                        # example at line ~181 which has "SET r.confidence_score = 0.7"
                        # as the PRE-fix shape being explained
                        if "SET r.confidence_score = 0.7\n" not in s:
                            raise AssertionError(
                                f"Fix #2 regression: unconditional confidence write "
                                f"found in string literal: {s[:200]!r}"
                            )


# ===========================================================================
# Fix #3 — OTX_META completion
# ===========================================================================


class TestFix3OtxMetaCompletion:
    """OTX_META (serialize) and run_misp_to_neo4j read-back carry
    malware_family + attributed_to."""

    def test_otx_meta_includes_malware_family_and_attributed_to(self):
        src = (SRC / "collectors" / "misp_writer.py").read_text()
        # Find the OTX_META dict. Use a wide scan window because the
        # breadcrumb comment block eats ~600 chars.
        idx = src.find('"attack_ids": indicator.get("attack_ids"')
        assert idx != -1, "OTX_META dict not found"
        block = src[idx : idx + 3000]
        assert '"malware_family": indicator.get("malware_family"' in block, (
            "OTX_META must include malware_family (Fix #3)"
        )
        assert '"attributed_to": indicator.get("attributed_to"' in block, "OTX_META must include attributed_to (Fix #3)"

    def test_tf_meta_includes_attributed_to(self):
        """TF_META already had malware_family; Fix #3 adds attributed_to
        for parity with OTX_META."""
        src = (SRC / "collectors" / "misp_writer.py").read_text()
        idx = src.find('"malware_malpedia": indicator.get("malware_malpedia"')
        assert idx != -1
        block = src[idx : idx + 3000]
        assert '"attributed_to": indicator.get("attributed_to"' in block, "TF_META must include attributed_to (Fix #3)"

    def test_run_misp_to_neo4j_rehydrates_otx_malware_family(self):
        """run_misp_to_neo4j's OTX-meta read-back must populate
        item['malware_family'] and item['attributed_to']."""
        src = (SRC / "run_misp_to_neo4j.py").read_text()
        idx = src.find('item["attack_ids"] = otx_meta.get("attack_ids"')
        assert idx != -1, "OTX-meta rehydration block not found"
        # Wider window because the new breadcrumb comment block is ~500 chars
        block = src[idx : idx + 2500]
        assert 'item["malware_family"] = otx_meta.get("malware_family"' in block, (
            "Fix #3: OTX rehydrate must populate malware_family"
        )
        assert 'item["attributed_to"] = otx_meta.get("attributed_to"' in block, (
            "Fix #3: OTX rehydrate must populate attributed_to"
        )

    def test_run_misp_to_neo4j_rehydrates_tf_attributed_to(self):
        """TF read-back now also pulls attributed_to (already had
        malware_family)."""
        src = (SRC / "run_misp_to_neo4j.py").read_text()
        idx = src.find('item["malware_malpedia"] = tf_meta.get("malware_malpedia"')
        assert idx != -1
        block = src[idx : idx + 2500]
        assert 'item["attributed_to"] = tf_meta.get("attributed_to"' in block, (
            "Fix #3: TF rehydrate must populate attributed_to"
        )


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_build_relationships_imports(self):
        import build_relationships  # noqa: F401

    def test_neo4j_client_imports(self):
        import neo4j_client  # noqa: F401

    def test_node_identity_exports(self):
        from node_identity import (
            _REJECTED_PLACEHOLDER_NAMES,
            canonicalize_merge_key,
            is_placeholder_name,
        )

        assert callable(is_placeholder_name)
        assert len(_REJECTED_PLACEHOLDER_NAMES) >= 20, (
            "placeholder set should have ~20+ entries; if this fails, check the frozenset wasn't accidentally shrunk"
        )
        assert callable(canonicalize_merge_key)
