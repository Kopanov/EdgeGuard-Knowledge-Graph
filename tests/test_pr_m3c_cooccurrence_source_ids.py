"""
PR-M3c — §8-RI-S3-Q9: Co-occurrence ``r.source_ids`` accumulation.

Superseded 2026-10 (relationship provenance): ``r.source_id`` / ``r.source_ids`` were dropped
in favour of the accumulating ``r.sources`` / ``r.source_refs`` / ``r.misp_event_ids`` lists
(``src/relationship_provenance.py``), with the kind of evidence in ``r.match_type``. The
tests below pin the successor contract for the same build_relationships sites; the history is
kept for context. The co-occurrence calibration job the history names was removed on 2026-10-18,
because no current code writes co-occurrence edges.

## The bug

``src/build_relationships.py`` Q4 (Indicator→Malware co-occurrence)
stamps ``r.source_id = "misp_cooccurrence"`` on the INDICATES edge.
Q9 (malware_family match) later MERGEs the SAME edge and OVERWRITES
``r.source_id = "malware_family_match"`` — the last-writer-wins scalar
hides the co-occurrence provenance.  The calibrator
(``calibrate_cooccurrence_confidence``) filters on
``r.source_id IN ["misp_cooccurrence", "misp_correlation"]`` and
silently MISSES these edges, leaving them at 0.8 confidence instead of
the bulk-dump tier's 0.30-0.50.  Estimated 30-50% of INDICATES edges
on a 730-day baseline are affected.

## The fix

1. Every MERGE site that sets ``r.source_id = "<X>"`` ALSO sets
   ``r.source_ids = apoc.coll.toSet(coalesce(r.source_ids, []) + ["<X>"])``
   so every tag that has ever applied to the edge is preserved.
2. Calibrator filter becomes
   ``(r.source_ids IS NOT NULL AND any(s IN r.source_ids WHERE s IN [...]))
   OR r.source_id IN [...]`` — array match for post-fix edges; scalar
   fallback for pre-fix/legacy edges.
3. Scalar ``r.source_id`` writes kept for backwards compat with any
   legacy reader.

## Test strategy

Source-pin the fix sites (Q3a/Q3b/Q4/Q9) so any future regression that
reintroduces the scalar ``r.source_id`` writes or the removed Q4 fails loudly.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ===========================================================================
# build_relationships.py — every source_id write site accumulates source_ids
# ===========================================================================


class TestBuildRelationshipsAccumulatesProvenance:
    """No MERGE site may erase earlier provenance (the bug: Q9 overwriting Q4's scalar).
    Since 2026-10 the provenance is the accumulating ``r.sources`` / ``r.source_refs`` /
    ``r.misp_event_ids`` lists, so nothing writes a last-writer-wins source field."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (SRC / "build_relationships.py").read_text()

    def test_q3a_exploits_vuln_accumulates_provenance(self, source: str) -> None:
        """2026-10 (relationship provenance) superseded ``r.source_ids``: Q3a accumulates the
        indicator's feeds, record ids and MISP events (``_prov_with`` / ``_prov_set``) and the
        evidence label stays ``cve_tag``; no scalar or set of evidence names is written."""
        block = source[source.find("_q3a_inner") : source.find("_q3a_skip")]
        assert '_prov_with("i", _node_feeds("i"))' in block and "_prov_set()" in block
        assert 'r.match_type = "cve_tag"' in block
        assert "source_id" not in block and "source_ids" not in block

    def test_q3b_exploits_cve_accumulates_provenance(self, source: str) -> None:
        block = source[source.find("_q3b_inner") : source.find("_q3b_skip")]
        assert '_prov_with("i", _node_feeds("i"))' in block and "_prov_set()" in block
        assert 'r.match_type = "cve_tag"' in block
        assert "source_id" not in block and "source_ids" not in block

    def test_q4_cooccurrence_query_removed(self, source: str) -> None:
        """2026-10 (fresh-baseline PR): Q4 — the whole-event
        ``misp_cooccurrence`` INDICATES query that this PR originally
        hardened — was REMOVED (ResilMesh conformance finding F1). The
        pre-overwrite site no longer exists, so nothing in this file may
        MERGE an INDICATES edge stamped ``misp_cooccurrence``. Report-scoped
        INDICATES edges now come from the MISP→Neo4j sync (``otx_pulse``);
        the reported-technique queries 5b / 6b took Q4's place."""
        assert "_q4_inner" not in source, "Q4 co-occurrence inner query must stay removed"
        assert "_q4_outer" not in source, "Q4 co-occurrence outer query must stay removed"
        # Scan the executable Cypher (string constants assigned to ``*_inner``
        # variables), not the prose — the Q9 comment trail still quotes the
        # old ``misp_cooccurrence`` stamp when explaining the overwrite bug.
        import ast

        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for tgt in node.targets:
                if not (isinstance(tgt, ast.Name) and tgt.id.endswith("_inner")):
                    continue
                body = "".join(
                    c.value for c in ast.walk(node.value) if isinstance(c, ast.Constant) and isinstance(c.value, str)
                )
                assert "misp_cooccurrence" not in body, f"{tgt.id} must not stamp misp_cooccurrence"
        assert '"employs_technique_reported"' in source, "5b (ThreatActor reported_techniques) must exist"
        assert '"malware_implements_technique_reported"' in source, "6b (Malware reported_techniques) must exist"

    def test_q9_malware_family_accumulates_provenance(self, source: str) -> None:
        """Q9 (the overwrite site this file was written for) can no longer erase anything:
        the feeds, record ids and MISP events only accumulate (``_prov_set``), and the evidence
        label ``malware_family`` lives in ``r.match_type``. The feeds are the indicator's
        family-label sources (``_family_feeds``)."""
        block = source[source.find("_q9_inner") : source.find("_q9_skip")]
        assert '_prov_with("i", _family_feeds("i"))' in block and "_prov_set()" in block
        assert 'r.match_type = "malware_family"' in block
        assert "source_id" not in block and "source_ids" not in block
