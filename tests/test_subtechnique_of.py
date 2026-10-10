"""Pins for the 2026-10 R6 build: ``(Technique)-[:SUBTECHNIQUE_OF]->(Technique)``.

MITRE encodes the sub-technique hierarchy in the dotted id (``T1021.006`` → ``T1021``) — the same
claim as its STIX ``subtechnique-of`` relationship — so ``build_relationships`` Q1b derives the edge
from the id with ``match_type='mitre_explicit'`` at 1.0, within one ``attack_domain``. 493
sub-techniques on the September graph, every parent present, zero edges before this build.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_BUILD_REL = _SRC / "build_relationships.py"
_ACCEPT = _SRC.parent / "scripts" / "verify_fresh_baseline.py"


def _assigned_string(name: str) -> str:
    tree = ast.parse(_BUILD_REL.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return "".join(
                c.value for c in ast.walk(node.value) if isinstance(c, ast.Constant) and isinstance(c.value, str)
            )
    raise AssertionError(f"{name} not found")


class TestSubtechniqueOfStep:
    def test_outer_selects_dotted_ids_only(self):
        assert _assigned_string("_q1b_outer") == 'MATCH (s:Technique) WHERE s.mitre_id CONTAINS "." RETURN s'

    def test_inner_derives_parent_from_the_id_within_one_domain(self):
        body = _assigned_string("_q1b_inner")
        assert 'split(s.mitre_id, ".")[0] AS parent_id' in body
        assert "MATCH (p:Technique {mitre_id: parent_id})" in body
        assert 'coalesce(p.attack_domain, "enterprise") = coalesce(s.attack_domain, "enterprise")' in body
        assert "MERGE (s)-[r:SUBTECHNIQUE_OF]->(p)" in body

    def test_inner_stamps_evidence_marker_and_uuids_unconditionally(self):
        body = _assigned_string("_q1b_inner")
        _, _, rest = body.partition("ON CREATE SET ")
        on_create, _, after = rest.partition(" SET ")
        assert "match_type" not in on_create
        assert 'r.match_type = "mitre_explicit"' in after and "r.confidence_score = 1.0" in after
        assert "r.edgeguard_managed = true" in after
        assert (
            "r.src_uuid = coalesce(r.src_uuid, s.uuid)" in after
            and "r.trg_uuid = coalesce(r.trg_uuid, p.uuid)" in after
        )

    def test_inner_uses_only_double_quoted_literals(self):
        # _safe_run_batched wraps the inner query in single quotes for apoc.periodic.iterate
        assert "'" not in _assigned_string("_q1b_inner")

    def test_step_is_wired_right_after_q1(self):
        text = _BUILD_REL.read_text()
        pos = [re.search(rf"\[LINK\] {s}/\d+ ", text).start() for s in ("1", "1b", "2")]
        assert pos == sorted(pos)
        assert '"subtechnique_of"' in text, "its own stats key"

    def test_step_count_is_eighteen(self):
        text = _BUILD_REL.read_text()
        banners = re.findall(r"\[LINK\] (\w+)/(\d+) ", text)
        assert {t for _, t in banners} == {"18"} and len(banners) == 18
        assert "failures=%d/18" in text


class TestAcceptanceScript:
    def test_relationship_type_is_policed_and_checked(self):
        script = _ACCEPT.read_text()
        assert '    "SUBTECHNIQUE_OF",\n' in script
        assert 'rep.add("subtechnique_of_complete"' in script
        assert "NOT EXISTS { (s)-[:SUBTECHNIQUE_OF]->(p) }" in script
