"""Campaign evidence (2026-10-16): the one definition of what a campaign rests on.

``src/campaign_evidence.py`` is read by ``build_campaign_nodes``, the baseline postcheck (INV-1) and
the acceptance checks. The fragments must read each link in the direction its claim is made, carry no
quotes (they run inside double-quoted ``apoc.periodic.iterate`` statements) and need nothing but the
standard library (the acceptance script imports the module without the driver or the configuration).
Behaviour on a real graph: ``tests/test_explainability_neo4j.py``.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import campaign_evidence as ce  # noqa: E402


def test_both_links_in_the_direction_of_their_claim():
    assert ce.CAMPAIGN_EVIDENCE_TYPES == ("ATTRIBUTED_TO", "USES_MALWARE")
    links = ce.evidence_links("a", "m")
    assert links == "[(a)<-[_ev:ATTRIBUTED_TO]-(m) | _ev] + [(a)-[_ev:USES_MALWARE]->(m) | _ev]"
    assert ce.evidence_links("a") == (
        "[(a)<-[_ev:ATTRIBUTED_TO]-(:Malware) | _ev] + [(a)-[_ev:USES_MALWARE]->(:Malware) | _ev]"
    )
    assert ce.has_evidence("a", "m") == (
        "(EXISTS { (a)<-[:ATTRIBUTED_TO]-(m) } OR EXISTS { (a)-[:USES_MALWARE]->(m) })"
    )
    members = ce.member_malware("a")
    assert members.startswith("apoc.coll.toSet(") and "(a)<-[:ATTRIBUTED_TO]-(_mm:Malware)" in members
    assert "(a)-[:USES_MALWARE]->(_mm:Malware)" in members
    paths = ce.indicator_paths("i", "a")
    assert "(i)-[_xi:INDICATES]->(:Malware)-[_xa:ATTRIBUTED_TO]->(a) | [_xi, _xa]" in paths
    assert "(i)-[_xi:INDICATES]->(:Malware)<-[_xa:USES_MALWARE]-(a) | [_xi, _xa]" in paths


def test_fragments_carry_no_quotes():
    for fragment in (
        ce.evidence_links("a"),
        ce.evidence_links("a", "m"),
        ce.member_malware("a"),
        ce.has_evidence("a"),
        ce.indicator_paths("i", "a"),
        ce.evidence_types("links"),
    ):
        assert '"' not in fragment and "'" not in fragment, fragment


def test_the_checks_and_the_postcheck_read_the_same_definition():
    assert ce.has_evidence("a", "m") in ce.MALWARE_MEMBERSHIP_CHECK_QUERY
    assert ce.MALWARE_MEMBERSHIP_CHECK_QUERY.count("AS ") == 2  # malware_links, without_evidence
    assert ce.CAMPAIGN_EVIDENCE_CHECK_QUERY.count(ce.has_evidence("a")) == 2  # campaigns and RUNS
    for name in ("campaigns", "without_evidence", "without_runs", "runs_without_evidence"):
        assert f"AS {name}" in ce.CAMPAIGN_EVIDENCE_CHECK_QUERY
    # INV-1: either link, to a malware an active indicator indicates.
    query = ce.QUALIFYING_ACTORS_QUERY
    assert "MATCH (a)<-[:ATTRIBUTED_TO]-(:Malware)<-[:INDICATES]-(i:Indicator) WHERE i.active = true" in query
    assert "MATCH (a)-[:USES_MALWARE]->(:Malware)<-[:INDICATES]-(i:Indicator) WHERE i.active = true" in query


def test_standard_library_only():
    tree = ast.parse((SRC / "campaign_evidence.py").read_text())
    imported = {
        alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    } | {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    assert imported <= {"__future__", "typing"}, imported
