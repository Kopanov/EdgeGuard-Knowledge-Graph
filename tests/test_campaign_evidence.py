"""Campaign evidence (2026-10-16): the one definition of what a campaign rests on.

``src/campaign_evidence.py`` is read by ``build_campaign_nodes``, the baseline postcheck (INV-1) and
the acceptance checks. The fragments must read each link in the direction its claim is made, carry no
quotes (they run inside double-quoted ``apoc.periodic.iterate`` statements) and need nothing but the
standard library (the acceptance script imports the module without the driver or the configuration).
Behaviour on a real graph: ``tests/test_explainability_neo4j.py``; the shared-malware rule (2026-11-06):
``tests/test_campaign_shared_malware.py`` and ``tests/test_campaign_shared_malware_neo4j.py``.
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
    assert links == (
        f"[(a)<-[_ev:ATTRIBUTED_TO]-(m) WHERE {ce.link_counts('_ev', 'm')} | _ev] + "
        f"[(a)-[_ev:USES_MALWARE]->(m) WHERE {ce.link_counts('_ev', 'm')} | _ev]"
    )
    assert ce.evidence_links("a") == (
        f"[(a)<-[_ev:ATTRIBUTED_TO]-(_em:Malware) WHERE {ce.link_counts('_ev', '_em')} | _ev] + "
        f"[(a)-[_ev:USES_MALWARE]->(_em:Malware) WHERE {ce.link_counts('_ev', '_em')} | _ev]"
    )
    assert ce.has_evidence("a", "m") == (
        f"(EXISTS {{ MATCH (a)<-[_hv:ATTRIBUTED_TO]-(m) WHERE {ce.link_counts('_hv', 'm')} }} OR "
        f"EXISTS {{ MATCH (a)-[_hv:USES_MALWARE]->(m) WHERE {ce.link_counts('_hv', 'm')} }})"
    )
    members = ce.member_malware("a")
    assert members.startswith("apoc.coll.toSet(") and "(a)<-[_mv:ATTRIBUTED_TO]-(_mm:Malware) WHERE " in members
    assert "(a)-[_mv:USES_MALWARE]->(_mm:Malware) WHERE " in members
    paths = ce.indicator_paths("i", "a")
    assert "(i)-[_xi:INDICATES]->(_xm:Malware)-[_xa:ATTRIBUTED_TO]->(a) WHERE " in paths
    assert "(i)-[_xi:INDICATES]->(_xm:Malware)<-[_xa:USES_MALWARE]-(a) WHERE " in paths
    assert paths.count(" | [_xi, _xa]]") == 2


def test_fragments_carry_no_quotes():
    for fragment in (
        ce.evidence_links("a"),
        ce.evidence_links("a", "m"),
        ce.member_malware("a"),
        ce.has_evidence("a"),
        ce.indicator_paths("i", "a"),
        ce.indicator_joins("i", "m", "a"),
        ce.indicates_shared("i"),
        ce.counts_for("l", "i"),
        ce.evidence_types("links"),
        ce.recorded_shared_malware("c"),
        ce.SHARED_LINKS_QUERY,
        ce.QUALIFYING_ACTORS_QUERY,
        ce.RECORDED_SHARED_MALWARE_QUERY,
        ce.MALWARE_MEMBERSHIP_CHECK_QUERY,
        ce.INDICATOR_MEMBERSHIP_CHECK_QUERY,
        ce.CAMPAIGN_EVIDENCE_CHECK_QUERY,
    ):
        assert '"' not in fragment and "'" not in fragment, fragment
    # 2026-11-06: the name key of the shared-malware count holds quotes; only that query, which never runs
    # inside apoc.periodic.iterate, reads it.
    assert ce.malware_key("name") in ce.SHARED_MALWARE_QUERY and '"' not in ce.SHARED_MALWARE_QUERY


def test_the_checks_and_the_postcheck_read_the_same_definition():
    # 2026-11-06: the checks judge a campaign with the shared malware its build recorded.
    recorded = ce.recorded_shared_malware("c")
    assert ce.has_evidence("a", "m", recorded) in ce.MALWARE_MEMBERSHIP_CHECK_QUERY
    assert ce.MALWARE_MEMBERSHIP_CHECK_QUERY.count("AS ") == 2  # malware_links, without_evidence
    assert ce.CAMPAIGN_EVIDENCE_CHECK_QUERY.count(ce.has_evidence("a", shared=recorded)) == 1  # campaigns
    assert ce.CAMPAIGN_EVIDENCE_CHECK_QUERY.count(ce.has_evidence("a", shared=ce.recorded_shared_malware("rc"))) == 1
    for name in ("campaigns", "without_evidence", "without_runs", "runs_without_evidence"):
        assert f"AS {name}" in ce.CAMPAIGN_EVIDENCE_CHECK_QUERY
    # INV-1: either link, to a malware an active indicator indicates, counting for that indicator.
    query = ce.QUALIFYING_ACTORS_QUERY
    assert (
        "MATCH (a)<-[_ql:ATTRIBUTED_TO]-(m:Malware)<-[:INDICATES]-(i:Indicator) WHERE i.active = true AND "
        + ce.counts_for("_ql", "i")
    ) in query
    assert (
        "MATCH (a)-[_ql:USES_MALWARE]->(m:Malware)<-[:INDICATES]-(i:Indicator) WHERE i.active = true AND "
        + ce.counts_for("_ql", "i")
    ) in query
    # 2026-11-06: the indicator membership check reads the builder's paths.
    assert ce.indicator_paths("i", "a", recorded) in ce.INDICATOR_MEMBERSHIP_CHECK_QUERY
    for name in ("indicator_links", "without_evidence"):
        assert f"AS {name}" in ce.INDICATOR_MEMBERSHIP_CHECK_QUERY


def test_standard_library_only():
    tree = ast.parse((SRC / "campaign_evidence.py").read_text())
    imported = {
        alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    } | {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    assert imported <= {"__future__", "typing"}, imported
