"""The completeness statements of the graph's shape (2026-11-02, ``src/graph_shape_checks.py``).

Each statement judges a family of links against the claims the writer reads, so it must read them as the
writer does: the same node labels and claims property, the same revoked-id translation, the same Tactic match,
the same zone rule. These tests derive that from the ``build_relationships`` statements themselves (rendered
without a database, as ``tests/test_verify_fresh_baseline.py`` renders them for the provenance contract). The
acceptance-level verdicts are tested in ``tests/test_verify_fresh_baseline.py``.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

import graph_shape_checks as gsc
from relationship_provenance import as_list, zone_prov_with

SRC = Path(__file__).resolve().parent.parent / "src"


def test_standard_library_only():
    """The acceptance script imports only standard-library modules and these shared ones."""
    tree = ast.parse((SRC / "graph_shape_checks.py").read_text())
    imported = {
        alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    } | {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    assert imported <= {"__future__", "typing", "relationship_provenance"}, imported


def test_the_sector_zones_are_the_valid_zones():
    import config

    assert set(gsc.SECTOR_ZONES) == set(config.VALID_ZONES) - {"global"}
    assert list(gsc.SECTOR_ZONES) == sorted(gsc.SECTOR_ZONES)


def test_the_cvss_types_are_the_writers():
    import cvss_selection

    assert sorted(gsc.CVSS_REL_TYPES) == sorted(v.rel_type for v in cvss_selection.CVSS_VERSIONS)
    for rel_type in gsc.CVSS_REL_TYPES:
        assert rel_type in gsc.CVE_CVSS_COVERAGE_QUERY


@pytest.fixture(scope="module")
def writer_steps() -> List[Tuple[str, str]]:
    """``(outer, inner)`` of every ``build_relationships`` step, rendered without a database."""
    import build_relationships

    steps: List[Tuple[str, str]] = []

    class _Client:
        def connect(self):
            return True

        def close(self):
            pass

        def run(self, query, **kw):
            return [{"count": 0, "c": 0}]

    def _batched(client, label, outer, inner, stats, key, batch_size=5000, skip_query=None, params=None):
        steps.append((outer, inner))
        return True

    mp = pytest.MonkeyPatch()
    try:
        mp.setattr(build_relationships, "Neo4jClient", _Client)
        mp.setattr(build_relationships, "_safe_run_batched", _batched)
        mp.setattr(build_relationships, "query_pause", lambda: None)
        build_relationships.build_relationships()
    finally:
        mp.undo()
    # 19 batched steps: step 2 (Malware.attributed_to, which no writer produces) runs no query.
    assert len(steps) == 19
    return steps


def _step(steps: List[Tuple[str, str]], merge: str) -> Tuple[str, str]:
    found = [(o, i) for o, i in steps if merge in i]
    assert len(found) == 1, (merge, len(found))
    return found[0]


@pytest.mark.parametrize("label, claims, rel_type, match_type", gsc.TECHNIQUE_CLAIM_LINKS)
def test_each_technique_claims_statement_reads_the_claims_as_its_writer(
    writer_steps, label, claims, rel_type, match_type
):
    """Steps 5, 6, 10 and 8: the writer matches the label's nodes by the claims property, translates each id
    through ``$revoked`` and links the Technique of that id; a MITRE step stamps ``match_type`` in the SET that
    runs on every write (not only ON CREATE), so a stored link of another label carries it too."""
    pairs = [
        (o, i)
        for o, i in writer_steps
        if re.fullmatch(rf"MATCH \((\w+):{label}\) WHERE size\(coalesce\(\1\.{claims}, \[\]\)\) > 0 RETURN \1", o)
        and f":{rel_type}]->(t)" in i
    ]
    assert len(pairs) == 1, pairs
    outer, inner = pairs[0]
    var = outer.split("(", 1)[1].split(":", 1)[0]
    assert f"UNWIND {var}.{claims} AS" in inner
    # The cited id is translated under another name: no statement re-binds a name to an expression of
    # itself (on Neo4j 2026.03.1 a subquery in the same WHERE read the untranslated id).
    translated = re.search(r"coalesce\(\$revoked\[toString\((\w+)\)\], \1\) AS (\w+)", inner)
    assert translated and translated.group(1) != translated.group(2)
    assert "MATCH (t:Technique {mitre_id: " in inner and f"MERGE ({var})-[r:{rel_type}]->(t)" in inner
    if match_type:
        assert (
            f'ON CREATE SET r.created_at = datetime() SET r.confidence_score = 0.95, r.match_type = "{match_type}"'
            in inner
        )

    statement = gsc.TECHNIQUE_CLAIMS_QUERIES[(label, rel_type)]
    assert statement.startswith(f"MATCH (n:{label}) WHERE size(coalesce(n.{claims}, [])) > 0 ")
    assert f"UNWIND {as_list('n.' + claims)} AS cited" in statement
    assert "coalesce($revoked[toString(cited)], cited) AS tid" in statement
    assert "OPTIONAL MATCH (t:Technique {mitre_id: tid})" in statement
    edge = f"(n)-[r:{rel_type}]->(t)" + (f" WHERE r.match_type = '{match_type}'" if match_type else "")
    assert f"NOT EXISTS {{ {edge} }}" in statement
    assert "target_missing, claims - target_missing AS claims_with_target, edge_missing" in statement
    assert ("AS mitre_nodes" in statement) is bool(match_type)


def test_implements_reads_malware_and_tool_apart():
    """One statement over ``(m:Malware OR m:Tool)`` took 54 s on the 730-day graph; one per label 0.3 s."""
    assert set(gsc.IMPLEMENTS_TECHNIQUE_COMPLETE_QUERIES) == {"Malware", "Tool"}
    for label, statement in gsc.IMPLEMENTS_TECHNIQUE_COMPLETE_QUERIES.items():
        assert statement.startswith(f"MATCH (n:{label}) ") and " OR " not in statement.split("UNWIND")[0]


def test_in_tactic_statement_matches_tactics_as_step_1(writer_steps):
    outer, inner = _step(writer_steps, "MERGE (t)-[r:IN_TACTIC]->(tc)")
    assert outer == "MATCH (t:Technique) WHERE size(coalesce(t.tactic_phases, [])) > 0 RETURN t"
    assert "tc.shortname IS NOT NULL" in inner
    assert 'coalesce(tc.attack_domain, "enterprise") = coalesce(t.attack_domain, "enterprise")' in inner
    assert "toLower(phase) = toLower(tc.shortname)" in inner

    statement = gsc.IN_TACTIC_COMPLETE_QUERY
    assert f"[p IN {as_list('t.tactic_phases')} WHERE p IS NOT NULL | toLower(p)] AS phases" in statement
    assert "tc.shortname IS NOT NULL AND toLower(tc.shortname) IN phases" in statement
    assert "coalesce(tc.attack_domain, 'enterprise') = coalesce(t.attack_domain, 'enterprise')" in statement
    assert "NOT EXISTS { (t)-[:IN_TACTIC]->(tc) }" in statement


def test_sector_statement_follows_steps_7a_to_7d():
    import build_relationships as br

    links: Dict[str, str] = {}
    for statements in (br._Q7A_STATEMENTS, br._Q7B_STATEMENTS, br._Q7C_STATEMENTS, br._Q7D_STATEMENTS):
        var = statements.outer.rsplit("RETURN ", 1)[1].strip()
        rel_type = re.search(rf"MERGE \({var}\)-\[r:(\w+)\]->\(sec\)", statements.inner).group(1)
        for label in re.findall(rf"\b{var}:(\w+)", statements.outer):
            links[label] = rel_type
        # the writer's zone rule, with the zones of config.VALID_ZONES
        assert zone_prov_with(var, br._SECTOR_IN_LIST) in statements.inner
    assert links == gsc.SECTOR_LINK_TYPES
    assert set(re.findall(r'"(\w+)"', br._SECTOR_IN_LIST)) - {"global"} == set(gsc.SECTOR_ZONES)

    statement = gsc.SECTOR_LINKS_COMPLETE_QUERY
    assert zone_prov_with("n", "$sector_zones") in statement
    assert gsc.sector_params() == {"sector_zones": list(gsc.SECTOR_ZONES)}
    for label, rel_type in gsc.SECTOR_LINK_TYPES.items():
        assert f"WHEN n:{label} THEN '{rel_type}'" in statement


def test_cve_coverage_reads_list_or_scalar_status_and_source():
    statement = gsc.CVE_CVSS_COVERAGE_QUERY
    assert f"'nvd' IN {as_list('c.source')}" in statement
    assert f"NOT 'rejected' IN [x IN {as_list('c.status')} | toLower(toString(x))]" in statement
    assert "c.edgeguard_managed = true" in statement


# Rows the statements returned on the iMac 730-day graph of 1 Nov 2026 (read-only, 2 Nov 2026).
_IN_TACTIC = {"techniques": 824, "with_phases": 824, "claims_with_target": 1024, "edge_missing": 0, "tactic_missing": 0}
_EMPLOYS = {
    "claims": 4854,
    "claiming_actors": 177,
    "target_missing": 0,
    "claims_with_target": 4854,
    "edge_missing": 0,
    "mitre_nodes": 189,
}
_USES = {
    "claims": 1587886,
    "claiming_indicators": 130419,
    "target_missing": 21207,
    "claims_with_target": 1566679,
    "edge_missing": 0,
}


@pytest.mark.parametrize(
    "row, verdict",
    [
        (_IN_TACTIC, True),
        (dict(_IN_TACTIC, edge_missing=1024), False),
        (dict(_IN_TACTIC, claims_with_target=0, tactic_missing=824), False),
        # the ICS tactics lost: the 106 ICS techniques reach no tactic, the 899 Enterprise phases are linked
        (dict(_IN_TACTIC, claims_with_target=899, tactic_missing=106), False),
        # a row without its defect counts fails
        ({"techniques": 824, "with_phases": 824, "claims_with_target": 1024}, False),
        # the CLI graph of 31 Oct 2026: techniques without their kill-chain phases
        ({"techniques": 718, "with_phases": 0, "claims_with_target": 0, "edge_missing": 0, "tactic_missing": 0}, False),
        ({"techniques": 0, "with_phases": 0, "claims_with_target": 0, "edge_missing": 0, "tactic_missing": 0}, None),
    ],
)
def test_in_tactic_verdict(row, verdict):
    assert gsc.in_tactic_verdict(row) is verdict


@pytest.mark.parametrize(
    "row, verdict",
    [
        (_EMPLOYS, True),
        (_USES, True),  # claims without their Technique are no defect
        (dict(_EMPLOYS, edge_missing=4854), False),
        (dict(_EMPLOYS, claims=0, claiming_actors=0, claims_with_target=0, mitre_nodes=187), False),  # the CLI graph
        (dict(_EMPLOYS, claims=0, claiming_actors=0, claims_with_target=0, mitre_nodes=0), None),
        (
            {"claims": 0, "claiming_indicators": 0, "target_missing": 0, "claims_with_target": 0, "edge_missing": 0},
            None,
        ),
        # claims none of which reaches a Technique (the Technique nodes gone): no link judged
        (dict(_EMPLOYS, target_missing=4854, claims_with_target=0), None),
        (dict(_USES, target_missing=1587886, claims_with_target=0), None),
        (dict(_USES, target_missing=1587885, claims_with_target=1), True),
        ({"claims": 12}, False),  # a missing count of missing links fails
        ({"claims": 12, "target_missing": 0, "edge_missing": 0}, False),  # and a missing count of judged claims
    ],
)
def test_technique_claims_verdict(row, verdict):
    assert gsc.technique_claims_verdict(row) is verdict


@pytest.mark.parametrize(
    "verdicts, combined",
    [((True, True), True), ((True, None), True), ((None, None), None), ((True, False), False), ((None, False), False)],
)
def test_combined_verdict(verdicts, combined):
    assert gsc.combined_verdict(verdicts) is combined


@pytest.mark.parametrize(
    "row, verdict",
    [
        ({"zoned_nodes": 61538, "node_sectors": 78262, "sector_link_missing": 0}, True),
        ({"zoned_nodes": 61538, "node_sectors": 78262, "sector_link_missing": 78262}, False),
        ({"zoned_nodes": 0, "node_sectors": 0, "sector_link_missing": 0}, None),
        ({"zoned_nodes": 5, "node_sectors": 5}, False),
    ],
)
def test_sector_links_verdict(row, verdict):
    assert gsc.sector_links_verdict(row) is verdict


@pytest.mark.parametrize(
    "judged, scored, verdict",
    [(146858, 142236, True), (5228, 4439, True), (100, 50, True), (100, 49, False), (152359, 0, False), (99, 0, None)],
)
def test_cvss_coverage_verdict(judged, scored, verdict):
    row = {"nvd_cves_not_rejected": judged, "nvd_cves_with_cvss": scored}
    assert gsc.cvss_coverage_verdict(row) is verdict
    assert gsc.CVE_CVSS_COVERAGE_MIN_CVES == 100 and gsc.CVE_CVSS_COVERAGE_MIN_SHARE == 0.5


def test_family_statement_judges_the_links_step_9_writes(writer_steps):
    """Step 9 MERGEs ``INDICATES`` to the nodes ``$family_targets`` names for the stored label and stamps
    ``malware_family`` on every write; the statement looks the same label up in the same map and looks for that
    label on the link."""
    outer, inner = _step(writer_steps, "UNWIND coalesce($family_targets[i.malware_family], []) AS mname")
    assert outer.startswith("MATCH (i:Indicator) WHERE i.malware_family IS NOT NULL ")
    assert (
        "MATCH (m:Malware {name: mname}) MERGE (i)-[r:INDICATES]->(m) ON CREATE SET r.created_at = datetime() SET "
        in inner
    )
    assert 'r.match_type = "malware_family"' in inner.split("ON CREATE SET r.created_at = datetime() SET ", 1)[1]

    statement = gsc.FAMILY_INDICATES_COMPLETE_QUERY
    assert statement.startswith("MATCH (i:Indicator) WHERE i.malware_family IN keys($family_targets) ")
    assert "UNWIND $family_targets[family] AS name MATCH (m:Malware {name: name})" in statement
    assert "EXISTS { (i)-[r:INDICATES]->(m) WHERE r.match_type = 'malware_family' } AS linked" in statement
    # grouped by label: one lookup of the nodes per label, not a scan of the Malware nodes per indicator
    assert statement.index("WITH i.malware_family AS family, collect(i) AS indicators") < statement.index(
        "MATCH (m:Malware"
    )


@pytest.mark.parametrize(
    "row, verdict",
    [
        ({"claims_with_target": 13900, "edge_missing": 0}, True),
        ({"claims_with_target": 13900, "edge_missing": 695}, False),
        ({"claims_with_target": 0, "edge_missing": 0}, None),
        ({"claims_with_target": 13900}, False),
        ({"claims_with_target": 0, "edge_missing": 3}, False),
    ],
)
def test_family_indicates_verdict(row, verdict):
    assert gsc.family_indicates_verdict(row) is verdict


@pytest.mark.parametrize(
    "delivered, sourced_from, verdict",
    [
        # the 730-day baseline of 2026-11-01: ThreatFox (lowest share), OTX, NVD
        (10000, 9774, True),
        (150857, 150615, True),
        (151186, 151186, True),
        (10000, 9000, True),
        (10000, 8999, False),
        (150857, 0, False),
        (0, 0, None),
        (0, 150615, None),
    ],
)
def test_source_delivery_verdict(delivered, sourced_from, verdict):
    assert gsc.source_delivery_verdict(delivered, sourced_from) is verdict
    assert gsc.SOURCE_DELIVERY_MIN_SHARE == 0.9


def test_the_source_statement_counts_the_edges_into_each_source_by_its_key():
    assert gsc.SOURCE_SOURCED_FROM_QUERY == (
        "MATCH (s:Source) RETURN s.source_id AS source_id, COUNT { (s)<-[:SOURCED_FROM]-() } AS sourced_from "
        "ORDER BY source_id"
    )
