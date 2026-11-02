"""Completeness of the graph's shape: the links the baseline writers must build from what the nodes claim.

``build_relationships`` derives links from properties the collectors store on the nodes: a technique's
kill-chain phases (``tactic_phases``, step 1 ``IN_TACTIC``), the techniques MITRE says a group or a piece of
software uses (``uses_techniques``, steps 5, 6 and 10, ``EMPLOYS_TECHNIQUE`` / ``IMPLEMENTS_TECHNIQUE`` with
``match_type = 'mitre_explicit'``), the ATT&CK ids of an OTX report on its indicators (``attack_ids``, step 8
``USES_TECHNIQUE``) and a node's sector zones (``zone``, steps 7a-7d ``TARGETS`` / ``AFFECTS`` to a ``Sector``).
A step that matches nothing still reports success, so a graph that lost a whole family of links looks like
a complete one until somebody counts. Each statement here judges a family against the claims stored on the
nodes, as the writer reads them:

* a claim whose target node exists and has no link is a defect (``edge_missing``);
* a claim whose target node does not exist is counted apart (``target_missing``): a limited collection or a
  revoked id the map does not translate leaves such claims, and the writer skips them too. The others
  (``claims_with_target``) are the claims judged: without one, nothing is judged;
* the nodes that must carry the claims are counted (``mitre_nodes``): MITRE actors or software without a
  single claim mean the claims were lost between the collector and the node.

The CVE score coverage (``CVE_CVSS_COVERAGE_QUERY``) is the share of NVD's non-rejected CVEs that have a
CVSS sub-node (``HAS_CVSS_*``): a run whose CVSS writes failed scores no CVE, and every consistency check of
the scores still passes on it.

The acceptance script (``scripts/verify_fresh_baseline.py``) runs these statements and reports their
verdicts. Standard library and the stdlib-only ``relationship_provenance`` at import, like the other modules
that script reads. The statements take no parameter but ``$revoked`` (the revoked-id map, the same the
writers read: ``attack_revoked.technique_successors``) and ``$sector_zones`` (``SECTOR_ZONES``).
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple

from relationship_provenance import as_list, zone_prov_with

# The relationship types of a CVE's CVSS sub-nodes (``cvss_selection.CVSS_VERSIONS``; pinned by a test).
CVSS_REL_TYPES: Tuple[str, ...] = ("HAS_CVSS_v2", "HAS_CVSS_v30", "HAS_CVSS_v31", "HAS_CVSS_v40")
# The CVE score coverage is judged on at least this many non-rejected NVD CVEs and passes from this share.
CVE_CVSS_COVERAGE_MIN_CVES = 100
CVE_CVSS_COVERAGE_MIN_SHARE = 0.5

# The sector zones a node can be linked by (``config.VALID_ZONES`` without ``global``; pinned by a test).
SECTOR_ZONES: Tuple[str, ...] = ("energy", "finance", "healthcare")
# Steps 7a-7d: the relationship type from each label that links to a Sector (pinned against the steps).
SECTOR_LINK_TYPES: Dict[str, str] = {
    "Indicator": "TARGETS",
    "CVE": "AFFECTS",
    "Vulnerability": "AFFECTS",
    "ThreatActor": "TARGETS",
    "Malware": "TARGETS",
}

# Steps 5, 6, 10 and 8: (node label, claims property, relationship type to the Technique, the match_type the
# step stamps on every link it writes or ``None`` when the step keeps the label of an existing link).
TECHNIQUE_CLAIM_LINKS: Tuple[Tuple[str, str, str, Optional[str]], ...] = (
    ("ThreatActor", "uses_techniques", "EMPLOYS_TECHNIQUE", "mitre_explicit"),
    ("Malware", "uses_techniques", "IMPLEMENTS_TECHNIQUE", "mitre_explicit"),
    ("Tool", "uses_techniques", "IMPLEMENTS_TECHNIQUE", "mitre_explicit"),
    ("Indicator", "attack_ids", "USES_TECHNIQUE", None),
)
# The column naming the nodes that carry claims, one per statement (distinct, so a reader can tell the rows apart).
_CLAIMANTS = {
    "ThreatActor": "claiming_actors",
    "Malware": "claiming_malware",
    "Tool": "claiming_tools",
    "Indicator": "claiming_indicators",
}

# Step 1: every kill-chain phase of a technique whose Tactic exists in the technique's ATT&CK domain (by
# ``shortname``, case-insensitive) has its IN_TACTIC. ``tactic_missing`` counts the techniques with phases
# and no such Tactic at all (the tactics are lost: a limited collection keeps every tactic).
IN_TACTIC_COMPLETE_QUERY = (
    "MATCH (t:Technique) "
    f"WITH t, [p IN {as_list('t.tactic_phases')} WHERE p IS NOT NULL | toLower(p)] AS phases "
    "OPTIONAL MATCH (tc:Tactic) WHERE tc.shortname IS NOT NULL AND toLower(tc.shortname) IN phases "
    "AND coalesce(tc.attack_domain, 'enterprise') = coalesce(t.attack_domain, 'enterprise') "
    "WITH t, phases, tc, tc IS NOT NULL AND NOT EXISTS { (t)-[:IN_TACTIC]->(tc) } AS unlinked "
    "WITH t, phases, count(tc) AS tactics, sum(CASE WHEN unlinked THEN 1 ELSE 0 END) AS unlinked_tactics "
    "RETURN count(t) AS techniques, sum(CASE WHEN size(phases) > 0 THEN 1 ELSE 0 END) AS with_phases, "
    "sum(tactics) AS claims_with_target, sum(unlinked_tactics) AS edge_missing, "
    "sum(CASE WHEN size(phases) > 0 AND tactics = 0 THEN 1 ELSE 0 END) AS tactic_missing, "
    "collect(CASE WHEN unlinked_tactics > 0 OR (size(phases) > 0 AND tactics = 0) THEN t.mitre_id END)[..10] "
    "AS examples"
)


def _technique_claims_query(label: str, claims: str, rel_type: str, match_type: Optional[str]) -> str:
    """Cypher: the claims ``claims`` of the ``label`` nodes, each translated through ``$revoked`` as the writer
    translates it, how many reach an existing Technique (``claims_with_target``) and how many of those lack
    their ``rel_type`` link (of ``match_type``, when given). With a ``match_type`` the statement also counts the
    MITRE nodes of the label (``mitre_nodes``), which must carry the claims."""
    edge = f"(n)-[r:{rel_type}]->(t)" + (f" WHERE r.match_type = '{match_type}'" if match_type else "")
    mitre_nodes = (
        f", COUNT {{ MATCH (x:{label}) WHERE 'mitre_attck' IN {as_list('x.source')} }} AS mitre_nodes"
        if match_type
        else ""
    )
    return (
        f"MATCH (n:{label}) WHERE size(coalesce(n.{claims}, [])) > 0 "
        f"UNWIND {as_list('n.' + claims)} AS cited "
        "WITH n, coalesce($revoked[toString(cited)], cited) AS tid "
        "OPTIONAL MATCH (t:Technique {mitre_id: tid}) "
        f"WITH n, tid, t, t IS NOT NULL AND NOT EXISTS {{ {edge} }} AS unlinked "
        f"WITH count(*) AS claims, count(DISTINCT n) AS {_CLAIMANTS[label]}, "
        "sum(CASE WHEN t IS NULL THEN 1 ELSE 0 END) AS target_missing, "
        "sum(CASE WHEN unlinked THEN 1 ELSE 0 END) AS edge_missing, "
        "collect(CASE WHEN unlinked THEN toString(coalesce(n.name, n.value, '?')) + ' -> ' + toString(tid) END)[..10] "
        "AS examples "
        f"RETURN claims, {_CLAIMANTS[label]}, target_missing, claims - target_missing AS claims_with_target, "
        "edge_missing, examples" + mitre_nodes
    )


# One statement per label: one over Malware and Tool together took 54 s on the 730-day graph, these 0.3 s.
TECHNIQUE_CLAIMS_QUERIES: Dict[Tuple[str, str], str] = {
    (label, rel_type): _technique_claims_query(label, claims, rel_type, match_type)
    for label, claims, rel_type, match_type in TECHNIQUE_CLAIM_LINKS
}
EMPLOYS_TECHNIQUE_COMPLETE_QUERY = TECHNIQUE_CLAIMS_QUERIES[("ThreatActor", "EMPLOYS_TECHNIQUE")]
IMPLEMENTS_TECHNIQUE_COMPLETE_QUERIES: Dict[str, str] = {
    label: TECHNIQUE_CLAIMS_QUERIES[(label, "IMPLEMENTS_TECHNIQUE")] for label in ("Malware", "Tool")
}
USES_TECHNIQUE_COMPLETE_QUERY = TECHNIQUE_CLAIMS_QUERIES[("Indicator", "USES_TECHNIQUE")]

_SECTOR_LINKED = " OR ".join(f"n:{label}" for label in SECTOR_LINK_TYPES)
_SECTOR_LINK_TYPE = "CASE " + " ".join(f"WHEN n:{label} THEN '{t}'" for label, t in SECTOR_LINK_TYPES.items()) + " END"
_SECTOR_LINKED_LABEL = "head([l IN labels(n) WHERE l IN [" + ", ".join(f"'{x}'" for x in SECTOR_LINK_TYPES) + "]])"

# Steps 7a-7d: every sector of a node's ``zone`` that one of its feeds gave (the writers' own rule,
# ``relationship_provenance.zone_prov_with``; a sector no feed gave is not linked, and check 10j reports it)
# has its link to the Sector: TARGETS from an Indicator, ThreatActor or Malware, AFFECTS from a CVE or a
# Vulnerability. ``global`` is never linked.
SECTOR_LINKS_COMPLETE_QUERY = (
    f"MATCH (n) WHERE ({_SECTOR_LINKED}) AND n.zone IS NOT NULL "
    + zone_prov_with("n", "$sector_zones")
    + f"WITH n, zone_name, {_SECTOR_LINK_TYPE} AS link_type "
    "WITH n, zone_name, EXISTS { MATCH (n)-[r]->(:Sector {name: zone_name}) WHERE type(r) = link_type } AS linked "
    "RETURN count(DISTINCT n) AS zoned_nodes, count(*) AS node_sectors, "
    "sum(CASE WHEN linked THEN 0 ELSE 1 END) AS sector_link_missing, "
    f"collect(CASE WHEN NOT linked THEN {_SECTOR_LINKED_LABEL} + ' ' "
    "+ toString(coalesce(n.name, n.value, n.cve_id, '?')) + ' -> ' + zone_name END)[..10] AS examples"
)

# The share of the EdgeGuard CVEs NVD delivered, not REJECTED, that have a CVSS sub-node. ``status`` and
# ``source`` are lists (a scalar reads as a one-entry list); CVEs only another feed delivered (CISA KEV, CISA
# ICS, OTX) are left out, and so are REJECTED records, which carry no score.
CVE_CVSS_COVERAGE_QUERY = (
    f"MATCH (c:CVE) WHERE c.edgeguard_managed = true AND 'nvd' IN {as_list('c.source')} "
    f"AND NOT 'rejected' IN [x IN {as_list('c.status')} | toLower(toString(x))] "
    "RETURN count(c) AS nvd_cves_not_rejected, "
    "sum(CASE WHEN EXISTS { (c)-[:" + "|".join(CVSS_REL_TYPES) + "]->() } THEN 1 ELSE 0 END) AS nvd_cves_with_cvss"
)


def technique_params(successors: Mapping[str, str]) -> Dict[str, Any]:
    """The parameters of the technique statements: the revoked-id map (``{}`` when it cannot be read, so a
    revoked id counts as a missing target, never as a missing link)."""
    return {"revoked": dict(successors)}


def sector_params() -> Dict[str, Any]:
    """The parameters of ``SECTOR_LINKS_COMPLETE_QUERY``."""
    return {"sector_zones": list(SECTOR_ZONES)}


def in_tactic_verdict(row: Mapping[str, Any]) -> Optional[bool]:
    """Informational without a Technique. Else passes when no phase whose Tactic exists lacks its link, no
    technique with phases reaches no Tactic, and some phase reaches one (techniques without any phase fail)."""
    if not row.get("techniques"):
        return None
    return row.get("edge_missing") == 0 and row.get("tactic_missing") == 0 and (row.get("claims_with_target") or 0) > 0


def technique_claims_verdict(row: Mapping[str, Any]) -> Optional[bool]:
    """Without a claim: fails when MITRE nodes of the label exist (``mitre_nodes``: their claims were lost),
    else informational. With claims of which none reaches an existing Technique (``claims_with_target`` 0: a
    limited collection, or no Technique node, which ``mangled_attack_entries_present`` fails): informational,
    no link is judged. Else passes when no claim whose Technique exists lacks its link (a missing count
    fails)."""
    if not row.get("claims"):
        return False if row.get("mitre_nodes") else None
    if row.get("claims_with_target") == 0:
        return None
    return row.get("edge_missing") == 0 and (row.get("claims_with_target") or 0) > 0


def combined_verdict(verdicts: Tuple[Optional[bool], ...]) -> Optional[bool]:
    """One verdict of several statements: fails when one fails, informational when none judged."""
    if any(v is False for v in verdicts):
        return False
    return True if any(v is True for v in verdicts) else None


def sector_links_verdict(row: Mapping[str, Any]) -> Optional[bool]:
    """Informational without a node sector a feed gave; else passes when every one has its link."""
    if not row.get("node_sectors"):
        return None
    return row.get("sector_link_missing") == 0


def cvss_coverage_verdict(row: Mapping[str, Any]) -> Optional[bool]:
    """Informational under ``CVE_CVSS_COVERAGE_MIN_CVES`` non-rejected NVD CVEs; else passes when at least
    ``CVE_CVSS_COVERAGE_MIN_SHARE`` of them have a CVSS sub-node."""
    judged = row.get("nvd_cves_not_rejected") or 0
    if judged < CVE_CVSS_COVERAGE_MIN_CVES:
        return None
    return (row.get("nvd_cves_with_cvss") or 0) / judged >= CVE_CVSS_COVERAGE_MIN_SHARE
