"""The secondary sector labels of a node (``:Finance``, ``:Healthcare``, ``:Energy``) (2026-11-02).

A node whose ``zone`` list names a sector also carries that sector, capitalised, as a label, so that
``MATCH (c:Campaign:Finance)`` finds what ``WHERE 'finance' IN c.zone`` finds. ``global`` gives no label.
Two writers keep the labels in step with the zones:

* ``Neo4jClient.apply_sector_labels`` adds the labels of every node of ``SECTOR_LABELLED_NODE_LABELS`` at
  the end of each MISP -> Neo4j sync. The sync only ever adds zones to a node, so it only adds labels.
* ``build_campaign_nodes`` recomputes a campaign's zones from its active indicators on every run, after
  the sync, so it sets the campaign's labels itself (``CAMPAIGN_SECTOR_LABELS_CYPHER``): it adds the labels
  of the campaign's zones and, on a campaign EdgeGuard created, removes the sector labels its zones no
  longer give. Before 2026-11-02 a campaign got its labels only from the next sync, so after a fresh
  baseline no campaign carried one.

The acceptance script reads ``SECTOR_LABELS_CHECK_QUERY``. Standard library and the stdlib-only
``relationship_provenance`` at import.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple

from relationship_provenance import as_list

# The node labels ``apply_sector_labels`` labels by zone.
SECTOR_LABELLED_NODE_LABELS: Tuple[str, ...] = (
    "Indicator",
    "Vulnerability",
    "Malware",
    "ThreatActor",
    "Technique",
    "Tactic",
    "Campaign",
    "Tool",
    "Source",
    "CVE",
)

# The labels of the sector zones (``config.VALID_ZONES`` without ``global``, capitalised).
SECTOR_LABELS: Tuple[str, ...] = ("Energy", "Finance", "Healthcare")


def wanted_labels(node_var: str) -> str:
    """Cypher: the sector labels the node's zones give, named as ``apply_sector_labels`` names them
    (``apoc.text.capitalize``: the first letter upper-cased). A zone stored as a string reads as a
    one-entry list."""
    return (
        f"[z IN {as_list(node_var + '.zone')} WHERE z IS NOT NULL AND z <> '' AND z <> 'global' "
        "| toUpper(left(z, 1)) + substring(z, 1)]"
    )


# Sets the sector labels of every campaign to its zones: adds the missing ones; on a campaign EdgeGuard
# created (its zones are the builder's alone) also removes the ones its zones no longer give. A partner's
# campaign keeps the labels it has. Returns the campaigns changed and the labels added and removed.
CAMPAIGN_SECTOR_LABELS_CYPHER = f"""
MATCH (c:Campaign)
WITH c, {wanted_labels("c")} AS wanted
WITH c,
     [l IN wanted WHERE NOT l IN labels(c)] AS missing,
     CASE WHEN c.edgeguard_managed = true
          THEN [l IN $sector_labels WHERE l IN labels(c) AND NOT l IN wanted]
          ELSE [] END AS stale
WHERE size(missing) > 0 OR size(stale) > 0
CALL apoc.create.removeLabels(c, stale) YIELD node AS kept
CALL apoc.create.addLabels(kept, missing) YIELD node
RETURN count(node) AS campaigns, sum(size(missing)) AS added, sum(size(stale)) AS removed
"""

# Acceptance (check 10n): every EdgeGuard node of the labelled kinds carries the sector labels of its zones
# and no sector label its zones do not give. Returns the nodes checked, the nodes with a missing or a
# stray label, and up to ten examples per node label.
SECTOR_LABELS_CHECK_QUERY = f"""
MATCH (n)
WHERE n.edgeguard_managed = true
  AND any(l IN labels(n) WHERE l IN $node_labels)
  AND (n.zone IS NOT NULL OR any(l IN labels(n) WHERE l IN $sector_labels))
WITH n, {wanted_labels("n")} AS wanted
WITH n, [l IN wanted WHERE NOT l IN labels(n)] AS missing,
     [l IN $sector_labels WHERE l IN labels(n) AND NOT l IN wanted] AS stray
WITH count(n) AS nodes,
     sum(CASE WHEN size(missing) > 0 THEN 1 ELSE 0 END) AS missing_label,
     sum(CASE WHEN size(stray) > 0 THEN 1 ELSE 0 END) AS stray_label,
     collect(CASE WHEN size(missing) > 0 OR size(stray) > 0
                  THEN {{label: [l IN labels(n) WHERE l IN $node_labels][0], missing: missing, stray: stray}}
             END) AS defects
RETURN nodes, missing_label, stray_label, defects[0..10] AS examples
"""


def check_params() -> dict:
    """The parameters of ``SECTOR_LABELS_CHECK_QUERY``."""
    return {"node_labels": list(SECTOR_LABELLED_NODE_LABELS), "sector_labels": list(SECTOR_LABELS)}


def check_verdict(row: Mapping[str, Any]) -> Optional[bool]:
    """The verdict of check 10n on the row ``SECTOR_LABELS_CHECK_QUERY`` returns: informational (None)
    without a checked node, else passed when no node misses a label and none carries a stray one."""
    if not row.get("nodes"):
        return None
    return row.get("missing_label") == 0 and row.get("stray_label") == 0
