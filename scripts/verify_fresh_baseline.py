"""
Read-only acceptance check for a fresh EdgeGuard baseline (2026-10 PR).

Runs over the Neo4j **HTTP Query API v2** (same env vars as
``scripts/run_cypher_catalog_http.py``) so it works wherever plain HTTPS reaches
the database, including a Cloudflare-proxied endpoint that only speaks
Bolt-over-WebSocket. Nothing is written.

What it verifies (see docs/BASELINE_LAUNCH_CHECKLIST.md § "Fresh-baseline
acceptance"): the whole-event co-occurrence edges are gone, every technique edge
labelled ``mitre_explicit`` really comes from a MITRE-sourced node, the ResilMesh
CVE list properties are on the ``CVE`` node (judged on CVEs NVD has had time to
analyse — see check 4), the ATT&CK entries that the MISP
import rule used to mangle are present, OTX actor names are clean, ``tlp`` and the
``edgeguard_managed`` marker are on every EdgeGuard node and edge, ICS techniques
link only to ICS tactics, and the ResilMesh-facing schema is unchanged. Since the
relationship-provenance, campaign-membership and CVE-score changes of 2026-10 it also
checks that every relationship type carries the provenance properties its writers
guarantee and none of the dropped ``source_id`` / ``source_ids`` / ``report_ids``,
that campaign membership is ``PART_OF_CAMPAIGN`` (``PART_OF`` stays ResilMesh's), that a
CVE's ``cvss_score`` / ``cvss_version`` / ``severity`` come from its CVSS sub-nodes, and
it reports the ``SOURCED_FROM`` count of every ``Source`` node, warning when a source
collected by default delivered nothing. Since the revoked-object change of 2026-10 it fails
when a Technique node carries an ATT&CK id the revoked-id map lists
(``src/reference/attack_revoked_ids.json``), or a ThreatActor, Malware or Tool node from MITRE
is a revoked group or piece of software, and warns when another source's actor still carries a
revoked group's name.

Env:
  NEO4J_HTTP_URL   base URL (default: https://neo4j.edgeguard.org)
  NEO4J_DATABASE   database name (default: neo4j)
  NEO4J_USER       basic-auth user (default: neo4j)
  NEO4J_PASSWORD   basic-auth password

Usage:
  set -a; source .env.edgeguard; set +a
  python scripts/verify_fresh_baseline.py                 # human-readable
  python scripts/verify_fresh_baseline.py --json          # machine-readable
  python scripts/verify_fresh_baseline.py --require-ics --require-cisa-ics
  python scripts/verify_fresh_baseline.py --require-malwarebazaar   # after enabling that source

Exit code 0 = every mandatory check passed; 1 = at least one failed; 2 = could
not reach Neo4j. A warning (``[WARN]``; ``ok: false`` with ``mandatory: false`` in the
JSON) is reported and leaves the exit code unchanged.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Standard library only (no driver, no config): the revoked ATT&CK ids of check 9b.
from attack_revoked import load_revoked_ids  # noqa: E402
from canonical_threat_actors import (  # noqa: E402
    OTX_REPORT_REF_PREFIX,
    REPORT_ACTORS_QUERY,
    REPORT_ATTRIBUTION_FEEDS,
    ReferenceUnavailable,
    attribution_reports_cypher,
    load_canonical_reference,
    reports_naming_several_actors,
)

# NEO4J_HTTP is the name docker-compose.yml / .env.example use for the same endpoint.
BASE = (os.getenv("NEO4J_HTTP_URL") or os.getenv("NEO4J_HTTP") or "https://neo4j.edgeguard.org").rstrip("/")
DB = os.getenv("NEO4J_DATABASE", "neo4j")
USER = os.getenv("NEO4J_USER", "neo4j")
PWD = os.getenv("NEO4J_PASSWORD", "")
URL = f"{BASE}/db/{DB}/query/v2"
_AUTH = "Basic " + base64.b64encode(f"{USER}:{PWD}".encode()).decode()
# Cloudflare in front of the hosted Neo4j rejects urllib's default agent (HTTP 403); same
# workaround as scripts/run_cypher_catalog_http.py.
_UA = os.getenv(
    "NEO4J_HTTP_USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
)

# Labels and relationship types EdgeGuard writes. Anything else on a shared
# database belongs to ResilMesh and is reported, never failed on.
EDGEGUARD_LABELS = (
    "Indicator",
    "CVE",
    "Vulnerability",
    "CVSSv2",
    "CVSSv30",
    "CVSSv31",
    "CVSSv40",
    "Malware",
    "ThreatActor",
    "Technique",
    "Tactic",
    "Tool",
    "Campaign",
    "Source",
    "Sector",
    # Alert nodes are created by EdgeGuard's alert processor (NATS); none exist on a baseline.
    "Alert",
)
EDGEGUARD_REL_TYPES = (
    "SOURCED_FROM",
    "EMPLOYS_TECHNIQUE",
    "IMPLEMENTS_TECHNIQUE",
    "USES_TECHNIQUE",
    "ATTRIBUTED_TO",
    "INDICATES",
    "EXPLOITS",
    "TARGETS",
    "AFFECTS",
    "IN_TACTIC",
    "SUBTECHNIQUE_OF",
    "USES_MALWARE",
    "USES_TOOL",
    "RUNS",
    "PART_OF_CAMPAIGN",  # 2026-10: was PART_OF, ResilMesh's name for its asset hierarchy
    # PART_OF (IP → Subnet, OrganizationUnit hierarchy) is ResilMesh's; EdgeGuard writes it only
    # for the asset model on alert ingestion, so none exist on a baseline.
    "PART_OF",
    "REFERS_TO",
    "HAS_CVSS_v2",
    "HAS_CVSS_v30",
    "HAS_CVSS_v31",
    "HAS_CVSS_v40",
    # INVOLVES (Alert → Indicator) is written by EdgeGuard's alert processor and carries the
    # marker since 2026-10; none exist on a baseline, so the checks below are vacuous until
    # alerts flow.
    "INVOLVES",
)
# Relationships built from the sources, which must say who asserts them (2026-10 relationship
# provenance: ``r.sources`` / ``r.source_refs`` / ``r.misp_event_ids``). Not SOURCED_FROM (the
# per-source node edge, ``r.source``), not INVOLVES (alert edges carry no source claim) and not
# PART_OF (ResilMesh's asset hierarchy).
PROVENANCE_REL_TYPES = tuple(t for t in EDGEGUARD_REL_TYPES if t not in ("SOURCED_FROM", "INVOLVES", "PART_OF"))
# What each relationship type is guaranteed to carry, by the writers of the baseline DAG (2026-10
# relationship provenance; a test derives the same table from the writers' Cypher). A list may be
# empty — ``misp_event_ids`` of a link whose records name no MISP event, ``source_refs`` of a feed
# keyed by the value itself — so the contract is presence; ``relationships_name_their_source``
# additionally requires ``sources`` to be non-empty.
_PROVENANCE_LISTS = ("sources", "source_refs", "misp_event_ids")
# ``enrichment_jobs``: the Vulnerability ↔ CVE bridge (REFERS_TO) takes the vulnerability record's
# lists and states no evidence label. The campaign links (RUNS, PART_OF_CAMPAIGN) inherit the lists
# of the links they are built from and, since 2026-10-15, state their evidence
# (``campaign_grouping``), so they are held to the full contract below.
_INHERITED_REL_TYPES = ("REFERS_TO",)
# ``Neo4jClient._merge_cvss_node``: the feed and the MISP event of the score; no record id (the CVE
# is the record) and no evidence label.
_CVSS_REL_TYPES = ("HAS_CVSS_v2", "HAS_CVSS_v30", "HAS_CVSS_v31", "HAS_CVSS_v40")
REL_PROVENANCE_CONTRACT: Dict[str, Tuple[str, ...]] = {
    # Every other provenance type is written by ``build_relationships``
    # (``relationship_provenance.prov_set``) and/or the sync (``create_misp_relationships_batch``),
    # both of which also state the evidence (``match_type``).
    **{
        t: _PROVENANCE_LISTS + ("match_type",)
        for t in PROVENANCE_REL_TYPES
        if t not in _INHERITED_REL_TYPES + _CVSS_REL_TYPES
    },
    **{t: _PROVENANCE_LISTS for t in _INHERITED_REL_TYPES},
    **{t: ("sources", "misp_event_ids") for t in _CVSS_REL_TYPES},
    # The per-source edge of a node: the source id (``source``, a string), the source's record ids
    # and the MISP events that carried the node.
    "SOURCED_FROM": ("source", "source_refs", "misp_event_ids"),
}
# One pass over the relationships, one row per type, for checks 12b and 12c: how many edges
# EdgeGuard manages, how many of those carry each contract property (``source`` only as a string,
# the scalar it must stay), how many have an empty ``misp_event_ids``, and how many edges carry a
# key dropped in 2026-10 (``source_id``, ``source_ids``, ``report_ids``).
_REL_PROVENANCE_SCAN = (
    "MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS edges, "
    "sum(CASE WHEN r.edgeguard_managed = true THEN 1 ELSE 0 END) AS managed, "
    "sum(CASE WHEN r.edgeguard_managed = true AND r.sources IS NOT NULL THEN 1 ELSE 0 END) AS with_sources, "
    "sum(CASE WHEN r.edgeguard_managed = true AND r.source_refs IS NOT NULL THEN 1 ELSE 0 END) AS with_source_refs, "
    "sum(CASE WHEN r.edgeguard_managed = true AND r.misp_event_ids IS NOT NULL THEN 1 ELSE 0 END) "
    "AS with_misp_event_ids, "
    "sum(CASE WHEN r.edgeguard_managed = true AND r.match_type IS NOT NULL THEN 1 ELSE 0 END) AS with_match_type, "
    "sum(CASE WHEN r.edgeguard_managed = true AND r.source IS NOT NULL "
    "THEN CASE apoc.meta.cypher.type(r.source) WHEN 'STRING' THEN 1 ELSE 0 END ELSE 0 END) AS with_source, "
    "sum(CASE WHEN r.edgeguard_managed = true AND r.misp_event_ids = [] THEN 1 ELSE 0 END) AS empty_misp_event_ids, "
    "sum(CASE WHEN r.source_id IS NOT NULL OR r.source_ids IS NOT NULL OR r.report_ids IS NOT NULL "
    "THEN 1 ELSE 0 END) AS legacy_keys "
    "ORDER BY type"
)
# Labels parsed from MISP attributes — the only nodes that carry ``tlp`` (the tag travels
# with the attribute). Source/Sector/Campaign/CVSS* and the ResilMesh-model nodes written
# on alert ingestion (Host, IP, Alert, …) are marker-stamped when EdgeGuard creates them but
# never have a TLP, so the check is an allowlist, not a skip-list.
_TLP_LABELS = ("Indicator", "CVE", "Vulnerability", "Malware", "ThreatActor", "Technique", "Tactic", "Tool")
# ATT&CK entries whose names contain ": Windows " — the MISP Import Regexp rule
# rewrote them to ``%WINDIR%\`` before the 2026-10 fix, so they vanished.
_MANGLED_TECHNIQUES = ("T1047", "T1021.006", "T1543.003", "T1222.001", "T1546.003")
_MANGLED_TOOLS_HINT = (
    "requires the MISP Import Regexp fix (docs/BASELINE_LAUNCH_CHECKLIST.md § [7], step 1) before the re-feed"
)
# NVD analysis lag: reference tags + CPE configurations appear weeks after publication.
_NVD_ANALYSIS_LAG_DAYS = 45
_MIN_ANALYSED_CVES = 100
_MANGLED_TOOLS = ("S0005",)
# CVE score (2026-10): a CVE takes ``cvss_score`` / ``cvss_version`` / ``severity`` from the first of
# its CVSS sub-nodes, in this order, whose ``base_score`` is a number in [0, 10]; without one the
# score and version are null and the severity is UNKNOWN (``cvss_selection.CVSS_VERSIONS``,
# ``Neo4jClient._cve_cvss_selection_cypher``; both pinned by a test).
_CVSS_SELECTION_ORDER = (
    ("HAS_CVSS_v31", "CVSSv31", "3.1"),
    ("HAS_CVSS_v30", "CVSSv30", "3.0"),
    ("HAS_CVSS_v2", "CVSSv2", "2.0"),
    ("HAS_CVSS_v40", "CVSSv40", "4.0"),
)
_CVSS_RATINGS = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_CVE_BEST_CVSS = (
    "head([p IN ["
    + ", ".join(
        f"[head([(c)-[:{rel}]->(x:{label}) WHERE x.base_score >= 0.0 AND x.base_score <= 10.0 | x]), '{version}']"
        for rel, label, version in _CVSS_SELECTION_ORDER
    )
    + "] WHERE p[0] IS NOT NULL]) AS best"
)
# Per-source presence (2026-10): the canonical ``Source.source_id`` of every collector, by how a
# default deployment runs it (``src/source_registry.py``, the collector flags in ``src/config.py``,
# the keys in ``src/source_key_check.py``; pinned by a test). Collected by default, without a key
# or a flag (NVD also answers without a key, at a lower rate):
DEFAULT_SOURCES = ("cisa_kev", "mitre_attck", "nvd", "urlhaus", "feodo_tracker", "ssl_blacklist")
# Skipped by design without an API key; this script cannot see which keys the deployment holds.
KEYED_SOURCES = ("alienvault_otx", "virustotal", "threatfox", "abuseipdb")
# Off unless EDGEGUARD_ENABLE_CISA_ICS / EDGEGUARD_ENABLE_MALWAREBAZAAR is set; judged by
# --require-cisa-ics / --require-malwarebazaar.
FLAG_GUARDED_SOURCES = ("cisa_ics", "malwarebazaar")


def _post(statement: str, params: Optional[Dict[str, Any]] = None, timeout: int = 180) -> List[Dict[str, Any]]:
    body = json.dumps({"statement": statement, "parameters": params or {}, "accessMode": "Read"}).encode()
    req = urllib.request.Request(URL, data=body, method="POST")
    req.add_header("Authorization", _AUTH)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", _UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode())
    if payload.get("errors"):
        raise RuntimeError(payload["errors"])
    data = payload["data"]
    return [dict(zip(data["fields"], row, strict=True)) for row in data["values"]]


class Report:
    def __init__(self) -> None:
        self.checks: List[Dict[str, Any]] = []

    def add(self, name: str, ok: Optional[bool], detail: Any, mandatory: bool = True) -> None:
        """``ok=None`` means informational (no pass/fail); ``ok=False`` on a check that is not
        mandatory is a warning: reported, the exit code unchanged."""
        self.checks.append({"check": name, "ok": ok, "mandatory": mandatory, "detail": detail})

    @property
    def failed(self) -> List[Dict[str, Any]]:
        return [c for c in self.checks if c["mandatory"] and c["ok"] is False]

    @property
    def warnings(self) -> List[Dict[str, Any]]:
        return [c for c in self.checks if not c["mandatory"] and c["ok"] is False]


def _one(statement: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    rows = _post(statement, params)
    return rows[0] if rows else {}


def run_checks(require_ics: bool, require_cisa_ics: bool, require_malwarebazaar: bool = False) -> Report:
    rep = Report()

    # 0. Inventory for the record.
    stats = _one(
        "CALL apoc.meta.stats() YIELD nodeCount, relCount, labels, relTypesCount RETURN nodeCount, relCount, labels, relTypesCount"
    )
    rep.add("inventory", None, stats)

    # 1. No whole-event co-occurrence edges.
    r = _one(
        "MATCH ()-[r]->() WHERE r.source_id = 'misp_cooccurrence' OR r.match_type = 'misp_cooccurrence' "
        "OR any(s IN coalesce(r.source_ids, []) WHERE s = 'misp_cooccurrence') RETURN count(r) AS c"
    )
    rep.add("no_cooccurrence_edges", r.get("c") == 0, r)

    # 2. ``mitre_explicit`` only from MITRE-sourced nodes.
    r = _one(
        "MATCH (n)-[r {match_type: 'mitre_explicit'}]->(:Technique) "
        "WHERE NOT 'mitre_attck' IN coalesce(n.source, []) RETURN count(r) AS c"
    )
    rep.add("mitre_explicit_only_from_mitre_nodes", r.get("c") == 0, r)

    # 3. Attribution edges state their evidence; fan-out is plausible.
    r = _one("MATCH (:Malware)-[r:ATTRIBUTED_TO]->(:ThreatActor) WHERE r.match_type IS NULL RETURN count(r) AS c")
    rep.add("attributed_to_has_match_type", r.get("c") == 0, r)
    r = _one(
        "MATCH (m:Malware) WITH m, COUNT { (m)-[:ATTRIBUTED_TO]->() } AS d WHERE d > 0 "
        "RETURN count(*) AS malware_with_attribution, percentileCont(d, 0.5) AS median_actors, max(d) AS max_actors"
    )
    median = r.get("median_actors")
    rep.add("attributed_to_fanout_plausible", (median is None) or (median <= 10), r)
    breakdown = _post(
        "MATCH ()-[r:ATTRIBUTED_TO|INDICATES|EMPLOYS_TECHNIQUE|IMPLEMENTS_TECHNIQUE|EXPLOITS]->() "
        "RETURN type(r) AS rel, r.match_type AS match_type, count(*) AS c ORDER BY rel, c DESC"
    )
    rep.add("evidence_labels_breakdown", None, breakdown)

    # 4. ResilMesh CVE list properties on the node (NVD-sourced CVEs only).
    #
    # Scope: CVEs published at least _NVD_ANALYSIS_LAG_DAYS ago. NVD analysts assign the
    # reference tags (``ref_tags``) and the CPE configurations (``cpe_type``) during
    # analysis, which lags publication by weeks; day-old CVEs carry neither. Measured on
    # the hosted graph on 2026-10-10: the 730-day baseline event had ref_tags/cpe_type on
    # 57 % of its NVD CVEs, every daily event of the last two weeks had them on 0 %. Without
    # the scope a short smoke baseline (7–30 days) fails this check with nothing wrong.
    # Below _MIN_ANALYSED_CVES analysed CVEs the check is informational.
    r = _one(
        "MATCH (c:CVE) WHERE 'nvd' IN coalesce(c.source, []) AND c.published IS NOT NULL "
        "AND datetime(c.published) < datetime() - duration({days: $lag}) RETURN count(c) AS n, "
        "sum(CASE WHEN c.cwe IS NOT NULL THEN 1 ELSE 0 END) AS cwe, "
        "sum(CASE WHEN c.ref_tags IS NOT NULL THEN 1 ELSE 0 END) AS ref_tags, "
        "sum(CASE WHEN c.cpe_type IS NOT NULL THEN 1 ELSE 0 END) AS cpe_type, "
        "sum(CASE WHEN c.result_impacts IS NOT NULL THEN 1 ELSE 0 END) AS result_impacts",
        {"lag": _NVD_ANALYSIS_LAG_DAYS},
    )
    n = r.get("n") or 0
    r["scope"] = f"NVD CVEs published > {_NVD_ANALYSIS_LAG_DAYS} days ago"
    if n < _MIN_ANALYSED_CVES:
        r["note"] = f"only {n} analysed CVEs (< {_MIN_ANALYSED_CVES}) — informational; rerun on a longer baseline"
        rep.add("cve_resilmesh_properties_present", None, r)
    else:
        ok = (
            (r["cwe"] / n) >= 0.5
            and (r["result_impacts"] / n) >= 0.5
            and (r["ref_tags"] / n) >= 0.2
            and (r["cpe_type"] / n) >= 0.2
        )
        rep.add("cve_resilmesh_properties_present", ok, r)

    # 5. Previously mangled ATT&CK entries are present.
    rows = _post(
        "UNWIND $ids AS id OPTIONAL MATCH (t:Technique {mitre_id: id}) RETURN id, t IS NOT NULL AS present",
        {"ids": list(_MANGLED_TECHNIQUES)},
    )
    tools = _post(
        "UNWIND $ids AS id OPTIONAL MATCH (t:Tool {mitre_id: id}) RETURN id, t IS NOT NULL AS present",
        {"ids": list(_MANGLED_TOOLS)},
    )
    present = all(x["present"] for x in rows + tools)
    rep.add(
        "mangled_attack_entries_present",
        present,
        {"entries": rows + tools, **({} if present else {"hint": _MANGLED_TOOLS_HINT})},
    )

    # 6. Actor names are clean.
    r = _one(
        "MATCH (a:ThreatActor) WHERE a.name CONTAINS ',' OR a.name CONTAINS ' and ' OR a.name CONTAINS ' & ' "
        "RETURN count(a) AS c, collect(a.name)[..10] AS examples"
    )
    rep.add("no_composite_actor_names", r.get("c") == 0, r)

    # 7. TLP on every node parsed from a MISP attribute. Since 2026-10 the sync gives a MISP
    #    attribute without a ``tlp:`` tag the level ``EDGEGUARD_DEFAULT_TLP`` and logs
    #    ``[TLP] MISP attribute <uuid> has no tlp: tag``, so a lost tag no longer fails this check:
    #    it shows in the sync log. The check still fails for a node of these labels that a writer
    #    left without ``tlp``.
    r = _one(
        "MATCH (n) WHERE n.edgeguard_managed = true AND any(l IN labels(n) WHERE l IN $labels) "
        "RETURN count(n) AS total, sum(CASE WHEN n.tlp IS NULL THEN 1 ELSE 0 END) AS missing",
        {"labels": list(_TLP_LABELS)},
    )
    r["note"] = (
        "a MISP attribute without a tlp: tag syncs with EDGEGUARD_DEFAULT_TLP; lost tags show in the sync log "
        "as '[TLP] MISP attribute <uuid> has no tlp: tag'"
    )
    rep.add("tlp_on_every_node", (r.get("total") or 0) > 0 and r.get("missing") == 0, r)

    # 8. Ownership marker on every EdgeGuard node and edge. 2026-10: ``edgeguard_managed`` is
    #    stamped only on nodes EdgeGuard created; a node a partner created first that EdgeGuard
    #    wrote to carries ``edgeguard_enriched`` instead, so neither marker on an EdgeGuard label
    #    means EdgeGuard never wrote to it (or a writer omitted the marker).
    nodes = _post(
        "MATCH (n) WHERE n.edgeguard_managed IS NULL AND n.edgeguard_enriched IS NULL "
        "UNWIND labels(n) AS l RETURN l AS label, count(*) AS c ORDER BY c DESC"
    )
    eg_nodes_missing = [x for x in nodes if x["label"] in EDGEGUARD_LABELS]
    rep.add("ownership_marker_on_nodes", not eg_nodes_missing, {"missing_by_label": nodes})
    edges = _post(
        "MATCH ()-[r]->() WHERE r.edgeguard_managed IS NULL RETURN type(r) AS type, count(*) AS c ORDER BY c DESC"
    )
    eg_edges_missing = [x for x in edges if x["type"] in EDGEGUARD_REL_TYPES]
    rep.add("ownership_marker_on_edges", not eg_edges_missing, {"missing_by_type": edges})

    # 9. ATT&CK for ICS: domain-consistent tactic links (always); presence (opt-in).
    r = _one(
        "MATCH (t:Technique)-[:IN_TACTIC]->(tc:Tactic) "
        "WHERE coalesce(t.attack_domain, 'enterprise') <> coalesce(tc.attack_domain, 'enterprise') RETURN count(*) AS c"
    )
    rep.add("in_tactic_same_domain", r.get("c") == 0, r)
    r = _one("MATCH (t:Technique {attack_domain: 'ics'}) RETURN count(t) AS c")
    rep.add("ics_techniques_present", (r.get("c") or 0) > 0 if require_ics else None, r, mandatory=require_ics)

    # 9b. Revoked ATT&CK objects (2026-10). The MITRE collector skips objects ATT&CK revoked, and a
    #     revoked technique id a feed names is translated to its successor, so no Technique node
    #     carries an id the revoked-id map lists, and no ThreatActor node from MITRE is a revoked
    #     group (judged by name: ATT&CK actors are keyed by name). A node another source named after
    #     a revoked group (an OTX pulse naming UNC2452) is a warning: the actor alias merge
    #     (enrichment) folds it into the successor, whose aliases carry the revoked group's name.
    #     The same holds for software: no Malware or Tool node from MITRE carries a revoked
    #     software's name. Informational when the graph has no Technique / no MITRE actor / no MITRE
    #     software; a map that cannot be read fails the checks (nothing to judge by).
    revoked = load_revoked_ids()
    if not revoked.loaded:
        detail = {"map": revoked.path, "problem": revoked.problem}
        rep.add("no_revoked_attack_techniques", False, detail)
        rep.add("no_revoked_attack_groups", False, detail)
        rep.add("no_revoked_attack_software", False, detail)
        rep.add("translated_links_record_cited_ids", False, detail)
    else:
        r = _one(
            "MATCH (t:Technique) WITH t, t.mitre_id IN $ids AS is_revoked "
            "RETURN count(t) AS techniques, sum(CASE WHEN is_revoked THEN 1 ELSE 0 END) AS revoked_ids, "
            "collect(CASE WHEN is_revoked THEN t.mitre_id END)[..10] AS examples",
            {"ids": sorted(revoked.techniques)},
        )
        r["map_version"] = revoked.version
        rep.add(
            "no_revoked_attack_techniques",
            None if not r.get("techniques") else r.get("revoked_ids") == 0,
            r,
        )
        r = _one(
            "MATCH (a:ThreatActor) WITH a, 'mitre_attck' IN coalesce(a.source, []) AS from_mitre, "
            "toLower(trim(a.name)) IN $names AS is_revoked "
            "RETURN sum(CASE WHEN from_mitre THEN 1 ELSE 0 END) AS mitre_actors, "
            "sum(CASE WHEN is_revoked AND from_mitre THEN 1 ELSE 0 END) AS revoked_groups_from_mitre, "
            "sum(CASE WHEN is_revoked AND NOT from_mitre THEN 1 ELSE 0 END) AS revoked_names_other_sources, "
            "collect(CASE WHEN is_revoked AND from_mitre THEN a.name END)[..10] AS examples_from_mitre, "
            "collect(CASE WHEN is_revoked AND NOT from_mitre THEN a.name END)[..10] AS examples_other_sources",
            {"names": sorted({n.strip().lower() for n in revoked.group_names()})},
        )
        r["map_version"] = revoked.version
        mitre_actors = r.get("mitre_actors") or 0
        rep.add("no_revoked_attack_groups", None if not mitre_actors else r.get("revoked_groups_from_mitre") == 0, r)
        rep.add(
            "revoked_group_names_folded",
            None if not mitre_actors else r.get("revoked_names_other_sources") == 0,
            {
                **r,
                "hint": "an actor another source named after a revoked ATT&CK group is folded into the "
                "successor by the actor alias merge (enrichment); see its [ACTOR-ALIAS-MERGE] log lines",
            },
            mandatory=False,
        )
        r = _one(
            "MATCH (n) WHERE (n:Malware OR n:Tool) AND 'mitre_attck' IN coalesce(n.source, []) "
            "WITH n, toLower(trim(n.name)) IN $names AS is_revoked "
            "RETURN count(n) AS mitre_software, sum(CASE WHEN is_revoked THEN 1 ELSE 0 END) AS revoked_software, "
            "collect(CASE WHEN is_revoked THEN n.name END)[..10] AS examples",
            {"names": sorted({n.strip().lower() for n in revoked.software_names()})},
        )
        r["map_version"] = revoked.version
        rep.add(
            "no_revoked_attack_software",
            None if not r.get("mitre_software") else r.get("revoked_software") == 0,
            r,
        )
        # Explainability (2026-10): a link a revoked id led to records the id the source cited
        # (``r.cited_ids``). Judged on the OTX indicator path, which carries most of these links:
        # every link to the successor of a revoked id in ``attack_ids`` names that id.
        r = _one(
            "MATCH (i:Indicator) WHERE size(coalesce(i.attack_ids, [])) > 0 "
            "UNWIND i.attack_ids AS cited "
            "WITH i, cited, $revoked[toString(cited)] AS successor WHERE successor IS NOT NULL "
            "OPTIONAL MATCH (i)-[r:USES_TECHNIQUE]->(:Technique {mitre_id: successor}) "
            "RETURN count(*) AS cited_revoked_ids, count(r) AS linked, "
            "sum(CASE WHEN r IS NOT NULL AND cited IN coalesce(r.cited_ids, []) THEN 1 ELSE 0 END) AS recorded",
            {"revoked": dict(revoked.techniques)},
        )
        r["map_version"] = revoked.version
        rep.add(
            "translated_links_record_cited_ids",
            None if not r.get("linked") else r.get("recorded") == r.get("linked"),
            r,
        )
    # Actors the alias merge folded others into (``n.merged_from``): reported, not judged.
    r = _one(
        "MATCH (a:ThreatActor) WHERE a.merged_from IS NOT NULL "
        "RETURN count(a) AS actors, sum(size(a.merged_from)) AS names_folded"
    )
    rep.add("actor_merges_recorded", None, r, mandatory=False)

    # 10. CISA ICS advisories (opt-in).
    r = _one(
        "OPTIONAL MATCH (s:Source {source_id: 'cisa_ics'}) RETURN s IS NOT NULL AS present, COUNT { (s)<-[:SOURCED_FROM]-() } AS edges"
    )
    rep.add(
        "cisa_ics_source_present",
        (bool(r.get("present")) and (r.get("edges") or 0) > 0) if require_cisa_ics else None,
        r,
        mandatory=require_cisa_ics,
    )

    # 10c. MalwareBazaar (opt-in, 2026-10): the Source node exists and at least one sha256 hash
    #      indicator is sourced from it. The sync stores every file hash as ``indicator_type = 'hash'``
    #      (``run_misp_to_neo4j.TYPE_MAPPING``), so a sha256 is recognised by its 64 hex characters.
    r = _one(
        "OPTIONAL MATCH (s:Source {source_id: 'malwarebazaar'}) "
        "RETURN s IS NOT NULL AS present, COUNT { (s)<-[:SOURCED_FROM]-(:Indicator) } AS indicators, "
        "COUNT { (s)<-[:SOURCED_FROM]-(i:Indicator) WHERE i.indicator_type = 'hash' "
        "AND toLower(i.value) =~ '[0-9a-f]{64}' } AS sha256_indicators"
    )
    rep.add(
        "malwarebazaar_source_present",
        (bool(r.get("present")) and (r.get("sha256_indicators") or 0) > 0) if require_malwarebazaar else None,
        r,
        mandatory=require_malwarebazaar,
    )

    # 10a. Sub-technique hierarchy complete (2026-10 R6): every dotted-id technique whose parent
    #      exists links to it with SUBTECHNIQUE_OF.
    r = _one(
        "MATCH (s:Technique) WHERE s.mitre_id CONTAINS '.' "
        "WITH s, split(s.mitre_id, '.')[0] AS pid "
        "OPTIONAL MATCH (p:Technique {mitre_id: pid}) "
        "RETURN count(s) AS subs, sum(CASE WHEN p IS NULL THEN 1 ELSE 0 END) AS parent_missing, "
        "sum(CASE WHEN p IS NOT NULL AND NOT EXISTS { (s)-[:SUBTECHNIQUE_OF]->(p) } THEN 1 ELSE 0 END) AS edge_missing"
    )
    rep.add("subtechnique_of_complete", (r.get("subs") or 0) > 0 and r.get("edge_missing") == 0, r)

    # 10a2. Group → software (2026-10 R6): every MITRE ``uses_malware`` / ``uses_tools`` claim whose
    #       target node exists has its USES_MALWARE / USES_TOOL edge. Informational until the
    #       MITRE collector of this build has run (no claims on the node yet).
    r = _one(
        "MATCH (a:ThreatActor) WHERE size(coalesce(a.uses_malware, [])) > 0 UNWIND a.uses_malware AS mn "
        "OPTIONAL MATCH (m:Malware {name: toLower(trim(mn))}) "
        "WITH a, mn, collect(m) AS ms "
        "RETURN count(*) AS claims, sum(CASE WHEN size(ms) = 0 THEN 1 ELSE 0 END) AS target_missing, "
        "sum(CASE WHEN size(ms) > 0 AND none(m IN ms WHERE EXISTS { (a)-[:USES_MALWARE]->(m) }) THEN 1 ELSE 0 END) AS edge_missing"
    )
    # 2026-10 audit: once a MITRE actor exists the claims MUST exist too — zero claims then means the
    # `m` / `s` lists were lost between collector and node, exactly what this check is for.
    mitre_actors = (
        _one("MATCH (a:ThreatActor) WHERE 'mitre_attck' IN coalesce(a.source, []) RETURN count(a) AS c").get("c") or 0
    )

    def _uses_ok(row: Dict[str, Any]) -> Optional[bool]:
        if mitre_actors == 0:
            return None
        return (row.get("claims") or 0) > 0 and row.get("edge_missing") == 0

    r["mitre_actors"] = mitre_actors
    rep.add("uses_malware_complete", _uses_ok(r), r)
    r = _one(
        "MATCH (a:ThreatActor) WHERE size(coalesce(a.uses_tools, [])) > 0 UNWIND a.uses_tools AS tid "
        "OPTIONAL MATCH (t:Tool {mitre_id: tid}) "
        "WITH a, tid, collect(t) AS ts "
        "RETURN count(*) AS claims, sum(CASE WHEN size(ts) = 0 THEN 1 ELSE 0 END) AS target_missing, "
        "sum(CASE WHEN size(ts) > 0 AND none(t IN ts WHERE EXISTS { (a)-[:USES_TOOL]->(t) }) THEN 1 ELSE 0 END) AS edge_missing"
    )
    r["mitre_actors"] = mitre_actors
    rep.add("uses_tool_complete", _uses_ok(r), r)

    # 10a4. Pulse-scoped INDICATES (2026-10, regular-update linking): every family a pulse named on an
    #       indicator, whose Malware node exists, has its INDICATES edge (Q9b). Informational only
    #       while no indicator carries pulse families (pre-change data).
    r = _one(
        "MATCH (i:Indicator) WHERE size(coalesce(i.pulse_malware_families, [])) > 0 "
        "UNWIND i.pulse_malware_families AS fam WITH i, toLower(trim(fam)) AS f "
        "OPTIONAL MATCH (m:Malware {name: f}) WITH i, f, collect(m) AS ms "
        "RETURN count(*) AS claims, sum(CASE WHEN size(ms) = 0 THEN 1 ELSE 0 END) AS target_missing, "
        "sum(CASE WHEN size(ms) > 0 AND none(m IN ms WHERE EXISTS { (i)-[:INDICATES]->(m) }) THEN 1 ELSE 0 END) AS edge_missing"
    )
    rep.add("pulse_indicates_complete", None if (r.get("claims") or 0) == 0 else r.get("edge_missing") == 0, r)

    # 10a3. `global` is the "no sector" marker: no TARGETS / AFFECTS edge may point at it (2026-10 audit:
    #       the old graph carried ~270k such edges at confidence 1.0).
    r = _one("MATCH ()-[r:TARGETS|AFFECTS]->(g:Sector {name: 'global'}) RETURN count(r) AS c")
    rep.add("no_global_sector_edges", r.get("c") == 0, r)

    # 10b. Sector coverage (informational; the "measure" input for demo day): how many nodes of
    #      each EdgeGuard label are linked to each Sector. 2026-10 sector-focus build adds
    #      ThreatActor / Malware → Sector TARGETS (Q7c / Q7d).
    cov = _post(
        "MATCH (n)-[r:TARGETS|AFFECTS]->(s:Sector) WHERE s.name <> 'global' "
        "RETURN s.name AS sector, labels(n)[0] AS label, count(DISTINCT n) AS nodes ORDER BY sector, label"
    )
    rep.add("sector_coverage", None, cov)

    # 11. ResilMesh-facing schema unchanged.
    types = [x["t"] for x in _post("CALL db.relationshipTypes() YIELD relationshipType AS t RETURN t")]
    unexpected = sorted(t for t in types if t not in EDGEGUARD_REL_TYPES)
    rep.add("relationship_types", None, {"present": sorted(types), "not_written_by_edgeguard": unexpected})
    cvss = _post(
        "UNWIND ['CVSSv30', 'CVSSv31', 'CVSSv40'] AS label "
        "CALL { WITH label MATCH (s) WHERE label IN labels(s) "
        "  WITH s, label, COUNT { (s)<-[]-(:CVE) } AS inc, COUNT { (s)-[]->(:CVE) } AS out "
        "  RETURN count(s) AS total, sum(CASE WHEN inc = 1 AND out = 1 THEN 1 ELSE 0 END) AS bidirectional } "
        "RETURN label, total, bidirectional"
    )
    rep.add("cvss_bidirectional", all(x["total"] == x["bidirectional"] for x in cvss), cvss)

    # 12. Relationship provenance (2026-10): every relationship built from the sources names
    #     them, and the provenance lists are lists. A list stored as a plain string (APOC's
    #     ``combine`` does that for equal values in the actor alias merge) breaks ``IN`` and
    #     ``size()`` for every consumer.
    unsourced = _post(
        "MATCH ()-[r]->() WHERE type(r) IN $types AND r.edgeguard_managed = true "
        "AND size(coalesce(r.sources, [])) = 0 "
        "RETURN type(r) AS type, count(*) AS c ORDER BY c DESC",
        {"types": list(PROVENANCE_REL_TYPES)},
    )
    rep.add("relationships_name_their_source", not unsourced, {"without_sources_by_type": unsourced})
    scalar_edges = _one(
        "MATCH ()-[r]->() WHERE "
        "(r.sources IS NOT NULL AND NOT apoc.meta.cypher.type(r.sources) STARTS WITH 'LIST') "
        "OR (r.source_refs IS NOT NULL AND NOT apoc.meta.cypher.type(r.source_refs) STARTS WITH 'LIST') "
        "OR (r.misp_event_ids IS NOT NULL AND NOT apoc.meta.cypher.type(r.misp_event_ids) STARTS WITH 'LIST') "
        "RETURN count(r) AS edges"
    )
    scalar_nodes = _one(
        "MATCH (n) WHERE "
        "(n.zone IS NOT NULL AND NOT apoc.meta.cypher.type(n.zone) STARTS WITH 'LIST') "
        "OR (n.source IS NOT NULL AND NOT apoc.meta.cypher.type(n.source) STARTS WITH 'LIST') "
        "RETURN count(n) AS nodes"
    )
    scalars = {"edges": scalar_edges.get("edges"), "nodes": scalar_nodes.get("nodes")}
    rep.add("provenance_lists_are_lists", scalars["edges"] == 0 and scalars["nodes"] == 0, scalars)
    by_source = _post(
        "MATCH ()-[r]->() WHERE r.sources IS NOT NULL AND type(r) <> 'SOURCED_FROM' "
        "UNWIND r.sources AS s RETURN type(r) AS type, s AS source, count(*) AS c ORDER BY type, c DESC"
    )
    rep.add("relationship_sources_breakdown", None, by_source)

    # 12b. Provenance per relationship type (2026-10): every EdgeGuard edge carries what
    #      ``REL_PROVENANCE_CONTRACT`` says the writers of its type guarantee. One pass over the
    #      relationships, one row per relationship type; a type outside the contract (ResilMesh's,
    #      INVOLVES, PART_OF) is not judged. Presence is judged, not content: an empty
    #      ``misp_event_ids`` list is legitimate (a same-pulse ATTRIBUTED_TO whose malware and actor
    #      records share no MISP event, a campaign link built on such links) and only counted.
    rel_rows = _post(_REL_PROVENANCE_SCAN)
    missing = [
        {"type": x["type"], "property": p, "edges": (x.get("managed") or 0) - (x.get(f"with_{p}") or 0)}
        for x in rel_rows
        for p in REL_PROVENANCE_CONTRACT.get(x["type"], ())
        if (x.get(f"with_{p}") or 0) < (x.get("managed") or 0)
    ]
    checked = sum(x.get("managed") or 0 for x in rel_rows if x["type"] in REL_PROVENANCE_CONTRACT)
    rep.add(
        "relationship_provenance_complete",
        None if checked == 0 else not missing,
        {
            "missing_by_type": missing,
            "edges_checked": checked,
            "empty_misp_event_ids_by_type": [
                {"type": x["type"], "edges": x["empty_misp_event_ids"]}
                for x in rel_rows
                if x.get("empty_misp_event_ids")
            ],
        },
    )

    # 12c. The relationship keys dropped in 2026-10 stay dropped: no ``source_id`` (last writer
    #      wins), ``source_ids`` (evidence names) or ``report_ids`` (OTX only) on a relationship of
    #      an EdgeGuard type; other types are reported, never failed on. ``Source`` nodes keep
    #      ``source_id``: it is their key, and every ``SOURCED_FROM`` write matches on it.
    source_rows = _post(
        "MATCH (s:Source) RETURN s.source_id AS source_id, COUNT { (s)<-[:SOURCED_FROM]-() } AS sourced_from "
        "ORDER BY source_id"
    )
    legacy = [{"type": x["type"], "edges": x["legacy_keys"]} for x in rel_rows if x.get("legacy_keys")]
    keyless = sum(1 for x in source_rows if x.get("source_id") is None)
    rep.add(
        "no_legacy_relationship_properties",
        not [x for x in legacy if x["type"] in EDGEGUARD_REL_TYPES] and keyless == 0,
        {"legacy_keys_by_type": legacy, "source_nodes_without_source_id": keyless, "source_nodes": len(source_rows)},
    )

    # 13. Campaign membership (2026-10): Malware / Indicator -[:PART_OF_CAMPAIGN]-> Campaign.
    #     ``PART_OF`` is ResilMesh's (IP → Subnet, the OrganizationUnit hierarchy); EdgeGuard used
    #     it for campaign membership until 2026-10, so none may end at a Campaign.
    r = _one(
        "RETURN COUNT { ()-[:PART_OF]->(:Campaign) } AS part_of_to_campaign, "
        "COUNT { (n)-[:PART_OF_CAMPAIGN]->(c) WHERE NOT c:Campaign OR NOT (n:Malware OR n:Indicator) } "
        "AS part_of_campaign_misplaced, "
        "COUNT { ()-[:PART_OF_CAMPAIGN]->() } AS part_of_campaign, COUNT { ()-[:PART_OF]->() } AS part_of"
    )
    rep.add(
        "campaign_membership_is_part_of_campaign",
        r.get("part_of_to_campaign") == 0 and r.get("part_of_campaign_misplaced") == 0,
        r,
    )

    # 13b. Attribution from a source report (2026-10): an OTX pulse that names several actors (the
    #      aliases of one actor count as one, canonical reference) attributes no malware, so no
    #      same-pulse attribution rests only on such pulses, unless another feed asserts it too, and
    #      none names one in its provenance (build_relationships step 2d removes and trims them).
    #      Informational without the reference: the aliases of one actor cannot be told apart.
    try:
        actor_reference = load_canonical_reference()
    except ReferenceUnavailable as exc:
        actor_reference = None
        reference_error = str(exc)
    report_actors = _one(REPORT_ACTORS_QUERY)
    several = reports_naming_several_actors(report_actors.get("reports") or [], actor_reference)
    r = _one(
        "MATCH (:Malware)-[r:ATTRIBUTED_TO]->(:ThreatActor) "
        "WHERE r.match_type = 'otx_pulse' AND r.edgeguard_managed = true "
        "WITH r, " + attribution_reports_cypher("r") + " AS reports "
        "RETURN count(r) AS links, "
        "sum(CASE WHEN size(reports) > 0 AND all(p IN reports WHERE p IN $several) "
        "AND all(s IN coalesce(r.sources, []) WHERE s IN $feeds) THEN 1 ELSE 0 END) AS resting_on_several_actor_reports, "
        "sum(CASE WHEN any(p IN reports WHERE p IN $several) THEN 1 ELSE 0 END) AS naming_several_actor_reports, "
        "sum(CASE WHEN size(reports) = 0 THEN 1 ELSE 0 END) AS without_reports",
        {"several": several, "otx_ref_prefix": OTX_REPORT_REF_PREFIX, "feeds": list(REPORT_ATTRIBUTION_FEEDS)},
    )
    r["reports_naming_several_actors"] = len(several)
    r["pulses_recorded_on_actors"] = report_actors.get("pulses") or 0
    if actor_reference is None:
        r["reference"] = f"unavailable ({reference_error})"
        attribution_ok = None
    elif not r["pulses_recorded_on_actors"]:
        # No actor records a pulse: there is nothing to judge, and a pass would be vacuous.
        r["reference"] = actor_reference.version
        attribution_ok = None
    else:
        r["reference"] = actor_reference.version
        attribution_ok = not r.get("resting_on_several_actor_reports") and not r.get("naming_several_actor_reports")
    rep.add("attribution_from_single_actor_reports", attribution_ok, r)

    # 13c. Campaign membership follows attribution (2026-10): a malware is part of a campaign only
    #      while it is attributed to the campaign's actor (build_campaign_nodes step 2b prunes the rest).
    r = _one(
        "MATCH (m:Malware)-[r:PART_OF_CAMPAIGN]->(c:Campaign) "
        "RETURN count(r) AS malware_links, "
        "sum(CASE WHEN NOT EXISTS { (m)-[:ATTRIBUTED_TO]->(:ThreatActor {name: c.actor_name}) } "
        "THEN 1 ELSE 0 END) AS unattributed"
    )
    rep.add("campaign_malware_attributed", None if not r.get("malware_links") else r.get("unattributed") == 0, r)

    # 14. CVE scores (2026-10): a CVE takes ``cvss_score`` / ``cvss_version`` / ``severity`` from
    #     its CVSS sub-nodes (``_CVSS_SELECTION_ORDER``): with a valid sub-node, the score and
    #     version are that sub-node's and the severity a CVSS rating; without one, score and
    #     version are null and the severity is UNKNOWN (before 2026-10 an unscored CVE read 3.0 /
    #     LOW, and the record merged last set the score). EdgeGuard-created CVEs only;
    #     informational while there is no CVE (the per-source check below names the silent source).
    r = _one(
        f"MATCH (c:CVE) WHERE c.edgeguard_managed = true WITH c, {_CVE_BEST_CVSS} "
        "RETURN count(c) AS cves, sum(CASE WHEN best IS NULL THEN 0 ELSE 1 END) AS with_cvss, "
        "sum(CASE WHEN best IS NOT NULL AND (c.cvss_score IS NULL OR c.cvss_version IS NULL) "
        "THEN 1 ELSE 0 END) AS scored_without_score, "
        "sum(CASE WHEN best IS NOT NULL AND c.cvss_score IS NOT NULL AND c.cvss_version IS NOT NULL "
        "AND (c.cvss_score <> best[0].base_score OR c.cvss_version <> best[1] "
        "OR NOT coalesce(c.severity, '') IN $ratings) THEN 1 ELSE 0 END) AS score_not_from_cvss, "
        "sum(CASE WHEN best IS NULL AND (c.cvss_score IS NOT NULL OR c.cvss_version IS NOT NULL "
        "OR coalesce(c.severity, '') <> 'UNKNOWN') THEN 1 ELSE 0 END) AS unscored_with_score",
        {"ratings": list(_CVSS_RATINGS)},
    )
    defects = ("scored_without_score", "score_not_from_cvss", "unscored_with_score")
    rep.add("cve_score_from_cvss", None if not r.get("cves") else all(r.get(k) == 0 for k in defects), r)

    # 14b. FIRST EPSS and CISA's SSVC on CVE nodes (2026-10). EPSS comes from the enrichment job, which
    #      skips an unavailable feed without failing the run: CVE nodes without any EPSS are a warning.
    #      One score date is expected; more mean a run stopped before clearing, or a short feed that was
    #      not used to clear. SSVC comes with NVD's records, for the CVEs CISA has decided on; reported.
    r = _one(
        "MATCH (c:CVE) RETURN count(c) AS cves, count(c.epss_score) AS with_epss, "
        "count(DISTINCT c.epss_score_date) AS epss_score_dates, max(c.epss_score_date) AS latest_epss_score_date, "
        "sum(CASE WHEN c.ssvc_exploitation IS NOT NULL OR c.ssvc_automatable IS NOT NULL "
        "OR c.ssvc_technical_impact IS NOT NULL THEN 1 ELSE 0 END) AS with_ssvc, "
        "sum(CASE WHEN c.ssvc_exploitation = 'active' THEN 1 ELSE 0 END) AS ssvc_exploitation_active"
    )
    epss_ok = None if not r.get("cves") else (r.get("with_epss") or 0) > 0
    if epss_ok is False:
        r["hint"] = (
            "no CVE node has EPSS: EDGEGUARD_ENABLE_EPSS is false or the feed was unavailable; "
            "the enrichment task log has an [EPSS] line"
        )
    rep.add("cve_epss_and_ssvc", epss_ok, r, mandatory=False)

    # 15. Per-source presence (2026-10): the ``SOURCED_FROM`` count of every ``Source`` node (the
    #     rows of 12c; alias nodes such as ``otx`` or ``cisa`` are listed too). A source collected by
    #     default that delivered nothing is a warning, not a failure: an upstream outage skips its
    #     collector without failing the run, and the collector's task log says why. A keyed source
    #     is skipped by design without its API key, a flag-guarded one without its flag (judged by
    #     ``--require-cisa-ics`` / ``--require-malwarebazaar``); both are only listed.
    delivered = {x.get("source_id"): x.get("sourced_from") or 0 for x in source_rows}
    silent = [s for s in DEFAULT_SOURCES if not delivered.get(s)]
    rep.add(
        "default_sources_delivered",
        not silent,
        {
            "default_sources_without_data": silent,
            "keyed_sources_without_data": [s for s in KEYED_SOURCES if not delivered.get(s)],
            "flag_guarded_sources_without_data": [s for s in FLAG_GUARDED_SOURCES if not delivered.get(s)],
            "sourced_from_by_source": source_rows,
        },
        mandatory=False,
    )
    return rep


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    ap.add_argument("--require-ics", action="store_true", help="fail if no ATT&CK for ICS techniques are present")
    ap.add_argument("--require-cisa-ics", action="store_true", help="fail if the cisa_ics source has no data")
    ap.add_argument(
        "--require-malwarebazaar",
        action="store_true",
        help="fail if the malwarebazaar source has no sha256 indicator",
    )
    args = ap.parse_args()

    try:
        rep = run_checks(args.require_ics, args.require_cisa_ics, args.require_malwarebazaar)
    except (urllib.error.URLError, OSError, RuntimeError) as exc:
        print(f"ERROR: cannot query {URL}: {exc}", file=sys.stderr)
        return 2

    result = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "url": URL,
        "passed": not rep.failed,
        "checks": rep.checks,
    }
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        for c in rep.checks:
            if c["ok"] is None:
                mark = "INFO"
            elif c["ok"]:
                mark = "PASS"
            else:
                mark = "FAIL" if c["mandatory"] else "WARN"
            detail = json.dumps(c["detail"], default=str)
            print(f"[{mark}] {c['check']}: {detail[:300]}")
        verdict = "PASS" if result["passed"] else f"FAIL ({len(rep.failed)} mandatory check(s) failed)"
        if rep.warnings:
            verdict += f"; {len(rep.warnings)} warning(s): " + ", ".join(c["check"] for c in rep.warnings)
        print("\nRESULT:", verdict)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
