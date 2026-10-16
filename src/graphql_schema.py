"""
EdgeGuard GraphQL Schema
========================
Strawberry type definitions for all EdgeGuard node types, structured to align
with the ResilMesh / ISIM GraphQL conventions:

  - CVE, Vulnerability, CVSSv2, CVSSv30, CVSSv31, CVSSv40  →  overlap with ISIM schema
  - Indicator, ThreatActor, Malware, Technique, Tactic, Tool, Campaign
      →  EdgeGuard-owned; planned for ISIM schema extension (see RESILMESH_INTEROPERABILITY.md §8.4)

Field names are snake_case here (Python convention); Strawberry auto-converts
to camelCase in the GraphQL SDL, matching the ISIM GraphQL style.

2026-10: every type that maps an EdgeGuard node carries ``tlp`` — the node's TLP level as
stored (``n.tlp``: clear / white / green / amber / amber+strict / red; the most restrictive
level any source gave), null when the node has none (the STIX export then applies
``EDGEGUARD_DEFAULT_TLP``). The CVSS sub-types are parts of a CVE and carry no level of their
own; the CVE's ``tlp`` applies.

Port: 4001  (mirrors ISIM's GraphQL port for consistency in ResilMesh deployments)
"""

from __future__ import annotations

from typing import List, Optional

import strawberry

# ─────────────────────────────────────────────────────────────────────────────
# CVSS sub-types
# ─────────────────────────────────────────────────────────────────────────────


@strawberry.type(description="CVSSv2 scoring node — bidirectional with CVE via HAS_CVSS_v2")
class CVSSv2:
    vector_string: str
    access_vector: Optional[str] = None
    access_complexity: Optional[str] = None
    authentication: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    base_score: Optional[float] = None
    base_severity: Optional[str] = None
    impact_score: Optional[float] = None
    exploitability_score: Optional[float] = None
    obtain_all_privilege: Optional[bool] = None
    obtain_user_privilege: Optional[bool] = None
    obtain_other_privilege: Optional[bool] = None
    user_interaction_required: Optional[bool] = None
    ac_insuf_info: Optional[bool] = None


@strawberry.type(description="CVSSv3.0 scoring node — bidirectional with CVE via HAS_CVSS_v30")
class CVSSv30:
    vector_string: str
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    base_score: Optional[float] = None
    base_severity: Optional[str] = None
    impact_score: Optional[float] = None
    exploitability_score: Optional[float] = None


@strawberry.type(description="CVSSv3.1 scoring node — bidirectional with CVE via HAS_CVSS_v31")
class CVSSv31:
    vector_string: str
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    base_score: Optional[float] = None
    base_severity: Optional[str] = None
    impact_score: Optional[float] = None
    exploitability_score: Optional[float] = None


@strawberry.type(description="CVSSv4.0 scoring node — bidirectional with CVE via HAS_CVSS_v40")
class CVSSv40:
    vector_string: str
    base_score: Optional[float] = None
    base_severity: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# ResilMesh-shared node types
# ─────────────────────────────────────────────────────────────────────────────


@strawberry.type(
    description=(
        "CVE node — shared with ISIM; queryable via ISIM GraphQL today. "
        "Properties align with ResilMesh neo4j_nodes_properties.csv."
    )
)
class CVE:
    cve_id: str
    description: Optional[str] = None
    # 2026-10-16: the source whose text ``description`` is (its canonical id, e.g. "nvd", "cisa_kev",
    # "mitre_attck"; ``description_ranking``); null when the node has none or was written before.
    description_source: Optional[str] = None
    published: Optional[str] = None
    last_modified: Optional[str] = None
    cpe_type: Optional[List[str]] = None
    result_impacts: Optional[List[str]] = None
    ref_tags: Optional[List[str]] = None
    cwe: Optional[List[str]] = None
    # Scoring — base_score / base_severity come from one CVSS version, in the order
    # v3.1 → v3.0 → v2 → v4.0, named by cvss_version; without any CVSS the score and version
    # are null and the severity UNKNOWN (2026-10).
    base_score: Optional[float] = None
    base_severity: Optional[str] = None
    cvss_version: Optional[str] = None
    # Provenance — who wrote this node and when
    edgeguard_managed: Optional[bool] = None
    # Deterministic per-node UUID — same value across local + cloud Neo4j
    # for the same logical entity, and equal to the UUID portion of the
    # corresponding STIX 2.1 SDO id. Populated by every node MERGE.
    # Pre-release framework: a fresh baseline rerun stamps every uuid; no
    # backfill script is shipped.
    uuid: Optional[str] = None
    source: Optional[List[str]] = None
    zone: Optional[List[str]] = None
    # 2026-10: the node's TLP level (``n.tlp``); null when the node has none.
    tlp: Optional[str] = None
    first_imported_at: Optional[str] = None
    # PR (S5): source-truthful observation times — populated when the
    # source is on the reliable allowlist (see source_truthful_timestamps.py).
    last_updated: Optional[str] = None
    last_imported_from: Optional[str] = None
    # Linked CVSS nodes (resolved lazily by resolvers)
    cvss_v40: Optional[CVSSv40] = strawberry.field(default=None)
    cvss_v31: Optional[CVSSv31] = strawberry.field(default=None)
    cvss_v30: Optional[CVSSv30] = strawberry.field(default=None)
    cvss_v2: Optional[CVSSv2] = strawberry.field(default=None)
    # Enrichment fields
    version_constraints: Optional[str] = None  # JSON string
    cisa_cwes: Optional[List[str]] = None
    cisa_notes: Optional[str] = None


@strawberry.type(
    description=(
        "Vulnerability entry returned by the vulnerabilities list — shared with ISIM. "
        "Since 2026-10 the list reads the CVE nodes the MISP to Neo4j sync writes (it read the "
        "Vulnerability label, which the sync does not write, and was always empty). "
        "status is LIST OF STRING per ResilMesh schema (NVD's record status, ['active'] or ['rejected']). "
        "cvss_score and severity come from the CVE's first CVSS (v3.1, v3.0, v2, v4.0), named by "
        "cvss_version; without any CVSS the score and version are null and the severity UNKNOWN. "
        "misp_event_ids[] lists every MISP event that has observed this vulnerability."
    )
)
class Vulnerability:
    cve_id: str
    description: Optional[str] = None
    # 2026-10-16: the source whose text ``description`` is (its canonical id, e.g. "nvd", "cisa_kev",
    # "mitre_attck"; ``description_ranking``); null when the node has none or was written before.
    description_source: Optional[str] = None
    status: Optional[List[str]] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    # 2026-10: which CVSS version cvss_score is ("3.1", "3.0", "2.0" or "4.0"), and NVD's
    # publication date of the CVE.
    cvss_version: Optional[str] = None
    published: Optional[str] = None
    zone: Optional[List[str]] = None
    # 2026-10: the node's TLP level (``n.tlp``); null when the node has none.
    tlp: Optional[str] = None
    edgeguard_managed: Optional[bool] = None
    # Deterministic per-node UUID — same value across local + cloud Neo4j
    # for the same logical entity, and equal to the UUID portion of the
    # corresponding STIX 2.1 SDO id. Populated by every node MERGE.
    # Pre-release framework: a fresh baseline rerun stamps every uuid; no
    # backfill script is shipped.
    uuid: Optional[str] = None
    source: Optional[List[str]] = None
    last_updated: Optional[str] = None
    # Provenance — MISP back-references (PR #33 round 10: array-only,
    # legacy scalar misp_event_id removed)
    misp_event_ids: Optional[List[str]] = None
    first_imported_at: Optional[str] = None
    last_imported_from: Optional[str] = None
    # Enrichment fields
    version_constraints: Optional[str] = None  # JSON string
    cisa_cwes: Optional[List[str]] = None
    cisa_notes: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# EdgeGuard-owned node types (planned for ISIM schema extension)
# ─────────────────────────────────────────────────────────────────────────────


@strawberry.type(
    description=(
        "Threat Indicator (IP, domain, hash, URL). "
        "Not yet in ISIM GraphQL schema — EdgeGuard extension. "
        "Ages by one rule for every supplier: confidence_score is source_confidence times the factor "
        "of its aging_tier, counted from last_reported_at (the latest report of any source, dated by "
        "the source's own last-report date capped at the MISP record time; first_imported_at when no "
        "report dated it, aging_basis says which); retired (active false, retired_by 'decay') after "
        "730 days without a report, reactivated by a newer one. "
        "misp_event_ids[] / misp_attribute_ids[] / misp_event_urls[] / misp_attribute_urls[] "
        "let analysts retrieve the full raw MISP context for every event/attribute that "
        "contributed to this indicator (original attributes, comments, attachments). "
        "misp_attribute_urls[] point at the single MISP attribute behind the indicator; "
        "misp_event_urls[] at the whole event, which for a large source holds 100,000+ attributes."
    )
)
class Indicator:
    value: str
    indicator_type: str
    confidence_score: Optional[float] = None
    zone: Optional[List[str]] = None
    # 2026-10: the node's TLP level (``n.tlp``); null when the node has none.
    tlp: Optional[str] = None
    active: Optional[bool] = None
    source: Optional[List[str]] = None
    last_updated: Optional[str] = None
    edgeguard_managed: Optional[bool] = None
    # Deterministic per-node UUID — same value across local + cloud Neo4j
    # for the same logical entity, and equal to the UUID portion of the
    # corresponding STIX 2.1 SDO id. Populated by every node MERGE.
    # Pre-release framework: a fresh baseline rerun stamps every uuid; no
    # backfill script is shipped.
    uuid: Optional[str] = None
    # Provenance — MISP back-references (PR #33 round 10: array-only,
    # legacy scalars misp_event_id / misp_attribute_id removed).
    misp_event_ids: Optional[List[str]] = None
    misp_attribute_ids: Optional[List[str]] = None
    # Computed from MISP_URL env + each id in misp_event_ids[]; one URL per event.
    misp_event_urls: Optional[List[str]] = None
    # Computed from MISP_URL env + each UUID in misp_attribute_ids[]: <MISP_URL>/attributes/view/<uuid>.
    # A client sending a MISP API key receives exactly that attribute as JSON (value, type, category,
    # comment metadata, tags, first/last seen); a browser needs a MISP login. Null when MISP_URL is unset.
    misp_attribute_urls: Optional[List[str]] = None
    # Import audit trail
    first_imported_at: Optional[str] = None
    last_imported_from: Optional[str] = None
    # Enrichment fields
    yara_rules: Optional[List[str]] = None
    sigma_rules: Optional[List[str]] = None
    sandbox_verdicts: Optional[str] = None  # JSON string
    abuse_categories: Optional[List[int]] = None
    indicator_role: Optional[str] = None
    url_status: Optional[str] = None
    last_online: Optional[str] = None
    threat_label: Optional[str] = None
    threat_category: Optional[str] = None
    # 2026-10-16 (indicator aging, ``indicator_aging``): the latest report of any source (its time,
    # source and MISP attribute uuid), the highest confidence a source gave (a node written before
    # 2026-10-16 shows its confidence_score), what the age counts from (source_date,
    # misp_recorded or first_imported), the tier reached (0 below the first tier day), the time the
    # current aging state began, the time at which the node's aging values were last written (a
    # write, or a job run that changed them; a job run that changes nothing leaves it unchanged; an
    # evaluation whose clock is behind it is lifted to it, so the aging never moves backwards), and
    # who retired the node ('decay', or a manual decommission).
    last_reported_at: Optional[str] = None
    last_reported_source: Optional[str] = None
    last_reported_ref: Optional[str] = None
    last_recorded_at: Optional[str] = None
    source_confidence: Optional[float] = None
    aging_basis: Optional[str] = None
    aging_tier: Optional[int] = None
    aging_factor: Optional[float] = None
    aging_since: Optional[str] = None
    aging_evaluated_at: Optional[str] = None
    retired_by: Optional[str] = None
    retired_at: Optional[str] = None


@strawberry.type(description="Threat actor node — EdgeGuard-owned, planned ISIM extension.")
class ThreatActor:
    name: str
    description: Optional[str] = None
    # 2026-10-16: the source whose text ``description`` is (its canonical id, e.g. "nvd", "cisa_kev",
    # "mitre_attck"; ``description_ranking``); null when the node has none or was written before.
    description_source: Optional[str] = None
    sophistication: Optional[str] = None
    primary_motivation: Optional[str] = None
    resource_level: Optional[str] = None
    zone: Optional[List[str]] = None
    # 2026-10: the node's TLP level (``n.tlp``); null when the node has none.
    tlp: Optional[str] = None
    confidence_score: Optional[float] = None
    source: Optional[List[str]] = None
    edgeguard_managed: Optional[bool] = None
    # PR (S5) (bugbot MED): source-truthful and
    # import-wall-clock timestamps, matching Indicator / Vulnerability /
    # Malware. Populated by ``parse_attribute`` via the
    # source_truthful_timestamps helper; MITRE intrusion-set SDOs carry
    # a canonical ``created`` timestamp (actor first documented by
    first_imported_at: Optional[str] = None
    last_updated: Optional[str] = None
    # Deterministic per-node UUID — same value across local + cloud Neo4j
    # for the same logical entity, and equal to the UUID portion of the
    # corresponding STIX 2.1 SDO id. Populated by every node MERGE.
    # Pre-release framework: a fresh baseline rerun stamps every uuid; no
    # backfill script is shipped.
    uuid: Optional[str] = None


@strawberry.type(description="Malware family node — EdgeGuard-owned, planned ISIM extension.")
class Malware:
    name: str
    malware_types: Optional[List[str]] = None
    description: Optional[str] = None
    # 2026-10-16: the source whose text ``description`` is (its canonical id, e.g. "nvd", "cisa_kev",
    # "mitre_attck"; ``description_ranking``); null when the node has none or was written before.
    description_source: Optional[str] = None
    zone: Optional[List[str]] = None
    # 2026-10: the node's TLP level (``n.tlp``); null when the node has none.
    tlp: Optional[str] = None
    confidence_score: Optional[float] = None
    source: Optional[List[str]] = None
    edgeguard_managed: Optional[bool] = None
    # PR (S5) (bugbot MED): source-truthful and
    # import-wall-clock timestamps, matching Indicator / Vulnerability /
    # ThreatActor. Populated by ``parse_attribute`` via the
    first_imported_at: Optional[str] = None
    last_updated: Optional[str] = None
    # Deterministic per-node UUID — same value across local + cloud Neo4j
    # for the same logical entity, and equal to the UUID portion of the
    # corresponding STIX 2.1 SDO id. Populated by every node MERGE.
    # Pre-release framework: a fresh baseline rerun stamps every uuid; no
    # backfill script is shipped.
    uuid: Optional[str] = None


@strawberry.type(description="MITRE ATT&CK technique — EdgeGuard-owned, planned ISIM extension.")
class Technique:
    technique_id: str
    name: str
    description: Optional[str] = None
    # 2026-10-16: the source whose text ``description`` is (its canonical id, e.g. "nvd", "cisa_kev",
    # "mitre_attck"; ``description_ranking``); null when the node has none or was written before.
    description_source: Optional[str] = None
    tactic_refs: Optional[List[str]] = None
    zone: Optional[List[str]] = None
    # 2026-10: the node's TLP level (``n.tlp``); null when the node has none.
    tlp: Optional[str] = None
    confidence_score: Optional[float] = None
    edgeguard_managed: Optional[bool] = None
    # PR (S5) (bugbot LOW): source-truthful + import-wall-clock
    # timestamps for API parity with Indicator / Vulnerability /
    # ThreatActor / Malware / Tool. MITRE attack-pattern SDOs carry
    # canonical ``created`` / ``modified`` which the collector maps
    # into item["first_seen"] / item["last_seen"].
    first_imported_at: Optional[str] = None
    last_updated: Optional[str] = None
    # Deterministic per-node UUID — same value across local + cloud Neo4j
    # for the same logical entity, and equal to the UUID portion of the
    # corresponding STIX 2.1 SDO id. Populated by every node MERGE.
    # Pre-release framework: a fresh baseline rerun stamps every uuid; no
    # backfill script is shipped.
    uuid: Optional[str] = None
    # Enrichment fields
    detection: Optional[str] = None
    is_subtechnique: Optional[bool] = None


@strawberry.type(description="MITRE ATT&CK tactic (kill-chain phase) — EdgeGuard-owned.")
class Tactic:
    tactic_id: str
    name: str
    description: Optional[str] = None
    # 2026-10-16: the source whose text ``description`` is (its canonical id, e.g. "nvd", "cisa_kev",
    # "mitre_attck"; ``description_ranking``); null when the node has none or was written before.
    description_source: Optional[str] = None
    # 2026-10: the node's TLP level (``n.tlp``); null when the node has none.
    tlp: Optional[str] = None
    edgeguard_managed: Optional[bool] = None
    # PR (S5) (bugbot LOW): source-truthful + import-wall-clock
    # timestamps for API parity. x-mitre-tactic SDOs carry canonical
    # ``created`` / ``modified``.
    first_imported_at: Optional[str] = None
    last_updated: Optional[str] = None
    # Deterministic per-node UUID — same value across local + cloud Neo4j
    # for the same logical entity, and equal to the UUID portion of the
    # corresponding STIX 2.1 SDO id. Populated by every node MERGE.
    # Pre-release framework: a fresh baseline rerun stamps every uuid; no
    # backfill script is shipped.
    uuid: Optional[str] = None


@strawberry.type(description="MITRE ATT&CK Tool (Cobalt Strike, Mimikatz, etc.) — EdgeGuard-owned.")
class Tool:
    mitre_id: str
    name: str
    description: Optional[str] = None
    # 2026-10-16: the source whose text ``description`` is (its canonical id, e.g. "nvd", "cisa_kev",
    # "mitre_attck"; ``description_ranking``); null when the node has none or was written before.
    description_source: Optional[str] = None
    tag: Optional[str] = None
    tool_types: Optional[List[str]] = None
    uses_techniques: Optional[List[str]] = None
    zone: Optional[List[str]] = None
    # 2026-10: the node's TLP level (``n.tlp``); null when the node has none.
    tlp: Optional[str] = None
    sources: Optional[List[str]] = None
    confidence_score: Optional[float] = None
    edgeguard_managed: Optional[bool] = None
    # Deterministic per-node UUID — see other types for details.
    uuid: Optional[str] = None
    first_imported_at: Optional[str] = None
    # PR (S5): source-truthful observation times — populated when the
    # source is on the reliable allowlist (see source_truthful_timestamps.py).
    last_updated: Optional[str] = None


# 2026-10-16: the description said a campaign was built when two indicators share an actor and a
# malware within a time window; the enrichment job never did that (``campaign_evidence``).
@strawberry.type(
    description=(
        "Inferred campaign node — EdgeGuard's grouping of one ThreatActor's malware (attributed to "
        "it, ATTRIBUTED_TO, or used by it, USES_MALWARE) and those malware's active indicators, built "
        "by the enrichment job build_campaign_nodes; deleted when the actor has neither link left."
    )
)
class Campaign:
    name: str
    description: Optional[str] = None
    zone: Optional[List[str]] = None
    # 2026-10: the node's TLP level (``n.tlp``); null when the node has none.
    tlp: Optional[str] = None
    confidence_score: Optional[float] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    edgeguard_managed: Optional[bool] = None
    # Deterministic per-node UUID — same value across local + cloud Neo4j
    # for the same logical entity, and equal to the UUID portion of the
    # corresponding STIX 2.1 SDO id. Populated by every node MERGE.
    # Pre-release framework: a fresh baseline rerun stamps every uuid; no
    # backfill script is shipped.
    uuid: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Input types for filtering
# ─────────────────────────────────────────────────────────────────────────────


@strawberry.input(description="Common filter arguments shared by list queries.")
class NodeFilter:
    zone: Optional[str] = strawberry.UNSET
    limit: int = 100
    offset: int = 0
    edgeguard_managed_only: bool = True


@strawberry.input
class IndicatorFilter:
    zone: Optional[str] = strawberry.UNSET
    indicator_type: Optional[str] = strawberry.UNSET
    active_only: bool = True
    min_confidence: float = 0.0
    limit: int = 100
    offset: int = 0


@strawberry.input
class ToolFilter:
    name: Optional[str] = strawberry.UNSET
    zone: Optional[str] = strawberry.UNSET


@strawberry.input
class VulnerabilityFilter:
    zone: Optional[str] = strawberry.UNSET
    status: Optional[str] = strawberry.UNSET
    min_cvss: float = 0.0
    limit: int = 100
    offset: int = 0
