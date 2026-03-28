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
    access_vector: Optional[str]
    access_complexity: Optional[str]
    authentication: Optional[str]
    confidentiality_impact: Optional[str]
    integrity_impact: Optional[str]
    availability_impact: Optional[str]
    base_score: Optional[float]
    base_severity: Optional[str]
    impact_score: Optional[float]
    exploitability_score: Optional[float]
    obtain_all_privilege: Optional[bool]
    obtain_user_privilege: Optional[bool]
    obtain_other_privilege: Optional[bool]
    user_interaction_required: Optional[bool]
    ac_insuf_info: Optional[bool]


@strawberry.type(description="CVSSv3.0 scoring node — bidirectional with CVE via HAS_CVSS_v30")
class CVSSv30:
    vector_string: str
    attack_vector: Optional[str]
    attack_complexity: Optional[str]
    privileges_required: Optional[str]
    user_interaction: Optional[str]
    scope: Optional[str]
    confidentiality_impact: Optional[str]
    integrity_impact: Optional[str]
    availability_impact: Optional[str]
    base_score: Optional[float]
    base_severity: Optional[str]
    impact_score: Optional[float]
    exploitability_score: Optional[float]


@strawberry.type(description="CVSSv3.1 scoring node — bidirectional with CVE via HAS_CVSS_v31")
class CVSSv31:
    vector_string: str
    attack_vector: Optional[str]
    attack_complexity: Optional[str]
    privileges_required: Optional[str]
    user_interaction: Optional[str]
    scope: Optional[str]
    confidentiality_impact: Optional[str]
    integrity_impact: Optional[str]
    availability_impact: Optional[str]
    base_score: Optional[float]
    base_severity: Optional[str]
    impact_score: Optional[float]
    exploitability_score: Optional[float]


@strawberry.type(description="CVSSv4.0 scoring node — bidirectional with CVE via HAS_CVSS_v40")
class CVSSv40:
    vector_string: str
    base_score: Optional[float]
    base_severity: Optional[str]


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
    description: Optional[str]
    published: Optional[str]
    last_modified: Optional[str]
    cpe_type: Optional[List[str]]
    result_impacts: Optional[List[str]]
    ref_tags: Optional[List[str]]
    cwe: Optional[List[str]]
    # Scoring
    base_score: Optional[float]
    base_severity: Optional[str]
    # Provenance — who wrote this node and when
    edgeguard_managed: Optional[bool]
    source: Optional[List[str]]
    zone: Optional[List[str]]
    first_imported_at: Optional[str]
    last_updated: Optional[str]
    last_imported_from: Optional[str]
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
        "Vulnerability instance node — shared with ISIM. "
        "status is LIST OF STRING per ResilMesh schema (e.g. ['active'], ['rejected']). "
        "Links to CVE via REFERS_TO relationship. "
        "misp_event_id lets analysts look up the originating MISP event for raw context."
    )
)
class Vulnerability:
    cve_id: str
    description: Optional[str]
    status: Optional[List[str]]
    severity: Optional[str]
    cvss_score: Optional[float]
    zone: Optional[List[str]]
    edgeguard_managed: Optional[bool]
    source: Optional[List[str]]
    last_updated: Optional[str]
    # Provenance
    misp_event_id: Optional[str]
    first_imported_at: Optional[str]
    last_imported_from: Optional[str]
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
        "confidence_score decays over time via enrichment jobs. "
        "misp_event_id and misp_event_url let analysts retrieve the full raw MISP event "
        "for context not stored in Neo4j (original attributes, comments, attachments)."
    )
)
class Indicator:
    value: str
    indicator_type: str
    confidence_score: Optional[float]
    zone: Optional[List[str]]
    active: Optional[bool]
    source: Optional[List[str]]
    last_updated: Optional[str]
    edgeguard_managed: Optional[bool]
    # Provenance — MISP back-references
    misp_event_id: Optional[str]
    misp_attribute_id: Optional[str]
    # Computed from MISP_URL env + misp_event_id; allows one-click retrieval of raw MISP context
    misp_event_url: Optional[str]
    # Import audit trail
    first_imported_at: Optional[str]
    last_imported_from: Optional[str]
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


@strawberry.type(description="Threat actor node — EdgeGuard-owned, planned ISIM extension.")
class ThreatActor:
    name: str
    description: Optional[str]
    sophistication: Optional[str]
    primary_motivation: Optional[str]
    resource_level: Optional[str]
    zone: Optional[List[str]]
    confidence_score: Optional[float]
    source: Optional[List[str]]
    edgeguard_managed: Optional[bool]


@strawberry.type(description="Malware family node — EdgeGuard-owned, planned ISIM extension.")
class Malware:
    name: str
    malware_types: Optional[List[str]]
    description: Optional[str]
    zone: Optional[List[str]]
    confidence_score: Optional[float]
    source: Optional[List[str]]
    edgeguard_managed: Optional[bool]


@strawberry.type(description="MITRE ATT&CK technique — EdgeGuard-owned, planned ISIM extension.")
class Technique:
    technique_id: str
    name: str
    description: Optional[str]
    tactic_refs: Optional[List[str]]
    zone: Optional[List[str]]
    confidence_score: Optional[float]
    edgeguard_managed: Optional[bool]
    # Enrichment fields
    detection: Optional[str] = None
    is_subtechnique: Optional[bool] = None


@strawberry.type(description="MITRE ATT&CK tactic (kill-chain phase) — EdgeGuard-owned.")
class Tactic:
    tactic_id: str
    name: str
    description: Optional[str]
    edgeguard_managed: Optional[bool]


@strawberry.type(description="MITRE ATT&CK Tool (Cobalt Strike, Mimikatz, etc.) — EdgeGuard-owned.")
class Tool:
    mitre_id: str
    name: str
    description: Optional[str] = None
    tag: Optional[str] = None
    tool_types: Optional[List[str]] = None
    uses_techniques: Optional[List[str]] = None
    zone: Optional[List[str]] = None
    sources: Optional[List[str]] = None
    confidence_score: Optional[float] = None
    edgeguard_managed: Optional[bool] = None
    first_imported_at: Optional[str] = None
    last_updated: Optional[str] = None


@strawberry.type(
    description=(
        "Inferred campaign node — built by EdgeGuard enrichment when "
        "≥2 indicators share the same ThreatActor + Malware within a time window."
    )
)
class Campaign:
    name: str
    description: Optional[str]
    zone: Optional[List[str]]
    confidence_score: Optional[float]
    first_seen: Optional[str]
    last_seen: Optional[str]
    edgeguard_managed: Optional[bool]


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
