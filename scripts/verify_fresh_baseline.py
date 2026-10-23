"""
Read-only acceptance check for a fresh EdgeGuard baseline (2026-10 PR).

Runs over the Neo4j **HTTP Query API v2** (the address and requests of
``src/neo4j_http_endpoint.py``, shared with ``scripts/run_cypher_catalog_http.py``) so it works
wherever plain HTTP(S) reaches the database, including a Cloudflare-proxied endpoint that only
speaks Bolt-over-WebSocket. Nothing is written.

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
revoked group's name. Since the Malware twin fix of 2026-10 it fails when a Malware node from another
source is still named after an ATT&CK software id (``cobalt strike - s0154``) while the enrichment job
``merge_malware_attack_twins`` would fold it: into the MITRE Malware node of that id or base name, or,
for software without one, into the node of its base name. Since the campaign evidence change of
2026-10-16 it fails when a campaign, a campaign's malware member or a ``RUNS`` rests on no
``ATTRIBUTED_TO`` or ``USES_MALWARE`` link between the campaign's actor and a malware
(``src/campaign_evidence.py``), and when a campaign link does not name the relationship types it rests
on (``evidence_types``). Since the sector evidence change of 2026-10-16 it fails when a link to a Sector
names a feed whose ``SOURCED_FROM`` zones do not give that sector, when ``advisory_sector`` sits anywhere
but on an AFFECTS link to a sector CISA's ICS advisory stated, when a sector CISA stated is not linked as
``advisory_sector``, when a sector link cites a record of a feed that recorded its references per sector
(``stated_refs``: the CISA ICS advisories) other than those of its sector, and when a sector link's
confidence is not the one its label gives (``src/sector_evidence.py``); it reports the links by evidence
label, what CISA ICS adds per sector and the node sectors no feed gave. Since the OTX industries change of
2026-10-18 it fails when ``otx_industries`` sits anywhere but on a TARGETS link from an Indicator,
ThreatActor or Malware to a sector an OTX record stated (``stated_zones`` of the alienvault_otx
``SOURCED_FROM`` edge), when such a link cites none of the pulses that stated its sector, and when a sector
an OTX record stated is not linked as ``otx_industries`` (with ``--require-otx-industries`` also when the
OTX records give sectors and none states one); the per-sector reference check judges only the feeds whose
records state every zone they give (CISA ICS). Since 2026-10-16 it also fails
when a ranked description names no source (``description_source``) or an Indicator has no
``aging_basis`` / ``source_confidence``. Since the same-report CVE links of 2026-10-18 it reports how many
indicators are linked to a CVE named in the same OTX report (``Indicator -[:INDICATES]-> CVE``) and fails
when such a link is not labelled ``otx_pulse`` or cites no OTX report (``alienvault_otx:<pulse id>``).

Env (``src/neo4j_http_endpoint.py``):
  NEO4J_HTTP_URL   base URL, then NEO4J_HTTP; neither set: the local Compose Neo4j
                   http://127.0.0.1:7474 (no remote default)
  NEO4J_DATABASE   database name (default: neo4j)
  NEO4J_USER       basic-auth user (default: neo4j)
  NEO4J_PASSWORD   basic-auth password
  NEO4J_HTTP_USER_AGENT  User-Agent (default: a browser's)

Usage, the Compose Neo4j (http://127.0.0.1:7474) with the credentials of .env:
  set -a; . ./.env; set +a
  python scripts/verify_fresh_baseline.py                 # human-readable
  python scripts/verify_fresh_baseline.py --json          # machine-readable
  python scripts/verify_fresh_baseline.py --require-ics --require-cisa-ics
  python scripts/verify_fresh_baseline.py --require-otx-industries   # after a baseline with OTX
  python scripts/verify_fresh_baseline.py --require-malwarebazaar   # after enabling that source

Another instance: source its credentials and name its address on the same line:
  set -a; . ./.env.edgeguard; set +a
  NEO4J_HTTP_URL=<instance HTTP address> python scripts/verify_fresh_baseline.py

Exit code 0 = every mandatory check passed; 1 = at least one failed; 2 = could
not reach Neo4j, or NEO4J_HTTP_URL / NEO4J_HTTP is not a valid http(s) URL. A warning
(``[WARN]``; ``ok: false`` with ``mandatory: false`` in the JSON) is reported and leaves
the exit code unchanged.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# The Neo4j address, credentials and User-Agent of every request (no remote default).
import neo4j_http_endpoint  # noqa: E402

# Standard library only (no driver, no config): the revoked ATT&CK ids of check 9b, the ATT&CK
# software ids in malware family names of checks 10a4 / 10a5, and (2026-10-16) the campaign evidence
# of checks 13c / 13d, which ``build_campaign_nodes`` reads from the same module.
from attack_revoked import load_revoked_ids  # noqa: E402
from attack_software_names import (  # noqa: E402
    CYPHER_BASE_NODES_READ,
    CYPHER_FOLDED_FAMILIES_READ,
    CYPHER_SOFTWARE_ID_SUFFIX,
    CYPHER_SUFFIXED_NAME,
    attack_software_id,
    cypher_family_name_variants,
    folded_family_names,
    plan_twin_folds,
    twin_base_names,
)
from campaign_evidence import CAMPAIGN_EVIDENCE_CHECK_QUERY, MALWARE_MEMBERSHIP_CHECK_QUERY  # noqa: E402
from canonical_threat_actors import (  # noqa: E402
    ATTRIBUTION_CHECK_QUERY,
    INDICATOR_MARKED_REPORTS_QUERY,
    OTX_REPORT_REF_PREFIX,
    REPORT_ACTORS_QUERY,
    REPORT_ATTRIBUTION_FEEDS,
    ReferenceUnavailable,
    load_canonical_reference,
    several_actor_reports,
)

# 2026-10-16: the description ranking (which labels name the source of their description, check 16a),
# the sector evidence table and the per-sector provenance rule of build_relationships steps 7a-7d
# (checks 10d-10k). Standard library and ``source_registry`` only, like the modules above.
from description_ranking import ranking_for_label  # noqa: E402
from relationship_provenance import as_list as _as_list  # noqa: E402
from relationship_provenance import zone_prov_with  # noqa: E402
from sector_evidence import (  # noqa: E402
    ADVISORY_SECTOR,
    LABEL_CONFIDENCE,
    OTX_INDUSTRIES,
    STATED_REF_SEPARATOR,
    STATEMENT_LABELS,
    STATING_FEEDS,
)
from source_registry import SOURCE_REF_SEPARATOR  # noqa: E402

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
# (``campaign_grouping``), so they are held to the full contract below; since 2026-10-16 they also
# name the relationship types they rest on (``evidence_types``: ATTRIBUTED_TO, USES_MALWARE and, on
# an indicator's link, INDICATES).
_INHERITED_REL_TYPES = ("REFERS_TO",)
_CAMPAIGN_REL_TYPES = ("RUNS", "PART_OF_CAMPAIGN")
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
        if t not in _INHERITED_REL_TYPES + _CVSS_REL_TYPES + _CAMPAIGN_REL_TYPES
    },
    **{t: _PROVENANCE_LISTS + ("match_type", "evidence_types") for t in _CAMPAIGN_REL_TYPES},
    **{t: _PROVENANCE_LISTS for t in _INHERITED_REL_TYPES},
    **{t: ("sources", "misp_event_ids") for t in _CVSS_REL_TYPES},
    # The per-source edge of a node: the source id (``source``, a string), the source's record ids
    # and the MISP events that carried the node.
    "SOURCED_FROM": ("source", "source_refs", "misp_event_ids"),
}
# One pass over the relationships, one row per type, for checks 12b and 12c: how many edges
# EdgeGuard manages, how many of those carry each contract property (``source`` only as a string,
# ``evidence_types`` of the campaign links since 2026-10-16,
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
    "sum(CASE WHEN r.edgeguard_managed = true AND r.evidence_types IS NOT NULL THEN 1 ELSE 0 END) "
    "AS with_evidence_types, "
    "sum(CASE WHEN r.edgeguard_managed = true AND r.source IS NOT NULL "
    "THEN CASE apoc.meta.cypher.type(r.source) WHEN 'STRING' THEN 1 ELSE 0 END ELSE 0 END) AS with_source, "
    "sum(CASE WHEN r.edgeguard_managed = true AND r.misp_event_ids = [] THEN 1 ELSE 0 END) AS empty_misp_event_ids, "
    "sum(CASE WHEN r.source_id IS NOT NULL OR r.source_ids IS NOT NULL OR r.report_ids IS NOT NULL "
    "THEN 1 ELSE 0 END) AS legacy_keys "
    "ORDER BY type"
)
# Labels parsed from MISP attributes — the only nodes that carry ``tlp`` (the tag travels
# with the attribute). Source/Sector/CVSS* and the ResilMesh-model nodes written on alert
# ingestion (Host, IP, Alert, …) are marker-stamped when EdgeGuard creates them but never have
# a TLP, and a Campaign carries one only when a link it rests on has one (2026-10), so the
# check is an allowlist, not a skip-list.
_TLP_LABELS = ("Indicator", "CVE", "Vulnerability", "Malware", "ThreatActor", "Technique", "Tactic", "Tool")
# ATT&CK entries whose names begin with "Windows": MISP's default Import Regexp rules rewrote the
# value "<id>: Windows ..." (``T1059.003: Windows Command Shell`` → ``T1059.00%WINDIR%\Command Shell``),
# so they were missing from the graph (nine on the run of 2026-10-20). MISPWriter writes
# "<id> - <name>" (``src/attack_values.py``), which the rules leave unchanged.
_MANGLED_TECHNIQUES = (
    "T1059.003",
    "T1047",
    "T1021.006",
    "T1543.003",
    "T1222.001",
    "T1546.003",
    "T1555.004",
    "T1686.003",
)
_MANGLED_TOOLS_HINT = (
    "the sync skips an ATT&CK value with no valid ATT&CK id: grep '[ATTACK-VALUE]' in the sync log and "
    "check the value MISP stored and its Import Regexp rules (docs/BASELINE_LAUNCH_CHECKLIST.md § [6], step 1)"
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
    # Address, credentials and User-Agent from the shared helper: NEO4J_HTTP_URL, then NEO4J_HTTP,
    # else the local Compose Neo4j; never a built-in remote host.
    req = neo4j_http_endpoint.query_request(body)
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


def _malware_twin_verdict(
    twins: List[Dict[str, Any]],
    attack_ids: Dict[str, Optional[str]],
    software_successors: Mapping[str, str],
    base_nodes: Optional[Mapping[str, Any]] = None,
) -> Tuple[Optional[bool], Dict[str, Any]]:
    """Check 10a5: ``(ok, detail)`` from the twin candidates, the MITRE Malware nodes' ATT&CK ids and
    the non-MITRE nodes named by a twin's base name.

    Fails when a twin the enrichment job folds (into a MITRE node, or into the node of its base name),
    or one it cannot decide (ambiguous), is still a node; informational (``None``) when no node carries
    an ATT&CK software id in its name.
    """
    plan = plan_twin_folds(twins, attack_ids, software_successors, base_nodes)
    foldable = sorted(plan.pairs + plan.base_pairs)
    detail: Dict[str, Any] = {
        "nodes_named_with_attack_id": plan.candidates,
        "foldable_remaining": len(foldable),
        "foldable_into_base_name": len(plan.base_pairs),
        "ambiguous": len(plan.ambiguous),
        "without_target": len(plan.no_target),
        "examples_foldable": [f"{twin} -> {target}" for target, twin in foldable[:10]],
        "examples_ambiguous": [f"{twin} -> {targets}" for twin, targets in plan.ambiguous[:10]],
        "examples_without_target": plan.no_target[:10],
        "hint": "run the enrichment jobs (merge_malware_attack_twins); see its [MALWARE-TWIN-MERGE] log lines",
    }
    if not plan.candidates:
        return None, detail
    return not foldable and not plan.ambiguous, detail


# Labels whose description names its source (2026-10-16, ``description_ranking``): read from the ranking,
# not listed here, so a label the ranking gains is checked too.
_RANKED_DESCRIPTION_LABELS = tuple(label for label in EDGEGUARD_LABELS if ranking_for_label(label) is not None)
# Labels that link to a Sector (build_relationships steps 7a-7d).
_SECTOR_LINKED_LABELS = ("Indicator", "CVE", "Vulnerability", "ThreatActor", "Malware")
_SECTOR_LINKED_WHERE = "(" + " OR ".join(f"n:{label}" for label in _SECTOR_LINKED_LABELS) + ")"
# A zone stored as a single string reads as a one-entry list (APOC ``combine`` stores equal values so).
_N_ZONES = _as_list("n.zone")
# 2026-10-18: the feeds whose TARGETS statement is ``otx_industries`` (the table: ``alienvault_otx``).
_OTX_INDUSTRIES_FEEDS = sorted(f for f, label in STATEMENT_LABELS["TARGETS"].items() if label == OTX_INDUSTRIES)
_TARGETS_START = "(n:Indicator OR n:ThreatActor OR n:Malware)"


def _sector_evidence_checks(rep: Report, require_cisa_ics: bool, require_otx_industries: bool = False) -> None:
    """Checks 10d-10m (2026-10-16): each link to a Sector names only the feeds that gave its sector and
    cites only the records that gave it, its label and confidence follow the table (``sector_evidence``),
    CISA's ICS statements are linked as ``advisory_sector`` on AFFECTS only and (2026-10-18) an OTX
    report's industries as ``otx_industries`` on TARGETS only. The per-source zones are on the
    ``SOURCED_FROM`` edges (``zones``, ``stated_zones``, ``stated_refs``); a graph written before them has
    none, so the judged checks report instead of passing vacuously."""
    # 10d. A link to a Sector names only the feeds whose SOURCED_FROM zones give the sector. An edge
    #      without ``zones`` (written before 2026-10-16, or by a path that records none) is not judged.
    zoned = _one(
        "MATCH ()-[sf:SOURCED_FROM]->(src) RETURN count(sf) AS edges, "
        "sum(CASE WHEN sf.zones IS NOT NULL THEN 1 ELSE 0 END) AS with_zones, "
        "sum(CASE WHEN sf.stated_zones IS NOT NULL THEN 1 ELSE 0 END) AS with_stated_zones, "
        "sum(CASE WHEN sf.stated_refs IS NOT NULL THEN 1 ELSE 0 END) AS with_stated_refs, "
        "sum(CASE WHEN sf.stated_refs IS NOT NULL AND src.source_id IN $stating_feeds THEN 1 ELSE 0 END) "
        "AS stating_feed_edges_with_stated_refs",
        {"stating_feeds": sorted(STATING_FEEDS)},
    )
    wrong = _post(
        "MATCH (n)-[r:AFFECTS|TARGETS]->(s:Sector) WHERE r.edgeguard_managed = true "
        "UNWIND " + _as_list("r.sources") + " AS f "
        "MATCH (n)-[sf:SOURCED_FROM]->(:Source {source_id: f}) "
        "WHERE sf.zones IS NOT NULL AND NOT s.name IN " + _as_list("sf.zones") + " "
        "RETURN type(r) AS type, labels(n)[0] AS label, f AS source, count(*) AS c ORDER BY c DESC"
    )
    rep.add(
        "sector_links_name_only_feeds_that_gave_the_sector",
        None if not zoned.get("with_zones") else not wrong,
        {"naming_a_feed_that_did_not_give_the_sector": wrong, "sourced_from": zoned},
    )

    # 10e. ``advisory_sector`` only on AFFECTS from a CVE / Vulnerability to a Sector that CISA's ICS
    #      advisory stated (the cisa_ics SOURCED_FROM ``stated_zones``): never on TARGETS, never on a
    #      sector CISA did not name. Informational while no link carries the label.
    r = _one(
        "MATCH (n)-[r]->(s) WHERE r.match_type = $advisory "
        "WITH n, r, s, type(r) = 'AFFECTS' AND s:Sector AND (n:CVE OR n:Vulnerability) "
        "AND EXISTS { MATCH (n)-[sf:SOURCED_FROM]->(:Source {source_id: 'cisa_ics'}) "
        "WHERE s.name IN " + _as_list("sf.stated_zones") + " } AS stated "
        "RETURN count(r) AS advisory_links, sum(CASE WHEN stated THEN 0 ELSE 1 END) AS misplaced, "
        "collect(CASE WHEN NOT stated THEN type(r) + ' ' + labels(n)[0] + ' -> ' + coalesce(s.name, '?') END)[..10] "
        "AS examples",
        {"advisory": ADVISORY_SECTOR},
    )
    rep.add(
        "advisory_sector_only_where_cisa_stated", None if not r.get("advisory_links") else r.get("misplaced") == 0, r
    )

    # The CISA ICS records and how many carry per-source zones (also reported by 10i). A record written
    # before 2026-10-16 has none and so can state no sector: 10f does not judge such a graph.
    records = _one(
        "MATCH (c)-[sf:SOURCED_FROM]->(:Source {source_id: 'cisa_ics'}) "
        "RETURN count(sf) AS cisa_records, sum(CASE WHEN sf.zones = ['global'] THEN 1 ELSE 0 END) AS cisa_global, "
        "sum(CASE WHEN sf.zones IS NULL THEN 1 ELSE 0 END) AS without_zones"
    )
    cisa_with_zones = (records.get("cisa_records") or 0) - (records.get("without_zones") or 0)

    # 10f. Every sector CISA's ICS advisory stated is linked as ``advisory_sector``. With
    #      ``--require-cisa-ics`` at least one must be stated once the CISA ICS records carry their zones;
    #      without the flag, or on a graph whose CISA ICS records carry none (built before 2026-10-16, or
    #      kept and not re-read since), no stated sector is informational.
    r = _one(
        "MATCH (c)-[sf:SOURCED_FROM]->(:Source {source_id: 'cisa_ics'}) WHERE c:CVE OR c:Vulnerability "
        "UNWIND " + _as_list("sf.stated_zones") + " AS z "
        "OPTIONAL MATCH (c)-[r:AFFECTS]->(:Sector {name: z}) "
        "RETURN count(*) AS stated, sum(CASE WHEN r IS NULL OR r.match_type <> $advisory THEN 1 ELSE 0 END) "
        "AS not_labelled, collect(CASE WHEN r IS NULL OR r.match_type <> $advisory "
        "THEN c.cve_id + ' ' + z END)[..10] AS examples",
        {"advisory": ADVISORY_SECTOR},
    )
    stated_ok: Optional[bool]
    if r.get("stated"):
        stated_ok = r.get("not_labelled") == 0
    elif require_cisa_ics and cisa_with_zones > 0:
        stated_ok = False
    else:
        stated_ok = None
    rep.add(
        "cisa_stated_sectors_linked_as_advisory_sector", stated_ok, {**r, "cisa_records_with_zones": cisa_with_zones}
    )

    # 10k. A sector link cites, of a feed whose records state every zone they give and record which of
    #      them stated which sector (the SOURCED_FROM ``stated_refs``, ``"<zone>|<ref>"``: the CISA ICS
    #      advisories, ``sector_evidence.STATING_FEEDS``), only the records of its sector: a CISA ICS link to
    #      healthcare cites no advisory whose note does not name Healthcare. A feed whose edge records
    #      nothing for the sector is not judged, and neither is OTX (2026-10-18): an OTX record also gives
    #      zones by keyword, for which it records no reference, so a link may rightly cite a pulse its
    #      ``stated_refs`` record for another sector only (10l judges OTX's statements).
    other_refs = _post(
        "MATCH (n)-[r:AFFECTS|TARGETS]->(s:Sector) WHERE r.edgeguard_managed = true "
        "MATCH (n)-[sf:SOURCED_FROM]->(src:Source) WHERE sf.stated_refs IS NOT NULL "
        "AND src.source_id IN $stating_feeds "
        "WITH r, s, src, [_x IN " + _as_list("sf.stated_refs") + " WHERE _x STARTS WITH s.name + $sep "
        "| substring(_x, size(s.name) + size($sep))] AS cited "
        "WHERE size(cited) > 0 "
        "UNWIND [_x IN " + _as_list("r.source_refs") + " WHERE _x STARTS WITH src.source_id + $ref_sep "
        "AND NOT _x IN cited] AS other "
        "RETURN type(r) AS type, src.source_id AS source, count(*) AS c, "
        "collect(s.name + ' ' + other)[..10] AS examples ORDER BY c DESC",
        {"sep": STATED_REF_SEPARATOR, "ref_sep": SOURCE_REF_SEPARATOR, "stating_feeds": sorted(STATING_FEEDS)},
    )
    rep.add(
        "sector_links_cite_only_records_that_gave_the_sector",
        None if not zoned.get("stating_feed_edges_with_stated_refs") else not other_refs,
        {
            "citing_a_record_of_another_sector": other_refs,
            "sourced_from_with_stated_refs": zoned.get("with_stated_refs"),
            "judged_sourced_from_with_stated_refs": zoned.get("stating_feed_edges_with_stated_refs"),
            "judged_feeds": sorted(STATING_FEEDS),
        },
    )

    # 10l. ``otx_industries`` (2026-10-18) only on TARGETS from an Indicator, ThreatActor or Malware to a
    #      Sector that an OTX record stated (the alienvault_otx SOURCED_FROM ``stated_zones``): never on
    #      AFFECTS, never on a sector the report's industries did not name. Where that edge records which
    #      pulse stated the sector (``stated_refs``), the link cites one of them. Informational while no
    #      link carries the label.
    otx = _one(
        "MATCH (n)-[r]->(s) WHERE r.match_type = $label "
        "WITH n, r, s, type(r) = 'TARGETS' AND s:Sector AND " + _TARGETS_START + " AS on_targets, "
        "[(n)-[sf:SOURCED_FROM]->(src:Source) WHERE src.source_id IN $feeds "
        "AND s.name IN " + _as_list("sf.stated_zones") + " | sf] AS stating "
        "WITH n, r, s, on_targets AND size(stating) > 0 AS stated, "
        "reduce(_a = [], _sf IN stating | _a + [_x IN " + _as_list("_sf.stated_refs") + " "
        "WHERE _x STARTS WITH s.name + $sep | substring(_x, size(s.name) + size($sep))]) AS stating_refs "
        "RETURN count(r) AS otx_links, sum(CASE WHEN type(r) = 'AFFECTS' THEN 1 ELSE 0 END) AS on_affects, "
        "sum(CASE WHEN stated THEN 0 ELSE 1 END) AS misplaced, "
        "sum(CASE WHEN stated AND size(stating_refs) > 0 AND NONE(_x IN stating_refs WHERE _x IN "
        + _as_list("r.source_refs")
        + ") THEN 1 ELSE 0 END) AS citing_no_stating_report, "
        "collect(CASE WHEN NOT stated THEN type(r) + ' ' + labels(n)[0] + ' -> ' + coalesce(s.name, '?') END)[..10] "
        "AS examples, "
        "collect(CASE WHEN stated AND size(stating_refs) > 0 AND NONE(_x IN stating_refs WHERE _x IN "
        + _as_list("r.source_refs")
        + ") THEN labels(n)[0] + ' ' + coalesce(n.name, n.value, '?') + ' -> ' + s.name END)[..10] "
        "AS citing_examples",
        {"label": OTX_INDUSTRIES, "feeds": _OTX_INDUSTRIES_FEEDS, "sep": STATED_REF_SEPARATOR},
    )
    rep.add(
        "otx_industries_only_where_otx_stated",
        None
        if not otx.get("otx_links")
        else otx.get("misplaced") == 0 and otx.get("on_affects") == 0 and otx.get("citing_no_stating_report") == 0,
        otx,
    )

    # The OTX records of the nodes that link to a Sector by TARGETS: how many give a sector and how many
    # state one. Read by 10m under ``--require-otx-industries``.
    otx_records = _one(
        "MATCH (n)-[sf:SOURCED_FROM]->(src:Source) WHERE " + _TARGETS_START + " AND src.source_id IN $feeds "
        "RETURN count(sf) AS otx_records, "
        "sum(CASE WHEN any(_z IN " + _as_list("sf.zones") + " WHERE _z <> 'global') THEN 1 ELSE 0 END) "
        "AS otx_records_with_a_sector, "
        "sum(CASE WHEN size(" + _as_list("sf.stated_zones") + ") > 0 THEN 1 ELSE 0 END) AS otx_records_stating",
        {"feeds": _OTX_INDUSTRIES_FEEDS},
    )
    otx_with_a_sector = otx_records.get("otx_records_with_a_sector") or 0

    # 10m. Every sector an OTX record stated is linked as ``otx_industries`` from the node (TARGETS, steps
    #      7a / 7c / 7d and the sync's indicator rows). A link whose label is outside the table (a curated or
    #      partner label, which the writers keep) is not judged. With ``--require-otx-industries`` at least
    #      one sector must be stated once the OTX records give a sector (a run that lost the pulses'
    #      industries on the way to the sync looks like a graph without statements); without the flag, or
    #      while no OTX record gives a sector, no stated sector is informational (a graph synced before
    #      2026-10-18).
    r = _one(
        "MATCH (n)-[sf:SOURCED_FROM]->(src:Source) WHERE " + _TARGETS_START + " AND src.source_id IN $feeds "
        "UNWIND " + _as_list("sf.stated_zones") + " AS z "
        "OPTIONAL MATCH (n)-[r:TARGETS]->(:Sector {name: z}) "
        "WITH n, z, r, r IS NULL OR (r.match_type IN $labels AND r.match_type <> $label) AS missing "
        "RETURN count(*) AS stated, sum(CASE WHEN missing THEN 1 ELSE 0 END) AS otx_not_labelled, "
        "collect(CASE WHEN missing THEN labels(n)[0] + ' ' + coalesce(n.name, n.value, '?') + ' ' + z END)[..10] "
        "AS examples",
        {"label": OTX_INDUSTRIES, "feeds": _OTX_INDUSTRIES_FEEDS, "labels": sorted(LABEL_CONFIDENCE)},
    )
    otx_stated_ok: Optional[bool]
    if r.get("stated"):
        otx_stated_ok = r.get("otx_not_labelled") == 0
    elif require_otx_industries and otx_with_a_sector > 0:
        otx_stated_ok = False
    else:
        otx_stated_ok = None
    rep.add("otx_stated_sectors_linked_as_otx_industries", otx_stated_ok, {**r, **otx_records})

    # 10g. The confidence of a sector link is the table's value of its label (the sync and step 7 write
    #      the same); a label outside the table (a curated or partner label) is not judged.
    rows = _post(
        "MATCH ()-[r:AFFECTS|TARGETS]->(:Sector) WHERE r.edgeguard_managed = true AND r.match_type IN $labels "
        "WITH r.match_type AS label, coalesce(r.confidence_score, -1.0) = $conf[r.match_type] AS ok "
        "RETURN label, count(*) AS links, sum(CASE WHEN ok THEN 0 ELSE 1 END) AS other_confidence ORDER BY label",
        {"labels": sorted(LABEL_CONFIDENCE), "conf": dict(LABEL_CONFIDENCE)},
    )
    off = [x for x in rows if x.get("other_confidence")]
    rep.add(
        "sector_confidence_follows_label",
        None if not sum(x.get("links") or 0 for x in rows) else not off,
        {"by_label": rows, "table": dict(LABEL_CONFIDENCE)},
    )

    # 10h. Links by relationship type and evidence label (informational), then broken down by start label
    #      and sector.
    by_label = _post(
        "MATCH ()-[r:AFFECTS|TARGETS]->(:Sector) "
        "RETURN type(r) AS type, r.match_type AS match_type, count(*) AS links ORDER BY type, match_type"
    )
    rep.add("sector_links_by_evidence_label", None, by_label)
    breakdown = _post(
        "MATCH (n)-[r:AFFECTS|TARGETS]->(s:Sector) "
        "RETURN type(r) AS type, labels(n)[0] AS label, s.name AS sector, r.match_type AS match_type, count(*) AS c "
        "ORDER BY type, label, sector, match_type"
    )
    rep.add("sector_evidence_breakdown", None, breakdown)

    # 10i. What CISA ICS adds, per sector (informational): the sectors it stated, those only CISA gave
    #      (``r.sources = ['cisa_ics']``) and those another feed also inferred; and its records whose
    #      advisory named no tracked sector (``zones = ['global']``).
    per_sector = _post(
        "MATCH (:CVE)-[r:AFFECTS]->(s:Sector) WHERE r.match_type = $advisory "
        "RETURN s.name AS sector, count(*) AS stated, "
        "sum(CASE WHEN " + _as_list("r.sources") + " = ['cisa_ics'] THEN 1 ELSE 0 END) AS cisa_alone, "
        "sum(CASE WHEN size(" + _as_list("r.sources") + ") > 1 THEN 1 ELSE 0 END) AS cisa_and_inferred "
        "ORDER BY sector",
        {"advisory": ADVISORY_SECTOR},
    )
    rep.add("cisa_ics_contribution", None, {"by_sector": per_sector, **records})

    # 10j. Node sectors no feed gave (informational): a zone on the node that no SOURCED_FROM edge with
    #      ``zones`` lists and no legacy edge or feed covers. Steps 7a-7d link none of them (their [SKIP]
    #      count); the same rule (``zone_prov_with``) over every zone the node holds. And the nodes that
    #      hold ``global`` next to a sector, which the zone rule of the writers drops.
    without = _post(
        f"MATCH (n) WHERE {_SECTOR_LINKED_WHERE} AND n.zone IS NOT NULL "
        + zone_prov_with("n", _N_ZONES, feeds_filter="= 0")
        + "RETURN labels(n)[0] AS label, zone_name AS sector, count(*) AS c ORDER BY label, sector"
    )
    global_next = _post(
        f"MATCH (n) WHERE n.zone IS NOT NULL WITH n, {_N_ZONES} AS z "
        "WHERE 'global' IN z AND size([x IN z WHERE x <> 'global']) > 0 "
        "RETURN labels(n)[0] AS label, count(*) AS c ORDER BY label"
    )
    rep.add(
        "node_sectors_without_a_feed",
        None,
        {"sectors_no_feed_gave": without, "nodes_with_global_next_to_a_sector": global_next},
    )


def _ranked_description_and_aging_checks(rep: Report) -> None:
    """Checks 16a / 16b (2026-10-16): every ranked description names its source and every Indicator has
    an aging basis and a source confidence. Informational on a graph without such nodes."""
    r = _one(
        "MATCH (n) WHERE n.edgeguard_managed = true AND any(l IN labels(n) WHERE l IN $labels) "
        "AND n.description IS NOT NULL AND n.description <> '' "
        "RETURN count(n) AS described, sum(CASE WHEN n.description_source IS NULL THEN 1 ELSE 0 END) AS without_source, "
        "collect(CASE WHEN n.description_source IS NULL THEN labels(n)[0] END)[..10] AS example_labels",
        {"labels": list(_RANKED_DESCRIPTION_LABELS)},
    )
    r["labels"] = list(_RANKED_DESCRIPTION_LABELS)
    judged = bool(r.get("described"))
    rep.add("descriptions_name_their_source", r.get("without_source") == 0 if judged else None, r)
    r = _one(
        "MATCH (i:Indicator) WHERE i.edgeguard_managed = true "
        "RETURN count(i) AS indicators, "
        "sum(CASE WHEN i.aging_basis IS NULL THEN 1 ELSE 0 END) AS without_aging_basis, "
        "sum(CASE WHEN i.source_confidence IS NULL THEN 1 ELSE 0 END) AS without_source_confidence"
    )
    judged = bool(r.get("indicators"))
    ok = r.get("without_aging_basis") == 0 and r.get("without_source_confidence") == 0
    rep.add("indicators_have_aging_basis", ok if judged else None, r)


def run_checks(
    require_ics: bool, require_cisa_ics: bool, require_malwarebazaar: bool = False, require_otx_industries: bool = False
) -> Report:
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
    #       while no indicator carries pulse families (pre-change data). A family is looked up as Q9b
    #       looks it up (2026-10): by its name as given and without an ATT&CK software id suffix
    #       ("Cobalt Strike - S0154" → "cobalt strike"), each through the names the twin merge folded
    #       into a node ("agenttesla" → "agent tesla", from ``merged_from``; same expression and map).
    folded_families = folded_family_names(_post(CYPHER_FOLDED_FAMILIES_READ, {"mitre_source": "mitre_attck"}))
    r = _one(
        "MATCH (i:Indicator) WHERE size(coalesce(i.pulse_malware_families, [])) > 0 "
        "UNWIND i.pulse_malware_families AS fam WITH i, toLower(trim(fam)) AS f "
        "OPTIONAL MATCH (m:Malware) WHERE m.name IN " + cypher_family_name_variants("f") + " "
        "WITH i, f, collect(m) AS ms "
        "RETURN count(*) AS claims, sum(CASE WHEN size(ms) = 0 THEN 1 ELSE 0 END) AS target_missing, "
        "sum(CASE WHEN size(ms) > 0 AND none(m IN ms WHERE EXISTS { (i)-[:INDICATES]->(m) }) THEN 1 ELSE 0 END) AS edge_missing",
        {"software_id_suffix": CYPHER_SOFTWARE_ID_SUFFIX, "folded_families": folded_families},
    )
    rep.add("pulse_indicates_complete", None if (r.get("claims") or 0) == 0 else r.get("edge_missing") == 0, r)

    # 10a6. Indicators and CVEs named in the same OTX report (2026-10-18): the sync links them as
    #       ``(Indicator)-[:INDICATES]->(CVE)`` with ``match_type`` ``otx_pulse`` and the report as
    #       ``alienvault_otx:<pulse id>`` in ``source_refs``. Informational: how many links, CVEs and
    #       indicators, and how many INDICATES links from an indicator reach a node that is neither a
    #       Malware nor a CVE (no writer creates one). Mandatory: no such CVE link is unlabelled, labelled
    #       otherwise or without an OTX report (the link says "named in the same report", nothing else);
    #       not judged while there is none.
    r = _one(
        "MATCH (i:Indicator)-[r:INDICATES]->(c:CVE) "
        "WITH r, c, i, " + _as_list("r.source_refs") + " AS refs "
        "RETURN count(r) AS indicator_cve_links, count(DISTINCT c) AS cves, count(DISTINCT i) AS indicators, "
        "sum(CASE WHEN r.match_type = 'otx_pulse' THEN 0 ELSE 1 END) AS not_otx_pulse, "
        "sum(CASE WHEN any(x IN refs WHERE x STARTS WITH 'alienvault_otx:') THEN 0 ELSE 1 END) AS without_otx_report"
    )
    r.update(
        _one(
            "MATCH (:Indicator)-[r:INDICATES]->(x) WHERE NOT x:Malware AND NOT x:CVE "
            "RETURN count(r) AS indicates_other_targets"
        )
    )
    rep.add("indicator_cve_report_links", None, dict(r))
    links = r.get("indicator_cve_links") or 0
    rep.add(
        "indicator_cve_links_are_same_report",
        None if links == 0 else (r.get("not_otx_pulse") or 0) == 0 and (r.get("without_otx_report") or 0) == 0,
        {k: r.get(k) for k in ("indicator_cve_links", "not_otx_pulse", "without_otx_report")},
    )

    # 10a5. Malware twins folded (2026-10): no Malware node from another source is named after an
    #       ATT&CK software id ("cobalt strike - s0154", the MISP galaxy naming OTX uses), or carries
    #       such an alias of its own name, when a MITRE Malware node of that id (read from the record
    #       MITRE delivered) or of that base name exists, or, for software without one (an ATT&CK
    #       tool), when a node of its base name exists: the enrichment job ``merge_malware_attack_twins``
    #       folds it into that node. The decision is the job's own (``attack_software_names.
    #       plan_twin_folds``), so a twin the job leaves (no such node) is reported, not failed; an
    #       ambiguous one fails (a decision is needed).
    twins = _post(
        "MATCH (d:Malware) WHERE d.name IS NOT NULL AND NOT 'mitre_attck' IN coalesce(d.source, []) "
        "WITH d, CASE WHEN d.aliases IS NULL THEN [] "
        "WHEN apoc.meta.cypher.type(d.aliases) STARTS WITH 'LIST' THEN d.aliases ELSE [d.aliases] END AS aliases "
        "WHERE d.name =~ $suffixed OR any(x IN aliases WHERE toString(x) =~ $suffixed) "
        "RETURN d.name AS name, aliases",
        {"suffixed": CYPHER_SUFFIXED_NAME},
    )
    attack_ids: Dict[str, Optional[str]] = {}
    if twins:
        for row in _post(
            "MATCH (c:Malware) WHERE 'mitre_attck' IN coalesce(c.source, []) "
            "OPTIONAL MATCH (c)-[sf:SOURCED_FROM]->(:Source {source_id: 'mitre_attck'}) "
            "WITH c, head(collect(sf.raw_data)) AS attack_raw RETURN c.name AS name, attack_raw"
        ):
            if row.get("name"):
                attack_ids[row["name"]] = attack_software_id(row.get("attack_raw"), row["name"])
    bases = twin_base_names(twins)
    base_nodes: Dict[str, Any] = {}
    if bases:
        for row in _post(CYPHER_BASE_NODES_READ, {"bases": bases, "mitre_source": "mitre_attck"}):
            if row.get("name"):
                base_nodes[row["name"]] = row.get("aliases")
    rep.add("malware_attack_twins_folded", *_malware_twin_verdict(twins, attack_ids, revoked.software, base_nodes))

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
    _sector_evidence_checks(rep, require_cisa_ics, require_otx_industries)

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
        # 2026-10-16: the per-source zones of a SOURCED_FROM edge (step 7 reads them with ``IN``)
        "OR (r.zones IS NOT NULL AND NOT apoc.meta.cypher.type(r.zones) STARTS WITH 'LIST') "
        "OR (r.stated_zones IS NOT NULL AND NOT apoc.meta.cypher.type(r.stated_zones) STARTS WITH 'LIST') "
        "OR (r.stated_refs IS NOT NULL AND NOT apoc.meta.cypher.type(r.stated_refs) STARTS WITH 'LIST') "
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
    #      The pulses naming several actors are step 2d's: those whose actor nodes are several actors
    #      and those the OTX collector marked on indicators (``several_actor_reports``).
    #      Informational without the reference (the aliases of one actor cannot be told apart), without
    #      a same-pulse attribution, and when neither an actor records a pulse nor an indicator a mark:
    #      a pass there would be vacuous.
    try:
        actor_reference = load_canonical_reference()
    except ReferenceUnavailable as exc:
        actor_reference = None
        reference_error = str(exc)
    report_actors = _one(REPORT_ACTORS_QUERY)
    marked = _one(INDICATOR_MARKED_REPORTS_QUERY)
    several = several_actor_reports(report_actors.get("reports") or [], marked.get("pulses") or [], actor_reference)
    r = _one(
        ATTRIBUTION_CHECK_QUERY,
        {"several": several, "otx_ref_prefix": OTX_REPORT_REF_PREFIX, "feeds": list(REPORT_ATTRIBUTION_FEEDS)},
    )
    r["reports_naming_several_actors"] = len(several)
    r["pulses_recorded_on_actors"] = report_actors.get("pulses") or 0
    r["pulses_marked_on_indicators"] = len(marked.get("pulses") or [])
    if actor_reference is None:
        r["reference"] = f"unavailable ({reference_error})"
        attribution_ok = None
    elif not r.get("links"):
        # No same-pulse attribution: nothing to judge (2026-10; it passed as mandatory before).
        r["reference"] = actor_reference.version
        attribution_ok = None
    elif not r["pulses_recorded_on_actors"] and not r["pulses_marked_on_indicators"]:
        # No actor records a pulse and no indicator a mark: there is nothing to judge.
        r["reference"] = actor_reference.version
        attribution_ok = None
    else:
        r["reference"] = actor_reference.version
        attribution_ok = not r.get("resting_on_several_actor_reports") and not r.get("naming_several_actor_reports")
    rep.add("attribution_from_single_actor_reports", attribution_ok, r)

    # 13c. Campaign membership follows the evidence (2026-10): a malware is part of a campaign only
    #      while it is attributed to the campaign's actor or (2026-10-16) used by it
    #      (``campaign_evidence``; build_campaign_nodes step 2b prunes the rest). Named
    #      ``campaign_malware_attributed`` until 2026-10-16, when it read ATTRIBUTED_TO only.
    r = _one(MALWARE_MEMBERSHIP_CHECK_QUERY)
    rep.add("campaign_malware_has_evidence", None if not r.get("malware_links") else r.get("without_evidence") == 0, r)

    # 13d. No campaign without evidence (2026-10-16): every campaign EdgeGuard built has an actor with
    #      an ATTRIBUTED_TO or USES_MALWARE link (build_campaign_nodes step 1b deletes the others)
    #      and that actor's RUNS, and no RUNS comes from an actor that is not the campaign's or has
    #      neither link (step 2c removes it). Informational while there is no campaign EdgeGuard built
    #      and no RUNS without evidence: a RUNS without evidence into any campaign (a partner's or one
    #      written before) fails even on a graph without EdgeGuard campaigns.
    r = _one(CAMPAIGN_EVIDENCE_CHECK_QUERY)
    defects = ("without_evidence", "without_runs", "runs_without_evidence")
    judged = r.get("campaigns") or r.get("runs_without_evidence")
    rep.add("campaigns_have_evidence", all(r.get(k) == 0 for k in defects) if judged else None, r)

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

    # 16. Ranked descriptions and indicator aging (2026-10-16).
    _ranked_description_and_aging_checks(rep)
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
    ap.add_argument(
        "--require-otx-industries",
        action="store_true",
        help="fail if OTX records give sectors but none states one (the pulses' industries did not reach the sync)",
    )
    args = ap.parse_args()

    try:
        url = neo4j_http_endpoint.query_api_url()
    except neo4j_http_endpoint.Neo4jHttpEndpointError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        rep = run_checks(
            args.require_ics, args.require_cisa_ics, args.require_malwarebazaar, args.require_otx_industries
        )
    except (urllib.error.URLError, OSError, RuntimeError) as exc:
        print(f"ERROR: cannot query {url}: {exc}", file=sys.stderr)
        return 2

    result = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "url": url,
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
