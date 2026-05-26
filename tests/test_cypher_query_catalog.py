#!/usr/bin/env python3
"""
EdgeGuard — Cypher query catalog & validation harness.

A data-driven catalog of read-only Cypher queries spanning BOTH graph layers:

  * threat_intel — Indicator / CVE / Vulnerability / CVSSv* / Malware /
    ThreatActor / Technique / Tactic / Tool / Sector / Campaign / Alert / Source
  * asset        — ResilMesh / ISIM topology: Host / Device / IP / Subnet /
    NetworkService / SoftwareVersion / Application / Role / User / Component /
    Mission / OrganizationUnit / MissionDependency / Node

Each query is verified two independent ways against a live Neo4j:

  1. VALIDITY (``test_query_is_valid``) — always runs, even on an EMPTY db. The
     query is sent with an ``EXPLAIN`` prefix straight to a raw driver session so
     Neo4j parses + plans it. Any CypherSyntaxError / ClientError (bad syntax,
     unknown procedure, …) raises and FAILS the test. This proves the query is a
     *valid combination* against the real schema.

     NB: we deliberately bypass ``Neo4jClient.run()`` here — it swallows
     ``CypherSyntaxError`` and returns ``[]`` (src/neo4j_client.py:1160), which
     would hide an invalid query behind an empty result set.

  2. ROW PRESENCE (``test_query_returns_rows``) — data-aware. The query is
     executed; if it returns >=1 row the projected column aliases are asserted;
     if it returns 0 rows the test SKIPS (that slice of the graph isn't populated
     in this db — e.g. the asset layer before any topology ingest, or a fresh
     baseline that writes :CVE rather than the legacy :Vulnerability label).

If Neo4j is unreachable the whole module skips (mirrors
tests/test_resilmesh_integration.py), so this is CI-safe.

Schema is the source of truth, verified 2026-05-25 against
``src/neo4j_client.py`` (``create_constraints`` + every ``merge_*``) and the 12
link steps in ``src/build_relationships.py``. See also docs/KNOWLEDGE_GRAPH.md
and docs/NEO4J_SAMPLE_QUERIES.md.

Run as a suite:        pytest tests/test_cypher_query_catalog.py -v
Run as a live report:  python tests/test_cypher_query_catalog.py

Against the Cloudflare-fronted edgeguard.org DB (Bolt-over-TCP blocked), tunnel
the driver through Bolt-over-WebSocket by setting NEO4J_WSS_HOST:
  set -a; source .env; source .env.edgeguard; set +a
  MISP_API_KEY=unused NEO4J_WSS_HOST=neo4j-bolt.edgeguard.org \
    pytest tests/test_cypher_query_catalog.py -q
"""

import os
import sys
from dataclasses import dataclass, field
from typing import Dict, Tuple

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))


# --------------------------------------------------------------------------- #
# Connectivity (mirrors tests/test_resilmesh_integration.py's skip-if-absent
# contract, but connects only ONCE — the module-scoped fixture below caches it)
# --------------------------------------------------------------------------- #
_SKIP_MSG = "Neo4j not available (integration test)"


# --------------------------------------------------------------------------- #
# Catalog model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CatalogQuery:
    """One read-only Cypher query plus how to test it.

    id          stable kebab-case identifier (used as the pytest parametrize id)
    layer       "schema" | "threat_intel" | "asset"
    title       human-readable one-liner
    cypher      the query (every projection aliased with AS so result keys are stable)
    params      query parameters (always passed to EXPLAIN + run)
    expect_rows when True, test_query_returns_rows runs (and skips on 0 rows)
    expect_keys result column aliases asserted present when rows are returned
    """

    id: str
    layer: str
    title: str
    cypher: str
    params: Dict = field(default_factory=dict)
    expect_rows: bool = True
    expect_keys: Tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# 0. Schema / overview
# --------------------------------------------------------------------------- #
_SCHEMA = [
    CatalogQuery(
        "schema-node-counts",
        "schema",
        "Count nodes by primary label",
        "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC",
        expect_keys=("label", "count"),
    ),
    CatalogQuery(
        "schema-rel-counts",
        "schema",
        "Count relationships by type",
        "MATCH ()-[r]->() RETURN type(r) AS rel_type, count(r) AS count ORDER BY count DESC",
        expect_keys=("rel_type", "count"),
    ),
    CatalogQuery(
        "schema-zone-counts",
        "schema",
        "Count zoned nodes by sector",
        "MATCH (n) WHERE n.zone IS NOT NULL UNWIND n.zone AS zone RETURN zone, count(n) AS count ORDER BY count DESC",
        expect_keys=("zone", "count"),
    ),
    CatalogQuery(
        "schema-labels",
        "schema",
        "List label tokens present in the db",
        "CALL db.labels() YIELD label RETURN label ORDER BY label",
        expect_keys=("label",),
    ),
    CatalogQuery(
        "schema-rel-types",
        "schema",
        "List relationship-type tokens present in the db",
        "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType ORDER BY relationshipType",
        expect_keys=("relationshipType",),
    ),
]

# --------------------------------------------------------------------------- #
# 1. Threat-intel — single node (label + real properties)
# --------------------------------------------------------------------------- #
_TI_NODES = [
    CatalogQuery(
        "ti-indicator",
        "threat_intel",
        "Indicators with type/confidence/zone",
        "MATCH (i:Indicator) "
        "RETURN i.value AS value, i.indicator_type AS type, "
        "i.confidence_score AS confidence, i.zone AS zone LIMIT 10",
        expect_keys=("value", "type"),
    ),
    CatalogQuery(
        "ti-indicator-by-type",
        "threat_intel",
        "Indicators of a given type (parameterized)",
        "MATCH (i:Indicator {indicator_type: $indicator_type}) "
        "RETURN i.value AS value, i.confidence_score AS confidence LIMIT 10",
        params={"indicator_type": "domain"},
        expect_keys=("value",),
    ),
    CatalogQuery(
        "ti-indicator-suspicious-ip",
        "threat_intel",
        "IPv4 indicators above a confidence floor",
        "MATCH (i:Indicator {indicator_type: 'ipv4'}) WHERE i.confidence_score > 0.5 "
        "RETURN i.value AS value, i.confidence_score AS confidence "
        "ORDER BY i.confidence_score DESC LIMIT 10",
        expect_keys=("value",),
    ),
    CatalogQuery(
        "ti-indicator-zone",
        "threat_intel",
        "Healthcare-zoned indicators (portable zone filter)",
        "MATCH (i:Indicator) WHERE 'healthcare' IN coalesce(i.zone, []) "
        "RETURN i.value AS value, i.indicator_type AS type LIMIT 10",
        expect_keys=("value",),
    ),
    CatalogQuery(
        "ti-cve",
        "threat_intel",
        "CVE nodes (production-primary vuln label)",
        "MATCH (c:CVE) RETURN c.cve_id AS cve, c.cvss_score AS cvss, c.severity AS severity LIMIT 10",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-cve-critical",
        "threat_intel",
        "Critical CVEs (cvss_score >= 9.0)",
        "MATCH (c:CVE) WHERE c.cvss_score >= 9.0 "
        "RETURN c.cve_id AS cve, c.cvss_score AS cvss ORDER BY c.cvss_score DESC LIMIT 20",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-cve-kev",
        "threat_intel",
        "CVEs on the CISA KEV list",
        "MATCH (c:CVE) WHERE c.cisa_exploit_add IS NOT NULL "
        "RETURN c.cve_id AS cve, c.cisa_vulnerability_name AS name LIMIT 10",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-vulnerability-legacy",
        "threat_intel",
        "Legacy :Vulnerability nodes (skips on CVE-only baselines)",
        "MATCH (v:Vulnerability) RETURN v.cve_id AS cve, v.cvss_score AS cvss LIMIT 10",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-cve-or-vulnerability",
        "threat_intel",
        "Both vuln labels in one match (portable)",
        "MATCH (v) WHERE v:CVE OR v:Vulnerability RETURN labels(v) AS labels, v.cve_id AS cve LIMIT 10",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-cvss31",
        "threat_intel",
        "CVSS v3.1 sub-nodes (base_score/base_severity)",
        "MATCH (n:CVSSv31) RETURN n.cve_id AS cve, n.base_score AS base_score, n.base_severity AS severity LIMIT 10",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-cvss40",
        "threat_intel",
        "CVSS v4.0 sub-nodes",
        "MATCH (n:CVSSv40) RETURN n.cve_id AS cve, n.base_score AS base_score, n.base_severity AS severity LIMIT 10",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-cvss30",
        "threat_intel",
        "CVSS v3.0 sub-nodes",
        "MATCH (n:CVSSv30) RETURN n.cve_id AS cve, n.base_score AS base_score, n.base_severity AS severity LIMIT 10",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-cvss2",
        "threat_intel",
        "CVSS v2 sub-nodes (skips when NVD supplied no v2 metrics)",
        "MATCH (n:CVSSv2) RETURN n.cve_id AS cve, n.base_score AS base_score LIMIT 10",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-malware",
        "threat_intel",
        "Malware families with aliases",
        "MATCH (m:Malware) RETURN m.name AS name, m.aliases AS aliases LIMIT 10",
        expect_keys=("name",),
    ),
    CatalogQuery(
        "ti-actor",
        "threat_intel",
        "Threat actors with aliases",
        "MATCH (a:ThreatActor) RETURN a.name AS name, a.aliases AS aliases LIMIT 10",
        expect_keys=("name",),
    ),
    CatalogQuery(
        "ti-actor-multisource",
        "threat_intel",
        "Actors merged from >1 source (provenance array)",
        "MATCH (a:ThreatActor) WHERE size(coalesce(a.source, [])) > 1 "
        "RETURN a.name AS name, a.source AS sources ORDER BY size(a.source) DESC LIMIT 20",
        expect_keys=("name",),
    ),
    CatalogQuery(
        "ti-technique",
        "threat_intel",
        "MITRE techniques (tactic_phases, NOT platforms)",
        "MATCH (t:Technique) RETURN t.mitre_id AS mitre_id, t.name AS name, t.tactic_phases AS phases LIMIT 10",
        expect_keys=("mitre_id",),
    ),
    CatalogQuery(
        "ti-technique-by-phase",
        "threat_intel",
        "Techniques in a kill-chain phase (parameterized)",
        "MATCH (t:Technique) WHERE $phase IN coalesce(t.tactic_phases, []) "
        "RETURN t.mitre_id AS mitre_id, t.name AS name LIMIT 20",
        params={"phase": "lateral-movement"},
        expect_keys=("mitre_id",),
    ),
    CatalogQuery(
        "ti-tactic",
        "threat_intel",
        "MITRE tactics (14 fixed nodes)",
        "MATCH (t:Tactic) RETURN t.mitre_id AS mitre_id, t.shortname AS shortname, "
        "t.name AS name ORDER BY t.mitre_id LIMIT 20",
        expect_keys=("mitre_id",),
    ),
    CatalogQuery(
        "ti-tool",
        "threat_intel",
        "MITRE tools",
        "MATCH (t:Tool) RETURN t.mitre_id AS mitre_id, t.name AS name LIMIT 10",
        expect_keys=("mitre_id",),
    ),
    CatalogQuery(
        "ti-sector",
        "threat_intel",
        "Sector nodes",
        "MATCH (s:Sector) RETURN s.name AS name ORDER BY s.name",
        expect_keys=("name",),
    ),
    CatalogQuery(
        "ti-source",
        "threat_intel",
        "Source provenance nodes",
        "MATCH (s:Source) RETURN s.source_id AS source_id, s.name AS name, "
        "s.reliability AS reliability ORDER BY s.source_id LIMIT 50",
        expect_keys=("source_id",),
    ),
    CatalogQuery(
        "ti-campaign",
        "threat_intel",
        "Campaign nodes (enrichment-derived)",
        "MATCH (c:Campaign) RETURN c.name AS name, c.zone AS zone LIMIT 10",
        expect_keys=("name",),
    ),
    CatalogQuery(
        "ti-alert",
        "threat_intel",
        "Alert nodes",
        "MATCH (a:Alert) RETURN a.alert_id AS alert_id LIMIT 10",
        expect_keys=("alert_id",),
    ),
]

# --------------------------------------------------------------------------- #
# 2. Threat-intel — 1-hop edges (directed; direction matters here)
# --------------------------------------------------------------------------- #
_TI_HOPS = [
    CatalogQuery(
        "ti-sourced-from",
        "threat_intel",
        "(n)-[:SOURCED_FROM]->(Source) provenance fan-in",
        "MATCH (n)-[:SOURCED_FROM]->(s:Source) RETURN s.name AS source, count(n) AS nodes ORDER BY nodes DESC LIMIT 20",
        expect_keys=("source", "nodes"),
    ),
    CatalogQuery(
        "ti-exploits-cve",
        "threat_intel",
        "(Indicator)-[:EXPLOITS]->(CVE)",
        "MATCH (i:Indicator)-[:EXPLOITS]->(c:CVE) RETURN i.value AS indicator, c.cve_id AS cve LIMIT 10",
        expect_keys=("indicator", "cve"),
    ),
    CatalogQuery(
        "ti-exploits-vuln",
        "threat_intel",
        "(Indicator)-[:EXPLOITS]->(Vulnerability) [legacy]",
        "MATCH (i:Indicator)-[:EXPLOITS]->(v:Vulnerability) RETURN i.value AS indicator, v.cve_id AS cve LIMIT 10",
        expect_keys=("indicator", "cve"),
    ),
    CatalogQuery(
        "ti-indicates",
        "threat_intel",
        "(Indicator)-[:INDICATES]->(Malware)",
        "MATCH (i:Indicator)-[r:INDICATES]->(m:Malware) "
        "RETURN i.value AS indicator, m.name AS malware, r.confidence_score AS confidence LIMIT 10",
        expect_keys=("indicator", "malware"),
    ),
    CatalogQuery(
        "ti-attributed",
        "threat_intel",
        "(Malware)-[:ATTRIBUTED_TO]->(ThreatActor)",
        "MATCH (m:Malware)-[:ATTRIBUTED_TO]->(a:ThreatActor) RETURN m.name AS malware, a.name AS actor LIMIT 10",
        expect_keys=("malware", "actor"),
    ),
    CatalogQuery(
        "ti-employs",
        "threat_intel",
        "(ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique) [attribution]",
        "MATCH (a:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t:Technique) "
        "RETURN a.name AS actor, t.mitre_id AS mitre_id, t.name AS technique LIMIT 10",
        expect_keys=("actor", "mitre_id"),
    ),
    CatalogQuery(
        "ti-implements",
        "threat_intel",
        "(Malware)-[:IMPLEMENTS_TECHNIQUE]->(Technique) [capability]",
        "MATCH (m:Malware)-[r:IMPLEMENTS_TECHNIQUE]->(t:Technique) "
        "RETURN m.name AS malware, t.mitre_id AS mitre_id, r.confidence_score AS confidence LIMIT 10",
        expect_keys=("malware", "mitre_id"),
    ),
    CatalogQuery(
        "ti-tool-implements",
        "threat_intel",
        "(Tool)-[:IMPLEMENTS_TECHNIQUE]->(Technique)",
        "MATCH (tool:Tool)-[:IMPLEMENTS_TECHNIQUE]->(t:Technique) "
        "RETURN tool.name AS tool, t.mitre_id AS mitre_id LIMIT 10",
        expect_keys=("tool", "mitre_id"),
    ),
    CatalogQuery(
        "ti-uses-technique",
        "threat_intel",
        "(Indicator)-[:USES_TECHNIQUE]->(Technique) [OTX attack_ids]",
        "MATCH (i:Indicator)-[:USES_TECHNIQUE]->(t:Technique) "
        "RETURN i.value AS indicator, t.mitre_id AS mitre_id LIMIT 10",
        expect_keys=("indicator", "mitre_id"),
    ),
    CatalogQuery(
        "ti-in-tactic",
        "threat_intel",
        "(Technique)-[:IN_TACTIC]->(Tactic)",
        "MATCH (t:Technique)-[:IN_TACTIC]->(tc:Tactic) RETURN t.mitre_id AS technique, tc.shortname AS tactic LIMIT 10",
        expect_keys=("technique", "tactic"),
    ),
    CatalogQuery(
        "ti-targets",
        "threat_intel",
        "(Indicator)-[:TARGETS]->(Sector) breakdown",
        "MATCH (i:Indicator)-[:TARGETS]->(s:Sector) "
        "RETURN s.name AS sector, count(i) AS indicators ORDER BY indicators DESC",
        expect_keys=("sector", "indicators"),
    ),
    CatalogQuery(
        "ti-affects",
        "threat_intel",
        "(CVE|Vulnerability)-[:AFFECTS]->(Sector) breakdown",
        "MATCH (v)-[:AFFECTS]->(s:Sector) WHERE v:CVE OR v:Vulnerability "
        "RETURN s.name AS sector, count(v) AS vulns ORDER BY vulns DESC",
        expect_keys=("sector", "vulns"),
    ),
    CatalogQuery(
        "ti-has-cvss",
        "threat_intel",
        "(CVE)-[:HAS_CVSS_v31]-(CVSSv31) [edge is bidirectional → undirected]",
        "MATCH (c:CVE)-[:HAS_CVSS_v31]-(n:CVSSv31) RETURN c.cve_id AS cve, n.base_score AS base_score LIMIT 10",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-has-cvss-v40",
        "threat_intel",
        "(CVE)-[:HAS_CVSS_v40]-(CVSSv40) [bidirectional → undirected]",
        "MATCH (c:CVE)-[:HAS_CVSS_v40]-(n:CVSSv40) RETURN c.cve_id AS cve, n.base_score AS base_score LIMIT 10",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-has-cvss-v30",
        "threat_intel",
        "(CVE)-[:HAS_CVSS_v30]-(CVSSv30) [bidirectional → undirected]",
        "MATCH (c:CVE)-[:HAS_CVSS_v30]-(n:CVSSv30) RETURN c.cve_id AS cve, n.base_score AS base_score LIMIT 10",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-has-cvss-v2",
        "threat_intel",
        "(CVE)-[:HAS_CVSS_v2]-(CVSSv2) [bidirectional → undirected]",
        "MATCH (c:CVE)-[:HAS_CVSS_v2]-(n:CVSSv2) RETURN c.cve_id AS cve LIMIT 10",
        expect_keys=("cve",),
    ),
    CatalogQuery(
        "ti-alert-involves",
        "threat_intel",
        "(Alert)-[:INVOLVES]->(Indicator)",
        "MATCH (a:Alert)-[:INVOLVES]->(i:Indicator) RETURN a.alert_id AS alert, i.value AS indicator LIMIT 10",
        expect_keys=("alert", "indicator"),
    ),
]

# --------------------------------------------------------------------------- #
# 3. Threat-intel — multi-hop traversals
# --------------------------------------------------------------------------- #
_TI_PATHS = [
    CatalogQuery(
        "ti-chain-attribution",
        "threat_intel",
        "Indicator → Malware → ThreatActor",
        "MATCH (i:Indicator)-[:INDICATES]->(m:Malware)-[:ATTRIBUTED_TO]->(a:ThreatActor) "
        "RETURN i.value AS indicator, m.name AS malware, a.name AS actor LIMIT 10",
        expect_keys=("indicator", "malware", "actor"),
    ),
    CatalogQuery(
        "ti-chain-4hop",
        "threat_intel",
        "Indicator → Malware → ThreatActor → Technique",
        "MATCH (i:Indicator)-[:INDICATES]->(m:Malware)-[:ATTRIBUTED_TO]->(a:ThreatActor)"
        "-[:EMPLOYS_TECHNIQUE]->(t:Technique) "
        "RETURN i.value AS indicator, m.name AS malware, a.name AS actor, "
        "t.mitre_id AS technique LIMIT 10",
        expect_keys=("indicator", "actor", "technique"),
    ),
    CatalogQuery(
        "ti-cve-cvss-exploit",
        "threat_intel",
        "Indicator → CVE with optional CVSS v3.1 score",
        "MATCH (i:Indicator)-[:EXPLOITS]->(c:CVE) "
        "OPTIONAL MATCH (c)-[:HAS_CVSS_v31]-(cvss:CVSSv31) "
        "RETURN i.value AS indicator, c.cve_id AS cve, cvss.base_score AS cvss_score "
        "ORDER BY cvss.base_score DESC LIMIT 15",
        expect_keys=("indicator", "cve"),
    ),
    CatalogQuery(
        "ti-actor-deepdive",
        "threat_intel",
        "All edges around one actor (parameterized)",
        "MATCH (a:ThreatActor {name: $name})-[r]-(x) "
        "RETURN type(r) AS rel, labels(x)[0] AS label, count(*) AS count ORDER BY count DESC",
        params={"name": "apt41"},
        expect_keys=("rel", "label", "count"),
    ),
    CatalogQuery(
        "ti-actor-tech-coverage",
        "threat_intel",
        "Actors ranked by technique count",
        "MATCH (a:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t:Technique) "
        "RETURN a.name AS actor, count(t) AS techniques ORDER BY techniques DESC LIMIT 10",
        expect_keys=("actor", "techniques"),
    ),
    CatalogQuery(
        "ti-cross-sector",
        "threat_intel",
        "Actors operating in BOTH healthcare and energy",
        "MATCH (a:ThreatActor) WHERE 'healthcare' IN coalesce(a.zone, []) "
        "AND 'energy' IN coalesce(a.zone, []) "
        "RETURN a.name AS actor, a.zone AS zones LIMIT 20",
        expect_keys=("actor", "zones"),
    ),
    CatalogQuery(
        "ti-malware-tech-via-actor",
        "threat_intel",
        "Malware → (actor) → techniques",
        "MATCH (m:Malware)-[:ATTRIBUTED_TO]->(a:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t:Technique) "
        "RETURN m.name AS malware, a.name AS actor, collect(DISTINCT t.name)[..5] AS techniques LIMIT 15",
        expect_keys=("malware", "actor"),
    ),
    CatalogQuery(
        "ti-provenance",
        "threat_intel",
        "INDICATES edges carrying MISP-event provenance",
        "MATCH (i:Indicator)-[r:INDICATES]->(m:Malware) "
        "WHERE size(coalesce(r.misp_event_ids, [])) > 0 "
        "RETURN i.value AS indicator, m.name AS malware, size(r.misp_event_ids) AS misp_events "
        "ORDER BY misp_events DESC LIMIT 10",
        expect_keys=("indicator", "misp_events"),
    ),
]

# --------------------------------------------------------------------------- #
# 4. Asset / ISIM topology — single node
# --------------------------------------------------------------------------- #
_ASSET_NODES = [
    CatalogQuery(
        "as-host",
        "asset",
        "Host nodes",
        "MATCH (h:Host) RETURN h.hostname AS hostname LIMIT 10",
        expect_keys=("hostname",),
    ),
    CatalogQuery(
        "as-device",
        "asset",
        "Device nodes",
        "MATCH (d:Device) RETURN d.device_id AS device_id LIMIT 10",
        expect_keys=("device_id",),
    ),
    CatalogQuery(
        "as-ip", "asset", "IP nodes", "MATCH (i:IP) RETURN i.address AS address LIMIT 10", expect_keys=("address",)
    ),
    CatalogQuery(
        "as-subnet",
        "asset",
        "Subnet nodes",
        "MATCH (s:Subnet) RETURN s.range AS range LIMIT 10",
        expect_keys=("range",),
    ),
    CatalogQuery(
        "as-networkservice",
        "asset",
        "NetworkService nodes (port, protocol)",
        "MATCH (n:NetworkService) RETURN n.port AS port, n.protocol AS protocol LIMIT 10",
        expect_keys=("port", "protocol"),
    ),
    CatalogQuery(
        "as-softwareversion",
        "asset",
        "SoftwareVersion nodes",
        "MATCH (sv:SoftwareVersion) RETURN sv.version AS version LIMIT 10",
        expect_keys=("version",),
    ),
    CatalogQuery(
        "as-application",
        "asset",
        "Application nodes",
        "MATCH (a:Application) RETURN a.name AS name LIMIT 10",
        expect_keys=("name",),
    ),
    CatalogQuery(
        "as-role",
        "asset",
        "Role nodes (keyed by permission)",
        "MATCH (r:Role) RETURN r.permission AS permission LIMIT 10",
        expect_keys=("permission",),
    ),
    CatalogQuery(
        "as-user",
        "asset",
        "User nodes (username, domain)",
        "MATCH (u:User) RETURN u.username AS username, u.domain AS domain LIMIT 10",
        expect_keys=("username", "domain"),
    ),
    CatalogQuery(
        "as-component",
        "asset",
        "Component nodes",
        "MATCH (c:Component) RETURN c.name AS name LIMIT 10",
        expect_keys=("name",),
    ),
    CatalogQuery(
        "as-mission",
        "asset",
        "Mission nodes",
        "MATCH (m:Mission) RETURN m.name AS name LIMIT 10",
        expect_keys=("name",),
    ),
    CatalogQuery(
        "as-orgunit",
        "asset",
        "OrganizationUnit nodes",
        "MATCH (o:OrganizationUnit) RETURN o.name AS name LIMIT 10",
        expect_keys=("name",),
    ),
    CatalogQuery(
        "as-missiondependency",
        "asset",
        "MissionDependency nodes",
        "MATCH (md:MissionDependency) RETURN md.dependency_id AS dependency_id LIMIT 10",
        expect_keys=("dependency_id",),
    ),
    CatalogQuery(
        "as-node",
        "asset",
        "Node (ISIM topology) nodes",
        "MATCH (n:Node) RETURN n.node_id AS node_id LIMIT 10",
        expect_keys=("node_id",),
    ),
]

# --------------------------------------------------------------------------- #
# 5. Asset / ISIM topology — 1-hop edges
# (the asset graph writes most edges in BOTH directions, so match undirected)
# --------------------------------------------------------------------------- #
_ASSET_HOPS = [
    CatalogQuery(
        "as-sv-on-host",
        "asset",
        "(SoftwareVersion)-[:ON]-(Host)",
        "MATCH (sv:SoftwareVersion)-[:ON]-(h:Host) RETURN sv.version AS version, h.hostname AS hostname LIMIT 10",
        expect_keys=("version", "hostname"),
    ),
    CatalogQuery(
        "as-netservice-on-host",
        "asset",
        "(NetworkService)-[:ON]-(Host)",
        "MATCH (ns:NetworkService)-[:ON]-(h:Host) "
        "RETURN ns.port AS port, ns.protocol AS protocol, h.hostname AS hostname LIMIT 10",
        expect_keys=("hostname",),
    ),
    CatalogQuery(
        "as-device-host-identity",
        "asset",
        "(Device)-[:HAS_IDENTITY]-(Host)",
        "MATCH (d:Device)-[:HAS_IDENTITY]-(h:Host) RETURN d.device_id AS device_id, h.hostname AS hostname LIMIT 10",
        expect_keys=("device_id", "hostname"),
    ),
    CatalogQuery(
        "as-app-component-identity",
        "asset",
        "(Application)-[:HAS_IDENTITY]-(Component)",
        "MATCH (a:Application)-[:HAS_IDENTITY]-(c:Component) "
        "RETURN a.name AS application, c.name AS component LIMIT 10",
        expect_keys=("application", "component"),
    ),
    CatalogQuery(
        "as-ip-part-of-subnet",
        "asset",
        "(IP)-[:PART_OF]-(Subnet)",
        "MATCH (i:IP)-[:PART_OF]-(s:Subnet) RETURN i.address AS address, s.range AS subnet LIMIT 10",
        expect_keys=("address", "subnet"),
    ),
    CatalogQuery(
        "as-node-is-a-host",
        "asset",
        "(Node)-[:IS_A]-(Host)",
        "MATCH (n:Node)-[:IS_A]-(h:Host) RETURN n.node_id AS node_id, h.hostname AS hostname LIMIT 10",
        expect_keys=("node_id", "hostname"),
    ),
    CatalogQuery(
        "as-ip-has-assigned-node",
        "asset",
        "(IP)-[:HAS_ASSIGNED]-(Node)",
        "MATCH (i:IP)-[:HAS_ASSIGNED]-(n:Node) RETURN i.address AS address, n.node_id AS node_id LIMIT 10",
        expect_keys=("address", "node_id"),
    ),
    CatalogQuery(
        "as-node-connected",
        "asset",
        "(Node)-[:IS_CONNECTED_TO]-(Node)",
        "MATCH (n1:Node)-[:IS_CONNECTED_TO]-(n2:Node) RETURN n1.node_id AS node_a, n2.node_id AS node_b LIMIT 10",
        expect_keys=("node_a", "node_b"),
    ),
    CatalogQuery(
        "as-vuln-in-sv",
        "asset",
        "(CVE|Vulnerability)-[:IN]-(SoftwareVersion)",
        "MATCH (v)-[:IN]-(sv:SoftwareVersion) WHERE v:Vulnerability OR v:CVE "
        "RETURN v.cve_id AS cve, sv.version AS version LIMIT 10",
        expect_keys=("cve", "version"),
    ),
    CatalogQuery(
        "as-vuln-refers-cve",
        "asset",
        "(Vulnerability)-[:REFERS_TO]-(CVE)",
        "MATCH (v:Vulnerability)-[:REFERS_TO]-(c:CVE) RETURN v.cve_id AS vuln, c.cve_id AS cve LIMIT 10",
        expect_keys=("vuln", "cve"),
    ),
    CatalogQuery(
        "as-component-supports-mission",
        "asset",
        "(Component)-[:SUPPORTS]-(Mission)",
        "MATCH (c:Component)-[:SUPPORTS]-(m:Mission) RETURN c.name AS component, m.name AS mission LIMIT 10",
        expect_keys=("component", "mission"),
    ),
    CatalogQuery(
        "as-host-provided-by-component",
        "asset",
        "(Host)-[:PROVIDED_BY]-(Component)",
        "MATCH (h:Host)-[:PROVIDED_BY]-(c:Component) RETURN h.hostname AS hostname, c.name AS component LIMIT 10",
        expect_keys=("hostname", "component"),
    ),
    CatalogQuery(
        "as-mission-for-orgunit",
        "asset",
        "(Mission)-[:FOR]-(OrganizationUnit)",
        "MATCH (m:Mission)-[:FOR]-(o:OrganizationUnit) RETURN m.name AS mission, o.name AS org_unit LIMIT 10",
        expect_keys=("mission", "org_unit"),
    ),
    CatalogQuery(
        "as-component-missiondependency",
        "asset",
        "(Component)-[:TO|FROM]-(MissionDependency)",
        "MATCH (c:Component)-[:TO|FROM]-(md:MissionDependency) "
        "RETURN c.name AS component, md.dependency_id AS dependency LIMIT 10",
        expect_keys=("component", "dependency"),
    ),
    CatalogQuery(
        "as-role-assigned-user",
        "asset",
        "(Role)-[:ASSIGNED_TO]-(User)",
        "MATCH (r:Role)-[:ASSIGNED_TO]-(u:User) RETURN r.permission AS permission, u.username AS username LIMIT 10",
        expect_keys=("permission", "username"),
    ),
    CatalogQuery(
        "as-device-to-role",
        "asset",
        "(Device)-[:TO]-(Role)",
        "MATCH (d:Device)-[:TO]-(r:Role) RETURN d.device_id AS device_id, r.permission AS permission LIMIT 10",
        expect_keys=("device_id", "permission"),
    ),
]

QUERY_CATALOG = _SCHEMA + _TI_NODES + _TI_HOPS + _TI_PATHS + _ASSET_NODES + _ASSET_HOPS


# --------------------------------------------------------------------------- #
# Fixtures + helpers
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def neo4j_client():
    try:
        import config

        # Guard against MagicMock pollution from other test modules' stubs.
        if not hasattr(config, "NEO4J_URI") or not isinstance(config.NEO4J_URI, str):
            pytest.skip(_SKIP_MSG)
        from neo4j_client import Neo4jClient
    except ImportError:
        pytest.skip(_SKIP_MSG)

    # Bridge mode: when NEO4J_WSS_HOST is set, tunnel the Bolt driver through
    # Cloudflare's WebSocket (see scripts/neo4j_wss_bridge.py). Needed for the
    # edgeguard.org deployment, where raw Bolt-over-TCP is blocked but
    # Bolt-over-WebSocket (the Neo4j Browser transport) works. Auth comes from
    # NEO4J_USER / NEO4J_PASSWORD. Zero effect when the env var is unset.
    wss_host = os.getenv("NEO4J_WSS_HOST")
    if wss_host:
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
            from neo4j_wss_bridge import Neo4jWssBridge
        except ImportError:
            pytest.skip("NEO4J_WSS_HOST set but websocket-client/bridge unavailable")
        auth = (os.getenv("NEO4J_USER", "neo4j"), os.getenv("NEO4J_PASSWORD", ""))
        bridge = Neo4jWssBridge(wss_host, auth)
        try:
            driver = bridge.connect()
            driver.verify_connectivity()
        except Exception:
            bridge.close()
            pytest.skip(_SKIP_MSG)
        c = Neo4jClient()
        c.driver = driver  # inject the bridged driver; skip c.connect()'s direct dial
        yield c
        bridge.close()
        return

    c = Neo4jClient()
    try:
        connected = c.connect()
    except Exception:
        # connect() may raise (e.g. ServiceUnavailable after exhausting
        # retries) rather than return False when no server is reachable.
        connected = False
    if not connected:
        pytest.skip(_SKIP_MSG)
    yield c
    c.close()


def _explain(client, q: "CatalogQuery"):
    """Plan ``EXPLAIN <query>`` on a raw driver session so any
    CypherSyntaxError / ClientError propagates (unlike Neo4jClient.run, which
    swallows syntax errors). Returns the result summary."""
    with client.driver.session() as session:
        result = session.run("EXPLAIN " + q.cypher, q.params)
        return result.consume()


# --------------------------------------------------------------------------- #
# Catalog self-checks (run without a db)
# --------------------------------------------------------------------------- #
def test_catalog_ids_unique():
    ids = [q.id for q in QUERY_CATALOG]
    assert len(ids) == len(set(ids)), "duplicate catalog ids: " + str(sorted({i for i in ids if ids.count(i) > 1}))


def test_catalog_covers_both_layers():
    layers = {q.layer for q in QUERY_CATALOG}
    assert {"threat_intel", "asset"}.issubset(layers)


# --------------------------------------------------------------------------- #
# Tier 1 — VALIDITY (runs even on an empty db)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("q", QUERY_CATALOG, ids=[q.id for q in QUERY_CATALOG])
def test_query_is_valid(neo4j_client, q):
    """EXPLAIN must not raise — proves the query is a valid combination."""
    _explain(neo4j_client, q)


# --------------------------------------------------------------------------- #
# Tier 2 — ROW PRESENCE (skips when a graph slice isn't populated)
# --------------------------------------------------------------------------- #
_ROW_QUERIES = [q for q in QUERY_CATALOG if q.expect_rows]


@pytest.mark.parametrize("q", _ROW_QUERIES, ids=[q.id for q in _ROW_QUERIES])
def test_query_returns_rows(neo4j_client, q):
    rows = neo4j_client.run(q.cypher, q.params)
    if not rows:
        pytest.skip(f"{q.id}: 0 rows — graph slice not populated in this db")
    if q.expect_keys:
        missing = set(q.expect_keys) - set(rows[0].keys())
        assert not missing, f"{q.id}: missing result keys {missing}; got {list(rows[0].keys())}"


# --------------------------------------------------------------------------- #
# Schema-token sanity (skips on empty db)
# --------------------------------------------------------------------------- #
def test_core_threat_intel_tokens_present(neo4j_client):
    counts = neo4j_client.run("MATCH (n) RETURN count(n) AS c")
    if not counts or counts[0]["c"] == 0:
        pytest.skip("empty db — no tokens to assert")
    labels = {r["label"] for r in neo4j_client.run("CALL db.labels() YIELD label RETURN label")}
    assert "Indicator" in labels, "no :Indicator label — threat-intel ingest may have never run"
    # CVE is production-primary; Vulnerability is the legacy label. Either is acceptable.
    assert "CVE" in labels or "Vulnerability" in labels, (
        "neither :CVE nor :Vulnerability present — the CVE ingest path may be broken"
    )


# --------------------------------------------------------------------------- #
# Live report:  python tests/test_cypher_query_catalog.py
# --------------------------------------------------------------------------- #
def _print_report():
    from neo4j_client import Neo4jClient

    c = Neo4jClient()
    if not c.connect():
        print("Neo4j not reachable — set NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD and retry.")
        return
    try:
        print(f"{'id':36} {'layer':12} {'valid':5} {'rows':>6}  title")
        print("-" * 100)
        n_valid = n_fail = 0
        for q in QUERY_CATALOG:
            try:
                _explain(c, q)
                valid, n_valid = "OK", n_valid + 1
            except Exception as e:  # noqa: BLE001 — report mode, show everything
                valid, n_fail = "FAIL", n_fail + 1
                print(f"{q.id:36} {q.layer:12} {valid:5} {'-':>6}  {q.title}  <<< {type(e).__name__}: {e}")
                continue
            try:
                nrows = len(c.run(q.cypher, q.params))
            except Exception:  # noqa: BLE001
                nrows = -1
            print(f"{q.id:36} {q.layer:12} {valid:5} {nrows:>6}  {q.title}")
        print("-" * 100)
        print(f"{len(QUERY_CATALOG)} queries — {n_valid} valid, {n_fail} invalid")
    finally:
        c.close()


if __name__ == "__main__":
    _print_report()
