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
link only to ICS tactics, and the ResilMesh-facing schema is unchanged.

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
not reach Neo4j.
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
from typing import Any, Dict, List, Optional

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
        """``ok=None`` means informational (no pass/fail)."""
        self.checks.append({"check": name, "ok": ok, "mandatory": mandatory, "detail": detail})

    @property
    def failed(self) -> List[Dict[str, Any]]:
        return [c for c in self.checks if c["mandatory"] and c["ok"] is False]


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

    # 7. TLP on every node parsed from a MISP attribute.
    r = _one(
        "MATCH (n) WHERE n.edgeguard_managed = true AND any(l IN labels(n) WHERE l IN $labels) "
        "RETURN count(n) AS total, sum(CASE WHEN n.tlp IS NULL THEN 1 ELSE 0 END) AS missing",
        {"labels": list(_TLP_LABELS)},
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
            mark = "INFO" if c["ok"] is None else ("PASS" if c["ok"] else "FAIL")
            detail = json.dumps(c["detail"], default=str)
            print(f"[{mark}] {c['check']}: {detail[:300]}")
        print("\nRESULT:", "PASS" if result["passed"] else f"FAIL ({len(rep.failed)} mandatory check(s) failed)")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
