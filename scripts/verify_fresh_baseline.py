"""
Read-only acceptance check for a fresh EdgeGuard baseline (2026-10 PR).

Runs over the Neo4j **HTTP Query API v2** (same env vars as
``scripts/run_cypher_catalog_http.py``) so it works wherever plain HTTPS reaches
the database, including a Cloudflare-proxied endpoint that only speaks
Bolt-over-WebSocket. Nothing is written.

What it verifies (see docs/BASELINE_LAUNCH_CHECKLIST.md § "Fresh-baseline
acceptance"): the whole-event co-occurrence edges are gone, every technique edge
labelled ``mitre_explicit`` really comes from a MITRE-sourced node, the ResilMesh
CVE list properties are on the ``CVE`` node, the ATT&CK entries that the MISP
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

BASE = os.getenv("NEO4J_HTTP_URL", "https://neo4j.edgeguard.org").rstrip("/")
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
    "RUNS",
    "PART_OF",
    "REFERS_TO",
    "HAS_CVSS_v2",
    "HAS_CVSS_v30",
    "HAS_CVSS_v31",
    "HAS_CVSS_v40",
    "INVOLVES",
)
# Nodes that are not parsed from a MISP attribute never carry ``tlp``.
_NO_TLP_LABELS = ("Source", "Sector", "Campaign", "CVSSv2", "CVSSv30", "CVSSv31", "CVSSv40")
# ATT&CK entries whose names contain ": Windows " — the MISP Import Regexp rule
# rewrote them to ``%WINDIR%\`` before the 2026-10 fix, so they vanished.
_MANGLED_TECHNIQUES = ("T1047", "T1021.006", "T1543.003", "T1222.001", "T1546.003")
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


def run_checks(require_ics: bool, require_cisa_ics: bool) -> Report:
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
    r = _one(
        "MATCH (c:CVE) WHERE 'nvd' IN coalesce(c.source, []) RETURN count(c) AS n, "
        "sum(CASE WHEN c.cwe IS NOT NULL THEN 1 ELSE 0 END) AS cwe, "
        "sum(CASE WHEN c.ref_tags IS NOT NULL THEN 1 ELSE 0 END) AS ref_tags, "
        "sum(CASE WHEN c.cpe_type IS NOT NULL THEN 1 ELSE 0 END) AS cpe_type, "
        "sum(CASE WHEN c.result_impacts IS NOT NULL THEN 1 ELSE 0 END) AS result_impacts"
    )
    n = r.get("n") or 0
    ok = (
        n > 0
        and (r["cwe"] / n) >= 0.5
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
    rep.add("mangled_attack_entries_present", all(x["present"] for x in rows + tools), rows + tools)

    # 6. Actor names are clean.
    r = _one(
        "MATCH (a:ThreatActor) WHERE a.name CONTAINS ',' OR a.name CONTAINS ' and ' OR a.name CONTAINS ' & ' "
        "RETURN count(a) AS c, collect(a.name)[..10] AS examples"
    )
    rep.add("no_composite_actor_names", r.get("c") == 0, r)

    # 7. TLP on every node parsed from a MISP attribute.
    r = _one(
        "MATCH (n) WHERE n.edgeguard_managed = true AND none(l IN labels(n) WHERE l IN $skip) "
        "RETURN count(n) AS total, sum(CASE WHEN n.tlp IS NULL THEN 1 ELSE 0 END) AS missing",
        {"skip": list(_NO_TLP_LABELS)},
    )
    rep.add("tlp_on_every_node", (r.get("total") or 0) > 0 and r.get("missing") == 0, r)

    # 8. Ownership marker on every EdgeGuard node and edge.
    nodes = _post(
        "MATCH (n) WHERE n.edgeguard_managed IS NULL UNWIND labels(n) AS l RETURN l AS label, count(*) AS c ORDER BY c DESC"
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
    args = ap.parse_args()

    try:
        rep = run_checks(args.require_ics, args.require_cisa_ics)
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
