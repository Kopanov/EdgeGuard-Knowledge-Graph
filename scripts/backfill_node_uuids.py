#!/usr/bin/env python3
"""One-shot backfill: stamp deterministic n.uuid on every existing node and
r.src_uuid / r.trg_uuid on every existing edge.

Why a Python script (not a .cypher file)?
    UUIDv5 cannot be computed inside Cypher — APOC has only the random
    apoc.create.uuid (v4). To produce uuids that are identical on local AND
    cloud (the whole point of this PR), the computation must happen in Python
    via node_identity.compute_node_uuid, then be written back via UNWIND.

Idempotency
    Skips nodes whose uuid is already set; skips edges whose src_uuid AND
    trg_uuid are both already set. Safe to re-run after partial failure.

Resumability
    Per-label / per-edge-type batches with progress logging — a crash mid-run
    leaves a consistent partial state and the next run picks up where it
    stopped.

Usage
    # From the repo root, inside the project venv with NEO4J_* env vars set:
    python scripts/backfill_node_uuids.py --dry-run        # report counts only
    python scripts/backfill_node_uuids.py --labels Indicator,Vulnerability
    python scripts/backfill_node_uuids.py                  # all labels + edges

    # Per-label batch size (default 1000):
    python scripts/backfill_node_uuids.py --batch-size 500

    # Skip the edge backfill (run nodes first to validate, then edges):
    python scripts/backfill_node_uuids.py --nodes-only

Operator runbook
    See docs/MIGRATIONS.md → "n.uuid + edge endpoint uuids backfill (2026-04)".
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import Any, Dict, List, Tuple

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from neo4j_client import Neo4jClient, _validate_label, _validate_rel_type  # noqa: E402
from node_identity import (  # noqa: E402
    compute_node_uuid,
    natural_key_props,
    supported_labels,
)

logger = logging.getLogger("backfill_node_uuids")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# Edges to backfill — each entry: (rel_type, from_label, to_label).
# Edge backfill computes endpoint uuids by reading n.uuid off the connected
# nodes (after the node-uuid pass has populated them), so the natural-key map
# is not consulted here directly.
EDGES_TO_BACKFILL: List[Tuple[str, str, str]] = [
    # MISP-derived
    ("INDICATES", "Indicator", "Malware"),
    ("INDICATES", "Indicator", "Vulnerability"),
    ("INDICATES", "Indicator", "CVE"),
    ("EXPLOITS", "Indicator", "Vulnerability"),
    ("EXPLOITS", "Indicator", "CVE"),
    ("EMPLOYS_TECHNIQUE", "ThreatActor", "Technique"),
    ("EMPLOYS_TECHNIQUE", "Campaign", "Technique"),
    ("IMPLEMENTS_TECHNIQUE", "Malware", "Technique"),
    ("IMPLEMENTS_TECHNIQUE", "Tool", "Technique"),
    ("ATTRIBUTED_TO", "Malware", "ThreatActor"),
    ("USES_TECHNIQUE", "Indicator", "Technique"),
    ("TARGETS", "Indicator", "Sector"),
    ("TARGETS", "Vulnerability", "Sector"),
    ("TARGETS", "CVE", "Sector"),
    ("AFFECTS", "Vulnerability", "Sector"),
    ("AFFECTS", "CVE", "Sector"),
    ("IN_TACTIC", "Technique", "Tactic"),
    # CVE / CVSS sub-nodes
    ("HAS_CVSS_v2", "CVE", "CVSSv2"),
    ("HAS_CVSS_v30", "CVE", "CVSSv30"),
    ("HAS_CVSS_v31", "CVE", "CVSSv31"),
    ("HAS_CVSS_v40", "CVE", "CVSSv40"),
    ("HAS_CVSS_v2", "CVSSv2", "CVE"),
    ("HAS_CVSS_v30", "CVSSv30", "CVE"),
    ("HAS_CVSS_v31", "CVSSv31", "CVE"),
    ("HAS_CVSS_v40", "CVSSv40", "CVE"),
    # Source provenance
    ("SOURCED_FROM", "Indicator", "Source"),
    ("SOURCED_FROM", "Vulnerability", "Source"),
    ("SOURCED_FROM", "CVE", "Source"),
    ("SOURCED_FROM", "Malware", "Source"),
    ("SOURCED_FROM", "ThreatActor", "Source"),
    ("SOURCED_FROM", "Technique", "Source"),
    ("SOURCED_FROM", "Tactic", "Source"),
    ("SOURCED_FROM", "Tool", "Source"),
    # Enrichment-derived
    ("REFERS_TO", "Vulnerability", "CVE"),
    ("REFERS_TO", "CVE", "Vulnerability"),
    ("RUNS", "ThreatActor", "Campaign"),
    ("PART_OF", "Malware", "Campaign"),
    ("PART_OF", "Indicator", "Campaign"),
    # ResilMesh topology — added round 7 to close the gap that the topology
    # relationship helpers weren't stamping src_uuid/trg_uuid. Only the 11
    # helpers whose endpoints are both in _NATURAL_KEYS are listed here;
    # helpers involving User/Node/Component/Mission/OrganizationUnit/
    # MissionDependency endpoints stay uuid-less until those labels are
    # added to the natural-key map.
    ("ON", "SoftwareVersion", "Host"),
    ("ON", "Host", "SoftwareVersion"),
    ("ON", "NetworkService", "Host"),
    ("ON", "Host", "NetworkService"),
    ("TO", "Role", "Device"),
    ("TO", "Device", "Role"),
    ("HAS_IDENTITY", "Device", "Host"),
    ("HAS_IDENTITY", "Host", "Device"),
    ("PART_OF", "IP", "Subnet"),
    ("PART_OF", "Subnet", "IP"),
    ("PART_OF", "Subnet", "Subnet"),
]


# --------------------------------------------------------------------------- #
# Node backfill
# --------------------------------------------------------------------------- #


def count_null_uuid_nodes(client: Neo4jClient, label: str) -> int:
    # Bugbot (PR #33 round 8, LOW): label is interpolated into Cypher via
    # f-string. --labels comes from the CLI so the value is user-supplied;
    # validate before interpolation per the project's Cypher-injection rules.
    _validate_label(label)
    query = f"MATCH (n:{label}) WHERE n.uuid IS NULL OR n.uuid = '' RETURN count(n) AS c"
    with client.driver.session(default_access_mode="READ") as s:
        rec = s.run(query).single()
        return rec["c"] if rec else 0


def backfill_label(client: Neo4jClient, label: str, batch_size: int, dry_run: bool) -> int:
    """Backfill n.uuid for every node of the given label.

    Reads the configured natural-key props per node, computes the deterministic
    UUIDv5 in Python via node_identity.compute_node_uuid, and writes back via
    UNWIND in batches. Skips nodes that already have a uuid set.
    """
    # Bugbot (PR #33 round 8, LOW): validate before any f-string interpolation.
    _validate_label(label)
    try:
        key_fields = natural_key_props(label)
    except KeyError:
        logger.warning("Skipping %s: not in node_identity._NATURAL_KEYS map", label)
        return 0

    total = count_null_uuid_nodes(client, label)
    if total == 0:
        logger.info("%s: 0 nodes need backfill", label)
        return 0

    logger.info("%s: %d nodes need backfill (batch=%d, dry_run=%s)", label, total, batch_size, dry_run)
    if dry_run:
        return total

    # Load nodes in batches (read-only), compute uuids in Python, write back.
    fields_clause = ", ".join(f"n.{f} AS {f}" for f in key_fields)
    read_query = (
        f"MATCH (n:{label}) WHERE n.uuid IS NULL OR n.uuid = '' "
        f"WITH n LIMIT $limit "
        f"RETURN id(n) AS nid, {fields_clause}"
    )

    written = 0
    while True:
        with client.driver.session(default_access_mode="READ") as s:
            rows = list(s.run(read_query, limit=batch_size))
        if not rows:
            break

        payload: List[Dict[str, Any]] = []
        for r in rows:
            key_dict = {f: r.get(f) for f in key_fields}
            uuid_str = compute_node_uuid(label, key_dict)
            payload.append({"nid": r["nid"], "uuid": uuid_str})

        write_query = (
            f"UNWIND $rows AS row "
            f"MATCH (n) WHERE id(n) = row.nid AND n:{label} "
            f"  AND (n.uuid IS NULL OR n.uuid = '') "
            f"SET n.uuid = row.uuid"
        )
        with client.driver.session() as s:
            s.run(write_query, rows=payload)
        written += len(payload)
        logger.info("%s: wrote %d/%d", label, written, total)
        time.sleep(0.5)

    return written


# --------------------------------------------------------------------------- #
# Edge backfill — copy endpoint n.uuid into r.src_uuid / r.trg_uuid
# --------------------------------------------------------------------------- #


def backfill_edge(
    client: Neo4jClient,
    rel_type: str,
    from_label: str,
    to_label: str,
    batch_size: int,
    dry_run: bool,
) -> int:
    """Stamp r.src_uuid / r.trg_uuid on every edge of the given type by
    reading the endpoint nodes' n.uuid. Pure Cypher — no Python computation
    needed once nodes carry uuid."""
    # Bugbot (PR #33 round 8, LOW): all three values flow into f-string
    # Cypher; validate before interpolation.
    _validate_label(from_label)
    _validate_label(to_label)
    _validate_rel_type(rel_type)
    # Bugbot (PR #33 round 6, LOW): the count query and the update query MUST
    # share the same filter, otherwise "committed X / Y edges" reports X<Y on
    # every clean run (Y counts edges with NULL endpoint uuids that we cannot
    # update; X excludes them). An operator could misread that as a partial
    # failure and re-run.
    count_query = (
        f"MATCH (a:{from_label})-[r:{rel_type}]->(b:{to_label}) "
        f"WHERE (r.src_uuid IS NULL OR r.trg_uuid IS NULL) "
        f"  AND a.uuid IS NOT NULL AND b.uuid IS NOT NULL "
        f"RETURN count(r) AS c"
    )
    skipped_query = (
        f"MATCH (a:{from_label})-[r:{rel_type}]->(b:{to_label}) "
        f"WHERE (r.src_uuid IS NULL OR r.trg_uuid IS NULL) "
        f"  AND (a.uuid IS NULL OR b.uuid IS NULL) "
        f"RETURN count(r) AS c"
    )
    with client.driver.session(default_access_mode="READ") as s:
        rec = s.run(count_query).single()
        total = rec["c"] if rec else 0
        rec_skip = s.run(skipped_query).single()
        skipped = rec_skip["c"] if rec_skip else 0
    if total == 0 and skipped == 0:
        return 0

    if skipped > 0:
        logger.warning(
            "(%s)-[:%s]->(%s): %d edges have endpoint nodes without uuid — run node backfill for those labels first",
            from_label,
            rel_type,
            to_label,
            skipped,
        )
    logger.info("(%s)-[:%s]->(%s): %d edges need backfill", from_label, rel_type, to_label, total)
    if dry_run:
        return total

    # Bugbot (PR #33 round 8, HIGH): apoc.periodic.iterate forwards the outer
    # query's RETURN columns into the inner query as $-prefixed parameters.
    # The inner Cypher must rebind them as variables via WITH $col AS col
    # before referencing them — without the rebind, ``r``, ``a``, ``b`` in the
    # SET clause are unbound and the query fails with "Variable `r` not
    # defined". Same convention as every other apoc.periodic.iterate call in
    # this codebase (build_relationships.py, run_pipeline.py).
    update_query = f"""
    CALL apoc.periodic.iterate(
        'MATCH (a:{from_label})-[r:{rel_type}]->(b:{to_label})
         WHERE (r.src_uuid IS NULL OR r.trg_uuid IS NULL)
           AND a.uuid IS NOT NULL AND b.uuid IS NOT NULL
         RETURN r, a, b',
        'WITH $r AS r, $a AS a, $b AS b
         SET r.src_uuid = coalesce(r.src_uuid, a.uuid),
             r.trg_uuid = coalesce(r.trg_uuid, b.uuid)',
        {{batchSize: $batch, parallel: false}}
    )
    YIELD batches, total
    RETURN batches, total
    """
    with client.driver.session() as s:
        rec = s.run(update_query, batch=batch_size).single()
        committed = rec["total"] if rec else 0
    logger.info(
        "(%s)-[:%s]->(%s): committed %d / %d edges",
        from_label,
        rel_type,
        to_label,
        committed,
        total,
    )
    return committed


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--labels",
        type=str,
        default=None,
        help="Comma-separated subset of labels (default: all in supported_labels())",
    )
    ap.add_argument("--batch-size", type=int, default=1000)
    ap.add_argument("--dry-run", action="store_true", help="Count only, do not write")
    ap.add_argument("--nodes-only", action="store_true", help="Skip edge backfill")
    ap.add_argument("--edges-only", action="store_true", help="Skip node backfill")
    args = ap.parse_args()

    labels = [s.strip() for s in args.labels.split(",") if s.strip()] if args.labels else list(supported_labels())

    client = Neo4jClient()
    if not client.driver:
        logger.error("Neo4j driver not connected — check NEO4J_* env vars")
        return 2

    try:
        if not args.edges_only:
            logger.info("=== NODE BACKFILL ===")
            for label in labels:
                backfill_label(client, label, args.batch_size, args.dry_run)

        if not args.nodes_only:
            logger.info("=== EDGE BACKFILL ===")
            for rel_type, from_label, to_label in EDGES_TO_BACKFILL:
                backfill_edge(client, rel_type, from_label, to_label, args.batch_size, args.dry_run)
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
