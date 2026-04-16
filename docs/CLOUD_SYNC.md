# Local Neo4j → Cloud Neo4j sync

EdgeGuard runs Neo4j locally for ingest and enrichment. For production analysis,
xAI / GraphRAG queries, or sharing with partners, the graph is replicated to a
cloud Neo4j (e.g. Aura). This doc describes the three sync paths and which one
to use when, with the explicit role of `n.uuid` + `r.src_uuid` / `r.trg_uuid`.

## At a glance

| Pattern | Cost / cadence | When to use | Requires `n.uuid` ? |
|---|---|---|---|
| `neo4j-admin database dump` + `database load` | Slow (full dump), one-shot | First-time copy, cold restore | No (topology preserved) |
| APOC `apoc.export.cypher.all` → `apoc.cypher.runFiles` | Slow, one-shot | Ad-hoc copy when admin tools aren't available | No (idempotent MERGE on natural keys) |
| **Custom incremental delta sync** | Fast, nightly/hourly | Production replication | **Yes** — this is the path the 2026-04 PR enables |

## How the delta sync uses uuids

Every node carries `n.uuid` = `uuid5(EDGEGUARD_NAMESPACE, canonical(label, natural_key))`.
The same input produces the same UUID on every machine — so the cloud copy of
an Indicator has the same `n.uuid` as the source local Indicator, even if the
two Neo4j instances were never in contact.

Every edge carries `r.src_uuid` and `r.trg_uuid` — the deterministic uuids of
the connected nodes. An edge document is therefore self-describing: it
identifies its endpoints by stable, cross-environment identifiers.

This unlocks two operational patterns:

### 1. Push deltas keyed by uuid

Producer side (local):

```cypher
// Nightly: collect everything written or modified in the last 24h.
MATCH (n)
WHERE n.last_updated >= datetime() - duration({days: 1})
  AND n.uuid IS NOT NULL
RETURN labels(n) AS labels, n.uuid AS uuid, properties(n) AS props
```

```cypher
MATCH (a)-[r]->(b)
WHERE r.updated_at >= datetime() - duration({days: 1})
  AND r.src_uuid IS NOT NULL AND r.trg_uuid IS NOT NULL
RETURN type(r) AS rel_type,
       r.src_uuid AS src_uuid, r.trg_uuid AS trg_uuid,
       properties(r) AS props
```

Consumer side (cloud) — for each node delta:

```cypher
UNWIND $node_deltas AS d
CALL apoc.merge.node(d.labels, {uuid: d.uuid}, d.props, {})
YIELD node
RETURN count(node)
```

For each edge delta:

```cypher
UNWIND $edge_deltas AS e
MATCH (a {uuid: e.src_uuid})
MATCH (b {uuid: e.trg_uuid})
CALL apoc.merge.relationship(a, e.rel_type, {}, e.props, b, {})
YIELD rel
RETURN count(rel)
```

No natural-key resolution required. The uuid index (`CREATE INDEX <label>_uuid`
in `Neo4jClient.create_indexes`) makes endpoint MATCHes O(1).

### 2. Self-describing edge serialization

Edge documents can be serialized to JSON and consumed by xAI / RAG pipelines
without the connected nodes:

```json
{
  "type": "INDICATES",
  "src_uuid": "6ca3af4a-4bf1-57c9-846d-ec8f80861fd0",
  "trg_uuid": "774960af-0687-56b1-9c05-ae55cd62ed58",
  "props": {
    "confidence_score": 0.85,
    "source_id": "misp_cooccurrence",
    "misp_event_ids": ["1234", "1235"],
    "imported_at": "2026-04-12T11:23:08Z"
  }
}
```

The consumer can resolve `src_uuid` and `trg_uuid` back to nodes only when it
needs to (lazy join), keeping context windows compact.

## Cross-system traceability with STIX

The UUID portion of a STIX 2.1 SDO id produced by `src/stix_exporter.py`
**equals** the corresponding Neo4j `n.uuid` for the same logical entity.

Example for an Indicator (`indicator_type="ipv4"`, `value="203.0.113.5"`):

```
Neo4j  n.uuid                      → "6ca3af4a-4bf1-57c9-846d-ec8f80861fd0"
STIX   sdo.id                      → "indicator--6ca3af4a-4bf1-57c9-846d-ec8f80861fd0"
                                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                              identical UUID portion
```

A bundle leaving EdgeGuard for ResilMesh can be resolved back to the source
Neo4j node by stripping the SDO id prefix (`indicator--`, `malware--`, etc.)
and looking up `n.uuid` in Neo4j. No translation table needed.

This parity holds for: `Indicator`, `Malware`, `ThreatActor` (STIX
`intrusion-set`), `Technique` (STIX `attack-pattern`), `Vulnerability`, `CVE`,
`Sector`, `Campaign`. **Not** for `Tool` — see
`src/node_identity.py` `_LABEL_NATURAL_KEY_FIELDS` for the rationale.

## Operator runbook

After deploying the 2026-04 PR (which adds the `compute_node_uuid` calls and
indexes), run the backfill once to stamp every existing node and edge:

```bash
# Inside the project venv with NEO4J_* env vars set
python scripts/backfill_node_uuids.py --dry-run     # report counts only
python scripts/backfill_node_uuids.py               # do it
```

The script is idempotent and resumable. See `docs/MIGRATIONS.md` for the full
runbook (pre-flight, snapshot, backfill, post-flight verification).

After backfill:

```cypher
MATCH (n) WHERE n.uuid IS NULL RETURN labels(n)[0] AS label, count(n) AS missing;
// Expected: empty result for every documented label.

MATCH ()-[r]->() WHERE r.src_uuid IS NULL OR r.trg_uuid IS NULL
RETURN type(r) AS rel_type, count(r) AS missing;
// Expected: empty for every edge type that connects documented labels.
```

## Caveats

- **Topology / ResilMesh-owned nodes** (`Component`, `Mission`,
  `OrganizationUnit`, `MissionDependency`, `Node`) are not in
  `_NATURAL_KEYS` yet — they don't get uuids. Documented as a deferred
  follow-up. Use full dump/restore for those if needed.
- **Standalone `create_*_relationship` helpers** (e.g.
  `create_indicator_malware_relationship`) don't stamp `r.src_uuid` /
  `r.trg_uuid` at runtime — they're legacy / individual-call paths. The
  backfill picks them up by joining endpoint `n.uuid` (zero loss).
- **Tool**'s natural key in Neo4j is `mitre_id`, but the STIX exporter uses
  `name`. Tool SDO IDs do NOT have UUID parity with Neo4j `n.uuid`. Worth
  reconciling in a follow-up if Tool round-trips become important.
