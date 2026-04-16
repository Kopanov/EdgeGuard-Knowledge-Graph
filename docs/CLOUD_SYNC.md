# Cross-environment tracking, reproducibility, and graph transfer

EdgeGuard runs Neo4j locally for ingest and enrichment. The same graph
shows up in multiple downstream contexts — production cloud Neo4j, xAI /
GraphRAG retrieval, STIX bundles to ResilMesh, partner shares. This doc
explains:

1. **The logic** — how every node and every relationship receives a
   deterministic identifier at MERGE time.
2. **Why it matters** — what reproducibility, AI-workflow, and transfer
   guarantees that gives you.
3. **The recipes** — copy-paste patterns for the common workflows.

## TL;DR — the contract

- Every documented node carries `n.uuid` = `uuid5(EDGEGUARD_NAMESPACE, canonical(label, natural_key))`.
- Every documented edge carries `r.src_uuid` and `r.trg_uuid` — the same
  deterministic uuids as the connected nodes.
- The same `(label, natural_key)` produces the **same UUID on every Neo4j
  instance, in every Python process, on every machine, forever**. UUIDv5
  is a pure function of its inputs.
- The UUID portion of a STIX 2.1 SDO id (from `src/stix_exporter.py`)
  **equals** the corresponding Neo4j `n.uuid` for the same logical
  entity (Indicator, Malware, ThreatActor → intrusion-set, Technique →
  attack-pattern, Vulnerability, CVE, Sector, Campaign — Tool documented
  exception).

The implementation is in [src/node_identity.py](../src/node_identity.py).
Wiring is in [src/neo4j_client.py](../src/neo4j_client.py),
[src/build_relationships.py](../src/build_relationships.py), and
[src/enrichment_jobs.py](../src/enrichment_jobs.py).

---

## The logic — how each node receives a uuid

### Step 1 — define the natural key

For every node label, EdgeGuard's UNIQUE constraint already nominates which
properties identify a node uniquely. `src/node_identity.py
_LABEL_NATURAL_KEY_FIELDS` is the single Python-side mirror of those keys:

| Neo4j label | Natural key fields | STIX type used in canonical string |
|---|---|---|
| Indicator | `indicator_type`, `value` | `indicator` |
| Malware | `name` | `malware` |
| ThreatActor | `name` | `intrusion-set` (MITRE convention) |
| Technique | `mitre_id` | `attack-pattern` |
| Tactic | `mitre_id` | `x-mitre-tactic` |
| Tool | `mitre_id` | `tool` (¹) |
| CVE / Vulnerability | `cve_id` | `vulnerability` |
| Sector | `name` | `identity` |
| Campaign | `name` | `campaign` |
| Source | `source_id` | `x-edgeguard-source` |
| CVSSv2 / v30 / v31 / v40 | `cve_id` | `x-edgeguard-cvssv*` |

¹ Tool is the documented STIX-parity exception — see "Caveats" below.

### Step 2 — build the canonical string

The serialization rule (`canonical_node_key` in `node_identity.py`) is:

```
canonical = f"{stix_type}:{natural_key_string}".lower()
```

…where `natural_key_string` joins the per-label key fields with `|` in the
documented order. Concrete examples:

| Logical entity | Canonical string |
|---|---|
| Indicator(indicator_type="ipv4", value="203.0.113.5") | `"indicator:ipv4\|203.0.113.5"` |
| Malware(name="Emotet") | `"malware:emotet"` |
| ThreatActor(name="APT28") | `"intrusion-set:apt28"` |
| Technique(mitre_id="T1059") | `"attack-pattern:t1059"` |
| CVE(cve_id="CVE-2024-1234") | `"vulnerability:cve-2024-1234"` |
| Vulnerability(cve_id="CVE-2024-1234") | `"vulnerability:cve-2024-1234"` (same as CVE) |
| Sector(name="healthcare") | `"identity:healthcare"` |

The trailing `.lower()` is what gives STIX parity — `_deterministic_id` in
the STIX exporter does exactly the same thing.

### Step 3 — hash with the fixed namespace

```python
EDGEGUARD_NODE_UUID_NAMESPACE = uuid.UUID("5f2e1f9a-6a1b-5e0f-9b25-ed9ea2d574cb")
n.uuid = str(uuid.uuid5(EDGEGUARD_NODE_UUID_NAMESPACE, canonical))
```

Worked example:

```
Indicator(indicator_type="ipv4", value="203.0.113.5")
  canonical:  "indicator:ipv4|203.0.113.5"
  uuid5:      "6ca3af4a-4bf1-57c9-846d-ec8f80861fd0"
```

This same line of code, run on any Python 3.x on any operating system at
any point in time, will produce `6ca3af4a-...-861fd0`. That's the
reproducibility guarantee.

### Step 4 — stamp the node at MERGE time

Every node MERGE in `Neo4jClient` computes the uuid in Python and threads
it into the Cypher as `$node_uuid`:

```python
# src/neo4j_client.py merge_node_with_source — applies to all 7 entity wrappers
node_uuid = compute_node_uuid(label, key_props)
session.run("""
    MERGE (n:<Label> {<key_props>})
    ON CREATE SET n.uuid = $node_uuid
    SET n.uuid = coalesce(n.uuid, $node_uuid),
        ...
""", node_uuid=node_uuid, ...)
```

`coalesce(n.uuid, $node_uuid)` is defensive — the same uuid is computed
on every call, but the coalesce ensures we never overwrite an existing
value (also lets the backfill be idempotent for nodes that were already
stamped).

### Frozen things — never change without a graph-wide migration

- `EDGEGUARD_NODE_UUID_NAMESPACE` — changing it invalidates every uuid in
  every running Neo4j AND every STIX bundle ever shipped.
- `_LABEL_NATURAL_KEY_FIELDS` — changing the field order or set for a
  label changes the canonical string for every existing node of that
  label.
- `NEO4J_TO_STIX_TYPE` — changing a mapping breaks STIX parity.
- The `.lower()` at the end of `canonical_node_key` — changing it breaks
  STIX parity.

---

## The logic — how each relationship receives src_uuid / trg_uuid

There are **three mechanisms**, all converging on the same property shape
(`r.src_uuid` and `r.trg_uuid` strings holding the connected nodes' uuids).
Different code paths use different mechanisms because they have different
information available at the time of the MERGE.

### Mechanism B (default) — read live `src.uuid` / `trg.uuid` from the MATCHed nodes

Used by every MISP-derived edge MERGE in the codebase, including:

- All 11 query templates in `Neo4jClient.create_misp_relationships_batch`
- All 6 standalone `Neo4jClient.create_*_relationship` helpers
- All 12 link queries in `src/build_relationships.py`
- The REFERS_TO bridge in `src/enrichment_jobs.py`
- The HAS_CVSS_v* edges in `Neo4jClient._merge_cvss_node`
- The RUNS / PART_OF edges in `enrichment_jobs.build_campaign_nodes`

The pattern: every endpoint has been MERGEd (and stamped with `n.uuid`)
upstream by the time the edge MERGE runs, so the SET reads the live value
off the bound variable:

```cypher
MATCH (i:Indicator) WHERE i.cve_id IS NOT NULL
MATCH (v:Vulnerability {cve_id: i.cve_id})
MERGE (i)-[r:EXPLOITS]->(v)
SET r.src_uuid = coalesce(r.src_uuid, i.uuid),
    r.trg_uuid = coalesce(r.trg_uuid, v.uuid)
```

If `i.uuid` is null (e.g. ingested before this PR, backfill hasn't run yet),
the coalesce keeps `r.src_uuid` null too — and the backfill will fix both
in a single pass later. No silent drift.

PR #33 used to have a separate "Mechanism A" (Python-side precomputation
of endpoint uuids, threaded into UNWIND row dicts) for
`create_misp_relationships_batch`. Bugbot caught a mismatch class on PR
#33 round 4 — a producer's incomplete from_key (e.g. an Indicator
relationship with no `indicator_type`) would yield a precomputed uuid
that didn't match the actual node's `n.uuid` because the node MERGE
used the real key. The refactor switched all 11 batch templates to
Mechanism B (deleted in commit `8465e71`); the precomputation Python is
gone. Same applies to what used to be a "Mechanism C" dual-label
routing helper — the bound-var form removes the per-label uuid swap
entirely.

### Mechanism A (limited) — Python precomputation for AUTO-CREATEd nodes

Mechanism B requires the endpoint to be MERGEd by an upstream pass that
stamps `n.uuid`. For nodes that are AUTO-CREATEd inside the same Cypher
that builds an edge (where there's no upstream MERGE pass), the uuid
must be precomputed in Python and injected as a parameter / Cypher CASE
literal. Three places use this:

- **Sector** auto-CREATE in `create_indicator_sector_relationship` and
  `create_vulnerability_sector_relationship` — Sector uuid pre-computed
  via `compute_node_uuid("Sector", {"name": sec})` and passed as
  `$sector_uuid`.
- **Sector** auto-CREATE in `build_relationships.py` 7a (TARGETS) and
  7b (AFFECTS) — the 4 known sector uuids precomputed at module load
  and embedded as a Cypher CASE expression.
- **Campaign** auto-CREATE in `enrichment_jobs.build_campaign_nodes` —
  pre-fetch qualifying actor names, compute `compute_node_uuid("Campaign",
  {"name": f"{actor_name} Campaign"})` for each, pass as a `$campaign_uuids`
  map keyed by actor name. The MERGE looks it up via
  `c.uuid = $campaign_uuids[a.name]`.

Same template pattern for all three: `ON CREATE SET <node>.uuid = <expr>`
plus an idempotent `SET <node>.uuid = coalesce(<node>.uuid, <expr>)`.

### What about SOURCED_FROM?

SOURCED_FROM edges follow Mechanism B — the connected node is MERGEd
upstream and the Source node is created by `ensure_sources()` at startup
with a deterministic uuid. The SET reads `n.uuid` and `s.uuid` directly.

### Cross-mechanism guarantee

All three mechanisms produce the **same uuid** for the same logical
endpoint, because they all delegate to `node_identity.compute_node_uuid`
(directly in A and C, transitively via the upstream node MERGE in B).
So an edge's `src_uuid` and `trg_uuid` always equal the connected nodes'
`n.uuid`, regardless of which path created the edge.

---

## Why it matters

### Reproducibility

The uuid for any logical entity is a **pure function of its label +
natural key**. Practical implications:

- Two analysts running the same ingest pipeline against the same MISP
  produce graphs with **identical uuids** — without ever coordinating.
- If you nuke your local Neo4j and re-run the pipeline from MISP, every
  node gets the same uuid it had before. Reports referencing
  `Indicator(uuid=6ca3af4a-...)` keep resolving.
- A uuid in a published paper, a Slack thread, a notebook, or a
  Grafana panel is a **stable address** — anyone with access to a Neo4j
  ingested from the same MISP can resolve it.
- Audit trail: a STIX bundle dated 2026-01 referencing
  `indicator--6ca3af4a-...` is provably the same logical entity as
  whatever has `n.uuid = "6ca3af4a-..."` in Neo4j today, with no
  translation table needed.

This is the property that makes "EdgeGuard graphs are reproducible
artifacts" true rather than aspirational.

### AI workflow integration

The two properties — node uuid + edge endpoint uuids — change what's
possible for downstream AI consumers.

**GraphRAG / retrieval over live Neo4j.** The standard pattern is
"retrieve a seed entity, expand 1-2 hops, serialize to LLM context".
Pre-uuid, expanded edges had no canonical identity for their endpoints
beyond the node's natural-key fields — fine when the LLM saw both
endpoints, brittle when context budget forced edge-only chunks. With
`r.src_uuid` / `r.trg_uuid`, every edge in the retrieved subgraph is
self-addressing.

**Concrete RAG chunk** for a "what do we know about CVE-2024-1234"
query:

```json
[
  {
    "kind": "node",
    "uuid": "85b67b2e-bb0c-5a7a-ae6f-2b6cc1aa077b",
    "label": "Vulnerability",
    "props": {"cve_id": "CVE-2024-1234", "severity": "HIGH", "cvss_score": 8.1}
  },
  {
    "kind": "node",
    "uuid": "6ca3af4a-4bf1-57c9-846d-ec8f80861fd0",
    "label": "Indicator",
    "props": {"indicator_type": "ipv4", "value": "203.0.113.5", "confidence_score": 0.85}
  },
  {
    "kind": "edge",
    "type": "EXPLOITS",
    "src_uuid": "6ca3af4a-4bf1-57c9-846d-ec8f80861fd0",
    "trg_uuid": "85b67b2e-bb0c-5a7a-ae6f-2b6cc1aa077b",
    "props": {"confidence_score": 1.0, "match_type": "cve_tag"}
  }
]
```

The LLM can be instructed: "any uuid you cite in your answer must be one
of the chunk uuids above." Citations become trivially verifiable. The
human (or another agent) can resolve any uuid back to Neo4j with a
single MATCH.

**Cross-bundle linkage.** Because the UUID portion of a STIX SDO id
equals the Neo4j n.uuid, an LLM that consumes both EdgeGuard's STIX
bundles AND its Neo4j queries can join across them with
`stix_id.split("--")[1] == n.uuid`. No translation layer.

**Embedding deduplication.** A vector store keyed on `n.uuid` won't
re-embed the same logical entity twice, even if the entity is rebuilt
from scratch in Neo4j between embedding runs.

### Transferring data between Neo4j instances

Several scenarios beyond the production cloud-sync:

| Scenario | Mechanism | What uuids buy you |
|---|---|---|
| Local → cloud (production) | Custom delta sync | Edges re-attach by uuid; no natural-key resolution. Fast. |
| Local → staging (dev) | `apoc.export.cypher.all` + replay | The replay's MERGEs by natural key happen to produce the **same uuids** as the source — verifiable post-import via `count(*) = count(distinct uuid)`. |
| Backup → restore (cold) | `neo4j-admin database dump`/`load` | Topology preserved; uuids preserved as ordinary properties. No semantic change. |
| Subgraph export → re-import | Hand-written Cypher producing JSON | Edges in the export are self-describing — the re-import doesn't need every node, just the ones referenced by `src_uuid`/`trg_uuid` it sees. |
| Multi-tenant fan-out | Same producer pipeline → N consumer instances | Every consumer gets identical uuids for shared entities. Consumers can reconcile/dedup locally. |
| Re-derive after pipeline change | Nuke, re-ingest from MISP | Uuids are reproducible — published references still resolve. |

The common thread: uuid is the **portable identifier** that survives the
choice of transfer mechanism. Pick the mechanism for cost/cadence
reasons; the identifier is the same either way.

---

## Recipes

### Recipe 1 — push deltas keyed by uuid

This is the production path the 2026-04 PR is designed for. Producer side (local):

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

For each edge delta — **MUST use label-scoped MATCH** (see warning below):

```cypher
UNWIND $edge_deltas AS e
// Scope MATCHes to the source/target labels carried in the edge delta —
// CVE and Vulnerability deliberately share a uuid (twin-node design,
// see "CVE/Vulnerability twin-node design" below), and a bare
// `MATCH (a {uuid: ...})` would non-deterministically pick whichever node
// Neo4j returns first.
MATCH (a) WHERE a.uuid = e.src_uuid AND e.src_label IN labels(a)
MATCH (b) WHERE b.uuid = e.trg_uuid AND e.trg_label IN labels(b)
CALL apoc.merge.relationship(a, e.rel_type, {}, e.props, b, {})
YIELD rel
RETURN count(rel)
```

This means the producer-side edge serialization must include the connected
nodes' labels:

```cypher
// Producer side — include src_label / trg_label in every edge delta.
MATCH (a)-[r]->(b)
WHERE r.updated_at >= datetime() - duration({days: 1})
  AND r.src_uuid IS NOT NULL AND r.trg_uuid IS NOT NULL
RETURN type(r)             AS rel_type,
       r.src_uuid          AS src_uuid,
       r.trg_uuid          AS trg_uuid,
       labels(a)[0]        AS src_label,
       labels(b)[0]        AS trg_label,
       properties(r)       AS props
```

The uuid index (`CREATE INDEX <label>_uuid` in
`Neo4jClient.create_indexes`) keeps endpoint MATCHes O(1).

> **CVE/Vulnerability twin-node design.** EdgeGuard models a CVE as TWO
> Neo4j nodes connected by `REFERS_TO`: `(:CVE)` is the NVD-canonical /
> ResilMesh-shared view, `(:Vulnerability)` is the EdgeGuard-managed /
> MISP-derived view. Both deterministically produce the **same**
> `n.uuid` because both map to STIX type `vulnerability` (STIX has only
> one `vulnerability` SDO per CVE, and uuid parity with STIX is the
> namespace contract). This means a bare `MATCH (n {uuid: $u})` may
> match BOTH nodes — always include the label in the MATCH (`MATCH
> (n:CVE {uuid: $u})` or `MATCH (n:Vulnerability {uuid: $u})`) when
> resolving an edge endpoint or a STIX SDO id back to Neo4j. The label
> is implicit in every edge document via the `src_label` / `trg_label`
> fields shown above.

### Recipe 2 — extract a self-describing subgraph for an LLM / RAG store

```cypher
// Seed: a CVE. Pull 1 hop on each side. Output is fully self-describing —
// every edge document carries src_uuid + trg_uuid, every node carries uuid.
MATCH (v:Vulnerability {cve_id: $cve_id})
OPTIONAL MATCH (i:Indicator)-[r1:EXPLOITS]->(v)
OPTIONAL MATCH (v)-[r2:AFFECTS]->(s:Sector)
WITH collect(DISTINCT v) + collect(DISTINCT i) + collect(DISTINCT s) AS nodes,
     collect(DISTINCT r1) + collect(DISTINCT r2) AS rels
UNWIND nodes AS n WITH nodes, rels, n WHERE n IS NOT NULL
RETURN
  collect(DISTINCT {
    kind: 'node',
    uuid: n.uuid,
    label: labels(n)[0],
    props: properties(n)
  }) AS node_chunks,
  [r IN rels WHERE r IS NOT NULL | {
    kind: 'edge',
    type: type(r),
    src_uuid: r.src_uuid,
    trg_uuid: r.trg_uuid,
    props: properties(r)
  }] AS edge_chunks
```

Each chunk in the result is independently meaningful. An LLM can be
given a subset and still reason about the relationships because every
`src_uuid` / `trg_uuid` resolves back to the source.

### Recipe 3 — re-derive after pipeline change (reproducibility check)

```bash
# 1. Snapshot current graph for comparison
neo4j-admin database dump neo4j --to-path=/backups
mv /backups/neo4j.dump /backups/before-rebuild.dump

# 2. Wipe + re-ingest from MISP (simulates a from-scratch rebuild)
python -c "from neo4j_client import Neo4jClient; Neo4jClient().run('MATCH (n) DETACH DELETE n')"
python -m run_misp_to_neo4j --full   # re-runs the production ingest

# 3. Sample uuids from before vs after — must match for any (label, natural_key)
#    that exists in both, since uuids are pure functions of those.
```

```cypher
// In a separate Neo4j with the before-rebuild snapshot loaded:
MATCH (i:Indicator) WHERE i.uuid = "6ca3af4a-4bf1-57c9-846d-ec8f80861fd0"
RETURN i.indicator_type, i.value;
//        ipv4              203.0.113.5    ← same in the rebuilt graph
```

This isn't a unit test — it's an operational sanity check that the uuid
contract holds in production. Useful after any change to
`node_identity.py`, `stix_exporter._deterministic_id`, or the per-label
natural-key constraints in `Neo4jClient.create_constraints`.

### Recipe 4 — share a STIX bundle and resolve back to Neo4j

```python
# Consumer side, given a STIX bundle from EdgeGuard:
import json

# STIX type → Neo4j label(s) — needed because some STIX types map to
# multiple Neo4j labels (vulnerability → CVE + Vulnerability twin nodes,
# see "CVE/Vulnerability twin-node design" in Recipe 1).
STIX_TO_NEO4J_LABELS = {
    "indicator":      ["Indicator"],
    "malware":        ["Malware"],
    "intrusion-set":  ["ThreatActor"],
    "attack-pattern": ["Technique"],
    "x-mitre-tactic": ["Tactic"],
    "tool":           ["Tool"],
    "vulnerability":  ["CVE", "Vulnerability"],   # twin nodes
    "identity":       ["Sector"],
    "campaign":       ["Campaign"],
}

bundle = json.load(open("from_edgeguard.json"))
for sdo in bundle["objects"]:
    if "--" not in sdo.get("id", ""):
        continue
    stix_type, uuid_part = sdo["id"].split("--", 1)
    labels = STIX_TO_NEO4J_LABELS.get(stix_type, [])
    if not labels:
        continue  # SROs and unknown types
    # Scope MATCH to the candidate label(s); for vulnerability this returns
    # both twin nodes (consumer can pick whichever it needs).
    cypher = (
        "MATCH (n) WHERE n.uuid = $u AND any(lbl IN $labels WHERE lbl IN labels(n)) "
        "RETURN labels(n) AS labels, properties(n) AS props"
    )
    rows = neo4j.session().run(cypher, u=uuid_part, labels=labels)
    # … now you have the live properties of the source node(s)
```

No id-mapping table, no fuzzy joins. The STIX→Neo4j round-trip is the
shortest possible path. The label-scoped MATCH is required because a bare
`MATCH (n {uuid: $u})` would non-deterministically pick one of the
CVE/Vulnerability twin nodes when the STIX type is `vulnerability` —
see Recipe 1's "CVE/Vulnerability twin-node design" callout.

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
