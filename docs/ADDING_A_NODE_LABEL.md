# Adding a new node label to EdgeGuard

This document is the **authoritative checklist** for introducing a new Neo4j
node label (e.g. `Sensor`, `Endpoint`, `Identity`) into EdgeGuard so it
participates in the deterministic-uuid contract from day one.

The PR #34 audit (rounds 25-28) found that the same anti-pattern — adding a
label to one source-of-truth list but forgetting another — recurred multiple
times. The fix is twofold:

1. **Invariant tests** in `tests/test_round26_invariants.py` automatically
   catch most omissions (missing constraint, mismatched merge-key dict, etc.).
2. **This checklist** documents the FULL set of touchpoints so a contributor
   doesn't even have to wait for the test to fail.

---

## TL;DR — the 7 touchpoints

To add a label `Foo` with natural key `(field_a, field_b)`:

```
[ ] 1. _NATURAL_KEYS                  src/node_identity.py
[ ] 2. NEO4J_TO_STIX_TYPE             src/node_identity.py  (only if STIX-exported)
[ ] 3. _ALLOWED_NODE_LABELS           src/neo4j_client.py
[ ] 4. UNIQUE constraint              src/neo4j_client.py — Neo4jClient.create_constraints
[ ] 5. n.uuid index                   src/neo4j_client.py — Neo4jClient.create_indexes
[ ] 6. Merge function                 src/neo4j_client.py — merge_foo / create_foo_node
[ ] 7. Backfill EDGES_TO_BACKFILL     scripts/backfill_node_uuids.py  (only if Foo has edges)
```

If any of these are missing, the round-26 invariant tests fail loudly.

---

## Detailed steps

### 1. Add to `_NATURAL_KEYS`

`src/node_identity.py`:

```python
_NATURAL_KEYS: Dict[str, Tuple[str, ...]] = {
    # ... existing entries ...
    "Foo": ("field_a", "field_b"),  # new label
}
```

This is the **single source of truth** for "what counts as a uuidable node."
Every other site below derives its behavior from this one entry.

### 2. Add to `NEO4J_TO_STIX_TYPE` (only if STIX-exported)

`src/node_identity.py`:

```python
NEO4J_TO_STIX_TYPE: Dict[str, str] = {
    # ... existing ...
    "Foo": "indicator",  # or whatever STIX type Foo maps to
}
```

If the label is **internal-only** (e.g. `Source`, `Alert`, CVSS sub-nodes,
`User`), use a custom prefix: `"Foo": "x-edgeguard-foo"`. The `x-edgeguard-`
prefix is the EdgeGuard convention for non-standard STIX SDO types.

If you skip this step entirely, the canonicalization falls back to
`"foo:..."` (lowercased label name) — deterministic but no STIX parity.
Acceptable for labels that genuinely have no STIX counterpart.

### 3. Add to `_ALLOWED_NODE_LABELS`

`src/neo4j_client.py`:

```python
_ALLOWED_NODE_LABELS = frozenset({
    # ... existing ...
    "Foo",
})
```

This list is the security guardrail for `_validate_label()`. Without the
entry, any Cypher query that tries to MERGE on `Foo` will raise with
`Cypher injection guard: 'Foo' is not a valid node label`.

### 4. Add a UNIQUE constraint

`src/neo4j_client.py` → `Neo4jClient.create_constraints`:

```python
constraints = [
    # ... existing ...
    "CREATE CONSTRAINT foo_key IF NOT EXISTS FOR (n:Foo) REQUIRE (n.field_a, n.field_b) IS UNIQUE",
]
```

The constraint fields MUST exactly match `_NATURAL_KEYS["Foo"]`. Without
this, two concurrent MERGEs on the same `(field_a, field_b)` can create
duplicate nodes. Round 26's `test_every_natural_key_label_has_a_unique_constraint`
catches this.

### 5. Add a uuid index

`src/neo4j_client.py` → `Neo4jClient.create_indexes`:

```python
indexes = [
    # ... existing ...
    "CREATE INDEX foo_uuid IF NOT EXISTS FOR (n:Foo) ON (n.uuid)",
]
```

Required for cloud-side `MATCH (n:Foo {uuid: $u})` to be O(1). Without it,
delta-sync MATCH-by-uuid is O(|Foo|) — fine on small graphs, painful at
scale.

### 6. Write the merge function

`src/neo4j_client.py`:

```python
def merge_foo(self, data: dict) -> bool:
    """MERGE a Foo node, stamping deterministic n.uuid."""
    a = data.get("field_a")
    b = data.get("field_b")
    if not a or not b:
        logger.error("merge_foo: missing natural-key fields")
        return False
    node_uuid = compute_node_uuid("Foo", {"field_a": a, "field_b": b})
    query = """
    MERGE (n:Foo {field_a: $field_a, field_b: $field_b})
    ON CREATE SET n.uuid = $node_uuid
    SET n.last_updated = datetime(),
        n.uuid = coalesce(n.uuid, $node_uuid)
    """
    try:
        with self.driver.session() as session:
            session.run(
                query,
                field_a=a,
                field_b=b,
                node_uuid=node_uuid,
                timeout=NEO4J_READ_TIMEOUT,
            )
        return True
    except Exception as e:
        logger.error(f"merge_foo failed: {e}")
        return False
```

**Critical contract checklist for the merge function** (each pinned by a
round-26 invariant):

- ✅ The dict passed to `compute_node_uuid` MUST contain exactly the fields
  in `_NATURAL_KEYS["Foo"]` — no more, no less. Caught by
  `test_merge_key_dict_matches_natural_keys_for_every_helper`.
- ✅ The Cypher MERGE WHERE clause MUST bind the same fields.
- ✅ `ON CREATE SET n.uuid = $node_uuid` — stamp on creation.
- ✅ `SET n.uuid = coalesce(n.uuid, $node_uuid)` — defensive idempotency.
- ✅ `session.run(query, ..., timeout=NEO4J_READ_TIMEOUT)` — never omit the
  timeout. Caught by `test_every_session_run_has_explicit_timeout`.
- ✅ Refuse to MERGE on missing natural-key fields (return `False`, not
  silently fall through). The invariant: every node in the graph has a
  valid uuid.

### 7. Add edges to `EDGES_TO_BACKFILL` (only if Foo has edges)

`scripts/backfill_node_uuids.py`:

```python
EDGES_TO_BACKFILL: List[Tuple[str, str, str]] = [
    # ... existing ...
    ("RELATES_TO", "Foo", "Bar"),     # if Foo→Bar edges exist
    ("RELATES_TO", "Bar", "Foo"),     # both directions if bidirectional
]
```

Without this, pre-existing Foo edges (created before deterministic uuids
were introduced for Foo) won't have `r.src_uuid` / `r.trg_uuid` stamped
during the next backfill run.

---

## Validation: run the invariant tests

Before opening a PR with the new label, run:

```bash
.venv/bin/python -m pytest tests/test_round26_invariants.py -v
```

If any test fails, the message tells you which touchpoint is missing.
Fix that, re-run, repeat until all 7 invariants pass.

For end-to-end uuid parity (Neo4j ↔ STIX), also run:

```bash
.venv/bin/python -m pytest tests/test_node_identity.py -v
```

If your label has STIX parity (step 2), add it to the
`test_neo4j_uuid_equals_stix_sdo_id_uuid_portion` parametrize list so
parity is pinned.

---

## Special cases

### Composite natural keys

Labels with multi-field keys (e.g. `Indicator: (indicator_type, value)`,
`User: (username, domain)`, `NetworkService: (port, protocol)`) work
identically — just list both fields in `_NATURAL_KEYS` and the constraint:

```python
"CREATE CONSTRAINT foo_key IF NOT EXISTS FOR (n:Foo) REQUIRE (n.field_a, n.field_b) IS UNIQUE",
```

Order doesn't matter for the constraint, but the dict order in
`_NATURAL_KEYS` MUST match the order used in `compute_node_uuid` calls
across the codebase. The canonicalization sorts keys alphabetically (see
`canonical_node_key`) so the resulting uuid is order-independent in
practice.

### Composite-key default-value normalization

If your composite key has a field that may be `None` / `""` / missing
(like `User.domain`), normalize to a single canonical form BEFORE calling
`compute_node_uuid`. Example:

```python
domain = data.get("domain") or "default"  # collapses None / "" / missing
node_uuid = compute_node_uuid("Foo", {"username": username, "domain": domain})
```

Otherwise three different callers (missing key, explicit None, explicit "")
each produce a DIFFERENT uuid for the same logical entity. PR #34 round 25
caught this for `User`. Pinned by
`test_merge_resilmesh_user_normalizes_domain_none_and_empty`.

### Labels with no STIX equivalent

Use a custom STIX prefix (`x-edgeguard-foo`) to keep the uuid deterministic
without claiming STIX standards compatibility. Examples in the codebase:
`Source`, `Alert`, `CVSSv2`, `CVSSv30`, `CVSSv31`, `CVSSv40`, `User`.

### Labels that auto-CREATE inside other queries

If your label is auto-CREATEd inside someone else's MERGE (e.g. `Sector`
nodes are auto-created by `build_relationships.py` queries 7a/7b), you
need to either:

1. Pre-compute a Python dict of `{key: uuid}` and embed as a Cypher CASE
   expression literal (the `_SECTOR_UUIDS` pattern), OR
2. Pass the uuid as a Cypher parameter at every MERGE site.

Don't try to `compute_node_uuid` inside Cypher — UUIDv5 is not available
as a Cypher function.

---

## What's pinned by tests vs. what's manual

| Touchpoint | Caught automatically by | Manual check needed? |
|---|---|---|
| 1. `_NATURAL_KEYS` | None directly — but downstream tests fail if missing | Yes |
| 2. `NEO4J_TO_STIX_TYPE` | `test_neo4j_to_stix_type_map_is_frozen_for_threat_intel_core` | Yes for STIX parity |
| 3. `_ALLOWED_NODE_LABELS` | None — but every MERGE call validates label | Yes |
| 4. UNIQUE constraint | ✅ `test_every_natural_key_label_has_a_unique_constraint` | No |
| 5. uuid index | None — but cloud-side O(n) MATCH at scale flags it | Yes |
| 6. Merge function | ✅ `test_merge_key_dict_matches_natural_keys_for_every_helper` (key match) + `test_every_session_run_has_explicit_timeout` (timeout) | Partial |
| 7. EDGES_TO_BACKFILL | None — silent skip in backfill log | Yes |

The "manual check needed" items are good candidates for future invariant
tests if the same anti-pattern recurs.

---

_Last updated: 2026-04-17 (PR #34 round 27)_
