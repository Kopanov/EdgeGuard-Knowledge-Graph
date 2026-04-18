# Migration: source-truthful first_seen_at_source / last_seen_at_source

**Date:** 2026-04
**PR:** S5 (audit-driven first_seen restoration)
**Backfill required:** No (NULL means "we don't know" — sources organically re-populate)
**Operator action:** Verification queries below; optional cleanup

---

## What changed

EdgeGuard previously stored only one set of temporal fields on Indicator/
Vulnerability/Malware/ThreatActor/Campaign nodes:

* `n.first_imported_at` — when EdgeGuard's sync first wrote the node
* `n.last_updated` — most recent sync touch

PR (S5) adds two **source-truthful** fields, mirroring the OpenCTI / STIX 2.1
industry consensus pattern that distinguishes "world's first observation"
from "DB-local insertion time":

| Property | Semantic | Source | When NULL |
|---|---|---|---|
| `n.first_seen_at_source` | World-truthful first observation | MISP-native `attribute.first_seen` (set by MISPWriter) → source-specific META JSON (NVD_META.published, etc.) | Source not on the reliable allowlist OR upstream feed didn't provide the value |
| `n.last_seen_at_source` | World-truthful last observation | Same fallback chain | Same |

`n.first_imported_at` and `n.last_updated` are unchanged.

## Reliable-source allowlist

Sources whose upstream first-seen field has canonical "world-truth" semantics:

* `nvd` — NVD `published`
* `cisa` — CISA KEV `dateAdded`
* `mitre_attck` (alias `mitre`) — STIX `created`
* `virustotal` (alias `vt`) — `first_submission_date`
* `abuseipdb` — `firstSeen` (check endpoint) / `lastReportedAt` (blacklist endpoint, mapped to last_seen — see PR (S5) commit 8 for the semantic-bug fix)
* `threatfox` — `first_seen`
* `urlhaus` — `dateadded`
* `feodo_tracker` (alias `feodo`) — `first_seen`
* `ssl_blacklist` (alias `abusech_ssl`) — `date`

Excluded (returns NULL even when the source provides a value):

* `otx` — pulse `created` is when the analyst AUTHORED the pulse, NOT when the IOC was first observed (semantically misleading)
* `cybercure` — synthesizes `now()` (useless)
* `misp` / sector feeds — use MISP event date as a proxy (was already a synthesis at collection time)

See `src/source_truthful_timestamps.py::_RELIABLE_FIRST_SEEN_SOURCES` for the canonical list.

## Why no bulk backfill?

`n.first_seen_at_source = NULL` is **honest and informative**: it means "no
reliable source has reported this indicator yet, so we don't know when the
world first saw it." Backfilling NULL → `first_imported_at` would lose
that signal — operators couldn't distinguish "we have source-truthful data
saying 2019" from "we just don't know."

Existing nodes will populate `first_seen_at_source` organically the next
time a reliable source re-imports them (within days, given baseline + 6
incremental DAGs running on schedule). For nodes that NEVER get re-touched
by a reliable source, NULL is the correct semantic.

If you genuinely need to backfill (e.g. for a one-off STIX export to a
consumer that can't handle NULL `first_seen`), the operator query in §
"Optional cleanup" below uses the OpenCTI fallback pattern: `coalesce(n.first_seen_at_source, n.first_imported_at)` per node.

## Verification queries

### 1. Schema is in place

```cypher
// Should return a non-empty count (new nodes will have the field)
MATCH (n:Indicator) WHERE n.first_seen_at_source IS NOT NULL
RETURN count(n) AS source_truthful_indicators;
```

### 2. STIX exporter no longer leaks 1970 timestamps

```cypher
// Before PR (S5): every Indicator's STIX bundle had valid_from = 1970.
// After: should be small/zero count.
MATCH (n:Indicator)
WHERE n.first_imported_at IS NULL AND n.first_seen_at_source IS NULL
RETURN count(n) AS nodes_that_would_export_with_1970;
```

### 3. Coverage by source — see how the allowlist is populating in practice

```cypher
MATCH (n:Indicator)
WITH apoc.coll.toSet(coalesce(n.source, [])) AS sources, n
UNWIND sources AS src
WITH src,
     count(n) AS total,
     sum(CASE WHEN n.first_seen_at_source IS NOT NULL THEN 1 ELSE 0 END) AS with_source_truth
RETURN src, total, with_source_truth,
       round(100.0 * with_source_truth / total, 1) AS pct_with_source_truth
ORDER BY total DESC;
```

Expected for reliable sources (nvd, cisa, mitre_attck, virustotal,
abuseipdb, threatfox, urlhaus, feodo_tracker, ssl_blacklist) after one
full incremental sync cycle: > 90% coverage.

Expected for excluded sources (otx, cybercure, misp): ~0% (NULL is
correct — these don't carry world-truth).

### 4. Sanity check: no future-dated values leaked through

The helper clamps future timestamps to `now()` with a warning, but verify:

```cypher
MATCH (n:Indicator)
WHERE n.first_seen_at_source > datetime()
   OR n.last_seen_at_source > datetime()
RETURN count(n) AS future_dated_leaks;
```

Expected: 0.

### 5. Out-of-order-write semantic check (run after a baseline)

If baseline + incremental have both run, the MIN logic should preserve
the earliest-observed value. Spot-check one indicator:

```cypher
MATCH (n:Indicator {value: '203.0.113.5', indicator_type: 'ipv4'})
RETURN n.first_seen_at_source, n.first_imported_at, n.last_seen_at_source, n.last_updated;
```

`first_seen_at_source <= first_imported_at` should always hold for nodes
where source-truth was found (the world saw it BEFORE EdgeGuard imported
it; never the other way around).

## Optional cleanup

### Backfill from first_imported_at (if your downstream consumer can't handle NULL)

NOT recommended (loses the "explicitly unknown" signal), but if needed:

```cypher
// Sets first_seen_at_source to first_imported_at for nodes where
// no reliable source has populated it yet. Idempotent.
MATCH (n)
WHERE (n:Indicator OR n:Vulnerability OR n:Malware OR n:ThreatActor OR n:Campaign OR n:Tool OR n:Technique OR n:Tactic)
  AND n.first_seen_at_source IS NULL
  AND n.first_imported_at IS NOT NULL
SET n.first_seen_at_source = n.first_imported_at
RETURN labels(n)[0] AS label, count(n) AS backfilled;
```

### Index for query performance (if you filter on the new field)

The merge sites already use the natural-key UNIQUE constraints, but if
you query by `WHERE n.first_seen_at_source > datetime() - duration({days: 30})`
frequently, add an index:

```cypher
CREATE INDEX indicator_first_seen_at_source IF NOT EXISTS
FOR (n:Indicator) ON (n.first_seen_at_source);

CREATE INDEX vulnerability_first_seen_at_source IF NOT EXISTS
FOR (n:Vulnerability) ON (n.first_seen_at_source);
```

## Rollback

The new fields are additive; rolling back to a pre-PR-(S5) deploy will
not require any data migration. The new fields will simply stop being
populated on subsequent syncs (no harm — they were NULL before too,
just unnamed). Downstream consumers that started reading
`first_seen_at_source` will see NULL for nodes touched after the
rollback; they should fall back to `first_imported_at`.

## See also

* `src/source_truthful_timestamps.py` — the helper that drives the
  per-source allowlist + extraction
* `src/run_misp_to_neo4j.py::parse_attribute` — wire-through site
* `src/neo4j_client.py::merge_indicators_batch` /
  `merge_vulnerabilities_batch` / `merge_node_with_source` — Cypher
  MIN/MAX SET clauses
* `src/stix_exporter.py::_indicator_sdo` — STIX `valid_from`
  resolution chain (no more 1970 epoch leak)
* `src/enrichment_jobs.py::build_campaign_nodes` — Campaign first_seen /
  last_seen now use source-truthful values via coalesce-min/max
* `src/alert_processor.py` — ResilMesh alert enrichment now carries
  source-truthful observation times
