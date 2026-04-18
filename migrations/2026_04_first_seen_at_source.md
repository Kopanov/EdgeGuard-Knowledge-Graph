# Migration: per-source timestamps on `SOURCED_FROM` edges

**Date:** 2026-04
**PR:** S5 — source-truthful timestamp restoration + edge-based provenance
**Backfill required:** No (NULL means "we don't know"; organic re-population
on the next incremental cycle).
**Operator action:** Read the consumer migration notes below.

---

## The model in one paragraph

Threat-intel nodes (Indicator, Vulnerability, Malware, ThreatActor, Technique,
Tactic, Tool) carry **two** timestamps — both DB-local facts about EdgeGuard's
own observation history that cannot be misread as real-world claims:

| Property on node | Semantic | Write rule |
|---|---|---|
| `n.first_imported_at` | When EdgeGuard's sync first MERGEd the node | `ON CREATE SET = datetime()` — set once, never overwritten |
| `n.last_updated` | When EdgeGuard's sync last MERGEd / touched it | `SET = datetime()` on every MERGE — always current |

Per-source claims live on the `(:Node)-[r:SOURCED_FROM]->(:Source)` edge,
**one edge per (entity, source) pair**, so multi-source IOCs preserve the full
provenance:

| Property on edge | Semantic | Write rule |
|---|---|---|
| `r.imported_at` | When EdgeGuard first saw THIS source report this entity | `ON CREATE SET = datetime()` |
| `r.updated_at` | When EdgeGuard last saw THIS source report it | `SET = datetime()` on every MERGE |
| `r.source_reported_first_at` | The source's own claim about when it first recorded the entity (NVD `published`, CISA `dateAdded`, AbuseIPDB `firstSeen`, ThreatFox `first_seen`, MITRE `created`) | MIN CASE with AND-guard: earliest claim wins; stale imports cannot regress |
| `r.source_reported_last_at` | The source's own claim about when it last recorded the entity (NVD `lastModified`, etc.) | MAX CASE with AND-guard: latest claim wins |

Plus the existing edge metadata: `r.confidence`, `r.source`, `r.raw_data`,
`r.src_uuid`, `r.trg_uuid`.

## What this fixes

**Original bug** (Tier S5 audit, Logic Tracker): `Indicator.valid_from` was
shipping `1970-01-01T00:00:00Z` to ResilMesh on every export because the
upstream first-seen value was being lost at multiple handoff points.

**Naming bug** (user-surfaced after first round): the field name
`first_seen_at_source` overstated the semantic — sources record
"when we cataloged it", not "when first observed in reality". For CVE-2013,
NVD's `published=2013-01-15` reflects when NVD published the record, not
when the vulnerability was first exploited.

**Aggregation bug** (user-surfaced): node-level MIN(first)/MAX(last)
collapsed multi-source provenance to a single value. For an IP reported by
NVD + AbuseIPDB + ThreatFox we lost the per-source detail.

The per-source edge model fixes all three:
- **No false-truth claim**: edge property names (`source_reported_first_at`)
  honestly describe what they are — claims FROM the source
- **Per-source preserved**: each source gets its own edge with its own claim
- **Stale-import resistant**: MIN/MAX with AND-guard handles backdated
  corrections AND prevents stale data from regressing the canonical claim

## Reliable-source allowlist

Only sources whose upstream timestamp has meaningful "the source recorded
this at time X" semantics are stamped on the edge:

| Source | Upstream field used | On allowlist? |
|---|---|---|
| `nvd` | `published` / `lastModified` | ✅ |
| `cisa_kev` (also `cisa`) | `dateAdded` | ✅ |
| `mitre_attck` (also `mitre`) | STIX `created` / `modified` | ✅ |
| `virustotal` (also `vt`) | `first_submission_date` | ✅ |
| `abuseipdb` | `firstSeen` / `lastReportedAt` | ✅ |
| `threatfox` | `first_seen` / `last_seen` | ✅ |
| `urlhaus` | `dateadded` / `last_online` | ✅ |
| `feodo_tracker` (also `feodo`) | `first_seen` | ✅ |
| `ssl_blacklist` (also `abusech_ssl`) | `date` | ✅ |
| `alienvault_otx` | (would be `pulse.created` — pulse-publish-date, NOT IOC first-seen) | 🚫 excluded by design |
| `cybercure` | (synthetic `now()`) | 🚫 excluded |
| `misp` (sector / mock feeds) | (no upstream first-seen) | 🚫 excluded |

When the source isn't on the allowlist, `r.source_reported_first_at` and
`r.source_reported_last_at` are NULL on that edge — semantic: "we don't have
a meaningful claim from this source". The `r.imported_at` / `r.updated_at`
DB-local pair is still populated.

## Querying the new model

### "What does each source say about CVE-2013-1234?"

```cypher
MATCH (v:Vulnerability {cve_id: "CVE-2013-1234"})-[r:SOURCED_FROM]->(s:Source)
RETURN s.source_id,
       r.source_reported_first_at,    // NVD published, CISA dateAdded, etc.
       r.source_reported_last_at,
       r.imported_at,                  // When EdgeGuard first saw THIS source
       r.updated_at                    // When EdgeGuard last saw THIS source
ORDER BY r.source_reported_first_at;
```

### "Earliest claim across ALL sources" (STIX `valid_from` semantic)

```cypher
MATCH (v:Vulnerability {cve_id: "CVE-2013-1234"})-[r:SOURCED_FROM]->(:Source)
RETURN coalesce(min(r.source_reported_first_at), v.first_imported_at) AS valid_from;
```

The STIX exporter computes this automatically per SDO via
`StixExporter._enrich_props_with_source_aggregates`.

### "Drill back into MISP"

Each node accumulates `n.misp_event_ids[]` and `n.misp_attribute_ids[]` —
APOC sets, accumulated across every (re-)import — so operators can resolve
the full source payload via the MISP UUID.

## Consumer migration

| Old read | New read |
|---|---|
| `n.first_seen_at_source` | `MIN(r.source_reported_first_at)` across `(n)-[r:SOURCED_FROM]->(:Source)` |
| `n.last_seen_at_source` | `MAX(r.source_reported_last_at)` across same edges |
| `n.first_imported_at` | (unchanged) |
| `n.last_updated` | (unchanged) |
| GraphQL `Indicator { first_seen_at_source }` | (removed — query the edges directly via the resolver, or rely on the STIX exporter to aggregate) |

## Verification queries (post-deploy)

```cypher
// 1. New nodes get first_imported_at on creation (always set)
MATCH (n:Indicator) WHERE n.first_imported_at IS NULL RETURN count(n);  // 0

// 2. SOURCED_FROM edges carry the per-source claim properties
MATCH (n)-[r:SOURCED_FROM]->(s:Source)
WHERE s.source_id IN ["nvd", "cisa_kev", "mitre_attck", "virustotal",
                      "abuseipdb", "threatfox", "urlhaus",
                      "feodo_tracker", "ssl_blacklist"]
RETURN s.source_id,
       count(r) AS edges_total,
       count(r.source_reported_first_at) AS edges_with_first,
       count(r.source_reported_last_at) AS edges_with_last;

// 3. Excluded sources have NULL on the edge (no false claim)
MATCH (n)-[r:SOURCED_FROM]->(s:Source {source_id: "alienvault_otx"})
WHERE r.source_reported_first_at IS NOT NULL
RETURN count(r);  // expect 0

// 4. STIX export still produces non-1970 valid_from for CVE-2013-style
//    historical entries
MATCH (v:Vulnerability)
WHERE v.cve_id STARTS WITH "CVE-2013"
OPTIONAL MATCH (v)-[r:SOURCED_FROM]->(:Source)
RETURN v.cve_id,
       v.first_imported_at,                  // recent (today's sync)
       min(r.source_reported_first_at) AS valid_from;  // 2013 (correct)
```

## What's NOT backfilled

The 350k-node baseline keeps its existing `first_imported_at` / `last_updated`
values. Existing `SOURCED_FROM` edges have NULL `r.source_reported_first_at` /
`r.source_reported_last_at` until the next incremental sync touches them.
Within ~3 days of incremental cycles every active edge is repopulated.

## Operator FAQ

**Q: My GraphQL queries that asked for `first_seen_at_source` now return null.**
Update queries to traverse `SOURCED_FROM` instead. Or rely on the STIX
exporter / alert processor to do the aggregation.

**Q: STIX `valid_from` is wall-clock NOW for an old CVE I just imported.**
This means no source on the SOURCED_FROM edges has a `source_reported_first_at`
populated yet (incremental hasn't touched the node since the deploy).
Wait one sync cycle.

**Q: Can a stale MISP export regress my edge timestamps?**
No. MIN-with-AND-guard on `r.source_reported_first_at` only accepts strictly-
earlier values. MAX-with-AND-guard on `r.source_reported_last_at` only accepts
strictly-later values. Stale data cannot rewrite history.
