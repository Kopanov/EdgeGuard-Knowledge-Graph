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

## No migration / backfill needed

EdgeGuard is **pre-release**: no production graph carries the
deprecated node-level `n.first_seen_at_source` / `n.last_seen_at_source`
properties. Every Indicator/Vulnerability/etc. node MERGEd by the new
code stamps the per-source claim on the `SOURCED_FROM` edge from the
first sync onward.

For dev / staging environments that experimented with the pre-PR
node-level shape: a one-off migration is **NOT** provided because
the old node value was an aggregate (MIN across sources) — copying
it onto every edge would fabricate uniform per-source claims that
never existed (Bug Hunter v3 #1). The honest behavior is **NULL on
the edge until a real source-truthful claim arrives via the next
incremental sync**. NULL means "we don't know what this source
specifically claimed"; that is the correct semantic, not a bug to
paper over.

If you have an experimental dev graph with orphan node properties
and want to reset, drop the database (`MATCH (n) DETACH DELETE n`)
and let the baseline DAG repopulate from MISP — every node will
arrive through the new code path with correct edge claims.

## Operator FAQ

**Q: My GraphQL queries that asked for `first_seen_at_source` now return null.**
Update queries to traverse `SOURCED_FROM` instead. Or rely on the STIX
exporter / alert processor to do the aggregation.

**Q: STIX `valid_from` is wall-clock NOW for an old CVE I just imported.**
This means the source's first-reported timestamp wasn't extracted —
either the source isn't on the reliable allowlist (e.g. OTX,
CyberCure), the upstream feed didn't ship a `published` /
`dateAdded` / equivalent field for this entry, OR the value failed
calendar validation in `coerce_iso`. The fallback to
``i.first_imported_at`` (then to current wall-clock) is intentional —
NULL on the edge means "we don't have a source claim", and we
cannot honestly fabricate one. Check the source's actual response
for the entry; if it should have shipped a timestamp, file a
collector-side bug report.

**Q: Can a stale MISP export regress my edge timestamps?**
No. MIN-with-AND-guard on `r.source_reported_first_at` only accepts strictly-
earlier values. MAX-with-AND-guard on `r.source_reported_last_at` only accepts
strictly-later values. Stale data cannot rewrite history.
