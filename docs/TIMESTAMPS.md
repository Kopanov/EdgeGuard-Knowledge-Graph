# EdgeGuard Timestamp Semantic Model

**Status:** Canonical (PR-M2, 2026-04). All timestamp handling in the
pipeline conforms to this document. If a code change conflicts with
this spec, fix the code or update the spec — never let them drift.

This document is the single source of truth for **what each timestamp
field means**, **where each one lives**, and **how each one maps into
STIX 2.1 export**. It exists because EdgeGuard has fixed timestamp bugs
in three previous PRs and the recurring root cause was conceptual
confusion between *"when did the source observe this?"* and *"when did
EdgeGuard ingest this?"*.

---

## TL;DR — the four canonical concepts

Every indicator/vulnerability flowing through EdgeGuard carries
**exactly four timestamps**, each answering a distinct question:

| # | Concept | Question | Example for CVE-2013-0156 ingested today |
|---|---------|----------|------------------------------------------|
| **1** | `source_reported_first_at` | *"When did the source claim this entity was first seen / published?"* | `2013-05-29T00:00:00+00:00` (NVD `published`) |
| **2** | `source_reported_last_at`  | *"When did the source last update this?"*                              | `2024-03-15T18:42:00+00:00` (NVD `lastModified`) |
| **3** | `first_imported_at`        | *"When did EdgeGuard first ingest this into our graph?"*               | `2026-04-21T08:00:00+00:00` |
| **4** | `last_updated`             | *"When did EdgeGuard last touch our record?"*                          | `2026-04-21T08:15:00+00:00` |

A consumer reading the full picture for that CVE understands:
**"This vulnerability was published by NIST on 2013-05-29 and last updated on
2024-03-15. EdgeGuard learned about it on 2026-04-21 and last refreshed
its record at 08:15 the same day."** Every field has one job.

---

## The two invariants

### Invariant 1 — Honest NULL

Concepts 1 and 2 (`source_reported_*`) are **NULLable**. If the source
didn't tell us when it first observed the indicator, we don't make it
up. We omit the field. Downstream consumers see NULL and know "no source
claim"; they don't see a wall-clock value masquerading as a real
observation.

The reference pattern is **AbuseIPDB blacklist** (`src/collectors/abuseipdb_collector.py`)
which omits `first_seen` for blacklist entries because the blacklist
endpoint doesn't expose it.

The anti-pattern (forbidden):

```python
# WRONG — silently lies about source observation time
"first_seen": pulse.get("created", datetime.now(timezone.utc).isoformat())
```

The correct form (mandatory):

```python
# RIGHT — honest NULL when source field is absent
"first_seen": pulse.get("created")  # may be None; coerce_iso(None) → None
```

### Invariant 2 — Always tz-aware UTC ISO-8601

Every timestamp crossing a layer boundary (collector → MISP → Neo4j → STIX)
is **either NULL or a tz-aware ISO-8601 string in UTC**. Canonical form
is `YYYY-MM-DDTHH:MM:SS+00:00` (or `Z` suffix — Neo4j and stix2 SDK both
accept either; stix2 normalizes `+00:00` to `Z` at validation time).

**Naive ISO strings are forbidden** because Neo4j's `datetime()` function
parses them as **server-local time**, not UTC. On a non-UTC Neo4j
deployment this silently shifts every naive timestamp by the server's
offset.

The single chokepoint is `coerce_iso()` in `src/source_truthful_timestamps.py`:

- Accepts: ISO string (with or without offset), Unix epoch (int/float),
  Python `datetime` (naive or aware), `None`
- Returns: `Optional[str]` — either a tz-aware UTC ISO-8601 string or `None`
- Naive datetime → assumes UTC, returns aware ISO
- Naive ISO string → injects `+00:00` offset (PR-M2 fix; was returning
  string unchanged, causing Finding 1's TZ shift)
- Unparseable input → `None` (refuses to export garbage)
- Sentinel rejection: epoch 0, negatives, year < 1970 — all rejected

`_stix_ts()` in `src/stix_exporter.py` is the STIX-boundary normalizer
that re-emits in `Z` form (stix2's `valid_from` validator rejects
`+00:00`).

---

## Where each concept lives, layer by layer

### Layer 0 — Source API response

Each provider has its own field names. The collector's job is to map
them to EdgeGuard's canonical `first_seen` / `last_seen` keys (concepts
1 and 2).

| Source | Concept 1 (`first_seen`) | Concept 2 (`last_seen`) | Notes |
|--------|--------------------------|-------------------------|-------|
| **NVD CVE 2.0** | `cve.published` | `cve.lastModified` | NIST publication timestamps. Naive ISO (no `+00:00`) — must pass through `coerce_iso` to add UTC offset |
| **OTX pulse** | `pulse.created` | `pulse.modified` | Aware ISO. Indicator-level `indicator.created` overrides pulse-level when present |
| **MITRE ATT&CK** | STIX object's `created` | STIX object's `modified` | Aware ISO; canonical |
| **CISA KEV** | `dateAdded` | (not exposed; omit) | Date-only string; `coerce_iso` normalizes to `T00:00:00+00:00` |
| **VirusTotal** | `attributes.first_submission_date` | `attributes.last_submission_date` | Unix epoch int; `coerce_iso` converts. **Missing → omit** (do NOT fall back to `now()`) |
| **ThreatFox** | `first_seen` | `last_seen` | Aware ISO |
| **URLhaus** | `dateadded` | `last_online` | Date or aware ISO |
| **Feodo / SSLBL** | First-seen column from CSV | (varies; often absent) | Date string; `coerce_iso` normalizes |
| **AbuseIPDB blacklist** | (endpoint doesn't expose; omit) | `lastReportedAt` | **Reference pattern** for honest NULL |
| **CyberCure** | (synthetic — not on reliable allowlist) | (synthetic) | Not source-truthful; safe |
| **MISP collector** | `event.date` | (varies) | Re-syncs from another MISP. **Missing → omit** (PR-M2 fixes 10 NOW-leaks at lines 248, 282, 302, 346, 373, 396, 422, 443, 465, 484) |

### Layer 1 — Item dict (collector → MISP writer)

Every collector emits items with these canonical keys:

```python
{
    "indicator_type": "ipv4",
    "value": "203.0.113.5",
    "first_seen": coerce_iso(source_value_or_None),   # Concept 1 (or None)
    "last_seen":  coerce_iso(source_value_or_None),   # Concept 2 (or None)
    # NO "last_updated" key — Cypher uses server-side datetime() (Concept 4)
    # NO "first_imported_at" key — Cypher uses server-side datetime() (Concept 3)
    ...
}
```

PR-M2 deletes `"last_updated": _coerce_to_iso(attr.get("timestamp"))`
from `parse_attribute` (Finding 11). It was a dead key — `merge_indicators_batch`
sets `n.last_updated = datetime()` server-side and never reads the
collector-supplied value. Latent trap.

### Layer 2 — MISP attribute

`_apply_source_truthful_timestamps` in `src/collectors/misp_writer.py`
populates the MISP 2.4.120+ native fields:

- `Attribute.first_seen` ← item's `first_seen` (passed through `coerce_iso`)
- `Attribute.last_seen`  ← item's `last_seen` (passed through `coerce_iso`)

**These are the source-truthful ones.** Do NOT confuse with:

- `Attribute.timestamp` — MISP's internal write-time epoch int. NOT a
  source claim. Used by MISP for sync/dedup. PR-M2 fixes Finding 3
  where the manual STIX fallback was treating this as ISO.

### Layer 3 — Neo4j: nodes vs. SOURCED_FROM edges

EdgeGuard's source-truthful subsystem stores per-source claims on the
**`SOURCED_FROM` edge between the indicator node and its `Source`
node**, not on the node itself. This is the architectural insight from
PR S5 (2026-04): a node has multiple sources; each source's claim lives
on its own edge.

#### Node properties (concepts 3 and 4 — EdgeGuard-internal)

| Property | Concept | Set by | Updated |
|----------|---------|--------|---------|
| `n.first_imported_at` | 3 | Cypher `ON CREATE SET ... = datetime()` | Once, never overwritten |
| `n.last_updated`      | 4 | Cypher `SET ... = datetime()` on every MERGE | Every sync |

#### Edge properties (concepts 1 and 2 — source-truthful per-source)

For each `(:Indicator)-[r:SOURCED_FROM]->(:Source)` edge:

| Property | Concept | Set by |
|----------|---------|--------|
| `r.source_reported_first_at` | 1 | MIN-CASE in `merge_indicators_batch` Cypher |
| `r.source_reported_last_at`  | 2 | MAX-CASE in `merge_indicators_batch` Cypher |

#### MIN/MAX CASE semantics

Each edge MERGE preserves the **earliest** reported `first_at` and the
**latest** reported `last_at` across all writes for that
(indicator, source) pair. Four-branch CASE:

```cypher
SET r.source_reported_first_at = CASE
    WHEN $first_seen_at_source IS NULL              THEN r.source_reported_first_at  -- no claim → preserve
    WHEN r.source_reported_first_at IS NULL         THEN datetime($first_seen_at_source)  -- first write
    WHEN datetime($first_seen_at_source) < r.source_reported_first_at
                                                    THEN datetime($first_seen_at_source)  -- earlier claim
    ELSE r.source_reported_first_at                                                       -- later claim → preserve
END
```

**Critical:** this CASE is internally sound but **dangerously fragile to
TZ mixing**. If one input is naive (parsed by Neo4j as server-local) and
another is tz-aware UTC, the comparison ranks them by their RAW datetime
literal, not by their absolute moment. Result: MIN picks the wrong edge.

This is why Invariant 2 is mandatory.

### Layer 4 — STIX 2.1 export

The export layer (`src/stix_exporter.py`) is the contract that ResilMesh
and other downstream consumers read. Each STIX SDO type has a canonical
mapping.

#### Indicator SDO (STIX 2.1 §3.2)

| STIX field | Required | Maps to | Notes |
|------------|----------|---------|-------|
| `created`              | ✅ | Concept 3 (`n.first_imported_at`) via `_producer_created_modified` | When the SDO was created in our system |
| `modified`             | ✅ | Concept 4 (`n.last_updated`) via `_producer_created_modified`    | When the SDO was last modified |
| `valid_from`           | ✅ | Concept 1 (`r.source_reported_first_at`, MIN across edges) `??` Concept 3 (`n.first_imported_at`) `??` `now()` | See "valid_from fallback chain" below |
| `valid_until`          | ⏵ | (omit unless we have a real expiry) | Don't synthesize |
| `x_edgeguard_first_seen_at_source` | custom | Concept 1 (verbatim, MIN across edges) | Explicit preservation; absent if no source claim |
| `x_edgeguard_last_seen_at_source`  | custom | Concept 2 (verbatim, MAX across edges) | Explicit preservation; absent if no source claim |
| `x_edgeguard_first_imported_at`    | custom | Concept 3 | Explicit preservation |
| `x_edgeguard_last_updated`         | custom | Concept 4 | Explicit preservation |
| `x_edgeguard_first_seen_inferred`  | custom | `true` if `valid_from` came from the fallback chain (concept 3 or `now()`); absent / `false` otherwise | **PR-M2 addition.** Lets honest consumers filter for source-truthful evidence only |

#### Vulnerability SDO (STIX 2.1 §3.4)

A Vulnerability SDO represents the CVE itself, not EdgeGuard's record
of it. The `created`/`modified` semantics differ:

| STIX field | Maps to | Notes |
|------------|---------|-------|
| `created`  | Concept 1 (NVD's `published`)      | The CVE was "created" when NIST published it |
| `modified` | Concept 2 (NVD's `lastModified`)   | When NIST last updated the CVE record |
| `x_edgeguard_first_imported_at`    | Concept 3 | When EdgeGuard ingested it (separate from NVD timeline) |
| `x_edgeguard_last_updated`         | Concept 4 | When EdgeGuard last refreshed |
| `x_edgeguard_first_seen_at_source` | Concept 1 (verbatim) | Same as `created`; explicit |
| `x_edgeguard_last_seen_at_source`  | Concept 2 (verbatim) | Same as `modified`; explicit |
| `x_edgeguard_first_seen_inferred`  | `true` if NVD timestamps absent and we synthesized | Should be rare for CVEs; NVD always provides `published` |

#### Report SDO (manual STIX fallback)

Reports are EdgeGuard-generated container objects. Their `created` is
*today* (when we generated the report) — this is correct STIX semantics.
The 2013-CVE-shows-as-2013 information lives **inside** the contained
Indicator/Vulnerability SDOs that the Report references via `object_refs`.

| STIX field | Maps to | Notes |
|------------|---------|-------|
| `created`     | `now()` | The Report itself is new |
| `modified`    | `now()` | Just generated |
| `published`   | `now()` | When we published the Report |
| `object_refs` | The contained SDO IDs | Each refd SDO carries source-truthful timestamps internally |

**PR-M2 fixes** (Findings 2, 3, 10): the previous manual fallback used
`Event.date` (today) as Report `created`/`modified` AND used the raw
MISP epoch int as Indicator `valid_from`. After PR-M2:
- Report SDO `created`/`modified` stays as `now()` (correct)
- Each contained Indicator SDO gets the same `valid_from` chain as the
  primary `_indicator_sdo` path (concept 1 → 3 → now, with inferred flag)

### `valid_from` fallback chain — the rule for design choice (c)

```
valid_from = source_reported_first_at IF available
          ELSE first_imported_at + set x_edgeguard_first_seen_inferred=true
          ELSE now() + set x_edgeguard_first_seen_inferred=true
```

| Branch | When | `x_edgeguard_first_seen_inferred` |
|--------|------|-----------------------------------|
| (1) Source-truthful | `r.source_reported_first_at IS NOT NULL` from any edge (primary path) — OR MISP-native `Attribute.first_seen` (manual-fallback path) | absent (or `false`) |
| (2) Inferred from import time | source claim absent BUT `n.first_imported_at` present (primary path) — OR MISP `Attribute.timestamp` present (manual-fallback path: when MISP first ingested the datum, analogous to `first_imported_at`) | `true` |
| (3) Inferred from now() | both absent (orphan SDO with no node context — defensive) | `true` |

**Manual-fallback path note.** The
``run_misp_to_neo4j._attribute_to_stix21`` path re-emits STIX directly
from MISP attributes without first writing to Neo4j (used when PyMISP's
``to_stix2()`` is unavailable). In that path, the canonical concept-3
analogue is **MISP ``Attribute.timestamp``** — the MISP-internal
write-time epoch for the attribute. It's not Neo4j's
``first_imported_at`` (that doesn't exist for this attribute yet) but
it's the closest available signal: MISP first ingested the datum at
that timestamp.  Better than wall-clock ``now()`` because it preserves
at least the MISP-side ingest history.

A conscientious consumer (e.g. ResilMesh's analyst-facing UI) can filter
for `x_edgeguard_first_seen_inferred IS NULL` to show only
source-truthful evidence; an automation consumer (correlation engine)
can use `valid_from` directly without worrying about NULLs. Both
audiences are served.

---

## What changed in PR-M2

The semantic model existed implicitly before; PR-M2 makes it explicit
and closes the bugs that violated it:

### Producer-side (Layer 0 → Layer 1)

- **F1.5** — `nvd_collector.py` now passes raw `published` / `lastModified`
  through `coerce_iso` before emitting (defense in depth — was relying
  on `coerce_iso` downstream)
- **F4** — `vt_collector.py` no longer falls back to `datetime.now()` when
  `first_submission_date` / `last_submission_date` is missing — omits
  the field (honest NULL)
- **F5** — `otx_collector.py` no longer falls back to `datetime.now()` when
  `pulse.created` / `pulse.modified` is missing — omits the field
- **misp_collector.py 10 NOW-leaks** (Agent 4 finding) — same
  honest-NULL conversion at lines 248, 282, 302, 346, 373, 396, 422,
  443, 465, 484
- **F11** — `parse_attribute` no longer stuffs the dead `last_updated`
  key into items (7 sites in `run_misp_to_neo4j.py`)

### Pipeline (Layer 1 → Layer 2)

- **F1** — `coerce_iso` full-string branch now injects `+00:00` when the
  parsed datetime is naive (mirrors `_stix_ts` line 145 pattern). Closes
  the Neo4j-parses-as-server-local TZ shift on every NVD ingest

### Storage (Layer 3)

No schema changes. Existing edge MIN/MAX CASE Cypher is correct under
Invariant 2. Pre-existing data with naive timestamps stays as-is until
re-ingested (see "Backwards compatibility" below).

### Export (Layer 4)

- **F2** — Manual STIX fallback now uses the same `valid_from` chain as
  `_indicator_sdo`. Each contained Indicator SDO carries source-truthful
  `valid_from` (or inferred-flag fallback)
- **F3** — `_attribute_to_stix21` runs MISP `attribute.timestamp` (Unix
  epoch int) through `coerce_iso` before using it as STIX `valid_from`.
  No more raw-epoch-as-ISO leaks
- **F10** — `event_date` wrapped through `_stix_ts(coerce_iso(...))`
  for STIX validator compliance (largely auto-resolved by F2)
- **NEW** — `x_edgeguard_first_seen_inferred = true` set on Indicator
  and Vulnerability SDOs whose `valid_from` came from the fallback chain
  (design choice (c))

### Cleanup

- **F6** — `SECTOR_TIME_RANGES` `months * 30` → `int(months * 30.437)`.
  Closes 10-day shoulder loss at the oldest end of a 24-month window
- **F7** — `_event_covers_since` boundary widened by 1 day. Closes
  3-hour-per-incremental-run cumulative loss
- **F9** — OTX checkpoint resume adds `tzinfo=timezone.utc` guard after
  `fromisoformat` to handle any naive checkpoint values from older
  versions

---

## Backwards compatibility

The 730-day baseline has likely produced data with corrupted timestamps
under the pre-PR-M2 bugs. Remediation strategy by bug class:

| Bug | Remediable for existing data? | Action |
|-----|------------------------------|--------|
| F1 (NVD TZ shift)   | Yes — Cypher `+ duration({hours: server_offset})` if operator knows their offset | **Deferred to follow-up PR** (PR-M2-followup migration script). PR-M2 stops the bleeding |
| F2, F3, F10 (STIX corruption) | Yes — STIX is a downstream view; re-export after PR-M2 produces correct bundles | **No action required**; next STIX export is correct |
| F4, F5 (wall-clock NOW leak) | **No** — ground-truth was never stored; can't recover | Operator can `fresh-baseline` after PR-M2 lands for a clean slate, OR accept tainted records age out via decay (typical 90-365 day windows) |
| F6, F7 (window/boundary)     | Yes — re-running baseline merges via MIN/MAX CASE without harm | Operator may re-run baseline if shoulder loss matters |
| F11 (dead key)               | No-op — the dead key was never read | No action required |

**Recommended operator action** after PR-M2 merges: run `edgeguard fresh-baseline`
to repopulate the graph with clean timestamps. Existing tainted records
will be replaced atomically; downtime is one baseline cycle.

---

## How to extend this model

### Adding a new collector

1. Identify the source's first-observation timestamp field (Concept 1)
   and last-update timestamp field (Concept 2)
2. Map them to item `first_seen` / `last_seen`, **always wrapped in
   `coerce_iso`**
3. **Never** add `datetime.now()` as a fallback for missing source
   fields — omit the key; let `coerce_iso(None)` return None
4. **Never** emit `last_updated` or `first_imported_at` from the
   collector — Cypher sets these server-side
5. Add a row to the Layer 0 table above
6. If the source is reliable enough to anchor source-truthful timestamps,
   add it to `_RELIABLE_FIRST_SEEN_SOURCES` in `src/source_registry.py`

### Adding a new STIX SDO type

1. Identify whether the SDO represents an EdgeGuard-internal record (use
   Indicator semantics) or a real-world entity (use Vulnerability
   semantics)
2. Always use `_producer_created_modified` for `created` / `modified`
   (or document why deviating)
3. Always call `_apply_source_truthful_custom_props` to attach the
   `x_edgeguard_*` extensions
4. If the SDO has its own validity timestamp (analogous to
   `valid_from`), use the source-truthful → import-time → now()
   fallback chain and set `x_edgeguard_first_seen_inferred` on the
   fallback branches
5. Add a row to the Layer 4 table above

### Modifying a timestamp helper

Any change to `coerce_iso`, `_stix_ts`, or `_clamp_future_to_now` must:

1. Preserve the contract documented above
2. Pass the property tests in `tests/test_pr_m2_timestamp_semantic_model.py`
3. Update this document if the contract changes
4. Add a regression test pinning the old behavior is gone

---

## Test coverage

`tests/test_pr_m2_timestamp_semantic_model.py` (introduced in PR-M2)
exercises:

- **Helper unit tests** — `coerce_iso` accepts/rejects every input shape;
  always returns NULL or tz-aware UTC ISO
- **Producer source-pins** — every collector that touches timestamps is
  pinned: forbidden `datetime.now()` fallbacks, required `coerce_iso`
  wrapping
- **Pipeline integration** — multi-source MIN/MAX CASE with mixed-TZ
  inputs (regression for the corruption Agent 2 identified)
- **End-to-end CVE-2013 fixture** — feed `published="2013-05-29T00:00:00Z"`
  through the full pipeline; assert STIX Indicator's `valid_from == "2013-..."`,
  `created == today`, `x_edgeguard_first_seen_at_source == "2013-..."`,
  `x_edgeguard_first_seen_inferred` absent
- **Inferred fallback fixture** — feed an indicator with no source
  `first_seen`; assert `x_edgeguard_first_seen_inferred == true`,
  `valid_from == first_imported_at`
- **Boundary tests** — epoch 0/1/9999, year 1900/9999, leap second

---

## References

- STIX 2.1 spec: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
- §3.2 Indicator SDO: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_muftrcpnf89v
- §3.4 Vulnerability SDO
- §3.6 Report SDO
- Flow audit: [`docs/flow_audits/04_timestamps_dates.md`](flow_audits/04_timestamps_dates.md)
- Source registry: `src/source_registry.py`
- Knowledge graph schema: [`docs/KNOWLEDGE_GRAPH.md`](KNOWLEDGE_GRAPH.md)
- ResilMesh interop: [`docs/RESILMESH_INTEROPERABILITY.md`](RESILMESH_INTEROPERABILITY.md)
