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

Every indicator/vulnerability carries **four canonical timestamps**, each
answering a distinct question (below); an Indicator additionally carries the
aging times (`last_reported_at`, `last_recorded_at`, `aging_since`,
`aging_evaluated_at`, `retired_at`; see Layer 3):

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
- Returns: `Optional[str]` — a tz-aware ISO-8601 string (naive input gets
  `+00:00`; an aware input keeps its offset) or `None`
- Naive datetime → assumes UTC, returns aware ISO
- Naive ISO string → injects `+00:00` offset (PR-M2 fix; was returning
  string unchanged, causing Finding 1's TZ shift)
- Unparseable input → `None` (refuses to export garbage)
- Sentinel rejection: integer epochs 0 and negative (and overflow) are
  rejected; strings have no year floor (a source's pre-1970 claim passes)

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
| **OTX pulse** | `pulse.created` | `pulse.modified` | Aware ISO. Indicator-level `indicator.created` overrides pulse-level when present, and `indicator.modified` overrides `pulse.modified` the same way. Not on the reliable first-seen allowlist (`reliable_first_seen=False`): the sync drops both claims, so OTX `SOURCED_FROM` edges carry no `source_reported_*` (pulse dates are publication dates). The attribute's `last_seen` still dates the indicator's aging (`last_reported_at`) |
| **MITRE ATT&CK** | STIX object's `created` | STIX object's `modified` | Aware ISO; canonical |
| **CISA KEV** | `dateAdded` | (not exposed; omit) | Date-only string; `coerce_iso` normalizes to `T00:00:00+00:00` |
| **CISA ICS advisory** | `initial_release_date` | `current_release_date` | CSAF aware ISO; earliest / latest over the advisories naming the CVE |
| **VirusTotal** | `attributes.first_submission_date` | `attributes.last_submission_date` | Unix epoch int; `coerce_iso` converts. **Missing → omit** (do NOT fall back to `now()`) |
| **ThreatFox** | `first_seen` | `last_seen` | `YYYY-MM-DD HH:MM:SS UTC`; `coerce_iso` strips the ` UTC` suffix (before 2026-10-13 the suffix made the value unparseable and both claims were dropped) |
| **URLhaus** | `dateadded` | `last_online` | Date or aware ISO |
| **Feodo Tracker** | `first_seen_utc` (earliest row of the address) | `last_online` (date; the first-seen time when both fall on the same day) | Naive UTC string / date; `coerce_iso` normalizes |
| **SSL Blacklist** | `Listingdate` | — | Naive UTC string; `coerce_iso` normalizes |
| **MalwareBazaar** | `first_seen_utc` | — | Emitted as aware UTC ISO by the collector |
| **AbuseIPDB blacklist** | (endpoint doesn't expose; omit) | `lastReportedAt` | **Reference pattern** for honest NULL |
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

Some collectors (CISA KEV, AbuseIPDB, ThreatFox / URLhaus, Feodo Tracker / SSL Blacklist,
VirusTotal enrichment) still set a wall-clock `last_updated` on their items; `MISPWriter`
does not send it, and the Neo4j writes set `n.last_updated = datetime()` whatever an item
carries. New collectors must not add it.

PR-M2 deletes `"last_updated": _coerce_to_iso(attr.get("timestamp"))`
from `parse_attribute` (Finding 11). It was a dead key — `merge_indicators_batch`
sets `n.last_updated = datetime()` server-side and never reads the
collector-supplied value. Latent trap.

### Layer 2 — MISP attribute

`_apply_source_truthful_timestamps` in `src/collectors/misp_writer.py`
populates the MISP 2.4.120+ native fields:

- `Attribute.first_seen` ← item's `first_seen` (passed through `coerce_iso`)
- `Attribute.last_seen`  ← item's `last_seen` (passed through `coerce_iso`)
- **Re-reported indicators (2026-10):** when a collector run reports an indicator MISP already
  holds for its source and MISP last wrote the stored copy (`Attribute.timestamp`) more than
  `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS` ago (default 30), `MISPWriter.push_items` edits the copy
  so that MISP writes a new `Attribute.timestamp`, which brings it into the next incremental sync.
  The edit sends `Attribute.last_seen` and nothing else: the item's `last_seen` when it is later
  than the stored one, otherwise the stored value unchanged. Concept 2 therefore holds only dates
  the source sent: a refresh never writes the time of a run into it (Invariant 1 holds for
  edited attributes too), and Concept 1 does not move. See
  [COLLECTORS.md](COLLECTORS.md#re-reported-indicators-2026-10).

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

**Indicator aging times (2026-10-16, `src/indicator_aging.py`).** An Indicator also keeps, forward
only, the latest report of any source: `n.last_reported_at` = `min(T, coalesce(L, T))`, where T is
the MISP attribute `timestamp` (when MISP recorded it, UTC) and L the source's own last-report date
(the attribute's `last_seen`, concept 2, capped at T), with `n.last_reported_source`,
`n.last_reported_ref` (the attribute uuid) and `n.last_reported_basis` (`source_date` / `misp_recorded`;
`n.aging_basis` is derived from it by the aging rule, `first_imported` without a report); and
`n.last_recorded_at`, the latest T. The indicator's `SOURCED_FROM` edge keeps that source's
`last_recorded_at`, `last_reported_at`, `last_reported_source` and `last_reported_ref` (not the
basis kind). The indicator ages from `coalesce(n.last_reported_at, n.first_imported_at)`;
`n.last_updated` (concept 4) is read neither for aging nor for ordering, so a re-sync of the same
data no longer makes an indicator look new. `n.aging_since` is when the node's aging state began.
`n.aging_evaluated_at` is the time at which the node's aging values were last written: by a write,
or by a job run that changed them; a job run that changes nothing leaves it unchanged. Every
evaluation, a write or the job, applies the rule at the database's current time (`datetime()`, a
database-local time like concept 4), lifted to this one when it is later, and stores that time
with the aging values; real time only moves forward, so a cleared or re-run task evaluates at the
time it runs, and the lift keeps two overlapping transactions or a clock set back from moving the
node's aging backwards. No DAG run passes a time. It is no source claim and is not read for
`modified`.

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
| `modified`             | ✅ | 2026-10-16: the latest of `created`, `n.last_recorded_at` and `n.aging_since` (`_indicator_created_modified`; it read concept 4, `n.last_updated`, before) | When a source last reported it or its aging state last changed; never before `created` |
| `valid_from`           | ✅ | Concept 1 (`r.source_reported_first_at`, MIN across edges) `??` Concept 3 (`n.first_imported_at`) `??` `now()` | See "valid_from fallback chain" below |
| `valid_until`          | ⏵ | (omit unless we have a real expiry) | Don't synthesize |
| `x_edgeguard_first_seen_at_source` | custom | Concept 1 (verbatim, MIN across edges) | Explicit preservation; absent if no source claim |
| `x_edgeguard_last_seen_at_source`  | custom | Concept 2 (verbatim, MAX across edges) | Explicit preservation; absent if no source claim |
| `x_edgeguard_first_imported_at`    | custom | Concept 3 | Explicit preservation |
| `x_edgeguard_last_updated`         | custom | Concept 4 | Explicit preservation |
| `x_edgeguard_first_seen_inferred`  | custom | `true` if `valid_from` came from the fallback chain (concept 3 or `now()`); absent / `false` otherwise | **PR-M2 addition.** Lets honest consumers filter for source-truthful evidence only |

#### Vulnerability SDO (STIX 2.1 §3.4)

A Vulnerability SDO represents the CVE itself. Its `created` / `modified` follow
`_producer_created_modified`, as for every SDO other than the Indicator; the CVE's own
timeline is carried in extension properties:

| STIX field | Maps to | Notes |
|------------|---------|-------|
| `created`  | Concept 3 (`n.first_imported_at`) via `_producer_created_modified` | When EdgeGuard first stored the CVE |
| `modified` | Concept 4 (`n.last_updated`) | When EdgeGuard last wrote it |
| `x_edgeguard_published`, `x_edgeguard_last_modified` | Node `published` / `last_modified` (NVD's record) | The CVE's own timeline (`_VULNERABILITY_PROMOTED_FIELDS`) |
| `x_edgeguard_first_imported_at`    | Concept 3 | When EdgeGuard ingested it (separate from NVD timeline) |
| `x_edgeguard_last_updated`         | Concept 4 | When EdgeGuard last refreshed |
| `x_edgeguard_first_seen_at_source` | Concept 1, MIN across the CVE's `SOURCED_FROM` edges | Earliest source claim (NVD `published`, KEV `dateAdded`, ICS `initial_release_date`) |
| `x_edgeguard_last_seen_at_source`  | Concept 2, MAX across the edges | Latest source claim |

Only Indicator SDOs carry `x_edgeguard_first_seen_inferred`.

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
  SDOs whose `valid_from` came from the fallback chain (design choice (c));
  a Vulnerability SDO has no `valid_from` and does not carry the flag

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
   set `reliable_first_seen=True` on its `Source(...)` entry in
   `src/source_registry.py` (`_RELIABLE_FIRST_SEEN_SOURCES` in
   `source_truthful_timestamps.py` derives from it)

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
  always returns NULL or a tz-aware ISO-8601 string
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

_Last updated: 2026-10-17 — corrections against the code: a Vulnerability SDO's `created` / `modified` are EdgeGuard's `first_imported_at` / `last_updated` (NVD's dates are `x_edgeguard_published` / `x_edgeguard_last_modified`; only Indicator SDOs carry `x_edgeguard_first_seen_inferred`); OTX claims are dropped by the reliable first-seen allowlist; CISA ICS row added; `coerce_iso` keeps an aware input's offset and has no year floor for strings; an Indicator's `SOURCED_FROM` edge keeps the report values, not the basis kind; the four canonical timestamps plus the aging times; collectors that still set `last_updated`; a reliable source is marked by `reliable_first_seen=True` in `src/source_registry.py`. Prior: 2026-10-16 — `n.aging_evaluated_at`, the time at which an indicator's aging values were last written (a job run that changes nothing leaves it unchanged); every evaluation applies the rule at the database's current time, lifted to it when it is later. Same day: the kind of an indicator's latest report is recorded in `n.last_reported_basis`; the aging rule derives `n.aging_basis` from it. Same day: indicator aging times: `last_reported_at` (`min(T, coalesce(L, T))`, the source's `last_seen` capped at the MISP timestamp), `last_reported_source`, `last_reported_ref`, `last_recorded_at` and `aging_basis` on the Indicator and its `SOURCED_FROM` edge, forward only; the indicator ages from `coalesce(last_reported_at, first_imported_at)`, never from `last_updated`; the STIX indicator's `modified` is the latest of `created`, `last_recorded_at` and `aging_since`._
