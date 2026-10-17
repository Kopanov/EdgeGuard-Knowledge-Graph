# EdgeGuard Timestamp Semantic Model

**Status:** Canonical. All timestamp handling in the pipeline conforms
to this document. If a code change conflicts with
this spec, fix the code or update the spec — never let them drift.

This document is the single source of truth for **what each timestamp
field means**, **where each one lives**, and **how each one maps into
STIX 2.1 export**. It exists because the recurring cause of timestamp
errors is confusion between *"when did the source observe this?"* and
*"when did EdgeGuard ingest this?"*.

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
- Naive ISO string → injects `+00:00` offset
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
| **NVD CVE 2.0** | `cve.published` | `cve.lastModified` | NIST publication timestamps. Naive ISO (no `+00:00`) — `nvd_collector.py` passes both through `coerce_iso` before emitting, which adds the UTC offset |
| **OTX pulse** | `pulse.created` | `pulse.modified` | Aware ISO. Indicator-level `indicator.created` overrides pulse-level when present, and `indicator.modified` overrides `pulse.modified` the same way. **Missing → omit** (no `now()` fallback). Not on the reliable first-seen allowlist (`reliable_first_seen=False`): the sync drops both claims, so OTX `SOURCED_FROM` edges carry no `source_reported_*` (pulse dates are publication dates). The attribute's `last_seen` still dates the indicator's aging (`last_reported_at`) |
| **MITRE ATT&CK** | STIX object's `created` | STIX object's `modified` | Aware ISO; canonical |
| **CISA KEV** | `dateAdded` | (not exposed; omit) | Date-only string; `coerce_iso` normalizes to `T00:00:00+00:00` |
| **CISA ICS advisory** | `initial_release_date` | `current_release_date` | CSAF aware ISO; earliest / latest over the advisories naming the CVE |
| **VirusTotal** | `attributes.first_submission_date` | `attributes.last_submission_date` | Unix epoch int; `coerce_iso` converts. **Missing → omit** (do NOT fall back to `now()`) |
| **ThreatFox** | `first_seen` | `last_seen` | `YYYY-MM-DD HH:MM:SS UTC`; `coerce_iso` strips the ` UTC` suffix |
| **URLhaus** | `dateadded` | `last_online` | Date or aware ISO |
| **Feodo Tracker** | `first_seen_utc` (earliest row of the address) | `last_online` (date; the first-seen time when both fall on the same day) | Naive UTC string / date; `coerce_iso` normalizes |
| **SSL Blacklist** | `Listingdate` | — | Naive UTC string; `coerce_iso` normalizes |
| **MalwareBazaar** | `first_seen_utc` | — | Emitted as aware UTC ISO by the collector |
| **AbuseIPDB blacklist** | (endpoint doesn't expose; omit) | `lastReportedAt` | **Reference pattern** for honest NULL |
| **MISP collector** | `event.date` | (varies) | Re-syncs from another MISP. **Missing → omit** at every emit site |

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
VirusTotal enrichment) set a wall-clock `last_updated` on their items; `MISPWriter`
does not send it, and the Neo4j writes set `n.last_updated = datetime()` whatever an item
carries. New collectors must not add it.

`parse_attribute` (`run_misp_to_neo4j.py`) puts no `last_updated` key into
the items it builds from MISP attributes: `merge_indicators_batch` sets
`n.last_updated = datetime()` server-side and never reads a supplied value.

### Layer 2 — MISP attribute

`_apply_source_truthful_timestamps` in `src/collectors/misp_writer.py`
populates the MISP 2.4.120+ native fields:

- `Attribute.first_seen` ← item's `first_seen` (passed through `coerce_iso`)
- `Attribute.last_seen`  ← item's `last_seen` (passed through `coerce_iso`)
- **Re-reported indicators:** when a collector run reports an indicator MISP already
  holds for its source and MISP last wrote the stored copy (`Attribute.timestamp`) more than
  `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS` ago (default 30), `MISPWriter.push_items` edits the copy
  so that MISP writes a new `Attribute.timestamp`, which brings it into the next incremental sync.
  The edit sends `Attribute.last_seen` and nothing else: the item's `last_seen` when it is later
  than the stored one, otherwise the stored value unchanged. Concept 2 therefore holds only dates
  the source sent: a refresh never writes the time of a run into it (Invariant 1 holds for
  edited attributes too), and Concept 1 does not move. See
  [COLLECTORS.md](COLLECTORS.md#re-reported-indicators).

**These are the source-truthful ones.** Do NOT confuse with:

- `Attribute.timestamp` — MISP's internal write-time epoch int. NOT a
  source claim. Used by MISP for sync/dedup. It is an epoch, not ISO:
  the manual STIX fallback passes it through `coerce_iso` before use.

### Layer 3 — Neo4j: nodes vs. SOURCED_FROM edges

EdgeGuard's source-truthful subsystem stores per-source claims on the
**`SOURCED_FROM` edge between the indicator node and its `Source`
node**, not on the node itself, because a node has multiple sources and
each source's claim lives on its own edge.

#### Node properties (concepts 3 and 4 — EdgeGuard-internal)

| Property | Concept | Set by | Updated |
|----------|---------|--------|---------|
| `n.first_imported_at` | 3 | Cypher `ON CREATE SET ... = datetime()` | Once, never overwritten |
| `n.last_updated`      | 4 | Cypher `SET ... = datetime()` on every MERGE | Every sync |

**Indicator aging times (`src/indicator_aging.py`).** An Indicator also keeps, forward
only, the latest report of any source: `n.last_reported_at` = `min(T, coalesce(L, T))`, where T is
the MISP attribute `timestamp` (when MISP recorded it, UTC) and L the source's own last-report date
(the attribute's `last_seen`, concept 2, capped at T), with `n.last_reported_source`,
`n.last_reported_ref` (the attribute uuid) and `n.last_reported_basis` (`source_date` / `misp_recorded`;
`n.aging_basis` is derived from it by the aging rule, `first_imported` without a report); and
`n.last_recorded_at`, the latest T. The indicator's `SOURCED_FROM` edge keeps that source's
`last_recorded_at`, `last_reported_at`, `last_reported_source` and `last_reported_ref` (not the
basis kind). The indicator ages from `coalesce(n.last_reported_at, n.first_imported_at)`;
`n.last_updated` (concept 4) is read neither for aging nor for ordering, so a re-sync of the same
data does not make an indicator look new. `n.aging_since` is when the node's aging state began.
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
| `modified`             | ✅ | The latest of `created`, `n.last_recorded_at` and `n.aging_since` (`_indicator_created_modified`); concept 4 (`n.last_updated`) is not read | When a source last reported it or its aging state last changed; never before `created` |
| `valid_from`           | ✅ | Concept 1 (`r.source_reported_first_at`, MIN across edges) `??` Concept 3 (`n.first_imported_at`) `??` `now()` | See "valid_from fallback chain" below |
| `valid_until`          | ⏵ | (omit unless we have a real expiry) | Don't synthesize |
| `x_edgeguard_first_seen_at_source` | custom | Concept 1 (verbatim, MIN across edges) | Explicit preservation; absent if no source claim |
| `x_edgeguard_last_seen_at_source`  | custom | Concept 2 (verbatim, MAX across edges) | Explicit preservation; absent if no source claim |
| `x_edgeguard_first_imported_at`    | custom | Concept 3 | Explicit preservation |
| `x_edgeguard_last_updated`         | custom | Concept 4 | Explicit preservation |
| `x_edgeguard_first_seen_inferred`  | custom | `true` if `valid_from` came from the fallback chain (concept 3 or `now()`); absent / `false` otherwise | Lets consumers filter for source-truthful evidence only |

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

Only Indicator SDOs carry `x_edgeguard_first_seen_inferred`; a Vulnerability SDO has no `valid_from`.

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

In the manual fallback:
- Report SDO `created` / `modified` / `published` are `now()`; `Event.date`
  (a date-only string, not a valid STIX timestamp) is not used
- Each contained Indicator SDO gets the same `valid_from` chain as the
  primary `_indicator_sdo` path (concept 1 → 3 → now, with the inferred
  flag); `_attribute_to_stix21` passes the MISP `attribute.timestamp`
  (a Unix epoch int) through `coerce_iso` before using it as `valid_from`

### `valid_from` fallback chain

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

## Windows and cursors

The same rules apply where a time window or a resume cursor is computed:

- **Sector window.** `get_sector_cutoff_date` (`src/config.py`; the start
  date of `run_misp_to_neo4j --sector`) counts `int(months * 30.437)`
  days, the average Gregorian month, so a 24-month window covers about
  731 days and loses no shoulder at its oldest end.
- **Incremental sync boundary.** When the MISP event index gives only the
  date-only `Event.date` (00:00:00 UTC), `_event_covers_since`
  (`src/run_misp_to_neo4j.py`) keeps an event whose day is on or after
  the day before `since` (`ev_day.date() >= (since - 1 day).date()`).
  `since` has a time of day and `Event.date` has none, so without the
  margin events at the window floor can be lost on every incremental run;
  the margin errs on the side of inclusion, and the few duplicates are
  resolved by MERGE.
- **OTX resume cursor.** The OTX checkpoint value
  `otx_last_pulse_modified` is parsed with `fromisoformat` and given
  `tzinfo=timezone.utc` when it is naive, so the resume cursor is always
  tz-aware (Invariant 2).

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
4. Add a regression test for the changed behaviour

---

## Test coverage

`tests/test_pr_m2_timestamp_semantic_model.py` exercises:

- **Helper unit tests** — `coerce_iso` accepts/rejects every input shape;
  always returns NULL or a tz-aware ISO-8601 string
- **Producer source-pins** — every collector that touches timestamps is
  pinned: forbidden `datetime.now()` fallbacks, required `coerce_iso`
  wrapping
- **Pipeline integration** — multi-source MIN/MAX CASE with mixed-TZ
  inputs
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
- Source registry: `src/source_registry.py`
- Knowledge graph schema: [`docs/KNOWLEDGE_GRAPH.md`](KNOWLEDGE_GRAPH.md)
- ResilMesh interop: [`docs/RESILMESH_INTEROPERABILITY.md`](RESILMESH_INTEROPERABILITY.md)

---

## Appendix: data written by earlier versions

The main text assumes a fresh baseline. A graph or MISP kept across an
upgrade can hold timestamps written before the rules above; the remedy
for all of them is a wipe and a fresh baseline (`edgeguard fresh-baseline`);
the downtime is one baseline cycle.

| Data written before | What it can hold | Repair without a fresh baseline |
|---|---|---|
| The `+00:00` injection in `coerce_iso` (2026-04) | NVD timestamps parsed by Neo4j as server-local time, shifted by the server's UTC offset on a non-UTC server | Cypher `+ duration({hours: <server offset>})` when the offset is known |
| The honest-NULL rule (2026-04) | Wall-clock run times stored as source first / last seen (VirusTotal, OTX, MISP collector) | None: the source value was never stored; such records age out |
| The 30.437-day month and the one-day sync margin (2026-04) | Events missing at the oldest end of a window or at an incremental boundary | Re-run the baseline; the MIN/MAX CASE merges without harm |
| The ` UTC` suffix handling for ThreatFox (2026-10-13) | ThreatFox `SOURCED_FROM` edges without `source_reported_*` (the values were unparseable) | None other than a fresh baseline |

STIX bundles need no repair: they are a view computed at export time.

---

_Last updated: 2026-10-17_

## History

- 2026-10-17 — Main text describes current behaviour only; the change notes of the timestamp model and its backwards-compatibility guide moved to History and the appendix.
- 2026-10-17 — Corrected against the code: a Vulnerability SDO's `created` / `modified` are `first_imported_at` / `last_updated` (NVD's dates are `x_edgeguard_published` / `x_edgeguard_last_modified`; only Indicator SDOs carry the inferred flag); OTX claims dropped by the reliable first-seen allowlist; CISA ICS row; `coerce_iso` keeps an aware input's offset and has no year floor for strings; an Indicator's `SOURCED_FROM` edge keeps the report values, not the basis kind; collectors that set `last_updated`; reliable sources marked by `reliable_first_seen=True` in `src/source_registry.py`.
- 2026-10-16 — Indicator aging times (`last_reported_at` with source, ref and basis, `last_recorded_at`, `aging_since`, `aging_evaluated_at`) on the Indicator and its `SOURCED_FROM` edge, forward only; aging from `coalesce(last_reported_at, first_imported_at)`, never from `last_updated`; the STIX Indicator's `modified` changed from `last_updated` to the latest of `created`, `last_recorded_at` and `aging_since`.
- 2026-10-13 — `coerce_iso` strips the ThreatFox ` UTC` suffix; before, both ThreatFox claims were unparseable and dropped.
- 2026-10 — Re-reported indicators: `MISPWriter` edits stored copies that MISP last wrote more than `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS` ago, so that they reach the next incremental sync.
- 2026-04 — Timestamp semantic model made canonical: `coerce_iso` injects `+00:00` into naive ISO strings (NVD times had been parsed as server-local); VirusTotal, OTX and the MISP collector (10 sites) stopped writing wall-clock time as source dates; NVD passes its dates through `coerce_iso` before emitting; the unread `last_updated` key removed from `parse_attribute`.
- 2026-04 — Export and windows: manual STIX fallback uses the `valid_from` chain and converts the MISP epoch through `coerce_iso`; `x_edgeguard_first_seen_inferred` added; sector window counts 30.437-day months; incremental boundary widened by one day; OTX resume cursor made tz-aware.
- 2026-04 — Per-source claims stored on `SOURCED_FROM` edges instead of the node (source-truthful timestamps).
