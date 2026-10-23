# EdgeGuard Collectors Documentation

This document details all data collectors in EdgeGuard, including their sources, zone detection methods, and output formats.

---

## Table of Contents

1. [Overview](#overview)
2. [OTX Collector](#1-otx-collector)
3. [NVD Collector](#2-nvd-collector)
4. [CISA Collector](#3-cisa-collector)
5. [MITRE Collector](#4-mitre-collector)
6. [AbuseIPDB Collector](#5-abuseipdb-collector)
7. [VirusTotal](#6-virustotal-lookup-enrichment)
8. [Finance Feed Collector](#7-finance-feed-collector)
9. [Global Feed Collector](#8-global-feed-collector)
10. [Healthcare Feed Collector](#9-healthcare-feed-collector)
11. [Energy Feed Collector](#10-energy-feed-collector)
12. [MISP Collector](#11-misp-collector)
13. [CISA ICS Advisories Collector](#12-cisa-ics-advisories-collector)
14. [MalwareBazaar Collector](#13-malwarebazaar-collector)
15. [History](#history)

---

## Overview

### Zone Detection Method (Conservative)

Collectors use **`detect_zones_from_text()`** and **`detect_zones_from_item()`** from **`config.py`** (see source for exact weights).

EdgeGuard uses a **weighted scoring system** to limit false positives:

- **`ZONE_DETECT_THRESHOLD`** (default **1.5**, **`EDGEGUARD_ZONE_DETECT_THRESHOLD`**) — applied inside **`detect_zones_from_text`** per snippet (so a single strong keyword at `body` weight **1.5** can qualify).
- **`ZONE_ITEM_COMBINED_THRESHOLD`** (default **1.5**, **`EDGEGUARD_ZONE_ITEM_THRESHOLD`**) — applied in **`detect_zones_from_item`** after multi-field accumulation.
- Context weights in **`detect_zones_from_text`**: `name` / `alias` / `title` **3.0**, `description` **2.0**, `body` **1.5**, `tag` **1.0**.
- **NVD** (`nvd_collector.py`): builds an item with **`description`** + **`comment`** = flattened CPE text from **`configurations_to_zone_text()`** (criteria URIs + vendor/product tokens), then calls **`detect_zones_from_item`**.

```python
# Authoritative implementation — always read config.py
# detect_zones_from_text(...)  -> per-field threshold ZONE_DETECT_THRESHOLD
# detect_zones_from_item(...)   -> combined threshold ZONE_ITEM_COMBINED_THRESHOLD
```

#### Detection Rules
1. **Thresholds**: Defaults **1.5** for both per-field and combined-item scoring (overridable via env — see **`.env.example`**).
2. **Relative filtering**: In **`detect_zones_from_item`**, sectors must be within **50%** of the max combined score.
3. **Negative keywords**: e.g. “not healthcare”, “except bank” exclude that sector for the analyzed text.
4. **Clean keywords**: malware family names are not sector keywords — link via graph relationships.

### Duplicate avoidance (MISP + incremental runs)

- **`MISPWriter.push_items`**:
  - **Target event.** When **`EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS`** is true (default), it loads existing **`(type, value)`** on the target event via **`/attributes/restSearch`** and skips attributes already present — covers same-day reruns and overlapping incremental windows.
  - **Across events.** It also lists **`(type, value)`** across every MISP event that carries the source's tag (**`EDGEGUARD_MISP_CROSS_EVENT_DEDUP`**, default on) and skips those too. If that listing fails part-way, the keys read so far are used and the check falls back to the target event. NVD incremental runs and CISA KEV runs pass their own complete listing instead (`known_source_keys`).
  - **Order.** A complete listing (every page read, or `known_source_keys`) is checked **before** the day's event is looked up: a (source, date) group MISP already holds entirely neither looks up nor creates `EdgeGuard-{source}-{date}`, and the log says so (`… no event looked up or created`). With cross-event dedup off, or a listing that stopped early (an error, the page cap of 200 × 5,000 rows, logged), the event is looked up first, because partial keys can miss the copy in today's event and the refresh of a re-reported indicator needs the copy MISP wrote last.
  - **Items that cannot be converted.** Items no MISP attribute can be built from (an unknown item type, or an empty value, CVE id, name or ATT&CK id) are logged once per push, per source tag with how many of its items, the reasons and whether they count as failed (`[CONVERT] 3 item(s) could not be converted to a MISP attribute, 2 of them counted as failed (…): alienvault_otx: 1 of 300 item(s), not counted as failed (1 vulnerability with an empty cve_id); threatfox: 2 of 2 item(s), counted as failed (2 unknown item type 'campaign')`, writer stats `items_not_converted` and `items_not_converted_failed`); a group left without attributes creates no event. They count as **failed** pushes only when the drop is systemic for the source in that push: all of its items, or at least half of them (`CONVERT_FAILED_MIN_SHARE` = 0.5 in `misp_writer.py`). A source whose payload stops converting thus fails `status_after_misp_push`, and its error names both causes (attributes MISP did not store, items logged as `[CONVERT]`); OTX's dropped items also hold its cursor until the collector reads the payload again (listed in `last_push_unstored_items`, OTX below). A few bad records do not: a failed item would fail a run that pushes nothing new (`status_after_misp_push` passes a run with failures only when it pushed something and its success rate reaches the minimum), would keep the CISA ICS cursor, the cursor an NVD baseline seeds and the MITRE ATT&CK ETag, which move only after a push without failures, and would hold the OTX cursor below its pulse (after a push with failures OTX advances only up to the oldest pulse with an item the writer lists), so the next run would read the same bad record and fail again. The threshold lies far above the share one bad record has in a small incremental window: one bad item fails a push only when its source has at most two items in it. The price: a payload change that breaks only a minority kind of a mixed source (for example OTX's CVE references) is reported on every run but does not fail it.
  - **`[DEDUP] All N items were already present`** appears only when nothing failed or was dropped, N being the attributes found present.
  - **Edits.** The only edit `push_items` makes to a stored attribute is the refresh of a re-reported indicator ([below](#re-reported-indicators)); NVD and CISA KEV updates go through `MISPWriter.update_attribute` (below). Reducing **incoming** volume is the job of collector cursors below.
- **OTX** (non-baseline): stores **`otx_last_pulse_modified`** in **`checkpoints/baseline_checkpoint.json`** under **`[source].incremental`** (`get_source_incremental("otx")`). Each run fetches pulses with **`modified_since`** = last cursor minus **`EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC`**. First run with no cursor uses **`EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS`**. The cursor advances to the newest pulse of the run after a **clean** MISP push (**`failed == 0`**) or when there is nothing to push, and stays after a push that stored nothing. After a push with stored and failed items it advances no further than the newest pulse modified before the oldest pulse with an item the writer lists as unstored (`MISPWriter.last_push_unstored_items`, [MISP push](#misp-push-attribute-types-and-characters)): its batch or its event lookup failed, or no attribute could be built from it and the drop is systemic for the source (a payload the collector no longer reads, counted as failed; the cursor then stays until the collector is fixed). An item several pulses list holds the oldest of them. It stays when no pulse is older, when an unstored item names no pulse, or when the writer gives no list. Failures the writer does not list do not hold it: a single record no attribute could be built from (below `CONVERT_FAILED_MIN_SHARE`, reported and not counted as failed), a value with 4-byte characters and an attribute missing from a batch MISP partly stored, which a later run cannot store either. A batch MISP refuses on every run (HTTP 4xx, or a 5xx that persists) holds the cursor until it is fixed; each run logs the batch and counts its attributes as failed.
- **NVD** (non-baseline): stores **`nvd_last_modified_cursor`** under **`[nvd].incremental`**. Each run reads every CVE modified since the cursor minus **`EDGEGUARD_NVD_CURSOR_OVERLAP_SEC`** (first run with no cursor: **`EDGEGUARD_NVD_INCREMENTAL_DAYS`**), adds the CVEs MISP does not hold yet and edits the stored attribute of a CVE when NVD's data for it changed. The cursor advances only when every MISP write succeeded and the window was read completely. See [§ 2](#2-nvd-collector).
- **CISA KEV**: no cursor. Every run compares the whole catalogue with EdgeGuard's `source:CISA-KEV` copies, adds the CVEs MISP lacks and edits the copies of entries CISA revised (at most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN`; the rest follow on the next run). See [§ 3](#revisions-every-run-compares-the-catalogue-with-misp).
- **MITRE** (non-baseline): stores **`mitre_bundle_etag`**; sends **`If-None-Match`** to GitHub. **HTTP 304** skips download, parse, and MISP push. **Baseline** runs always fetch the full bundle. A changed bundle is pushed whole: `mitre` is in `config.OWN_RUN_CAP_SOURCES`, so `EDGEGUARD_INCREMENTAL_LIMIT` does not cut it. The ETag is saved only after **`failed == 0`** on MISP push (or immediately when **`push_to_misp`** is false) and only when no item limit cut the run (`EDGEGUARD_MAX_ENTRIES`; a cut run logs `[MITRE] item limit … the bundle's ETag is not stored`), so the next run reads the bundle again. MISPWriter skips the objects MISP already holds (same attribute type and value, the value holding the name), so a new ATT&CK release adds its new techniques, groups and software, and a renamed object as a new attribute under its new name; a changed description, relationship or deprecation of an object already held reaches the graph with the next fresh baseline.

### Re-reported indicators

The duplicate check above drops every indicator the source already holds in MISP, and the incremental MISP → Neo4j sync reads only attributes whose MISP timestamp moved. Without a refresh, the stored copy of an IOC a feed keeps listing would never be written again, and `decay_ioc_confidence` would lower the node at 90 and 180 days and retire it at 365 days while the feed still lists it. An indicator ages from its latest report, dated by the source's own last-report date capped at the MISP timestamp ([below](#the-source-date-an-indicator-ages-from), [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#indicator-aging)).

`MISPWriter.push_items` therefore refreshes such an indicator. When a collector reports an indicator (an item with `indicator_type`; not CVEs, ATT&CK objects or actors) that MISP holds for the same source in an earlier EdgeGuard event, and MISP last wrote that copy (its attribute `timestamp`) more than `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS` ago (default 30), the copy is edited with `update_attribute`. The edit sends `last_seen` and nothing else: the source's own last-seen date when the re-reported item carries one later than the stored value (AbuseIPDB's `lastReportedAt`; for OTX the indicator's `modified` in the pulse, or the pulse's `modified` when the indicator has none), otherwise the stored value unchanged. The field keeps holding what a source claimed, never the time of a run, and value, type, tags and comment stay as they are. MISP stamps the edited attribute and its event with a new timestamp (MISP 2.5 `AttributesController::edit`; the writer counts the edit only when MISP's answer shows a later timestamp), so the next incremental sync reads the attribute and merges the node again. The edit moves the indicator's age only when the source's `last_seen` moved (the report time is `min(T, coalesce(L, T))`), or, for a source without a date (SSL Blacklist, MalwareBazaar), to the time of the edit; a newer report lifts a decay retirement in the same write. An indicator re-reported within the interval keeps its older date until the interval has passed, so a source that keeps reporting an undated indicator holds it in the first tier (below 90 days). `first_imported_at` does not move, and the source's claims (`r.source_reported_first_at`, `r.source_reported_last_at`) move only when the source itself claims a later last-seen date ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), [TIMESTAMPS.md](TIMESTAMPS.md)).

- **Bound.** The decision reads MISP's write time, which the edit resets, so a copy is edited at most once per interval (30 days, well inside the first aging tier of 90 days); a copy a baseline wrote is first due 30 days after it. When the source holds the indicator in several EdgeGuard events, the copy MISP wrote last decides and is the one edited. A copy that carries the source tag in another event (an analyst's, a federated organisation's) is never edited: the sync does not read it, and it is not EdgeGuard's to change.
- **Which indicators.** Only what a collector run reports again is refreshed, and at most `EDGEGUARD_MISP_REFRESH_MAX_PER_RUN` of them per run. ThreatFox re-lists an IOC for 7 days and URLhaus `csv_recent` for 30 days after it was added, so their entries rarely need it; OTX refreshes the known IOCs of the pulses a run reads. Feodo Tracker and SSL Blacklist report their whole list per run, up to their own caps ([§ 7](#7-finance-feed-collector)), so the stored copy of every entry of the list a run reads is refreshed; the AbuseIPDB blacklist reports at most 10,000 addresses per run, which AbuseIPDB chooses ([§ 5](#5-abuseipdb-collector)), so a listed address outside that answer is not refreshed. A Feodo Tracker daily run reads the 30-day list (5 servers on 2026-10-12), not the complete history a baseline loads, so the history is not reported again; the feed has not been updated since 2026-03-04, its refreshed addresses keep their March `last_online` as `last_seen`, and they age from it. Each run refreshes at most `EDGEGUARD_MISP_REFRESH_MAX_PER_RUN` (2,000) copies within `EDGEGUARD_MISP_REFRESH_MAX_SECONDS` (600 s), the longest unwritten first, so a list of about 10,000 entries whose copies fall due together is refreshed over several daily runs.
- **Cost in MISP.** The cross-event prefetch reads every attribute of the source; for the refresh it keeps uuid, timestamp and dates for the keys the push reports, and reads each row's event name (no extra request; measured on 150,000 rows in the MISP 2.5 listing format and a push reporting 20,000 indicators, the parse of the listing takes 48 ms instead of 31 ms and about 3 MB more memory, against the seconds each listed page takes MISP to serve). Each refresh is one MISP request (`POST /attributes/edit/{uuid}`, retried like the NVD edits), paced with `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` after every 50 edits, which is also where the parent-DAG liveness check runs, the longest unwritten first. A run stops refreshing at `EDGEGUARD_MISP_REFRESH_MAX_PER_RUN` edits (default 2,000), once `EDGEGUARD_MISP_REFRESH_MAX_SECONDS` (default 600) is spent, or after 5 failed edits in a row (MISP failing: a failed edit costs up to three attempts with a 600 s read timeout each). An edit in flight is not interrupted, so a run can exceed the time budget by one edit's attempts; the shortest collector task limit is 1 hour.
- **Cost in the sync.** Each refresh moves the timestamp of the event that holds the copy: after a baseline, the source's single baseline event. The incremental sync selects events by event timestamp, downloads each selected event whole (PyMISP `get_event`), writes only the changed attributes, and for changed OTX items also parses the event's unchanged attributes to find the ones of the same pulses (report-scoped linking). Once refreshes begin, 30 days after a baseline, most incremental syncs therefore download and parse the OTX baseline event (149,270 attributes on 2026-10-13), as they already download the NVD baseline event (139,862 attributes) whenever NVD edits a stored CVE; the Feodo Tracker, SSL Blacklist and AbuseIPDB events (7,607 / 10,967 / 10,000 attributes) are read the same way. This has not been measured on the 730-day instance: time one incremental sync after the first refreshes, and set `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS=0` if the sync becomes too slow.
- **Accounting.** Refreshed, failed and deferred edits are counted in the writer's stats (`attributes_refreshed`, `attributes_refresh_failed`, `attributes_refresh_deferred`) and logged (`[REFRESH] N re-reported indicator(s) whose stored copy MISP last wrote more than 30 days ago: R refreshed, F failed, D left for a later run (reason)`; the push summary names the refreshed count). A failed or deferred refresh does not fail the push: the stored timestamp stays old and the next run that reports the indicator tries again.
- **Limit.** The refresh changes nothing but MISP's timestamp and, when the source claims a later date, `last_seen`. An existing IOC listed by a new OTX pulse does not receive that pulse's families, adversaries, report id or TLP: those travel in the attribute's `OTX_META` comment and tags, which this path never rewrites.
- **Off switch.** `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS=0`. All three variables are forwarded by `docker-compose.yml`.

### The source date an indicator ages from

An indicator ages from `min(T, coalesce(L, T))`: T is the MISP timestamp of the attribute, L the source's own last-report date the collector stored in the attribute's native `last_seen` (`MISPWriter._apply_source_truthful_timestamps`: the item's `last_seen`, or `last_modified` as an alias; dropped when earlier than `first_seen`, which MISP refuses). The sync reads L for every source (not through the first-seen allowlist: it can only make an indicator older than T), ignores one earlier than `EDGEGUARD_EARLIEST_IOC_DATE` or from an event whose creator the trust check refuses, and caps a later one at T (`run_misp_to_neo4j.misp_report_times`).

| Source (indicator collector) | L stored in `last_seen` | Collection time? |
|---|---|---|
| AlienVault OTX | the indicator's `modified` in the pulse, else the pulse's `modified` | no |
| ThreatFox | the IOC's `last_seen` (often empty for a new IOC: then T) | no |
| URLhaus | `last_online` (empty while the URL is online: then T) | no |
| Feodo Tracker | `last_online` (day resolution; the first-seen time on the first-seen day; none when empty or earlier, `feodo_last_seen`) | no |
| AbuseIPDB | `lastReportedAt` | no |
| VirusTotal (`vt_collector`, scheduled) | `last_submission_date` | no |
| VirusTotal (`virustotal_collector`, command line) | `last_analysis_date`, else `last_modification_date` | no |
| SSL Blacklist | none (the listing date is `first_seen`): T | — |
| MalwareBazaar | none (`first_seen_utc` is `first_seen`): T | — |

No indicator collector stores the collection time as `last_seen` (`MISPWriter._validate_honest_null` warns when a date lies within five minutes of the run); one that did would give `L = T` and change nothing. `aging_basis` on the node says which date dated its latest report (`source_date` or `misp_recorded`; recorded with the report as `last_reported_basis`).

### MISP push: attribute types and characters

MISP answers a batch push with HTTP 200 but does not store an attribute that fails its validation, and a single character its database cannot store fails the whole batch with HTTP 500. `MISPWriter` therefore:

- types a generic `hash` by the length of its hex digest: 32 characters → `md5`, 40 → `sha1`, 64 → `sha256`, 128 → `sha512` (`map_indicator_type`), because MISP does not store an MD5 or SHA1 value typed `sha256`;
- strips characters outside the Basic Multilingual Plane (4-byte UTF-8, such as emoji) from comments and tag names, because MISP's MySQL / MariaDB columns are 3-byte `utf8`. An attribute whose value needs such characters is skipped with a warning (`[SKIP] attribute value contains 4-byte characters`) and counted as failed, whatever MISP answers;
- reports attributes missing from MISP's answer as `[UNCONFIRMED]` ([AIRFLOW_DAGS.md](AIRFLOW_DAGS.md), MISP push accounting);
- lists after each push, in `last_push_unstored_items` (positions in the pushed list), the items MISP did not store because their batch failed (HTTP 4xx, a batch error, HTTP 429 or 5xx after the retries; with `EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING`, an HTTP 200 that confirms none of the batch) or because their event lookup failed, and the items no attribute could be built from when the drop is systemic for their source (counted as failed: a later run stores them once the collector reads the payload again). A skipped 4-byte value (counted as failed), a single item no attribute could be built from (reported only) and an attribute missing from a batch MISP partly stored are not listed. The OTX cursor stops below the oldest pulse with a listed item ([Duplicate avoidance](#duplicate-avoidance-misp--incremental-runs)).

The MISP → Neo4j sync gives an attribute without a `tlp:` tag the level `EDGEGUARD_DEFAULT_TLP` (default `white`) and logs the attribute's UUID (`[TLP]` warning): a push interrupted between the attribute insert and its tags leaves the attribute untagged, and its source may have stated a stricter level.

### Common Output Fields

All collectors return items with these common fields:

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Item type: `vulnerability`, `malware`, `actor`, `technique`, `tactic`, `tool` (indicators carry `indicator_type` instead) |
| `zone` | list | **All matching zones as array** (e.g., `['finance', 'healthcare']`) |
| `tag` | string | Source tag for MISP |
| `source` | list | Source identifiers (the collector's tag) |
| `confidence_score` | float | 0.0-1.0 confidence rating |
| `first_seen` | ISO-8601 or a feed date string, normalised to tz-aware UTC by MISPWriter (`coerce_iso`), **OPTIONAL** | Source's claim about when it first observed this entity (concept 1 in [`docs/TIMESTAMPS.md`](TIMESTAMPS.md)). **Omit when source field is absent — never substitute wall-clock NOW.** |
| `last_seen` | ISO-8601 or a feed date string, normalised to tz-aware UTC by MISPWriter (`coerce_iso`), **OPTIONAL** | Source's claim about when it last updated this entity (concept 2). Same omit-when-absent rule. |

**Note:** The `zone` property is always an array; items carry no `zones` property.

**`last_updated` on collector items.** The NVD, OTX, MITRE, CISA ICS, MalwareBazaar and VirusTotal (`vt_collector`) items carry no `last_updated` key. The CISA KEV, AbuseIPDB, ThreatFox, URLhaus, Feodo Tracker, SSL Blacklist and `virustotal_collector` items carry it (wall-clock time). MISPWriter never reads it, so it reaches neither MISP nor the graph: Cypher MERGE sets `n.last_updated = datetime()` server-side. Concepts 3 (`first_imported_at`) and 4 (`last_updated`) are EdgeGuard-internal and always set server-side. New collectors must not emit it.

**Honest-NULL invariant.** If a collector's source doesn't expose a first/last-seen field, OMIT the key from the item dict — do not substitute `datetime.now()`. The downstream MIN/MAX CASE on the `SOURCED_FROM` edge preserves any prior real claim from another source. The reference pattern is `src/collectors/abuseipdb_collector.py` (blacklist endpoint omits `first_seen` because the API doesn't expose it). See [`docs/TIMESTAMPS.md`](TIMESTAMPS.md) for the full semantic model.

---

## 1. OTX Collector

**File:** `src/collectors/otx_collector.py`

### What It Does
Collects threat intelligence pulses from AlienVault OTX, including:
- Indicators (IPs, domains, hashes, URLs, e-mail addresses) with per-indicator description. **Types:** `FileHash-MD5` / `-SHA1` / `-SHA256` reach MISP as `md5` / `sha1` / `sha256` (typed by digest length, above); import hashes (`FileHash-IMPHASH`), PE hashes (`FileHash-PEHASH`), JA3 TLS fingerprints and SSL certificate fingerprints (`SSLCertFingerprint`) are not collected, because typed by length they would be stored as file hashes (the run logs how many it left out: `[SKIP] OTX: N indicators of a non-file hash type`); OTX `email` indicators, and values of an unmapped OTX type that have the form `user@host.tld`, are typed as e-mail addresses (`email-src`), not as domains
- Malware families with the pulse's ATT&CK technique IDs as `reported_techniques` (a pulse-level association, written to MISP as `MITRE_USES_TECHNIQUES:{"rt":[…],"pid":"<pulse id>","rids":[…]}` — `rids` lists the other pulses of the same run that named the entity (the collector's dedup folds them in instead of dropping them; indicators carry the same list as `OTX_META.report_ids`); on MITRE actors the block also carries `m` (malware names) and `s` (tool S-ids) from the group → software `uses` relationships (`USES_MALWARE` / `USES_TOOL`) and linked downstream as `IMPLEMENTS_TECHNIQUE` with `match_type='otx_pulse'`, 0.6 — never as `uses_techniques` / `mitre_explicit`)
- **Family names without the ATT&CK software id:** OTX names families as the MISP ATT&CK galaxy names its clusters, with the ATT&CK software id as a suffix (`"Cobalt Strike - S0154"`, `"njRAT - S0385"`). Passed through, each would become a `Malware` node of its own (`cobalt strike - s0154`) beside the node ATT&CK delivers (`cobalt strike`), and the family's indicators would split between the two. The collector therefore names the malware item, its `family` and the indicators' `pulse_malware_families` / `pulse_malware_actor_pairs` by the base name (`split_attack_software_id` in `src/attack_software_names.py`: a trailing `<whitespace>-<whitespace>S` and four digits, case and extra whitespace ignored) and keeps the original string in the item's `aliases` (sent as an `alias:` tag; a same-run duplicate folds its aliases into the kept item). A `malware_families` entry is a string or an object named by `name`, `display_name` or, last, `id` (OTX gives a family its name as id; no recorded pulse in the repository carries an object entry, so the object shape is assumed); an entry with none of them is skipped.
- CVE references (all CVEs per pulse, no collection cap). A CVE's description follows the source ranking NVD > CISA KEV > CISA ICS > any other source, OTX among the others, whatever the order of the merges, and the node names the source in `description_source`. A CVE of a pulse reaches MISP as a `vulnerability` attribute with an `OTX_META` comment naming the pulse (`pulse_id`, the other pulses of the run that named it in `report_ids`): an OTX indicator of type CVE carries the indicator's block, a `cve_references` item a block of `pulse_id`, `report_ids` and `pulse_name`. The sync groups the CVE into its pulse from it, so the pulse's indicators are linked to it (`(Indicator)-[:INDICATES]->(CVE)`, `otx_pulse`, "named in the same report"; at most 50 CVEs and 2,000 indicators of a pulse, the first in event order; [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#relationship-types)), and takes only the block's own `description` field as a description, never the raw JSON (a `cve_references` block has none; it was empty in both OTX CVE attributes sampled from the hosted MISP on 2026-10-14), so CISA's KEV text describes a CVE that only OTX and the KEV name. A CVE attribute with a plain comment (the pulse reference "Referenced in OTX pulse: <name>" or "CVE from alienvault_otx", written for a `cve_references` item without a pulse id) gives no description and joins no pulse.
- **Pulse metadata:** `attack_ids` (MITRE ATT&CK), `industries` (the pulse's own sector classification, below), `targeted_countries`, `tags`, `references`, `author_name`, `adversary`, `TLP`
- **The pulse's industries as its sector statement.** A pulse that classifies itself into industries states, through its author, which sectors the campaign it describes targets. The zones those industries map to (`config.OTX_INDUSTRY_ZONE_ALIASES`, read through `config.otx_industry_zones`; an industry the table does not map gives none) join the zones keyword detection finds in the pulse (`zone`, below), and every item of the pulse carries the raw list (`otx_industries`). It travels to the sync as `OTX_META.otx_industries` on an indicator and as `MITRE_USES_TECHNIQUES.ind` on a malware family and an adversary (at most 20 names). A CVE the pulse lists as an indicator (OTX type `CVE`, a MISP `vulnerability` attribute) carries it in `OTX_META` like any indicator, and a CVE of `cve_references` carries none; the sync reads no industries from a `vulnerability` attribute, so `AFFECTS` never takes `otx_industries`. The sync takes the zones the item's industries map to as the pulse's statement (`stated_zones`, with the pulse as `stated_refs` on the OTX `SOURCED_FROM` edge): a `TARGETS` link to such a sector carries `otx_industries` (0.6), a sector only keyword detection found stays `zone_classification` (0.5), and a CVE the pulse names keeps `zone_classification` on `AFFECTS`, because a targeted industry says nothing about where a product is deployed (`src/sector_evidence.py`; [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Links to a Sector"). An item several pulses of one run list is the first pulse's item: the later pulses join `report_ids`, and the sectors their industries state join the item's zones and travel as `"<zone>|<pulse id>"` entries (`OTX_META.report_stated_zones`, `MITRE_USES_TECHNIQUES.rsz`; the first pulse of each sector first, and over the comment budget only the pulses still in `report_ids`), so each stated sector carries `otx_industries` and cites the pulses that stated it, whichever pulse listed the item first. The sectors keyword detection finds in a later pulse's text are not added (the item keeps the first pulse's inferred zones), and a sector inferred from the text cites every pulse of the item. Across runs MISP keeps the attribute written first (cross-event deduplication): a pulse of a later run that lists the same item adds neither its id nor its statement.
- **Pulse families / adversaries on every indicator:** each IOC item carries `pulse_malware_families` (the pulse's `malware_families`, cleaned, ≤ 20) and `pulse_malware_actor_pairs` (`"family::adversary::pulse"` for the pulse's families × its `adversary` names through `clean_actor_names`, ≤ 50 — the pair encoding keeps the same-pulse guarantee when several pulses' lists are unioned on one IOC); they travel as `OTX_META.mf` / `.pa`, accumulate on `Indicator.pulse_malware_families` / `.pulse_malware_actor_pairs`, and `build_relationships` Q9b / Q2d link them (`otx_pulse`, 0.6). `OTX_META.pa` holds the first pair of each family and adversary (the first pulse's) before the later pulses' pairs for them, and within the 4000-character comment `pa` is shortened before `report_ids` and `mf`, from the end, so the later pulses' pairs are dropped first and the first pairs stay while the comment fits ([MISP_SOURCES.md](MISP_SOURCES.md), "Metadata Comment Prefixes").
  - **One actor or several.** Whether a pulse's adversaries are one actor is decided here, on the pulse's whole `adversary` list (aliases of one actor count as one, canonical threat-actor reference): a pulse naming several actors gets no pairs, and every item of it lists the pulse in `several_actor_pulses` (`OTX_META.sap` on indicators, `MITRE_USES_TECHNIQUES.sap` on malware and actors), so the sync attributes nothing from it even when MISP has dropped some of its actors as duplicates. The mark also accumulates on the indicator (`Indicator.several_actor_pulses`): `build_relationships` step 2d and the acceptance check take a pulse marked there as naming several actors, as the collector judged it, besides the pulses whose actor nodes are several actors. Without the canonical reference the aliases of one actor count as several: the pulse still writes no pair, but its mark goes to `several_actor_pulses_by_name` (`OTX_META.sapn` / `MITRE_USES_TECHNIQUES.sapn`), which the sync uses for its own run and never stores on a node, so step 2d removes no link on a judgement made without the reference.
  - **A pulse edited later.** The actor nodes miss a pulse edited to name several actors after its pairs were written, because MISP does not push an actor it already holds again. Nor does MISP take an IOC it holds again, and the MISP writer adds no mark to a stored copy, because MISP keeps what the sources said and the mark is EdgeGuard's judgement: the mark of such a pulse reaches the graph only through its new IOCs, whose pushed attributes carry it. A pulse edited later to name several actors, whose IOCs MISP already holds and which brings no new IOC, is therefore not marked, and the pairs written before the edit stay linkable: a known limit, to be closed by a per-pulse MISP record.
  - **Linking.** Q2d links a pair to the adversary's node or, when the actor alias merge has folded that name away, to its canonical actor, with the pair's pulse as provenance. This is what keeps report-scoped linking working on regular updates: the family / actor attribute itself is a MISP cross-event duplicate after the first pulse and is never re-pushed. `OTX_META` is written for every pulse indicator.
- **TLP of an entity several pulses list:** when pulses of one run list the same IOC (or family, actor, CVE), the collector's dedup keeps the most restrictive `pulse_tlp` of those pulses (white / clear < green < amber < amber+strict < red, ranked as `MISPWriter` writes the `tlp:` tag; an empty or unknown value ranks as `EDGEGUARD_DEFAULT_TLP` and never displaces a stricter level). A pulse of a later run that lists an IOC MISP already holds does not change the stored TLP ([Re-reported indicators](#re-reported-indicators)).
- **Adversaries as ThreatActor items.** The pulse's free-text `adversary` field is decided once per pulse, and the actor items, the `family::adversary::pulse` pairs and the one-actor-or-several decision above all use the same names:
  - `actor_name_hygiene.clean_actor_names` splits composites (`"apt-c-13, sandworm"` → two names) and drops descriptions (`"multiple russian state-backed groups"`) and country or state names and nationality adjectives standing on their own (`"north korea"`, `"dprk"`, `"russian federation"`, `"iranian"`; `"North Korea (APT37)"` is `APT37`): a pulse whose adversary field reads `"APT37, North Korea"` names one actor and counts as a pulse naming one actor. A name that contains a country stays a name (`"cyber army of russia reborn"`). The run logs the distinct country, state and nationality names it dropped this way, alphabetically, each with the number of pulses that carried it and up to three of their ids (`[ACTOR-NAMES] OTX: N distinct country, state or nationality name(s) in M pulse(s), dropped from the adversary field by the actor-name hygiene (never actor names; a group named after a country needs a qualified name): north korea (2 pulses: <id>, <id>); russia (1 pulse: <id>)`; `actor_name_hygiene.dropped_geopolitical_names`). A fragment that yields a name is not listed (`"North Korea (APT37)"`); a country followed by a parenthetical that yields no name is (`"Cuba (Ransomware)"` lists `cuba`). A group whose common name is a country is written under a qualified name (`Cuba Ransomware Gang`), which the canonical threat-actor reference can give to an actor ([RUNBOOK.md](RUNBOOK.md), "Canonical threat-actor reference").
  - A name the same pulse lists both as adversary and as a malware family (equal actor key, the family also without its ATT&CK software id or a trailing parenthetical, every family of the pulse) is an actor only when the canonical threat-actor reference resolves it (a name the reference lists as ambiguous or never_merge, such as `winnti`, counts as unknown): `Kimsuky` or `Akira` stay actors, and so do the ransomware operations named after their own ransomware that the reference holds through override decisions (`Rhysida`, `BlackSuit`, `Trigona`), and so does a ransomware operation the reference holds as a name of its operator (`Conti`: Wizard Spider, `LockBit`: BITWISE SPIDER, `Qilin` and its earlier name `Agenda`: Water Galura); `Lumma Stealer` or `AsyncRAT` are not taken as actors for that pulse and stay its malware family item (a `Malware` node). A name that only another pulse lists as a family stays an actor. The run logs the distinct names it left out, how many and in how many pulses (`[ACTOR-NAMES] OTX: N distinct adversary name(s) in M pulse(s) …: <names>`, every name, alphabetically). An actor the reference lacks is added to the reference through `src/reference/canonical_threat_actor_overrides.json` ([RUNBOOK.md](RUNBOOK.md), "Canonical threat-actor reference"). Without the reference the rule cannot decide and the name is kept as an actor (the warning `[ATTRIBUTION] canonical reference unavailable` is logged once per run).
- **No entity description:** malware-family and adversary items carry no `description`, because the pulse's description describes the report, not the family or actor. A family or actor only OTX names shows no description; the pulse that first named it (and the other pulses of that run that named it) are in `n.pulse_ids[]`, later pulses link to it through `Indicator.pulse_malware_families` / `.pulse_malware_actor_pairs`. MISPWriter writes such an item's comment as the `MITRE_USES_TECHNIQUES` block alone. The sync takes no description from an OTX malware or actor attribute. The pulse's description is stored on no item (an indicator keeps its own `description`); it feeds sector detection, which scans the whole pulse, so it decides the `zone` of every item the pulse yields, families and adversaries included.

### Source
- **URL:** `https://otx.alienvault.com/api/v1/pulses/subscribed`
- **API Key:** Required (free)
- **Rate Limits:** ~30 requests/minute (free tier, 2s between requests)

### Zone Detection
```python
def detect_sectors(self, text: str) -> List[str]:
    return detect_zones_from_text(text)   # weighted scorer, config.py

pulse_text = json.dumps(pulse).lower()    # the whole pulse
sectors = self.detect_sectors(pulse_text)
# + the zones of the pulse's industries (config.otx_industry_zones); 'global' dropped once a sector is present
```

The zones are one list on the item; which of them its pulses stated is decided by the sync from `otx_industries` and `report_stated_zones` (above).

### Example Output

```python
# Indicator
{
    'indicator_type': 'ipv4',
    'value': '192.168.1.100',
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'tag': 'alienvault_otx',
    'source': ['alienvault_otx'],
    'first_seen': '2024-01-15T10:30:00Z',
    # no 'last_updated': set server-side by Cypher MERGE; collectors must not emit it.
    'confidence_score': 0.5,
    'description': 'C2 beacon indicator',
    'pulse_id': '5f3a2b...',
    'pulse_name': 'Emotet Banking Trojan IOCs',
    'attack_ids': ['T1059', 'T1071'],        # MITRE ATT&CK from pulse
    'targeted_countries': ['US', 'DE'],       # OTX geo targeting
    'pulse_tags': ['emotet', 'banking'],      # Pulse labels
    'pulse_references': ['https://...'],      # Source URLs
    'pulse_author': 'AlienVault',
    'pulse_tlp': 'white',
    'otx_industries': ['Finance'],            # the pulse's own industries (its sector statement)
}

# Malware (with ATT&CK technique IDs). A family the pulse names "Cobalt Strike - S0154" is
# 'name': 'Cobalt Strike', 'family': 'Cobalt Strike', 'aliases': ['Cobalt Strike - S0154'].
{
    'type': 'malware',
    'name': 'Emotet',
    'aliases': [],
    'malware_types': ['unknown'],
    'family': 'Emotet',
    # no 'description': the pulse's text describes the report, not the family
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'tag': 'alienvault_otx',
    'source': ['alienvault_otx'],
    'confidence_score': 0.5,
    'reported_techniques': ['T1059', 'T1071'],  # ATT&CK from pulse attack_ids (reported, not MITRE-explicit)
    'pulse_id': '5f3a2b...',   # source report id → report-scoped INDICATES / ATTRIBUTED_TO
    'pulse_name': 'Emotet Banking Trojan IOCs',
}

# CVE Reference (no cap — all CVEs from pulse)
{
    'type': 'vulnerability',
    'cve_id': 'CVE-2024-1234',
    'description': 'Referenced in OTX pulse: Emotet Banking Trojan IOCs',  # the MISP comment only of an item without a pulse id; never a CVE description
    'pulse_id': '5f3a2b...',   # → OTX_META.pulse_id: the pulse's indicators INDICATES this CVE (otx_pulse)
    'pulse_name': 'Emotet Banking Trojan IOCs',  # → OTX_META.pulse_name
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'tag': 'alienvault_otx',
    'source': ['alienvault_otx'],
    'first_seen': '2024-01-15T10:30:00Z',
    # no 'last_updated': set server-side by Cypher MERGE; collectors must not emit it.
    'confidence_score': 0.5,
    'severity': 'UNKNOWN',
    'cvss_score': None,  # a pulse reference carries no CVSS
    # no 'attack_vector'
}

# Threat Actor (auto-extracted from pulse adversary field — the free-text
# adversary goes through actor_name_hygiene.clean_actor_names: "apt-c-13, sandworm"
# → two actor items, "multiple russian state-backed groups" → none, "APT37, North Korea"
# → one; a name the pulse also lists as a malware family only when the canonical
# threat-actor reference knows it)
{
    'type': 'actor',
    'name': 'TA542',
    # no 'description': the pulse's text describes the report, not the actor
    'zone': ['finance'],
    'tag': 'alienvault_otx',
    'source': ['alienvault_otx'],
    'confidence_score': 0.5,
    'reported_techniques': ['T1059', 'T1071'],
    'aliases': [],
}
```

---

## 2. NVD Collector

**File:** `src/collectors/nvd_collector.py`

### What It Does
Collects CVE records from the National Vulnerability Database, including:
- CVE IDs and descriptions (up to 1000 chars)
- Every CVSS version NVD supplies (v4.0, v3.1, v3.0, v2), each with full component data
- `cvss_score` / `severity`: the record's first CVSS in the order v3.1 → v3.0 → v2 → v4.0 (`src/cvss_selection.py`); `None` / `UNKNOWN` when the record has none — rejected CVEs, CVEs awaiting NVD analysis without a CNA score. The CVSS 2 rating is read from the metric object, where NVD API 2.0 puts it.
- Affected products (CPE matching)
- `attack_vector`: NVD's word (`NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL`) for the attack vector of the CVSS that gives the score; `None` without CVSS. `result_impacts` come from the scoring CVSS when it is 3.x (none from CVSS 2 or 4.0).
- CWE identifiers
- Reference URLs and tags (advisory/patch links)
- **CISA KEV fields** — `cisa_exploit_add`, `cisa_action_due`, `cisa_required_action`, `cisa_vulnerability_name` (strongest signal of active exploitation; auto-boosts confidence to 0.9)

**NIST notice:** This product uses data from the NVD API but is not endorsed or certified by the NVD ([Start Here](https://nvd.nist.gov/developers/start-here)).


### Known-exploited CVEs outside the baseline window
A baseline also fetches, after its publication windows, the NVD record of every CVE on CISA's KEV list (NVD `hasKev`; `EDGEGUARD_NVD_BASELINE_KEV_SWEEP`, default on) and of the CVE ids in `EDGEGUARD_NVD_EXTRA_CVE_IDS`, whatever their publication date (`_fetch_supplementary_cves`). These records are not duplicated when a window already collected them, and a failed request is logged (`[NVD-KEV-SWEEP]`, `[NVD-EXTRA-CVE]`) and skipped. The KEV collector likewise takes the whole catalogue in baseline mode (`EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE`).

### Source
- **URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **API Key:** Optional (strongly recommended — higher throughput). Sent as HTTP header `apiKey` with the key value (per [NVD Developers — Start Here](https://nvd.nist.gov/developers/start-here)).
- **Rate Limits (NIST):** With key **50** requests / 30 seconds; without key **5** requests / 30 seconds. NIST recommends ~**6 seconds** between requests during bulk sync; this collector uses ~**0.7s** between paginated baseline/incremental pages when a key is set (still under the rolling cap) and ~**6.5s** without a key.

### Published-date API rules (implementation)
NVD 2.0 requires **`pubStartDate` and `pubEndDate` together**; each window **≤ 120 days**. The collector uses **`NVD_MAX_PUBLISHED_DATE_RANGE_DAYS`**, **`clamp_nvd_published_range()`**, and for baseline **`iter_nvd_published_windows()`** — see `src/collectors/nvd_collector.py`.

**Incremental runs** read every CVE NVD **modified** since a stored cursor (`checkpoints/baseline_checkpoint.json` → `nvd.incremental.nvd_last_modified_cursor`) and keep MISP in step with NVD (`NVDCollector._collect_incremental`):

- **Window.** `lastModStartDate` = cursor − `EDGEGUARD_NVD_CURSOR_OVERLAP_SEC` (default 3,600 s, at least 60 s, so a record NVD stamps with a clock behind the worker's is still read), `lastModEndDate` = now. Without a cursor (after a wipe, or on a deployment that never stored one), the run reads the last `EDGEGUARD_NVD_INCREMENTAL_DAYS` days (default 14).
- **Reading in slices.** The window is read in time slices, oldest first, each with a single request (`_iter_lastmod_slices`). NVD evaluates the query again for every request, so paging is unsafe: a record modified again while the window is paged leaves the result, and the records behind it move down past a page boundary (on 2026-10-14, 75 of 19,520 records left a 14-day window while it was paged). A single answer has no page boundary, and a record modified again during the run only moves after the window's end, where the next run reads it.
  - A window whose `totalResults` exceeds one answer (2,000) is split by time into slices of about 1,500 records; no slice spans more than 120 days. An answer that holds fewer records than its `totalResults` although it had room for more is not split further: its records are handled and the read counts as incomplete.
  - A slice that cannot be split into parts of at least 2 seconds (one narrower than 4 seconds) and still holds more than 2,000 records is paged instead. When `totalResults` drops between its pages, the stretch below the current index is read again; a further drop meanwhile, or an empty page before the end, marks the read incomplete.
  - Each slice is handled before the next is read, so memory stays at one slice.
- **CVEs MISP does not hold yet** (no `source:NVD` attribute) are added when they lie in the scope a baseline collects: published within `EDGEGUARD_BASELINE_DAYS` of now (default 730), on CISA's KEV list (`cisaExploitAdd`), or listed in `EDGEGUARD_NVD_EXTRA_CVE_IDS`. NVD also modifies older CVEs (1,002 published more than 24 months earlier in the 14 days to 2026-10-14); those are not added. The scope follows the `EDGEGUARD_BASELINE_DAYS` environment variable on the worker, default 730; the Airflow Variable `BASELINE_DAYS` and a run's `baseline_days` are not read. A test value left in place (such as 7) narrows the scope.
- **CVEs MISP holds.** The run lists them with `MISPWriter.index_source_attributes` once the first record has been read: the complete listing of `source:NVD` attributes, non-exportable tags included (`includeAllTags`). A listing that fails writes nothing, since a partial one would make stored CVEs look new. Each read CVE is rebuilt and compared with each stored copy:
  - `NVD_META` by digest (`nvd_meta_digest`). `last_modified`, keys with empty values and the order of `cwe`, `ref_tags`, `cpe_type` and `affected_products` are ignored, so a change only to data EdgeGuard does not store (translations, CNA product data) needs no edit. CISA's SSVC decision points (`ssvc`) are stored, so a change to them is an edit. `attack_vector` is ignored too, because it is derived from the CVSS payloads.
  - Tags by family; tag names compare without case, as MISP resolves them.

  A copy that differs is edited in place (`MISPWriter.update_attribute`, `POST /attributes/edit/{uuid}`):
  - the new `NVD_META` comment and `first_seen` / `last_seen`;
  - `severity:` and `cvss:` tags replaced;
  - zone, KEV and source tags added and never removed, `zone:Global` only on an attribute without a zone tag;
  - a `tlp:` tag only when the attribute has none.

  Edits pause `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` (default 5 s) after every 50, as `push_items` pauses between batches: the 5,000 writes a run may make wait about 8 minutes in all. The edit counts only when MISP's answer shows the new comment and tags. MISP 2.5 then moves the attribute's and the event's timestamps. The incremental MISP → Neo4j sync (changed attributes only, `EDGEGUARD_SYNC_ATTRIBUTE_FILTER`) reads the event again and writes the changed attributes. For an NVD record read from MISP (`nvd_record`), `merge_cve` then updates the `CVE` node as follows:
  - **Description, `published`, `last_modified` and `status`** are taken from the record; the four KEV fields (`cisa_exploit_add`, `cisa_action_due`, `cisa_required_action`, `cisa_vulnerability_name`) only where the node has none, since the KEV record owns them ([§ 3](#revisions-every-run-compares-the-catalogue-with-misp)). The dates come from NVD's record alone: a KEV, CISA ICS or OTX record, a STIX import or a partner write fills them only where the node has none. The description follows the source ranking NVD > CISA KEV > CISA ICS > any other source, with `description_source`, so NVD's text replaces theirs and theirs never replaces NVD's, whatever the order of the events in the sync. `status` becomes `["rejected"]` once NVD rejects the CVE.
  - **NVD's lists** (`cwe`, `ref_tags`, `cpe_type`, `result_impacts`, `reference_urls`, `affected_products`) are set from the record even when empty, on a node EdgeGuard manages whose only source is NVD; an empty list removes the property. CISA ICS, the KEV and OTX records and partner writes supply these lists as well, so on a node with another source an empty NVD list leaves the property as it is (on the hosted graph on 2026-10-15, 126,669 of the CVE nodes with `cwe` had NVD as their only source and 3,679 had NVD and another source). A record from another source only fills a list the node does not have, so it never replaces NVD's.
  - **CVSS sub-nodes** are updated for the versions the record has; a CISA ICS record only fills a property of a sub-node NVD has asserted, so the sub-node keeps NVD's values whatever the order. A sub-node of a version the record no longer has is removed (`_replace_nvd_owned_cve_data`), but only when EdgeGuard manages it and NVD is the only feed that asserted it: CISA ICS writes CVSS sub-nodes too. On a sub-node CISA ICS also asserted, NVD leaves `sources` and its event leaves `misp_event_ids` of both edges, so CISA ICS's next record (at the latest the next full sync) sets its values again, as a rebuild from the same records gives; until then the sub-node keeps NVD's values, and the impact and exploitability sub-scores CSAF does not give keep NVD's on a graph that is kept.
  - **CISA's SSVC decision points** (`ssvc_exploitation`, `ssvc_automatable`, `ssvc_technical_impact`, `ssvc_version`, `ssvc_timestamp`) are set from the record on any node and removed when the record has none: no other source supplies them, so a decision CISA changed or withdrew does not stay from an earlier record. Values outside SSVC's decision points are dropped on the way in (`nvd_collector.cisa_ssvc`, and again in `_replace_nvd_owned_cve_data`, since MISP is an input boundary).
  - **Score.** The node's `cvss_score`, `severity`, `cvss_version` and `attack_vector` are then derived from its remaining CVSS sub-nodes (`_set_cve_score_from_cvss`, the last step of `merge_cve`), so a CVSS version NVD withdrew stops scoring the node once its sub-node is removed or CISA ICS's next record has set its own values there.
  - **Not changed:** a removed KEV entry (the KEV fields are not cleared) and zones (they accumulate).

  `EDGEGUARD_NVD_UPDATE_EXISTING=false` leaves stored CVEs as they are.
- **Cap.** At most `EDGEGUARD_NVD_MAX_PER_RUN` MISP writes per run (default 5,000; additions plus edits; `EDGEGUARD_MAX_ENTRIES` lowers it when set; `EDGEGUARD_INCREMENTAL_LIMIT` does not apply to NVD). Records are handled in order of modification; a run that reaches the cap stops at that record and the next run continues there.
- **Cursor.** Moves only when the window was read completely and every write was confirmed: to the end of the window, or to the record at which the cap stopped the run.
  - Additions count as written when MISP's answers confirm them. When they do not confirm every addition (a failed batch, an attribute absent from the returned event, or an answer without an attribute list, as MISP 2.5 gives when every attribute of a batch fails validation), the run asks MISP by value (`MISPWriter.existing_values`), and only the CVEs MISP then holds count as added.
  - What keeps it: an addition MISP does not hold after that check, an edit MISP's answer does not confirm, or an incomplete read. The next run then reads the same changes again; CVEs already written compare as unchanged.
  - A cursor that stays fails the task, also when the run's writes clear `EDGEGUARD_MISP_MIN_SUCCESS_RATE`. The error names the CVEs not written (the first 20; `not_written` in the run's status lists up to 100). A write that fails on every run keeps the cursor until its cause is fixed, and the window grows meanwhile.
  - A baseline whose push succeeded stores its start time as the cursor when none is stored; on a resume, the start of the interrupted attempt. A wipe clears it.
- **NVD outage.** NVD not serving the window after the retries raises `NvdIncrementalUnavailable`, a transient error: the DAG task is skipped with an alert. Nothing is written and the cursor stays.
- **Volume (measured 2026-10-14).**
  - CVEs with any change per 8-hour interval: median 398, p90 1,483, maximum 2,516, so one to three requests. A request takes about 20 s per 2,000 records without a key, about 12 s with one.
  - Stored CVEs with a change to data EdgeGuard keeps: median 71, maximum 417 per interval, one MISP edit each. Counting only CVSS, CPE, CWE, description, status or KEV changes: median 26, maximum 287.
  - The MISP listing reads every `source:NVD` attribute, 28 pages of 5,000 (about 0.5 GB) for the 730-day baseline. An edit makes the next incremental sync read its event (the baseline's holds 139,862 attributes), but it writes only the changed ones.
  - Live dry run of 2026-10-14, cursor 13 Oct 13:00 UTC, writes intercepted: 5,887 CVEs read, 2,526 added (the 1,930 missing since the baseline among them), 768 edited (3 rejections), 2,146 unchanged, 447 outside the scope, in about 4 minutes.

**No age filter after the fetch.** What a run collects is decided by its request: a baseline's publication windows (plus the KEV sweep and named ids, whatever their age), an incremental run's lastMod window since its cursor. One selection rule applies in incremental runs: a CVE MISP does not hold yet is added only within the baseline's scope (above), compared on timezone-aware UTC values. No sector time-range check filters records after the fetch, because such a check (its cutoff computed after the windows are fetched) would cut the oldest hours of every baseline, any baseline longer than 24 months back to 24 months, and the KEV sweep's older records unless exempted (1,330 of 1,741 on 2026-10-14). OTX pulses are not filtered by their `created` time either, because a pulse created years ago can still be receiving new IOCs (a sampled pulse created in January 2023 had 42 of its 93 IOCs added within the last 24 months).

### Zone detection (implementation)

**`detect_sectors(description, configurations)`** builds `{"description": …, "comment": …}` where **`comment`** is plain text from **`configurations_to_zone_text()`** (CPE **`criteria`** strings plus vendor/product tokens from CPE 2.3 URIs). It calls **`detect_zones_from_item()`** — not `json.dumps` on the raw JSON (that breaks word-boundary keyword matches).

### Example Output

```python
{
    'type': 'vulnerability',
    'cve_id': 'CVE-2024-1234',
    'description': 'SQL injection vulnerability in hospital management system...',
    'zone': ['healthcare'],  # Array of all matching zones
    'tag': 'nvd',
    'source': ['nvd'],
    'first_seen': '2024-01-10T00:00:00Z',
    # no 'last_updated': set server-side by Cypher MERGE; collectors must not emit it.
    'confidence_score': 0.9,  # 0.9 when on CISA KEV, 0.6 otherwise
    'severity': 'HIGH',
    'cvss_score': 8.5,
    'attack_vector': 'NETWORK',  # NVD's word for the scoring CVSS's attack vector; None without CVSS
    'affected_products': ['cpe:2.3:a:hospital_mgmt:system:1.0:*:*:*:*:*:*:*'],
    'reference_urls': ['https://vendor.example.com/advisory/2024-001'],
    'cisa_exploit_add': '2024-01-12',       # date added to CISA KEV
    'cisa_action_due': '2024-02-02',        # federal remediation deadline
    'cisa_required_action': 'Apply update per vendor instructions.',
    'cisa_vulnerability_name': 'Hospital Mgmt SQL Injection',
}
```

---

## 3. CISA Collector

**File:** `src/collectors/cisa_collector.py`

### What It Does
Collects Known Exploited Vulnerabilities (KEV) from CISA, including:
- CVE IDs with exploitation confirmation
- Vendor and product information
- Required actions and due dates
- Known ransomware campaign use (`known_ransomware_use`; no score is derived from it)

**Scope:** every run, the baseline and the run of `edgeguard_medium_freq` every 4 hours, takes the whole catalogue, whatever an entry's `dateAdded` (`EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE`, default `true`; `false` takes only the entries whose `dateAdded` lies within a window of the baseline length), and compares it with EdgeGuard's MISP copies ([below](#revisions-every-run-compares-the-catalogue-with-misp)). `EDGEGUARD_CISA_INCREMENTAL_DAYS` is not read. With `false`, an entry outside the window is neither added nor edited, so its revisions reach neither MISP nor the graph; where NVD's record (the NVD KEV sweep) is the only one that gives it KEV fields, that record only fills them on the `CVE` node, so they keep its first values (a later NVD record shows only in the `raw_data` of NVD's edge).

### Source
- **URL:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **API Key:** Not required
- **Update Frequency:** Daily

### Zone Detection
```python
def detect_sectors(self, text: str) -> list:
    """Detect ALL sectors from vendor/project/product."""
    return detect_zones_from_text(text)
```

### Example Output

```python
{
    'type': 'vulnerability',
    'cve_id': 'CVE-2023-1234',
    'description': 'Remote code execution in power grid management software...',
    'zone': ['energy', 'finance'],  # Array of all matching zones
    'tag': 'cisa_kev',
    'source': ['cisa_kev'],
    'first_seen': '2024-01-15',
    'last_updated': '2024-01-15T09:00:00+00:00',  # emitted (wall-clock time); MISPWriter never reads it
    'confidence_score': 0.9,  # High confidence - confirmed exploited
    'severity': 'UNKNOWN',
    'cvss_score': None,
    # no 'attack_vector'
    'vendor': 'SCADA Systems Inc',
    'product': 'Grid Manager Pro',
    'required_action': 'Apply patch by due date',
    'due_date': '2024-02-01',
    'known_ransomware_use': 'Known'
}
# Note: the KEV catalogue carries no CVSS, so a KEV record has no score; the CVE's CVSS
# comes from the NVD collector, and the CVE node takes it from its CVSS sub-nodes whatever record
# arrives last.
# `known_ransomware_use` ("Known" / "Unknown") travels in NVD_META (and as the `ransomware:known`
# MISP tag) to the CVE node property of the same name.
# The description (CISA's short text) ranks below NVD's and above CISA ICS's and any other source's
# (with description_source "cisa_kev").
```

### Revisions: every run compares the catalogue with MISP

CISA revises entries in place and publishes no per-entry modification date. Between the cisagov/kev-data snapshot of 2026-05-22 and the feed of 2026-10-16, 26 entries went from ransomware use Unknown to Known, one description was extended and one due date moved (CVE-2022-0995, 2026-09-09 → 2026-08-29); none was removed, and every revised entry had been added more than 30 days earlier (the oldest on 2021-11-03). A run that took only recently added entries, or skipped every entry MISP already holds, would therefore never carry a revision to MISP or the graph.

Every run follows one path (`CISACollector._update_misp`, `src/collectors/vulnerability_update.py`): the stored MISP copy becomes CISA's latest statement.

- **Download.** The whole catalogue (about 1.8 MB, 1,748 entries on 2026-10-16). An empty answer, or an open circuit breaker, makes a skipped run (`skip_reason_class` `cisa_empty_catalogue`): nothing is compared or written, never "every entry was removed".
- **Scope and order.** The whole catalogue (above), newest `dateAdded` first, then by CVE id. The generic incremental limit (`EDGEGUARD_INCREMENTAL_LIMIT`, 200) does not apply: `cisa` and `cisa_kev` are in `config.OWN_RUN_CAP_SOURCES`.
- **Listing.** EdgeGuard's copies are listed once (`MISPWriter.index_source_attributes("source:CISA-KEV", "vulnerability", keep_meta=True)`, every page, non-exportable tags included; one page of about 1,750 attributes). A listing that fails writes nothing and fails the run, since a partial one would make stored CVEs look new. Only copies in events EdgeGuard created (`Event.info` starting with `EdgeGuard-`, the rule of the indicator refresh) are compared and edited: a copy in another event (an analyst's, a federated organisation's) is never edited, and a CVE MISP holds only in such events is neither added nor edited and is counted (`foreign_only`) with a WARNING naming the first 20. The sync reads more events than these: every event whose `Event.info` contains `EDGEGUARD_MISP_EVENT_SEARCH` (default `EdgeGuard`, in any case) or whose organisation is named `EdgeGuard`; a copy in such an event that does not start with `EdgeGuard-` is synced but not kept in step (Limits). A MISP answer whose rows lacked their event would show up there, as every CVE.
- **Comparison.** Each entry is rebuilt as the attribute a new push would write and compared with each stored copy (`MISPWriter.plan_vulnerability_update`):
  - `NVD_META` by digest: `shortDescription` (its first 500 characters), `vendorProject`, `product`, `dateAdded`, `dueDate`, `requiredAction`, `vulnerabilityName` and `knownRansomwareCampaignUse`; empty values count as absent;
  - tags by family: `severity:` and `cvss:` are replaced and, for KEV, the tag `ransomware:known`, the only ransomware tag EdgeGuard writes (`KEV_REPLACED_TAGS`), so an entry CISA reverts to Unknown loses it; any other `ransomware:` tag (a machine tag of MISP's `ransomware` taxonomy an analyst attached) is left alone and plans no edit; zone, `CISA-KEV` and source tags are only added; `tlp:` only when the copy has none.
- **Additions.** A CVE MISP lacks is added through `push_items`, given the listing (`known_source_keys`), so MISP is not listed twice. Additions MISP's answers do not confirm are looked up by value (`MISPWriter.existing_values`), as in the NVD incremental run.
- **Edits.** A copy that differs is edited in place (`MISPWriter.update_attribute`, `POST /attributes/edit/{uuid}`): the new `NVD_META` comment, `first_seen` and the tag changes. An edit counts only when MISP's answer shows it and an attribute timestamp later than the stored copy's, because the incremental sync re-reads an attribute only when that timestamp moves. The edits follow the stop rules of the indicator refresh: a pause of `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` (default 5 s) and the parent-DAG liveness check after every 50 edits; no edit starts once `EDGEGUARD_MISP_REFRESH_MAX_SECONDS` (default 600) is spent, nor after 5 failed edits in a row.
- **Cap.** At most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN` edits per run (default 500): the CVE whose edits would pass it and the CVEs after it are deferred. A deferred edit is no failure: the comparison is stateless, so the next run plans it again. Additions are not capped. A run's explicit limit cuts the additions and lowers the edit cap. `EDGEGUARD_KEV_UPDATE_EXISTING=false` adds new entries only and leaves stored copies as they are.
- **Removals.** A CVE MISP holds in an EdgeGuard event that the catalogue no longer lists is counted (`stored_not_in_catalogue`) and logged at WARNING with the first 20 ids; its MISP copy and the node's KEV fields stay.
- **Status.** The additions plus the attempted edits are the run's items in `status_after_misp_push`, so a failed edit fails the run like a failed addition (`EDGEGUARD_MISP_MIN_SUCCESS_RATE`). `kev_update` in the status holds `catalogue`, `catalogue_version`, `scope`, `added`, `updated`, `unchanged`, `stored_not_updated`, `foreign_only`, `deferred`, `failed`, `not_written` (up to 100 CVE ids), `changed_keys` (the `NVD_META` keys of each planned edit, up to 100 CVEs), `stored_not_in_catalogue`, `stored_not_in_catalogue_ids` and `stop_reasons`.
- **Logs.** One line per edit, `[KEV-UPDATE] CVE-2026-63077 attribute <uuid> event <id>: known_ransomware_use; tags +ransomware:known` (INFO; a WARNING `… MISP did not confirm the edit (planned: …)` when MISP's answer does not show it), and one summary line per run, for example `CISA KEV: catalogue 2026.10.16 (2026-10-16T17:15:48.8752Z) of 1748 entries, 1748 in scope; 9 added, 2 updated, 1737 unchanged, 0 stored and not updated, 0 only in other events, 0 deferred, 0 failed; 0 stored and no longer in the catalogue`.
- **Graph.** The incremental MISP → Neo4j sync re-reads the edited attribute through the normal path. On the `CVE` node a KEV record sets `cisa_exploit_add`, `cisa_action_due`, `cisa_required_action`, `cisa_vulnerability_name` and `known_ransomware_use`; NVD's record only fills the first four where the node has none, in either order of the sync (NVD did not move `lastModified` when CISA moved the due date of CVE-2022-0995, so NVD's MISP copy kept the old date). The `SOURCED_FROM` edge's `raw_data` holds the latest KEV record (the reduced record of the opt-in STIX import never replaces it). The description follows the source ranking NVD > CISA KEV > CISA ICS, so a revised KEV text shows on the node only where NVD gave none ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md)).
- **Volume.** Per run: one catalogue download and one listing page; about 5 edits a month in steady state (measured from the snapshots of 2026-05-22, 2026-09-16 and 2026-10-08 against the feed of 2026-10-16) and 1 to 5 additions a day. Each edit makes the next incremental sync download the KEV event that holds the copy (the baseline event holds about 1,750 attributes); only the edited attributes are merged.

**Limits.**
- Removals never propagate: an entry dropped from the catalogue keeps its MISP copy and its node fields (counted and logged only).
- KEV `notes`, `cwes` and `forensicTriage` (BOD 26-04) are not stored in `NVD_META`, so a change to them is not seen, and the GraphQL fields `cisaNotes` and `cisaCwes` stay empty. `shortDescription` is compared up to its 500th character (9 entries are longer on 2026-10-16).
- A change to EdgeGuard's own rules for KEV items (the zone keywords, the TLP, the `NVD_META` keys) looks like a revision of every affected entry and edits each copy once, within the cap.
- That `POST /attributes/edit` moves the event's timestamp, which the sync selects events by, rests on MISP 2.5's code (`AttributesController::edit` → `unpublishEvent`), not on a test against MISP; the first live edit is the check ([RUNBOOK.md](RUNBOOK.md)).
- A KEV copy in an event the sync reads but EdgeGuard did not create (`Event.info` containing `EdgeGuard` without starting with `EdgeGuard-`, or an event of the `EdgeGuard` organisation with another title) is synced but never edited: when the sync merges it after EdgeGuard's copy (a full sync reads events by ascending attribute count), its older record sets the node's four KEV fields and the edge's `raw_data` back. Such copies are not counted apart from EdgeGuard's.
- KEV copies in other events are not edited; NVD's update path does edit such copies, and its edit loop keeps its own code without these stop rules (moving it to `vulnerability_update` is a planned follow-up).

---

## 4. MITRE Collector

**File:** `src/collectors/mitre_collector.py`

### What It Does
Collects threat intelligence from MITRE ATT&CK framework, including:
- Attack techniques (T###)
- Threat actors (intrusion sets)
- Malware families
- Relationships (uses, attributed-to, subtechnique-of) — STIX **`uses`** populates **`uses_techniques`** on **actors** and **malware** for **`build_relationships.py`** (malware round-trips via MISP **`MITRE_USES_TECHNIQUES:`**)
- **Descriptions:** ATT&CK's description of each group, malware, tool, technique and tactic (up to 500 characters). MISPWriter writes it on the line after the comment's `MITRE_USES_TECHNIQUES` / `MITRE_TACTIC_PHASES` block where there is one, else as the whole comment (a tactic, a technique without tactic phases, a tool without techniques, a group or malware with nothing for the block); groups, techniques and tactics up to 255 characters, malware and tools up to 400. MITRE's record ranks first for a `Malware`, `ThreatActor`, `Tool`, `Technique` or `Tactic` node's description (MITRE ATT&CK > a curated source > any other source, with `description_source`), so ATT&CK's text stays whatever the order of the merges.

### Source
- **URL:** `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- **ATT&CK for ICS (`EDGEGUARD_ENABLE_MITRE_ICS=true`, default off):** `ics-attack/ics-attack.json` from the same repository (`MITRE_ICS_ATTACK_URL` to override) is fetched after the Enterprise bundle and parsed with the same code (`_parse_bundle`, kill-chain name `mitre-ics-attack`). 97 techniques (T08xx), 12 tactics (TA0100–TA0111, 9 short names identical to Enterprise), 14 groups, 23 malware. Every item carries `attack_domain` (`enterprise` | `ics`); groups/malware present in both bundles are emitted once with `uses_techniques` unioned. An ICS fetch/parse failure is logged, counted (`pipeline_errors_total{task=collect_mitre_ics}`) and never affects the Enterprise items; the MITRE circuit breaker is not tripped. No ETag for ICS: on an Enterprise HTTP 304 the ICS bundle is skipped (baseline runs ignore ETag). ICS items are **not** auto-zoned `energy` (`x_mitre_sectors` / assets unused — follow-up).
- **API Key:** Not required
- **Format:** STIX 2.1 bundle

### Revoked and deprecated objects

The ATT&CK bundles keep replaced and retired objects. `_parse_bundle` (Enterprise and ICS alike):

- **Revoked** (`revoked: true`, with a `revoked-by` relationship to the successor): skipped, whatever the type. No item, no relationship to or from it (`uses`, `subtechnique-of`, `attributed-to`), so no `uses_techniques` / `uses_malware` / `uses_tools` entry names it. A revoked group's or software's name and aliases are appended to its successor's `aliases` (the successor's own aliases first; a chain A → B → C ends on C): `UNC2452` → `APT29`, `Dragonfly 2.0` → `Dragonfly`, `Stolen Pencil` → `Kimsuky`, `Darkmoon` → `PoisonIvy`. Tool items carry `aliases` too (`x_mitre_aliases`), but the MISP writer tags aliases of actors and malware only, so a tool's aliases do not reach the graph.
- **Deprecated** (`x_mitre_deprecated: true`, no successor): kept, with `deprecated: True`; every other item carries `deprecated: False`. The MISP writer tags a deprecated item `attack-status:deprecated`; the sync turns the tag into `n.deprecated = true`.
- The log line `skipped N revoked ATT&CK objects {...} and M relationships that reach them` gives the counts per bundle.

Feeds that still name a revoked technique id (OTX pulses citing `T1086`) are translated to the successor downstream, with `src/reference/attack_revoked_ids.json` (`src/attack_revoked.py`; see `docs/KNOWLEDGE_GRAPH.md`, "Revoked and deprecated ATT&CK objects"). Groups and software need no map: the bundle names every successor. A revoked technique the map does not list is therefore kept, with the warning `[ATTACK-REVOKED] N technique(s) the bundle revokes are not in the revoked-id map (…)`, so the links that cite it are not lost; rebuild the map (`docs/RUNBOOK.md`, "Rebuilding the ATT&CK revoked-id map") and the next run skips it.

### MISP values

MISPWriter writes each technique, tactic (Enterprise and ICS) and tool as a MISP `text` attribute whose value is the ATT&CK id, ` - ` and the name (`attack_values.format_attack_value`): `T1059.003 - Windows Command Shell`, `TA0002 - Execution`, `T0807 - Command-Line Interface`, `S0005 - Windows Credential Editor`. A group is a `threat-actor` attribute and a malware a `malware-type` attribute, each valued by its name. The ATT&CK values carry no colon, so MISP's default Import Regexp rules, which rewrite a value where any character, a colon and any character precede "Windows" (`/.:.Windows./i` → `%WINDIR%\`), leave them unchanged ([MISP_SOURCES.md](MISP_SOURCES.md#attribute-types-and-values)). The MISP → Neo4j sync reads the id and the name back with `attack_values.parse_attack_value`, which also reads `<id>: <name>`, and skips a value without a valid ATT&CK id with an `[ATTACK-VALUE]` warning. MISPWriter's dedup (per event and across events) reads a `text` value in either form as the same ATT&CK entry (`attack_values.attack_value_key`), so an entry stored as `<id>: <name>` is not written again as `<id> - <name>`; a value MISP rewrote holds no valid id and counts as a different value. The check that confirms a push compares the exact value.

### Zone Detection
```python
def detect_sectors(self, text):
    """Detect ALL sectors from technique/actor description."""
    return detect_zones_from_text(text)
```

### Example Output

```python
# Technique
{
    'type': 'technique',
    'mitre_id': 'T1566.001',
    'name': 'Spearphishing Attachment',
    'description': 'Adversaries may send spearphishing emails with malicious attachments...',
    'zone': ['global'],  # Array of all matching zones
    'tag': 'mitre_attck',
    'source': ['mitre_attck'],
    'platforms': ['Windows', 'macOS', 'Linux'],
    'data_sources': ['Application Log', 'File', 'Network Traffic'],
    'deprecated': False,  # True for an object ATT&CK deprecated; revoked objects are skipped
    'confidence_score': 0.8
}

# Threat Actor
{
    'type': 'actor',
    'name': 'APT29',
    'aliases': ['Cozy Bear', 'The Dukes', 'PowerDuke', 'UNC2452', 'StellarParticle'],  # + revoked groups' names
    'description': 'APT29 is a threat group that has been attributed to the Russian government...',
    'zone': ['healthcare', 'finance'],  # Array of all matching zones
    'tag': 'mitre_attck',
    'source': ['mitre_attck'],
    'confidence_score': 0.7,
    'uses_techniques': ['T1566', 'T1059'],  # From STIX actor→technique **uses** (example)
}

# Malware
{
    'type': 'malware',
    'name': 'Conti',
    'malware_types': ['Ransomware'],
    'family': 'Conti',
    'description': 'Conti is a ransomware family that has been used in attacks against healthcare...',
    'zone': ['healthcare', 'finance', 'energy'],  # Array of all matching zones
    'tag': 'mitre_attck',
    'source': ['mitre_attck'],
    'confidence_score': 0.7,
    'uses_techniques': ['T1486', 'T1490'],  # From STIX malware→technique **uses** (example)
}

# Tool (from MITRE ATT&CK)
{
    'type': 'tool',
    'mitre_id': 'S0002',
    'name': 'Mimikatz',
    'description': 'Credential dumping tool...',
    'zone': ['global'],
    'tag': 'mitre_attck',
    'source': ['mitre_attck'],
    'tool_types': ['credential-theft'],
    'confidence_score': 0.7,
    'uses_techniques': ['T1003.001', 'T1078'],
}
```

---

## 5. AbuseIPDB Collector

**File:** `src/collectors/abuseipdb_collector.py`  
**Class:** `AbuseIPDBCollector`  
**DAG:** `edgeguard_daily` (`collect_abuseipdb`)

### What It Does
Fetches IP reputation / blacklist data from the AbuseIPDB API v2 and pushes indicators to MISP:
- The blacklist (`GET /blacklist`, `confidenceMinimum` 90): for each address, the abuse confidence score (`confidence_score` = score / 100), the country code and `lastReportedAt` (the last-seen time the source reports; the endpoint gives no first-seen date). MISP receives the address, `last_seen`, the tags and the comment `AbuseIPDB confidence: N%, Country: XX`. Reverse DNS, hostnames, ISP, usage type, the Tor and whitelist flags and reports come only from the `check` endpoint (`check_ip`, `enrich_ip`), which no DAG task calls.

### Source
- **Base URL:** `https://api.abuseipdb.com/api/v2`
- **API Key:** Required — `ABUSEIPDB_API_KEY`
- **Rate limits:** Free tier ~1,000 checks/day and 5 blacklist requests per UTC day; collector enforces ~1 request/second (`MIN_INTERVAL_SECONDS`)

### Blacklist quota and cached answer
- **A 429 fails the task.** A blacklist request answered with HTTP 429 means the day's 5 requests are spent. The request returns the 429 at once, without the rate-limit backoff (502, 503 and 504 are retried), and `collect()` reports a failure (`daily blacklist quota exhausted (429)`), so `collect_abuseipdb` turns red and the lost day's blacklist is signalled. Operator steps: [RUNBOOK.md](RUNBOOK.md), "AbuseIPDB daily blacklist quota".
- **The answer is reused within the UTC day.** A successful, non-empty answer is written atomically to `<EDGEGUARD_STATE_DIR or ./state>/abuseipdb_blacklist_cache.json` (the directory from `collector_utils.state_dir()`, shared with the VirusTotal ledger) with its request parameters and fetch time. A run that asks for the same parameters (`confidenceMinimum`, `limit`) reuses it and sends no request while it was fetched on the current UTC day (AbuseIPDB's quota day) and is at most `EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS` old (default 20, forwarded by `docker-compose.yml`; `0` turns the cache off). This covers the task's retries after a MISP push failure, a cleared task, and a baseline or daily run with the same parameters on that day; the log line `reusing the blacklist fetched … (<age>h old, …)` shows it. The daily and the baseline runs share one cache key: with the default settings both ask for `{confidenceMinimum: 90, limit: 10000}` (`limit` is `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN`, the same in both DAGs; see the per-run cap below), so a baseline that collects later on the UTC day of a daily run, within the maximum age, reuses that run's answer and sends no request, and the daily run reuses a baseline's answer fetched after 00:00 UTC that day. Only a lower `limit` gives a run its own request: `EDGEGUARD_MAX_ENTRIES` below 10,000 (daily runs) or a baseline `BASELINE_COLLECTION_LIMIT` below 10,000. An answer from an earlier UTC day is not reused, so the 02:00 UTC daily run never works from the previous day's answer; it reuses one only when a run with the same parameters fetched it after 00:00 UTC that day (for example a failed daily task cleared after midnight), and otherwise sends a request. The file holds the latest answer only; a run with other parameters sends its own request and replaces it. An empty answer is not kept, and a failed write only logs a warning.
- **Dates.** A reused answer carries the `lastReportedAt` values of the original fetch, never a later date; it misses at most the reports made since the fetch, within the same UTC day.

### Per-run cap
At most one `GET /blacklist` request per run, and none when the run reuses the answer fetched earlier on the same UTC day ("Blacklist quota and cached answer" above); `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` (default 10,000, forwarded by `docker-compose.yml`) is that request's `limit`, so the stored copy of every address the answer lists is reported again on each run.

- **Within the plan's limits.** The cap changes the size of the answer, not the number of requests: the daily run makes at most one, a baseline at most one more, and a run that reuses the answer fetched earlier on the same UTC day makes none (with the default settings the two runs share one cache key, so on a day with both, the run that collects second sends no request while the first one's answer is within the maximum age). 10,000 is the most one blacklist request returns on the free plan (`AbuseIPDBCollector.BLACKLIST_MAX_PER_REQUEST`; the 730-day baseline of 2026-10-13 received 10,000). A larger value is logged and the request still asks for 10,000; a plan that returns more per request needs that ceiling raised, never more requests. `0` = 10,000; `EDGEGUARD_MAX_ENTRIES` still applies when lower. The source key check uses the `check` endpoint, not the blacklist.
- **Which addresses.** AbuseIPDB chooses which addresses fill the request; an answer that fills it is logged (`the blacklist answer fills the request …`), because the blacklist may list more. An answer longer than the request keeps the addresses reported most recently (`lastReportedAt`) and logs a warning.

### Zone detection
`detect_zones_from_text` on the country code and, when the answer carries them, ISP, usage type and domain (the blacklist answer does not); `global` when nothing matches.

---

## 6. VirusTotal (lookup enrichment)

**File:** `src/collectors/vt_collector.py` (`VTCollector`)  
**DAG:** `edgeguard_medium_freq` (every 4 hours) — task id `collect_virustotal` → `run_vt_collection`. Not part of the baseline DAG.

### What It Does
The public (free) VirusTotal API v3 offers **single-object lookups only** (`GET /files/{hash}`); feed and Intelligence-search endpoints need a premium licence and return nothing on a free key. The collector therefore does not act as a feed. Each run:

1. lists the SHA-256 attributes other sources pushed to MISP — ThreatFox, MalwareBazaar, OTX and others (`attributes/restSearch`, type `sha256`, attribute timestamp within `EDGEGUARD_VIRUSTOTAL_CANDIDATE_DAYS`, default 30 days; VirusTotal's own attributes are excluded by tag) — and drops the hashes the ledger remembers as already looked up;
2. looks each remaining hash up within the per-run cap and the daily budget (below);
3. pushes the enriched items to MISP under `source:VirusTotal`. The MISP→Neo4j sync merges each one into the **same** Indicator node as the source that reported the hash (the hash key is case-insensitive).

What a lookup adds to the graph:

| Graph element | Value | From |
|---|---|---|
| `(Indicator)-[:SOURCED_FROM]->(Source {source_id: "virustotal"})` | a second source edge; `source_reported_first_at` / `source_reported_last_at` = first and last submission to VirusTotal | `first_submission_date`, `last_submission_date` |
| `confidence_score` | 0.8 when about two thirds or more of the engines flag the file, otherwise 0.5; the node keeps the highest value across its sources | `last_analysis_stats` |
| `threat_label` | VirusTotal's suggested label, for example `trojan.mirai/gafgyt` | `popular_threat_classification.suggested_threat_label` |
| `yara_rules`, `sigma_rules` | names of matching crowdsourced rules (added to the lists on the node) | `crowdsourced_yara_results`, `sigma_analysis_results` |
| `zone` | sectors detected in file names, tags and sandbox verdicts (usually `global`) | keyword detector |

VirusTotal deliberately sends no `malware_family` and no `reference`: both are single-valued on the node and the last writer wins, so a corroborating source would overwrite the family reported by ThreatFox or MalwareBazaar. For the same reason a lookup creates no `INDICATES` edge by itself. MD5, SHA-1, file size and sandbox verdicts are not carried. The label and rule names travel in the shared feed-metadata comment (`TF_META`), written only when VirusTotal returns them.

Hashes are looked up **once** while the ledger remembers them. It keeps the most recent 20,000 delivered lookups (`LOOKED_UP_MAX`), hashes unknown to VirusTotal (HTTP 404) included, so a remembered hash is not looked up again. An enriched hash is remembered only after its MISP push succeeded. The ledger is the only record of what was looked up (MISP cannot tell which hashes of other sources were enriched): if the file is lost, hashes inside the candidate window are looked up again, which costs quota but creates no duplicate attributes. The query shape was confirmed against a live MISP 2.5 on 2026-10-12 (HTTP 200, `response.Attribute` list).

### Free-tier safety (never blocks the workflow)

| Limit | Enforcement |
|-------|-------------|
| 4 lookups/min | `RateLimiter(requests_per_minute=4)` in-process. Every lookup passes the limiter exactly once: the HTTP helper is called without retries, because a retried request would bypass the limiter and the budget |
| 500 lookups/day | Ledger `virustotal_daily_budget.json` in the state directory (`./state` bind mount): `EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET` (default **400**) per UTC day, `EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN` (default **60**) per run — six runs a day stay below the budget |
| HTTP 429 | The day is marked exhausted in the ledger; the run stops and pushes what it has. Exception: within two minutes of a source key check (`src/source_key_check.py`, one lookup spent by another process) the answer may be the shared per-minute limit, so the run stops without marking the day and the next run continues. A 5xx or a transport error is counted and the run goes on; three in a row stop it |
| Budget exhausted | Task returns `skipped=True`, `skip_reason_class="virustotal_daily_budget"` (`virustotal_rate_limited` when VirusTotal answered 429 before any lookup succeeded); the Airflow task stays green and downstream continues |
| MISP candidate listing fails | `skip_reason_class="virustotal_candidates_unavailable"` (no lookup is spent) |
| MISP unreachable while pushing the results | `skip_reason_class="virustotal_misp_unavailable"`: a skip, not a failed task, because Airflow retries a failed task and each retry would spend the same lookups again. The hashes stay eligible for the next run |
| Task killed mid-run (execution timeout, worker restart) | The ledger is written every 10 lookups, so at most 10 lookups are unaccounted on the retry |
| Per-run cap set too high | `EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN` is capped at 200: more cannot finish in the task's one-hour timeout at 4 lookups a minute |
| API key missing / rejected | `missing_virustotal_key` / `virustotal_auth_denied` |

Keep `EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET` at or above six times the per-run cap (the task runs six times a day). A skipped run does not refresh the collector's last-success time, so a budget that runs out early in the day, or a day ended by an HTTP 429, raises the `EdgeGuardCollectionStale` alert for `virustotal` after nine hours; with the defaults (400 and 60) the budget is never exhausted by the schedule itself.

Every quota message is logged with the prefix **`[VT-QUOTA]`** (budget state at the start of the run, exhaustion events, run summary with lookups / enriched / unknown / errors), so `grep VT-QUOTA` on the task log shows what happened. The task result carries `vt_lookups`, `vt_enriched`, `vt_unknown`, `vt_lookup_errors`, `vt_stopped`, `vt_budget_used`, `vt_budget_remaining`.

Coverage: at the defaults at most 360 hashes per day (six runs of 60) gain VirusTotal corroboration. This is a sample, not full coverage: after a fresh baseline every SHA-256 attribute in MISP is inside the candidate window (the window is the attribute's MISP timestamp, not the age of the indicator), candidates are taken in the order MISP returns them, and hashes that are not reached within the window are not looked up later. Fuller coverage needs a premium key (raise the two budget knobs; the collector logic does not change) or a narrower candidate selection, for example by source.

### Zone Detection
```python
def _detect_zones_from_attributes(self, attrs):
    """Detect ALL sectors from file names, tags, sandbox verdicts and the popular threat label."""
    ...
    return detect_zones_from_text(combined_text)
```

### Example Output

```python
# Hash enrichment (from GET /files/{sha256})
{
    'indicator_type': 'hash',
    'value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'zone': ['finance'],                 # from file names / tags / sandbox verdicts
    'tag': 'virustotal',
    'source': ['virustotal'],
    'first_seen': '2024-01-01T00:00:00+00:00',   # first_submission_date (source-truthful)
    'confidence_score': 0.85,           # from last_analysis_stats
    'md5': '...', 'sha1': '...', 'sha256': '...',
    'file_type': 'Win32 EXE', 'file_size': 123456,
    'vt_reputation': -12, 'vt_names': ['invoice.exe'],
    'threat_label': 'trojan.emotet/heodo', 'threat_category': 'trojan',
    'yara_rules': [...], 'sigma_rules': [...], 'sandbox_verdicts': {...}
}
```

### `virustotal_collector.py` (`VirusTotalCollector`) — not scheduled
`src/collectors/virustotal_collector.py` is a legacy module (`run_virustotal_enrichment_collection` in the DAG file, `virustotal_enrich` in `run_pipeline`) that lists `/files` — a premium endpoint — and offers `query_domain` / `query_hash` / `query_ip` helpers. No DAG schedules it; it uses the same key and its own 4/min limiter (not `VTCollector`'s), and not the daily ledger. Use `VTCollector` for production runs.

---

## 7. Finance Feed Collector

**File:** `src/collectors/finance_feed_collector.py`

### What It Does
Collects two abuse.ch feeds historically associated with banking trojans:
- **Feodo Tracker:** botnet C&C server IPs (QakBot, Emotet, TrickBot, Dridex, BumbleBee, Pikabot) with the malware family, port and online/offline status
- **SSL Blacklist:** SHA-1 fingerprints of malicious TLS certificates with the listing reason, stored as `x509-fingerprint-sha1` indicators (see below)

### Sources
- **Feodo (regular runs):** `https://feodotracker.abuse.ch/downloads/ipblocklist.csv` — C2 servers active in the last 30 days
- **Feodo (baseline runs):** `https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv` — the complete C2 history (same columns); a fresh baseline seeds the history once, the daily task then adds what is currently active
- **SSL Blacklist:** `https://sslbl.abuse.ch/blacklist/sslblacklist.csv`
- **API Key:** Not required

### Per-run caps
Both feeds are lists: a run reads the whole list the source publishes, and an entry stays on it as long as the source lists it. Each feed has its own cap covering the whole list, so the stored copy of every listed entry is reported again on each run and refreshed ([Re-reported indicators](#re-reported-indicators)) rather than ageing while still listed; the generic incremental default does not apply (`feodo` and `sslbl` are in `config.OWN_RUN_CAP_SOURCES`):

| Variable | Default | Effect |
|----------|---------|--------|
| `EDGEGUARD_FEODO_MAX_PER_RUN` | `15000` | Servers (rows merged per address) collected per run, baseline and daily: about twice the complete C2 history a baseline reads (7,607 servers on 2026-10-12), which grows when the feed moves again. A run whose list is longer keeps the servers seen online most recently (`last_online`, else `first_seen`) and logs a warning |
| `EDGEGUARD_SSLBL_MAX_PER_RUN` | `20000` | Certificates collected per run: about twice the blacklist (10,964 rows on 2026-10-12). A run whose list is longer keeps the newest by `Listingdate` and logs a warning |

`EDGEGUARD_MAX_ENTRIES` and an explicit baseline limit still apply when lower, and keep the newest entries too; `0` removes the cap. Both variables are forwarded by `docker-compose.yml` with the code defaults. The SSL Blacklist column header is recognised by its name whether it is a comment line (`# Listingdate,SHA1,Listingreason`, the abuse.ch banner form) or a plain row, so the first listing is never taken for the header.

### Zone Detection
Both collectors use `detect_zones_from_text()` on malware names and listing reasons:

```python
# Feodo Collector
zones = detect_zones_from_text(" ".join(rec["families"]).lower())   # every family of the merged address

# SSL Blacklist Collector
zones = detect_zones_from_text(reason)
```

The keyword detector deliberately contains no malware family names (families are linked to sectors through graph relationships), so in practice both feeds are tagged `zone:Global`: measured on 2026-10-12, all 7,980 Feodo rows (7,607 servers) and all 10,964 SSL Blacklist rows. Neither feed is hard-coded to Finance.

### Feodo Tracker: what is loaded and what reaches the graph
- **The feed is a historical snapshot at present.** Both downloads carry the header `# Last updated: 2026-03-04 14:28:39 UTC` (checked 2026-10-12): abuse.ch has not updated Feodo Tracker for seven months. A baseline loads the history once; the daily task then finds nothing new until the feed moves again. The collector logs a warning when the header is older than 7 days.
- **Parsing.** CSV with every field quoted and CRLF line endings, read with the `csv` module; the header row is recognised by name.
- **One record per address.** The feed has one row per address and port, and a re-used address appears again under another family: 7,980 rows describe 7,607 addresses (290 addresses on several rows, 81 with more than one family). MISP holds one attribute per value, so rows are merged per address: earliest `first_seen`, latest `last_online`, every port, every family. The primary family is that of the most recently active row.
- **Actionable or historical.** A server counts as recently active when its `last_online` date is within 30 days of the collection day (`FEODO_ACTIVE_DAYS`). The `c2_status` column is not used for this: it is only as fresh as the feed (the single "online" row of 2026-10-12 was last seen online on 2026-03-12). Recently active: `confidence:medium`, MISP detection flag set. Everything else: `confidence:low`, `to_ids=false`. abuse.ch advises against blocking on the complete history because addresses are re-used. On 2026-10-12 all 7,607 servers were historical.
- **Not rewritten.** EdgeGuard does not rewrite the confidence tag or the detection flag of an attribute MISP already holds (the refresh of a re-reported indicator edits `last_seen` only), so both stay as they were at the first collection.
- **Outages (Feodo Tracker and SSL Blacklist).** A timeout, a connection error, a truncated transfer or an HTTP 429 / 5xx after the retries is raised as a transient error: the Airflow task is skipped (`transient_external_error`) and the alert path is used. An open circuit breaker skips the run (`feodo_circuit_breaker_open`, `sslbl_circuit_breaker_open`). HTTP 401 / 403 skips (`*_auth_denied`). Any other HTTP status, or a defect in the code, fails the task. A body that is not the CSV yields zero items and a warning.

| Graph element | Value | From |
|---|---|---|
| `Indicator {indicator_type: "ipv4", value}` | the address; shared with ThreatFox, AbuseIPDB and OTX when they report the same address | `dst_ip` |
| `malware_family` | primary family, source spelling | `malware` |
| `last_online` | date the server was last seen online | `last_online` |
| `reference` | Feodo Tracker host page | built from the address |
| `confidence_score` | 0.5 recently active, 0.3 historical (the node keeps the highest value across its sources) | recency rule |
| `zone` | `global` | keyword detector on the family names |
| `(Indicator)-[:SOURCED_FROM]->(Source {source_id: "feodo_tracker"})` | `source_reported_first_at` = `first_seen_utc`; `source_reported_last_at` = `last_online` (the first-seen time when both fall on the same day; absent when the feed gives no date); `raw_data` JSON keeps `threat_type=botnet_cc` and the labels `c2_status:…`, `port:…`, `family:…` | per source |
| `(Indicator)-[:INDICATES]->(Malware)` | built by `build_relationships` when `malware_family` equals a Malware node name or alias (case-insensitive); QakBot, Emotet, TrickBot, Dridex, BumbleBee and Pikabot all match MITRE ATT&CK software | family match |

The source-reported last-seen time matters for campaigns: a Campaign's `last_seen` falls back to the import time for an indicator with no such claim, which would make a botnet that stopped in 2021 look active today.

### SSL Blacklist: what reaches the graph
Each row is the SHA-1 fingerprint of a TLS certificate seen on malware infrastructure, not a file hash. It is collected as `indicator_type: "x509-fingerprint-sha1"`, pushed to MISP under MISP's own attribute type `x509-fingerprint-sha1` (default category *Network activity*) and synced as an `x509-fingerprint-sha1` Indicator; the STIX export pattern is `[x509-certificate:hashes.'SHA-1' = '…']`.

| Graph element | Value | From |
|---|---|---|
| `Indicator {indicator_type: "x509-fingerprint-sha1", value}` | the fingerprint, 40 lower-case hexadecimal characters | `SHA1` |
| `zone` | keyword detector on the listing reason (`global` in practice); the reason itself is not written to MISP | `Listingreason` |
| `(Indicator)-[:SOURCED_FROM]->(Source {source_id: "ssl_blacklist"})` | `source_reported_first_at` = the listing date | `Listingdate` |

### Example Output

```python
# Feodo Indicator (botnet C&C; an address re-used by a second botnet, merged from three rows)
{
    'indicator_type': 'ipv4',
    'value': '103.61.101.11',
    'zone': ['global'],
    'tag': 'feodo_tracker',
    'source': ['feodo_tracker'],
    'first_seen': '2021-01-17 10:00:00',   # earliest row; published to MISP as 2021-01-17T10:00:00+00:00
    'last_seen': '2021-03-02',             # from last_online; → SOURCED_FROM.source_reported_last_at
    'last_online': '2021-03-02',           # latest row; → Indicator.last_online
    'confidence_score': 0.4,               # 0.7 when last_online is within 30 days of the collection day
    'to_ids': False,                       # True when recently active
    'malware_family': 'TrickBot',          # family of the most recently active row
    'port': '447',
    'status': 'offline',
    'reference': 'https://feodotracker.abuse.ch/browse/host/103.61.101.11/',
    'threat_type': 'botnet_cc',
    'tags': ['c2_status:offline', 'port:447', 'port:449', 'family:TrickBot', 'family:Dridex']
}

# SSL Blacklist Indicator (TLS certificate fingerprint; MISP type x509-fingerprint-sha1)
{
    'indicator_type': 'x509-fingerprint-sha1',
    'value': 'a1b2c3d4e5f6...',
    'zone': ['global'],  # Array of all matching zones
    'tag': 'ssl_blacklist',
    'source': ['ssl_blacklist'],
    'first_seen': '2024-01-10',
    'last_updated': '2024-01-15T09:00:00+00:00',  # emitted (wall-clock time); MISPWriter never reads it
    'confidence_score': 0.6,
    'listing_reason': 'dridex'
}
```

---

## 8. Global Feed Collector

**File:** `src/collectors/global_feed_collector.py`

### What It Does
Collects universal threat feeds that apply to all zones, including:
- **ThreatFox:** IOCs with malware family context
- **URLhaus:** Malware distribution URLs

### Configuration
- **ThreatFox** requires **`THREATFOX_API_KEY`** in the same environment as the collector (Airflow worker / `.env`). Get a free key from [auth.abuse.ch](https://auth.abuse.ch/). Without it, the task **skips** or returns **401 Unauthorized** if the API is called without credentials.

### Sources
- **ThreatFox:** `https://threatfox-api.abuse.ch/api/v1/`
- **URLhaus:** `https://urlhaus.abuse.ch/downloads/csv_recent/`. When it cannot be read, the run falls back to `https://urlhaus.abuse.ch/downloads/csv_top10k/`, and the task fails only when both fail

### Per-run caps

Neither feed has a cursor: each run reads a window, ThreatFox `get_iocs` the IOCs of the last 7 days (7,398 on the 730-day baseline of 2026-10-13; about 1,050–1,140 new per day) and URLhaus `csv_recent` the URLs of the last 30 days (34,003 on the same baseline; about 1,130 new per day). Each source has its own cap, sized to the whole window with headroom so that no day's entries leave the window uncollected, and the generic incremental default does not apply (`threatfox` and `urlhaus` are in `config.OWN_RUN_CAP_SOURCES`, like MalwareBazaar and NVD):

| Variable | Default | Effect |
|----------|---------|--------|
| `EDGEGUARD_THREATFOX_MAX_PER_RUN` | `10000` | IOCs collected per run, baseline and daily. A run whose window lists more keeps the newest by `first_seen` and logs a warning naming how many older IOCs it left out |
| `EDGEGUARD_URLHAUS_MAX_PER_RUN` | `50000` | URLs collected per run from `csv_recent`, baseline and daily. A run whose file lists more keeps the newest by `dateadded` and logs a warning |

The feeds' own order does not matter: a run that reaches its cap sorts by the date field first. `EDGEGUARD_MAX_ENTRIES` and an explicit baseline limit still apply when lower; `0` removes the cap. Entries MISP already holds for the source are not pushed again (cross-event duplicate prefetch), so a daily run that re-reads the window writes only the new entries (and refreshes the stored copies MISP last wrote more than `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS` ago, see [Re-reported indicators](#re-reported-indicators)). Both variables are forwarded into the containers by `docker-compose.yml` (`x-common-env`) with the code defaults.

### Zone Detection

```python
def get_zones_from_malware(malware_name):
    """Determine ALL zones based on malware family name."""
    return detect_zones_from_text(malware_name or "")

# ThreatFox uses malware family
zones = get_zones_from_malware(malware)

# URLhaus uses threat tags
zones = get_zones_from_malware(threat) or get_zones_from_malware(tags)
```

### Example Output

```python
# ThreatFox Indicator
{
    'indicator_type': 'domain',
    'value': 'malware-c2.example.com',
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'tag': 'threatfox',
    'source': ['threatfox'],
    'first_seen': '2024-01-14T10:00:00Z',
    'last_seen': '2024-01-15T08:00:00Z',     # Most recent observation
    'last_updated': '2024-01-15T09:00:00+00:00',  # emitted (wall-clock time); MISPWriter never reads it
    'confidence_score': 0.75,
    'malware_family': 'emotet',
    'threat_type': 'botnet_cc',
    'threat_type_desc': 'Botnet Command&Control server',
    'malware_malpedia': 'https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet',
    'reference': 'https://threatfox.abuse.ch/ioc/12345/',
    'tags': ['emotet', 'epoch4', 'tier1'],    # IOC classification labels
}

# URLhaus Indicator
{
    'indicator_type': 'url',
    'value': 'http://evil-site.com/malware.exe',
    'zone': ['healthcare'],  # Array of all matching zones
    'tag': 'urlhaus',
    'source': ['urlhaus'],
    'first_seen': '2024-01-14',
    'last_updated': '2024-01-15T09:00:00+00:00',  # emitted (wall-clock time); MISPWriter never reads it
    'confidence_score': 0.6,
    'threat_type': 'malware_download',
    'tags': 'exe,windows'
}
```

---

## 9. Healthcare Feed Collector

**File:** `src/collectors/healthcare_feed_collector.py`

### What It Does
Placeholder for healthcare-specific threat feed collection.

### Decision
No healthcare-specific feed is collected: Health-ISAC (H-ISAC) requires a membership that is not budgeted, and HC3, a public source of the US Department of Health and Human Services, is not collected. The `healthcare` sector comes from keyword detection in every collector, from the industries an OTX pulse names and, with `EDGEGUARD_ENABLE_CISA_ICS=true`, from the sectors CISA names in its ICS advisories. No DAG task calls this module.

### Current State
Returns `skipped=True` (`skip_reason_class="placeholder"`); no feed is wired.

### Example Output
```python
# Placeholder - no active output yet
{
    'source': 'healthcare_placeholder',
    'success': True,
    'count': 0,
    'timestamp': '2024-01-15T12:00:00Z'
}
```

---

## 10. Energy Feed Collector

**File:** `src/collectors/energy_feed_collector.py`

### What It Does
Placeholder for energy/ICS-specific threat feed collection.

### Decision
No energy member-only feed collector is planned: EE-ISAC (European Energy ISAC) membership is not budgeted. CISA ICS-CERT energy sector advisories are collected by the flag-guarded CISA ICS Advisories collector (`cisa_ics`); MITRE ATT&CK for ICS is available through the MITRE collector flag. No DAG task calls this module.

### Current State
Returns `skipped=True` (`skip_reason_class="placeholder"`); no feed is wired.

### Example Output
```python
# Placeholder - no active output yet
{
    'source': 'energy_placeholder',
    'success': True,
    'count': 0,
    'timestamp': '2024-01-15T12:00:00Z'
}
```

---

## 11. MISP Collector

**File:** `src/collectors/misp_collector.py`

### What It Does
Pulls data from local MISP instance for **optional** Neo4j-oriented ingest (legacy / alternate path), including:
- Indicators (all types)
- Vulnerabilities (CVEs)
- Malware families
- Threat actors
- MITRE techniques
- Relationships

**Note:** **Production Airflow** does **not** use this module for graph fill. Scheduled **MISP → Neo4j** is **`run_misp_to_neo4j`**: **attribute parse** → **per-event** dedupe and same-event cross-item edges → chunked node merges (**`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**) → batched relationship writes (**`EDGEGUARD_REL_BATCH_SIZE`**). A separate **CLI** path can use STIX helpers (`run_pipeline` / `MISPToNeo4jSync` STIX methods) — see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

**Limits & wiring:** This module is **not** run by the **`edgeguard_baseline`** DAG or by **`run_pipeline` step 2** (external collectors only). **`run_misp_to_neo4j`** discovers events via **paginated `/events/index`** (+ client filter) with a **paginated `restSearch` fallback** (event headers only) — see **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)**. This collector uses **`resolve_collection_limit(..., baseline=False)`** and caps **`/events`** fetch at **`min(3×limit, 2000)`** or **2000**, plus **500** attributes per event.

### Source
- **URL:** Configured MISP instance (`MISP_URL`)
- **API Key:** Required (`MISP_API_KEY`)

### Zone Detection
```python
def detect_sectors(self, text):
    """Detect ALL sectors from text (tags, description)."""
    return detect_zones_from_text(text)
```

### Source Tag Mapping
```python
SOURCE_TAG_MAPPING = {
    'AlienVault-OTX': 'alienvault_otx',
    'NVD': 'nvd',
    'CISA-KEV': 'cisa_kev',
    'MITRE-ATT&CK': 'mitre_attck',
    'VirusTotal': 'virustotal',
    'AbuseIPDB': 'abuseipdb',
    'Feodo-Tracker': 'feodo',
    'SSL-Blacklist': 'sslbl',
    'URLhaus': 'urlhaus',
    'ThreatFox': 'threatfox'
}
```

### Example Output

```python
# Indicator from MISP
{
    'type': 'indicator',
    'value': '192.168.1.100',
    'indicator_type': 'ipv4',
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'source': 'alienvault_otx',
    'original_source': 'alienvault_otx',
    'event_id': '1234',
    'tags': ['zone:Finance', 'zone:Healthcare', 'source:AlienVault-OTX']
}

# Vulnerability from MISP
{
    'type': 'vulnerability',
    'value': 'CVE-2024-1234',
    'zone': ['healthcare'],  # Array of all matching zones
    'source': 'nvd',
    'original_source': 'nvd',
    'severity': 'HIGH',
    'cvss_score': 8.5
}
```

---

## 12. CISA ICS Advisories Collector

**File:** `src/collectors/cisa_ics_collector.py` — **flag-guarded, OFF by default** (`EDGEGUARD_ENABLE_CISA_ICS=true` to enable).

### What It Does
Collects CISA ICS-CERT advisories (`ICSA-*`) and ICS medical advisories (`ICSMA-*`) published as **CSAF 2.0** JSON files in the public `cisagov/CSAF` GitHub repository and emits **one `vulnerability` item per CVE** (the advisories that name one CVE are merged, see *One item per CVE* below). The point of this collector is the **source-asserted critical-infrastructure sector**: every advisory carries a `"Critical infrastructure sectors"` note written by CISA (e.g. `"Critical Manufacturing, Energy, Information Technology"`). The keyword sector detector (`detect_zones_from_text`) is **deliberately not applied** to these items.

### Source
- **Base URL:** `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/` (`EDGEGUARD_CISA_ICS_BASE_URL`)
- **Listing files:** `index.txt` (all advisories as `YYYY/<file>.json`, ~3,960 entries 2010–2026, newest first) and `changes.csv` (`"YYYY/<file>.json","<ISO timestamp>"`, no header, newest first)
- **Per advisory:** `document.tracking.{id,initial_release_date,current_release_date}`, `document.title`, `document.notes[]`, `document.references[]` (`category: self` → cisa.gov URL), `product_tree.branches[]` (vendor → product_name), `vulnerabilities[]` (`cve`, `cwe`, `notes`, `scores[].cvss_v3`)
- **API Key:** Not required · **Licence:** TLP:WHITE ("Disclosure is not limited")
- **Mode selection:** baseline → `index.txt` filtered to the years inside `baseline_days` and pre-filtered on the day-of-year encoded in the file name (`icsa-26-281-01` → 2026-10-08, with a 45-day margin), fetched newest-first, then filtered by `initial_release_date >= cutoff`; incremental → `changes.csv` rows newer than the stored cursor (`checkpoints/baseline_checkpoint.json` → `cisa_ics.incremental.cisa_ics_last_change_ts`, minus a 24 h overlap; first run uses `EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS`, default 30). The cursor advances only when every selected advisory was fetched (`fetch_failed == 0`) and the MISP push had no failure (`failed == 0`), or, on a run without items, when no fetch failed. A baseline does not set it.
- **Per-run limit:** `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` (1,200 advisory files) bounds every run, daily and baseline. The generic incremental limit (`EDGEGUARD_INCREMENTAL_LIMIT`, 200) does not apply: `cisa_ics` is in `config.OWN_RUN_CAP_SOURCES`, so the daily DAG passes no item limit (`EDGEGUARD_MAX_ENTRIES` still applies when set). An item limit would count (advisory, CVE) items: an advisory naming more CVEs than the limit (350–378 on three advisories of the 2026-10-16 baseline) would stop every run inside the same advisory.

### Zone Mapping (source-asserted, fixed table)

| CISA sector (from the advisory note) | EdgeGuard zone |
|---|---|
| `Energy` | `energy` |
| `Healthcare and Public Health` | `healthcare` |
| `Financial Services` | `finance` |
| any other sector (Critical Manufacturing, Water, Communications, …) | contributes nothing |
| nothing mapped | `['global']` |

The raw sector list is kept on the item as `ics_sectors`; every emitted zone is validated against `config.VALID_ZONES`.

**What the sector means.** CISA's note names the sectors where the affected product is **deployed**, not the sectors an adversary targets. In the graph a mapped sector is CISA's statement: the CVE's `AFFECTS` link to the Sector carries the evidence label `advisory_sector` at confidence 0.9 (`src/sector_evidence.py`), never `TARGETS`, and the link names `cisa_ics` only when CISA's record gave that sector (the `SOURCED_FROM` edge of `cisa_ics` keeps the record's `zones` and `stated_zones`). A sector NVD, KEV or OTX infers for the same CVE stays `zone_classification` at 0.5 unless CISA also states it, in which case the one link carries `advisory_sector` and names both feeds. The field is often broad (Siemens advisories list nearly every sector), so read a finance or energy figure from CISA as "deployed in", not as a targeting signal.

**One item per CVE.** A CVE that several advisories name (a shared component, a multi-vendor product, a medical and an ICS advisory) would otherwise be one item per advisory, and MISPWriter keeps the first item of a value, so the CVE would keep the sectors of whichever advisory came first (newest first in a baseline, oldest first in an incremental run). `merge_items_per_cve` therefore merges them before the push: the union of the zones (`global` dropped once a sector is present), of `ics_sectors` and of `reference_urls`, sorted; `advisory_ids`, the sorted ids of every advisory; `advisory_zones`, the zones of each advisory (advisory id → its specific zones, `[]` for an advisory that maps to none), so a sector link cites only the advisories that name its sector; every other field (description, advisory id and title, vendor, product, affected products, CWE, CVSS) from the newest advisory (largest `current_release_date`, then largest id); the earliest `published` / `first_seen` and the latest `last_modified` / `last_seen`. The result is the same in any order.

**Advisory provenance.** MISPWriter writes `advisory_ids` (at most 50), `ics_sectors` (at most 20) and `advisory_zones` (the advisories kept in `advisory_ids` only) into the attribute's `NVD_META` comment, for a CISA ICS item only (NVD and KEV records carry none of these keys, so their `NVD_META` digest does not depend on them). The sync puts the three on the item: they reach the `raw_data` of the CVE's `SOURCED_FROM` edge to `cisa_ics` (CISA's own words, including sectors EdgeGuard has no zone for, such as Water), and each advisory becomes a record reference `cisa_ics:<advisory id>` on that edge (`r.source_refs`). On an AFFECTS link a sector cites only the advisories that name it: the edge records them per sector (`stated_refs`, e.g. `healthcare|cisa_ics:ICSMA-26-283-01`), and both the sync and `build_relationships` step 7b read them from there; a record without `advisory_zones` cites all of its advisories on every sector. The STIX export turns it into an `external_reference` with the cisa.gov page (`ics-advisories`, or `ics-medical-advisories` for `ICSMA-*`). No node property holds the raw sector names.

### Example Output

```python
{
    'type': 'vulnerability',
    'cve_id': 'CVE-2026-32645',
    'description': 'ICSA-26-281-01: Red Lion Controls N-Tron 700 Series — Default factory credentials ...',
    'zone': ['energy'],                      # from "Critical Manufacturing, Energy, Information Technology"
    'ics_sectors': ['Commercial Facilities', 'Communications', 'Critical Manufacturing', 'Energy', 'Information Technology'],
    'advisory_id': 'ICSA-26-281-01',         # the newest advisory naming the CVE
    'advisory_ids': ['ICSA-26-281-01'],       # every advisory naming the CVE, sorted
    'advisory_zones': {'ICSA-26-281-01': ['energy']},  # the zones of each advisory
    'tag': 'cisa_ics',
    'source': ['cisa_ics'],
    'confidence_score': 0.9,                  # authoritative government advisory
    'published': '2026-10-08T06:00:00+00:00',     # initial_release_date
    'last_modified': '2026-10-08T06:00:00+00:00', # current_release_date
    'first_seen': '2026-10-08T06:00:00+00:00',    # source-truthful (same two dates)
    'last_seen': '2026-10-08T06:00:00+00:00',
    'severity': 'MEDIUM', 'cvss_score': 6.0, 'attack_vector': 'LOCAL',
    'cvss_v31_data': {'vector_string': 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N', 'base_score': 6.0, ...,
                      'impact_score': None, 'exploitability_score': None},  # CSAF gives none
    'cvss_v30_data': None,
    'cwe': ['CWE-798'],
    'vendor': 'Red Lion Controls', 'product': '700 Series',
    'affected_products': ['Red Lion Controls 700 Series'],
    'reference_urls': ['https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-01'],
    'ref_tags': [], 'cpe_type': [], 'result_impacts': ['HIGH', 'HIGH', 'NONE'],
}
# No CVSS block in the advisory → no score: severity UNKNOWN, cvss_score None, attack_vector None.
# Dates absent → the four timestamp keys are omitted (honest-NULL), never wall-clock.
# MISP: tagged source:CISA-ICS + zone:<Zone>; NOT tagged CISA-KEV. Same CVE in two advisories → one item with the
# union of their sectors and ids.
# A CVE MISP already holds is not pushed again: an incremental run's new advisory naming it does not add its
# sectors (no update path for revised advisories yet).
# published / last_modified only fill a CVE node without them: NVD's record sets them. The
# description ranks below NVD's and the KEV's and above any other source's (description_source
# "cisa_ics"), so a CVE NVD also holds shows NVD's description and dates, not the advisory's.
# The lists (cwe, reference_urls, affected_products, result_impacts) only fill a CVE node without them, and the
# CVSS sub-node of a CVE and version NVD has asserted keeps NVD's values: a CVE NVD also holds shows NVD's
# lists and CVSS, the advisory's only where NVD gives none.
```

### Flags & knobs

The settings are defined in the CISA ICS advisories section of `src/config.py`; `EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS` and the 24 h cursor overlap are in `src/collectors/cisa_ics_collector.py`.

| Env var | Default | Meaning |
|---|---|---|
| `EDGEGUARD_ENABLE_CISA_ICS` | `false` | Master switch. Off → the daily task and `collect()` log "disabled by flag" and return a skipped status (success, 0 items) **without any HTTP request** |
| `EDGEGUARD_CISA_ICS_BASE_URL` | GitHub raw `OT/white/` folder | Where `index.txt`, `changes.csv` and the advisory files live |
| `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` | `1200` | Hard cap on advisory files fetched per run (a 24-month baseline is ~900); the per-run limit of daily runs too, which `EDGEGUARD_INCREMENTAL_LIMIT` does not cut |
| `EDGEGUARD_CISA_ICS_MIN_EXPECTED_ADVISORIES` | `50` | Baseline-only sanity floor (see below) |
| `EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS` | `30` | Lookback for the first incremental run (no cursor yet) |

### Safety behaviour
- **Isolated:** own circuit breaker (`cisa_ics`, 3 failures → open 30 min), own `RateLimiter` (≤ 4 req/s, sequential fetches), `retry_with_backoff` (3 retries) + `request_with_rate_limit_retries` (429/5xx backoff). Shares only the generic helpers with the KEV collector.
- **Per-file failures never abort the run:** a file that is not a JSON object with `document` + `vulnerabilities`, a JSON decode error, or a per-file 404 is counted in the status `stats` (`malformed`, `fetch_failed`, `skipped_vulns`, …) and skipped. Ten **consecutive** fetch failures (or the breaker opening mid-run) abort as a transient error **before** anything is pushed.
- **Baseline sanity floor:** when at least `CISA_ICS_MIN_EXPECTED_ADVISORIES` advisories were attempted but fewer parsed, or the index lists nothing in the window, the collector logs an error, increments `pipeline_errors_total{task="collect_cisa_ics"}` and raises `CISAICSBaselineFloorError` (a `TransientServerError` subclass) → `run_collector_with_metrics` marks the task **skipped + Slack alert** instead of writing a thin dataset. Not evaluated when fewer than the floor were attempted (small `collection_limit` smoke runs).
- **Upstream outage** (timeout / connection error / 5xx on the index) propagates as transient → skip + alert. A 4xx on `index.txt`/`changes.csv` (layout change) returns `success=False` so the task goes red for an operator. Code defects re-raise (DAG catastrophic branch).
- `health_check()` GETs `index.txt` and returns the same `{healthy, response_time_ms, ...}` shape as the other collectors.

---

## 13. MalwareBazaar Collector

**File:** `src/collectors/global_feed_collector.py` (`MalwareBazaarCollector`) — **flag-guarded, OFF by default** (`EDGEGUARD_ENABLE_MALWAREBAZAAR=true` to enable).

### What It Does
Collects the sha256 hashes of recent malware samples from [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) and emits **one `sha256` indicator per sample**. The `signature` column is the malware family: it becomes `malware_family` on the item, travels to MISP inside the `TF_META` comment exactly like the ThreatFox family, is rehydrated as `Indicator.malware_family` by `run_misp_to_neo4j.parse_attribute`, and `build_relationships` step 9 links it to `Malware` nodes (`INDICATES`, `match_type = malware_family`). Samples whose `signature` is `n/a` are pushed without a family.

### Source
- **Export URL:** `https://bazaar.abuse.ch/export/csv/recent/` — the samples of the last 48 hours (about 1,000 rows; 1,027 on 2026-10-12, of which 458 Mirai and 265 `n/a`). No API key is required. The **full export** (`/export/csv/full/`) is the complete history and is deliberately **not** used: baseline and regular runs both read the recent export, so the history in MISP / Neo4j builds up over successive daily runs.
- **Columns:** `first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type_guess, mime_type, signature, clamav, vtpercent, imphash, ssdeep, tlsh` (quoted, `", "` separated; the header is a `#` comment line and is read by name, so a reordered export still parses).
- **Auth:** when `THREATFOX_API_KEY` (the abuse.ch Auth-Key, shared by all abuse.ch platforms) is configured it is sent as the `Auth-Key` header; placeholders (`demo`, `YOUR_THREATFOX_API_KEY_HERE`) are treated as unset.
- **Terms:** MalwareBazaar data is free of charge for commercial and non-commercial use ([Terms of Use](https://bazaar.abuse.ch/faq/#tos)).

### Flags & knobs

The settings are defined in the MalwareBazaar (abuse.ch) section of `src/config.py`.

| Variable | Default | Effect |
|----------|---------|--------|
| `EDGEGUARD_ENABLE_MALWAREBAZAAR` | `false` | Master switch. Off → the daily and baseline tasks and `collect()` log "disabled by flag" and return a skipped status (success, 0 items, `skip_reason_class = malwarebazaar_disabled_by_flag`) **without any HTTP request** |
| `EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN` | `500` | Per-run cap on samples pushed to MISP. Labelled samples (`signature` other than `n/a`) are kept before unlabelled ones, then the list is cut at the cap. This cap is the per-run limit for the source: the generic `EDGEGUARD_INCREMENTAL_LIMIT` (200) does not apply (`malwarebazaar` is in `config.OWN_RUN_CAP_SOURCES`), because one 48-hour export holds about 1,000 samples and a daily run cut at 200 would let most of them age out of the window. The global hard override `EDGEGUARD_MAX_ENTRIES` and an explicit baseline limit still apply when lower. `0` removes the cap. |

Both variables are forwarded into the containers by `docker-compose.yml` (`x-common-env`) with the code defaults.

### Zone Detection
`detect_zones_from_text(signature)` (via `get_zones_from_malware`); `global` when the label is `n/a`.

### Failure contract (optional source)
- Flag off → skipped, no HTTP request.
- HTTP 401/403 → skipped (`malwarebazaar_auth_denied`); the circuit breaker is not tripped.
- HTTP 429 after the `Retry-After` retries, HTTP 5xx, timeouts and connection errors → `MalwareBazaarTransientError` (a `TransientServerError`) propagates; `run_collector_with_metrics` marks the task **skipped** (`transient_external_error`), sends the alert and marks the source unhealthy — the DAG continues.
- Other HTTP errors (for example 404 after an upstream layout change) → `success=False` (the task fails and needs an operator).
- Own circuit breaker (`malwarebazaar`, 3 failures → open 30 min) and `RateLimiter` (one download per run); `retry_with_backoff` (3 retries) + `request_with_rate_limit_retries` (429/5xx backoff).

### Example Output

```python
# MalwareBazaar Indicator
{
    'indicator_type': 'sha256',
    'value': '38cbdf411e85b4136c8d4b725f7b46530919d45799a8065965d408db5ebcc15d',
    'zone': ['global'],                     # detect_zones_from_text(signature)
    'tag': 'malwarebazaar',
    'source': ['malwarebazaar'],
    'first_seen': '2026-10-12T19:25:15+00:00',   # first_seen_utc, tz-aware UTC (source-truthful)
    'confidence_score': 0.7,                # 0.6 when the family label is n/a
    'malware_family': 'Mirai',              # '' when signature is n/a
    'md5': '2cbdeeb34862d4f0a40aabcc3236b891',
    'sha1': 'd382bede96d914347228a5392812851da046858f',
    'file_name': 'net.arm5',
    'file_type': 'elf',
    'mime_type': 'application/x-executable',
    'reporter': 'abuse_ch',
    'reference': 'https://bazaar.abuse.ch/sample/38cbdf41…/',   # sample page; triggers TF_META
    'tags': ['elf'],                        # TF_META.tags → raw_data of the SOURCED_FROM edge (no node property)
}
```

In MISP the attribute is `sha256` with the tags `source:MalwareBazaar`, `zone:*`, `tlp:*`, `confidence:*`, the MISP-native `first_seen`, and a `TF_META:` comment carrying `malware_family`, `reporter`, `reference` and `tags`.

### Acceptance
`python scripts/verify_fresh_baseline.py --require-malwarebazaar` fails unless `Source {source_id: 'malwarebazaar'}` exists with at least one sha256 hash indicator sourced from it.

---

## Collector Summary Table

| Collector | Sources | Status | Zone Detection |
|-----------|---------|--------|----------------|
| OTX | AlienVault OTX | ✅ Active | `detect_sectors()` → list |
| NVD | NVD | ✅ Active | `detect_sectors()` → `detect_zones_from_item` + CPE flattening → list |
| CISA | CISA KEV | ✅ Active | `detect_zones_from_text()` → list |
| MITRE | MITRE ATT&CK | ✅ Active | `detect_zones_from_text()` → list |
| AbuseIPDB | AbuseIPDB API | ✅ Active | See `AbuseIPDBCollector` |
| VirusTotal | VirusTotal API v3 lookups (free tier) | ✅ Active | `VTCollector` (`vt_collector.py`): enrichment of MISP hashes within a daily budget; `VirusTotalCollector` (`virustotal_collector.py`) is not scheduled |
| Finance Feed | Feodo, SSLBL | ✅ Active | `detect_zones_from_text()` → list |
| Global Feed | URLhaus, ThreatFox | ✅ Active | `detect_zones_from_text()` → list |
| Healthcare | — (HC3 / Health-ISAC not planned) | ⏳ Placeholder | - |
| Energy | — (EE-ISAC not planned; ICS-CERT via `cisa_ics`) | ⏳ Placeholder | - |
| MISP | Local MISP | ✅ Active | `detect_sectors()` → list |
| CISA ICS | cisagov/CSAF (ICS-CERT advisories) | 🚩 Flag-guarded (`EDGEGUARD_ENABLE_CISA_ICS`, default off) | Source-asserted sector → fixed table (`map_sectors_to_zones()`), no keyword detector |
| MalwareBazaar | abuse.ch recent sample export (sha256 + family label) | 🚩 Flag-guarded (`EDGEGUARD_ENABLE_MALWAREBAZAAR`, default off) | `detect_zones_from_text()` on the family label → list |

---

## Feed metadata that reaches the Indicator node

Indicators arrive in Neo4j only through MISP. Fields beyond type, value, tags and the native first/last-seen times travel in a JSON comment on the MISP attribute (`OTX_META:` for OTX, `TF_META:` for the abuse.ch feeds and VirusTotal) and are rehydrated by `run_misp_to_neo4j.parse_attribute`. A collector field that is not in that comment does not reach the graph.

| `TF_META` key | Indicator property | Set by |
|---|---|---|
| `malware_family` | `malware_family` (drives `INDICATES`) | ThreatFox, MalwareBazaar, Feodo Tracker |
| `malware_malpedia`, `reference`, `reporter` | same names | ThreatFox, URLhaus, MalwareBazaar, Feodo Tracker (`reference`) |
| `url_status`, `last_online` (optional) | same names | URLhaus; Feodo Tracker (`last_online`) |
| `threat_label`, `yara_rules`, `sigma_rules` (optional) | same names | VirusTotal |
| `tags`, `threat_type`, `threat_type_desc`, `ioc_id`, `malware_alias` | none: kept in `raw_data` on the `SOURCED_FROM` edge | ThreatFox, URLhaus, MalwareBazaar, Feodo Tracker |

The optional keys are written only when the item carries a value, and the sync sets a property only when the key is present, so a source never blanks another source's value on a shared node. `tests/test_source_graph_footprint.py` checks this path per source up to the row handed to the MERGE query.

A comment whose JSON after the prefix is not an object (`OTX_META:null`, `OTX_META:["x"]`, `TF_META:"s"`, `MITRE_USES_TECHNIQUES:null`, written by a MISP user or a federated instance) is read as no metadata, with a `[META]` warning naming the attribute's UUID, and the attribute is synced without it, so such a comment does not fail its event, and the STIX conversion of a tool's comment does not drop the event (`tests/test_malformed_meta_comments.py`). A list-valued key holding a string (`{"t":"T1059"}`) is ignored instead of being split into characters, and a list keeps only its strings and numbers (numbers as strings), because Neo4j refuses a node property list holding a map, a list, a null or mixed types and would fail the whole batch. A technique's `MITRE_TACTIC_PHASES` block is read the same way (a string such as `{"p":"execution"}` is ignored, and a list keeps only its strings and numbers); its bare-list form, which no writer produces, keeps its strings and numbers. `TF_META.tags` is not list-only: URLhaus writes it as the feed's comma-separated string.

## Baseline collection limits

This table captures **what each collector pulls on a 730-day
baseline** and the **upstream API constraint** driving that choice. Operators running long baselines
should expect the numbers in the "Current ceiling" column as the hard
upper bound for a single baseline run.

| Collector | Current ceiling | Upstream API constraint | Notes |
|-----------|-----------------|-------------------------|----------------------------|
| **NVD** | Full windowed collection (no artificial run-level cap on baseline) | `resultsPerPage <= 2000`; `pubStartDate..pubEndDate` must span `<= 120` days per request | Iterates 120-day windows via `iter_nvd_published_windows`. A run-level `limit` present in a baseline (an incremental-style setting) is ignored with a WARNING, because it would silently truncate ~99% of the windowed collection |
| **OTX** | `max_pages = 200` × `50/page` ≈ 10k pulses (~7 min runtime, 2 s between pages) | No publicly documented pulse cap; effective throttle ≈ 30 req/min on the free tier | `EDGEGUARD_OTX_BASELINE_MAX_PAGES` (default 200, forwarded by `docker-compose.yml`) sets the ceiling; a baseline that stops at it with a full last page logs a warning |
| **CISA KEV** | Full KEV snapshot per run, compared with EdgeGuard's MISP copies in every run | Public JSON, no auth, no rate limit; no per-entry modification date | Revised entries edited in place, at most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN` (500) per run ([§ 3](#revisions-every-run-compares-the-catalogue-with-misp)); `notes`, `cwes` and `forensicTriage` are not stored in MISP (`cwes` and `notes` are read onto the item but not written to `NVD_META`) |
| **MITRE ATT&CK** | Full STIX 2.1 bundle per run | Public GitHub raw file, no rate limit | A scheduled run pushes the whole changed bundle; objects MISP already holds keep their stored text ([§ Duplicate avoidance](#duplicate-avoidance-misp--incremental-runs)) |
| **MISP (local)** | Not collected: `MISPCollector` is library code that no DAG or CLI step runs | Bounded by local MISP; no external quota | The graph is built from MISP by the MISP → Neo4j sync instead |
| **AbuseIPDB** | At most one blacklist request per run, of at most `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` (10,000) addresses, baseline and daily (the incremental default of 200 does not apply) | Free plan: at most 10,000 addresses per blacklist request; 5 blacklist requests per UTC day; `check` quota 1,000 per day (the source key check) | A fetched blacklist is reused for the rest of its UTC day, and a 429 fails the task ([§ 5](#5-abuseipdb-collector)); a plan that returns more per request needs `AbuseIPDBCollector.BLACKLIST_MAX_PER_REQUEST` raised; the number of requests stays at most one per run, none when the answer is reused |
| **VirusTotal** | `EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN` lookups per run (default 60), `EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET` per UTC day (default 400); not in the baseline DAG | Free tier: **4 req/min**, **500 req/day**; lookups only (`GET /files/{hash}`), no feed or search endpoints | Enrichment of hashes already in MISP (see [§ 6](#6-virustotal-lookup-enrichment)); the ledger in `./state` carries the daily counter across runs and remembers looked-up hashes. A premium key raises the two knobs |
| **Finance (Feodo / SSLBL)** | Feodo: full C2 history on baselines (`ipblocklist_aggressive.csv`: 7,980 rows merged to 7,607 servers on 2026-10-12), 30-day list on regular runs, at most `EDGEGUARD_FEODO_MAX_PER_RUN` (15,000) servers per run; SSLBL: full feed, at most `EDGEGUARD_SSLBL_MAX_PER_RUN` (20,000) per run (baseline and daily, the newest kept when a cap is reached, the incremental default of 200 does not apply) | Public CSV/text feeds, no rate limit | Feodo Tracker has not been updated by abuse.ch since 2026-03-04: a baseline loads history, daily runs add nothing until the feed moves again |
| **Global (URLhaus / ThreatFox)** | **ThreatFox: last 7 days via API** (the `days` parameter clamped to 7), at most `EDGEGUARD_THREATFOX_MAX_PER_RUN` (10,000) IOCs per run; URLhaus `csv_recent` (last 30 days), at most `EDGEGUARD_URLHAUS_MAX_PER_RUN` (50,000) URLs per run (baseline and daily, the newest kept when a cap is reached, the incremental default of 200 does not apply) | **abuse.ch ThreatFox:** `get_iocs` `days` param `Min 1, Max 7` per [abuse.ch docs](https://threatfox.abuse.ch/api/); historical >7d is the documented **JSON/CSV bulk export** (`https://threatfox.abuse.ch/export/`), NOT this endpoint | IOCs older than 7 days are not collected ([ROADMAP.md](ROADMAP.md)) |
| **Energy (sector)** | Placeholder module (returns `skipped=True`, `skip_reason_class="placeholder"`); no DAG task calls it | — | No member-only feed (EE-ISAC) is planned. The ICS-CERT part is a collector: [CISA ICS Advisories](#12-cisa-ics-advisories-collector) (`cisa_ics`, flag-guarded by `EDGEGUARD_ENABLE_CISA_ICS`, default off) feeds `energy` / `healthcare` / `finance` from CISA's own sector assertion |
| **CISA ICS Advisories** | `min(index entries in window, CISA_ICS_MAX_ADVISORIES_PER_RUN=1200)` advisory files (~900 on a 730-day run), one item per CVE (baseline and daily; the incremental default of 200 does not apply) | Public GitHub raw files, no auth; polite sequential fetch ≤ 4 req/s | Flag-guarded, default **off**. Baseline sanity floor `CISA_ICS_MIN_EXPECTED_ADVISORIES=50` → transient skip + alert instead of a thin dataset |
| **MalwareBazaar** | `min(samples in the recent export ≈ 1,000, MALWAREBAZAAR_MAX_PER_RUN=500)` sha256 indicators per run (baseline and daily; the incremental default of 200 does not apply), labelled samples first | The key-free export covers the last 48 hours only; the full export is the whole history and is not used | Flag-guarded, default **off**. A baseline loads the same window as a daily run; the history builds up over daily runs |
| **Healthcare (sector)** | Placeholder module (returns `skipped=True`, `skip_reason_class="placeholder"`); no DAG task calls it | — | No member-only feed (Health-ISAC) is planned, and HC3, a public US HHS source, is not collected |

Planned work on collection depth (an import of the ThreatFox export, paid VirusTotal and AbuseIPDB plans) is listed in [ROADMAP.md](ROADMAP.md).

---

## Testing Collectors

Each collector can be tested individually:

```bash
cd EdgeGuard-Knowledge-Graph/src   # or your clone path

python -m collectors.otx_collector
python -m collectors.nvd_collector
python -m collectors.cisa_collector
python -m collectors.mitre_collector
python -m collectors.abuseipdb_collector
python -m collectors.vt_collector
python -m collectors.virustotal_collector
python -m collectors.finance_feed_collector
python -m collectors.global_feed_collector
python -m collectors.healthcare_feed_collector
python -m collectors.energy_feed_collector
```


---

## Adding a new reliable source — checklist

When adding a new collector that has a **canonical first-reported / last-reported timestamp** that should flow into the source-truthful timestamp pipeline (see `docs/KNOWLEDGE_GRAPH.md#sourced_from-edge-schema`), follow this **5-step checklist**:

> Step 1 is a single declarative edit in `src/source_registry.py`.
> The registries `_RELIABLE_FIRST_SEEN_SOURCES`, `SOURCE_TAGS`,
> `SOURCES`, `MISPWriter.SOURCE_TAGS` and `DEFAULT_SOURCES` are
> derived from it, so adding a `Source(...)` entry there propagates to
> all five simultaneously. The propagation is pinned by
> `tests/test_source_registry.py::test_adding_a_new_source_propagates_to_all_five_derivations`.

### 1. Add a `Source(...)` entry to `src/source_registry.py`

Append one record to the `_REGISTRY` tuple. Required fields:
``canonical_id``, ``display_name``, ``source_type``, ``reliability``,
``misp_tag``, ``reliable_first_seen``. Optional but recommended:
``aliases`` (covers other short names so collector lookups by
either spelling resolve identically), ``cli_id`` / ``api_key_env`` /
``rate_limit`` / ``cli_default_enabled`` / ``cli_description`` (the
``edgeguard sources`` CLI listing), ``cli_display_name`` (only needed
when the CLI label differs from the Neo4j ``Source.name`` — currently
only NVD).

The ``reliable_first_seen`` flag controls whether the source's
first/last_seen claims land on the ``SOURCED_FROM`` edge. ``False``
for sources whose first_seen field means something other than "first
observed in the wild" (OTX pulse-publish-date, MISP pipeline
metadata).

### 2. Have the collector emit `item["first_seen"]` (and `item["last_seen"]` if available)

In your new `collectors/<name>_collector.py`, populate the source-truthful timestamps directly from upstream:

```python
processed.append({
    "type": "indicator",  # or vulnerability, malware, etc.
    "value": <value>,
    "tag": "your_source_tag",
    "source": ["your_source_tag"],
    # Source-truthful timestamps. NULL is honest — do NOT
    # fall back to wall-clock NOW. The source-truthful extractor will
    # return None for missing values, and the SOURCED_FROM edge MIN/MAX
    # CASE preserves any prior value.
    "first_seen": upstream_data.get("first_reported_at") or None,
    "last_seen":  upstream_data.get("last_reported_at")  or None,
    # ...
})
```

### 3. Verify MISPWriter passthrough fires for your entity type

The `_apply_source_truthful_timestamps` helper in `src/collectors/misp_writer.py` is called from all 7 `create_*_attribute` methods (indicator, vulnerability, malware, actor, technique, tactic, tool) AS THE LAST STATEMENT before `return attribute`. If you add a NEW entity type, you must add the helper call to its `create_*_attribute` method too. The helper uses `coerce_iso` to accept int epochs, datetime objects, and date-only strings.

### 4. Add Layer-2 META JSON parser if your source ships structured metadata

If your source ships a structured-metadata JSON blob (like NVD_META, TF_META, CISA_META) that needs to round-trip through the MISP attribute comment field, add a Layer-2 fallback branch in `src/source_truthful_timestamps.py::extract_source_truthful_timestamps`. Most sources only need Layer-1 (MISP-native attribute fields).

### 5. Update `tests/test_source_reported_timestamps.py`

Add your tag to the static enumeration in `test_collector_emitted_tags_match_allowlist` so the test catches future tag drift.

### Verification

After adding a new source, run:

```bash
.venv/bin/python -m pytest tests/test_source_reported_timestamps.py -v
```

The full suite should pass. If any test fails, the new source isn't wired through correctly — the assertion message names the exact symbol you missed.

For an end-to-end smoke test:

```cypher
MATCH (n)-[r:SOURCED_FROM]->(:Source {source_id: "your_source_tag"})
RETURN n.uuid,
       r.source_reported_first_at,
       r.source_reported_last_at,
       r.imported_at,
       r.updated_at
LIMIT 10;
```

Should show populated source-reported timestamps if your upstream provides them.

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — The energy and healthcare placeholders are modules no DAG task calls (the page said they show on the skip dashboard); HC3 named as a public source that is not collected; the unsupported OTX node estimate removed; the MISP row states that no DAG or CLI step runs `MISPCollector`. These were the README's collector-limit notes. The baseline-limits section keeps the current limits only (its title no longer says "planned"): the ThreatFox import and the paid VirusTotal path are listed in ROADMAP.md.
- 2026-10-22 — MITRE: MISPWriter's dedup reads an ATT&CK `text` value as `<id> - <name>` or `<id>: <name>` (`attack_values.attack_value_key`), so an entry a MISP holds in the colon form is not written again in the hyphen form.
- 2026-10-22 — OTX adversaries: the run logs the country, state and nationality names the actor-name hygiene dropped from adversary fields (`[ACTOR-NAMES]`, with the pulses of each name), also a country followed by a parenthetical that yields no name; `Qilin` and `Agenda` count as Water Galura in the canonical threat-actor reference.
- 2026-10-20 — OTX adversaries the same pulse lists as a malware family: ransomware operations named after their own ransomware (`Rhysida`, `BlackSuit`, `Trigona`) stay actors, as the canonical threat-actor reference holds them through override decisions, either as actors of their own or as names of their operator (`Conti`, `LockBit`).
- 2026-10-20 — MITRE: techniques, tactics and tools reach MISP as `<id> - <name>` (they were `<id>: <name>`, which MISP's default Import Regexp rules rewrote for the entries named "Windows …"); new subsection "MISP values".
- 2026-10-18 — A pulse's `cve_references` item reaches MISP with an `OTX_META` block naming the pulse (it carried the note "Referenced in OTX pulse: <name>"), and the sync groups an OTX CVE into its pulse, linking the pulse's indicators to it (`INDICATES`, `otx_pulse`; at most 50 CVEs and 2,000 indicators of a pulse).
- 2026-10-18 — OTX: a pulse's own industries are its sector statement (`otx_industries` on `TARGETS`); malware families and adversaries carry them to the sync in `MITRE_USES_TECHNIQUES.ind`, and the statements of the later pulses of a run that list the same item travel with it (`report_stated_zones`, `rsz`).
- 2026-10-18 — OTX adversaries: country and state names and nationality adjectives are not actor names (`"APT37, North Korea"` names one actor), and an adversary the same pulse lists as a malware family is an actor only when the canonical threat-actor reference resolves it (kept without the reference); the actor items, pairs and several-actor decision use the same names.
- 2026-10-18 — MITRE: a scheduled run pushes the whole changed bundle (`mitre` in `OWN_RUN_CAP_SOURCES`) and stores the ETag only when no item limit cut it; a release adds new and renamed objects, and changes to objects already in MISP arrive with the next fresh baseline.
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Main text restated as a guide to current behaviour; the change history moved to this section and the handling of data written by earlier versions to the appendix.
- 2026-10-17 — OTX cursor: after a push with stored and failed items it stops below the oldest pulse with an item the writer lists in `last_push_unstored_items` (a failed batch or event lookup, or a systemic conversion drop), because the newest pulse of the first `success` items by position could pass a failed batch's pulses so that no later run read them.
- 2026-10-17 — CISA ICS: `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` is the per-run limit of daily runs instead of the 200-item incremental limit, which counted (advisory, CVE) items, stopped every run inside the same large advisory and kept the cut CVEs and every newer advisory out of MISP.
- 2026-10-17 — CVSS edges written before `sources` existed keep their asserting feed in `sources` on their first write.
- 2026-10-17 — Corrected against the code: item fields (`source` list, item types, the `last_updated` key some collectors emit), OTX zone detection, the AbuseIPDB blacklist fields, the VirusTotal ledger size and limiter, the Feodo Tracker zone text, the URLhaus fallback, the CISA ICS cursor and the MalwareBazaar `tags`.
- 2026-10-16 — NVD's record holds a CVE's CVSS sub-nodes and lists: another record only fills a list, a CISA ICS record only fills a sub-node NVD asserted, and CISA ICS items carry `None` instead of 0.0 for the impact and exploitability sub-scores CSAF does not give.
- 2026-10-16 — CISA KEV: every run compares the whole catalogue with EdgeGuard's MISP copies and edits revised entries in place (`EDGEGUARD_KEV_MAX_EDITS_PER_RUN`), since an incremental run took only the entries added within 30 days and no revision reached MISP or the graph short of a wipe; `EDGEGUARD_CISA_INCREMENTAL_DAYS` retired.
- 2026-10-16 — `push_items` checks a complete cross-event listing before the day's event is looked up, and items no attribute can be built from are logged as `[CONVERT]` and count as failed only when systemic (`CONVERT_FAILED_MIN_SHARE`); they had been dropped silently, and a push of only such items reported `[DEDUP] All N items were already present`.
- 2026-10-16 — CISA ICS: one item per CVE (`merge_items_per_cve`) with the advisories' ids, raw sectors and per-advisory zones in `NVD_META`, and a mapped sector as an `advisory_sector` statement at 0.9; with one item per (advisory, CVE) the first advisory's sectors had won.
- 2026-10-16 — AbuseIPDB: a blacklist 429 fails the task (it had produced an empty list and a green task, losing that day's blacklist without a signal), and a fetched answer is reused within its UTC day, the daily and baseline runs sharing one cache key.
- 2026-10-16 — Feodo Tracker and SSL Blacklist report their whole list per run under their own caps, and AbuseIPDB asks for up to `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` (10,000) blacklist addresses; with the first 200 entries per daily run, all but 200 of the 7,607 Feodo Tracker, 10,967 SSL Blacklist and 10,000 AbuseIPDB attributes of the 730-day baseline of 2026-10-13 had not been reported again and aged while listed; the SSL Blacklist header is recognised by name (a comment header had cost the first listing).
- 2026-10-16 — Indicators age from the source's own last-report date capped at the MISP timestamp (section "The source date an indicator ages from", `last_reported_basis`); the refresh moves the age only when the source's date moved.
- 2026-10-16 — Descriptions follow a source ranking with `description_source` (CVE: NVD > CISA KEV > CISA ICS > other; entity: MITRE ATT&CK > curated > other); NVD's and MITRE's records had set them and other records only filled them.
- 2026-10-16 — OTX: `OTX_META.pa` lists the first pair of each family and adversary first and is shortened before `report_ids` and `mf` (the same pair from N pulses had been N entries that crowded them out); the several-actor mark accumulates on `Indicator.several_actor_pulses`, a mark judged without the canonical reference goes to `sapn`, and the writer does not edit stored copies to add a mark.
- 2026-10-16 — A technique's `MITRE_TACTIC_PHASES` block goes through the metadata guards (a string value had given a string of phases, and a list holding a map or a null had failed the batch); the `MISPCollector` notes name the paginated, headers-only `restSearch` fallback of the sync.
- 2026-10-15 — OTX malware-family and adversary items carry no description (they carried the pulse's description, which replaced ATT&CK's text on the node); MITRE tactics carry ATT&CK's description (MISP held the placeholder "MITRE ATT&CK tactic").
- 2026-10-15 — ThreatFox and URLhaus per-run caps sized to each feed's window; cut at 200 per run, about 80% of each day's entries had left the window uncollected.
- 2026-10-15 — Re-reported indicators: a stored copy MISP last wrote more than `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS` ago is refreshed, since an IOC a feed kept listing was never written again and decayed while still listed.
- 2026-10-15 — OTX: the same-run dedup keeps the most restrictive pulse TLP (the first pulse's level had won); a metadata comment that is not a JSON object is read as no metadata (it had raised in the parser, failing its event and every later incremental run, and the STIX conversion of a tool's comment had dropped the whole event).
- 2026-10-15 — OTX: the collector decides on a pulse's whole adversary list whether it names one actor; pairs carry the pulse (`family::adversary::pulse`) and a pulse naming several actors is marked on its items.
- 2026-10-15 — OTX family names lose the ATT&CK software id suffix (on the graph of 2026-10-14, 136 twin `Malware` nodes held 16,005 `INDICATES` links, and the ATT&CK Cobalt Strike node showed 55 indicators instead of about 2,078); `malware_families` objects named by `display_name` or `id` are read (an entry without a name had become a placeholder `Unknown` item).
- 2026-10-15 — A CVE's dates come from NVD's record, and neither an OTX pulse reference nor an `OTX_META` comment is a CVE description (the raw `OTX_META` JSON had become the description).
- 2026-10-15 — NVD: CISA's SSVC decision points travel in `NVD_META` (`ssvc`) and are set on the CVE node from NVD's record only.
- 2026-10-15 — MITRE ATT&CK: revoked objects are skipped and their names given to the successor; deprecated objects are kept and marked; tool items carry `aliases`.
- 2026-10-15 — NVD keeps every CVSS version (only one of v3.1, v3.0 and v2 had been kept, and an incremental update removed the sub-node of an older version when NVD added a newer one); `attack_vector` is NVD's word for the scoring CVSS (it was the CVSS 3.x `AV` letter or `UNKNOWN`); KEV, OTX and CISA ICS records send none (an invented `NETWORK` had been sent).
- 2026-10-15 — SSL Blacklist fingerprints are collected as `x509-fingerprint-sha1` (they had been `sha1` file hashes, `hash` Indicators shared with file hashes, and `[file:hashes.'SHA-1' = …]` STIX patterns).
- 2026-10-15 — MISP push: generic hashes are typed by digest length (every generic hash had been pushed as `sha256`, and MISP dropped the MD5 and SHA1 values; with the 4-byte character failures this lost tens of thousands of OTX attributes of the 730-day baseline without a failed task), 4-byte characters are stripped or the attribute skipped, an untagged attribute gets the default TLP at sync; OTX non-file hashes are not collected and e-mail addresses are typed as such.
- 2026-10-15 — CISA KEV baselines take the whole catalogue and ransomware use derives no score; the OTX baseline page ceiling is the forwarded setting `EDGEGUARD_OTX_BASELINE_MAX_PAGES`.
- 2026-10-15 — The sector time-range filter on NVD and OTX removed: it compared NVD's zone-less `published` with a timezone-aware cutoff, swallowed the `TypeError` and had not dropped a record since v2026.3.28.
- 2026-10-14 — NVD incremental runs read every CVE modified since a stored cursor and edit stored copies NVD changed; the newest 200 of a 14-day lastMod window by publication date, with held CVEs skipped, had missed 37% of new CVEs in a 30-day replay (6,151 of 16,571), left 1,930 of the 2,130 CVEs published after the hosted 730-day baseline out of MISP and kept the old version of all 1,500 baseline CVEs NVD had changed.
- 2026-10-14 — CVE scores: NVD takes the first CVSS in the order v3.1 → v3.0 → v2 → v4.0, and records without CVSS carry no score (they had carried 0.0 tagged `cvss:low`, shown as 3.0 / LOW on 14,451 CVEs of the hosted 730-day baseline; KEV records a ransomware-derived 9.0 / 7.0 that could replace NVD's CVSS; CISA ICS records 7.0 / HIGH and `NETWORK`).
- 2026-10-13 — Feodo Tracker and SSL Blacklist outages (a timeout, a connection error, a truncated transfer, HTTP 429 / 5xx after the retries) skip the task as transient errors instead of failing it.
- 2026-10-12 — MalwareBazaar collector added (flag-guarded); Feodo Tracker baselines load the complete C2 history; VirusTotal runs as a free-tier lookup enrichment with a daily budget; no energy (EE-ISAC) or healthcare (HC3, Health-ISAC) member-only feed collector is planned.
- 2026-10-10 — OTX families and adversaries travel on every pulse indicator (`pulse_malware_families`, `pulse_malware_actor_pairs`), so report-scoped linking works on regular updates; `OTX_META` is written for every pulse indicator, not only when the pulse had `attack_ids` or `targeted_countries`.
- 2026-10-10 — CISA ICS Advisories collector (flag-guarded, CSAF, source-asserted sectors) and ATT&CK for ICS (`EDGEGUARD_ENABLE_MITRE_ICS`) added.
- 2026-04-26 — The `last_updated` key removed from the per-collector example items, since Cypher sets it server-side.
- 2026-04-21 — Timestamp model of four concepts: collectors omit a first/last-seen date the source does not give, never substituting the wall-clock time, and several stop emitting `last_updated`, which Cypher sets server-side.
- 2026-04-20 — Baseline limits: an NVD baseline ignores a run-level limit with a warning, ThreatFox requests are clamped to the 7 days `get_iocs` serves, and placeholder collectors report a skip instead of a silent zero count.
- 2026-04-18 — Source-truthful timestamps flow from collector items through MISP to the `SOURCED_FROM` edge (the passthrough added to five `create_*_attribute` methods that lacked it); the five source registries are derived from `src/source_registry.py`, so the new-source checklist starts with one `Source(...)` entry.
- 2026-03-28 — First version (v2026.3.28).
