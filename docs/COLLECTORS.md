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
  - **Target event.** When **`EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS`** is true (default), it loads existing **`(type, value)`** on the target event via **`/attributes/restSearch`** and skips attributes already present — covers same-day reruns and overlapping incremental windows. With the event split (`EDGEGUARD_MISP_EVENT_SPLIT_ABOVE`, default 20000), the target is the first part of the day with room (`EdgeGuard-{source}-{date}`, then `-part2`, `-part3`, …), and what does not fit goes on to later parts of at most that many attributes each ([COLLECTION_AND_SYNC_LIMITS.md § MISP event parts](COLLECTION_AND_SYNC_LIMITS.md#misp-event-parts)).
  - **Across events.** It also lists **`(type, value)`** across every MISP event that carries the source's tag (**`EDGEGUARD_MISP_CROSS_EVENT_DEDUP`**, default on) and skips those too. If that listing fails part-way, the keys read so far are used and the check falls back to the target event. NVD incremental runs and CISA KEV runs pass their own complete listing instead (`known_source_keys`). A complete listing also covers the other parts of the day; without one, the push lists every other part of the day and filters against them.
  - **Comparison.** Both checks, and the refresh of a re-reported indicator ([below](#re-reported-indicators)), compare a pushed attribute with the stored ones as MISP compares a value with the one it stores (`_dedup_key`, the rule of the dedup within the push below): surrounding whitespace ignored, and case for the types whose case MISP changes on save (`_CASE_NORMALISED_TYPES` in `misp_writer.py`: hashes, domains, host names, IP and e-mail addresses, CVE ids, …), so a hash a source reports as `ABC…` is the copy MISP stores as `abc…`: present, not pushed again. Malware and threat-actor names, URLs and every other type keep their case, and an ATT&CK `text` value is compared in its current form ([MITRE collector, MISP values](#misp-values)). A caller's `known_source_keys` are keyed by the same rule.
  - **Order.** A complete listing (every page read, or `known_source_keys`) is checked **before** the day's event is looked up: a (source, date) group MISP already holds entirely neither looks up nor creates the day's event (`EdgeGuard-{source}-{date}` or a part), and the log says so (`… no event looked up or created`). With cross-event dedup off, or a listing that stopped early (an error, the page cap of 200 × 5,000 rows, logged), the event is looked up first, because partial keys can miss the copy in today's event and the refresh of a re-reported indicator needs the copy MISP wrote last.
  - **Items that cannot be converted.** Items no MISP attribute can be built from (an unknown item type, or an empty value, CVE id, name or ATT&CK id) are logged once per push, per source tag with how many of its items, the reasons and whether they count as failed (`[CONVERT] 3 item(s) could not be converted to a MISP attribute, 2 of them counted as failed (…): alienvault_otx: 1 of 300 item(s), not counted as failed (1 vulnerability with an empty cve_id); threatfox: 2 of 2 item(s), counted as failed (2 unknown item type 'campaign')`, writer stats `items_not_converted` and `items_not_converted_failed`); a group left without attributes creates no event. They count as **failed** pushes only when the drop is systemic for the source in that push: all of its items, or at least half of them (`CONVERT_FAILED_MIN_SHARE` = 0.5 in `misp_writer.py`). A source whose payload stops converting thus fails `status_after_misp_push`, and its error names both causes (attributes MISP did not store, items logged as `[CONVERT]`); OTX's dropped items are listed in `last_push_unstored_items` too, so their pulses go on OTX's retry list and are fetched again until the collector reads the payload again or they are given up (OTX below). A few bad records do not: a failed item would fail a run that pushes nothing new (`status_after_misp_push` passes a run with failures only when it pushed something and its success rate reaches the minimum), would keep the CISA ICS cursor, the cursor an NVD baseline seeds and the MITRE ATT&CK ETag, which move only after a push without failures, and would put its OTX pulse on the retry list, so every later run would read the same bad record and fail again. The threshold lies far above the share one bad record has in a small incremental window: one bad item fails a push only when its source has at most two items in it. The price: a payload change that breaks only a minority kind of a mixed source (for example OTX's CVE references) is reported on every run but does not fail it.
  - **`[DEDUP] All N items were already present`** appears only when nothing failed or was dropped, N being the attributes found present.
  - **Within the push.** Two attributes of one (source, date) group that MISP holds as one value are pushed once: the comparison is the push confirmation's (`_attribute_match_key`: surrounding whitespace ignored, and case for the types whose case MISP changes on save, `_CASE_NORMALISED_TYPES`), the rule of the checks above; malware and threat-actor names, URLs and every other type are compared exactly. The first attribute is pushed; a later one that differs from it only so is logged once per group (WARNING `[CASE-VARIANT] MISP push <source> (<date>): N attribute(s) not pushed, …`, with the first five), because its comment and tags are not merged into the attribute pushed, and its item counts as unstored when that attribute's batch fails. The OTX collector folds its own case variants before the push (OTX below).
  - **Edits.** The only edit `push_items` makes to a stored attribute is the refresh of a re-reported indicator ([below](#re-reported-indicators)); NVD and CISA KEV updates go through `MISPWriter.update_attribute` (below). Reducing **incoming** volume is the job of collector cursors below.
- **OTX** (non-baseline): stores **`otx_last_pulse_modified`** in **`checkpoints/baseline_checkpoint.json`** under **`[source].incremental`** (`get_source_incremental("otx")`). Each run fetches pulses with **`modified_since`** = last cursor minus **`EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC`**. First run with no cursor uses **`EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS`**. **`EDGEGUARD_INCREMENTAL_LIMIT`** counts the pulses modified after the cursor, oldest first, and leaves the rest to the next run ([Scheduled runs: limit and cursor](#scheduled-runs-limit-and-cursor)). The cursor after the window's push follows one rule ([Scheduled runs: the retry list](#scheduled-runs-the-retry-list)); the run writes it, with the pulses that push put on the retry list, before it pushes the pulses of the list:
  - **No failure.** The cursor advances to the newest pulse the run processed (**`failed == 0`**), also when MISP already held every item (`push_items` counts an item MISP holds as neither stored nor failed, so the push returns 0 stored and 0 failed), and when there is nothing to push.
  - **Some items failed.** The writer lists items as unstored (`MISPWriter.last_push_unstored_items`, [MISP push](#misp-push-attribute-types-and-characters)): their batch or their event lookup failed, or no attribute could be built from them and the drop is systemic for the source (a payload the collector no longer reads). Unless every listed item failed at its MISP event (next bullet), the cursor advances as after a push without failures, and every pulse a listed item names (its `pulse_id`, and through `report_ids` the other pulses of the run that listed it) goes on the **retry list**, which later runs fetch by id and push after their window's push, in batches of their own and within `EDGEGUARD_OTX_RETRY_MAX_SECONDS`. This holds whatever share of the push failed: a value MISP refuses fails its whole batch (HTTP 4xx, or 5xx after the retries), and with the default batch of 500 that batch can hold every new item of the run. Failures the writer does not list put no pulse on it: a value with 4-byte characters and an attribute missing from a batch MISP answered with HTTP 200 and partly stored, which a later run cannot store either; a single record no attribute could be built from (below `CONVERT_FAILED_MIN_SHARE`) is reported and not counted as failed.
  - **MISP failed at the event.** When every listed item failed at its MISP event (`MISPWriter.last_push_event_failed_items`: the lookup or creation of the day's event or of a part of it failed after the retries, or its id was empty once sanitised), none of the unstored items reached a batch: MISP became unreachable after the `misp_health_check` task that runs before `collect_otx`, or the day's event failed. The cursor advances no further than the newest pulse modified before the oldest pulse of the window with a listed item, and no pulse goes on the list; the items MISP held, or can never store, do not change this. It stays when no pulse is older, when a pulse with a listed item has no readable `modified`, or when a listed item names no pulse the run processed (an OTX row without an id). An outage thus holds back nothing MISP could have stored, and the next run reads those pulses again.
  - **The push stopped.** When MISP kept failing for longer than the push's cap and the push stopped (`MISPWriter.last_push_stopped`, `[MISP-PUSH-STOPPED]`, [MISP push](#misp-push-attribute-types-and-characters)), the items it did not send (`last_push_unsent_items`) say nothing about their pulses: an outage, not a refusal. The cursor advances no further than the newest pulse modified before the oldest pulse of the window that such an item names, and stays when that pulse has no readable `modified`; those pulses go on no list, and a pulse already on the list that such an item names keeps its entry unchanged, also when a listed item names no pulse the run processed (an OTX row without an id: then the cursor stays and no pulse goes on the list). The pulses whose items were sent and failed go on the list as above, and a pulse of the list read in the window whose items were all sent follows that push. The pulses of the list are not pushed in that run.
  - **Unknown failures.** When the writer gives no list, or a listed item names no pulse the run processed and not every listed item failed at its event, the cursor stays and no pulse goes on the list.
  - **Raised.** A connection error or timeout that raises out of the window's push fails the run with the cursor and the list unchanged. One that raises out of the push of the listed pulses, or a task killed during it, fails the run after the cursor and the window's new pulses on the list were written, within the list's cap; the listed pulses keep their entries, except that the pulse that push began with is marked (`last_push_started_at`) and goes behind the others at the next run.
  - **Report records.** The window's report records are pushed before the cursor moves, and the cursor passes a pulse whose record MISP does not hold only once that record is saved on `report_pending`; when the list cannot be saved, the cursor advances no further than the newest pulse modified before the oldest such pulse. A pulse of the retry list keeps its entry until its record is in MISP or saved on `report_pending` ([Report records](#report-records)).
- **NVD** (non-baseline): stores **`nvd_last_modified_cursor`** under **`[nvd].incremental`**. Each run reads every CVE modified since the cursor minus **`EDGEGUARD_NVD_CURSOR_OVERLAP_SEC`** (first run with no cursor: **`EDGEGUARD_NVD_INCREMENTAL_DAYS`**), adds the CVEs MISP does not hold yet and edits the stored attribute of a CVE when NVD's data for it changed. The cursor advances only when every MISP write succeeded and the window was read completely. See [§ 2](#2-nvd-collector).
- **CISA KEV**: no cursor. Every run compares the whole catalogue with EdgeGuard's `source:CISA-KEV` copies, adds the CVEs MISP lacks and edits the copies of entries CISA revised (at most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN`; the rest follow on the next run). See [§ 3](#revisions-every-run-compares-the-catalogue-with-misp).
- **MITRE** (non-baseline): stores **`mitre_bundle_etag`**; sends **`If-None-Match`** to GitHub. **HTTP 304** skips download, parse, and MISP push. **Baseline** runs always fetch the full bundle. A changed bundle is pushed whole: `mitre` is in `config.OWN_RUN_CAP_SOURCES`, so `EDGEGUARD_INCREMENTAL_LIMIT` does not cut it. The ETag is saved only after **`failed == 0`** on MISP push (or immediately when **`push_to_misp`** is false), only when no item limit cut the run (`EDGEGUARD_MAX_ENTRIES`; a cut run logs `[MITRE] item limit … the bundle's ETag is not stored`) and, with `EDGEGUARD_ENABLE_MITRE_ICS=true`, only when the ICS bundle was read (`[MITRE] ATT&CK for ICS failed: … the bundle's ETag is not stored`), so the next run reads the bundle again. MISPWriter skips the objects MISP already holds (same attribute type and value, the value holding the name), so a new ATT&CK release adds its new techniques, groups and software, and a renamed object as a new attribute under its new name; a changed description, relationship or deprecation of an object already held reaches the graph with the next fresh baseline.

### Re-reported indicators

The duplicate check above drops every indicator the source already holds in MISP, and the incremental MISP → Neo4j sync reads only attributes whose MISP timestamp moved. Without a refresh, the stored copy of an IOC a feed keeps listing would never be written again, and `decay_ioc_confidence` would lower the node at 90 and 180 days and retire it at 365 days while the feed still lists it. An indicator ages from its latest report, dated by the source's own last-report date capped at the MISP timestamp ([below](#the-source-date-an-indicator-ages-from), [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#indicator-aging)).

`MISPWriter.push_items` therefore refreshes such an indicator. When a collector reports an indicator (an item with `indicator_type`; not CVEs, ATT&CK objects or actors) that MISP holds for the same source in an earlier EdgeGuard event (compared as the duplicate check compares it: a hash reported in upper case is the copy MISP stored in lower case), and MISP last wrote that copy (its attribute `timestamp`) more than `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS` ago (default 30), the copy is edited with `update_attribute`. The edit goes to the stored copy, by its uuid, and sends `last_seen` and nothing else: the source's own last-seen date when the re-reported item carries one later than the stored value (AbuseIPDB's `lastReportedAt`; for OTX the indicator's `modified` in the pulse, or the pulse's `modified` when the indicator has none), otherwise the stored value unchanged. The field keeps holding what a source claimed, never the time of a run, and value, type, tags and comment stay as they are. MISP stamps the edited attribute and its event with a new timestamp (MISP 2.5 `AttributesController::edit`; the writer counts the edit only when MISP's answer shows a later timestamp), so the next incremental sync reads the attribute and merges the node again. The edit moves the indicator's age only when the source's `last_seen` moved (the report time is `min(T, coalesce(L, T))`), or, for a source without a date (SSL Blacklist, MalwareBazaar), to the time of the edit; a newer report lifts a decay retirement in the same write. An indicator re-reported within the interval keeps its older date until the interval has passed, so a source that keeps reporting an undated indicator holds it in the first tier (below 90 days). `first_imported_at` does not move, and the source's claims (`r.source_reported_first_at`, `r.source_reported_last_at`) move only when the source itself claims a later last-seen date ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), [TIMESTAMPS.md](TIMESTAMPS.md)).

- **Bound.** The decision reads MISP's write time, which the edit resets, so a copy is edited at most once per interval (30 days, well inside the first aging tier of 90 days); a copy a baseline wrote is first due 30 days after it. When the source holds the indicator in several EdgeGuard events, the copy MISP wrote last decides and is the one edited. A copy that carries the source tag in another event (an analyst's, a federated organisation's) is never edited: the sync does not read it, and it is not EdgeGuard's to change.
- **Which indicators.** Only what a collector run reports again is refreshed, and at most `EDGEGUARD_MISP_REFRESH_MAX_PER_RUN` of them per run. ThreatFox re-lists an IOC for 7 days after it was added, so its entries rarely need it; URLhaus re-lists a URL for as long as it stays in the `recent.csv` export (the URLs added in the past 30 days: about 63,000 on 2026-10-24), so a URL still listed after the refresh interval is refreshed; OTX refreshes the known IOCs of the pulses a run reads. Feodo Tracker and SSL Blacklist report their whole list per run, up to their own caps ([§ 7](#7-finance-feed-collector)), so the stored copy of every entry of the list a run reads is refreshed; the AbuseIPDB blacklist reports at most 10,000 addresses per run, which AbuseIPDB chooses ([§ 5](#5-abuseipdb-collector)), so a listed address outside that answer is not refreshed. A Feodo Tracker daily run reads the 30-day list (5 servers on 2026-10-12), not the complete history a baseline loads, so the history is not reported again; the feed has not been updated since 2026-03-04, its refreshed addresses keep their March `last_online` as `last_seen`, and they age from it. Each run refreshes at most `EDGEGUARD_MISP_REFRESH_MAX_PER_RUN` (2,000) copies within `EDGEGUARD_MISP_REFRESH_MAX_SECONDS` (600 s), the longest unwritten first, so a list of about 10,000 entries whose copies fall due together is refreshed over several daily runs.
- **Cost in MISP.** The cross-event prefetch reads every attribute of the source; for the refresh it keeps uuid, timestamp and dates for the keys the push reports, and reads each row's event name (no extra request; measured on 150,000 rows in the MISP 2.5 listing format and a push reporting 20,000 indicators, the parse of the listing takes 48 ms instead of 31 ms and about 3 MB more memory, against the seconds each listed page takes MISP to serve). Each refresh is one MISP request (`POST /attributes/edit/{uuid}`, retried like the NVD edits), paced with `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` after every 50 edits, which is also where the parent-DAG liveness check runs, the longest unwritten first. A run stops refreshing at `EDGEGUARD_MISP_REFRESH_MAX_PER_RUN` edits (default 2,000), once `EDGEGUARD_MISP_REFRESH_MAX_SECONDS` (default 600) is spent, or after 5 failed edits in a row (MISP failing: a failed edit costs up to three attempts with a 600 s read timeout each). An edit in flight is not interrupted, so a run can exceed the time budget by one edit's attempts; the shortest collector task limit is 1 hour.
- **Cost in the sync.** Each refresh moves the timestamp of the event that holds the copy: after a baseline, the source's baseline event, or for a source the writer splits, the part that holds the copy. The incremental sync selects events by event timestamp, downloads every attribute of each selected event (events with up to `EDGEGUARD_MISP_PAGED_FETCH_ABOVE` attributes, default 20,000, whole as `/events/view/<id>/excludeGalaxy:1`, without the galaxy clusters; larger ones as `/events/restSearch` metadata plus `/attributes/restSearch` pages of 5,000, held in memory as one list), writes only the changed attributes, and for changed OTX items also parses the event's unchanged attributes to find the ones of the same pulses (report-scoped linking). Once refreshes begin, 30 days after a baseline, most incremental syncs therefore download and parse the OTX baseline event (149,270 attributes on 2026-10-13; the writer does not split OTX events). An NVD edit of a stored CVE or a URLhaus refresh makes the sync download the part that holds the copy, of at most `EDGEGUARD_MISP_EVENT_SPLIT_ABOVE` (20,000) attributes, fetched whole because the sync pages only events above `EDGEGUARD_MISP_PAGED_FETCH_ABOVE` (also 20,000). The writer adds attributes only to the event of the push day, so an event of an earlier day keeps its size, also one larger than the limit (an OTX event, which is never split, or an event written with the split off or at a higher limit); an edit or a refresh of a copy in such an event makes the sync download that whole event, in `/attributes/restSearch` pages above `EDGEGUARD_MISP_PAGED_FETCH_ABOVE`. The Feodo Tracker, SSL Blacklist and AbuseIPDB events (7,607 / 10,967 / 10,000 attributes) are read whole too. This has not been measured on the 730-day instance: time one incremental sync after the first refreshes, and set `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS=0` if the sync becomes too slow.
- **Accounting.** Refreshed, failed and deferred edits are counted in the writer's stats (`attributes_refreshed`, `attributes_refresh_failed`, `attributes_refresh_deferred`) and logged (`[REFRESH] N re-reported indicator(s) whose stored copy MISP last wrote more than 30 days ago: R refreshed, F failed, D left for a later run (reason)`; the push summary names the refreshed count). A failed or deferred refresh does not fail the push: the stored timestamp stays old and the next run that reports the indicator tries again.
- **Limit.** The refresh changes nothing but MISP's timestamp and, when the source claims a later date, `last_seen`. An existing IOC listed by a new OTX pulse does not receive that pulse's families, adversaries, report id or TLP: those travel in the attribute's `OTX_META` comment and tags, which this path never rewrites. For the same reason the values of a `TF_META` comment that change at the source (URLhaus `url_status`, `last_online`; Feodo Tracker `c2_status`, `last_online`; the AbuseIPDB score; the VirusTotal detection counts) are those of the first report for the life of the attribute: the comment records when they were read (`as_of`), and they read as "at first report". The same holds for the records a source merges into one value: an indicator ThreatFox or Feodo Tracker reports again with a new port, record id, family or threat type keeps the `ports`, `ioc_ids`, `families` and `threat_types` (and the primary record's keys, `confidence_level`, tags and confidence) of the run that first wrote it.
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
- lists after each push, in `last_push_unstored_items` (positions in the pushed list), the items MISP did not store because their batch failed (HTTP 4xx, a batch error or HTTP 429 after the retries; after HTTP 5xx and the retries, the items whose attributes the lookup in the event does not find, all of them when that lookup fails; an event id that is empty once sanitised, MISP having answered one of only whitespace or control characters, for which no request is sent; with `EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING`, an HTTP 200 that confirms none of the batch) or because their event lookup failed, their event part could not be created, or they did not fit the parts found and the lookup of the next part failed, or the lookup of a later part failed without a complete cross-event listing (nothing of the group is written), and the items no attribute could be built from when the drop is systemic for their source (counted as failed: a later run stores them once the collector reads the payload again). A skipped 4-byte value (counted as failed), a single item no attribute could be built from (reported only) and an attribute missing from a batch MISP answered with HTTP 200 and partly stored are not listed. Among the listed items, `last_push_event_failed_items` names those that failed at their event (its lookup or creation, a later part's lookup, a part not created, an event id empty once sanitised), which no batch carried. OTX holds its cursor below the listed items when all of them failed at their event, and puts the pulses with a listed item on its retry list otherwise ([Duplicate avoidance](#duplicate-avoidance-misp--incremental-runs));
- with `push_items(..., batch_key=f)`, never puts attributes whose items `f` maps to different values in one batch: each value's attributes go in batches of their own, the values in the order of their first item (an attribute built from several items of the push takes the first item's value), with the throttle between all batches. OTX passes it for the pulses of its retry list, so that a value MISP refuses fails only its own pulse's items;
- with `push_items(..., deadline=t)` (a `time.monotonic()` value), starts a batch only when the throttle pause before it, and the back-off cooldown when one is due, end before `t`, and starts no refresh edit after it; the items of the batches not sent are listed in `last_push_skipped_items` and count neither as stored nor as failed. A batch already sent is not interrupted, and the event lookup and listings before the first batch are not bounded. OTX passes it for the push of its retry list's pulses (`EDGEGUARD_OTX_RETRY_MAX_SECONDS`);
- retries a batch three times (four attempts, 10, 20 and 40 s apart) after HTTP 429 or 5xx, a timeout or a connection error, and an event or part lookup four times. After every three batches in a row that failed after their retries it pauses `EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC` (up to 300 s) in 30 s steps, and after a step, while at least 40 s of the pause is left (the request's 10 s connect and 30 s read timeouts), asks MISP a light request (one page of the day's event lookup, event headers only; a failure is logged at DEBUG): an HTTP 200 ends the pause. The time the request takes counts toward the pause, so the light requests never make it longer than its length (the baseline writer's parent-DAG liveness checks between the steps are not counted);
- stops a push once MISP has kept failing for `EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC` (900 s; `0` = no cap), or for the baseline's writer `EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE` (3600 s), at most until 10 minutes before its task's `execution_timeout` ends and at least 60 s ([CONFIGURATION.md](CONFIGURATION.md#collection-limits-and-the-misp-push)). The time is that of the current failing streak: from the start of the first request that failed (a batch answered HTTP 429 or 5xx, a timeout or a connection error, a failed event or part lookup) through the lookups after a 5xx, the back-off, `Retry-After` and cooldown waits and the attempts that follow; a batch MISP answered (stored, refused with HTTP 4xx, partly stored) ends it, and so does the group's event lookup before the batches, and the next failure starts a new streak with the whole cap. Successful requests and the throttle never start one, so time alone never stops a push; within a streak its time is wall time, the throttle pauses between its failing batches included. A batch's retries stop when the next wait would reach the cap, a `Retry-After` wait is cut to the time left, the lookups after a 5xx get timeouts of at most the time left (with none left the batch counts as not stored, without a lookup), and before a batch the push stops when the batch would start at or after the cap: the streak has reached it, or the throttle pause and the cooldown due before the batch would pass it (they are not slept); the check runs again after the pause, the cooldown and the parent-DAG liveness check (a new part of the event split is created after it). In a push of several sources the push also stops before a group's listings and event lookup once the streak has reached the cap (no collector pushes more than one source in one call). The cap never cuts a request short: a batch request has 30 s to connect and a 300 s read timeout, and a read timeout limits each wait for data, not the whole answer. Of the requests outside the batches, the day's event lookup, the lookups of later event parts and a new part's creation stop retrying at the cap but keep each request's full timeouts, and a new part is created after the last check before its first batch; the listings (no retries; each page has 30 s to connect and a 600 s read timeout) and, after the last batch of a push that did not stop, the refresh of re-reported indicators (its own limits) are not limited by the cap. So a MISP that answers slowly can keep a push going past the cap, most of all through the parts of a large NVD day (event split). The batch whose retries the cap cut short counts as a failed batch. After a stop nothing more is sent and no event part is created; the items of the batches not sent (of the current group, taken from its batches as built, and of every later one) count as failed, are listed in `last_push_unstored_items` and in `last_push_unsent_items`, and `last_push_stopped` is true; one ERROR `[MISP-PUSH-STOPPED] MISP push <source>: MISP kept failing for N s (EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC=900), so the push stopped before batch B of T: K batch(es) with A attribute(s) not sent, counted as failed; the push ends and the run goes on` names it, `edgeguard_misp_push_stopped_total` counts it (alert `EdgeGuardMispPushStopped`), the back-off counters are reset (only at a stop: the next push on the writer starts without a cooldown), and the refresh of re-reported indicators is left for a later run. The push returns its counts as usual. A timeout or a connection error after a batch's retries still raises out of `push_items`, sooner with the cap. NVD incremental runs attempt no edit of a stored CVE after a stopped push (the edits have no stop rule of their own); they count as not written and the cursor stays.

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
- **Pulse metadata:** `attack_ids` (MITRE ATT&CK), `industries` (the pulse's own sector classification, below), `targeted_countries`, `tags`, `references`, `author_name`, `adversary`, and the pulse's TLP, which every item of the pulse carries as `pulse_tlp` and MISP as its `tlp:` tag. OTX names the TLP field by endpoint: `tlp` in the subscribed list (scheduled and baseline runs), `TLP` in a pulse read by id (the retry list); the collector reads either (`tests/fixtures/otx_pulse_keys_2026_11_07.json`). A pulse stating no level is written at `EDGEGUARD_DEFAULT_TLP`. The lists copied onto the items (`attack_ids`, `industries`, `targeted_countries`, `tags`, `references`) are read as the pulse's report record reads them (`report_records.otx_pulse_list`): each item as one line, in the pulse's order, without blank or whitespace-only items (OTX answers some pulses' tags or references as `[""]`), items that are not strings or are longer than the record allows, and repeats; a value that is not a list is empty. The record holds the same items, sorted, so the copies and the record agree. An `attack_ids` entry is a string or an object read by its `id`.
- **Pulse text on the items, by TLP.** The pulse's name, tags, references and targeted countries are copied onto its items (`pulse_name`, `pulse_tags`, `pulse_references`, `targeted_countries`; the CVE reference's description names the pulse) only when the pulse states white, clear or green. An amber, amber+strict or red pulse, and a pulse that states no known level (counted as amber, as for its report record), keeps that text in its report record ([below](#report-records)), which MISP shares with the writer's organisation only. Its items carry the copies empty and keep `pulse_id`, `pulse_tlp`, `attack_ids` and `industries`, which the sync needs to link them. The sync takes no pulse name from such an item's comment, which is the whole `OTX_META` block: the indicator's `pulse_name` (on the `SOURCED_FROM` edge's `raw_data`) stays empty. `MISPWriter` applies the same rule to `OTX_META` (`misp_writer.pulse_copies_allowed`). An item several pulses list keeps the first pulse's copies, so withheld copies are never lent to another pulse's item; the item's `pulse_tlp` is the most restrictive of those pulses, so the copies of a white pulse whose IOC an amber pulse also lists are withheld too.
- **The pulse's industries as its sector statement.** A pulse that classifies itself into industries states, through its author, which sectors the campaign it describes targets. The zones those industries map to (`config.OTX_INDUSTRY_ZONE_ALIASES`, read through `config.otx_industry_zones`; an industry the table does not map gives none) join the zones keyword detection finds in the pulse (`zone`, below), and every item of the pulse carries the raw list (`otx_industries`). It travels to the sync as `OTX_META.otx_industries` on an indicator and as `MITRE_USES_TECHNIQUES.ind` on a malware family and an adversary (at most 20 names). A CVE the pulse lists as an indicator (OTX type `CVE`, a MISP `vulnerability` attribute) carries it in `OTX_META` like any indicator, and a CVE of `cve_references` carries none; the sync reads no industries from a `vulnerability` attribute, so `AFFECTS` never takes `otx_industries`. The sync takes the zones the item's industries map to as the pulse's statement (`stated_zones`, with the pulse as `stated_refs` on the OTX `SOURCED_FROM` edge): a `TARGETS` link to such a sector carries `otx_industries` (0.6), a sector only keyword detection found stays `zone_classification` (0.5), and a CVE the pulse names keeps `zone_classification` on `AFFECTS`, because a targeted industry says nothing about where a product is deployed (`src/sector_evidence.py`; [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Links to a Sector"). An item several pulses of one run list is the first pulse's item: the later pulses join `report_ids`, and the sectors their industries state join the item's zones and travel as `"<zone>|<pulse id>"` entries (`OTX_META.report_stated_zones`, `MITRE_USES_TECHNIQUES.rsz`; the first pulse of each sector first, and over the comment budget only the pulses still in `report_ids`), so each stated sector carries `otx_industries` and cites the pulses that stated it, whichever pulse listed the item first. The sectors keyword detection finds in a later pulse's text are not added (the item keeps the first pulse's inferred zones), and a sector inferred from the text cites every pulse of the item. Across runs MISP keeps the attribute written first (cross-event deduplication): a pulse of a later run that lists the same item adds neither its id nor its statement.
- **Pulse families / adversaries on every indicator:** each IOC item carries `pulse_malware_families` (the pulse's `malware_families`, cleaned, ≤ 20) and `pulse_malware_actor_pairs` (`"family::adversary::pulse"` for the pulse's families × its `adversary` names through `clean_actor_names`, ≤ 50 — the pair encoding keeps the same-pulse guarantee when several pulses' lists are unioned on one IOC); they travel as `OTX_META.mf` / `.pa`, accumulate on `Indicator.pulse_malware_families` / `.pulse_malware_actor_pairs`, and `build_relationships` Q9b / Q2d link them (`otx_pulse`, 0.6). `OTX_META.pa` holds the first pair of each family and adversary (the first pulse's) before the later pulses' pairs for them, and within the 4000-character comment `pa` is shortened before `report_ids` and `mf`, from the end, so the later pulses' pairs are dropped first and the first pairs stay while the comment fits ([MISP_SOURCES.md](MISP_SOURCES.md), "Metadata Comment Prefixes").
  - **One actor or several.** Whether a pulse's adversaries are one actor is decided here, on the pulse's whole `adversary` list (aliases of one actor count as one, canonical threat-actor reference): a pulse naming several actors gets no pairs, and every item of it lists the pulse in `several_actor_pulses` (`OTX_META.sap` on indicators, `MITRE_USES_TECHNIQUES.sap` on malware and actors), so the sync attributes nothing from it even when MISP has dropped some of its actors as duplicates. The mark also accumulates on the indicator (`Indicator.several_actor_pulses`): `build_relationships` step 2d and the acceptance check take a pulse marked there as naming several actors, as the collector judged it, besides the pulses whose actor nodes are several actors. Without the canonical reference the aliases of one actor count as several: the pulse still writes no pair, but its mark goes to `several_actor_pulses_by_name` (`OTX_META.sapn` / `MITRE_USES_TECHNIQUES.sapn`), which the sync uses for its own run and never stores on a node, so step 2d removes no link on a judgement made without the reference.
  - **A pulse edited later.** The actor nodes miss a pulse edited to name several actors after its pairs were written, because MISP does not push an actor it already holds again. Nor does MISP take an IOC it holds again, and the MISP writer adds no mark to a stored copy, because MISP keeps what the sources said and the mark is EdgeGuard's judgement: the mark of such a pulse reaches the graph only through its new IOCs, whose pushed attributes carry it. A pulse edited later to name several actors, whose IOCs MISP already holds and which brings no new IOC, is therefore not marked, and the pairs written before the edit stay linkable: a known limit. The pulse's report record ([below](#report-records)) holds its adversaries as edited; the sync does not read the records yet.
  - **Linking.** Q2d links a pair to the adversary's node or, when the actor alias merge has folded that name away, to its canonical actor, with the pair's pulse as provenance. This is what keeps report-scoped linking working on regular updates: the family / actor attribute itself is a MISP cross-event duplicate after the first pulse and is never re-pushed. `OTX_META` is written for every pulse indicator.
- **One item per entity of a run, compared as MISP compares it:** pulses spell one family or adversary in several cases (`DcRat`, `DCRAT`, `DCRat`, `DcRAT`, `dcrat`; `qilin`, `Qilin`), and in one event MISP does not store an attribute whose type and value match, ignoring case, an attribute an earlier request stored (within one request it stores both). The collector's dedup (`_pulse_item_key`) therefore keys a malware family or adversary by its graph key (`canonical_threat_actors.name_key`: NFC, trimmed, lower-case; a run of whitespace counts as one space), an indicator value whose MISP type MISP changes in case on save (`_CASE_NORMALISED_TYPES` in `src/collectors/misp_writer.py`) in the case MISP stores it (hashes, domains, IP and e-mail addresses lower-cased; CVE ids upper-cased, so a CVE indicator and a pulse's CVE reference of the same id are one item), a URL with its scheme and host lower-cased (the graph's `url` key, [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#indicator-identity)), and any other value as given, NFC-normalised and trimmed. A variant folds into the first item of the run, which keeps the first pulse's spelling (MISP shows that spelling, the graph's key is lower-case) and takes the later pulses' ids, techniques, stated sectors and TLP as for any duplicate. A defanged indicator value is refanged first, as MISP refangs a value of its MISP type on save, by MISP's own rules (`misp_writer.refang_as_misp`: `[.]`, `[dot]` and `(dot)` in URLs, domains, host names, IP and e-mail addresses; a leading `hxxp`, `hxtp`, `htxp`, `meow` or `h[tt]p` as `http`, `[hxxp://]` and `[:]` in URLs; `[@]` and `[at]` in e-mail addresses; other forms, such as `(.)`, stay as given, as MISP stores them). A pulse that lists `https://bashupload.com/uCiPm/SENT_Kill[.]zip` gives the item `https://bashupload.com/uCiPm/SENT_Kill.zip`, the value MISP stores: the push sends it and confirms it, the duplicate checks against MISP compare it, and it folds with that value when the pulse or an earlier one of the run lists it. Across runs MISP keeps the spelling it stored: an indicator value of those types that a later run lists in another case is the stored copy, present and not pushed again ([Duplicate avoidance](#duplicate-avoidance-misp--incremental-runs)); a family or adversary name a later run pushes in another case to the same event is not stored, and the push confirmation reports it (`[UNCONFIRMED]`). Two URLs of one run whose paths differ only in case stay two items, as they stay two Indicators in the graph: MISP stores both when one request carries them, but when they reach one event in different requests (two batches, or two runs) it may keep only the first, and the push confirmation, which compares URLs exactly, reports the other as `[UNCONFIRMED]`.
- **TLP of an entity several pulses list:** when pulses of one run list the same IOC (or family, actor, CVE), the collector's dedup keeps the most restrictive `pulse_tlp` of those pulses (white / clear < green < amber < amber+strict < red, ranked as `MISPWriter` writes the `tlp:` tag; an empty or unknown value ranks as `EDGEGUARD_DEFAULT_TLP` and never displaces a stricter level). A pulse of a later run that lists an IOC MISP already holds does not change the stored TLP ([Re-reported indicators](#re-reported-indicators)).
- **Adversaries as ThreatActor items.** The pulse's free-text `adversary` field is decided once per pulse, and the actor items, the `family::adversary::pulse` pairs and the one-actor-or-several decision above all use the same names:
  - `actor_name_hygiene.clean_actor_names` splits composites (`"apt-c-13, sandworm"` → two names; `"BlackHatSect0r && DXQRTXX"` → two names), never inside parentheses or before a company's legal form (`"Black Owl (BO Team, Hackers of the Black Owl)"` is `Black Owl`, and `"Black Owl (BO Team"`, cut off as an OTX report gives it, too; `"Integrity Technology Group, Inc."` is one name), drops a name that is only a legal form (`"Ltd."`), and drops descriptions (`"multiple russian state-backed groups"`, `"chinese-speaking group"`), and country or state names, nationality adjectives and state intelligence and security agencies standing on their own (`"north korea"`, `"dprk"`, `"russian federation"`, `"iranian"`; `"mois"`, `"gru"`, `"russian federal security service"`, `"russian intelligence services"`; `"North Korea (APT37)"` is `APT37`): a pulse whose adversary field reads `"APT37, North Korea"` or `"APT28, GRU"` names one actor and counts as a pulse naming one actor. A name that contains a country or an agency stays a name (`"cyber army of russia reborn"`, `"GRU Unit 26165"`). The run logs the distinct country, state, nationality and agency names it dropped this way, alphabetically, each with the number of pulses that carried it and up to three of their ids (`[ACTOR-NAMES] OTX: N distinct country, state, nationality or state-agency name(s) in M pulse(s), dropped from the adversary field by the actor-name hygiene (never actor names; a group named after a country or an agency needs a qualified name): mois (1 pulse: <id>); north korea (2 pulses: <id>, <id>); russia (1 pulse: <id>)`; `actor_name_hygiene.dropped_geopolitical_names`). A fragment that yields a name is not listed (`"North Korea (APT37)"`); a country followed by a parenthetical that yields no name is (`"Cuba (Ransomware)"` lists `cuba`). A group whose common name is a country is written under a qualified name (`Cuba Ransomware Gang`), which the canonical threat-actor reference can give to an actor ([RUNBOOK.md](RUNBOOK.md), "Canonical threat-actor reference").
  - A name the canonical threat-actor reference lists as no actor (its `not_actors`: names a review found to be a technique, malware, a kit, a hosting network, a forum, a company or a campaign, such as `ClickFix`, `Proton66`, `Agent Tesla` or `BreachForums`) is dropped, whatever families the pulse lists; the pulse's malware families stay its malware items. `"TAG-124, ClickFix"` names one actor. The run logs the distinct names it dropped this way, alphabetically, each with the number of pulses that carried it and up to three of their ids (`[ACTOR-NAMES] OTX: N distinct adversary name(s) in M pulse(s) that the canonical threat-actor reference lists as no actors, dropped from the adversary field: clickfix (2 pulses: <id>, <id>); proton66 (1 pulse: <id>)`). A name the list should not hold is taken out of the reference's overrides file ([RUNBOOK.md](RUNBOOK.md), "Canonical threat-actor reference"). Without the reference nothing is dropped.
  - A name the same pulse lists both as adversary and as a malware family (equal actor key, the family also without its ATT&CK software id or a trailing parenthetical, every family of the pulse) is an actor only when the canonical threat-actor reference resolves it (a name the reference lists as ambiguous or never_merge, such as `winnti`, counts as unknown): `Kimsuky` or `Akira` stay actors, and so do the ransomware operations named after their own ransomware that the reference holds through override decisions (`Rhysida`, `BlackSuit`, `Trigona`), and so does a ransomware operation the reference holds as a name of its operator (`Conti`: Wizard Spider, `LockBit`: BITWISE SPIDER, `Qilin` and its earlier name `Agenda`: Water Galura); `Lumma Stealer` or `AsyncRAT` are not taken as actors for that pulse and stay its malware family item (a `Malware` node). A name that only another pulse lists as a family stays an actor. The run logs the distinct names it left out, how many and in how many pulses (`[ACTOR-NAMES] OTX: N distinct adversary name(s) in M pulse(s) …: <names>`, every name, alphabetically). An actor the reference lacks is added to the reference through `src/reference/canonical_threat_actor_overrides.json` ([RUNBOOK.md](RUNBOOK.md), "Canonical threat-actor reference"). Without the reference the rule cannot decide and the name is kept as an actor (the warning `[ATTRIBUTION] canonical reference unavailable` is logged once per run).
- **No entity description:** malware-family and adversary items carry no `description`, because the pulse's description describes the report, not the family or actor. A family or actor only OTX names shows no description; the pulse that first named it (and the other pulses of that run that named it) are in `n.pulse_ids[]`, later pulses link to it through `Indicator.pulse_malware_families` / `.pulse_malware_actor_pairs`. MISPWriter writes such an item's comment as the `MITRE_USES_TECHNIQUES` block alone. The sync takes no description from an OTX malware or actor attribute. The pulse's description is stored on no item (an indicator keeps its own `description`); it feeds sector detection, which scans the whole pulse, so it decides the `zone` of every item the pulse yields, families and adversaries included.

### Source
- **URL:** `https://otx.alienvault.com/api/v1/pulses/subscribed`; the pulses of the retry list one by one, `https://otx.alienvault.com/api/v1/pulses/{id}` ([Scheduled runs: the retry list](#scheduled-runs-the-retry-list))
- The pulses whose report record waits on `report_pending`, one by one by id as the retry list's ([Report records](#report-records))
- **API Key:** Required (free)
- **Rate Limits:** ~30 requests/minute (free tier, 2s between requests)

### Pages and pulse counts
OTX pages `/api/v1/pulses/subscribed` by offset (`page` and `limit`), and the request names no sort order. When the order shifts between two page requests (a pulse modified while the pages are read, or pulses that share a `modified` time), a pulse can come back on a later page and another be passed over. Both fetch paths, the baseline and the scheduled run, therefore keep the first copy of each pulse id and leave out the later rows (`_first_copy_of_each_pulse`); a row without an id is kept. The scheduled run removes the repeats before it applies `EDGEGUARD_INCREMENTAL_LIMIT`, so a repeated row takes no slot of the limit.

Each run logs:

- the distinct pulses beside the rows the pages returned and, when OTX states it (`count` in the answer), the number of pulses OTX reported: `Baseline complete: N distinct pulses collected of M that OTX reported for the window (R rows read, X of them repeating a pulse already read)`; a scheduled run logs `OTX incremental: N distinct pulses read of M that OTX reported for the window (R rows read, X of them repeating a pulse already read)`;
- at WARNING, when pages repeated pulses, how many rows and pulses and the ids of up to 20 of the repeated pulses, whose first copy was kept (ids only): `[PULSES] OTX: X page row(s) repeated P pulse(s) already read (repeated ids: <id>, <id>, …); the first copy of each is kept. If the page order shifted between requests, as many other pulses may have been passed over.` The ids name the pulses that came back, not the ones that may have been passed over, which the run cannot see;
- after processing, the pulses processed and those that yielded no item (no collected indicator, malware family, CVE or adversary; for example a pulse whose indicators are all of a non-file hash type), with the ids of up to 20 of them: `[PULSES] OTX: N pulse(s) processed, K of them yielded no item (no collected indicator, malware family, CVE or adversary): <id>, …`. A pulse whose items another pulse of the run listed first is not among them: its id travels in the kept item's `report_ids`. A pulse without an id is counted as processed but never among them (OTX gives every pulse an id).

A scheduled run also logs the pulses its limit left to the next run, and a page ceiling reached with pulses left to read ([below](#scheduled-runs-limit-and-cursor)).

The status a run returns carries the same counts as `pulse_counts`: `rows_read`, `distinct`, `repeated_rows`, `processed`, `without_item` and `deferred` (the pulses a scheduled run's limit left to the next run; 0 in a baseline). A scheduled run that pushed adds the retry list's counts ([below](#scheduled-runs-the-retry-list)): `retry_pending`, `retry_added`, `retry_fetched`, `retry_recovered`, `retry_given_up`, `retry_not_found`, `retry_fetch_failed` and `retry_not_pushed`, and `held_unsent`, the window's pulses whose items a push that stopped because MISP kept failing did not send; `processed` counts the window's pulses only. Every run that pushed also returns `report_counts` ([Report records](#report-records)). A distinct count below the reported one, with repeated rows, points to paging; pulses that yielded items but have no reference on the graph point to items lost after the collector (in MISP or the sync).

### Scheduled runs: limit and cursor
OTX returns the pulses of `/api/v1/pulses/subscribed` newest-modified first. A scheduled run reads the pulses modified since its cursor (`otx_last_pulse_modified`) minus `EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC` (300 s) and divides them (`_incremental_pulses_within_limit`):

- the pulses modified after the stored cursor count toward the run's limit, oldest first (by `modified`, then by id): the run takes the oldest 200 and leaves the rest to the next run. The limit is `EDGEGUARD_INCREMENTAL_LIMIT` (200), or `EDGEGUARD_MAX_ENTRIES` when that is set ([CONFIGURATION.md](CONFIGURATION.md#collection-limits-and-the-misp-push)), which counts the same way;
- the pulses modified at or before the cursor, which the run reads only because of the overlap, are processed without counting, and so are pulses without a readable `modified`, which can neither be placed against the cursor nor move it (WARNING `[PULSES] OTX: N pulse(s) without a readable 'modified' processed outside the limit; they cannot move the cursor, so every run that reads them processes them again (ids: …)`).

Without a stored cursor, or with one that does not parse, the run reads the last `EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS` (3) days and every pulse with a readable `modified` counts. The pulses processed keep OTX's order, so an item several pulses of the run list is the newest pulse's item, as in a baseline. `EDGEGUARD_INCREMENTAL_LIMIT=0` processes every pulse read.

The cursor then advances to the newest `modified` among the pulses processed (compared as UTC: a value without a zone is UTC; the cursor keeps the value as OTX wrote it), subject to the push rules in [Duplicate avoidance](#duplicate-avoidance-misp--incremental-runs). A push of items MISP already holds (after an additive baseline over an older cursor, or pulses re-modified without a new indicator) stores nothing and fails nothing; the cursor advances to the newest of those pulses, as after any push without failures, so the next run takes the newer ones. Every pulse the limit left out is modified at or after that value, so the next run reads it again: counted when it is modified after the new cursor, as a re-read of the overlap when it shares the cursor's value. Pulses that share one `modified` value do not stall the cursor, however many of them the limit cuts: the next run processes them as re-reads and counts the newer pulses. This rests on OTX answering the pages of a run in one order. When the order shifts between page requests, a pulse can be passed over unread, and the cursor can pass it. The WARNING on repeated page rows ([Pages and pulse counts](#pages-and-pulse-counts)) marks a run in which a pulse already read came back on a later page, as it does when the order of pulses that share a `modified` value changes. A pulse removed from the subscription between two page requests (deleted, or no longer subscribed) moves the later rows up by one instead: one pulse is passed over without a repeated row and without a warning.

A run processes at most the limit of pulses modified after its cursor, plus the overlap's re-reads and the pulses without a readable `modified`. The re-reads are every pulse modified in the 300 s before the cursor, processed again on each run whose window reaches them. In a sparse window they are a few pulses. While a backlog of more than the limit per 300 s of `modified` drains (pulses modified in bulk), each run processes again every pulse the earlier runs took in that span, so the work of a run grows by up to the limit from run to run, at most to the page ceiling (2,500 pulses), until the cursor moves more than 300 s past them; the same holds while more pulses than the limit share the cursor's value. Nothing is lost: the extra work is items MISP already holds, which the push's duplicate check skips.

A pulse whose item MISP does not store does not hold the cursor: the cursor advances and the pulse goes on the retry list ([below](#scheduled-runs-the-retry-list)), so the next runs take the newer pulses. This holds whatever the push stored: a push whose items MISP holds but one returns 0 stored and 1 failed, and the run fails, but the cursor moves on; a value MISP refuses fails its whole batch, so every pulse of that batch goes on the list, and the next run pushes each in a batch of its own, which frees all but the pulse of the refused value. A failure the writer does not list holds no pulse and puts none on the list: when a value MISP can never store (4-byte characters) is the only item MISP lacks among the pulses a run takes, the run fails and the cursor advances to the newest pulse it processed. Only a push whose listed items all failed at their MISP event holds the cursor, below the oldest pulse with a listed item, until MISP answers again, and so does a push that stopped because MISP kept failing, below the oldest pulse with an item it did not send; each run then takes the same oldest pulses after it again, and when more pulses than the limit are modified after the held cursor, the newer ones wait.

When the limit leaves pulses out, the run logs `[PULSES] OTX: N pulse(s) deferred to the next run: the run's limit of 200 (EDGEGUARD_INCREMENTAL_LIMIT, or EDGEGUARD_MAX_ENTRIES when set) counts the pulses modified after the cursor, oldest first, and the run took those modified up to <modified>; K pulse(s) re-read inside the overlap window were processed outside the limit`, and the status counts them as `pulse_counts.deferred`.

**Page ceiling.** The run reads pages of 100 pulses, at most `EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES` (25). When it stops there with pulses left to read (a full last page, or OTX reporting more pulses than were read), the pulses not read are the oldest of the window, older than every pulse the run processes, and any advance of the cursor passes them. The run logs a WARNING: `OTX incremental stopped at its page ceiling (EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES=25, 100 per page): N distinct pulses read of M that OTX reported for the window. OTX returns the newest-modified pulses first, so the pulses not read are the oldest of the window, and any advance of the cursor passes them; raise EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES or run a baseline to read them`.

### Scheduled runs: the retry list
A scheduled run whose push leaves items unstored in batches MISP answered, or in a systemic conversion drop, moves its cursor on ([Duplicate avoidance](#duplicate-avoidance-misp--incremental-runs)) and records the pulses of those items on a retry list, `otx_retry_pulses`, beside the cursor in the incremental state (`checkpoints/baseline_checkpoint.json`, `[otx].incremental`). The failure is recorded and the flow goes on: the newer pulses keep reaching MISP while the failed ones are tried again.

- **Entry.** One per pulse: `id`, `modified` (as OTX wrote it, when readable; a pulse without a readable `modified` is listed by its id), `first_failed_at` and `last_tried_at` (UTC, the start of the run that put it on the list or last pushed its items), `attempts`, `last_reason` (the run's failure, or the error of the last fetch by id; at most 300 printable ASCII characters, another character, a control character included, written as `?`), `failed_items` (references to up to 10 of its items that failed: the item's type and 16 hex digits of the SHA-256 of its identity key, at most 49 characters each, whatever the length of the value), after a fetch by id that failed `last_fetch_failed_at`, and on the pulse a push of the list's pulses began with, when that push raised or the task was killed, `last_push_started_at` (the run's start, written before that push; no try, and dropped at the pulse's next try). `attempts` counts the runs that pushed the pulse and kept it on the list: an item of it listed again, an item recorded as failed that the pulse as read lacks, or an unknown failure; the task's own Airflow retries are runs of their own. A pulse already on the list keeps its `first_failed_at` and gets one more attempt. A run that did not push the pulse's items changes nothing of its entry but `last_reason` and `last_fetch_failed_at` after a failed fetch: a fetch by id that failed, a run whose push failed at the MISP event (below), a pulse the time budget left unpushed and a pulse whose items a push that stopped because MISP kept failing did not send count no attempt and leave `last_tried_at`. In the state file, which `baseline_checkpoint` writes with `json.dump(..., indent=2)`, an entry takes about 490 bytes and at most 2,000 (`otx_collector._RETRY_ENTRY_MAX_BYTES`; the largest, with ten references of 49 characters and a reason JSON escapes, about 1,710), so the list at most 2 MB at its cap of 1,000. The cursor and the pulses the window's push adds are written in one update of the incremental state, after the window's push and within the list's cap; the list is written again after the push of its pulses.
- **Retries.** Each scheduled run fetches up to `EDGEGUARD_OTX_RETRY_PER_RUN` (50; `0` = none) pulses of the list by id, those tried longest ago first (a pulse whose fetch failed goes behind those tried since, and so does the pulse marked with `last_push_started_at`): `GET /api/v1/pulses/{id}` with the session, timeouts and TLS setting of the page fetch, and 2 s after each request, as between pages (OTX allows about 30 requests a minute; 50 retries add at least 100 s of pauses to a run). A pulse the run's window reads is not fetched: the window processes it (a pulse modified again), or a later run does (a pulse the limit defers, which the cursor cannot pass). OTX's answer by id (read on 2026-11-02) carries every field the collector reads of a pulse except `cve_references` (its CVE came as an indicator of type `CVE`), and its indicators carry no `role` or `modified`; the collector reads each with its default, as for a subscribed pulse without them. The pulses fetched are processed after the window's, so an item both list keeps the window's copy and names the retried pulse in its `report_ids`; they count toward no limit, and their `modified` never moves the cursor.
- **Two pushes.** The run first pushes its window: every item that names a pulse not on the list, in one push without a batch key, as before the list existed. It then writes the cursor and the pulses that push put on the list. Then it pushes the items that only pulses of the list name (fetched by id, or read in its window), in one push of their own: each pulse in batches of its own (`push_items`' `batch_key`), those tried longest ago first, so a value MISP refuses fails only its own pulse's items. An item two pulses of the list name goes in the batches of the one tried longest ago; an item a window pulse without an id shares with a pulse of the list names that pulse only in its `report_ids` and goes in its batches. A run that put the pulses of one refused batch on the list thus frees, at the next run, all but the pulse of the refused value. An item that a pulse not on the list also names goes in the window's push. When the window's push failed at the MISP event, or stopped because MISP kept failing, the pulses of the list are not pushed in that run. The list written before the push of its pulses marks the pulse that push begins with (`last_push_started_at`), and the list written after it drops the mark. When that push raises (MISP not answering a batch after the writer's attempts: the run fails with `Timeout: …`) or the task is killed, the marked pulse goes behind the others at the next run; a pulse whose batch raises on every run thus moves to the back once it comes first, and the pulses before it in each run's push are sent. Such a pulse records no try, so it is not given up by age: every run that pushes it fails, and it leaves the list at the cap or at a fresh baseline. When every pulse of the list fits in one run's push, every run pushes it and fails before it settles the list: the other pulses' items reach MISP, but those pulses record no try and stay on the list until that pulse leaves it.
- **Time budget.** The push of the list's pulses runs within `EDGEGUARD_OTX_RETRY_MAX_SECONDS` (600), counted from its start: no batch starts once its throttle pause, and a back-off cooldown when one is due, would end at or after the budget, and no refresh edit starts after it (`push_items`' `deadline`). A batch already sent finishes with its attempts (after HTTP 5xx, four of them with 70 s of pauses), so the push ends at most one batch after the budget. The pulses whose items were not all sent keep their entries unchanged, count in `pulse_counts.retry_not_pushed`, are named in a WARNING (`[OTX-RETRY] OTX: the push of the retry list's pulses reached its time budget (EDGEGUARD_OTX_RETRY_MAX_SECONDS=600) after S s: N pulse(s) were not pushed; they keep their entries and are pushed first by the next run (ids: …)`) and go first at the next run. Like every push, it looks up the day's event and lists MISP's attributes, the event's and the source's (5,000 a page), before its first batch, and that counts toward the budget: for an OTX event of 150,683 attributes (the 730-day baseline of 2026-11-02) and as many under the source tag, 63 requests, about 0.75 s on the collector's side, and about 2 minutes at MISP at the rate the writer records for its listings (about 30-40 s for 19 pages); for a day's event of 2,000 attributes and the same source listing, 33 requests. One push serves all the pulses of the list, so a run pays this once, not once per pulse. With the 5 s throttle a pulse in one batch takes about 5 s, so 50 fit; into a day's event of 100,000 attributes or more (the throttle 30 s, [MISP_TUNING.md](MISP_TUNING.md)) about 15. A pulse whose batch keeps answering HTTP 5xx takes about 75 s, and a cooldown follows three such batches in a row: it ends after its first 30 s step when MISP answers a light request (the batches failing on the event's size, as on 2026-11-01), so about six of them fit, and it lasts its 300 s when the light request fails too, so about four fit; the others take their turn at the next runs. Without the budget the push would go on until the writer's cap on failure time stopped it (`EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC`, 900 s, [MISP push](#misp-push-attribute-types-and-characters)), a quarter of the task's limit for one push.
- **Stopped push.** When either push stops because MISP kept failing for longer than the writer's cap (`[MISP-PUSH-STOPPED]`), the items it did not send (`last_push_unsent_items`) count as failed but say nothing about their pulses. After the window's push the cursor stops below the oldest window pulse such an item names, those pulses go on no list, the pulses of the list that such an item names keep their entries, a pulse of the list read in the window whose items were all sent follows that push (it leaves the list when they were stored), and the list's push does not run; WARNING `[OTX-RETRY] OTX: the MISP push stopped because MISP kept failing ([MISP-PUSH-STOPPED]): the items of N pulse(s) of the window were not sent; those pulses do not go on the retry list, and the cursor …`, and `pulse_counts.held_unsent` counts them. When a listed item names no pulse the run processed (an OTX row without an id), the cursor stays and no pulse goes on the list, and the pulses of the list that an item not sent names still keep their entries. The list's cap (`EDGEGUARD_OTX_RETRY_MAX_PULSES`) still applies: the pulses the stopped push adds can take the oldest pulses off the list, those whose entries the stop kept included. After the push of the list's pulses, the pulses whose items it did not send keep their entries unchanged and go first at the next run, as after the time budget, and count in `pulse_counts.retry_not_pushed` (WARNING `[OTX-RETRY] OTX: the push of the retry list's pulses stopped because MISP kept failing ([MISP-PUSH-STOPPED]) after S s: N pulse(s) were not pushed; …`). The pulses whose items were sent and failed are treated as after any batch failure: added to the list, or one more attempt.
- **Recovery.** After the push, a pulse of the list the run processed leaves the list when none of its items is listed as unstored and every item recorded as failed was pushed again for it, so stored or found in MISP (INFO `[OTX-RETRY] OTX: N pulse(s) recovered …`). A pulse read without such an item (it no longer lists it, or OTX's answer by id lacks it) stays, with a WARNING (`[OTX-RETRY] OTX: N pulse(s) of the retry list read without items of theirs that failed earlier …`), and is given up in the end, with an ERROR, rather than taken off without a word. A pulse also stays after a failure at the event, which adds no pulse, leaves the entries as they were (no attempt, no `last_tried_at`, no reason) and gives up no pulse by age (an outage says nothing about the pulses), when a stopped push did not send its items (likewise), and after an unknown failure.
- **Fetch failures.** HTTP 404 means the pulse was deleted or is no longer subscribed: it leaves the list with a WARNING (`[OTX-RETRY] OTX: pulse <id> answered HTTP 404 …`), counted as `retry_not_found`, not as given up. Any other answer keeps it on the list, logs a WARNING and sets `last_reason` and `last_fetch_failed_at`. It is no try: the pulse's items were not pushed, so `attempts` and `last_tried_at` stay and the give-up rule does not count it; `last_fetch_failed_at` only puts the pulse behind those tried since, so a pulse OTX keeps failing to answer holds no other back. A pulse whose fetch keeps failing is not given up by age: it stays, and `EdgeGuardOtxRetryPulsesWaiting` keeps firing ([RUNBOOK.md](RUNBOOK.md)). HTTP 429 or 5xx (429, 502, 503 and 504 after one retry, 30 s later or after the answer's `Retry-After`) or an error of the request itself (a timeout, a connection error, a body cut off: any `requests` exception) also stops the fetches of the run, and the pulses not fetched wait for the next run, where they come before the one whose fetch failed. An answer by id that cannot be processed (a field of another type than a subscribed pulse carries, such as `indicators: null`) is set aside the same way: the pulse stays, without a try, with a WARNING (`[OTX-RETRY] OTX: the answer by id for pulse <id> could not be read …`), and the run goes on; the items the pulse yielded are dropped, and it is named or counted on none of the run's `[ACTOR-NAMES]` and `[SKIP]` lines (a pulse's names and counts are added once all its items are built).
- **Giving up.** A pulse first failed more than `EDGEGUARD_OTX_RETRY_MAX_DAYS` (7) days ago is given up once a run has pushed its items after that deadline (fetched by id or read in the window, then pushed): a pulse that waited while no run pushed it (after a pause of the scheduled runs, beyond a run's fetches or its time budget, deferred by the limit, while its fetch by id failed, while the push failed at the MISP event, or while a stopped push did not send its items) gets that try first. It leaves the list with an ERROR that names it with its `modified`, attempts, first failure and last reason (`[OTX-RETRY-GAVE-UP] OTX: N pulse(s) given up (EDGEGUARD_OTX_RETRY_MAX_DAYS=7, EDGEGUARD_OTX_RETRY_MAX_PULSES=1000): … <id> (modified <time>, attempts A, first failed <time>, last reason: …)`, up to 50 pulses a line), and `edgeguard_otx_retry_given_up_total` counts it. The list holds at most `EDGEGUARD_OTX_RETRY_MAX_PULSES` (1000) pulses; beyond it the pulses that first failed longest ago are given up the same way, tried or not, when the run writes the pulses its window's push added, before the list's pulses are pushed (their items are then not pushed), so a run that raises or is killed later leaves no longer list. A pulse whose last retry stores its items leaves as recovered, not given up by age: the age rule waits for that push. A given-up pulse's failed items are not in MISP and no scheduled run collects them; a baseline whose window reaches its `modified` does, once the cause is fixed ([RUNBOOK.md](RUNBOOK.md), "OTX retry backlog and given-up pulses").
- **Each run** with a pulse on the list, or one that changed it, logs `[OTX-RETRY] OTX: P pulse(s) on the retry list after the run (the first failure of the longest waiting: <time>); this run fetched F by id, recovered R, added A and gave up G; N answered HTTP 404, E could not be fetched or read, U were not pushed (time budget, a stopped push, or a failure at the MISP event)`, at WARNING while P is above 0. Pulses put on the list are named at WARNING (`[OTX-RETRY] OTX: N pulse(s) put on the retry list: … (ids: …)`), and a failure at the event says where the cursor went (`[OTX-RETRY] OTX: every unstored item of the push failed at its MISP event …`).
- **Metrics.** After every scheduled run that pushed, `edgeguard_otx_retry_pulses` gives the pulses on the list and `edgeguard_otx_retry_oldest_failure_timestamp_seconds` the first failure of the one waiting longest (0 when the list is empty); `EdgeGuardOtxRetryPulsesWaiting` fires when a pulse has waited more than 24 hours, `EdgeGuardOtxRetryPulsesGivenUp` when pulses were given up in the last 24 hours ([PROMETHEUS_SETUP.md](PROMETHEUS_SETUP.md)). A fresh baseline's wipe sets both gauges to an empty list.
- **Run status.** The status is unchanged (`status_after_misp_push`, over the counts of both pushes; items the time budget left unsent count neither way, items a stopped push did not send count as failed): a push with failures fails the run when it stored nothing or falls below `EDGEGUARD_MISP_MIN_SUCCESS_RATE`, also when the cursor moves on. The task then fails and Airflow retries it (two retries, 5 minutes apart), each retry a run of its own. While a pulse of the list keeps failing, a run with no new item to store stores nothing and fails (the subscription read on 2026-11-02 held 370 pulses modified in 60 days, about 6 a day, against 48 runs a day), and so do its two retries, which fetch and push the same pulse again; `EdgeGuardDAGRunFailures` and `EdgeGuardSourceUnhealthy` then fire beside `EdgeGuardOtxRetryPulsesWaiting`, from the same cause. A run that stores the items of new pulses passes when their share reaches the minimum (20 stored and 1 failed does). Nothing else waits on it: the only task after `collect_otx` in `edgeguard_pipeline` is `log_summary` (an echo, then `upstream_failed`), the next run starts at its next 30-minute slot whatever the state of this one (one run at a time), and the MISP → Neo4j sync is a DAG of its own.
- **Baselines.** A baseline neither reads nor changes the list. A fresh baseline removes it with the rest of the incremental state (`baseline_clean._wipe_checkpoints`, `clear_checkpoint(include_incremental=True)`, which then sets the retry gauges to an empty list); an additive baseline keeps it, and the next scheduled run's retries find the pulses the baseline stored and take them off the list.

### Report records
Every pulse a run processes, and every pulse it fetches by id for the retry list or for `report_pending`, gets one report record: one MISP Event Report, written by `MISPWriter.push_reports` ([MISP_SOURCES.md § Report records](MISP_SOURCES.md#report-records-event-reports)). A new record goes to the OTX day event, or to its companion event `EdgeGuard-alienvault_otx-<date>-reports` when the day event holds more than `EDGEGUARD_MISP_EVENT_SPLIT_ABOVE` attributes. A baseline's OTX day event holds more than that, because an OTX event is never split. A revised record is edited in the event that already holds it. The record holds the pulse as OTX gives it, its full description included, and the indicators as `[MISP type, value]` pairs, exactly those the push sends for the pulse's items: the collector's and the writer's type mapping on the value `sanitize_value` leaves, a defanged value refanged as above, the non-file hash types left out, CVE references and CVE indicators as `vulnerability` in upper case. Indicators the same-run fold makes one item give one pair, in the first spelling, the one the push sends: a pulse that lists `http://setseta.com/set.exe` and later `http://Setseta.com/set.exe` gives one pair, and `indicator_count` counts it once. A spelling an earlier pulse of the run listed is the one MISP holds; the graph keys both alike. A pulse read in the window and by id gives the same record, and one pulse read twice in a run gives one record. A pulse without an id gets none.

- **Order.** A record is pushed after the push that carries its pulse's items, whatever happened to them: a pulse whose items failed, or that yielded no item, still gets its record. The window's records are pushed after the window's push and before the cursor moves; the records of the retry list's pulses, read in the window or fetched by id, and of the pulses fetched for `report_pending`, after the push of the retry list's pulses. Those of the retry list's pulses are pushed before the list is settled. A baseline pushes the records of all its pulses after its push.
- **Batches.** The records are built and pushed 100 at a time. The pulses are in memory for the whole run anyway, since they hold every indicator; built in batches, the records add at most one batch's copy of them, and each batch's outcome is saved before the next starts. A record whose build raises any error fails that record (`the record could not be built (<error>)`), which waits on `report_pending`; a date past year 9999 in UTC counts as no date.
- **`report_pending`.** After each batch `report_records.note_report_push` keeps the records whose push failed, or that the push did not try, on `report_pending` beside the cursor (`checkpoints[otx]["incremental"]["report_pending"]`), on baselines and scheduled runs alike, and takes off those MISP now holds. Each entry holds `record_ref`, `first_failed_at`, `attempts`, `last_tried_at` (absent while the record was never tried) and `last_reason`, and, while the fetches of its pulse by id fail, `first_fetch_failed_at` and `last_fetch_failed_at`. A run without records saves the list once, so its gauges follow it. The list is apart from the retry list: a pulse can be on both, one for its items and one for its record.
- **Retries.** Each run that pushes, a baseline included, fetches up to `EDGEGUARD_OTX_RETRY_PER_RUN` (50; `0` = none) pulses of `report_pending` by id, those tried or fetched in vain longest ago first, leaving out the pulses its window read or the retry list fetched or tried to fetch (their records are built there, or wait for that list), and pushes their records; their items are not pushed again. HTTP 404 takes a record off the list (WARNING `[REPORT-PENDING] OTX: N pulse(s) answered HTTP 404 …`). Any other failure of the fetch is no try: the entry keeps `attempts` and `last_tried_at`, gets `last_fetch_failed_at` (and `first_fetch_failed_at` on the first such failure since its pulse was last read) and `last_reason`, and goes behind the others at the next run, so a pulse OTX keeps failing to answer holds no other back. HTTP 429, 5xx or a request error stops the fetches of the run, and when the retry list's fetches stopped, the run fetches no pulse of `report_pending`. A pulse fetched, or a push that tries its record, ends its fetch failures. An answer that is not JSON, or is nested deeper than the decoder goes, is an answer that is not the pulse. These fetches come before the window's push; when they raise, the run logs an ERROR `[REPORT-PENDING] OTX: the fetches for report_pending failed …`, fetches none of them this run, and pushes its window as usual.
- **Giving up.** A record still failing `EDGEGUARD_REPORT_PENDING_MAX_DAYS` (7) days after its first failure is given up by the next push that tries it, with an ERROR `[REPORT-GAVE-UP] alienvault_otx: …`. A record whose pulse has failed to be fetched by id for more than that many days, the last of those fetches past the record's deadline, is given up too; the line names the first of those failures. A record no push tried (its task's end came first, or MISP kept failing) and whose pulse answers is never given up by age, and a fetch failure shorter than the limit gives up nothing.
- **Limits.** `push_reports` gets the writer's parent-DAG liveness callback (the baseline's; called before each record) and stops at the writer's `task_ends_at`: both OTX tasks give their writer the end of their `execution_timeout` (one hour scheduled, five hours for the baseline), so no record starts later than 10 minutes before it and the run saves `report_pending` before Airflow kills the task. Once a push leaves records untried (the task's end, MISP failing, no day event), the later batches are not pushed and wait on the list, untried, with the same reason.
- **The cursor.** The cursor passes a pulse whose record MISP does not hold only once that record is on `report_pending` and the list is saved. When the list cannot be saved after a batch of the window's records (ERROR `[REPORT-PENDING] OTX: report_pending could not be saved …; the cursor passes none of these pulses`), the window's remaining batches are not pushed and the cursor stops below the oldest pulse of the window whose record is neither in MISP nor saved (WARNING `[REPORT-PENDING] OTX: the report records of N pulse(s) of the window are neither in MISP nor saved on report_pending; the cursor …`), as below a pulse with an item not sent. A pulse of the retry list, read in the window or fetched by id, whose record is neither in MISP nor saved keeps its entry on the retry list unchanged (the ERROR line ends `those of them still on the retry list keep their entries …`, and the pulse counts in `retry_not_pushed`), so the next run fetches it by id and writes its record; a push of these records that raises leaves the list as written after the window's push. A pulse given up beyond `EDGEGUARD_OTX_RETRY_MAX_PULSES` in that run is not protected this way: its record waits until OTX modifies the pulse again. The records of the retry list's pulses and of the pulses fetched for `report_pending` are still pushed after a failed save; the entries of the latter stay as last saved.
- **Logs and status.** `push_reports` logs a `[REPORTS] alienvault_otx: …` line per batch, and the run one `[REPORTS] OTX: N pulse record(s) this run: … added, … updated, … unchanged, … deleted in MISP, … failed, … not tried; … record(s) on report_pending after the run, … given up` line; after a run in which a save of `report_pending` failed (the save after a batch of records, or the one after the fetches by id), that part reads `… record(s) on report_pending as last saved (the list could not be saved)`, with the count read back from the state file (`unknown` when it cannot be read). The status carries `report_counts`: `records`, `reports_added`, `reports_updated`, `reports_unchanged`, `reports_deleted_in_misp`, `reports_failed` (records that could not be built included), `reports_foreign`, `reports_skipped`, `report_tag_drift`, `pending` (the records on the list after the run; after a failed save, the list as last saved, `null` when it cannot be read), `given_up`, `pending_saved` (false when a save of the list failed in the run), `pending_fetched`, `pending_not_found` and `pending_fetch_failed`. Records do not change the run's status, which follows its items.

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
# → one, "APT28, GRU" → one; no name the canonical threat-actor reference lists as no
# actor ("ClickFix"); a name the pulse also lists as a malware family only when the
# canonical threat-actor reference knows it)
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
- CVE IDs and descriptions (NVD's whole text, up to the 4,096 characters the CVE record format allows; the MISP → Neo4j sync writes at most 1,000 characters of a CVE's description to the graph, markup stripped and cut at a sentence or word end, while MISP keeps the whole text: [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#descriptions-and-their-source))
- Every CVSS version NVD supplies (v4.0, v3.1, v3.0, v2), each with full component data
- `cvss_score` / `severity`: the record's first CVSS in the order v3.1 → v3.0 → v2 → v4.0 (`src/cvss_selection.py`); `None` / `UNKNOWN` when the record has none — rejected CVEs, CVEs awaiting NVD analysis without a CNA score. The CVSS 2 rating is read from the metric object, where NVD API 2.0 puts it.
- Affected products (CPE matching)
- `attack_vector`: NVD's word (`NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL`) for the attack vector of the CVSS that gives the score; `None` without CVSS. `result_impacts` come from the scoring CVSS when it is 3.x (none from CVSS 2 or 4.0).
- CWE identifiers
- Reference URLs and tags (advisory/patch links)
- **CISA KEV fields** — `cisa_exploit_add`, `cisa_action_due`, `cisa_required_action`, `cisa_vulnerability_name` (strongest signal of active exploitation; auto-boosts confidence to 0.9)
- Source facts MISP holds in `NVD_META` and the sync does not read yet ([MISP_SOURCES.md](MISP_SOURCES.md#nvd_meta-cve-records)):
  - `nvd_vuln_status`: NVD's analysis state as NVD writes it (`Analyzed`, `Awaiting Analysis`, `Deferred`, `Modified`, `Rejected` ...); `status` keeps ResilMesh's `["active"]` / `["rejected"]`;
  - `references`: every reference, each URL once with the tags of every source that listed it (`Exploit`, `Patch`, `Vendor Advisory` ...); a URL longer than 2,048 characters is left out, never cut. `reference_urls` keeps the first 10 URLs in NVD's order;
  - `affected`: the vendor / product pairs of the CNA's own `affected` container (the entry whose `source` is the record's `sourceIdentifier`; an ADP container such as CISA-ADP's is left out), at most 20, each once; `n/a`, `Unknown`, `*` and `-` count as no name, a pair keeps the name it has and is left out with none; an entry that names its product only by its package (`collectionURL` + `packageName`, e.g. a PyPI or git package) keeps the package name as `product`;
  - `cvss_scorers`: for each CVSS payload, who scored the metric it was read from (`scored_by`: `nvd@nist.gov`, a CNA's address or UUID) and its `score_type` (NVD's `Primary` / `Secondary` label as given; `Primary` is usually NVD's own metric, but a CNA's metric can be `Primary` and NVD's own `Secondary`, so `scored_by`, not `score_type`, names the scorer). The payload is still the first metric NVD lists for its version, which is the CNA's on most recent records;
  - `cwe_names` (`"CWE-89: <name>"`) and `cwe_names_version`: the names of the record's CWE ids from the pinned MITRE CWE list ([§ CWE names](#cwe-names)); an id the list does not hold (`NVD-CWE-noinfo`, `NVD-CWE-Other`) has none.

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

  Edits pause `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` (default 5 s) after every 50, as `push_items` pauses between batches: the 5,000 writes a run may make wait about 8 minutes in all. The edit counts only when MISP's answer shows the new comment and tags. MISP 2.5 then moves the attribute's and the event's timestamps. The incremental MISP → Neo4j sync (changed attributes only, `EDGEGUARD_SYNC_ATTRIBUTE_FILTER`) reads the event again and writes the changed attributes. For an NVD record read from MISP (`nvd_record`), the sync then updates the `CVE` node as `merge_cve` writes it (the sync writes CVEs in batches, `merge_cves_batch`), as follows:
  - **Description, `published`, `last_modified` and `status`** are taken from the record; the four KEV fields (`cisa_exploit_add`, `cisa_action_due`, `cisa_required_action`, `cisa_vulnerability_name`) only where the node has none, since the KEV record owns them ([§ 3](#revisions-every-run-compares-the-catalogue-with-misp)). The dates come from NVD's record alone: a KEV, CISA ICS or OTX record or a partner write fills them only where the node has none. The description follows the source ranking NVD > CISA KEV > CISA ICS > any other source, with `description_source`, so NVD's text replaces theirs and theirs never replaces NVD's, whatever the order of the events in the sync. `status` becomes `["rejected"]` once NVD rejects the CVE.
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
  - The MISP listing reads every `source:NVD` attribute, 28 pages of 5,000 (about 0.5 GB) for the 730-day baseline. An edit makes the next incremental sync read the event part that holds the CVE (a baseline's NVD parts hold at most 20,000 attributes each, `EDGEGUARD_MISP_EVENT_SPLIT_ABOVE`), but it writes only the changed ones.
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
    'nvd_vuln_status': 'Analyzed',
    'references': [{'url': 'https://vendor.example.com/advisory/2024-001', 'tags': ['Vendor Advisory', 'Patch']}],
    'affected': [{'vendor': 'Hospital Mgmt', 'product': 'System'}],
    'cvss_scorers': {'cvss_v31_data': {'scored_by': 'nvd@nist.gov', 'score_type': 'Primary'}},
    'cwe_names': ['CWE-89: Improper Neutralization of Special Elements used in an SQL Command'],
    'cwe_names_version': '5.0',
}
```

### CWE names

NVD and CISA KEV name a CVE's weaknesses by id only. The NVD and KEV collectors add the names of a record's CWE ids from `src/reference/cwe_names.json` (`src/cwe_names.py`), so MISP holds them with the record and no request is made at collection time. The list holds every weakness and grouping of MITRE's CWE list (version 5.0 of 2026-10-28, 1,415 names, deprecated and obsolete entries included; views are left out), with MITRE's copyright designation and the CWE licence ([DATA_SOURCES.md](DATA_SOURCES.md#9b-mitre-cwe-list-reference-data)). `scripts/build_cwe_names.py` builds it from `cwec_latest.xml.zip`; it changes only before a fresh baseline, since names written at collection time would otherwise come from two CWE versions ([RUNBOOK.md](RUNBOOK.md#rebuilding-the-cwe-name-list)). A list that cannot be read gives no names, with a warning; the run goes on.

---

## 3. CISA Collector

**File:** `src/collectors/cisa_collector.py`

### What It Does
Collects Known Exploited Vulnerabilities (KEV) from CISA, including:
- CVE IDs with exploitation confirmation
- Vendor and product information (`vendorProject` and `product`, whole in `NVD_META`: `vendor`, `product`)
- Required actions and due dates
- Known ransomware campaign use (`known_ransomware_use`; no score is derived from it)
- CISA's short description whole (up to 821 characters on 2026-11-06), its `notes` whole (`cisa_notes`: vendor advisory and patch URLs separated by `;`, some labelled, such as `BOD 26-04: <url>`), its CWE ids (`cisa_cwes`), whether BOD 26-04 requires forensic triage (`cisa_forensic_triage`, `Yes` / `No`) and the names of the CWE ids (`cwe_names`, [§ CWE names](#cwe-names)), in `NVD_META`; the sync does not read the last four yet

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
    'known_ransomware_use': 'Known',
    'cisa_cwes': ['CWE-78'],
    'cisa_notes': 'https://vendor.example.com/advisory ; https://nvd.nist.gov/vuln/detail/CVE-2023-1234',
    'cisa_forensic_triage': 'No',
    'cwe_names': ['CWE-78: Improper Neutralization of Special Elements used in an OS Command'],
    'cwe_names_version': '5.0',
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
  - `NVD_META` by digest: `shortDescription`, `vendorProject`, `product`, `dateAdded`, `dueDate`, `requiredAction`, `vulnerabilityName`, `knownRansomwareCampaignUse`, `notes`, `cwes` (with their names) and `forensicTriage`; empty values count as absent;
  - tags by family: `severity:` and `cvss:` are replaced and, for KEV, the tag `ransomware:known`, the only ransomware tag EdgeGuard writes (`KEV_REPLACED_TAGS`), so an entry CISA reverts to Unknown loses it; any other `ransomware:` tag (a machine tag of MISP's `ransomware` taxonomy an analyst attached) is left alone and plans no edit; zone, `CISA-KEV` and source tags are only added; `tlp:` only when the copy has none.
- **Additions.** A CVE MISP lacks is added through `push_items`, given the listing (`known_source_keys`), so MISP is not listed twice. Additions MISP's answers do not confirm are looked up by value (`MISPWriter.existing_values`), as in the NVD incremental run.
- **Edits.** A copy that differs is edited in place (`MISPWriter.update_attribute`, `POST /attributes/edit/{uuid}`): the new `NVD_META` comment, `first_seen` and the tag changes. An edit counts only when MISP's answer shows it and an attribute timestamp later than the stored copy's, because the incremental sync re-reads an attribute only when that timestamp moves. The edits follow the stop rules of the indicator refresh: a pause of `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` (default 5 s) and the parent-DAG liveness check after every 50 edits; no edit starts once `EDGEGUARD_MISP_REFRESH_MAX_SECONDS` (default 600) is spent, nor after 5 failed edits in a row.
- **Cap.** At most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN` edits per run (default 500): the CVE whose edits would pass it and the CVEs after it are deferred. A deferred edit is no failure: the comparison is stateless, so the next run plans it again. Additions are not capped. A run's explicit limit cuts the additions and lowers the edit cap. `EDGEGUARD_KEV_UPDATE_EXISTING=false` adds new entries only and leaves stored copies as they are.
- **Removals.** A CVE MISP holds in an EdgeGuard event that the catalogue no longer lists is counted (`stored_not_in_catalogue`) and logged at WARNING with the first 20 ids; its MISP copy and the node's KEV fields stay.
- **Status.** The additions plus the attempted edits are the run's items in `status_after_misp_push`, so a failed edit fails the run like a failed addition (`EDGEGUARD_MISP_MIN_SUCCESS_RATE`). `kev_update` in the status holds `catalogue`, `catalogue_version`, `scope`, `added`, `updated`, `unchanged`, `stored_not_updated`, `foreign_only`, `deferred`, `failed`, `not_written` (up to 100 CVE ids), `changed_keys` (the `NVD_META` keys of each planned edit, up to 100 CVEs), `stored_not_in_catalogue`, `stored_not_in_catalogue_ids` and `stop_reasons`.
- **Logs.** One line per edit, `[KEV-UPDATE] CVE-2026-63077 attribute <uuid> event <id>: known_ransomware_use; tags +ransomware:known` (INFO; a WARNING `… MISP did not confirm the edit (planned: …)` when MISP's answer does not show it), and one summary line per run, for example `CISA KEV: catalogue 2026.10.16 (2026-10-16T17:15:48.8752Z) of 1748 entries, 1748 in scope; 9 added, 2 updated, 1737 unchanged, 0 stored and not updated, 0 only in other events, 0 deferred, 0 failed; 0 stored and no longer in the catalogue`.
- **Graph.** The incremental MISP → Neo4j sync re-reads the edited attribute through the normal path. On the `CVE` node a KEV record sets `cisa_exploit_add`, `cisa_action_due`, `cisa_required_action`, `cisa_vulnerability_name` and `known_ransomware_use`; NVD's record only fills the first four where the node has none, in either order of the sync (NVD did not move `lastModified` when CISA moved the due date of CVE-2022-0995, so NVD's MISP copy kept the old date). The `SOURCED_FROM` edge's `raw_data` holds the latest KEV record. The description follows the source ranking NVD > CISA KEV > CISA ICS, so a revised KEV text shows on the node only where NVD gave none ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md)).
- **Volume.** Per run: one catalogue download and one listing page; about 5 edits a month in steady state (measured from the snapshots of 2026-05-22, 2026-09-16 and 2026-10-08 against the feed of 2026-10-16) and 1 to 5 additions a day. Each edit makes the next incremental sync download the KEV event that holds the copy (the baseline event holds about 1,750 attributes); only the edited attributes are merged.

**Limits.**
- Removals never propagate: an entry dropped from the catalogue keeps its MISP copy and its node fields (counted and logged only).
- KEV `notes`, `cwes` and `forensicTriage` (BOD 26-04) reach MISP, but the sync does not set them on the `CVE` node yet, so the GraphQL fields `cisaNotes` and `cisaCwes` stay empty.
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
- **Descriptions:** ATT&CK's whole description of each group, malware, tool, technique and tactic, with its markup. MISPWriter writes it whole on the line after the comment's `MITRE_USES_TECHNIQUES` / `MITRE_TACTIC_PHASES` block where there is one, else as the whole comment (a tactic, a technique without tactic phases, a tool without techniques, a group or malware with nothing for the block): control characters removed and the surrounding whitespace stripped, up to `ENTITY_DESCRIPTION_MAX_CHARS` (8,000 characters; ATT&CK's longest, T1553.003 in Enterprise ATT&CK 20.1, has 4,668). A longer text would be cut at its last whitespace within the bound, with an `[ENTITY-TEXT]` warning giving the lengths. MISP therefore holds ATT&CK's text; the MISP → Neo4j sync writes at most 500 characters of it to the node, without ATT&CK's markdown links (the name stays), `(Citation: …)` markers, `<code>` tags, markdown bold `**` and the tags `<b>`, `<strong>`, `<i>` and `<em>` outside backtick code spans (code spans and bullet lists stay), cut at a sentence or word end (a cut inside a bulleted list keeps no line that holds only a list marker) ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#descriptions-and-their-source)). A technique's zones are detected in the first 500 characters of its description; read whole, 3 Enterprise and 20 ICS techniques of ATT&CK 20.1 would gain a sector from a keyword further on. `x_mitre_detection` (deprecated in ATT&CK) is read as its first 1,000 characters and not written to MISP. MITRE's record ranks first for a `Malware`, `ThreatActor`, `Tool`, `Technique` or `Tactic` node's description (MITRE ATT&CK > a curated source > any other source, with `description_source`), so ATT&CK's text stays whatever the order of the merges.

### Source
- **URL:** `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- **ATT&CK for ICS (`EDGEGUARD_ENABLE_MITRE_ICS=true`, default off):** `ics-attack/ics-attack.json` from the same repository (`MITRE_ICS_ATTACK_URL` to override) is fetched after the Enterprise bundle and parsed with the same code (`_parse_bundle`, kill-chain name `mitre-ics-attack`). ATT&CK for ICS 20.1: 118 techniques (T08xx, 14 of them deprecated), 12 tactics (TA0100–TA0111, 9 short names identical to Enterprise), 14 groups, 26 malware (1 deprecated). Every item carries `attack_domain` (`enterprise` | `ics`); groups/malware present in both bundles are emitted once with `uses_techniques` unioned. An ICS fetch/parse failure is logged, counted (`pipeline_errors_total{task=collect_mitre_ics}`) and never affects the Enterprise items; the MITRE circuit breaker is not tripped. No ETag for ICS: on an Enterprise HTTP 304 the ICS bundle is skipped (baseline runs ignore ETag). ICS items are zoned by keyword detection on their descriptions only, so they are **not** zoned `energy` automatically: `x_mitre_sectors` and `x-mitre-asset` are not read (planned: [ROADMAP.md § Collection depth and scale](ROADMAP.md#collection-depth-and-scale)).
- **API Key:** Not required
- **Format:** STIX 2.1 bundle
- **Licence:** ATT&CK's terms of use. MITRE's terms and notice for the ATT&CK text EdgeGuard copies (MISP comments, node descriptions, the APIs and the STIX export) are given in [DATA_SOURCES.md § 5](DATA_SOURCES.md#5-mitre-attck); the copies themselves do not carry the notice.

### Revoked and deprecated objects

The ATT&CK bundles keep replaced and retired objects. `_parse_bundle` (Enterprise and ICS alike):

- **Revoked** (`revoked: true`, with a `revoked-by` relationship to the successor): skipped, whatever the type. No item, no relationship to or from it (`uses`, `subtechnique-of`, `attributed-to`), so no `uses_techniques` / `uses_malware` / `uses_tools` entry names it. A revoked group's or software's name and aliases are appended to its successor's `aliases` (the successor's own aliases first; a chain A → B → C ends on C): `UNC2452` → `APT29`, `Dragonfly 2.0` → `Dragonfly`, `Stolen Pencil` → `Kimsuky`, `Darkmoon` → `PoisonIvy`. Tool items carry `aliases` too (`x_mitre_aliases`), and the MISP writer tags them as it tags those of actors and malware (see "MISP tags" below); the sync does not read a tool's alias tags yet, so they do not reach the graph.
- **Deprecated** (`x_mitre_deprecated: true`, no successor): kept, with `deprecated: True`; every other item carries `deprecated: False`. The MISP writer tags a deprecated item `attack-status:deprecated`; the sync turns the tag into `n.deprecated = true`, and an ATT&CK record without the tag sets `n.deprecated = false`.
- **One item per node** (`_one_item_per_node_key`, per bundle and again when the ICS bundle is merged): groups and malware whose names are equal once lower-cased (the `ThreatActor` / `Malware` node key) become one item, and tools of one ATT&CK id (the `Tool` node key). An active object wins over a deprecated one: the active ICS `Triton` (S1009) replaces the deprecated Enterprise `TRITON` (S0609), and the deprecated ICS copies whose only ATT&CK id is an ATT&CK for ICS one (`Killdisk` S1005, `Stuxnet` S1008, `EKANS` S0017, which is the id of the Enterprise `BISCUIT`, `Industroyer` S1004, `Bad Rabbit` S1001, `Conficker` S1003) are left out beside the active objects of their names; these copies carry no relationships. Of several active items (the same STIX object in both bundles) the first is kept, Enterprise first, with their `uses_techniques`, `uses_malware` and `uses_tools` united. `[ATTACK-SAME-NAME] <label>: N deprecated object(s) left out, an active one has the same name: …` names each object left out, and a warning names one left out with a technique or software link the kept item lacks, which is not kept. MISP does not store a value that differs only in case from one an earlier request stored in the event (within one request it stores both), and the deprecated object would mark the node of its name deprecated. When ATT&CK for ICS is on and its bundle fails, the run pushes no deprecated group or malware (an active object of the same name may be in the ICS bundle) and does not store the Enterprise ETag, so the next run reads both bundles again (`[MITRE] ATT&CK for ICS failed: N deprecated group(s) / malware held back …`).
- **Domains and platforms:** group, malware and tool items carry `attack_domains`, the ATT&CK domains of `x_mitre_domains` (`enterprise`, `ics`, `mobile`, in ATT&CK's order; the bundle's domain when the object lists none), and malware and tool items carry `platforms` (`x_mitre_platforms`) as techniques do. Of several active items of one object, the kept one unites their `attack_domains` and `platforms` too.
- **ATT&CK ids:** group and malware items carry their ATT&CK id (`mitre_id`, `G####` / `S####`) like techniques, tactics and tools; the MISP writer carries it in the `aid` key of the `MITRE_USES_TECHNIQUES` block, since their MISP value is the name ([MISP_SOURCES.md](MISP_SOURCES.md)). One helper reads the id of every object (`_attack_external_id`): the `external_id` of its `mitre-attack` reference, else that of its `mitre-ics-attack` reference; no other reference (`capec`, citations) gives an id. Every Enterprise object and every active ICS object has a `mitre-attack` id. 19 deprecated objects of the ICS bundle of ATT&CK 20.1 have only the ICS one: `BlackEnergy 3` (S1002), the only object of its name, is kept and marked deprecated with its id; the other 6 malware are the copies left out above; the 12 techniques (`Control Device Identification` T0808, `Data Historian Compromise` T0810, `Engineering Workstation Compromise` T0818, `I/O Module Discovery` T0824, `Location Identification` T0825, `Modify Control Logic` T0833, `Network Service Scanning` T0841, `Program Organization Units` T0844, `Role Identification` T0850, `Serial Connection Enumeration` T0854, `Detect Program State` T0870, `Change Program State` T0875) are kept and marked deprecated, with their ICS tactics, like any deprecated technique; they have no relationships. A technique, tactic or tool without either id is skipped.
- The log line `skipped N revoked ATT&CK objects {...} and M relationships that reach them` gives the counts per bundle.

Feeds that still name a revoked technique id (OTX pulses citing `T1086`) are translated to the successor downstream, with `src/reference/attack_revoked_ids.json` (`src/attack_revoked.py`; see `docs/KNOWLEDGE_GRAPH.md`, "Revoked and deprecated ATT&CK objects"). Groups and software need no map: the bundle names every successor. A revoked technique the map does not list is therefore kept, with the warning `[ATTACK-REVOKED] N technique(s) the bundle revokes are not in the revoked-id map (…)`, so the links that cite it are not lost; rebuild the map (`docs/RUNBOOK.md`, "Rebuilding the ATT&CK revoked-id map") and the next run skips it.

### MISP values

MISPWriter writes each technique, tactic (Enterprise and ICS) and tool as a MISP `text` attribute whose value is the ATT&CK id, ` - ` and the name (`attack_values.format_attack_value`): `T1059.003 - Windows Command Shell`, `TA0002 - Execution`, `T0807 - Command-Line Interface`, `S0005 - Windows Credential Editor`. A group is a `threat-actor` attribute and a malware a `malware-type` attribute, each valued by its name. The ATT&CK values carry no colon, so MISP's default Import Regexp rules, which rewrite a value where any character, a colon and any character precede "Windows" (`/.:.Windows./i` → `%WINDIR%\`), leave them unchanged ([MISP_SOURCES.md](MISP_SOURCES.md#attribute-types-and-values)). The MISP → Neo4j sync reads the id and the name back with `attack_values.parse_attack_value`, which also reads `<id>: <name>`, and skips a value without a valid ATT&CK id with an `[ATTACK-VALUE]` warning. MISPWriter's dedup (per event and across events) reads a `text` value in either form as the same ATT&CK entry (`attack_values.attack_value_key`), so an entry stored as `<id>: <name>` is not written again as `<id> - <name>`; a value MISP rewrote holds no valid id and counts as a different value. The check that confirms a push compares the exact value.

### MISP tags

Besides the zone, source, TLP and `attack-status:deprecated` tags every ATT&CK attribute carries:

| Tag | On | Value |
|---|---|---|
| `platform:<platform>` | techniques, malware, tools | every platform ATT&CK lists, sent in ATT&CK's casing (`platform:Network Devices`, `platform:Field Controller/RTU/PLC/IED`), de-duplicated case-insensitively; a value over 64 characters is skipped, and at most 32 are written (ATT&CK 20.1 lists at most 10 on one object). MISP may hold it in another casing (below) |
| `attack-domain:<domain>` | every item | techniques and tactics: the domain of their bundle; groups, malware and tools: one tag per domain of `attack_domains` |
| `alias:<name>` | groups, malware, tools | the item's aliases, at most 20, each up to 100 characters |
| `misp-galaxy:mitre-attack-pattern="<name> - <id>"` | techniques | ATT&CK's own MISP galaxy cluster, plus `mitre-attack:technique="<id>"` |
| `misp-galaxy:mitre-intrusion-set="<name> - G####"`; `misp-galaxy:mitre-software="<name> - S####"`, or `misp-galaxy:mitre-malware="<name> - S####"` / `misp-galaxy:mitre-tool="<name> - S####"` | groups, malware, tools with an ATT&CK id | ATT&CK's own MISP galaxy cluster, beside the community cluster tag (`misp-galaxy:threat-actor`, `misp-galaxy:malware`, `misp-galaxy:tool`); MISP attaches the cluster (ATT&CK's card, with its references) to the attribute. Malware and tools take `mitre-software` when the MISP has that galaxy enabled, else `mitre-malware` / `mitre-tool` (below). ATT&CK publishes no galaxy of tactics |
| `mitre-tactic:<shortname>`, `tool-type:<type>`, `malware-type:<type>`, `malware-family:<family>` | tactics, tools, malware | the tactic's short name; the types ATT&CK gives (`tool`, `malware`); a family other than the name |

**The software galaxy.** The MISP galaxy repository merged `mitre-malware`, `mitre-tool` and the ICS software into one galaxy, `mitre-software`, on 2026-08-30, marked the old ones deprecated and updates only the merged one since. Its clusters keep the value (`"<name> - S####"`) and the uuid of every cluster of the two it replaces and add the ICS software (`BlackEnergy 3 - S1002`, `Triton - S1009`) and the software ATT&CK added later (`Vidar - S9050`), which the old galaxies never get. MISPWriter reads MISP's galaxy list (`GET /galaxies/index`) once per writer, the first time a push holds a malware or tool item with an ATT&CK id, and logs `[ATTACK-GALAXY]` with the galaxy it uses: `mitre-software` when the list holds it enabled, else `mitre-malware` / `mitre-tool`; a failed read (no answer, an HTTP status other than 200, a body that is not JSON) keeps the old galaxies for that run, with a warning. A push without ATT&CK software sends no such request. A stored attribute keeps the tag it was written with (the writer does not rewrite the tags of a value MISP holds), so a MISP that held ATT&CK software before shows the new tag on new attributes only, until its events are wiped. A tag without a cluster stays a plain tag; the galaxies of a MISP are updated by its administrator (*Update Galaxies* on MISP's galaxy list).

On the project's test MISP (2.5.50, galaxies loaded 2026-10-31: `mitre-software` cluster version 2, `mitre-malware` 42, `mitre-tool` 40, `mitre-attack-pattern` and `mitre-intrusion-set` one release behind) the galaxy tags of ATT&CK 20.1 match a cluster for 187 of 189 groups (Enterprise and ICS) and 818 of 836 techniques (the 12 deprecated ICS techniques read by their ICS id among them, all with a cluster). Of the 849 software tags (754 malware, 95 tools), 825 match with `mitre-malware` / `mitre-tool` and 832 with `mitre-software` (`ACAD/Medre.A`, `FrostyGoop`, `Fuxnet`, `INCONTROLLER`, `PLC-Blaster`, `Triton` and `BlackEnergy 3` have a cluster only there); all 849 are values of the current release (`mitre-software` cluster version 3, 2026-10-14), so the remaining 17 (S9045–S9067) match after a galaxy update. MISP resolves a tag name without regard to case and keeps the casing of a tag it already holds, so on a MISP that already holds a `platform:` tag in another casing (`platform:windows`, `platform:network devices`) the attribute comes back with that tag, and an `alias:` tag likewise keeps the casing MISP first stored. A tag row outlives the events that used it (an event wipe leaves MISP's tag list as it is), so a MISP that held the lower-cased platform tags of earlier writes keeps returning them: on the project's test MISP, 3,129 of the 3,148 platform tags of the 2026-11-08 baseline came back in lower case (13 existing tag rows) and the other 19, on 7 platform names new to that MISP, in ATT&CK's casing. The values equal ATT&CK's without regard to case, and the graph never stores MISP's casing (the sync keeps a technique's platforms in ATT&CK's spelling). Renaming the tag rows is an action of the MISP administrator; EdgeGuard does not write to MISP's tag list. The MISP → Neo4j sync reads the platform tags of a technique (`platforms` on the record) in ATT&CK's spelling whatever casing MISP returns: `canonical_attack_platforms` (`src/attack_platforms.py`) maps each value, without regard to case, to the platform names of Enterprise and ICS ATT&CK 20.1 (a value it does not know is kept as written) and drops repeats. It reads the domain tag of a technique or tactic; it takes no node, label or link from the domain, alias, platform or ATT&CK galaxy tags of a group, malware or tool.

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
    'platforms': ['Windows', 'macOS', 'Linux'],  # every platform, in ATT&CK's casing
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
    'attack_domains': ['enterprise'],  # x_mitre_domains (Sandworm Team, G0034: ['enterprise', 'ics', 'mobile'])
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
    'aliases': ['Mimikatz'],
    'attack_domains': ['enterprise'],
    'platforms': ['Windows'],
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
- The blacklist (`GET /blacklist`, `confidenceMinimum` 90): for each address, the abuse confidence score (`confidence_score` = score / 100), the country code and `lastReportedAt` (the last-seen time the source reports; the endpoint gives no first-seen date). MISP receives the address, `last_seen`, the tags and a `TF_META` comment with `abuse_confidence_score` (AbuseIPDB's 0-100 score, an integer), `ip_country_code` (the country AbuseIPDB gives for the address: where the address is, never a country the activity targets, so it never feeds `targeted_countries`) and `as_of` (the collection time: the score changes at the source, and MISP keeps the first report's value, see [Re-reported indicators](#re-reported-indicators)). A field the answer does not carry is left out: an entry without a score gets no score and the writer's default confidence (`confidence:medium`), and the blacklist answer has no report or reporter counts, so the item carries none. Reverse DNS, hostnames, ISP, usage type, the Tor and whitelist flags, report counts and reports come only from the `check` endpoint (`check_ip`, `enrich_ip`), which no DAG task calls; a count it does not return is `None`, never 0.

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

VirusTotal deliberately sends no `malware_family` and no `reference`: both are single-valued on the node and the last writer wins, so a corroborating source would overwrite the family reported by ThreatFox or MalwareBazaar. For the same reason a lookup creates no `INDICATES` edge by itself. The label and rule names travel in the shared feed-metadata comment (`TF_META`), written only when VirusTotal returns them, and so do the facts of the file and the counts of the last analysis: `threat_category` (the first `popular_threat_category`), `meaningful_name`, `file_type` (`type_description`), `file_size`, `file_md5`, `file_sha1`, `detection_malicious` and `detection_total` (the engines that gave a verdict: malicious, suspicious, harmless, undetected). A field VirusTotal does not return is left out (the file type is never set to `unknown`, a missing size is never set to 0 while a size of 0 that VirusTotal reports for an empty file is kept, and partial analysis stats give no counts). The counts change at VirusTotal after the lookup; they are the values of the analysis at the time of the lookup, recorded with `as_of`. MISP keeps them (the sync does not read them); sandbox verdicts are not carried.

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
    'file_md5': '...', 'file_sha1': '...', 'sha256': '...',
    'file_type': 'Win32 EXE', 'file_size': 123456, 'meaningful_name': 'invoice.exe',
    'detection_malicious': 52, 'detection_total': 70,
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
- **Feodo Tracker:** botnet C&C server IPs (QakBot, Emotet, TrickBot, Dridex, BumbleBee, Pikabot) with the malware families, ports and online/offline status
- **SSL Blacklist:** SHA-1 fingerprints of malicious TLS certificates with the listing reason (kept verbatim, with its role and family part apart), stored as `x509-fingerprint-sha1` indicators (see below)

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
zones = detect_zones_from_text(reason.lower())
```

The keyword detector deliberately contains no malware family names (families are linked to sectors through graph relationships), so in practice both feeds are tagged `zone:Global`: measured on 2026-10-12, all 7,980 Feodo rows (7,607 servers) and all 10,964 SSL Blacklist rows. Neither feed is hard-coded to Finance.

### Feodo Tracker: what is loaded and what reaches the graph
- **The feed is a historical snapshot at present.** Both downloads carry the header `# Last updated: 2026-03-04 14:28:39 UTC` (checked 2026-10-12): abuse.ch has not updated Feodo Tracker for seven months. A baseline loads the history once; the daily task then finds nothing new until the feed moves again. The collector logs a warning when the header is older than 7 days.
- **Parsing.** CSV with every field quoted and CRLF line endings, read with the `csv` module; the header row is recognised by name.
- **One record per address.** The feed has one row per address and port, and a re-used address appears again under another family: 7,980 rows describe 7,607 addresses (290 addresses on several rows, 81 with more than one family). MISP holds one attribute per value, so rows are merged per address: earliest `first_seen`, latest `last_online`, every port, every family. The primary family is that of the most recently active row. The attribute's `TF_META` comment carries every port as `ports` (integers, ascending), every family as `families` (the primary first) and the most recent row's `c2_status`, with `as_of` (the time it was read: `c2_status` and `last_online` are first-report values, see [Re-reported indicators](#re-reported-indicators)); the same facts are also kept as the labels `c2_status:…`, `port:…`, `family:…` in `tags`. The merge covers the rows of one run: a port or family the list adds for an address MISP already holds does not reach its stored comment ([Re-reported indicators](#re-reported-indicators)).
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
| `(Indicator)-[:INDICATES]->(Malware)` | built by `build_relationships` to the Malware nodes whose name or alias equals `malware_family` (case-insensitive) or, when none matches, to the one node whose name equals it without whitespace, hyphens, underscores and dots, or of several such nodes to the ATT&CK node when every other is OTX-only ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Feed family labels"); QakBot, Emotet, TrickBot, Dridex, BumbleBee and Pikabot all match MITRE ATT&CK software | family match |

The source's dates matter for campaigns: for an indicator without a last-seen time, a Campaign's `last_seen` takes the edge's first-seen claim (`first_seen_utc`), and the time MISP recorded the row only for a row without a date ([TIMESTAMPS.md](TIMESTAMPS.md#seen-dates-of-an-indicator-campaigns-alert-enrichment)); with the record time, a botnet that stopped in 2021 would look active on the day it was collected.

### SSL Blacklist: what reaches the graph
Each row is the SHA-1 fingerprint of a TLS certificate seen on malware infrastructure, not a file hash. It is collected as `indicator_type: "x509-fingerprint-sha1"`, pushed to MISP under MISP's own attribute type `x509-fingerprint-sha1` (default category *Network activity*) and synced as an `x509-fingerprint-sha1` Indicator; the STIX export pattern is `[x509-certificate:hashes.'SHA-1' = '…']`.

| Graph element | Value | From |
|---|---|---|
| `Indicator {indicator_type: "x509-fingerprint-sha1", value}` | the fingerprint, 40 lower-case hexadecimal characters | `SHA1` |
| `reference` | the certificate's SSL Blacklist page, `https://sslbl.abuse.ch/ssl-certificates/sha1/<sha1>/` (the link form of the site's own certificate list; the page can show no entry for a recent listing) | built from the fingerprint |
| `zone` | keyword detector on the listing reason (`global` in practice) | `Listingreason` |
| `(Indicator)-[:SOURCED_FROM]->(Source {source_id: "ssl_blacklist"})` | `source_reported_first_at` = the listing date | `Listingdate` |

In MISP the attribute carries a `TF_META` comment with the certificate page as `reference` and the listing reason three ways:
- `listing_reason`: the reason as the list gives it (`Vidar C&C`, `Malware C&C`, `NetSupport RAT malware distribution`, `Vawtrak MITM`, `doxbin.cy`);
- `threat_type`: the role, in ThreatFox's vocabulary: `botnet_cc` for `<family> C&C`, `payload_delivery` for `<family> malware distribution`; none for `<family> MITM` and for a reason without a role suffix;
- `listing_family`: the family part of a reason with a role suffix, in the list's spelling. A family part that is a category word (`Malware C&C`, `Malware distribution`, `Ransomware C&C`) gives none, by the rule that keeps such words out of Malware node names (`node_identity.is_placeholder_name`); so does a word the list uses for a kind of server (`Spambot C&C`, `Steal C&C`, `Downloder-Bot C&C`, `hVNC C&C`, one listing each on 2026-11-07; `Stealc C&C` keeps `Stealc`), and a reason without a role suffix (`QuasarRAT`, `Sinkhole`, `FIN7`, `doxbin.cy`) gives none, because it does not say whether it names a family. A listing family is the list's own label: it may name a malware family, an actor (`TA505 C&C`, `Sofacy C&C`), a legitimate product (`ConnectWise C&C`) or a traffic-distribution cluster (`KongTuke C&C`).

The family is never written as `malware_family`, so the sync does not link it as a feed family label: `listing_family` is kept in MISP only, and no graph link is made from it. Of the 11,164 listings of 2026-11-07, 405 were `Malware C&C`, 22 `Malware distribution` and 25 `Ransomware C&C`; 265 distinct reasons, the longest 35 characters.

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
    'tags': ['c2_status:offline', 'port:447', 'port:449', 'family:TrickBot', 'family:Dridex'],
    'ports': [447, 449],                   # → TF_META.ports
    'families': ['TrickBot', 'Dridex'],    # → TF_META.families (primary first)
    'c2_status': 'offline'                 # → TF_META.c2_status (with TF_META.as_of)
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
    'listing_reason': 'Dridex C&C',               # verbatim
    'threat_type': 'botnet_cc',                   # the role
    'listing_family': 'Dridex',                   # the family part (none for "Malware C&C")
    'reference': 'https://sslbl.abuse.ch/ssl-certificates/sha1/a1b2c3d4e5f6.../'
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
- **URLhaus** requires the same key, the abuse.ch Auth-Key (as does MalwareBazaar, [§ 13](#13-malwarebazaar-collector)); `python src/source_key_check.py` and `edgeguard preflight` report it for all three sources.

### Sources
- **ThreatFox:** `https://threatfox-api.abuse.ch/api/v1/`
- **URLhaus:** `https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv` (about 16 MB and about 63,000 URLs on 2026-10-24, regenerated every 5 minutes), the only URL the collector reads, so the task fails when it cannot be read. The abuse.ch Auth-Key (`THREATFOX_API_KEY`) is part of the path and is redacted from every log line and error, the DEBUG records of the HTTP library included; without a key the task is skipped (`missing_abusech_key`), and HTTP 401/403 skips it (`urlhaus_auth_denied`)

### Per-run caps

Neither feed has a cursor: each run reads a window, ThreatFox `get_iocs` the IOCs of the last 7 days (7,398 on the 730-day baseline of 2026-10-13; about 1,050–1,140 new per day) and URLhaus its `recent.csv` export, the URLs added in the past 30 days (about 63,000 on 2026-10-24, about 2,100 a day on average). Each source has its own cap, sized to the whole window with headroom so that no day's entries leave the window uncollected, and the generic incremental default does not apply (`threatfox` and `urlhaus` are in `config.OWN_RUN_CAP_SOURCES`, like MalwareBazaar and NVD):

| Variable | Default | Effect |
|----------|---------|--------|
| `EDGEGUARD_THREATFOX_MAX_PER_RUN` | `10000` | IOC records collected per run, baseline and daily (before the records of one value are merged, below). A run whose window lists more keeps the newest by `first_seen` and logs a warning naming how many older IOCs it left out |
| `EDGEGUARD_URLHAUS_MAX_PER_RUN` | `100000` | URLs collected per run from `recent.csv`, baseline and daily. A run whose file lists more keeps the newest by `dateadded` and logs a warning |

The feeds' own order does not matter: a run that reaches its cap sorts by the date field first. `EDGEGUARD_MAX_ENTRIES` and an explicit baseline limit still apply when lower; `0` removes the cap. Entries MISP already holds for the source are not pushed again (cross-event duplicate prefetch), so a daily run that re-reads the window writes only the new entries (and refreshes the stored copies MISP last wrote more than `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS` ago, see [Re-reported indicators](#re-reported-indicators)). Both variables are forwarded into the containers by `docker-compose.yml` (`x-common-env`) with the code defaults.

### ThreatFox: one item per value

`get_iocs` lists one record per IOC report, and an `ip:port` IOC carries its port in the value. MISP `ip-dst` takes no port, so the port is stripped, and MISP holds one attribute per value: two records `IP:443` and `IP:8080`, or a value reported twice for two families, are one attribute. The collector therefore merges the records of a value into one item (`threatfox_merge_iocs`), as Feodo Tracker merges its rows per address:

- the scalar keys (`malware_family`, `threat_type`, `threat_type_desc`, `ioc_id`, `malware_alias`, `malware_malpedia`, `reporter`, `reference`) are the primary record's, the most recent one (`first_seen`, then the higher id); `reference` and `reporter` fall back to the most recent other record that has one, `malware_malpedia` only to a record of the primary record's family (the Malpedia page names the family);
- `first_seen` is the earliest and `last_seen` the latest of the records;
- the lists hold every record's value once: `ports` (integers, ascending, from `ip:port` IOCs), `ioc_ids` (ascending), `families` (`malware_printable`) and `threat_types` with the primary record's value first, and `tags`;
- `confidence_level` is the highest ThreatFox `confidence_level` (0-100, an integer) of the records, and `confidence_score` that value / 100. A record without a level adds none; a value whose records state none gets no `confidence_level` and a `confidence_score` of 0.5.

The merge covers the records of one run. The attribute keeps what the run that first wrote the value merged: every `TF_META` key (the primary record's keys, the lists, `tags` and `confidence_level`) and the attribute's tags and confidence. A record a later run reads for a value MISP already holds (a new port, id, family or threat type) is not pushed again (the cross-event duplicate check above), and the refresh of a re-reported indicator changes only `last_seen` ([Re-reported indicators](#re-reported-indicators)).

Every key of the item reaches MISP in the `TF_META` comment when the value is first written. Three confidence fields are kept apart: `TF_META.confidence_level` is ThreatFox's own 0-100 scale; the edge's `confidence` is EdgeGuard's bucket of the attribute's `confidence:*` tag (0.8 / 0.5 / 0.3); the node's `source_confidence` is the highest of its sources' values (0-1). The Malpedia family id needs no key of its own: it is the last path segment of `malware_malpedia`.

### Zone Detection

```python
def get_zones_from_malware(malware_name):
    """Determine ALL zones based on malware family name."""
    return detect_zones_from_text(malware_name or "")

# ThreatFox uses the families of the value's records
zones = get_zones_from_malware(" ".join(families))

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
    'ioc_id': '12345',                        # the primary record
    'ioc_ids': ['12340', '12345'],            # every record of the value
    'families': ['emotet'],
    'threat_types': ['botnet_cc'],
    'confidence_level': 75,                   # ThreatFox's 0-100 level (the highest of the records)
    # 'ports': [443, 8080] for an ip:port value
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
No healthcare-specific feed is collected: Health-ISAC (H-ISAC) requires a membership that is not budgeted, and HC3, a public source of the US Department of Health and Human Services, is not collected. The `healthcare` sector comes from keyword detection in every collector, from the industries an OTX pulse names and from the sectors CISA names in its ICS advisories (collected by default). No DAG task calls this module.

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
No energy member-only feed collector is planned: EE-ISAC (European Energy ISAC) membership is not budgeted. CISA ICS-CERT energy sector advisories are collected by the CISA ICS Advisories collector (`cisa_ics`, on by default); MITRE ATT&CK for ICS is available through the MITRE collector flag. No DAG task calls this module.

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
Pulls data from the local MISP instance (no DAG or `run_pipeline.py` runs it), including:
- Indicators (all types)
- Vulnerabilities (CVEs)
- Malware families
- Threat actors
- MITRE techniques
- Relationships

**Note:** **Production Airflow** does **not** use this module for graph fill. Scheduled **MISP → Neo4j** is **`run_misp_to_neo4j`**: **attribute parse** → **per-event** dedupe and same-event cross-item edges → chunked node merges (**`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**) → batched relationship writes (**`EDGEGUARD_REL_BATCH_SIZE`**). `python src/run_pipeline.py` runs the collectors into MISP only and writes nothing to Neo4j, and the MISP → STIX helpers of `MISPToNeo4jSync` (`convert_to_stix21`, `fetch_stix21_from_misp`) have no pipeline caller ([ARCHITECTURE.md § Pipeline flow](ARCHITECTURE.md#pipeline-flow-what-actually-runs-where)).

**Limits & wiring:** This module is **not** run by the **`edgeguard_baseline`** DAG or by **`run_pipeline.py`** (external collectors only). **`run_misp_to_neo4j`** discovers events via **paginated `/events/index`** (+ client filter) with a **paginated `restSearch` fallback** (event headers only) — see **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)**. This collector uses **`resolve_collection_limit(..., baseline=False)`** and caps **`/events`** fetch at **`min(3×limit, 2000)`** or **2000**, plus **500** attributes per event.

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

**File:** `src/collectors/cisa_ics_collector.py` — **on by default**; `EDGEGUARD_ENABLE_CISA_ICS=false` turns it off.

### What It Does
Collects CISA ICS-CERT advisories (`ICSA-*`) and ICS medical advisories (`ICSMA-*`) published as **CSAF 2.0** JSON files in the public `cisagov/CSAF` GitHub repository and emits **one `vulnerability` item per CVE** (the advisories that name one CVE are merged, see *One item per CVE* below) and **one report record per advisory** (see *Advisory report records* below). The point of this collector is the **source-asserted critical-infrastructure sector**: every advisory carries a `"Critical infrastructure sectors"` note written by CISA (e.g. `"Critical Manufacturing, Energy, Information Technology"`). The keyword sector detector (`detect_zones_from_text`) is **deliberately not applied** to these items.

### Source
- **Base URL:** `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/` (`EDGEGUARD_CISA_ICS_BASE_URL`)
- **Listing files:** `index.txt` (all advisories as `YYYY/<file>.json`, ~3,960 entries 2010–2026, newest first) and `changes.csv` (`"YYYY/<file>.json","<ISO timestamp>"`, no header, newest first)
- **Per advisory:** `document.tracking.{id,initial_release_date,current_release_date,version,revision_history}`, `document.title`, `document.publisher`, `document.distribution.tlp`, `document.notes[]`, `document.references[]` (`category: self` → cisa.gov URL and the CSAF file), `product_tree` (vendor → product_name → product, with its `product_id`; `full_product_names`, `relationships`; the first vendor and product reach `NVD_META` whole as `vendor` and `product`), `vulnerabilities[]` (`cve`, `cwe`, `notes`, `product_status`, `remediations`, `scores[].cvss_v3`)
- **API Key:** Not required · **Licence:** TLP:WHITE ("Disclosure is not limited")
- **Mode selection:** baseline → `index.txt` filtered to the years inside `baseline_days` and pre-filtered on the day-of-year encoded in the file name (`icsa-26-281-01` → 2026-10-08, with a 45-day margin), fetched newest-first, then filtered by `initial_release_date >= cutoff`; incremental → `changes.csv` rows newer than the stored cursor (`checkpoints/baseline_checkpoint.json` → `cisa_ics.incremental.cisa_ics_last_change_ts`, minus a 24 h overlap; first run uses `EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS`, default 30). The cursor advances only when every selected advisory was fetched (`fetch_failed == 0`) and the MISP push had no failure (`failed == 0`), or, on a run without items, when no fetch failed. A report record whose push failed does not hold it: `report_pending` keeps the record. A report record holds the cursor only while it is neither in MISP nor saved on that list. A baseline does not set it.
- **Per-run limit:** `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` (1,200 advisory files) bounds every run, daily and baseline. The generic incremental limit (`EDGEGUARD_INCREMENTAL_LIMIT`, 200) does not apply: `cisa_ics` is in `config.OWN_RUN_CAP_SOURCES`, so the daily DAG passes no item limit (`EDGEGUARD_MAX_ENTRIES` still applies when set). An item limit would count (advisory, CVE) items: an advisory naming more CVEs than the limit (350–378 on three advisories of the 2026-10-16 baseline) would stop every run inside the same advisory.

### Zone Mapping (source-asserted, fixed table)

| CISA sector (from the advisory note) | EdgeGuard zone |
|---|---|
| `Energy` | `energy` |
| `Healthcare and Public Health` | `healthcare` |
| `Financial Services` | `finance` |
| any other sector (Critical Manufacturing, Water, Communications, …) | contributes nothing |
| nothing mapped | `['global']` |

The raw sector list is kept on the item as `ics_sectors`; every emitted zone is validated against `config.VALID_ZONES`. The note is a list: `parse_sectors` splits it at commas and drops a leading `and` or `&` of a part, so `"Commercial Facilities, Critical Manufacturing, and Energy"` (ICSA-24-354-07) gives `Energy`. A name with `and` and no comma before it (`Food and Agriculture`, `Water and Wastewater Systems`) stays one name, and CISA's sector "Nuclear Reactors, Materials, and Waste" is kept whole (`LISTED_NAMES_WITH_COMMAS`, ICSA-24-165-12), also with other words in its part (`Nuclear Reactors, Materials, and Waste Sector`). The table ignores case and a trailing word `Sector` (`Healthcare and Public Health Sector`, ICSMA-24-254-01).

**What the sector means.** CISA's note names the sectors where the affected product is **deployed**, not the sectors an adversary targets. In the graph a mapped sector is CISA's statement: the CVE's `AFFECTS` link to the Sector carries the evidence label `advisory_sector` at confidence 0.9 (`src/sector_evidence.py`), never `TARGETS`, and the link names `cisa_ics` only when CISA's record gave that sector (the `SOURCED_FROM` edge of `cisa_ics` keeps the record's `zones` and `stated_zones`). A sector NVD, KEV or OTX infers for the same CVE stays `zone_classification` at 0.5 unless CISA also states it, in which case the one link carries `advisory_sector` and names both feeds. The field is often broad (Siemens advisories list nearly every sector), so read a finance or energy figure from CISA as "deployed in", not as a targeting signal.

**One item per CVE.** A CVE that several advisories name (a shared component, a multi-vendor product, a medical and an ICS advisory) would otherwise be one item per advisory, and MISPWriter keeps the first item of a value, so the CVE would keep the sectors of whichever advisory came first (newest first in a baseline, oldest first in an incremental run). `merge_items_per_cve` therefore merges them before the push: the union of the zones (`global` dropped once a sector is present), of `ics_sectors` and of `reference_urls`, sorted; `advisory_ids`, the sorted ids of every advisory; `advisory_zones`, the zones of each advisory (advisory id → its specific zones, `[]` for an advisory that maps to none), so a sector link cites only the advisories that name its sector; every other field (description, advisory id and title, vendor, product, affected products, CWE, CVSS) from the newest advisory (largest `current_release_date`, then largest id); the earliest `published` / `first_seen` and the latest `last_modified` / `last_seen`. The result is the same in any order.

**Advisory provenance.** MISPWriter writes `advisory_ids` (at most 50), `ics_sectors` (at most 20) and `advisory_zones` (the advisories kept in `advisory_ids` only) into the attribute's `NVD_META` comment, for a CISA ICS item only (NVD and KEV records carry none of these keys, so their `NVD_META` digest does not depend on them). The sync puts the three on the item: they reach the `raw_data` of the CVE's `SOURCED_FROM` edge to `cisa_ics` (CISA's own words, including sectors EdgeGuard has no zone for, such as Water), and each advisory becomes a record reference `cisa_ics:<advisory id>` on that edge (`r.source_refs`). On an AFFECTS link a sector cites only the advisories that name it: the edge records them per sector (`stated_refs`, e.g. `healthcare|cisa_ics:ICSMA-26-283-01`), and both the sync and `build_relationships` step 7b read them from there; a record without `advisory_zones` cites all of its advisories on every sector. The STIX export turns it into an `external_reference` with the cisa.gov page (`ics-advisories`, or `ics-medical-advisories` for `ICSMA-*`). No node property holds the raw sector names.

### Advisory report records

Every advisory the run reads in its window gets one report record (`parse_advisory_record`, schema `edgeguard.report.v1`, [MISP_SOURCES.md § Report records](MISP_SOURCES.md#report-records-event-reports)), an advisory that names no CVE included. MISP keeps it as one Event Report (`MISPWriter.push_reports`) in the `cisa_ics` day event, or in its companion event `EdgeGuard-cisa_ics-<date>-reports` when the day event holds more than `EDGEGUARD_MISP_EVENT_SPLIT_ABOVE` attributes; its uuid is that of the graph node `VulnerabilityAdvisory` (`record_ref` `cisa_ics:<tracking id>`).

| Record field | CSAF source |
|---|---|
| `record_id` | `tracking.id` |
| `url` | the advisory's `self` reference on cisa.gov, else the page its id gives |
| `csaf_url` | the `self` reference that ends with the file's name (CISA's copy on GitHub), else the URL read |
| `kind` | `ICSA` or `ICSMA`, from the id |
| `title`, `publisher` | `document.title`, `document.publisher.name` |
| `description` | the note "Advisory Summary", else the first note of category `summary` ("Summary", "Overview" in advisories converted from a vendor's), whole |
| `tlp` | `distribution.tlp.label` (`WHITE` → `white`, `CLEAR` → `clear`) |
| `published`, `last_modified` | `tracking.initial_release_date`, `tracking.current_release_date` |
| `revision`, `version` | the number of `tracking.revision_history` entries; `tracking.version` as given (a whole number, or a version such as `1.0.1` on 72 of the 1,389 advisories of 2024-2026) |
| `deployment_sectors`, `deployment_countries` | the names the notes "Critical infrastructure sectors" and "Countries/areas deployed" list; the countries note loses the full stop that ends its sentence, and names it joins with `and` are split (`"Europe, the Middle East and Asia."` gives `Europe`, `the Middle East`, `Asia`), except a country name that holds `and` (`Bosnia and Herzegovina`) |
| `vendor_headquarters` | the note "Company headquarters location" (several such notes joined with `, `) |
| `vendors`, `products` | every vendor name and every `<vendor> <product>` label of the product tree; a tree without `product_name` branches gives its `<vendor> <family>` labels (13 of the 1,389 advisories of 2024-2026; ICSA-25-303-01, with specification branches only, gives no product) |
| `cve_ids`, `vulnerabilities` | per vulnerability with a valid CVE id: `cve_id`; `summary`, its first note of category `summary`, else of category `description`, else of category `details` whose title names no CVSS or SSVC score, whole; `remediations` (`category`: `vendor_fix`, `mitigation`, `workaround`, `none_available`, `no_fix_planned`, and `details`); `affected_products`, the full names of the products `product_status` lists as `first_affected`, `known_affected` or `last_affected`, resolved through the product tree; `cwes` (`id`, `name`) |

- **Push.** The records are written after the CVE items, 100 per `push_reports` call: MISP answers each item batch with the whole event, every report included, so records written first would come back with every batch. A run without items writes them before its return. The scheduled run's writer and the baseline's know their task's end, so no record starts later than 10 minutes before it, and the CVE items' push also stops a failing streak 10 minutes before that end ([CONFIGURATION.md](CONFIGURATION.md)).
- **`report_pending`.** After each call, the records whose push failed or was not tried go on the `report_pending` list of the `cisa_ics` incremental state, on baselines and scheduled runs alike. A record that cannot be built goes there too, and so does the record of an advisory in the window that could not be fetched (on a baseline, by the date its file name gives): a baseline sets no cursor, and the look-back of the run after it may not reach that advisory again. After a baseline, the next run reads that advisory for its record only, and its CVE items wait until the source changes the file or the next baseline; after a scheduled run, the fetch failure holds the cursor, so the next run selects the advisory again and reads it whole, items included. The list's gauges are set on every run that pushes, also one without records, and a record still failing `EDGEGUARD_REPORT_PENDING_MAX_DAYS` after its first failure is given up with an ERROR `[REPORT-GAVE-UP]`.
- **Records on the list.** Each run that pushes reads the advisories of up to 100 records on the list, those tried longest ago first, for their records only: their items are not pushed again, the window does not apply to them, and their fetch is not counted in `fetch_failed`. The file comes from the run's listing (`index.txt` or `changes.csv`, by the advisory id). An advisory the run selected but left unread because its item limit was reached (for CISA ICS only `EDGEGUARD_MAX_ENTRIES` on a scheduled run, or an explicit baseline limit such as `BASELINE_COLLECTION_LIMIT` on a baseline, sets one) is still read for its record when that record is on the list. An advisory the run reads for its items whose record is on the list under its file name tries that entry too: a malformed file is a failed try, and a file whose `tracking.id` names another advisory takes the entry off. A record whose advisory cannot be fetched or parsed counts as a failed try, and so does a record whose advisory the listing does not name (a WARNING `[REPORT-PENDING]` names it), so an advisory really withdrawn is given up in the end like any other record. A listing without a row (an empty or unreadable `changes.csv`) leaves the list untouched and untried, with a WARNING `[REPORT-PENDING]`. These reads come after the run's own and keep a fetch-failure streak of their own: they do not count toward the 10 consecutive fetch failures that abort a run, and 10 failed fetches in a row among them stop them for the run (WARNING `[REPORT-PENDING]` with the number of records left untried, which keep their entries as they were). An open circuit breaker (`cisa_ics`, 3 failures, the retries of one read included) stops them the same way, and the run still pushes what it read; a breaker that opens while the run's own reads are still going aborts it before the push. Any error of such a read (also a broken body, a redirect loop, a file that is not valid CSAF) is a failed try of its entry, while the run's own reads raise every error but a timeout, a connection or HTTP error and a body that is not JSON. A file whose `tracking.id` is not the entry's id gives the record of that id, and the entry leaves the list (WARNING `[REPORT-PENDING]`).
- **Cursor.** A record failure does not hold the cursor. When the list cannot be saved, the records neither in MISP nor on the list hold it (ERROR `[REPORT-PENDING]`), and the later batches of the run are not pushed.
- **Status.** The run's status carries `report_counts` (`records`, the counts `push_reports` gives, `pending`, `given_up`, `pending_saved`); `stats` carries `records`, `pending_fetched`, `pending_failed` and `pending_not_listed`. One `[REPORTS] CISA ICS` line per run sums them up.
- **Caps.** The record's list caps sit above the advisories of 2024-2026: 500 remediations and 5,000 affected products per CVE (at most 85 and 644 measured, ICSA-26-113-03 and ICSA-24-235-03), 2,000 products per advisory (at most 497, ICSA-24-193-05). A list a cap cuts is logged at WARNING `[REPORTS] CISA ICS <record_ref>` with the list and the counts.
- **Size.** The largest record of 2024-2026 (ICSA-26-295-11, the largest CSAF file, 428 CVEs) is about 940 KB.

### Example Output

```python
{
    'type': 'vulnerability',
    'cve_id': 'CVE-2026-32645',
    'description': 'ICSA-26-281-01: Red Lion Controls N-Tron 700 Series — Default factory credentials ...',  # whole note
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
# sectors (no update path for revised advisories yet); the advisory's report record is revised in place.
# The description is the advisory id and title and the vulnerability's whole note: MISP holds it uncut, and the
# sync caps the graph's copy at 1,000 characters.
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
| `EDGEGUARD_ENABLE_CISA_ICS` | `true` | Master switch. `false` → the daily and baseline tasks and `collect()` log "disabled by flag" and return a skipped status (success, 0 items) **without any HTTP request** |
| `EDGEGUARD_CISA_ICS_BASE_URL` | GitHub raw `OT/white/` folder | Where `index.txt`, `changes.csv` and the advisory files live |
| `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` | `1200` | Hard cap on advisory files fetched per run (a 24-month baseline is ~900); the per-run limit of daily runs too, which `EDGEGUARD_INCREMENTAL_LIMIT` does not cut |
| `EDGEGUARD_CISA_ICS_MIN_EXPECTED_ADVISORIES` | `50` | Baseline-only sanity floor (see below) |
| `EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS` | `30` | Lookback for the first incremental run (no cursor yet) |

### Safety behaviour
- **Isolated:** own circuit breaker (`cisa_ics`, 3 failures → open 30 min), own `RateLimiter` (≤ 4 req/s, sequential fetches), `retry_with_backoff` (3 retries) + `request_with_rate_limit_retries` (429/5xx backoff). Shares only the generic helpers with the KEV collector.
- **Per-file failures never abort the run:** a file that is not a JSON object with `document` + `vulnerabilities`, a JSON decode error, or a per-file 404 is counted in the status `stats` (`malformed`, `fetch_failed`, `skipped_vulns`, …) and skipped; one outside the window (its `initial_release_date`) is counted in `outside_window`, with its record. Ten **consecutive** fetch failures (or the breaker opening mid-run) abort as a transient error **before** anything is pushed.
- **Baseline sanity floor:** when at least `CISA_ICS_MIN_EXPECTED_ADVISORIES` advisories were attempted but fewer parsed, or the index lists nothing in the window, the collector logs an error, increments `pipeline_errors_total{task="collect_cisa_ics"}` and raises `CISAICSBaselineFloorError` (a `TransientServerError` subclass) → `run_collector_with_metrics` marks the task **skipped + Slack alert** instead of writing a thin dataset. Not evaluated when fewer than the floor were attempted (small `collection_limit` smoke runs).
- **Upstream outage** (timeout / connection error / 5xx on the index) propagates as transient → skip + alert. A 4xx on `index.txt`/`changes.csv` (layout change) returns `success=False` so the task goes red for an operator. Code defects re-raise (DAG catastrophic branch).
- `health_check()` GETs `index.txt` and returns the same `{healthy, response_time_ms, ...}` shape as the other collectors.

---

## 13. MalwareBazaar Collector

**File:** `src/collectors/global_feed_collector.py` (`MalwareBazaarCollector`) — **flag-guarded, OFF by default** (`EDGEGUARD_ENABLE_MALWAREBAZAAR=true` to enable).

### What It Does
Collects the sha256 hashes of recent malware samples from [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) and emits **one `sha256` indicator per sample**. The `signature` column is the malware family: it becomes `malware_family` on the item, travels to MISP inside the `TF_META` comment exactly like the ThreatFox family, is rehydrated as `Indicator.malware_family` by `run_misp_to_neo4j.parse_attribute`, and `build_relationships` step 9 links it to `Malware` nodes (`INDICATES`, `match_type = malware_family`). Samples whose `signature` is `n/a` are pushed without a family.

### Source
- **Export URL:** `https://mb-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv` — the samples of the last 48 hours (about 830 to 1,000 rows; 1,027 on 2026-10-12, of which 458 Mirai and 265 `n/a`; about 830 on 2026-10-24). The abuse.ch Auth-Key is required and sits in the URL path, where it is redacted from every log line and error, the DEBUG records of the HTTP library included. Without a key the task is skipped (`missing_abusech_key`). The **full export** (all hashes, a v2 export with the Auth-Key, regenerated hourly) is the complete history and is deliberately **not** used: baseline and regular runs both read the recent export, so the history in MISP / Neo4j builds up over successive daily runs.
- **Columns:** `first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type_guess, mime_type, signature, clamav, vtpercent, imphash, ssdeep, tlsh` (quoted, `", "` separated; the header is a `#` comment line and is read by name, so a reordered export still parses).
- **Auth:** `THREATFOX_API_KEY` (the abuse.ch Auth-Key, shared by all abuse.ch platforms) is part of the export URL path; placeholders (`demo`, `YOUR_THREATFOX_API_KEY_HERE`) are treated as unset and the source is skipped.
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
    'file_md5': '2cbdeeb34862d4f0a40aabcc3236b891',    # '' when n/a or not 32 hex characters
    'file_sha1': 'd382bede96d914347228a5392812851da046858f',
    'file_name': 'net.arm5',                # as the export gives it
    'file_type': 'elf',
    'mime_type': 'application/x-executable',
    'reporter': 'abuse_ch',
    'reference': 'https://bazaar.abuse.ch/sample/38cbdf41…/',   # sample page; triggers TF_META
    'tags': ['elf'],                        # TF_META.tags → raw_data of the SOURCED_FROM edge (no node property)
}
```

In MISP the attribute is `sha256` with the tags `source:MalwareBazaar`, `zone:*`, `tlp:*`, `confidence:*`, the MISP-native `first_seen`, and a `TF_META:` comment carrying `malware_family`, `reporter`, `reference`, `tags` and the facts of the sample's file: `file_name`, `file_md5`, `file_sha1` and `file_type` (each only when the export gives it). The MD5 and SHA-1 are facts of the file, the same for every source; the sync does not read them. A file name is a lure name chosen by the attacker and may name a company or a person: it is public source data, kept in MISP, and stays out of deliverables and training samples.

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
| CISA ICS | cisagov/CSAF (ICS-CERT advisories) | ✅ Active (on by default; `EDGEGUARD_ENABLE_CISA_ICS=false` turns it off) | Source-asserted sector → fixed table (`map_sectors_to_zones()`), no keyword detector |
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
| `ports`, `families` (optional) | none: MISP only | ThreatFox, Feodo Tracker |
| `ioc_ids`, `threat_types`, `confidence_level` (optional) | none: MISP only | ThreatFox |
| `c2_status` (optional) | none: MISP only | Feodo Tracker |
| `listing_reason`, `listing_family`, `threat_type` (optional for this source) | none: MISP only (`threat_type` in `raw_data`) | SSL Blacklist |
| `abuse_confidence_score`, `ip_country_code` (optional) | none: MISP only | AbuseIPDB |
| `file_name`, `file_md5`, `file_sha1`, `file_type` (optional) | none: MISP only | MalwareBazaar, VirusTotal (`file_name` MalwareBazaar only) |
| `threat_category`, `meaningful_name`, `file_size`, `detection_malicious`, `detection_total` (optional) | none: MISP only | VirusTotal |
| `as_of` | none: the time the comment was written, present when the comment holds a value that changes at the source (`url_status`, `last_online`, `c2_status`, `abuse_confidence_score`, `detection_malicious`, `detection_total`) | URLhaus, Feodo Tracker, AbuseIPDB, VirusTotal |

The optional keys are written only when the item carries a value, and the sync sets a property only when the key is present, so a source never blanks another source's value on a shared node. The list-source keys (`ports` to `detection_total` above) are written as the source gives them; only the comment's 4,000-character budget shortens them, and only when a block exceeds it ([MISP_SOURCES.md § Metadata Comment Prefixes](MISP_SOURCES.md#metadata-comment-prefixes)). No value is invented for a field the source does not give (no 0, no `unknown`); the sync does not read them, so they are kept in MISP only. The edge's `raw_data.pulse_name` is the OTX pulse name, else the feed's `malware_family`, else a plain comment, never a metadata block, so the `TF_META` of an item with neither (SSL Blacklist, AbuseIPDB, VirusTotal, an unlabelled MalwareBazaar sample) does not reach the graph. Their time-variant values are the first report's: the writer never re-comments a stored attribute ([Re-reported indicators](#re-reported-indicators)), so they read as "at first report", dated by `as_of`; for the same reason the merged lists (`ports`, `ioc_ids`, `families`, `threat_types`) hold the records of the run that first wrote the value. `tests/test_source_graph_footprint.py` checks this path per source up to the row handed to the MERGE query.

A comment whose JSON after the prefix is not an object (`OTX_META:null`, `OTX_META:["x"]`, `TF_META:"s"`, `MITRE_USES_TECHNIQUES:null`, written by a MISP user or a federated instance) is read as no metadata, with a `[META]` warning naming the attribute's UUID, and the attribute is synced without it, so such a comment does not fail its event (`tests/test_malformed_meta_comments.py`). A list-valued key holding a string (`{"t":"T1059"}`) is ignored instead of being split into characters, and a list keeps only its strings and numbers (numbers as strings), because Neo4j refuses a node property list holding a map, a list, a null or mixed types and would fail the whole batch. A technique's `MITRE_TACTIC_PHASES` block is read the same way (a string such as `{"p":"execution"}` is ignored, and a list keeps only its strings and numbers); its bare-list form, which no writer produces, keeps its strings and numbers. `TF_META.tags` is not list-only: URLhaus writes it as the feed's comma-separated string.

## Baseline collection limits

What each collector pulls on a 730-day baseline, and the upstream limit behind it. The ceiling is the upper bound of a single baseline run.

| Collector | Baseline ceiling | Upstream limit |
|-----------|------------------|----------------|
| NVD | Every 120-day window, no item cap | 2,000 per page, 120 days per request |
| OTX | 200 pages (`EDGEGUARD_OTX_BASELINE_MAX_PAGES`) of 50 pulses, or of the baseline limit when one is set | No documented cap |
| CISA KEV | The whole catalogue | None |
| MITRE ATT&CK | The whole STIX bundle | None |
| MISP (local) | Not collected | — |
| AbuseIPDB | One blacklist request, 10,000 addresses | Free plan limits |
| VirusTotal | Not in the baseline | Free tier: lookups only |
| Feodo Tracker | Complete C2 history, 15,000 servers | None |
| SSL Blacklist | The whole feed, 20,000 entries | None |
| ThreatFox | Last 7 days, 10,000 IOCs | API returns 7 days |
| URLhaus | The `recent.csv` export (the URLs added in the past 30 days: about 63,000 on 2026-10-24), 100,000 URLs | The export's window (Auth-Key required) |
| CISA ICS | Advisories in the window, at most 1,200 | None |
| MalwareBazaar | Last 48 hours, 500 samples | Export of the last 48 hours (Auth-Key required) |
| Energy, Healthcare | Placeholders, no DAG task | — |

- **NVD.** The baseline iterates 120-day windows (`iter_nvd_published_windows`); NVD allows `resultsPerPage` up to 2,000 and a `pubStartDate`..`pubEndDate` span of at most 120 days. A run-level `limit` present in a baseline (an incremental-style setting) is ignored with a warning, because it would cut almost the whole windowed collection.
- **OTX.** `EDGEGUARD_OTX_BASELINE_MAX_PAGES` (default 200, forwarded by `docker-compose.yml`) sets the ceiling, about 10,000 pulses at 2 s between pages; a baseline that stops at it with a full last page logs a warning. OTX documents no pulse cap; the effective throttle of the free tier is about 30 requests per minute. A pulse that comes back on a later page is kept once, and the run logs the distinct pulses beside the rows read ([Pages and pulse counts](#pages-and-pulse-counts)).
- **CISA KEV.** The public JSON has no authentication, no rate limit and no per-entry modification date. Every run compares the whole catalogue with EdgeGuard's MISP copies and edits revised entries in place, at most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN` (500) per run ([§ 3](#revisions-every-run-compares-the-catalogue-with-misp)); `notes`, `cwes` and `forensicTriage` are in MISP (`NVD_META`: `cisa_notes`, `cisa_cwes`, `cisa_forensic_triage`), so a change to them is an edit; the sync does not set them on the `CVE` node yet.
- **MITRE ATT&CK.** The bundle is a public GitHub raw file. A scheduled run pushes the whole changed bundle; objects MISP already holds keep their stored text ([§ Duplicate avoidance](#duplicate-avoidance-misp--incremental-runs)).
- **MISP (local).** `MISPCollector` is library code that no DAG or CLI step runs; the graph is built from MISP by the MISP → Neo4j sync instead.
- **AbuseIPDB.** At most one blacklist request per run, of at most `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` (10,000) addresses, in the baseline and the daily runs (the incremental default of 200 does not apply). The free plan returns at most 10,000 addresses per blacklist request and allows 5 blacklist requests per UTC day, and the `check` quota of 1,000 per day serves the source key check. A fetched blacklist is reused for the rest of its UTC day, and a 429 fails the task ([§ 5](#5-abuseipdb-collector)). A plan that returns more per request needs the class constant `AbuseIPDBCollector.BLACKLIST_MAX_PER_REQUEST` raised; a run still makes at most one request, none when it reuses the answer.
- **VirusTotal.** Not in the baseline DAG. The scheduled lookups stay within `EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN` (60) per run and `EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET` (400) per UTC day; the free tier allows 4 requests per minute and 500 per day, lookups only (`GET /files/{hash}`), with no feed or search endpoint. They enrich hashes already in MISP ([§ 6](#6-virustotal-lookup-enrichment)); the ledger in `./state` carries the daily counter across runs and remembers looked-up hashes. A premium key raises the two settings.
- **Feodo Tracker and SSL Blacklist.** Public CSV and text feeds without a rate limit. Feodo Tracker: the complete C2 history (`ipblocklist_aggressive.csv`) on baselines, the 30-day list on regular runs, at most `EDGEGUARD_FEODO_MAX_PER_RUN` (15,000) servers per run; the state of the feed itself is in [§ 7](#7-finance-feed-collector). SSL Blacklist: the whole feed, at most `EDGEGUARD_SSLBL_MAX_PER_RUN` (20,000) per run. Both apply their caps in the baseline and the daily runs, keep the newest entries when a cap is reached, and ignore the incremental default of 200.
- **ThreatFox and URLhaus.** ThreatFox's `get_iocs` takes `days` from 1 to 7 ([ThreatFox API](https://threatfox.abuse.ch/api/)), so the collector clamps it to 7; older IOCs are only in the [ThreatFox export](https://threatfox.abuse.ch/export/), which EdgeGuard does not read ([ROADMAP.md](ROADMAP.md#collection-depth-and-scale)). URLhaus reads its `recent.csv` export, the URLs added in the past 30 days (abuse.ch Auth-Key required; about 63,000 on 2026-10-24). The caps `EDGEGUARD_THREATFOX_MAX_PER_RUN` (10,000) and `EDGEGUARD_URLHAUS_MAX_PER_RUN` (100,000) cover each whole window with headroom, apply in the baseline and the daily runs, keep the newest entries when reached, and replace the incremental default of 200.
- **CISA ICS Advisories.** On by default (`EDGEGUARD_ENABLE_CISA_ICS=false` turns it off). The advisory files of the index entries in the window, at most `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` (1,200), about 900 on a 730-day run, one item per CVE; public GitHub raw files without authentication, fetched sequentially at no more than 4 requests per second. A baseline that parses fewer than `EDGEGUARD_CISA_ICS_MIN_EXPECTED_ADVISORIES` (50) is skipped with an alert instead of loading a thin dataset.
- **MalwareBazaar.** Flag-guarded, default off. The export (abuse.ch Auth-Key required) covers the last 48 hours (about 830 to 1,000 samples); at most `EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN` (500) SHA-256 indicators per run, labelled samples first. The full export, the whole history, is not used, so a baseline loads the same window as a daily run and the history builds up over the daily runs.
- **Energy and Healthcare.** Placeholder modules that return `skipped=True` (`skip_reason_class="placeholder"`) and that no DAG task calls. No member-only feed (EE-ISAC, Health-ISAC) is collected, and HC3, a public US HHS source, is not collected either. CISA's ICS advisories ([§ 12](#12-cisa-ics-advisories-collector), `EDGEGUARD_ENABLE_CISA_ICS`) give `energy`, `healthcare` and `finance` from CISA's own sector statement.

Planned work on collection depth (an import of the ThreatFox export, paid VirusTotal and AbuseIPDB plans) is listed in [ROADMAP.md](ROADMAP.md#collection-depth-and-scale).

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
either spelling resolve identically; an alias is never a ``Source``
node: the graph has one per ``canonical_id``, and the ``SOURCED_FROM``
writers resolve an alias to it), ``cli_id`` / ``api_key_env`` /
``rate_limit`` / ``cli_default_enabled`` / ``cli_description`` (the
``edgeguard source list`` CLI listing), ``cli_display_name`` (only needed
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

_Last updated: 2026-11-08_

## History

- 2026-11-08 — Feodo Tracker, `INDICATES` row: of several nodes whose name equals the family label without separators, the ATT&CK node is linked when every other is OTX-only.
- 2026-11-08 — MITRE ATT&CK, descriptions: the node's text also loses markdown bold and the inline HTML emphasis tags outside backtick code spans, and a cut inside a bulleted list keeps no lone list marker.
- 2026-11-08 — Cost in the sync: an event of up to `EDGEGUARD_MISP_PAGED_FETCH_ABOVE` attributes is downloaded as `/events/view/<id>/excludeGalaxy:1`, without the galaxy clusters (the text named PyMISP `get_event`).
- 2026-11-08 — MITRE ATT&CK in MISP: malware and tools carry the `mitre-software` galaxy cluster tag when the MISP has that galaxy enabled (one galaxy-list read per writer; `mitre-malware` / `mitre-tool` otherwise and on a failed read), since the MISP galaxy repository updates only the merged galaxy; an object's ATT&CK id is its `mitre-attack` id, else its `mitre-ics-attack` one, so `BlackEnergy 3` carries S1002 and 12 deprecated ICS techniques are kept and marked (they were skipped for want of a `mitre-attack` id); ATT&CK for ICS 20.1 counts; why MISP returns platform tags in lower case on a MISP that held them.
- 2026-11-08 — OTX: a defanged indicator value is refanged before the push by MISP's own rules, so MISP, the report record and the graph hold the value sent (it was sent as given, MISP stored it refanged and the push reported it `[UNCONFIRMED]`); the report record lists exactly the pairs the push sends, a URL repeated with another case of its scheme or host once (`indicator_count` counted it twice); the lists copied onto the items hold no blank item (OTX's `[""]` gave `pulse_tags`, `pulse_references` and `attack_ids` of `[""]`), read as the report record reads them.
- 2026-11-08 — CISA ICS Advisories is on by default (`EDGEGUARD_ENABLE_CISA_ICS` defaults to `true`; `false` turns it off). OTX and CISA ICS report records: a new record goes to the source's day event, or to its `EdgeGuard-<source>-<date>-reports` companion event when the day event holds more than `EDGEGUARD_MISP_EVENT_SPLIT_ABOVE` attributes (always the case for a baseline's OTX day event); a revised record is edited where MISP holds it (the text named the day event only). Feed metadata: the list-source `TF_META` keys are described as shortened only by the comment's 4,000-character budget, in line with MISP_SOURCES.md and COLLECTION_AND_SYNC_LIMITS.md (the text said they were never cut).
- 2026-11-07 — NVD, CISA KEV and CISA ICS: no collector cuts a CVE text before MISP (NVD's description was cut at 1,000 characters, KEV's short description at 500). New `NVD_META` source facts: NVD's `nvd_vuln_status`, `references` with their tags, the CNA's `affected` pairs and `cvss_scorers`; KEV's `cisa_notes`, `cisa_cwes` and `cisa_forensic_triage`, so the KEV comparison sees a change to them; `cwe_names` from a pinned MITRE CWE list (§ CWE names). KEV's `vendorProject` / `product` and an ICS advisory's first vendor / product reach `NVD_META` whole (cut at 100 characters with `...` before); a CNA entry that names only a package keeps its package name as `product`; `score_type` is NVD's label as given (the text said Primary meant NVD's own score); the KEV source notes said `notes`, `cwes` and `forensicTriage` were not stored.
- 2026-11-07 — CISA ICS: one report record per advisory (summary, sectors, countries, vendor headquarters, TLP, dates, `revision` as the number of revision-history entries and `version` as `tracking.version`, vendors, products, and per CVE the whole note, remediations, affected products and CWE), also for an advisory without a CVE, pushed after the CVE items and, on a run without items, before its return. Records whose push failed or was not tried wait on `report_pending` instead of holding the cursor, and so do the record that cannot be built and the record of an advisory in the window that could not be fetched (on a baseline, by its file-name date); each run reads the advisories of up to 100 listed records for their records only, with a fetch-failure streak of their own that stops these reads, not the run, and so does an open circuit breaker; any error of such a read is a failed try; a record whose advisory the listing does not name is a failed try, and a listing without a row leaves the list untouched. The record's list caps are 500 remediations and 5,000 affected products per CVE and 2,000 products per advisory (the record library's 50, 500 and 500: 50 remediations had cut ICSA-26-113-03 and 500 affected products ICSA-24-235-03), and a cut is logged. The vulnerability summary falls back to a `details` note that holds no score; the countries note is split at `and` and loses its closing full stop. The sector note's last list item loses its `and` (`"…, and Energy"` gave the sector `and Energy`, which mapped to no zone), and a sector named with a trailing `Sector` maps to its zone. The vulnerability note reaches MISP whole (it was cut at 1,000 characters). The scheduled run's writer knows its task's end: no record starts, and no failing streak of the item push goes on, later than 10 minutes before it. The window applies to an advisory by its `initial_release_date`, also to one without a CVE.
- 2026-11-07 — ATT&CK in MISP: the collector passes every description whole and MISPWriter writes it whole (up to 8,000 characters; it cut groups, techniques and tactics at 255 characters and malware and tools at 400 with "..." added mid-word, and a comment without a block at 500); every platform is a tag sent in ATT&CK's casing, on malware and tools too (the first 3 of a technique, lower-cased), and the sync reads the platform tags in ATT&CK's spelling whatever casing MISP holds them in; tools carry alias tags; groups, malware and tools carry their ATT&CK domains as `attack-domain:` tags and ATT&CK's own galaxy cluster tag beside the community one; a technique's zones are still read from its first 500 characters; MITRE's terms and notice for the copied text.
- 2026-11-07 — OTX: an indicator of an amber, red or unknown-TLP pulse gets an empty `pulse_name` in the graph; the sync took the comment as the fallback name, which for such an item is the whole `OTX_META` block, and now takes no metadata block as a name.
- 2026-11-07 — OTX report records: one MISP Event Report per pulse, pushed after the pulse's items in batches of 100; `report_pending` on baselines and scheduled runs, its pulses fetched by id on every run (a failed fetch is no try and puts the entry behind the others; none after the retry list's fetches stopped), given up after `EDGEGUARD_REPORT_PENDING_MAX_DAYS`, also when the pulse's fetch keeps failing that long; the cursor passes a pulse whose record failed only once it is saved on the list, and a pulse of the retry list keeps its entry until its record is; the scheduled writer knows its task's end; `report_counts` in the status, whose `pending` gives the list as last saved after a failed save of it. The text of an amber or red pulse, or of one without a known TLP, is no longer copied onto its items.
- 2026-11-07 — Sync: the `raw_data.pulse_name` of a `SOURCED_FROM` edge takes a plain comment only, never a metadata block (the whole `TF_META` of an item without a family, every URLhaus item among them, was copied into it, and the list-source fields with it).
- 2026-11-07 — List sources: the fields the collectors dropped before MISP reach the `TF_META` comment. ThreatFox merges the records of one value into one item (two records `IP:443` and `IP:8080` were two items, and MISP kept only the first record's port, id, family and threat type; the port was lost on every `ip:port` IOC) with `ports`, `ioc_ids`, `families`, `threat_types` and the integer `confidence_level` (a record without a level raised `TypeError`). SSL Blacklist writes the listing reason verbatim (it was lower-cased and never reached MISP), the certificate page as `reference`, the role as `threat_type` and the family part as `listing_family`, never a category word ("Malware C&C", "Ransomware C&C"). Feodo Tracker adds `ports`, `families` and `c2_status`. AbuseIPDB writes `abuse_confidence_score` and `ip_country_code` in `TF_META` (they were in a prose comment) and leaves out a field the answer lacks (a missing score was 0 and `confidence:low`; the blacklist item held report and reporter counts of 0 the endpoint never returns). MalwareBazaar adds `file_name`, `file_md5`, `file_sha1` and `file_type`; VirusTotal adds `threat_category`, `meaningful_name`, `file_type`, `file_size`, `file_md5`, `file_sha1` and the detection counts (the file type was `unknown` and the size 0 when VirusTotal gave none). Values that change at the source carry `as_of`. The merged lists of ThreatFox and Feodo Tracker hold the records of the run that first wrote the value.
- 2026-11-07 — NVD and ATT&CK descriptions: the MISP → Neo4j sync writes at most 1,000 characters of a CVE's description and 500 of an ATT&CK description to the graph, markup stripped and cut at a sentence or word end; MISP keeps what the collectors send.
- 2026-11-07 — OTX: the pulse TLP is read from `tlp`, the field the subscribed list answers (only `TLP`, the field of an answer by id, was read, so every pulse of a window reached MISP without its level and was written at the default; on the 730-day test graph of 2026-11-03 every OTX indicator was `white` and `pulse_tlp` was empty on every OTX `SOURCED_FROM` edge).
- 2026-11-06 — OTX adversaries: a list is not split inside parentheses or before a company's legal form, a name that is only a legal form is dropped, and no name keeps unbalanced parentheses (the split had made the actors `black owl (bo team` and `ltd.`).
- 2026-11-05 — OTX adversaries: `"&&"` joins two names like `"&"`, a `"<language>-speaking"` qualifier marks a description, and state intelligence and security agencies on their own (`MOIS`, `GRU`, `Russian Federal Security Service`, `Russian intelligence services`) are dropped like country names and logged on the same `[ACTOR-NAMES]` line; a name the canonical threat-actor reference lists as no actor (`ClickFix`, `Proton66`) is dropped before the malware-family rule, with an `[ACTOR-NAMES]` line of its own. On the 730-day baseline of 2026-11-03 these rules would have kept out 43 `ThreatActor` nodes with 791 relationships. A pulse of the retry list whose answer by id cannot be processed is named or counted on none of the run's `[ACTOR-NAMES]` and `[SKIP]` lines (its names and non-file hashes were counted as they were read, although its items were dropped).
- 2026-11-03 — MISP push: a batch has three retries (four attempts, 10, 20 and 40 s apart; it had five attempts); a cooldown ends early when MISP answers a light request; a push stops once MISP has kept failing for `EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC` (900 s; the baseline's writer `EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE`, 3600 s, and 10 minutes before its task's end), counts the items not sent as failed, lists them in `last_push_unsent_items` and lets the run go on (`[MISP-PUSH-STOPPED]`); the lookups after a 5xx get timeouts of at most the time left, the throttle and the cooldown due count in the check before a batch, and a cooldown's light requests count toward it; the event and part lookups and a new part's creation stop retrying at the cap but keep their full timeouts, and the listings and the refresh are not limited by it. Nothing stopped a push before: every failed batch cost five attempts and a 300 s cooldown followed every three, so a long push against a failing MISP ran until the task was killed, which saved nothing. OTX: a stopped push holds the cursor below the oldest window pulse with an item it did not send, those pulses go on no retry list and the listed pulses those items name keep their entries, also when a window row has no id (`pulse_counts.held_unsent`); the time budget's figures follow the shorter retries (about six failing pulses fit a run when MISP answers light requests, about four when it answers nothing). NVD incremental runs attempt no edit after a stopped push.
- 2026-11-02 — OTX scheduled runs: `EDGEGUARD_INCREMENTAL_LIMIT` counts the pulses modified after the cursor, oldest first; the overlap's re-reads and pulses without a readable `modified` are processed without counting. OTX returns the pulses newest-modified first (three pages of 20 read on 2026-11-02 with a 60-day `modified_since`, of 370 pulses OTX reported: `modified` never rose over the 59 consecutive pairs, 5 of them equal), and the limit took them in that order, so a run whose window held more pulses than the limit processed the newest and the cursor passed the older ones, which no later run read. The run logs the deferred pulses (`pulse_counts.deferred`) and a WARNING when it stops at `EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES` with pulses left to read. The cursor compares `modified` values as UTC: a run whose pulses mixed values with and without a zone raised `TypeError` when it moved the cursor, after the push, and the cursor stayed. The cursor also advances after a push whose items MISP already held, which `push_items` counts as neither stored nor failed; it moved only after a push that stored an item, so with the oldest-first limit a run whose oldest pulses MISP held (an additive baseline over an older cursor, pulses re-modified without a new indicator) would have taken the same pulses on every run, each run passing, while the newer ones waited. `MISPWriter` counts a batch whose event id is empty once sanitised as failed and lists its items; it returned 0 stored and 0 failed, the count of a batch MISP already held. After a push in which MISP failed items in batches it answered, whatever it stored, the cursor advances and the pulses of the listed items go on a retry list in the incremental state (`otx_retry_pulses`): later runs fetch them by id (`EDGEGUARD_OTX_RETRY_PER_RUN`, 50), take them off when their items are stored or OTX answers HTTP 404, and give them up after `EDGEGUARD_OTX_RETRY_MAX_DAYS` (7) or beyond `EDGEGUARD_OTX_RETRY_MAX_PULSES` (1000) with an ERROR (`[OTX-RETRY-GAVE-UP]`); each run logs the list (`[OTX-RETRY]`) and counts it in `pulse_counts`, and the metrics `edgeguard_otx_retry_pulses`, `edgeguard_otx_retry_oldest_failure_timestamp_seconds` and `edgeguard_otx_retry_given_up_total` feed two alerts. The cursor stopped below the oldest pulse with a listed item after a push that stored an item, and stayed after one that stored nothing: with the oldest-first limit a pulse whose item kept failing, or a value with 4-byte characters (counted as failed, not listed) as the only item MISP lacked, would have held every newer pulse back, each run red. Only a push whose listed items all failed at their MISP event (`MISPWriter.last_push_event_failed_items`: MISP unreachable, the day's event failing) holds the cursor below the oldest pulse with a listed item, and puts no pulse on the list; a batch MISP refuses is a failure of its items, whatever share of the push it holds. The items of the pulses on the list are pushed in batches of their own (`push_items`' `batch_key`), so a value MISP refuses fails no other pulse; a pulse leaves the list only when the items recorded as failed (`failed_items`) were pushed again, and is given up only after a run tried it past its deadline. An answer by id that cannot be read, or a `requests` error of the fetch, keeps the pulse and lets the run go on. A fresh baseline's wipe sets the retry gauges to an empty list. The OTX cursor bullet names the case of a pulse with a listed item and no readable `modified`, which leaves the cursor where it is. The baseline table gave 50 pulses per page also with a baseline limit. The pulses of the list are pushed after the window's push, which writes the cursor and the pulses it lists first, in one push of their own within `EDGEGUARD_OTX_RETRY_MAX_SECONDS` (600): pushed with the window, each pulse whose batch kept answering HTTP 5xx added about 2.6 minutes, and about 14 of them took the task past its limit of one hour before it saved the cursor or the list. Only a push of a pulse's items is a try: a fetch by id that failed and a run whose push failed at the MISP event counted as one, so a pulse could be given up untried, and they now leave the entry as it was. `failed_items` keeps a reference of at most 49 characters per item; it kept the identity key, a whole URL. The cap is applied when the run writes the window's new pulses, before the list's pulses are pushed, and that write marks the pulse the push begins with (`last_push_started_at`), which goes behind the others after a raise or a killed task: the cap was applied only after that push, so a pulse whose batch raised on every run let the list grow by every run's new pulses and kept the other pulses of the list from being pushed. An item that a window pulse without an id shares with a pulse of the list goes in that pulse's batches (the push was ordered by the items' `pulse_id`, and such an item failed the run before its window's push). `last_reason` keeps printable ASCII only, and the entry's bound is stated in the state file's format, 2,000 bytes (it was stated for compact JSON, 1,500).
- 2026-11-02 — Checked against the code: the MITRE ETag is also not stored when ATT&CK for ICS is on and its bundle failed (the cursor paragraph gave this condition only further down); after HTTP 5xx and the retries, the writer lists the items whose attributes the lookup in the event does not find, so only an attribute missing from a batch answered with HTTP 200 goes unlisted (the text listed whole 5xx batches and no partly stored one); MISP drops a case variant of a value an earlier request stored, and stores both within one request (the text said it stores one of two); a campaign's `last_seen` takes a Feodo row's first-seen claim when the row has no last-seen time (the text named the MISP record time); `MISPCollector` and the MISP → STIX helpers of `MISPToNeo4jSync` have no pipeline caller (the text named an alternate Neo4j ingest and a CLI STIX path); the URLhaus export is described as the URLs added in the past 30 days; a duplicated History bullet of 2026-11-02 is removed.
- 2026-11-02 — Feodo Tracker, `INDICATES` row: a family label that equals no `Malware` name or alias links to the one node whose name equals it without separators; the row named the name or alias match only.
- 2026-11-02 — OTX: the same-run dedup folds the case variants of a family, an adversary or an indicator value into the first pulse's item (keyed case-exactly, a later pulse's spelling was pushed as an item of its own and MISP did not store it: 164 family and 6 adversary spellings of the 730-day baseline of 2026-11-01, with the ids of the pulses that named them); a URL is compared by its lower-cased scheme and host. `push_items` compares the attributes of one push as the push confirmation does and logs a variant it does not push (`[CASE-VARIANT]`); it compared them exactly. The checks against what MISP holds (per event, across events, a caller's `known_source_keys`) and the refresh of a re-reported indicator compare by the same rule (`_dedup_key`); compared exactly, a hash re-reported in upper case was pushed again on every run while its stored lower-case copy was never refreshed, and when the push dropped the variant in MISP's spelling, the refresh of the stored copy was dropped with it.
- 2026-11-02 — `MISPCollector` wiring: `run_pipeline.py`, which runs the collectors into MISP only, leaves it out (the text named its step 2). CISA KEV dates and `raw_data` no longer name the command-line STIX import (removed).
- 2026-11-02 — Adding a source: the CLI listing is `edgeguard source list` (the text named `edgeguard sources`, a command that does not exist).
- 2026-11-02 — OTX: both fetch paths keep the first copy of each pulse id (offset paging can return a pulse on two pages; the rows were appended as they came, so a repeated pulse was processed twice and, in a scheduled run, took a slot of the limit); the baseline logs the distinct pulses beside the rows read (it logged the rows as `N total pulses collected`), the repeated pulse ids and the pulses that yielded no item, and the status carries `pulse_counts`; the page-ceiling warning counts distinct pulses (it counted the rows).
- 2026-11-01 — NVD, CVEs MISP holds: the sync updates the `CVE` node as `merge_cve` writes it, in batches (`merge_cves_batch`); the text named `merge_cve` as the sync's writer.
- 2026-11-01 — MITRE ATT&CK: one item per group / malware name (lower-cased), an active object winning over a deprecated one (`[ATTACK-SAME-NAME]`); a failed ICS bundle holds back the deprecated groups and malware and leaves the ETag unstored (it was stored, so ICS waited for the next Enterprise release); group and malware items carry their ATT&CK id (`aid` in MISP); the push confirmation ignores case only for the attribute types whose case MISP changes on save (a value the event held only in another case had been confirmed).
- 2026-10-25 — MISP push: the items of a group whose later-part lookup failed without a complete cross-event listing are listed as unstored.
- 2026-10-25 — Cost in the sync: an event of an earlier day keeps its size, also one larger than `EDGEGUARD_MISP_EVENT_SPLIT_ABOVE`, and an edit or a refresh of a copy in it makes the sync download that whole event.
- 2026-10-25 — URLhaus: the `recent.csv` export lists the URLs added in the past 30 days, about 2,100 a day on average on 2026-10-24 (the page gave about 1,130 a day, the rate of the keyless 30-day file). MalwareBazaar: the full export is a v2 export with the Auth-Key (the keyless `/export/csv/full/` answers HTTP 410).
- 2026-10-25 — A source's aliases are lookup keys only: the graph has one `Source` node per canonical id (until then also one per alias).
- 2026-10-25 — Duplicate avoidance, MISP push, Cost in the sync and the NVD volume name the event parts (`EDGEGUARD_MISP_EVENT_SPLIT_ABOVE`): the target is the first part of the day with room, dedup covers every part, the items of a part that could not be created are listed as unstored, and an NVD edit or a URLhaus refresh makes the sync read the part of at most 20,000 attributes that holds the copy; OTX events are not split (the page said a refresh moves the source's single baseline event and the sync downloads the NVD event of 139,862 attributes and the URLhaus event of about 63,000).
- 2026-10-25 — Cost in the sync: the URLhaus baseline event (its whole `recent.csv` export, about 63,000 URLs on 2026-10-24) is among the events the incremental sync re-reads once refreshes begin.
- 2026-10-25 — URLhaus and MalwareBazaar read the abuse.ch v2 `recent.csv` exports with the Auth-Key (`THREATFOX_API_KEY`) in the URL path, because the keyless downloads (`downloads/csv_recent/`, `csv_top10k/`, `/export/csv/recent/`) answer HTTP 410 since 2026-10 (`csv_top10k` has no v2 equivalent); the key is redacted from logs, errors and the HTTP library's DEBUG records, the source key check reports it for all three abuse.ch sources, and `EDGEGUARD_URLHAUS_MAX_PER_RUN` is 100,000 (was 50,000), above the about 63,000 URLs the export listed on 2026-10-24 (the keyless 30-day file held 34,003 on 2026-10-13).
- 2026-10-25 — Cost in the sync: events over `EDGEGUARD_MISP_PAGED_FETCH_ABOVE` (default 20,000) attributes, among them the OTX and NVD baseline events, are downloaded as metadata plus `/attributes/restSearch` pages of 5,000, not with `get_event`.
- 2026-10-25 — Feodo Tracker: a Campaign's `last_seen` for an indicator without a last-seen claim is the edge's latest report (`last_reported_at`), not the import time.
- 2026-10-23 — The energy and healthcare placeholders are modules no DAG task calls (the page said they show on the skip dashboard); HC3 named as a public source that is not collected; the unsupported OTX node estimate removed; the MISP row states that no DAG or CLI step runs `MISPCollector`. These were the README's collector-limit notes. The baseline-limits section keeps the current limits only (its title no longer says "planned"), as a three-column table with the notes in a list below it (the Feodo Tracker feed state is left to § 7); the ThreatFox import, the paid VirusTotal path and the ATT&CK for ICS sector mapping are listed in ROADMAP.md.
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
