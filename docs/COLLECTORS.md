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

### Duplicate avoidance (MISP + incremental runs)

- **`MISPWriter.push_items`**: when **`EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS`** is true (default), loads existing **`(type, value)`** on the target event via **`/attributes/restSearch`** and skips attributes already present — covers same-day reruns and overlapping incremental windows. It also lists **`(type, value)`** across every MISP event that carries the source's tag (**`EDGEGUARD_MISP_CROSS_EVENT_DEDUP`**, default on, PR-F7) and skips those too. If that listing fails part-way, the keys read so far are used and the check falls back to the target event. NVD incremental runs pass their own complete listing instead (`known_source_keys`). `push_items` never edits a stored attribute; NVD updates go through `MISPWriter.update_attribute` (below). Reducing **incoming** volume is the job of collector cursors below.
- **OTX** (non-baseline): stores **`otx_last_pulse_modified`** in **`checkpoints/baseline_checkpoint.json`** under **`[source].incremental`** (`get_source_incremental("otx")`). Each run fetches pulses with **`modified_since`** = last cursor minus **`EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC`**. First run with no cursor uses **`EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS`**. Cursor advances only after a **clean** MISP push (**`failed == 0`**) or when there is nothing to push.
- **NVD** (non-baseline, 2026-10): stores **`nvd_last_modified_cursor`** under **`[nvd].incremental`**. Each run reads every CVE modified since the cursor minus **`EDGEGUARD_NVD_CURSOR_OVERLAP_SEC`** (first run with no cursor: **`EDGEGUARD_NVD_INCREMENTAL_DAYS`**), adds the CVEs MISP does not hold yet and edits the stored attribute of a CVE when NVD's data for it changed. The cursor advances only when every MISP write succeeded and the window was read completely. See [§ 2](#2-nvd-collector).
- **MITRE** (non-baseline): stores **`mitre_bundle_etag`**; sends **`If-None-Match`** to GitHub. **HTTP 304** skips download, parse, and MISP push. **Baseline** runs always fetch the full bundle. ETag is saved only after **`failed == 0`** on MISP push (or immediately when **`push_to_misp`** is false).

### MISP push: attribute types and characters (2026-10)

MISP answers a batch push with HTTP 200 but does not store an attribute that fails its validation, and a single character its database cannot store fails the whole batch with HTTP 500. On the 730-day baseline of 2026-10 this lost tens of thousands of OTX attributes without a failed task. `MISPWriter` therefore:

- types a generic `hash` by the length of its hex digest: 32 characters → `md5`, 40 → `sha1`, 64 → `sha256`, 128 → `sha512` (`map_indicator_type`). Until 2026-10 every generic hash was pushed as `sha256`, and MISP dropped the MD5 and SHA1 values;
- strips characters outside the Basic Multilingual Plane (4-byte UTF-8, such as emoji) from comments and tag names, because MISP's MySQL / MariaDB columns are 3-byte `utf8`. An attribute whose value needs such characters is skipped with a warning (`[SKIP] attribute value contains 4-byte characters`) and counted as failed, whatever MISP answers;
- reports attributes missing from MISP's answer as `[UNCONFIRMED]` ([AIRFLOW_DAGS.md](AIRFLOW_DAGS.md), MISP push accounting).

The MISP → Neo4j sync gives an attribute without a `tlp:` tag the level `EDGEGUARD_DEFAULT_TLP` (default `white`) and logs the attribute's UUID (`[TLP]` warning): a push interrupted between the attribute insert and its tags leaves the attribute untagged, and its source may have stated a stricter level.

#### Detection Rules
1. **Thresholds**: Defaults **1.5** for both per-field and combined-item scoring (overridable via env — see **`.env.example`**).
2. **Relative filtering**: In **`detect_zones_from_item`**, sectors must be within **50%** of the max combined score.
3. **Negative keywords**: e.g. “not healthcare”, “except bank” exclude that sector for the analyzed text.
4. **Clean keywords**: malware family names are not sector keywords — link via graph relationships.

### Common Output Fields

All collectors return items with these common fields:

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Item type: `indicator`, `vulnerability`, `malware`, `actor`, `technique` |
| `zone` | list | **All matching zones as array** (e.g., `['finance', 'healthcare']`) |
| `tag` | string | Source tag for MISP |
| `sources` | list | List of source identifiers |
| `confidence_score` | float | 0.0-1.0 confidence rating |
| `first_seen` | tz-aware ISO-8601, **OPTIONAL** | Source's claim about when it first observed this entity (concept 1 in [`docs/TIMESTAMPS.md`](TIMESTAMPS.md)). **Omit when source field is absent — never substitute wall-clock NOW** (PR-M2 §4-F4 / F5). |
| `last_seen` | tz-aware ISO-8601, **OPTIONAL** | Source's claim about when it last updated this entity (concept 2). Same omit-when-absent rule. |

**Note:** The `zone` property is always an array. The old `zones` property has been removed.

**Removed in PR-M2:** the `last_updated` key on collector items (Finding 11). It was a dead key — Cypher MERGE sets `n.last_updated = datetime()` server-side and never reads the collector-supplied value. Concepts 3 (`first_imported_at`) and 4 (`last_updated`) are EdgeGuard-internal and always set server-side; collectors must NOT emit them.

**Honest-NULL invariant.** If a collector's source doesn't expose a first/last-seen field, OMIT the key from the item dict — do not substitute `datetime.now()`. The downstream MIN/MAX CASE on the `SOURCED_FROM` edge preserves any prior real claim from another source. The reference pattern is `src/collectors/abuseipdb_collector.py` (blacklist endpoint omits `first_seen` because the API doesn't expose it). See [`docs/TIMESTAMPS.md`](TIMESTAMPS.md) for the full semantic model.

---

## 1. OTX Collector

**File:** `src/collectors/otx_collector.py`

### What It Does
Collects threat intelligence pulses from AlienVault OTX, including:
- Indicators (IPs, domains, hashes, URLs, e-mail addresses) with per-indicator description. **Types (2026-10):** `FileHash-MD5` / `-SHA1` / `-SHA256` reach MISP as `md5` / `sha1` / `sha256` (typed by digest length, above); import hashes (`FileHash-IMPHASH`), PE hashes (`FileHash-PEHASH`), JA3 TLS fingerprints and SSL certificate fingerprints (`SSLCertFingerprint`) are not collected, because typed by length they would be stored as file hashes (the run logs how many it left out: `[SKIP] OTX: N indicators of a non-file hash type`); OTX `email` indicators, and values of an unmapped OTX type that have the form `user@host.tld`, are typed as e-mail addresses (`email-src`), not as domains
- Malware families with the pulse's ATT&CK technique IDs as `reported_techniques` (2026-10: pulse-level association, written to MISP as `MITRE_USES_TECHNIQUES:{"rt":[…],"pid":"<pulse id>","rids":[…]}` — `rids` lists the other pulses of the same run that named the entity (the collector's dedup folds them in instead of dropping them; indicators carry the same list as `OTX_META.report_ids`); on MITRE actors the block also carries `m` (malware names) and `s` (tool S-ids) from the group → software `uses` relationships (R6: `USES_MALWARE` / `USES_TOOL`) and linked downstream as `IMPLEMENTS_TECHNIQUE` with `match_type='otx_pulse'`, 0.6 — never as `uses_techniques` / `mitre_explicit`)
- CVE references (all CVEs per pulse, no cap)
- **Pulse metadata:** `attack_ids` (MITRE ATT&CK), `industries` (authoritative sector classification), `targeted_countries`, `tags`, `references`, `author_name`, `adversary`, `TLP`
- **Pulse families / adversaries on every indicator (2026-10):** each IOC item carries `pulse_malware_families` (the pulse's `malware_families`, cleaned, ≤ 20) and `pulse_malware_actor_pairs` (`"family::adversary"` for the pulse's families × its `adversary` names through `clean_actor_names`, ≤ 50 — the pair encoding keeps the same-pulse guarantee when several pulses' lists are unioned on one IOC); they travel as `OTX_META.mf` / `.pa`, accumulate on `Indicator.pulse_malware_families` / `.pulse_malware_actor_pairs`, and `build_relationships` Q9b / Q2d link them (`otx_pulse`, 0.6). This is what keeps report-scoped linking working on regular updates: the family / actor attribute itself is a MISP cross-event duplicate after the first pulse and is never re-pushed. `OTX_META` is now written for every pulse indicator (before: only when the pulse had `attack_ids` or `targeted_countries`).
- Named adversaries are automatically extracted as ThreatActor items

### Source
- **URL:** `https://otx.alienvault.com/api/v1/pulses/subscribed`
- **API Key:** Required (free)
- **Rate Limits:** ~30 requests/minute (free tier, 2s between requests)

### Zone Detection
```python
def detect_sectors(self, text: str) -> List[str]:
    """Detect ALL sectors from pulse text using word boundary matching."""
    import re
    text_lower = text.lower()
    matched_sectors = set()
    
    for sector, keywords in SECTOR_KEYWORDS.items():
        for keyword in keywords:
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, text_lower):
                matched_sectors.add(sector)
    
    return list(matched_sectors) if matched_sectors else ['global']
```

### Example Output

```python
# Indicator
{
    'indicator_type': 'ipv4',
    'value': '192.168.1.100',
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'tag': 'alienvault_otx',
    'sources': ['alienvault_otx'],
    'first_seen': '2024-01-15T10:30:00Z',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
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
    'otx_industries': ['finance'],            # OTX-native sector classification
}

# Malware (with ATT&CK technique IDs)
{
    'type': 'malware',
    'name': 'Emotet',
    'malware_types': ['unknown'],
    'family': 'Emotet',
    'description': 'Banking trojan targeting financial institutions...',
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'tag': 'alienvault_otx',
    'sources': ['alienvault_otx'],
    'confidence_score': 0.5,
    'reported_techniques': ['T1059', 'T1071'],  # ATT&CK from pulse attack_ids (2026-10: reported, not MITRE-explicit)
    'pulse_id': '6aa4409a4290cc035d81500c',   # source report id → report-scoped INDICATES / ATTRIBUTED_TO
    'pulse_id': '5f3a2b...',
    'pulse_name': 'Emotet Banking Trojan IOCs',
}

# CVE Reference (no cap — all CVEs from pulse)
{
    'type': 'vulnerability',
    'cve_id': 'CVE-2024-1234',
    'description': 'Referenced in OTX pulse: Emotet Banking Trojan IOCs',
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'tag': 'alienvault_otx',
    'sources': ['alienvault_otx'],
    'first_seen': '2024-01-15T10:30:00Z',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
    'confidence_score': 0.5,
    'severity': 'UNKNOWN',
    'cvss_score': None,  # a pulse reference carries no CVSS (2026-10; was 0.0, tagged cvss:low)
    # no 'attack_vector' (2026-10; an invented 'NETWORK' was sent)
}

# Threat Actor (auto-extracted from pulse adversary field — 2026-10: the free-text
# adversary goes through actor_name_hygiene.clean_actor_names: "apt-c-13, sandworm"
# → two actor items, "multiple russian state-backed groups" → none)
{
    'type': 'actor',
    'name': 'TA542',
    'description': 'Emotet distribution group...',
    'zone': ['finance'],
    'tag': 'alienvault_otx',
    'sources': ['alienvault_otx'],
    'confidence_score': 0.5,
    'reported_techniques': ['T1059', 'T1071'],  # 2026-10
    'aliases': [],
}
```

---

## 2. NVD Collector

**File:** `src/collectors/nvd_collector.py`

### What It Does
Collects CVE records from the National Vulnerability Database, including:
- CVE IDs and descriptions (up to 1000 chars)
- Every CVSS version NVD supplies (v4.0, v3.1, v3.0, v2), each with full component data (2026-10; before, the record kept only one of v3.1, v3.0 and v2, and an incremental update then removed the sub-node of an older version when NVD added a newer one)
- `cvss_score` / `severity`: the record's first CVSS in the order v3.1 → v3.0 → v2 → v4.0 (`src/cvss_selection.py`); `None` / `UNKNOWN` when the record has none — rejected CVEs, CVEs awaiting NVD analysis without a CNA score. Until 2026-10 such a record carried 0.0, was tagged `cvss:low` and showed as 3.0 / LOW in Neo4j (14,451 CVEs on the hosted 730-day baseline). The CVSS 2 rating is read from the metric object, where NVD API 2.0 puts it.
- Affected products (CPE matching)
- `attack_vector`: NVD's word (`NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL`) for the attack vector of the CVSS that gives the score; `None` without CVSS. Until 2026-10 it was the letter of the CVSS 3.x vector's `AV` metric (`N`, `L`, `A`, `P`), or `UNKNOWN` without CVSS 3.x. `result_impacts` also come from the scoring CVSS when it is 3.x, as before (none from CVSS 2 or 4.0).
- CWE identifiers
- Reference URLs and tags (advisory/patch links)
- **CISA KEV fields** — `cisa_exploit_add`, `cisa_action_due`, `cisa_required_action`, `cisa_vulnerability_name` (strongest signal of active exploitation; auto-boosts confidence to 0.9)

**NIST notice:** This product uses data from the NVD API but is not endorsed or certified by the NVD ([Start Here](https://nvd.nist.gov/developers/start-here)).


### Known-exploited CVEs outside the baseline window (2026-10)
A baseline also fetches, after its publication windows, the NVD record of every CVE on CISA's KEV list (NVD `hasKev`; `EDGEGUARD_NVD_BASELINE_KEV_SWEEP`, default on) and of the CVE ids in `EDGEGUARD_NVD_EXTRA_CVE_IDS`, whatever their publication date (`_fetch_supplementary_cves`). These records are not duplicated when a window already collected them, and a failed request is logged (`[NVD-KEV-SWEEP]`, `[NVD-EXTRA-CVE]`) and skipped. The KEV collector likewise takes the whole catalogue in baseline mode (`EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE`).

### Source
- **URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **API Key:** Optional (strongly recommended — higher throughput). Sent as HTTP header `apiKey` with the key value (per [NVD Developers — Start Here](https://nvd.nist.gov/developers/start-here)).
- **Rate Limits (NIST):** With key **50** requests / 30 seconds; without key **5** requests / 30 seconds. NIST recommends ~**6 seconds** between requests during bulk sync; this collector uses ~**0.7s** between paginated baseline/incremental pages when a key is set (still under the rolling cap) and ~**6.5s** without a key.

### Published-date API rules (implementation)
NVD 2.0 requires **`pubStartDate` and `pubEndDate` together**; each window **≤ 120 days**. The collector uses **`NVD_MAX_PUBLISHED_DATE_RANGE_DAYS`**, **`clamp_nvd_published_range()`**, and for baseline **`iter_nvd_published_windows()`** — see `src/collectors/nvd_collector.py`.

**Incremental runs (2026-10)** read every CVE NVD **modified** since a stored cursor (`checkpoints/baseline_checkpoint.json` → `nvd.incremental.nvd_last_modified_cursor`) and keep MISP in step with NVD (`NVDCollector._collect_incremental`):

- **Window.** `lastModStartDate` = cursor − `EDGEGUARD_NVD_CURSOR_OVERLAP_SEC` (default 3,600 s, at least 60 s, so a record NVD stamps with a clock behind the worker's is still read), `lastModEndDate` = now. Without a cursor (after a wipe, or on a deployment that never stored one), the run reads the last `EDGEGUARD_NVD_INCREMENTAL_DAYS` days (default 14).
- **Reading in slices.** The window is read in time slices, oldest first, each with a single request (`_iter_lastmod_slices`). NVD evaluates the query again for every request, so paging is unsafe: a record modified again while the window is paged leaves the result, and the records behind it move down past a page boundary (on 2026-10-14, 75 of 19,520 records left a 14-day window while it was paged). A single answer has no page boundary, and a record modified again during the run only moves after the window's end, where the next run reads it.
  - A window whose `totalResults` exceeds one answer (2,000) is split by time into slices of about 1,500 records; no slice spans more than 120 days. An answer that holds fewer records than its `totalResults` although it had room for more is not split further: its records are handled and the read counts as incomplete.
  - A slice narrower than 2 seconds that still holds more than 2,000 records is paged instead. When `totalResults` drops between its pages, the stretch below the current index is read again; a further drop meanwhile, or an empty page before the end, marks the read incomplete.
  - Each slice is handled before the next is read, so memory stays at one slice.
- **CVEs MISP does not hold yet** (no `source:NVD` attribute) are added when they lie in the scope a baseline collects: published within `EDGEGUARD_BASELINE_DAYS` of now (default 730), on CISA's KEV list (`cisaExploitAdd`), or listed in `EDGEGUARD_NVD_EXTRA_CVE_IDS`. NVD also modifies older CVEs (1,002 published more than 24 months earlier in the 14 days to 2026-10-14); those are not added. The scope follows the `EDGEGUARD_BASELINE_DAYS` environment variable on the worker, default 730; the Airflow Variable `BASELINE_DAYS` and a run's `baseline_days` are not read. A test value left in place (such as 7) narrows the scope.
- **CVEs MISP holds.** The run lists them with `MISPWriter.index_source_attributes` once the first record has been read: the complete listing of `source:NVD` attributes, non-exportable tags included (`includeAllTags`). A listing that fails writes nothing, since a partial one would make stored CVEs look new. Each read CVE is rebuilt and compared with each stored copy:
  - `NVD_META` by digest (`nvd_meta_digest`). `last_modified`, keys with empty values and the order of `cwe`, `ref_tags`, `cpe_type` and `affected_products` are ignored, so a change only to data EdgeGuard does not store (translations, SSVC, CNA product data) needs no edit. `attack_vector` is ignored too (2026-10): it is derived from the CVSS payloads, and copies written before 2026-10 hold a letter (`N`) or `UNKNOWN` where the rebuilt item has NVD's word.
  - Tags by family; tag names compare without case, as MISP resolves them.
  - One-time edits: a copy written before 2026-10 compares as changed once if its CVE has more than 10 CPE matches, because its `affected_products` held a hash-order-dependent 10 of them and the collector now keeps NVD's first 10. That was 21% of a 2,000-record sample and 33 of 768 planned edits in the live dry run of 2026-10-14; they count against the cap. Likewise, a copy of a CVE for which NVD has more than one of CVSS 3.1, 3.0 and 2 compares as changed once: the collector kept only the first of them until 2026-10, and the edit adds the others, whose sub-nodes the sync then keeps.

  A copy that differs is edited in place (`MISPWriter.update_attribute`, `POST /attributes/edit/{uuid}`):
  - the new `NVD_META` comment and `first_seen` / `last_seen`;
  - `severity:` and `cvss:` tags replaced;
  - zone, KEV and source tags added and never removed, `zone:Global` only on an attribute without a zone tag;
  - a `tlp:` tag only when the attribute has none.

  Edits pause `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` (default 5 s) after every 50, as `push_items` pauses between batches: the 5,000 writes a run may make wait about 8 minutes in all. The edit counts only when MISP's answer shows the new comment and tags. MISP 2.5 then moves the attribute's and the event's timestamps. The incremental MISP → Neo4j sync (changed attributes only, `EDGEGUARD_SYNC_ATTRIBUTE_FILTER`) reads the event again and writes the changed attributes. For an NVD record read from MISP (`nvd_record`), `merge_cve` then updates the `CVE` node as follows:
  - **Description, KEV fields, `last_modified` and `status`** are taken from the record. `status` becomes `["rejected"]` once NVD rejects the CVE; a node written before 2026-10 gets `status` at its next write, and a full sync writes it on every NVD CVE.
  - **NVD's lists** (`cwe`, `ref_tags`, `cpe_type`, `result_impacts`, `reference_urls`, `affected_products`) are set from the record even when empty, on a node EdgeGuard manages whose only source is NVD; an empty list removes the property. CISA ICS, the KEV and OTX records and partner writes supply these lists as well, so on a node with another source an empty NVD list leaves the property as it is (on the hosted graph on 2026-10-15, 126,669 of the CVE nodes with `cwe` had NVD as their only source and 3,679 had NVD and another source).
  - **CVSS sub-nodes** are updated for the versions the record has. A sub-node of a version the record no longer has is removed (`_replace_nvd_owned_cve_data`), but only when EdgeGuard manages it and NVD is the only feed that asserted it: CISA ICS writes CVSS sub-nodes too.
  - **Score.** The node's `cvss_score`, `severity`, `cvss_version` and `attack_vector` are then derived from its remaining CVSS sub-nodes (`_set_cve_score_from_cvss`, the last step of `merge_cve`), so a CVSS version NVD withdrew no longer scores the node.
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

**Before 2026-10**, a run took the newest N records of the 14-day lastMod window by *publication* date (N = `EDGEGUARD_INCREMENTAL_LIMIT`, 200; at most 15,000), and `push_items` skipped every CVE MISP already held. Measured on 2026-10-14:
- a replay of the 8-hourly schedule over 30 days missed 37% of new CVEs (6,151 of 16,571);
- on the hosted instance, 1,930 of the 2,130 CVEs published after the 730-day baseline were not in MISP;
- all 1,500 baseline CVEs that NVD changed after the baseline still had their old version in MISP.

**No age filter after the fetch (2026-10).** What a run collects is decided by its request: a baseline's publication windows (plus the KEV sweep and named ids, whatever their age), an incremental run's lastMod window since its cursor. One selection rule remains in incremental runs: a CVE MISP does not hold yet is added only within the baseline's scope (above), compared on timezone-aware UTC values. The former `SECTOR_TIME_RANGES` check compared NVD's zone-less `published` (`"2021-12-10T10:15:09.143"`) with a timezone-aware cutoff and swallowed the `TypeError`, so it had not dropped a record since v2026.3.28. It was removed rather than repaired: a working check would have cut the oldest hours of every baseline (its cutoff is computed after the windows are fetched), any baseline longer than 24 months back to 24 months, and the KEV sweep's older records unless exempted (1,330 of 1,741 on 2026-10-14). The same check on the OTX pulse `created` time was removed for the same reason: a pulse created years ago can still be receiving new IOCs (a sampled pulse created in January 2023 had 42 of its 93 IOCs added within the last 24 months).

### Zone detection (implementation)

**`detect_sectors(description, configurations)`** builds `{"description": …, "comment": …}` where **`comment`** is plain text from **`configurations_to_zone_text()`** (CPE **`criteria`** strings plus vendor/product tokens from CPE 2.3 URIs). It calls **`detect_zones_from_item()`** — not `json.dumps` on the raw JSON (that broke word-boundary keyword matches).

### Example Output

```python
{
    'type': 'vulnerability',
    'cve_id': 'CVE-2024-1234',
    'description': 'SQL injection vulnerability in hospital management system...',
    'zone': ['healthcare'],  # Array of all matching zones
    'tag': 'nvd',
    'sources': ['nvd'],
    'first_seen': '2024-01-10T00:00:00Z',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
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
- Known ransomware campaign use (`known_ransomware_use`; no score is derived from it, 2026-10)

**Scope (2026-10):** a baseline takes the whole catalogue, whatever an entry's `dateAdded` (`EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE`, default `true`; `false` restores the `dateAdded` window of the baseline length). Incremental runs take the entries added within `EDGEGUARD_CISA_INCREMENTAL_DAYS` (default 30).

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
    'sources': ['cisa_kev'],
    'first_seen': '2024-01-15',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
    'confidence_score': 0.9,  # High confidence - confirmed exploited
    'severity': 'UNKNOWN',
    'cvss_score': None,
    # no 'attack_vector' (2026-10; an invented 'NETWORK' was sent)
    'vendor': 'SCADA Systems Inc',
    'product': 'Grid Manager Pro',
    'required_action': 'Apply patch by due date',
    'due_date': '2024-02-01',
    'known_ransomware_use': 'Known'
}
# Note (2026-10): the KEV catalogue carries no CVSS, so a KEV record has no score; the CVE's CVSS
# comes from the NVD collector, and the CVE node takes it from its CVSS sub-nodes whatever record
# arrives last. Until 2026-10 the score was derived from `knownRansomwareCampaignUse`
# (Known = CRITICAL / 9.0, Unknown = HIGH / 7.0, read back as 7.5) and could replace NVD's CVSS.
# `known_ransomware_use` ("Known" / "Unknown") travels in NVD_META (and as the `ransomware:known`
# MISP tag) to the CVE node property of the same name.
```

---

## 4. MITRE Collector

**File:** `src/collectors/mitre_collector.py`

### What It Does
Collects threat intelligence from MITRE ATT&CK framework, including:
- Attack techniques (T###)
- Threat actors (intrusion sets)
- Malware families
- Relationships (uses, attributed-to, subtechnique-of) — STIX **`uses`** populates **`uses_techniques`** on **actors** and **malware** for **`build_relationships.py`** (malware round-trips via MISP **`MITRE_USES_TECHNIQUES:`**)

### Source
- **URL:** `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- **ATT&CK for ICS (2026-10, `EDGEGUARD_ENABLE_MITRE_ICS=true`, default off):** `ics-attack/ics-attack.json` from the same repository (`MITRE_ICS_ATTACK_URL` to override) is fetched after the Enterprise bundle and parsed with the same code (`_parse_bundle`, kill-chain name `mitre-ics-attack`). 97 techniques (T08xx), 12 tactics (TA0100–TA0111, 9 short names identical to Enterprise), 14 groups, 23 malware. Every item carries `attack_domain` (`enterprise` | `ics`); groups/malware present in both bundles are emitted once with `uses_techniques` unioned. An ICS fetch/parse failure is logged, counted (`pipeline_errors_total{task=collect_mitre_ics}`) and never affects the Enterprise items; the MITRE circuit breaker is not tripped. No ETag for ICS: on an Enterprise HTTP 304 the ICS bundle is skipped (baseline runs ignore ETag). ICS items are **not** auto-zoned `energy` (`x_mitre_sectors` / assets unused — follow-up).
- **API Key:** Not required
- **Format:** STIX 2.1 bundle

### Revoked and deprecated objects (2026-10)

The ATT&CK bundles keep replaced and retired objects. `_parse_bundle` (Enterprise and ICS alike):

- **Revoked** (`revoked: true`, with a `revoked-by` relationship to the successor): skipped, whatever the type. No item, no relationship to or from it (`uses`, `subtechnique-of`, `attributed-to`), so no `uses_techniques` / `uses_malware` / `uses_tools` entry names it. A revoked group's or software's name and aliases are appended to its successor's `aliases` (the successor's own aliases first; a chain A → B → C ends on C): `UNC2452` → `APT29`, `Dragonfly 2.0` → `Dragonfly`, `Stolen Pencil` → `Kimsuky`, `Darkmoon` → `PoisonIvy`. Tool items now carry `aliases` too (`x_mitre_aliases`), but the MISP writer tags aliases of actors and malware only, so a tool's aliases do not reach the graph.
- **Deprecated** (`x_mitre_deprecated: true`, no successor): kept, with `deprecated: True`; every other item carries `deprecated: False`. The MISP writer tags a deprecated item `attack-status:deprecated`; the sync turns the tag into `n.deprecated = true`.
- The log line `skipped N revoked ATT&CK objects {...} and M relationships that reach them` gives the counts per bundle.

Feeds that still name a revoked technique id (OTX pulses citing `T1086`) are translated to the successor downstream, with `src/reference/attack_revoked_ids.json` (`src/attack_revoked.py`; see `docs/KNOWLEDGE_GRAPH.md`, "Revoked and deprecated ATT&CK objects"). Groups and software need no map: the bundle names every successor. A revoked technique the map does not list is therefore kept, as before 2026-10, with the warning `[ATTACK-REVOKED] N technique(s) the bundle revokes are not in the revoked-id map (…)`, so the links that cite it are not lost; rebuild the map (`docs/RUNBOOK.md`, "Rebuilding the ATT&CK revoked-id map") and the next run skips it.

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
    'sources': ['mitre_attck'],
    'platforms': ['Windows', 'macOS', 'Linux'],
    'data_sources': ['Application Log', 'File', 'Network Traffic'],
    'deprecated': False,  # True for an object ATT&CK deprecated (2026-10); revoked objects are skipped
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
    'sources': ['mitre_attck'],
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
    'sources': ['mitre_attck'],
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
    'sources': ['mitre_attck'],
    'tool_types': ['credential-theft'],
    'confidence_score': 0.95,
    'uses_techniques': ['T1003.001', 'T1078'],
}
```

---

## 5. AbuseIPDB Collector

**File:** `src/collectors/abuseipdb_collector.py`  
**Class:** `AbuseIPDBCollector`  
**DAG:** `edgeguard_daily` (`collect_abuseipdb`)

### What It Does
Fetches IP reputation / blacklist data from the AbuseIPDB API v2 and pushes indicators to MISP, including:
- Abuse confidence score, total reports, and unique reporter count (`num_distinct_users`)
- Reverse DNS (`domain`), associated `hostnames`
- ISP, country code, usage type
- Tor exit node and whitelist flags
- Top 5 report objects per IP

### Source
- **Base URL:** `https://api.abuseipdb.com/api/v2`
- **API Key:** Required — `ABUSEIPDB_API_KEY`
- **Rate limits:** Free tier ~1,000 checks/day; collector enforces ~1 request/second (`MIN_INTERVAL_SECONDS`)

### Zone detection
Typically **`global`** or derived from feed context — see `collect()` implementation for scoring → zone mapping.

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

Hashes are looked up **once**: the ledger remembers every delivered lookup, including hashes unknown to VirusTotal (HTTP 404), so no lookup is repeated across runs. An enriched hash is remembered only after its MISP push succeeded. The ledger is the only record of what was looked up (MISP cannot tell which hashes of other sources were enriched): if the file is lost, hashes inside the candidate window are looked up again, which costs quota but creates no duplicate attributes. The query shape was confirmed against a live MISP 2.5 on 2026-10-12 (HTTP 200, `response.Attribute` list).

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
`src/collectors/virustotal_collector.py` is an older module (`run_virustotal_enrichment_collection` in the DAG file, `virustotal_enrich` in `run_pipeline`) that lists `/files` — a premium endpoint — and offers `query_domain` / `query_hash` / `query_ip` helpers. No DAG schedules it; it shares the key and the 4/min limiter but not the daily ledger. Use `VTCollector` for production runs.

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

### Zone Detection
Both collectors use `detect_zones_from_text()` on malware names and listing reasons:

```python
# Feodo Collector
zones = detect_zones_from_text(malware.lower())

# SSL Blacklist Collector
zones = detect_zones_from_text(reason)
```

The keyword detector deliberately contains no malware family names (families are linked to sectors through graph relationships), so in practice both feeds are tagged `zone:Global`: measured on 2026-10-12, all 7,980 Feodo rows (7,607 servers) and all 10,964 SSL Blacklist rows. Neither feed is hard-coded to Finance.

### Feodo Tracker: what is loaded and what reaches the graph
- **The feed is a historical snapshot at present.** Both downloads carry the header `# Last updated: 2026-03-04 14:28:39 UTC` (checked 2026-10-12): abuse.ch has not updated Feodo Tracker for seven months. A baseline loads the history once; the daily task then finds nothing new until the feed moves again. The collector logs a warning when the header is older than 7 days.
- **Parsing.** CSV with every field quoted and CRLF line endings, read with the `csv` module; the header row is recognised by name.
- **One record per address.** The feed has one row per address and port, and a re-used address appears again under another family: 7,980 rows describe 7,607 addresses (290 addresses on several rows, 81 with more than one family). MISP holds one attribute per value, so rows are merged per address: earliest `first_seen`, latest `last_online`, every port, every family. The primary family is that of the most recently active row.
- **Actionable or historical.** A server counts as recently active when its `last_online` date is within 30 days of the collection day (`FEODO_ACTIVE_DAYS`). The `c2_status` column is not used for this: it is only as fresh as the feed (the single "online" row of 2026-10-12 was last seen online on 2026-03-12). Recently active: `confidence:medium`, MISP detection flag set. Everything else: `confidence:low`, `to_ids=false`. abuse.ch advises against blocking on the complete history because addresses are re-used. On 2026-10-12 all 7,607 servers were historical.
- **Not rewritten.** EdgeGuard does not update an attribute MISP already holds, so confidence and detection flag are those of the first collection.
- **Outages (Feodo Tracker and SSL Blacklist).** A timeout, a connection error, a truncated transfer or an HTTP 429 / 5xx after the retries is raised as a transient error: the Airflow task is skipped (`transient_external_error`) and the alert path is used; it no longer fails the task. An open circuit breaker skips the run (`feodo_circuit_breaker_open`, `sslbl_circuit_breaker_open`). HTTP 401 / 403 skips (`*_auth_denied`). Any other HTTP status, or a defect in the code, fails the task. A body that is not the CSV yields zero items and a warning.

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
Each row is the SHA-1 fingerprint of a TLS certificate seen on malware infrastructure, not a file hash. Since 2026-10 it is collected as `indicator_type: "x509-fingerprint-sha1"`, pushed to MISP under MISP's own attribute type `x509-fingerprint-sha1` (default category *Network activity*) and synced as an `x509-fingerprint-sha1` Indicator; the STIX export pattern is `[x509-certificate:hashes.'SHA-1' = '…']`. Before, the rows were typed `sha1`: MISP `sha1` attributes, `hash` Indicators shared with the file hashes, and `[file:hashes.'SHA-1' = '…']` patterns. A MISP instance or graph loaded before the change keeps those `sha1` attributes and `hash` nodes until it is wiped and re-baselined; MISP does not treat an `x509-fingerprint-sha1` attribute as a duplicate of a `sha1` attribute with the same value.

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
    'sources': ['ssl_blacklist'],
    'first_seen': '2024-01-10',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
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
- **URLhaus:** `https://urlhaus.abuse.ch/downloads/csv_recent/`

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
    'sources': ['threatfox'],
    'first_seen': '2024-01-14T10:00:00Z',
    'last_seen': '2024-01-15T08:00:00Z',     # Most recent observation
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
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
    'sources': ['urlhaus'],
    'first_seen': '2024-01-14',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
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

### Decision (2026-10)
No healthcare member-only feed collector is planned: HC3 and Health-ISAC (H-ISAC) require memberships that are not budgeted. Public healthcare advisories are covered by the CISA KEV and CISA ICS Advisories collectors. The placeholder stays so the slot is visible on the skip dashboard.

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

### Decision (2026-10)
No energy member-only feed collector is planned: EE-ISAC (European Energy ISAC) membership is not budgeted. CISA ICS-CERT energy sector advisories are collected by the flag-guarded CISA ICS Advisories collector (`cisa_ics`); MITRE ATT&CK for ICS is available through the MITRE collector flag. The placeholder stays so the slot is visible on the skip dashboard.

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

**Limits & wiring:** This module is **not** run by the **`edgeguard_baseline`** DAG or by **`run_pipeline` step 2** (external collectors only). **`run_misp_to_neo4j`** discovers events via **paginated `/events/index`** (+ client filter) with **`restSearch` fallback** (`limit: 1000`) — see **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)**. This collector uses **`resolve_collection_limit(..., baseline=False)`** and caps **`/events`** fetch at **`min(3×limit, 2000)`** or **2000**, plus **500** attributes per event.

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

**File:** `src/collectors/cisa_ics_collector.py` — **flag-guarded, OFF by default** (`EDGEGUARD_ENABLE_CISA_ICS=true` to enable). Added 2026-10.

### What It Does
Collects CISA ICS-CERT advisories (`ICSA-*`) and ICS medical advisories (`ICSMA-*`) published as **CSAF 2.0** JSON files in the public `cisagov/CSAF` GitHub repository and emits **one `vulnerability` item per (advisory, CVE)**. The point of this collector is the **source-asserted critical-infrastructure sector**: every advisory carries a `"Critical infrastructure sectors"` note written by CISA (e.g. `"Critical Manufacturing, Energy, Information Technology"`). The keyword sector detector (`detect_zones_from_text`) is **deliberately not applied** to these items.

### Source
- **Base URL:** `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/` (`EDGEGUARD_CISA_ICS_BASE_URL`)
- **Listing files:** `index.txt` (all advisories as `YYYY/<file>.json`, ~3,960 entries 2010–2026, newest first) and `changes.csv` (`"YYYY/<file>.json","<ISO timestamp>"`, no header, newest first)
- **Per advisory:** `document.tracking.{id,initial_release_date,current_release_date}`, `document.title`, `document.notes[]`, `document.references[]` (`category: self` → cisa.gov URL), `product_tree.branches[]` (vendor → product_name), `vulnerabilities[]` (`cve`, `cwe`, `notes`, `scores[].cvss_v3`)
- **API Key:** Not required · **Licence:** TLP:WHITE ("Disclosure is not limited")
- **Mode selection:** baseline → `index.txt` filtered to the years inside `baseline_days` and pre-filtered on the day-of-year encoded in the file name (`icsa-26-281-01` → 2026-10-08, with a 45-day margin), fetched newest-first, then filtered by `initial_release_date >= cutoff`; incremental → `changes.csv` rows newer than the stored cursor (`checkpoints/baseline_checkpoint.json` → `cisa_ics.incremental.cisa_ics_last_change_ts`, minus a 24 h overlap; first run uses `EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS`, default 30). The cursor advances **only after a clean MISP push** (`failed == 0`), like the OTX/MITRE cursors.

### Zone Mapping (source-asserted, fixed table)

| CISA sector (from the advisory note) | EdgeGuard zone |
|---|---|
| `Energy` | `energy` |
| `Healthcare and Public Health` | `healthcare` |
| `Financial Services` | `finance` |
| any other sector (Critical Manufacturing, Water, Communications, …) | contributes nothing |
| nothing mapped | `['global']` |

The raw sector list is kept on the item as `ics_sectors`; every emitted zone is validated against `config.VALID_ZONES`.

### Example Output

```python
{
    'type': 'vulnerability',
    'cve_id': 'CVE-2026-32645',
    'description': 'ICSA-26-281-01: Red Lion Controls N-Tron 700 Series — Default factory credentials ...',
    'zone': ['energy'],                      # from "Critical Manufacturing, Energy, Information Technology"
    'ics_sectors': ['Commercial Facilities', 'Communications', 'Critical Manufacturing', 'Energy', 'Information Technology'],
    'advisory_id': 'ICSA-26-281-01',
    'tag': 'cisa_ics',
    'source': ['cisa_ics'],
    'confidence_score': 0.9,                  # authoritative government advisory
    'published': '2026-10-08T06:00:00+00:00',     # initial_release_date
    'last_modified': '2026-10-08T06:00:00+00:00', # current_release_date
    'first_seen': '2026-10-08T06:00:00+00:00',    # source-truthful (same two dates)
    'last_seen': '2026-10-08T06:00:00+00:00',
    'severity': 'MEDIUM', 'cvss_score': 6.0, 'attack_vector': 'LOCAL',
    'cvss_v31_data': {'vector_string': 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N', 'base_score': 6.0, ...},
    'cvss_v30_data': None,
    'cwe': ['CWE-798'],
    'vendor': 'Red Lion Controls', 'product': '700 Series',
    'affected_products': ['Red Lion Controls 700 Series'],
    'reference_urls': ['https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-01'],
    'ref_tags': [], 'cpe_type': [], 'result_impacts': ['HIGH', 'HIGH', 'NONE'],
}
# No CVSS block in the advisory → no score: severity UNKNOWN, cvss_score None, attack_vector None
# (2026-10; was 7.0 / HIGH, copied from the KEV collector's ransomware-derived values, and NETWORK).
# Dates absent → the four timestamp keys are omitted (honest-NULL), never wall-clock.
# MISP: tagged source:CISA-ICS + zone:<Zone>; NOT tagged CISA-KEV. Same CVE in two advisories → MISP dedups the
# second attribute (type, value); the first advisory's metadata wins.
```

### Flags & knobs (`src/config.py`, section "CISA ICS advisories collector (2026-10)")

| Env var | Default | Meaning |
|---|---|---|
| `EDGEGUARD_ENABLE_CISA_ICS` | `false` | Master switch. Off → the daily task and `collect()` log "disabled by flag" and return a skipped status (success, 0 items) **without any HTTP request** |
| `EDGEGUARD_CISA_ICS_BASE_URL` | GitHub raw `OT/white/` folder | Where `index.txt`, `changes.csv` and the advisory files live |
| `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` | `1200` | Hard cap on advisory files fetched per run (a 24-month baseline is ~900) |
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

**File:** `src/collectors/global_feed_collector.py` (`MalwareBazaarCollector`) — **flag-guarded, OFF by default** (`EDGEGUARD_ENABLE_MALWAREBAZAAR=true` to enable). Added 2026-10.

### What It Does
Collects the sha256 hashes of recent malware samples from [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) and emits **one `sha256` indicator per sample**. The `signature` column is the malware family: it becomes `malware_family` on the item, travels to MISP inside the `TF_META` comment exactly like the ThreatFox family, is rehydrated as `Indicator.malware_family` by `run_misp_to_neo4j.parse_attribute`, and `build_relationships` step 9 links it to `Malware` nodes (`INDICATES`, `match_type = malware_family`). Samples whose `signature` is `n/a` are pushed without a family.

### Source
- **Export URL:** `https://bazaar.abuse.ch/export/csv/recent/` — the samples of the last 48 hours (about 1,000 rows; 1,027 on 2026-10-12, of which 458 Mirai and 265 `n/a`). No API key is required. The **full export** (`/export/csv/full/`) is the complete history and is deliberately **not** used: baseline and regular runs both read the recent export, so the history in MISP / Neo4j builds up over successive daily runs.
- **Columns:** `first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type_guess, mime_type, signature, clamav, vtpercent, imphash, ssdeep, tlsh` (quoted, `", "` separated; the header is a `#` comment line and is read by name, so a reordered export still parses).
- **Auth:** when `THREATFOX_API_KEY` (the abuse.ch Auth-Key, shared by all abuse.ch platforms) is configured it is sent as the `Auth-Key` header; placeholders (`demo`, `YOUR_THREATFOX_API_KEY_HERE`) are treated as unset.
- **Terms:** MalwareBazaar data is free of charge for commercial and non-commercial use ([Terms of Use](https://bazaar.abuse.ch/faq/#tos)).

### Flags & knobs (`src/config.py`, section "MalwareBazaar (abuse.ch) collector (2026-10)")

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
    'tags': ['elf'],                        # TF_META.tags → tf_tags in Neo4j
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
| Healthcare | — (HC3 / Health-ISAC not planned, decision 2026-10) | ⏳ Placeholder | - |
| Energy | — (EE-ISAC not planned, decision 2026-10; ICS-CERT via `cisa_ics`) | ⏳ Placeholder | - |
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

## Baseline collection limits — current & planned

This table captures **what each collector actually pulls on a 730-day
baseline today**, the **upstream API constraint** driving that choice,
and any **planned follow-up work**. Operators running long baselines
should expect the numbers in the "Current ceiling" column as the hard
upper bound for a single baseline run.

| Collector | Current ceiling | Upstream API constraint | Notes & planned follow-ups |
|-----------|-----------------|-------------------------|----------------------------|
| **NVD** | Full windowed collection (no artificial run-level cap on baseline) | `resultsPerPage <= 2000`; `pubStartDate..pubEndDate` must span `<= 120` days per request | Already iterates 120-day windows via `iter_nvd_published_windows`. PR-M1 adds a defensive WARNING + ignore if an incremental-style `limit` env is present in baseline (prevents ~99% silent truncation) |
| **OTX** | `max_pages = 200` × `50/page` ≈ 10k pulses (~7 min runtime, 2 s between pages) | No publicly documented pulse cap; effective throttle ≈ 30 req/min on the free tier | Current settings produce **~100k nodes + relationships** on a 730-day run. `EDGEGUARD_OTX_BASELINE_MAX_PAGES` (default 200, forwarded by `docker-compose.yml`) sets the ceiling; a baseline that stops at it with a full last page logs a warning (2026-10) |
| **CISA KEV** | Full KEV snapshot per run | Public JSON, no auth, no rate limit | No change planned |
| **MITRE ATT&CK** | Full STIX 2.1 bundle per run | Public GitHub raw file, no rate limit | No change planned |
| **MISP (local)** | Full MISP server content matching the filter | Bounded by local MISP; no external quota | No change planned |
| **AbuseIPDB** | As per `ABUSEIPDB_*` limits | Public API daily checks quota (1k free) | No change planned |
| **VirusTotal** | `EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN` lookups per run (default 60), `EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET` per UTC day (default 400); not in the baseline DAG | Free tier: **4 req/min**, **500 req/day**; lookups only (`GET /files/{hash}`), no feed or search endpoints | Enrichment of hashes already in MISP (see [§ 6](#6-virustotal-lookup-enrichment)); the ledger in `./state` carries the daily counter across runs and remembers looked-up hashes. A premium key raises the two knobs |
| **Finance (Feodo / SSLBL)** | Feodo: full C2 history on baselines (`ipblocklist_aggressive.csv`: 7,980 rows merged to 7,607 servers on 2026-10-12), 30-day list on regular runs; SSLBL: full feed | Public CSV/text feeds, no rate limit | Feodo Tracker has not been updated by abuse.ch since 2026-03-04: a baseline loads history, daily runs add nothing until the feed moves again |
| **Global (URLhaus / ThreatFox)** | **ThreatFox: last 7 days via API** (clamped in PR-M1); URLhaus full feeds | **abuse.ch ThreatFox:** `get_iocs` `days` param `Min 1, Max 7` per [abuse.ch docs](https://threatfox.abuse.ch/api/); historical >7d is the documented **JSON/CSV bulk export** (`https://threatfox.abuse.ch/export/`), NOT this endpoint | **Planned:** bulk-import collector that ingests the ThreatFox JSON/CSV export for true historical depth beyond 7 days |
| **Energy (sector)** | Placeholder (returns `skipped=True`, `skip_reason_class="placeholder"`) | — | No member-only feed (EE-ISAC) is planned (decision 2026-10). Surfaces on the skip dashboard as a placeholder (not silent zero-count) since PR-M1. **Since 2026-10 the ICS-CERT part is a real collector:** [CISA ICS Advisories](#12-cisa-ics-advisories-collector) (`cisa_ics`, flag-guarded by `EDGEGUARD_ENABLE_CISA_ICS`, default off) feeds `energy` / `healthcare` / `finance` from CISA's own sector assertion |
| **CISA ICS Advisories** | `min(index entries in window, CISA_ICS_MAX_ADVISORIES_PER_RUN=1200)` advisory files (~900 on a 730-day run), one item per CVE | Public GitHub raw files, no auth; polite sequential fetch ≤ 4 req/s | Flag-guarded, default **off**. Baseline sanity floor `CISA_ICS_MIN_EXPECTED_ADVISORIES=50` → transient skip + alert instead of a thin dataset |
| **MalwareBazaar** | `min(samples in the recent export ≈ 1,000, MALWAREBAZAAR_MAX_PER_RUN=500)` sha256 indicators per run (baseline and daily; the incremental default of 200 does not apply), labelled samples first | The key-free export covers the last 48 hours only; the full export is the whole history and is not used | Flag-guarded, default **off**. A baseline loads the same window as a daily run; the history builds up over daily runs |
| **Healthcare (sector)** | Placeholder (returns `skipped=True`, `skip_reason_class="placeholder"`) | — | No member-only feed (HC3, Health-ISAC) is planned (decision 2026-10). Same skip-dashboard behaviour as Energy |

### Planned improvements (future PRs)

- **ThreatFox bulk-import collector** for historical IOCs >7 days (reads the abuse.ch JSON/CSV export, pushes to MISP with a dedicated `Source(source_id="threatfox_bulk")`)
- **VT Premium API path** for operators with licensed service steps (unlocks bulk Intelligence search beyond the 500/day free-tier cap)

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

When adding a new collector that has a **canonical first-reported / last-reported timestamp** that should flow into the source-truthful timestamp pipeline (PR S5, 2026-04 — see `docs/KNOWLEDGE_GRAPH.md#sourced_from-edge-schema`), follow this **5-step checklist**:

> **Chip 5a (PR follow-up) consolidated steps 1–4** of the legacy
> 8-step checklist into a single declarative edit in
> `src/source_registry.py`. The five legacy registries
> (`_RELIABLE_FIRST_SEEN_SOURCES`, `SOURCE_TAGS`, `SOURCES`,
> `MISPWriter.SOURCE_TAGS`, `DEFAULT_SOURCES`) are now derived from
> the registry, so adding a `Source(...)` entry there propagates to
> all five simultaneously. The propagation is pinned by
> `tests/test_source_registry.py::test_adding_a_new_source_propagates_to_all_five_derivations`.

### 1. Add a `Source(...)` entry to `src/source_registry.py`

Append one record to the `_REGISTRY` tuple. Required fields:
``canonical_id``, ``display_name``, ``source_type``, ``reliability``,
``misp_tag``, ``reliable_first_seen``. Optional but recommended:
``aliases`` (covers historical short-names so collector lookups by
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
    # PR (S5): source-truthful timestamps. NULL is honest — do NOT
    # fall back to wall-clock NOW. The source-truthful extractor will
    # return None for missing values, and the SOURCED_FROM edge MIN/MAX
    # CASE preserves any prior value.
    "first_seen": upstream_data.get("first_reported_at") or None,
    "last_seen":  upstream_data.get("last_reported_at")  or None,
    # ...
})
```

### 3. Verify MISPWriter passthrough fires for your entity type

The `_apply_source_truthful_timestamps` helper in `src/collectors/misp_writer.py` is called from all 7 `create_*_attribute` methods (indicator, vulnerability, malware, actor, technique, tactic, tool) AS THE LAST STATEMENT before `return attribute`. If you add a NEW entity type, you must add the helper call to its `create_*_attribute` method too — commit `9a414ac` had to add it for 5 entity types that had been missed. The helper uses `coerce_iso` to accept int epochs, datetime objects, and date-only strings.

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

_Last updated: 2026-10-15 — § 2 NVD: every CVSS version NVD supplies is kept; `attack_vector` is NVD's word for the scoring CVSS's attack vector (`None` without CVSS), and the KEV, OTX and ICS records send none; the NVD_META digest ignores `attack_vector`; § 7 SSL Blacklist: fingerprints are collected as `x509-fingerprint-sha1` (MISP type `x509-fingerprint-sha1`, `[x509-certificate:hashes.'SHA-1' = …]` in STIX) instead of `sha1` file hashes; what reaches the graph; overview: "MISP push: attribute types and characters" (generic hashes typed by digest length, 4-byte characters stripped or the attribute skipped and counted as failed, default TLP at sync for an untagged attribute); § 1 OTX indicator types (non-file hashes not collected, e-mail addresses typed as e-mail); § 3 KEV baseline scope (whole catalogue) and ransomware use without a derived score; the source-truthful helper note no longer names a review tool; after #189: the OTX baseline page ceiling is the forwarded setting `EDGEGUARD_OTX_BASELINE_MAX_PAGES` (removed from the planned list). Prior: 2026-10-14 — § 2 NVD incremental runs: a stored lastModified cursor instead of the newest 200 by publication date; stored CVEs NVD changed are edited in MISP; duplicate avoidance describes the cross-event check. Prior: 2026-10-14 — CVE scores: the NVD rule (first CVSS in the order v3.1 → v3.0 → v2 → v4.0, `None` / `UNKNOWN` without CVSS), OTX references, KEV and ICS records without CVSS carry no score (no more ransomware-derived 9.0 / 7.0 or 7.0 default). Prior: 2026-10-12 — § 13 MalwareBazaar collector (flag-guarded abuse.ch source: recent export, sha256 per sample, family label → `INDICATES`), summary and baseline-limit rows. Prior: 2026-04-26 — PR-N33 docs audit: removed all 11 occurrences of the dead `last_updated` key from per-collector example dicts (the doc itself says at L71 "PR-M2 removed `last_updated` from collector emit"; the example dicts were stale and contradicted the rule). Replaced with explanatory comments referencing PR-M2. Prior: 2026-04-18 chip 5a refactor._
