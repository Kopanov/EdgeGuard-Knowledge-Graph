# EdgeGuard-Knowledge-Graph — Bugbot Review Rules

---

## Architecture & Data Flow (read this first)

EdgeGuard is a **security-critical** graph-augmented threat intelligence pipeline. Every piece of data follows one mandatory path:

```
External Sources → Collectors → MISP (single source of truth) → Neo4j Knowledge Graph
                                                                      ↕
                                                        REST API (port 8000)  +  GraphQL API (port 4001)
```

- **Collectors** (`src/collectors/`) fetch from OTX, NVD, CISA, MITRE ATT&CK, VirusTotal, AbuseIPDB, ThreatFox, URLhaus, Feodo, SSLBlacklist and, behind their enable flags (2026-10), CISA ICS and MalwareBazaar
- **MISP** is the only place collector output lands first — no collector writes directly to Neo4j
- **Neo4j (primary path):** `src/run_misp_to_neo4j.py` syncs from MISP. **Optional CLI path:** `run_pipeline.py` with STIX flow calls `load_stix21_to_neo4j()` — still not collector→Neo4j direct writes
- **Optional allowlist:** `EDGEGUARD_COLLECT_SOURCES` — canonical names in `src/collector_allowlist.py` (import this from DAGs at parse time, **not** `collectors/__init__.py`, which loads every collector)
- **REST API** (`src/query_api.py`) — external-facing read API on port 8000
- **GraphQL API** (`src/graphql_api.py`) — Strawberry-based API on port 4001 mirroring ISIM's interface
- **Airflow DAGs** (`dags/`) orchestrate scheduled collection and sync
- **Sector zones**: `global`, `healthcare`, `energy`, `finance` — only valid values
- **Node types**: Indicator, Vulnerability, CVE, CVSSv40 / CVSSv31 / CVSSv30 / CVSSv2 (CVE sub-nodes), Malware, ThreatActor, Technique, Tactic, Campaign, Tool, Sector, Source, Alert — `Tool` represents MITRE ATT&CK software tools (distinct from Malware)
- **MISP/PyMISP version compatibility**: `src/misp_health.py` performs a version detection check; flag any code that assumes a specific PyMISP API without guarding against version differences
- **Historical windows**: the same for every sector — `baseline_days` (default 730 days = 24 months) for a baseline, the source's incremental window otherwise; CISA KEV and the NVD KEV sweep take the whole catalogue on purpose. No collector filters by sector (see "Historical window / collection limit exceeded")
- **Resilience**: circuit breakers and retry logic protect all external calls
- **Provenance invariant**: every node EdgeGuard creates from a source record carries `first_imported_at`, `source[]`, `edgeguard_managed = true` (set on create; a node another system created that EdgeGuard writes to gets `edgeguard_enriched = true` instead) and a `SOURCED_FROM` edge to its `Source` node. Derived nodes (Campaign, Sector, the CVSS sub-nodes) carry `edgeguard_managed = true` and no `SOURCED_FROM` edge. MISP-originated nodes accumulate `misp_event_ids[]` / `misp_attribute_ids[]` (there is no scalar `misp_event_id`)
- **ResilMesh deployment**: EdgeGuard runs on the same server as ResilMesh — port isolation and `edgeguard_managed` tagging are mandatory

Review every change against these principles. Flag anything that violates them.

---

## 1. SECURITY — Blocking

### Hardcoded credentials
Flag any literal API key, password, token, or secret hardcoded in source code, config files, or Dockerfiles.
Env vars (`os.getenv(...)`) and `.env.example` placeholders are fine. Actual values are not.

### Exception details leaked to HTTP callers
In `src/query_api.py`, `HTTPException(detail=...)` must never contain `str(e)`, exception messages, stack traces, file paths, or internal system details.
Always return a generic message and log the full error server-side with `exc_info=True`.

### Cypher injection
In `src/neo4j_client.py`, `src/run_misp_to_neo4j.py`:
- Node labels interpolated into f-strings must call `_validate_label()` first
- Property names interpolated into f-strings must call `_validate_prop_name()` first
- Values must always be passed as Cypher parameters (`$param`), never concatenated
- Flag any f-string Cypher query where the interpolated part could originate from external data

### Bare `except:` clauses
`except:` with no exception type catches `SystemExit` and `KeyboardInterrupt` — never allowed.
`except Exception: pass` that swallows errors silently is also a bug — at minimum log it with `exc_info=True`.

### SSL verification disabled globally
`urllib3.disable_warnings()` called unconditionally at module level silences MitM warnings for the entire process.
It must only appear inside an `if not SSL_VERIFY:` guard.

### Unvalidated zone values written to Neo4j or MISP
Zone/sector values from external sources (MISP tags, API responses, config) must be filtered through
`VALID_ZONES = {'global', 'healthcare', 'energy', 'finance'}` before being stored anywhere.
Flag any code that writes a zone value without validation.

### Credentials in Docker image
`COPY credentials/` in a Dockerfile bakes secrets into image layers permanently.
Credentials must be injected at runtime via `--env-file` or Docker secrets.

### Admin Cypher endpoint
The `/admin/query` endpoint must always use `default_access_mode="READ"` and must block write keywords
(CREATE, MERGE, DELETE, DETACH, SET, REMOVE, DROP, CALL apoc.*).
Flag any change that weakens these guards.

### New API endpoint missing authentication
Every new `@app.get` or `@app.post` route (except `/health`) must include `dependencies=[Depends(_verify_api_key)]`.
This applies to both `src/query_api.py` (REST) and `src/graphql_api.py` (GraphQL).

### New API endpoint missing rate limiting
Every new endpoint must be decorated with `@limiter.limit(...)`.
The GraphQL `/graphql` route is a single endpoint but can be abused with deeply nested queries — see Section 12 for GraphQL-specific guards.

### User input logged verbatim
Query strings, indicator values, or zone parameters from API requests must not be logged at INFO level.
Log at DEBUG only, and strip newlines (`\n`, `\r`) before any logging to prevent log injection.

### Threat model — source identity (chip 5e)
EdgeGuard's source-truthful timestamp pipeline (PR #41) trusts the source identity carried in MISP attribute tags (`raw_data.original_source` / event-tag-resolved `source_id`). The trust boundary is the MISP write surface, not just EdgeGuard's collector accounts:
- Compromised MISP user account in a shared MISP deployment.
- Third-party feed pushing into a MISP that EdgeGuard also reads.
- Internal user manually adding an attribute and (mis)tagging it with a "trusted" source name.

Defense-in-depth lives in `src/source_trust.py`: a parent-event creator-org allowlist (`EDGEGUARD_TRUSTED_MISP_ORG_UUIDS` / `EDGEGUARD_TRUSTED_MISP_ORG_NAMES`). When configured, `extract_source_truthful_timestamps` refuses claims whose `event["Orgc"]` isn't on the allowlist — IOC ingest still succeeds, only the source-truthful timestamp claim is dropped + the `edgeguard_source_truthful_creator_rejected_total` Prometheus counter increments.

When neither env var is set, the check is BYPASSED (backward-compat for pre-release / dev). PRs that:
- Widen the trust surface (e.g. accept claims without `Orgc`, default the allowlist to `*`, weaken the case-insensitive comparison, or call `extract_source_truthful_timestamps` without plumbing `event_info` through from `parse_attribute`) — flag as a Tier-S deploy blocker.
- Add a NEW `extract_source_truthful_timestamps(...)` callsite without the `event_info=` kwarg — flag MED, the trust check is silently disabled for that path.
- Remove the `creator_org_missing` rejection (treating "no Orgc" as trusted) — flag HIGH, lets unattributable events claim authoritative status.

Per-attribute creator_user (`MISPAttribute` doesn't expose this directly — only the parent event's `Orgc` is reliably available across PyMISP versions) is a deliberate non-goal until MISP's REST surface stabilizes.

---

## 2. COLLECTORS — Blocking

### Collector bypasses MISP
All collectors must write to MISP via `self.misp_writer` before any data reaches Neo4j.
Flag any collector that calls `neo4j_client` methods directly or writes graph data without going through MISP first.

### New collector missing MISP writer
Any new `*_collector.py` file must accept `misp_writer` as a constructor parameter and call it during collection.

### API key required but not checked at startup
For **optional** third-party feeds (OTX, VirusTotal, AbuseIPDB, ThreatFox — NVD works without a key, with slower rate limits), `collect(..., push_to_misp=True)` must:
1. Detect a missing/placeholder key before hammering the API (**ThreatFox** requires a free key from abuse.ch; skip with `missing_threatfox_key` if unset)
2. On **HTTP 401/403** or “invalid API key” responses, treat like optional failure: **`success=True`, `skipped=True`** with a `*_auth_denied` **`skip_reason_class`** (see `is_auth_or_access_denied` in `collector_utils.py`) so the DAG does not fail
3. Log a clear `WARNING` and return **`make_status(..., success=True, skipped=True, skip_reason, skip_reason_class)`** so Airflow **`run_collector_with_metrics`** records **`edgeguard_collector_skips_total`**
Flag collectors that return **`success=False`** for “no key” on optional sources, or that raise unhandled exceptions for auth failures on those feeds.

### New collector missing from `EDGEGUARD_COLLECT_SOURCES` allowlist
When adding a collector wired through **`run_collector_with_metrics`**, add its canonical task name to **`COLLECT_SOURCES_CANONICAL`** in **`src/collector_allowlist.py`** (and document in **`docs/AIRFLOW_DAGS.md`**). Otherwise operators cannot include it in **`EDGEGUARD_COLLECT_SOURCES`**.

### No pre-flight connectivity check
Before starting a full collection run, the collector should verify that the source is reachable.
Flag collectors that make 50+ API calls with no up-front connection test — a failed DNS lookup at item #1000 wastes all prior work and time.

### Collector missing circuit breaker
All external HTTP calls in collectors must be protected by a circuit breaker from `src/resilience.py`.
Flag HTTP calls that have no circuit breaker state check. A circuit breaker prevents hammering a failing API with hundreds of retries.

### Collector missing retry logic
Network requests must use `@retry_with_backoff` from `src/collectors/collector_utils.py`.
Flag bare `requests.get/post` calls not wrapped in a retry-decorated method.

### Collector missing rate limiter
Each collector must use `RateLimiter` from `src/collectors/collector_utils.py`.
Flag any collector that makes network calls without rate limiting. Also flag if the configured rate limit does not match the documented limit in `docs/DATA_SOURCES_RATE_LIMITS.md`.

### Rate limit values do not match documented source limits
If a `RateLimiter` or sleep interval is changed, verify the new value still respects the upstream source's documented API limit.
Flag any rate limiter value that is more aggressive (higher frequency) than the source allows.

### Historical window / collection limit exceeded
How far back a collector reaches comes from the run, not from the collector: `baseline_days` in baseline mode (default 730 days = 24 months, the same for every sector; `BASELINE_DAYS` / `--days`) and the source's incremental window otherwise. No collector filters by sector or on `SECTOR_TIME_RANGES` (2026-10). NVD and OTX apply the window in the request; CISA KEV takes its whole catalogue in every run (2026-10); CISA ICS downloads more and filters by `baseline_days` / its incremental days.

Flag any collector that uses a hardcoded absolute date instead of a relative offset from `datetime.now()`, or that hardcodes a lookback instead of taking `baseline_days` / its incremental window. Taking a whole catalogue on purpose (every CISA KEV run and the NVD KEV sweep, `docs/DATA_SOURCES.md`) is not a lookback violation.
Flag any comparison of a timestamp parsed from a source payload with a timezone-aware datetime when the parsed value is not normalised first (`tzinfo is None` → UTC). NVD and OTX send timestamps without a zone; the comparison raises `TypeError`, and inside a broad `except` the check silently never runs (the former NVD/OTX sector time-range filter, removed 2026-10).
Flag any collector that ignores `resolve_collection_limit` / `get_effective_limit` (env: `EDGEGUARD_MAX_ENTRIES`, `EDGEGUARD_INCREMENTAL_LIMIT`). Sources in `config.OWN_RUN_CAP_SOURCES` (2026-10) apply their own per-run cap instead of `EDGEGUARD_INCREMENTAL_LIMIT` (`EDGEGUARD_<SOURCE>_MAX_PER_RUN`: MalwareBazaar 500, NVD 5,000 MISP writes, ThreatFox 10,000, URLhaus 50,000, Feodo 15,000, SSLBL 20,000, AbuseIPDB 10,000; CISA KEV compares its whole catalogue and caps only its edits, `EDGEGUARD_KEV_MAX_EDITS_PER_RUN`); `EDGEGUARD_MAX_ENTRIES` still overrides them. Flag a source added there without its own cap, or a cap that cuts below one run's window.

### Incremental cursor moved past work that did not reach MISP
A collector with an incremental cursor advances it only over work whose MISP writes succeeded: OTX to the last pulse it pushed, CISA ICS and NVD only after a run without a failed write. NVD (2026-10) also requires the lastMod window to have been read completely, counts an addition as written only when MISP's answer or a lookup by value (`MISPWriter.existing_values`) shows it stored, fails the task while the cursor cannot move, and moves the cursor at most to the record where `EDGEGUARD_NVD_MAX_PER_RUN` stopped the run. NVD's lastMod results must be read one answer per time slice (`_iter_lastmod_slices`), not paged across a window that changes while it is read.
Flag a cursor update that runs before, or regardless of, the result of the push or the edits. Flag an NVD change that brings back a newest-N selection by publication date (37% of new CVEs lost in a 30-day replay, 2026-10-14), or that re-adds a changed CVE as a new attribute instead of editing the stored one (`MISPWriter.update_attribute`). Flag a change to `Neo4jClient._replace_nvd_owned_cve_data` that clears list properties on a CVE node with a source other than NVD, or removes a CVSS sub-node another feed also asserted (an NVD record without that version takes `'nvd'` out of the `sources` of both `HAS_CVSS_*` edges and its event out of their `misp_event_ids` instead). Flag a change (2026-10) that lets a record other than NVD's set, rather than fill, `cwe`, `ref_tags`, `cpe_type`, `result_impacts`, `reference_urls` or `affected_products` on a CVE (`_NVD_OWNED_CVE_LISTS`), or set a property of a CVSS sub-node NVD has asserted (`'nvd'` in the `sources` of the CVE's `HAS_CVSS_*` edge to it, or the node's `tag` where the edge has no `sources`, `_cvss_legacy_sources_cypher`; `_merge_cvss_node` lets other feeds only fill it); that logs a CVE sub-write error without `merge_cve` returning False; or that passes an `NVD_META` CVSS payload to `_merge_cvss_node` without `_meta_cvss_payload` (a payload that is not an object or is left without a base score counts as absent; non-finite numbers, map / list values and `CVSS_PAYLOAD_RESERVED_NAMES` are dropped).

### Source revisions edited in place (2026-10)
Every CISA KEV run compares the whole catalogue with EdgeGuard's `source:CISA-KEV` copies and edits the copy of a revised entry in place, only through `src/collectors/vulnerability_update.py` (`plan_source_updates`, `push_additions`, `apply_vulnerability_edits`): one complete listing (a failed listing writes nothing), only copies in EdgeGuard events (`KnownAttribute.own_event`), each edit confirmed against the stored copy's timestamp (`written_after`), the refresh path's stop rules, and `EDGEGUARD_KEV_MAX_EDITS_PER_RUN`. A deferred edit is not a failure; a failed edit counts in the run's status.
Flag a KEV change that brings back a `dateAdded` window for incremental runs or the generic incremental limit, pushes a revised entry as a new attribute, edits a copy outside an EdgeGuard event, edits without `written_after` or outside the stop rules, or counts a deferred edit as failed. Flag a new `NVD_META` key written for every source or with an empty default: it changes the digest of every stored copy and edits each once; add a key only when the item carries it. Flag a change to `Neo4jClient.merge_cve` that lets a record other than CISA KEV's set `cisa_exploit_add`, `cisa_action_due`, `cisa_required_action` or `cisa_vulnerability_name` on a node that holds a value, or that writes a CVE's `SOURCED_FROM.raw_data` only when the edge is created for a record from a MISP attribute, or replaces it with the reduced record of the STIX import (`run_pipeline`, `refresh_raw_data=False`). Flag a KEV tag policy that detaches a tag EdgeGuard does not write: `KEV_REPLACED_TAGS` names the families `severity:` and `cvss:` and the one tag `ransomware:known`, never the whole `ransomware:` namespace (an analyst's taxonomy tags).

### Collector missing status return
Every `collect()` method must return a status dict using `make_status()` from `src/collectors/collector_utils.py`.
Flag collectors that return `None`, `{}`, or ad-hoc dicts that don't match the standard schema.

### Duplicate source registration
A new source needs its own `Source` entry in `_REGISTRY` in `src/source_registry.py` (canonical id, aliases, MISP tag, `reliability`, `source_type`). `neo4j_client.SOURCES`, the sync's `MISPToNeo4jSync.SOURCE_MAPPING` (`src/run_misp_to_neo4j.py`, via `misp_tag_to_canonical_map()`) and `MISPWriter.SOURCE_TAGS` derive from it, and its `reliability` orders it in the description ranking (`src/description_ranking.py`).
Flag any source that reuses another source's canonical id / `source_id` (e.g., a new feed incorrectly mapped to `abuseipdb`).

---

## 3. MISP DATA QUALITY — Blocking

### Required MISP metadata
The day event `EdgeGuard-{source}-{date}` carries the single event tag `EdgeGuard`; sources and zones are not event tags. Every attribute EdgeGuard writes carries:
- **Source tag**: `MISPWriter.SOURCE_TAGS` (derived from `source_registry`, e.g. `source:AlienVault-OTX`), or `source:<name>` for a source the registry does not know
- **Zone tags**: `zone:<Zone>` for each of the item's specific zones, `zone:Global` when it has only global or none (`_get_zones_to_tag`)
- **TLP tag** (2026-10): `tlp:<level>` (`_tlp_tag`: the item's or the OTX pulse's level, else `EDGEGUARD_DEFAULT_TLP`, default `white`)

No attribute carries a `collection_date` or `last_updated` value: MISP's own attribute `timestamp` records the last write, and an in-place edit is confirmed against it (`written_after`).

Flag a writer path that builds an attribute without its source, zone or TLP tag, and an event given source, sector or zone tags.

### Overwriting with corrupt or empty data
Before updating an existing MISP event or attribute:
- Validate that the new value is not `None`, empty string `""`, `"unknown"`, `"N/A"`, or a bare IP placeholder like `0.0.0.0`
- Validate that dates are in a sensible range (after year 2000, not in the future)
- Validate that CVE IDs match the pattern `CVE-YYYY-NNNNN`
- Validate that IP addresses are valid (use `ipaddress` stdlib, not string checks)

Flag any merge/update path that does not validate the incoming value before overwriting.

### Duplicate event creation
Events are created only through `MISPWriter._get_or_create_event(source, date)`: one event `EdgeGuard-{source}-{date}` per source and UTC day of the push (zones live on attribute `zone:` tags). It finds the day's event through `_restsearch_events_for_name`: `/events/restSearch` with `eventinfo` (an exact match from MISP 2.4.177 on) and `metadata: true`, paged until a row matches or a page comes back short, at most `EVENT_LOOKUP_MAX_PAGES` pages, then the exact `Event.info` match. It creates an event only inside `_cross_process_event_creation_lock` after a second lookup, never after a failed or capped lookup (`MispLookupError`), and `push_items` looks up an event only for a (source, date) group with at least one attribute left to write (2026-10).
Flag a collector that creates events directly, a lookup that filters by anything other than `eventinfo` (the earlier `info` key is not a restSearch parameter: MISP answered the first events of the store and a duplicate same-day event was created), asks for full events or reads one page only, and an event created after a lookup error — duplicates inflate MISP with redundant events and corrupt provenance tracking.
In `fetch_edgeguard_events` (2026-10), flag an event listing not de-duplicated by event id, paging that continues after a page that brings no new event, and a listing reported complete after a failed page, a cut at the page cap or a page-1 payload that is not a listing: the run must fail, so the sync cursor is not stamped past events never listed.

### `imported_at` / `first_seen` overwritten on re-import
Original import timestamps (`imported_at`, `first_seen`) must be set with `ON CREATE SET` semantics — written once and never updated.
Flag any code path that overwrites these timestamps on subsequent imports of the same record.

### MISP health check insufficient
`src/misp_health.py` must verify:
1. Network connectivity to the MISP URL
2. Valid authentication (API key accepted)
3. MISP API version is compatible

**Product semantics:** **`healthy`** and **`healthy_for_collection`** both mean **API + DB OK**; **workers are optional** for sync/collectors. Stricter “require workers” belongs in DAGs via **`EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS`** (see **`dags/edgeguard_pipeline.py`**), not by forcing **`healthy=False`** when only workers fail.

Flag health checks that rely on substring matching like `'health' in str(response).lower()` — almost any response body (including error pages) can contain the word "health", producing false positives.
Flag health checks that do not record their result as a Prometheus metric.

### MISP Prometheus scrape target is wrong endpoint
The Prometheus scrape job for MISP must target a metrics-formatted endpoint, not a JSON API endpoint.
Scraping a JSON endpoint produces parse errors and no usable metrics. Flag any configuration that points a `scrape_config` at a MISP REST API URL.

### MISP event list / event view must be normalized before `event.get("id")`

**`fetch_edgeguard_events`** should prefer **paginated `GET /events/index`** (then **`/events`**) + client-side EdgeGuard filter before falling back to PyMISP **`restSearch`** (heavy on huge events). PyMISP `search` and REST index responses often use **`{'Event': {…}}`** or **`response` / `events`** wrappers. Code that does `event.get("id")` on the outer dict gets **`None`**, skips detail fetch, and can make sync **“succeed” with zero Neo4j writes**.

**Required patterns** (see `src/run_misp_to_neo4j.py`):
- **`normalize_misp_event_index_payload()`** after every fetch in **`fetch_edgeguard_events`**
- Sync **`requests.Session`** must send **`Accept: application/json`** (and **`Authorization`**) so MISP returns JSON, not login HTML
- **`misp_event_object_to_event_dict()`** for **`get_event`** / REST view — if PyMISP returns an object, convert via **`to_dict()`**; always fall back to REST when conversion fails
- **`coerce_misp_attribute_list()`** before iterating **`Attribute`** (single dict vs list)
- **`normalize_misp_tag_list()`** before **`tag.get("name")`** loops (tags may be strings)

Flag any new MISP→sync code that assumes a flat event dict without normalization.

### MISP attribute comment sentinels must stay paired (writer ↔ `parse_attribute`)

| Prefix | Writer | Reader |
|--------|--------|--------|
| **`NVD_META:`** | `misp_writer.create_vulnerability_attribute` | `run_misp_to_neo4j.parse_attribute` (vulnerability) |
| **`MITRE_USES_TECHNIQUES:`** | `misp_writer.create_malware_attribute`, `create_actor_attribute`, `create_tool_attribute` (actors also carry `uses_malware` / `uses_tools` as keys `m` / `s`) | `run_misp_to_neo4j.parse_attribute` → **`uses_techniques`** on **`merge_malware`** / **`merge_actor`** / **`merge_tool`** |
| **`MITRE_TACTIC_PHASES:`** | `misp_writer.create_technique_attribute` | `run_misp_to_neo4j.parse_attribute` (`tactic_phases`) |
| **`OTX_META:`** (2026-10) | `misp_writer.create_attribute` (OTX items) | `run_misp_to_neo4j.parse_attribute` (pulse malware families, ATT&CK ids, several-actor marks) |
| **`TF_META:`** (2026-10) | `misp_writer.create_attribute` (ThreatFox items) | `run_misp_to_neo4j.parse_attribute` |

Flag new embedded JSON sentinels added on one side without the other, or truncation that breaks JSON parsing.

### `EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE` (`sync_to_neo4j`)

Default **`500`** (Python-side chunk size). **`0`** or **`all`** (case-insensitive) = **single pass** over the sorted item list — same peak-memory shape as unchunked sync (**OOM risk** on large backfills). Flag changes to **`_parse_neo4j_sync_chunk_size`** / **`sync_to_neo4j`** without updates to **`.env.example`**, **`README.md`**, **`docs/AIRFLOW_DAGS.md`**, and related ops docs.

### STIX 2.1: never put `labels` on Cyber-observable Objects (SCOs)

STIX 2.1 does not define **`labels`** on SCO types (`ipv4-addr`, `domain-name`, `file`, `url`, …). The PyMISP **`to_stix2()`** bundle path must call **`apply_edgeguard_zone_metadata_to_stix_dict()`** so zones go to **`x_edgeguard_zones`** on SCOs and **`labels`** only on SDOs.

Flag any change that adds **`labels`** to SCO dicts in **`convert_to_stix21()`** or strips **`x_edgeguard_zones`** from observables consumed by **`run_pipeline._extract_zones_from_stix_labels`**.

---

## 4. ZONE & ENRICHMENT INTEGRITY — Blocking

These rules were derived from runtime-confirmed bugs found via debug instrumentation (`scripts/debug_zone_check.py`). Each rule has a failing test case as evidence.

### Zone combination must merge, not replace

In `run_misp_to_neo4j.py`, `convert_to_stix21()` and `_manual_convert_to_stix21()`, the zone combination block must **merge** both sources:

```python
# CORRECT: merge, prefer specific sectors over global
all_zones = set()
if zone_from_name:
    all_zones.add(zone_from_name)
for z in zones_from_tags:
    all_zones.add(z)
specific = {z for z in all_zones if z != "global"}
event_zones = sorted(specific) if specific else ["global"]
```

Flag any version that uses `if zone_from_name: event_zones = [zone_from_name]` — this silently discards tag-sourced zones. Example failure: event name=`FINANCE` + tag `zone:healthcare` → should produce `['finance','healthcare']`, not `['finance']`. The same applies when `zone_from_name='global'` — the specific tags must win over the generic name.

### `parse_attribute` must use all three zone sources with priority layers

In `run_misp_to_neo4j.py`, `parse_attribute()`, zone resolution must follow this priority:
1. If the **attribute itself** has specific zone tags → use those exclusively (most precise)
2. Otherwise → merge event-level `Tag` zones + event name (all three sources)

```python
# CORRECT priority layers
zones_from_attr = self.extract_zones_from_tags(tags)
specific_from_attr = [z for z in zones_from_attr if z != "global"]
if specific_from_attr:
    zones = sorted(specific_from_attr)   # attribute zone wins
else:
    _az = set(zones_from_attr)
    for z in self.extract_zones_from_tags(event_info.get("Tag", [])):
        _az.add(z)
    zone_from_name = self._extract_zone_from_event_name(event_info.get("info", ""))
    if zone_from_name:
        _az.add(zone_from_name)
    specific = {z for z in _az if z != "global"}
    zones = sorted(specific) if specific else ["global"]
```

Flag any version that checks only `event_info.get("info")` (event name) as fallback without also consulting `event_info.get("Tag")`. Example failure: attribute with no zone tag, event has `Tag: [{"name":"zone:healthcare"}]`, event name is `GLOBAL` → should produce `['healthcare']`, not `['global']`.

### ThreatActor→Technique EMPLOYS_TECHNIQUE must use `uses_techniques` list, not `misp_event_id` co-occurrence

In `build_relationships.py`, the query linking `ThreatActor` to `Technique` must match on `a.uses_techniques` and use the specialized rel type `EMPLOYS_TECHNIQUE` (prior to 2026-04 this was a generic `USES`; see [`docs/KNOWLEDGE_GRAPH.md`](../docs/KNOWLEDGE_GRAPH.md#technique-edges-attribution-vs-capability-vs-observation) — pre-release framework, no migration script shipped; a fresh baseline rerun writes the specialized edge type directly):

```cypher
// CORRECT
MATCH (a:ThreatActor), (t:Technique)
WHERE t.mitre_id IN coalesce(a.uses_techniques, [])
MERGE (a)-[r:EMPLOYS_TECHNIQUE]->(t)
SET r.confidence_score = 0.95, r.match_type = 'mitre_explicit'
```

Flag any version using `WHERE a.misp_event_id = t.misp_event_id` for this relationship — MITRE ATT&CK actors and techniques always come from separate MISP events, so `misp_event_id` never matches and this query always returns 0. Confirmed bug: the co-occurrence approach produced zero edges in all test runs.

Also flag any new code that emits the legacy `USES` rel type for Actor→Technique. The backward-compat `rel_type="USES"` shim in `create_misp_relationships_batch` was removed (PR-N1); `EMPLOYS_TECHNIQUE` / `IMPLEMENTS_TECHNIQUE` rows must name `from_type` (a row without it is dropped with a warning).

### `uses_techniques` must be populated in the MITRE collector

In `src/collectors/mitre_collector.py`, the actor item dict must include `uses_techniques` populated from the STIX relationship objects:

```python
# CORRECT: build lookup from self.relationships before constructing actor list
_actor_uses = {}
for rel in self.relationships:
    if rel["type"] == "uses" and rel["source_type"] == "actor":
        _actor_uses.setdefault(rel["source_name"], []).append(rel["target_mitre_id"])

# Then on each actor:
actors.append({
    ...
    "uses_techniques": _actor_uses.get(actor_name, []),
})
```

Flag any MITRE collector that sets `self.relationships` (the parsed STIX relationships list) but does not propagate it into **both** actor **and** malware item dicts (`uses_techniques` from `_actor_uses` / `_malware_uses`). `self.relationships` as a standalone instance variable with no consumers is dead code.

### Malware→Technique IMPLEMENTS_TECHNIQUE must use `uses_techniques` on Malware — never `CONTAINS`

Same source as ThreatActor: explicit STIX **`uses`** (malware → attack-pattern). In `build_relationships.py` the graph edge is the specialized `IMPLEMENTS_TECHNIQUE` (capability semantic, vs `EMPLOYS_TECHNIQUE` which is the attribution semantic for actors — see the note above):

```cypher
MATCH (m:Malware), (t:Technique)
WHERE t.mitre_id IN coalesce(m.uses_techniques, [])
MERGE (m)-[r:IMPLEMENTS_TECHNIQUE]->(t)
SET r.confidence_score = 0.95, r.match_type = 'mitre_explicit'
```

The MITRE collector must populate **`uses_techniques`** on each malware dict from `_malware_uses`. `misp_writer.create_malware_attribute` must embed **`MITRE_USES_TECHNIQUES:`** JSON in the attribute comment when non-empty so `run_misp_to_neo4j` can restore the property on **`merge_malware`**. **`neo4j_client.merge_malware`** must pass **`uses_techniques`** in `extra_props`.

Flag any **`CAN_USE`** relationship or fuzzy name/description matching between Malware and Technique — that pattern was removed as a hallucination risk.

### Zone lists come from `VALID_ZONES`

Event names carry no zone (`EdgeGuard-{source}-{date}`): `_extract_zone_from_event_name()` in `run_misp_to_neo4j.py` always returns None, and zones come from `zone:` tags (`extract_zones_from_tags`, checked against `config.VALID_ZONES`).

Flag any new hard-coded zone list instead of an import of `VALID_ZONES`.

### Zone values must be validated before storing in Neo4j or MISP

All zone values resolved from any source (MISP tags, event names, text detection) must be checked against `VALID_ZONES = frozenset({"global", "healthcare", "energy", "finance"})` before any `MERGE` or MISP push. Unrecognised zone values create orphaned Sector nodes and corrupt zone-filtered queries. This is already enforced in `extract_zones_from_tags()` — flag any new code path that bypasses this check.

---

## 5. FALSE POSITIVES & HALLUCINATIONS — Blocking

These rules guard against the most dangerous class of bugs in threat intelligence systems: logic that *looks* correct but silently produces fabricated or spurious intelligence. False positives mislead analysts into investigating non-threats. Hallucinated relationships corrupt the graph and erode analyst trust permanently.

### Substring / `CONTAINS` matching must never be used to infer relationships

Text-based matching (e.g., `WHERE indicator.value CONTAINS malware.name`) always produces hallucinated relationships. An IP address like `1.2.3.4` will never correctly "contain" the string `Emotet`, and a CVE description containing the word "bank" does not mean that CVE targets the finance sector.

Flag any relationship-building query in `build_relationships.py`, `run_pipeline.py`, or `run_misp_to_neo4j.py` that uses `CONTAINS`, `STARTS WITH`, or Python `in` string checks to link two threat intelligence entities. The only acceptable linking methods are:
- **Explicit source data**: `uses_techniques` on **ThreatActor** and **Malware** (MITRE STIX), `cve_id` tag, `misp_event_id` shared between nodes within the same tightly-scoped event
- **Shared unique identifiers**: CVE ID, MITRE technique ID, hash value, exact domain/IP match

### Co-occurrence relationships require event size guard

Creating relationships between all indicators co-occurring in a MISP event is valid for small, targeted reports — but a bulk feed event with 500+ attributes would generate O(n²) spurious edges, all labelled as intelligence.

Any co-occurrence relationship builder (e.g., `_build_cross_item_relationships`, `build_relationships.py` co-occurrence queries) must check the event size before creating edges. Flag any code that creates co-occurrence relationships without a size cap or without reading event attribute count first:

```python
# CORRECT: only link entities from small, focused events
if len(event_attributes) <= MAX_COOCCURRENCE_EVENT_SIZE:  # e.g., 50
    # create INDICATES, EXPLOITS, etc.
```

Flag any co-occurrence loop that processes events of unlimited size — this is the single largest source of hallucinated graph edges.

### Confidence score must reflect actual evidence quality

Assigning a static `confidence_score = 0.8` to every node regardless of source quality inflates confidence uniformly and makes the score meaningless for triage. Each collector must set confidence based on concrete criteria:

| Evidence type | Acceptable score range |
|---------------|----------------------|
| MITRE ATT&CK explicit STIX relationship | 0.90 – 0.95 |
| Confirmed vulnerability with CVSS ≥ 9.0 | 0.85 – 0.95 |
| Multi-source corroboration (≥ 2 sources) | 0.70 – 0.85 |
| Single commercial feed (OTX, VT) | 0.50 – 0.70 |
| Co-occurrence inference | 0.30 – 0.50 |
| Text keyword detection only | 0.10 – 0.30 |

Links to a `Sector` take their confidence from `sector_evidence.LABEL_CONFIDENCE` (`zone_classification` 0.5, `advisory_sector` 0.9; 2026-10), not from this table.

Flag any node or relationship that hardcodes a confidence score above `0.70` for data that has not been explicitly corroborated by source material. Flag any relationship with `confidence_score > 0.80` and `match_type = 'misp_cooccurrence'` — co-occurrence is inherently weak signal.

### Generic entity names must never become graph nodes

Node keys like `"unknown"`, `"malware"`, `"trojan"`, `"backdoor"`, `"virus"`, `"actor"`, `"ransomware"`, or any single-character / empty string will match against thousands of unrelated records, causing massive false-positive enrichment cascades.

Flag any `MERGE` or `merge_node_with_source()` call where the primary key property could be one of these generic terms. Check the name with `node_identity.is_placeholder_name()` (`_REJECTED_PLACEHOLDER_NAMES`, which holds every term above) before writing, as `merge_malware` and `merge_actor` do (aliases are filtered the same way). Flag a new merge path for a name-keyed label that does not call it, and a second blocklist.

### Zone keyword false positives — single generic words must not trigger sector tagging

Using single common words as zone keywords (e.g., `"bank"`, `"power"`, `"care"`, `"medical"`) will match in unrelated contexts ("power off", "take care", "bank of results"). Zone keywords must be:
- Multi-word phrases preferred (e.g., `"power grid"`, `"banking trojan"`, `"medical device"`)
- Whole-word matched only (`re.search(r'\b' + re.escape(kw) + r'\b', text)`)
- Require minimum score threshold (≥ 2.0) when using weighted scoring

Flag any new zone keyword added to `SECTOR_KEYWORDS` in `config.py` that is a single common word (≤ 6 characters, no space) without a corresponding negative-keyword guard. Especially flag additions to the finance sector — words like `"card"`, `"pay"`, `"fund"` appear in non-financial threat intel constantly.

### Relationship direction must follow the semantic model

Incorrect edge direction silently produces wrong graph traversals. The canonical directions are:

```
(Indicator)   -[:INDICATES]->          (Malware)            # same OTX pulse (otx_pulse) or malware_family label (credited to FAMILY_LABEL_FEEDS)
(Indicator)   -[:EXPLOITS]->           (Vulnerability|CVE)
(Malware)     -[:ATTRIBUTED_TO]->      (ThreatActor)        # malware attributed to actor
(ThreatActor) -[:USES_MALWARE]->       (Malware)            # MITRE uses / curated claim; campaign evidence with ATTRIBUTED_TO
(ThreatActor) -[:USES_TOOL]->          (Tool)
(ThreatActor) -[:EMPLOYS_TECHNIQUE]->  (Technique)          # attribution: actor performs TTP (MITRE STIX uses)
(Campaign)    -[:EMPLOYS_TECHNIQUE]->  (Technique)          # campaign-level attribution (future)
(Malware)     -[:IMPLEMENTS_TECHNIQUE]->(Technique)         # capability: malware implements TTP
(Tool)        -[:IMPLEMENTS_TECHNIQUE]->(Technique)         # capability: tool implements TTP
(Indicator)   -[:USES_TECHNIQUE]->     (Technique)          # observation: IOC tied to TTP (OTX attack_ids)
(Technique)   -[:IN_TACTIC]->          (Tactic)
(ThreatActor) -[:RUNS]->               (Campaign)
(Malware|Indicator)-[:PART_OF_CAMPAIGN]-> (Campaign)     # PART_OF until 2026-10; PART_OF is ResilMesh's topology relationship (IP / Subnet / OrganizationUnit)
(Indicator)   -[:TARGETS]->            (Sector)
(Vulnerability|CVE)-[:AFFECTS]->       (Sector)             # sector from zone list (build_relationships)
```

**Sector links (2026-10-16).** Flag a write of a link to a `Sector` that names in `r.sources` (or copies `source_refs` / `misp_event_ids` from) a feed whose `SOURCED_FROM.zones` do not hold that sector: use `relationship_provenance.zone_prov_with`, never `prov_with(n, node_feeds(n))`, for a sector link. Flag `advisory_sector` anywhere but on `AFFECTS` from a CVE / Vulnerability whose `cisa_ics` record stated the sector (`sector_evidence.STATEMENT_LABELS`; a CISA advisory sector means "deployed in", never TARGETS), a hard-coded confidence on a sector link (it comes from `sector_evidence.LABEL_CONFIDENCE`), and a statement label whose confidence is not above `zone_classification`'s. A new `SOURCED_FROM` write site must set `zones`, `stated_zones` and `stated_refs` (`neo4j_client._sourced_zone_items`). Flag a sector link that cites every record of a stating feed instead of those recorded for its sector (`sector_evidence.zone_refs`, `stated_refs`), and a light copy of a parsed item (the paged sync's `_REL_KEYS`) that drops `stated_zones` or `stated_refs`.

> **2026-04 rename:** `EMPLOYS_TECHNIQUE` / `IMPLEMENTS_TECHNIQUE` were previously a single generic `USES` edge. The backward-compat `rel_type="USES"` shim in `create_misp_relationships_batch` was removed (PR-N1): `EMPLOYS_TECHNIQUE` / `IMPLEMENTS_TECHNIQUE` rows must name `from_type`, and a row without it is dropped with a warning. Flag any code that **emits** `USES` for a Technique edge; reads against both are fine.

Flag **`(ThreatActor)-[:ATTRIBUTED_TO]->(Malware)`** (reversed). Flag any relationship creation that reverses the rows above. Wrong `ATTRIBUTED_TO` direction makes traversals return empty results silently.

### Circular enrichment — a node must not be used to enrich itself

If the same source (`source_id`) has already been recorded in `n.source`, writing back properties derived only from that source does not constitute corroboration and should not increase `confidence_score`.

Flag any enrichment path where:
1. The enrichment query matches a node by its existing properties
2. The only new data comes from the same `source_id` already in `n.source`
3. The confidence score is raised as a result

This is a form of hallucination: the system convincing itself a piece of data is more reliable because it "confirmed" itself.

### Stale data re-import must not reset or boost `confidence_score`

Re-importing the same record from the same source (common during baseline collection) must neither lower a node's confidence nor undo an Indicator's aging: on labels other than Indicator a write keeps the higher `confidence_score` (max-wins); on an Indicator the higher value is kept in `source_confidence` and `confidence_score` is recomputed by the aging rule, so a re-import of an old report does not restore an aged confidence (only a newer report moves the basis; §14 "Confidence: max-wins per label", 2026-10-16). Flag a sync path that overwrites `source_confidence`, or a non-Indicator `confidence_score`, without comparing it with the stored value.

---

## 6. NEO4J DATA INTEGRITY — Blocking

### `CREATE` used instead of `MERGE` for nodes
All node creation in `src/neo4j_client.py` and `src/run_misp_to_neo4j.py` must use `MERGE`, not `CREATE`.
`CREATE` will produce duplicate nodes every time the sync runs. Flag every `CREATE (:Label {…})` that is not inside a `MERGE … ON CREATE SET …` pattern.

### `first_seen` / `imported_at` overwritten on update
Properties that record when a record was first seen must use `ON CREATE SET`, not `SET`.
`SET v.imported_at = timestamp()` overwrites the original value every sync. Flag it.

### `last_updated` not set on every sync
Every `MERGE` that modifies an existing node must include `SET node.last_updated = timestamp()` or equivalent.
Flag MERGE blocks that update properties but do not refresh `last_updated`.

### Source provenance array overwritten
The node property `source` (a list) must be appended to, not replaced:
```cypher
SET n.source = apoc.coll.toSet(coalesce(n.source, []) + $source_array)
```
Flag any `SET n.source = [value]` that discards the accumulated source history.

### Sector label never applied
After the sync, `Neo4jClient.apply_sector_labels()` (called once by `run_misp_to_neo4j`) adds the sector labels (`:Finance`, `:Healthcare`, `:Energy`) from each node's `zone` list, one statement per label of its `edgeguard_labels` list:
```cypher
MATCH (n:Indicator)
WHERE n.zone IS NOT NULL AND size(n.zone) > 0
WITH n, [z IN n.zone WHERE z <> 'global' | apoc.text.capitalize(z)] AS sectorLabels
WHERE size(sectorLabels) > 0
CALL apoc.create.addLabels(n, sectorLabels) YIELD node
RETURN count(DISTINCT node) AS labeled
```
The yielded variable must differ from the bound one. Flag removal of that call, and a new zoned node label missing from `edgeguard_labels`. Without the labels, sector-filtered Cypher queries return empty results.

### UNIQUE constraint missing for new node type
If a new EdgeGuard-owned node label is added, flag a missing `CREATE CONSTRAINT` in `Neo4jClient.create_constraints`. Missing constraints allow race-condition duplicates. Never add a UNIQUE constraint on a partner-owned label (`SHARED_LABELS_WITHOUT_UNIQUE_CONSTRAINT`: Device, NetworkService, SoftwareVersion, Application, Role, User; 2026-10): such a constraint made the partner's scanner writes fail, and `create_constraints` drops those constraints on every run.

### Direct string formatting in Cypher
Never build Cypher queries using `%` formatting, `.format()`, or f-strings with external data.
All variable data must go through parameterized queries (`session.run(query, {"param": value})`).

### Relationship `CREATE` instead of `MERGE`
Relationships between nodes must also use `MERGE` to avoid duplicate edges on repeated syncs.
Flag `CREATE (a)-[:REL]->(b)` patterns that are not inside a `MERGE` block.

### Empty or null identifier written as node key
Never write `None`, `""`, `"unknown"`, or `"N/A"` as the primary identifier of a node (e.g., `Indicator.value`, `Vulnerability.cve_id`, `ThreatActor.name`).
Flag any path where the key property could be empty before the `MERGE` is executed.

### `MATCH (n)` full-graph scan
`MATCH (n)` without a label scans every node in the database. In a large graph this is catastrophically slow.
Flag any Cypher query that uses `MATCH (n)` without a label constraint.

### `active`: set by the aging rule on Indicators, on create only elsewhere (2026-10-16)
A node that does not age gets `active = true` on its create path only (`neo4j_client._create_active`, in `merge_node_with_source` and `merge_vulnerabilities_batch`); a node write never changes `active` of a matched node, so a node another system created keeps its own lifecycle. An Indicator's `active`, `retired_at` and `retired_by` come only from `indicator_aging.aging_map` (`aging_set_clause`): a newer report reactivates a decay retirement in the same write; a manual decommission is kept. A Campaign's `active` follows its active indicators (`enrichment_jobs.build_campaign_nodes`: Step 1 sets it true, Step 4 false). Flag any other `active` write on the match path of a non-aging label, and an Indicator write that sets `active` / `retired_at` / `retired_by` other than through `aging_set_clause`.

### Merge functions must promote queryable properties to `extra_props`
Every merge function (`merge_cve`, `merge_vulnerability`, `merge_malware`, `merge_actor`, `merge_technique`, `merge_tactic`, `merge_tool`) must promote analyst-relevant fields to `extra_props` (or `fill_props`, for a field the current record only fills where the node has none) so they become queryable Neo4j node properties. Fields NOT in `key_props`, `extra_props` or `fill_props` go to `raw_data` on the SOURCED_FROM edge (a JSON blob invisible to Cypher queries).

Required promotions by node type:
- **CVE**: `known_ransomware_use`; `published`, `last_modified`, `cwe`, `ref_tags`, `cpe_type`, `result_impacts`, `reference_urls`, `affected_products` (set by NVD's record, filled by any other); `status`; the four KEV-owned `cisa_*` fields (set by CISA KEV's record, filled by any other). `cvss_score`, `severity`, `cvss_version` and `attack_vector` are NOT promoted from the record: `merge_cve` sets them from the CVSS sub-nodes (`_set_cve_score_from_cvss`, 2026-10). Flag any code that writes a CVE score from the record, from a `cvss:` tag, from a 0.0 placeholder or from another field (CISA KEV ransomware use, a collector default) — that is how 14,451 unscored CVEs showed as 3.0 / LOW. Likewise flag any code that writes a CVE's `attack_vector` from the record or invents one (`NETWORK`, `UNKNOWN`, a vector-string letter): it is NVD's word for the attack vector of the CVSS that gives the score, null without CVSS (`cvss_selection`); mixed values made `attack_vector = 'NETWORK'` match 3,305 of about 100,000 network-exploitable CVEs.
- **Vulnerability**: `cvss_score`, `severity`, `attack_vector`
- **Technique / Tactic**: `name`
- **Tool**: `name`, `aliases`
- **Malware**: `malware_types`, `aliases`, `uses_techniques`
- **ThreatActor**: `aliases`, `uses_techniques`, `sophistication`, `primary_motivation`, `resource_level`

`description` and `description_source` (2026-10-16) are never in `extra_props` or `fill_props` of a CVE, Vulnerability, Malware, ThreatActor, Tool, Technique or Tactic merge (`merge_node_with_source` raises `ValueError`): the merge passes `description=CVE_DESCRIPTIONS.record(...)` / `ENTITY_DESCRIPTIONS.record(...)`, so the fixed source ranking of `src/description_ranking.py` decides (CVE / Vulnerability: NVD > CISA KEV > CISA ICS > any other source; the other labels: MITRE ATT&CK > a curated source > any other source). A record replaces the text only when its source ranks at least as high as the stored text's, and `description_source` names that source. Flag a description written outside `DescriptionRanking.set_cypher` / `best_of_cypher` (alias and twin merges), and a new label with a description but no ranking.

Flag any new merge function that leaves `name` in raw_data only. Flag any change to a merge function that removes a field from `extra_props`.

### CVSS sub-nodes must filter None/empty values before SET
`_merge_cvss_node()` dynamically builds SET clauses from a dict. If the dict contains `None` or `""` values, they get SET as NULL on the Neo4j node, hiding valid data. The correct pattern is:
```python
filtered = {k: v for k, v in cvss_data.items() if v is not None and v != ""}
```
Flag any dynamic SET clause builder (CVSS or otherwise) that does NOT filter None/empty values before constructing the Cypher query.

### Numeric truthiness — never use `if score:` for floats
`if v.get("base_score"):` drops `0.0` (falsy in Python but a valid CVSS score). The correct pattern is:
```python
if v.get("base_score") is not None:  # keeps 0.0
```
Flag any `if data.get("score")`, `if data.get("confidence")`, `if data.get("base_score")`, or similar truthiness check on a numeric property. These silently drop zero values.

---

## 7. PYTHON CODE QUALITY — Non-blocking

### Bare `datetime.now()` without timezone — Blocking
All `datetime.now()` calls MUST use `datetime.now(timezone.utc)`. Bare `datetime.now()` without timezone is a blocking issue (Python 3.12 compatibility). `datetime.utcnow()` is also deprecated in Python 3.12 — use `datetime.now(timezone.utc)` instead. Flag any occurrence of `datetime.now()` or `datetime.utcnow()` that does not pass an explicit timezone.

### Silent exception swallowing
`except Exception: pass` hides real bugs. Flag any catch block that does nothing — at minimum `logger.debug(e, exc_info=True)`.

### Mutable default arguments
`def func(items=[])` is a classic Python bug — the list is shared across all calls.
Flag any function with a mutable default argument (list, dict, set).

### Unused imports
Flag imports that are not used anywhere in the file.

### Resource leak — unclosed connections
Neo4j driver sessions, MISP connections, and file handles opened with `open()` outside a `with` block
must be explicitly closed. Flag any resource opened without a context manager or explicit `.close()` in a `finally` block.

### Hardcoded magic numbers
Numeric literals used as limits, timeouts, or thresholds inline in logic (e.g., `if score > 0.7`) should be named constants.
Flag magic numbers that appear more than once or have unclear purpose.

### Dead code
Flag functions, classes, or imports that are defined but never called or used anywhere in the codebase.

### Missing type hints on new public functions
New public functions (not starting with `_`) should have parameter and return type hints.

---

## 8. AIRFLOW DAGS — Non-blocking

### `run_collector_with_metrics` must respect `EDGEGUARD_COLLECT_SOURCES`

At task start, if **`is_collector_enabled_by_allowlist(collector_name)`** is false, return **`make_skipped_optional_source`** with **`skip_reason_class=collector_disabled_by_config`** (do not run the collector). The DAG must import **`collector_allowlist`** from **`src/collector_allowlist.py`**, not from **`collectors`** package init.

### Neo4j sync DAG short-circuit vs real work

**`edgeguard_neo4j_sync`**: when **`check_sync_needed`** (ShortCircuitOperator) returns false, downstream **`run_neo4j_sync`**, **`build_relationships`**, and enrichment are **skipped** — a green run may mean no sync. Each writing task also skips on its own while a baseline holds the baseline lock (2026-10-16; §18 "Baseline lock"). Document/operator expectations must stay aligned with **`docs/AIRFLOW_DAGS.md`**.

### Dynamic start_date
`start_date = pendulum.now()` or any expression that changes on re-parse breaks Airflow scheduling.
`start_date` must be a fixed literal date like `pendulum.datetime(2025, 1, 1, tz="UTC")`.

### Missing execution_timeout on tasks
Tasks without `execution_timeout` hold worker slots indefinitely on network hangs.
Flag any `PythonOperator` or `BashOperator` without an `execution_timeout`.

### Lambda as python_callable
Lambdas cannot be pickled by Airflow's DAG serializer — use named functions or direct callables instead.

### Missing catchup=False
DAGs without `catchup=False` will backfill all missed runs since `start_date` on first deploy.

### Metrics server started at module level
`start_http_server()` or any `start_metrics_server()` call at DAG module level is forbidden.
Airflow re-parses DAG files every 30 seconds — module-level server starts will fail or bind duplicate ports.
The metrics server must only be started inside a task function.

### Credentials hardcoded in DAG
Passwords or API keys in DAG files are stored in Airflow's unencrypted DAG serialization.
Credentials must come from environment variables or Airflow Connections, not imported `config.py` values.

---

## 9. INFRASTRUCTURE — Non-blocking

### Docker service missing resource limits
Services in docker-compose files without `deploy.resources.limits.memory` can OOM the host.
Flag any new service without memory limits. Current limits: Prometheus 1 GB, Grafana 512 MB, Alertmanager 256 MB.

### Docker service missing healthcheck
New services in docker-compose files must have a `healthcheck` defined with a `start_period` so orchestrators
don't mark the service unhealthy before it finishes initializing.

### Environment variable with no entry in .env.example
Any new `os.getenv("NEW_VAR")` call must have a corresponding entry in `.env.example` with a description and example value.

### Prometheus admin API enabled
`--web.enable-admin-api` in docker-compose allows metric deletion and server shutdown.
Flag if this flag is re-enabled in `docker-compose.monitoring.yml`.

---

## 10. TESTING — Non-blocking

### New collector with no tests
Any new `*_collector.py` must have at least one test in `tests/` covering:
1. Successful collection returns valid status dict
2. MISP push is called
3. Missing API key is handled gracefully (no crash)
4. Network error / timeout is handled (circuit breaker or retry kicks in)

### New API endpoint with no tests
Changes to `src/query_api.py` that add or modify routes must have corresponding changes in `tests/test_query_api.py`.

### Test that doesn't assert anything
A test function with no `assert` statement (or mock assertion) is not actually testing anything. Flag it.

---

## 11. DOCUMENTATION — Non-blocking

### docs/COLLECTORS.md not updated for new collector
If a new collector file is added, flag if `docs/COLLECTORS.md` does not appear to be updated in the same PR.

### docs/DATA_SOURCES_RATE_LIMITS.md not updated for new source
If a new data source or rate limit value is added, flag if `docs/DATA_SOURCES_RATE_LIMITS.md` is not updated.

### README not updated for new env variable
If a new required environment variable is added (no default in `os.getenv`), flag if `README.md` and `.env.example` are not updated.

### Public function missing docstring
New public functions (not prefixed with `_`) in `src/` should have a docstring explaining purpose, parameters, and return value.

### RESILMESH_INTEROPERABILITY.md not updated for new integration touch-point
If a PR changes a port binding, relationship type, node label, property name, or zone value that affects ResilMesh's view of the graph, flag if `docs/RESILMESH_INTEROPERABILITY.md` is not updated in the same PR.

### Core graph docs for MITRE / `build_relationships` / MISP sync changes
If a PR changes **`build_relationships.py`**, **`mitre_collector.py`**, **`misp_writer`** comment sentinels, **`merge_malware` / `merge_actor`**, or MISP→Neo4j fetch/normalization, flag if these are not updated when behavior changes:
- `docs/KNOWLEDGE_GRAPH.md`
- `docs/ARCHITECTURE.md` (relationship table)
- `docs/RESILMESH_INTEROPERABILITY.md` (integration contract)
- `docs/DOCUMENTATION_AUDIT.md` (index row / refresh date if needed)

### `.env.example` and `docs/AIRFLOW_DAGS.md` for new operator env vars
If a PR adds environment variables operators must set (e.g. **`EDGEGUARD_COLLECT_SOURCES`**), flag missing entries in **`.env.example`** and **`docs/AIRFLOW_DAGS.md`** (or the doc that owns that feature).

---

## 12. GRAPHQL API — Blocking

### GraphQL resolver exposes exception details
In `src/graphql_api.py`, resolver functions must never return raw exception messages or stack traces to the caller.
Catch exceptions, log them server-side with `exc_info=True`, and raise a `strawberry.exceptions.GraphQLError` with a generic message.
Flag any resolver that passes `str(e)` or `repr(e)` into a GraphQL error response.

### GraphQL resolver bypasses the ownership filter
Every list resolver (indicators, vulnerabilities, CVEs, etc.) must restrict to `(n.edgeguard_managed = true OR n.edgeguard_enriched = true)`: nodes EdgeGuard created or enriched (2026-10; `_resolve_list` applies it while `NodeFilter.edgeguard_managed_only` is true, the default).
Flag any resolver that queries `MATCH (n:Label)` without this filter — it would expose ResilMesh-owned nodes EdgeGuard never wrote to EdgeGuard clients — and one that filters on `edgeguard_managed` alone (it hides partner CVEs EdgeGuard enriched).

### GraphQL Cypher query not parameterised
All Cypher in `src/graphql_api.py` must use `$param` placeholders passed to `session.run(query, **params)`.
Flag any f-string, `.format()`, or string concatenation used to build a Cypher query inside a resolver.

### GraphQL playground enabled in production
`EDGEGUARD_GRAPHQL_PLAYGROUND` must default to `false` and must only be `true` during development.
Flag any change that hardcodes `graphql_ide="graphiql"` without an env-var guard.

### GraphQL query depth not limited
Deeply nested GraphQL queries (e.g., Campaign → Indicator → Malware → ThreatActor → Technique…) can cause unbounded Neo4j traversals.
If a new type introduces a resolver that follows more than one graph hop, flag if there is no `LIMIT` clause in the Cypher.
All list-returning resolvers must have `LIMIT $limit` and `$limit` must be capped at a sane maximum (e.g., 1000).

### New GraphQL type has no test
Any new Strawberry type added to `src/graphql_schema.py` must have at least one corresponding test in `tests/test_graphql_api.py` that:
1. Queries the type via the TestClient
2. Asserts at least one field value is correct
3. Asserts an empty list is returned when Neo4j returns no rows (not `null`)

### GraphQL type exposes internal system fields
Fields like `driver`, `_client`, internal Neo4j node IDs, or any field prefixed with `_` must never appear in a Strawberry type definition.
Flag any `@strawberry.type` field whose name starts with `_` or whose value would reveal infrastructure details.

### New GraphQL field not added to resolver mapper
When a field is added to a Strawberry type in `graphql_schema.py`, verify that the corresponding resolver in `graphql_api.py` populates it.
Flag schema fields that are always `None` because the resolver never reads the property from the Neo4j node.

---

## 13. RESILMESH INTEROPERABILITY — Blocking

These rules protect the shared Neo4j database and prevent EdgeGuard from corrupting ResilMesh's graph or accidentally exposing ResilMesh data through EdgeGuard APIs.

### New service binds to a reserved ResilMesh port
EdgeGuard must never bind to these ports (all used by ResilMesh on the shared edge server):

| Port | ResilMesh service |
|------|-------------------|
| 8080 | Temporal (workflow orchestration) |
| 10443 | MISP HTTPS |
| 3100 | PPCTI |
| 3400 | IOB STIX |
| 8030 / 8501 | THF |
| 3443 | Shuffle |
| 4433 | Wazuh |
| 8000 | iSIM REST API (EdgeGuard also uses 8000 — intentional, different host context) |
| 4001 | iSIM GraphQL (EdgeGuard also uses 4001 — intentional, different host context) |

Flag any new `ports:` entry in docker-compose files or any `os.getenv("..._PORT", "XXXX")` default that clashes with the table above, unless the clash is intentional and documented in `docs/RESILMESH_INTEROPERABILITY.md`.

### Ownership markers on new MERGE (shared-database contract, 2026-10)
Every `MERGE (n:Label …)` in `src/neo4j_client.py`, `src/run_misp_to_neo4j.py`, or any enrichment job must set `n.edgeguard_managed = true` in `ON CREATE SET` only, and mark a node another system created on the match path (`neo4j_client._enriched_on_match_clause`):
```cypher
MERGE (n:Malware {name: $name})
ON CREATE SET n.edgeguard_managed = true
ON MATCH SET n.edgeguard_enriched = CASE WHEN n.edgeguard_managed = true THEN n.edgeguard_enriched ELSE true END
```
Every EdgeGuard edge sets `r.edgeguard_managed = true`. These markers are the only way to distinguish EdgeGuard-owned nodes from ResilMesh-owned nodes in the shared graph. Flag a MERGE without the create-path marker, and any unconditional `SET n.edgeguard_managed = true`: it claims a node another system created, and the baseline wipe (`baseline_clean._wipe_neo4j` → `Neo4jClient.clear_edgeguard_managed`) would delete it.

### New relationship type collides with ResilMesh schema
Before introducing a new relationship type, verify it does not already exist in the ResilMesh schema with a different direction or semantics. Known ResilMesh relationship types to avoid reusing: `RESOLVES_TO` (reserved for `(IP)-[:RESOLVES_TO]->(DomainName)`), `HAS_CVSS_v31`, `HAS_CVSS_v2`, `IN`, `PART_OF` (ResilMesh topology: IP / Subnet / OrganizationUnit; EdgeGuard's campaign membership is `PART_OF_CAMPAIGN`).
Flag any new relationship type that is a case-insensitive match for an existing ResilMesh type.

### `cve_id` written in uppercase
The ResilMesh schema defines `cve_id` as lowercase. Flag any code that writes `CVE_id`, `CVE_ID`, or `CveId` as a Neo4j property name. The canonical form is `cve_id`.

### `Vulnerability.status` written as a string instead of a list
The ResilMesh schema defines `Vulnerability.status` as `LIST OF STRING` (e.g., `["active"]`, `["rejected"]`).
Flag any path that writes `status = "active"` (a scalar string) instead of `status = ["active"]` (a list).

### EdgeGuard relationship direction deviates from ResilMesh canonical model
The following directions are canonical and shared with ResilMesh — deviating breaks cross-system Cypher queries:
```
(Vulnerability)-[:REFERS_TO]->(CVE)            ← bidirectional
(CVE)-[:HAS_CVSS_v31]->(CVSSv31)               ← bidirectional
(Indicator)-[:TARGETS]->(Sector)
(Vulnerability)-[:AFFECTS]->(Sector)
(Indicator)-[:INDICATOR_RESOLVES_TO]->(IP)     ← NOT RESOLVES_TO (reserved)
```
Flag any PR that changes the direction of these relationships.

### ISIM GraphQL schema extended without documentation
EdgeGuard types (`Indicator`, `ThreatActor`, `Malware`, `Technique`, `Tactic`, `Campaign`) are planned extensions to the ISIM GraphQL schema. Any change to these types' field names or types in `src/graphql_schema.py` is a breaking change for the planned ISIM extension. Flag such changes if `docs/RESILMESH_INTEROPERABILITY.md` §8 is not updated in the same PR.

---

## 14. PROVENANCE & AUDIT TRAIL — Blocking

These rules ensure that every node in Neo4j can be traced back to its original source, and that raw data remains accessible via MISP.

### MERGE block missing SOURCED_FROM edge
Every MERGE of a node from a source record must be followed (in the same transaction or immediately after) by a `MERGE (n)-[:SOURCED_FROM]->(s:Source {source_id: $source_id})` that stores the full collector payload in `r.raw_data`. Derived nodes (Campaign, Sector, the CVSS sub-nodes) have no `SOURCED_FROM` edge.
Flag any node creation path for a source record that does not create or update the `SOURCED_FROM` relationship. Without it, there is no way to retrieve the raw data that produced the node.

### `first_imported_at` overwritten after initial import
`first_imported_at` records when a node first entered the graph and must never be updated after creation.
```cypher
// CORRECT
ON CREATE SET n.first_imported_at = datetime()
// WRONG
SET n.first_imported_at = datetime()
```
Flag any `SET n.first_imported_at` that is not inside an `ON CREATE SET` block.

### MISP id lists replaced instead of accumulated
In `merge_node_with_source`, `merge_indicators_batch` and `merge_vulnerabilities_batch`, `misp_event_ids` / `misp_attribute_ids` accumulate (`_dedup_concat_clause` / `_dedup_concat_optional_clause`); the scalar `misp_event_id` / `misp_attribute_id` node properties were dropped (PR #33).
Flag a write that replaces either list, or brings back the scalar `misp_event_id` / `misp_attribute_id` node properties.

### `misp_event_url` persisted to Neo4j
`misp_event_url` is a **computed field** — it is constructed at API query time from `MISP_URL + misp_event_id`.
It must never be stored as a Neo4j node property. Flag any `SET n.misp_event_url = …` in Cypher queries.

### New node type missing `source[]` accumulation
Every node type must accumulate sources as a set, not replace:
```cypher
SET n.source = apoc.coll.toSet(coalesce(n.source, []) + $source_array)
```
Flag any `SET n.source = $source` that discards the accumulated source history.

### Confidence: max-wins per label (2026-10-16)
On every label but `Indicator` a write keeps the higher confidence:
```cypher
SET n.confidence_score = CASE
    WHEN n.confidence_score IS NULL OR $confidence > n.confidence_score
    THEN $confidence
    ELSE n.confidence_score END
```
On an `Indicator` the max-wins applies to `n.source_confidence` (`indicator_aging.source_confidence_item`, incoming values only), and `n.confidence_score` is the value of the one aging rule (`src/indicator_aging.py`): `max(0.10, round(source_confidence × factor, 2))`, with factors 0.85 / 0.70 / 0.55 from 90 / 180 / 365 days (`EDGEGUARD_AGING_TIER_DAYS`, `EDGEGUARD_AGING_FACTORS`) and retirement from `EDGEGUARD_AGING_RETIRE_DAYS` (default 730). Every Indicator write recomputes it (`merge_indicators_batch`, `merge_node_with_source`, `create_indicator_from_alert`, through `aging_set_clause`), and so does `enrichment_jobs.decay_ioc_confidence`; a node written before 2026-10-16 without `source_confidence` keeps its stored value.
Flag an Indicator write that sets `confidence_score` other than through `aging_map`, a max-wins on an Indicator's `confidence_score`, `source_confidence` filled from an aged `confidence_score`, and any path that lowers a non-Indicator node's confidence.

### `SOURCED_FROM` edge provenance
`r.raw_data` on the `SOURCED_FROM` edge is written when the edge is created (`ON CREATE SET`), except on CVE: `merge_cve` passes `refresh_raw_data=True` (the default, 2026-10), so the edge holds the source's latest record (a MISP copy edited in place and re-read by the sync); the STIX import (`run_pipeline`, a reduced record) passes `refresh_raw_data=False` and never replaces it.
`r.imported_at` is immutable after creation. `r.confidence`, `r.source`, `r.misp_event_ids`, `r.source_refs`, `r.zones` / `r.stated_zones` / `r.stated_refs` and `r.updated_at` are updated on every write; `r.source_reported_first_at` / `r.source_reported_last_at` move by MIN / MAX, and an Indicator's edge records the source's report forward only (`indicator_aging.edge_report_items`).

---

## 15. ENRICHMENT JOBS — Blocking

### Enrichment job not idempotent
All enrichment jobs in `src/enrichment_jobs.py` must use `MERGE` (not `CREATE`) for every node and relationship they produce.
Running the same job twice must produce identical graph state. Flag any job that uses `CREATE` for nodes or relationships, which would produce duplicates on every pipeline run.

### Indicator aging basis (2026-10-16)
Only `Indicator` nodes age (`src/indicator_aging.py`); CVE, CVSS, Vulnerability, Malware, ThreatActor, Technique, Tactic, Tool, Sector, Source and Alert never age by time. The age counts from `coalesce(n.last_reported_at, n.first_imported_at)` (`basis_expr`): `last_reported_at` is the latest report of any source, `min(MISP attribute time, source last_seen)` (`run_misp_to_neo4j.misp_report_times`), kept forward only (`node_report_items`); `first_imported_at` dates a node no MISP report dated. The rule runs at the database's time (`DATABASE_TIME`), lifted to the node's `aging_evaluated_at` when that is later (`evaluated_at_expr`).
Flag an age computed from `n.last_updated` (every write refreshes it), a run- or Python-supplied evaluation time in production (`decay_ioc_confidence(as_of=...)` is for tests only), a report time that moves backwards, an aging statement that reads `edgeguard_managed` / `edgeguard_enriched`, and aging of any label other than Indicator.

### Indicator retirement (2026-10-16)
The aging rule (`indicator_aging.aging_map`, applied by every Indicator write and by `enrichment_jobs.decay_ioc_confidence`) retires an Indicator `EDGEGUARD_AGING_RETIRE_DAYS` (default 730) after its basis: `active = false`, `retired_by = 'decay'`, `retired_at` = basis + retire days. A newer report that brings the age below that clears a decay retirement; a manual decommission (`retired_at` with `retired_by` other than `'decay'`) is kept. The job logs per-tier, retired and per-basis counts at INFO (`[AGING]`).
Flag `retired_at = datetime()`, a retirement without `retired_by = 'decay'`, code that clears a manual decommission, and a job that writes a node whose `AGING_FIELDS` did not change (other than the one-time stamp of a node without `aging_evaluated_at`) or writes without `apoc.lock.nodes`.

### Campaign builder follows its evidence (2026-10-16)
`build_campaign_nodes` builds a Campaign for a ThreatActor with an `ATTRIBUTED_TO` (Malware→ThreatActor) or `USES_MALWARE` (ThreatActor→Malware) link to a malware that at least one active Indicator `INDICATES`; one indicator is enough. The definitions come only from `src/campaign_evidence.py` (`has_evidence`, `member_malware`, `evidence_links`, `QUALIFYING_ACTORS_QUERY`), shared with the baseline postcheck (INV-1) and `scripts/verify_fresh_baseline.py`. Every campaign link carries `match_type = 'campaign_grouping'`, the confidence of the evidence it rests on, `r.evidence_types` and replace-mode provenance. Step 1b deletes an EdgeGuard-created campaign whose actor has neither link left, Step 2b prunes a malware membership without evidence, and Step 2c removes a RUNS from an actor that is not the campaign's or has no evidence.
Flag a second definition of campaign evidence, a campaign link without `evidence_types` or with a hard-coded confidence, provenance added to instead of replaced, a campaign kept without evidence, and deletion of a campaign that is not `edgeguard_managed`.

### `bridge_vulnerability_cve` not bidirectional
The enrichment job that creates `REFERS_TO` links between `Vulnerability` and `CVE` nodes must create **both directions**:
```cypher
MERGE (v)-[:REFERS_TO]->(c)
MERGE (c)-[:REFERS_TO]->(v)
```
This matches the ResilMesh schema. Flag any version that only creates the `(v)-[:REFERS_TO]->(c)` direction.

### Enrichment job failure not counted or raised
Every enrichment job returns a dict of counts. A failure either counts in `errors` (the alias and twin merges, per batch) or raises so the task fails (`decay_ioc_confidence`, `build_campaign_nodes`, `bridge_vulnerability_cve`, and `calibrate_cooccurrence_confidence` after all tiers ran); only `enrich_cve_epss` logs and skips a feed outage by design.
Flag a job that returns `None` / `True` / `False`, or catches an error without counting or raising it.

---

## 16. CLI & INSTALLATION — Non-blocking

### `install.sh` contains hardcoded credential or URL
`install.sh` must never contain API keys, passwords, database URIs, or environment-specific hostnames.
All runtime configuration must come from `.env` (loaded at runtime) or `.env.example` (template only).
Flag any string literal in `install.sh` that looks like a credential or a non-localhost URL.

### `install.sh` missing `set -e` (fail-fast)
Installation scripts that continue after a failed command leave the system in a partially configured state that is hard to diagnose.
`install.sh` must start with `set -euo pipefail`. Flag scripts that are missing this guard.

### `Makefile` target missing error propagation
`make` targets that invoke subshells with `&&` chains are fine. Targets that use `;` to chain commands will continue even on failure.
Flag any `Makefile` target that uses `;` between commands where a failure of the first command should abort the rest.

### `.envrc` exports secret values
`.envrc` is committed to version control. It must only call `dotenv .env` to load secrets — it must never contain literal secret values.
Flag any `.envrc` that contains `export API_KEY=...` or similar assignments with non-placeholder values.

### `pyproject.toml` optional dependency version unpinned
Dependencies in `pyproject.toml` `[project.optional-dependencies]` should use `~=` (compatible release) or `>=X,<Y` version constraints, not bare package names.
Flag any optional dependency with no version constraint — this breaks reproducible installs.

### New `make` target not in README
If a new `Makefile` target is added, flag if it is not mentioned in `README.md` under the "Quick Start" or "Development" section so developers can discover it.

---

## 17. MONITORING — Non-blocking

### New Prometheus metric uses name that collides with ResilMesh
EdgeGuard metrics must all be prefixed with `edgeguard_`. The following prefixes are reserved by ResilMesh components and must never be used:
`resilmesh_`, `isim_`, `crusoe_`, `temporal_`, `wazuh_`, `shuffle_`, `thf_`.
Flag any `Counter(...)`, `Gauge(...)`, or `Histogram(...)` whose name does not start with `edgeguard_`.

### Prometheus metric registered at module level without collision guard
Registering a Prometheus metric at module level without checking `METRICS_SERVER_AVAILABLE` will raise a `ValueError: Duplicated timeseries` when Airflow re-parses the DAG or when the module is imported twice.
```python
# CORRECT pattern
if ENABLE_PROMETHEUS_METRICS and not METRICS_SERVER_AVAILABLE and not PROMETHEUS_AVAILABLE:
    MY_COUNTER = Counter("edgeguard_...", "...")
```
Flag any `Counter(...)` / `Gauge(...)` / `Histogram(...)` at module level that is not inside this guard.

### Metrics server binds to `0.0.0.0` by default
For **bare-metal / host runs**, `EDGEGUARD_METRICS_HOST` must default to `127.0.0.1` so the Prometheus metrics endpoint is not reachable from other hosts on the shared ResilMesh server.
`0.0.0.0` is only acceptable when Prometheus runs on a separate machine and the override is explicitly documented in `.env.example`.
**Docker (2026-10):** inside a compose service, container-loopback is unreachable by ANY scraper (it is not the host's loopback), so the `metrics` service (`src.metrics_exporter`, multi-process mode) binds `0.0.0.0` **in-container** and publishes `127.0.0.1:8001:8001`; Prometheus scrapes `metrics:8001` over `edgeguard_net`. That pattern (in-container any-addr + host-loopback publish) is correct. The `airflow` service publishes no metrics port: its task processes write to `PROMETHEUS_MULTIPROC_DIR`, and `EDGEGUARD_ENABLE_METRICS` only governs the in-process server of bare-metal installs. Flag instead: (a) a metrics port mapping that binds `0.0.0.0` on the HOST side, or (b) a bare-metal default of `0.0.0.0`. The in-container bind is reachable by peer containers on `edgeguard_net`; the endpoint serves only Prometheus counters/gauges (no secrets).

### Health endpoint does not reflect actual dependency status
The `/health` endpoint in both `src/query_api.py` and `src/graphql_api.py` must verify that Neo4j is reachable before returning `{"status": "ok"}`.
Flag any `/health` implementation that returns 200 unconditionally without checking the Neo4j connection.

### New data source not added to source reliability table
A new source needs its own entry in `src/source_registry.py` (canonical id, aliases, MISP tag, `reliability`, `source_type`); `neo4j_client.SOURCES`, `MISPToNeo4jSync.SOURCE_MAPPING` and `MISPWriter.SOURCE_TAGS` derive from it, and its `reliability` orders it in the description ranking.
If a new collector is added, flag if there is no corresponding registry entry with an appropriate `reliability` value (0.0–1.0), or if the source reuses another's canonical id.
Leaving a source out means its nodes get no `SOURCED_FROM` edges and no reliability weighting.

---

## 18. AIRFLOW DAG CONCURRENCY, TIMEOUTS & RETRIES — Blocking

These rules protect against stuck/hung pipelines and concurrent run races. Violations can cause silent data loss or indefinite hangs in production.

### Every DAG must have `max_active_runs=1`

All 6 DAGs in `dags/edgeguard_pipeline.py` must set `max_active_runs=1`. Without this, a slow run causes the scheduler to pile up concurrent runs that race on MISP and Neo4j writes. Flag any DAG definition (`DAG(...)`) that is missing `max_active_runs=1`.

### Every DAG must have `dagrun_timeout`

All 6 DAGs must set `dagrun_timeout=timedelta(...)`. This is wall-clock time from DAG run start — if the entire run (including retries) exceeds this, Airflow marks it failed. Without it, a stuck run hangs indefinitely.

The timeout must be **greater than** the worst-case task chain: `sum of sequential tasks' (execution_timeout x (1 + retries) + retries x retry_delay)`, using `max()` for parallel task groups, with at least 20% buffer. Flag any `dagrun_timeout` that is shorter than the worst-case calculation.

Current correct values:

| DAG | dagrun_timeout |
|-----|---------------|
| `edgeguard_pipeline` | 5h 30m |
| `edgeguard_medium_freq` | 5h |
| `edgeguard_low_freq` | 8h 30m |
| `edgeguard_daily` | 8h 30m |
| `edgeguard_neo4j_sync` | 68h |
| `edgeguard_baseline` | 32h |

### Every task must have `execution_timeout`

All `PythonOperator` and `BashOperator` tasks must set `execution_timeout`. Without it, a single task can hang forever (e.g., MISP unresponsive) within the DAG run. Flag any task missing `execution_timeout`.

### `dagrun_timeout` must be recalculated when task timeouts or retries change

If someone changes a task's `execution_timeout`, or changes `retries`/`retry_delay` in `default_args`, the parent DAG's `dagrun_timeout` may need updating. Flag such changes without a corresponding `dagrun_timeout` update and ask for verification.

### `default_args` must include `on_failure_callback`

The `default_args` dict must include `on_failure_callback` pointing to `_on_task_failure`. This ensures all task failures are logged with `[ALERT]` and optionally sent to Slack. Flag removal of this callback.

### `default_args` must include `on_success_callback`

The `default_args` dict must include `on_success_callback` pointing to `_on_task_success`. This updates the `edgeguard_dag_last_success_timestamp` Prometheus gauge for stuck-run detection. Without it, the `EdgeGuardDAGLastSuccessStale` alert becomes dead code. Flag removal of this callback.

### DAG runs are marked in progress by the listener plugin only (2026-10)

`edgeguard_dag_run_in_progress_start_timestamp` is written only by `plugins/edgeguard_dag_run_state.py`: `on_dag_run_running` sets the run's `start_date`, `on_dag_run_success` and `on_dag_run_failed` set 0, or the start time of the earliest other run of the same DAG still running (`_other_running_start`, read in a non-scoped session of its own). The scheduler calls these hooks in order when it starts and ends a run, and the API server calls the end hooks when a run is marked failed or successful by hand. `docker-compose.yml` must keep `AIRFLOW__CORE__PLUGINS_FOLDER` and the `./plugins` mount on the `airflow` service. Flag any code in `dags/` that writes `DAG_RUN_START` (a DAG-level callback runs late in the DAG processor and can clear the next run's mark, and none runs on a manual state change), a hook that can raise, and a new DAG missing from the `edgeguard:dag_run_max_seconds` recording rule in `prometheus/alerts.yml`. Also flag any call from a listener hook to an Airflow function decorated with `@provide_session` (`DagRun.find()` and the like) without an explicit, separate session (`create_session(scoped=False)`): without one the call uses Airflow's scoped session, which in the scheduler is the scheduling loop's own session under `prohibit_commit`; the commit attempted on exit is refused, the session is rolled back and closed, the `DagRun` the scheduler is finishing is detached, and the scheduler's next read of it raises `DetachedInstanceError` and stops the scheduler at the end of every run.

### Baseline DAG must have `is_paused_upon_creation=False`

`edgeguard_baseline` must set `is_paused_upon_creation=False`. Without this, manual triggers silently queue forever because Airflow starts DAGs paused by default. `schedule=None` (Airflow 3; `schedule_interval` was removed) already prevents automatic execution. Flag removal of this setting.

### Neo4j merge return values must be checked before incrementing stats

In `src/run_misp_to_neo4j.py` and `src/run_pipeline.py`, every call to `merge_indicator()`, `merge_vulnerability()`, `merge_cve()`, `merge_malware()`, `merge_actor()`, `merge_technique()` must check the boolean return value before incrementing the stats counter. Flag any pattern like:
```python
self.neo4j.merge_vulnerability(item, ...)
self.stats["vulnerabilities_synced"] += 1  # BUG: not checking return value
```
The correct pattern is:
```python
if self.neo4j.merge_vulnerability(item, ...):
    self.stats["vulnerabilities_synced"] += 1
```

### Every write result is read inside its retry (2026-10)

The Neo4j driver reports an execution or commit error only when a result is read. Every `session.run` / `tx.run` in `src/` must read its result (`.consume()`, `.single()`, iteration) inside the `try` / `@retry_with_backoff` that classifies its error (`tests/test_neo4j_write_results.py::TestNoWriteResultIsDiscarded`). Batch merges pass that one summary to the counter helper; each relationship group is retried and charged on its own; single-item writes and `merge_cve`'s sub-writes (`_merge_cvss_node`, `_replace_nvd_owned_cve_data`, `_set_cve_score_from_cvss`) retry a retryable error, raise it once the retries are spent, and return False on a terminal one (`_cve_sub_write_failed`), so the sync counts the item as an error; the alias and twin merges run each batch and its follow-ups in one explicit transaction. Flag a discarded or late-read result, a result read outside its retry, and a write error logged without being returned or counted.

### Baseline lock (2026-10-16)

Every writing task of `edgeguard_neo4j_sync` (`run_neo4j_sync` and its retries, `build_relationships`, `run_enrichment_jobs`) calls `_skip_while_baseline_holds_lock` at its start (`baseline_skip_reason(own_holder=_baseline_run_holder(context))`), not only `check_sync_needed`; every collector task calls `baseline_skip_reason`. In `edgeguard_baseline` the collectors refuse while no baseline holds the lock, and `full_neo4j_sync`, the baseline's `build_relationships` and `run_enrichment_jobs` refuse unless the sentinel names their own DAG run (`_require_baseline_lock(own=True)`, `is_own_dag_run_sentinel`). A refusal of `baseline_clean` before the wipe releases the lock (`_release_lock_on_pre_wipe_refusal`), and `baseline_clean` / `baseline_start` take it again (`_retake_baseline_lock`). Flag a new Neo4j- or MISP-writing task without one of these checks, a baseline writer that runs without the lock or under another run's lock, a refusal before the wipe that keeps the lock, and a skip that stamps the sync state file.

### Collector tasks share one pool (2026-10)

Every collector task (scheduled and baseline) sets `pool=COLLECTOR_POOL` (`edgeguard_collectors`, `EDGEGUARD_COLLECTOR_POOL_SLOTS`, default 4, created by `docker-compose.yml` at start); sync, relationships, enrichment, health checks and the baseline lock stay outside it. Flag a collector task without it, and a `dagrun_timeout` recalculation that ignores the time a task waits for a slot (it counts against `dagrun_timeout`, not `execution_timeout`).

### `clear_checkpoint()` must preserve incremental state

`src/baseline_checkpoint.py` `clear_checkpoint(source=None)` (the `--fresh-baseline` path) must preserve `"incremental"` sub-dicts inside each source entry. These hold OTX `modified_since` cursors, MITRE ETags, etc. Destroying them forces scheduled runs to re-process all historical data. Flag any change to `clear_checkpoint` that deletes incremental state on the global (no-source) path.

### Prometheus stuck-run alerts require gauge wiring

The `EdgeGuardDAGRunStuck` and `EdgeGuardDAGLastSuccessStale` alerts in `prometheus/alerts.yml` depend on `edgeguard_dag_run_in_progress_start_timestamp` (2026-10; formerly `edgeguard_dag_run_start_timestamp`; set by the listener plugin `plugins/edgeguard_dag_run_state.py`) and `edgeguard_dag_last_success_timestamp` (set by `_on_task_success`) being written. `EdgeGuardBuildRelationshipsSilentDeath` (2026-10) compares `edgeguard_neo4j_sync_last_success_timestamp` (stamped by `record_neo4j_sync` after a successful sync, scheduled or baseline) with `edgeguard_build_relationships_last_completion_timestamp` (stamped by `record_build_relationships_completion` at build_relationships' SUMMARY line). If these gauges are defined but never `.set()`, the alerts are dead code. Flag removal of `on_success_callback`, of the listener plugin or its compose mount, of the `DAG_LAST_SUCCESS`/`DAG_RUN_START` gauge definitions, or of either stamp call without also removing the corresponding alerts.

---

## 19. CROSS-FILE CONTRACTS — Blocking

These rules catch inconsistencies between Python files that interact through shared data, metrics, or conventions.

### All `datetime.now()` must use `timezone.utc`

Every call to `datetime.now()` across `src/`, `dags/`, `tests/`, and `scripts/` must pass `timezone.utc`. Bare `datetime.now()` produces naive timestamps that crash when compared to timezone-aware values (common in MISP/Airflow/Neo4j data). Flag any bare `datetime.now()` without `timezone.utc`.

### Neo4j timestamps must use Cypher `datetime()`, not Python ISO strings

All Cypher SET clauses for `first_seen`, `last_updated`, `first_imported_at` must use the Neo4j server-side `datetime()` function, not Python-side `$parameter` strings. Storing ISO strings as `last_updated` breaks `duration.between()` in enrichment decay queries. Flag any Cypher that writes `$first_seen` or `$last_updated` as string parameters instead of `datetime()`.

### Prometheus metric labels must match between `metrics_server.py` and `dags/edgeguard_pipeline.py`

Both files define the same Prometheus metrics (standalone and production paths). The label sets MUST be identical:
- `PIPELINE_ERRORS`: `["task", "error_type", "source"]`
- `DAG_RUNS_TOTAL`: `["dag_id", "status", "run_type"]`
- `INDICATORS_COLLECTED`: `["source", "zone", "status"]`
- `NEO4J_NODES`: `["label", "zone"]`
- `SOURCE_HEALTH`: `["source", "zone"]` (metric name: `edgeguard_source_health`)
- `DAG_LAST_SUCCESS`: `["dag_id"]`

`DAG_RUN_START` (`edgeguard_dag_run_in_progress_start_timestamp`, labels `["dag_id"]`) is defined only in `metrics_server.py` and written only by the listener plugin (2026-10); flag a definition or write of it in `dags/`.

Flag any change to metric labels in one file without updating the other. Also flag any `.labels()` call that does not pass ALL required labels.

### Production metrics import must cover all metrics used by DAG functions

When `METRICS_SERVER_AVAILABLE` is True, the DAG imports metrics from `metrics_server.py`. ALL metrics used by unconditionally-defined functions (`record_indicators`, `record_neo4j_nodes`, `record_error`, `set_source_health`, etc.) must be imported. Flag any new metric usage in a DAG function without a corresponding import in the `METRICS_SERVER_AVAILABLE` block.

### `retry_with_backoff` semantics must be consistent

Three implementations exist: `collector_utils.py`, `neo4j_client.py`, `run_misp_to_neo4j.py`. All must use `range(max_retries + 1)` (first attempt + max_retries retries). The final error log must say `max_retries + 1` attempts. Flag any `range(max_retries)` without the `+ 1`.

### Sync state file path must be checked in both `state/` and `dags/` directories

`dags/edgeguard_pipeline.py` writes to `state/edgeguard_last_neo4j_sync.json`. `src/edgeguard.py` reads from multiple paths. Both `get_sync_status()` and `check_last_sync()` must include `state/` as a search path. Flag removal of the `state/` directory from the alt_paths list.

### `source` field contract: singular key, list value, `n.source` Neo4j property

All collector dicts must use `"source": [tag]` (singular key, list value). Neo4j node property is `n.source` (singular). Relationship properties may use `r.sources` (plural, different namespace). Flag any `"sources":` dict key in collector output, any `n.sources` in Cypher matching nodes, or any `.get("sources")` reading from Neo4j node results.

### Changes must be reflected in documentation

When code changes affect user-visible behavior (CLI commands, env vars, DAG settings, API responses), the corresponding documentation must be updated. Check: `README.md` (CLI table, env vars), `docs/AIRFLOW_DAGS.md` (DAG settings, CLI section), `docs/DEPLOYMENT_READINESS_CHECKLIST.md` (preflight steps), `docs/PRODUCTION_READINESS.md` (component status). Flag code changes without matching doc updates.
