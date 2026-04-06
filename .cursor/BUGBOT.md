# EdgeGuard-Knowledge-Graph — Bugbot Review Rules

---

## Architecture & Data Flow (read this first)

EdgeGuard is a **security-critical** graph-augmented threat intelligence pipeline. Every piece of data follows one mandatory path:

```
External Sources → Collectors → MISP (single source of truth) → Neo4j Knowledge Graph
                                                                      ↕
                                                        REST API (port 8000)  +  GraphQL API (port 4001)
```

- **Collectors** (`src/collectors/`) fetch from OTX, NVD, CISA, MITRE ATT&CK, VirusTotal, AbuseIPDB, ThreatFox, URLhaus, Feodo, SSLBlacklist, CyberCure
- **MISP** is the only place collector output lands first — no collector writes directly to Neo4j
- **Neo4j (primary path):** `src/run_misp_to_neo4j.py` syncs from MISP. **Optional CLI path:** `run_pipeline.py` with STIX flow calls `load_stix21_to_neo4j()` — still not collector→Neo4j direct writes
- **Optional allowlist:** `EDGEGUARD_COLLECT_SOURCES` — canonical names in `src/collector_allowlist.py` (import this from DAGs at parse time, **not** `collectors/__init__.py`, which loads every collector)
- **REST API** (`src/query_api.py`) — external-facing read API on port 8000
- **GraphQL API** (`src/graphql_api.py`) — Strawberry-based API on port 4001 mirroring ISIM's interface
- **Airflow DAGs** (`dags/`) orchestrate scheduled collection and sync
- **Sector zones**: `global`, `healthcare`, `energy`, `finance` — only valid values
- **Node types**: Indicator, Vulnerability, CVE, Malware, ThreatActor, Technique, Tactic, Campaign, Tool, Sector, Source — `Tool` represents MITRE ATT&CK software tools (distinct from Malware)
- **MISP/PyMISP version compatibility**: `src/misp_health.py` performs a version detection check; flag any code that assumes a specific PyMISP API without guarding against version differences
- **Historical windows**: all sectors (global/healthcare/energy/finance)=24 months — never exceed these
- **Resilience**: circuit breakers and retry logic protect all external calls
- **Provenance invariant**: every Neo4j node carries `first_imported_at`, `source[]`, `edgeguard_managed=true` and a `SOURCED_FROM` edge to its source node. MISP-originated nodes (Indicator, Vulnerability, CVE, Malware, ThreatActor) additionally carry `misp_event_id`
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
Collectors must respect the sector time ranges:
- All sectors (`global`, `healthcare`, `energy`, `finance`): maximum 24 months lookback

Flag any collector that uses a hardcoded absolute date instead of a relative offset from `datetime.now()`, or that sets a lookback period longer than the allowed window.
Flag any collector that ignores `resolve_collection_limit` / `get_effective_limit` (env: `EDGEGUARD_MAX_ENTRIES`, `EDGEGUARD_INCREMENTAL_LIMIT`).

### Collector missing status return
Every `collect()` method must return a status dict using `make_status()` from `src/collectors/collector_utils.py`.
Flag collectors that return `None`, `{}`, or ad-hoc dicts that don't match the standard schema.

### Duplicate source registration
If a new source is added, verify it has its own entry in `SOURCE_MAPPING` in `src/neo4j_client.py`.
Flag any source that reuses another source's `source_id` (e.g., a new feed incorrectly mapped to `abuseipdb`).

---

## 3. MISP DATA QUALITY — Blocking

### Missing required event metadata
Every MISP event created by a collector must include ALL of the following before being pushed:
- **Source tag**: `source:SourceName` (e.g., `source:AlienVault-OTX`)
- **Sector/zone tag**: `sector:SectorName` or `sector:Global`
- **TLP tag**: `tlp:amber` (sector-specific) or `tlp:green` (global)
- **`collection_date`** attribute: ISO 8601 timestamp of when the data was collected
- **`last_updated`** attribute: ISO 8601 timestamp, updated on every sync

Flag any collector that pushes events missing any of these fields.

### Overwriting with corrupt or empty data
Before updating an existing MISP event or attribute:
- Validate that the new value is not `None`, empty string `""`, `"unknown"`, `"N/A"`, or a bare IP placeholder like `0.0.0.0`
- Validate that dates are in a sensible range (after year 2000, not in the future)
- Validate that CVE IDs match the pattern `CVE-YYYY-NNNNN`
- Validate that IP addresses are valid (use `ipaddress` stdlib, not string checks)

Flag any merge/update path that does not validate the incoming value before overwriting.

### Duplicate event creation
Before creating a new MISP event, the collector must call `misp_writer.find_existing_event()` (or equivalent) to check whether an event for the same source + sector combination already exists.
Flag any collector that creates events without a deduplication check — this inflates MISP with redundant events and corrupts provenance tracking.

### `imported_at` / `first_seen` overwritten on re-import
Original import timestamps (`imported_at`, `first_seen`) must be set with `ON CREATE SET` semantics — written once and never updated.
Flag any code path that overwrites these timestamps on subsequent imports of the same record.

### `last_updated` not refreshed on sync
Every time an existing MISP event or attribute is updated, `last_updated` must be set to `datetime.now().isoformat()`.
Flag update paths that merge data but do not refresh this timestamp.

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
| **`NVD_META:`** | `misp_writer` CVE attributes | `run_misp_to_neo4j.parse_attribute` (vulnerability) |
| **`MITRE_USES_TECHNIQUES:`** | `misp_writer.create_malware_attribute` | `run_misp_to_neo4j.parse_attribute` (malware-type) → **`uses_techniques`** on **`merge_malware` |

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

### ThreatActor→Technique USES must use `uses_techniques` list, not `misp_event_id` co-occurrence

In `build_relationships.py`, the query linking `ThreatActor` to `Technique` must match on `a.uses_techniques`:

```cypher
-- CORRECT
MATCH (a:ThreatActor), (t:Technique)
WHERE t.mitre_id IN coalesce(a.uses_techniques, [])
MERGE (a)-[r:USES]->(t)
SET r.confidence_score = 0.95, r.match_type = 'mitre_explicit'
```

Flag any version using `WHERE a.misp_event_id = t.misp_event_id` for this relationship — MITRE ATT&CK actors and techniques always come from separate MISP events, so `misp_event_id` never matches and this query always returns 0. Confirmed bug: the co-occurrence approach produced zero USES relationships in all test runs.

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

### Malware→Technique USES must use `uses_techniques` on Malware — never `CONTAINS`

Same source as ThreatActor: explicit STIX **`uses`** (malware → attack-pattern). In `build_relationships.py`:

```cypher
MATCH (m:Malware), (t:Technique)
WHERE t.mitre_id IN coalesce(m.uses_techniques, [])
MERGE (m)-[r:USES]->(t)
SET r.confidence_score = 0.95, r.match_type = 'mitre_explicit'
```

The MITRE collector must populate **`uses_techniques`** on each malware dict from `_malware_uses`. `misp_writer.create_malware_attribute` must embed **`MITRE_USES_TECHNIQUES:`** JSON in the attribute comment when non-empty so `run_misp_to_neo4j` can restore the property on **`merge_malware`**. **`neo4j_client.merge_malware`** must pass **`uses_techniques`** in `extra_props`.

Flag any **`CAN_USE`** relationship or fuzzy name/description matching between Malware and Technique — that pattern was removed as a hallucination risk.

### Hardcoded zone list must stay in sync with `VALID_ZONES`

`_extract_zone_from_event_name()` in `run_misp_to_neo4j.py` uses a hardcoded `valid_zones = ["global", "finance", "energy", "healthcare"]`. This list must always match `VALID_ZONES` in `config.py`.

Flag any PR that adds a new zone to `VALID_ZONES` in `config.py` without also updating the hardcoded list in `_extract_zone_from_event_name()`. The preferred fix is to import `VALID_ZONES` directly instead of duplicating it.

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

Flag any node or relationship that hardcodes a confidence score above `0.70` for data that has not been explicitly corroborated by source material. Flag any relationship with `confidence_score > 0.80` and `match_type = 'misp_cooccurrence'` — co-occurrence is inherently weak signal.

### Generic entity names must never become graph nodes

Node keys like `"unknown"`, `"malware"`, `"trojan"`, `"backdoor"`, `"virus"`, `"actor"`, `"ransomware"`, or any single-character / empty string will match against thousands of unrelated records, causing massive false-positive enrichment cascades.

Flag any `MERGE` or `merge_node_with_source()` call where the primary key property could be one of these generic terms. Add a blocklist check before writing:

```python
GENERIC_NAMES_BLOCKLIST = frozenset({
    "unknown", "malware", "trojan", "backdoor", "virus", "actor",
    "ransomware", "threat", "attack", "hacker", "apt", "n/a", "",
})
if name.strip().lower() in GENERIC_NAMES_BLOCKLIST:
    logger.warning("Skipping generic entity name: %s", name)
    return False
```

### Zone keyword false positives — single generic words must not trigger sector tagging

Using single common words as zone keywords (e.g., `"bank"`, `"power"`, `"care"`, `"medical"`) will match in unrelated contexts ("power off", "take care", "bank of results"). Zone keywords must be:
- Multi-word phrases preferred (e.g., `"power grid"`, `"banking trojan"`, `"medical device"`)
- Whole-word matched only (`re.search(r'\b' + re.escape(kw) + r'\b', text)`)
- Require minimum score threshold (≥ 2.0) when using weighted scoring

Flag any new zone keyword added to `SECTOR_KEYWORDS` in `config.py` that is a single common word (≤ 6 characters, no space) without a corresponding negative-keyword guard. Especially flag additions to the finance sector — words like `"card"`, `"pay"`, `"fund"` appear in non-financial threat intel constantly.

### Relationship direction must follow the semantic model

Incorrect edge direction silently produces wrong graph traversals. The canonical directions are:

```
(Indicator)   -[:INDICATES]->   (Malware)
(Indicator)   -[:INDICATES]->    (Malware)          # co-occurrence or malware_family match
(Indicator)   -[:EXPLOITS]->   (Vulnerability | CVE)
(Malware)     -[:ATTRIBUTED_TO]-> (ThreatActor)   # malware attributed to actor
(ThreatActor) -[:USES]->       (Technique)        # explicit MITRE STIX uses_techniques
(Malware)     -[:USES]->       (Technique)        # same — uses_techniques on Malware node
(ThreatActor) -[:USES_TECHNIQUE]-> (Technique)    # alternative explicit link
(Malware)     -[:USES_TECHNIQUE]-> (Technique)    # alternative explicit link
(Tool)        -[:USES_TECHNIQUE]-> (Technique)    # tool → technique mapping
(ThreatActor) -[:USES]->       (Tool)             # actor uses tool
(Technique)   -[:IN_TACTIC]->  (Tactic)
(ThreatActor) -[:RUNS]->       (Campaign)
(Malware | Indicator)-[:PART_OF]-> (Campaign)
(Indicator)   -[:TARGETS]->    (Sector)
(Vulnerability | CVE)-[:AFFECTS]-> (Sector)      # sector from zone list (build_relationships)
```

Flag **`(ThreatActor)-[:ATTRIBUTED_TO]->(Malware)`** (reversed). Flag any relationship creation that reverses the rows above. Wrong `ATTRIBUTED_TO` direction makes traversals return empty results silently.

### Circular enrichment — a node must not be used to enrich itself

If the same source (`source_id`) has already been recorded in `n.sources`, writing back properties derived only from that source does not constitute corroboration and should not increase `confidence_score`.

Flag any enrichment path where:
1. The enrichment query matches a node by its existing properties
2. The only new data comes from the same `source_id` already in `n.sources`
3. The confidence score is raised as a result

This is a form of hallucination: the system convincing itself a piece of data is more reliable because it "confirmed" itself.

### Stale data re-import must not reset or boost `confidence_score`

Re-importing the same indicator from the same source (common during baseline collection) must use `ON MATCH SET` with `CASE WHEN` logic that only raises confidence, never lowers it due to decay from other jobs. Flag any sync path that unconditionally overwrites `confidence_score` without checking the existing value.

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
The `sources` property must be appended to, not replaced:
```cypher
SET node.sources = COALESCE(node.sources, []) + [new_source]
```
Flag any `SET node.sources = [value]` that discards the accumulated source history.

### Sector label never applied
After a node MERGE, the sector label must be applied:
```cypher
CALL apoc.create.addLabels(node, [sector]) YIELD node
```
Flag any node creation path that does not apply the sector label. Without it, all sector-filtered Cypher queries return empty results.

### UNIQUE constraint missing for new node type
If a new node label is added to the graph schema, flag if there is no corresponding `CREATE CONSTRAINT` call in `src/neo4j_client.py`. Missing constraints allow race-condition duplicates.

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

### `n.active = true` must respect decay retirement
Merge paths must not blindly set `n.active = true`. If a node has been retired by the decay job (`retired_at IS NOT NULL`), its `active` flag must be preserved. The correct pattern is:
```cypher
n.active = CASE WHEN n.retired_at IS NOT NULL THEN n.active ELSE true END
```
Flag any `SET n.active = true` in merge paths (`merge_node_with_source`, `merge_indicators_batch`, `merge_vulnerabilities_batch`, `mark_inactive_nodes`, ResilMesh `merge_indicator`) that does not check `retired_at`. An unconditional `SET n.active = true` silently un-retires indicators that the decay job correctly retired, creating zombie nodes with `confidence_score=0.10, active=true`.

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

**`edgeguard_neo4j_sync`**: when **`check_sync_needed`** (ShortCircuitOperator) returns false, downstream **`run_neo4j_sync`**, **`build_relationships`**, and enrichment are **skipped** — a green run may mean no sync. Document/operator expectations must stay aligned with **`docs/AIRFLOW_DAGS.md`**.

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

### GraphQL resolver bypasses `edgeguard_managed` filter
Every list resolver (indicators, vulnerabilities, CVEs, etc.) must include `n.edgeguard_managed = true` in its WHERE clause.
Flag any resolver that queries `MATCH (n:Label)` without this filter — it would expose ResilMesh-owned nodes to EdgeGuard clients and vice versa.

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

### `edgeguard_managed` not set on new MERGE
Every `MERGE (n:Label …)` in `src/neo4j_client.py`, `src/run_misp_to_neo4j.py`, or any enrichment job must include:
```cypher
SET n.edgeguard_managed = true
```
This tag is the only way to distinguish EdgeGuard-owned nodes from ResilMesh-owned nodes in the shared graph. Flag any MERGE block that does not set it.

### New relationship type collides with ResilMesh schema
Before introducing a new relationship type, verify it does not already exist in the ResilMesh schema with a different direction or semantics. Known ResilMesh relationship types to avoid reusing: `RESOLVES_TO` (reserved for `(IP)-[:RESOLVES_TO]->(DomainName)`), `HAS_CVSS_v31`, `HAS_CVSS_v2`, `IN`.
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
Every `MERGE (n:Label …)` must be followed (in the same transaction or immediately after) by a `MERGE (n)-[:SOURCED_FROM]->(s:Source {source_id: $source_id})` that stores the full collector payload in `r.raw_data`.
Flag any node creation path that does not create or update the `SOURCED_FROM` relationship. Without it, there is no way to retrieve the raw data that produced the node.

### `first_imported_at` overwritten after initial import
`first_imported_at` records when a node first entered the graph and must never be updated after creation.
```cypher
-- CORRECT
ON CREATE SET n.first_imported_at = datetime()
-- WRONG
SET n.first_imported_at = datetime()
```
Flag any `SET n.first_imported_at` that is not inside an `ON CREATE SET` block.

### `misp_event_id` overwritten after initial import (batch path)
In `merge_indicators_batch` and `merge_vulnerabilities_batch`, `misp_event_id` and `misp_attribute_id` must use `coalesce(n.misp_event_id, item.misp_event_id)` semantics — written once, never replaced.
Flag any batch MERGE that unconditionally sets `n.misp_event_id = item.misp_event_id` without the coalesce guard.

### `misp_event_url` persisted to Neo4j
`misp_event_url` is a **computed field** — it is constructed at API query time from `MISP_URL + misp_event_id`.
It must never be stored as a Neo4j node property. Flag any `SET n.misp_event_url = …` in Cypher queries.

### New node type missing `source[]` accumulation
Every node type must accumulate sources as a set, not replace:
```cypher
SET n.source = apoc.coll.toSet(coalesce(n.source, []) + $source_array)
```
Flag any `SET n.source = $source` that discards the accumulated source history.

### Confidence score lowered without decay job context
The confidence score must only decrease through the scheduled `ioc_confidence_decay` enrichment job.
Flag any sync or merge path (outside of `src/enrichment_jobs.py`) that lowers `n.confidence_score`.
In merge paths, the correct pattern is:
```cypher
SET n.confidence_score = CASE
    WHEN n.confidence_score IS NULL OR $confidence > n.confidence_score
    THEN $confidence
    ELSE n.confidence_score END
```

### `SOURCED_FROM` edge `raw_data` preserves original provenance
`r.raw_data` on the `SOURCED_FROM` edge captures the **original** collector payload at first import.
It is set via `ON CREATE SET r.raw_data = …` and intentionally NOT overwritten on re-import.
`r.confidence`, `r.source`, and `r.updated_at` are updated on every import; `r.raw_data` and `r.imported_at` are immutable after creation.

---

## 15. ENRICHMENT JOBS — Blocking

### Enrichment job not idempotent
All enrichment jobs in `src/enrichment_jobs.py` must use `MERGE` (not `CREATE`) for every node and relationship they produce.
Running the same job twice must produce identical graph state. Flag any job that uses `CREATE` for nodes or relationships, which would produce duplicates on every pipeline run.

### Confidence decay job using wrong time comparison
The decay job must compare `datetime()` against `n.last_updated` (when the node was last seen in fresh data), not `n.first_imported_at` (when it was first seen).
Using `first_imported_at` would decay newly created nodes that haven't had a chance to be updated yet.
Flag any decay WHERE clause that references `first_imported_at` for age calculation.

### Decay job retires nodes without logging
When `ioc_confidence_decay` sets `n.active = false`, it must:
1. Set `n.retired_at = datetime()`
2. Log the count of retired nodes at INFO level

Flag any decay path that silently marks nodes inactive without recording `retired_at` or logging a count.

### Campaign builder creates campaign with only one indicator
`build_campaign_nodes` should only create a `Campaign` node when there is meaningful evidence of coordinated activity.
The query must include `WHERE size(indicators) >= 2` (or a configurable minimum).
Flag any campaign builder that creates campaigns for a single indicator — this produces noise that misleads analysts.

### `bridge_vulnerability_cve` not bidirectional
The enrichment job that creates `REFERS_TO` links between `Vulnerability` and `CVE` nodes must create **both directions**:
```cypher
MERGE (v)-[:REFERS_TO]->(c)
MERGE (c)-[:REFERS_TO]->(v)
```
This matches the ResilMesh schema. Flag any version that only creates the `(v)-[:REFERS_TO]->(c)` direction.

### Enrichment job missing error count in return dict
Every enrichment job function must return a dict with at minimum `{"linked": N, "errors": N}` (or equivalent counts).
Flag any job that returns `None`, `True`/`False`, or a dict without an error counter.

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
`EDGEGUARD_METRICS_HOST` must default to `127.0.0.1` so the Prometheus metrics endpoint is not reachable from other hosts on the shared ResilMesh server.
`0.0.0.0` is only acceptable when Prometheus runs on a separate machine and the override is explicitly documented in `.env.example`.
Flag any change to `METRICS_HOST` that sets the default to `0.0.0.0`.

### Health endpoint does not reflect actual dependency status
The `/health` endpoint in both `src/query_api.py` and `src/graphql_api.py` must verify that Neo4j is reachable before returning `{"status": "ok"}`.
Flag any `/health` implementation that returns 200 unconditionally without checking the Neo4j connection.

### New data source not added to source reliability table
`src/neo4j_client.py` maintains a `SOURCES` dict with `reliability` scores for each source.
If a new collector is added, flag if there is no corresponding entry in `SOURCES` with an appropriate `reliability` value (0.0–1.0).
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
| `edgeguard_neo4j_sync` | 22h |
| `edgeguard_baseline` | 32h |

### Every task must have `execution_timeout`

All `PythonOperator` and `BashOperator` tasks must set `execution_timeout`. Without it, a single task can hang forever (e.g., MISP unresponsive) within the DAG run. Flag any task missing `execution_timeout`.

### `dagrun_timeout` must be recalculated when task timeouts or retries change

If someone changes a task's `execution_timeout`, or changes `retries`/`retry_delay` in `default_args`, the parent DAG's `dagrun_timeout` may need updating. Flag such changes without a corresponding `dagrun_timeout` update and ask for verification.

### `default_args` must include `on_failure_callback`

The `default_args` dict must include `on_failure_callback` pointing to `_on_task_failure`. This ensures all task failures are logged with `[ALERT]` and optionally sent to Slack. Flag removal of this callback.

### `default_args` must include `on_success_callback`

The `default_args` dict must include `on_success_callback` pointing to `_on_task_success`. This updates the `edgeguard_dag_last_success_timestamp` Prometheus gauge for stuck-run detection. Without it, the `EdgeGuardDAGLastSuccessStale` alert becomes dead code. Flag removal of this callback.

### Baseline DAG must have `is_paused_upon_creation=False`

`edgeguard_baseline` must set `is_paused_upon_creation=False`. Without this, manual triggers silently queue forever because Airflow starts DAGs paused by default. The `schedule_interval=None` already prevents automatic execution. Flag removal of this setting.

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

### `clear_checkpoint()` must preserve incremental state

`src/baseline_checkpoint.py` `clear_checkpoint(source=None)` (the `--fresh-baseline` path) must preserve `"incremental"` sub-dicts inside each source entry. These hold OTX `modified_since` cursors, MITRE ETags, etc. Destroying them forces scheduled runs to re-process all historical data. Flag any change to `clear_checkpoint` that deletes incremental state on the global (no-source) path.

### Prometheus stuck-run alerts require gauge wiring

The `EdgeGuardDAGRunStuck` and `EdgeGuardDAGLastSuccessStale` alerts in `prometheus/alerts.yml` depend on `edgeguard_dag_run_start_timestamp` and `edgeguard_dag_last_success_timestamp` gauges being set by the DAG code. If these gauges are defined but never `.set()`, the alerts are dead code. Flag removal of `on_success_callback` or the `DAG_LAST_SUCCESS`/`DAG_RUN_START` gauge definitions without also removing the corresponding alerts.

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
- `DAG_RUN_START`: `["dag_id"]`

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
