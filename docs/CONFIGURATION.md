# EdgeGuard settings reference

Every EdgeGuard setting is an environment variable; a few baseline and sync controls are Airflow Variables. This page lists them by area, with their defaults and what they do. `.env.example` is the annotated template, and [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md) explains which limit applies at which stage. Deployment shapes (the `EDGEGUARD_ENV` label, conda, edge devices, service addresses) are in [ENVIRONMENTS.md](ENVIRONMENTS.md).

---

## How settings reach the code

- **No `.env` loading in the code.** Every module reads `os.environ`. A value in `.env` reaches a process only when Docker Compose forwards it or the shell exports it (`set -a; . ./.env; set +a`).
- **Docker Compose** substitutes `.env` into `docker-compose.yml`. The `x-common-env` block goes to `airflow`, `api` and `graphql`; each service's own `environment` adds what only that service reads. A variable Compose does not forward has no effect in the containers, whatever `.env` says.
- **Fixed values.** Some values are literals in `docker-compose.yml`, so `.env` cannot change them there: `NEO4J_URI` (`bolt://neo4j:7687`), `EDGEGUARD_API_PORT` (`8000`), `EDGEGUARD_GRAPHQL_PORT` (`4001`), `EDGEGUARD_METRICS_PORT` (`8001`), `EDGEGUARD_API_WORKERS` and `EDGEGUARD_GRAPHQL_WORKERS` (`2`), and the host ports, which are published on 127.0.0.1.
- **Applying a change.** Run `docker compose up -d` (or `docker compose up -d <service>`), which recreates the containers whose settings changed; `docker compose restart` keeps the old environment.
- **Defaults.** "Default" below is the code's default. Where Compose sets another value, the table says so.

---

## MISP connection

| Variable | Default | Purpose |
|---|---|---|
| `MISP_URL` | `https://localhost:8443` | Base URL of your MISP |
| `MISP_API_KEY` | required | MISP automation key |
| `EDGEGUARD_MISP_HTTP_HOST` | unset | `Host` header when MISP's virtual host differs from the URL |
| `EDGEGUARD_MISP_EVENT_SEARCH` | `EdgeGuard` | Text that identifies EdgeGuard events in `Event.info` |
| `EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS` | `false` | The DAGs' MISP check also requires MISP's background workers |
| `EDGEGUARD_SKIP_MISP_PREFLIGHT` | `false` | The DAGs skip their MISP check (emergency use; logged) |

- On the Compose stack an unset `MISP_URL` becomes `https://misp.local`, which usually does not resolve inside the containers: set the address the containers reach ([MISP_SOURCES.md](MISP_SOURCES.md)).
- `EDGEGUARD_MISP_EVENT_SEARCH` filters the event index and the `restSearch` fallback; the fallback sends it as `eventinfo` (MISP 2.4.177 or later). It must match the event titles (`EdgeGuard-<source>-<date>`).

---

## Neo4j connection and memory

| Variable | Default | Purpose |
|---|---|---|
| `NEO4J_URI` | `bolt://localhost:7687` | Bolt address; the scheme selects TLS |
| `NEO4J_USER` | `neo4j` | Neo4j user |
| `NEO4J_PASSWORD` | required | Neo4j password |
| `NEO4J_DATABASE` | unset | Database of every session (multi-database servers) |
| `NEO4J_HTTP` | `http://neo4j:7474` on Compose | Neo4j HTTP API of the DAG diagnostics; of the host scripts when `NEO4J_HTTP_URL` is unset |
| `NEO4J_HTTP_URL` | `http://127.0.0.1:7474` | Neo4j HTTP API of the host scripts |
| `NEO4J_HTTP_USER_AGENT` | a browser's | User-Agent of the host scripts' HTTP requests |
| `NEO4J_WSS_HOST` | unset | Host of the Bolt-over-WebSocket bridge: `scripts/neo4j_wss_bridge.py` run on its own exits 2 without it; `tests/test_cypher_query_catalog.py` uses the bridge when it is set |
| `NEO4J_HEAP_INITIAL` | `512m` | JVM initial heap of the `neo4j` service |
| `NEO4J_HEAP_MAX` | `2g` | JVM maximum heap |
| `NEO4J_PAGECACHE` | `1g` | Page cache |
| `NEO4J_TX_MEMORY_MAX` | `4g` | Cap of all running transactions together |
| `NEO4J_CONTAINER_MEMORY_LIMIT` | `8g` | Container memory limit of `neo4j` |

- `NEO4J_URI` is fixed to `bolt://neo4j:7687` inside the Compose services; a value in `.env` applies to host-side commands only, which use `bolt://localhost:7687`. TLS schemes: `bolt+s://` / `neo4j+s://` (system CAs) and `bolt+ssc://` / `neo4j+ssc://` (self-signed); `EDGEGUARD_SSL_VERIFY` does not apply to Bolt.
- Neo4j applies `NEO4J_PASSWORD` when it creates its data volume and keeps that password afterwards.
- `NEO4J_DATABASE` unset or empty uses the server's default database.
- The five memory variables are set in the `neo4j` service of `docker-compose.yml`; the values above are the Compose defaults. `NEO4J_TX_MEMORY_MAX` limits transaction memory inside the heap and off-heap budget and is not added to it; the 8g container default covers the default heap, page cache and off-heap overhead.
- A 730-day baseline needs the baseline-capable profile: heap 12g (initial = maximum), page cache 8g, transaction memory 8g, container 32g ([MEMORY_TUNING.md](MEMORY_TUNING.md), [DOCKER_SETUP_GUIDE.md](DOCKER_SETUP_GUIDE.md#recommended-neo4j-memory-profiles)). `edgeguard doctor --memory`, run on the Compose host, compares the values in effect with the recommended ones ([CLI.md](CLI.md#readiness-and-diagnosis)).
- `scripts/verify_fresh_baseline.py`, `scripts/run_cypher_catalog_http.py` and `scripts/build_canonical_threat_actors.py` build their requests with `src/neo4j_http_endpoint.py`: they read `NEO4J_HTTP_URL`, then `NEO4J_HTTP`, and with neither set (or both empty) use `http://127.0.0.1:7474`, the HTTP port the `neo4j` service of `docker-compose.yml` publishes on host loopback. They send `NEO4J_USER` and `NEO4J_PASSWORD` to that address only; there is no remote default. A set value must be an `http://` or `https://` URL with a host, a numeric port from 0 to 65535 when it names one, and no space or control character: another value stops the script with exit code 2 before any request. `NEO4J_DATABASE` unset or empty is `neo4j` in their request path. `.env.example` lists `NEO4J_HTTP` commented out.
- `NEO4J_HTTP_USER_AGENT` unset or empty, the three scripts send a browser's User-Agent: a Cloudflare proxy in front of a hosted instance rejects urllib's default agent (HTTP 403, error 1010).
- `scripts/neo4j_wss_bridge.py` run on its own sends `NEO4J_USER` and `NEO4J_PASSWORD` to `wss://<NEO4J_WSS_HOST>`; unset or empty, it exits with code 2 before it connects.

---

## Source API keys and selection

| Variable | Default | Purpose |
|---|---|---|
| `OTX_API_KEY` | unset | AlienVault OTX; without it OTX is skipped |
| `NVD_API_KEY` | unset | NVD; without it NVD runs at the lower anonymous rate |
| `THREATFOX_API_KEY` | unset | abuse.ch key; ThreatFox, URLhaus and MalwareBazaar are skipped without it |
| `ABUSEIPDB_API_KEY` | unset | AbuseIPDB; skipped without it |
| `VIRUSTOTAL_API_KEY` | unset | VirusTotal lookups; skipped without it |
| `EDGEGUARD_COLLECT_SOURCES` | unset (all) | Comma-separated allowlist of collectors |
| `EDGEGUARD_SOURCE_KEY_CHECK` | `true` | Ask each provider whether it accepts the key |
| `EDGEGUARD_BASELINE_REQUIRED_SOURCES` | empty | Keyed sources a baseline must not start without |

- `THREATFOX_API_KEY` is also the key of the URLhaus and MalwareBazaar exports, part of the export URL path (redacted in every log line); without it both are skipped.
- The key check runs in `edgeguard preflight`, `scripts/preflight_baseline.sh` and the baseline task `source_key_check`, one authenticated request per key; `false` reports configured keys as unverified. One ThreatFox query checks the abuse.ch key, and its line names each of ThreatFox, URLhaus and MalwareBazaar that is switched on.
- `EDGEGUARD_BASELINE_REQUIRED_SOURCES` takes `otx`, `nvd`, `virustotal`, `threatfox`, `urlhaus`, `malwarebazaar` and `abuseipdb`; `urlhaus` and `malwarebazaar` are judged by `THREATFOX_API_KEY`. A listed source without a key, with a rejected key or switched off (for MalwareBazaar also `EDGEGUARD_ENABLE_MALWAREBAZAAR=false`) fails `source_key_check`, before the lock and the wipe, and is an error in `edgeguard preflight`.
- How to obtain each key: [API_KEYS_SETUP.md](API_KEYS_SETUP.md).

---

## Optional sources

| Variable | Default | Purpose |
|---|---|---|
| `EDGEGUARD_ENABLE_CISA_ICS` | `false` | CISA ICS advisories (CSAF 2.0) with CISA's sectors |
| `EDGEGUARD_ENABLE_MITRE_ICS` | `false` | MITRE ATT&CK for ICS in the MITRE collector |
| `EDGEGUARD_ENABLE_MALWAREBAZAAR` | `false` | MalwareBazaar sample hashes with the family label |
| `EDGEGUARD_ENABLE_EPSS` | `true` | FIRST EPSS scores on existing CVE nodes |

- CISA ICS maps CISA's sectors to `energy`, `healthcare` and `finance`; its `AFFECTS` links carry `advisory_sector` at 0.9. It runs as an isolated daily task and in the baseline.
- ATT&CK for ICS items carry `attack_domain = ics`; a failed ICS fetch never affects the Enterprise ingest.
- MalwareBazaar reads the export of the last 48 hours (abuse.ch Auth-Key required); its samples link to `Malware` nodes by `INDICATES`.
- EPSS runs after every Neo4j sync and the baseline; a feed outage is logged and skipped.
- On an existing graph, an additive baseline loads the history of CISA ICS and ATT&CK for ICS; for ATT&CK for ICS, `MITRE_FORCE_REFETCH=true` for one daily run also works.

---

## Per-source limits and windows

**Vulnerabilities**

| Variable | Default | Purpose |
|---|---|---|
| `EDGEGUARD_NVD_INCREMENTAL_DAYS` | `14` | NVD look-back without a stored cursor |
| `EDGEGUARD_NVD_CURSOR_OVERLAP_SEC` | `3600` | NVD runs start this far before the cursor (at least 60) |
| `EDGEGUARD_NVD_MAX_PER_RUN` | `5000` | MISP writes per NVD incremental run |
| `EDGEGUARD_NVD_UPDATE_EXISTING` | `true` | Edit the MISP copy of a CVE NVD changed |
| `EDGEGUARD_NVD_BASELINE_KEV_SWEEP` | `true` | Baseline fetches the NVD record of every KEV CVE |
| `EDGEGUARD_NVD_EXTRA_CVE_IDS` | empty | CVE ids a baseline fetches by id (at most 2,000) |
| `EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE` | `true` | Every KEV run compares the whole catalogue with MISP |
| `EDGEGUARD_KEV_MAX_EDITS_PER_RUN` | `500` | Revised KEV copies edited per run |
| `EDGEGUARD_KEV_UPDATE_EXISTING` | `true` | Edit the MISP copy of a KEV entry CISA revised |
| `EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS` | `30` | CISA ICS look-back without a stored cursor |
| `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` | `1200` | Advisory files fetched per run |
| `EDGEGUARD_CISA_ICS_MIN_EXPECTED_ADVISORIES` | `50` | Baseline sanity floor of parsed advisories |
| `EDGEGUARD_CISA_ICS_BASE_URL` | the `cisagov/CSAF` folder | Raw base URL of the CSAF advisories |
| `EPSS_URL` | the FIRST daily file | Address of the EPSS gzip CSV |
| `EPSS_MAX_BYTES` | `67108864` | Download abort size (compressed bytes) |
| `EPSS_DOWNLOAD_DEADLINE_SEC` | `300` | Download abort time |

- NVD incremental runs read every CVE modified since the cursor and add the new ones published within `EDGEGUARD_BASELINE_DAYS` (730 when unset; the Airflow Variable `BASELINE_DAYS` does not apply), on KEV or named in `EDGEGUARD_NVD_EXTRA_CVE_IDS`. A run that reaches `EDGEGUARD_NVD_MAX_PER_RUN` stops there and the next run continues.
- With `EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE=false` KEV uses the baseline window, and an entry outside it follows no revision. KEV edits beyond the cap are deferred to the next run; additions are not capped ([COLLECTORS.md § 3](COLLECTORS.md#revisions-every-run-compares-the-catalogue-with-misp)).
- When at least `EDGEGUARD_CISA_ICS_MIN_EXPECTED_ADVISORIES` advisories were attempted but fewer parsed, or the index lists none in the window, a CISA ICS baseline pushes nothing and its task is skipped with an alert.
- Default addresses: `EDGEGUARD_CISA_ICS_BASE_URL` is the `csaf_files/OT/white/` folder of the `cisagov/CSAF` repository on `raw.githubusercontent.com`; `EPSS_URL` is the current scores file of FIRST EPSS:

  ```
  https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
  ```

**ATT&CK and OTX**

| Variable | Default | Purpose |
|---|---|---|
| `EDGEGUARD_MITRE_CONDITIONAL_GET` | `true` | Scheduled runs skip an unchanged ATT&CK bundle (ETag) |
| `MITRE_FORCE_REFETCH` | unset | Skip the ETag check: full download and push |
| `MITRE_ICS_ATTACK_URL` | the MITRE CTI file | Address of the ATT&CK for ICS bundle |
| `EDGEGUARD_MITRE_MAX_RELATIONSHIPS` | `0` (no cap) | Relationship edges per ATT&CK sync |
| `EDGEGUARD_OTX_BASELINE_MAX_PAGES` | `200` | OTX pages (50 pulses each) per baseline |
| `EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES` | `25` | OTX pages per incremental run |
| `EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS` | `3` | First incremental run: `modified_since` look-back |
| `EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC` | `300` | Overlap subtracted from the stored OTX cursor |

- A baseline always downloads the ATT&CK bundle. `MITRE_FORCE_REFETCH=true` makes scheduled runs do the same, for example for one run after enabling ATT&CK for ICS.
- `MITRE_ICS_ATTACK_URL` unset or empty uses `ics-attack/ics-attack.json` of the `mitre/cti` repository.
- `EDGEGUARD_MITRE_MAX_RELATIONSHIPS` also reads the older name `MITRE_MAX_RELATIONSHIPS`.
- A baseline that stops at `EDGEGUARD_OTX_BASELINE_MAX_PAGES` with a full last page logs a warning, because older pulses of the window were not read; raise it for very active subscriptions.

**Indicator feeds**

| Variable | Default | Purpose |
|---|---|---|
| `EDGEGUARD_THREATFOX_MAX_PER_RUN` | `10000` | ThreatFox indicators per run (newest kept) |
| `EDGEGUARD_URLHAUS_MAX_PER_RUN` | `100000` | URLhaus URLs per run (newest kept); above the whole `recent.csv` export |
| `EDGEGUARD_FEODO_MAX_PER_RUN` | `15000` | Feodo Tracker servers per run |
| `EDGEGUARD_SSLBL_MAX_PER_RUN` | `20000` | SSL Blacklist certificates per run |
| `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` | `10000` | Limit of the one AbuseIPDB blacklist request per run |
| `EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS` | `20` | Reuse of the day's blacklist answer (`0` = off) |
| `EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN` | `500` | MalwareBazaar samples pushed per run |
| `EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET` | `400` | VirusTotal lookups per UTC day |
| `EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN` | `60` | VirusTotal lookups per run (at most 200) |
| `EDGEGUARD_VIRUSTOTAL_CANDIDATE_DAYS` | `30` | Age window of the MISP hashes looked up |
| `EDGEGUARD_VIRUSTOTAL_BUDGET_PATH` | in the state directory | VirusTotal daily ledger file |

- The ThreatFox, URLhaus, Feodo Tracker, SSL Blacklist, AbuseIPDB and MalwareBazaar caps replace `EDGEGUARD_INCREMENTAL_LIMIT` for their sources, in baseline and scheduled runs alike; `0` means no cap, except for AbuseIPDB, where `0` means 10,000.
- ThreatFox's API returns at most the last 7 days and URLhaus its `recent.csv` export (about 63,000 URLs on 2026-10-24); a run that reaches its cap keeps the newest items and logs a warning.
- AbuseIPDB makes at most one blacklist request per run, none when it reuses the answer fetched earlier on the same UTC day; the free plan returns at most 10,000 addresses per request and allows 5 blacklist requests per day, and a 429 fails `collect_abuseipdb` ([RUNBOOK.md § AbuseIPDB daily blacklist quota](RUNBOOK.md#abuseipdb-daily-blacklist-quota-429)).
- MalwareBazaar keeps labelled samples first. VirusTotal's free tier allows 500 lookups per day; an exhausted budget skips the task (log prefix `[VT-QUOTA]`). The ledger file defaults to `virustotal_daily_budget.json` in the state directory.

---

## Collection limits and the MISP push

| Variable | Default | Purpose |
|---|---|---|
| `EDGEGUARD_INCREMENTAL_LIMIT` | `200` | Items per source per scheduled run (OTX) |
| `EDGEGUARD_MAX_ENTRIES` | `0` (off) | Global override of every per-run cap |
| `EDGEGUARD_MISP_PUSH_BATCH_SIZE` | `500` | Attributes per MISP push batch |
| `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` | `5.0` | Pause between push batches and edit groups |
| `EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD` | `50000` | From this event size: 100 per batch, 15 s pause |
| `EDGEGUARD_MISP_HUGE_EVENT_THRESHOLD` | `100000` | From this event size: 50 per batch, 30 s pause |
| `EDGEGUARD_MISP_BACKOFF_THRESHOLD` | `3` | Consecutive failed batches before a cooldown |
| `EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC` | `300` | Length of that cooldown |
| `EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS` | `true` | Skip values the target event already holds |
| `EDGEGUARD_MISP_CROSS_EVENT_DEDUP` | `true` | Skip values the source holds in any EdgeGuard event |
| `EDGEGUARD_MISP_MIN_SUCCESS_RATE` | `0.95` | Share of attempted pushes that must succeed |
| `EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING` | `false` | Count unconfirmed attributes as failed pushes |
| `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS` | `30` | Refresh a re-reported indicator's MISP copy after this age |
| `EDGEGUARD_MISP_REFRESH_MAX_PER_RUN` | `2000` | Refresh edits per run (`0` = no cap) |
| `EDGEGUARD_MISP_REFRESH_MAX_SECONDS` | `600` | Time spent on refresh edits per run (`0` = no limit) |
| `EDGEGUARD_DEFAULT_TLP` | `white` | TLP level of an item whose source states none |
| `EDGEGUARD_ZONE_DETECT_THRESHOLD` | `1.5` | Minimum keyword score for a sector in one text |
| `EDGEGUARD_ZONE_ITEM_THRESHOLD` | `1.5` | Minimum combined keyword score of an item |
| `EDGEGUARD_EARLIEST_IOC_DATE` | `1995-01-01` | Earliest source date accepted as first-seen |

- `EDGEGUARD_INCREMENTAL_LIMIT` applies to the sources without their own per-run rule: OTX, and VirusTotal, which is bounded by its lookup cap of 60 first. NVD, CISA KEV, CISA ICS, MITRE ATT&CK (the whole changed bundle) and the indicator feeds above apply their own rules (`OWN_RUN_CAP_SOURCES` in `src/config.py`). `docker-compose.yml` forwards neither `EDGEGUARD_INCREMENTAL_LIMIT` nor `EDGEGUARD_MAX_ENTRIES`; on that deployment set them in the `airflow` service environment.
- `EDGEGUARD_MAX_ENTRIES` above `0` caps every source, the own-rule sources included when it is lower.
- The large-event tiers depend on the size of the target event, which the duplicate check reads; a cooldown follows sustained 5xx answers. MISP server settings for such events: [MISP_TUNING.md](MISP_TUNING.md).
- `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` also paces every 50 edits of an NVD incremental run, of a CISA KEV run and of the refresh. `0` removes the pause except the large-event floors.
- `EDGEGUARD_MISP_MIN_SUCCESS_RATE` fails the collector task below that share; skipped duplicates are not attempts, `0` disables the check, and a value outside [0, 1] falls back to the default with a warning.
- The refresh edits the stored copy of an indicator a run reports again, once MISP last wrote it more than the interval ago, so the incremental sync reads it again; value, type, tags and comment do not change ([COLLECTORS.md § Re-reported indicators](COLLECTORS.md#re-reported-indicators)). `EDGEGUARD_MISP_REFRESH_MAX_SECONDS` also bounds the CISA KEV edits of a run, and both stop after 5 failed edits in a row.
- `EDGEGUARD_DEFAULT_TLP` is stamped as `tlp:<level>`; a source that states its own level (OTX `pulse_tlp`) overrides it, and the sync applies it to an attribute without a `tlp:` tag and logs it (`[TLP]`).

---

## Baseline

| Variable | Default | Purpose |
|---|---|---|
| `EDGEGUARD_BASELINE_DAYS` | unset (730) | Baseline window; also the scope of scheduled NVD runs |
| `EDGEGUARD_BASELINE_COLLECTION_LIMIT` | unset (`0`) | Items per source in a baseline (`0` = no cap) |
| `EDGEGUARD_BASELINE_LOCK_PATH` | `checkpoints/baseline_in_progress.lock` | Baseline lock file |
| `EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC` | `172800` (48 h) | Age after which a leftover lock is released |
| `EDGEGUARD_LAST_BACKUP_AT` | unset | Time of the last backup, for the backup gate |
| `EDGEGUARD_BACKUP_MAX_AGE_HOURS` | `240` | How old that backup may be |
| `EDGEGUARD_PARENT_DAG_LIVENESS_CHECK` | `true` | A baseline collector stops when its DAG run ended |
| `EDGEGUARD_LIVENESS_CHECK_INTERVAL_SEC` | `60` | Least time between two of those checks |

**Airflow Variables**

| Variable | Default | Purpose |
|---|---|---|
| `BASELINE_DAYS` | `730` | Baseline window |
| `BASELINE_COLLECTION_LIMIT` | `0` | Items per source in a baseline (`0` = no cap) |
| `NEO4J_FULL_SYNC` | `false` | The next sync is a full sync; cleared after success |
| `SKIP_NEXT_NEO4J_SYNC` | `false` | Skip the next incremental sync once |

- Window precedence: the run configuration's `baseline_days` (or `edgeguard baseline --days N`), then `EDGEGUARD_BASELINE_DAYS`, then the Airflow Variable `BASELINE_DAYS`, then 730. The collection limit follows the same order. ThreatFox reaches back at most 7 days, and CISA KEV ignores the window unless `EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE=false`.
- Remove a short test value of `EDGEGUARD_BASELINE_DAYS` after a smoke test: it also narrows the scheduled NVD runs ([BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md)).
- The lock file is derived from the module location (`<repository>/checkpoints/`, mounted at `/opt/airflow/checkpoints` in the container). The 48-hour age is above the baseline's 32-hour `dagrun_timeout`; on the same host the holder's liveness is checked first.
- The backup gate of `edgeguard fresh-baseline` and the `baseline_clean` task refuses a wipe of non-empty stores unless `EDGEGUARD_LAST_BACKUP_AT` (ISO 8601 or Unix seconds) lies within `EDGEGUARD_BACKUP_MAX_AGE_HOURS`. The bypasses are explicit and logged (`--skip-backup-check`, or `skip_backup_check: true` in the run configuration) ([BACKUP.md](BACKUP.md)). Compose forwards both variables to `airflow` only.
- The liveness check calls the Airflow REST API between MISP write batches.

---

## MISP → Neo4j sync

| Variable | Default | Purpose |
|---|---|---|
| `EDGEGUARD_SYNC_INTERVAL_DAYS` | `3` | Window of `run_misp_to_neo4j.py` on its own (plus 1 day) |
| `EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS` | `1` | The Airflow sync reads back this far before the last sync |
| `EDGEGUARD_SYNC_ATTRIBUTE_FILTER` | `true` | Incremental syncs write only changed attributes |
| `EDGEGUARD_SYNC_MIN_EVENTS` | `1` | Fewest events a sync window must return (`0` = off) |
| `EDGEGUARD_MISP_PAGE_SIZE` | `500` | Rows per page of the MISP event index |
| `EDGEGUARD_MISP_MAX_PAGES` | `100` | Index pages per sync run |
| `EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC` | `2.0` | Pause between event fetches |
| `EDGEGUARD_MAX_EVENT_ATTRIBUTES` | `50000` | Larger events are deferred to the end (`0` = off) |
| `EDGEGUARD_MISP_PAGED_FETCH_ABOVE` | `20000` | Larger events are fetched as `/events/restSearch` metadata plus `/attributes/restSearch` pages of 5000 instead of one `/events/view` (`0` = off; a whole-event fetch that keeps answering 5xx falls back to pages either way) |
| `EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES` | `4096` | Largest attribute value the sync accepts |
| `EDGEGUARD_MISP_RETRY_COOLDOWN_SEC` | `15.0` | Pause before retrying events that failed |
| `EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE` | `500` | Parsed items merged per chunk |
| `EDGEGUARD_REL_BATCH_SIZE` | `500` | Relationships per Neo4j write batch |
| `EDGEGUARD_NEO4J_READ_TIMEOUT` | `3600` | Transaction timeout of pipeline statements (s) |
| `EDGEGUARD_MISP_DELETE_TIMEOUT_SEC` | `900` | Read timeout of one MISP event delete |
| `EDGEGUARD_QUERY_PAUSE_SECONDS` | `0` | Pause between Neo4j chunks (at most 60) |
| `EDGEGUARD_DEBUG_GC` | unset | `gc.collect()` after each node chunk (diagnostics) |
| `EDGEGUARD_SUBPROCESS_TAIL_LINES` | `2000` | Output lines kept from a subprocess step |

- The overlap is short so that the first sync after a baseline does not rewrite the whole baseline; it holds because the collectors and the sync use the same MISP and the Airflow and MISP hosts keep their clocks synchronised. Values from 0 to 60 s become 60 s; a value that is not a number, is negative or is above 720 falls back to the default. A MISP filled by MISP-to-MISP synchronisation keeps the origin's timestamps and needs an overlap above the copy delay.
- An edit that changes only event-level tags, and a Neo4j restored from a dump older than MISP, need a full sync (`NEO4J_FULL_SYNC=true`); `EDGEGUARD_SYNC_ATTRIBUTE_FILTER=false` processes whole events.
- A window with fewer than `EDGEGUARD_SYNC_MIN_EVENTS` events is a failed run, not an empty success.
- A listing that reaches `EDGEGUARD_MISP_MAX_PAGES` with a full last page is incomplete: the run is reported as failed and keeps its cursor. Raise the cap when the index holds more rows than pages × page size.
- A value longer than `EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES` (UTF-8 bytes) is skipped with a warning; values below 64 count as 64.
- Lower `EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE` (for example to 250) when the worker is killed for memory after the parse; `0` or `all` merges everything in one pass, with a high risk of running out of memory. Lower `EDGEGUARD_REL_BATCH_SIZE` when Neo4j transactions time out on very large events ([HEARTBEAT.md](HEARTBEAT.md)).
- `EDGEGUARD_NEO4J_READ_TIMEOUT` lets the server abort a statement that hangs (`[NEO4J-TIMEOUT]` in the task log); relationship batch writes use 600 s and the REST and STIX queries 300 s.
- `EDGEGUARD_MISP_DELETE_TIMEOUT_SEC` applies to the fresh-baseline wipe, `edgeguard clear misp` and `scripts/clear_misp.py`.

---

## Enrichment

| Variable | Default | Purpose |
|---|---|---|
| `EDGEGUARD_AGING_TIER_DAYS` | `90,180,365` | Ages from which the aging factors apply |
| `EDGEGUARD_AGING_FACTORS` | `0.85,0.70,0.55` | Confidence factor per tier |
| `EDGEGUARD_AGING_RETIRE_DAYS` | `730` | Age without a report at which an indicator retires |
| `EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE` | `true` | Merge duplicate actors (`false` = report only) |
| `EDGEGUARD_CANONICAL_THREAT_ACTORS` | the shipped file | Path of the canonical threat-actor reference |
| `EDGEGUARD_ENABLE_MALWARE_TWIN_MERGE` | `true` | Fold ATT&CK malware twins (`false` = report only) |

- An indicator's confidence is `max(0.10, round(source_confidence × factor, 2))` from its latest report; tier days are strictly ascending, factors lie in (0, 1], and the retirement age lies above the last tier day. A wrong value stops the indicator writes and the aging job with an error ([KNOWLEDGE_GRAPH.md § Indicator aging](KNOWLEDGE_GRAPH.md#indicator-aging)).
- The actor merge folds a non-MITRE actor into the MITRE actor whose alias it is, or into the actor the canonical reference resolves it to. The shipped reference is `src/reference/canonical_threat_actors.json`; a missing or invalid file makes the merge use the ATT&CK aliases alone, with one warning ([RUNBOOK.md § Canonical threat-actor reference](RUNBOOK.md#canonical-threat-actor-reference)).
- The twin merge folds a non-MITRE `Malware` node named after an ATT&CK software id (`cobalt strike - s0154`) into the ATT&CK node of that id, or into the node of its base name.

---

## REST and GraphQL APIs

| Variable | Default | Purpose |
|---|---|---|
| `EDGEGUARD_API_KEY` | unset | Key both APIs require in the `X-API-Key` header |
| `EDGEGUARD_ENV` | unset (production) | Environment label; decides the production checks |
| `EDGEGUARD_ALLOW_UNAUTH` | unset | Start without a key on a non-loopback bind (non-production only) |
| `EDGEGUARD_CORS_ORIGINS` | two localhost origins | CORS allowlist of both APIs |
| `EDGEGUARD_API_HOST` | `127.0.0.1` | REST bind address (`0.0.0.0` on Compose) |
| `EDGEGUARD_API_PORT` | `8000` | REST port (fixed on Compose) |
| `EDGEGUARD_API_WORKERS` | `1` | REST worker processes (`2` on Compose) |
| `EDGEGUARD_API_RELOAD` | `false` | Reload on code change (development; one worker) |
| `EDGEGUARD_GRAPHQL_HOST` | `127.0.0.1` | GraphQL bind address (`0.0.0.0` on Compose) |
| `EDGEGUARD_GRAPHQL_PORT` | `4001` | GraphQL port (fixed on Compose) |
| `EDGEGUARD_GRAPHQL_WORKERS` | `1` | GraphQL worker processes (`2` on Compose) |
| `EDGEGUARD_GRAPHQL_PLAYGROUND` | `false` | Serve GraphiQL at `/graphql` |
| `EDGEGUARD_MAX_BODY_BYTES` | `1048576` | Largest request body; larger answers 413 |
| `EDGEGUARD_GRAPHQL_MAX_DEPTH` | `8` | GraphQL query depth limit |
| `EDGEGUARD_GRAPHQL_MAX_ALIASES` | `15` | Root fields one operation executes |
| `EDGEGUARD_GRAPHQL_MAX_SELECTIONS` | `2000` | Expanded selection budget of an operation |
| `EDGEGUARD_RATE_LIMIT_READ` | `60/minute` | Per-address limit of the REST data routes |
| `EDGEGUARD_RATE_LIMIT_ADMIN` | `10/minute` | Per-address limit of `POST /admin/query` |
| `EDGEGUARD_RATE_LIMIT_GRAPHQL` | `120/minute` | Per-address limit of every GraphQL route |
| `EDGEGUARD_ENABLE_ADMIN_QUERY` | `false` | Enable `POST /admin/query` (read-only Cypher) |
| `EDGEGUARD_ADMIN_TOKEN` | unset | Token `POST /admin/query` expects |
| `EDGEGUARD_GIT_SHA` | unset | Deployed commit, reported by `/health` |

- **Production** is `EDGEGUARD_ENV` unset, empty or any value other than `dev`, `development`, `local`, `staging` and `test` (`stage` and `edge` included). In production both APIs refuse to start without `EDGEGUARD_API_KEY`, whatever `EDGEGUARD_ALLOW_UNAUTH` says, GraphQL introspection is blocked, `/docs` and `/redoc` are off and `/openapi.json` needs the key. In non-production an API without a key starts only on a loopback bind or with `EDGEGUARD_ALLOW_UNAUTH=1` ([ENVIRONMENTS.md](ENVIRONMENTS.md)).
- `./install.sh` generates `EDGEGUARD_API_KEY` when it is blank. `GET /health` needs no key.
- The CORS default is `http://localhost,http://localhost:3000`; append an origin exactly as the browser shows it, never `*`, and recreate both APIs (`docker compose up -d api graphql`). The Graph Explorer depends on it ([GRAPH_EXPLORER.md](GRAPH_EXPLORER.md)).
- The rate limits count per client address; behind a reverse proxy every client shares the proxy's address, so raise `EDGEGUARD_RATE_LIMIT_GRAPHQL` (for example to `600/minute`) for integrations. An empty or invalid limit falls back to the default.
- `POST /admin/query` refuses write clauses and needs the `X-Admin-Token` header and, when it is set, the API key; enabled without a token it answers 503.
- `EDGEGUARD_GIT_SHA` is written into `.env` by `scripts/record_deployed_commit.sh`, which `./install.sh` runs; set it there, not as a shell export. Compose forwards it to `api` and `graphql` only. The REST and GraphQL `/health` responses report it as `git_sha` (null when unset) and STIX exports as the `X-EdgeGuard-Git-Sha` header ([DOCKER_SETUP_GUIDE.md](DOCKER_SETUP_GUIDE.md)).

---

## Airflow

Set on the `airflow` service of `docker-compose.yml`; a pip-installed Airflow sets them in its own installation. The host CLI also reads `AIRFLOW_API_USER`, `AIRFLOW_API_PASSWORD`, `AIRFLOW_API_VERSION` and `AIRFLOW_WEBSERVER_URL`.

| Variable | Default | Purpose |
|---|---|---|
| `AIRFLOW_API_AUTH_JWT_SECRET` | required | Signing secret of the Airflow API server |
| `AIRFLOW_FERNET_KEY` | required in production | Encryption key of Airflow's stored secrets |
| `AIRFLOW_API_USER` | `admin` | User of the Airflow REST calls (CLI and tasks) |
| `AIRFLOW_API_PASSWORD` | unset | Its password (required on the host) |
| `AIRFLOW_API_VERSION` | `v2` | `v2` (Airflow 3) or `v1` (Airflow 2) |
| `AIRFLOW_WEBSERVER_URL` | `http://localhost:8082` | Airflow API base URL for the CLI and tasks |
| `AIRFLOW_MEMORY_LIMIT` | `12g` | Container memory limit of `airflow` |
| `AIRFLOW_POSTGRES_USER` | `airflow` | Metadata database user (Compose) |
| `AIRFLOW_POSTGRES_PASSWORD` | `airflow` | Its password; set a strong one |
| `AIRFLOW_POSTGRES_DB` | `airflow` | Metadata database name |
| `AIRFLOW_POSTGRES_MEMORY_LIMIT` | `2g` | Container memory limit of `airflow_postgres` |
| `EDGEGUARD_COLLECTOR_POOL_SLOTS` | `4` | Slots of the collector pool across all DAGs |

- Compose passes `AIRFLOW_API_AUTH_JWT_SECRET` to Airflow as `AIRFLOW__API_AUTH__JWT_SECRET` and `AIRFLOW_FERNET_KEY` as `AIRFLOW__CORE__FERNET_KEY`; set the short names in `.env`. With an empty JWT secret the API server does not start; keep both values stable, because a new Fernet key makes the stored connections and variables unreadable. `./install.sh` generates both when they are blank.
- The CLI, the scheduled DAGs' check of the baseline lock's holder and the baseline collectors' liveness check exchange `AIRFLOW_API_USER` and `AIRFLOW_API_PASSWORD` for a token at `POST /auth/token` (`AIRFLOW_API_VERSION=v2`); Compose forwards both to the `airflow` service. With the password unset, a process inside the Airflow container reads the password file the Simple auth manager generates; on the host the password is required. A wrong password in `.env` also reaches the tasks: the lock check then falls back to the lock file's age, and the liveness check cannot tell whether the DAG run has ended.
- The password of `AIRFLOW_POSTGRES_PASSWORD` must stay URL-safe (no `@`, `#`, `/`, `?`), because it goes into the SQLAlchemy URI.
- Every collector task of every DAG runs in the pool `edgeguard_collectors`; the Compose `airflow` service creates or resizes it at every start, so apply a change with `docker compose up -d airflow`. Without Compose, create it once after `airflow db migrate`:

  ```bash
  airflow pools set edgeguard_collectors 4 "Collector tasks of all DAGs"
  ```

**Values fixed in `docker-compose.yml`**

- `AIRFLOW__CORE__EXECUTOR=LocalExecutor`, `AIRFLOW__CORE__LOAD_EXAMPLES=false`, `AIRFLOW__LOGGING__LOGGING_LEVEL=INFO`.
- `AIRFLOW__CORE__DAGS_FOLDER=/opt/airflow/dags` and `AIRFLOW__CORE__PLUGINS_FOLDER=/opt/airflow/plugins` (the repository's `plugins/`, with the listener plugin that marks each DAG run in progress).
- `AIRFLOW__API__PORT=8082` and `AIRFLOW__API__BASE_URL=http://localhost:8082`; port 8082 avoids ResilMesh's Temporal on 8080. `AIRFLOW__WEBSERVER__WEB_SERVER_PORT=8082` is the Airflow 2 name, which Airflow 3 does not read.
- `AIRFLOW__DATABASE__SQL_ALCHEMY_CONN`, built from the three `AIRFLOW_POSTGRES_*` values; a pip-installed Airflow sets its own.

**Task heartbeat timeouts** (both can be set in `.env`):

- `AIRFLOW__SCHEDULER__TASK_INSTANCE_HEARTBEAT_TIMEOUT`, default `3600` on Compose (Airflow's own default is 300): seconds after a task's last heartbeat at which the scheduler fails it.
- `AIRFLOW__SCHEDULER__TASK_INSTANCE_HEARTBEAT_TIMEOUT_DETECTION_INTERVAL`, default `60` on Compose (Airflow's default is 10): how often the scheduler looks for such tasks.
- Airflow 3 does not read the Airflow 2 names `SCHEDULER_ZOMBIE_TASK_THRESHOLD`, `ZOMBIE_DETECTION_INTERVAL` and `LOCAL_TASK_JOB_HEARTBEAT_SEC`. The value in effect: `docker compose exec airflow airflow config get-value scheduler task_instance_heartbeat_timeout` ([HEARTBEAT.md](HEARTBEAT.md)).

---

## Monitoring and alerting

| Variable | Default | Purpose |
|---|---|---|
| `PROMETHEUS_MULTIPROC_DIR` | unset | Shared metrics directory of the task processes |
| `EDGEGUARD_ENABLE_METRICS` | `false` | In-process metrics server (bare-metal installs) |
| `EDGEGUARD_METRICS_HOST` | `127.0.0.1` | Metrics bind address |
| `EDGEGUARD_METRICS_PORT` | `8001` | Metrics port (fixed on Compose) |
| `EDGEGUARD_VERSION` | `1.0.0` | `version` label of the in-process info metric |
| `GRAFANA_ADMIN_USER` | `admin` | Grafana admin user |
| `GRAFANA_ADMIN_PASSWORD` | required | Grafana admin password |
| `GRAFANA_ROOT_URL` | `http://localhost:3000` | Grafana root URL for links and alerts |
| `EDGEGUARD_ENABLE_SLACK_ALERTS` | unset | Slack message on a collector failure |
| `SLACK_WEBHOOK_URL` | unset | Webhook of those messages |
| `NATS_URL` | unset | Address the `edgeguard doctor` NATS check probes |

- On Compose, `PROMETHEUS_MULTIPROC_DIR` is `/opt/airflow/metrics_multiproc`: every task process writes its metrics there, and the `metrics` service aggregates and serves them on `127.0.0.1:8001`, binding `0.0.0.0` inside its container. A `.env` value of `EDGEGUARD_METRICS_HOST` does not reach that service.
- `EDGEGUARD_VERSION` applies only to a bare-metal single-process metrics server; in the multi-process mode of Compose the info metric is not exported. The APIs and logs take the version from `pyproject.toml`.
- `GRAFANA_ADMIN_USER`, `GRAFANA_ADMIN_PASSWORD` and `GRAFANA_ROOT_URL` are passed to Grafana as `GF_SECURITY_ADMIN_USER`, `GF_SECURITY_ADMIN_PASSWORD` and `GF_SERVER_ROOT_URL`; a `GF_*` value in `.env` is not read. Grafana keeps the admin password of its first start. `docker-compose.monitoring.yml` fixes `GF_USERS_ALLOW_SIGN_UP=false`, the plugin list and the home dashboard.
- `AIRFLOW__SLACK__WEBHOOK_URL` is read like `SLACK_WEBHOOK_URL`.
- Alertmanager reads its Slack webhook from `prometheus/secrets/slack_api_url`. Slack receives the critical alerts and the collector alerts, PagerDuty the circuit-breaker alerts, and the default e-mail receiver every other alert; the e-mail and PagerDuty receivers are placeholders in `prometheus/alertmanager.yml` ([PROMETHEUS_SETUP.md](PROMETHEUS_SETUP.md#alertmanager-notifications)).
- `NATS_URL` is read only by `edgeguard doctor`; the NATS client library takes its servers as an argument.

---

## TLS and trust

| Variable | Default | Purpose |
|---|---|---|
| `EDGEGUARD_SSL_VERIFY` | `true` | Verify HTTPS certificates (MISP and the feeds): `true`, `1`, `yes`, `on` verify; `false`, `0`, `no`, `off` do not |
| `SSL_VERIFY` | unset | The same values; read only when `EDGEGUARD_SSL_VERIFY` is unset or blank |
| `REQUESTS_CA_BUNDLE` | unset | CA bundle of `requests` (pip installs) |
| `EDGEGUARD_TRUSTED_MISP_ORG_UUIDS` | unset | MISP organisations trusted for source-stated timestamps |
| `EDGEGUARD_TRUSTED_MISP_ORG_NAMES` | unset | The same by organisation name |

- The value is read case-insensitively, ignoring spaces, tabs and line breaks (ASCII whitespace) around it. Unset or blank means `true`. Any other value, a typo or a value with another character around it (a non-breaking space pasted from a web page) included, keeps verification on: each process that reads it logs one warning naming the variable and the value, and `edgeguard validate` and `scripts/preflight_baseline.sh` report it. Turning verification off (`false`) is for a development MISP with a self-signed certificate; `edgeguard validate` and the preflight report that as well.
- One rule (`src/tls_verify.py`) reads it for every caller: `config.SSL_VERIFY`, which the collectors, the MISP clients, the sync and the health checks take, the fresh-baseline probe and wipe, `scripts/clear_misp.py`, `scripts/import_curated_package.py --push`, and `scripts/preflight_baseline.sh`, which applies the same rule in the shell, byte-wise in the C locale, so it judges a value as the services do in any locale.
- On Compose, `EDGEGUARD_SSL_VERIFY` is always set (default `true`) and reaches every service; `SSL_VERIFY` is not forwarded. Without Compose, set it in the environment of every Airflow process that runs tasks. `SSL_CERT_VERIFY` is not read.
- `requests` and PyMISP verify against the `certifi` bundle (`certifi>=2026.10.19` in every dependency list), not the system store. A private CA goes into a bundle named by `REQUESTS_CA_BUNDLE` on a pip install; `docker-compose.yml` does not forward it. The Neo4j driver's `+s` schemes use the system CAs ([AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)).
- The trust allowlists name the creator organisations whose source-stated timestamps are accepted; names are compared case-insensitively after Unicode normalisation. The UUID is checked first and the name next, so a creator whose UUID is not in the UUID list is still trusted when its name is listed: leave the name list empty when only UUIDs should match. While both are empty, every claim is accepted, a startup warning is logged and the gauge `edgeguard_misp_tag_impersonation_defense_disabled` reports it ([SECURITY_ROADMAP.md](SECURITY_ROADMAP.md)).

---

## Paths and operator tools

| Variable | Default | Purpose |
|---|---|---|
| `EDGEGUARD_CHECKPOINT_DIR` | `checkpoints/` | Collector checkpoints (host CLI) |
| `EDGEGUARD_STATE_DIR` | `state/` | Sync state and ledgers (host CLI) |
| `EDGEGUARD_BASE_DIR` | the parent of `dags/` | Project root the DAGs resolve paths from |
| `EDGEGUARD_DESTRUCTIVE_OPS_AUDIT_PATH` | `logs/destructive_ops.jsonl` | Audit log of destructive operations |
| `EDGEGUARD_MISP_EVENT_LOCK_PATH` | a file in `/tmp` | Lock of MISP event creation |
| `EDGEGUARD_INSTALL_WAIT_SEC` | `300` | Seconds `./install.sh` waits for healthy services |
| `EDGEGUARD_PREFLIGHT_STRICT` | `0` | `1`: preflight warnings fail the preflight script |
| `EDGEGUARD_PREFLIGHT_LAUNCH_PATH` | unset | Default `--launch-path` of the preflight script |
| `EDGEGUARD_DEPLOY_CHECK_LIVE` | unset | `1`: the deployment check also probes live services |
| `EDGEGUARD_API_BASE` | `http://127.0.0.1:8000` | API address of the STIX smoke script |

- The checkpoint and state directories are relative to the project root and must stay inside it. The Airflow container uses `/opt/airflow/checkpoints` and `/opt/airflow/state`, bind-mounted from `./checkpoints` and `./state`, so the host CLI reads what the DAGs wrote.
- `EDGEGUARD_MISP_EVENT_LOCK_PATH` defaults to `/tmp/edgeguard_misp_get_or_create_event.lock`; collectors that create the day's MISP event take it, so two runs do not create the same event twice.
- `EDGEGUARD_INSTALL_WAIT_SEC` is read from the shell, not from `.env`; `0` checks once.
- `scripts/deployment_wiring_check.sh` also reads `EDGEGUARD_REST_HEALTH_URL`, `EDGEGUARD_GRAPHQL_HEALTH_URL` and `EDGEGUARD_SKIP_HTTP_HEALTH`.

---

## Operations-only switches

Leave this unset in normal operation: it stops a safeguard, and the process logs `[KILL-SWITCH-ACTIVE]` when it starts with it set.

| Variable | Default | Purpose |
|---|---|---|
| `EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION` | unset | Stop the zero-write check of Neo4j batches |

When to set it, and when to lower `EDGEGUARD_EARLIEST_IOC_DATE` for historical corpora: [RUNBOOK.md § Quick reference — kill-switches](RUNBOOK.md#quick-reference--kill-switches). `EDGEGUARD_SKIP_MISP_PREFLIGHT` ([MISP connection](#misp-connection)) is the other emergency setting.

---

## Variables without effect

`.env.example` lists these, but no service reads them:

- `EDGEGUARD_DEV_MODE`, `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_EXPORTER_OTLP_INSECURE`: read only by `init_tracing()` in `src/opentelemetry_config.py`, which nothing calls.
- `PROMETHEUS_ADMIN_PASSWORD`: no Prometheus web configuration is shipped ([SECRETS_MANAGEMENT.md](SECRETS_MANAGEMENT.md)).
- `AIRFLOW_CONN_NEO4J_DEFAULT`: Airflow registers it as the connection `neo4j_default`, which EdgeGuard does not use; the tasks connect with `NEO4J_URI`, `NEO4J_USER` and `NEO4J_PASSWORD`.

---

_Last updated: 2026-10-25_

## History

- 2026-10-25 — `THREATFOX_API_KEY` is the key of the URLhaus and MalwareBazaar v2 exports too (the keyless downloads answer HTTP 410 since 2026-10); `EDGEGUARD_BASELINE_REQUIRED_SOURCES` takes `urlhaus` and `malwarebazaar` (a listed one that is switched off is also an error in `edgeguard preflight`); `EDGEGUARD_URLHAUS_MAX_PER_RUN` default 100,000 (was 50,000), above the about 63,000 URLs of the export on 2026-10-24.
- 2026-10-25 — Row for `EDGEGUARD_MISP_PAGED_FETCH_ABOVE` (default 20000): larger MISP events are fetched as `/events/restSearch` metadata plus `/attributes/restSearch` pages of 5000 instead of one `/events/view`, which the hosted MISP answered with HTTP 500 for a 145k-attribute event on 2026-10-24.
- 2026-10-23 — The host scripts that query Neo4j over HTTP have no remote default: with neither `NEO4J_HTTP_URL` nor `NEO4J_HTTP` set they use the Compose Neo4j at `http://127.0.0.1:7474` (they sent the credentials to a built-in remote address), `scripts/run_cypher_catalog_http.py` also reads `NEO4J_HTTP`, a value that is not a valid http(s) URL (scheme, host, port) stops them, and `scripts/neo4j_wss_bridge.py` requires `NEO4J_WSS_HOST`; rows for `NEO4J_HTTP_USER_AGENT` and `NEO4J_WSS_HOST`.
- 2026-10-23 — `EDGEGUARD_SSL_VERIFY` and `SSL_VERIFY` fail closed: `true`/`1`/`yes`/`on` and `false`/`0`/`no`/`off` are recognised, any other value keeps verification on with a warning, and every reader uses the one rule in `src/tls_verify.py`; only ASCII whitespace around the value is ignored, and `scripts/preflight_baseline.sh` applies the rule in the C locale.
- 2026-10-23 — Created from the README's settings tables, split by area, with the rows that were missing (`EDGEGUARD_API_KEY`, `EDGEGUARD_CORS_ORIGINS`, the MISP push thresholds and back-off, `EDGEGUARD_SYNC_INTERVAL_DAYS`, `EDGEGUARD_EARLIEST_IOC_DATE`, the paths and operator tools) and the behaviour stated as the code has it: `NEO4J_URI`, the API ports and the metrics bind fixed on Compose, the Fernet, JWT and Grafana names Compose maps, the memory variables on the `neo4j` service, `EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES` skipping longer values, `EDGEGUARD_SSL_VERIFY` turning verification off for any value other than `true`, `MITRE_FORCE_REFETCH` for scheduled runs, `EDGEGUARD_INCREMENTAL_LIMIT` applying to OTX and VirusTotal, and `EDGEGUARD_VERSION` on bare-metal metrics only.
