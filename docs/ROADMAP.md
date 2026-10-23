# EdgeGuard roadmap

This page is the list of planned work on EdgeGuard. Each item states what the code does today, what is missing, what the work depends on and, where one exists, the open GitHub issue that tracks it. The other documents describe the current behaviour and its limits ([CONTRIBUTING.md § Documentation](../CONTRIBUTING.md#documentation)); where an item's design needs more room, the item links the document that holds the design.

The dependency of an item is one of:

- **none**: work in this repository only.
- **partner**: needs a decision, data, hosting or configuration from ResilMesh or from the operator of a deployment.
- **licence**: needs a paid product or plan.
- **upstream**: waits on a release of a third-party project.

---

## ResilMesh integration

| Item | Dependency | Issue |
|---|---|---|
| NATS alert loop | partner | — |
| Indicator type in alert enrichment | none | [#127](https://github.com/Kopanov/EdgeGuard-Knowledge-Graph/issues/127) |
| ISIM GraphQL schema extension | partner | — |
| SoftwareVersion bridge | partner | — |
| Links to the topology layer | partner | — |
| Neo4j role separation | licence or partner | — |

- **NATS alert loop.** `src/alert_processor.py` records an alert as an `Alert` node with its enrichment and rejects a payload without a non-empty `alert_id` or whose `threat` is not an object; `src/nats_client.py` connects over TLS and reconnects without limit. Missing:
  - a deployed consumer (no process subscribes to `resilmesh.alerts.zone.*`);
  - publishing the enriched response (the client's message handler discards the callback's return value);
  - publishing threat intelligence per zone on `resilmesh.threats.zone.<zone>` and across zones on `resilmesh.threats.cross_zone` (`publish_threat` in `src/nats_client.py` has no caller), and the other subjects [TECHNICAL_SPEC.md § NATS Topics](TECHNICAL_SPEC.md#nats-topics) marks as planned;
  - NATS authentication and queue groups, validation against a payload schema agreed with ResilMesh, and running the blocking enrichment outside the event loop.

  The subjects, the schema and the hosting are ResilMesh's ([RESILMESH_INTEGRATION_GUIDE.md](RESILMESH_INTEGRATION_GUIDE.md)).
- **Indicator type in alert enrichment.** One value may be stored under several indicator types. `/search/indicator` answers with the node of the resolved type; the five queries of `AlertProcessor._enrich_indicator` match on the value alone. Missing: the same type preference in those queries, with a test for a value stored under two types.
- **ISIM GraphQL schema extension.** The GraphQL API on port 4001 serves `CVE` with its CVSS sub-nodes, `Vulnerability` (read from the `CVE` nodes), `Indicator`, `ThreatActor`, `Malware`, `Tool`, `Technique`, `Tactic` and `Campaign` in EdgeGuard's own schema: camelCase fields, relationship traversal only to the CVSS sub-nodes. ISIM's schema has no threat-intelligence types. Missing: the schema extension agreed with ResilMesh (proposed types: [RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) § 8.4). A committed SDL file with a drift test would give ResilMesh a concrete schema to review.
- **SoftwareVersion bridge** `(Vulnerability)-[:IN]->(SoftwareVersion)-[:ON]->(Host)`. For each CVE the NVD collector stores up to ten CPE match strings (`affected_products`), their CPE parts (`cpe_type`) and up to ten version ranges (`version_constraints`); no job maps them to `SoftwareVersion` nodes, and the `IN` and `ON` helpers in `src/neo4j_client.py` have no caller in the pipeline. Missing:
  - complete CPE configurations from NVD: the collector keeps ten, drops `versionStartExcluding` and does not record whether the end bound is inclusive;
  - a matcher on the exact CPE vendor and product with a version-range check, and a normaliser for the version strings ResilMesh's scanners write;
  - the `SoftwareVersion` and `Host` nodes those scanners write, and ResilMesh's decision on who writes `Vulnerability` and `IN`.

  The chain and the attack-surface query it enables: [RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) § 4.4.
- **Links to the topology layer.** No EdgeGuard threat-intelligence node links to a node of ResilMesh's topology layer (`IP`, `Host`): there is no `(Indicator)-[:INDICATOR_RESOLVES_TO]->(IP)` (no helper exists in `src/neo4j_client.py`; the name avoids ISIM's `(IP)-[:RESOLVES_TO]->(DomainName)`) and no `(Malware)-[:TARGETS]->(Host)`. Missing: the data each link would rest on (DNS resolutions for the indicator link), ResilMesh's `IP` and `Host` nodes with the keys `IP.address` and `Host.hostname`, and the matching rule for each link ([RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) § 3.2).
- **Neo4j role separation.** Every service and ResilMesh use one Neo4j user (`NEO4J_USER` / `NEO4J_PASSWORD`), and the Community edition that `docker-compose.yml` runs has no role-based access control. Missing: Neo4j Enterprise roles (licence), or ResilMesh reading through the GraphQL or REST layer instead of Bolt (partner). Opening the GraphQL resolvers' sessions in read mode would add a safeguard, not a separation.

---

## Partner access and alert delivery

| Item | Dependency | Issue |
|---|---|---|
| External access to the APIs | partner | — |
| Alert delivery | partner | — |

- **External access to the APIs.** Docker Compose publishes REST (8000) and GraphQL (4001) on host loopback only, and the repository ships no TLS endpoint or reverse proxy. The APIs accept one shared `EDGEGUARD_API_KEY` and apply a CORS allowlist and per-address rate limits; they do not take the client address from a proxy's forwarding headers, so behind a proxy every client shares one rate limit. Missing: a TLS reverse proxy with an IP allowlist and a hostname, which belong to the deployment; per-partner API keys with rotation and per-key limits; rate limits by the client address a trusted proxy forwards.
- **Alert delivery.** `prometheus/alertmanager.yml` reads the Slack webhook from `prometheus/secrets/slack_api_url` and routes the critical and the collector alerts to Slack, the circuit-breaker alerts to PagerDuty and every other alert to the default e-mail receiver. Its e-mail receivers (`edgeguard.local` addresses, `localhost:587`) and its PagerDuty `service_key` (an unrendered template, which Alertmanager reads literally) are placeholders, and the preflight check `[7b]` fails until the file is rendered. Missing: a receiver the operator chooses and a test alert that reaches a person; reading the PagerDuty key and the SMTP password from files, which Alertmanager supports, would remove the template. The watchdog rule is listed under [Operational guardrails](#operational-guardrails).

---

## Security and supply chain

| Item | Dependency | Issue |
|---|---|---|
| MISP trust boundary, Tier 3 | partner | — |
| Trivy gate on the Airflow image | upstream | [#52](https://github.com/Kopanov/EdgeGuard-Knowledge-Graph/issues/52) |

- **MISP trust boundary, Tier 3.** The fail-closed boot refusal planned after Tiers 1 and 2 is described in [SECURITY_ROADMAP.md](SECURITY_ROADMAP.md); each deployment must set its MISP creator-organisation allowlist before it lands.
- **Trivy gate on the Airflow image.** CI fails the `edgeguard-kg` image on fixed HIGH and CRITICAL findings, and the `edgeguard-airflow` image on fixed CRITICAL findings only; the HIGH findings of the Airflow image, most of them in packages of the `apache/airflow` 3.3.2 base image, are reported by an informational step. Missing: the HIGH and CRITICAL gate on the Airflow image, which waits on a newer base image. The Debian packages that already have fixed versions can be upgraded in the image's own layer before then.

---

## Collection depth and scale

| Item | Dependency | Issue |
|---|---|---|
| MISP event partitioning | none | [#61](https://github.com/Kopanov/EdgeGuard-Knowledge-Graph/issues/61) |
| Bounded memory for large MISP events | none | — |
| Resumable NVD baseline | none | [#63](https://github.com/Kopanov/EdgeGuard-Knowledge-Graph/issues/63) |
| MISP push success-rate gauge | none | [#62](https://github.com/Kopanov/EdgeGuard-Knowledge-Graph/issues/62) |
| ThreatFox history | none | — |
| Deeper VirusTotal and AbuseIPDB data | licence | — |
| ATT&CK for ICS sectors | none | — |
| Sector classification beyond keywords | none | — |

- **MISP event partitioning.** `MISPWriter.push_items` groups attributes by source and run date, so a baseline writes one MISP event per source. The NVD and OTX events grow past 50,000 attributes, which needs raised PHP and MySQL limits on the MISP server ([MISP_TUNING.md](MISP_TUNING.md)) and makes the writer slow its batches as the event grows. Missing: partitioning large baseline events by date range.
- **Bounded memory for large MISP events.** The MISP → Neo4j sync pages the event index and writes a large event to Neo4j in chunks of 5,000 attributes, but fetches each event whole (`fetch_event_details` in `src/run_misp_to_neo4j.py`) before chunking. `MISPWriter` pages its reads of existing attributes, but parses the full event MISP returns after each batch push, which it uses to confirm the batch. Missing: fetching the attributes of a large event page by page (`/attributes/restSearch`), and confirming a pushed batch without the full-event answer. Partitioning (above) also reduces the size of each event.
- **Resumable NVD baseline.** The NVD baseline pushes its records to MISP after the last 120-day window, so an attempt that stops part-way has pushed nothing and its retry reads every window again; the checkpoint keeps the window the attempt stopped at. Missing: pushing each window once it is read, so that a retry resumes at the window where the attempt stopped.
- **MISP push success-rate gauge.** A collector run that pushes to MISP logs a `COLLECTOR_SUMMARY` line with its push counts and fails when its MISP push success rate is below `EDGEGUARD_MISP_MIN_SUCCESS_RATE` (default 0.95), and `edgeguard_misp_push_permanent_failure_total{source}` counts the batches lost after the retries. Missing: the per-source success-rate gauge and its Grafana panel, the parts of the issue not yet built.
- **ThreatFox history.** The ThreatFox API returns at most the last 7 days, so `ThreatFoxCollector.collect` clamps `days` to 7 and a baseline holds the ThreatFox indicators of the last 7 days only. Missing: an import of the [ThreatFox export](https://threatfox.abuse.ch/export/) for older indicators, with its window, de-duplication and TLP rules, the MISP push and the DAG wiring.
- **Deeper VirusTotal and AbuseIPDB data.** On the free plans EdgeGuard looks up hashes already in MISP on VirusTotal, within a daily budget of 400 lookups and 60 per run, and reads one AbuseIPDB blacklist of at most 10,000 addresses per run. Bulk VirusTotal data and larger AbuseIPDB blacklists need paid plans ([COLLECTORS.md](COLLECTORS.md)).
- **ATT&CK for ICS sectors.** With `EDGEGUARD_ENABLE_MITRE_ICS=true` the ATT&CK for ICS items are zoned by keyword detection on their descriptions only; the sectors and assets ATT&CK for ICS names (`x_mitre_sectors`, `x-mitre-asset`) are not read. Missing: a mapping of those sectors to `energy` and the other EdgeGuard sectors, with its evidence label ([COLLECTORS.md § 4](COLLECTORS.md#4-mitre-collector)).
- **Sector classification beyond keywords.** Sector labels come from keyword scores (`SECTOR_KEYWORDS` in `src/config.py`), the industries an OTX pulse names and the sectors CISA names in its ICS advisories. [METHODOLOGY.md](METHODOLOGY.md) § 3.7 and § 6 sketch a language-model classifier and an embedding classifier; no code for either exists. Missing: the classifier, labelled samples to evaluate it on, and an evidence label of its own for the sector links it would write.

---

## Graph and code maintenance

| Item | Dependency | Issue |
|---|---|---|
| MISP session helper | none | [#53](https://github.com/Kopanov/EdgeGuard-Knowledge-Graph/issues/53) |
| MISP wipe on the event tag | none | [#54](https://github.com/Kopanov/EdgeGuard-Knowledge-Graph/issues/54) |
| Native Cypher list functions | partner | — |
| Architecture flow diagrams | none | — |

- **MISP session helper.** Each MISP client in `src/` and `scripts/clear_misp.py` builds its own `requests.Session`; only the Host-header step is shared (`apply_misp_http_host_header` in `src/config.py`), and the sessions differ in redirect policy, TLS verification and headers. Missing: one helper that sets the headers, TLS verification, Host header and redirect policy for every caller, with an end-to-end test per caller, since the fresh-baseline wipe and `edgeguard clear misp` are among them. The issue lists further items, of which `docs/BACKUP.md`, the destructive-operations audit trail and the shared baseline-trigger helper are implemented; its checklist is not current.
- **MISP wipe on the event tag.** `_wipe_misp_events` in `src/baseline_clean.py` searches MISP for `EdgeGuard`, keeps the events whose `info` contains it and pages with a loop that advances on an empty round and restarts after deletions. Missing: selecting the events by the `EdgeGuard` event tag, which `MISPWriter` and the curated-package importer set, or collecting the event ids before deleting, with the destructive-path tests rewritten. How the event index filters on tags has to be checked on the MISP version in use first.
- **Native Cypher list functions.** APOC deprecates `apoc.coll.toSet` and `apoc.coll.sort` under Cypher 25 in favour of `coll.distinct()` and `coll.sort()`; the driver does not log deprecation notices. The list-accumulator writes build their expression through `_dedup_concat_clause` and `_dedup_concat_optional_clause` in `src/neo4j_client.py`; `src/relationship_provenance.py`, `src/enrichment_jobs.py`, `src/campaign_evidence.py`, `src/attack_software_names.py`, `src/build_relationships.py` and `src/query_api.py` call the APOC functions directly, and `Neo4jClient.health_check` probes APOC with `apoc.coll.toSet`. Missing:
  - Cypher 25 as the default language of every EdgeGuard database, which the deployment's `neo4j.conf` sets;
  - Neo4j integration tests of the element order and the null handling the writes rely on; `tests/test_dedup_clause_helpers.py` already pins, without a database, the contract the replacement must keep (deduplication, order, the null guard);
  - a health-check probe on an APOC procedure that stays in use (`apoc.periodic.iterate`, `apoc.create.addLabels`).
- **Architecture flow diagrams.** [ARCHITECTURE_FLOW.md](ARCHITECTURE_FLOW.md) scopes eight end-to-end diagrams (baseline sequence, checkpoint state machine, collector → MISP → Neo4j data flow, MISP ↔ Neo4j traceability, incremental sync, deployment topology, STIX export, sector detection), each still a placeholder; [ARCHITECTURE_DIAGRAMS.md](ARCHITECTURE_DIAGRAMS.md) already covers the system overview, the data pipeline, the DAG schedule and the sync chain. Missing: the diagrams, each checked against the code, and the documentation pin test extended to them.

---

## Deployment and framework

| Item | Dependency | Issue |
|---|---|---|
| Cloud deployment and service-level objectives | partner | — |
| Query engine | none | — |

- **Cloud deployment and service-level objectives.** The repository provides one deployment form, the single-host Docker Compose stack; a managed Neo4j (for example Aura), a cloud-hosted MISP and Kubernetes manifests are not provided. The alert rules cover staleness, failures and run duration, but no service-level objectives (freshness, success rate and duration of the incremental runs) are defined. Missing: manifests or a chart; a check of the APOC procedures a managed Neo4j offers (the code needs `apoc.periodic.iterate`, `apoc.create.addLabels`, `apoc.refactor.mergeNodes` and `apoc.lock.nodes`, and the list functions above); a MISP hosting decision; agreed objectives with their alert rules.
- **Query engine.** A language-model query layer over the knowledge graph is a later module of the EdgeGuard framework; this repository holds no code for it.

---

## After the next fresh baseline

These items need the graph of the next fresh baseline to be checked or changed. None depends on anything outside the repository, and none has an issue.

- **TLP on the read paths.** Only the STIX export marks TLP. The REST actor summary (`/actors/{name}/summary`), `/graph/explore`, the alert enrichment and the Cypher catalog runner (`scripts/run_cypher_catalog_http.py`) return links without their `tlp`, and GraphQL returns the nodes' `tlp` only. Missing: the links' `tlp` in those answers, and a decision on filtering by clearance.
- **A campaign's TLP and its actor.** The campaign builder sets the `tlp` of a campaign and of its `RUNS` and `PART_OF_CAMPAIGN` links to the most restrictive level of the evidence links it rests on; the actor node's own `tlp` is not included.
- **Campaign stamps.** Step 2c of the campaign builder stamps `updated_at` on `RUNS` and `last_updated` on the campaign only when the TLP level changes, so a change of the provenance alone is not selected by an export filtered on those times.
- **DragonForce.** The `dragonforce` entry of the canonical threat-actor reference is the hacktivist group based in Malaysia; the operators of the DragonForce ransomware have no actor of their own in the reference.
- **Curated packages.**
  - A fresh-baseline wipe deletes the package's MISP event, whose title contains `EdgeGuard`, and a full sync on an empty graph processes the package before the events that create its ends (the sync takes the smallest events first), so its claims attach to nothing and are not retried. A package is therefore imported after the baseline, and again after every wipe ([RUNBOOK.md § Importing a curated package](RUNBOOK.md#importing-a-curated-package)).
  - The STIX flow of `src/run_pipeline.py` writes an actor's technique link through `create_actor_technique_relationship`, which sets `confidence_score` to 0.7 on every write, so a run of that path over a pair that a curated claim created lowers the claim's 0.85. The Airflow sync keeps the higher value.
  - The sync takes the first `tlp:` tag of an attribute and its event (`_extract_tlp_tag`), not the most restrictive one.
  - Withdrawing a claim from a package and importing the package again does not remove the link the claim created; the removal is the manual procedure of the RUNBOOK section above.
- **Acceptance check.** The co-occurrence check of `scripts/verify_fresh_baseline.py` rejects links labelled `misp_cooccurrence`; it should also reject `misp_correlation`. Nothing writes either label.
- **Invisible characters in names.** Merge keys are NFC-normalised, trimmed and lower-cased; zero-width and bidi control characters are stripped only before the placeholder-name check and in indicator lookups, so a `Malware`, `ThreatActor` or `Tool` name can keep them. Missing: a read-only check that reports such names, then a decision on stripping them on write.
- **Concurrent checkpoint writers.** `update_source_checkpoint` and `update_source_incremental` in `src/baseline_checkpoint.py` take an exclusive file lock, and the tests cover the lock's release and exceptions, not two writers at once; `clear_checkpoint` writes without the lock, through the same temporary file name. Missing: a two-writer test whose writers start together, and the same lock in `clear_checkpoint`.

---

## Operational guardrails

A run fails on collector errors, on a MISP push success rate below its threshold, on sync errors and on dropped relationships. These groups add checks for failures that end green today, in this order, after the next fresh baseline. None has an issue.

| Group | Dependency |
|---|---|
| CI safety net | none |
| Sync DAG guardrails | none |
| Alerting | partner |
| Live graph invariants | none |
| Baseline, cursor and configuration safety | none |
| Source-change and schema safety | none |

**CI safety net**

- Collection-time stubs in `tests/test_graphql_api.py` leave mock modules in `sys.modules`, so in a full run `tests/test_indicator_enrichment_parity.py` skips its check of the batch writer's ATT&CK-id promotion. Planned: the stubs in a fixture, and a session hook that fails when `neo4j_client` is a mock.
- CI builds no Airflow DagBag, and `scripts/preflight_ci.sh` fails at its DagBag step ([Known defects](#known-defects)). Planned: a DagBag check of every DAG in CI and in the built Airflow image.
- CI runs neither `promtool` nor `amtool`, and the preflight skips `promtool` when it is not installed. Planned: CI checks and unit-tests the alert rules and checks the Alertmanager configuration.
- `tests/test_compose_env_forwarding.py` checks a fixed list of variables. Planned: a scan of the code's environment reads against `docker-compose.yml`, which catches a new setting Compose does not forward.
- The coverage floor is 30 %. Planned: a higher floor as the collectors' unit tests grow.

**Sync DAG guardrails**

- Node counts are recorded per label and alerted on a drop; relationships are counted only in the logs. Planned: a per-type relationship total, and a drop check that fails the post-sync task when a type loses more than half its edges.
- The sync state file (`edgeguard_last_neo4j_sync.json` in the state directory) is written in place, and an unreadable file falls back to the fixed `EDGEGUARD_SYNC_INTERVAL_DAYS` window. Planned: an atomic write, and a full sync after an unreadable file or a `last_sync` in the future.

**Alerting**

- No rule fires constantly, so a monitoring path that stopped is not noticed. Planned: a watchdog rule routed to an external dead-man's switch, which the operator chooses.
- Data-loss alerts such as `EdgeGuardMispBatchPermanentFailure` fire on `rate(...[5m]) > 0` held for 5 minutes, which a single increment does not satisfy. Planned: `increase` over a longer window, without a hold.
- Some failure signals are only logged: a defaulted TLP, an unmapped revoked ATT&CK object, a skipped FIRST EPSS update, an item that cannot be routed, an enrichment merge error. Planned: one anomaly counter with an alert.
- No alert watches the freshness of the FIRST EPSS scores or the CISA KEV catalogue. Planned: freshness gauges with staleness alerts.

**Live graph invariants**

- The sync DAG's `check_neo4j_quality` task cannot fail: it exits 0 when its query fails. The acceptance checks of `scripts/verify_fresh_baseline.py` run by hand, after a fresh baseline. Planned: a task that runs the checks that must hold between baselines (precise relationship types, live indicator aging, fresh EPSS scores, the expected constraints), fails on a broken one and exports a metric.
- Most relationship-build statements, the CVE bridge, the schema statements and the acceptance queries never run on a real Neo4j in CI. Planned: an `EXPLAIN` test of every statement, and a golden-path test on an empty database.

**Baseline, cursor and configuration safety**

- The baseline's collector groups run under `ALL_DONE`, and a transient collector error is a green skip, so a baseline can end green while a source failed. Planned: a final task that names each enabled collector that failed or was skipped.
- A baseline does not seed the OTX and CISA ICS incremental cursors, so the first scheduled run reads only its default lookback (3 days for OTX). Planned: cursors seeded from the baseline's start, and a per-source cursor gauge with an alert.
- `edgeguard fresh-baseline` sends no item limit in the run configuration, so an `EDGEGUARD_BASELINE_COLLECTION_LIMIT` left from a smoke test applies. Planned: a `--collection-limit` option, default 0, always sent.
- `EDGEGUARD_DEFAULT_TLP` given with its prefix (`TLP:WHITE`) is written as `tlp:tlp:white`, and a malformed integer setting falls back to its default without a message. Planned: one shared parser that validates each value and logs a rejected one.

**Source-change and schema safety**

- A change of format at NVD or CISA KEV, or a parser bug, can turn into edits that remove data from MISP and the graph, and no limit stops a run whose edits remove far more than usual. Planned: a run that refuses when its removing edits exceed a threshold.
- Schema setup drops and re-creates the EdgeGuard constraints on every connection and counts a `DatabaseError` as success. Planned: no self-cancelling drops, and a failed constraint on an EdgeGuard label fails the connection.
- A scheduled MITRE run adds a new ATT&CK release's new and renamed objects; an object MISP already holds keeps its stored text and relationships until the next fresh baseline ([COLLECTORS.md](COLLECTORS.md)). Planned: detecting the release version and reporting that a fresh baseline is due.

---

## Known defects

Defects found in the code; each is fixed in its own change.

- `src/config.py` (`edgeguard_ssl_verify_from_env`): any set value of `EDGEGUARD_SSL_VERIFY` other than `true`, a typo or `1` included, turns TLS verification off; `edgeguard validate` and `scripts/preflight_baseline.sh` warn, the services do not.
- `src/edgeguard.py` (`clear_lock_files`, run by `edgeguard heal`): removes every `edgeguard_*.lock` in the temporary directory and every `*.lock` in the repository root without checking whether a process holds it, the lock file `MISPWriter` uses for event creation included.
- `Makefile` (`install`): creates `.env` before it runs `./install.sh`, which then skips generating `GRAFANA_ADMIN_PASSWORD`, so the template value `changeme` stays.
- `src/edgeguard.py` (`main`): `edgeguard setup` loads the configuration first, so it fails without exported settings (`NEO4J_PASSWORD`), unlike `version` and `update`.
- `src/edgeguard.py`: with `--json`, `stats`, `checkpoint status`, `dag status` and `preflight` print a text banner to stdout before the JSON, and `preflight` its report too.
- `src/edgeguard.py` (`cmd_preflight`): the circuit-breaker check reads the breakers of the CLI process only, so it always passes.
- `src/edgeguard.py` and `pyproject.toml`: describe `edgeguard monitor` as a real-time or live display; it prints one snapshot.
- `install.sh`: the hint for the pip path prints `apache-airflow[postgres]~=3.2` (the pin is `~=3.3`) and a pull-request number.
- `Makefile` (`lint`, `type-check`, `test`, `ci`): run `python3` from `PATH`, so `make ci` after `./install.sh --python --dev` uses the system interpreter unless `.venv` is activated.
- `scripts/preflight_ci.sh`: `DagBag(include_examples=...)` raises `TypeError` on Airflow 3.3, so the script, `scripts/deployment_wiring_check.sh` and `make deploy-check` stop at the DAG parse step.
- `scripts/preflight_baseline.sh` (check `[11]`, part c): runs `.venv/bin/python`; without the repository's `.venv` it reports the three critical-chain tasks as missing `retries=0`.
- `scripts/verify_fresh_baseline.py`, `scripts/run_cypher_catalog_http.py` and `scripts/build_canonical_threat_actors.py`: without `NEO4J_HTTP_URL` (and, for the first and the last, `NEO4J_HTTP`) they send the Neo4j credentials to a built-in remote address instead of failing.
- `dags/edgeguard_pipeline.py`: `run_virustotal_enrichment_collection` is wired to no task, while the module docstring lists `virustotal_collector.py` as a daily collector and the energy and healthcare placeholders as collectors.
- `src/collectors/energy_feed_collector.py` and `src/collectors/healthcare_feed_collector.py`: the module docstrings call public sources "already working" and "actively collected", and the skip reasons say the sector advisories are collected by `cisa_collector`; CISA's ICS advisories come from the opt-in `cisa_ics` collector.
- `src/metrics.py` (`PipelineMetrics`): nothing records a run, so `edgeguard stats` shows no pipeline summary and `src/health_check.py` always reports the last pipeline run as "Never".
- `src/neo4j_client.py` (`scrape_list_dedup_sizes`): no task calls it, so the histogram `edgeguard_neo4j_list_dedup_size` holds no data.
- `src/opentelemetry_config.py` (`init_tracing`): nothing calls it, so `EDGEGUARD_DEV_MODE` and the `OTEL_EXPORTER_OTLP_*` settings have no effect.
- `src/run_misp_to_neo4j.py` (`_process_single_event`): the docstring and a comment say a large event's attributes are fetched page by page from `/attributes/restSearch`; the event is fetched whole.
- `.env.example`: describes `NATS_URL` as real-time alert publishing; only `edgeguard doctor` reads it.
- `.envrc`: the header comment says direnv creates and activates `.venv`, while its `layout python` line creates `.direnv/python-3.x`.

---

## Open issues with implemented work

- **[#57](https://github.com/Kopanov/EdgeGuard-Knowledge-Graph/issues/57) Airflow-aware baseline lock.** Implemented: the `edgeguard_baseline` DAG takes `checkpoints/baseline_in_progress.lock` with the DAG run as holder (`baseline_acquire_lock`, `baseline_release_lock`), the scheduled DAGs read the holder's run state through the Airflow REST API and fall back to the lock's age, and `src/run_pipeline.py --baseline` takes the same lock ([RUNBOOK.md § Baseline-day protocol](RUNBOOK.md#baseline-day-protocol)). The issue is still open.

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — Removed the known defect of `scripts/clear_neo4j.py` (deleted nodes by label, partner `Vulnerability` and `CVE` nodes included, without an audit line): the script deletes the nodes EdgeGuard created through the wipe of the fresh baseline and records every delete.
- 2026-10-23 — Created as the list of planned work: the planned items of the README, of PRODUCTION_READINESS.md, of COLLECTORS.md, of MISP_TUNING.md and of RESILMESH_INTEROPERABILITY.md with their current state (the README's timestamp model, sector placeholder decision and task-label clamp left out as done or decided), the ATT&CK for ICS sectors, the zone threat subjects on NATS, the links to the topology layer, the sector classifiers that METHODOLOGY.md sketches, the MISP trust Tier 3 pointer, the follow-ups after the next fresh baseline, the operational guardrails, the known code defects and the open issues whose work is implemented; the documents whose planned sections it replaces point here.
