# EdgeGuard Knowledge Graph — Architecture Diagrams

> Graph-Augmented xAI for Threat Intelligence on Edge Infrastructure
> (IICT-BAS + Ratio1, funded by ResilMesh)

**Design philosophy:** Neo4j is the **linked intelligence layer** for fast graph queries and cross-source correlation. MISP holds the **ground truth** with full provenance, raw data, and audit trails. Every node in Neo4j traces back to its MISP source events via `misp_event_ids` and `SOURCED_FROM` relationships.

All diagrams are written in [Mermaid](https://mermaid.js.org/) and render natively on GitHub.
To export for papers: paste into [mermaid.live](https://mermaid.live) and download as PNG/SVG/PDF.

---

## 1. System Architecture Overview

```mermaid
graph TB
    subgraph External Sources
        OTX[AlienVault OTX]
        NVD[NVD - NIST]
        CISA[CISA KEV]
        MITRE[MITRE ATT&CK]
        VT[VirusTotal]
        AIPDB[AbuseIPDB]
        TF[ThreatFox]
        UH[URLhaus]
        FD[Feodo Tracker]
        SSL[SSL Blacklist]
        MB[MalwareBazaar<br/>flag-guarded]
        ICS[CISA ICS advisories<br/>flag-guarded]
    end

    subgraph EdgeGuard Pipeline
        COLL[Collectors<br/>10 sources + 2 flag-guarded]
        MISP[(MISP 2.4 / 2.5<br/>Single Source of Truth<br/>port 8443)]
        SYNC[MISP-to-Neo4j Sync<br/>Paged streaming + OOM-safe chunking<br/>+ _MispFallbackHardError sentinel<br/>+ MISP_FETCH_FALLBACK_ACTIVE Counter]
        NEO4J[(Neo4j 2026.03<br/>Knowledge Graph<br/>ports 7474 / 7687)]
        BREL["build_relationships<br/>20 link steps → many edge types<br/>incl. INDICATES, EXPLOITS, TARGETS, AFFECTS<br/>+ provenance on every edge: sources, source_refs, misp_event_ids"]
        ENRICH[Enrichment Jobs<br/>Bridge / Actor alias merge /<br/>Malware twin merge / Indicator aging /<br/>Campaigns / Calibration / EPSS]
    end

    subgraph APIs
        REST[FastAPI REST<br/>port 8000]
        GQL[Strawberry GraphQL<br/>port 4001]
        METRICS[Prometheus Metrics<br/>port 8001<br/>+ 2 fallback alerts:<br/>EdgeGuardMispFetchFallbackActive warning<br/>EdgeGuardMispFetchFallbackHardError critical]
    end

    subgraph Orchestration
        AF[Apache Airflow<br/>6 DAGs<br/>port 8082]
    end

    subgraph Integrations
        NATS["NATS Alerts (ResilMesh)<br/>port 4222<br/>consumer not deployed"]
        GRAFANA[Grafana<br/>port 3000]
        PROM[Prometheus<br/>port 9090]
    end

    OTX & NVD & CISA & MITRE & VT & AIPDB --> COLL
    TF & UH & FD & SSL --> COLL
    MB & ICS -.->|when enabled| COLL
    COLL -->|push indicators| MISP
    MISP -->|paginated fetch| SYNC
    SYNC -->|MERGE nodes| NEO4J
    NEO4J --> BREL
    BREL --> ENRICH
    ENRICH --> NEO4J
    NEO4J --> REST & GQL
    NATS -.->|"planned: alert enrichment via alert_processor"| NEO4J
    METRICS --> PROM --> GRAFANA
    AF -->|schedules| COLL & SYNC & BREL & ENRICH
```

---

## 2. Data Pipeline Flow

```mermaid
flowchart LR
    subgraph Step 2: Collection
        C1[OTX] --> MW[MISPWriter]
        C2[NVD] --> MW
        C3[CISA] --> MW
        C4[MITRE] --> MW
        C5["Others<br/>8 more (2 flag-guarded)"] --> MW
    end

    subgraph MISP
        MW -->|create events<br/>dedup attributes| MISP_DB[(MISP<br/>Events + Attributes)]
    end

    subgraph Step 3: Sync
        MISP_DB -->|paginated<br/>index fetch| FETCH[Fetch Events<br/>primary index: 500/page × 100 pages<br/>fallback PyMISP/restSearch: 500/page × 200 pages<br/>+ _MispFallbackHardError on cap-hit]
        FETCH --> PARSE[Parse Attributes<br/>per event]
        PARSE -->|< 5000 attrs| NORMAL[Normal Path]
        PARSE -->|> 5000 attrs| PAGED[Paged Streaming<br/>5000/page + gc.collect]
        NORMAL --> DEDUP[Deduplicate]
        PAGED --> DEDUP
        DEDUP --> CHUNK[Chunk at 500 items]
        CHUNK -->|UNWIND node merge<br/>1000/batch| NEO4J_MERGE["Neo4j MERGE<br/>Indicators, CVEs, techniques, tactics,<br/>actors, malware, tools"]
    end

    subgraph Step 4-5: Enrich
        NEO4J_MERGE --> REL[Build Relationships<br/>apoc.periodic.iterate<br/>batchSize 5000]
        REL --> BRIDGE[CVE Bridge]
        BRIDGE --> ALIAS[Actor alias merge]
        ALIAS --> TWIN[Malware twin merge]
        TWIN --> AGING[Indicator aging]
        AGING --> CAMP[Campaign Builder]
        CAMP --> CALIB["Co-occurrence calibration (no-op on a fresh baseline)"]
        CALIB --> EPSS[FIRST EPSS]
    end

    EPSS --> GRAPH[(Knowledge Graph)]
```

---

## 3. Knowledge Graph Schema

```mermaid
graph TB
    TA[ThreatActor] -->|EMPLOYS_TECHNIQUE| T[Technique]
    TA -->|RUNS| CAMP[Campaign]
    M[Malware] -->|IMPLEMENTS_TECHNIQUE| T
    M -->|ATTRIBUTED_TO| TA
    M -->|PART_OF_CAMPAIGN| CAMP
    I[Indicator] -->|INDICATES| M
    I -->|EXPLOITS| V[Vulnerability]
    I -->|EXPLOITS| CVE[CVE]
    I -->|TARGETS| S[Sector]
    I -->|USES_TECHNIQUE| T
    I -->|PART_OF_CAMPAIGN| CAMP
    V -->|AFFECTS| S
    CVE -->|AFFECTS| S
    V -->|REFERS_TO| CVE
    CVE -->|REFERS_TO| V
    CVE -->|HAS_CVSS_v*| CVSS[CVSSv2 / v3.0 / v3.1 / v4.0]
    CVSS -->|HAS_CVSS_v*| CVE
    T -->|IN_TACTIC| TAC[Tactic]
    T -->|SUBTECHNIQUE_OF| T
    TA -->|USES_MALWARE| M
    TA -->|USES_TOOL| TOOL[Tool]
    TA -->|EXPLOITS| CVE
    M -->|EXPLOITS| CVE
    TA -->|TARGETS| S
    M -->|TARGETS| S
    TOOL[Tool] -->|IMPLEMENTS_TECHNIQUE| T

    %% Edge legend:
    %%   EMPLOYS_TECHNIQUE    = attribution  (who is doing the TTP)
    %%   IMPLEMENTS_TECHNIQUE = capability   (what the code/tool can do)
    %%   USES_TECHNIQUE       = observation  (indicator observed tied to a TTP)
    %%
    %% HAS_CVSS_v* expands to four concrete edge types written by
    %% _merge_cvss_node inside merge_cve(): HAS_CVSS_v2, HAS_CVSS_v30,
    %% HAS_CVSS_v31, HAS_CVSS_v40 (per neo4j_client.py — note the
    %% underscore + lowercase v + version), each in both directions
    %% (CVE to CVSS and CVSS to CVE), as in the ResilMesh model.
    %%
    %% Provenance: every relationship built from the sources carries
    %% r.sources[] (who asserts it), r.source_refs[] (their record ids) and
    %% r.misp_event_ids[] (the MISP events); see KNOWLEDGE_GRAPH.md
    %% "Relationship provenance".
    %%
    %% ThreatActor / Malware -[:EXPLOITS]-> CVE comes only from curated
    %% packages; ThreatActor / Malware -[:TARGETS]-> Sector from
    %% build_relationships Q7c / Q7d.

    classDef core fill:#2563eb,stroke:#1d4ed8,color:#fff
    classDef vuln fill:#dc2626,stroke:#b91c1c,color:#fff
    classDef infra fill:#059669,stroke:#047857,color:#fff
    classDef enriched fill:#7c3aed,stroke:#6d28d9,color:#fff

    class TA,M,I core
    class V,CVE,CVSS vuln
    class S,TOOL infra
    class CAMP,T,TAC enriched
```

---

## 4. Airflow DAG Scheduling

```mermaid
gantt
    title EdgeGuard Airflow DAG Schedule (24h view)
    dateFormat HH:mm
    axisFormat %H:%M

    section High Frequency
    edgeguard_pipeline (OTX)        :active, 00:00, 00:05
    edgeguard_pipeline (OTX)        :active, 00:30, 00:35
    edgeguard_pipeline (OTX)        :active, 01:00, 01:05

    section Medium Frequency
    edgeguard_medium_freq (CISA+VT) :crit, 00:00, 00:15
    edgeguard_medium_freq (CISA+VT) :crit, 04:00, 04:15

    section Low Frequency
    edgeguard_low_freq (NVD)        :done, 00:00, 00:30
    edgeguard_low_freq (NVD)        :done, 08:00, 08:30

    section Daily
    edgeguard_daily (MITRE+7 more)  :02:00, 02:45

    section Neo4j Sync
    edgeguard_neo4j_sync (every 72 h) :03:00, 04:00
```

---

## 5. Neo4j Sync Task Chain

```mermaid
flowchart LR
    A[check_sync_needed<br/>ShortCircuitOperator] -->|sync needed| B[neo4j_health_check<br/>Health check]
    B --> C[run_neo4j_sync<br/>MISP to Neo4j<br/>up to 8h timeout]
    C --> D["build_relationships<br/>20 link steps → many edge types incl. INDICATES (family + same-pulse), EXPLOITS, TARGETS, AFFECTS, SUBTECHNIQUE_OF, USES_MALWARE / USES_TOOL"]
    D --> E[run_enrichment_jobs<br/>7 post-sync jobs]
    E --> F[check_neo4j_quality<br/>Node/edge counts]

    A -->|"skip: a baseline holds the lock, or the last sync started < 24 h ago (force_sync bypasses the 24 h guard)"| SKIP[All downstream<br/>SKIPPED]

    style SKIP fill:#fbbf24,stroke:#d97706,color:#000
    style A fill:#3b82f6,stroke:#2563eb,color:#fff
    style C fill:#10b981,stroke:#059669,color:#fff
```

`run_neo4j_sync` (and its retries), `build_relationships` and `run_enrichment_jobs` each skip
(`AirflowSkipException`) when a baseline has taken the lock before they start; the
tasks downstream of a skipped task skip with it.

---

## 6. Retry and Resilience Architecture

```mermaid
flowchart TD
    REQ[Request] --> DEC{retry_with_backoff<br/>decorator}
    DEC -->|attempt| FN[Function body]
    FN -->|success| RET[Return result]
    FN -->|transient error<br/>ServiceUnavailable<br/>TransientError<br/>ConnectionError<br/>TimeoutError| DEC
    FN -->|non-transient error<br/>DatabaseError<br/>CypherSyntaxError| ERR[Log + return default]

    DEC -->|retries exhausted<br/>neo4j: 3 retries, 2s base<br/>misp: 4 retries, 10s base| RAISE[Re-raise exception]
    RAISE --> CALLER{Caller handles}
    CALLER -->|run_pipeline| RECONNECT[Reconnect loop<br/>3 attempts]
    CALLER -->|run_misp_to_neo4j| CIRCUIT[Circuit breaker<br/>record_failure]
    CALLER -->|Airflow DAG<br/>incremental tasks: retries=2| AIRFLOW[AirflowException<br/>task marked FAILED]
    CALLER -->|Airflow DAG<br/>baseline critical chain<br/>retries=0| BASELINE_FAIL[AirflowException<br/>FAILS IMMEDIATELY<br/>no retry — operator pages<br/>via EdgeGuardMispFetchFallbackHardError]

    style DEC fill:#7c3aed,stroke:#6d28d9,color:#fff
    style RAISE fill:#dc2626,stroke:#b91c1c,color:#fff
    style RECONNECT fill:#f59e0b,stroke:#d97706,color:#fff
    style CIRCUIT fill:#f59e0b,stroke:#d97706,color:#fff
    style BASELINE_FAIL fill:#dc2626,stroke:#b91c1c,color:#fff
```

**Baseline critical chain without retries (operator-relevant):** the four baseline critical-chain
tasks — `baseline_clean`, `full_neo4j_sync`, `build_relationships`,
`run_enrichment_jobs` (top-level task ids of `edgeguard_baseline`; only
`baseline_clean` carries the `baseline_` prefix) — override `retries=0` (see
their task definitions in `dags/edgeguard_pipeline.py`); `source_key_check`
also runs once. A single failure on any of these tasks immediately marks
the DAG run FAILED rather than auto-retrying. This is intentional: a 5–6h
critical-chain task that retries once would burn 12h of the 32h `dagrun_timeout`
cap and could leave the graph mid-mutated. Combined with the
`EdgeGuardMispFetchFallbackHardError` Prometheus alert, the operator
gets paged immediately when the `_MispFallbackHardError` sentinel raises.

---

## 7. OOM Protection Strategy

```mermaid
flowchart TD
    EVENT[MISP Event<br/>N attributes] --> CHECK{N > 5000?}

    CHECK -->|Yes: Large event| PAGED[Paged Streaming<br/>5000 attrs/page]
    CHECK -->|No: Normal event| NORMAL[Process all in memory]

    PAGED --> PAGE_LOOP["For each page:<br/>parse + dedup + sync<br/>then gc.collect + query_pause<br/>(EDGEGUARD_QUERY_PAUSE_SECONDS, default 0)"]
    PAGE_LOOP --> BUILD_REL_P["Build report-scoped rels after all pages<br/>(same OTX pulse only)<br/>per-pulse caps: indicators 2000,<br/>malware 50, actors 10"]

    NORMAL --> DEDUP_N[Deduplicate items]
    DEDUP_N --> BUILD_REL_N["Build report-scoped rels<br/>same per-pulse caps"]

    BUILD_REL_P & BUILD_REL_N --> CHUNK["Node sync: 500 items/chunk<br/>UNWIND node merge: 1000/batch<br/>Rel UNWIND: 500/batch (EDGEGUARD_REL_BATCH_SIZE), 600 s timeout<br/>Post-sync: apoc.periodic.iterate 5000/batch"]
    CHUNK --> NEO4J[(Neo4j)]

    style PAGED fill:#3b82f6,stroke:#2563eb,color:#fff
    style CHUNK fill:#10b981,stroke:#059669,color:#fff
```

---

## 8. Enrichment Pipeline Detail

```mermaid
flowchart LR
    subgraph "Job 1/7: CVE Bridge"
        BR1[Vulnerability] -->|matching cve_id| BR2[CVE]
        BR2 -->|REFERS_TO| BR1
    end

    subgraph "Job 5/7: Campaign Builder"
        CB1[ThreatActor] --> CB2{"Actor has ATTRIBUTED_TO or USES_MALWARE malware<br/>with an active INDICATES indicator?"}
        CB2 -->|Yes| CB3[Create/reactivate Campaign]
        CB3 --> CB4["Link: RUNS + PART_OF_CAMPAIGN (r.evidence_types)<br/>No evidence left: delete campaign + links<br/>Evidence but no active indicator: inactive"]
    end

    subgraph "Job 6/7: Calibration (no-op on a fresh baseline)"
        CAL0[Pre-compute: one COUNT<br/>per MISP event] --> CAL1[Group events by tier]
        CAL1 --> CAL2{Event size tier}
        CAL2 -->|1-10| CAL3[conf = 0.50]
        CAL2 -->|11-20| CAL3b[conf = 0.45]
        CAL2 -->|21-100| CAL4[conf = 0.40]
        CAL2 -->|101-500| CAL5[conf = 0.35]
        CAL2 -->|> 500| CAL6[conf = 0.30]
    end

    subgraph "Job 4/7: Indicator aging (before the campaigns)"
        D1[Every Indicator,<br/>whoever supplied it] --> D2{Days since the<br/>latest report}
        D2 -->|from 90d| D3[source_confidence x 0.85]
        D2 -->|from 180d| D4[source_confidence x 0.70]
        D2 -->|from 365d| D6[source_confidence x 0.55]
        D2 -->|from 730d| D5[active = false<br/>retired_at = basis + 730d]
    end
```

`run_all_enrichment_jobs` (`src/enrichment_jobs.py`) runs seven jobs in this order: 1/7 the CVE bridge,
2/7 the actor alias merge, 3/7 the Malware ATT&CK-id twin merge, 4/7 the indicator aging, 5/7 the
campaign builder, 6/7 the calibration and 7/7 FIRST EPSS. Jobs 2/7, 3/7 and 7/7 are not drawn above.

---

## Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Graph Database | Neo4j Community | 2026.03 |
| Threat Intel Platform | MISP | 2.4 / 2.5 (hosted instance 2.5.45; the writer's exact `eventinfo` lookup needs 2.4.177 or later, older versions page through) |
| Orchestration | Apache Airflow | 3.3 (image 3.3.2) |
| REST API | FastAPI + Uvicorn | latest |
| GraphQL API | Strawberry | latest |
| Messaging | NATS | latest |
| Monitoring | Prometheus + Grafana | latest |
| Data Format | STIX 2.1 | standard |
| Language | Python | 3.12+ |
| Versioning | CalVer | 2026.10.x |

---

_Last updated: 2026-10-18_

## History

- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Rewritten as a guide to current behaviour: change notes moved to this history, data from earlier versions to the appendix.
- 2026-10-17 — Corrected against the code: § 1 NATS has no deployed consumer and the APIs do not publish to it, MISP 2.4 / 2.5; § 2 the further collectors, the seven enrichment jobs and the labels the sync MERGE writes (it said indicators and vulnerabilities); § 3 `HAS_CVSS_v*` in both directions; § 4 MITRE + 7 daily collectors; § 5 task `neo4j_health_check`, the baseline-lock skips and `force_sync`; § 6 the baseline task ids; § 7 report-scoped linking with per-pulse caps, `query_pause` and the 600 s relationship timeout (no cross-product sampling); § 8 jobs numbered of seven and the campaign evidence; technology stack versions.
- 2026-10-16 — The sync DAG runs every 72 hours, skips its chain when the last sync started less than 24 hours ago, and its writing tasks skip while a baseline holds the lock.
- 2026-10-16 — One indicator aging rule for every Indicator from its latest report (×0.85 / ×0.70 / ×0.55 from 90 / 180 / 365 days, retired from 730; no Vulnerability tiers), run before the campaign builder; campaigns rest on `ATTRIBUTED_TO` or `USES_MALWARE`.
- 2026-10-15 — `run_neo4j_sync` timeout 8 h (was 4 h); seven post-sync jobs including the Malware ATT&CK-id twin merge (the count said five); § 3 `USES_MALWARE` / `USES_TOOL` drawn from `ThreatActor`, `EXPLOITS` and `TARGETS` from actors and malware, `AFFECTS` from `CVE`; the provenance note covers every relationship.
- 2026-10-14 — Campaign membership renamed `PART_OF_CAMPAIGN`; every relationship built from the sources carries `sources[]`, `source_refs[]` and `misp_event_ids[]`.
- 2026-10-10 — Whole-event co-occurrence `INDICATES` edges are no longer written, so the calibration job has nothing to change on a fresh baseline.
- 2026-04-28 — Corrected against the code: Neo4j retries 3 (it said 5) with a 2 s base; the `retries=0` branch of the baseline critical chain; the `build_relationships` label aligned with § 5 and the enrichment order; the fallback counter and alerts annotated; edge label `HAS_CVSS_v*` with the comment block on its four concrete types.
- 2026-04-25 — The MISP fetch fallback counter `MISP_FETCH_FALLBACK_ACTIVE` and the alerts `EdgeGuardMispFetchFallbackActive` / `EdgeGuardMispFetchFallbackHardError`.
- 2026-04-24 — Baseline critical-chain tasks run with `retries=0`; `_MispFallbackHardError` is raised when the fallback reaches its page cap.
- 2026-04-23 — `INDICATES`, `EXPLOITS`, `TARGETS` and `AFFECTS` carry `r.misp_event_ids[]`.
- 2026-04-15 — The generic `USES` technique edge split into `EMPLOYS_TECHNIQUE` (attribution) and `IMPLEMENTS_TECHNIQUE` (capability); `USES_TECHNIQUE` (Indicator) unchanged.
- 2026-03-30 — Mermaid architecture diagrams added.
