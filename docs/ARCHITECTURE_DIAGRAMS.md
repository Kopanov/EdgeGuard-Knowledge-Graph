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
        MISP[(MISP 2.4.x<br/>Single Source of Truth<br/>port 8443)]
        SYNC[MISP-to-Neo4j Sync<br/>Paged streaming + OOM-safe chunking<br/>+ PR-N29 _MispFallbackHardError sentinel<br/>+ PR-N31 MISP_FETCH_FALLBACK_ACTIVE Counter]
        NEO4J[(Neo4j 2026.03<br/>Knowledge Graph<br/>ports 7474 / 7687)]
        BREL["build_relationships<br/>20 link steps → many edge types<br/>incl. INDICATES, EXPLOITS, TARGETS, AFFECTS<br/>+ provenance on every edge: sources, source_refs, misp_event_ids"]
        ENRICH[Enrichment Jobs<br/>Bridge / Campaigns / Calibration /<br/>Decay / Actor alias merge /<br/>Malware twin merge / EPSS]
    end

    subgraph APIs
        REST[FastAPI REST<br/>port 8000]
        GQL[Strawberry GraphQL<br/>port 4001]
        METRICS[Prometheus Metrics<br/>port 8001<br/>+ 2 PR-N31 fallback alerts:<br/>EdgeGuardMispFetchFallbackActive warning<br/>EdgeGuardMispFetchFallbackHardError critical]
    end

    subgraph Orchestration
        AF[Apache Airflow<br/>6 DAGs<br/>port 8082]
    end

    subgraph Integrations
        NATS[NATS Alerts<br/>port 4222]
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
    REST & GQL --> NATS
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
        C5[Others<br/>7 more] --> MW
    end

    subgraph MISP
        MW -->|create events<br/>dedup attributes| MISP_DB[(MISP<br/>Events + Attributes)]
    end

    subgraph Step 3: Sync
        MISP_DB -->|paginated<br/>index fetch| FETCH[Fetch Events<br/>primary index: 500/page × 100 pages<br/>fallback PyMISP/restSearch: 500/page × 200 pages<br/>+ _MispFallbackHardError on cap-hit PR-N29]
        FETCH --> PARSE[Parse Attributes<br/>per event]
        PARSE -->|< 5000 attrs| NORMAL[Normal Path]
        PARSE -->|> 5000 attrs| PAGED[Paged Streaming<br/>5000/page + gc.collect]
        NORMAL --> DEDUP[Deduplicate]
        PAGED --> DEDUP
        DEDUP --> CHUNK[Chunk at 500 items]
        CHUNK -->|UNWIND node merge<br/>1000/batch| NEO4J_MERGE[Neo4j MERGE<br/>Indicators + Vulnerabilities]
    end

    subgraph Step 4-5: Enrich
        NEO4J_MERGE --> REL[Build Relationships<br/>apoc.periodic.iterate<br/>batchSize 5000]
        REL --> BRIDGE[CVE Bridge]
        BRIDGE --> CAMP[Campaign Builder]
        CAMP --> CALIB[Legacy co-occurrence calibration (no-op since 2026-10)]
        CALIB --> DECAY[IOC Decay]
    end

    DECAY --> GRAPH[(Knowledge Graph)]
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
    %% Split from a generic USES edge in the 2026-04 refactor.
    %%
    %% HAS_CVSS_v* expands to four concrete edge types written by
    %% _merge_cvss_node inside merge_cve(): HAS_CVSS_v2, HAS_CVSS_v30,
    %% HAS_CVSS_v31, HAS_CVSS_v40 (per neo4j_client.py — note the
    %% underscore + lowercase v + version).
    %%
    %% Provenance (2026-10): every relationship built from the sources
    %% carries r.sources[] (who asserts it), r.source_refs[] (their record
    %% ids) and r.misp_event_ids[] (the MISP events); see KNOWLEDGE_GRAPH.md
    %% "Relationship provenance". PR-N26 (2026-04-23) had added
    %% r.misp_event_ids[] to INDICATES, EXPLOITS, TARGETS and AFFECTS only;
    %% scripts/backfill_edge_misp_event_ids.py backfills those four types on
    %% graphs that pre-date PR-N26.
    %%
    %% ThreatActor / Malware -[:EXPLOITS]-> CVE comes only from curated
    %% packages (2026-10); ThreatActor / Malware -[:TARGETS]-> Sector from
    %% build_relationships Q7c / Q7d (2026-10).

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
    edgeguard_daily (MITRE+6 more)  :02:00, 02:45

    section Neo4j Sync
    edgeguard_neo4j_sync            :03:00, 04:00
```

---

## 5. Neo4j Sync Task Chain

```mermaid
flowchart LR
    A[check_sync_needed<br/>ShortCircuitOperator] -->|sync needed| B[neo4j_preflight<br/>Health check]
    B --> C[run_neo4j_sync<br/>MISP to Neo4j<br/>up to 4h timeout]
    C --> D[build_relationships<br/>20 link steps → many edge types incl. INDICATES (family + same-pulse), EXPLOITS, TARGETS, AFFECTS, SUBTECHNIQUE_OF, USES_MALWARE / USES_TOOL]
    D --> E[run_enrichment_jobs<br/>5 post-sync jobs]
    E --> F[check_neo4j_quality<br/>Node/edge counts]

    A -->|skip: last sync < 72h| SKIP[All downstream<br/>SKIPPED]

    style SKIP fill:#fbbf24,stroke:#d97706,color:#000
    style A fill:#3b82f6,stroke:#2563eb,color:#fff
    style C fill:#10b981,stroke:#059669,color:#fff
```

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
    CALLER -->|Airflow DAG<br/>baseline critical chain<br/>PR-N29 H1: retries=0| BASELINE_FAIL[AirflowException<br/>FAILS IMMEDIATELY<br/>no retry — operator pages<br/>via EdgeGuardMispFetchFallbackHardError]

    style DEC fill:#7c3aed,stroke:#6d28d9,color:#fff
    style RAISE fill:#dc2626,stroke:#b91c1c,color:#fff
    style RECONNECT fill:#f59e0b,stroke:#d97706,color:#fff
    style CIRCUIT fill:#f59e0b,stroke:#d97706,color:#fff
    style BASELINE_FAIL fill:#dc2626,stroke:#b91c1c,color:#fff
```

**PR-N29 H1 carve-out (operator-relevant):** the four baseline critical-chain
tasks — `baseline_clean`, `baseline_full_neo4j_sync`, `baseline_build_relationships`,
`baseline_run_enrichment_jobs` — override `retries=0` (`dags/edgeguard_pipeline.py:2772,
2927, 2953, 2971`). A single failure on any of these tasks immediately marks
the DAG run FAILED rather than auto-retrying. This is intentional: a 5–6h
critical-chain task that retries once would burn 12h of the 32h `dagrun_timeout`
cap and could leave the graph mid-mutated. Combined with the
`EdgeGuardMispFetchFallbackHardError` Prometheus alert (PR-N31), the operator
gets paged immediately when the `_MispFallbackHardError` sentinel raises.

---

## 7. OOM Protection Strategy

```mermaid
flowchart TD
    EVENT[MISP Event<br/>N attributes] --> CHECK{N > 5000?}

    CHECK -->|Yes: Large event| PAGED[Paged Streaming<br/>5000 attrs/page]
    CHECK -->|No: Normal event| NORMAL[Process all in memory]

    PAGED --> PAGE_LOOP[For each page:<br/>parse + dedup + sync<br/>then gc.collect + sleep 2s]
    PAGE_LOOP --> BUILD_REL_P[Build cross-item rels<br/>static caps: actors 500,<br/>techniques 500, malware 500,<br/>indicators 2000, vulns 1000]

    NORMAL --> DEDUP_N[Deduplicate items]
    DEDUP_N --> BUILD_REL_N[Build cross-item rels<br/>same static caps]

    BUILD_REL_P & BUILD_REL_N --> DYN{Cross-product<br/>> 50K rels?}
    DYN -->|Yes| REDUCE[Dynamic sampling:<br/>proportional cap reduction<br/>all types scaled down]
    DYN -->|No| CHUNK
    REDUCE --> CHUNK[Node sync: 500 items/chunk<br/>UNWIND node merge: 1000/batch<br/>Rel UNWIND: 500/batch, 60s timeout<br/>Post-sync: apoc.periodic.iterate 5000/batch]
    CHUNK --> NEO4J[(Neo4j)]

    style PAGED fill:#3b82f6,stroke:#2563eb,color:#fff
    style SKIP_REL fill:#f59e0b,stroke:#d97706,color:#000
    style CHUNK fill:#10b981,stroke:#059669,color:#fff
```

---

## 8. Enrichment Pipeline Detail

```mermaid
flowchart LR
    subgraph "Job 1/4: CVE Bridge"
        BR1[Vulnerability] -->|matching cve_id| BR2[CVE]
        BR2 -->|REFERS_TO| BR1
    end

    subgraph "Job 2/4: Campaign Builder"
        CB1[ThreatActor] --> CB2{Has ATTRIBUTED_TO<br/>Malware with active<br/>INDICATES Indicator?}
        CB2 -->|Yes| CB3[Create/reactivate Campaign]
        CB3 --> CB4[Link: RUNS + PART_OF_CAMPAIGN<br/>Deactivate empty campaigns]
    end

    subgraph "Job 3/4: Calibration (pre-computed event sizes)"
        CAL0[Pre-compute: one COUNT<br/>per MISP event] --> CAL1[Group events by tier]
        CAL1 --> CAL2{Event size tier}
        CAL2 -->|1-10| CAL3[conf = 0.50]
        CAL2 -->|11-20| CAL3b[conf = 0.45]
        CAL2 -->|21-100| CAL4[conf = 0.40]
        CAL2 -->|101-500| CAL5[conf = 0.35]
        CAL2 -->|> 500| CAL6[conf = 0.30]
    end

    subgraph "Job 4/4: IOC Decay (last — idempotent)"
        D1[Indicators +<br/>Vulnerabilities] --> D2{Days since<br/>last_updated}
        D2 -->|90-180d| D3[confidence x 0.85]
        D2 -->|180-365d| D4[confidence x 0.70]
        D2 -->|> 365d| D5[active = false<br/>retired_at = now]
    end
```

---

## Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Graph Database | Neo4j Community | 2026.03 |
| Threat Intel Platform | MISP | 2.4.x |
| Orchestration | Apache Airflow | 3.2 |
| REST API | FastAPI + Uvicorn | latest |
| GraphQL API | Strawberry | latest |
| Messaging | NATS | latest |
| Monitoring | Prometheus + Grafana | latest |
| Data Format | STIX 2.1 | standard |
| Language | Python | 3.12+ |
| Versioning | CalVer | 2026.4.x |

---

*Last updated: 2026-10-15 — enrichment node lists the Malware ATT&CK-id twin merge. Same day: §3: `USES_MALWARE` / `USES_TOOL` start at the `ThreatActor` node (they pointed at an undefined node `A` and drew a second `Tool` node); `EXPLOITS` from actors and malware (curated packages) and `TARGETS` from actors and malware and `AFFECTS` from `CVE` added; the provenance note covers every relationship (`sources`, `source_refs`, `misp_event_ids`), not only the four PR-N26 types; §1 `build_relationships` label likewise. Prior: 2026-10-14 — campaign membership renamed `PART_OF_CAMPAIGN`.*

*Prior: 2026-04-28 — PR-N34 verification pass against code at HEAD. Fixed 6 drift findings:*

- *§6 (HIGH): `neo4j: 5 retries, 2s base` → `3 retries, 2s base` (matches `_run_with_retries` and `_retry_db_op` in `src/neo4j_client.py`).*
- *§6 (MED): added new branch + explanatory note for the PR-N29 H1 `retries=0` carve-out on the 4 baseline critical-chain tasks (`baseline_clean`, `baseline_full_neo4j_sync`, `baseline_build_relationships`, `baseline_run_enrichment_jobs`); operator now sees the immediate-fail path that pages via `EdgeGuardMispFetchFallbackHardError`.*
- *§1 (MED): aligned BREL block with §5's wording — "11 relationship types" → "12 link queries → many edge types incl. INDICATES, EXPLOITS, TARGETS, AFFECTS + PR-N26 r.misp_event_ids array on edges". Reordered ENRICH job list to match actual execution order in `run_all_enrichment_jobs` (Bridge → Campaigns → Calibration → Decay).*
- *§1 (LOW): added PR-N31 observability annotations on the SYNC node (`MISP_FETCH_FALLBACK_ACTIVE` Counter + `_MispFallbackHardError` sentinel) and METRICS node (the 2 fallback alerts).*
- *§3 (LOW): added comment block at the bottom of the schema explaining (a) `HAS_CVSS_v*` expands to four concrete edge types and (b) PR-N26 wired `r.misp_event_ids[]` onto the 4 build_relationships edges.*
- *§3 (LOW): edge label `HAS_CVSS` → `HAS_CVSS_v*` (matches `neo4j_client.py:_merge_cvss_node` which writes `HAS_CVSS_v2 / v30 / v31 / v40` with underscore + lowercase v + version).*

*Prior: 2026-04-26 PR-N33 docs audit; 2026-04-06.*
