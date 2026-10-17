# EdgeGuard Methodology & Architecture

**Purpose:** Document the technical approach, algorithms, and decision logic

---

## 1. Data Collection Pipeline

### 1.1 Sources & Collection Methods

| Source | Method | Frequency | Data Type |
|--------|--------|-----------|-----------|
| AlienVault OTX | REST API polling | Scheduled (Airflow) | IOCs, malware, CVEs |
| MISP | REST API | Sync / ingest | Events, attributes |
| NVD | REST API | Scheduled | CVE details (see **120-day** published-date windows in `nvd_collector.py`) |
| CISA KEV | JSON download | Scheduled | Known exploited vulns |
| MITRE ATT&CK | STIX bundle download | Scheduled | TTPs, actors, malware |
| VirusTotal | REST API | Scheduled (`vt_collector`) | IOCs / enrichment |
| AbuseIPDB | REST API | Scheduled | IP reputation |
| URLhaus, ThreatFox, Feodo, SSLBL | CSV/API | Scheduled | Feeds (see `global_feed_collector.py`, `finance_feed_collector.py`) |
| CISA ICS advisories | CSAF 2.0 download | Daily (flag-guarded, `EDGEGUARD_ENABLE_CISA_ICS`) | CVEs, sectors stated by CISA |
| MalwareBazaar | CSV export | Daily (flag-guarded, `EDGEGUARD_ENABLE_MALWAREBAZAAR`) | File hashes + malware family |
| FIRST EPSS | CSV download | After each Neo4j sync and the baseline | EPSS scores on CVE nodes (written straight to Neo4j) |

_Full inventory: [`DATA_SOURCES.md`](DATA_SOURCES.md)._

### 1.2 Collection Flow

```
Source API
  → Collector (normalise, zone detection)
  → MISPWriter (dedup against MISP, tags)
  → MISP (hub)
  → MISPToNeo4jSync (parse_attribute, dedupe per event, MERGE)
  → Neo4j
  → build_relationships
  → enrichment jobs
```

Collectors never write to Neo4j: the graph is loaded from MISP only. FIRST EPSS
is the one feed written straight to Neo4j, by the enrichment job `enrich_cve_epss`.

---

## 2. Data Normalization

### 2.1 Indicator Type Mapping

Each source uses different attribute types. We normalize to a standard set:

| Our Standard | MISP | OTX | Notes |
|--------------|------|-----|-------|
| `ipv4` | ip-src, ip-dst (IPv4 address) | IPv4 | IPv4 addresses |
| `ipv6` | ip-src, ip-dst (IPv6 address) | IPv6 | IPv6 addresses: MISP has one type for both families, so the address decides |
| `domain` | domain, hostname | domain | DNS names |
| `url` | url | URL | Web addresses |
| `hash` | md5, sha1, sha256, sha512 — chosen by the length of the hex digest | MD5, SHA1, SHA256 (`FileHash-MD5` / `-SHA1` / `-SHA256`) | File hashes. Import hashes, PE hashes and JA3 fingerprints from OTX are not collected |
| `x509-fingerprint-sha1` | x509-fingerprint-sha1 | — (SSLCertFingerprint is not collected) | SHA-1 fingerprints of TLS certificates (SSL Blacklist) |
| `email` | email-src, email-dst | EMAIL, email | Email addresses (OTX e-mail indicators are typed as e-mail, not as domains) |
| `cve` | vulnerability | CVE | CVE IDs |

### 2.2 Normalization Logic

```python
def normalize_indicator(source_type, value):
    # 1. Type mapping
    indicator_type = TYPE_MAPPING.get(source_type, 'unknown')
    
    # 2. Value validation
    if indicator_type == 'ipv4':
        if not is_valid_ipv4(value):
            # Try to detect actual type
            if is_domain(value):
                indicator_type = 'domain'
            else:
                indicator_type = 'unknown'
    
    # 3. Sanitization
    value = sanitize(value)
    
    return {'type': indicator_type, 'value': value}
```

---

## 3. Sector Classification

### 3.1 Approach: Keyword-Based with Word Boundaries

**Why Keywords?**
- Interpretable and explainable
- Fast and lightweight
- Easy to tune and update
- Works well with structured threat intel tags

### 3.2 Word Boundary Matching

We use regex word boundaries to prevent false positives. Production matching is
`config.detect_zones_from_text` / `detect_zones_from_item` (`src/config.py`): word-boundary
regexes (`_SECTOR_PATTERNS`), context weights (title / alias / name 3.0, description 2.0,
body 1.5, tag 1.0), negative keywords, and the threshold `ZONE_DETECT_THRESHOLD` 1.5
(`EDGEGUARD_ZONE_DETECT_THRESHOLD`). Every zone whose score reaches the threshold is
returned (multi-zone); when none does, the result is `['global']`.

**Example False Positive Prevention:**
| Keyword | Text | Match? | Why |
|---------|------|--------|-----|
| `phishing` | "phishing campaign" | ✅ Yes | Word boundary |
| `phishing` | "phishing" in "hospital" | ❌ No | "phishing" not separate word |
| `his` | "hospital information system" | ❌ No | "his" is part of "his" |

### 3.3 Sector Coverage

Examples from `SECTOR_KEYWORDS` (the full lists, including negative keywords, are in
`src/config.py`). Single generic words such as `patient`, `grid`, `power`, `bank`,
`payment` and `trading` are not keywords; the multi-word forms are:

| Sector | Example keywords |
|--------|-----------------|
| Healthcare | hospital, medical, healthcare, patient data, medical device |
| Energy | scada, power grid, electric grid, energy sector, ICS vendors and products (siemens, simatic …, § 3.6b) |
| Finance | banking, banking trojan, payment gateway, trading platform, swift payment |

### 3.4 Measured Data Distribution

**Measured on the graph of 2026-03-02:**

| Sector | Nodes | % | Primary Source |
|--------|-------|---|-----------------|
| Healthcare | 8,657 | 66% | AlienVault OTX (COVID-era medical targeting) |
| Energy | 3,884 | 30% | AlienVault OTX (ICS/SCADA threats) |
| Global | 894 | 3% | Mixed |
| Finance | 258 | 2% | AlienVault OTX |

**Key Finding:** The low Finance count is due to **data source availability**, not classification issues:
- Public OSINT feeds (OTX, MISP) have less finance-specific content
- Financial institutions share via private ISACs (FS-ISAC), not public feeds
- Healthcare/Energy were heavily targeted in recent years (COVID, Colonial Pipeline)

**Recommended Feeds for Finance Data:**
- Feodo Tracker (banking trojan C&C)
- Abuse.ch feeds (malware tracking)
- Phishtank (phishing URLs)
- FS-ISAC (requires membership)

### 3.5 Hybrid Classification (Tested)

We tested a hybrid approach (keyword + token overlap fallback) vs. keyword-only:

| Method | Result |
|--------|--------|
| Keyword | ✅ Sufficient - no improvement from hybrid |
| Hybrid | Same accuracy as keyword-only |

**Conclusion:** Keyword classification is the default. Hybrid provides no benefit on the tested data.

### 3.6 Malware Families (Not Used for Sectors)

Malware family names are deliberately **not** sector keywords (`src/config.py`: conservative
keywords, no malware families). A feed's family links an indicator to its `Malware` node
(`INDICATES`, `malware_family`, `build_relationships` step 9). A sector comes from sector
keywords in the record's text or from a sector the source states itself (OTX pulse
`industries`; CISA ICS advisory sectors → `advisory_sector`). Feodo Tracker, SSL Blacklist and
MalwareBazaar IOCs are therefore `global` unless their text names a sector:
`detect_zones_from_text("QakBot C&C server")` returns `['global']`.

### 3.6b CPE Vendor and Product Vocabulary

**Why:** the NVD collector scores CPE vendor / product tokens (`configurations_to_zone_text` → the `comment` field of the item), and these tokens match a sector only when the vocabulary names the vendor. Measured on the hosted graph (25k-CVE NVD sample, 2026-10-10) with a vocabulary without vendor names: Siemens 238 CVEs with 4 tagged energy, Rockwell Automation 49 / 0, Fuji Electric 29 / 0, Growatt 30 / 0, ABB 28 / 0, Advantech 26 / 0, Delta Electronics 25 / 0, Phoenix Contact 14 / 0, Schneider Electric 10 / 0, Hitachi Energy 7 / 0.

**Vocabulary:** `SECTOR_KEYWORDS['energy']` contains ICS / energy vendors and product families as they appear in CPE strings (`siemens`, `simatic`, `wincc`, `rockwellautomation`, `factorytalk`, `modicon`, `ecostruxure`, `experion`, `deltav`, `codesys`, `iec 61850`, `dnp3`, solar inverter vendors, EV charging / OCPP, smart meters …), and `SECTOR_KEYWORDS['finance']` contains payment / ATM / banking-software vendors (`diebold nixdorf`, `vynamic`, `ingenico`, `verifone`, `temenos`, `finastra`, `flexcube`, `iso 8583`, `iso 20022`, `metatrader`, crypto wallets …). Generic or shared names (`ge`, `sel`, `oracle`, `sap`, `cisco`, `huawei`, Honeywell's consumer lines) stay out. A vendor can own non-OT product lines, so `healthineers` / `siemens healthineers` are **negative** energy keywords: a Siemens Healthineers CVE stays healthcare only.

**Effect (same 25k sample):** with the vendor vocabulary, 513 CVEs are tagged energy instead of 26, and 24 more are tagged finance. On the full NVD set that is roughly +2,800 energy CVEs against the 234 that the vocabulary without vendor names produces. Tags are assigned at collection.

### 3.7 Future: LLM-Based Classification (Roadmap)

For sources without sector tags or sector keywords, we can use LLM classification:

**Option A: Cloud API (MiniMax)**
- Pros: High accuracy, no infrastructure
- Cons: API cost, privacy concerns

**Option B: Local Small Models (Recommended)**
- Models: NVIDIA Nemotron, IBM Granite, Qwen
- Pros: No API cost, privacy preserved, offline capable
- Cons: Requires hardware (MPS/MPS-compatible)

**Implementation would be:**
```python
def classify_llm(text: str) -> str:
    prompt = f"""Classify this threat intel into sector:
    {text}
    
    Sectors: healthcare, energy, finance, global
    Answer with single word."""
    
    # Use local model (Ollama with Granite/Qwen)
    response = ollama.generate(model='granite4:latest', prompt=prompt)
    return response['response'].strip()
```

**Recommended approach for EdgeGuard:**
1. Start with keyword classification (malware families link to `Malware` nodes, not to sectors; § 3.6)
2. Add local LLM classification
3. Use Ollama with Granite-4 or Qwen-4 for inference

---

## 4. Deduplication & Merging

### 4.1 Deduplication Strategy

We use UNIQUE constraints as deduplication keys. No key includes `tag`, so the same entity merges across sources:

| Node Type | UNIQUE Constraint Key |
|-----------|----------------------|
| CVE | `(cve_id)` |
| Vulnerability | `(cve_id)` |
| Indicator | `(indicator_type, value)` |
| Technique | `(mitre_id)` |
| ThreatActor | `(name)` |
| Malware | `(name)` |
| Tactic | `(mitre_id)` |
| Tool | `(mitre_id)` |
| Campaign | `(name)` |
| Sector | `(name)` |

**Note:** no EdgeGuard threat-intel constraint includes `tag`; the keys
are single-key `(name)` / `(cve_id)` / `(mitre_id)` or
`(indicator_type, value)`. The same entity MERGEs across sources into one
node, with per-source provenance carried on
`(Node)-[:SOURCED_FROM]->(Source)` edges (see `merge_node_with_source`
in `src/neo4j_client.py`). Do not add `tag` to a constraint without
re-architecting the SOURCED_FROM model.

### 4.2 Merge Logic

```python
def merge_node(existing, new):
    # last_updated = the database's time of this write (datetime()), not a max
    existing.last_updated = now()
    
    # Merge lists (sources, tags)
    existing.sources = list(set(existing.sources + new.sources))
    
    # Non-Indicator labels: keep the highest confidence.
    # Indicators: source_confidence = max(incoming), and
    # confidence_score = max(0.10, round(source_confidence × aging factor, 2))
    # (src/indicator_aging.py)
    if existing.label != "Indicator":
        existing.confidence_score = max(
            existing.confidence_score,
            new.confidence_score
        )
    else:
        existing.source_confidence = max(
            existing.source_confidence,
            new.confidence_score
        )
        existing.confidence_score = aged(existing.source_confidence)
    
    return existing
```

### 4.3 Confidence Scoring

The values each collector sets on its items (layer 1 below says which of them reach Neo4j):

| Source | Base Confidence | Rationale |
|--------|---------------|-----------|
| MITRE ATT&CK | 0.7 (actors, malware, tools) / 0.8 (techniques) / 0.9 (tactics) | Authoritative; `mitre_collector.py` sets the value by object type |
| CISA KEV | 0.9 (also affects NVD) | Government-confirmed exploitation. NVD CVEs ALSO get 0.9 when listed in CISA KEV (`nvd_collector.py`: `0.9 if cisa_exploit_add else 0.6`) |
| NVD | 0.6 (default) / 0.9 (on CISA KEV) | CVE database; bumps to 0.9 when the same CVE is listed in CISA KEV |
| AlienVault OTX | 0.5 | Community-driven, all 4 OTX emit sites use 0.5 |
| MISP (collector / read side) | 0.5–0.8 | `misp_collector.py` per-attribute (0.5 for raw, 0.6/0.7/0.8 for tagged tiers) |
| AbuseIPDB | `abuseConfidenceScore / 100.0` | Vendor-supplied 0-100 score divided to 0-1 range |
| ThreatFox | `confidence_level / 100` (0.5 when absent) | Vendor-supplied (`global_feed_collector.py`) |
| URLhaus | 0.6 | `global_feed_collector.py` |
| MalwareBazaar | 0.7 (with a signature) / 0.6 | `global_feed_collector.py`; flag-guarded |
| Feodo Tracker | 0.7 (active) / 0.4 (historical) | `finance_feed_collector.py` |
| SSL Blacklist | 0.6 | `finance_feed_collector.py` |
| CISA ICS advisories | 0.9 | Government advisory (`cisa_ics_collector.py`); flag-guarded |

**Confidence Calculation:**

There is no data-quality factor or other multiplier on the source
confidence: downstream consumers (including the Stage-2 fine-tuning
dataset) must not assume one. The model is three independent layers:

1. **Source prior** — each collector sets a confidence (table above). It
   reaches Neo4j through MISP only as a band: `MISPWriter` tags each
   indicator attribute `confidence:high` (≥ 0.8), `confidence:medium`
   (≥ 0.5) or `confidence:low` (< 0.5), and the sync reads these back as
   0.8 / 0.5 / 0.3; the highest banded value a source gave is the
   indicator's `source_confidence`. CVE, Malware and ThreatActor attributes
   carry no confidence tag and are stored at 0.5; Technique, Tactic and
   Tool are stored at 0.8, 0.95 and 0.9.
2. **Co-occurrence calibration** (post-sync, `enrichment_jobs.py`
   `calibrate_cooccurrence_confidence`): co-occurrence-derived `INDICATES`
   **and** `EXPLOITS` edges from large bulk-feed MISP events are
   down-weighted by event size into the 0.30–0.50 band (≤10 → 0.50,
   ≤20 → 0.45, ≤100 → 0.40, ≤500 → 0.35, >500 → 0.30); only edges marked
   `misp_cooccurrence` / `misp_correlation` are touched. The pipeline writes
   no such edges — links are report-scoped (same OTX pulse,
   `match_type='otx_pulse'`, 0.6) — so this step changes nothing on a fresh
   baseline.
3. **Indicator aging** (`src/indicator_aging.py`; applied by
   every Indicator write and by the post-sync job `decay_ioc_confidence`):
   one rule for every `Indicator`, whoever supplied it — the age counts
   from the latest report of any source (the source's own `last_seen`
   capped at the MISP timestamp; `first_imported_at` when no report dated
   it), and `confidence_score = max(0.10, round(source_confidence × factor,
   2))` with ×0.85 from 90 days, ×0.70 from 180 and ×0.55 from 365; from
   730 days the indicator is retired (`active=false`, `retired_by =
   'decay'`). `source_confidence` is the highest confidence a source gave,
   so the factor never applies twice. No other label ages (`Vulnerability`
   included). Each node carries `aging_basis`,
   `aging_tier`, `aging_factor`, `aging_since` and `aging_evaluated_at`
   (the time at which its aging values were last written: by a write, or
   by a job run that changed them; a job run that changes nothing leaves
   it unchanged). The rule runs at the database's current time, lifted to
   `aging_evaluated_at` when that is later, so the aging never moves
   backwards.

When explaining a score, cite the layer that produced it (source prior,
`source_confidence`, the co-occurrence calibration band, or the aging tier
with its basis) — multi-source
corroboration is visible through per-source `SOURCED_FROM` edges and, for a
relationship, through `r.sources[]` (`size(r.sources) >= 2` = two or more
sources assert it), not folded into a single multiplier.

---

## 5. Relationship Building

### 5.1 Relationship Types

| Relationship | Source | Logic |
|-------------|--------|-------|
| `EMPLOYS_TECHNIQUE` | MITRE | ThreatActor employs Technique (attribution — from STIX `uses`) |
| `IMPLEMENTS_TECHNIQUE` | MITRE | Malware / Tool implements Technique (capability — from STIX `uses`) |
| `USES_TECHNIQUE` | OTX | Indicator observed tied to Technique (from `attack_ids`) |
| `ATTRIBUTED_TO` | Malware's own claim / OTX | Malware attributed to ThreatActor: exact `attributed_to` name or alias match (1.0), or named in the same OTX pulse when the pulse's actors are one actor (`otx_pulse`, 0.6) |
| `INDICATOR_RESOLVES_TO` (planned) | DNS | Indicator → IP; not written |
| `EXPLOITS` | CVEs | Indicator exploits Vulnerability (exact CVE ID match) |
| `INDICATES` | Malware | Indicator indicates Malware (same OTX pulse `otx_pulse` 0.6, or malware_family match 0.8; never from whole-event co-occurrence) |

Also written: `USES_MALWARE` / `USES_TOOL` (MITRE explicit, 0.95), `SUBTECHNIQUE_OF`, `IN_TACTIC`,
`TARGETS` / `AFFECTS` (`zone_classification` 0.5, `advisory_sector` 0.9), `RUNS` /
`PART_OF_CAMPAIGN` and `REFERS_TO`; see [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md), "Complete Relationship Schema".

### 5.2 Relationship Quality

- **EMPLOYS_TECHNIQUE / IMPLEMENTS_TECHNIQUE**: High quality - direct from MITRE STIX `uses` relationships. Two types separate attribution (actor→technique) from capability (malware/tool→technique), so that Cypher queries and LLM/GraphRAG retrieval can tell the two semantics apart; both collapse back to STIX `uses` on export.
- **ATTRIBUTED_TO**: Exact (1.0) when the malware's own `attributed_to` names the actor; medium (0.6, `otx_pulse`) when malware and actor are named in the same OTX pulse and the pulse's actors are one actor. A pulse naming several actors does not say which malware is whose and attributes nothing; aliases of one actor count as one. EdgeGuard does not attribute by whole-event co-occurrence, because a large MISP event can link one malware to up to 152 actors.
- **EXPLOITS**: High quality - deterministic CVE ID match (confidence 1.0)
- **INDICATES**: Medium quality - same OTX pulse (0.6, `otx_pulse`) or malware_family name match (0.8). No `INDICATES` edge comes from whole-event co-occurrence.
- **INDICATOR_RESOLVES_TO** (planned): requires external DNS data; not written

---

## 6. Future: Embedding-Based Classification

### 6.1 Why Embeddings?

Current keyword approach has limitations:
- Can't handle synonyms or variations
- Misses context-dependent classifications
- Limited to predefined keywords

### 6.2 Proposed Approach

```python
# Future implementation concept
def classify_with_embeddings(text):
    # 1. Generate embedding
    embedding = embed_model.encode(text)
    
    # 2. Compare to sector centroids
    similarities = {
        'healthcare': cosine_similarity(embedding, healthcare_centroid),
        'energy': cosine_similarity(embedding, energy_centroid),
        'finance': cosine_similarity(embedding, finance_centroid)
    }
    
    # 3. Return best match if above threshold
    best = max(similarities, key=similarities.get)
    if similarities[best] > 0.7:
        return best
    return 'global'
```

### 6.3 Training Data

To train sector embeddings, we'd need:
- Labeled threat intel samples per sector
- OR use pre-trained domain-specific embeddings
- Fine-tune on OTX pulse descriptions

---

## 7. Text Summaries & GraphRAG

### 7.1 Node Summaries

Each node can have a text summary for LLM consumption:

```cypher
// Generate summary for threat actor
MATCH (a:ThreatActor {name: 'APT29'})
OPTIONAL MATCH (a)-[:EMPLOYS_TECHNIQUE]->(t:Technique)
RETURN a.name AS actor,
       a.aliases AS aliases,
       collect(t.name) AS techniques
```

**Output:**
```json
{
  "actor": "APT29",
  "aliases": ["Cozy Bear", "The Dukes"],
  "techniques": ["Spearphishing", "Credential Dumping"]
}
```

### 7.2 GraphRAG Query Pattern

```python
def enrich_alert_with_rag(ip_address):
    # 1. Find context in graph
    context = """
    IP: {ip}
    Associated malware: {malware}
    Known threat actors: {actors}
    Used techniques: {techniques}
    CVEs exploited: {cves}
    """
    
    # 2. Build prompt for LLM
    prompt = f"""
    Given this threat intelligence about IP {ip_address}:
    {context}
    
    Provide a summary for a SOC analyst.
    """
    
    # 3. Call LLM (MiniMax)
    summary = llm.generate(prompt)
    
    return summary
```

---

## 8. Performance Considerations

### 8.1 Query Latency

| Query Type | Expected Latency | Notes |
|-----------|------------------|-------|
| Simple lookup | <50ms | By ID/index |
| Pattern match | <150ms | With limits |
| Full enrichment | <2s | Multiple hops |

### 8.2 Indexing Strategy

```cypher
// Constraints (unique)
CREATE CONSTRAINT vulnerability_key IF NOT EXISTS FOR (v:Vulnerability) REQUIRE (v.cve_id) IS UNIQUE

// Indexes (for speed)
CREATE INDEX indicator_value IF NOT EXISTS FOR (i:Indicator) ON (i.value)
CREATE INDEX indicator_type IF NOT EXISTS FOR (i:Indicator) ON (i.indicator_type)
CREATE INDEX technique_mitre IF NOT EXISTS FOR (t:Technique) ON (t.mitre_id)
CREATE INDEX actor_name IF NOT EXISTS FOR (a:ThreatActor) ON (a.name)
```

---

## 9. Data Quality Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Duplicate nodes | 0% | 0% |
| Missing confidence | 0% | 0% |
| Invalid IPs | <1% | 0% |
| Unknown indicators | <5% | 0% |

---

## 10. Summary

EdgeGuard uses a **keyword-based sector classification** with word boundary matching to prevent false positives. Data is normalized to a standard schema, deduplicated by composite keys, and assigned confidence scores based on source reliability.

The architecture supports multiple data sources, with MITRE providing the highest quality TTP relationships (`EMPLOYS_TECHNIQUE` for actors, `IMPLEMENTS_TECHNIQUE` for malware/tools), and community sources (OTX, MISP) providing broad IOC coverage.

Future enhancements include embedding-based classification for better context understanding and GraphRAG integration for natural language threat queries.

---

*Methodology Version: 1.1*

---

## Appendix: data written by earlier versions

The main text assumes a fresh baseline. A graph kept across an upgrade can still hold:

- **Co-occurrence edges.** Versions before report-scoped linking wrote `INDICATES` and `EXPLOITS` edges from whole-event co-occurrence (`match_type` `misp_cooccurrence` / `misp_correlation`). The calibration job `calibrate_cooccurrence_confidence` (§ 4.3, layer 2) down-weights them by event size; a fresh baseline writes none.
- **Attributions from multi-actor pulses.** `build_relationships` step 2d removes an `ATTRIBUTED_TO` edge that rests only on OTX pulses naming several actors (a graph built before that rule holds them), unless another feed asserts the link too, and drops such pulses from the provenance of the attributions that remain; see [RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md).
- **Sector tags without the CPE vendor vocabulary.** Tags are assigned at collection, so CVEs collected before the vocabulary of § 3.6b keep their earlier zones until a baseline or a daily run collects them again.

---

_Last updated: 2026-10-17_

## History

- 2026-10-17 — Main text describes current behaviour only; history and repairs of data from earlier versions moved to the end.
- 2026-10-17 — Corrected against the code: each collector's confidence value (MITRE by object type; ThreatFox, URLhaus, MalwareBazaar, Feodo Tracker, SSL Blacklist and CISA ICS rows), only an indicator's band (0.8 / 0.5 / 0.3) reaches Neo4j, collection flow through MISP, production zone matching and keywords, malware families not sector keywords, CISA ICS / MalwareBazaar / FIRST EPSS sources, `ATTRIBUTED_TO` as Malware → ThreatActor, `INDICATOR_RESOLVES_TO` as the planned DNS bridge, merge pseudo-code with write-time `last_updated` and Indicator aging, MISP `uri` not read as a URL.
- 2026-10-16 — Time decay replaced by indicator aging: one rule for every Indicator from the latest report of any source, ×0.85 / ×0.70 / ×0.55 from 90 / 180 / 365 days, retirement from 730 days, `aging_*` properties (incl. `aging_evaluated_at`) instead of `last_decayed_tier`; Vulnerability decay tiers removed.
- 2026-10-15 — Type mapping: `ipv6` by address, `x509-fingerprint-sha1` for SSL Blacklist, hash type by digest length, OTX non-file hashes not collected, OTX e-mail typed as e-mail; corroboration through `r.sources[]`; `ATTRIBUTED_TO` only from a pulse whose actors are one actor.
- 2026-10 — Links made report-scoped (same OTX pulse, 0.6): whole-event co-occurrence `INDICATES` (0.5) and attribution (up to 152 actors for one malware) removed, so the co-occurrence calibration changes nothing on a fresh baseline.
- 2026-10 — CPE vendor and product vocabulary added to the energy and finance keywords (energy-tagged CVEs 26 → 513 on a 25k-CVE sample).
- 2026-06-11 — Removed the `data_quality_factor` confidence formula, which no code implements; documented the three-layer model.
- 2026-04-28 — Per-source confidence table corrected against `src/collectors/` (NVD 0.6 / 0.9 on CISA KEV, OTX flat 0.5; AbuseIPDB, ThreatFox and global feeds added).
- 2026-04-26 — Removed the statement that `tag` scopes the dedup key; fixed the `vulnerability_key` Cypher.
- 2026-04 — Generic `USES` split into `EMPLOYS_TECHNIQUE` (actor) and `IMPLEMENTS_TECHNIQUE` (malware / tool).
