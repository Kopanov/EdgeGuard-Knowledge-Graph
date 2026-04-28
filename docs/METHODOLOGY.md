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
| URLhaus, ThreatFox, CyberCure, Feodo, SSLBL | CSV/API | Scheduled | Feeds (see `global_feed_collector.py`, `finance_feed_collector.py`) |

_Full inventory: [`DATA_SOURCES.md`](DATA_SOURCES.md)._

### 1.2 Collection Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Source    │────▶│  Collector  │────▶│ Normalizer  │
│   API/IO    │     │   (Python)  │     │   (Python)  │
└─────────────┘     └─────────────┘     └─────────────┘
                                              │
                                              ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    Neo4j   │◀────│   Loader    │◀────│Deduplicator │
│  Database  │     │   (Python)  │     │   (Python)  │
└─────────────┘     └─────────────┘     └─────────────┘
```

---

## 2. Data Normalization

### 2.1 Indicator Type Mapping

Each source uses different attribute types. We normalize to a standard set:

| Our Standard | MISP | OTX | Notes |
|--------------|------|-----|-------|
| `ipv4` | ip-src, ip-dst | IPv4 | IP addresses |
| `domain` | domain, hostname | domain | DNS names |
| `url` | url, uri | URL | Web addresses |
| `hash` | md5, sha1, sha256 | MD5, SHA256 | File hashes |
| `email` | email-src, email-dst | EMAIL | Email addresses |
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

We use regex word boundaries to prevent false positives:

```python
import re

def detect_sector(text):
    """Match keywords with word boundaries"""
    text_lower = text.lower()
    
    for sector, keywords in SECTOR_KEYWORDS.items():
        for keyword in keywords:
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, text_lower):
                return sector
    
    return DEFAULT_SECTOR  # 'global'
```

**Example False Positive Prevention:**
| Keyword | Text | Match? | Why |
|---------|------|--------|-----|
| `phishing` | "phishing campaign" | ✅ Yes | Word boundary |
| `phishing` | "phishing" in "hospital" | ❌ No | "phishing" not separate word |
| `his` | "hospital information system" | ❌ No | "his" is part of "his" |

### 3.3 Sector Coverage

| Sector | Primary Keywords | Secondary (Threat Context) |
|--------|-----------------|---------------------------|
| Healthcare | hospital, medical, patient | healthcare sector, medical device |
| Energy | scada, grid, power | energy sector, power grid |
| Finance | bank, payment, trading | banking trojan, financial theft |

### 3.4 Current Data Distribution

**As of 2026-03-02:**

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

**Conclusion:** Keep keyword as default. Hybrid provides no benefit on current data.

### 3.6 Option 2: Malware Family Mapping (IMPLEMENTED)

**Problem:** Public OSINT feeds lack sector tags for most IOCs.

**Solution:** Use malware family names from threat feeds to auto-classify:

| Source | Malware Families | Sector |
|--------|-----------------|--------|
| Feodo Tracker | Emotet, Dridex, TrickBot, QakBot | Finance |
| SSL Blacklist | Vidar, RedLine, Raccy, FormBook | Finance |
| MalwareBazaar | Multiple stealers | Finance |
| OTX Pulses | Tagged malware | Auto-detected |

**Implementation:** Added malware family names to `SECTOR_KEYWORDS['finance']` in `src/config.py`.

**Result:** When feeds provide malware family names (e.g., "QakBot C&C server"), classification now works automatically.

### 3.7 Future: LLM-Based Classification (Roadmap)

For sources without sector tags or malware family names, we can use LLM classification:

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
1. Start with keyword + malware family mapping
2. Add local LLM classification in Sprint 2
3. Use Ollama with Granite-4 or Qwen-4 for inference

---

## 4. Deduplication & Merging

### 4.1 Deduplication Strategy

We use UNIQUE constraints as deduplication keys — `tag` removed from all entity keys so the same entity merges across sources:

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

**Note (PR-N33 docs audit, 2026-04-26):** `tag` was REMOVED from every
EdgeGuard threat-intel constraint in earlier passes (the keys above are
the current truth — single-key `(name)` / `(cve_id)` / `(mitre_id)` /
`(indicator_type, value)`). The same entity now MERGEs across sources
into one node, with per-source provenance carried on
`(Node)-[:SOURCED_FROM]->(Source)` edges (see `merge_node_with_source`
in `src/neo4j_client.py`). Do not re-introduce `tag` into a constraint
without re-architecting the SOURCED_FROM model.

### 4.2 Merge Logic

```python
def merge_node(existing, new):
    # Always keep the most recent
    existing.last_updated = max(
        existing.last_updated, 
        new.last_updated
    )
    
    # Merge lists (sources, tags)
    existing.sources = list(set(existing.sources + new.sources))
    
    # Take highest confidence
    existing.confidence_score = max(
        existing.confidence_score,
        new.confidence_score
    )
    
    return existing
```

### 4.3 Confidence Scoring

| Source | Base Confidence | Rationale |
|--------|---------------|-----------|
| MITRE ATT&CK | 0.8 / 0.9 | Authoritative; `mitre_collector.py` writes 0.8 or 0.9 depending on relationship type |
| CISA KEV | 0.9 (also affects NVD) | Government-confirmed exploitation. NVD CVEs ALSO get 0.9 when listed in CISA KEV (`nvd_collector.py`: `0.9 if cisa_exploit_add else 0.6`) |
| NVD | 0.6 (default) / 0.9 (on CISA KEV) | CVE database; bumps to 0.9 when the same CVE is listed in CISA KEV |
| AlienVault OTX | 0.5 | Community-driven, all 4 OTX emit sites use 0.5 |
| MISP (push side) | 0.8 | `misp_writer.py` baseline confidence for EdgeGuard-pushed indicators |
| MISP (collector / read side) | 0.5–0.8 | `misp_collector.py` per-attribute (0.5 for raw, 0.6/0.7/0.8 for tagged tiers) |
| AbuseIPDB | `abuseConfidenceScore / 100.0` | Vendor-supplied 0-100 score divided to 0-1 range |
| ThreatFox / global feeds | 0.5 / 0.6 / vendor-supplied | `global_feed_collector.py`; vendor-supplied takes precedence |

**Confidence Calculation:**
```
final_confidence = source_confidence * data_quality_factor

# data_quality_factor accounts for:
# - Completeness of attributes (0.8-1.0)
# - Age of data (newer = higher)
# - Number of sources confirming (more = higher)
```

---

## 5. Relationship Building

### 5.1 Relationship Types

| Relationship | Source | Logic |
|-------------|--------|-------|
| `EMPLOYS_TECHNIQUE` | MITRE | ThreatActor employs Technique (attribution — from STIX `uses`). *Split from generic `USES` in 2026-04.* |
| `IMPLEMENTS_TECHNIQUE` | MITRE | Malware / Tool implements Technique (capability — from STIX `uses`). *Split from generic `USES` in 2026-04.* |
| `USES_TECHNIQUE` | OTX | Indicator observed tied to Technique (from `attack_ids`) |
| `ATTRIBUTED_TO` | OTX | Indicator associated with Malware (from pulse) |
| `RESOLVES_TO` | DNS | Domain resolves to IP (needs DNS data) |
| `EXPLOITS` | CVEs | Indicator exploits Vulnerability (exact CVE ID match) |
| `INDICATES` | Malware | Indicator indicates Malware (MISP co-occurrence or malware_family match) |

### 5.2 Relationship Quality

- **EMPLOYS_TECHNIQUE / IMPLEMENTS_TECHNIQUE**: High quality - direct from MITRE STIX `uses` relationships. The split into attribution (actor→technique) and capability (malware/tool→technique) was made in 2026-04 to disambiguate the two semantics for Cypher queries and LLM/GraphRAG retrieval; both collapse back to STIX `uses` on export.
- **ATTRIBUTED_TO**: Medium quality - inferred from OTX pulse
- **EXPLOITS**: High quality - deterministic CVE ID match (confidence 1.0)
- **INDICATES**: Medium quality - MISP co-occurrence (0.5) or malware_family name match (0.8)
- **RESOLVES_TO**: Requires external DNS data (not yet implemented)

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

The architecture supports multiple data sources, with MITRE providing the highest quality TTP relationships (`EMPLOYS_TECHNIQUE` for actors, `IMPLEMENTS_TECHNIQUE` for malware/tools — previously a single `USES` edge, split in 2026-04), and community sources (OTX, MISP) providing broad IOC coverage.

Future enhancements include embedding-based classification for better context understanding and GraphRAG integration for natural language threat queries.

---

*Methodology Version: 1.1*

---

_Last updated: 2026-04-28 — PR-N36 Tier-2 deep verification: corrected the per-source confidence table to match `src/collectors/`. Findings: NVD says 0.7 in doc but actual is 0.6 (default) / 0.9 (when CISA-listed); OTX says 0.5-0.7 range but actual is flat 0.5 across all 4 emit sites; added missing rows for AbuseIPDB (vendor score / 100), ThreatFox/global feeds (0.5/0.6/vendor), and split MISP into push-side (0.8) vs collector-side (0.5–0.8). Prior: 2026-04-26 PR-N33 docs audit (removed contradictory "tag scopes the dedup key"; fixed `vulnerability_key` Cypher); 2026-03-28._
