# Graph Explorer

Interactive browser-based visualization for the EdgeGuard knowledge graph. Built on **Cytoscape.js**, connects directly to the FastAPI backend, and works with the default Neo4j Community Edition — no additional licenses required.

**File:** [`docs/visualization.html`](visualization.html)
**API endpoint:** `GET /graph/explore`
**Last updated:** 2026-03-27

---

## Why not Neo4j Bloom?

Neo4j Bloom is a mature graph visualization tool, but it requires a **Neo4j Enterprise license** (paid). EdgeGuard defaults to Community Edition to keep the stack accessible for SMEs and research institutions. The built-in graph explorer provides equivalent interactive exploration capabilities without license constraints.

If your deployment uses Neo4j Enterprise or Aura, Bloom can be used alongside or instead of the built-in explorer — the underlying graph schema is fully compatible.

---

## Quick Start

1. **Start the API** (if not already running):
   ```bash
   # Via Docker Compose
   docker compose up api

   # Or directly
   uvicorn src.query_api:app --host 0.0.0.0 --port 8000
   ```

2. **Open the explorer** in your browser:
   ```
   docs/visualization.html
   ```
   Or serve it via any static file server.

3. **Connect** by entering:
   - **API URL:** `http://localhost:8000` (or your deployment URL)
   - **API Key:** your `EDGEGUARD_API_KEY` value

   Credentials are saved in `localStorage` for convenience — the explorer auto-reconnects on next visit.

---

## Views

The explorer offers four pre-built views, each running a different Cypher query against the live Neo4j database.

### Malware (default)

**What it shows:** Malware families linked to their indicators (IOCs), grouped by target sector.

**Layout:** Top-down hierarchical (dagre) — malware at the top, indicators in the middle, sector triangles at the bottom.

**Use case:** "Which malware families are targeting our sector? What IOCs should we block?"

**Cypher pattern:**
```cypher
MATCH (m:Malware)-[r]->(i:Indicator)
WHERE type(r) IN ['INDICATES', 'USES', 'DROPS']
```

### Actors

**What it shows:** Threat actors (APT groups) connected to their known ATT&CK techniques and tactics.

**Layout:** Force-directed (cose) — actors cluster around shared techniques.

**Use case:** "What techniques does APT29 use? Which actors share the same TTPs?"

**Cypher pattern:**
```cypher
MATCH (a:ThreatActor)-[:USES]->(t:Technique)
OPTIONAL MATCH (t)-[:IN_TACTIC]->(tac:Tactic)
```

### Indicators

**What it shows:** IOCs (IPs, domains, hashes, URLs) grouped and colored by zone.

**Layout:** Force-directed — indicators orbit their sector nodes.

**Use case:** "What are the highest-confidence IOCs in the healthcare zone?"

**Cypher pattern:**
```cypher
MATCH (n:Indicator)
ORDER BY n.confidence_score DESC
```

### CVEs (Vulnerability Landscape)

**What it shows:** Vulnerabilities sized by CVSS score. CISA KEV entries are highlighted with a red glow and border.

**Layout:** Force-directed — critical/KEV CVEs appear largest.

**Use case:** "Which vulnerabilities are actively exploited? What's the CVSS distribution in our zone?"

**Cypher pattern:**
```cypher
MATCH (n)
WHERE (n:Vulnerability OR n:CVE) AND n.cve_id IS NOT NULL
-- Coalesces data from both labels so CISA KEV fields on CVE nodes are found
```

---

## Controls

| Control | What it does |
|---------|--------------|
| **View buttons** (Malware / Actors / Indicators / CVEs) | Switch between graph views |
| **Zone filter** | Restrict to a single zone (healthcare, energy, finance, global) or show all |
| **Node limit** | 50 / 100 / 200 / 500 — controls how many nodes the API returns |
| **Search box** | Type to highlight matching nodes; non-matching nodes dim to 15% opacity |
| **Fit** | Zoom to fit all nodes in the viewport |
| **Layout** | Re-run the layout algorithm (useful after filtering or when nodes overlap) |

### Node Interaction

- **Hover** a node to see a tooltip with its label, type, and key metric (CVSS, indicator type, KEV status)
- **Click** a node to open the **detail panel** (right sidebar) showing all properties and connected neighbors
- **Click the background** to close the detail panel

---

## API Endpoint

```
GET /graph/explore?view={view}&zone={zone}&limit={limit}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `view` | `attacks` \| `actors` \| `indicators` \| `vulnerabilities` | `attacks` | Which graph view to load |
| `zone` | `healthcare` \| `energy` \| `finance` \| `global` | *(all)* | Filter nodes by zone |
| `limit` | `10`–`500` | `100` | Maximum nodes returned |

**Response format** (Cytoscape.js-native):
```json
{
  "nodes": [
    {"data": {"id": "malware:Emotet", "label": "Emotet", "type": "malware", "family": "Emotet"}}
  ],
  "edges": [
    {"data": {"source": "malware:Emotet", "target": "indicator:192.168.1.1", "type": "USES"}}
  ],
  "stats": {"nodes": 42, "edges": 67}
}
```

**Authentication:** requires `X-API-Key` header (same key as all other API endpoints).

---

## Node Visual Encoding

| Node Type | Shape | Color | Size Logic |
|-----------|-------|-------|------------|
| **Sector** | Triangle | Healthcare=green, Energy=blue, Finance=purple, Global=grey | Fixed (large landmark) |
| **Malware** | Circle | Red (#e74c3c) | Fixed (44px) |
| **Threat Actor** | Circle | Red (#e74c3c) | Fixed (40px) |
| **Technique** | Diamond | Yellow (#ffd93d) | Fixed (28px) |
| **Tactic** | Hexagon | Orange (#ff9f43) | Fixed (34px) |
| **Indicator** | Small circle | Colored by zone (green/blue/purple/teal) | Fixed (18px) |
| **Vulnerability** | Rounded rect | Orange (#ff9f43); **Red if CISA KEV** | Scales with CVSS score (24–60px) |

| Edge Type | Style | Color |
|-----------|-------|-------|
| `USES` | Solid, thick | Red |
| `BELONGS_TO` / `IN_ZONE` | Dashed | Teal |
| `IN_TACTIC` | Dotted | Orange |

---

## Tech Stack

- **Cytoscape.js 3.28** — graph rendering and interaction
- **Dagre** — hierarchical layout for the Malware view
- **Cose** (built-in) — force-directed layout for other views
- **FastAPI** — backend API serving graph data
- **Neo4j** — source of truth for all graph queries

No build step, no npm, no bundler — a single self-contained HTML file.

---

## Extending

### Adding a new view

1. Add a new `GraphView` enum value in `src/query_api.py`
2. Add a Cypher query block in the `graph_explore()` endpoint
3. Add a layout config in the `layoutOpts` object in `visualization.html`
4. Add a legend entry in the `legends` object
5. Add a view button in the header HTML

### Custom styling

All Cytoscape.js styles are defined inline in the `cy` initialization. Node colors, sizes, and shapes can be modified there. CSS variables at the top of `<style>` control the overall theme.
