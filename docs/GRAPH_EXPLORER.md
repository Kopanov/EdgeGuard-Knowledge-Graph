# Graph Explorer

Interactive browser-based visualization for the EdgeGuard knowledge graph. Built on **Cytoscape.js**, connects directly to the FastAPI backend, and works with the default Neo4j Community Edition — no additional licenses required.

**File:** [`docs/visualization.html`](visualization.html)
**API endpoint:** `GET /graph/explore`
**Last updated:** 2026-10-17 — the CVE view's `description` (first 200 characters) and `description_source` (of a CVE's twins, the text the source ranking keeps); the Cypher pattern comments use `//` (`--` is not a Cypher comment). Prior: 2026-10-15 — Quick Start: when the monitoring stack's Grafana holds port 3000, serve `docs/` on port 3001 and append `http://localhost:3001` to `EDGEGUARD_CORS_ORIGINS`; `limit` caps the rows each view reads, not the nodes; the CVE view's Cypher comment says which label carries the score and KEV fields (`:CVE`). Same day: the default view (`attacks`) matches `(Indicator)-[:INDICATES]->(Malware)`, the direction every writer creates (it matched the reverse direction and a `DROPS` type that nothing writes, and was always empty); edges point the way the graph relationship does and are listed once; Quick Start serves the page from an origin the default CORS allowlist accepts (opening the file directly is refused) and says how to add a presenter's origin with `EDGEGUARD_CORS_ORIGINS`; edge style table matches the page. Prior: 2026-04-26 — PR-N33 docs audit: clarified that the "Malware (default)" view's API enum value is `attacks` (was confusing — heading said "Malware" but the API parameter says `attacks`). Prior: 2026-03-27.

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
   uvicorn src.query_api:app --host 127.0.0.1 --port 8000
   ```

2. **Serve the explorer from an allowed origin.** The page calls the API from the browser, so the
   API must list the page's origin in its CORS allowlist, `EDGEGUARD_CORS_ORIGINS` (default
   `http://localhost,http://localhost:3000`). A page opened directly from disk has the origin
   `null` and is refused, and so is any other static server whose origin is not in the list. With
   the default list, serve `docs/` on port 3000:
   ```bash
   python3 -m http.server 3000 --bind 127.0.0.1 --directory docs
   ```
   and open **`http://localhost:3000/visualization.html`** — with the host name `localhost`:
   the origin is compared as a string, so `http://127.0.0.1:3000` is a different origin and is
   refused.

   **Presenting from another origin** (another port, host name or machine): add that origin to
   the allowlist instead of widening it — never `*`, never `null`. In `.env`, keep the defaults and
   append the presenter's origin exactly as the browser's address bar shows it (scheme, host,
   port; no path, no trailing slash):
   ```bash
   EDGEGUARD_CORS_ORIGINS=http://localhost,http://localhost:3000,https://demo.example.org
   ```
   then restart the API (`docker compose up -d api`; `docker-compose.yml` forwards the variable to
   both APIs) or, without Docker, export the variable before starting `uvicorn`. The list is read
   once at start-up.

   **When Grafana holds port 3000.** The optional monitoring stack (`make monitoring`,
   `docker-compose.monitoring.yml`) binds Grafana to `127.0.0.1:3000`. The command above then
   stops with *Address already in use*, and `http://localhost:3000/visualization.html` answers
   with Grafana's own 404 page. Serve `docs/` on another port and append that origin to the
   allowlist (the default stays as it is):
   ```bash
   python3 -m http.server 3001 --bind 127.0.0.1 --directory docs
   ```
   ```bash
   # .env
   EDGEGUARD_CORS_ORIGINS=http://localhost,http://localhost:3000,http://localhost:3001
   ```
   then restart the API as above and open **`http://localhost:3001/visualization.html`**.

3. **Connect** by entering:
   - **API URL:** `http://localhost:8000` (or your deployment URL)
   - **API Key:** your `EDGEGUARD_API_KEY` value

   Credentials are saved in `localStorage` for convenience — the explorer auto-reconnects on next visit.
   **Connect** calls `GET /health`, which answers 503 while Neo4j is unavailable; the explorer then
   reports the status code instead of loading a view.

---

## Views

The explorer offers four pre-built views, each running a different Cypher query against the live Neo4j database.

### Malware (API enum value: `attacks` — the default)

**What it shows:** Indicators (IOCs) linked to the malware families they indicate, and each indicator's sectors.

**Layout:** Top-down hierarchical (dagre). Edges point the way the graph relationship does —
indicator → malware (`INDICATES`) and indicator → sector — so the indicators form the top row and
the malware families and sector triangles the row below.

**Use case:** "Which malware families are targeting our sector? What IOCs should we block?"

**Cypher pattern:**
```cypher
MATCH (i:Indicator)-[:INDICATES]->(m:Malware)
// Both ends EdgeGuard-created or enriched; zone filter on the indicator.
// 2026-10: every writer (build_relationships, the MISP → Neo4j sync, the
// alert path) creates (Indicator)-[:INDICATES]->(Malware). The view
// matched (Malware)-[INDICATES|DROPS]->(Indicator) before — a direction
// and a DROPS type that nothing writes — and was always empty.
```

### Actors

**What it shows:** Threat actors (APT groups) connected to their known ATT&CK techniques and tactics.

**Layout:** Force-directed (cose) — actors cluster around shared techniques.

**Use case:** "What techniques does APT29 use? Which actors share the same TTPs?"

**Cypher pattern:**
```cypher
MATCH (a:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t:Technique)
OPTIONAL MATCH (t)-[:IN_TACTIC]->(tac:Tactic)
// EMPLOYS_TECHNIQUE is the actor→technique edge since the 2026-04 split
// of the generic USES relationship. For malware/tool capability instead,
// use IMPLEMENTS_TECHNIQUE.
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

**What it shows:** Vulnerabilities sized by CVSS score. CISA KEV entries are highlighted with a red glow and border. Each CVE node carries `description` (first 200 characters) and `description_source` (2026-10-16): of a CVE's `:CVE` and `:Vulnerability` twins, the text the source ranking keeps (NVD > CISA KEV > CISA ICS > other; at an equal rank, the twin that names a source).

**Layout:** Force-directed — critical/KEV CVEs appear largest.

**Use case:** "Which vulnerabilities are actively exploited? What's the CVSS distribution in our zone?"

**Cypher pattern:**
```cypher
MATCH (n)
WHERE (n:Vulnerability OR n:CVE) AND n.cve_id IS NOT NULL
// The MISP → Neo4j sync writes :CVE nodes, which carry the score, the
// severity and the CISA KEV fields (merge_cve); :Vulnerability nodes come
// only from the per-item fallback and the alert path. Both labels are read
// and grouped by cve_id, so a CVE / Vulnerability pair is one node.
```

---

## Controls

| Control | What it does |
|---------|--------------|
| **View buttons** (Malware / Actors / Indicators / CVEs) | Switch between graph views |
| **Zone filter** | Restrict to a single zone (healthcare, energy, finance, global) or show all |
| **Node limit** | 50 / 100 / 200 / 500 — the `limit` the API applies to the rows each view reads (see `limit` under *API Endpoint*); the graph can hold more nodes than the limit |
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
| `limit` | `10`–`500` | `100` | Maximum rows the view reads, not nodes: (indicator, malware) pairs in `attacks`, (actor, technique) pairs in `actors` (before the tactics are added), indicators in `indicators`, CVEs in `vulnerabilities`. Sector and tactic nodes come on top, so `stats.nodes` can exceed `limit` |

**Response format** (Cytoscape.js-native):
```json
{
  "nodes": [
    {"data": {"id": "malware:emotet", "label": "emotet", "type": "malware", "family": "emotet"}},
    {"data": {"id": "indicator:203.0.113.5", "label": "203.0.113.5", "type": "indicator", "sector": "finance"}}
  ],
  "edges": [
    {"data": {"source": "indicator:203.0.113.5", "target": "malware:emotet", "type": "INDICATES"}}
  ],
  "stats": {"nodes": 42, "edges": 67}
}
```

Edges named after a graph relationship (`INDICATES`, `EMPLOYS_TECHNIQUE`, `IN_TACTIC`) point the
way the relationship does. `BELONGS_TO` (indicator → sector) and `IN_ZONE` (CVE → sector) are not
graph relationships: they draw the node's `zone` property as a link to a sector node. Each
(source, target, type) edge is listed once (2026-10).

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
| `INDICATES` (indicator → malware) | Solid | Red |
| `EMPLOYS_TECHNIQUE` (actor → technique) | Solid, thick | Red |
| `BELONGS_TO` / `IN_ZONE` (node → sector, from the `zone` property) | Dashed | Teal |
| `IN_TACTIC` (technique → tactic) | Dotted | Orange |

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
