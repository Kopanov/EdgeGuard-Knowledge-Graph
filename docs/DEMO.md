# EdgeGuard Demo

**Last updated:** 2026-10-16 — rewritten for `demo/alert_enrichment_demo.py`, which runs EdgeGuard's alert enrichment read-only against the configured Neo4j and prints the processor's own response; the earlier NATS mock, which printed random values as an enrichment without querying anything, was removed. New section "Workflow demonstration": the end-to-end checks a presenter can run against a deployment. Same day: the alert enrichment reads CVEs as the graph links them, `(Indicator)-[:EXPLOITS]->` a `CVE` or `Vulnerability` node (it read `INDICATES` to a `Vulnerability`, which no code path writes, and found none), with the score and severity of one node. Same day: a failed enrichment query is `enriched: false` and ends the demo with exit code 1, an alert the processor raises on is named and gives exit code 2; the prerequisites set a Bolt URI the host can reach; the comparison with `process_alert` covers confidence and last update; `stats --misp` counts every page of MISP's event index.

Everything shown on this page is what the code returns from the graph it is pointed at. The
output samples below give the **shape** only; the values in angle brackets are placeholders, not
results.

---

## Alert enrichment demo

**Script:** [`demo/alert_enrichment_demo.py`](../demo/alert_enrichment_demo.py)

### What it shows

A ResilMesh alert carries an indicator (IP, domain, hash, URL). EdgeGuard enriches it from the
knowledge graph with `src/alert_processor.py`: the malware families the indicator indicates, the
threat actors those families are attributed to and the ATT&CK techniques the actors employ, the
CVEs the indicator exploits, its confidence, first / last seen and zones, and recommendations
generated from those fields. The demo hands alerts to that code and prints the response as JSON.

- **Real enrichment, read-only.** The demo calls `AlertProcessor.enrich_alert_read_only`: the same
  validation, indicator canonicalization (refang, case-fold, type inference) and enrichment
  queries as `process_alert`, without its writes (`process_alert` first records the Alert node,
  the alert's Indicator and `INVOLVES`, and afterwards stores the enrichment on the Alert node).
  Apart from `Neo4jClient`'s connection check (`RETURN 1`, in a session of the default access
  mode), every statement is a `MATCH` / `RETURN` query sent in a read access session: the
  enrichment's queries and, with `--from-graph`, the selection query below.
- **No NATS.** The alert is passed to the processor directly. EdgeGuard subscribes to
  `resilmesh.alerts.zone.*` in code but has no deployed consumer, and does not publish the
  enriched response yet ([TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) § NATS Topics).
- **Graph patterns read** (each one written by the MISP → Neo4j sync or `build_relationships`):
  `(Indicator)-[:INDICATES]->(Malware)`, `(Malware)-[:ATTRIBUTED_TO]->(ThreatActor)`,
  `(ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique)`, `(Indicator)-[:EXPLOITS]->(CVE | Vulnerability)`,
  the indicator's `SOURCED_FROM` edges (first / last seen as the sources report them) and its
  `zone` list. Techniques are those of the attributed actors; the indicator's own
  `USES_TECHNIQUE` links and the malware's `IMPLEMENTS_TECHNIQUE` links are not part of the
  enrichment.

How the read-only answer differs from a `process_alert` answer, because nothing is recorded:

| Field | Demo (read-only) | `process_alert` |
|-------|------------------|-----------------|
| `query_metadata.indicator_found` | `false` for an indicator the graph does not hold | `true` once its write succeeded: it creates the indicator before reading |
| `enrichment.confidence` | the stored value (`0.0` for an indicator the graph does not hold) | at least 0.8: before reading, the write raises the indicator's confidence to 0.8 when it is lower, for a known indicator too (`create_indicator_from_alert`) |
| `enrichment.last_updated`, `first_seen` | the stored values (`null` for an indicator the graph does not hold) | when no source reports a last seen, `last_updated` is the time of the write (it sets `last_updated` on every alert); an indicator it creates is first imported then |
| `enrichment.sectors_affected` | the indicator's stored zones (the alert's `zone` when the graph does not hold the indicator), plus the alert's `tags` | the indicator's zones after the alert's zones (its `tags`, else its `zone`) were added to them, plus the alert's `tags` |
| `enrichment.known_malware`, `query_metadata.malware_found` | a malware the alert names is listed even when the graph does not hold the indicator, so `malware_found` can be `true` from the alert alone | the same |
| `enrichment.assets`, `users` | empty | empty: no code path writes `(Alert)-[:TARGETS]->(Asset)` or `(Alert)-[:INVOLVES_USER]->(User)` |
| `enriched` when an enrichment query fails | `false`, with `query_metadata.error` | `true`, with `query_metadata.error` |

### Prerequisites

- The repository's Python environment (`./install.sh --python`, or the project's `.venv`).
- A populated Neo4j (after a baseline and a MISP → Neo4j sync).
- The connection settings in the environment, as for every EdgeGuard command
  ([SETUP_GUIDE.md](SETUP_GUIDE.md) § 3.6): `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`.
  `src/config.py` also requires `MISP_API_KEY` when it is imported; the demo does not contact MISP.
- `.env` names the Compose service (`NEO4J_URI=bolt://neo4j:7687`), which resolves inside the
  Compose network only. From the host of a Compose deployment, Neo4j's Bolt port is published on
  the loopback interface: set `NEO4J_URI` after loading `.env`. A remote deployment needs its own
  Bolt URI (for example through a tunnel to its Bolt port).

```bash
set -a && source .env && set +a          # bash/zsh
export NEO4J_URI=bolt://localhost:7687   # host of a Compose deployment; .env names the container
```

### Commands

```bash
# Usage, the selection query and the exit codes
python demo/alert_enrichment_demo.py --help

# Build 3 alerts from real indicators in the graph and enrich them
python demo/alert_enrichment_demo.py --from-graph 3

# The same, restricted to indicators whose zone list holds "energy"
python demo/alert_enrichment_demo.py --from-graph 3 --zone energy

# Enrich alerts from a file: one alert object or a list of them
python demo/alert_enrichment_demo.py --alerts alerts.json

# Only the enrichment of the first response (stdout carries JSON only)
python demo/alert_enrichment_demo.py --from-graph 1 | jq '.[0].enrichment'
```

`--from-graph N` selects N indicators with this read-only query (also printed by `--help`):

```cypher
MATCH (i:Indicator)
WHERE i.active = true
  AND ($zone IS NULL OR $zone IN coalesce(i.zone, []))
  AND EXISTS { MATCH (i)-[:INDICATES]->(:Malware) }
RETURN i.value AS value, i.indicator_type AS indicator_type, i.zone AS zone
ORDER BY i.last_updated DESC, i.value
LIMIT $limit
```

Each alert built from a selected indicator holds only what the graph says about it: the
indicator's value and type, its first stored zone other than `global` (or the `--zone` given),
the time the alert was built, the alert id `demo-graph-<n>` and the source `edgeguard-demo`. It
names no malware, CVE or host, so everything in `known_malware`, `threat_actors`, `techniques` and
`cves` comes from the graph.

An alert file uses the ResilMesh alert schema ([TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) § Alert
Format, `ResilMeshAlert` in `src/alert_processor.py`). Only `alert_id` (a non-empty string) is
required, and `threat`, when present, must be an object; an alert failing that check is answered
with `enriched: false` and the reason, as `process_alert` answers it. Fields the alert itself
carries are reported as such: a CVE the alert names is listed with `"source": "alert"`; a malware
the alert names is listed with the description `From alert (not in graph)` whether or not the
graph holds the indicator, unless a family the indicator is linked to has exactly that name (graph
names are lower case and the comparison is case-sensitive). `malware_found` is then `true` from
the alert alone, and the recommendations include `Deploy signatures for <malware>`.

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Every alert answered (a rejected alert is answered with `enriched: false` and the reason) |
| `1` | Neo4j unreachable (one connection attempt, without the pipeline's retries), the selection query failed, or an enrichment query failed. A failed enrichment query leaves the processor's defaults (nothing found, confidence `0.0`) for every part it had not read yet, which would read as "the graph holds nothing more on this indicator" although those parts were never read: that response is printed with `enriched: false` and `query_metadata.error`, and its alert id is named on stderr |
| `2` | Usage or configuration error, an unreadable alert file, or an alert the processor raised on (for example a `threat.cve` that is not a string): that alert is left out of the output and named on stderr with the exception, the other alerts are answered |
| `3` | `--from-graph` selected no indicator |

Read the exit code, or `enriched` and `query_metadata.error`, before showing a response: the
`jq '.[0].enrichment'` recipe above prints the enrichment without them.

### Output shape

A JSON array with one response per alert, the `EnrichedAlert` of `src/alert_processor.py`:

```json
[
  {
    "alert_id": "demo-graph-1",
    "enriched": true,
    "edgeguard_version": "<CalVer from pyproject.toml>",
    "latency_ms": "<milliseconds the enrichment took>",
    "query_metadata": {
      "indicator_found": "<true | false>",
      "malware_found": "<true | false>",
      "actor_found": "<true | false>",
      "techniques_found": "<count>",
      "cves_found": "<count>",
      "assets_found": 0,
      "users_found": 0
    },
    "enrichment": {
      "indicator": "<canonical indicator value>",
      "indicator_type": "<graph type: ipv4, ipv6, domain, url, hash, ...>",
      "known_malware": [
        {"name": "<malware>", "family": "<family or null>", "malware_types": ["<type>"], "description": "<text or null>"}
      ],
      "threat_actors": [{"name": "<actor>", "aliases": ["<alias>"], "description": "<text or null>"}],
      "techniques": [{"mitre_id": "<T####>", "name": "<technique>", "description": "<text or null>"}],
      "cves": [{"cve_id": "<CVE id>", "cvss_score": "<score or null>", "severity": "<severity or null>"}],
      "assets": [],
      "users": [],
      "confidence": "<the indicator's confidence_score>",
      "first_seen": "<earliest first seen a source reports, else the first import>",
      "last_updated": "<latest last seen a source reports, else the last update>",
      "sectors_affected": ["<zone>"],
      "cross_zone_detected": "<true when more than one zone>",
      "recommendations": ["<generated from the fields above, e.g. Block IP <indicator> at perimeter firewall>"]
    },
    "original_alert": {"<the alert as given>": "..."}
  }
]
```

A failed enrichment query gives `enriched: false` with `query_metadata.error` and the defaults in
`enrichment`; a rejected alert is `enriched: false` with `query_metadata.error` and an empty
`enrichment`. `cves` takes each CVE's score and severity from one node: the `CVE` node's (a null
score with severity `UNKNOWN` when the CVE has no CVSS), or the `Vulnerability` node's when no
`CVE` node of that id states them.

---

## Workflow demonstration

End-to-end checks a presenter can run against a deployment, in pipeline order. The commands are
those of [README.md](../README.md), [GRAPH_EXPLORER.md](GRAPH_EXPLORER.md),
[TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) and [RESILMESH_QUICKSTART_STIX.md](RESILMESH_QUICKSTART_STIX.md),
checked against `src/query_api.py`, `src/graphql_api.py` and `src/edgeguard.py`. They assume the
REST API on `http://localhost:8000`, the GraphQL API on `http://localhost:4001` and the API key in
`EDGEGUARD_API_KEY` (every route except `/health` requires the `X-API-Key` header when the key is
set). Take the identifiers (`<indicator>`, `<actor>`, `<CVE id>`) from the alert enrichment demo's
output, so each check shows data the graph holds.

### 1. MISP events by source

```bash
edgeguard stats --misp          # or: python src/edgeguard.py stats --misp
```

Next to the graph's node counts, prints the number of EdgeGuard events and attributes in MISP and
a table of events and attributes per source, parsed from the event names
(`EdgeGuard-<source>-<date>`). The summary reads every page of MISP's `/events/index`
(`searchall=EdgeGuard`, 500 events a page, at most 200 pages; it warns when it stops at that cap,
and `--json` then carries `"truncated": true`). `--json` prints the same as JSON.

### 2. Graph Explorer

```bash
docker compose up api                                     # or: uvicorn src.query_api:app --host 127.0.0.1 --port 8000
python3 -m http.server 3000 --bind 127.0.0.1 --directory docs
```

Open **`http://localhost:3000/visualization.html`** (the host name `localhost`, an origin in the
default `EDGEGUARD_CORS_ORIGINS`), connect to `http://localhost:8000` with the API key, and switch
between the Malware (`attacks`), Actors, Indicators and CVEs views. When the monitoring stack's
Grafana holds port 3000, serve `docs/` on port 3001 and append `http://localhost:3001` to
`EDGEGUARD_CORS_ORIGINS` before restarting the API ([GRAPH_EXPLORER.md](GRAPH_EXPLORER.md) § Quick Start).

### 3. REST: one indicator

```bash
curl -X POST http://localhost:8000/search/indicator \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $EDGEGUARD_API_KEY" \
  -d '{"value": "<indicator>"}'
```

The body also takes `indicator_type` and `zone`. The value is canonicalized before the lookup (a
defanged or mixed-case paste is fine); `related` and `relationships` list the indicator's
neighbours and the relationship to each.

### 4. REST: actor summary

```bash
curl -H "X-API-Key: $EDGEGUARD_API_KEY" \
  "http://localhost:8000/actors/<actor>/summary"
```

The profile, attributed malware (up to 10), employed techniques (up to 15) and the campaigns the
actor runs (up to 5), each with its total count. The name is matched case-insensitively and
through aliases; URL-encode spaces (`Lazarus%20Group`).

### 5. GraphQL: vulnerabilities

```bash
curl -X POST http://localhost:4001/graphql \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $EDGEGUARD_API_KEY" \
  -d '{"query": "{ vulnerabilities(filter: { zone: \"healthcare\", minCvss: 9.0 }) { cveId description status severity cvssScore cvssVersion published tlp } }"}'
```

The `CVE` nodes EdgeGuard created or enriched, highest score first; the filter also takes
`status`, `limit` and `offset`.

### 6. STIX 2.1 export

```bash
export EDGEGUARD_API_BASE="http://127.0.0.1:8000"
curl -s -H "X-API-Key: $EDGEGUARD_API_KEY" "$EDGEGUARD_API_BASE/stix/types" | jq .
curl -s -H "X-API-Key: $EDGEGUARD_API_KEY" \
    -H "Accept: application/stix+json;version=2.1" \
    "$EDGEGUARD_API_BASE/stix/export/indicator/<indicator>" | jq .
```

`object_type` is `indicator`, `actor`, `technique` or `cve`; `depth` (1 or 2) and `limit` (1–500)
are query parameters. `scripts/resilmesh_stix_smoke.sh` runs every listed type
([RESILMESH_QUICKSTART_STIX.md](RESILMESH_QUICKSTART_STIX.md)).

### 7. Wazuh CDB export

```bash
curl -s -D - -o edgeguard_energy_indicators.cdb \
  -H "X-API-Key: $EDGEGUARD_API_KEY" \
  "http://localhost:8000/export/wazuh/cdb?list=indicators&zone=energy"
head edgeguard_energy_indicators.cdb
```

One `key:value` line per active entry (`<indicator>:type=<type> confidence=<score>`; with
`list=cves`, `<CVE id>:severity=<severity> cvss=<score>` and `kev=<date>` for KEV entries). The
headers `X-EdgeGuard-Entries`, `X-EdgeGuard-Skipped` and `X-EdgeGuard-Truncated` say how many
lines were written, how many keys were skipped (URL and IPv6 keys contain `:`) and whether the
50,000-entry cap cut the list. Further filters: `indicator_type`, `min_confidence`.
