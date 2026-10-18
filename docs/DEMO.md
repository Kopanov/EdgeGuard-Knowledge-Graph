# EdgeGuard Demo

Everything shown on this page is what the code returns from the graph it is pointed at. The
output samples below give the **shape** only; the values in angle brackets are placeholders, not
results.

---

## Alert enrichment demo

**Script:** [`demo/alert_enrichment_demo.py`](../demo/alert_enrichment_demo.py)

### What it shows

A ResilMesh alert carries an indicator (IP, domain, hash, URL). EdgeGuard enriches it from the
knowledge graph with `src/alert_processor.py`: the malware families the indicator indicates, the
threat actors those families are attributed to and the ATT&CK techniques the actors employ, its
confidence, first / last seen and zones, and recommendations generated from those fields. The demo
hands alerts to that code and prints the response as JSON.

**CVEs from the graph: named in the same report.** The enrichment also lists the CVEs the graph
links to the indicator, each with the `evidence` of its links. An indicator and a CVE named in the
same OTX report are linked as `(Indicator)-[:INDICATES]->(CVE)` (`match_type` `otx_pulse`, meaning
"named in the same OTX report as the indicator"). The indicator's own claim to exploit a CVE
(`EXPLOITS`, `cve_tag`) comes only from a CVE tag on its MISP record, and no feed gives one:
EdgeGuard's collectors write no such tag. On a graph they built, `cves` therefore lists the CVEs the
graph links to the indicator as named in the same OTX report: an alert built with `--from-graph`
shows CVEs when the graph links the selected indicator to such a CVE (`INDICATES`, `otx_pulse`), and
`cves: []` with `cves_found: 0` otherwise. An indicator of a pulse that lists CVEs can have no such
link: the sync builds it per MISP event and per pulse, for at most 2,000 indicators and 50 CVEs of
the pulse, and an indicator or CVE MISP already held from an earlier pulse is not linked to a later
one ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#relationship-types)).
A same-report CVE says that one report names the indicator and the CVE, not that the indicator
exploits it, and its recommendation says so (`Apply patch for <CVE id> (named in the same OTX report
as the indicator)`). To show such an alert, pick an indicator that has the link with this read-only
query and enrich it from an alert file (`--alerts`, below):

```cypher
MATCH (i:Indicator)-[r:INDICATES]->(:CVE)
WHERE i.active = true AND r.match_type = 'otx_pulse'
RETURN i.value AS value, i.indicator_type AS indicator_type, count(r) AS cves
ORDER BY cves DESC, value
LIMIT 5
```

- **Real enrichment, read-only.** The demo calls `AlertProcessor.enrich_alert_read_only`: the same
  validation, indicator canonicalization (refang, case-fold, type inference) and enrichment
  queries as `process_alert`, without its writes (`process_alert` first records the Alert node,
  the alert's Indicator and `INVOLVES`, and afterwards stores the enrichment on the Alert node).
  Apart from `Neo4jClient`'s connection check (`RETURN 1`, in a session of the default access
  mode), every statement is a `MATCH` / `RETURN` query sent in a read access session: the
  enrichment's queries and, with `--from-graph`, the selection query below.
- **No NATS.** The alert is passed to the processor directly. EdgeGuard subscribes to
  `resilmesh.alerts.zone.*` in code but has no deployed consumer, and does not publish the
  enriched response ([TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) § NATS Topics).
- **Graph patterns read** (each one written by the MISP → Neo4j sync or `build_relationships`):
  `(Indicator)-[:INDICATES]->(Malware)`, `(Malware)-[:ATTRIBUTED_TO]->(ThreatActor)`,
  `(ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique)`, `(Indicator)-[:EXPLOITS]->(CVE | Vulnerability)`,
  `(Indicator)-[:INDICATES]->(CVE)`, the indicator's `SOURCED_FROM` edges (first / last seen as the
  sources report them) and its `zone` list. Techniques are those of the attributed actors; the
  indicator's own `USES_TECHNIQUE` links and the malware's `IMPLEMENTS_TECHNIQUE` links are not part
  of the enrichment. The `EXPLOITS` pattern finds nothing on a graph the collectors built; the CVEs
  come from `INDICATES` (see "CVEs from the graph: named in the same report" above).

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
python demo/alert_enrichment_demo.py --from-graph 3 2>/dev/null

# The same, restricted to indicators whose zone list holds "energy"
python demo/alert_enrichment_demo.py --from-graph 3 --zone energy 2>/dev/null

# Enrich alerts from a file: one alert object or a list of them
python demo/alert_enrichment_demo.py --alerts alerts.json 2>/dev/null

# Only the enrichment of the first response (stdout carries JSON only)
python demo/alert_enrichment_demo.py --from-graph 1 2>/dev/null | jq '.[0].enrichment'
```

The demo imports the pipeline's configuration, which prints a warning on stderr at every start
while no trusted MISP organisation is configured (the MISP tag-impersonation notice of
`src/source_trust.py`); `2>/dev/null` keeps it off the screen. It also hides the error lines the
demo writes on stderr, so read the exit code before showing a response (below), or run the command
once without `2>/dev/null` when it fails.

`--from-graph N` selects N indicators with this read-only query (also printed by `--help`):

```cypher
MATCH (i:Indicator)
WHERE i.active = true
  AND ($zone IS NULL OR $zone IN coalesce(i.zone, []))
  AND EXISTS { MATCH (i)-[:INDICATES]->(:Malware) }
RETURN i.value AS value, i.indicator_type AS indicator_type, i.zone AS zone
ORDER BY coalesce(i.last_reported_at, i.first_imported_at) DESC, i.value
LIMIT $limit
```

Each alert built from a selected indicator holds only what the graph says about it: the
indicator's value and type, its first stored zone other than `global` (or the `--zone` given),
the time the alert was built, the alert id `demo-graph-<n>` and the source `edgeguard-demo`. It
names no malware, CVE or host, so everything in `known_malware`, `threat_actors`, `techniques` and
`cves` comes from the graph; `cves` holds the CVEs the graph links to the indicator as named in the
same OTX report, if any (see "CVEs from the graph: named in the same report" above).

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
      "cves": [
        {"cve_id": "<CVE id>", "cvss_score": "<score or null>", "severity": "<severity>",
         "evidence": [{"relationship": "INDICATES", "match_type": "otx_pulse",
                       "meaning": "named in the same OTX report as the indicator"}]}
      ],
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
`enrichment`. A CVE the alert names is listed as `{"cve_id": "<CVE id>", "source": "alert"}`. A CVE
the graph links to the indicator is listed as `{"cve_id", "cvss_score", "severity", "evidence"}`, with
the score and severity of one node: the `CVE` node's (a null score with severity `UNKNOWN` when the
CVE has no CVSS), or the `Vulnerability` node's when no `CVE` node of that id states them. `evidence`
names each link of the CVE once: `INDICATES` / `otx_pulse` ("named in the same OTX report as the
indicator") and, the indicator's own claim, `EXPLOITS` / `cve_tag` ("the indicator's own CVE tag"),
listed first when present.

---

## Workflow demonstration

End-to-end checks a presenter can run against a deployment, in pipeline order. The commands are
those of [README.md](../README.md), [GRAPH_EXPLORER.md](GRAPH_EXPLORER.md),
[TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) and [RESILMESH_QUICKSTART_STIX.md](RESILMESH_QUICKSTART_STIX.md),
checked against `src/query_api.py`, `src/graphql_api.py` and `src/edgeguard.py`. They assume the
REST API on `http://localhost:8000`, the GraphQL API on `http://localhost:4001` and the API key in
`EDGEGUARD_API_KEY` (every route except `/health` (and, when `EDGEGUARD_ENV` is non-production, `/docs`,
`/redoc` and `/openapi.json`) requires the `X-API-Key` header when the key is set). Take
`<indicator>` and `<actor>` from the alert enrichment demo's output (`enrichment.indicator` and a
name in `enrichment.threat_actors`), and `<CVE id>` from a `cveId` that step 5 (GraphQL
vulnerabilities) returns or from the alert output's `cves` (a CVE the graph links to the indicator as
named in the same OTX report), so each check shows data the graph holds.

### 1. MISP events by source

```bash
edgeguard stats --misp          # or: python src/edgeguard.py stats --misp
```

Next to the graph's node counts, prints the number of EdgeGuard events and attributes in MISP and
a table of events and attributes per source, parsed from the event names
(`EdgeGuard-<source>-<date>`). The summary reads every page of MISP's `/events/index`
(`searchall=EdgeGuard`, 500 events a page, at most 200 pages; it warns when it stops at that cap,
and `--json` then carries `"truncated": true`). `--json` prints the same as JSON. The closing
"Last sync" line reads the sync state file of the host it runs on
(`state/edgeguard_last_neo4j_sync.json`, which the Airflow sync writes); on any other host, or when
the file cannot be read or parsed, it is a warning, `Last sync: no readable sync state file on this
host`.

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

The profile, attributed malware (up to 10), the malware the actor uses (`malware_used`, up to 10;
a campaign rests on either link), employed techniques (up to 15) and the campaigns the actor runs
(up to 5), each with its total count. The name is matched case-insensitively and
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
IND=$(jq -rn --arg v '<indicator>' '$v | @uri')   # URL-encode: a URL indicator holds "/" and ":"
curl -s -H "X-API-Key: $EDGEGUARD_API_KEY" \
    -H "Accept: application/stix+json;version=2.1" \
    "$EDGEGUARD_API_BASE/stix/export/indicator/$IND" | jq .
curl -s -H "X-API-Key: $EDGEGUARD_API_KEY" \
    "$EDGEGUARD_API_BASE/stix/export/cve/<CVE id>" | jq '[.objects[].type] | group_by(.) | map({(.[0]): length}) | add'
```

`object_type` is `indicator`, `actor`, `technique` or `cve`; `depth` (1 or 2) and `limit` (1–500)
are query parameters. A CVE bundle holds the `vulnerability` and the indicators the graph links to
the CVE as named in the same OTX report, if any (`related-to`, `x_edgeguard_match_type` `otx_pulse`;
at `depth=1` too), at depth 2 also the sectors it affects and the threat actors and malware a curated
package says exploit it. A CVE without such a link has no indicator, and at `depth=1` its bundle holds
the `vulnerability` alone next to the producer `identity`, the `extension-definition` and the TLP
markings. An indicator bundle holds, at depth 2, the CVEs the graph links to the indicator as named in
the same OTX report, if any (`related-to`; see "CVEs from the graph: named in the same report" above
for when the graph has the link). `scripts/resilmesh_stix_smoke.sh` runs every listed type
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

---

_Last updated: 2026-10-18_

## History

- 2026-10-18 — The alert enrichment lists the CVEs named in the same OTX report as the indicator (`INDICATES`, `otx_pulse`), each with its `evidence`; the guide states when an alert shows them (the indicator has the link; per-event build and per-pulse caps) and how to pick such an indicator, and the STIX step names the indicators and CVEs of the bundles (those the graph links as named in the same OTX report, if any).
- 2026-10-18 — Step 1 says that `stats` warns when it reads no sync state file on the host (none there, or unreadable).
- 2026-10-18 — The alert enrichment shows no CVE from the graph (an indicator links to a CVE only through its own CVE tag, which the collectors do not write), so the output shape shows `cves: []` and the workflow takes `<CVE id>` from the GraphQL step instead of the alert output; the demo commands discard the configuration warning on stderr (`2>/dev/null`); the STIX example URL-encodes the indicator and adds a CVE bundle.

- 2026-10-17 — Restated as a guide to the current behaviour, with the change history moved here; the API key note lists the routes served without the key in a non-production `EDGEGUARD_ENV` (`/docs`, `/redoc`, `/openapi.json`).
- 2026-10-16 — The actor summary lists the malware the actor uses (`malware_used`); the `--from-graph` selection orders the indicators by their latest report (`coalesce(last_reported_at, first_imported_at)`) instead of the last database write.
- 2026-10-16 — Rewritten for `demo/alert_enrichment_demo.py`, which runs EdgeGuard's alert enrichment read-only against the configured Neo4j and prints the processor's own response; the earlier NATS mock, which printed random values as an enrichment without querying anything, was removed, and the section "Workflow demonstration" was added.
- 2026-10-16 — The alert enrichment reads CVEs as the graph links them, `(Indicator)-[:EXPLOITS]->` a `CVE` or `Vulnerability` node (it read `INDICATES` to a `Vulnerability`, which no code path writes); a failed enrichment query gives `enriched: false` and exit code 1, and an alert the processor raises on is named and gives exit code 2; the prerequisites set a Bolt URI the host can reach; the comparison with `process_alert` covers confidence and last update; `stats --misp` counts every page of MISP's event index.
