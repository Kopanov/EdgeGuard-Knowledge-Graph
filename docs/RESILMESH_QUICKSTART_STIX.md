# ResilMesh ↔ EdgeGuard — STIX 2.1 Quickstart

The fastest path to pulling STIX 2.1 bundles out of EdgeGuard's
threat-intel graph. Intended for a ResilMesh integrator running their
first smoke test. Full design notes are in
[STIX21_EXPORTER_PROPOSAL.md](STIX21_EXPORTER_PROPOSAL.md).

**Status:** prototype. The four object types listed below work; the
gaps (TAXII, per-partner auth, bulk export, push) are tracked as
follow-ups in the proposal doc § 10.

---

## 1. Prerequisites

- EdgeGuard Query API reachable (default `http://127.0.0.1:8000`; in
  production `https://edgeguard.org` or the ResilMesh-side hostname)
- A valid `X-API-Key` (ask the EdgeGuard team — this is the internal
  read key; per-partner keys are a follow-up)
- `curl` + `jq` installed (the smoke script uses both)

```bash
export EDGEGUARD_API_BASE="http://127.0.0.1:8000"
export EDGEGUARD_API_KEY="<your-key>"
```

## 2. Discovery

```bash
curl -s -H "X-API-Key: $EDGEGUARD_API_KEY" \
    "$EDGEGUARD_API_BASE/stix/types" | jq .
```

Returns the list of supported `object_type` values, their primary
relation, what each export walks (`returns`, every graph relationship
at `depth=2`), and a working example identifier per type. Since 2026-10
`relationship_mappings` lists the STIX relationship each graph
relationship becomes (in graph direction: `graph_relationship`,
`graph_source`, `graph_target`; the SRO: `source`, `relationship_type`,
`target`, reversed where STIX 2.1 models the pair the other way round),
taken from the exporter's own table; a pair not listed is exported as
`related-to`. Hit this first — every other endpoint in the exporter is
discoverable from it.

Abbreviated response:

```json
{
  "media_type": "application/stix+json;version=2.1",
  "default_depth": 2,
  "supported_depths": [1, 2],
  "default_limit": 100,
  "max_limit": 500,
  "object_types": [
    {"name": "indicator", "example": "1.2.3.4", "primary_relation": "indicates→malware"},
    {"name": "actor",     "example": "APT28",   "primary_relation": "intrusion-set uses malware"},
    {"name": "technique", "example": "T1059",   "primary_relation": "actors uses technique"},
    {"name": "cve",       "example": "CVE-2021-44228", "primary_relation": "indicators related-to CVE"}
  ],
  "relationship_mappings": [
    {"graph_relationship": "ATTRIBUTED_TO", "graph_source": "malware", "graph_target": "intrusion-set",
     "relationship_type": "uses", "source": "intrusion-set", "target": "malware"},
    {"graph_relationship": "INDICATES", "graph_source": "indicator", "graph_target": "malware",
     "relationship_type": "indicates", "source": "indicator", "target": "malware"}
  ]
}
```

## 3. Fetch a bundle

```bash
# Indicator (depth=2 is the default, full 1-hop)
curl -s -H "X-API-Key: $EDGEGUARD_API_KEY" \
    -H "Accept: application/stix+json;version=2.1" \
    "$EDGEGUARD_API_BASE/stix/export/indicator/1.2.3.4" | jq .

# Threat actor
curl -s -H "X-API-Key: $EDGEGUARD_API_KEY" \
    "$EDGEGUARD_API_BASE/stix/export/actor/APT28" | jq .

# MITRE ATT&CK technique
curl -s -H "X-API-Key: $EDGEGUARD_API_KEY" \
    "$EDGEGUARD_API_BASE/stix/export/technique/T1059" | jq .

# CVE
curl -s -H "X-API-Key: $EDGEGUARD_API_KEY" \
    "$EDGEGUARD_API_BASE/stix/export/cve/CVE-2021-44228" | jq .
```

The response is always a STIX 2.1 `bundle` with
`Content-Type: application/stix+json;version=2.1`.

### URL-like indicators

URL indicators contain `/` — URL-encode them so the FastAPI path
converter sees a single segment:

```bash
curl -s -H "X-API-Key: $EDGEGUARD_API_KEY" \
    "$EDGEGUARD_API_BASE/stix/export/indicator/http%3A%2F%2Fevil.com%2Fpayload"
```

(The server declares the `{identifier:path}` converter, so unencoded
URLs work too, but encoding is safer across proxies.)

## 4. Response shape

Every bundle carries:

- `type: "bundle"` + a **content-deterministic UUIDv5** `id`. The
  bundle id is `uuid5(EDGEGUARD_STIX_NAMESPACE, sha256(sorted object ids))`
  — two calls for the same seed yield **identical bundle IDs**
  (and identical object IDs, because object IDs are also deterministic
  UUIDv5 over the node's natural key, sharing the same namespace UUID).
  This makes diffing + content-addressed caching safe across versions.
  The `EDGEGUARD_DETERMINISTIC_BUNDLE` env var omits
  `x_edgeguard_generated_at` on the producer identity for fully
  reproducible output
- `objects: [...]` — SDOs + SROs for the seed and its neighborhood,
  plus three kinds of supporting objects in every bundle:
  the EdgeGuard producer `identity` (referenced by `created_by_ref`
  on every SDO/SRO; carries the provenance, see below), one
  `extension-definition` declaring the `x_edgeguard_*` properties, and
  the STIX 2.1 TLP `marking-definition` objects referenced by
  `object_marking_refs`

A STIX 2.1 bundle carries no other top-level keys; the bundle parses
with `stix2.parse(bundle)` under the default strict mode.

**TLP (2026-10):** every SDO carries `object_marking_refs` with one of
the four STIX 2.1 TLP marking ids, derived from the node's `tlp`
property (`white`/`clear` → TLP:WHITE, `green`, `amber`, `red`;
`amber+strict` has no STIX 2.1 built-in and is exported as TLP:RED;
an unrecognised level is exported as TLP:AMBER; a node without `tlp`
receives the deployment default `EDGEGUARD_DEFAULT_TLP`). Relationship
objects carry the most restrictive marking of their two endpoints and of
the relationship's own `tlp`: a curated-package link carries the
package's level, so it is never exported less restricted than the
package, whatever its endpoints' markings.

Each SDO built from a Neo4j node with zone tags carries
`x_edgeguard_zones: ["healthcare", "global", ...]`. Filter bundles by
sector on the ResilMesh side without re-querying the graph.

**Indicator patterns.** The `pattern` of an `indicator` follows the
node's `indicator_type` (`_build_pattern` in `src/stix_exporter.py`):

| `indicator_type` | Pattern |
|------------------|---------|
| `ipv4`, `ipv6` (and the MISP / ResilMesh names `ip`, `ip-src`, `ip-dst`, `ip-src\|port`, `ip-dst\|port`) | `[ipv4-addr:value = '…']` or `[ipv6-addr:value = '…']`, chosen by the address itself (2026-10; the declared family applies only to a value that is not an address); a `\|port` suffix is dropped |
| `domain`, `hostname` | `[domain-name:value = '…']` |
| `url` | `[url:value = '…']` |
| `email` | `[email-addr:value = '…']` |
| `hash` (every file digest) | `[file:hashes.'<ALGO>' = '…']`, the algorithm (`MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `SSDEEP`, `TLSH`) from the digest; `UNKNOWN` when none fits |
| `x509-fingerprint-sha1` (SSL Blacklist TLS certificate fingerprints, 2026-10) | `[x509-certificate:hashes.'SHA-1' = '…']` |
| `filename` | `[file:name = '…']` |
| anything else | the type inferred from the value's shape, else `[x-edgeguard-observable:value = '…']` |

**MISP traceability (2026-04):** every SDO sourced from a node with
MISP provenance also carries:

- `x_edgeguard_misp_event_ids: ["1234", "1235", ...]` — every MISP event
  that has observed this entity, taken from the node's `misp_event_ids[]`
  array. Lets ResilMesh resolve a STIX object back to the originating
  MISP events without round-tripping through Neo4j.
- `x_edgeguard_misp_attribute_ids: ["uuid-a", ...]` — every MISP attribute
  UUID that contributed to this entity, from `misp_attribute_ids[]`.
  Present on Indicator-derived SDOs (the only nodes where MISP attribute
  UUIDs are populated).

Both fields are omitted entirely when the source node has no MISP
references — bundles do not grow empty fields on every object.

**Relationship provenance (2026-10):** every relationship (SRO) carries
the provenance of the graph relationship it comes from:

- `confidence` — 0–100, from the relationship's `confidence_score`;
- `external_references` — one per source record (`source_name` = the
  source, `external_id` = its record id), with a `url` where the record has
  a public page (OTX pulse, ThreatFox IOC, URLhaus entry, ATT&CK object);
  at most 20 per SRO, the first records of the sorted list;
- `x_edgeguard_match_type` — the kind of evidence (`mitre_explicit`,
  `otx_pulse`, `malware_family`, `cve_tag`, `coreideas_curated`, …);
- `x_edgeguard_sources` — the sources that assert the link (`mitre_attck`,
  `alienvault_otx`, `threatfox`, `coreideas`, …);
- `x_edgeguard_source_refs` — their record ids, `"<source>:<id>"` (at most 200);
- `x_edgeguard_misp_event_ids` — the MISP events that carried the link;
- `x_edgeguard_cited_ids` — only on a link to a technique that a source cited by an id ATT&CK has
  since revoked: the ids the sources cited (an OTX pulse citing `T1562` gives a link to `T1685`
  with `["T1562"]`; definition version 1.3.0).

An `intrusion-set` the actor alias merge folded other actor nodes into carries
`x_edgeguard_merged_from`: their names (`["cl0p"]` on `clop`; version 1.3.0). The intrusion-set ids
of those names, derived from the names, no longer appear in exports.

```json
{
  "type": "relationship",
  "relationship_type": "uses",
  "source_ref": "intrusion-set--…",
  "target_ref": "attack-pattern--…",
  "confidence": 95,
  "external_references": [
    {"source_name": "mitre_attck", "external_id": "G0016", "url": "https://attack.mitre.org/groups/G0016/"},
    {"source_name": "alienvault_otx", "external_id": "5f3c…", "url": "https://otx.alienvault.com/pulse/5f3c…"}
  ],
  "x_edgeguard_match_type": "mitre_explicit",
  "x_edgeguard_sources": ["alienvault_otx", "mitre_attck"],
  "x_edgeguard_source_refs": ["alienvault_otx:5f3c…", "mitre_attck:G0016"],
  "x_edgeguard_misp_event_ids": ["135", "140"]
}
```

### Provenance — the producer `identity`

STIX 2.1 permits only `type`, `id` and `objects` on a bundle, so the
provenance travels on the EdgeGuard producer identity (a fixed,
deterministic id; every other object's `created_by_ref` points to it):

```json
{
  "type": "identity",
  "spec_version": "2.1",
  "id": "identity--a7db38b6-f036-5ede-9307-443d46bd51c3",
  "name": "EdgeGuard Knowledge Graph",
  "identity_class": "system",
  "object_marking_refs": ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"],
  "extensions": {"extension-definition--a9516685-381e-5b4f-9bd4-5cad8c3b1511": {"extension_type": "toplevel-property-extension"}},
  "x_edgeguard_exporter": "stix_exporter",
  "x_edgeguard_git_sha": "d5dc41f",
  "x_edgeguard_generated_at": "2026-04-15T13:42:07Z"
}
```

`x_edgeguard_git_sha` comes from the `EDGEGUARD_GIT_SHA` env var set on
the API pod at deploy time and is omitted if unset.

### EdgeGuard extension definition

All `x_edgeguard_*` properties (source-truthful and import timestamps,
`x_edgeguard_zones`, MISP traceability, NVD / CISA KEV enrichment on
`vulnerability` (since 2026-10-15, definition version 1.2.0, also NVD's
record status `x_edgeguard_status`: `["rejected"]` or `["active"]`; since
definition version 1.4.0, FIRST EPSS as `x_edgeguard_epss_score`,
`x_edgeguard_epss_percentile`, `x_edgeguard_epss_score_date` and
`x_edgeguard_epss_model_version`, and CISA's SSVC decision as
`x_edgeguard_ssvc_exploitation`, `x_edgeguard_ssvc_automatable`,
`x_edgeguard_ssvc_technical_impact`, `x_edgeguard_ssvc_version` and
`x_edgeguard_ssvc_timestamp`),
the relationship provenance on SROs, the identity
provenance above) are **top-level
extension properties** of the STIX 2.1 extension
`extension-definition--a9516685-381e-5b4f-9bd4-5cad8c3b1511`
(`extension_types: ["toplevel-property-extension"]`; version 1.1.0 added
the relationship provenance properties, version 1.2.0 the record status, version 1.3.0
`x_edgeguard_cited_ids` and `x_edgeguard_merged_from`, version 1.4.0 EPSS and SSVC). The definition
object is included in every bundle; its `extension_properties` lists
every property name EdgeGuard can emit. Each object that carries at
least one such property declares the extension in its `extensions`
map, as in the identity above. Objects without `x_edgeguard_*`
properties carry no `extensions` map.

## 5. The `depth` knob

```
GET /stix/export/{object_type}/{identifier}?depth=1   # minimal
GET /stix/export/{object_type}/{identifier}?depth=2   # full (default)
```

`depth=1` returns only the seed plus its **primary** relation type
(listed in `/stix/types`). Use it for:

- Integration smoke tests that want a minimal bundle
- UI previews that only need the first hop
- Quick sanity checks against a seeded graph

`depth=2` is the full 1-hop neighborhood and is the default. Pick this
for enrichment and analyst UIs.

| Object type | depth=1 returns                                | depth=2 adds                              |
|-------------|------------------------------------------------|-------------------------------------------|
| `indicator` | seed + `INDICATES→Malware`                     | CVE, technique, sector, campaign edges    |
| `actor`     | seed + attributed Malware                      | actor techniques, mal→tech chain, campaigns, `USES_MALWARE` / `USES_TOOL` software, exploited CVEs, targeted sectors |
| `technique` | seed + ThreatActors that employ it             | Malware, Tools, Indicators, parent and sub-techniques |
| `cve`       | seed + exploiting Indicators                   | exploiting ThreatActors and Malware, affected Sectors |

Today `depth` is a Python-side filter — the Cypher always fetches the
full neighborhood and the exporter drops the non-primary groups when
`depth<2`. Bundle size shrinks; query time does not. A future
optimization pushes the filter into Cypher.

### The `limit` knob

```
GET /stix/export/{object_type}/{identifier}?limit=100   # default
GET /stix/export/{object_type}/{identifier}?limit=500   # maximum
```

`limit` bounds **each related-node collection** of the bundle (for a
technique: actors, malware, tools and indicators separately) inside
the Cypher, so a highly connected seed such as `T1059` returns at most
`limit` nodes per collection. Every collection is ordered by its
natural key before the bound is applied, so truncation is
deterministic. Values outside `[1, 500]` are rejected with `422`; the
bounds are advertised by `/stix/types` (`default_limit`, `max_limit`).

Relationship types follow the STIX 2.1 relationship summary table for
each (source, target) pair: `indicator indicates malware /
attack-pattern`, `intrusion-set uses malware` (the graph's
`ATTRIBUTED_TO`), `intrusion-set / malware / tool uses attack-pattern`,
`campaign attributed-to intrusion-set` (the graph's `RUNS`), and
`related-to` for pairs the table does not define (indicator →
vulnerability, indicator / vulnerability → sector identity). Since
2026-10 the bundles also carry `intrusion-set uses malware / tool` (the
graph's `USES_MALWARE` / `USES_TOOL`), `malware exploits vulnerability`
and `intrusion-set targets vulnerability` (`EXPLOITS` from malware and
actors), `intrusion-set / malware targets identity` (`TARGETS` a sector),
`campaign uses malware` and `indicator indicates campaign`
(`PART_OF_CAMPAIGN`), and `subtechnique-of` (`SUBTECHNIQUE_OF`, the type
MITRE ATT&CK's own STIX uses). Not exported as SROs: `IN_TACTIC` (a
kill-chain phase on the `attack-pattern`), `SOURCED_FROM`, `REFERS_TO`,
`HAS_CVSS_*` and `INVOLVES`.

## 6. One-shot smoke script

```bash
scripts/resilmesh_stix_smoke.sh               # depth=2, pretty
scripts/resilmesh_stix_smoke.sh --depth 1     # depth=1, minimal
scripts/resilmesh_stix_smoke.sh --no-pretty   # raw JSON on stdout
```

The script reads `/stix/types` first, then curls every listed object
type at its example identifier. It asserts HTTP 200 and bundle shape,
and prints the producer identity's provenance. Exit code `0` on success.

## 7. Validation

EdgeGuard does not run the STIX 2.1 validator on the response. To
validate on the ResilMesh side:

```bash
pip install stix2-validator
curl -s -H "X-API-Key: $EDGEGUARD_API_KEY" \
    "$EDGEGUARD_API_BASE/stix/export/indicator/1.2.3.4" \
    > /tmp/bundle.json
stix2_validator /tmp/bundle.json
```

Notes:

- The `x_edgeguard_*` properties are declared by the EdgeGuard
  `extension-definition` (see §4), so `stix2.parse(bundle)` accepts the
  bundle in its default strict mode (`allow_custom=False`); no bundle-level
  custom properties are emitted.
- The TLP markings are the four STIX 2.1 marking definitions with their
  fixed identifiers; `stix2` rejects any deviation from them.

## 8. Known gaps (proposal § 10)

These are **not** in the prototype. Each is a follow-up PR:

- No TAXII 2.1 collection/manifest endpoints
- No bulk / full-graph export
- No push / webhook subscriptions (delta bundles over NATS)
- No per-partner API keys / audit log
- No bundle signing (JWS)
- Indicator pattern coverage is limited to the common MISP types

Raise anything surprising here against
[#27](https://github.com/Kopanov/EdgeGuard-Knowledge-Graph/pull/27) or
file an issue with `stix-exporter` in the title.

## 9. Who owns what

| Concern                                      | Owner     |
|-----------------------------------------------|-----------|
| Threat-intel graph (Indicator, Actor, Malware, Technique, Tool, Campaign) | EdgeGuard |
| Asset / vulnerability layer (Host, Device, CVE, CVSS) | ResilMesh |
| The STIX exporter itself                      | EdgeGuard |
| Downstream scoring / alerting on received bundles | ResilMesh |
| Bundle signing, TAXII, per-partner auth (future) | EdgeGuard |

See [RESILMESH_INTEGRATION_GUIDE.md](RESILMESH_INTEGRATION_GUIDE.md)
for the full node/relationship mapping across both sides.

---

_Last updated: 2026-10-15 — `/stix/types`: each `returns` names the 2026-10 relationships, and `relationship_mappings` lists the graph relationship → STIX relationship table; STIX timestamps of nodes the sync wrote with `datetime()` carry at most six fractional digits (the nine the driver printed made every such export fail with HTTP 500). Same day: FIRST EPSS and CISA's SSVC decision points on `vulnerability` (extension definition 1.4.0). Same day: explainability: `x_edgeguard_cited_ids` on SROs and `x_edgeguard_merged_from` on intrusion-sets (extension definition 1.3.0). Same day: `x_edgeguard_status` on `vulnerability` (NVD's record status; extension definition 1.2.0); § 4 indicator pattern table: IP patterns take `ipv4-addr` / `ipv6-addr` from the address (IPv6 indicators synced as `ipv4` were exported as `ipv4-addr`); SSL Blacklist certificate fingerprints export as `[x509-certificate:hashes.'SHA-1' = …]` (were `file:hashes`); relationship-type paragraph lists the 2026-10 mappings (`USES_MALWARE` / `USES_TOOL`, `EXPLOITS` from actors and malware, actor / malware `TARGETS`, `PART_OF_CAMPAIGN`, `subtechnique-of`) and the relationships not exported as SROs; bounds on `external_references` (20) and `x_edgeguard_source_refs` (200); extension definition versions (1.1.0: relationship provenance; 1.2.0: `x_edgeguard_status`). Prior: 2026-10-14 — every relationship exported with its provenance (`confidence`, `external_references`, `x_edgeguard_match_type`, `x_edgeguard_sources`, `x_edgeguard_source_refs`, `x_edgeguard_misp_event_ids`), curated-package claims included; `depth` table extended. Prior: 2026-10-12 — export hardening: `?limit=` per-collection bound (default 100, maximum 500), case-insensitive actor lookup, TLP `marking-definition` objects and `object_marking_refs`, provenance moved from the bundle to the producer `identity` with the `x_edgeguard_*` properties declared by an `extension-definition` (strict `stix2.parse` passes), STIX 2.1 relationship-table mapping and `industry-sector-ov` sectors. Prior: 2026-04-26 — PR-N33 docs audit: corrected bundle-id claim (was "random UUIDv4 per request", actually content-deterministic UUIDv5 over sorted SDO ids — `uuid5(EDGEGUARD_STIX_NAMESPACE, sha256(sorted_ids))`); documented `EDGEGUARD_DETERMINISTIC_BUNDLE` env knob for `generated_at` freezing. Prior: 2026-04-17._
