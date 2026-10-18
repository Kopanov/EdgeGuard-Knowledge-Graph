# EdgeGuard STIX 2.1 export — guide for threat-intelligence platforms and ResilMesh

The fastest path to pulling STIX 2.1 bundles out of EdgeGuard's
threat-intel graph. Intended for anyone who consumes STIX: a
threat-intelligence platform or SIEM integrating EdgeGuard as a source,
or a ResilMesh integrator running a first smoke test. The design
decisions behind the bundles are in § 8, the open points in § 9.

---

## 1. Prerequisites

- EdgeGuard Query API reachable (default `http://127.0.0.1:8000`; in
  production `https://edgeguard.org` or the ResilMesh-side hostname)
- A valid `X-API-Key` (ask the EdgeGuard team — this is the internal
  read key; per-partner credentials are an open point, § 9)
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
at `depth=2`), and a working example identifier per type.
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

# Threat actor (matched case-insensitively by name or alias)
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
`Content-Type: application/stix+json;version=2.1`. When the server sets
`EDGEGUARD_GIT_SHA`, the response header `X-EdgeGuard-Git-Sha` names the
EdgeGuard build that served it; the HTTP `Date` header gives the time.

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
  Every `created`, `modified` and `valid_from` comes from the graph,
  never from the clock (§ 8), so re-exporting the same graph state gives
  a **byte-identical** bundle. `modified` follows the node's or
  relationship's own times (§ 8). An indicator's `modified` moves when a
  source reports it with a later time or its aging state changes, which
  covers the usual changes of its `confidence` and `valid_until`; it
  does not carry `x_edgeguard_last_updated`, which every full sync
  moves. A few changes leave `modified` as it is: a report with an
  earlier time than the indicator's latest report (it can add
  provenance or raise `confidence`), a change of
  `EDGEGUARD_AGING_RETIRE_DAYS` (the projected `valid_until`), and a
  change of an endpoint's TLP (a relationship's `object_marking_refs`).
  A consumer that must see those compares objects rather than keying on
  (`id`, `modified`) alone
- `objects: [...]` — SDOs + SROs for the seed and its neighborhood,
  plus three kinds of supporting objects in every bundle:
  the EdgeGuard producer `identity` (referenced by `created_by_ref`
  on every SDO/SRO; carries the provenance, see below), one
  `extension-definition` declaring the `x_edgeguard_*` properties, and
  the STIX 2.1 TLP `marking-definition` objects referenced by
  `object_marking_refs`

A STIX 2.1 bundle carries no other top-level keys; the bundle parses
with `stix2.parse(bundle)` under the default strict mode. Timestamps
carry at most six fractional digits, the precision `stix2` accepts.

**TLP:** every SDO carries `object_marking_refs` with one of
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
`x_edgeguard_zones: ["healthcare", "energy"]` (a node in a sector never
also carries `global`; a node in no sector carries `["global"]`). Filter bundles by
sector on the ResilMesh side without re-querying the graph.

**Indicator patterns.** The `pattern` of an `indicator` follows the
node's `indicator_type` (`_build_pattern` in `src/stix_exporter.py`):

| `indicator_type` | Pattern |
|------------------|---------|
| `ipv4`, `ipv6` (and the MISP / ResilMesh names `ip`, `ip-src`, `ip-dst`, `ip-src\|port`, `ip-dst\|port`) | `[ipv4-addr:value = '…']` or `[ipv6-addr:value = '…']`, chosen by the address itself (the declared family applies only to a value that is not an address); a `\|port` suffix is dropped |
| `domain`, `hostname` | `[domain-name:value = '…']` |
| `url` | `[url:value = '…']` |
| `email` | `[email-addr:value = '…']` |
| `hash` (every file digest) | `[file:hashes.'<ALGO>' = '…']`, the algorithm (`MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `SSDEEP`, `TLSH`) from the digest; `UNKNOWN` when none fits |
| `x509-fingerprint-sha1` (SSL Blacklist TLS certificate fingerprints) | `[x509-certificate:hashes.'SHA-1' = '…']` |
| `filename` | `[file:name = '…']` |
| anything else | the type inferred from the value's shape, else `[x-edgeguard-observable:value = '…']` |

**MISP traceability:** every SDO sourced from a node with
MISP provenance also carries:

- `x_edgeguard_misp_event_ids: ["1234", "1235", ...]` — every MISP event
  that has observed this entity, taken from the node's `misp_event_ids[]`
  array. Lets ResilMesh resolve a STIX object back to the originating
  MISP events without round-tripping through Neo4j.
- `x_edgeguard_misp_attribute_ids: ["uuid-a", ...]` — every MISP attribute
  UUID that contributed to this entity, from `misp_attribute_ids[]`.
  Present on every SDO whose node a MISP attribute wrote: indicators,
  vulnerabilities, malware, intrusion-sets, attack-patterns and tools.

Both fields are omitted entirely when the source node has no MISP
references — bundles do not grow empty fields on every object.

**Relationship provenance:** every relationship (SRO) carries
the provenance of the graph relationship it comes from:

- `confidence` — 0–100, from the relationship's `confidence_score`;
- `external_references` — one per source record (`source_name` = the
  source, `external_id` = its record id), with a `url` where the record has
  a public page (OTX pulse, ThreatFox IOC, URLhaus entry, ATT&CK object, and
  a CISA ICS advisory on cisa.gov; on a sector link only the
  advisories whose sector note names that sector);
  at most 20 per SRO, the first records of the sorted list;
- `x_edgeguard_match_type` — the kind of evidence (`mitre_explicit`,
  `otx_pulse`, `malware_family`, `cve_tag`, `coreideas_curated`, …). On a
  `vulnerability related-to identity` (the graph's `AFFECTS` to a sector):
  `advisory_sector` (confidence 90) when CISA's ICS advisory states that the
  product is deployed in the sector, `zone_classification` (50) when EdgeGuard
  inferred the sector (values of `x_edgeguard_match_type`, not properties of
  their own). Read `advisory_sector` as "deployed in", never as targeting;
- `x_edgeguard_sources` — the sources that assert the link (`mitre_attck`,
  `alienvault_otx`, `threatfox`, `coreideas`, …);
- `x_edgeguard_source_refs` — their record ids, `"<source>:<id>"` (at most 200);
- `x_edgeguard_misp_event_ids` — the MISP events that carried the link;
- `x_edgeguard_cited_ids` — only on a link to a technique that a source cited by an id ATT&CK has
  since revoked: the ids the sources cited (an OTX pulse citing `T1562` gives a link to `T1685`
  with `["T1562"]`; definition version 1.3.0);
- `x_edgeguard_evidence_types` — only on a campaign link (`campaign attributed-to intrusion-set`,
  `indicator indicates campaign`): the relationship types of the graph
  links it rests on, `ATTRIBUTED_TO` and `USES_MALWARE` between the actor and a malware, and
  `INDICATES` on an indicator's link (`["ATTRIBUTED_TO", "USES_MALWARE"]`; definition version 1.5.0).

An `intrusion-set` the actor alias merge folded other actor nodes into carries
`x_edgeguard_merged_from`: their names (`["cl0p"]` on `clop`; version 1.3.0). The intrusion-set ids
of those names, derived from the names, do not appear in exports.

An SDO with a `description` (`vulnerability`, `malware`, `intrusion-set`, `tool`, `attack-pattern`)
carries `x_edgeguard_description_source`: the source whose text the description is,
the one a fixed ranking keeps among the sources that gave one (`vulnerability`: NVD, CISA KEV, CISA ICS,
then any other source; the others: MITRE ATT&CK, a curated source, then any other source), e.g.
`"nvd"`, `"cisa_kev"`, `"mitre_attck"` (version 1.6.0). It is absent on a `campaign`
(EdgeGuard's own text). The other sources' texts
stay in MISP, in the events `x_edgeguard_misp_event_ids` names.

An `indicator` carries its aging (version 1.7.0): every indicator ages by one rule, whoever
supplied it, from the latest report of any source. `x_edgeguard_last_reported_at` is that report's time
(the source's own last-report date capped at the MISP record time), `x_edgeguard_last_reported_source`
its source and `x_edgeguard_last_reported_ref` the MISP attribute uuid that holds it;
`x_edgeguard_source_confidence` is the highest confidence a source gave, `x_edgeguard_aging_basis` what
the age counts from (`source_date`, `misp_recorded`, `first_imported`), `x_edgeguard_aging_tier` the tier
reached (0 below 90 days, 1 from 90, 2 from 180, 3 from 365; the confidence is ×0.85 / ×0.70 / ×0.55 of
the source's), `x_edgeguard_active` whether it is active and `x_edgeguard_retired_by` who retired it
(`decay` from 730 days without a report). The indicator's `modified` is the latest of `created`, the latest
MISP record of a report and the time its aging state last changed, so it moves when a source reports the
indicator again or its confidence or lifecycle changes, not when a sync merely writes the node again.

An `indicator` also carries the standard fields platforms act on. `confidence` is the aged confidence on
the 0–100 scale (`confidence_score` × 100; the source's confidence when the node holds no aged value).
`valid_until` is when the indicator stops being valid: its retirement time when it is retired, otherwise
the time the aging rule will retire it if no source reports it again (the basis of its age plus
`EDGEGUARD_AGING_RETIRE_DAYS`, 730 days by default); a newer report moves it later. The projected value
uses the current `EDGEGUARD_AGING_RETIRE_DAYS`, so changing that setting changes the `valid_until` of an
indicator that is not yet retired without a later `modified`. An indicator written before the aging rule
existed carries no `valid_until`. `revoked` is never set: a retired indicator expires, it is not withdrawn.

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
  "x_edgeguard_exporter": "stix_exporter"
}
```

The identity is the same object in every bundle (`created`
`2026-10-11T00:00:00.000Z`, `modified` `2026-10-18T00:00:00.000Z`). It
carries no export time and no build, so it never changes between
exports: the build is the `X-EdgeGuard-Git-Sha` response header (from
the `EDGEGUARD_GIT_SHA` env var set on the API container at deploy time;
absent if unset).

### EdgeGuard extension definition

All `x_edgeguard_*` properties (source-truthful and import timestamps,
`x_edgeguard_zones`, MISP traceability, NVD / CISA KEV enrichment on
`vulnerability` (including NVD's record status `x_edgeguard_status`:
`["rejected"]` or `["active"]`, FIRST EPSS as `x_edgeguard_epss_score`,
`x_edgeguard_epss_percentile`, `x_edgeguard_epss_score_date` and
`x_edgeguard_epss_model_version`, and CISA's SSVC decision as
`x_edgeguard_ssvc_exploitation`, `x_edgeguard_ssvc_automatable`,
`x_edgeguard_ssvc_technical_impact`, `x_edgeguard_ssvc_version` and
`x_edgeguard_ssvc_timestamp`),
the relationship provenance on SROs, the identity
provenance above) are **top-level
extension properties** of the STIX 2.1 extension
`extension-definition--a9516685-381e-5b4f-9bd4-5cad8c3b1511`
(`extension_types: ["toplevel-property-extension"]`; the properties by
definition version: 1.1.0 the relationship provenance properties, 1.2.0 the record status, 1.3.0
`x_edgeguard_cited_ids` and `x_edgeguard_merged_from`, 1.4.0 EPSS and SSVC, 1.5.0
`x_edgeguard_evidence_types`, 1.6.0 `x_edgeguard_description_source`, 1.7.0 the aging
properties of an indicator). The definition
object is included in every bundle; its `extension_properties` lists
every property name EdgeGuard can emit, and two it does not emit:
`x_edgeguard_git_sha` and `x_edgeguard_generated_at` (declaring a property
that is not emitted is valid). Each object that carries at
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
| `cve`       | seed + its Indicators (both links below)       | exploiting ThreatActors and Malware, affected Sectors |

An indicator is linked to a CVE in two ways, both exported as `indicator related-to vulnerability`:
the CVEs named in the same OTX report as the indicator (`INDICATES`, `x_edgeguard_match_type`
`otx_pulse`, confidence 60, an `external_references` entry per report with its OTX link), and the CVE
the indicator's own MISP record tags (`EXPLOITS`, `cve_tag`), which EdgeGuard's collectors do not
write. On a graph they built, an `indicator` bundle therefore holds, at `depth=2`, the CVEs the graph
links to the indicator, and a `cve` bundle, at `depth=1` too, the indicators linked to the CVE. The
link is built per MISP event and per OTX report, for at most 2,000 indicators and 50 CVEs of a report,
and an item MISP already held from an earlier report gets no link to a later one (see
[KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md)); so an indicator of a report that names CVEs can have none.
A CVE without such a link has no indicator, and its `depth=1` bundle holds the `vulnerability` alone. An indicator with both links to one CVE has one SRO whose provenance merges
both (`x_edgeguard_match_type` names the stronger link's label). The ThreatActors and Malware that
exploit a CVE come from curated packages.

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
vulnerability, the graph's `EXPLOITS` and `INDICATES`; indicator /
vulnerability → sector identity). The
bundles also carry `intrusion-set uses malware / tool` (the
graph's `USES_MALWARE` / `USES_TOOL`), `malware exploits vulnerability`
and `intrusion-set targets vulnerability` (`EXPLOITS` from malware and
actors), `intrusion-set targets identity` (an actor's `TARGETS` a sector),
`indicator indicates campaign` (an indicator's `PART_OF_CAMPAIGN`), and
`subtechnique-of` (`SUBTECHNIQUE_OF`, the type MITRE ATT&CK's own STIX
uses). `relationship_mappings` also lists `malware targets identity` and
`campaign uses malware`; no export walks a malware's sector or campaign
links today, so no bundle carries them. Not exported as SROs: `IN_TACTIC`
(a kill-chain phase on the `attack-pattern`), `SOURCED_FROM`, `REFERS_TO`,
`HAS_CVSS_*` and `INVOLVES`.

## 6. One-shot smoke script

```bash
scripts/resilmesh_stix_smoke.sh               # depth=2, pretty
scripts/resilmesh_stix_smoke.sh --depth 1     # depth=1, minimal
scripts/resilmesh_stix_smoke.sh --no-pretty   # raw JSON on stdout
scripts/resilmesh_stix_smoke.sh --actor "Lazarus Group" --cve CVE-2017-0144
```

The script reads `/stix/types` first, then exports one object of every
listed type: the actor `APT28`, the technique `T1059`, the CVE
`CVE-2021-44228` (all three are in a baseline graph) and the newest
indicator `GET /indicators?limit=1` returns; `--actor`, `--technique`,
`--cve` and `--indicator` name others. A type without one of these
identifiers is exported at its `/stix/types` example. Each export must
answer HTTP 200 with a STIX bundle that holds at least one object besides
the producer identity, the extension definition and the TLP marking
definitions: a bundle holding only those means the identifier is not in
the graph, and the check fails. The script prints the producer identity
and the build (`X-EdgeGuard-Git-Sha`) and exits `0` when every check
passes, `1` otherwise. It runs on bash 3.2 (the macOS system bash) and
later, and needs curl and jq.

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
- The test suite checks every export path, on a real Neo4j as well, for
  the rules `stix2` does not check: re-exporting gives byte-identical
  JSON, and `modified` is never before `created`. It also asserts that
  `valid_until` is after `valid_from`. `stix2` enforces that rule when it
  builds the object, so the exporter omits a `valid_until` that is not
  later.

## 8. Design decisions

- **Groups are `intrusion-set`.** MITRE ATT&CK models named groups (APT28,
  FIN7, …) as `intrusion-set` and keeps `threat-actor` for individuals;
  no collector ingests individual actors. A consumer that expects
  `threat-actor` maps the type on its side.
- **Relationship types.** Each graph relationship becomes the
  `relationship_type` the STIX 2.1 relationship summary table defines
  for its (source, target) pair, reversed where the table models the
  pair the other way round (§ 5); a pair the table does not define is
  `related-to`. An indicator's technique link is `indicates`, the only
  relationship STIX 2.1 defines from an indicator to an attack-pattern.
  Two pairs follow MITRE ATT&CK's own STIX instead: `tool uses
  attack-pattern` and `subtechnique-of`. The table is `_SRO_BY_EDGE` in
  `src/stix_exporter.py`, served as `relationship_mappings` by
  `/stix/types`.
- **Deterministic identifiers.** Every id is
  `uuid5(5f2e1f9a-6a1b-5e0f-9b25-ed9ea2d574cb, "<type>:<natural key>".lower())`;
  the namespace equals the one of `n.uuid` (`src/node_identity.py`,
  checked when the module loads), so the UUID part of an SDO id is the
  node's `n.uuid`. Tool is the documented exception
  ([CLOUD_SYNC.md](CLOUD_SYNC.md)): its id derives from the name, while
  `n.uuid` keys on the ATT&CK id; consumers match a tool by its
  `mitre-attack` reference.

  | SDO type | Natural key |
  |----------|-------------|
  | `indicator` | `{indicator_type}\|{value}` |
  | `malware`, `intrusion-set`, `tool`, `campaign`, `identity` (sector) | `{name}` |
  | `attack-pattern` | `{mitre_id}` |
  | `vulnerability` | `{cve_id}` |
  | `relationship` | `{source_ref}\|{relationship_type}\|{target_ref}` |

- **External references.** A relationship cites EdgeGuard's own source
  records (`source_name` = the source id such as `mitre_attck` or
  `alienvault_otx`, `external_id` = the record id, § 4). An
  `attack-pattern` carries a `mitre-attack` reference (the ATT&CK id
  and its page), and so does a `tool` whose ATT&CK software id (S
  followed by four digits) is known; a `vulnerability` carries a `cve`
  reference (the CVE id and its NVD page).
- **One top-level property extension.** Every `x_edgeguard_*` property
  sits at the top level of its object and is declared by one
  `extension-definition` of type `toplevel-property-extension` (§ 4), so
  strict parsers accept the bundle and consumers read the properties
  without unwrapping an extension.
- **TLP 1.0 markings.** Objects carry the four STIX 2.1 TLP marking
  definitions (§ 4); `clear` is exported as TLP:WHITE and
  `amber+strict`, which has no STIX 2.1 marking, as TLP:RED, never
  loosened to TLP:AMBER.
- **Where the times, the confidence and the expiry come from.** Nothing
  is read from the clock:

  | Field | Source |
  |-------|--------|
  | SDO `created` | the node's `first_imported_at`, else its `created_at` (a campaign, or a sector created by the sync) |
  | SDO `modified` | the later of `created` and the node's `last_updated` |
  | `indicator` `modified` | the latest of `created`, `last_recorded_at` (the latest MISP record of a report) and `aging_since` (the latest change of its aging state) |
  | SRO `created` | the relationship's `created_at`, else its `imported_at` |
  | SRO `modified` | the later of `created` and the relationship's `updated_at` |
  | SRO behind several graph relationships (the edges to twin CVE / Vulnerability nodes; `ATTRIBUTED_TO` and `USES_MALWARE`) | the earliest `created` and the latest `modified` |
  | an object without any of these times | `2026-10-11T00:00:00.000Z` |
  | `indicator` `valid_from` | the earliest source claim of a first observation, else `first_imported_at`, else `created` (both marked `x_edgeguard_first_seen_inferred`) |
  | `indicator` `confidence` | `confidence_score` (the aged value) × 100, else `source_confidence` × 100 |
  | `indicator` `valid_until` | `retired_at`, else the basis of the age plus `EDGEGUARD_AGING_RETIRE_DAYS`; only on a node the aging rule evaluated (`aging_basis` or `retired_at`) and only when later than `valid_from`; a wrong aging setting omits it (logged) and the export stays available |
  | `malware` `is_family` | always `true`: a graph Malware node is a named family |
  | `malware_types`, `tool_types` | the node's values without the placeholder `malware` / `tool`; `unknown` when nothing else remains |

  [TIMESTAMPS.md](TIMESTAMPS.md) describes the graph's times.

## 9. Open points

- **TAXII 2.1.** A read-only TAXII 2.1 collection (discovery, one API
  root, an indicators collection, paging with `added_after`) would let
  platforms such as Microsoft Sentinel, Elastic and OpenCTI poll
  EdgeGuard by configuration alone. It is not built; the per-seed
  export above is the only STIX surface.
- **Per-partner credentials.** The export accepts the internal
  `X-API-Key` only; separate credentials per partner (HTTP Basic or
  Bearer for TAXII clients) are not built.
- **No signal when `limit` cuts a collection.** A collection that holds
  exactly `limit` objects may have been cut; the response does not say
  so.
- **ATT&CK ids on groups and malware.** Intrusion-sets and malware carry
  no `mitre-attack` reference, because the graph's ThreatActor and
  Malware nodes hold no ATT&CK group or software id (`G…`, `S…`); adding
  them is a change on the write side.
- **Bitcoin addresses.** STIX 2.1 has no Cyber-observable type for a
  bitcoin address, so such an indicator uses the custom pattern
  `[x-edgeguard-observable:value = '…']`: valid under the patterning
  grammar, but no consumer evaluates it.

For anything surprising, file an issue with `stix-exporter` in the title.

## 10. Who owns what

| Concern                                      | Owner     |
|-----------------------------------------------|-----------|
| Threat-intel graph (Indicator, Actor, Malware, Technique, Tool, Campaign) and the CVE + CVSS nodes EdgeGuard writes from NVD, CISA KEV and CISA ICS (shared labels: `edgeguard_managed` when EdgeGuard created them, `edgeguard_enriched` when a partner did) | EdgeGuard |
| Asset layer and scanner findings (Host, Device, IP, SoftwareVersion, Vulnerability) | ResilMesh |
| The STIX exporter itself                      | EdgeGuard |
| Downstream scoring / alerting on received bundles | ResilMesh |
| TAXII 2.1 and per-partner credentials (open points, § 9) | EdgeGuard |

See [RESILMESH_INTEGRATION_GUIDE.md](RESILMESH_INTEGRATION_GUIDE.md)
for the full node/relationship mapping across both sides.

---

_Last updated: 2026-10-19_

## History

- 2026-10-19 — The indicator–CVE paragraph states when the graph has the link (per MISP event and OTX report, within the per-report caps) instead of promising every CVE of an indicator's reports.
- 2026-10-18 — Indicator and CVE bundles carry the `related-to` links between an indicator and the CVEs named in the same OTX report (`INDICATES`, `otx_pulse`).
- 2026-10-18 — § 6: the smoke script runs on bash 3.2, exports identifiers a baseline graph holds (`APT28`, `T1059`, `CVE-2021-44228`, the newest indicator; flags name others) and fails a bundle without a graph object (it passed on the empty bundle of the `/stix/types` indicator example).
- 2026-10-18 — § 5 states that the collectors link no indicator to a CVE, so a `cve` bundle at `depth=1` holds the `vulnerability` alone.
- 2026-10-18 — Addressed to every STIX consumer; the design proposal (deleted, git history keeps it) folded into "Design decisions" (§ 8) and "Open points" (§ 9), and "Known gaps" and the prototype status removed. Every `created` / `modified` / `valid_from` comes from the graph, so re-exports are byte-identical (the response shape says which properties can change under the same `modified`): campaigns and sectors without `first_imported_at` take `created_at`, relationships their own times, `modified` is never before `created` (relationships and sectors had the export time, campaigns a `modified` before `created`); indicators carry `confidence` and `valid_until` and no longer `x_edgeguard_last_updated`; malware is a family and the placeholder types `malware` / `tool` are dropped; tools carry their `mitre-attack` reference; the producer identity no longer carries `x_edgeguard_generated_at` and `x_edgeguard_git_sha` (the build is the `X-EdgeGuard-Git-Sha` header; `EDGEGUARD_DETERMINISTIC_BUNDLE` removed).
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Rewritten as a guide to current behaviour and checked against the code: no bundle carries `malware targets identity` or `campaign uses malware`, so `x_edgeguard_evidence_types` appears on `campaign attributed-to intrusion-set` and `indicator indicates campaign` only; `x_edgeguard_misp_attribute_ids` is on every SDO a MISP attribute wrote; a node in a sector never also carries `global` in `x_edgeguard_zones`; § 9 gives EdgeGuard the CVE + CVSS nodes and ResilMesh the asset layer and scanner findings.
- 2026-10-16 — `advisory_sector` (confidence 90) on a vulnerability's sector link where CISA's ICS advisory states the sector, with the advisory's cisa.gov page in `external_references`.
- 2026-10-16 — Indicator aging (extension definition 1.7.0) and an indicator's `modified` from its reports and aging instead of the last database write; `x_edgeguard_description_source` (1.6.0); `x_edgeguard_evidence_types` on campaign links (1.5.0).
- 2026-10-15 — `/stix/types` names each export's relationships and lists `relationship_mappings`; timestamps cut to six fractional digits (the nine the driver printed made every export of a sync-written node fail with HTTP 500); EPSS and SSVC on `vulnerability` (1.4.0); `x_edgeguard_cited_ids` and `x_edgeguard_merged_from` (1.3.0); `x_edgeguard_status` (1.2.0).
- 2026-10-15 — IP patterns take `ipv4-addr` / `ipv6-addr` from the address (IPv6 indicators synced as `ipv4` were exported as `ipv4-addr`); certificate fingerprints export as `x509-certificate:hashes` (they were `file:hashes`); the new relationship mappings; `external_references` bounded at 20 and `x_edgeguard_source_refs` at 200.
- 2026-10-14 — Every relationship exported with its provenance (extension definition 1.1.0), curated-package claims included; `depth` table extended.
- 2026-10-12 — Export hardening: `?limit=` per collection, case-insensitive actor lookup, TLP marking definitions, provenance on the producer `identity` with an `extension-definition` (strict `stix2.parse` passes), STIX 2.1 relationship-table mapping and `industry-sector-ov` sectors.
- 2026-04-26 — Bundle id documented as content-deterministic UUIDv5 over the sorted object ids (it had been described as a random UUIDv4 per request); `EDGEGUARD_DETERMINISTIC_BUNDLE` documented (omits `x_edgeguard_generated_at` for reproducible output).
- 2026-04-17 — `x_edgeguard_misp_event_ids` and `x_edgeguard_misp_attribute_ids` come from the node's array properties only.
- 2026-04-16 — MISP traceability properties added.
- 2026-04-15 — First version, for the STIX 2.1 exporter prototype.
