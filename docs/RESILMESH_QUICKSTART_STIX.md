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
relation, and a working example identifier per type. Hit this first —
every other endpoint in the exporter is discoverable from it.

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
objects inherit the most restrictive marking of their two endpoints.

Each SDO built from a Neo4j node with zone tags carries
`x_edgeguard_zones: ["healthcare", "global", ...]`. Filter bundles by
sector on the ResilMesh side without re-querying the graph.

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
`vulnerability`, the identity provenance above) are **top-level
extension properties** of the STIX 2.1 extension
`extension-definition--a9516685-381e-5b4f-9bd4-5cad8c3b1511`
(`extension_types: ["toplevel-property-extension"]`). The definition
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
| `indicator` | seed + `INDICATES→Malware`                     | CVE, technique, sector edges              |
| `actor`     | seed + attributed Malware                      | actor techniques, mal→tech chain, campaigns |
| `technique` | seed + ThreatActors that employ it             | Malware, Tools, Indicators                |
| `cve`       | seed + exploiting Indicators                   | affected Sectors                          |

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
vulnerability, indicator / vulnerability → sector identity).

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

_Last updated: 2026-10-12 — export hardening: `?limit=` per-collection bound (default 100, maximum 500), case-insensitive actor lookup, TLP `marking-definition` objects and `object_marking_refs`, provenance moved from the bundle to the producer `identity` with the `x_edgeguard_*` properties declared by an `extension-definition` (strict `stix2.parse` passes), STIX 2.1 relationship-table mapping and `industry-sector-ov` sectors. Prior: 2026-04-26 — PR-N33 docs audit: corrected bundle-id claim (was "random UUIDv4 per request", actually content-deterministic UUIDv5 over sorted SDO ids — `uuid5(EDGEGUARD_STIX_NAMESPACE, sha256(sorted_ids))`); documented `EDGEGUARD_DETERMINISTIC_BUNDLE` env knob for `generated_at` freezing. Prior: 2026-04-17._
