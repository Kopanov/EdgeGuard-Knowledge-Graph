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
  "object_types": [
    {"name": "indicator", "example": "1.2.3.4", "primary_relation": "indicates→malware"},
    {"name": "actor",     "example": "APT28",   "primary_relation": "malware attributed-to actor"},
    {"name": "technique", "example": "T1059",   "primary_relation": "actors uses technique"},
    {"name": "cve",       "example": "CVE-2021-44228", "primary_relation": "indicators indicate CVE"}
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
  bundle id is `uuid5(EDGEGUARD_STIX_NAMESPACE, sha256(sorted SDO ids))`
  — two calls for the same seed yield **identical bundle IDs**
  (and identical object IDs, because object IDs are also deterministic
  UUIDv5 over the node's natural key, sharing the same namespace UUID).
  This makes diffing + content-addressed caching safe across versions.
  The `EDGEGUARD_DETERMINISTIC_BUNDLE` env var freezes
  `x_edgeguard_source.generated_at` for fully reproducible output
- `objects: [...]` — SDOs + SROs for the seed and its neighborhood
- `x_edgeguard_source` — EdgeGuard-specific provenance (see below)

Each SDO built from a Neo4j node with zone tags carries
`x_edgeguard_zones: ["healthcare", "global", ...]` as a custom
property. Filter bundles by sector on the ResilMesh side without
re-querying the graph.

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

### Provenance — `x_edgeguard_source`

```json
{
  "producer": "EdgeGuard Knowledge Graph",
  "exporter": "stix_exporter",
  "generated_at": "2026-04-15T13:42:07Z",
  "git_sha": "d5dc41f",
  "spec_version": "2.1"
}
```

`git_sha` comes from the `EDGEGUARD_GIT_SHA` env var set on the API
pod at deploy time; it is `null` if unset.

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

## 6. One-shot smoke script

```bash
scripts/resilmesh_stix_smoke.sh               # depth=2, pretty
scripts/resilmesh_stix_smoke.sh --depth 1     # depth=1, minimal
scripts/resilmesh_stix_smoke.sh --no-pretty   # raw JSON on stdout
```

The script reads `/stix/types` first, then curls every listed object
type at its example identifier. It asserts HTTP 200, bundle shape,
and non-empty `x_edgeguard_source`. Exit code `0` on success.

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

Known validator quirks:

- `x_edgeguard_source` and `x_edgeguard_zones` are producer-specific
  custom properties (STIX 2.1 OASIS 3.7.2). The validator may flag
  them as `warning` unless run in permissive mode.
- Bundle-level custom properties are allowed; the validator's
  `--lax-prefix` flag silences the warning.

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

_Last updated: 2026-04-26 — PR-N33 docs audit: corrected bundle-id claim (was "random UUIDv4 per request", actually content-deterministic UUIDv5 over sorted SDO ids — `uuid5(EDGEGUARD_STIX_NAMESPACE, sha256(sorted_ids))`); documented `EDGEGUARD_DETERMINISTIC_BUNDLE` env knob for `generated_at` freezing. Prior: 2026-04-17._
