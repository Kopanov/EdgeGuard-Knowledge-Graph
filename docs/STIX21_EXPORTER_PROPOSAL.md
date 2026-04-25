# Proposal: STIX 2.1 graph exporter for ResilMesh integration

Status: DRAFT — prototype implementation in `src/stix_exporter.py` and
`GET /stix/export/{object_type}/{identifier}` in `src/query_api.py`.

History: the specialised `EMPLOYS_TECHNIQUE` / `IMPLEMENTS_TECHNIQUE`
/ `USES_TECHNIQUE` rel types this proposal exports were introduced in
the 2026-04 USES specialisation work and have shipped on `main`. No
external dependency remains.

## 1. Problem

EdgeGuard and ResilMesh share a Neo4j instance. ResilMesh owns the
asset/vulnerability layer (Host, Device, IP, Mission, Component,
Vulnerability, CVE, CVSSv*). EdgeGuard owns the threat-intel layer
(Indicator, Malware, ThreatActor, Technique, Tool, Campaign). The
layers meet at `CVE` and the bridging edges `REFERS_TO` / `HAS_CVSS_v*`.

ResilMesh partners want to pull our threat-intel as **STIX 2.1**
programmatically, so their analysts can enrich an asset with "what do
we know about this indicator / actor / technique / CVE?" Today,
EdgeGuard only converts MISP → STIX on the *input* side
(`run_misp_to_neo4j.py::convert_to_stix21`). There is no graph → STIX
exporter. This proposal fills that gap.

Out of scope (see §10):

- Full-graph bulk export
- TAXII 2.1 collection service
- Push updates (webhooks / NATS-to-STIX relay)
- Authenticated multi-tenancy

## 2. Shape of the API

Prototype endpoint:

```
GET /stix/export/{object_type}/{identifier}
Accept: application/stix+json;version=2.1
```

| object_type | identifier         | Returns                                           |
|-------------|--------------------|---------------------------------------------------|
| `indicator` | raw value          | Indicator + 1-hop (Malware, CVE, Technique, Sector) |
| `actor`     | name or alias      | Actor + Malware + Techniques + Campaigns (depth 2) |
| `technique` | MITRE ATT&CK ID    | Technique + Actors/Malware/Tools/Indicators using it |
| `cve`       | CVE ID             | CVE + Indicators that exploit it + Sectors         |

Response body is a STIX 2.1 `bundle` SDO, JSON-encoded. The media type
is `application/stix+json;version=2.1` (OASIS section 3.1). Bundle ID
is **content-deterministic UUIDv5** —
`uuid5(EDGEGUARD_STIX_NAMESPACE, sha256(sorted SDO ids))` — so two
calls for the same seed yield identical bundle IDs (PR #33 work; see
§6). Every object inside the bundle has a **deterministic** UUIDv5
ID over its natural key, sharing the same namespace UUID.

Example:

```bash
curl -H 'X-API-Key: ...' \
  https://edgeguard/stix/export/indicator/1.2.3.4
```

## 3. Architecture

```
 ┌────────────────┐       ┌───────────────────┐       ┌─────────────────┐
 │  ResilMesh     │──────▶│  /stix/export/*   │──────▶│  StixExporter   │
 │  (enrichment)  │ HTTPS │  query_api.py     │  call │  stix_exporter  │
 └────────────────┘       └───────────────────┘       └────────┬────────┘
                                                               │ Cypher
                                                               ▼
                                                       ┌───────────────┐
                                                       │    Neo4j      │
                                                       │ (shared graph)│
                                                       └───────────────┘
```

- `StixExporter` is a thin class that wraps a `Neo4jClient` (only needs
  `.driver`). Four public methods: `export_indicator`,
  `export_threat_actor`, `export_technique`, `export_cve`.
- Each method runs a single Cypher query that fetches the seed node and
  its neighbourhood in one round-trip, then walks the rows to build SDOs
  and SROs.
- SDO/SRO construction goes through the `stix2` SDK (pinned to `~=3.0`
  in `pyproject.toml`) so the library enforces schema and timestamps.
  Final serialisation is `json.loads(obj.serialize())` → plain dict.
- Pattern strings for `indicator` SDOs reuse the existing helper
  `MISPToNeo4jSync._value_to_stix_pattern` (lazy import, no
  duplication). Zone metadata helpers (`apply_edgeguard_zone_metadata_to_stix_dict`)
  are available for future use but not wired in for the prototype (see
  §10).

## 4. Node → SDO mapping

| Graph node    | STIX 2.1 SDO                                 | Notes                                                    |
|---------------|----------------------------------------------|----------------------------------------------------------|
| `Indicator`   | `indicator`                                  | Pattern built from `indicator_type` + `value`            |
| `Malware`     | `malware`                                    | `is_family=true` if `malware_types` contains "family"    |
| `ThreatActor` | `intrusion-set`                              | Default — MITRE convention for actor groups              |
| `Technique`   | `attack-pattern` + `kill_chain_phases` + `external_references[mitre-attack]` | Tactics become phases, not SDOs |
| `Tactic`      | *(not emitted)*                              | Represented only as `kill_chain_phases` on attack-pattern |
| `Tool`        | `tool`                                       |                                                          |
| `Campaign`    | `campaign`                                   |                                                          |
| `CVE`         | `vulnerability` + `external_references[cve]` |                                                          |
| `Vulnerability` | `vulnerability`                            | Deduplicated with CVE by `cve_id`                        |
| `Sector`      | `identity` with `identity_class:"class"`     | `sectors:[<name>]`                                       |

Decision: use `intrusion-set` rather than `threat-actor` by default.
MITRE ATT&CK models named groups (APT28, FIN7, ...) as `intrusion-set`
and reserves `threat-actor` for individuals. None of our current
collectors ingest individual actors. A follow-up can introspect a
boolean property on the node if that changes.

## 5. Relationship mapping

| Graph edge                                         | STIX 2.1 SRO                                                           | Rationale                                                                                                            |
|----------------------------------------------------|------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| `(ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique)` | `relationship(uses)` src=intrusion-set tgt=attack-pattern              | Matches STIX 2.1 `intrusion-set → attack-pattern` vocab entry.                                                        |
| `(Malware)-[:IMPLEMENTS_TECHNIQUE]->(Technique)`  | `relationship(uses)` src=malware tgt=attack-pattern                    | STIX 2.1 `malware → attack-pattern` vocab.                                                                            |
| `(Tool)-[:IMPLEMENTS_TECHNIQUE]->(Technique)`     | `relationship(uses)` src=tool tgt=attack-pattern                       | STIX 2.1 `tool → attack-pattern` vocab.                                                                               |
| `(Indicator)-[:USES_TECHNIQUE]->(Technique)`      | `relationship(indicates)` src=indicator tgt=attack-pattern             | STIX 2.1 only defines `indicator → attack-pattern = indicates`; there is no `uses` vocab entry with indicator src.    |
| `(Indicator)-[:INDICATES]->(Malware)`             | `relationship(indicates)`                                              | Direct vocabulary match.                                                                                              |
| `(Indicator)-[:EXPLOITS]->(CVE\|Vulnerability)`   | `relationship(indicates)`                                              | STIX has no `exploits` predicate. `indicates` is the closest vocabulary term — see §7.                                |
| `(Malware)-[:ATTRIBUTED_TO]->(ThreatActor)`       | `relationship(attributed-to)` src=malware tgt=intrusion-set            |                                                                                                                      |
| `(Campaign)-[:ATTRIBUTED_TO]->(ThreatActor)`      | `relationship(attributed-to)` src=campaign tgt=intrusion-set           |                                                                                                                      |
| `(Technique)-[:IN_TACTIC]->(Tactic)`              | *(no SRO)* — emitted as `kill_chain_phases` property on attack-pattern | STIX 2.1 ATT&CK convention.                                                                                           |
| `(Indicator)-[:TARGETS]->(Sector)`                | `relationship(targets)` src=indicator tgt=identity                     |                                                                                                                      |
| `(Vulnerability\|CVE)-[:AFFECTS]->(Sector)`       | `relationship(affects)` src=vulnerability tgt=identity                 | TARGETS is reserved for Indicator → Sector; Vuln/CVE → Sector is AFFECTS (PR #33 round 11).                            |

**Edge type semantics.** Pre-release fresh start emits the post-PR-#24
specialised types directly: `EMPLOYS_TECHNIQUE` (attribution: ThreatActor
/ Campaign → Technique), `IMPLEMENTS_TECHNIQUE` (capability: Malware /
Tool → Technique), `USES_TECHNIQUE` (observation: Indicator → Technique).
All three collapse back to STIX 2.1 `relationship_type: "uses"` on
export.

References:

- STIX 2.1 Relationship vocabulary: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p5ra8a8xrap4
- `uses` definition: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_i9uyt2tokbtz
- `indicates` definition: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_9mjnj16e1t6p
- ATT&CK kill-chain-phases convention: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_i4tjv75ce50h

## 6. Deterministic IDs

Every SDO/SRO gets a `type--<UUIDv5>` ID, computed as:

```
uuid.uuid5(EDGEGUARD_STIX_NAMESPACE, f"{type}:{natural_key}".lower())
```

where `EDGEGUARD_STIX_NAMESPACE` is a fixed UUIDv4 constant hard-coded
in `stix_exporter.py`. Natural keys per type:

| SDO type            | Natural key                  |
|---------------------|------------------------------|
| `indicator`         | `{indicator_type}|{value}`   |
| `malware`           | `{name}`                     |
| `intrusion-set`     | `{name}`                     |
| `attack-pattern`    | `{mitre_id}`                 |
| `tool`              | `{name}`                     |
| `campaign`          | `{name}`                     |
| `vulnerability`     | `{cve_id}`                   |
| `identity` (sector) | `sector|{name}`              |
| `relationship`      | `{source_ref}|{rel}|{target_ref}` |

Consequences:

- Re-exporting the same graph state produces byte-identical object IDs
  → ResilMesh can diff bundles and cache.
- Two different EdgeGuard environments (dev vs prod) emit the **same**
  IDs for the same entities. **This is now a SHIPPED behavior with a
  runtime parity check** at module import time:
  `EDGEGUARD_STIX_NAMESPACE` (in `src/stix_exporter.py`) and
  `EDGEGUARD_NODE_UUID_NAMESPACE` (in `src/node_identity.py`) MUST
  equal — a `RuntimeError` is raised on import drift. This guarantees
  the UUID portion of any STIX SDO id matches the corresponding
  Neo4j `n.uuid` for the same entity. See `docs/CLOUD_SYNC.md` for
  the cross-environment sync contract this enables.
- The bundle envelope ID is **content-deterministic UUIDv5** —
  `uuid5(EDGEGUARD_STIX_NAMESPACE, sha256(sorted SDO ids))` — so
  bundles are reproducible up to the `x_edgeguard_source.generated_at`
  timestamp (frozen via `EDGEGUARD_DETERMINISTIC_BUNDLE` for fully
  byte-identical output). This was promoted from "random UUIDv4 per
  request" in earlier drafts.

## 7. Open semantic questions (confirm with ResilMesh before merge)

1. **`EXPLOITS` → `indicates` vs `related-to`.** We picked `indicates`
   because it is a defined vocab term for `indicator → vulnerability`
   and it preserves the "this is a sign of" semantics. The alternative
   is the generic `related-to`, which is schema-valid but carries less
   meaning. ResilMesh should confirm whichever matches their downstream
   scoring logic.
2. **`Indicator → Technique` as `indicates` (not `uses`).** STIX 2.1
   does not define `uses` with `indicator` source_ref. Filing this as
   `indicates` is the only vocabulary-correct option.
3. **`intrusion-set` vs `threat-actor`.** Default to `intrusion-set`.
   Partners that expect `threat-actor` will need to map the type on
   their side.
4. ~~**Zone/sector metadata.**~~ **Resolved — we emit them.** Every
   SDO built by `_node_to_sdo` now carries an `x_edgeguard_zones`
   custom property populated from the source Neo4j node's `zone` list.
   Objects with no zones omit the key entirely to keep bundle size
   flat. See `_attach_zones` in `src/stix_exporter.py`. ResilMesh can
   filter bundles by sector without traversing the graph.

   **Update 2026-04:** the same pattern was extended to MISP traceability.
   Every SDO additionally carries `x_edgeguard_misp_event_ids` and
   `x_edgeguard_misp_attribute_ids` from the node's `misp_event_ids[]` /
   `misp_attribute_ids[]` arrays (deduped + stringified; omitted when
   empty). PR #33 round 10 dropped the legacy scalar fields — array-only
   now. ResilMesh consumers can resolve a bundle object back to every
   originating MISP event / attribute without round-tripping through
   Neo4j. See
   `_attach_misp_provenance` in `src/stix_exporter.py`.
5. **CVSS bridging.** ResilMesh stores CVSSv* as separate nodes linked
   to CVE via `HAS_CVSS_v*`. STIX has no first-class CVSS SDO. For now
   we flatten nothing — CVSS stays on the ResilMesh side. Confirm this
   matches their enrichment path.

## 8. Pagination

The four prototype endpoints all return **bounded** neighbourhoods
(indicator 1-hop, actor depth 2 with capped fan-out via DISTINCT, etc.)
so no pagination is required in the prototype. Hot spots:

- `export_technique("T1059")` → "Command and Scripting Interpreter"
  will link to many malware families. If a response exceeds a size
  threshold (say 5 MB) we will introduce a `?limit=` query parameter
  and a continuation token keyed by object ID.
- Full-graph or time-range bulk export is explicitly out of scope; that
  is a TAXII endpoint, not this one (see §10).

## 9. Authentication

**The prototype reuses the existing `X-API-Key` header** (dependency
`_verify_api_key`). This is not suitable for partner integration long
term. TODO before production (still open as of 2026-04-18):

1. Issue per-partner API keys (separate from the internal read key) and
   record the partner in the audit log.
2. Consider mTLS for ResilMesh ↔ EdgeGuard traffic if they share a
   private network.
3. Add a rate-limit bucket scoped per partner key (the prototype uses
   the default per-IP read bucket; the endpoint docstring calls this
   out as a gap).

## 10. Explicit non-goals / follow-ups

Tracked as separate tickets; do **not** expand this PR:

- **FU-1: TAXII 2.1 collection service.** Wrap the exporter in a TAXII
  server exposing `Collection`, `Manifest`, `Objects` endpoints. This
  is what partners really want long-term.
- **FU-2: Bulk / full-graph export.** A background job that writes a
  full STIX bundle to object storage, then a signed-URL endpoint. Huge
  memory footprint — needs streaming JSON.
- **FU-3: Push updates.** Subscribe to the EdgeGuard NATS bus and emit
  delta STIX bundles over webhooks / TAXII `added_after`.
- ~~**FU-4: Zone metadata export.**~~ **Done (2026-04).** The
  `x_edgeguard_*` custom-property namespace is now in use. Currently
  emitted: `x_edgeguard_zones`, `x_edgeguard_misp_event_ids`,
  `x_edgeguard_misp_attribute_ids`. Confidence and decay score remain
  open if/when ResilMesh asks for them.
- **FU-5: Per-partner API keys & audit log.** See §9.
- **FU-6: Bundle signing / provenance.** Sign bundles with a JWS so
  ResilMesh can verify EdgeGuard as the origin.
- **FU-7: Pattern coverage.** `_value_to_stix_pattern` only handles a
  subset of MISP types. Add coverage for file names, user accounts,
  registry keys, x509, etc.
- **FU-8: Relationship metadata.** Carry `confidence_score`,
  `match_type`, `created_at` from Neo4j onto the SRO as custom
  properties.

## 11. Testing

Unit tests live in `tests/test_stix_exporter.py` and mock the Neo4j
driver with `MagicMock`. They verify:

- Actor with two techniques → 1 `intrusion-set`, 2 `attack-pattern`,
  2 `uses` SROs
- Actor with attributed malware → `attributed-to` SRO
- Indicator `INDICATES` malware → `indicates` SRO
- Deterministic IDs stable across exporter instances
- Technique `kill_chain_phases` emitted as property, not as SRO
<!-- Removed in PR-N33 docs audit (2026-04-26): the legacy `USES` rel type
shim was REMOVED in PR-N1 — no backward-compat matching to test for.
The exporter only matches the specialized triple
(EMPLOYS_TECHNIQUE / IMPLEMENTS_TECHNIQUE / USES_TECHNIQUE). See
RESILMESH_INTEROPERABILITY.md § 3.2.1. -->
- `edgeguard_managed` filter present in Cypher (no ResilMesh leakage)
- Empty bundle when seed is not found

Integration against a real Neo4j is a follow-up — the prototype
intentionally does not add Docker fixtures.

## 12. Rollout

1. ~~Merge PR #24 (USES specialisation)~~ — **already shipped** on `main`.
2. Merge this PR (prototype + doc) as DRAFT. Stays behind the
   default read API key.
3. ResilMesh tries the four endpoints against staging. Capture
   feedback on §7 decisions.
4. Promote decisions to final, add per-partner auth (FU-5), then flip
   from DRAFT → production.

---

_Last updated: 2026-04-26 — PR-N33 docs audit: corrected bundle-id determinism (was "random UUIDv4", actually content-deterministic UUIDv5 over sorted SDO ids); promoted the dev-vs-prod namespace claim from "if it turns out to be a problem we'll fix" to "shipped behavior with import-time parity check between EDGEGUARD_STIX_NAMESPACE and node_identity.EDGEGUARD_NODE_UUID_NAMESPACE"; removed §11 test bullet "Legacy USES rel type still matched" (USES shim was removed in PR-N1, contradicted by RESILMESH_INTEROPERABILITY.md § 3.2.1). Prior: 2026-04-18 PR #41 cleanup._
