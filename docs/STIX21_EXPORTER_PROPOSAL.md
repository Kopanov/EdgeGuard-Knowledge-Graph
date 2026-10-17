# Proposal: STIX 2.1 graph exporter for ResilMesh integration

> **Historical record** of the STIX 2.1 exporter design proposal, not maintained; the current exporter is described in [RESILMESH_QUICKSTART_STIX.md](RESILMESH_QUICKSTART_STIX.md) and implemented in `src/stix_exporter.py`.

Status: DRAFT — prototype implementation in `src/stix_exporter.py` and
`GET /stix/export/{object_type}/{identifier}` in `src/query_api.py`.

History: the specialised `EMPLOYS_TECHNIQUE` / `IMPLEMENTS_TECHNIQUE`
/ `USES_TECHNIQUE` rel types this proposal exports were introduced in
the 2026-04 USES specialisation work and have shipped on `main`. No
external dependency remains.

## 1. Problem

EdgeGuard and ResilMesh share a Neo4j instance. ResilMesh owns the
asset layer and scanner findings (Host, Device, IP, Mission, Component,
Vulnerability). EdgeGuard owns the threat-intel layer (Indicator,
Malware, ThreatActor, Technique, Tool, Campaign) and writes CVE +
CVSSv* into the shared labels (`edgeguard_managed` on the nodes it
creates, `edgeguard_enriched` on partner nodes it writes to). The
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
| `indicator` | raw value          | Indicator + 1-hop (Malware, CVE, Technique, Sector, Campaign) |
| `actor`     | name or alias      | Actor + attributed Malware + Techniques + the attributed malware's techniques + Campaigns + USES_MALWARE / USES_TOOL software + exploited CVEs + targeted Sectors |
| `technique` | MITRE ATT&CK ID    | Technique + Actors/Malware/Tools/Indicators using it + parent and sub-techniques |
| `cve`       | CVE ID             | CVE + exploiting Indicators, ThreatActors and Malware + affected Sectors |

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
- Pattern strings for `indicator` SDOs are built in the exporter
  (`_build_pattern`, STIX 2.1 patterning grammar). Zone metadata is
  emitted as `x_edgeguard_zones` on every SDO whose node has zones
  (`_attach_zones`, §7 item 4).

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
| `Sector`      | `identity` with `identity_class:"class"`     | `name` = the zone; `sectors` = its `industry-sector-ov` value (`finance` → `financial-services`, `healthcare`, `energy`; none for `global`) |

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
| `(Indicator)-[:EXPLOITS]->(CVE\|Vulnerability)`   | `relationship(related-to)`                                             | The STIX 2.1 relationship summary table defines no `indicator → vulnerability` pair — see §7.                        |
| `(Malware)-[:ATTRIBUTED_TO]->(ThreatActor)`       | `relationship(uses)` src=intrusion-set tgt=malware (reversed)          | `attributed-to` is defined only for campaign / intrusion-set sources; MITRE ATT&CK models the pair as `intrusion-set uses malware`. |
| `(ThreatActor)-[:RUNS]->(Campaign)`               | `relationship(attributed-to)` src=campaign tgt=intrusion-set (reversed) | The table defines `campaign attributed-to intrusion-set`.                                                           |
| `(Technique)-[:IN_TACTIC]->(Tactic)`              | *(no SRO)* — emitted as `kill_chain_phases` property on attack-pattern | STIX 2.1 ATT&CK convention.                                                                                           |
| `(Indicator)-[:TARGETS]->(Sector)`                | `relationship(related-to)` src=indicator tgt=identity                  | `indicator` has no `targets` relationship in the table.                                                              |
| `(Vulnerability\|CVE)-[:AFFECTS]->(Sector)`       | `relationship(related-to)` src=vulnerability tgt=identity              | `affects` is not a STIX 2.1 relationship type, and `vulnerability` has no outgoing relationships in the table. In the graph, TARGETS is reserved for Indicator / ThreatActor / Malware → Sector; Vuln/CVE → Sector is AFFECTS (PR #33 round 11). |

The full mapping, including the 2026-10 relationships, is `_SRO_BY_EDGE` in `src/stix_exporter.py`, served as `relationship_mappings` by `GET /stix/types`.

**Edge type semantics.** Pre-release fresh start emits the post-PR-#24
specialised types directly: `EMPLOYS_TECHNIQUE` (attribution: ThreatActor
/ Campaign → Technique), `IMPLEMENTS_TECHNIQUE` (capability: Malware /
Tool → Technique), `USES_TECHNIQUE` (observation: Indicator → Technique).
`EMPLOYS_TECHNIQUE` and `IMPLEMENTS_TECHNIQUE` collapse back to STIX 2.1
`relationship_type: "uses"` on export; `USES_TECHNIQUE` is exported as
`indicates`.

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

where `EDGEGUARD_STIX_NAMESPACE` is a fixed UUID constant
(`5f2e1f9a-6a1b-5e0f-9b25-ed9ea2d574cb`, equal to
`node_identity.EDGEGUARD_NODE_UUID_NAMESPACE`) hard-coded in
`stix_exporter.py`. Natural keys per type:

| SDO type            | Natural key                  |
|---------------------|------------------------------|
| `indicator`         | `{indicator_type}|{value}`   |
| `malware`           | `{name}`                     |
| `intrusion-set`     | `{name}`                     |
| `attack-pattern`    | `{mitre_id}`                 |
| `tool`              | `{name}`                     |
| `campaign`          | `{name}`                     |
| `vulnerability`     | `{cve_id}`                   |
| `identity` (sector) | `{name}`                     |
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
  bundles are reproducible up to the producer identity's
  `x_edgeguard_generated_at` (omitted when `EDGEGUARD_DETERMINISTIC_BUNDLE`
  is set, for byte-identical output). This was promoted from "random UUIDv4 per
  request" in earlier drafts.

## 7. Open semantic questions (confirm with ResilMesh before merge)

1. **`EXPLOITS` (indicator → vulnerability): resolved as `related-to`.**
   The STIX 2.1 relationship summary table defines no
   `indicator → vulnerability` pair, so the exporter emits `related-to`.
   ResilMesh should confirm this matches their downstream scoring logic.
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
  links to many malware families. Every export takes `?limit=` (default
  100, maximum 500; values outside `[1, 500]` return 422). It bounds each
  related-node collection after ordering it by its natural key, so
  `T1059` returns at most `limit` actors, malware, tools and indicators.
  A continuation token is not implemented.
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
  emitted: every property of the EdgeGuard extension definition
  (version 1.7.0, `EDGEGUARD_EXTENSION_PROPERTIES`; see
  RESILMESH_QUICKSTART_STIX.md § EdgeGuard extension definition),
  including the indicator's confidence and aging.
- **FU-5: Per-partner API keys & audit log.** See §9.
- **FU-6: Bundle signing / provenance.** Sign bundles with a JWS so
  ResilMesh can verify EdgeGuard as the origin.
- **FU-7: Pattern coverage.** Partly done: the exporter builds its own
  patterns (`_build_pattern` in `src/stix_exporter.py`), which cover
  e-mail addresses, file names and, since 2026-10, TLS certificate
  fingerprints (`x509-fingerprint-sha1` →
  `[x509-certificate:hashes.'SHA-1' = …]`). User accounts, registry
  keys etc. remain.
- ~~**FU-8: Relationship metadata.**~~ **Done (2026-10-14, extension
  definition 1.1.0):** SROs carry `confidence`, `external_references`,
  `x_edgeguard_match_type`, `x_edgeguard_sources`,
  `x_edgeguard_source_refs` and `x_edgeguard_misp_event_ids`.

## 11. Testing

Unit tests live in `tests/test_stix_exporter.py` and mock the Neo4j
driver with `MagicMock`. They verify:

- Actor with two techniques → 1 `intrusion-set`, 2 `attack-pattern`,
  2 `uses` SROs
- Actor with attributed malware → `intrusion-set uses malware` SRO (no `attributed-to`)
- Indicator `INDICATES` malware → `indicates` SRO
- Deterministic IDs stable across exporter instances
- Technique `kill_chain_phases` emitted as property, not as SRO
<!-- Removed in PR-N33 docs audit (2026-04-26): the legacy `USES` rel type
shim was REMOVED in PR-N1 — no backward-compat matching to test for.
The exporter only matches the specialized triple
(EMPLOYS_TECHNIQUE / IMPLEMENTS_TECHNIQUE / USES_TECHNIQUE). See
RESILMESH_INTEROPERABILITY.md § 3.2.1. -->
- `edgeguard_managed = true OR edgeguard_enriched = true` filter in every query: nodes EdgeGuard created or enriched are exported; a partner node EdgeGuard never wrote to is not
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

_Last updated: 2026-10-17 — documentation audit against the code: §1 ownership (ResilMesh the asset layer and scanner findings, EdgeGuard writes CVE + CVSSv*); §2 what each export returns; §3 patterns from `_build_pattern`, zones emitted; §4 sector `identity` (`name`, `industry-sector-ov` `sectors`); §5 the exported relationship types (`EXPLOITS`, indicator `TARGETS` and `AFFECTS` are `related-to`, `ATTRIBUTED_TO` is `intrusion-set uses malware`, `RUNS` is `campaign attributed-to intrusion-set`, `USES_TECHNIQUE` is `indicates`) and a pointer to `_SRO_BY_EDGE`; §6 the namespace is a fixed UUID (not UUIDv4), the sector key is `{name}`, `x_edgeguard_generated_at` on the producer identity; §7 item 1 resolved as `related-to`; §8 `?limit=` exists; FU-4 and FU-8 done; §11 test bullets. Prior: 2026-10-15 — FU-7: x509 certificate fingerprint patterns done; file names and e-mail addresses were already covered by `_build_pattern`. Prior: 2026-04-26 — PR-N33 docs audit: corrected bundle-id determinism (was "random UUIDv4", actually content-deterministic UUIDv5 over sorted SDO ids); promoted the dev-vs-prod namespace claim from "if it turns out to be a problem we'll fix" to "shipped behavior with import-time parity check between EDGEGUARD_STIX_NAMESPACE and node_identity.EDGEGUARD_NODE_UUID_NAMESPACE"; removed §11 test bullet "Legacy USES rel type still matched" (USES shim was removed in PR-N1, contradicted by RESILMESH_INTEROPERABILITY.md § 3.2.1). Prior: 2026-04-18 PR #41 cleanup._
