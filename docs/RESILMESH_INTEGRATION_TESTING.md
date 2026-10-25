## Testing EdgeGuard ↔ ResilMesh integration

This guide explains how to verify that EdgeGuard correctly integrates with the ResilMesh Neo4j data model, and whether you should run the integration as a **push** from EdgeGuard or a **pull** from ResilMesh.

**Contract vs helpers:** What the **scheduled pipeline** creates (relationship types, enrichment bridges) is defined in **[RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md)**. **`Neo4jClient`** also exposes many **`create_*`** helpers for ResilMesh-shaped graphs — not every ResilMesh relationship name has a matching method yet (see INTEROP “cross-layer bridges”).

---

### 1. High-level integration model

EdgeGuard maintains its own **threat intelligence graph** (indicators, CVEs, vulnerabilities, malware, actors, techniques, sources, zones).

ResilMesh defines a **mission/asset/vulnerability graph** in Neo4j using the node and relationship types from:

- `data model - general/Neo4j/neo4j_nodes_properties.csv`
- `data model - general/Neo4j/neo4j_relationships_properties.csv`

In EdgeGuard, the ResilMesh schema and bridges are implemented via:

- `src/neo4j_client.py` – `merge_*` and `create_*` methods for ResilMesh nodes and relationships.
- `tests/test_resilmesh_schema.py` – pytest checks (no Neo4j) of the ResilMesh helper methods and labels.

---

### 2. Push vs pull – recommended pattern

There are two main options:

- **Push**: EdgeGuard writes directly into the ResilMesh Neo4j schema using `Neo4jClient` ResilMesh methods.
- **Pull**: ResilMesh reads from EdgeGuard’s TI graph and does the mapping itself.

**Recommended ([RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) §4, §6):** ResilMesh writes its own topology, identity, mission and scanner data (`Host`, `IP`, `Vulnerability`, `SoftwareVersion`, `IN`, `ON`, …). EdgeGuard writes the threat-intelligence layer and `CVE` + `CVSSv*` into the same database, plus `REFERS_TO` where a `Vulnerability` carries `cve_id`. The ResilMesh `merge_*` / `create_*` helpers in `neo4j_client.py` are schema-compatible tools for tests and imports; no scheduled EdgeGuard path calls them.

Pull is also possible (ResilMesh reads EdgeGuard's nodes from the shared Neo4j, through the APIs, or as STIX 2.1 bundles from `/stix/export/*`).

---

### 3. Testing the schema integration (unit-level)

Use `tests/test_resilmesh_schema.py` to check that the ResilMesh helper methods and labels exist.

From the repo root:

```bash
python -m pytest tests/test_resilmesh_schema.py -q
```

The file is a pytest module (run as a plain script it only defines its test functions and checks nothing). It needs no Neo4j, creates no nodes and applies no constraints. It checks that:

- `Neo4jClient` has these node merges: `merge_ip`, `merge_host`, `merge_device`, `merge_subnet`, `merge_node`, `merge_softwareversion`, `merge_application`, `merge_networkservice`, `merge_resilmesh_cve`, `merge_resilmesh_user`, `merge_role`, `merge_component`, `merge_mission`, `merge_organizationunit`, `merge_missiondependency` and `merge_resilmesh_vulnerability`. CVSS nodes come from `merge_cve`; there are no standalone `merge_cvss*` mergers.
- `Neo4jClient` has the relationship helpers it names: `create_softwareversion_on_host`, `create_role_to_device`, `create_role_assigned_to_user`, `create_device_has_identity_host`, `create_host_is_a_node`, `create_ip_part_of_subnet`, `create_subnet_part_of_subnet`, `create_networkservice_on_host`, `create_vulnerability_in_softwareversion` and `create_cve_refers_to_vulnerability`. **CVSS edges (`HAS_CVSS_v*`: `HAS_CVSS_v2` / `HAS_CVSS_v30` / `HAS_CVSS_v31` / `HAS_CVSS_v40`)** are NOT exposed as standalone helpers — they are created automatically by `merge_cve()` via `_merge_cvss_node` when CVSS data is present in the input dict; there are no `create_cve_has_cvss_v*` helpers.
- `Neo4jClient` has the EdgeGuard core methods it names (`merge_indicator`, `merge_cve`, `merge_node_with_source`, `create_constraints`, `create_indexes`, …).
- `_ALLOWED_NODE_LABELS` holds the ResilMesh and EdgeGuard labels.

Bridge-style methods that **do exist**: `create_vulnerability_refers_to_cve`, `create_cve_refers_to_vulnerability` (plus automatic **`bridge_vulnerability_cve`** from `enrichment_jobs`). **Planned / not in `neo4j_client`:** `create_indicator_resolves_to_ip` (planned edge type: `INDICATOR_RESOLVES_TO`, NOT `RESOLVES_TO`, to avoid ISIM collision), `create_malware_targets_host`. There is no `create_vulnerability_maps_to_cve` — use `create_vulnerability_refers_to_cve` instead, or rely on `bridge_vulnerability_cve` to auto-create the REFERS_TO edge during enrichment.

**Expected outcome**: every test passes, so every method and label the file names is present. Creating nodes and relationships in a running Neo4j is a separate check (the unit-test example in [RESILMESH_INTEGRATION_GUIDE.md](RESILMESH_INTEGRATION_GUIDE.md) § Testing the Integration).

---

### 4. Testing the integration end-to-end (threat intel → ResilMesh graph)

To verify a full flow from external feeds all the way into the ResilMesh data model:

1. **Prepare Neo4j and MISP**
   - Start Neo4j with the expected constraints/indexes (EdgeGuard’s `neo4j_client.create_constraints()` / `.create_indexes()`).
   - Ensure MISP is reachable and configured with an API key.

2. **Run the EdgeGuard pipeline**

   ```bash
   # From repository root; env vars: MISP_URL, MISP_API_KEY, NEO4J_*, etc.
   python src/run_pipeline.py
   ```
   (Prefer **Airflow DAGs** for production — see [SETUP_GUIDE.md](SETUP_GUIDE.md). Use `run_pipeline.py` for direct testing.)
   - (Optionally) trigger any integration logic you add that maps TI into ResilMesh nodes.

3. **Call the ResilMesh merge/bridge methods**

   In your integration job (or an interactive test):

   ```python
   from neo4j_client import Neo4jClient

   client = Neo4jClient()
   client.connect()

   # Example: map an EdgeGuard CVE to a ResilMesh CVE node
   client.merge_resilmesh_cve({
       "cve_id": "CVE-2024-12345",
       "description": "Example vulnerability",
       # plus any other fields you compute/populate
   })
   # published and last_modified only fill a CVE node that has none (NVD's record, written
   # by the MISP → Neo4j sync, sets them). description follows the sync's source ranking
   # with description_source "resilmesh", below every registered feed: it fills a CVE without a
   # description and never replaces a feed's text (NVD's, the KEV's, ...); it can replace the text of
   # another source without a description rank (an unregistered source, or stix_import, registered with
   # ranked_for_descriptions=False) whose id sorts after it, such as stix_import's. cwe, ref_tags,
   # cpe_type and result_impacts are kept when omitted.

   # Example: create the bridge between a ResilMesh Vulnerability (keyed on cve_id) and the CVE.
   # Use create_vulnerability_refers_to_cve (REFERS_TO edge); there is no
   # create_vulnerability_maps_to_cve helper. Or rely on
   # enrichment_jobs.bridge_vulnerability_cve() to auto-create the bridge.
   client.create_vulnerability_refers_to_cve(cve_id="CVE-2024-12345")
   ```

   `tests/test_resilmesh_schema.py` only checks that the helpers exist; for calls with real arguments see the relationship examples in [RESILMESH_INTEGRATION_GUIDE.md](RESILMESH_INTEGRATION_GUIDE.md).

4. **Inspect the resulting graph in Neo4j Browser**
   - Verify that:
     - ResilMesh node labels (`Mission`, `Component`, `OrganizationUnit`, `Host`, `Subnet`, `Vulnerability`, `CVE`, `CVSSv*`, etc.) exist with the properties defined in the CSVs.
     - EdgeGuard's `CVE` / `CVSSv*` nodes appear, and, where ResilMesh wrote `Vulnerability` nodes with `cve_id`, the `REFERS_TO` edges of `bridge_vulnerability_cve`. No bridge from indicators or CVEs to hosts, components or software versions exists yet (`INDICATOR_RESOLVES_TO`, `Malware → Host` and the `SoftwareVersion` bridge are planned).

---

### 5. Who should run what (EdgeGuard vs ResilMesh)

**EdgeGuard responsibilities:**

- Ingest and normalize threat intelligence; write the threat-intelligence layer and `CVE` + `CVSSv*` into the shared database. CVSS sub-nodes + `(:CVE)-[:HAS_CVSS_v*]->(:CVSSv*)` edges (`HAS_CVSS_v2` / `HAS_CVSS_v30` / `HAS_CVSS_v31` / `HAS_CVSS_v40`) are created internally by `merge_cve()` via `_merge_cvss_node` — not via standalone helpers.
- `REFERS_TO` between a ResilMesh `Vulnerability` that carries `cve_id` and its `CVE`, through the automatic `enrichment_jobs.bridge_vulnerability_cve()` (the helpers `create_vulnerability_refers_to_cve` / `create_cve_refers_to_vulnerability` write the same edge from custom code).
- Not yet: `Indicator` → `IP` / `Host` — **planned** via `create_indicator_resolves_to_ip` (planned `INDICATOR_RESOLVES_TO` edge) and `create_malware_targets_host`. Not implemented in `neo4j_client.py`; do not require these in smoke tests.

**ResilMesh responsibilities:**

- Define and maintain the **asset, mission and scanner** side:
  - `Host`, `IP`, `Mission`, `Component`, `OrganizationUnit`, `NetworkService`, `SoftwareVersion`, the scanner's `Vulnerability`, etc.
  - The relationships between them (`PROVIDED_BY`, `SUPPORTS`, `PART_OF`, `IN`, `ON`, etc.).
- Optionally run their own analysis/queries on the enriched graph.

ResilMesh then works on a Neo4j graph that holds **both**:

- Their mission/asset topology and scanner findings, and
- EdgeGuard's threat intelligence and `CVE` + `CVSSv*` nodes, joined to the findings by `REFERS_TO`.

---

### 6. Summary

- `neo4j_client.py` has schema-compatible `merge_*` / `create_*` helpers for the ResilMesh labels (from the CSVs), for tests and imports; no scheduled EdgeGuard path calls them.
- **Recommended:** each system writes its own layer into the shared database (RESILMESH_INTEROPERABILITY.md §4, §6): ResilMesh the topology, identity, mission and scanner data, EdgeGuard the threat intelligence and `CVE` + `CVSSv*`, joined by `REFERS_TO`.
- `python -m pytest tests/test_resilmesh_schema.py -q` checks that the helpers and labels exist; manual Neo4j inspection (§4) checks the shared graph.



---

_Last updated: 2026-10-25_

## History

- 2026-10-25 — `merge_resilmesh_cve` example: `stix_import` is a registered source without a description rank (`ranked_for_descriptions=False`), so `resilmesh`, whose id sorts first, still replaces its text.
- 2026-10-17 — Rewritten as a guide to current behaviour and checked against the code: `tests/test_resilmesh_schema.py` is a pytest module that needs no Neo4j (as a plain script it checks nothing) and the methods and labels it checks are listed; the recommended split follows RESILMESH_INTEROPERABILITY.md §4 and §6 (ResilMesh writes its topology, mission and scanner data, EdgeGuard the threat intelligence and `CVE` + `CVSSv*`); no indicator- or CVE-to-asset bridge exists yet.
- 2026-10-16 — `merge_resilmesh_cve` example: the description follows the sync's source ranking with `description_source` `resilmesh`, below every registered feed.
- 2026-10-15 — `merge_resilmesh_cve` example: `description`, `published` and `last_modified` only fill a CVE node that has none, and the lists a call omits are kept.
- 2026-04-26 — The non-existent `create_vulnerability_maps_to_cve` replaced by `create_vulnerability_refers_to_cve` / `bridge_vulnerability_cve`; `create_indicator_resolves_to_ip` and `create_malware_targets_host` marked as planned; CVSS edges come from `merge_cve()` (the `create_cve_has_cvss_v*` helpers were removed).
- 2026-03-17 — Earliest recorded revision.
