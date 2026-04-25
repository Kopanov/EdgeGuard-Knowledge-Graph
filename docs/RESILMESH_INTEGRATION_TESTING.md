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
- `tests/test_resilmesh_schema.py` – test script that validates the combined schema (ResilMesh + EdgeGuard TI).

---

### 2. Push vs pull – recommended pattern

There are two main options:

- **Push**: EdgeGuard writes directly into the ResilMesh Neo4j schema using `Neo4jClient` ResilMesh methods.
- **Pull**: ResilMesh reads from EdgeGuard’s TI graph and does the mapping itself.

**Recommended**: **Push from EdgeGuard into the ResilMesh schema**, because:

- EdgeGuard already:
  - Normalizes CVEs, vulns, indicators and zones.
  - Has `merge_resilmesh_*` and bridge relationships implemented.
- It keeps data transformation logic close to the TI ingestion code and in one place.

Pull is still possible (ResilMesh connects to EdgeGuard’s Neo4j as a read-only source), but then **they** must reimplement the mapping logic that EdgeGuard already has.

---

### 3. Testing the schema integration (unit-level)

Use `test_resilmesh_schema.py` to validate that all ResilMesh node/relationship shapes and bridges exist and work.

From the repo root:

```bash
python3 tests/test_resilmesh_schema.py
```

This script:

- Verifies that `Neo4jClient` implements all required ResilMesh methods:
  - Node merges: `merge_ip`, `merge_host`, `merge_device`, `merge_subnet`, `merge_softwareversion`, `merge_application`, `merge_networkservice`, `merge_resilmesh_cve`, `merge_cvssv2`, `merge_cvssv30`, `merge_cvssv31`, `merge_cvssv40`, `merge_resilmesh_user`, `merge_role`, `merge_component`, `merge_mission`, `merge_organizationunit`, `merge_missiondependency`, `merge_resilmesh_vulnerability`, etc.
  - Relationships: `create_softwareversion_on_host`, `create_role_assigned_to_user`, `create_device_has_identity_host`, `create_host_has_identity_device`, `create_ip_part_of_subnet`, `create_subnet_part_of_organizationunit`, `create_mission_for_organizationunit`, `create_mission_supports_component`, `create_component_provided_by_host`, `create_vulnerability_in_softwareversion`, `create_cve_refers_to_vulnerability`, `create_vulnerability_refers_to_cve`, `create_node_is_connected_to_node`, etc. **CVSS edges (`HAS_CVSSv*`)** are NOT exposed as standalone helpers — they are created automatically by `merge_cve()` via `_merge_cvss_node` when CVSS data is present in the input dict (the four `create_cve_has_cvss_v*` helpers were removed in PR #33 round 12).
  - Bridge-style methods that **do exist**: `create_vulnerability_refers_to_cve`, `create_cve_refers_to_vulnerability` (plus automatic **`bridge_vulnerability_cve`** from `enrichment_jobs`). **Planned / not in `neo4j_client`:** `create_indicator_resolves_to_ip` (planned edge type: `INDICATOR_RESOLVES_TO`, NOT `RESOLVES_TO`, to avoid ISIM collision), `create_malware_targets_host`. There is no `create_vulnerability_maps_to_cve` — use `create_vulnerability_refers_to_cve` instead, or rely on `bridge_vulnerability_cve` to auto-create the REFERS_TO edge during enrichment.
- Optionally creates sample nodes and relationships to assert that:
  - ResilMesh nodes can be created without errors.
  - Constraints and indexes are applied successfully.

**Expected outcome**: All required methods are present and sample nodes/relationships can be created in a running Neo4j instance.

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

   # Example: create bridge between EdgeGuard Vulnerability and ResilMesh CVE.
   # Use create_vulnerability_refers_to_cve (REFERS_TO edge); the historical
   # create_vulnerability_maps_to_cve helper does NOT exist. Or rely on
   # enrichment_jobs.bridge_vulnerability_cve() to auto-create the bridge.
   client.create_vulnerability_refers_to_cve(cve_id="CVE-2024-12345")
   ```

   You can follow the patterns used in `tests/test_resilmesh_schema.py` for realistic examples (IP → Host → Component → Mission, etc.).

4. **Inspect the resulting graph in Neo4j Browser**
   - Verify that:
     - ResilMesh node labels (`Mission`, `Component`, `OrganizationUnit`, `Host`, `Subnet`, `Vulnerability`, `CVE`, `CVSSv*`, etc.) exist with the properties defined in the CSVs.
     - Bridge relationships (e.g. TI indicators/CVEs linked to ResilMesh hosts, components, software versions) appear as expected.

---

### 5. Who should run what (EdgeGuard vs ResilMesh)

**EdgeGuard responsibilities (push model):**

- Ingest and normalize threat intelligence.
- Map:
  - `Indicator` → `IP` / `Host` — **planned** via `create_indicator_resolves_to_ip` (planned `INDICATOR_RESOLVES_TO` edge) and `create_malware_targets_host`. Not yet implemented in `neo4j_client.py` at HEAD; do not require these in smoke tests.
  - EdgeGuard `Vulnerability` ↔ `CVE` via `create_vulnerability_refers_to_cve` / `create_cve_refers_to_vulnerability` + the automatic `enrichment_jobs.bridge_vulnerability_cve()`. CVSS sub-nodes + `(:CVE)-[:HAS_CVSSv*]->(:CVSSv*)` edges are created internally by `merge_cve()` via `_merge_cvss_node` — not via standalone helpers.
- Maintain bridge relationships between TI and mission/asset graph.

**ResilMesh responsibilities:**

- Define and maintain the **asset and mission** side:
  - `Mission`, `Component`, `OrganizationUnit`, `NetworkService`, `SoftwareVersion`, etc.
  - The relationships between them (`PROVIDED_BY`, `SUPPORTS`, `PART_OF`, etc.).
- Optionally run their own analysis/queries on the enriched graph.

In this push model, ResilMesh consumes a Neo4j graph that is already populated with **both**:

- Their mission/asset topology, and
- EdgeGuard’s mapped threat intelligence.

---

### 6. Summary

- The ResilMesh Neo4j schema (from the CSVs) is implemented in `neo4j_client.py`.
- Bridge methods allow you to connect EdgeGuard’s TI graph into that schema.
- **Recommended:** EdgeGuard **pushes** into the ResilMesh schema using those methods, and `tests/test_resilmesh_schema.py` + manual Neo4j inspection are used to verify that the integration is working end-to-end.



---

_Last updated: 2026-04-26 — PR-N33 docs audit: removed references to non-existent `create_vulnerability_maps_to_cve` (use `create_vulnerability_refers_to_cve` or rely on `bridge_vulnerability_cve`); marked `create_indicator_resolves_to_ip` / `create_malware_targets_host` as planned (not implemented at HEAD); clarified that CVSS edges are created internally by `merge_cve()` (the four `create_cve_has_cvss_v*` helpers were removed in PR #33 round 12). Prior: 2026-03-17._
