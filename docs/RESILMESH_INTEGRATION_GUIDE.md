# EdgeGuard × ResilMesh integration guide

> **Code alignment:** Cross-layer helpers exist on **`Neo4jClient`** (`src/neo4j_client.py`). Verify names with `grep "def create_" src/neo4j_client.py`. The **contract** for what production **writes today** (e.g. **`REFERS_TO`** Vuln↔CVE, **`EXPLOITS`**, **`INDICATES`** Indicator→Malware / CVE) is **[RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md)** — some rows below are **ResilMesh target shapes**, not all implemented as named methods.

## How EdgeGuard integrates with ResilMesh

### Architecture Overview

EdgeGuard serves as the **Threat Intelligence Enrichment Layer** for ResilMesh. While ResilMesh focuses on network monitoring and topology, EdgeGuard adds threat context from external intelligence sources.

```
┌─────────────────────────────────────────────────────────────────┐
│                         ResilMesh                               │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │  Wazuh  │  │ Suricata│  │  Zeek   │  │  Nmap   │            │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘            │
│       └─────────────┴─────────────┴─────────────┘                │
│                     │                                            │
│                     ▼                                            │
│              ┌─────────────┐                                     │
│              │    NATS     │ ◄────── Alert Stream               │
│              └─────────────┘                                     │
│                     │                                            │
└─────────────────────┼───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                       EdgeGuard                                 │
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   NATS      │    │   Alert     │    │   Enrich    │         │
│  │   Client    │───►│  Processor  │───►│   Engine    │         │
│  └─────────────┘    └─────────────┘    └──────┬──────┘         │
│                                                │                 │
│       ┌────────────────────────────────────────┘                 │
│       ▼                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Neo4j     │◄──►│   Graph     │◄──►│  External   │         │
│  │   Client    │    │    RAG      │    │   Sources   │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│       │                                                         │
│       ▼                                                         │
│  ┌─────────────┐                                                 │
│  │  Response   │ ──────► Back to ResilMesh via NATS             │
│  │   Builder   │                                                 │
│  └─────────────┘                                                 │
└─────────────────────────────────────────────────────────────────┘
```

> **Status:** everything up to the response builder is implemented and tested; the
> "Back to ResilMesh via NATS" step is the target design — no code path publishes the response yet.

---

## Node Type Mappings

### Complete Node Mapping Table

| ResilMesh Concept | EdgeGuard Node | Neo4j Label | Purpose |
|-------------------|----------------|-------------|---------|
| IP Address | IP | `:IP` | Network endpoint identity |
| Host/Workstation | Host | `:Host` | Named network host |
| Network Device | Device | `:Device` | Physical device identity |
| Network Node | Node | `:Node` | Topology graph node with centrality |
| Subnet/VLAN | Subnet | `:Subnet` | Network segment |
| Software Version | SoftwareVersion | `:SoftwareVersion` | Installed software |
| Network Service | NetworkService | `:NetworkService` | Open port/service |
| Application | Application | `:Application` | Software application |
| User Account | User | `:User` | User identity |
| User Role | Role | `:Role` | Role-based access |
| System Component | Component | `:Component` | Mission component |
| Mission | Mission | `:Mission` | Organizational mission |
| Org Unit | OrganizationUnit | `:OrganizationUnit` | Organizational structure |
| Mission Dependency | MissionDependency | `:MissionDependency` | Dependency tracking |
| CVE Entry | CVE | `:CVE` | Vulnerability database entry |
| CVSS Score | CVSSv2/v30/v31/v40 | `:CVSSv2`, `:CVSSv30`, `:CVSSv31`, `:CVSSv40` | Scoring metrics |
| Vulnerability | Vulnerability | `:Vulnerability` | ResilMesh vuln tracking |

### Node Creation Examples

#### IP Node
```python
client.merge_ip({
    "address": "192.168.1.100",
    "status": "active",
    "version": 4,
    "tag": "healthcare_wazuh",
    "first_seen": datetime.now().isoformat(),
    "last_updated": datetime.now().isoformat()
})
```

#### Host Node
```python
client.merge_host({
    "hostname": "hospital-server-01",
    "tag": "healthcare_inventory",
    "first_seen": datetime.now().isoformat(),
    "last_updated": datetime.now().isoformat()
})
```

#### Software Version Node
```python
client.merge_softwareversion({
    "version": "Apache/2.4.41",
    "cve_timestamp": "2026-03-01T00:00:00Z",
    "tag": "healthcare_scan",
    "first_seen": datetime.now().isoformat(),
    "last_updated": datetime.now().isoformat()
})
```

#### CVE Node (ResilMesh)
```python
client.merge_resilmesh_cve({
    "cve_id": "CVE-2021-43297",
    "description": "Apache Log4j2 JNDI features...",
    "published": "2021-12-09T00:00:00Z",
    "last_modified": "2022-01-15T00:00:00Z",
    "cpe_type": ["cpe:2.3:a:apache:log4j"],
    "cwe": ["CWE-502", "CWE-400"],
    "tag": "nvd_import",
    "first_seen": datetime.now().isoformat(),
    "last_updated": datetime.now().isoformat()
})
```

`published` and `last_modified` only fill a CVE node that has none: NVD's record, written by the MISP → Neo4j sync, sets them, and a call without them leaves the stored values in place. `description` follows the source ranking of the sync: the call writes it with `description_source` `"resilmesh"`, a source below every registered feed, so it fills a CVE without a description and never replaces a feed's text (NVD's, the KEV's, …); `merge_resilmesh_vulnerability` does the same on a `Vulnerability` node. `cpe_type`, `result_impacts`, `ref_tags` and `cwe` are set when the call carries them and kept when it does not.

---

## Relationship Mappings

### Complete Relationship Mapping Table

| ResilMesh Relationship | EdgeGuard Method | Direction | Purpose |
|------------------------|------------------|-----------|---------|
| Software runs on Host | `create_softwareversion_on_host()` | `(:SoftwareVersion)-[:ON]->(:Host)` | Software installation |
| Role assigned to Device | `create_role_to_device()` | `(:Role)-[:TO]->(:Device)` | Device roles |
| Role assigned to User | `create_role_assigned_to_user()` | `(:Role)-[:ASSIGNED_TO]->(:User)` | User roles |
| Device is Host | `create_device_has_identity_host()` | `(:Device)-[:HAS_IDENTITY]->(:Host)` | Device identity |
| Host is Device | `create_host_has_identity_device()` | `(:Host)-[:HAS_IDENTITY]->(:Device)` | Host identity |
| Node is Host | `create_node_is_a_host()` | `(:Node)-[:IS_A]->(:Host)` | Node classification |
| Host is Node | `create_host_is_a_node()` | `(:Host)-[:IS_A]->(:Node)` | Host classification |
| IP assigned to Node | `create_ip_has_assigned_node()` | `(:IP)-[:HAS_ASSIGNED]->(:Node)` | IP assignment |
| Node has IP | `create_node_has_assigned_ip()` | `(:Node)-[:HAS_ASSIGNED]->(:IP)` | Node addressing |
| IP in Subnet | `create_ip_part_of_subnet()` | `(:IP)-[:PART_OF]->(:Subnet)` | Network membership |
| Subnet hierarchy | `create_subnet_part_of_subnet()` | `(:Subnet)-[:PART_OF]->(:Subnet)` | Subnet nesting |
| Subnet in Org | `create_subnet_part_of_organizationunit()` | `(:Subnet)-[:PART_OF]->(:OrganizationUnit)` | Org mapping |
| Org hierarchy | `create_organizationunit_part_of_organizationunit()` | `(:OrganizationUnit)-[:PART_OF]->(:OrganizationUnit)` | Org nesting |
| Mission for Org | `create_mission_for_organizationunit()` | `(:Mission)-[:FOR]->(:OrganizationUnit)` | Mission assignment |
| Mission supports Component | `create_mission_supports_component()` | `(:Mission)-[:SUPPORTS]->(:Component)` | Mission support |
| Component from Dependency | `create_component_from_missiondependency()` | `(:Component)-[:FROM]->(:MissionDependency)` | Dependency source |
| Component to Dependency | `create_component_to_missiondependency()` | `(:Component)-[:TO]->(:MissionDependency)` | Dependency target |
| Component on Host | `create_component_provided_by_host()` | `(:Component)-[:PROVIDED_BY]->(:Host)` | Component hosting |
| Node connectivity | `create_node_is_connected_to_node()` | `(:Node)-[:IS_CONNECTED_TO]->(:Node)` | Network topology |
| Service on Host | `create_networkservice_on_host()` | `(:NetworkService)-[:ON]->(:Host)` | Service location |
| App is Component | `create_application_has_identity_component()` | `(:Application)-[:HAS_IDENTITY]->(:Component)` | App identity |
| Component is App | `create_component_has_identity_application()` | `(:Component)-[:HAS_IDENTITY]->(:Application)` | Component identity |
| Vuln refers to CVE | `create_vulnerability_refers_to_cve()` | `(:Vulnerability)-[:REFERS_TO]->(:CVE)` | Vuln mapping |
| CVE refers to Vuln | `create_cve_refers_to_vulnerability()` | `(:CVE)-[:REFERS_TO]->(:Vulnerability)` | CVE mapping |
| CVE has CVSS | *(internal: `_merge_cvss_node` inside `merge_cve()`)* | `(:CVE)-[:HAS_CVSS_v*]->(:CVSSv*)` | Scoring link — created automatically by `Neo4jClient.merge_cve()` when CVSS data is present in the input. There is **no** standalone `create_cve_has_cvss()` or `create_cve_has_cvss_v*` helper, because the relationship is fully derived from CVSS sub-node creation in `_merge_cvss_node`. |
| Indicator → IP (planned) | *(no method yet — see INTEROP § cross-layer bridges)* | `INDICATOR_RESOLVES_TO` planned | Use **`IP.address`** for future matching. Note: the planned edge name is **`INDICATOR_RESOLVES_TO`** (NOT `RESOLVES_TO`) to avoid collision with ISIM's `(IP)-[:RESOLVES_TO]->(DomainName)`. |
| Vuln ↔ CVE bridge | `create_vulnerability_refers_to_cve()` / `create_cve_refers_to_vulnerability()` | `(:Vulnerability)-[:REFERS_TO]->(:CVE)` (+ reverse) | Also created by **`enrichment_jobs.bridge_vulnerability_cve()`** |
| Malware → Host | *(not implemented)* | `(:Malware)-[:TARGETS]->(:Host)` | Listed in INTEROP as **not** in scheduled pipeline |

### Relationship Creation Examples

#### Software on Host
```python
client.create_softwareversion_on_host(version="Apache/2.4.41", hostname="hospital-server-01")
```

#### IP in Subnet
```python
client.create_ip_part_of_subnet(address="192.168.1.100", subnet_range="192.168.1.0/24")
```

#### Service on Host
```python
client.create_networkservice_on_host(port=443, protocol="tcp", hostname="hospital-server-01", status="open")
```

These helpers take no `tag` argument; they MATCH the two nodes by their keys and write only the
relationship (and, for a network service, its `status`).

#### CVE to CVSS

CVSS sub-nodes (`CVSSv2`, `CVSSv30`, `CVSSv31`, `CVSSv40`) and the
matching `(:CVE)-[:HAS_CVSS_v*]->(:CVSSv*)` edges are created
**automatically** by `Neo4jClient.merge_cve()` when the input dict
contains CVSS data. There is no standalone helper to call:

```python
# CVSS data flows through merge_cve, not via a separate helper.
client.merge_cve(
    {
        "cve_id": "CVE-2021-43297",
        "description": "Apache Log4j2 JNDI features...",
        "cvss_v31_data": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "base_score": 9.8},
    },
    source_id="nvd",
)
# → merge_cve MERGEs the CVE, then _merge_cvss_node MERGEs the CVSSv31 node and both
#   HAS_CVSS_v31 edges in a transaction of its own; a failed sub-write makes merge_cve return False.
```

`Neo4jClient` has no standalone `create_cve_has_cvss_v2/v30/v31/v40`
helpers, because the relationship is fully derived from CVSS sub-node
creation; calling such a name raises `AttributeError`.

---

## How Alerts Flow Through the System

### Complete Alert Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. ALERT GENERATION                                             │
│    ResilMesh (Wazuh) detects suspicious activity                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. ALERT PUBLICATION                                            │
│    ResilMesh publishes to NATS topic:                           │
│    resilmesh.alerts.zone.healthcare                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. ALERT INGESTION                                              │
│    EdgeGuard NATS client receives alert                         │
│    - Parses JSON payload                                        │
│    - Validates required fields                                  │
│    - Extracts indicator, zone, severity                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. NODE CREATION                                                │
│    process_complete_resilmesh_alert (Neo4jClient) creates:      │
│    - Alert node (alert_id, source, zone, severity)              │
│    - Indicator node (value, type, zones)                        │
│    - IP / Host nodes: not written by the alert path (helpers    │
│      exist, see the tables above)                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. RELATIONSHIP CREATION                                        │
│    Creates relationships:                                       │
│    - (Alert)-[:INVOLVES]->(Indicator)                          │
│    - (Indicator)-[:INDICATOR_RESOLVES_TO]->(IP) [planned]      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. ENRICHMENT QUERY (AlertProcessor._enrich_indicator, reads)   │
│    - Malware the indicator INDICATES                            │
│    - Threat actors that malware is ATTRIBUTED_TO                │
│    - MITRE techniques those actors EMPLOY (EMPLOYS_TECHNIQUE)   │
│    - CVEs the indicator EXPLOITS (CVE / Vulnerability nodes)    │
│    - CVEs named in the same OTX report (INDICATES to CVE)       │
│    - Network context (hosts, subnets): planned, not read        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 7. RESPONSE BUILDING                                            │
│    Constructs enriched alert response:                          │
│    - Original alert metadata                                    │
│    - Malware information                                        │
│    - Threat actor details                                       │
│    - MITRE ATT&CK mappings                                      │
│    - CVE details with CVSS scores                               │
│    - Network context: planned (assets / users stay empty)       │
│    - Cross-zone impact assessment                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 8. ENRICHED ALERT PUBLICATION                                   │
│    EdgeGuard publishes to NATS (PLANNED — not wired yet):       │
│    resilmesh.enriched.alerts                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 9. CONSUMPTION                                                  │
│    ResilMesh consumes enriched alert for (PLANNED):             │
│    - SOC dashboard display                                      │
│    - Incident response workflows                                │
│    - Automated blocking decisions                               │
│    - Threat hunting prioritization                              │
└─────────────────────────────────────────────────────────────────┘
```

### Detailed Flow Code Example

```python
# Step 1: Alert received from NATS
alert_data = {
    "alert_id": "wazuh-001",
    "source": "wazuh",
    "zone": "healthcare",
    "timestamp": "2026-03-07T10:30:00Z",
    "tags": ["healthcare", "finance"],
    "threat": {
        "indicator": "192.168.1.100",
        "type": "ip",
        "severity": 9,
        "hostname": "hospital-server-01"
    }
}

# Step 2: Record and enrich the alert (src/alert_processor.py)
processor = AlertProcessor(neo4j_client=client)
response = processor.process_alert(alert_data)
# Records: the Alert node, the alert's Indicator node, (Alert)-[:INVOLVES]->(Indicator)
# Reads: malware (INDICATES), actors (ATTRIBUTED_TO), techniques (EMPLOYS_TECHNIQUE),
#        CVEs (EXPLOITS to CVE / Vulnerability, INDICATES to CVE: named in the same OTX report),
#        the indicator's zones and source dates
# Returns: an EnrichedAlert; response.to_dict() is the JSON (TECHNICAL_SPEC.md § Output)
# Without recording the alert: processor.enrich_alert_read_only(alert_data)
#   (demo/alert_enrichment_demo.py, DEMO.md)

# Step 3: Publish to NATS — target design, not implemented. The handler
# (`alert_processor.handle_resilmesh_alert`) returns the response to its caller; no code
# path publishes it. Subject and response schema are pending agreement with ResilMesh.
await nats_client.publish("resilmesh.enriched.alerts", json.dumps(response.to_dict()))
```

---

## Testing the Integration

### Unit Tests

```python
# test_resilmesh_integration.py

import pytest
from neo4j_client import Neo4jClient

@pytest.fixture
def client():
    c = Neo4jClient()
    c.connect()
    yield c
    c.close()

def test_create_all_resilmesh_nodes(client):
    """Test that all ResilMesh node types can be created"""
    
    # IP
    client.merge_ip({
        "address": "10.0.0.1",
        "status": "active",
        "version": 4,
        "tag": "test",
        "first_seen": "2026-03-07T00:00:00Z",
        "last_updated": "2026-03-07T00:00:00Z"
    })
    
    # Host
    client.merge_host({
        "hostname": "test-host",
        "tag": "test",
        "first_seen": "2026-03-07T00:00:00Z",
        "last_updated": "2026-03-07T00:00:00Z"
    })
    
    # Device
    client.merge_device({
        "device_id": "dev-001",
        "tag": "test",
        "first_seen": "2026-03-07T00:00:00Z",
        "last_updated": "2026-03-07T00:00:00Z"
    })
    
    # ... test other node types
    
    # Verify (get_stats counts only EdgeGuard labels and has no relationship counts by type)
    with client.driver.session() as s:
        for label in ("IP", "Host", "Device"):
            assert s.run(f"MATCH (n:{label}) RETURN count(n) AS c").single()["c"] >= 1

def test_create_all_resilmesh_relationships(client):
    """Test that all ResilMesh relationships can be created"""
    
    # Create prerequisite nodes
    client.merge_softwareversion({
        "version": "1.0",
        "cve_timestamp": "2026-03-01T00:00:00Z",
        "tag": "test",
        "first_seen": "2026-03-07T00:00:00Z",
        "last_updated": "2026-03-07T00:00:00Z"
    })
    client.merge_host({
        "hostname": "test-host",
        "tag": "test",
        "first_seen": "2026-03-07T00:00:00Z",
        "last_updated": "2026-03-07T00:00:00Z"
    })
    
    # Test relationship
    client.create_softwareversion_on_host("1.0", "test-host")
    
    # Verify (get_stats has no relationship counts by type)
    with client.driver.session() as s:
        assert s.run("MATCH (:SoftwareVersion)-[r:ON]->(:Host) RETURN count(r) AS c").single()["c"] >= 1

def test_alert_processing(client):
    """Test complete alert processing pipeline"""
    
    alert_data = {
        "alert_id": "test-alert-001",
        "source": "wazuh",
        "zone": "healthcare",
        "timestamp": "2026-03-07T10:30:00Z",
        "threat": {
            "indicator": "10.0.0.99",
            "type": "ip",
            "severity": 5
        }
    }
    
    result = client.process_complete_resilmesh_alert(alert_data)
    
    assert f"Alert:{alert_data['alert_id']}" in result['created_nodes']
    assert f"Indicator:{alert_data['threat']['indicator']}" in result['created_nodes']
    assert len(result['errors']) == 0
```

### Integration Test Script

```bash
#!/bin/bash
# test_integration.sh

echo "=== EdgeGuard x ResilMesh Integration Test ==="

# 1. Test Neo4j connection
echo "Testing Neo4j connection..."
cd EdgeGuard-Knowledge-Graph/src
python3 -c "
from neo4j_client import Neo4jClient
c = Neo4jClient()
if c.connect():
    print('✅ Neo4j connected')
    c.close()
else:
    print('❌ Neo4j connection failed')
    exit(1)
"

# 2. Test constraints creation
echo "Creating constraints..."
python3 -c "
from neo4j_client import Neo4jClient
c = Neo4jClient()
c.connect()
c.create_constraints()
c.close()
print('✅ Constraints created')
"

# 3. Test alert processing
echo "Testing alert processing..."
python3 << 'EOF'
from neo4j_client import Neo4jClient
import json

client = Neo4jClient()
client.connect()

alert = {
    "alert_id": "integration-test-001",
    "source": "test",
    "zone": "healthcare",
    "timestamp": "2026-03-07T10:30:00Z",
    "threat": {
        "indicator": "192.168.1.200",
        "type": "ip",
        "severity": 5
    }
}

result = client.process_complete_resilmesh_alert(alert)
print(f"Created nodes: {result['created_nodes']}")
print(f"Errors: {result['errors']}")

if len(result['errors']) == 0:
    print('✅ Alert processing successful')
else:
    print('❌ Alert processing failed')

client.close()
EOF

# 4. Verify graph stats
echo "Verifying graph statistics..."
python3 << 'EOF'
from neo4j_client import Neo4jClient
import json

client = Neo4jClient()
client.connect()
stats = client.get_stats()
print(json.dumps(stats, indent=2))
client.close()
EOF

echo "=== Integration Test Complete ==="
```

### Manual Testing with Cypher

```cypher
// Verify the test nodes exist (by key or list membership: merge_ip stores `tag` as a list,
// merge_host / merge_device / merge_softwareversion store no `tag`)
MATCH (n)
WHERE (n:IP AND 'test' IN coalesce(n.tag, []))
   OR (n:Host AND n.hostname = 'test-host')
   OR (n:SoftwareVersion AND n.version = '1.0')
   OR (n:Device AND n.device_id = 'dev-001')
RETURN labels(n)[0] AS node_type, count(n) AS count
ORDER BY count DESC;

// Verify ResilMesh relationships
MATCH ()-[r]->()
WHERE type(r) IN ['ON', 'TO', 'ASSIGNED_TO', 'HAS_IDENTITY', 'IS_A',
                  'HAS_ASSIGNED', 'PART_OF', 'FOR', 'SUPPORTS',
                  'PROVIDED_BY', 'FROM', 'IS_CONNECTED_TO', 'REFERS_TO',
                  'HAS_CVSS_v2', 'HAS_CVSS_v30', 'HAS_CVSS_v31', 'HAS_CVSS_v40']
RETURN type(r) as relationship_type, count(r) as count
ORDER BY count DESC;

// Verify bridge relationships (planned: Indicator → IP via INDICATOR_RESOLVES_TO,
// distinct from ISIM's IP → DomainName RESOLVES_TO. EdgeGuard does not create the
// edge yet — see RESILMESH_INTEROPERABILITY.md § cross-layer bridges.)
// MATCH (i:Indicator)-[r:INDICATOR_RESOLVES_TO]->(ip:IP)
// RETURN i.value as indicator, ip.address as resolved_ip;

// Test enrichment chain: an indicator INDICATES malware, EXPLOITS the CVE its own CVE tag names,
// and INDICATES the CVEs named in the same OTX report (match_type 'otx_pulse')
MATCH (i:Indicator {value: '192.168.1.100'})
OPTIONAL MATCH (i)-[:INDICATES]->(m:Malware)
OPTIONAL MATCH (i)-[:EXPLOITS]->(c:CVE)
OPTIONAL MATCH (i)-[:INDICATES]->(rc:CVE)
RETURN i.value, collect(DISTINCT m.name), collect(DISTINCT c.cve_id), collect(DISTINCT rc.cve_id);

// Clean up the test nodes, only those EdgeGuard created
MATCH (n)
WHERE n.edgeguard_managed = true
  AND ((n:IP AND 'test' IN coalesce(n.tag, []))
    OR (n:Host AND n.hostname = 'test-host')
    OR (n:SoftwareVersion AND n.version = '1.0')
    OR (n:Device AND n.device_id = 'dev-001'))
DETACH DELETE n;
```

---

## Troubleshooting

### Common Issues

#### Issue: Neo4j Connection Failed
```
Error: Neo4j connection failed: ServiceUnavailable
```
**Solution:**
```bash
# Check Neo4j is running
docker ps | grep neo4j

# Check logs (container name is `edgeguard_neo4j` per docker-compose.yml)
docker logs edgeguard_neo4j

# Verify credentials
echo $NEO4J_PASSWORD
```

#### Issue: Constraint Creation Failed
```
Warning: Constraint creation: Constraint already exists
```
**Solution:**
```cypher
// List existing constraints
SHOW CONSTRAINTS;

// Drop and recreate if needed
DROP CONSTRAINT constraint_name IF EXISTS;
```

#### Issue: Alert Processing Slow
```
Enrichment latency > 500ms
```
**Solution:**
```cypher
// Check for missing indexes
SHOW INDEXES;

// Analyze query performance
EXPLAIN MATCH (i:Indicator {value: $value})
OPTIONAL MATCH (i)-[:INDICATES]->(m:Malware)
RETURN i, m;
```

#### Issue: NATS Connection Failed
```
Error: NATS connection failed
```
**Solution:**
```bash
# Check NATS is running
docker ps | grep nats

# Test connection
nats pub test "hello"
nats sub test
```

---

## Best Practices

### 1. Tag Management
Always use consistent tags for data provenance:
```python
# Good
tag = f"{zone}_{source}"  # "healthcare_wazuh"

# Bad
tag = "test"  # Non-descriptive
```

### 2. Temporal Tracking
In the source-truthful timestamp model ([TIMESTAMPS.md](TIMESTAMPS.md)),
the node carries only DB-local timestamps; per-source observation
claims live on the `SOURCED_FROM` edge. Do NOT write `first_seen` on
the node: it would conflate DB-local import time with source-claimed
first-observation time.

```python
now = datetime.now(timezone.utc).isoformat()
node_data = {
    "first_imported_at": now,   # ON CREATE only — never overwritten
    "last_updated":      now,   # SET on every MERGE — DB-local refresh
}

# Per-source observation timestamps (when the source actually claims
# first/last observation) go on the SOURCED_FROM edge, NOT on the node.
# Honest-NULL: only set if the source genuinely reported the value;
# do not synthesize from the import wall clock.
edge_data = {
    "imported_at":               now,            # ON CREATE only: when EdgeGuard first linked this source (immutable)
    "updated_at":                now,            # set every merge
    "source_reported_first_at":  source_first,   # MIN-CASE; may be None
    "source_reported_last_at":   source_last,    # MAX-CASE; may be None
}
```

The ResilMesh helpers `merge_host`, `merge_device`, `merge_subnet`, `merge_networkservice`,
`merge_softwareversion`, `merge_application`, `merge_role`, `merge_component`, `merge_mission`,
`merge_organizationunit`, `merge_missiondependency`, `merge_resilmesh_user`, `merge_resilmesh_cve` and
`merge_node` set `first_seen` (the first EdgeGuard write) on the node; `merge_ip` and
`merge_resilmesh_vulnerability` set `first_imported_at`.

### 3. Zone Handling
Use multi-zone support for cross-sector threats:
```python
zones = tags if tags else [zone]
data = {"zone": zones}  # zone is a list on every node (Alert included); the alert path keeps only VALID_ZONES names
```

### 4. Error Handling
Always wrap graph operations in try-catch:
```python
try:
    client.merge_ip(data)
except Exception as e:
    logger.error(f"Failed to create IP: {e}")
    # Fallback or retry logic
```

---

## Summary

EdgeGuard's ResilMesh integration today:

- ✅ **Shared Neo4j database** — EdgeGuard writes the threat-intelligence layer (`Indicator`, `Malware`, `ThreatActor`, `Campaign`, `Technique`, `Tactic`, `Tool`, `Sector`, `Source`, `CVE` + `CVSSv*`) with `edgeguard_managed` on every node it creates and `edgeguard_enriched` on partner nodes it writes to; 22 relationship types, every edge stamped (`edgeguard_managed`, provenance), and every claim between threat-intelligence entities evidence-labelled (`match_type`); the structural `SOURCED_FROM`, `HAS_CVSS_*`, `REFERS_TO` and `INVOLVES` carry no `match_type`.
- ✅ **Schema-compatible helpers** for the ResilMesh topology / identity / mission labels and their relationships (the tables above) — available to an alert or import path; the scheduled pipeline does not write them.
- ✅ **Vulnerability ↔ CVE bridge job** (`REFERS_TO`, both directions) for any `Vulnerability` node carrying `cve_id`.
- ✅ **Inbound alert enrichment** — `resilmesh.alerts.zone.*` → `Alert` node, `Indicator`, `INVOLVES`, enrichment chain.
- ⚠️ **Not implemented:** publishing the enriched response back over NATS, a deployable NATS consumer service, validation against a payload schema agreed with ResilMesh (the processor checks only `alert_id` and `threat`), the `SoftwareVersion` bridge (`IN` / `ON`), `INDICATOR_RESOLVES_TO`, `Malware → Host`. See [RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) § 4.4 and § 8.6 for what each needs, and [ROADMAP.md](ROADMAP.md) for the planned work.

The integration enables **context-aware threat detection** that combines:
- External threat intelligence (CVE, MITRE, IOCs)
- Internal network topology (Hosts, Subnets, Services)
- Mission context (Components, Missions, Org Units)
- Cross-zone correlation (Multi-sector threat detection)

---

*Integration Guide Version: 2.1*  
*For ResilMesh and EdgeGuard Engineers*

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — The summary no longer lists inbound payload validation as missing: the alert processor rejects a payload without an `alert_id` or whose `threat` is not an object; what is missing is a schema agreed with ResilMesh. It links ROADMAP.md.
- 2026-10-18 — The alert enrichment also reads `(Indicator)-[:INDICATES]->(CVE)`, a CVE named in the same OTX report.
- 2026-10-17 — Rewritten as a guide to current behaviour and checked against the code: 22 relationship types; the relationship examples call the helpers with their real arguments (no `tag`); `merge_cve` takes a data dict and runs its CVSS sub-writes in transactions of their own; the test examples count nodes and `ON` edges directly; the manual Cypher selects and cleans up the test nodes by key and follows `INDICATES` / `EXPLOITS` to `CVE`; `SOURCED_FROM.imported_at` is set on create only; `zone` is a list.
- 2026-10-16 — `merge_resilmesh_cve` / `merge_resilmesh_vulnerability` write the description with `description_source` `resilmesh`, below every registered feed; the alert flow and its code example state what the alert path writes and reads (the example called a stub that returned sample data).
- 2026-10-15 — `merge_resilmesh_cve` only fills `description`, `published` and `last_modified` and keeps the lists a call omits (a call without them had removed NVD's lists).
- 2026-10-11 — The alert-flow steps 8–9, the publish step of the code example and the summary state what is implemented and what is planned.
- 2026-04-28 — CVSS edge names corrected to `HAS_CVSS_v2` / `HAS_CVSS_v30` / `HAS_CVSS_v31` / `HAS_CVSS_v40`.
- 2026-04-26 — Calls to the removed `create_cve_has_cvss_v*` helpers dropped (`merge_cve` creates the CVSS edges); the planned Indicator → IP edge named `INDICATOR_RESOLVES_TO` to avoid a collision with ISIM's `RESOLVES_TO`.
- 2026-04-18 — Node `first_seen` retired for EdgeGuard nodes in favour of DB-local node timestamps and source claims on `SOURCED_FROM` (historical record: [`migrations/2026_04_first_seen_at_source.md`](../migrations/2026_04_first_seen_at_source.md)).
- 2026-03-21 — Cross-layer helper names aligned with `Neo4jClient`.
