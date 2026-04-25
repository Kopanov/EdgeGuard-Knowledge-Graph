# EdgeGuard × ResilMesh integration guide

> **2026-03-21 — Code alignment:** Cross-layer helpers exist on **`Neo4jClient`** (`src/neo4j_client.py`). Verify names with `grep "def create_" src/neo4j_client.py`. The **contract** for what production **writes today** (e.g. **`REFERS_TO`** Vuln↔CVE, **`EXPLOITS`**, **`INDICATES`** Indicator→Malware) is **[RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md)** — some rows below are **ResilMesh target shapes**, not all implemented as named methods.

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
| CVE has CVSS | *(internal: `_merge_cvss_node` inside `merge_cve()`)* | `(:CVE)-[:HAS_CVSSv*]->(:CVSSv*)` | Scoring link — created automatically by `Neo4jClient.merge_cve()` when CVSS data is present in the input. There is **no** standalone `create_cve_has_cvss()` helper today (the four `create_cve_has_cvss_v*` helpers were removed in PR #33 round 12 because the relationship is fully derived from CVSS sub-node creation in `_merge_cvss_node`). |
| Indicator → IP (planned) | *(no method yet — see INTEROP § cross-layer bridges)* | `INDICATOR_RESOLVES_TO` planned | Use **`IP.address`** for future matching. Note: the planned edge name is **`INDICATOR_RESOLVES_TO`** (NOT `RESOLVES_TO`) to avoid collision with ISIM's `(IP)-[:RESOLVES_TO]->(DomainName)`. |
| Vuln ↔ CVE bridge | `create_vulnerability_refers_to_cve()` / `create_cve_refers_to_vulnerability()` | `(:Vulnerability)-[:REFERS_TO]->(:CVE)` (+ reverse) | Also created by **`enrichment_jobs.bridge_vulnerability_cve()`** |
| Malware → Host | *(not implemented)* | `(:Malware)-[:TARGETS]->(:Host)` | Listed in INTEROP as **not** in scheduled pipeline |

### Relationship Creation Examples

#### Software on Host
```python
client.create_softwareversion_on_host(
    version="Apache/2.4.41",
    hostname="hospital-server-01",
    tag="healthcare"
)
```

#### IP in Subnet
```python
client.create_ip_part_of_subnet(
    address="192.168.1.100",
    range="192.168.1.0/24",
    tag="healthcare"
)
```

#### Service on Host
```python
client.create_networkservice_on_host(
    port=443,
    protocol="tcp",
    hostname="hospital-server-01",
    tag="healthcare",
    status="open"
)
```

#### CVE to CVSS

CVSS sub-nodes (`CVSSv2`, `CVSSv30`, `CVSSv31`, `CVSSv40`) and the
matching `(:CVE)-[:HAS_CVSSv*]->(:CVSSv*)` edges are created
**automatically** by `Neo4jClient.merge_cve()` when the input dict
contains CVSS data. There is no standalone helper to call:

```python
# CVSS data flows through merge_cve, not via a separate helper.
client.merge_cve(
    cve_id="CVE-2021-43297",
    description="Apache Log4j2 JNDI features...",
    cvss_v31_data={
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "base_score": 9.8,
    },
    source_id="nvd",
)
# → MERGE the CVSSv31 node + the (:CVE)-[:HAS_CVSSv31]->(:CVSSv31) edge
#   inside _merge_cvss_node, in the same transaction as the CVE itself.
```

The four standalone `create_cve_has_cvss_v2/v30/v31/v40` helpers were
removed in PR #33 round 12 because the relationship is fully derived
from CVSS sub-node creation. Calling them on the current API will
raise `AttributeError`.

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
│    Neo4jClient creates/updates:                                 │
│    - Alert node (alert_id, source, zone, severity)              │
│    - Indicator node (value, type, zones)                        │
│    - IP node (if indicator is IP)                               │
│    - Host node (if hostname in alert)                           │
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
│ 6. ENRICHMENT QUERY                                             │
│    GraphRAG queries for enrichment:                             │
│    - Find malware attributed to indicator                       │
│    - Find threat actors using malware                           │
│    - Find MITRE techniques used by actors                       │
│    - Find CVEs linked to indicator                              │
│    - Find network context (hosts, subnets)                      │
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
│    - Network context from ResilMesh topology                    │
│    - Cross-zone impact assessment                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 8. ENRICHED ALERT PUBLICATION                                   │
│    EdgeGuard publishes to NATS:                                 │
│    resilmesh.enriched.alerts                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 9. CONSUMPTION                                                  │
│    ResilMesh consumes enriched alert for:                       │
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

# Step 2: Process complete alert
result = client.process_complete_resilmesh_alert(alert_data)
# Creates: Alert node, Indicator node, IP node, Host node
# Links: Alert->Indicator, Indicator->IP

# Step 3: Enrichment query
enrichment = client.get_enrichment_chain("192.168.1.100")

# Step 4: Build response
response = {
    "alert_id": alert_data["alert_id"],
    "enriched": True,
    "latency_ms": 120,
    "enrichment": enrichment
}

# Step 5: Publish to NATS
await nats_client.publish("resilmesh.enriched.alerts", json.dumps(response))
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
    
    # Verify
    stats = client.get_stats()
    assert stats['IP'] >= 1
    assert stats['Host'] >= 1
    assert stats['Device'] >= 1

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
    client.create_softwareversion_on_host("1.0", "test-host", "test")
    
    # Verify
    stats = client.get_stats()
    assert stats['relationships'].get('ON', 0) >= 1

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
-- Verify all ResilMesh node types exist
MATCH (n) 
WHERE n.tag = 'healthcare' OR n.tag = 'test'
RETURN labels(n)[0] as node_type, count(n) as count
ORDER BY count DESC;

-- Verify ResilMesh relationships
MATCH ()-[r]->()
WHERE type(r) IN ['ON', 'TO', 'ASSIGNED_TO', 'HAS_IDENTITY', 'IS_A',
                  'HAS_ASSIGNED', 'PART_OF', 'FOR', 'SUPPORTS',
                  'PROVIDED_BY', 'FROM', 'IS_CONNECTED_TO', 'REFERS_TO',
                  'HAS_CVSSv2', 'HAS_CVSSv30', 'HAS_CVSSv31', 'HAS_CVSSv40']
RETURN type(r) as relationship_type, count(r) as count
ORDER BY count DESC;

-- Verify bridge relationships (planned: Indicator → IP via INDICATOR_RESOLVES_TO,
-- distinct from ISIM's IP → DomainName RESOLVES_TO. The edge is not yet created
-- by EdgeGuard at HEAD — see RESILMESH_INTEROPERABILITY.md § cross-layer bridges.)
-- MATCH (i:Indicator)-[r:INDICATOR_RESOLVES_TO]->(ip:IP)
-- RETURN i.value as indicator, ip.address as resolved_ip;

-- Test enrichment chain (uses CVE → Vulnerability bridge created by
-- enrichment_jobs.bridge_vulnerability_cve)
MATCH (i:Indicator {value: '192.168.1.100'})
OPTIONAL MATCH (i)-[:ATTRIBUTED_TO]->(m:Malware)
OPTIONAL MATCH (i)-[:EXPLOITS]->(v:Vulnerability)-[:REFERS_TO]->(c:CVE)
RETURN i.value, collect(DISTINCT m.name), collect(DISTINCT c.cve_id);

-- Clean up test data
MATCH (n) WHERE n.tag = 'test' DETACH DELETE n;
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

# Check logs
docker logs neo4j

# Verify credentials
echo $NEO4J_PASSWORD
```

#### Issue: Constraint Creation Failed
```
Warning: Constraint creation: Constraint already exists
```
**Solution:**
```cypher
-- List existing constraints
SHOW CONSTRAINTS;

-- Drop and recreate if needed
DROP CONSTRAINT constraint_name IF EXISTS;
```

#### Issue: Alert Processing Slow
```
Enrichment latency > 500ms
```
**Solution:**
```cypher
-- Check for missing indexes
SHOW INDEXES;

-- Analyze query performance
EXPLAIN MATCH (i:Indicator {value: $value})
OPTIONAL MATCH (i)-[:ATTRIBUTED_TO]->(m:Malware)
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
Per the **PR #41 source-truthful architecture** (see
[`migrations/2026_04_first_seen_at_source.md`](../migrations/2026_04_first_seen_at_source.md)),
the node carries only DB-local timestamps; per-source observation
claims live on the `SOURCED_FROM` edge. Do NOT write `first_seen` on
the node — that field was retired because it conflated DB-local
import time with source-claimed first-observation time.

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
    "imported_at":               now,            # set every merge
    "updated_at":                now,            # set every merge
    "source_reported_first_at":  source_first,   # MIN-CASE; may be None
    "source_reported_last_at":   source_last,    # MAX-CASE; may be None
}
```

### 3. Zone Handling
Use multi-zone support for cross-sector threats:
```python
zones = tags if tags else [zone]
data = {
    "zone": zone,       # Primary zone
    "zones": zones      # All applicable zones
}
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

EdgeGuard provides **complete ResilMesh integration** with:

- ✅ **20 node types** from ResilMesh schema
- ✅ **35 relationship types** (78% coverage)
- ✅ **Full bridge layer** between threat intel and topology
- ✅ **Complete alert pipeline** from ingestion to enrichment
- ✅ **Production-ready** constraints and indexes
- ✅ **Comprehensive testing** capabilities

The integration enables **context-aware threat detection** that combines:
- External threat intelligence (CVE, MITRE, IOCs)
- Internal network topology (Hosts, Subnets, Services)
- Mission context (Components, Missions, Org Units)
- Cross-zone correlation (Multi-sector threat detection)

---

*Integration Guide Version: 2.1*  
*For ResilMesh and EdgeGuard Engineers*


---

_Last updated: 2026-04-26 — PR-N33 docs audit: removed calls to deleted `create_cve_has_cvss()` helper (now internal to `merge_cve()` via `_merge_cvss_node`); fixed `RESOLVES_TO` → `INDICATOR_RESOLVES_TO` (planned name avoids ISIM `(IP)-[:RESOLVES_TO]->(DomainName)` collision); updated `HAS_CVSS_v*` → `HAS_CVSSv*` (matches actual edge type names). Prior: 2026-04-18 PR #41 cleanup pass._
