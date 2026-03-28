# EdgeGuard Demo

Demonstration scripts live in the repository **`demo/`** directory (repo root).

---

## Available Demos

### Mock ResilMesh Publisher

Simulates NATS messages from ResilMesh and demonstrates EdgeGuard's alert processing.

```bash
cd EdgeGuard-Knowledge-Graph/demo   # repo root
python mock_resilmesh_publisher.py
```

**What it demonstrates:**
1. ResilMesh alert received via NATS
2. Zone-based topic subscription
3. Neo4j query for enrichment
4. Enriched threat response

**Sample Output:**
```
🎯 EdgeGuard Received Alert: wazuh-001
📍 Zone: healthcare
🔍 Indicator: 192.168.1.100
🦠 Malware: TrickBot
🔢 CVE: CVE-2021-43297

🔎 Querying Neo4j...
✅ Neo4j Query Complete!

📊 ENRICHED RESPONSE:
{
  "indicator": "192.168.1.100",
  "known_malware": true,
  "confidence": 0.87,
  "related_cves": ["CVE-2021-43297"],
  "related_techniques": ["T1071 - Application Layer Protocol"],
  "sectors_affected": ["healthcare", "global"],
  "threat_actor": "Wizards Spider"
}
```

## Demo Scenarios (10 total)

### Healthcare Zone (3 scenarios)
| ID | Threat | Indicator | CVE |
|----|---------|-----------|-----|
| wazuh-001 | TrickBot C2 | 192.168.1.100 | CVE-2021-43297 |
| wazuh-002 | Medjack | meddevice-c2.evil.com | CVE-2019-0708 |
| wazuh-003 | Ransomware | SHA256 hash | CVE-2024-21412 |

### Energy Zone (3 scenarios)
| ID | Threat | Indicator | CVE |
|----|---------|-----------|-----|
| wazuh-004 | Industroyer2 | evil-energy-attack.com | CVE-2022-26377 |
| wazuh-005 | CrashOverride | scada-attack.evil.net | CVE-2020-15368 |
| wazuh-006 | Triton | 10.0.100.50 | CVE-2017-14491 |

### Finance Zone (3 scenarios)
| ID | Threat | Indicator | CVE |
|----|---------|-----------|-----|
| wazuh-007 | Banking Trojan | SHA256 hash | - |
| wazuh-008 | Carbanak | swift-fraud.evil.com | CVE-2019-16278 |
| wazuh-009 | Backoff POS | pos-malware.evil.net | CVE-2013-4002 |

### Global/Cross-Zone (1 scenario)
| ID | Threat | Indicator | CVE | Affects |
|----|---------|-----------|-----|---------|
| wazuh-010 | Emotet | emotet-payload.exe | CVE-2019-2725 | All zones |

### Multi-Zone Test Scenarios (4 scenarios)
These specifically test the cross-zone detection feature:

| ID | Primary Zone | Cross-Zone Impact | Threat |
|----|--------------|-------------------|--------|
| multizone-001 | Healthcare | Finance | TrickBot (billing) |
| multizone-002 | Energy | Finance | Industroyer (trading) |
| multizone-003 | Finance | Healthcare | Carbanak (insurance) |
| multizone-004 | Global | All 3 zones | APT29 (nation-state) |

**Multi-Zone Output Example:**
```
🌐 MULTI-ZONE DETECTED!
   Primary Zone: healthcare
   Affected Zones: ['healthcare', 'finance']
```

## Extending Demos

Add more scenarios to `mock_resilmesh_publisher.py`:
```python
SAMPLE_ALERTS.append({
    "alert_id": "custom-001",
    "zone": "your_zone",
    "threat": { ... }
})
```
