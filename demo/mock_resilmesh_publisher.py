#!/usr/bin/env python3
"""
Mock ResilMesh Publisher
Simulates NATS messages from ResilMesh for demo purposes.

Usage:
    python mock_resilmesh_publisher.py
    
The script simulates:
1. A threat alert from ResilMesh
2. EdgeGuard receives it via NATS subscription
3. EdgeGuard queries Neo4j for enrichment
4. Returns enriched response

This is for demonstration only - doesn't require actual NATS server.
"""

import json
import time
import random
import asyncio
from datetime import datetime, timezone


# Sample threat data that simulates Wazuh/ResilMesh alerts
SAMPLE_ALERTS = [
    # Healthcare Scenarios
    {
        "alert_id": "wazuh-001",
        "source": "wazuh",
        "zone": "healthcare",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "192.168.1.100",
            "type": "ip",
            "malware": "TrickBot",
            "cve": "CVE-2021-43297",
            "description": "Suspected TrickBot C2 communication detected",
            "severity": 9,
            "source_ip": "192.168.1.100",
            "dest_ip": "185.220.101.45",
            "hostname": "hospital-server-01",
            "user": "admin"
        }
    },
    {
        "alert_id": "wazuh-002",
        "source": "wazuh",
        "zone": "healthcare",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "meddevice-c2.evil.com",
            "type": "domain",
            "malware": "Medjack",
            "cve": "CVE-2019-0708",
            "description": "Medical device command and control detected",
            "severity": 10,
            "device_type": "MRI Scanner",
            "hostname": "mri-scanner-01"
        }
    },
    {
        "alert_id": "wazuh-003",
        "source": "wazuh",
        "zone": "healthcare",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "75c8e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
            "type": "file_hash",
            "malware": "Ransomware",
            "cve": "CVE-2024-21412",
            "description": "Encrypted health records detected",
            "severity": 10,
            "affected_files": 15000,
            "ransom_demand": "50 BTC"
        }
    },
    
    # Energy/ICS Scenarios
    {
        "alert_id": "wazuh-004",
        "source": "wazuh", 
        "zone": "energy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "evil-energy-attack.com",
            "type": "domain",
            "malware": "Industroyer2",
            "cve": "CVE-2022-26377",
            "description": "ICS protocol anomaly detected",
            "severity": 10,
            "protocol": "IEC61850",
            "device": "RTU-001",
            "substation": "SUB-NORTH-01"
        }
    },
    {
        "alert_id": "wazuh-005",
        "source": "wazuh",
        "zone": "energy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "scada-attack.evil.net",
            "type": "domain",
            "malware": "CrashOverride",
            "cve": "CVE-2020-15368",
            "description": "SCADA system compromise detected",
            "severity": 10,
            "protocol": "Modbus",
            "plc": "Siemens S7-1200"
        }
    },
    {
        "alert_id": "wazuh-006",
        "source": "wazuh",
        "zone": "energy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "10.0.100.50",
            "type": "ip",
            "malware": "Triton",
            "cve": "CVE-2017-14491",
            "description": "Safety system targeted",
            "severity": 10,
            "target": "Safety Instrumented System",
            "plant_area": "Zone A"
        }
    },
    
    # Finance Scenarios
    {
        "alert_id": "wazuh-007",
        "source": "wazuh",
        "zone": "finance",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "bancos-stealer.exe",
            "type": "file_hash",
            "malware": "BankingTrojan",
            "sha256": "a1b2c3d4e5f6789012345678901234567890abcd1234567890efgh1234567890ij",
            "description": "Suspicious banking trojan detected",
            "severity": 8,
            "process": "svchost.exe",
            "target_app": "notepad.exe"
        }
    },
    {
        "alert_id": "wazuh-008",
        "source": "wazuh",
        "zone": "finance",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "swift-fraud.evil.com",
            "type": "domain",
            "malware": "Carbanak",
            "cve": "CVE-2019-16278",
            "description": "SWIFT transaction anomaly",
            "severity": 10,
            "transaction_id": "TXN-2026-001",
            "amount": "5000000 USD"
        }
    },
    {
        "alert_id": "wazuh-009",
        "source": "wazuh",
        "zone": "finance",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "pos-malware.evil.net",
            "type": "domain",
            "malware": "Backoff",
            "cve": "CVE-2013-4002",
            "description": "POS malware detected",
            "severity": 9,
            "target": "Payment Terminal",
            "card_data_compromised": 1500
        }
    },
    
    # Global/Cross-Zone Scenarios
    {
        "alert_id": "wazuh-010",
        "source": "wazuh",
        "zone": "global",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "emotet-payload.exe",
            "type": "file_hash",
            "malware": "Emotet",
            "cve": "CVE-2019-2725",
            "description": "Widespread ransomware dropper",
            "severity": 9,
            "propagation": "Email attachments",
            "affects": ["healthcare", "energy", "finance"]
        }
    },
    
    # === MULTI-ZONE TEST SCENARIOS ===
    # These test the multi-zone detection feature
    
    # Healthcare → Finance (medical billing systems)
    {
        "alert_id": "multizone-001",
        "source": "wazuh",
        "zone": "healthcare",  # Primary zone
        "tags": ["healthcare", "finance"],  # Multi-zone tags
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "medbilling-c2.evil.com",
            "type": "domain",
            "malware": "TrickBot",
            "cve": "CVE-2021-44228",
            "description": "Medical billing system compromised, affects finance reporting",
            "severity": 9,
            "primary_zone": "healthcare",
            "cross_zone_impact": ["finance"],
            "affected_system": "Epic EHR - Billing Module",
            "patient_data_at_risk": True
        }
    },
    
    # Energy → Finance (grid operators trading)
    {
        "alert_id": "multizone-002",
        "source": "wazuh",
        "zone": "energy",
        "tags": ["energy", "finance"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "grid-trading-c2.evil.net",
            "type": "domain",
            "malware": "Industroyer",
            "cve": "CVE-2022-26377",
            "description": "Energy grid trading systems targeted",
            "severity": 10,
            "primary_zone": "energy",
            "cross_zone_impact": ["finance"],
            "affected_system": "Energy Trading Platform",
            "electricity_market_impact": True
        }
    },
    
    # Finance → Healthcare (insurance payments)
    {
        "alert_id": "multizone-003",
        "source": "wazuh",
        "zone": "finance",
        "tags": ["finance", "healthcare"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "insurance-fraud-c2.evil.com",
            "type": "ip",
            "malware": "Carbanak",
            "cve": "CVE-2020-1472",
            "description": "Insurance payment processor targeted",
            "severity": 8,
            "primary_zone": "finance",
            "cross_zone_impact": ["healthcare"],
            "affected_system": "Insurance Claims System",
            "claims_at_risk": 50000
        }
    },
    
    # All Three Zones
    {
        "alert_id": "multizone-004",
        "source": "wazuh",
        "zone": "global",
        "tags": ["healthcare", "energy", "finance", "global"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat": {
            "indicator": "apt29-c2.evil.net",
            "type": "domain",
            "malware": "CozyDuke",
            "cve": "CVE-2021-34527",
            "description": "APT29 campaign targeting critical infrastructure",
            "severity": 10,
            "primary_zone": "global",
            "cross_zone_impact": ["healthcare", "energy", "finance"],
            "affected_sectors": ["healthcare", "energy", "finance"],
            "nation_state": "Russia"
        }
    }
]


class MockNATSServer:
    """Mock NATS server for demonstration"""
    
    def __init__(self):
        self.subscribers = {}
        self.published_messages = []
    
    async def publish(self, subject: str, data: bytes):
        """Simulate publishing to a subject"""
        message = json.loads(data.decode())
        self.published_messages.append({
            'subject': subject,
            'data': message,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        print(f"\n📤 NATS PUBLISH: {subject}")
        print(f"   Payload: {json.dumps(message, indent=2)[:200]}...")
        for pattern, callback in self.subscribers.items():
            pattern_parts = pattern.split('.')
            subject_parts = subject.split('.')
            if len(pattern_parts) == len(subject_parts) and all(
                p == s or p == '*' for p, s in zip(pattern_parts, subject_parts)
            ):
                await callback(message)
        return True
    
    async def subscribe(self, subject: str, callback):
        """Simulate subscription"""
        self.subscribers[subject] = callback
        print(f"📥 NATS SUBSCRIBE: {subject}")
        return True


class EdgeGuardDemo:
    """Demo of EdgeGuard receiving and processing NATS messages"""
    
    def __init__(self, nats_client):
        self.nats_client = nats_client
        self.neo4j_queries = []
    
    async def process_alert(self, alert: dict):
        """Process a threat alert from NATS"""
        zone = alert.get('zone', 'global')
        threat = alert.get('threat', {})
        indicator = threat.get('indicator')
        
        print(f"\n{'='*60}")
        print(f"🎯 EdgeGuard Received Alert: {alert['alert_id']}")
        print(f"{'='*60}")
        print(f"📍 Zone: {zone}")
        print(f"🔍 Indicator: {indicator}")
        print(f"🦠 Malware: {threat.get('malware', 'Unknown')}")
        print(f"🔢 CVE: {threat.get('cve', 'N/A')}")
        
        # Simulate Neo4j enrichment query
        print(f"\n🔎 Querying Neo4j...")
        query = f"""
        MATCH (i:Indicator {{value: '{indicator}'}})
        OPTIONAL MATCH (i)-[:ATTRIBUTED_TO]->(s:Source)
        OPTIONAL MATCH (i)-[:USES]->(t:Technique)
        RETURN i.value as indicator, s.name as source, 
               t.name as technique, i.confidence_score as confidence
        """
        
        self.neo4j_queries.append({
            'indicator': indicator,
            'zone': zone,
            'query': query
        })
        
        # Handle multi-zone detection
        cross_zone_impact = threat.get('cross_zone_impact', [])
        tags = alert.get('tags', [])
        
        # If tags contain multiple zones, use them
        if tags and any(t in ['healthcare', 'energy', 'finance', 'global'] for t in tags):
            sectors_affected = [t for t in tags if t in ['healthcare', 'energy', 'finance', 'global']]
        elif cross_zone_impact:
            sectors_affected = [zone] + cross_zone_impact
        else:
            sectors_affected = [zone, 'global'] if random.random() > 0.5 else [zone]
        
        # Simulate enriched response
        enriched = {
            'original_alert': alert,
            'enrichment': {
                'indicator': indicator,
                'known_malware': random.choice([True, False]),
                'confidence': round(random.uniform(0.6, 0.95), 2),
                'related_cves': [threat.get('cve', 'N/A')] if threat.get('cve') else [],
                'related_techniques': self._get_mock_techniques(threat.get('malware', '')),
                'sectors_affected': sectors_affected,
                'primary_zone': zone,
                'cross_zone_detected': len(sectors_affected) > 1,
                'first_seen': f"2025-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
                'last_updated': datetime.now(timezone.utc).isoformat(),
                'threat_actor': self._get_mock_actor(threat.get('malware', '')),
                'recommendations': self._get_recommendations(threat)
            }
        }
        
        # Highlight multi-zone detection
        if len(sectors_affected) > 1:
            print(f"\n🌐 MULTI-ZONE DETECTED!")
            print(f"   Primary Zone: {zone}")
            print(f"   Affected Zones: {sectors_affected}")
        
        print(f"✅ Neo4j Query Complete!")
        print(f"\n📊 ENRICHED RESPONSE:")
        print(json.dumps(enriched['enrichment'], indent=2))
        
        return enriched
    
    def _get_mock_techniques(self, malware: str) -> list:
        """Mock technique mapping"""
        mappings = {
            'TrickBot': ['T1071 - Application Layer Protocol', 'T1082 - System Information Discovery'],
            'Industroyer2': ['T0856 - Modify Control Logic', 'T0849 - Long Duration Code Execution'],
            'BankingTrojan': ['T1056 - Input Capture', 'T1003 - OS Credential Dumping'],
        }
        return mappings.get(malware, ['T1566 - Phishing'])
    
    def _get_mock_actor(self, malware: str) -> str:
        """Mock threat actor mapping"""
        actors = {
            'TrickBot': 'Wizards Spider',
            'Industroyer2': 'Sandworm Team',
            'BankingTrojan': 'Carbanak',
        }
        return actors.get(malware, 'Unknown APT')
    
    def _get_recommendations(self, threat: dict) -> list:
        """Get security recommendations"""
        return [
            f"Block indicator {threat.get('indicator')} at perimeter",
            f"Check {threat.get('hostname', 'affected host')} for compromise indicators",
            f"Review logs for related IOCs from past 30 days",
            f"Apply patch for {threat.get('cve', 'related CVE')}" if threat.get('cve') else None
        ]


async def run_demo():
    """Run the complete demo"""
    print("""
███████╗██████╗  ██████╗ ███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██╔════╝██╔══██╗██╔════╝ ██╔════╝██╔════╝ ██╗   ██║██╔══██╗██╔══██╗██╔══██╗
█████╗  ██║  ██║██║  ███╗█████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔══╝  ██║  ██║██║   ██║██╔══╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
███████╗██████╔╝╚██████╔╝███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚══════╝╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝

Graph-Augmented xAI for Threat Intelligence on Edge Infrastructure
IICT-BAS + Ratio1 | financed by ResilMesh - open call 2

╔══════════════════════════════════════════════════════════════╗
║          EdgeGuard + ResilMesh Integration Demo              ║
║                                                              ║
║  This demo simulates:                                        ║
║  1. ResilMesh sends threat alert via NATS                    ║
║  2. EdgeGuard subscribes to zone.alerts.*                    ║
║  3. EdgeGuard queries Neo4j for enrichment                   ║
║  4. Returns enriched threat intelligence                     ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Create mock NATS
    nats = MockNATSServer()
    
    # Create EdgeGuard demo
    edgeguard = EdgeGuardDemo(nats)
    
    # Subscribe to zone alerts
    print("\n📡 Subscribing to ResilMesh alert topics...")
    await nats.subscribe("resilmesh.alerts.zone.*", edgeguard.process_alert)
    
    # Give time for subscription
    await asyncio.sleep(0.5)
    
    # Publish sample alerts
    print("\n" + "="*60)
    print("🚀 Publishing sample ResilMesh alerts...")
    print("="*60)
    
    for alert in SAMPLE_ALERTS:
        subject = f"resilmesh.alerts.zone.{alert['zone']}"
        await nats.publish(subject, json.dumps(alert).encode())
        await asyncio.sleep(1)  # Brief pause between alerts
    
    # Summary
    print("\n" + "="*60)
    print("📊 DEMO SUMMARY")
    print("="*60)
    print(f"Messages published: {len(SAMPLE_ALERTS)}")
    print(f"Neo4j queries simulated: {len(edgeguard.neo4j_queries)}")
    print("\n✅ Demo complete!")
    print("\nIn production:")
    print("  1. Real NATS server replaces MockNATSServer")
    print("  2. Actual Neo4j queries replace mock queries")  
    print("  3. Real-time enrichment from live database")


if __name__ == "__main__":
    asyncio.run(run_demo())
