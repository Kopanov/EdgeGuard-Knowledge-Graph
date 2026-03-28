# EdgeGuard Prototype - Collectors
"""
EdgeGuard Threat Intelligence Collectors

This module provides collectors for various threat intelligence sources,
all pushing to MISP as the single source of truth.

Available Collectors:
- AbuseIPDBCollector: IP reputation and blacklist from AbuseIPDB
- ThreatFoxCollector: Malware IOCs from ThreatFox
- URLhausCollector: Malware URLs from URLhaus
- CyberCureCollector: General IOC feeds from CyberCure
- CISACollector: Known Exploited Vulnerabilities from CISA
- MITRECollector: MITRE ATT&CK framework data
- NVDCollector: National Vulnerability Database
- OTXCollector: AlienVault Open Threat Exchange
- VirusTotalCollector: VirusTotal enrichment
- VTCollector: Alternative VirusTotal collector
- MISPCollector: MISP feed collector
- MISPWriter: Pushes indicators to MISP

Sector-Specific Collectors (Placeholders):
- EnergyPlaceholderCollector: Placeholder for E-ISAC feeds (requires membership)
- HealthcarePlaceholderCollector: Placeholder for H-ISAC feeds (requires membership)
- FeodoCollector: Feodo Tracker feeds
- SSLBlacklistCollector: SSL Blacklist feeds

Usage:
    from collectors import AbuseIPDBCollector, ThreatFoxCollector

    # Collect from AbuseIPDB
    abuse_collector = AbuseIPDBCollector()
    indicators = abuse_collector.collect(limit=100)

    # Collect from ThreatFox
    tf_collector = ThreatFoxCollector()
    indicators = tf_collector.collect(limit=100)
"""

# Global threat feed collectors
from collectors.abuseipdb_collector import AbuseIPDBCollector

# Vulnerability and framework collectors
from collectors.cisa_collector import CISACollector

# Sector-specific collectors
from collectors.energy_feed_collector import EnergyCollector, EnergyPlaceholderCollector
from collectors.finance_feed_collector import FeodoCollector, SSLBlacklistCollector
from collectors.global_feed_collector import (
    CyberCureCollector,
    ThreatFoxCollector,
    URLhausCollector,
    collect_all_global_feeds,
)
from collectors.healthcare_feed_collector import HealthcareCollector, HealthcarePlaceholderCollector
from collectors.misp_collector import MISPCollector

# MISP integration
from collectors.misp_writer import MISPWriter
from collectors.mitre_collector import MITRECollector
from collectors.nvd_collector import NVDCollector

# Enrichment collectors
from collectors.otx_collector import OTXCollector
from collectors.virustotal_collector import VirusTotalCollector
from collectors.vt_collector import VTCollector

__all__ = [
    # Global feeds
    "AbuseIPDBCollector",
    "ThreatFoxCollector",
    "URLhausCollector",
    "CyberCureCollector",
    "collect_all_global_feeds",
    # Vulnerability/framework
    "CISACollector",
    "MITRECollector",
    "NVDCollector",
    # Enrichment
    "OTXCollector",
    "VirusTotalCollector",
    "VTCollector",
    # Sector-specific
    "EnergyPlaceholderCollector",
    "EnergyCollector",
    "HealthcarePlaceholderCollector",
    "HealthcareCollector",
    "FeodoCollector",
    "SSLBlacklistCollector",
    # MISP
    "MISPWriter",
    "MISPCollector",
]
