#!/usr/bin/env python3
"""
EdgeGuard - Direct collectors for Finance feeds
Fetches data from abuse.ch feeds and processes to Neo4j
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import csv
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from collectors.collector_utils import (
    RateLimiter,
    is_auth_or_access_denied,
    make_skipped_optional_source,
    make_status,
    request_with_rate_limit_retries,
    retry_with_backoff,
    status_after_misp_push,
)

# Import MISP writer
from collectors.misp_writer import MISPWriter
from config import SSL_VERIFY, detect_zones_from_text, resolve_collection_limit
from resilience import get_circuit_breaker

logger = logging.getLogger(__name__)

# Circuit breakers
FEODO_CIRCUIT_BREAKER = get_circuit_breaker("feodo", failure_threshold=3, recovery_timeout=1800)
SSLBL_CIRCUIT_BREAKER = get_circuit_breaker("sslbl", failure_threshold=3, recovery_timeout=1800)

FEODO_RATE_LIMITER = RateLimiter(min_interval=1.0)
SSLBL_RATE_LIMITER = RateLimiter(min_interval=1.0)

# Feodo Tracker host page of a C2 address. Setting it as the item ``reference`` also makes
# ``MISPWriter`` emit the shared abuse.ch metadata comment (``TF_META``), which is what carries
# ``malware_family`` to MISP and on to ``Indicator.malware_family`` in Neo4j (INDICATES edges).
FEODO_HOST_URL = "https://feodotracker.abuse.ch/browse/host/{ip}/"
# ThreatFox vocabulary for a botnet command-and-control endpoint (same value ThreatFox reports).
FEODO_THREAT_TYPE = "botnet_cc"
FEODO_THREAT_TYPE_DESC = "Botnet Command&Control server (C&C)"
# A C2 that Feodo Tracker reports online is actionable; an offline one is history. The complete
# history loaded by a baseline is almost entirely offline servers (7,979 of 7,980 on 2026-10-12),
# so they are published at low confidence: MISP tag ``confidence:low`` (0.3 in the graph) against
# ``confidence:medium`` (0.5) for online servers. Consumers filter with ``min_confidence``.
# Offline servers are also published with the MISP detection flag cleared (``to_ids=False``):
# abuse.ch states that the complete history causes false positives when used for blocking.
FEODO_CONFIDENCE_ONLINE = 0.7
FEODO_CONFIDENCE_OFFLINE = 0.4


class FeodoCollector:
    """Collects Feodo Tracker Botnet C2 IP Blocklist"""

    # Regular runs: C2 servers active in the last 30 days (abuse.ch "ipblocklist").
    # Baseline runs: the complete C2 history (abuse.ch "aggressive" list, same columns).
    # Both lists are public and need no key; the aggressive list is several
    # thousand rows, the 30-day list a handful, so a fresh baseline seeds the
    # history once and the daily task only adds what is currently active.
    URL_RECENT = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    URL_AGGRESSIVE = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv"

    def __init__(self, misp_writer: MISPWriter = None):
        self.url = self.URL_RECENT
        self.baseline_url = self.URL_AGGRESSIVE
        self.tag = "feodo_tracker"
        self.source_name = "feodo"
        self.misp_writer = misp_writer or MISPWriter()

    def list_url(self, baseline: bool) -> str:
        """URL of the blocklist a run downloads: full history for baselines, 30-day list otherwise."""
        return self.baseline_url if baseline else self.url

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _fetch_raw(self, url: Optional[str] = None) -> str:
        """Download a Feodo blocklist CSV (default: the 30-day list) with retry."""
        response = request_with_rate_limit_retries(
            "GET",
            url or self.url,
            session=None,
            timeout=30,
            verify=SSL_VERIFY,
            max_rate_limit_retries=3,
            fallback_delay_sec=30.0,
            retry_on_403=False,
            context="Feodo",
        )
        response.raise_for_status()
        return response.text

    def collect(
        self, limit=None, push_to_misp=True, baseline: bool = False, baseline_days: int = 365
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Fetch and parse Feodo blocklist. Returns status dict when ``push_to_misp=True``."""
        # Baseline runs download the complete C2 history (aggressive list); regular
        # runs the 30-day list. Same columns, so one parser serves both.
        list_url = self.list_url(baseline)
        if baseline:
            logger.info("📜 Baseline mode: downloading the full Feodo C2 history (%s)", list_url)
        else:
            logger.info("Feodo: downloading C2 servers active in the last 30 days (%s)", list_url)

        # Check circuit breaker
        if not FEODO_CIRCUIT_BREAKER.can_execute():
            logger.warning("Feodo circuit breaker open - skipping")
            if push_to_misp:
                return make_status("feodo", False, count=0, error="Circuit breaker open")
            return []

        # Rate limiting
        FEODO_RATE_LIMITER.wait_if_needed()

        limit = resolve_collection_limit(limit, "feodo", baseline=baseline)
        try:
            raw_text = self._fetch_raw(list_url)

            # Parse with the csv module: every field is quoted and the download uses CRLF line
            # endings. (A hand-rolled split left the last column as ``QakBot"\r``.) Comment
            # lines start with ``#``; the header row is recognised by its first column name.
            data_lines = [ln for ln in raw_text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]

            results = []
            online = 0
            for row in csv.reader(data_lines):
                if limit is not None and len(results) >= limit:
                    break

                parts = [field.strip() for field in row]
                if len(parts) < 5 or parts[0].lower() == "first_seen_utc":
                    continue

                first_seen, dst_ip, dst_port, c2_status, last_online = parts[:5]
                malware = parts[5] if len(parts) > 5 else ""

                if not dst_ip:
                    continue

                status = c2_status.lower()
                is_online = status == "online"
                online += 1 if is_online else 0

                # Zones come from the conservative keyword detector on the family name; malware
                # families are linked to sectors through graph relationships, not keywords.
                zones = detect_zones_from_text(malware.lower())

                # Labels that survive the MISP round-trip (TF_META.tags -> Indicator.tf_tags).
                labels = [f"c2_status:{status}"] if status else []
                if dst_port:
                    labels.append(f"port:{dst_port}")
                if last_online:
                    labels.append(f"last_online:{last_online}")

                results.append(
                    {
                        "indicator_type": "ipv4",
                        "value": dst_ip,
                        "zone": zones,  # zone is now an array
                        "tag": self.tag,
                        "source": [self.tag],
                        "first_seen": first_seen,
                        "last_updated": datetime.now(timezone.utc).isoformat(),
                        "confidence_score": FEODO_CONFIDENCE_ONLINE if is_online else FEODO_CONFIDENCE_OFFLINE,
                        "to_ids": is_online,  # history is knowledge, not a detection candidate
                        "malware_family": malware,  # source spelling; graph matching is case-insensitive
                        "port": dst_port,
                        "status": c2_status,
                        "last_online": last_online,  # C2 actuality - active vs stale
                        "reference": FEODO_HOST_URL.format(ip=dst_ip),
                        "threat_type": FEODO_THREAT_TYPE,
                        "threat_type_desc": FEODO_THREAT_TYPE_DESC,
                        "tags": labels,
                    }
                )

            logger.info(
                f"[OK] Feodo: Collected {len(results)} C&C servers ({online} online, {len(results) - online} offline)"
            )
            if not results:
                logger.warning("Feodo returned 0 C&C servers — check feed availability")

            FEODO_CIRCUIT_BREAKER.record_success()
            if push_to_misp:
                if not results:
                    return make_status("feodo", True, count=0, failed=0)
                success, failed = self.misp_writer.push_indicators(results, self.source_name)
                logger.info(f"[PUSH] Feodo: Pushed {success} to MISP ({failed} failed)")
                return status_after_misp_push("feodo", len(results), success, failed)
            return results

        except Exception as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"Feodo: auth/access denied — skipping (optional public feed): {e}")
                FEODO_CIRCUIT_BREAKER.record_success()
                return make_skipped_optional_source(
                    "feodo",
                    skip_reason=str(e),
                    skip_reason_class="feodo_auth_denied",
                )
            logger.error(f"Feodo collection error: {e}")
            FEODO_CIRCUIT_BREAKER.record_failure()
            return make_status("feodo", False, count=0, error=str(e)) if push_to_misp else []


class SSLBlacklistCollector:
    """Collects SSL Blacklist from abuse.ch"""

    def __init__(self, misp_writer: MISPWriter = None):
        self.url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
        self.tag = "ssl_blacklist"
        self.source_name = "sslbl"
        self.misp_writer = misp_writer or MISPWriter()

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _fetch_raw(self) -> str:
        """Download the SSL Blacklist CSV with retry."""
        response = request_with_rate_limit_retries(
            "GET",
            self.url,
            session=None,
            timeout=30,
            verify=SSL_VERIFY,
            max_rate_limit_retries=3,
            fallback_delay_sec=30.0,
            retry_on_403=False,
            context="SSLBL",
        )
        response.raise_for_status()
        return response.text

    def collect(
        self, limit=None, push_to_misp=True, baseline: bool = False, baseline_days: int = 365
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Fetch and parse SSL blacklist. Returns status dict when ``push_to_misp=True``."""
        # SSL Blacklist is a bulk download - baseline doesn't change much
        if baseline:
            logger.info("📜 Baseline mode: Collecting all SSL Blacklist data...")

        # Check circuit breaker
        if not SSLBL_CIRCUIT_BREAKER.can_execute():
            logger.warning("SSL Blacklist circuit breaker open - skipping")
            if push_to_misp:
                return make_status("sslbl", False, count=0, error="Circuit breaker open")
            return []

        # Rate limiting
        SSLBL_RATE_LIMITER.wait_if_needed()

        limit = resolve_collection_limit(limit, "sslbl", baseline=baseline)
        try:
            raw_text = self._fetch_raw()

            # Parse CSV - skip comments and header
            lines = [ln for ln in raw_text.strip().split("\n") if ln and not ln.startswith("#")]

            results = []
            for i, line in enumerate(lines[1:]):  # Skip header
                if limit is not None and i >= limit:
                    break

                parts = line.split(",")
                if len(parts) < 3:
                    continue

                date = parts[0].strip().strip('"')
                sha1 = parts[1].strip().strip('"')
                reason = parts[2].strip().strip('"').lower()

                if not sha1:
                    continue

                # Determine ALL zones from reason using common detection
                zones = detect_zones_from_text(reason)

                results.append(
                    {
                        "indicator_type": "sha1",  # SSL cert fingerprint
                        "value": sha1,
                        "zone": zones,  # zone is now an array
                        "tag": self.tag,
                        "source": [self.tag],
                        "first_seen": date,
                        "last_updated": datetime.now(timezone.utc).isoformat(),
                        "confidence_score": 0.6,
                        "listing_reason": reason,
                    }
                )

            logger.info(f"[OK] SSL Blacklist: Collected {len(results)} SSL certs")
            if not results:
                logger.warning("SSL Blacklist returned 0 certs — check feed availability")

            SSLBL_CIRCUIT_BREAKER.record_success()
            if push_to_misp:
                if not results:
                    return make_status("sslbl", True, count=0, failed=0)
                success, failed = self.misp_writer.push_indicators(results, self.source_name)
                logger.info(f"[PUSH] SSL Blacklist: Pushed {success} to MISP ({failed} failed)")
                return status_after_misp_push("sslbl", len(results), success, failed)
            return results

        except Exception as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"SSL Blacklist: auth/access denied — skipping (optional public feed): {e}")
                SSLBL_CIRCUIT_BREAKER.record_success()
                return make_skipped_optional_source(
                    "sslbl",
                    skip_reason=str(e),
                    skip_reason_class="sslbl_auth_denied",
                )
            logger.error(f"SSL Blacklist collection error: {e}")
            SSLBL_CIRCUIT_BREAKER.record_failure()
            return make_status("sslbl", False, count=0, error=str(e)) if push_to_misp else []


def test():
    """Test collectors"""
    print("=== Testing Feodo Collector ===")
    feodo = FeodoCollector()
    data = feodo.collect(limit=10, push_to_misp=False)
    print(f"Collected: {len(data)}")
    for item in data[:3]:
        print(f"  {item['value']} ({item.get('malware_family')})")

    print("\n=== Testing SSL Blacklist Collector ===")
    ssl = SSLBlacklistCollector()
    data = ssl.collect(limit=10, push_to_misp=False)
    print(f"Collected: {len(data)}")
    for item in data[:3]:
        print(f"  {item['value'][:30]}... ({item.get('listing_reason')})")


if __name__ == "__main__":
    test()
