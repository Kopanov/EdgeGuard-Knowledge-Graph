#!/usr/bin/env python3
"""
EdgeGuard - Direct collectors for Finance feeds
Fetches data from abuse.ch feeds and processes to Neo4j
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Union

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


class FeodoCollector:
    """Collects Feodo Tracker Botnet C2 IP Blocklist"""

    def __init__(self, misp_writer: MISPWriter = None):
        self.url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
        self.tag = "feodo_tracker"
        self.source_name = "feodo"
        self.misp_writer = misp_writer or MISPWriter()

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _fetch_raw(self) -> str:
        """Download the Feodo blocklist CSV with retry."""
        response = request_with_rate_limit_retries(
            "GET",
            self.url,
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
        # Feodo is a bulk download - baseline doesn't change much
        if baseline:
            logger.info("📜 Baseline mode: Collecting all Feodo data...")

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
            raw_text = self._fetch_raw()

            # Parse CSV - skip comment lines and header
            lines = [ln for ln in raw_text.strip().split("\n") if ln and not ln.startswith("#")]

            results = []
            for i, line in enumerate(lines[1:]):  # Skip header row
                if limit is not None and i >= limit:
                    break

                parts = line.split('","')
                if len(parts) < 5:
                    continue

                # Clean up quotes
                first_seen = parts[0].strip('"')
                dst_ip = parts[1].strip('"')
                dst_port = parts[2].strip('"')
                c2_status = parts[3].strip('"')
                last_online = parts[4].strip('"')
                malware = parts[5].strip('"') if len(parts) > 5 else ""

                if not dst_ip:
                    continue

                malware = malware.lower()

                # Feodo = banking trojans, but detect all matching zones
                zones = detect_zones_from_text(malware)

                results.append(
                    {
                        "indicator_type": "ipv4",
                        "value": dst_ip,
                        "zone": zones,  # zone is now an array
                        "tag": self.tag,
                        "source": [self.tag],
                        "first_seen": first_seen,
                        "last_updated": datetime.now(timezone.utc).isoformat(),
                        "confidence_score": 0.7,
                        "malware_family": malware,
                        "port": dst_port,
                        "status": c2_status,
                        "last_online": last_online,  # C2 actuality - active vs stale
                    }
                )

            logger.info(f"[OK] Feodo: Collected {len(results)} C&C servers")

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
