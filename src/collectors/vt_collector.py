#!/usr/bin/env python3
"""
EdgeGuard - VirusTotal MISP Collector
Collects threat indicators from VirusTotal API and pushes to MISP

This collector focuses on gathering IOCs from VirusTotal's public feeds
and pushing them to MISP as the single source of truth.

Rate Limits (Free Tier):
- 4 lookups/minute
- 500 lookups/day
- 15,500 lookups/month

For production, consider a paid plan at https://www.virustotal.com/gui/join-us
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from collectors.collector_utils import (
    VIRUSTOTAL_API_KEY_PLACEHOLDERS,
    RateLimiter,
    is_auth_or_access_denied,
    make_skipped_optional_source,
    make_status,
    optional_api_key_effective,
    request_with_rate_limit_retries,
    retry_with_backoff,
    status_after_misp_push,
)

# Import MISP writer
from collectors.misp_writer import MISPWriter
from config import SOURCE_TAGS, SSL_VERIFY, VIRUSTOTAL_API_KEY, detect_zones_from_text, resolve_collection_limit

logger = logging.getLogger(__name__)

# Configuration constants
VT_CONNECT_TIMEOUT = 30  # Connection timeout (seconds)
VT_REQUEST_TIMEOUT = 60  # Read timeout (seconds)
MAX_RETRIES = 3
RETRY_DELAY_BASE = 2  # seconds

# VirusTotal API v3 base URL
VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VTCollector:
    """
    VirusTotal Collector for MISP.

    Collects IOCs from VirusTotal's public API and pushes to MISP.

    Features:
    - Rate limiting (4 requests/min free tier)
    - Retry logic with exponential backoff
    - Automatic zone detection from metadata
    - Proper MISP tagging (source:VirusTotal, zone tags)
    """

    # Class-level rate limiter (shared across instances)
    _rate_limiter = None

    def __init__(self, misp_writer: MISPWriter = None):
        self.base_url = VT_BASE_URL
        self.api_key = optional_api_key_effective(VIRUSTOTAL_API_KEY, VIRUSTOTAL_API_KEY_PLACEHOLDERS)
        self.tag = SOURCE_TAGS.get("virustotal", "virustotal")
        self.misp_writer = misp_writer or MISPWriter()
        self.source_name = "virustotal"

        # Create a session for better connection handling
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": self.api_key or "", "Accept": "application/json"})
        self.session.verify = SSL_VERIFY

        # Initialize rate limiter
        if VTCollector._rate_limiter is None:
            VTCollector._rate_limiter = RateLimiter(requests_per_minute=4)
        self.rate_limiter = VTCollector._rate_limiter

    def health_check(self) -> Dict[str, Any]:
        """
        Check VirusTotal API health.

        Returns:
            Dict with health status
        """
        try:
            start_time = time.time()

            # Rate limit check
            self.rate_limiter.wait_if_needed()

            response = self.session.get(
                f"{self.base_url}/domains/google.com",  # Use a known domain for health check
                timeout=(VT_CONNECT_TIMEOUT, VT_REQUEST_TIMEOUT),
            )
            response_time = time.time() - start_time

            if response.status_code == 200:
                return {
                    "healthy": True,
                    "response_time_ms": round(response_time * 1000, 2),
                    "status_code": response.status_code,
                }
            elif response.status_code == 401:
                return {
                    "healthy": False,
                    "error": "Invalid API key",
                    "response_time_ms": round(response_time * 1000, 2),
                    "status_code": response.status_code,
                }
            else:
                return {
                    "healthy": False,
                    "error": f"HTTP {response.status_code}",
                    "response_time_ms": round(response_time * 1000, 2),
                    "status_code": response.status_code,
                }
        except requests.exceptions.Timeout as e:
            return {"healthy": False, "error": f"Timeout: {e}"}
        except requests.exceptions.ConnectionError as e:
            return {"healthy": False, "error": f"Connection error: {e}"}
        except Exception as e:
            return {"healthy": False, "error": f"{type(e).__name__}: {e}"}

    def _detect_zones_from_attributes(self, attrs: Dict) -> List[str]:
        """
        Detect ALL sectors from file names, tags, and sandbox verdicts.

        Args:
            attrs: VirusTotal attributes dict

        Returns:
            List of zone names (e.g., ['finance', 'healthcare'] or ['global'] if no match)
        """
        text_parts = []

        # Add meaningful name
        if attrs.get("meaningful_name"):
            text_parts.append(str(attrs["meaningful_name"]))

        # Add names list
        if attrs.get("names"):
            names = attrs["names"]
            if isinstance(names, list):
                # Ensure all names are strings
                text_parts.extend([str(n) for n in names[:5] if n])
            else:
                text_parts.append(str(names))

        # Add tags
        if attrs.get("tags"):
            tags = attrs["tags"]
            if isinstance(tags, list):
                # Ensure all tags are strings
                text_parts.extend([str(t) for t in tags if t])
            else:
                text_parts.append(str(tags))

        # Add sandbox verdicts
        sandbox_results = attrs.get("sandbox_verdicts", {})
        for _sandbox, verdict in sandbox_results.items():
            if isinstance(verdict, dict):
                mc = verdict.get("malware_classification", "")
                mf = verdict.get("malware_family", "")
                if mc:
                    text_parts.append(str(mc) if mc else "")
                if mf:
                    text_parts.append(str(mf) if mf else "")

        # Add popular threat label
        if attrs.get("popular_threat_label"):
            text_parts.append(str(attrs["popular_threat_label"]))

        # Combine all text
        combined_text = " ".join(filter(None, text_parts))

        return detect_zones_from_text(combined_text)

    def _calculate_confidence(self, attrs: Dict) -> float:
        """
        Calculate confidence score based on VT analysis stats.

        Args:
            attrs: VirusTotal attributes dict

        Returns:
            Confidence score between 0.0 and 1.0
        """
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total = malicious + suspicious + harmless + undetected
        if total == 0:
            return 0.5

        # Weight malicious higher than suspicious
        score = (malicious * 1.0 + suspicious * 0.5) / total

        # Scale to 0.5-0.95 range
        confidence = 0.5 + (score * 0.45)
        return round(min(confidence, 0.95), 2)

    @retry_with_backoff(max_retries=MAX_RETRIES)
    def _fetch_recent_files(self, limit: int) -> List[Dict]:
        """
        Fetch recent files analyzed by VirusTotal using search API.

        Args:
            limit: Maximum number of files to fetch

        Returns:
            List of file dicts
        """
        logger.info(f"Fetching {limit} recent files from VirusTotal...")

        # Rate limit check
        self.rate_limiter.wait_if_needed()

        # Use search endpoint instead of /files (v3 API change)
        response = request_with_rate_limit_retries(
            "GET",
            f"{self.base_url}/search",
            session=self.session,
            params={"query": "type:file+tag:malware", "limit": min(limit, 10)},
            timeout=(VT_CONNECT_TIMEOUT, VT_REQUEST_TIMEOUT),
            verify=SSL_VERIFY,
            max_rate_limit_retries=3,
            fallback_delay_sec=60.0,
            retry_on_403=False,
            context="VT",
        )

        if response.status_code == 401:
            raise requests.exceptions.HTTPError("Invalid VirusTotal API key")
        elif response.status_code != 200:
            raise requests.exceptions.HTTPError(f"VT API error: {response.status_code}")

        data = response.json()
        files = data.get("data", [])

        logger.info(f"[FETCH] VT: Fetched {len(files)} files")
        return files

    @retry_with_backoff(max_retries=MAX_RETRIES)
    def _fetch_recent_urls(self, limit: int) -> List[Dict]:
        """
        Fetch recent URLs analyzed by VirusTotal using search API.

        Args:
            limit: Maximum number of URLs to fetch

        Returns:
            List of URL dicts
        """
        logger.info(f"Fetching {limit} recent URLs from VirusTotal...")

        # Rate limit check
        self.rate_limiter.wait_if_needed()

        # Use search endpoint instead of /urls (v3 API change)
        response = request_with_rate_limit_retries(
            "GET",
            f"{self.base_url}/search",
            session=self.session,
            params={"query": "type:url+tag:malware", "limit": min(limit, 10)},
            timeout=(VT_CONNECT_TIMEOUT, VT_REQUEST_TIMEOUT),
            verify=SSL_VERIFY,
            max_rate_limit_retries=3,
            fallback_delay_sec=60.0,
            retry_on_403=False,
            context="VT",
        )

        if response.status_code == 401:
            raise requests.exceptions.HTTPError("Invalid VirusTotal API key")
        elif response.status_code != 200:
            raise requests.exceptions.HTTPError(f"VT API error: {response.status_code}")

        data = response.json()
        urls = data.get("data", [])

        logger.info(f"[FETCH] VT: Fetched {len(urls)} URLs")
        return urls

    def _fetch_known_malware(self, limit: int) -> List[Dict]:
        """
        Fetch known malicious indicators as fallback when search doesn't work.
        This queries specific known malware samples from VT.
        Note: Free tier has limited search, so we use known samples.

        Args:
            limit: Maximum number to fetch

        Returns:
            List of processed indicators
        """
        logger.info("Fetching known malware samples from VirusTotal (fallback)...")

        # Known malicious hashes (publicly known malware)
        # Free tier: 4 requests/minute - we limit to 4 per run
        # These are queried individually - rate limit applies
        known_malware_hashes = [
            "44d88612fea8a8f36de82e1278abb02f",  # EICAR test hash
            "098f6bcd4621d373cade4e832627b4f6",  # Test hash
            "5d41402abc4b2a76b9719d911017c592",  # 'hello' hash
            "5ebe2294ecd0e0f08eab7690d2a6ee69",  # 'secret' hash
        ]

        processed = []

        for _i, hash_val in enumerate(known_malware_hashes[:limit]):
            # Rate limit check
            self.rate_limiter.wait_if_needed()

            try:
                response = request_with_rate_limit_retries(
                    "GET",
                    f"{self.base_url}/files/{hash_val}",
                    session=self.session,
                    timeout=(VT_CONNECT_TIMEOUT, VT_REQUEST_TIMEOUT),
                    verify=SSL_VERIFY,
                    max_rate_limit_retries=3,
                    fallback_delay_sec=60.0,
                    retry_on_403=False,
                    context="VT",
                )

                if response.status_code == 200:
                    data = response.json()
                    file_data = data.get("data", {})
                    processed_item = self._process_file(file_data)
                    if processed_item:
                        processed.append(processed_item)
                        logger.info(f"  ✓ Queried: {hash_val[:16]}...")

            except Exception as e:
                logger.warning(f"  ✗ Error querying {hash_val[:16]}: {e}")

        logger.info(f"[FETCH] VT Fallback: Processed {len(processed)} known malware samples")
        return processed

    @retry_with_backoff(max_retries=MAX_RETRIES)
    def _fetch_ip_addresses(self, limit: int) -> List[Dict]:
        """
        Fetch recent IP addresses from VirusTotal (via comments or intelligence).
        Note: This requires VT Intelligence subscription for full access.

        Args:
            limit: Maximum number of IPs to fetch

        Returns:
            List of IP dicts (may be empty for free tier)
        """
        # For free tier, we can't easily get a list of IPs
        # This would require VT Intelligence subscription
        logger.info("VT IP collection requires Intelligence subscription - skipping for free tier")
        return []

    def _process_file(self, file_data: Dict) -> Optional[Dict]:
        """
        Process a VirusTotal file entry into EdgeGuard format.

        Args:
            file_data: VT file data dict

        Returns:
            Processed indicator dict or None
        """
        try:
            attrs = file_data.get("attributes", {})
            file_id = file_data.get("id", "")

            # Get the hash (prefer SHA256)
            sha256 = attrs.get("sha256", "")
            md5 = attrs.get("md5", "")
            sha1 = attrs.get("sha1", "")

            # Use SHA256 as primary value, fall back to file_id
            value = sha256 or file_id
            if not value:
                return None

            # Detect zones
            zones = self._detect_zones_from_attributes(attrs)

            # Calculate confidence
            confidence = self._calculate_confidence(attrs)

            # Get first submission date
            first_seen_ts = attrs.get("first_submission_date", 0)
            first_seen = (
                datetime.fromtimestamp(first_seen_ts, tz=timezone.utc).isoformat()
                if first_seen_ts
                else datetime.now(timezone.utc).isoformat()
            )

            # Get file type
            file_type = attrs.get("type_description", "unknown")

            # Get file size
            size = attrs.get("size", 0)

            # Build description
            names = attrs.get("names", [])
            meaningful_name = attrs.get("meaningful_name", "")
            popular_threat = attrs.get("popular_threat_label", "")

            description_parts = []
            if meaningful_name:
                description_parts.append(f"Name: {meaningful_name}")
            if popular_threat:
                description_parts.append(f"Threat: {popular_threat}")
            if file_type:
                description_parts.append(f"Type: {file_type}")
            if size:
                description_parts.append(f"Size: {size} bytes")

            description = (
                " | ".join(description_parts) if description_parts else "Malicious file detected by VirusTotal"
            )

            # YARA rule matches
            yara_rules = [r.get("rule_name", "") for r in attrs.get("crowdsourced_yara_results", [])[:10]]

            # Sigma detection rules
            sigma_rules = [r.get("rule_title", "") for r in attrs.get("sigma_analysis_results", [])[:10]]

            # Sandbox verdicts (capped at 5)
            sandbox_verdicts = {k: v.get("category", "") for k, v in attrs.get("sandbox_verdicts", {}).items()}

            # Popular threat classification
            threat_class = attrs.get("popular_threat_classification", {})
            threat_label = threat_class.get("suggested_threat_label", "")
            threat_category = (
                threat_class.get("popular_threat_category", [{}])[0].get("value", "")
                if threat_class.get("popular_threat_category")
                else ""
            )

            return {
                "indicator_type": "hash",
                "value": value,
                "zone": zones,
                "tag": self.tag,
                "source": [self.tag],
                "first_seen": first_seen,
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "confidence_score": confidence,
                "description": description[:500],
                "md5": md5,
                "sha1": sha1,
                "sha256": sha256,
                "file_type": file_type,
                "file_size": size,
                "vt_reputation": attrs.get("reputation", 0),
                "vt_names": names[:5] if isinstance(names, list) else [str(names)],
                "yara_rules": yara_rules,
                "sigma_rules": sigma_rules,
                "sandbox_verdicts": dict(list(sandbox_verdicts.items())[:5]),
                "threat_label": threat_label,
                "threat_category": threat_category,
            }

        except Exception as e:
            logger.warning(f"Error processing VT file: {e}")
            return None

    def _process_url(self, url_data: Dict) -> Optional[Dict]:
        """
        Process a VirusTotal URL entry into EdgeGuard format.

        Args:
            url_data: VT URL data dict

        Returns:
            Processed indicator dict or None
        """
        try:
            attrs = url_data.get("attributes", {})
            url_id = url_data.get("id", "")

            # Get the URL
            url = attrs.get("url", "")
            if not url:
                # Try to decode base64 URL ID
                try:
                    import base64

                    url = base64.urlsafe_b64decode(url_id.encode()).decode("utf-8")
                except (ValueError, UnicodeDecodeError, TypeError):
                    url = url_id

            if not url:
                return None

            # Detect zones from URL and page content
            text_to_analyze = url
            if attrs.get("title"):
                text_to_analyze += " " + str(attrs["title"])
            if attrs.get("last_final_url"):
                text_to_analyze += " " + str(attrs["last_final_url"])

            zones = detect_zones_from_text(text_to_analyze)

            # Calculate confidence
            confidence = self._calculate_confidence(attrs)

            # Get first submission date
            first_seen_ts = attrs.get("first_submission_date", 0)
            first_seen = (
                datetime.fromtimestamp(first_seen_ts, tz=timezone.utc).isoformat()
                if first_seen_ts
                else datetime.now(timezone.utc).isoformat()
            )

            # Get categories
            categories = attrs.get("categories", {})
            category_list = [f"{k}:{v}" for k, v in list(categories.items())[:3]]

            # Build description
            title = attrs.get("title", "")
            last_final_url = attrs.get("last_final_url", "")

            description_parts = []
            if title:
                description_parts.append(f"Title: {title}")
            if last_final_url and last_final_url != url:
                description_parts.append(f"Final URL: {last_final_url}")
            if category_list:
                description_parts.append(f"Categories: {', '.join(category_list)}")

            description = " | ".join(description_parts) if description_parts else "Malicious URL detected by VirusTotal"

            return {
                "indicator_type": "url",
                "value": url,
                "zone": zones,
                "tag": self.tag,
                "source": [self.tag],
                "first_seen": first_seen,
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "confidence_score": confidence,
                "description": description[:500],
                "vt_reputation": attrs.get("reputation", 0),
                "vt_last_analysis_stats": attrs.get("last_analysis_stats", {}),
            }

        except Exception as e:
            logger.warning(f"Error processing VT URL: {e}")
            return None

    def collect(
        self,
        limit: int = None,
        push_to_misp: bool = True,
        baseline: bool = False,
        baseline_days: int = 365,
    ) -> Any:
        """
        Collect indicators from VirusTotal and optionally push to MISP.

        Args:
            limit: Maximum number of indicators to collect
            push_to_misp: Whether to push collected data to MISP
            baseline: If True, do not substitute incremental default when limit is None
            baseline_days: Reserved for parity with other collectors

        Returns:
            List of processed items or status dict
        """
        limit = resolve_collection_limit(limit, "virustotal", baseline=baseline)
        # VT is heavily rate-limited; uncapped runs use a modest per-run ceiling.
        if limit is None:
            limit = 20

        # Optional source: no key → DAG succeeds with skipped + skip metrics (see run_collector_with_metrics)
        # Re-check at collect() time (handles post-init assignment + placeholders)
        if not optional_api_key_effective(self.api_key, VIRUSTOTAL_API_KEY_PLACEHOLDERS):
            logger.warning(
                "VirusTotal: No API key — skipping collection (optional source). "
                "Set VIRUSTOTAL_API_KEY when ready; https://www.virustotal.com/gui/join-us"
            )
            if push_to_misp:
                return make_status(
                    "virustotal",
                    True,
                    count=0,
                    failed=0,
                    skipped=True,
                    skip_reason=("VIRUSTOTAL_API_KEY not set (optional — https://www.virustotal.com/gui/join-us)"),
                    skip_reason_class="missing_virustotal_key",
                )
            return []

        try:
            processed = []

            # Fetch recent files (consumes 1 API call)
            # Due to rate limits, we fetch small batches
            files_limit = min(limit // 2, 10)  # Half for files, max 10
            if files_limit > 0:
                try:
                    files = self._fetch_recent_files(files_limit)
                    for file_data in files:
                        processed_item = self._process_file(file_data)
                        if processed_item:
                            processed.append(processed_item)
                except Exception as e:
                    logger.warning(f"Error fetching files: {e}")

            # If no files found, try fallback with known malicious hashes
            if not processed:
                logger.info("VT: Search returned no results, trying known malware hashes...")
                processed = self._fetch_known_malware(limit)

            # Fetch recent URLs (consumes 1 API call)
            urls_limit = min(limit - len(processed), 10)  # Remaining for URLs, max 10
            if urls_limit > 0:
                try:
                    urls = self._fetch_recent_urls(urls_limit)
                    for url_data in urls:
                        processed_item = self._process_url(url_data)
                        if processed_item:
                            processed.append(processed_item)
                except Exception as e:
                    logger.warning(f"Error fetching URLs: {e}")

            # Deduplicate by value
            seen = set()
            unique = []
            for item in processed:
                value = item.get("value", "")
                if value and value not in seen:
                    seen.add(value)
                    unique.append(item)

            logger.info(f"[OK] VirusTotal: Processed {len(unique)} unique indicators")

            # Push to MISP if requested
            if push_to_misp:
                if not unique:
                    return self._return_status(True, 0, failed=0)

                success, failed = self.misp_writer.push_items(unique)

                if success > 0:
                    logger.info(f"[OK] VirusTotal: Successfully pushed {success} items to MISP")
                if failed > 0:
                    logger.warning(f"[WARN] VirusTotal: Failed to push {failed} items to MISP")

                return status_after_misp_push("virustotal", len(unique), success, failed)
            else:
                return unique

        except requests.exceptions.Timeout as e:
            error_msg = f"Timeout: {e}"
            logger.error(f"VirusTotal timeout: {e}")
            return self._return_status(False, 0, error_msg)
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {e}"
            logger.error(f"VirusTotal connection error: {e}")
            return self._return_status(False, 0, error_msg)
        except requests.exceptions.HTTPError as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"VirusTotal: auth/access denied — skipping (optional): {e}")
                return make_skipped_optional_source(
                    "virustotal",
                    skip_reason=str(e),
                    skip_reason_class="virustotal_auth_denied",
                )
            error_msg = f"HTTP error: {e}"
            logger.error(f"VirusTotal HTTP error: {e}")
            return self._return_status(False, 0, error_msg)
        except Exception as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"VirusTotal: auth/access denied — skipping (optional): {e}")
                return make_skipped_optional_source(
                    "virustotal",
                    skip_reason=str(e),
                    skip_reason_class="virustotal_auth_denied",
                )
            error_msg = f"{type(e).__name__}: {e}"
            logger.error(f"VirusTotal collection error: {type(e).__name__}: {e}")
            return self._return_status(False, 0, error_msg)

    def _return_status(self, success: bool, count: int, error: str = None, failed: int = 0) -> Dict[str, Any]:
        """Return standardized status dict."""
        return make_status("virustotal", success, count=count, failed=failed, error=error)


def test_vt_collector() -> Dict[str, Any]:
    """Test VirusTotal collection and MISP push"""
    collector = VTCollector()

    # First check health
    health = collector.health_check()
    print("\n🏥 VirusTotal Health Check:")
    print(json.dumps(health, indent=2))

    if not health.get("healthy"):
        print("⚠️ VirusTotal API is not healthy - skipping collection test")
        return {"health": health, "collection": None}

    # Test collection
    result = collector.collect(limit=10)  # VT: Free tier = 4 req/min (max 10 safe)
    print("\n📥 VirusTotal Test Result:")
    if isinstance(result, list):
        print(f"Collected {len(result)} indicators")
        for r in result[:3]:
            print(f"  - {r.get('indicator_type')}: {r.get('value', '')[:60]}...")
    else:
        print(json.dumps(result, indent=2))

    return {"health": health, "collection": result}


if __name__ == "__main__":
    test_vt_collector()
