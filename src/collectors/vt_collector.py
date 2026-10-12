#!/usr/bin/env python3
"""
EdgeGuard - VirusTotal MISP Collector (free-tier lookup enrichment)

Enriches hashes that other EdgeGuard sources already pushed to MISP (ThreatFox,
MalwareBazaar, OTX, ...) with VirusTotal's file analysis and pushes the result to
MISP under ``source:VirusTotal``. The MISP→Neo4j sync then merges the VirusTotal
attribute into the same Indicator node (second SOURCED_FROM edge, VirusTotal
confidence, threat label, first-submission date).

Why lookups and not a feed: the public (free) VirusTotal API v3 offers single-object
lookups only (``GET /files/{hash}``). Feed and Intelligence-search endpoints require
a premium licence, so a "recent malware" query returns nothing on a free key.

Rate limits (free tier) and how the collector respects them:
- 4 lookups/minute  — ``RateLimiter(requests_per_minute=4)`` (in-process)
- 500 lookups/day   — ``virustotal_budget.VirusTotalBudget`` ledger in the shared
                      state directory (default budget 400/day, 60 per run); all
                      quota messages are prefixed ``[VT-QUOTA]``
- HTTP 429          — marks the day exhausted; the run stops and returns what it
                      has; the Airflow task stays green (optional source)
- quota exhausted   — the task is skipped with ``skip_reason_class=virustotal_daily_budget``

Knobs: ``EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET`` (400), ``EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN``
(60), ``EDGEGUARD_VIRUSTOTAL_CANDIDATE_DAYS`` (30), ``EDGEGUARD_VIRUSTOTAL_BUDGET_PATH``.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

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
    status_after_misp_push,
)

# Import MISP writer
from collectors.misp_writer import MISPWriter
from collectors.virustotal_budget import (
    QUOTA_LOG_PREFIX,
    VirusTotalBudget,
    candidate_days,
    max_lookups_per_run,
)
from config import SOURCE_TAGS, SSL_VERIFY, VIRUSTOTAL_API_KEY, detect_zones_from_text, resolve_collection_limit

logger = logging.getLogger(__name__)

# Configuration constants
VT_CONNECT_TIMEOUT = 30  # Connection timeout (seconds)
VT_REQUEST_TIMEOUT = 60  # Read timeout (seconds)
MAX_RETRIES = 3
RETRY_DELAY_BASE = 2  # seconds

# VirusTotal API v3 base URL
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# MISP candidate paging (hashes awaiting enrichment)
MISP_CANDIDATE_PAGE_SIZE = 1000
MISP_CANDIDATE_MAX_PAGES = 25

# Consecutive transport/server errors after which a run stops early (transient outage).
MAX_CONSECUTIVE_LOOKUP_ERRORS = 3

_HEX = frozenset("0123456789abcdef")


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and set(value) <= _HEX


class VTCollector:
    """
    VirusTotal lookup-enrichment collector for MISP.

    One run: list SHA-256 attributes in MISP that no VirusTotal attribute covers yet
    (newest ``EDGEGUARD_VIRUSTOTAL_CANDIDATE_DAYS`` days), look each up with
    ``GET /files/{sha256}`` within the per-run cap and the daily budget, and push the
    enriched items to MISP.

    Features:
    - Rate limiting (4 requests/min free tier) and a persisted daily budget
    - Hashes are looked up once (ledger memory, including hashes unknown to VirusTotal)
    - Automatic zone detection from file names, tags and sandbox verdicts
    - Proper MISP tagging (source:VirusTotal, zone tags)
    - Never blocks the workflow: quota, 429 and auth problems are skips, not failures
    """

    # Class-level rate limiter (shared across instances)
    _rate_limiter = None

    def __init__(self, misp_writer: MISPWriter = None):
        self.base_url = VT_BASE_URL
        self.api_key = optional_api_key_effective(VIRUSTOTAL_API_KEY, VIRUSTOTAL_API_KEY_PLACEHOLDERS)
        self.tag = SOURCE_TAGS.get("virustotal", "virustotal")
        self.misp_tag = MISPWriter.SOURCE_TAGS.get(self.tag, f"source:{self.tag}")
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

            # PR-M2 §4-F4 (HIGH): VirusTotal is on
            # ``_RELIABLE_FIRST_SEEN_SOURCES`` so MISP's ``Attribute.first_seen``
            # propagates into ``r.source_reported_first_at`` (concept 1 in
            # docs/TIMESTAMPS.md).  The previous wall-clock-NOW fallback for
            # records missing ``first_submission_date`` (or having epoch 0)
            # poisoned the source-truthful chronology forever via the MIN-CASE
            # — every such VT record permanently anchored its
            # ``MIN(source_reported_first_at)`` at baseline day 1.
            #
            # Honest-NULL pattern (mirrors AbuseIPDB blacklist): omit
            # ``first_seen`` from the item when the source field is absent
            # so MISP's attribute carries no claim and the MIN-CASE
            # preserves any prior real value.  ``coerce_iso(None)`` → None
            # downstream.
            first_seen_ts = attrs.get("first_submission_date", 0)
            first_seen = datetime.fromtimestamp(first_seen_ts, tz=timezone.utc).isoformat() if first_seen_ts else None
            # PR-M2: also propagate last_submission_date → last_seen
            # (concept 2 in docs/TIMESTAMPS.md). Same honest-NULL pattern.
            last_seen_ts = attrs.get("last_submission_date", 0)
            last_seen = datetime.fromtimestamp(last_seen_ts, tz=timezone.utc).isoformat() if last_seen_ts else None

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

            # PR-M2 honest-NULL: omit ``first_seen`` entirely when None
            # rather than serializing a None value into the item dict.
            # MISP writer's ``_apply_source_truthful_timestamps`` only
            # writes the MISP-native ``Attribute.first_seen`` field when
            # the key is non-empty, so omission is the right signal.
            item: Dict[str, Any] = {
                "indicator_type": "hash",
                "value": value,
                "zone": zones,
                "tag": self.tag,
                "source": [self.tag],
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
            if first_seen is not None:
                item["first_seen"] = first_seen
            if last_seen is not None:
                item["last_seen"] = last_seen
            return item

        except Exception as e:
            logger.warning(f"Error processing VT file: {e}")
            return None

    # ------------------------------------------------------------------
    # Candidate selection (MISP) and lookups (VirusTotal)
    # ------------------------------------------------------------------

    def _candidate_hashes(self, wanted: int, budget: VirusTotalBudget) -> List[str]:
        """Return up to *wanted* SHA-256 values from MISP that still lack VirusTotal enrichment.

        Uses ``attributes/restSearch`` on the collector's MISP instance: type ``sha256``,
        attribute timestamp within ``EDGEGUARD_VIRUSTOTAL_CANDIDATE_DAYS`` days, and not
        already tagged with the VirusTotal source tag. Hashes recorded in the ledger
        (looked up before, found or not) are excluded. Raises on MISP transport or
        HTTP errors — the caller turns that into a skipped run.
        """
        days = candidate_days()
        url = f"{self.misp_writer.url}/attributes/restSearch"
        out: List[str] = []
        seen: set = set()
        page = 1
        while len(out) < wanted and page <= MISP_CANDIDATE_MAX_PAGES:
            payload = {
                "returnFormat": "json",
                "type": "sha256",
                "tags": [f"!{self.misp_tag}"],
                "timestamp": f"{days}d",
                "page": page,
                "limit": MISP_CANDIDATE_PAGE_SIZE,
            }
            response = self.misp_writer.session.post(
                url,
                json=payload,
                verify=self.misp_writer.verify_ssl,
                timeout=(VT_CONNECT_TIMEOUT, VT_REQUEST_TIMEOUT * 2),
            )
            response.raise_for_status()
            data = response.json()
            resp = data.get("response", data) if isinstance(data, dict) else data
            rows: List[Any] = []
            if isinstance(resp, list):
                rows = resp
            elif isinstance(resp, dict):
                raw = resp.get("Attribute")
                if isinstance(raw, list):
                    rows = raw
                elif isinstance(raw, dict):
                    rows = [raw]
            for row in rows:
                if not isinstance(row, dict):
                    continue
                value = str(row.get("value", "")).strip().lower()
                if not _is_sha256(value) or value in seen or budget.already_looked_up(value):
                    continue
                seen.add(value)
                out.append(value)
                if len(out) >= wanted:
                    break
            if len(rows) < MISP_CANDIDATE_PAGE_SIZE:
                break
            page += 1
        logger.info(
            "VirusTotal: %d candidate sha256 hashes awaiting enrichment (MISP window %d days, %d page(s) read)",
            len(out),
            days,
            page,
        )
        return out

    def _lookup_hashes(self, candidates: List[str], budget: VirusTotalBudget) -> Tuple[List[Dict], Dict[str, Any]]:
        """Look up *candidates* one by one within the budget; returns (items, run summary).

        HTTP 200 → enriched item; 404 → remembered as unknown to VirusTotal (never
        retried); 429 → the day is marked exhausted and the run stops; 401/403 →
        ``requests.HTTPError`` (the caller skips the source as auth-denied); other
        errors are counted and the run stops after
        :data:`MAX_CONSECUTIVE_LOOKUP_ERRORS` consecutive ones.
        """
        items: List[Dict] = []
        summary: Dict[str, Any] = {"lookups": 0, "found": 0, "not_found": 0, "errors": 0, "stopped": None}
        consecutive_errors = 0
        for sha256 in candidates:
            if budget.is_exhausted():
                summary["stopped"] = "daily_budget"
                logger.warning(
                    "%s daily budget reached during the run (%s) — stopping lookups; the workflow continues",
                    QUOTA_LOG_PREFIX,
                    budget.summary(),
                )
                break
            self.rate_limiter.wait_if_needed()
            try:
                response = request_with_rate_limit_retries(
                    "GET",
                    f"{self.base_url}/files/{sha256}",
                    session=self.session,
                    timeout=(VT_CONNECT_TIMEOUT, VT_REQUEST_TIMEOUT),
                    verify=SSL_VERIFY,
                    max_rate_limit_retries=1,
                    fallback_delay_sec=60.0,
                    retry_on_403=False,
                    context="VT",
                )
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
                summary["errors"] += 1
                consecutive_errors += 1
                logger.warning("VirusTotal lookup %s… failed: %s", sha256[:16], exc)
                if consecutive_errors >= MAX_CONSECUTIVE_LOOKUP_ERRORS:
                    summary["stopped"] = "transport_errors"
                    break
                continue
            code = response.status_code
            if code == 429:
                budget.mark_exhausted(f"HTTP 429 after {summary['lookups']} lookups this run")
                budget.save()
                summary["stopped"] = "rate_limited"
                break
            if code in (401, 403):
                raise requests.exceptions.HTTPError(
                    f"VirusTotal HTTP {code}: API key rejected or access denied", response=response
                )
            budget.consume(1)
            summary["lookups"] += 1
            if code == 200:
                consecutive_errors = 0
                budget.remember(sha256, "ok")
                try:
                    file_data = response.json().get("data", {})
                except ValueError:
                    file_data = {}
                item = self._process_file(file_data) if isinstance(file_data, dict) else None
                if item:
                    items.append(item)
                    summary["found"] += 1
                continue
            if code == 404:
                consecutive_errors = 0
                budget.remember(sha256, "not_found")
                summary["not_found"] += 1
                continue
            summary["errors"] += 1
            consecutive_errors += 1
            logger.warning("VirusTotal lookup %s… answered HTTP %s", sha256[:16], code)
            if consecutive_errors >= MAX_CONSECUTIVE_LOOKUP_ERRORS:
                summary["stopped"] = "http_errors"
                break
        return items, summary

    def collect(
        self,
        limit: int = None,
        push_to_misp: bool = True,
        baseline: bool = False,
        baseline_days: int = 365,
    ) -> Any:
        """
        Enrich MISP hashes with VirusTotal lookups and optionally push the results to MISP.

        Args:
            limit: Maximum number of lookups for this run (further bounded by
                ``EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN`` and the daily budget)
            push_to_misp: Whether to push collected data to MISP
            baseline: Baseline runs pass ``limit=None``; the per-run cap still applies
                (the daily quota does not care which DAG spends it)
            baseline_days: Reserved for parity with other collectors

        Returns:
            List of processed items or status dict
        """
        limit = resolve_collection_limit(limit, "virustotal", baseline=baseline)

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

        budget = VirusTotalBudget()
        per_run = max_lookups_per_run()
        allowed = per_run if limit is None else min(limit, per_run)
        allowed = min(allowed, budget.remaining)
        if budget.is_exhausted() or allowed <= 0:
            logger.warning(
                "%s skipping this run — %s; lookups resume after 00:00 UTC (task success; downstream continues)",
                QUOTA_LOG_PREFIX,
                budget.summary(),
            )
            if push_to_misp:
                return make_skipped_optional_source(
                    "virustotal",
                    skip_reason=f"VirusTotal daily lookup budget exhausted ({budget.summary()})",
                    skip_reason_class="virustotal_daily_budget",
                )
            return []
        logger.info(
            "%s %s — this run performs at most %d lookups (per-run cap %d%s)",
            QUOTA_LOG_PREFIX,
            budget.summary(),
            allowed,
            per_run,
            "" if limit is None else f", task limit {limit}",
        )

        try:
            candidates = self._candidate_hashes(allowed, budget)
        except Exception as exc:
            logger.warning("VirusTotal: listing candidate hashes in MISP failed — skipping this run: %s", exc)
            if push_to_misp:
                return make_skipped_optional_source(
                    "virustotal",
                    skip_reason=f"could not list candidate hashes in MISP: {type(exc).__name__}: {exc}",
                    skip_reason_class="virustotal_candidates_unavailable",
                )
            raise
        if not candidates:
            logger.info(
                "VirusTotal: no sha256 indicators awaiting enrichment in MISP (window %d days) — nothing to look up",
                candidate_days(),
            )
            return self._return_status(True, 0) if push_to_misp else []

        try:
            items, summary = self._lookup_hashes(candidates, budget)
            budget.save()
            logger.info(
                "%s run finished: %d lookups (%d enriched, %d unknown to VirusTotal, %d errors)%s — %s",
                QUOTA_LOG_PREFIX,
                summary["lookups"],
                summary["found"],
                summary["not_found"],
                summary["errors"],
                f", stopped early: {summary['stopped']}" if summary["stopped"] else "",
                budget.summary(),
            )

            seen: set = set()
            unique: List[Dict] = []
            for item in items:
                value = item.get("value", "")
                if value and value not in seen:
                    seen.add(value)
                    unique.append(item)
            logger.info(f"[OK] VirusTotal: Processed {len(unique)} unique indicators")

            if not push_to_misp:
                return unique
            if not unique and summary["stopped"] == "rate_limited":
                return make_skipped_optional_source(
                    "virustotal",
                    skip_reason=f"VirusTotal answered HTTP 429 before any lookup succeeded ({budget.summary()})",
                    skip_reason_class="virustotal_rate_limited",
                )
            if not unique:
                status = self._return_status(True, 0, failed=0)
            else:
                success, failed = self.misp_writer.push_items(unique)
                if success > 0:
                    logger.info(f"[OK] VirusTotal: Successfully pushed {success} items to MISP")
                if failed > 0:
                    logger.warning(f"[WARN] VirusTotal: Failed to push {failed} items to MISP")
                status = status_after_misp_push("virustotal", len(unique), success, failed)
            status.update(
                {
                    "vt_lookups": summary["lookups"],
                    "vt_enriched": summary["found"],
                    "vt_unknown": summary["not_found"],
                    "vt_lookup_errors": summary["errors"],
                    "vt_stopped": summary["stopped"],
                    "vt_budget_used": budget.used,
                    "vt_budget_remaining": budget.remaining,
                }
            )
            return status

        except requests.exceptions.Timeout as e:
            error_msg = f"Timeout: {e}"
            logger.error(f"VirusTotal timeout: {e}")
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {e}"
            logger.error(f"VirusTotal connection error: {e}")
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise
        except requests.exceptions.HTTPError as e:
            budget.save()
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"VirusTotal: auth/access denied — skipping (optional): {e}")
                return make_skipped_optional_source(
                    "virustotal",
                    skip_reason=str(e),
                    skip_reason_class="virustotal_auth_denied",
                )
            error_msg = f"HTTP error: {e}"
            logger.error(f"VirusTotal HTTP error: {e}")
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise
        except Exception as e:
            budget.save()
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"VirusTotal: auth/access denied — skipping (optional): {e}")
                return make_skipped_optional_source(
                    "virustotal",
                    skip_reason=str(e),
                    skip_reason_class="virustotal_auth_denied",
                )
            error_msg = f"{type(e).__name__}: {e}"
            logger.error(f"VirusTotal collection error: {type(e).__name__}: {e}")
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise

    def _return_status(self, success: bool, count: int, error: str = None, failed: int = 0) -> Dict[str, Any]:
        """Return standardized status dict."""
        return make_status("virustotal", success, count=count, failed=failed, error=error)


def test_vt_collector() -> Dict[str, Any]:
    """Manual check: VirusTotal health, then one bounded enrichment run."""
    collector = VTCollector()

    # First check health
    health = collector.health_check()
    print("\n🏥 VirusTotal Health Check:")
    print(json.dumps(health, indent=2))

    if not health.get("healthy"):
        print("⚠️ VirusTotal API is not healthy - skipping collection test")
        return {"health": health, "collection": None}

    # Bounded run (free tier: 4 lookups/min; the daily budget ledger is honoured)
    result = collector.collect(limit=10)
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
