#!/usr/bin/env python3
"""
EdgeGuard - Direct collectors for Finance feeds
Fetches data from abuse.ch feeds and processes to Neo4j
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import csv
import ipaddress
import logging
import re
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

import requests

from collector_failure_alerts import is_transient_external_error
from collectors.collector_utils import (
    RateLimiter,
    TransientServerError,
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


class FeedTransientError(TransientServerError):
    """HTTP 429 / 5xx from an abuse.ch download after the helper's own retries.

    Raised outside the ``retry_with_backoff``-decorated download so the retries are not
    multiplied, and recognised by ``run_collector_with_metrics`` as a transient external error:
    the Airflow task is skipped with an alert instead of failing.
    """


def _feed_text(response: requests.Response, context: str) -> str:
    """Body of a feed download; 429 / 5xx → :class:`FeedTransientError`, other errors → ``HTTPError``."""
    code = response.status_code
    if code == 429 or code >= 500:
        raise FeedTransientError(f"{context} download HTTP {code}", response=response)
    response.raise_for_status()
    return response.text


def _feed_failure(
    source: str,
    breaker: Any,
    exc: Exception,
    push_to_misp: bool,
    auth_skip_class: str,
) -> Dict[str, Any]:
    """Shared ``except`` policy of the two feeds; returns a status dict or re-raises.

    * 401 / 403 → skipped (optional public feed), breaker untouched.
    * Transient upstream failure (timeout, connection error, truncated transfer, 429 / 5xx) →
      re-raised: ``run_collector_with_metrics`` turns it into a skipped task with an alert, a
      direct caller sees the error. It used to become ``success=False`` and a failed task.
    * Anything else → ``success=False`` when pushing to MISP (needs an operator), re-raised
      otherwise.
    """
    if push_to_misp and is_auth_or_access_denied(exc):
        logger.warning(f"{source}: auth/access denied — skipping (optional public feed): {exc}")
        breaker.record_success()
        return make_skipped_optional_source(source, skip_reason=str(exc), skip_reason_class=auth_skip_class)
    breaker.record_failure()
    if is_transient_external_error(exc):
        logger.warning(f"{source}: transient upstream failure — {type(exc).__name__}: {exc}")
        raise exc
    logger.error(f"{source} collection error: {type(exc).__name__}: {exc}")
    if push_to_misp:
        return make_status(source, False, count=0, error=str(exc))
    raise exc


# Feodo Tracker host page of a C2 address. Setting it as the item ``reference`` also makes
# ``MISPWriter`` emit the shared abuse.ch metadata comment (``TF_META``), which is what carries
# ``malware_family`` to MISP and on to ``Indicator.malware_family`` in Neo4j (INDICATES edges).
FEODO_HOST_URL = "https://feodotracker.abuse.ch/browse/host/{ip}/"
# ThreatFox vocabulary for a botnet command-and-control endpoint (same value ThreatFox reports).
FEODO_THREAT_TYPE = "botnet_cc"
FEODO_THREAT_TYPE_DESC = "Botnet Command&Control server (C&C)"
# Actionable versus historical. A server counts as recently active when Feodo Tracker saw it
# online within ``FEODO_ACTIVE_DAYS`` of the collection day; the ``c2_status`` column alone is
# not used, because it is only as fresh as the feed (on 2026-10-12 the feed had not been updated
# since 2026-03-04 and its single "online" row was last seen online on 2026-03-12).
# Recently active servers are published with ``confidence:medium`` (0.5 in the graph) and the MISP
# detection flag; everything else is history: ``confidence:low`` (0.3) and ``to_ids=False``.
# abuse.ch itself advises against blocking on the complete history because addresses are re-used.
FEODO_ACTIVE_DAYS = 30
FEODO_CONFIDENCE_ACTIVE = 0.7
FEODO_CONFIDENCE_HISTORICAL = 0.4
# The download header carries "# Last updated: <timestamp> UTC"; older than this many days is logged.
FEODO_STALE_FEED_DAYS = 7
_FEODO_LAST_UPDATED_RE = re.compile(r"^#\s*Last updated:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", re.MULTILINE)


def _utc_today() -> date:
    """Collection day in UTC (a function so tests can pin it)."""
    return datetime.now(timezone.utc).date()


def feodo_feed_last_updated(raw_text: str) -> Optional[datetime]:
    """Timestamp of the ``# Last updated:`` header line of a Feodo download, or ``None``."""
    match = _FEODO_LAST_UPDATED_RE.search(raw_text or "")
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def feodo_last_seen(first_seen: str, last_online: str) -> Optional[str]:
    """Source-reported last-seen time of a server, from the ``last_online`` date column.

    ``last_online`` has day resolution. Later than the first-seen day: that date (published as
    midnight UTC). Same day: the first-seen timestamp itself, which is the last observation the
    feed reports for that day and keeps ``last_seen >= first_seen`` (MISP rejects the opposite).
    Empty, or earlier than the first-seen day: ``None`` — no last-seen claim is made.
    """
    first_day = (first_seen or "")[:10]
    if not last_online or not first_day:
        return None
    if last_online > first_day:
        return last_online
    if last_online == first_day:
        return first_seen
    return None


def feodo_is_recently_active(last_online: str, today: Optional[date] = None) -> bool:
    """True when ``last_online`` (``YYYY-MM-DD``) is within ``FEODO_ACTIVE_DAYS`` of *today* (UTC)."""
    try:
        seen = datetime.strptime(last_online, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return False
    return (((today or _utc_today()) - seen).days) <= FEODO_ACTIVE_DAYS


def feodo_merge_rows(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """One record per address from the feed rows (file order of first appearance is kept).

    The feed lists one row per address and port, and an address re-used by another botnet appears
    again with another family (373 of 7,980 rows repeated an address on 2026-10-12; 81 addresses
    carried more than one family). MISP holds one attribute per value, so without merging only the
    first row of an address would survive. Merged record: earliest ``first_seen``, latest
    ``last_online``, every port, every family; the primary family, status and port are those of
    the most recently active row.
    """

    def recency(row: Dict[str, str]) -> Tuple[str, str]:
        return (row.get("last_online") or "", row.get("first_seen") or "")

    merged: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        rec = merged.get(row["ip"])
        if rec is None:
            merged[row["ip"]] = {
                "ip": row["ip"],
                "first_seen": row["first_seen"],
                "last_online": row["last_online"],
                "primary": row,
                "ports": [row["port"]] if row["port"] else [],
                "families": [row["malware"]] if row["malware"] else [],
                "rows": 1,
            }
            continue
        rec["rows"] += 1
        if row["first_seen"] and (not rec["first_seen"] or row["first_seen"] < rec["first_seen"]):
            rec["first_seen"] = row["first_seen"]
        if row["last_online"] > rec["last_online"]:
            rec["last_online"] = row["last_online"]
        if recency(row) > recency(rec["primary"]):
            rec["primary"] = row
        if row["port"] and row["port"] not in rec["ports"]:
            rec["ports"].append(row["port"])
        if row["malware"] and row["malware"] not in rec["families"]:
            rec["families"].append(row["malware"])
    for rec in merged.values():
        primary_family = rec["primary"]["malware"]
        if primary_family and rec["families"] and rec["families"][0] != primary_family:
            rec["families"] = [primary_family] + [f for f in rec["families"] if f != primary_family]
        rec["ports"].sort(key=lambda port: (not port.isdigit(), int(port) if port.isdigit() else 0, port))
    return list(merged.values())


class FeodoCollector:
    """Collects Feodo Tracker Botnet C2 IP Blocklist"""

    # Regular runs: C2 servers active in the last 30 days (abuse.ch "ipblocklist").
    # Baseline runs: the complete C2 history (abuse.ch "aggressive" list, same columns).
    # Both lists are public and need no key; the aggressive list is several
    # thousand rows, the 30-day list a handful, so a fresh baseline seeds the
    # history once and the daily task only adds what is currently active.
    # Rows are merged per address (see ``feodo_merge_rows``).
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
    def _download(self, url: str) -> requests.Response:
        """One download with transport-error retry; HTTP 429 / 5xx are retried inside the helper."""
        return request_with_rate_limit_retries(
            "GET",
            url,
            session=None,
            timeout=30,
            verify=SSL_VERIFY,
            max_rate_limit_retries=3,
            fallback_delay_sec=30.0,
            retry_on_403=False,
            context="Feodo",
        )

    def _fetch_raw(self, url: Optional[str] = None) -> str:
        """Download a Feodo blocklist CSV (default: the 30-day list)."""
        return _feed_text(self._download(url or self.url), "Feodo")

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
            logger.warning("Feodo circuit breaker open after repeated upstream failures - skipping this run")
            if push_to_misp:
                return make_skipped_optional_source(
                    "feodo",
                    skip_reason="Feodo circuit breaker open (repeated upstream failures)",
                    skip_reason_class="feodo_circuit_breaker_open",
                )
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

            rows: List[Dict[str, str]] = []
            not_an_address = 0
            for row in csv.reader(data_lines):
                parts = [field.strip() for field in row]
                if len(parts) < 5 or parts[0].lower() == "first_seen_utc" or not parts[1]:
                    continue
                # The address column must hold an IPv4 address: an HTTP 200 body that is not the
                # CSV (an error page) must not turn into "C&C servers".
                try:
                    if ipaddress.ip_address(parts[1]).version != 4:
                        raise ValueError("not IPv4")
                except ValueError:
                    not_an_address += 1
                    continue
                rows.append(
                    {
                        "first_seen": parts[0],
                        "ip": parts[1],
                        "port": parts[2],
                        "status": parts[3],
                        "last_online": parts[4],
                        "malware": parts[5] if len(parts) > 5 else "",
                    }
                )

            if not_an_address:
                logger.warning(
                    "Feodo: %d row(s) skipped — the address column did not hold an IPv4 address%s",
                    not_an_address,
                    "" if rows else "; the download does not look like the Feodo CSV",
                )

            records = feodo_merge_rows(rows)
            if limit is not None:
                records = records[:limit]

            today = _utc_today()
            feed_updated = feodo_feed_last_updated(raw_text)
            if feed_updated is not None and (today - feed_updated.date()).days > FEODO_STALE_FEED_DAYS:
                logger.warning(
                    "Feodo Tracker feed was last updated on %s (%d days ago): the download is a historical "
                    "snapshot and no new servers will arrive until abuse.ch updates it",
                    feed_updated.strftime("%Y-%m-%d"),
                    (today - feed_updated.date()).days,
                )

            results = []
            active = 0
            for rec in records:
                primary = rec["primary"]
                malware = primary["malware"]
                status = primary["status"].lower()
                first_seen = rec["first_seen"]
                last_online = rec["last_online"]
                is_active = feodo_is_recently_active(last_online, today)
                active += 1 if is_active else 0

                # Zones come from the conservative keyword detector on the family name; malware
                # families are linked to sectors through graph relationships, not keywords.
                zones = detect_zones_from_text(" ".join(rec["families"]).lower())

                # Labels kept with the source record (TF_META.tags; stored in the raw data of the
                # SOURCED_FROM edge): status of the most recent row, every port, and every family
                # when the address served more than one.
                labels = [f"c2_status:{status}"] if status else []
                labels.extend(f"port:{port}" for port in rec["ports"])
                if len(rec["families"]) > 1:
                    labels.extend(f"family:{family}" for family in rec["families"])

                item: Dict[str, Any] = {
                    "indicator_type": "ipv4",
                    "value": rec["ip"],
                    "zone": zones,  # zone is now an array
                    "tag": self.tag,
                    "source": [self.tag],
                    "first_seen": first_seen,
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                    "confidence_score": FEODO_CONFIDENCE_ACTIVE if is_active else FEODO_CONFIDENCE_HISTORICAL,
                    "to_ids": is_active,  # history is knowledge, not a detection candidate
                    "malware_family": malware,  # most recent family; source spelling (matching is case-insensitive)
                    "port": primary["port"],
                    "status": primary["status"],
                    "last_online": last_online,  # → Indicator.last_online
                    "reference": FEODO_HOST_URL.format(ip=rec["ip"]),
                    "threat_type": FEODO_THREAT_TYPE,
                    "threat_type_desc": FEODO_THREAT_TYPE_DESC,
                    "tags": labels,
                }
                # Source-reported last-seen → SOURCED_FROM.source_reported_last_at (activity window).
                last_seen = feodo_last_seen(first_seen, last_online)
                if last_seen:
                    item["last_seen"] = last_seen
                results.append(item)

            logger.info(
                f"[OK] Feodo: Collected {len(results)} C&C servers from {len(rows)} rows "
                f"({active} active in the last {FEODO_ACTIVE_DAYS} days, {len(results) - active} historical)"
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
            status = _feed_failure("feodo", FEODO_CIRCUIT_BREAKER, e, push_to_misp, "feodo_auth_denied")
            if not push_to_misp:
                raise
            return status


class SSLBlacklistCollector:
    """Collects SSL Blacklist from abuse.ch"""

    def __init__(self, misp_writer: MISPWriter = None):
        self.url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
        self.tag = "ssl_blacklist"
        self.source_name = "sslbl"
        self.misp_writer = misp_writer or MISPWriter()

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _download(self) -> requests.Response:
        """One download with transport-error retry; HTTP 429 / 5xx are retried inside the helper."""
        return request_with_rate_limit_retries(
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

    def _fetch_raw(self) -> str:
        """Download the SSL Blacklist CSV."""
        return _feed_text(self._download(), "SSL Blacklist")

    def collect(
        self, limit=None, push_to_misp=True, baseline: bool = False, baseline_days: int = 365
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Fetch and parse SSL blacklist. Returns status dict when ``push_to_misp=True``."""
        # SSL Blacklist is a bulk download - baseline doesn't change much
        if baseline:
            logger.info("📜 Baseline mode: Collecting all SSL Blacklist data...")

        # Check circuit breaker
        if not SSLBL_CIRCUIT_BREAKER.can_execute():
            logger.warning("SSL Blacklist circuit breaker open after repeated upstream failures - skipping this run")
            if push_to_misp:
                return make_skipped_optional_source(
                    "sslbl",
                    skip_reason="SSL Blacklist circuit breaker open (repeated upstream failures)",
                    skip_reason_class="sslbl_circuit_breaker_open",
                )
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
                        # The SHA-1 fingerprint of a TLS certificate, not of a file (2026-10: was ``sha1``,
                        # which made it a file-hash Indicator with a ``file:hashes`` STIX pattern).
                        "indicator_type": "x509-fingerprint-sha1",
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
            status = _feed_failure("sslbl", SSLBL_CIRCUIT_BREAKER, e, push_to_misp, "sslbl_auth_denied")
            if not push_to_misp:
                raise
            return status


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
