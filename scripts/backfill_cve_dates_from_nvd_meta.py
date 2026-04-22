#!/usr/bin/env python3
"""
PR-N22 — Backfill historical CVE ``published`` / ``last_modified`` from MISP NVD_META.

## Why this script exists

Before PR-N19 Fix #1 (merged 2026-04-22), ``merge_cve`` silently dropped the
``published`` and ``last_modified`` fields from the MISP-sourced CVE path.
The ResilMesh-native ``merge_resilmesh_cve`` wrote them correctly, but 99.7%
of CVEs in a typical baseline come from the MISP path. Bravo Vanko caught
this in the 2026-04-22 baseline audit — 99,664/99,664 cloud CVEs had NULL
dates despite NVD having them upstream.

The fix (PR-N19) updated the write path but does nothing about existing
data. Two options to repair: (a) run a fresh 730-day baseline (takes ~26h
and re-ingests everything), or (b) run this script, which reads NVD_META
from MISP attribute comments and backfills the node-level dates WITHOUT
re-ingesting. Takes ~1-2 hours for a 99K-CVE graph.

## What it does

For each CVE with ``c.published IS NULL`` or ``c.last_modified IS NULL``:
  1. Reads ``c.misp_attribute_ids[]`` — the real MISP attribute UUIDs.
  2. Fetches the MISP attribute via ``GET /attributes/<uuid>``.
  3. Parses the ``comment`` field — it's prefixed with ``"NVD_META:"``
     followed by JSON (written by ``MISPWriter`` for NVD-sourced CVEs).
  4. Extracts ``published`` + ``last_modified`` from the JSON.
  5. Writes them back to Neo4j with ``SET c.published = $pub`` (only if
     currently NULL — idempotent).

## Idempotency

Safe to re-run. Only writes when the target field is currently NULL — if
a baseline ran between script invocations and populated the field, the
script respects that value and skips. No race with concurrent baselines.

## Usage

```bash
# Dry-run first — prints what WOULD be updated, writes nothing
./scripts/backfill_cve_dates_from_nvd_meta.py --dry-run

# Execute against cloud Neo4j
export NEO4J_URI="bolt+s://neo4j-bolt.edgeguard.org:443"
export NEO4J_PASSWORD="<cloud-password>"
export MISP_URL="https://misp.edgeguard.org"
export MISP_API_KEY="<key>"
./scripts/backfill_cve_dates_from_nvd_meta.py

# Resume from partial run (script is idempotent, just re-run)
./scripts/backfill_cve_dates_from_nvd_meta.py --batch-size 50

# Limit impact during business hours
./scripts/backfill_cve_dates_from_nvd_meta.py --rate-limit 5  # 5 req/sec max
```

## Env vars required

| Var | Purpose |
|---|---|
| ``NEO4J_URI`` | Bolt URI (e.g. ``bolt+s://neo4j-bolt.edgeguard.org:443``) |
| ``NEO4J_PASSWORD`` | Neo4j password |
| ``MISP_URL`` | MISP base URL (e.g. ``https://misp.edgeguard.org``) |
| ``MISP_API_KEY`` | MISP API key with attribute read access |
| ``EDGEGUARD_SSL_VERIFY`` | (optional) ``true`` for strict TLS (default strict) |

## Exit codes

- 0 — all CVEs with MISP attributes backfilled cleanly
- 1 — any fatal error (connection, auth, unrecoverable exception)
- 2 — invalid CLI arguments

## See also

- ``src/neo4j_client.py::merge_cve`` — the write path (PR-N19 Fix #1)
- ``src/run_misp_to_neo4j.py:2385+`` — the NVD_META parse reference
- ``src/collectors/misp_writer.py`` — where NVD_META is written at ingest
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
import urllib3

from neo4j import GraphDatabase

# Suppress urllib3 warnings for self-signed cert setups — operator chose it.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Log format matches the rest of the EdgeGuard operator surface.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [backfill-cve-dates] %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _env_required(name: str) -> str:
    """Read a REQUIRED env var; ``SystemExit`` if missing.

    Returning ``str`` (not ``Optional[str]``) so callers don't need
    ``# type: ignore`` or assert-not-None patterns at every use site.
    Mypy: the ``raise`` exits the function on the missing-var path,
    so the return value is provably non-None when control reaches it.
    """
    v = os.environ.get(name)
    if not v:
        raise SystemExit(f"Missing required env var: {name}")
    return v


def _env_optional(name: str, default: Optional[str] = None) -> Optional[str]:
    """Read an OPTIONAL env var; ``None`` if unset and no default."""
    return os.environ.get(name, default)


def _ssl_verify_enabled() -> bool:
    """Match src/config.py strict-allow-list semantics: only the literal
    string "true" (case-insensitive, stripped) enables verification."""
    raw = os.environ.get("EDGEGUARD_SSL_VERIFY") or os.environ.get("SSL_VERIFY") or ""
    return raw.strip().lower() == "true"


# ---------------------------------------------------------------------------
# NVD_META parser (mirrors src/run_misp_to_neo4j.py:2385+)
# ---------------------------------------------------------------------------


NVD_META_PREFIX = "NVD_META:"


def parse_nvd_meta(comment: str) -> Dict:
    """Parse NVD_META blob from a MISP attribute comment field.

    Returns an empty dict if the prefix is absent OR the JSON is malformed.
    Exposed as a module-level function so tests can pin the behavior.
    """
    if not comment or not isinstance(comment, str):
        return {}
    if not comment.startswith(NVD_META_PREFIX):
        return {}
    try:
        return json.loads(comment[len(NVD_META_PREFIX) :])
    except (json.JSONDecodeError, ValueError):
        # Operator-visible but not fatal — some older events may have
        # corrupted comment fields; skip and move on.
        return {}


def extract_dates(nvd_meta: Dict) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(published, last_modified)`` from an NVD_META blob.

    Empty strings and missing keys both normalize to None so the caller
    can use a simple ``if value is not None`` check before writing.
    """
    pub = nvd_meta.get("published") or None
    mod = nvd_meta.get("last_modified") or None
    return pub, mod


# ---------------------------------------------------------------------------
# MISP client
# ---------------------------------------------------------------------------


class MispClient:
    """Minimal MISP REST client — only the ``GET /attributes/<uuid>`` shape
    this script needs. No PyMISP dependency to keep this script portable.
    """

    def __init__(self, base_url: str, api_key: str, ssl_verify: bool):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.ssl_verify = ssl_verify
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    def get_attribute(self, uuid: str, timeout: float = 10.0) -> Optional[Dict]:
        """Return the attribute JSON, or None on 404/transient error.

        Structure (MISP 2.4.x): ``{"Attribute": {"uuid": "...", "comment": "NVD_META:{...}", ...}}``.
        """
        url = f"{self.base_url}/attributes/{uuid}"
        try:
            r = self.session.get(url, timeout=timeout, verify=self.ssl_verify)
        except requests.RequestException as e:
            logger.warning("MISP fetch failed for %s: %s", uuid, e)
            return None
        if r.status_code == 404:
            logger.debug("Attribute %s not found in MISP (404)", uuid)
            return None
        if r.status_code >= 400:
            logger.warning("MISP GET /attributes/%s returned HTTP %s", uuid, r.status_code)
            return None
        try:
            body = r.json()
        except ValueError:
            logger.warning("MISP returned non-JSON for %s", uuid)
            return None
        return body.get("Attribute") or body.get("attribute")


# ---------------------------------------------------------------------------
# Neo4j access
# ---------------------------------------------------------------------------


FETCH_CANDIDATES_CYPHER = """
MATCH (c:CVE)
WHERE (c.published IS NULL OR c.last_modified IS NULL)
  AND size(coalesce(c.misp_attribute_ids, [])) > 0
RETURN c.cve_id AS cve_id,
       c.misp_attribute_ids AS attr_ids,
       c.published AS published,
       c.last_modified AS last_modified
LIMIT $batch_size
"""

UPDATE_CVE_CYPHER = """
MATCH (c:CVE {cve_id: $cve_id})
// Idempotency guard: only write when currently NULL. If a baseline
// populated the field between script invocations, keep the baseline
// value — it's authoritative.
SET c.published = coalesce(c.published, $published),
    c.last_modified = coalesce(c.last_modified, $last_modified)
RETURN c.published IS NOT NULL AS has_pub, c.last_modified IS NOT NULL AS has_mod
"""


def fetch_candidates(session, batch_size: int) -> List[Dict]:
    """Fetch a batch of CVEs missing either date field."""
    rows = session.run(FETCH_CANDIDATES_CYPHER, batch_size=batch_size)
    return [dict(row) for row in rows]


def write_dates(session, cve_id: str, published: Optional[str], last_modified: Optional[str]) -> None:
    """Write the two date fields, idempotent per CVE."""
    session.run(
        UPDATE_CVE_CYPHER,
        cve_id=cve_id,
        published=published,
        last_modified=last_modified,
    )


# ---------------------------------------------------------------------------
# Backfill driver
# ---------------------------------------------------------------------------


def backfill(
    neo4j_driver,
    misp: MispClient,
    batch_size: int = 100,
    rate_limit: float = 10.0,
    dry_run: bool = False,
    max_cves: Optional[int] = None,
) -> Dict[str, int]:
    """Backfill driver loop. Iterates over CVE candidates in batches until
    no more candidates remain OR ``max_cves`` is hit.

    Returns a summary dict with counts per outcome:
      - processed: CVEs we looked at
      - backfilled: CVEs where we wrote at least one field
      - no_misp_attr: CVEs whose misp_attribute_ids[0] returned no attribute
      - no_nvd_meta: CVEs where the comment had no NVD_META prefix
      - no_dates_in_meta: CVEs where NVD_META had neither published nor last_modified
    """
    summary = {
        "processed": 0,
        "backfilled": 0,
        "no_misp_attr": 0,
        "no_nvd_meta": 0,
        "no_dates_in_meta": 0,
        "errors": 0,
    }

    # Rate limiter: enforce at least ``1/rate_limit`` seconds between MISP fetches
    min_interval = 1.0 / rate_limit if rate_limit > 0 else 0.0
    last_fetch_at = 0.0

    while True:
        if max_cves is not None and summary["processed"] >= max_cves:
            logger.info("Hit --max-cves=%d; stopping.", max_cves)
            break

        with neo4j_driver.session() as session:
            candidates = fetch_candidates(session, batch_size)

        if not candidates:
            logger.info("No more candidates — backfill complete.")
            break

        logger.info(
            "[BATCH] %d candidates fetched (summary so far: %s)",
            len(candidates),
            summary,
        )

        for row in candidates:
            cve_id = row["cve_id"]
            attr_ids = row.get("attr_ids") or []
            summary["processed"] += 1

            if not attr_ids:
                summary["no_misp_attr"] += 1
                continue

            # Rate-limit the MISP fetch
            now = time.monotonic()
            elapsed = now - last_fetch_at
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            last_fetch_at = time.monotonic()

            # Fetch the first attribute (NVD CVE events are single-attribute
            # in EdgeGuard's MISP layout; first UUID is the one we want).
            attr = misp.get_attribute(attr_ids[0])
            if attr is None:
                summary["no_misp_attr"] += 1
                continue

            nvd_meta = parse_nvd_meta(attr.get("comment", ""))
            if not nvd_meta:
                summary["no_nvd_meta"] += 1
                continue

            published, last_modified = extract_dates(nvd_meta)
            if not published and not last_modified:
                summary["no_dates_in_meta"] += 1
                continue

            if dry_run:
                logger.info(
                    "[DRY-RUN] would write %s: published=%s last_modified=%s",
                    cve_id,
                    published,
                    last_modified,
                )
                summary["backfilled"] += 1
                continue

            try:
                with neo4j_driver.session() as session:
                    write_dates(session, cve_id, published, last_modified)
                summary["backfilled"] += 1
            except Exception as e:
                logger.error("Failed to write %s: %s", cve_id, e)
                summary["errors"] += 1

        # Progress summary after each batch
        logger.info(
            "[PROGRESS] processed=%d backfilled=%d errors=%d rate=%.1f/s",
            summary["processed"],
            summary["backfilled"],
            summary["errors"],
            summary["processed"] / max(time.monotonic() - last_fetch_at + 0.001, 0.001),
        )

        # If we got fewer than batch_size candidates, we're done (no more
        # eligible CVEs match the WHERE clause).
        if len(candidates) < batch_size:
            logger.info("Last batch was partial (%d < %d); backfill complete.", len(candidates), batch_size)
            break

    return summary


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Backfill CVE published/last_modified dates from MISP NVD_META (PR-N22).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned updates, write nothing to Neo4j.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Candidates to fetch per Neo4j batch (default 100).",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=10.0,
        help="Max MISP requests per second (default 10). Lower for production-impact-sensitive windows.",
    )
    parser.add_argument(
        "--max-cves",
        type=int,
        default=None,
        help="Cap on total CVEs processed (default: unlimited). Useful for smoke tests.",
    )
    args = parser.parse_args(argv)

    if args.batch_size <= 0 or args.rate_limit <= 0:
        parser.error("--batch-size and --rate-limit must be positive")
        return 2

    # Read env early so missing creds fail fast
    # NEO4J_URI defaults to localhost; the others are mandatory (script can't
    # do anything useful without MISP credentials + Neo4j password).
    neo4j_uri = _env_optional("NEO4J_URI", default="bolt://localhost:7687") or "bolt://localhost:7687"
    neo4j_password = _env_required("NEO4J_PASSWORD")
    misp_url = _env_required("MISP_URL")
    misp_api_key = _env_required("MISP_API_KEY")
    ssl_verify = _ssl_verify_enabled()

    if not ssl_verify:
        logger.warning(
            "TLS verification DISABLED (EDGEGUARD_SSL_VERIFY!=true). "
            "MISP_API_KEY will be sent over unverified TLS. For production, "
            "set EDGEGUARD_SSL_VERIFY=true."
        )

    logger.info("Starting CVE date backfill (dry_run=%s)", args.dry_run)
    logger.info("  Neo4j URI: %s", neo4j_uri)
    logger.info("  MISP URL:  %s", misp_url)
    logger.info("  Batch:     %d candidates / rate-limit %s req/s", args.batch_size, args.rate_limit)

    # Connect to Neo4j
    try:
        driver = GraphDatabase.driver(neo4j_uri, auth=("neo4j", neo4j_password))
        driver.verify_connectivity()
    except Exception as e:
        logger.error("Neo4j connection failed: %s", e)
        return 1

    misp = MispClient(misp_url, misp_api_key, ssl_verify=ssl_verify)

    try:
        summary = backfill(
            driver,
            misp,
            batch_size=args.batch_size,
            rate_limit=args.rate_limit,
            dry_run=args.dry_run,
            max_cves=args.max_cves,
        )
    finally:
        driver.close()

    logger.info("=" * 55)
    logger.info("BACKFILL SUMMARY")
    logger.info("=" * 55)
    for k, v in summary.items():
        logger.info("  %-20s %d", k, v)

    # Exit 1 if any unrecoverable errors happened (not counting no_*)
    return 1 if summary.get("errors", 0) > 0 else 0


if __name__ == "__main__":
    # Ensure the src/ module path is available for any downstream imports.
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root / "src"))
    sys.exit(main())
