#!/usr/bin/env python3
"""
EdgeGuard — CVE exploit-likelihood enrichment (FIRST EPSS)
==========================================================
A post-sync enrichment job that adds FIRST's Exploit Prediction Scoring System (EPSS) to the
``CVE`` nodes that already exist. It runs from ``enrichment_jobs.run_all_enrichment_jobs``, at
every Neo4j sync and after the baseline.

``enrich_cve_epss`` reads FIRST's daily gzip CSV and sets ``epss_score``, ``epss_percentile``,
``epss_score_date``, ``epss_model_version`` and ``epss_updated_at``. A CVE that has left the feed
(NVD rejected it, for example) loses its EPSS properties once the whole feed has been written.

EPSS is the one source EdgeGuard writes straight to Neo4j instead of through MISP: it is a new score
for every published CVE every day (about 390,000 rows), a measurement of the CVE rather than
threat intelligence about it, and MISP would only hold a copy of it. CISA's SSVC decision points come
with the NVD records instead (``nvd_collector``, ``NVD_META``), through MISP like every other source.

Failure contract
----------------
* Feed failures (HTTP error, timeout, deadline, bad payload, size cap) are logged at ERROR and the
  job returns ``{"skipped": "<reason>"}``; they never raise, because the DAG task runs every
  enrichment job in one PythonOperator.
* Database failures raise (PR-N21 rule). A partial batch failure therefore aborts the job before
  any value is cleared, and the next run re-applies the whole feed (idempotent SET).
* The feed is never written to disk.
"""

import gzip
import io
import logging
import os
import re
import sys
import time
import zlib
from typing import Dict, List, Optional, Tuple

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config  # noqa: E402
from neo4j_client import NEO4J_READ_TIMEOUT  # noqa: E402
from query_pause import query_pause  # noqa: E402

logger = logging.getLogger(__name__)

EPSS_BATCH_SIZE = 5000
EPSS_MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024
_MAX_LINE_CHARS = 65536
_MAX_VALUE_CHARS = 64
_CHUNK_BYTES = 1024 * 1024
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_EPSS_META_RE = re.compile(r"(\w+):([^,\s]+)")
# A feed holding fewer rows than this share of the CVE nodes that already have EPSS is not used to
# clear values: a short file must never wipe the scores of the graph.
_MIN_FEED_SHARE_FOR_CLEARING = 0.5


class FeedError(Exception):
    """The feed could not be fetched or parsed. Caught inside the job."""


def fetch_epss_bytes(url: str) -> bytes:
    """Download the EPSS gzip CSV into memory, within ``EPSS_MAX_BYTES`` and
    ``EPSS_DOWNLOAD_DEADLINE_SEC``. Raises ``FeedError``."""
    max_bytes = config.EPSS_MAX_BYTES
    deadline = time.monotonic() + config.EPSS_DOWNLOAD_DEADLINE_SEC
    total = 0
    parts: List[bytes] = []
    try:
        resp = requests.get(url, timeout=(10, 120), stream=True, allow_redirects=True)
        try:
            resp.raise_for_status()
            for chunk in resp.iter_content(chunk_size=_CHUNK_BYTES):
                total += len(chunk)
                if total > max_bytes:
                    logger.error("[EPSS] download aborted at %d bytes (cap %d)", total, max_bytes)
                    raise FeedError(f"EPSS download exceeds cap of {max_bytes} bytes")
                if time.monotonic() > deadline:
                    # Per-read timeouts only bound a stalled connection; a trickling one could otherwise
                    # hold the enrichment task until its own limit, after the other jobs succeeded.
                    raise FeedError(f"EPSS download exceeds {config.EPSS_DOWNLOAD_DEADLINE_SEC} s")
                parts.append(chunk)
        finally:
            resp.close()  # an aborted stream would otherwise keep its connection open
    except requests.RequestException as exc:
        raise FeedError(f"EPSS download failed: {exc}") from exc
    logger.info("[EPSS] downloaded %d bytes", total)
    return b"".join(parts)


def parse_epss(raw: bytes) -> Tuple[Optional[str], str, List[Dict], int]:
    """Parse the EPSS gzip CSV with bounded, line-wise decompression.

    Returns ``(model_version, score_date, rows, skipped)``. ``rows`` are
    ``{"cve", "epss", "percentile"}`` dicts. The first line is a comment
    ``#model_version:v2026.06.15,score_date:2026-10-11T12:00:25Z``. Raises
    ``FeedError`` on bad gzip, output above ``EPSS_MAX_DECOMPRESSED_BYTES``, a feed without a
    ``score_date`` (it is what tells a current value from a stale one), or an empty feed.
    """
    model_version: Optional[str] = None
    score_date: Optional[str] = None
    rows: List[Dict] = []
    skipped = 0
    header_seen = False
    total = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            text = io.TextIOWrapper(gz, encoding="utf-8", errors="replace")
            while True:
                line = text.readline(_MAX_LINE_CHARS)
                if not line:
                    break
                total += len(line)
                if total > EPSS_MAX_DECOMPRESSED_BYTES:
                    raise FeedError(f"EPSS decompressed size exceeds cap of {EPSS_MAX_DECOMPRESSED_BYTES} bytes")
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    meta = dict(_EPSS_META_RE.findall(line.lstrip("#")))
                    model_version = meta.get("model_version", model_version)
                    score_date = meta.get("score_date", score_date)
                    continue
                fields = [f.strip() for f in line.split(",")]
                if not header_seen:
                    if [f.lower() for f in fields[:3]] != ["cve", "epss", "percentile"]:
                        raise FeedError("EPSS feed has no 'cve,epss,percentile' header")
                    header_seen = True
                    continue
                try:
                    cve, epss, pct = fields[0].upper(), float(fields[1]), float(fields[2])
                except (IndexError, ValueError):
                    skipped += 1
                    continue
                if not _CVE_ID_RE.fullmatch(cve) or not (0.0 <= epss <= 1.0) or not (0.0 <= pct <= 1.0):
                    skipped += 1
                    continue
                rows.append({"cve": cve, "epss": epss, "percentile": pct})
    except (OSError, EOFError, zlib.error) as exc:
        raise FeedError(f"EPSS payload is not valid gzip: {exc}") from exc
    if not header_seen:
        raise FeedError("EPSS feed has no 'cve,epss,percentile' header")
    if not rows:
        raise FeedError("EPSS feed contains no valid rows")
    if not score_date:
        raise FeedError("EPSS feed has no score_date")
    # Bound header-derived values before they reach the graph.
    return (
        model_version[:_MAX_VALUE_CHARS] if model_version else None,
        score_date[:_MAX_VALUE_CHARS],
        rows,
        skipped,
    )


# Only CVE nodes that exist are touched (MATCH). A node a partner created first gets the
# shared-database marker ``edgeguard_enriched`` (docs/RESILMESH_INTEROPERABILITY.md, §3.4).
_EPSS_CYPHER = """
UNWIND $rows AS r
MATCH (c:CVE {cve_id: r.cve})
SET c.epss_score = r.epss,
    c.epss_percentile = r.percentile,
    c.epss_score_date = $score_date,
    c.epss_model_version = $model_version,
    c.epss_updated_at = datetime(),
    c.edgeguard_enriched = CASE WHEN c.edgeguard_managed = true THEN c.edgeguard_enriched ELSE true END
RETURN count(c) AS updated
"""

_EPSS_SCORED_CYPHER = "MATCH (c:CVE) WHERE c.epss_score IS NOT NULL RETURN count(c) AS scored"

# After the whole feed is written: a CVE whose EPSS is from an earlier file has left the feed.
_EPSS_CLEAR_CYPHER = """
MATCH (c:CVE)
WHERE c.epss_score IS NOT NULL AND c.epss_score_date <> $score_date
REMOVE c.epss_score, c.epss_percentile, c.epss_score_date, c.epss_model_version, c.epss_updated_at
RETURN count(c) AS cleared
"""


def _apply_batches(neo4j_client, cypher: str, rows: List[Dict], batch_size: int, label: str, **params) -> int:
    """Run *cypher* over *rows* in batches; return the summed ``updated`` count.

    Database errors are logged and re-raised (PR-N21): a later run re-applies the whole feed.
    """
    updated = 0
    try:
        with neo4j_client.driver.session() as session:
            for i in range(0, len(rows), batch_size):
                result = session.run(cypher, rows=rows[i : i + batch_size], timeout=NEO4J_READ_TIMEOUT, **params)
                record = result.single()
                updated += record["updated"] if record else 0
                query_pause()
    except Exception:
        logger.error("[%s] Cypher batch failed; a later run re-applies the whole feed", label, exc_info=True)
        raise
    return updated


def _single_value(neo4j_client, cypher: str, key: str, **params) -> int:
    with neo4j_client.driver.session() as session:
        record = session.run(cypher, timeout=NEO4J_READ_TIMEOUT, **params).single()
        return int((record[key] if record else 0) or 0)


def enrich_cve_epss(neo4j_client) -> Dict:
    """Set EPSS properties on the ``CVE`` nodes that exist, and clear them where the feed dropped the CVE."""
    url = config.EPSS_URL
    try:
        raw = fetch_epss_bytes(url)
        model_version, score_date, rows, skipped = parse_epss(raw)
    except FeedError as exc:
        logger.error("[EPSS] feed unavailable, skipping: %s", exc)
        return {"skipped": str(exc)}

    logger.info(
        "[EPSS] parsed %d rows (%d malformed) model_version=%s score_date=%s",
        len(rows),
        skipped,
        model_version,
        score_date,
    )
    scored_before = _single_value(neo4j_client, _EPSS_SCORED_CYPHER, "scored")
    updated = _apply_batches(
        neo4j_client,
        _EPSS_CYPHER,
        rows,
        EPSS_BATCH_SIZE,
        "EPSS",
        score_date=score_date,
        model_version=model_version,
    )
    if len(rows) < _MIN_FEED_SHARE_FOR_CLEARING * scored_before:
        logger.warning(
            "[EPSS] the feed holds %d rows, fewer than %d%% of the %d CVE nodes scored before; "
            "earlier scores are kept, not cleared",
            len(rows),
            int(_MIN_FEED_SHARE_FOR_CLEARING * 100),
            scored_before,
        )
        cleared = 0
    else:
        cleared = _single_value(neo4j_client, _EPSS_CLEAR_CYPHER, "cleared", score_date=score_date)

    if updated == 0 and _single_value(neo4j_client, "MATCH (c:CVE) RETURN count(c) AS cves", "cves") > 0:
        # Every published CVE is in the feed, so CVE nodes with no match mean a changed format or id
        # scheme, not an absence of data.
        logger.warning("[EPSS] no CVE node matched the %d feed rows", len(rows))
    logger.info("[EPSS] updated %d CVE nodes, cleared %d that left the feed", updated, cleared)
    return {
        "rows_in_feed": len(rows),
        "cves_updated": updated,
        "cves_cleared": cleared,
        "rows_skipped": skipped,
        "score_date": score_date,
        "model_version": model_version,
    }
