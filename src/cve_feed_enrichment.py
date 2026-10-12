#!/usr/bin/env python3
"""
EdgeGuard — CVE threat-signal feed enrichment
=============================================
Two post-sync enrichment jobs that add free, licence-clean threat signals to
existing ``CVE`` nodes. They run from ``enrichment_jobs.run_all_enrichment_jobs``.

1. ``enrich_cve_epss``          — FIRST EPSS daily gzip CSV
                                  → ``epss_score``, ``epss_percentile``,
                                    ``epss_score_date``, ``epss_model_version``
2. ``enrich_cve_vulnrichment``  — CISA Vulnrichment branch zip (CC0)
                                  → ``ssvc_exploitation``, ``ssvc_automatable``,
                                    ``ssvc_technical_impact``, ``ssvc_timestamp``

Failure contract
----------------
* Feed failures (HTTP error, timeout, bad payload, size cap) are logged at ERROR
  and the job returns ``{"skipped": "<reason>"}``; they never raise, because the
  DAG task runs every enrichment job in one PythonOperator.
* Database failures raise (PR-N21 rule). A partial batch failure therefore
  aborts the job and the next run re-applies the whole feed (idempotent SET).
* Feeds are never written to disk, except the Vulnrichment archive which is
  streamed to a temp file that is always deleted.
"""

import gzip
import io
import json
import logging
import os
import re
import sys
import tempfile
import zipfile
import zlib
from typing import Dict, List, Optional, Set, Tuple

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
_SSVC_ALLOWED = {
    "exploitation": {"none", "poc", "active"},
    "automatable": {"yes", "no"},
    "technical_impact": {"partial", "total"},
}
VULNRICHMENT_BATCH_SIZE = 2000
_CHUNK_BYTES = 1024 * 1024
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CVE_FILE_RE = re.compile(r"^(CVE-\d{4}-\d{4,})\.json$")
_EPSS_META_RE = re.compile(r"(\w+):([^,\s]+)")


class FeedError(Exception):
    """A feed could not be fetched or parsed. Caught inside the jobs."""


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------


def fetch_epss_bytes(url: str) -> bytes:
    """Download the EPSS gzip CSV into memory, capped at ``EPSS_MAX_BYTES``. Raises ``FeedError``."""
    max_bytes = config.EPSS_MAX_BYTES
    total = 0
    parts: List[bytes] = []
    try:
        resp = requests.get(url, timeout=(10, 120), stream=True, allow_redirects=True)
        resp.raise_for_status()
        for chunk in resp.iter_content(chunk_size=_CHUNK_BYTES):
            total += len(chunk)
            if total > max_bytes:
                logger.error("[EPSS] download aborted at %d bytes (cap %d)", total, max_bytes)
                raise FeedError(f"EPSS download exceeds cap of {max_bytes} bytes")
            parts.append(chunk)
    except requests.RequestException as exc:
        raise FeedError(f"EPSS download failed: {exc}") from exc
    logger.info("[EPSS] downloaded %d bytes", total)
    return b"".join(parts)


def parse_epss(raw: bytes) -> Tuple[Optional[str], Optional[str], List[Dict], int]:
    """Parse the EPSS gzip CSV with bounded, line-wise decompression.

    Returns ``(model_version, score_date, rows, skipped)``. ``rows`` are
    ``{"cve", "epss", "percentile"}`` dicts. The first line is a comment
    ``#model_version:v2026.06.15,score_date:2026-10-11T12:00:25Z``. Raises
    ``FeedError`` on bad gzip, output above ``EPSS_MAX_DECOMPRESSED_BYTES``, or an empty feed.
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
    # Bound header-derived values before they reach the graph.
    return (
        model_version[:_MAX_VALUE_CHARS] if model_version else None,
        score_date[:_MAX_VALUE_CHARS] if score_date else None,
        rows,
        skipped,
    )


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


_EPSS_CYPHER = """
UNWIND $rows AS r
MATCH (c:CVE {cve_id: r.cve})
SET c.epss_score = r.epss,
    c.epss_percentile = r.percentile,
    c.epss_score_date = $score_date,
    c.epss_model_version = $model_version,
    c.epss_updated_at = datetime()
RETURN count(c) AS updated
"""


def enrich_cve_epss(neo4j_client) -> Dict:
    """Set EPSS properties on ``CVE`` nodes that already exist in the graph."""
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
    updated = _apply_batches(
        neo4j_client,
        _EPSS_CYPHER,
        rows,
        EPSS_BATCH_SIZE,
        "EPSS",
        score_date=score_date,
        model_version=model_version,
    )

    logger.info("[EPSS] updated %d CVE nodes", updated)
    return {
        "rows_in_feed": len(rows),
        "cves_updated": updated,
        "rows_skipped": skipped,
        "score_date": score_date,
        "model_version": model_version,
    }


# ---------------------------------------------------------------------------
# CISA Vulnrichment
# ---------------------------------------------------------------------------


def download_vulnrichment_archive(url: str, max_bytes: int) -> str:
    """Stream the branch zip to a temp file and return its path.

    Aborts (and deletes the file) when more than *max_bytes* arrive. The caller
    owns the returned file and must delete it. Raises ``FeedError``.
    """
    tmp = tempfile.NamedTemporaryFile(prefix="vulnrichment_", suffix=".zip", delete=False)
    path = tmp.name
    total = 0
    try:
        with tmp:
            resp = requests.get(url, timeout=(10, 600), stream=True, allow_redirects=True)
            resp.raise_for_status()
            for chunk in resp.iter_content(chunk_size=_CHUNK_BYTES):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise FeedError(f"Vulnrichment archive exceeds cap of {max_bytes} bytes")
                tmp.write(chunk)
    except BaseException as exc:
        logger.info("[VULNRICHMENT] downloaded %d bytes before abort", total)
        _remove_quietly(path)
        if isinstance(exc, requests.RequestException):
            raise FeedError(f"Vulnrichment download failed: {exc}") from exc
        if isinstance(exc, OSError):
            raise FeedError(f"Vulnrichment download could not be stored: {exc}") from exc
        raise
    logger.info("[VULNRICHMENT] downloaded %d bytes", total)
    return path


def _remove_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def parse_vulnrichment_record(raw: bytes) -> Optional[Dict]:
    """Extract SSVC data from one CVE-JSON-5 Vulnrichment file.

    Returns ``{"exploitation", "automatable", "technical_impact", "timestamp"}``
    (missing or out-of-allow-list values are ``None``) or ``None`` when the
    file has no usable CISA-ADP SSVC data or is malformed. Never raises.
    """
    try:
        return _parse_vulnrichment_record(raw)
    except (ValueError, AttributeError, TypeError, KeyError):
        return None


def _dicts(value) -> List[Dict]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _parse_vulnrichment_record(raw: bytes) -> Optional[Dict]:
    doc = json.loads(raw)
    containers = doc.get("containers") if isinstance(doc, dict) else None
    out: Dict = {"exploitation": None, "automatable": None, "technical_impact": None, "timestamp": None}
    found = False
    for adp in _dicts((containers or {}).get("adp")):
        meta = adp.get("providerMetadata")
        if not isinstance(meta, dict) or meta.get("shortName") != "CISA-ADP":
            continue
        for metric in _dicts(adp.get("metrics")):
            other = metric.get("other")
            if not isinstance(other, dict) or str(other.get("type", "")).lower() != "ssvc":
                continue
            content = other.get("content")
            if not isinstance(content, dict):
                continue
            for opt in _dicts(content.get("options")):
                for key, field in (
                    ("Exploitation", "exploitation"),
                    ("Automatable", "automatable"),
                    ("Technical Impact", "technical_impact"),
                ):
                    value = str(opt[key]).strip().lower() if opt.get(key) is not None else None
                    if value in _SSVC_ALLOWED[field]:
                        out[field] = value
                        found = True
            if content.get("timestamp"):
                out["timestamp"] = str(content["timestamp"])[:_MAX_VALUE_CHARS]
    return out if found else None


_VULNRICHMENT_CYPHER = """
UNWIND $rows AS r
MATCH (c:CVE {cve_id: r.cve})
SET c.ssvc_exploitation = coalesce(r.exploitation, c.ssvc_exploitation),
    c.ssvc_automatable = coalesce(r.automatable, c.ssvc_automatable),
    c.ssvc_technical_impact = coalesce(r.technical_impact, c.ssvc_technical_impact),
    c.ssvc_timestamp = coalesce(r.timestamp, c.ssvc_timestamp),
    c.ssvc_updated_at = datetime()
RETURN count(c) AS updated
"""


def _load_graph_cve_ids(neo4j_client) -> Set[str]:
    with neo4j_client.driver.session() as session:
        result = session.run("MATCH (c:CVE) RETURN c.cve_id AS cve_id", timeout=NEO4J_READ_TIMEOUT)
        return {r["cve_id"] for r in result if r["cve_id"]}


def read_vulnrichment_archive(path: str, graph_ids: Set[str]) -> Tuple[List[Dict], int, int]:
    """Read matching CVE files from the zip. Returns ``(rows, records_in_archive, skipped)``."""
    rows: List[Dict] = []
    in_archive = 0
    skipped = 0
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise FeedError(f"Vulnrichment archive is not a valid zip: {exc}") from exc
    with zf:
        members = zf.infolist()
        if len(members) > config.VULNRICHMENT_MAX_MEMBERS:
            raise FeedError(f"Vulnrichment archive has {len(members)} members (cap {config.VULNRICHMENT_MAX_MEMBERS})")
        for info in members:
            if info.is_dir():
                continue
            m = _CVE_FILE_RE.fullmatch(info.filename.rsplit("/", 1)[-1])
            if not m:
                continue
            in_archive += 1
            cve_id = m.group(1)
            if cve_id not in graph_ids:
                continue
            if info.file_size > config.VULNRICHMENT_MAX_MEMBER_BYTES:
                skipped += 1
                continue
            try:
                rec = parse_vulnrichment_record(zf.read(info))
            except (zipfile.BadZipFile, OSError, zlib.error, RuntimeError):
                rec = None
            if rec is None:
                skipped += 1
                continue
            rec["cve"] = cve_id
            rows.append(rec)
    return rows, in_archive, skipped


def enrich_cve_vulnrichment(neo4j_client) -> Dict:
    """Set SSVC properties on existing ``CVE`` nodes."""
    graph_ids = _load_graph_cve_ids(neo4j_client)
    logger.info("[VULNRICHMENT] %d CVE ids in graph", len(graph_ids))

    path: Optional[str] = None
    try:
        path = download_vulnrichment_archive(config.VULNRICHMENT_ARCHIVE_URL, config.VULNRICHMENT_MAX_BYTES)
        rows, in_archive, skipped = read_vulnrichment_archive(path, graph_ids)
    except FeedError as exc:
        logger.error("[VULNRICHMENT] feed unavailable, skipping: %s", exc)
        return {"skipped": str(exc)}
    finally:
        if path:
            _remove_quietly(path)

    logger.info(
        "[VULNRICHMENT] archive records=%d usable_matches=%d unusable=%d",
        in_archive,
        len(rows),
        skipped,
    )
    updated = _apply_batches(neo4j_client, _VULNRICHMENT_CYPHER, rows, VULNRICHMENT_BATCH_SIZE, "VULNRICHMENT")

    logger.info("[VULNRICHMENT] updated %d CVE nodes", updated)
    return {
        "records_in_archive": in_archive,
        "records_matched": len(rows),
        "cves_updated": updated,
        "records_skipped": skipped,
    }
