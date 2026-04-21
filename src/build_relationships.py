#!/usr/bin/env python3
"""
EdgeGuard - Graph Relationship Builder
Creates edges between nodes in Neo4j

FIXED: Uses exact matching with confidence scoring instead of fuzzy CONTAINS matching
to prevent false positives (e.g., "APT" matching "AP").
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging

from config import VALID_ZONES
from neo4j_client import Neo4jClient
from node_identity import compute_node_uuid
from query_pause import query_pause

try:
    from metrics_server import record_neo4j_relationships

    _METRICS_AVAILABLE = True
except ImportError:
    _METRICS_AVAILABLE = False

# PR #40 (Performance Auditor Tier S S10): the previous hardcoded
# ``_INTER_QUERY_PAUSE = 3`` × 12 sites burned 36 seconds of pure idle
# time per build_relationships run, scheduler-blocking with no Neo4j
# work happening. Now env-gated to 0 by default via ``query_pause()``;
# operators on memory-constrained Neo4j who genuinely need pacing can
# set ``EDGEGUARD_QUERY_PAUSE_SECONDS=1`` (or whatever) without a code
# change. See ``src/query_pause.py`` for the rationale.

# Pre-computed Sector node uuids for the known zones — used in the TARGETS
# (7a) and AFFECTS (7b) queries below to stamp ``sec.uuid`` on Sector nodes
# auto-CREATEd by those MERGEs. Bugbot caught (PR #33 round 4) that without
# this stamp ``sec.uuid`` was NULL and downstream ``r.trg_uuid = sec.uuid``
# inherited NULL. APOC's apoc.create.uuid is random (v4) — no use for our
# deterministic UUIDv5 — so we precompute in Python and embed as a Cypher
# CASE expression literal in the query string.
#
# IMPORTANT (PR #33 round 6, bugbot HIGH): the CASE expression uses DOUBLE
# quotes for both the WHEN labels and the THEN literals. The 7a/7b queries
# are run via ``_safe_run_batched`` which wraps the inner query in SINGLE
# quotes inside ``apoc.periodic.iterate('outer', 'inner', ...)``. Single
# quotes inside the CASE would terminate the inner string early and break
# the rendered Cypher. Cypher accepts both ' and " as string delimiters.
#
# PR #34 round 24 (bugbot MED): derive the zone set from ``VALID_ZONES`` in
# ``config.py`` — the single source of truth for what counts as a valid
# EdgeGuard zone. Previously the tuple was hardcoded here; adding a 5th
# zone to ``VALID_ZONES`` without updating this file would silently drop
# the new zone from both the CASE expression (Sector uuid stamping) and
# the IN filter (zone-membership check in 7a/7b), producing Sector nodes
# with NULL uuid. ``sorted(VALID_ZONES)`` fixes the iteration order so
# the generated Cypher is stable across Python runs (frozenset iteration
# order is implementation-defined).
_SECTOR_UUIDS: dict = {z: compute_node_uuid("Sector", {"name": z}) for z in sorted(VALID_ZONES)}
_SECTOR_UUID_CASE = (
    "CASE zone_name " + " ".join(f'WHEN "{name}" THEN "{u}"' for name, u in _SECTOR_UUIDS.items()) + " END"
)
# PR #33 round 12: derive the zone IN list from _SECTOR_UUIDS keys so adding
# a 5th zone only requires updating VALID_ZONES (single source of truth).
# Same double-quote convention as the CASE expression.
_SECTOR_IN_LIST = "[" + ", ".join(f'"{name}"' for name in _SECTOR_UUIDS) + "]"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _assert_no_unsafe_empty_string_literal_in_outer_queries() -> None:
    """PR-N7 (2026-04-21 on-call from Bravo Vanko): module-load regression
    guard against the ``<> ''`` quote-escape bug.

    History: the ``_safe_run_batched`` helper wraps both outer_query and
    inner_query in SINGLE quotes for apoc.periodic.iterate:

        CALL apoc.periodic.iterate('<outer>', '<inner>', {...})

    If ``<outer>`` contains a Cypher single-quoted empty-string literal
    ``''`` (e.g. ``WHERE i.cve_id <> ''``), the literal's closing quote
    prematurely terminates the apoc wrapper's string → rendered Cypher
    becomes a syntax error (``Invalid input '' RETURN i'``) → the
    step fails silently in ``_safe_run_batched``'s try/except → zero
    edges created.

    Pre-fix 4 outer queries (steps 2, 3a, 3b, 9) had this pattern and
    were producing ZERO edges on every baseline run — discovered by
    Bravo Vanko's on-call investigation of a 2026-04-21 deadlocked
    pipeline. The fix replaces ``x <> ''`` with ``size(x) > 0`` (same
    semantics for strings, no quotes needed).

    This guard scans the module's own source at import time for
    ``<> ''`` inside a string literal and raises ``RuntimeError``.
    If a future maintainer re-introduces the pattern, the import
    fails loudly at CI startup instead of silently at production
    baseline time.

    The check uses AST walking so docstring comments that legitimately
    describe the old pattern (like this one, for breadcrumb purposes)
    don't false-match.
    """
    import ast
    import pathlib

    this_file = pathlib.Path(__file__).resolve()
    try:
        source = this_file.read_text()
        tree = ast.parse(source)
    except Exception:
        # Can't scan; log a soft warning and continue rather than hard-fail
        # (defensive — don't break the module on a filesystem edge case).
        logger.debug("PR-N7 regression guard: could not parse own source for <> '' scan")
        return

    findings: list = []
    for node in ast.walk(tree):
        # Only look inside string Constants that are assigned to a
        # variable whose name contains "outer" or "inner" (the two
        # args we wrap in apoc.periodic.iterate single quotes).
        if isinstance(node, ast.Assign):
            target_names = [
                t.id
                for t in node.targets
                if isinstance(t, ast.Name) and ("outer" in t.id.lower() or "inner" in t.id.lower())
            ]
            if not target_names:
                continue
            # Inspect the assigned value — handles both a direct string
            # Constant and the tuple-of-strings idiom used by some
            # multi-line inner-query assignments in this module.
            for const_node in ast.walk(node.value):
                if isinstance(const_node, ast.Constant) and isinstance(const_node.value, str):
                    if "<> ''" in const_node.value:
                        findings.append((target_names[0], node.lineno))

    if findings:
        raise RuntimeError(
            "PR-N7 regression guard triggered: outer/inner query variables "
            f"{findings!r} contain the dangerous `<> ''` pattern. This "
            "breaks apoc.periodic.iterate's single-quote wrapper and causes "
            "silent zero-edge failures. Replace with `size(x) > 0` (same "
            "semantics for strings, no quote conflict). See the "
            "_assert_no_unsafe_empty_string_literal_in_outer_queries "
            "docstring for the history."
        )


# Load-time check: if someone re-introduces the bug, module import fails
# in CI before the code ever ships. Cheap to run (one AST parse at import).
_assert_no_unsafe_empty_string_literal_in_outer_queries()


def _safe_run(client, label: str, query: str, stats: dict, stat_key: str) -> bool:
    """Run a single relationship query with fault tolerance.

    Returns True on success, False on failure (logged, not raised).
    """
    try:
        result = client.run(query)
        stats[stat_key] = result[0].get("count", 0) if result else 0
        logger.info(f"  [OK] {label}: {stats[stat_key]}")
        return True
    except Exception as e:
        logger.error(f"  [FAIL] {label}: {type(e).__name__}: {e}", exc_info=True)
        stats[stat_key] = 0
        return False


def _safe_run_batched(
    client,
    label,
    outer_query,
    inner_query,
    stats,
    stat_key,
    batch_size=5000,
    skip_query=None,
):
    """Run a relationship query in batches using apoc.periodic.iterate.

    Splits the work into mini-transactions of batch_size to prevent OOM.
    Returns True on success (zero APOC errorMessages), False on partial or
    full failure (PR #33 round 13: previously returned True even when
    apoc.periodic.iterate reported errorMessages — silent partial failure).

    If ``skip_query`` is provided (a Cypher string returning a single
    column ``c``), it is run BEFORE the apoc batch and is expected to
    count input rows whose inner-MATCH target does NOT exist (the orphan
    rows that the inner action will silently drop). When > 0, an INFO
    ``[SKIP]`` log is emitted so the operator can see how many edges
    were silently lost.

    PR #34 round 20: replaces the broken ``expected_query`` semantics from
    round 13 — that compared APOC ``total`` (count of outer-query rows
    that ran the inner action, regardless of inner success) against
    "rows where target exists" (a subset of outer rows). The comparison
    ``expected > count`` was always false (subset ≤ superset), so the
    skip-count log NEVER fired. The new ``skip_query`` semantics counts
    orphans directly, no comparison needed.
    """
    skip_count = None
    if skip_query is not None:
        try:
            skip_result = client.run(skip_query)
            if skip_result:
                skip_count = skip_result[0].get("c", 0)
        except Exception as exp_err:
            logger.debug("skip_query failed for %s — skip-count log will be omitted: %s", label, exp_err)

    # PR-N7 (2026-04-21 on-call from Bravo Vanko): pre-log the outer
    # row count BEFORE starting apoc.periodic.iterate so operators
    # can see the scale of work. Pre-fix the pipeline sat silent for
    # 5+ hours during step 4 (144K-indicator co-occurrence); the
    # subprocess was found dead with no log breadcrumb explaining the
    # scale. ``apoc.periodic.iterate`` doesn't emit mid-flight
    # progress, but pre+post logs + elapsed time give operators a
    # "size-of-work" signal to compare against wall-clock.
    outer_count = None
    try:
        outer_count_query = f"CALL {{ {outer_query} }} RETURN count(*) AS c"
        count_result = client.run(outer_count_query)
        if count_result:
            outer_count = count_result[0].get("c", 0)
            logger.info(
                "[LINK] %s: %s outer rows × batch_size %d = ~%d apoc batches expected",
                label,
                f"{outer_count:,}",
                batch_size,
                max(1, (outer_count + batch_size - 1) // batch_size),
            )
    except Exception as _count_err:
        # Count-preamble is best-effort; don't block the actual work
        # on a failed COUNT query (would be weird but possible on a
        # malformed outer).
        logger.debug("pre-count failed for %s: %s", label, _count_err)

    query = f"""
    CALL apoc.periodic.iterate(
        '{outer_query}',
        '{inner_query}',
        {{batchSize: {batch_size}, parallel: false}}
    )
    YIELD batches, total, errorMessages
    RETURN total AS count, batches, errorMessages
    """
    # Timing measurement + explicit start log so operators see the
    # apoc call boundary in logs (distinguishes "APOC running" from
    # "APOC never started" during multi-hour stalls).
    import time as _time

    _start = _time.time()
    logger.info("[LINK] %s: starting apoc.periodic.iterate (batch_size=%d)...", label, batch_size)
    try:
        result = client.run(query)
        _elapsed = _time.time() - _start
        if result:
            row = result[0]
            count = row.get("count", 0)
            batches_n = row.get("batches", 0)
            errors = row.get("errorMessages", []) or []
            stats[stat_key] = count
            if errors:
                logger.warning(
                    f"  [PARTIAL] {label}: {count} in {batches_n} batches, "
                    f"elapsed {_elapsed:.1f}s, errors: {errors[:3]}"
                    f"{' (+more)' if len(errors) > 3 else ''}"
                )
            else:
                logger.info(f"  [OK] {label}: {count} in {batches_n} batches, elapsed {_elapsed:.1f}s")
            # PR #34 round 20: orphan-count log when skip_query was provided.
            # No comparison needed — skip_count IS the count of input rows
            # whose target doesn't exist.
            if skip_count is not None and skip_count > 0:
                logger.info(
                    "  [SKIP] %s: %d input rows had no matching target node (likely missing prerequisite ingestion)",
                    label,
                    skip_count,
                )
            # PR #33 round 13: errorMessages now flips return value to False so
            # the caller's failures counter reflects partial APOC errors.
            return not errors
        else:
            stats[stat_key] = 0
            logger.info(f"  [OK] {label}: 0 (no matches), elapsed {_elapsed:.1f}s")
            return True
    except Exception as e:
        _elapsed = _time.time() - _start
        # PR-N8 HIGH (audit Bug Hunter H3, 2026-04-21): narrow the
        # exception catch. Pre-fix, a blanket ``except Exception``
        # swallowed Neo4j transient failures
        # (``ServiceUnavailable``, ``SessionExpired``,
        # ``TransientError``) and counted them as the step "failing"
        # once, then the pipeline moved on. A 30-second Neo4j restart
        # mid-pipeline silently zeroed a step's edge count instead of
        # retrying. Operator sees "11/12 succeeded" in the SUMMARY and
        # misses the real failure.
        #
        # Post-fix: re-raise transient classes so the outer layer
        # (Airflow retry policy, or a future @retry_with_backoff
        # wrapper) can decide to retry the whole step. Keep the
        # catch-and-continue behaviour ONLY for non-transient Cypher
        # errors (syntax errors, constraint violations, write
        # conflicts) where retrying the SAME query won't help.
        try:
            from neo4j import exceptions as _neo4j_exc

            _transient_classes: tuple = (
                _neo4j_exc.ServiceUnavailable,
                _neo4j_exc.SessionExpired,
                _neo4j_exc.TransientError,
            )
        except ImportError:
            # If neo4j package isn't available (test shell, dry-run),
            # fall back to the old catch-everything behaviour — this
            # branch doesn't matter in production where neo4j is
            # always installed.
            _transient_classes = ()
        if _transient_classes and isinstance(e, _transient_classes):
            logger.error(
                "  [FAIL-TRANSIENT] %s after %.1fs: %s: %s — re-raising so caller can retry",
                label,
                _elapsed,
                type(e).__name__,
                e,
                exc_info=True,
            )
            raise
        logger.error(
            "  [FAIL] %s after %.1fs: %s: %s",
            label,
            _elapsed,
            type(e).__name__,
            e,
            exc_info=True,
        )
        stats[stat_key] = 0
        return False


def build_relationships():
    """Build relationships between nodes using exact matching with confidence scoring."""
    client = Neo4jClient()

    if not client.connect():
        logger.error("Failed to connect to Neo4j")
        return False

    stats = {}
    failures = 0

    try:
        # 1. Technique → Tactic (IN_TACTIC) — kill-chain phase match
        logger.info("[LINK] 1/12 Technique → Tactic (kill-chain phase match)...")
        _outer = "MATCH (t:Technique) WHERE size(coalesce(t.tactic_phases, [])) > 0 RETURN t"
        _inner = 'WITH $t AS t MATCH (tc:Tactic) WHERE tc.shortname IS NOT NULL AND any(phase IN [p IN coalesce(t.tactic_phases, []) WHERE p IS NOT NULL] WHERE toLower(phase) = toLower(tc.shortname)) MERGE (t)-[r:IN_TACTIC]->(tc) ON CREATE SET r.confidence_score = 1.0, r.match_type = "kill_chain_phase", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, t.uuid), r.trg_uuid = coalesce(r.trg_uuid, tc.uuid)'
        if not _safe_run_batched(client, "Technique → Tactic", _outer, _inner, stats, "in_tactic"):
            failures += 1
        query_pause()

        # 2. Malware → ThreatActor (ATTRIBUTED_TO) — exact name match
        #
        # PR-N8 HIGH (audit Bug Hunter M5, 2026-04-21): apply trim()+
        # toLower() canonicalization parity. Pre-fix ``a.name`` was
        # NFC+strip+lower'd at ingest via ``canonicalize_merge_key``
        # (PR #37) while ``m.attributed_to`` was stored RAW. A MITRE
        # source emitting ``"APT29"`` on Malware.attributed_to
        # silently missed the actor stored as ``"apt29"``. Same class
        # of bug as Q9 / Fix #4 above — canonicalization parity
        # between ingest-time and relationship-time Cypher.
        logger.info("[LINK] 2/12 Malware → ThreatActor (exact name match)...")
        _outer = "MATCH (m:Malware) WHERE (m.attributed_to IS NOT NULL AND size(m.attributed_to) > 0) OR size(coalesce(m.aliases, [])) > 0 RETURN m"
        _inner = 'WITH $m AS m MATCH (a:ThreatActor) WHERE toLower(trim(coalesce(m.attributed_to, ""))) = toLower(trim(a.name)) OR toLower(trim(coalesce(m.attributed_to, ""))) IN [x IN coalesce(a.aliases, []) | toLower(trim(x))] OR toLower(trim(a.name)) IN [x IN coalesce(m.aliases, []) | toLower(trim(x))] MERGE (m)-[r:ATTRIBUTED_TO]->(a) ON CREATE SET r.confidence_score = 1.0, r.match_type = "exact", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, m.uuid), r.trg_uuid = coalesce(r.trg_uuid, a.uuid)'
        if not _safe_run_batched(client, "Malware → ThreatActor", _outer, _inner, stats, "attributed_to"):
            failures += 1
        query_pause()

        # 3a. Indicator → Vulnerability (EXPLOITS) — exact CVE match (indexed)
        logger.info("[LINK] 3a/12 Indicator → Vulnerability (exact CVE match)...")
        _q3a_outer = "MATCH (i:Indicator) WHERE i.cve_id IS NOT NULL AND size(i.cve_id) > 0 RETURN i"
        # PR-M3c §8-RI-S3-Q9: accumulate ``r.source_ids`` (set-valued) in
        # addition to writing scalar ``r.source_id`` (last-writer-wins, kept
        # for legacy readers and observability). Multiple merge passes (e.g.
        # Q4 co-occurrence and Q9 malware-family-match) share the same
        # INDICATES edge endpoints — scalar overwrite hides prior provenance
        # from the calibrator filter. Accumulating via ``apoc.coll.toSet``
        # preserves every source tag that has ever applied to the edge; the
        # calibrator can then match on ANY() over the array.
        _q3a_inner = (
            "WITH $i AS i MATCH (v:Vulnerability {cve_id: i.cve_id}) MERGE (i)-[r:EXPLOITS]->(v) "
            'ON CREATE SET r.confidence_score = 1.0, r.match_type = "cve_tag", '
            '   r.source_id = "cve_tag_match", r.created_at = datetime() '
            "SET r.updated_at = datetime(), "
            '    r.source_ids = apoc.coll.toSet(coalesce(r.source_ids, []) + ["cve_tag_match"]), '
            "    r.src_uuid = coalesce(r.src_uuid, i.uuid), r.trg_uuid = coalesce(r.trg_uuid, v.uuid)"
        )
        # PR #34 round 20: count Indicator orphans (cve_id set but no
        # matching Vulnerability) — directly the skip count, no comparison.
        _q3a_skip = (
            "MATCH (i:Indicator) WHERE i.cve_id IS NOT NULL AND size(i.cve_id) > 0 "
            "AND NOT EXISTS { MATCH (v:Vulnerability {cve_id: i.cve_id}) } "
            "RETURN count(i) AS c"
        )
        if not _safe_run_batched(
            client,
            "Indicator → Vulnerability (EXPLOITS)",
            _q3a_outer,
            _q3a_inner,
            stats,
            "exploits_vuln",
            skip_query=_q3a_skip,
        ):
            failures += 1
        query_pause()

        # 3b. Indicator → CVE (EXPLOITS) — exact CVE match (indexed)
        logger.info("[LINK] 3b/12 Indicator → CVE (exact CVE match)...")
        _q3b_outer = "MATCH (i:Indicator) WHERE i.cve_id IS NOT NULL AND size(i.cve_id) > 0 RETURN i"
        # PR-M3c: see Q3a above for rationale — same accumulate-source_ids
        # pattern applied uniformly to every site that sets ``r.source_id``.
        _q3b_inner = (
            "WITH $i AS i MATCH (c:CVE {cve_id: i.cve_id}) MERGE (i)-[r:EXPLOITS]->(c) "
            'ON CREATE SET r.confidence_score = 1.0, r.match_type = "cve_tag", '
            '   r.source_id = "cve_tag_match", r.created_at = datetime() '
            "SET r.updated_at = datetime(), "
            '    r.source_ids = apoc.coll.toSet(coalesce(r.source_ids, []) + ["cve_tag_match"]), '
            "    r.src_uuid = coalesce(r.src_uuid, i.uuid), r.trg_uuid = coalesce(r.trg_uuid, c.uuid)"
        )
        _q3b_skip = (
            "MATCH (i:Indicator) WHERE i.cve_id IS NOT NULL AND size(i.cve_id) > 0 "
            "AND NOT EXISTS { MATCH (c:CVE {cve_id: i.cve_id}) } "
            "RETURN count(i) AS c"
        )
        if not _safe_run_batched(
            client,
            "Indicator → CVE (EXPLOITS)",
            _q3b_outer,
            _q3b_inner,
            stats,
            "exploits_cve",
            skip_query=_q3b_skip,
        ):
            failures += 1
        query_pause()

        # 4. Indicator → Malware (INDICATES) — MISP event co-occurrence (BATCHED)
        # This query caused OOM on 170K+ indicators. Uses apoc.periodic.iterate
        # to process in 5000-node mini-transactions instead of one giant transaction.
        #
        # PR #33 round 10: dropped legacy scalar misp_event_id from both filter
        # and join. Outer filter only selects Indicators with a non-empty
        # misp_event_ids[]; inner Malware match uses array IN-membership.
        #
        # PR-N7 (2026-04-21 on-call from Bravo Vanko): REVERSED the join
        # direction to iterate from Malware (the small side, ~3.4K nodes
        # in production) instead of Indicator (~144K nodes). Neo4j CE
        # cannot index array elements, so ``eid IN m.misp_event_ids``
        # is an unindexed scan of every Malware per (indicator, event_id)
        # pair. Pre-fix that was ~500K outer pairs × 3.4K malware scan
        # ≈ 1.7B comparisons → 5+ hours on the 730-day baseline and
        # the pipeline was found stuck with no progress logs.
        #
        # Post-fix: 3.4K outer Malware × avg ~10 event_ids each =
        # ~34K outer pairs × 144K indicator scan ≈ 5B comparisons in
        # the worst case — WORSE on paper, but in practice each outer
        # Malware touches only a tiny subset of Indicators (those
        # sharing at least one event_id), and Neo4j's query planner
        # can short-circuit on the first-found match because the inner
        # MATCH doesn't need all indicators. The 43× drop in
        # apoc.periodic.iterate outer iterations (144K → 3.4K) means
        # 43× fewer batch transactions + commit overheads, which
        # dominates. Field observation from Bravo: ~5 hours stuck →
        # expected ~10-20 min with the reversal + reduced outer count.
        #
        # Correctness: the resulting edge set is identical — MERGE on
        # (i)-[:INDICATES]->(m) is commutative in the Cartesian sense
        # (every (i, m) pair sharing an event_id matches from either
        # direction). MERGE idempotence means re-running is safe.
        logger.info("[LINK] 4/12 Indicator → Malware (co-occurrence, batched — reversed join for scale)...")
        _q4_outer = "MATCH (m:Malware) WHERE m.misp_event_ids IS NOT NULL AND size(m.misp_event_ids) > 0 RETURN m"
        _q4_inner = (
            "WITH $m AS m "
            # Cap per-malware event id fan-out at 200 (same cap as the
            # pre-reversal form to match existing bounded behaviour).
            "WITH m, [eid IN m.misp_event_ids WHERE eid IS NOT NULL AND size(eid) > 0][0..200] AS eids "
            "UNWIND eids AS eid "
            "WITH m, eid "
            "MATCH (i:Indicator) "
            "WHERE i.misp_event_ids IS NOT NULL AND eid IN i.misp_event_ids "
            "MERGE (i)-[r:INDICATES]->(m) "
            "ON CREATE SET r.confidence_score = 0.5, "
            '  r.match_type = "misp_cooccurrence", '
            '  r.source_id = "misp_cooccurrence", '
            "  r.created_at = datetime() "
            # PR #33 round 14 + PR-M3c §8-RI-S3-Q9: r.updated_at + source_ids
            # accumulation (see pre-reversal comments for rationale).
            "SET r.updated_at = datetime(), "
            '    r.source_ids = apoc.coll.toSet(coalesce(r.source_ids, []) + ["misp_cooccurrence"]), '
            "    r.src_uuid = coalesce(r.src_uuid, i.uuid), "
            "    r.trg_uuid = coalesce(r.trg_uuid, m.uuid)"
        )
        if not _safe_run_batched(
            client,
            "Indicator → Malware (co-occurrence)",
            _q4_outer,
            _q4_inner,
            stats,
            "indicates_cooccurrence",
        ):
            failures += 1
        query_pause()

        # 5. ThreatActor → Technique (EMPLOYS_TECHNIQUE) — explicit ATT&CK
        # uses_techniques list. Attribution semantics: "who uses this TTP".
        # PR #34 round 20: skip_query counts (actor, technique-id) ORPHAN
        # pairs — pairs whose Technique node does NOT exist. Each orphan
        # pair is an edge that the inner action silently fails to create.
        # Direct skip count, no comparison with APOC total needed.
        logger.info("[LINK] 5/12 ThreatActor → Technique (ATT&CK explicit)...")
        _outer = "MATCH (a:ThreatActor) WHERE size(coalesce(a.uses_techniques, [])) > 0 RETURN a"
        _inner = 'WITH $a AS a UNWIND a.uses_techniques AS tid WITH a, tid MATCH (t:Technique {mitre_id: tid}) MERGE (a)-[r:EMPLOYS_TECHNIQUE]->(t) ON CREATE SET r.confidence_score = 0.95, r.match_type = "mitre_explicit", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, a.uuid), r.trg_uuid = coalesce(r.trg_uuid, t.uuid)'
        _q5_skip = (
            "MATCH (a:ThreatActor) WHERE size(coalesce(a.uses_techniques, [])) > 0 "
            "UNWIND a.uses_techniques AS tid "
            "WITH tid WHERE NOT EXISTS { MATCH (t:Technique {mitre_id: tid}) } "
            "RETURN count(*) AS c"
        )
        if not _safe_run_batched(
            client,
            "ThreatActor → Technique (ATT&CK explicit)",
            _outer,
            _inner,
            stats,
            "employs_technique_explicit",
            skip_query=_q5_skip,
        ):
            failures += 1
        query_pause()

        # 6. Malware → Technique (IMPLEMENTS_TECHNIQUE) — MITRE STIX uses
        # relationships. Capability semantics: "what the code can do".
        # PR #34 round 20: skip_query counts orphan (malware, technique-id)
        # pairs whose Technique node does NOT exist — direct skip count.
        logger.info("[LINK] 6/12 Malware → Technique (MITRE explicit)...")
        _outer = "MATCH (m:Malware) WHERE size(coalesce(m.uses_techniques, [])) > 0 RETURN m"
        _inner = 'WITH $m AS m UNWIND m.uses_techniques AS tid WITH m, tid MATCH (t:Technique {mitre_id: tid}) MERGE (m)-[r:IMPLEMENTS_TECHNIQUE]->(t) ON CREATE SET r.confidence_score = 0.95, r.match_type = "mitre_explicit", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, m.uuid), r.trg_uuid = coalesce(r.trg_uuid, t.uuid)'
        _q6_skip = (
            "MATCH (m:Malware) WHERE size(coalesce(m.uses_techniques, [])) > 0 "
            "UNWIND m.uses_techniques AS tid "
            "WITH tid WHERE NOT EXISTS { MATCH (t:Technique {mitre_id: tid}) } "
            "RETURN count(*) AS c"
        )
        if not _safe_run_batched(
            client,
            "Malware → Technique (MITRE explicit)",
            _outer,
            _inner,
            stats,
            "malware_implements_technique",
            skip_query=_q6_skip,
        ):
            failures += 1
        query_pause()

        # 7a. Indicator → Sector (TARGETS)
        # The Sector node is auto-CREATEd here — stamp its uuid with the
        # deterministic Python-precomputed value embedded as a Cypher CASE
        # expression literal (sector names are a fixed set of 4). Without this,
        # sec.uuid would be NULL and r.trg_uuid would inherit NULL.
        logger.info("[LINK] 7a/12 Indicator → Sector (TARGETS)...")
        _q7a_outer = "MATCH (i:Indicator) WHERE size(coalesce(i.zone, [])) > 0 RETURN i"
        # NB (PR #33 round 6): all string literals inside this inner query use
        # DOUBLE quotes. _safe_run_batched wraps the inner query in single
        # quotes for apoc.periodic.iterate('outer', 'inner', ...), so embedded
        # single quotes terminate the outer string early. Same convention used
        # in run_pipeline.py's working co-occurrence query.
        _q7a_inner = (
            "WITH $i AS i UNWIND i.zone AS zone_name WITH i, zone_name "
            'WHERE zone_name IS NOT NULL AND zone_name <> "" '
            f"AND zone_name IN {_SECTOR_IN_LIST} "
            "MERGE (sec:Sector {name: zone_name}) "
            # PR #37 (Devil's Advocate Tier S): stamp ``edgeguard_managed=true``
            # on auto-created Sector nodes. Without it, ``stix_exporter`` —
            # which filters every Sector lookup with
            # ``WHERE s.edgeguard_managed = true`` (src/stix_exporter.py:203,254,473)
            # — silently DROPS the Sector identity SDO and the
            # ``targets`` SRO from every bundle. ResilMesh consumers
            # then think the indicator is unscoped (zone metadata
            # invisible). One-line fix: stamp the flag on CREATE and
            # on every SET. Pre-release framework — no production
            # graph to backfill.
            f"  ON CREATE SET sec.uuid = {_SECTOR_UUID_CASE}, sec.edgeguard_managed = true, sec.first_imported_at = datetime() "
            f"  SET sec.uuid = coalesce(sec.uuid, {_SECTOR_UUID_CASE}), "
            "      sec.edgeguard_managed = true, "
            "      sec.last_updated = datetime() "
            "MERGE (i)-[r:TARGETS]->(sec) "
            "ON CREATE SET r.confidence_score = 1.0, r.created_at = datetime() "
            "SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, i.uuid), r.trg_uuid = coalesce(r.trg_uuid, sec.uuid)"
        )
        if not _safe_run_batched(
            client, "Indicator -> Sector (TARGETS)", _q7a_outer, _q7a_inner, stats, "indicator_targets_sector"
        ):
            failures += 1
        query_pause()

        # 7b. Vulnerability/CVE → Sector (AFFECTS)
        # Same Sector-uuid stamp as 7a — see comment above.
        logger.info("[LINK] 7b/12 Vulnerability/CVE → Sector (AFFECTS)...")
        _q7b_outer = "MATCH (v) WHERE (v:Vulnerability OR v:CVE) AND size(coalesce(v.zone, [])) > 0 RETURN v"
        # See 7a above: double quotes for inner string literals.
        _q7b_inner = (
            "WITH $v AS v UNWIND v.zone AS zone_name WITH v, zone_name "
            'WHERE zone_name IS NOT NULL AND zone_name <> "" '
            f"AND zone_name IN {_SECTOR_IN_LIST} "
            "MERGE (sec:Sector {name: zone_name}) "
            # PR #37: same edgeguard_managed stamp as 7a — keeps STIX export
            # from silently dropping AFFECTS/TARGETS Sector edges.
            f"  ON CREATE SET sec.uuid = {_SECTOR_UUID_CASE}, sec.edgeguard_managed = true, sec.first_imported_at = datetime() "
            f"  SET sec.uuid = coalesce(sec.uuid, {_SECTOR_UUID_CASE}), "
            "      sec.edgeguard_managed = true, "
            "      sec.last_updated = datetime() "
            "MERGE (v)-[r:AFFECTS]->(sec) "
            "ON CREATE SET r.confidence_score = 1.0, r.created_at = datetime() "
            "SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, v.uuid), r.trg_uuid = coalesce(r.trg_uuid, sec.uuid)"
        )
        if not _safe_run_batched(
            client, "Vulnerability/CVE -> Sector (AFFECTS)", _q7b_outer, _q7b_inner, stats, "vuln_affects_sector"
        ):
            failures += 1
        query_pause()

        # 8. Indicator → Technique (USES_TECHNIQUE) — OTX attack_ids
        # PR #34 round 20: skip_query counts orphan (indicator, attack_id)
        # pairs whose Technique node does NOT exist — direct skip count.
        logger.info("[LINK] 8/12 Indicator → Technique (OTX attack_ids)...")
        _q8_outer = "MATCH (i:Indicator) WHERE size(coalesce(i.attack_ids, [])) > 0 RETURN i"
        _q8_inner = 'WITH $i AS i UNWIND i.attack_ids AS tech_id WITH i, tech_id MATCH (t:Technique {mitre_id: tech_id}) MERGE (i)-[r:USES_TECHNIQUE]->(t) ON CREATE SET r.confidence_score = 0.85, r.match_type = "otx_attack_ids", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, i.uuid), r.trg_uuid = coalesce(r.trg_uuid, t.uuid)'
        _q8_skip = (
            "MATCH (i:Indicator) WHERE size(coalesce(i.attack_ids, [])) > 0 "
            "UNWIND i.attack_ids AS tech_id "
            "WITH tech_id WHERE NOT EXISTS { MATCH (t:Technique {mitre_id: tech_id}) } "
            "RETURN count(*) AS c"
        )
        if not _safe_run_batched(
            client,
            "Indicator → Technique (attack_ids)",
            _q8_outer,
            _q8_inner,
            stats,
            "indicator_uses_technique",
            skip_query=_q8_skip,
        ):
            failures += 1
        query_pause()

        # 9. Indicator → Malware (INDICATES) — malware_family name match
        # PR #34 round 20: skip_query counts Indicators with a non-empty
        # malware_family that have NO matching Malware node (by name, alias,
        # or family) — direct skip count, no comparison.
        logger.info("[LINK] 9/12 Indicator → Malware (malware_family match)...")
        _q9_outer = "MATCH (i:Indicator) WHERE i.malware_family IS NOT NULL AND size(i.malware_family) > 0 RETURN i"
        # PR-M3c §8-RI-S3-Q9 (HIGH): this is the overwrite site. The SAME
        # INDICATES edge may already exist from Q4 (co-occurrence) with
        # ``r.source_id = "misp_cooccurrence"``. Before this fix, Q9's MERGE
        # matched that edge and clobbered ``r.source_id`` with
        # ``"malware_family_match"``, so the calibrator's filter
        # (``source_id IN ["misp_cooccurrence", "misp_correlation"]``)
        # missed the edge and its confidence stayed at 0.8 even when the
        # underlying MISP event was a 96k-indicator bulk dump that should
        # have demoted it to 0.30. Estimated 30-50% of INDICATES edges on
        # a 730-day baseline were inflated this way.
        #
        # Fix: accumulate ``"malware_family_match"`` into ``r.source_ids``
        # via ``apoc.coll.toSet`` — both sources now coexist on the edge.
        # The scalar ``r.source_id`` write is kept (last-writer-wins, for
        # legacy readers) but the calibrator filter is updated in
        # enrichment_jobs.py to match against the ``r.source_ids`` array
        # so co-occurrence provenance is always seen.
        # PR-N8 BLOCK-MERGE (audit Logic Tracker, 2026-04-21): the CASE
        # expression below now gates on ``r.calibrated_at IS NOT NULL``
        # to RESPECT the calibrator's demotion.
        #
        # Pre-fix: ``SET r.confidence_score = CASE WHEN 0.8 >
        # r.confidence_score THEN 0.8 ELSE r.confidence_score END`` ran
        # unconditionally on every re-MERGE. An edge that the calibrator
        # had just demoted from 0.8 → 0.30 (e.g. for a 96K-indicator
        # bulk MISP dump) would be re-inflated to 0.8 on the very next
        # build_relationships run. The flap cycle was daily:
        #
        #     Day 1  → build_relationships Q4     sets 0.5 (ON CREATE)
        #     Day 1  → build_relationships Q9     re-stamps 0.8 (CASE floor)
        #     Day 1  → enrichment calibrator      detects bulk dump, sets 0.30 + calibrated_at
        #     Day 2  → build_relationships Q9     RE-INFLATES to 0.8 ←── BUG
        #     Day 2  → enrichment calibrator      detects bulk dump again, sets 0.30
        #     … repeats nightly since the calibrator shipped (months) …
        #
        # Since the calibrator stamps ``r.calibrated_at`` at both of its
        # write sites (``enrichment_jobs.py:661`` small-event path, and
        # ``:710`` large-event path — see commit audit trail), we key
        # the respect-clause on ``r.calibrated_at IS NOT NULL``. On a
        # calibrated edge the CASE now short-circuits to the existing
        # value, preserving the calibrator's work. On a fresh (never-
        # calibrated) edge the previous max-wins floor still applies.
        #
        # Note: this does NOT recursively mean calibrated edges never
        # upgrade again — if the calibrator later decides a bulk-dump
        # edge deserves 0.8 (e.g. the dump was re-classified as
        # "curated"), it clears or re-writes r.calibrated_at and the
        # floor runs again.
        # PR-N8 HIGH (audit Bug Hunter H1, 2026-04-21): canonicalization
        # parity — apply ``trim() + toLower()`` on BOTH sides of every
        # string comparison. Pre-fix ``m.name`` was NFC+strip+lower'd
        # at ingest via ``canonicalize_merge_key`` (PR #37), while
        # ``i.malware_family`` was stored RAW. A feed emitting
        # ``"Emotet "`` (trailing whitespace) or ``"eMotet"`` (mixed
        # case) on an Indicator wouldn't match ``m.name = "emotet"``
        # despite being semantically identical — silent edge drop.
        # ``trim()`` covers the whitespace case; ``toLower()`` covers
        # case. NFC normalization is a known remaining gap (Cypher /
        # APOC don't have ``unicodedata.normalize`` — NFD vs NFC of
        # accented chars still miss, rare in practice but filed as a
        # follow-up: fix at ingest via ``canonicalize_merge_key``).
        _q9_inner = (
            "WITH $i AS i MATCH (m:Malware) "
            "WHERE toLower(trim(m.name)) = toLower(trim(i.malware_family)) "
            "   OR toLower(trim(i.malware_family)) IN [x IN coalesce(m.aliases, []) | toLower(trim(x))] "
            "   OR toLower(trim(coalesce(m.family, ''))) = toLower(trim(i.malware_family)) "
            "MERGE (i)-[r:INDICATES]->(m) "
            "ON CREATE SET r.created_at = datetime() "
            "SET r.confidence_score = CASE "
            # PR-N8 BLOCK-MERGE: respect calibrator. Must be the FIRST
            # clause so it short-circuits before the 0.8 floor.
            "       WHEN r.calibrated_at IS NOT NULL THEN r.confidence_score "
            "       WHEN r.confidence_score IS NULL OR 0.8 > r.confidence_score THEN 0.8 "
            "       ELSE r.confidence_score "
            "    END, "
            '    r.match_type = "malware_family", '
            '    r.source_id = "malware_family_match", '
            '    r.source_ids = apoc.coll.toSet(coalesce(r.source_ids, []) + ["malware_family_match"]), '
            "    r.updated_at = datetime(), "
            "    r.src_uuid = coalesce(r.src_uuid, i.uuid), "
            "    r.trg_uuid = coalesce(r.trg_uuid, m.uuid)"
        )
        # PR-N8 HIGH: same trim()+toLower() parity as _q9_inner so the
        # orphan count matches the actual post-fix match behaviour.
        _q9_skip = (
            "MATCH (i:Indicator) WHERE i.malware_family IS NOT NULL AND size(i.malware_family) > 0 "
            "AND NOT EXISTS { "
            "  MATCH (m:Malware) "
            "  WHERE toLower(trim(m.name)) = toLower(trim(i.malware_family)) "
            "     OR toLower(trim(i.malware_family)) IN [x IN coalesce(m.aliases, []) | toLower(trim(x))] "
            "     OR toLower(trim(coalesce(m.family, ''))) = toLower(trim(i.malware_family)) "
            "} "
            "RETURN count(i) AS c"
        )
        if not _safe_run_batched(
            client,
            "Indicator → Malware (family match)",
            _q9_outer,
            _q9_inner,
            stats,
            "indicates_family",
            skip_query=_q9_skip,
        ):
            failures += 1
        query_pause()

        # 10. Tool → Technique (IMPLEMENTS_TECHNIQUE) — MITRE uses_techniques.
        # Same capability semantics as Malware above; both are "code/tool can
        # execute this TTP". PR #34 round 20: skip_query counts orphan
        # (tool, technique-id) pairs whose Technique node does NOT exist.
        logger.info("[LINK] 10/12 Tool → Technique (MITRE explicit)...")
        _outer = "MATCH (tool:Tool) WHERE size(coalesce(tool.uses_techniques, [])) > 0 RETURN tool"
        _inner = 'WITH $tool AS tool UNWIND tool.uses_techniques AS tid WITH tool, tid MATCH (t:Technique {mitre_id: tid}) MERGE (tool)-[r:IMPLEMENTS_TECHNIQUE]->(t) ON CREATE SET r.confidence_score = 0.95, r.match_type = "mitre_explicit", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, tool.uuid), r.trg_uuid = coalesce(r.trg_uuid, t.uuid)'
        _q10_skip = (
            "MATCH (tool:Tool) WHERE size(coalesce(tool.uses_techniques, [])) > 0 "
            "UNWIND tool.uses_techniques AS tid "
            "WITH tid WHERE NOT EXISTS { MATCH (t:Technique {mitre_id: tid}) } "
            "RETURN count(*) AS c"
        )
        if not _safe_run_batched(
            client,
            "Tool → Technique (MITRE explicit)",
            _outer,
            _inner,
            stats,
            "tool_implements_technique",
            skip_query=_q10_skip,
        ):
            failures += 1
        query_pause()

        # Cross-source dedup is handled at ingest time via single-key MERGE
        # (name for Malware/ThreatActor, cve_id for CVE/Vulnerability, mitre_id
        # for Technique/Tactic/Tool). Source provenance tracked via `source`/`tags` arrays.

        # Get final stats
        try:
            logger.info("\n[STATS] Final Graph Statistics:")
            result = client.run("""
                MATCH (a)-[r]->(b)
                RETURN type(r) as relationship, count(*) as count,
                       avg(r.confidence_score) as avg_confidence
                ORDER BY count DESC
            """)
            for row in result:
                avg_conf = row.get("avg_confidence")
                if avg_conf is not None:
                    avg_conf = f"{float(avg_conf):.2f}"
                else:
                    avg_conf = "N/A"
                logger.info(f"   {row['relationship']}: {row['count']} (avg confidence: {avg_conf})")
        except Exception as e:
            logger.error(f"Failed to fetch final stats: {e}")

        # PR #33 round 13: explicit summary line that an operator can grep.
        # Always emitted (even on full success) so absence in logs is a clear
        # "build_relationships didn't reach the end" signal rather than just
        # "no failures, must have worked."
        total_rels = sum(v for k, v in stats.items() if k != "multi_zone_indicators")
        per_query = ", ".join(f"{k}={v}" for k, v in sorted(stats.items()) if k != "multi_zone_indicators")
        logger.info(
            "[BUILD_RELATIONSHIPS SUMMARY] total_edges=%d failures=%d/12 per_query=[%s]",
            total_rels,
            failures,
            per_query,
        )
        if failures:
            logger.warning("Relationship types failed: %d/12 — partial success", failures)

        if _METRICS_AVAILABLE:
            try:
                record_neo4j_relationships(stats)
            except Exception:
                logger.debug("Metrics recording failed", exc_info=True)

        return failures == 0

    except Exception as e:
        logger.error(f"Error building relationships: {e}")
        import traceback

        traceback.print_exc()
        return False

    finally:
        client.close()


if __name__ == "__main__":
    print("=" * 50)
    print("EdgeGuard - Building Graph Relationships")
    print("=" * 50)
    print("\nUsing EXACT matching with confidence scoring...")
    print()

    if build_relationships():
        print("\n✅ Relationships built successfully!")
    else:
        print("\n❌ Failed to build relationships")
        sys.exit(1)
