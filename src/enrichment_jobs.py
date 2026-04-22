#!/usr/bin/env python3
"""
EdgeGuard — Post-Sync Enrichment Jobs
======================================
Four graph-quality jobs that run AFTER every MISP→Neo4j sync.
They are designed to be idempotent — safe to re-run at any time.

Jobs
----
1. decay_ioc_confidence   — Reduce confidence of stale indicators over time
2. build_campaign_nodes   — Group ThreatActor / Malware / Indicator into Campaigns
3. calibrate_cooccurrence — Adjust INDICATES/EXPLOITS confidence for large MISP feed dumps
4. bridge_vulnerability_cve — Create REFERS_TO between Vulnerability and CVE nodes
"""

import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neo4j_client import NEO4J_READ_TIMEOUT, _dedup_concat_clause  # noqa: E402
from node_identity import compute_node_uuid  # noqa: E402
from query_pause import query_pause

try:
    from metrics_server import record_enrichment_duration

    _METRICS_AVAILABLE = True
except ImportError:
    _METRICS_AVAILABLE = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. IOC CONFIDENCE DECAY
# ---------------------------------------------------------------------------


def decay_ioc_confidence(neo4j_client) -> Dict:
    """
    Time-decay confidence scores for Indicator and Vulnerability nodes.

    Threat intelligence has a shelf life.  An IP flagged 18 months ago
    with no recent sightings is far less actionable than one seen yesterday.

    Decay tiers (based on days since last_updated):
      < 90 days   → no change
      90–180 days → confidence × 0.85 (15% reduction)
      180–365 days→ confidence × 0.70 (30% reduction)
      > 365 days  → active = false (retired, not deleted)

    All changes are non-destructive:
    - Minimum confidence floor is 0.10 (node stays queryable)
    - Retired nodes (active=false) are kept for historical queries
    - first_imported_at and source are never touched
    """
    if not neo4j_client.driver:
        logger.error("decay_ioc_confidence: no Neo4j connection")
        return {}

    results = {}

    tiers = [
        # (label, min_days, max_days, multiplier, retire)
        ("Indicator", 90, 180, 0.85, False),
        ("Indicator", 180, 365, 0.70, False),
        ("Indicator", 365, None, 1.00, True),  # retire
        ("Vulnerability", 90, 180, 0.90, False),
        ("Vulnerability", 180, 365, 0.80, False),
        ("Vulnerability", 365, None, 1.00, True),
    ]

    try:
        with neo4j_client.driver.session() as session:
            for label, min_days, max_days, multiplier, retire in tiers:
                if retire:
                    cypher = f"""
                    MATCH (n:{label})
                    WHERE n.last_updated IS NOT NULL
                      AND n.active = true
                      AND duration.between(n.last_updated, datetime()).days > $min_days
                    SET n.active = false,
                        n.retired_at = datetime()
                    RETURN count(n) AS affected
                    """
                    desc = f"{label} retired (>{min_days}d)"
                    # Retire path is idempotent via the ``n.active = true``
                    # guard in WHERE — already-retired nodes skip. No
                    # ``last_decayed_tier`` gating needed here.
                    params = {"min_days": min_days, "max_days": max_days, "mult": multiplier}
                else:
                    # PR-M3b §8-RI-S4-Decay: gate by ``last_decayed_tier`` so
                    # the multiplicative decay fires AT MOST ONCE per tier
                    # transition per node.  The prior query had no idempotency
                    # marker: every enrichment run matched the same nodes in
                    # the same tier and re-applied the multiplier, so a
                    # node sitting in the 180-365d tier for 100 daily runs
                    # got ``confidence × 0.70^100`` ≈ 0 (floored at 0.10)
                    # within ~7 runs.  All indicators in the tier collapsed
                    # to the 0.10 floor long before aging out — losing all
                    # discriminatory power for filtering / ranking.
                    #
                    # Fix: each tier gets a unique label (``"<min>-<max>"``
                    # format, stable across runs) stored on the node as
                    # ``n.last_decayed_tier``. The WHERE clause excludes
                    # nodes already decayed at this tier; the SET clause
                    # updates the marker so the next run is a no-op.  When
                    # a node AGES INTO the next tier, ``last_decayed_tier``
                    # differs from the new tier label → decay fires once
                    # for the new tier and updates the marker.  Net: each
                    # node sees at most one decay application per tier
                    # boundary crossed, matching the semantic intent
                    # documented in the function docstring.
                    cypher = f"""
                    MATCH (n:{label})
                    WHERE n.last_updated IS NOT NULL
                      AND n.confidence_score IS NOT NULL
                      AND duration.between(n.last_updated, datetime()).days >= $min_days
                      AND duration.between(n.last_updated, datetime()).days < $max_days
                      AND (n.last_decayed_tier IS NULL OR n.last_decayed_tier <> $tier_label)
                    SET n.confidence_score = CASE
                            WHEN n.confidence_score * $mult < 0.10 THEN 0.10
                            ELSE round(n.confidence_score * $mult * 100) / 100
                        END,
                        n.last_decayed_tier = $tier_label,
                        n.last_decayed_at = datetime()
                    RETURN count(n) AS affected
                    """
                    desc = f"{label} decayed ({min_days}–{max_days}d, ×{multiplier})"
                    tier_label = f"{label.lower()}-{min_days}-{max_days}"
                    params = {
                        "min_days": min_days,
                        "max_days": max_days,
                        "mult": multiplier,
                        "tier_label": tier_label,
                    }

                result = session.run(cypher, timeout=NEO4J_READ_TIMEOUT, **params)
                record = result.single()
                count = record["affected"] if record else 0
                results[desc] = count
                if count:
                    logger.info(f"  [DECAY] {desc}: {count} nodes")

    except Exception as e:
        # PR-N21 BLOCKER: re-raise instead of silently returning zero
        # results. The pre-N21 ``except Exception: logger.error()`` (no
        # raise) swallowed real Cypher errors (timeouts, schema drift,
        # OOM) and returned ``{}`` — which the runner happily aggregated
        # and Airflow marked SUCCESS. Operators saw a green DAG with no
        # decay actually applied, identical to a "no work needed" run.
        # The 2026-04-22 cloud baseline showed ``Campaign = 0`` with the
        # same root cause (the swallower in ``build_campaign_nodes``).
        # Fix: re-raise so the DAG task FAILS loudly and the operator
        # sees the actual exception in the Airflow log.
        logger.error(f"[DECAY] decay_ioc_confidence FAILED: {e}", exc_info=True)
        raise

    total = sum(results.values())
    logger.info(f"[DECAY] IOC decay complete — {total} nodes updated")
    return results


# ---------------------------------------------------------------------------
# 2. CAMPAIGN NODE BUILDER
# ---------------------------------------------------------------------------


def build_campaign_nodes(neo4j_client) -> Dict:
    """
    Materialise Campaign nodes from the existing threat graph.

    A Campaign represents a coordinated set of threat activity by one actor.
    We infer campaigns from graph structure:
      ThreatActor -[:ATTRIBUTED_TO]<- Malware -[:INDICATES]<- Indicator

    For each ThreatActor that has at least one attributed malware and one
    related indicator, we create a Campaign node and link:
      ThreatActor -[:RUNS]-> Campaign
      Malware     -[:PART_OF]-> Campaign
      Indicator   -[:PART_OF]-> Campaign  (sampled — up to 100 per campaign)

    Campaign properties:
      name            — "{actor_name} Campaign"
      actor_name      — source actor name
      indicator_count — number of indicators at last update
      malware_count   — number of malware families at last update
      first_seen      — earliest world-truthful indicator first observation
                        (from coalesce(i.first_seen_at_source,
                        i.first_imported_at) — see PR (S5) for the
                        source-truthful timestamps design)
      last_seen       — latest world-truthful indicator last observation
                        (from coalesce(i.last_seen_at_source,
                        i.last_updated))
      zone            — union of all indicator zones
      tag             — actor tag (for UNIQUE constraint key)
    """
    if not neo4j_client.driver:
        logger.error("build_campaign_nodes: no Neo4j connection")
        return {}

    results = {"campaigns_created": 0, "campaigns_updated": 0, "links_created": 0}

    # PR-M3d: capture the run's start time in ISO-8601 with UTC offset.
    # Passed to Step 3b's prune query as ``$run_start_at`` to distinguish
    # edges touched by THIS run (``r.updated_at >= $run_start_at``) from
    # stale edges left over from prior runs' non-deterministic top-100
    # (``r.updated_at < $run_start_at``).  Python-side capture is
    # sufficient because Neo4j server-side ``datetime()`` in Step 3a's
    # SET is monotonic — any value stamped in Step 3a is guaranteed
    # >= run_start_at (both read the same wall clock; Step 3a runs
    # after this line by definition).
    run_start_at = datetime.now(timezone.utc).isoformat()

    try:
        with neo4j_client.driver.session() as session:
            # Pre-fetch the names of every qualifying ThreatActor so we can
            # compute deterministic Campaign uuids in Python (Campaign name is
            # ``"<actor> Campaign"``). Without this, the MERGE below would
            # create Campaign nodes with NULL uuid — silently breaking the
            # cross-environment traceability contract this PR exists for.
            # Caught in the post-PR-#33 fresh-eyes audit.
            qualifying_actors_query = """
            MATCH (a:ThreatActor)
            WHERE EXISTS((a)<-[:ATTRIBUTED_TO]-(:Malware))
            RETURN a.name AS name
            """
            actor_names = [
                r["name"] for r in session.run(qualifying_actors_query, timeout=NEO4J_READ_TIMEOUT) if r["name"]
            ]
            campaign_uuids = {name: compute_node_uuid("Campaign", {"name": f"{name} Campaign"}) for name in actor_names}

            # Step 1: Materialise Campaign nodes (one per ThreatActor with evidence).
            # ``c.uuid`` is set from the precomputed map keyed by the actor's name;
            # the RUNS edge stamps src_uuid / trg_uuid from a.uuid / c.uuid (both
            # bound, both set in this query).
            #
            # PR #34 round 21 (bugbot LOW): added the
            # ``WHERE a.name IN keys($campaign_uuids)`` guard immediately after
            # the outer MATCH. Bugbot caught a TOCTOU race: if a NEW
            # ThreatActor gains an ATTRIBUTED_TO edge between the pre-fetch
            # (line ~169) and this MERGE, the new actor enters the MERGE
            # path but ``$campaign_uuids[a.name]`` returns NULL — the
            # Campaign would be created with ``uuid=null``, silently
            # breaking the cross-environment traceability contract until a
            # subsequent rerun. Filtering ensures we only MERGE actors
            # whose deterministic uuid was precomputed; new actors are
            # picked up on the next run when they're included in the
            # pre-fetch.
            create_cypher = f"""
            MATCH (a:ThreatActor)
            WHERE EXISTS((a)<-[:ATTRIBUTED_TO]-(:Malware))
              AND a.name IN keys($campaign_uuids)
            WITH a
            OPTIONAL MATCH (a)<-[:ATTRIBUTED_TO]-(m:Malware)
            WITH a, collect(DISTINCT m) AS malware_list
            OPTIONAL MATCH (a)<-[:ATTRIBUTED_TO]-(:Malware)<-[:INDICATES]-(i:Indicator)
            WHERE i.active = true
            // PR (S5) (bugbot c9bb277 MED + architecture redesign):
            // per-source timestamps live on SOURCED_FROM edges, not on
            // the node. We want "earliest claim across ALL sources for
            // this indicator" per indicator, THEN aggregate across
            // indicators for the campaign.
            //
            // The previous shape `min/max(coalesce(r.X, i.Y))` had a
            // row-multiplication bug (bugbot c9bb277 MED): for an
            // indicator with N edges, the OPTIONAL MATCH produces N
            // rows. If any edge had NULL source_reported_last_at, that
            // row's coalesce fell back to `i.last_updated` (a recent
            // sync wall-clock), and the outer `max()` would pick the
            // wall-clock over the real older source claims from OTHER
            // edges. Campaign `c.last_seen` would reflect EdgeGuard's
            // sync time instead of the source's actual last-reported
            // claim.
            //
            // Fix: aggregate edges per-indicator FIRST (ignoring NULL
            // claims — that's what min/max do natively), THEN coalesce
            // the per-indicator result with the node-level DB-local
            // fallback ONLY when ALL source claims are NULL.
            OPTIONAL MATCH (i)-[r:SOURCED_FROM]->(:Source)
            WITH a, malware_list, i,
                 min(r.source_reported_first_at) AS i_source_first,
                 max(r.source_reported_last_at)  AS i_source_last
            // PR-M3d §5-MD-C2 (CRITICAL): ``all_zones`` (below) used to be
            // computed from ``collect(DISTINCT i)[0..100]``, a 100-sample
            // in Neo4j's internal (non-deterministic) iteration order. On
            // a Campaign with 500 associated indicators spanning multiple
            // zones, ``c.zone`` would flap between different subsets of
            // the full zone set across enrichment runs (e.g. ``["healthcare"]``
            // on run 1, ``["healthcare","energy"]`` on run 2). Dashboards
            // filtering ``WHERE 'healthcare' IN c.zone`` saw the campaign
            // flicker in/out. Fix: compute zones from the FULL active-
            // indicator set (no slice) — deterministic + semantically
            // correct (Campaign's zones shouldn't depend on sample size).
            // The slice was cheap compute defense; the full reduce is O(N)
            // and trivial even for 10k-indicator campaigns.
            WITH a, malware_list,
                 count(DISTINCT i) AS indicator_total,
                 collect(DISTINCT i) AS all_indicators,
                 min(coalesce(i_source_first, i.first_imported_at)) AS first_seen,
                 max(coalesce(i_source_last,  i.last_updated))      AS last_seen
            WHERE size(malware_list) > 0 AND indicator_total > 0
            // PR-N5 C5 (Devil's Advocate F3, audit 09): deterministic
            // zone ordering. ``apoc.coll.toSet()`` dedupes but preserves
            // the INSERTION order of its input, which here comes from
            // ``reduce()`` iterating ``all_indicators`` in the order
            // ``collect(DISTINCT i)`` returned them — a Neo4j-internal
            // iteration order that's non-deterministic across runs.
            // Net: ``c.zone`` on the same logical campaign would come
            // out ``["healthcare","energy"]`` one run and
            // ``["energy","healthcare"]`` the next — same set, different
            // list. Downstream diff tooling (Neo4j MERGE detect-change,
            // STIX/GraphQL serialization) would flag the node as "updated"
            // on every enrichment run even when nothing semantically changed,
            // and dashboards/queries doing ``c.zone[0]`` would see the
            // "primary" zone flicker. Wrapping in ``apoc.coll.sort()``
            // pins the list to a stable alphabetical order.
            WITH a, malware_list, indicator_total, first_seen, last_seen,
                 apoc.coll.sort(
                     apoc.coll.toSet(
                         reduce(z=[], ind IN all_indicators | z + coalesce(ind.zone, []))
                     )
                 ) AS all_zones
            MERGE (c:Campaign {{name: a.name + ' Campaign'}})
            ON CREATE SET c.created_at = datetime(),
                          c.actor_name = a.name,
                          c.uuid = $campaign_uuids[a.name]
            SET c.tags = {_dedup_concat_clause("c.tags", "coalesce(a.tags, [])")},
                c.aliases          = apoc.coll.toSet(coalesce(a.aliases, [])),
                c.active           = CASE WHEN indicator_total > 0 THEN true ELSE c.active END,
                c.last_updated     = datetime(),
                c.indicator_count  = indicator_total,
                c.malware_count    = size(malware_list),
                // PR (S5) (bugbot LOW): the AND-guard on the
                // incoming aggregate prevents a transient NULL aggregate
                // (e.g. brand-new campaign with zero active indicators)
                // from overwriting an existing non-NULL c.first_seen.
                // Same defensive shape on c.last_seen below.
                c.first_seen       = CASE WHEN first_seen IS NOT NULL
                                       AND (c.first_seen IS NULL OR first_seen < c.first_seen)
                                       THEN first_seen ELSE c.first_seen END,
                // PR (S5) (bugbot MED): MAX-guard c.last_seen
                // symmetrically with c.first_seen. Rationale: the
                // aggregation now reads ``max(coalesce(i.last_seen_at_source,
                // i.last_updated))`` — with source-truthful data, an
                // indicator's ``last_seen_at_source`` can be much OLDER
                // than its ``last_updated`` (e.g. source claims 2020,
                // EdgeGuard last sync'd in 2026). Without the MAX-guard,
                // ``c.last_seen`` would regress backwards on the first
                // post-deploy enrichment run. The CASE mirrors the
                // first_seen pattern and is safe against both baseline
                // and incremental (MAX preserves the newest observation).
                // bugbot LOW: same NULL-aggregate defensive guard.
                c.last_seen        = CASE WHEN last_seen IS NOT NULL
                                       AND (c.last_seen IS NULL OR last_seen > c.last_seen)
                                       THEN last_seen ELSE c.last_seen END,
                c.zone             = all_zones,
                c.uuid             = coalesce(c.uuid, $campaign_uuids[a.name])
            MERGE (a)-[r_runs:RUNS]->(c)
            // PR-N8 HIGH (audit Cross-Checker, 2026-04-21): stamp
            // created_at / updated_at so this edge is visible to cloud
            // delta-sync + STIX incremental export (both filter by
            // r.updated_at >= cutoff — see docs/CLOUD_SYNC.md). Pre-fix
            // the RUNS edge was missing both timestamps, so every
            // re-run was invisible to delta consumers. Same omission
            // existed on PART_OF(malware) and REFERS_TO — fixed below.
            ON CREATE SET r_runs.src_uuid = a.uuid, r_runs.trg_uuid = c.uuid,
                          r_runs.created_at = datetime()
            SET r_runs.src_uuid = coalesce(r_runs.src_uuid, a.uuid),
                r_runs.trg_uuid = coalesce(r_runs.trg_uuid, c.uuid),
                r_runs.updated_at = datetime()
            RETURN count(DISTINCT c) AS campaigns
            """
            result = session.run(create_cypher, campaign_uuids=campaign_uuids, timeout=NEO4J_READ_TIMEOUT)
            record = result.single()
            results["campaigns_created"] = record["campaigns"] if record else 0

            # Defense-in-depth: if any prior race wrote a Campaign with NULL
            # uuid (from before this guard landed), backfill it now using the
            # same precomputed dict. Costs one cheap query — covers historical
            # corruption + any rare leak we missed.
            backfill_cypher = """
            MATCH (c:Campaign)
            WHERE c.uuid IS NULL AND c.actor_name IN keys($campaign_uuids)
            SET c.uuid = $campaign_uuids[c.actor_name]
            RETURN count(c) AS backfilled
            """
            bf = session.run(backfill_cypher, campaign_uuids=campaign_uuids, timeout=NEO4J_READ_TIMEOUT).single()
            backfilled = bf["backfilled"] if bf else 0
            if backfilled:
                logger.info(
                    "[CAMPAIGN] backfilled c.uuid on %d pre-existing Campaign nodes (likely from a pre-round-21 race)",
                    backfilled,
                )
            query_pause()

            # Step 2: Link malware to their campaigns. Both endpoints have
            # n.uuid by now (Malware via merge_node_with_source, Campaign via
            # step 1 above) so the edge SET reads bound .uuid directly.
            link_malware = """
            MATCH (a:ThreatActor)<-[:ATTRIBUTED_TO]-(m:Malware)
            MATCH (c:Campaign {actor_name: a.name})
            MERGE (m)-[r:PART_OF]->(c)
            // PR-N8 HIGH (audit Cross-Checker): stamp created_at /
            // updated_at so PART_OF(malware) edges are visible to
            // cloud delta-sync. See RUNS comment above for rationale.
            ON CREATE SET r.src_uuid = m.uuid, r.trg_uuid = c.uuid,
                          r.created_at = datetime()
            SET r.src_uuid = coalesce(r.src_uuid, m.uuid),
                r.trg_uuid = coalesce(r.trg_uuid, c.uuid),
                r.updated_at = datetime()
            RETURN count(*) AS links
            """
            result = session.run(link_malware, timeout=NEO4J_READ_TIMEOUT)
            record = result.single()
            results["links_created"] += record["links"] if record else 0
            query_pause()

            # Step 3a: Link active indicators to their campaigns (top 100 per
            # campaign by recency).
            #
            # PR-M3d §8-RI-S3-Camp (CRITICAL): the old implementation used
            # ``collect(i)[0..100]`` which returns the first 100 in Neo4j's
            # internal iteration order — NOT a stable order across runs.
            # Combined with MERGE's no-delete semantic, PART_OF edges
            # accumulated monotonically: run N attached {i1..i100}, run N+1
            # attached {i17..i116}, old 16 kept their edges forever. After
            # 730 daily runs, a ThreatActor with 10k active indicators had
            # EVERY single one wired via PART_OF — defeating the 100-cap's
            # purpose and producing a non-deterministic graph where "is
            # indicator X PART_OF campaign C?" depended on history, not
            # current state.
            #
            # Fix:
            # (a) Deterministic ordering via ``ORDER BY i.first_imported_at
            #     DESC, i.value ASC`` BEFORE the slice. Newest-first with a
            #     stable tiebreaker on value. Same input graph → same top-
            #     100 every run.
            # (b) ``r.updated_at = datetime()`` stamped unconditionally on
            #     every MERGE so Step 3b below can prune edges that WEREN'T
            #     touched this run (i.e., indicators that have fallen out
            #     of the top 100 since the last run).
            # (c) ``r.created_at`` on ON CREATE for audit-trail.
            #
            # Net: PART_OF edges for each Campaign always equal the current
            # top-100 of active indicators. Reproducible, bounded, matches
            # the documented "sample: up to 100 per campaign" contract.
            #
            # PR-N21 (next-baseline robustness): wrap in
            # ``apoc.periodic.iterate`` with one Campaign per batch so the
            # cartesian explosion (Campaign × Malware × Indicator) doesn't
            # materialize in a single transaction. Pre-N21 the un-batched
            # version produced an intermediate row count of (n_campaigns ×
            # avg_malware × avg_indicators) ≈ 0.5–3M rows for the cloud
            # graph (156 campaigns × ~22 malware × ~159 indicators) — fine
            # at 1-year scale, fragile at 730-day scale. The
            # 2026-04-22 Campaign = 0 incident was almost certainly this
            # query timing out / OOMing inside a single TX, then the
            # broad ``except Exception`` (now removed) swallowing the
            # raise. Same shape ``bridge_vulnerability_cve`` already
            # uses for symmetric scale safety.
            link_indicators_batched = """
            CALL apoc.periodic.iterate(
              "MATCH (c:Campaign) RETURN c",
              "MATCH (a:ThreatActor {name: c.actor_name})<-[:ATTRIBUTED_TO]-(m:Malware)<-[:INDICATES]-(i:Indicator)
               WHERE i.active = true
               WITH c, i
               ORDER BY i.first_imported_at DESC, i.value ASC
               WITH c, collect(i)[0..100] AS indicators
               UNWIND indicators AS i
               MERGE (i)-[r:PART_OF]->(c)
               ON CREATE SET r.created_at = datetime(),
                             r.src_uuid = i.uuid,
                             r.trg_uuid = c.uuid
               SET r.src_uuid = coalesce(r.src_uuid, i.uuid),
                   r.trg_uuid = coalesce(r.trg_uuid, c.uuid),
                   r.updated_at = datetime()",
              {batchSize: 25, parallel: false, retries: 2}
            )
            YIELD batches, total, errorMessages, committedOperations
            RETURN batches, total, errorMessages, committedOperations
            """
            result = session.run(link_indicators_batched, timeout=NEO4J_READ_TIMEOUT)
            record = result.single()
            if record:
                # ``committedOperations`` is the number of inner-query rows
                # that produced a MERGE — the PART_OF link count.
                results["links_created"] += record.get("committedOperations") or 0
                err_msgs = record.get("errorMessages") or {}
                if err_msgs:
                    # Fail loudly: any per-batch error counts as a partial
                    # data-loss event; we want the operator to see it.
                    raise RuntimeError(f"[CAMPAIGNS] link_indicators apoc.periodic.iterate batch errors: {err_msgs}")
            query_pause()

            # Step 3b: Prune stale PART_OF edges — indicators that WERE in a
            # prior run's top-100 but aren't in THIS run's (aged out, retired,
            # or displaced by newer active indicators).
            #
            # PR-M3d: without this prune, Step 3a's deterministic-top-100
            # still accumulates across runs (MERGE never removes). We use
            # ``r.updated_at`` as the freshness marker: every edge touched
            # by Step 3a above gets ``r.updated_at = datetime()`` (which is
            # always >= ``$run_start_at`` captured below). Any PART_OF edge
            # with ``r.updated_at < $run_start_at`` OR ``r.updated_at IS
            # NULL`` (from pre-fix edges) is stale and gets deleted.
            #
            # Type note: ``$run_start_at`` is passed as an ISO-8601 string
            # from Python (``datetime.now(timezone.utc).isoformat()``).
            # Neo4j returns NULL when comparing a DateTime to a String, so
            # we parse it to a temporal via ``datetime($run_start_at)``.
            # Same pattern as merge_indicators_batch in neo4j_client.py.
            #
            # Edge case: if Step 3a failed mid-run (transaction abort), some
            # edges may have stale timestamps. Idempotent — next successful
            # run reconciles.
            prune_indicators = """
            MATCH (i:Indicator)-[r:PART_OF]->(c:Campaign)
            WHERE r.updated_at IS NULL OR r.updated_at < datetime($run_start_at)
            DELETE r
            RETURN count(r) AS pruned
            """
            prune_result = session.run(
                prune_indicators,
                run_start_at=run_start_at,
                timeout=NEO4J_READ_TIMEOUT,
            )
            prune_record = prune_result.single()
            pruned = prune_record["pruned"] if prune_record else 0
            if pruned:
                logger.info(
                    "[CAMPAIGN] pruned %d stale PART_OF edges (aged out of top-100 or pre-fix residue)",
                    pruned,
                )
            results["links_pruned"] = pruned
            query_pause()

            # Step 4: Deactivate campaigns whose indicators are all retired.
            #
            # PR-M3d: must use OPTIONAL MATCH. The old inner-MATCH
            # (``MATCH (c:Campaign)<-[:PART_OF]-(i:Indicator)``) relied on
            # stale PART_OF edges to now-retired indicators to detect
            # all-retired campaigns. After Step 3b prunes those stale
            # edges, a campaign whose indicators have ALL become inactive
            # ends up with ZERO PART_OF edges (Step 3a only (re)creates
            # edges for ``i.active = true``) — the inner MATCH would miss
            # it entirely and the campaign would remain ``active = true``
            # as a zombie. OPTIONAL MATCH includes campaigns with no
            # PART_OF edges, and the explicit check on ``c.active`` avoids
            # re-setting campaigns already marked inactive.
            logger.info("[DECAY] Deactivating campaigns with no active indicators...")
            cleanup_query = """
                MATCH (c:Campaign)
                WHERE c.active IS NULL OR c.active = true
                OPTIONAL MATCH (c)<-[:PART_OF]-(i:Indicator {active: true})
                WITH c, count(i) AS active_links
                WHERE active_links = 0
                SET c.active = false
                RETURN count(c) as count
            """
            result = session.run(cleanup_query, timeout=NEO4J_READ_TIMEOUT)
            record = result.single()
            cleanup_count = record["count"] if record else 0
            logger.info(f"  [OK] Deactivated {cleanup_count} campaigns with no active indicators")
            results["campaigns_deactivated"] = cleanup_count

            # Step 5: Count re-activated campaigns (updated in this run, now active)
            reactivated_query = """
                MATCH (c:Campaign)
                WHERE c.active = true
                  AND duration.between(c.last_updated, datetime()).minutes < 5
                RETURN count(c) as count
            """
            result = session.run(reactivated_query, timeout=NEO4J_READ_TIMEOUT)
            record = result.single()
            reactivated = record["count"] if record else 0
            if reactivated > 0:
                logger.info(f"  [OK] {reactivated} campaigns active (updated in this run)")

    except Exception as e:
        # PR-N21 BLOCKER (root cause of 2026-04-22 cloud Campaign = 0):
        # the pre-N21 swallower ate exceptions and returned
        # ``{campaigns_created: 0, links_created: 0}``. Airflow saw a
        # clean dict, marked the task SUCCESS, and the operator
        # discovered Campaign = 0 only via post-baseline manual
        # inspection. With 156 qualifying ThreatActors in the cloud
        # graph, the expected output was ~156 Campaigns; the actual
        # output was 0 because the link_indicators step (likely
        # exception cause: Neo4j transaction memory / timeout on the
        # un-batched MATCH (c)<-[:RUNS]-(a)<-[:ATTRIBUTED_TO]-(m)<-
        # [:INDICATES]-(i) cartesian) raised mid-run.
        # Fix: re-raise. Airflow then marks task FAILED with the real
        # traceback, and the operator gets a 1-shot diagnostic instead
        # of a multi-day mystery. See also: ``link_indicators`` is now
        # wrapped in ``apoc.periodic.iterate`` (this PR) to reduce the
        # likelihood of the underlying timeout in the first place.
        logger.error(f"[CAMPAIGNS] build_campaign_nodes FAILED: {e}", exc_info=True)
        raise

    logger.info(f"[CAMPAIGNS] Built {results['campaigns_created']} campaigns, {results['links_created']} links")
    return results


# ---------------------------------------------------------------------------
# 3. CO-OCCURRENCE CONFIDENCE CALIBRATION
# ---------------------------------------------------------------------------


def calibrate_cooccurrence_confidence(neo4j_client) -> Dict:
    """
    Adjust confidence of MISP-event-co-occurrence INDICATES/EXPLOITS edges.

    Large bulk feed dumps (e.g. Feodo Tracker with 5,000 IPs and one malware
    tag) create co-occurrence relationships with artificially high confidence.
    The larger the MISP event, the weaker the actual co-occurrence signal.

    Confidence tiers by event size (number of indicators in same event),
    capped at 0.50 (co-occurrence ceiling):
      ≤ 10  → 0.50  (tight incident report)
      ≤ 20  → 0.45  (small report)
      ≤ 100 → 0.40  (medium feed)
      ≤ 500 → 0.35  (large feed)
      > 500 → 0.30  (bulk dump — weak signal)

    Only edges with ``'misp_cooccurrence'`` or ``'misp_correlation'`` in
    ``r.source_ids`` (set-valued, populated by every source-tagged MERGE
    in ``build_relationships.py``) are modified.  For edges that predate
    PR-M3c and only have the scalar ``r.source_id``, that legacy field
    is also consulted (fallback path).  Explicit-only matches
    (``cve_tag_match``, ``mitre_explicit``) and manually curated edges
    are untouched.

    PR-M3c §8-RI-S3-Q9: this filter used to be ``r.source_id IN [...]``
    (scalar) but Q9 (malware_family match) in build_relationships.py
    OVERWROTE ``r.source_id`` on edges that ALSO came from Q4 co-occurrence,
    hiding the co-occurrence tag and silently exempting ~30-50% of
    INDICATES edges on a 730d baseline from calibration.  The
    ``r.source_ids`` set accumulates every source tag that has ever
    applied to the edge, so co-occurrence provenance cannot be erased
    by a later MERGE.
    """
    if not neo4j_client.driver:
        logger.error("calibrate_cooccurrence_confidence: no Neo4j connection")
        return {}

    results = {}

    # Map: (min_size, max_size, new_confidence)
    # Co-occurrence confidence tiers — capped at 0.50 per co-occurrence ceiling.
    # Tight events (few indicators) get higher confidence within the range;
    # bulk dumps get lower confidence.
    tiers = [
        (0, 10, 0.50),
        (11, 20, 0.45),
        (21, 100, 0.40),
        (101, 500, 0.35),
        (501, None, 0.30),
    ]

    try:
        with neo4j_client.driver.session() as session:
            # Step 1: Pre-compute event sizes ONCE (instead of per-edge).
            # Previously each edge re-counted all indicators in its event — millions
            # of redundant COUNT queries. Now: one COUNT per event, then join.
            #
            # PR #33 round 10: dropped legacy scalar misp_event_id; event
            # membership comes only from misp_event_ids[].
            logger.info("  [CALIBRATE] Pre-computing MISP event sizes...")
            event_sizes_query = """
            MATCH (i:Indicator)
            WHERE i.misp_event_ids IS NOT NULL AND size(i.misp_event_ids) > 0
            UNWIND [eid IN i.misp_event_ids WHERE eid IS NOT NULL AND eid <> ''] AS eid
            RETURN eid, count(DISTINCT i) AS sz
            """
            event_size_result = session.run(event_sizes_query, timeout=NEO4J_READ_TIMEOUT)
            event_sizes = {r["eid"]: r["sz"] for r in event_size_result}
            if event_sizes:
                min_sz = min(event_sizes.values())
                max_sz = max(event_sizes.values())
                avg_sz = sum(event_sizes.values()) / len(event_sizes)
                logger.info(
                    f"  [CALIBRATE] Pre-computed sizes for {len(event_sizes)} events "
                    f"(min={min_sz}, max={max_sz}, avg={avg_sz:.0f})"
                )
            else:
                logger.info("  [CALIBRATE] No events with indicators found — skipping calibration")
                return results

            # Step 2: For each tier, collect matching event IDs and update edges in chunks.
            for min_s, max_s, conf in tiers:
                tier_label = f"size {min_s}\u2013{max_s if max_s else '\u221e'} \u2192 conf={conf}"
                try:
                    tier_eids = [
                        eid for eid, sz in event_sizes.items() if sz >= min_s and (max_s is None or sz <= max_s)
                    ]
                    if not tier_eids:
                        logger.info(f"  [CALIBRATE] {tier_label}: 0 events in range — skipped")
                        results[tier_label] = 0
                        continue

                    # Match indicators that have this event id in misp_event_ids[].
                    # PR #33 round 10: dropped legacy scalar misp_event_id leg.
                    # PR-M3c §8-RI-S3-Q9: match on ``r.source_ids`` (set-
                    # valued accumulator, populated by every source-tagged
                    # MERGE in build_relationships.py as of this PR) OR fall
                    # back to scalar ``r.source_id`` for legacy edges that
                    # predate PR-M3c and have no array yet. Before this fix,
                    # Q9's MERGE overwrote ``r.source_id = "malware_family_match"``
                    # on edges that ALSO came from Q4 co-occurrence, and the
                    # scalar filter silently exempted them from size-based
                    # calibration → confidence frozen at 0.8 instead of the
                    # bulk-dump tier's 0.30. Matching on ANY() over the
                    # accumulated array restores the co-occurrence tag's
                    # visibility.
                    update_cypher = """
                    UNWIND $eids AS eid
                    MATCH (i:Indicator)
                    WHERE i.misp_event_ids IS NOT NULL AND eid IN i.misp_event_ids
                    MATCH (i)-[r:INDICATES|EXPLOITS]->(target)
                    WHERE (r.source_ids IS NOT NULL
                           AND any(s IN r.source_ids WHERE s IN ["misp_cooccurrence", "misp_correlation"]))
                       OR r.source_id IN ["misp_cooccurrence", "misp_correlation"]
                    SET r.confidence_score = $conf,
                        r.calibrated_at = datetime()
                    RETURN count(r) AS updated
                    """
                    total_updated = 0
                    # Split large events (>1000 indicators) into individual chunks
                    # to avoid transaction memory issues from millions of edges
                    large_eids = [eid for eid in tier_eids if event_sizes.get(eid, 0) > 1000]
                    small_eids = [eid for eid in tier_eids if event_sizes.get(eid, 0) <= 1000]

                    # Small events: batch 1000 event IDs at a time with 3s pause
                    for ci in range(0, len(small_eids), 1000):
                        chunk = small_eids[ci : ci + 1000]
                        result = session.run(update_cypher, eids=chunk, conf=conf, timeout=NEO4J_READ_TIMEOUT)
                        record = result.single()
                        total_updated += record["updated"] if record else 0
                        if ci + 1000 < len(small_eids):
                            query_pause()

                    # Large events: use apoc.periodic.iterate to batch at edge level.
                    # A 96K-indicator event can have millions of edges — too many for one tx.
                    if large_eids:
                        logger.info(
                            f"  [CALIBRATE] {tier_label}: processing {len(large_eids)} large events "
                            f"(>{1000} indicators each) via apoc.periodic.iterate"
                        )
                    # Same array-only semantics as the small-event path.
                    #
                    # Parameterized via apoc.periodic.iterate's ``params`` config so $eid and
                    # $conf are safely bound inside both the matcher and the action.
                    #
                    # PR #34 round 19 (bugbot MED): cross-transaction entity safety.
                    # apoc.periodic.iterate runs the inner action in a NEW transaction
                    # per batch — raw entity references from the outer query (``r``)
                    # cannot safely be used as bound entities in the inner. Pattern:
                    # outer returns ``id(r) AS rid`` (primitive long), inner re-MATCHes
                    # ``MATCH ()-[r]->() WHERE id(r) = $rid`` to bind a fresh handle.
                    # PR-M3c: same array-or-scalar filter as the small path
                    # (see ``update_cypher`` above).  Must be expressed inside
                    # the apoc.periodic.iterate OUTER matcher; a single line
                    # with both branches concatenated with OR.
                    large_batch_query = (
                        "CALL apoc.periodic.iterate("
                        "  'MATCH (i:Indicator) WHERE i.misp_event_ids IS NOT NULL AND $eid IN i.misp_event_ids "
                        "  MATCH (i)-[r:INDICATES|EXPLOITS]->(target) "
                        "  WHERE (r.source_ids IS NOT NULL "
                        '         AND any(s IN r.source_ids WHERE s IN ["misp_cooccurrence", "misp_correlation"])) '
                        '     OR r.source_id IN ["misp_cooccurrence", "misp_correlation"] '
                        "  RETURN id(r) AS rid', "
                        "  'MATCH ()-[r]->() WHERE id(r) = $rid "
                        "  SET r.confidence_score = $conf, r.calibrated_at = datetime()', "
                        "  {batchSize: 5000, parallel: false, params: {eid: $eid, conf: $conf}}"
                        ") YIELD total "
                        "RETURN total AS updated"
                    )
                    for eid in large_eids:
                        evt_size = event_sizes.get(eid, 0)
                        result = session.run(large_batch_query, eid=eid, conf=conf, timeout=NEO4J_READ_TIMEOUT)
                        record = result.single()
                        evt_updated = record["updated"] if record else 0
                        total_updated += evt_updated
                        logger.info(
                            f"  [CALIBRATE]   event {eid} ({evt_size} indicators): {evt_updated} edges calibrated"
                        )
                        query_pause()  # Let Neo4j flush between large event batches

                    results[tier_label] = total_updated
                    if total_updated:
                        logger.info(f"  [CALIBRATE] {tier_label}: {total_updated} edges ({len(tier_eids)} events)")
                except Exception as tier_err:
                    logger.error(f"  [CALIBRATE] {tier_label} FAILED: {tier_err}")
                    results[tier_label] = 0

    except Exception as e:
        # PR-N21 BLOCKER: see decay_ioc_confidence + build_campaign_nodes
        # for full rationale. Re-raise so enrichment task fails loudly.
        # Note: per-tier exception handling at line ~743 already catches
        # transient per-event failures and continues with the next tier
        # (results[tier_label] = 0 + log) — that's the correct
        # best-effort behaviour at the FINE-GRAINED level. The OUTER
        # except (here) catches whole-session failures (driver dead,
        # schema corruption, etc.) which must NOT be silently
        # swallowed.
        logger.error(f"[CALIBRATE] calibrate_cooccurrence_confidence FAILED: {e}", exc_info=True)
        raise

    total = sum(results.values())
    tier_summary = ", ".join(f"{k}: {v}" for k, v in results.items() if v > 0)
    logger.info(f"[CALIBRATE] Confidence calibration complete — {total} edges updated")
    if tier_summary:
        logger.info(f"[CALIBRATE] Tier breakdown: {tier_summary}")
    return results


# ---------------------------------------------------------------------------
# JOB 4: Vulnerability ↔ CVE REFERS_TO Bridge
# ---------------------------------------------------------------------------
# The ResilMesh data model defines bidirectional REFERS_TO relationships
# between Vulnerability and CVE nodes (neo4j_relationships_properties.csv).
# EdgeGuard writes both node types but populates cve_id on both sides —
# the relationship itself is not created during the per-item sync.
# This job closes the gap in a single idempotent Cypher pass.
# ---------------------------------------------------------------------------


def bridge_vulnerability_cve(neo4j_client) -> Dict:
    """
    Create bidirectional REFERS_TO relationships between Vulnerability and
    CVE nodes that share the same cve_id value.

    ResilMesh schema (neo4j_relationships_properties.csv):
        (Vulnerability)-[:REFERS_TO]->(CVE)
        (CVE)-[:REFERS_TO]->(Vulnerability)

    Both directions are MERGEd so the job is safe to run repeatedly.
    """
    results: Dict = {"linked": 0, "errors": 0}

    # Both REFERS_TO edges carry src_uuid + trg_uuid for cross-environment
    # traceability — endpoints (Vulnerability + CVE) already have n.uuid set
    # by their respective MERGE paths (merge_vulnerabilities_batch / merge_cve).
    #
    # The inner apoc.periodic.iterate action MUST be a single Cypher string
    # literal. Python implicit-concat does NOT apply inside a triple-quoted
    # outer string — adjacent ``'...' '...'`` fragments would be sent to
    # Neo4j as separate quoted tokens and produce a syntax error. Bugbot
    # caught this on PR #33 round 3. Keep the inner action on a single
    # logical line (long but unambiguous).
    # PR-N8 HIGH (audit Cross-Checker, 2026-04-21): stamp ON CREATE
    # ``r.created_at`` + SET ``r.updated_at`` on BOTH directions of
    # the bidirectional REFERS_TO. Pre-fix these edges had neither,
    # so every bridge-job re-run was invisible to cloud delta-sync +
    # STIX incremental export (both filter by ``r.updated_at >= cutoff``).
    # Same omission was patched on RUNS + PART_OF(malware) in
    # build_campaign_nodes above.
    query = """
    CALL apoc.periodic.iterate(
        'MATCH (v:Vulnerability) WHERE v.cve_id IS NOT NULL RETURN v',
        'WITH $v AS v MATCH (c:CVE {cve_id: v.cve_id}) MERGE (v)-[r1:REFERS_TO]->(c) ON CREATE SET r1.created_at = datetime() SET r1.src_uuid = coalesce(r1.src_uuid, v.uuid), r1.trg_uuid = coalesce(r1.trg_uuid, c.uuid), r1.updated_at = datetime() MERGE (c)-[r2:REFERS_TO]->(v) ON CREATE SET r2.created_at = datetime() SET r2.src_uuid = coalesce(r2.src_uuid, c.uuid), r2.trg_uuid = coalesce(r2.trg_uuid, v.uuid), r2.updated_at = datetime()',
        {batchSize: 5000, parallel: false}
    )
    YIELD total
    RETURN total AS linked
    """

    # PR #34 round 20: count Vulnerability orphans directly with NOT EXISTS.
    # Replaces the broken round-18 ``expected_query`` design — that compared
    # ``expected > results["linked"]`` where ``expected`` was pairs-with-CVE
    # (subset) and ``results["linked"]`` was the apoc ``total`` (count of
    # OUTER-query rows processed, regardless of inner MATCH success — a
    # superset). The comparison was therefore always false (subset ≤ superset)
    # and the orphan log NEVER fired. The new ``skip_query`` counts orphans
    # directly: Vulnerabilities with cve_id but no matching CVE node — every
    # one is an edge silently dropped by the bridge.
    skip_query = (
        "MATCH (v:Vulnerability) WHERE v.cve_id IS NOT NULL "
        "AND NOT EXISTS { MATCH (c:CVE {cve_id: v.cve_id}) } "
        "RETURN count(v) AS c"
    )

    try:
        with neo4j_client.driver.session() as session:
            try:
                skip_rec = session.run(skip_query, timeout=NEO4J_READ_TIMEOUT).single()
                skip_count = skip_rec["c"] if skip_rec else 0
            except Exception as exp_err:
                logger.debug("bridge_vulnerability_cve skip_query failed: %s", exp_err)
                skip_count = 0
            record = session.run(query, timeout=NEO4J_READ_TIMEOUT).single()
            results["linked"] = record["linked"] if record else 0
        logger.info(f"[BRIDGE] Vulnerability↔CVE REFERS_TO: {results['linked']} pairs linked")
        if skip_count > 0:
            logger.info(
                "[BRIDGE] %d Vulnerability nodes have no matching CVE — likely missing NVD ingestion",
                skip_count,
            )
    except Exception as e:
        # PR-N21 BLOCKER: see decay_ioc_confidence + build_campaign_nodes
        # for full rationale. The pre-N21 swallower downgraded to
        # WARNING + incremented results["errors"], but neither Airflow
        # nor any post-baseline assertion read results["errors"], so
        # the failure was effectively invisible.
        # Re-raise so the DAG task FAILS loudly. Operators see the
        # actual exception in the Airflow log on the FIRST failed run
        # instead of debugging stale REFERS_TO counts days later.
        logger.error(f"[BRIDGE] Vulnerability↔CVE bridge FAILED: {e}", exc_info=True)
        raise

    return results


# ---------------------------------------------------------------------------
# CONVENIENCE RUNNER
# ---------------------------------------------------------------------------


def run_all_enrichment_jobs(neo4j_client) -> Dict:
    """
    Run all four post-sync enrichment jobs in sequence.

    Returns a summary dict for logging/metrics.
    """
    summary = {}

    logger.info("=" * 55)
    logger.info("Running post-sync enrichment jobs")
    logger.info("=" * 55)

    def _timed(label, fn, *args):
        _t0 = time.monotonic()
        result = fn(*args)
        if _METRICS_AVAILABLE:
            try:
                record_enrichment_duration(label, time.monotonic() - _t0)
            except Exception:
                logger.debug("Metrics recording failed", exc_info=True)
        return result

    logger.info("\n[1/4] Vulnerability↔CVE REFERS_TO Bridge...")
    summary["bridge"] = _timed("bridge", bridge_vulnerability_cve, neo4j_client)

    logger.info("\n[2/4] Campaign Node Builder...")
    summary["campaigns"] = _timed("campaigns", build_campaign_nodes, neo4j_client)

    logger.info("\n[3/4] Co-occurrence Confidence Calibration...")
    summary["calibration"] = _timed("calibration", calibrate_cooccurrence_confidence, neo4j_client)

    logger.info("\n[4/4] IOC Confidence Decay...")
    summary["decay"] = _timed("decay", decay_ioc_confidence, neo4j_client)

    # PR #33 round 13: explicit aggregated summary so an operator scanning logs
    # sees totals from all 4 jobs without grepping each function's output.
    def _sum(d):
        if isinstance(d, dict):
            return sum(v for v in d.values() if isinstance(v, (int, float)))
        return d if isinstance(d, (int, float)) else 0

    logger.info(
        "[ENRICHMENT SUMMARY] bridge=%s campaigns=%s calibration=%s decay=%s",
        _sum(summary.get("bridge")),
        _sum(summary.get("campaigns")),
        _sum(summary.get("calibration")),
        _sum(summary.get("decay")),
    )
    logger.info("[DONE] All enrichment jobs complete")
    return summary


if __name__ == "__main__":
    from neo4j_client import Neo4jClient

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    client = Neo4jClient()
    client.connect()
    run_all_enrichment_jobs(client)
    client.close()
