#!/usr/bin/env python3
"""
EdgeGuard — Post-Sync Enrichment Jobs
======================================
Five graph-quality jobs that run AFTER every MISP→Neo4j sync.
They are designed to be idempotent — safe to re-run at any time.

Jobs
----
1. decay_ioc_confidence   — Reduce confidence of stale indicators over time
2. build_campaign_nodes   — Group ThreatActor / Malware / Indicator into Campaigns
3. calibrate_cooccurrence — Adjust INDICATES/EXPLOITS confidence for large MISP feed dumps
4. bridge_vulnerability_cve — Create REFERS_TO between Vulnerability and CVE nodes
5. merge_alias_duplicate_actors — Fold alias-duplicate ThreatActors into their MITRE canonical
"""

import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neo4j_client import NEO4J_READ_TIMEOUT, _dedup_concat_clause, apoc_iterate_failures  # noqa: E402
from node_identity import _REJECTED_PLACEHOLDER_NAMES, compute_node_uuid  # noqa: E402
from query_pause import query_pause
from relationship_provenance import aggregated_prov_set, inherited_prov_set, node_feeds, prov_set, prov_with  # noqa: E402

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
    - 2026-10: retirement by this job is tagged ``retired_by = 'decay'`` so a node that
      is observed again in a later sync is reactivated (``active = true``, ``retired_at``
      cleared, decay tier reset) — only a manual decommission (``retired_at`` set without
      that tag) survives a re-observation
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
                        n.retired_at = datetime(),
                        n.retired_by = 'decay'
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
      Malware     -[:PART_OF_CAMPAIGN]-> Campaign
      Indicator   -[:PART_OF_CAMPAIGN]-> Campaign  (sampled — up to 100 per campaign)

    ``PART_OF_CAMPAIGN`` was ``PART_OF`` until 2026-10: ResilMesh uses ``PART_OF`` for its own
    asset model (IP → Subnet, the OrganizationUnit hierarchy), and in the shared database one
    relationship name must have one meaning.

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
                          c.uuid = $campaign_uuids[a.name],
                          c.edgeguard_managed = true
            ON MATCH SET c.edgeguard_enriched = CASE WHEN c.edgeguard_managed = true THEN c.edgeguard_enriched ELSE true END
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
            // existed on PART_OF_CAMPAIGN(malware) and REFERS_TO — fixed below.
            ON CREATE SET r_runs.src_uuid = a.uuid, r_runs.trg_uuid = c.uuid,
                          r_runs.created_at = datetime()
            SET r_runs.src_uuid = coalesce(r_runs.src_uuid, a.uuid),
                r_runs.trg_uuid = coalesce(r_runs.trg_uuid, c.uuid),
                r_runs.updated_at = datetime(),
                r_runs.edgeguard_managed = true,
                // 2026-10 (relationship provenance): the campaign is built from the
                // actor's ATTRIBUTED_TO links, so RUNS carries their feeds, record ids
                // and MISP events.
                {aggregated_prov_set("r_runs", "(a)<-[_at:ATTRIBUTED_TO]-(:Malware)", "_at")}
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
            link_malware = f"""
            MATCH (a:ThreatActor)<-[_at:ATTRIBUTED_TO]-(m:Malware)
            MATCH (c:Campaign {{actor_name: a.name}})
            MERGE (m)-[r:PART_OF_CAMPAIGN]->(c)
            // PR-N8 HIGH (audit Cross-Checker): stamp created_at /
            // updated_at so PART_OF_CAMPAIGN(malware) edges are visible to
            // cloud delta-sync. See RUNS comment above for rationale.
            ON CREATE SET r.src_uuid = m.uuid, r.trg_uuid = c.uuid,
                          r.created_at = datetime()
            SET r.src_uuid = coalesce(r.src_uuid, m.uuid),
                r.trg_uuid = coalesce(r.trg_uuid, c.uuid),
                r.updated_at = datetime(),
                r.edgeguard_managed = true,
                // 2026-10 (relationship provenance): inherited from the ATTRIBUTED_TO link.
                {inherited_prov_set("r", ["_at"])}
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
            # Combined with MERGE's no-delete semantic, PART_OF_CAMPAIGN edges
            # accumulated monotonically: run N attached {i1..i100}, run N+1
            # attached {i17..i116}, old 16 kept their edges forever. After
            # 730 daily runs, a ThreatActor with 10k active indicators had
            # EVERY single one wired via PART_OF_CAMPAIGN — defeating the 100-cap's
            # purpose and producing a non-deterministic graph where "is
            # indicator X PART_OF_CAMPAIGN campaign C?" depended on history, not
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
            # Net: PART_OF_CAMPAIGN edges for each Campaign always equal the current
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
              "MATCH (a:ThreatActor {name: c.actor_name})<-[_at:ATTRIBUTED_TO]-(m:Malware)<-[_ind:INDICATES]-(i:Indicator)
               WHERE i.active = true
               WITH c, i, _at, _ind
               ORDER BY i.first_imported_at DESC, i.value ASC
               WITH c, collect({i: i, at: _at, ind: _ind})[0..100] AS _paths
               UNWIND _paths AS _p
               WITH c, _p.i AS i, _p.at AS _at, _p.ind AS _ind
               MERGE (i)-[r:PART_OF_CAMPAIGN]->(c)
               ON CREATE SET r.created_at = datetime(),
                             r.src_uuid = i.uuid,
                             r.trg_uuid = c.uuid
               SET r.src_uuid = coalesce(r.src_uuid, i.uuid),
                   r.trg_uuid = coalesce(r.trg_uuid, c.uuid),
                   r.updated_at = datetime(),
                   r.edgeguard_managed = true,
                   __INHERITED_PROV__",
              {batchSize: 25, parallel: false, retries: 2}
            )
            YIELD batches, total, errorMessages, failedBatches, failedOperations, wasTerminated,
                  batch, operations, updateStatistics
            RETURN batches, total, errorMessages, failedBatches, failedOperations, wasTerminated,
                   batch, operations, updateStatistics
            """.replace(
                # 2026-10 (relationship provenance): inherited from the INDICATES and
                # ATTRIBUTED_TO links of the path that put the indicator in the campaign.
                "__INHERITED_PROV__",
                inherited_prov_set("r", ["_ind", "_at"]),
            )
            result = session.run(link_indicators_batched, timeout=NEO4J_READ_TIMEOUT)
            record = result.single()
            if record:
                # Fail loudly: any per-batch failure counts as a partial
                # data-loss event; we want the operator to see it. Every
                # APOC failure column is read, not only errorMessages: a
                # heap OOM inside a batch reports empty errorMessages with
                # failedBatches=1 and batch.errors set.
                failures = apoc_iterate_failures(record)
                if failures:
                    raise RuntimeError(f"[CAMPAIGNS] link_indicators apoc.periodic.iterate batch failures: {failures}")
            query_pause()

            # Bugbot round 1 (PR #105, MEDIUM): the pre-fix code used
            # ``record.get("committedOperations")`` as the PART_OF_CAMPAIGN link
            # count. Per APOC docs ``committedOperations`` is the number
            # of SUCCESSFUL INNER-STATEMENT EXECUTIONS — one per outer row
            # (i.e. one per Campaign) — NOT the number of MERGE rows
            # produced. Pre-N21 ``count(*) AS links`` returned ~15,600
            # for 156 campaigns × ~100 indicators; using
            # committedOperations would report ~156 instead → ~100× low.
            # The ``[CAMPAIGNS] Built N campaigns, M links`` log at the
            # end of build_campaign_nodes would show a misleading M.
            #
            # Fix: run a follow-up count query keyed on
            # ``r.updated_at >= $run_start_at`` — this gives the true
            # count of PART_OF_CAMPAIGN edges touched by THIS run's Step 3a
            # (same freshness marker Step 3b uses to prune).
            links_count_query = """
            MATCH (:Indicator)-[r:PART_OF_CAMPAIGN]->(:Campaign)
            WHERE r.updated_at >= datetime($run_start_at)
            RETURN count(r) AS links
            """
            links_result = session.run(
                links_count_query, run_start_at=run_start_at, timeout=NEO4J_READ_TIMEOUT
            ).single()
            results["links_created"] += int((links_result["links"] if links_result else 0) or 0)

            # Step 3b: Prune stale PART_OF_CAMPAIGN edges — indicators that WERE in a
            # prior run's top-100 but aren't in THIS run's (aged out, retired,
            # or displaced by newer active indicators).
            #
            # PR-M3d: without this prune, Step 3a's deterministic-top-100
            # still accumulates across runs (MERGE never removes). We use
            # ``r.updated_at`` as the freshness marker: every edge touched
            # by Step 3a above gets ``r.updated_at = datetime()`` (which is
            # always >= ``$run_start_at`` captured below). Any PART_OF_CAMPAIGN edge
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
            MATCH (i:Indicator)-[r:PART_OF_CAMPAIGN]->(c:Campaign)
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
                    "[CAMPAIGN] pruned %d stale PART_OF_CAMPAIGN edges (aged out of top-100 or pre-fix residue)",
                    pruned,
                )
            results["links_pruned"] = pruned
            query_pause()

            # Step 4: Deactivate campaigns whose indicators are all retired.
            #
            # PR-M3d: must use OPTIONAL MATCH. The old inner-MATCH
            # (``MATCH (c:Campaign)<-[:PART_OF_CAMPAIGN]-(i:Indicator)``) relied on
            # stale PART_OF_CAMPAIGN edges to now-retired indicators to detect
            # all-retired campaigns. After Step 3b prunes those stale
            # edges, a campaign whose indicators have ALL become inactive
            # ends up with ZERO PART_OF_CAMPAIGN edges (Step 3a only (re)creates
            # edges for ``i.active = true``) — the inner MATCH would miss
            # it entirely and the campaign would remain ``active = true``
            # as a zombie. OPTIONAL MATCH includes campaigns with no
            # PART_OF_CAMPAIGN edges, and the explicit check on ``c.active`` avoids
            # re-setting campaigns already marked inactive.
            logger.info("[DECAY] Deactivating campaigns with no active indicators...")
            cleanup_query = """
                MATCH (c:Campaign)
                WHERE c.active IS NULL OR c.active = true
                OPTIONAL MATCH (c)<-[:PART_OF_CAMPAIGN]-(i:Indicator {active: true})
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

    Only edges whose evidence label (``r.match_type``) is
    ``misp_cooccurrence`` or ``misp_correlation`` are modified. Explicit
    matches (``cve_tag``, ``mitre_explicit``, ``malware_family``) and
    manually curated edges are untouched.

    2026-10: no producer writes event co-occurrence edges any more (removed
    with the fresh-baseline PR — EdgeGuard MISP events are per-source,
    per-day buckets, so sharing one asserted nothing), so on a fresh graph
    this job finds nothing to calibrate. The filter moved from the dropped
    ``r.source_id`` / ``r.source_ids`` fields (which mixed feed names with
    evidence names) to ``r.match_type``, where the kind of evidence lives.
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
            failed_tiers: List[Tuple[str, str]] = []
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
                    # 2026-10 (relationship provenance): the kind of evidence lives in
                    # ``r.match_type``; ``r.source_id`` / ``r.source_ids`` were dropped
                    # (they mixed feed names with evidence names). See the docstring.
                    update_cypher = """
                    UNWIND $eids AS eid
                    MATCH (i:Indicator)
                    WHERE i.misp_event_ids IS NOT NULL AND eid IN i.misp_event_ids
                    MATCH (i)-[r:INDICATES|EXPLOITS]->(target)
                    WHERE r.match_type IN ["misp_cooccurrence", "misp_correlation"]
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
                        '  WHERE r.match_type IN ["misp_cooccurrence", "misp_correlation"] '
                        "  RETURN id(r) AS rid', "
                        "  'MATCH ()-[r]->() WHERE id(r) = $rid "
                        "  SET r.confidence_score = $conf, r.calibrated_at = datetime()', "
                        "  {batchSize: 5000, parallel: false, params: {eid: $eid, conf: $conf}}"
                        ") YIELD batches, total, errorMessages, failedBatches, failedOperations, wasTerminated, "
                        "  batch, operations, updateStatistics "
                        "RETURN total AS updated, batches, errorMessages, failedBatches, failedOperations, "
                        "  wasTerminated, batch, operations, updateStatistics"
                    )
                    for eid in large_eids:
                        evt_size = event_sizes.get(eid, 0)
                        result = session.run(large_batch_query, eid=eid, conf=conf, timeout=NEO4J_READ_TIMEOUT)
                        record = result.single()
                        failures = apoc_iterate_failures(record) if record else []
                        if failures:
                            # A failed batch leaves part of the event uncalibrated; the
                            # outer ``total`` would still count every outer row.
                            raise RuntimeError(
                                f"[CALIBRATE] event {eid} apoc.periodic.iterate batch failures: {failures}"
                            )
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
                    failed_tiers.append((tier_label, str(tier_err)))

            if failed_tiers:
                # Every tier was attempted (best effort per tier), but a failed
                # tier leaves edges uncalibrated, so the job must not end green.
                raise RuntimeError(f"[CALIBRATE] {len(failed_tiers)} tier(s) failed: {failed_tiers}")

    except Exception as e:
        # PR-N21 BLOCKER: see decay_ioc_confidence + build_campaign_nodes
        # for full rationale. Re-raise so enrichment task fails loudly.
        # Note: per-tier exception handling above catches per-event
        # failures and continues with the next tier (results[tier_label]
        # = 0 + log) so the remaining tiers still get calibrated; the
        # job then raises once all tiers ran. The OUTER except (here)
        # also catches whole-session failures (driver dead, schema
        # corruption, etc.) which must NOT be silently swallowed.
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
    # Same omission was patched on RUNS + PART_OF_CAMPAIGN(malware) in
    # build_campaign_nodes above.
    query = (
        """
    CALL apoc.periodic.iterate(
        'MATCH (v:Vulnerability) WHERE v.cve_id IS NOT NULL RETURN v',
        'WITH $v AS v __PROV_WITH__MATCH (c:CVE {cve_id: v.cve_id}) MERGE (v)-[r1:REFERS_TO]->(c) ON CREATE SET r1.created_at = datetime() SET r1.src_uuid = coalesce(r1.src_uuid, v.uuid), r1.trg_uuid = coalesce(r1.trg_uuid, c.uuid), r1.updated_at = datetime(), r1.edgeguard_managed = true, __PROV_SET_R1__ MERGE (c)-[r2:REFERS_TO]->(v) ON CREATE SET r2.created_at = datetime() SET r2.src_uuid = coalesce(r2.src_uuid, c.uuid), r2.trg_uuid = coalesce(r2.trg_uuid, v.uuid), r2.updated_at = datetime(), r2.edgeguard_managed = true, __PROV_SET_R2__',
        {batchSize: 5000, parallel: false}
    )
    YIELD batches, total, errorMessages, failedBatches, failedOperations, wasTerminated,
          batch, operations, updateStatistics
    RETURN total AS linked, batches, errorMessages, failedBatches, failedOperations, wasTerminated,
           batch, operations, updateStatistics
    """.replace(
            # 2026-10 (relationship provenance): the link is asserted by the vulnerability record
            # itself (its cve_id), so both directions carry that record's feeds, ids and events.
            "__PROV_WITH__",
            prov_with("v", node_feeds("v")),
        )
        .replace("__PROV_SET_R1__", prov_set("r1"))
        .replace("__PROV_SET_R2__", prov_set("r2"))
    )

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
            failures = apoc_iterate_failures(record) if record else []
            if failures:
                raise RuntimeError(f"[BRIDGE] Vulnerability↔CVE apoc.periodic.iterate batch failures: {failures}")
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
# JOB 5: ThreatActor alias-duplicate merge
# ---------------------------------------------------------------------------
# OTX pulses and MISP galaxy tags name the same actor under several labels
# (``reddelta`` / ``twill typhoon`` / ``unc6384`` next to the MITRE node
# ``mustang panda`` whose ``aliases[]`` already lists all three). Each label
# became its own ThreatActor node, splitting the actor's Malware
# ATTRIBUTED_TO edges, Campaigns and technique links across N nodes.
# This job folds every NON-MITRE node whose name is an alias of exactly ONE
# MITRE-sourced actor into that canonical node with
# ``apoc.refactor.mergeNodes``. It runs BEFORE ``build_campaign_nodes`` so
# campaigns are materialised on the merged actor.
#
# String-level hygiene for the SAME problem at ingest (composite / generic
# names) lives in ``src/actor_name_hygiene.py``.
# ---------------------------------------------------------------------------

_ACTOR_ALIAS_MERGE_ENV_FLAG = "EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE"
_ACTOR_ALIAS_MERGE_BATCH_SIZE = 200  # (canonical, duplicate) pairs per transaction
_ACTOR_ALIAS_MERGE_MAX_PAIRS_PER_RUN = 2000  # hard cap; the rest waits for the next run
_ACTOR_ALIAS_MERGE_MITRE_SOURCE = "mitre_attck"  # SOURCE_TAGS["mitre"] — canonical actors

# ``apoc.refactor.mergeNodes`` property strategy. First node in the list is
# the canonical; ``"discard"`` keeps the canonical's value, ``"combine"``
# unions both values into a list. Every SCALAR the rest of the codebase
# reads as a scalar is listed explicitly as ``"discard"`` so it can never be
# silently turned into a list; every list-typed accumulator is
# ``"combine"``. ``".*"`` is APOC's catch-all — ``"discard"`` so an
# unforeseen scalar also stays scalar (the ``".*": "combine"`` wildcard is
# deliberately NOT used). The same map governs relationship properties when
# ``mergeRels: true`` collapses two parallel edges, hence the edge-side
# list props (``sources``, ``source_ids``) are included.
_ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY: Dict[str, str] = {
    # identity — canonical wins; the UNIQUE(name) constraint stays satisfied
    "name": "discard",
    "uuid": "discard",
    "mitre_id": "discard",
    # node scalars (merge_node_with_source / merge_actor / decay job)
    "description": "discard",
    "confidence_score": "discard",
    "tag": "discard",
    "active": "discard",
    "first_imported_at": "discard",
    "last_updated": "discard",
    "last_imported_from": "discard",
    "edgeguard_managed": "discard",
    "retired_at": "discard",
    "retired_by": "discard",
    "last_decayed_tier": "discard",
    "last_decayed_at": "discard",
    "sophistication": "discard",
    "primary_motivation": "discard",
    "resource_level": "discard",
    "tlp": "discard",
    # node lists (accumulators)
    "aliases": "combine",
    "source": "combine",
    "zone": "combine",
    "tags": "combine",
    "uses_techniques": "combine",
    "reported_techniques": "combine",
    "misp_event_ids": "combine",
    "misp_attribute_ids": "combine",
    "pulse_ids": "combine",
    # edge lists (only relevant when mergeRels collapses parallel edges);
    # ``misp_event_ids`` above covers edges too
    "sources": "combine",
    "source_refs": "combine",
    # everything else: keep the canonical's value, never listify
    ".*": "discard",
}

# Candidate pairs. ``d`` must NOT be MITRE-sourced, ``c`` MUST be, and
# ``toLower(trim(d.name))`` must equal ``toLower(trim(x))`` for some
# ``x IN c.aliases``. Placeholder names (``"unknown"``, ``"apt"`` …) are
# excluded on both sides — same ``_REJECTED_PLACEHOLDER_NAMES`` gate that
# ``build_relationships`` Q2 applies to alias matching. Grouped per
# duplicate so the caller can apply the ambiguity guard
# (``size(canonical_names) > 1`` → skip).
_ACTOR_ALIAS_MERGE_CANDIDATES_CYPHER = """
MATCH (d:ThreatActor)
WHERE d.name IS NOT NULL
  AND size(trim(d.name)) > 0
  AND NOT toLower(trim(d.name)) IN $placeholders
  AND NOT $mitre_source IN coalesce(d.source, [])
WITH d, toLower(trim(d.name)) AS dup_key
MATCH (c:ThreatActor)
WHERE c <> d
  AND $mitre_source IN coalesce(c.source, [])
  AND c.aliases IS NOT NULL
  AND dup_key IN [x IN c.aliases
                  WHERE x IS NOT NULL
                    AND size(trim(toString(x))) > 0
                    AND NOT toLower(trim(toString(x))) IN $placeholders
                  | toLower(trim(toString(x)))]
WITH d, collect(DISTINCT c.name) AS canonical_names
RETURN d.name AS duplicate_name, canonical_names
ORDER BY duplicate_name
"""

# One ``mergeNodes`` call per canonical with ALL of its duplicates in the
# batch, so rows of the UNWIND never touch each other's nodes (a duplicate
# maps to exactly one canonical thanks to the ambiguity guard). The
# MITRE-side guards are re-checked here so a stale candidate list can never
# merge two canonical actors. ``c.aliases`` gains the duplicate names BEFORE
# the merge, as required; ``apoc.coll.toSet`` afterwards de-duplicates what
# ``"combine"`` produced.
_ACTOR_ALIAS_MERGE_APPLY_CYPHER = """
UNWIND $groups AS g
MATCH (c:ThreatActor {name: g.canonical})
WHERE $mitre_source IN coalesce(c.source, [])
MATCH (d:ThreatActor)
WHERE d.name IN g.duplicates
  AND d <> c
  AND NOT $mitre_source IN coalesce(d.source, [])
WITH c, collect(DISTINCT d) AS dups
WHERE size(dups) > 0
SET c.aliases = apoc.coll.toSet(coalesce(c.aliases, []) + [d IN dups | d.name])
WITH c, size(dups) AS n_dups, dups
CALL apoc.refactor.mergeNodes([c] + dups, {
    properties: $strategy,
    mergeRels: true,
    produceSelfRel: false
})
YIELD node
SET node.aliases = apoc.coll.toSet(coalesce(node.aliases, [])),
    node.source = apoc.coll.toSet(coalesce(node.source, [])),
    node.last_updated = datetime()
RETURN sum(n_dups) AS merged, count(node) AS canonicals
"""

# APOC's ``combine`` keeps a list only when the merged values differ: when the canonical
# and a duplicate hold the same value (``zone = ["global"]`` on both, or
# ``r.sources = ["alienvault_otx"]`` on two parallel edges) it stores that one value as a
# plain string. Found on the 730-day graph (2026-10-14): the 11 MITRE actors that had
# absorbed an OTX duplicate held ``zone`` as a string, and 21 of their ATTRIBUTED_TO edges
# held ``r.sources`` as a string. Every ``combine`` property is a list by contract, so the
# canonical node and all of its edges are wrapped back into lists after each merge batch.
# On edges only the provenance lists are lists: ``source`` on a SOURCED_FROM edge is the
# scalar source id (``combine`` of two parallel edges to the same Source keeps it scalar) and
# must stay one; the node keys (``zone``, ``aliases`` …) do not exist on edges.
_ACTOR_ALIAS_MERGE_EDGE_LIST_PROPS: Tuple[str, ...] = ("misp_event_ids", "source_refs", "sources")
_ACTOR_ALIAS_MERGE_LIST_PROPS: Tuple[str, ...] = tuple(
    sorted(
        k
        for k, v in _ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY.items()
        if v == "combine" and k not in ("sources", "source_refs")
    )
)


def _list_or_wrapped(ref: str) -> str:
    """Cypher: ``ref`` as a de-duplicated list (``[x]`` for a scalar, null stays null)."""
    return (
        f"CASE WHEN {ref} IS NULL THEN NULL "
        f'WHEN apoc.meta.cypher.type({ref}) STARTS WITH "LIST" THEN apoc.coll.toSet({ref}) '
        f"ELSE [{ref}] END"
    )


_ACTOR_ALIAS_MERGE_NORMALISE_CYPHER = (
    "UNWIND $canonicals AS cname\n"
    "MATCH (c:ThreatActor {name: cname})\n"
    "SET " + ",\n    ".join(f"c.{p} = {_list_or_wrapped('c.' + p)}" for p in _ACTOR_ALIAS_MERGE_LIST_PROPS) + "\n"
    "WITH c\n"
    "MATCH (c)-[r]-()\n"
    "SET " + ",\n    ".join(f"r.{p} = {_list_or_wrapped('r.' + p)}" for p in _ACTOR_ALIAS_MERGE_EDGE_LIST_PROPS) + "\n"
    "RETURN count(r) AS normalised_edges"
)

# Edges moved over from a duplicate still carry the DUPLICATE's uuid in
# ``r.src_uuid`` / ``r.trg_uuid`` (cross-environment traceability contract,
# see node_identity.py). Re-stamp them with the canonical's uuid.
_ACTOR_ALIAS_MERGE_RESTAMP_OUT_CYPHER = """
UNWIND $canonicals AS cname
MATCH (c:ThreatActor {name: cname})-[r]->()
WHERE r.src_uuid IS NOT NULL AND r.src_uuid <> c.uuid
SET r.src_uuid = c.uuid
RETURN count(r) AS restamped
"""
_ACTOR_ALIAS_MERGE_RESTAMP_IN_CYPHER = """
UNWIND $canonicals AS cname
MATCH (c:ThreatActor {name: cname})<-[r]-()
WHERE r.trg_uuid IS NOT NULL AND r.trg_uuid <> c.uuid
SET r.trg_uuid = c.uuid
RETURN count(r) AS restamped
"""


def _actor_alias_merge_enabled() -> bool:
    """``EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE`` (default ``"true"``). Read at
    call time — not import time — so an operator can flip it between DAG
    runs without a restart (same truthy set as ``config._env_bool``)."""
    raw = os.getenv(_ACTOR_ALIAS_MERGE_ENV_FLAG, "true")
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _is_apoc_missing_error(exc: BaseException) -> bool:
    """True when ``exc`` is Neo4j telling us an ``apoc.*`` procedure /
    function does not exist (APOC plugin not installed)."""
    code = str(getattr(exc, "code", "") or "")
    msg = str(exc)
    lowered = msg.lower()
    if code == "Neo.ClientError.Procedure.ProcedureNotFound":
        return True
    if "procedurenotfound" in lowered:
        return True
    if "apoc." in lowered and ("there is no procedure with the name" in lowered or "unknown function" in lowered):
        return True
    return False


def merge_alias_duplicate_actors(neo4j_client) -> Dict:
    """Fold alias-duplicate ThreatActor nodes into their canonical MITRE node.

    Candidate pair = (canonical ``c``, duplicate ``d``) where
      * ``"mitre_attck" IN c.source`` and NOT ``"mitre_attck" IN d.source``
        (a MITRE-sourced node is never a duplicate — two canonical actors
        are never merged);
      * ``toLower(trim(d.name)) = toLower(trim(x))`` for some ``x IN c.aliases``;
      * neither name is a placeholder (``_REJECTED_PLACEHOLDER_NAMES``).

    Ambiguity guard: a duplicate whose name is an alias of MORE THAN ONE
    canonical actor is skipped and counted (``skipped_ambiguous``).

    Merge = ``SET c.aliases += d.name`` then
    ``apoc.refactor.mergeNodes([c, d], {properties: <explicit map>,
    mergeRels: true, produceSelfRel: false})`` — see
    ``_ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY`` for the per-property rules
    (scalars ``"discard"`` = canonical wins, lists ``"combine"``). The
    canonical keeps its ``name`` / ``uuid``; the duplicate node disappears,
    so the UNIQUE constraint on ``ThreatActor.name`` holds throughout. All
    of the duplicate's relationships move to the canonical; their
    ``src_uuid`` / ``trg_uuid`` are re-stamped with the canonical's uuid.

    Campaigns: a stale ``"<duplicate> Campaign"`` node (if any) is NOT
    touched here. ``build_campaign_nodes`` runs right after this job: its
    Step 3b prunes the stale PART_OF_CAMPAIGN edges and Step 4 marks the campaign
    ``active = false`` (the repo's retire-don't-delete rule), while the
    canonical's own campaign is (re)built with the merged aliases.

    Batching: ``_ACTOR_ALIAS_MERGE_BATCH_SIZE`` pairs per transaction,
    ``_ACTOR_ALIAS_MERGE_MAX_PAIRS_PER_RUN`` cap per run (idempotent —
    leftovers merge on the next run).

    Dry run: ``EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE=false`` logs the candidate
    count and merges nothing.

    APOC missing: logs a WARNING and returns (``apoc_missing = 1``) instead
    of failing the enrichment run. Any other per-batch failure is logged,
    counted in ``errors`` and the next batch proceeds (same best-effort
    shape as the per-tier handler in ``calibrate_cooccurrence_confidence``);
    whole-session failures re-raise per PR-N21.

    Returns ``{candidates, merged, skipped_ambiguous, errors,
    restamped_edges, apoc_missing}``.
    """
    if not neo4j_client.driver:
        logger.error("merge_alias_duplicate_actors: no Neo4j connection")
        return {}

    results: Dict = {
        "candidates": 0,
        "merged": 0,
        "skipped_ambiguous": 0,
        "errors": 0,
        "restamped_edges": 0,
        "apoc_missing": 0,
    }
    placeholders = sorted(_REJECTED_PLACEHOLDER_NAMES)

    try:
        with neo4j_client.driver.session() as session:
            rows = session.run(
                _ACTOR_ALIAS_MERGE_CANDIDATES_CYPHER,
                placeholders=placeholders,
                mitre_source=_ACTOR_ALIAS_MERGE_MITRE_SOURCE,
                timeout=NEO4J_READ_TIMEOUT,
            )
            pairs: List[Tuple[str, str]] = []  # (canonical_name, duplicate_name)
            for row in rows:
                dup_name = row["duplicate_name"]
                canonical_names = [n for n in (row["canonical_names"] or []) if n]
                if not dup_name or not canonical_names:
                    continue
                if len(canonical_names) > 1:
                    results["skipped_ambiguous"] += 1
                    logger.warning(
                        "[ACTOR-ALIAS-MERGE] skipping %r — alias of %d canonical actors %s (ambiguous)",
                        dup_name,
                        len(canonical_names),
                        sorted(canonical_names),
                    )
                    continue
                pairs.append((canonical_names[0], dup_name))
            results["candidates"] = len(pairs) + results["skipped_ambiguous"]

            if not pairs:
                logger.info(
                    "[ACTOR-ALIAS-MERGE] no alias-duplicate ThreatActor pairs (ambiguous skipped: %d)",
                    results["skipped_ambiguous"],
                )
                return results

            if not _actor_alias_merge_enabled():
                logger.info(
                    "[ACTOR-ALIAS-MERGE] DRY RUN (%s=false): %d mergeable pair(s), %d ambiguous skipped — "
                    "merging nothing. Sample: %s",
                    _ACTOR_ALIAS_MERGE_ENV_FLAG,
                    len(pairs),
                    results["skipped_ambiguous"],
                    pairs[:10],
                )
                return results

            if len(pairs) > _ACTOR_ALIAS_MERGE_MAX_PAIRS_PER_RUN:
                logger.warning(
                    "[ACTOR-ALIAS-MERGE] %d mergeable pairs exceed the per-run cap %d — "
                    "merging the first %d, the rest on the next run",
                    len(pairs),
                    _ACTOR_ALIAS_MERGE_MAX_PAIRS_PER_RUN,
                    _ACTOR_ALIAS_MERGE_MAX_PAIRS_PER_RUN,
                )
                pairs = pairs[:_ACTOR_ALIAS_MERGE_MAX_PAIRS_PER_RUN]

            batches = [
                pairs[i : i + _ACTOR_ALIAS_MERGE_BATCH_SIZE]
                for i in range(0, len(pairs), _ACTOR_ALIAS_MERGE_BATCH_SIZE)
            ]
            for batch_no, batch in enumerate(batches, start=1):
                grouped: Dict[str, List[str]] = {}
                for canonical, dup in batch:
                    grouped.setdefault(canonical, []).append(dup)
                groups = [{"canonical": c, "duplicates": sorted(set(d))} for c, d in sorted(grouped.items())]
                try:
                    rec = session.run(
                        _ACTOR_ALIAS_MERGE_APPLY_CYPHER,
                        groups=groups,
                        strategy=_ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY,
                        mitre_source=_ACTOR_ALIAS_MERGE_MITRE_SOURCE,
                        timeout=NEO4J_READ_TIMEOUT,
                    ).single()
                    merged = int((rec["merged"] if rec else 0) or 0)
                    results["merged"] += merged
                    canonical_names = [g["canonical"] for g in groups]
                    for restamp_cypher in (
                        _ACTOR_ALIAS_MERGE_RESTAMP_OUT_CYPHER,
                        _ACTOR_ALIAS_MERGE_RESTAMP_IN_CYPHER,
                    ):
                        rs = session.run(
                            restamp_cypher, canonicals=canonical_names, timeout=NEO4J_READ_TIMEOUT
                        ).single()
                        results["restamped_edges"] += int((rs["restamped"] if rs else 0) or 0)
                    # Lists stay lists (see _ACTOR_ALIAS_MERGE_LIST_PROPS).
                    session.run(
                        _ACTOR_ALIAS_MERGE_NORMALISE_CYPHER, canonicals=canonical_names, timeout=NEO4J_READ_TIMEOUT
                    )
                    logger.info(
                        "[ACTOR-ALIAS-MERGE] batch %d/%d: merged %d duplicate(s) into %d canonical actor(s)",
                        batch_no,
                        len(batches),
                        merged,
                        len(groups),
                    )
                except Exception as batch_err:
                    if _is_apoc_missing_error(batch_err):
                        logger.warning(
                            "[ACTOR-ALIAS-MERGE] APOC unavailable (%s) — skipping alias merge; "
                            "install the APOC plugin to enable it. %d pair(s) left untouched.",
                            batch_err,
                            len(pairs),
                        )
                        results["apoc_missing"] = 1
                        return results
                    results["errors"] += 1
                    logger.error(
                        "[ACTOR-ALIAS-MERGE] batch %d/%d FAILED (%d pairs rolled back): %s",
                        batch_no,
                        len(batches),
                        len(batch),
                        batch_err,
                        exc_info=True,
                    )
                if batch_no < len(batches):
                    query_pause()
    except Exception as e:
        # PR-N21: whole-session failures (driver dead, candidate query
        # broken) must fail loudly — only per-batch and APOC-missing
        # conditions are handled above.
        logger.error(f"[ACTOR-ALIAS-MERGE] merge_alias_duplicate_actors FAILED: {e}", exc_info=True)
        raise

    logger.info(
        "[ACTOR-ALIAS-MERGE] complete — candidates=%d merged=%d skipped_ambiguous=%d errors=%d restamped_edges=%d",
        results["candidates"],
        results["merged"],
        results["skipped_ambiguous"],
        results["errors"],
        results["restamped_edges"],
    )
    return results


# ---------------------------------------------------------------------------
# CONVENIENCE RUNNER
# ---------------------------------------------------------------------------


def run_all_enrichment_jobs(neo4j_client) -> Dict:
    """
    Run all five post-sync enrichment jobs in sequence.

    Order matters: ``merge_alias_duplicate_actors`` runs BEFORE
    ``build_campaign_nodes`` so campaigns are built on merged actors.

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

    logger.info("\n[1/5] Vulnerability↔CVE REFERS_TO Bridge...")
    summary["bridge"] = _timed("bridge", bridge_vulnerability_cve, neo4j_client)

    # Must precede build_campaign_nodes: campaigns are keyed on actor name.
    logger.info("\n[2/5] ThreatActor Alias-Duplicate Merge...")
    summary["actor_alias_merge"] = _timed("actor_alias_merge", merge_alias_duplicate_actors, neo4j_client)

    logger.info("\n[3/5] Campaign Node Builder...")
    summary["campaigns"] = _timed("campaigns", build_campaign_nodes, neo4j_client)

    logger.info("\n[4/5] Co-occurrence Confidence Calibration...")
    summary["calibration"] = _timed("calibration", calibrate_cooccurrence_confidence, neo4j_client)

    logger.info("\n[5/5] IOC Confidence Decay...")
    summary["decay"] = _timed("decay", decay_ioc_confidence, neo4j_client)

    # PR #33 round 13: explicit aggregated summary so an operator scanning logs
    # sees totals from all 5 jobs without grepping each function's output.
    def _sum(d):
        if isinstance(d, dict):
            return sum(v for v in d.values() if isinstance(v, (int, float)))
        return d if isinstance(d, (int, float)) else 0

    logger.info(
        "[ENRICHMENT SUMMARY] bridge=%s actor_alias_merge=%s campaigns=%s calibration=%s decay=%s",
        _sum(summary.get("bridge")),
        _sum(summary.get("actor_alias_merge")),
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
