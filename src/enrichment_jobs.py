#!/usr/bin/env python3
"""
EdgeGuard — Post-Sync Enrichment Jobs
======================================
Seven graph-quality jobs that run AFTER every MISP→Neo4j sync.
They are designed to be idempotent — safe to re-run at any time.

Jobs
----
1. decay_ioc_confidence   — The one aging rule for Indicator nodes, every supplier alike (2026-10-16,
                            indicator_aging): confidence by age since the last report, retirement
                            after 730 days without one
2. build_campaign_nodes   — Group ThreatActor / Malware / Indicator into Campaigns
3. calibrate_cooccurrence — Adjust INDICATES/EXPLOITS confidence for large MISP feed dumps
4. bridge_vulnerability_cve — Create REFERS_TO between Vulnerability and CVE nodes
5. merge_alias_duplicate_actors — Fold duplicate ThreatActors into their canonical actor (ATT&CK
   aliases and the canonical threat-actor reference, src/reference/canonical_threat_actors.json)
6. merge_malware_attack_twins — Fold Malware nodes named "<family> - S####" (the ATT&CK software id
   of the MISP galaxy naming) into the MITRE Malware node of that id, or, for software without one,
   into the node of the base name (2026-10)
7. enrich_cve_epss          — FIRST EPSS scores onto CVE nodes (cve_feed_enrichment.py; CISA's SSVC
                               comes with the NVD records, not from a job)
"""

import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, NamedTuple, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import campaign_evidence  # noqa: E402
import config  # noqa: E402
from attack_revoked import load_revoked_ids  # noqa: E402
from attack_software_names import (  # noqa: E402
    CYPHER_BASE_NODES_READ,
    CYPHER_SOFTWARE_ID_SUFFIX,
    CYPHER_SUFFIXED_NAME,
    attack_software_id,
    plan_twin_folds,
    twin_base_names,
)
from canonical_threat_actors import (  # noqa: E402
    CanonicalReference,
    MergePlan,
    ReferenceUnavailable,
    load_canonical_reference,
    plan_alias_merges,
    reference_merge_candidates,
)
from cve_feed_enrichment import enrich_cve_epss  # noqa: E402
from description_ranking import ranking_for_label  # noqa: E402
from indicator_aging import (  # noqa: E402
    AGING_BASES,
    DATABASE_TIME,
    AgingPolicy,
    aging_map,
    basis_expr,
    changed_predicate,
    evaluation_time,
    load_aging_policy,
)
from neo4j_client import (  # noqa: E402
    APOC_ITERATE_YIELD,
    NEO4J_READ_TIMEOUT,
    _dedup_concat_clause,
    _tlp_most_restrictive_clause,
    apoc_iterate_failures,
)
from node_identity import _REJECTED_PLACEHOLDER_NAMES, compute_node_uuid  # noqa: E402
from query_pause import query_pause
from relationship_provenance import aggregated_prov_set, node_feeds, prov_set, prov_with  # noqa: E402

try:
    from metrics_server import record_enrichment_duration

    _METRICS_AVAILABLE = True
except ImportError:
    _METRICS_AVAILABLE = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. IOC CONFIDENCE DECAY
# ---------------------------------------------------------------------------


# 2026-10-16: the time the aging job evaluates the rule at, before the per-node lift: the database's
# current time (``indicator_aging.DATABASE_TIME``; in ``apoc.periodic.iterate`` each batch reads it
# when its transaction starts). ``$as_of`` is null in production; a test may give a time.
AGING_JOB_TIME = f"coalesce(datetime($as_of), {DATABASE_TIME})"


def _aging_job_statements(policy: AgingPolicy) -> Tuple[str, str, str]:
    """The aging job's statements: the nodes whose aging changes (``outer``), the update applied to
    each (``inner``) and their count, at ``AGING_JOB_TIME``. Parameter: ``$as_of`` (ISO-8601, or
    null for the database's current time).

    2026-10-16: ``inner`` takes the node's write lock (``apoc.lock.nodes``) before it reads the node,
    then evaluates the rule again and writes only where a value still changes. A concurrent writer
    (the sync of another run, a baseline) either committed before the lock, and the rule reads what
    it wrote, ``aging_evaluated_at`` included, or waits for this batch: the job never writes values
    it computed from a node another transaction changed in between. ``outer`` reads without a lock
    and only selects the candidates, so unchanged nodes are neither locked nor written: a write that
    commits a newer report on a node ``outer`` did not select is evaluated by that write alone, at
    its statement's start, which can be earlier than this job's time (``indicator_aging``, *The time
    of an evaluation*)."""
    aged = aging_map("n", AGING_JOB_TIME, policy)
    changed = f"WITH n, {aged} AS aged WHERE {changed_predicate('n', 'aged')}"
    select = f"MATCH (n:Indicator) WHERE {basis_expr('n')} IS NOT NULL {changed}"
    outer = f"{select} RETURN n"
    inner = f"CALL apoc.lock.nodes([n]) {changed} SET n += aged"
    count = f"{select} RETURN count(n) AS changed"
    return outer, inner, count


_AGING_ITERATE_CYPHER = (
    "CALL apoc.periodic.iterate($outer, $inner, "
    "{batchSize: 10000, parallel: false, retries: 2, params: {as_of: $as_of}}) "
    f"YIELD {APOC_ITERATE_YIELD} RETURN {APOC_ITERATE_YIELD}"
)

# What the job logs after it ran: Indicators per tier, retired, by basis, and those with no time.
_AGING_STATS_CYPHER = (
    "MATCH (n:Indicator) "
    "RETURN n.aging_tier AS tier, n.aging_basis AS basis, "
    "coalesce(n.retired_by = 'decay', false) AS retired, "
    "(n.last_reported_at IS NULL AND n.first_imported_at IS NULL) AS no_time, count(*) AS c"
)


def decay_ioc_confidence(neo4j_client, as_of=None) -> Dict:
    """Apply the one aging rule to every Indicator at ``as_of`` (2026-10-16, ``indicator_aging``).

    Threat intelligence has a shelf life, and an indicator is a time-bound claim. Each Indicator
    ages from ``coalesce(last_reported_at, first_imported_at)`` (the latest report of any source,
    dated by the source's own last-report date capped at the MISP record time; the time EdgeGuard
    created a node no MISP report dated), whichever supplier reported it and whoever created the
    node. With the defaults (``EDGEGUARD_AGING_TIER_DAYS``, ``EDGEGUARD_AGING_FACTORS``,
    ``EDGEGUARD_AGING_RETIRE_DAYS``):

      below 90 days   → confidence_score = source_confidence
      from 90 days    → × 0.85
      from 180 days   → × 0.70
      from 365 days   → × 0.55 (never below 0.10)
      from 730 days   → retired: active = false, retired_by = 'decay', retired_at = basis + 730 d

    The value is recomputed from ``source_confidence`` (not multiplied step by step), so a missed
    or repeated run gives the same graph, and a run in which no node's aging changes writes nothing.
    Only nodes whose aging changes are written (``apoc.periodic.iterate`` batches). Nothing is
    deleted; a manual decommission (``retired_at`` without the ``'decay'`` tag) is kept; a newer
    report reactivates a node in the sync's write. Every other label (CVE, CVSS, Vulnerability,
    Malware, ThreatActor, Technique, Tactic, Tool, Sector, Source, Alert) never ages. An Indicator
    with neither time (no EdgeGuard evidence) is counted and left untouched.

    The rule runs at the database's current time (``AGING_JOB_TIME``), lifted to a node's
    ``aging_evaluated_at`` when that is later, as in every Indicator write: a cleared or re-run task
    evaluates at the time it runs, and no evaluation moves a node backwards. The job locks a node
    before it evaluates and writes it (``_aging_job_statements``). ``as_of`` is for tests only (a
    datetime or an ISO-8601 string; None, as in production, means the database's current time); a
    time given there is lifted per node in the same way, so it can never move a node backwards.
    """
    if not neo4j_client.driver:
        logger.error("decay_ioc_confidence: no Neo4j connection")
        return {}

    policy = load_aging_policy()
    outer, inner, count = _aging_job_statements(policy)
    params = {"as_of": None if as_of is None else evaluation_time(as_of).isoformat()}
    results: Dict = {"as_of": params["as_of"]}

    try:
        with neo4j_client.driver.session() as session:
            record = session.run(count, timeout=NEO4J_READ_TIMEOUT, **params).single()
            results["changed"] = int(record["changed"]) if record else 0
            record = session.run(
                _AGING_ITERATE_CYPHER, outer=outer, inner=inner, timeout=NEO4J_READ_TIMEOUT, **params
            ).single()
            failures = apoc_iterate_failures(record) if record else []
            if failures:
                raise RuntimeError(f"[AGING] apoc.periodic.iterate batch failures: {failures}")
            tiers: Dict[str, int] = {f"tier_{t}": 0 for t in range(len(policy.tier_days) + 1)}
            by_basis: Dict[str, int] = {basis: 0 for basis in AGING_BASES}
            retired = no_time = 0
            for row in session.run(_AGING_STATS_CYPHER, timeout=NEO4J_READ_TIMEOUT):
                c = int(row["c"] or 0)
                if row["no_time"]:
                    no_time += c
                    continue
                if row["tier"] is not None:
                    tiers[f"tier_{int(row['tier'])}"] = tiers.get(f"tier_{int(row['tier'])}", 0) + c
                if row["basis"] is not None:
                    by_basis[str(row["basis"])] = by_basis.get(str(row["basis"]), 0) + c
                if row["retired"]:
                    retired += c
    except Exception as e:
        # PR-N21 BLOCKER: re-raise instead of silently returning zero
        # results. The pre-N21 ``except Exception: logger.error()`` (no
        # raise) swallowed real Cypher errors (timeouts, schema drift,
        # OOM) and returned ``{}`` — which the runner happily aggregated
        # and Airflow marked SUCCESS. Operators saw a green DAG with no
        # decay actually applied, identical to a "no work needed" run.
        # Fix: re-raise so the DAG task FAILS loudly and the operator
        # sees the actual exception in the Airflow log.
        logger.error(f"[DECAY] decay_ioc_confidence FAILED: {e}", exc_info=True)
        raise

    results.update({"tiers": tiers, "retired": retired, "by_basis": by_basis, "no_time": no_time})
    starts = (0,) + tuple(policy.tier_days)
    tier_text = ", ".join(
        f"tier {t} (from {starts[t]} d, x{policy.factor(t):.2f}): {tiers.get(f'tier_{t}', 0)}"
        for t in range(len(starts))
    )
    logger.info(
        "[AGING] at %s: %d Indicator(s) changed; %s; retired (from %d d): %d",
        params["as_of"] or "the database's current time",
        results["changed"],
        tier_text,
        policy.retire_days,
        retired,
    )
    logger.info("[AGING] by basis: %s", ", ".join(f"{basis}={count_}" for basis, count_ in sorted(by_basis.items())))
    if no_time:
        logger.warning(
            "[AGING] %d Indicator(s) have neither last_reported_at nor first_imported_at (no EdgeGuard "
            "time; expected 0): left untouched",
            no_time,
        )
    else:
        logger.info("[AGING] Indicators with no time at all: 0")
    return results


# ---------------------------------------------------------------------------
# 2. CAMPAIGN NODE BUILDER
# ---------------------------------------------------------------------------


# 2026-10 (explainability): a campaign is EdgeGuard's grouping of one actor's malware and those
# malware's active indicators, not a source's claim. Its links say so (``match_type``) and carry the
# confidence of the evidence they rest on: a malware link its strongest link to the actor (since
# 2026-10-16 ATTRIBUTED_TO or USES_MALWARE, ``campaign_evidence``); an indicator link its best path,
# each path as strong as its weaker link (INDICATES, then ATTRIBUTED_TO or USES_MALWARE); RUNS the
# actor's strongest link. ``r.evidence_types`` names the relationship types the link rests on.
# Recomputed on every run, like the links themselves.
CAMPAIGN_MATCH_TYPE = "campaign_grouping"


def _weaker(x: str, y: str) -> str:
    """Cypher: the smaller of two confidences, ignoring a missing one."""
    return f"CASE WHEN {x} IS NULL THEN {y} WHEN {y} IS NULL THEN {x} WHEN {x} < {y} THEN {x} ELSE {y} END"


def _strongest(values: str) -> str:
    """Cypher: the largest non-null value of a list (null when there is none)."""
    return (
        f"reduce(_best = null, _v IN {values} | "
        "CASE WHEN _v IS NOT NULL AND (_best IS NULL OR _v > _best) THEN _v ELSE _best END)"
    )


def _campaign_evidence(rel_var: str, confidence: str, types: str, quote: str = '"') -> str:
    """``SET`` items naming a campaign link's evidence: its kind, its confidence and (2026-10-16) the
    relationship types it rests on; ``quote`` is ``'`` inside a double-quoted ``apoc.periodic.iterate``
    statement."""
    return (
        f"{rel_var}.match_type = {quote}{CAMPAIGN_MATCH_TYPE}{quote}, {rel_var}.confidence_score = {confidence}, "
        f"{rel_var}.evidence_types = {types}"
    )


def _links_evidence(rel_var: str, links: str, quote: str = '"') -> str:
    """``SET`` items for a campaign link resting on the list of links ``links`` (RUNS, a malware
    member): the strongest link's confidence, their types, and their provenance, replaced on each
    run so the link names no evidence removed or trimmed since."""
    return (
        _campaign_evidence(
            rel_var,
            _strongest(f"[_e IN {links} | _e.confidence_score]"),
            campaign_evidence.evidence_types(links),
            quote,
        )
        + ", "
        + aggregated_prov_set(rel_var, f"_e IN {links}", "_e", replace=True)
    )


def build_campaign_nodes(neo4j_client) -> Dict:
    """
    Materialise Campaign nodes from the existing threat graph.

    A Campaign represents a coordinated set of threat activity by one actor.
    We infer campaigns from graph structure (``campaign_evidence``):
      ThreatActor <-[:ATTRIBUTED_TO]- Malware <-[:INDICATES]- Indicator
      ThreatActor -[:USES_MALWARE]->  Malware <-[:INDICATES]- Indicator   (2026-10-16)

    For each ThreatActor that has at least one malware attributed to it or used
    by it, and an active indicator of such a malware, we create a Campaign node and link:
      ThreatActor -[:RUNS]-> Campaign
      Malware     -[:PART_OF_CAMPAIGN]-> Campaign
      Indicator   -[:PART_OF_CAMPAIGN]-> Campaign  (sampled — up to 100 per campaign)

    The links follow the evidence (2026-10): a campaign whose actor has neither link left is
    deleted with its links (Step 1b, 2026-10-16), a malware link without either link is pruned
    (Step 2b), a RUNS whose actor is not the campaign's or has no evidence is removed (Step 2c), and
    every link's provenance is replaced on each run by that of the links it currently rests on;
    ``r.evidence_types`` names their relationship types. A campaign with evidence whose indicators
    all expired stays, inactive (Step 4). A re-created campaign keeps its ``uuid``: it is computed
    from the actor's name (``compute_node_uuid``), never stored elsewhere.

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
    # Passed to Step 3b's prune query (and the link count) as ``$run_start_at`` to distinguish
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
            # 2026-10: Step 3b's prune and the link count compare ``r.updated_at``, which the server's
            # ``datetime()`` stamps, with ``run_start_at``: read it from the same clock, so a worker
            # clock ahead of the database's can never make this run's edges look stale. (Step 2b
            # judges the evidence itself since 2026-10-16, not the time.)
            now_record = session.run("RETURN toString(datetime()) AS now", timeout=NEO4J_READ_TIMEOUT).single()
            try:
                server_now = now_record["now"] if now_record is not None else None
            except (KeyError, TypeError):
                server_now = None
            if isinstance(server_now, str) and server_now:
                run_start_at = server_now
            # Pre-fetch the names of every qualifying ThreatActor so we can
            # compute deterministic Campaign uuids in Python (Campaign name is
            # ``"<actor> Campaign"``). Without this, the MERGE below would
            # create Campaign nodes with NULL uuid — silently breaking the
            # cross-environment traceability contract this PR exists for.
            # Caught in the post-PR-#33 fresh-eyes audit.
            # 2026-10-16: an actor qualifies with either evidence link (ATTRIBUTED_TO or USES_MALWARE).
            qualifying_actors_query = f"""
            MATCH (a:ThreatActor)
            WHERE {campaign_evidence.has_evidence("a")}
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
            #
            # 2026-10-16: the members are the malware with either evidence link to the actor
            # (``campaign_evidence``); an indicator counts through INDICATES to any member, once.
            create_cypher = f"""
            MATCH (a:ThreatActor)
            WHERE {campaign_evidence.has_evidence("a")}
              AND a.name IN keys($campaign_uuids)
            WITH a, {campaign_evidence.member_malware("a")} AS malware_list
            UNWIND malware_list AS _member
            OPTIONAL MATCH (_member)<-[:INDICATES]-(i:Indicator)
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
            WITH a, c, {campaign_evidence.evidence_links("a")} AS actor_evidence
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
                // 2026-10 (explainability, relationship provenance): the campaign is built from
                // the actor's links to malware (ATTRIBUTED_TO and, since 2026-10-16, USES_MALWARE),
                // so RUNS carries the strongest link's confidence, their relationship types, and
                // their feeds, record ids and MISP events: those of the current links (replaced,
                // not added to, so RUNS names no pulse build_relationships step 2d removed or trimmed).
                {_links_evidence("r_runs", "actor_evidence")}
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

            # Step 1b (2026-10-16): a campaign without evidence is deleted, not kept. When no
            # ThreatActor of the campaign's actor name has an ATTRIBUTED_TO or USES_MALWARE link left
            # (build_relationships step 2d removed its same-pulse attributions, or the actor alias
            # merge folded the actor into another, so no actor of that name remains), the Campaign
            # node goes with every link it has (RUNS, PART_OF_CAMPAIGN) in this run. Only campaigns
            # EdgeGuard created: a partner's node keeps existing, and Steps 2b, 2c and 3b remove
            # EdgeGuard's links to it. A campaign with evidence whose indicators all expired stays
            # (Step 4 marks it inactive). Re-created later, it gets the same uuid (computed from the
            # actor's name).
            delete_without_evidence = f"""
            MATCH (c:Campaign)
            WHERE c.edgeguard_managed = true
              AND NOT EXISTS {{
                MATCH (a:ThreatActor {{name: c.actor_name}})
                WHERE {campaign_evidence.has_evidence("a")}
              }}
            WITH c, c.name AS name,
                 COUNT {{ (c)<-[:RUNS]-() }} AS runs,
                 COUNT {{ (c)<-[:PART_OF_CAMPAIGN]-() }} AS members
            ORDER BY name
            DETACH DELETE c
            RETURN count(*) AS deleted, sum(runs) AS runs_removed, sum(members) AS members_removed,
                   collect(name)[0..20] AS names
            """
            deleted_record = session.run(delete_without_evidence, timeout=NEO4J_READ_TIMEOUT).single()
            campaigns_deleted = int((deleted_record["deleted"] if deleted_record else 0) or 0)
            if campaigns_deleted:
                logger.info(
                    "[CAMPAIGN] deleted %d campaigns whose actor has no ATTRIBUTED_TO or USES_MALWARE link left "
                    "(with %s RUNS and %s PART_OF_CAMPAIGN links); first names: %s",
                    campaigns_deleted,
                    deleted_record["runs_removed"],
                    deleted_record["members_removed"],
                    list(deleted_record["names"] or []),
                )
            results["campaigns_deleted"] = campaigns_deleted
            query_pause()

            # Step 2: Link malware to their campaigns. Both endpoints have
            # n.uuid by now (Malware via merge_node_with_source, Campaign via
            # step 1 above) so the edge SET reads bound .uuid directly.
            # 2026-10-16: every malware with an evidence link to the campaign's actor (ATTRIBUTED_TO
            # or USES_MALWARE) is a member; the link rests on those links (one or both).
            link_malware = f"""
            MATCH (c:Campaign)
            MATCH (a:ThreatActor {{name: c.actor_name}})
            UNWIND {campaign_evidence.member_malware("a")} AS m
            WITH c, a, m, {campaign_evidence.evidence_links("a", "m")} AS member_evidence
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
                // 2026-10 (explainability, relationship provenance): the strongest of the links it
                // rests on, their relationship types, and their provenance (replaced, not added to:
                // it follows the links' removal and trimming).
                {_links_evidence("r", "member_evidence")}
            RETURN count(*) AS links
            """
            result = session.run(link_malware, timeout=NEO4J_READ_TIMEOUT)
            record = result.single()
            results["links_created"] += record["links"] if record else 0
            query_pause()

            # Step 2b (2026-10): prune the malware membership that no evidence supports any more: the
            # malware has neither an ATTRIBUTED_TO nor (2026-10-16) a USES_MALWARE link to the
            # campaign's actor (build_relationships step 2d removed a same-pulse attribution, or the
            # actor is gone). Judged by the same definition as Step 2 (``campaign_evidence``), not by
            # the time Step 2 last touched the link.
            prune_malware = f"""
            MATCH (m:Malware)-[r:PART_OF_CAMPAIGN]->(c:Campaign)
            WHERE NOT EXISTS {{
              MATCH (a:ThreatActor {{name: c.actor_name}})
              WHERE {campaign_evidence.has_evidence("a", "m")}
            }}
            DELETE r
            RETURN count(r) AS pruned
            """
            prune_record = session.run(prune_malware, timeout=NEO4J_READ_TIMEOUT).single()
            malware_pruned = prune_record["pruned"] if prune_record else 0
            if malware_pruned:
                logger.info(
                    "[CAMPAIGN] pruned %d malware PART_OF_CAMPAIGN edges with no ATTRIBUTED_TO or USES_MALWARE "
                    "link to the campaign's actor",
                    malware_pruned,
                )
            results["malware_links_pruned"] = malware_pruned
            query_pause()

            # Step 2c (2026-10): RUNS follows the evidence too. Step 1 rewrites RUNS only for actors
            # that still qualify (evidence and an active indicator); every RUNS is settled here:
            # removed when its actor is not the campaign's actor or has neither link left (after
            # Step 1b, a campaign EdgeGuard did not create, or the RUNS the alias merge moved onto
            # another actor), otherwise its evidence and provenance are recomputed from the actor's
            # current links. Either way RUNS names no link step 2d removed or trimmed.
            settle_runs = f"""
            MATCH (a:ThreatActor)-[r_runs:RUNS]->(c:Campaign)
            WITH a, c, r_runs, {campaign_evidence.evidence_links("a")} AS actor_evidence
            WITH a, c, r_runs, actor_evidence,
                 coalesce(a.name = c.actor_name, false) AND size(actor_evidence) > 0 AS evidenced
            FOREACH (_ IN CASE WHEN evidenced THEN [] ELSE [1] END | DELETE r_runs)
            FOREACH (_ IN CASE WHEN evidenced THEN [1] ELSE [] END |
                SET {_links_evidence("r_runs", "actor_evidence")})
            RETURN sum(CASE WHEN evidenced THEN 0 ELSE 1 END) AS removed
            """
            runs_record = session.run(settle_runs, timeout=NEO4J_READ_TIMEOUT).single()
            runs_removed = runs_record["removed"] if runs_record else 0
            if runs_removed:
                logger.info(
                    "[CAMPAIGN] removed %d RUNS edges whose actor is not the campaign's or has no "
                    "ATTRIBUTED_TO or USES_MALWARE link left",
                    runs_removed,
                )
            results["runs_removed"] = runs_removed
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
            # 2026-10-16: the slice takes 100 distinct indicators (it took 100 paths, so an
            # indicator reached through two member malware, or through a malware that is both
            # attributed to and used by the actor, took two places), reached through INDICATES to
            # any member malware; the indicator type breaks a tie of date and value (the indicator
            # key is type and value), so the order is total.
            #
            # 2026-10-16 (indicator aging): newest first by the latest report of any source, or when
            # EdgeGuard created the node (``coalesce(i.last_reported_at, i.first_imported_at)``), so the
            # sample follows the MISP data, not the time a sync happened to write the node.
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
            link_indicators_batched = (
                """
            CALL apoc.periodic.iterate(
              "MATCH (c:Campaign) RETURN c",
              "MATCH (a:ThreatActor {name: c.actor_name})
               UNWIND __MEMBERS__ AS m
               MATCH (m)<-[:INDICATES]-(i:Indicator)
               WHERE i.active = true
               WITH DISTINCT c, a, i
               ORDER BY coalesce(i.last_reported_at, i.first_imported_at) DESC, i.value ASC, i.indicator_type ASC
               WITH c, a, collect(i)[0..100] AS _top
               UNWIND _top AS i
               WITH c, a, i, __PATHS__ AS _paths
               MERGE (i)-[r:PART_OF_CAMPAIGN]->(c)
               ON CREATE SET r.created_at = datetime(),
                             r.src_uuid = i.uuid,
                             r.trg_uuid = c.uuid
               SET r.src_uuid = coalesce(r.src_uuid, i.uuid),
                   r.trg_uuid = coalesce(r.trg_uuid, c.uuid),
                   r.updated_at = datetime(),
                   r.edgeguard_managed = true,
                   __CAMPAIGN_EVIDENCE__,
                   __INHERITED_PROV__",
              {batchSize: 25, parallel: false, retries: 2}
            )
            YIELD batches, total, errorMessages, failedBatches, failedOperations, wasTerminated,
                  batch, operations, updateStatistics
            RETURN batches, total, errorMessages, failedBatches, failedOperations, wasTerminated,
                   batch, operations, updateStatistics
            """.replace(
                    # 2026-10-16: the campaign's members and the indicator's paths to the actor through
                    # them, each ``[INDICATES, ATTRIBUTED_TO or USES_MALWARE]`` (``campaign_evidence``).
                    "__MEMBERS__",
                    campaign_evidence.member_malware("a"),
                )
                .replace(
                    "__PATHS__",
                    campaign_evidence.indicator_paths("i", "a"),
                )
                .replace(
                    # 2026-10 (relationship provenance): that of both links of every path from the
                    # indicator to the campaign's actor, replaced on each run.
                    "__INHERITED_PROV__",
                    aggregated_prov_set("r", "_p IN _paths", ["_p[0]", "_p[1]"], replace=True),
                )
                .replace(
                    # 2026-10 (explainability): the indicator's best path to the campaign's actor, each
                    # path as strong as its weaker link; over every path, so the row order does not
                    # matter. The relationship types of every path (INDICATES and the actor's links).
                    "__CAMPAIGN_EVIDENCE__",
                    _campaign_evidence(
                        "r",
                        _strongest(
                            "[_p IN _paths | " + _weaker("_p[0].confidence_score", "_p[1].confidence_score") + "]"
                        ),
                        campaign_evidence.evidence_types("reduce(_flat = [], _p IN _paths | _flat + _p)"),
                        quote="'",
                    ),
                )
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
                    # ``MATCH ()-[r]->() WHERE id(r) = rid`` to bind a fresh handle. In the
                    # default batch mode apoc.periodic.iterate exposes the outer columns to
                    # the inner statement as *variables* (it prepends
                    # ``UNWIND $_batch AS _batch WITH _batch.rid AS rid``), not as
                    # parameters: ``$rid`` fails with "Expected parameter(s): rid", which
                    # every run before 2026-10-12 swallowed (the tier was logged FAILED and
                    # the job ended "complete"). Only ``params`` entries are ``$``-parameters.
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
                        "  'MATCH ()-[r]->() WHERE id(r) = rid "
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
# 2026-10: the canonical threat-actor reference (``src/reference/
# canonical_threat_actors.json``, see ``src/canonical_threat_actors.py``) adds a
# second rule: a non-MITRE node whose name resolves there to another canonical
# actor that is a node on the graph folds into that node (``lazarus`` into
# ``lazarus group``, ``cl0p`` into ``clop``). A MITRE-sourced node is never a
# duplicate; a duplicate the two rules give different canonicals, and a node
# that would be both a canonical and a duplicate in one run, are skipped. When
# the file is missing, unreadable or inconsistent the job logs one warning and
# runs on ATT&CK aliases alone.
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
    # node scalars (merge_node_with_source / merge_actor / decay job). The merge statement sets
    # ``description`` and ``description_source`` afterwards to the pair the source ranking keeps
    # (2026-10-16, ``_alias_merge_apply_cypher``), so "discard" never splits them.
    "description": "discard",
    "description_source": "discard",
    "confidence_score": "discard",
    "tag": "discard",
    "active": "discard",
    "first_imported_at": "discard",
    "last_updated": "discard",
    "last_imported_from": "discard",
    "edgeguard_managed": "discard",
    "retired_at": "discard",
    "retired_by": "discard",
    "sophistication": "discard",
    "primary_motivation": "discard",
    "resource_level": "discard",
    # ``discard`` keeps the canonical's value, which the merge statement first sets to the most
    # restrictive level of the group (2026-10): TLP is never loosened by a merge.
    "tlp": "discard",
    # node lists (accumulators)
    "aliases": "combine",
    "source": "combine",
    "zone": "combine",
    "tags": "combine",
    "uses_techniques": "combine",
    "reported_techniques": "combine",
    # 2026-10: the software lists (ATT&CK ``uses`` and pulse families) were "discard" by the
    # wildcard, so a folded duplicate's claims were lost from the canonical node
    "uses_malware": "combine",
    "uses_tools": "combine",
    "misp_event_ids": "combine",
    "misp_attribute_ids": "combine",
    "pulse_ids": "combine",
    # 2026-10 (explainability): the names of the nodes folded into this one, kept across merges
    "merged_from": "combine",
    # edge lists (only relevant when mergeRels collapses parallel edges);
    # ``misp_event_ids`` above covers edges too
    "sources": "combine",
    "source_refs": "combine",
    # 2026-10 (explainability): the revoked ATT&CK ids a technique link was cited by
    "cited_ids": "combine",
    # 2026-10-16 (sector evidence): on a SOURCED_FROM edge, the zones the source's records gave the
    # node, those it stated itself and which record stated which; two edges of a folded node to one
    # Source keep the union, so a sector link still names that source and cites its records
    # (``relationship_provenance.zone_prov_with``)
    "zones": "combine",
    "stated_zones": "combine",
    "stated_refs": "combine",
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

# One read of every ThreatActor node's name and sources: the reference rule's
# candidates are computed from it in Python (``reference_merge_candidates``).
_ACTOR_ALIAS_MERGE_ACTORS_CYPHER = """
MATCH (a:ThreatActor)
WHERE a.name IS NOT NULL
RETURN a.name AS name, a.source AS source
"""

# APOC's ``combine`` keeps a list only when the merged values differ: when the canonical
# and a duplicate hold the same value (``zone = ["global"]`` on both, or
# ``r.sources = ["alienvault_otx"]`` on two parallel edges) it stores that one value as a
# plain string. Found on the 730-day graph (2026-10-14): the 11 MITRE actors that had
# absorbed an OTX duplicate held ``zone`` as a string, and 21 of their ATTRIBUTED_TO edges
# held ``r.sources`` as a string. Every ``combine`` property is a list by contract, so the
# canonical node is wrapped back into lists in the merge statement itself, and the node and
# all of its edges again after each merge batch.
# On edges only the provenance lists are lists: ``source`` on a SOURCED_FROM edge is the
# scalar source id (``combine`` of two parallel edges to the same Source keeps it scalar) and
# must stay one; the node keys (``zone``, ``aliases`` …) do not exist on edges. APOC's
# ``singleElementAsArray`` option is not used for that reason: it applies to edges too.
_ACTOR_ALIAS_MERGE_EDGE_LIST_PROPS: Tuple[str, ...] = (
    "cited_ids",
    "misp_event_ids",
    "source_refs",
    "sources",
    "stated_refs",
    "stated_zones",
    "zones",
)
# The ``combine`` lists that exist on edges only; every other ``combine`` key is a node list.
_ALIAS_MERGE_EDGE_ONLY_PROPS: Tuple[str, ...] = (
    "sources",
    "source_refs",
    "cited_ids",
    "zones",
    "stated_zones",
    "stated_refs",
)
_ACTOR_ALIAS_MERGE_LIST_PROPS: Tuple[str, ...] = tuple(
    sorted(
        k
        for k, v in _ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY.items()
        if v == "combine" and k not in _ALIAS_MERGE_EDGE_ONLY_PROPS
    )
)


def _list_or_wrapped(ref: str) -> str:
    """Cypher: ``ref`` as a de-duplicated list (``[x]`` for a scalar, null stays null).

    ``apoc.coll.toSet`` alone raises on a string (``Can't coerce String to List``)."""
    return (
        f"CASE WHEN {ref} IS NULL THEN NULL "
        f'WHEN apoc.meta.cypher.type({ref}) STARTS WITH "LIST" THEN apoc.coll.toSet({ref}) '
        f"ELSE [{ref}] END"
    )


def _strongest_on_parallel_edges(direction: str) -> str:
    """Cypher ``CALL`` block: before ``mergeNodes`` collapses parallel edges (same type, same other
    node, same direction) of the canonical and its duplicates, every edge of a group takes the
    strongest evidence of the group: the highest ``confidence_score`` and its ``match_type`` (on a
    tie the alphabetically first label). ``mergeNodes`` keeps one edge's scalars ("discard"), so
    without this a weaker canonical edge would replace a stronger duplicate edge, against the rule
    every writer follows (the stronger evidence keeps the label and the confidence). Every edge of a
    group also takes the most restrictive ``r.tlp`` of the group (2026-10; curated-package links carry
    one), so a collapsed edge is never marked less restrictively than one of the edges it replaces."""
    pattern = "(n)-[r]->(x)" if direction == "out" else "(n)<-[r]-(x)"
    return (
        "CALL (c, dups) {\n"
        "    UNWIND [c] + dups AS n\n"
        f"    MATCH {pattern}\n"
        "    WHERE NOT x IN [c] + dups\n"
        "    WITH x, type(r) AS rel_type, collect(r) AS group\n"
        "    WHERE size(group) > 1\n"
        "    UNWIND group AS e\n"
        "    WITH group, e\n"
        "    ORDER BY coalesce(e.confidence_score, -1.0) DESC,\n"
        "             CASE WHEN e.match_type IS NULL THEN 1 ELSE 0 END, e.match_type\n"
        "    WITH group, head(collect(e)) AS best\n"
        f"    WITH group, best, reduce(_t = null, _e IN group | {_tlp_most_restrictive_clause('_t', '_e.tlp')}) AS tlp\n"
        "    FOREACH (e IN group | SET e.confidence_score = best.confidence_score, e.match_type = best.match_type,\n"
        "        e.tlp = tlp)\n"
        f"    RETURN count(*) AS parallel_groups_{direction}\n"
        "}\n"
    )


# One ``mergeNodes`` call per canonical with ALL of its duplicates in the
# batch, so rows of the UNWIND never touch each other's nodes (a duplicate
# maps to exactly one canonical thanks to the ambiguity guard). The
# canonical must be MITRE-sourced or a canonical the reference named in this
# run (``$reference_canonicals``), and a duplicate is never MITRE-sourced:
# re-checked here so a stale candidate list can never merge two canonical
# actors. ``c.aliases`` gains the duplicate names BEFORE the merge, as
# required, and so does ``c.merged_from`` (explainability, 2026-10: unlike
# ``aliases``, which also hold every source's aliases, it names only the
# nodes this job folded in), and ``c.tlp`` becomes the most restrictive level of the group (2026-10:
# ``"discard"`` alone kept the canonical's, so an amber duplicate folded into a white canonical
# would have been exported as white). After the merge every list property of the node is wrapped back
# into a de-duplicated list (``_list_or_wrapped``): two nodes with the same
# single source (``["alienvault_otx"]`` on both, as for two OTX names of one
# actor) come out of ``"combine"`` with ``source`` as a string, and
# ``apoc.coll.toSet`` on that string would roll back the whole batch.
# Parallel edges that collapse keep the union of their provenance lists
# (``"combine"``) and, set on every edge of the group before the merge, the
# strongest evidence's label and confidence (``_strongest_on_parallel_edges``).
# 2026-10-16: the merged node keeps the description, with its ``description_source``, that the source
# ranking keeps among the group (``description_ranking.DescriptionRanking.best_of_cypher``): ``"discard"``
# kept the canonical's description and could take ``description_source`` from a duplicate where the
# canonical had none, so the node could name a source that did not write its text.
# 2026-10: the statements are built per label (``_alias_merge_statements``) so the Malware
# twin merge (JOB 6) runs the same merge; the actor statements are unchanged.
def _alias_merge_apply_cypher(
    label: str, canonical_guard: str, list_props: Tuple[str, ...], duplicate_guard: str = ""
) -> str:
    """The merge statement for ``label``: every group's duplicates into its canonical (see above).

    ``canonical_guard`` is the ``WHERE`` that re-checks the canonical ``c`` at merge time; a duplicate
    is never MITRE-sourced, and also meets ``duplicate_guard`` when one is given (a condition on ``d``
    and ``c``; the actor merge has none). ``list_props`` are wrapped back into lists after the merge."""
    duplicate_condition = f"\n  AND {duplicate_guard}" if duplicate_guard else ""
    ranking = ranking_for_label(label)
    kept_description = (
        f",\n     {ranking.best_of_cypher('c', 'dups')} AS described\n"
        "WITH c, n_dups, dups, described.description AS kept_description,\n"
        "     described.description_source AS kept_description_source"
        if ranking is not None
        else ""
    )
    set_description = (
        "node.description = kept_description,\n    node.description_source = kept_description_source,\n    "
        if ranking is not None
        else ""
    )
    return (
        f"""
UNWIND $groups AS g
MATCH (c:{label} {{name: g.canonical}})
WHERE {canonical_guard}
MATCH (d:{label})
WHERE d.name IN g.duplicates
  AND d <> c
  AND NOT $mitre_source IN coalesce(d.source, []){duplicate_condition}
WITH c, collect(DISTINCT d) AS dups
WHERE size(dups) > 0
SET c.aliases = apoc.coll.toSet(coalesce(c.aliases, []) + [d IN dups | d.name]),
    c.merged_from = apoc.coll.toSet(coalesce(c.merged_from, []) + [d IN dups | d.name]),
    c.tlp = reduce(_t = c.tlp, _d IN dups | """
        + _tlp_most_restrictive_clause("_t", "_d.tlp")
        + """)
WITH c, size(dups) AS n_dups, dups"""
        + kept_description
        + "\n"
        + _strongest_on_parallel_edges("out")
        + _strongest_on_parallel_edges("in")
        + """CALL apoc.refactor.mergeNodes([c] + dups, {
    properties: $strategy,
    mergeRels: true,
    produceSelfRel: false
})
YIELD node
SET """
        + set_description
        + ",\n    ".join(f"node.{p} = {_list_or_wrapped('node.' + p)}" for p in list_props)
        + """,
    node.last_updated = datetime()
RETURN sum(n_dups) AS merged, count(node) AS canonicals
"""
    )


# The zone lists of a SOURCED_FROM edge (2026-10-16, ``Neo4jClient._sourced_zone_items``).
_SOURCED_FROM_ZONE_LISTS = frozenset({"zones", "stated_zones", "stated_refs"})


def _edge_list_normalised(prop: str) -> str:
    """Cypher: the edge list ``r.<prop>`` as a list after a merge. The zone lists of a ``SOURCED_FROM`` edge
    (2026-10-16) also get the writer's form back: sorted sets, and ``zones`` without ``global`` once a
    sector is present (``Neo4jClient._sourced_zone_items``), so a folded edge reads as one the sync wrote."""
    ref = f"r.{prop}"
    wrapped = _list_or_wrapped(ref)
    if prop not in _SOURCED_FROM_ZONE_LISTS:
        return wrapped
    if prop == "zones":
        specifics = f'[_z IN {wrapped} WHERE _z <> "global"]'
        return (
            f"CASE WHEN {ref} IS NULL THEN NULL WHEN size({specifics}) > 0 THEN apoc.coll.sort({specifics}) "
            f"ELSE apoc.coll.sort({wrapped}) END"
        )
    return f"CASE WHEN {ref} IS NULL THEN NULL ELSE apoc.coll.sort({wrapped}) END"


def _alias_merge_normalise_cypher(label: str, list_props: Tuple[str, ...]) -> str:
    """Every list property of the canonicals, and the provenance lists of their edges, as lists."""
    return (
        "UNWIND $canonicals AS cname\n"
        f"MATCH (c:{label} {{name: cname}})\n"
        "SET " + ",\n    ".join(f"c.{p} = {_list_or_wrapped('c.' + p)}" for p in list_props) + "\n"
        "WITH c\n"
        "MATCH (c)-[r]-()\n"
        "SET "
        + ",\n    ".join(f"r.{p} = {_edge_list_normalised(p)}" for p in _ACTOR_ALIAS_MERGE_EDGE_LIST_PROPS)
        + "\n"
        "RETURN count(r) AS normalised_edges"
    )


# Edges moved over from a duplicate still carry the DUPLICATE's uuid in
# ``r.src_uuid`` / ``r.trg_uuid`` (cross-environment traceability contract,
# see node_identity.py). Re-stamp them with the canonical's uuid.
def _alias_merge_restamp_cypher(label: str, direction: str) -> str:
    """Re-stamp ``r.src_uuid`` (``direction="out"``) or ``r.trg_uuid`` (``"in"``) of the canonicals' edges."""
    pattern, prop = ("-[r]->()", "src_uuid") if direction == "out" else ("<-[r]-()", "trg_uuid")
    return f"""
UNWIND $canonicals AS cname
MATCH (c:{label} {{name: cname}}){pattern}
WHERE r.{prop} IS NOT NULL AND r.{prop} <> c.uuid
SET r.{prop} = c.uuid
RETURN count(r) AS restamped
"""


class _AliasMergeStatements(NamedTuple):
    """The four statements of one label's merge, in the order a batch runs them."""

    apply: str
    restamp_out: str
    restamp_in: str
    normalise: str


def _alias_merge_statements(
    label: str, canonical_guard: str, list_props: Tuple[str, ...], duplicate_guard: str = ""
) -> _AliasMergeStatements:
    """The merge statements for ``label`` (see ``_alias_merge_apply_cypher`` for the arguments)."""
    return _AliasMergeStatements(
        apply=_alias_merge_apply_cypher(label, canonical_guard, list_props, duplicate_guard),
        restamp_out=_alias_merge_restamp_cypher(label, "out"),
        restamp_in=_alias_merge_restamp_cypher(label, "in"),
        normalise=_alias_merge_normalise_cypher(label, list_props),
    )


_ACTOR_ALIAS_MERGE_STATEMENTS = _alias_merge_statements(
    "ThreatActor",
    "$mitre_source IN coalesce(c.source, []) OR c.name IN $reference_canonicals",
    _ACTOR_ALIAS_MERGE_LIST_PROPS,
)
_ACTOR_ALIAS_MERGE_APPLY_CYPHER = _ACTOR_ALIAS_MERGE_STATEMENTS.apply
_ACTOR_ALIAS_MERGE_NORMALISE_CYPHER = _ACTOR_ALIAS_MERGE_STATEMENTS.normalise
_ACTOR_ALIAS_MERGE_RESTAMP_OUT_CYPHER = _ACTOR_ALIAS_MERGE_STATEMENTS.restamp_out
_ACTOR_ALIAS_MERGE_RESTAMP_IN_CYPHER = _ACTOR_ALIAS_MERGE_STATEMENTS.restamp_in


def _actor_alias_merge_enabled() -> bool:
    """``EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE`` (default ``"true"``). Read at
    call time — not import time — so an operator can flip it between DAG
    runs without a restart (same truthy set as ``config._env_bool``)."""
    return _env_flag_enabled(_ACTOR_ALIAS_MERGE_ENV_FLAG)


def _load_actor_reference() -> Optional[CanonicalReference]:
    """The canonical threat-actor reference, or ``None`` (one warning) when it is unavailable.
    Never raises: a missing or bad file must not fail enrichment."""
    try:
        reference = load_canonical_reference()
    except ReferenceUnavailable as exc:
        reason = str(exc)
    except Exception as exc:  # any failure of the optional reference degrades the same way
        reason = f"{type(exc).__name__}: {exc}"
    else:
        logger.info(
            "[ACTOR-ALIAS-MERGE] canonical reference %s: %d actors (%s)",
            reference.version,
            reference.actor_count,
            reference.path,
        )
        return reference
    logger.warning("[ACTOR-ALIAS-MERGE] canonical reference unavailable (%s); merging by MITRE aliases only", reason)
    return None


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


def _env_flag_enabled(name: str) -> bool:
    """An enrichment job's on/off flag (default ``"true"``), read at call time — not import time — so
    an operator can flip it between DAG runs without a restart (same truthy set as ``config._env_bool``)."""
    raw = os.getenv(name, "true")
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _cap_merge_pairs(pairs: List[Tuple[str, str]], cap: int, log_tag: str) -> List[Tuple[str, str]]:
    """The first ``cap`` pairs (the rest merge on the next run; every merge job is idempotent)."""
    if len(pairs) <= cap:
        return pairs
    logger.warning(
        "[%s] %d mergeable pairs exceed the per-run cap %d — merging the first %d, the rest on the next run",
        log_tag,
        len(pairs),
        cap,
        cap,
    )
    return pairs[:cap]


def _run_alias_merge_batches(
    session,
    pairs: List[Tuple[str, str]],
    *,
    statements: _AliasMergeStatements,
    batch_size: int,
    apply_params: Dict,
    results: Dict,
    log_tag: str,
    canonical_noun: str,
) -> bool:
    """Merge ``(canonical, duplicate)`` pairs in batches of ``batch_size`` with one label's
    ``statements`` (2026-10: shared by the actor alias merge and the Malware twin merge).

    Per batch: the merge statement (one ``mergeNodes`` call per canonical with all of its
    duplicates), then the uuid re-stamps and the list normalisation of the canonicals. Adds to
    ``results["merged"]`` and ``results["restamped_edges"]``. A failed batch is logged, counted in
    ``results["errors"]`` and the next one proceeds. Returns False, with ``results["apoc_missing"] = 1``,
    when APOC is not installed (nothing more can merge in this run).
    """
    batches = [pairs[i : i + batch_size] for i in range(0, len(pairs), batch_size)]
    for batch_no, batch in enumerate(batches, start=1):
        grouped: Dict[str, List[str]] = {}
        for canonical, dup in batch:
            grouped.setdefault(canonical, []).append(dup)
        groups = [{"canonical": c, "duplicates": sorted(set(d))} for c, d in sorted(grouped.items())]
        try:
            rec = session.run(statements.apply, groups=groups, timeout=NEO4J_READ_TIMEOUT, **apply_params).single()
            merged = int((rec["merged"] if rec else 0) or 0)
            results["merged"] += merged
            canonical_names = [g["canonical"] for g in groups]
            for restamp_cypher in (statements.restamp_out, statements.restamp_in):
                rs = session.run(restamp_cypher, canonicals=canonical_names, timeout=NEO4J_READ_TIMEOUT).single()
                results["restamped_edges"] += int((rs["restamped"] if rs else 0) or 0)
            # Lists stay lists (see _ACTOR_ALIAS_MERGE_LIST_PROPS).
            session.run(statements.normalise, canonicals=canonical_names, timeout=NEO4J_READ_TIMEOUT).consume()
            logger.info(
                "[%s] batch %d/%d: merged %d duplicate(s) into %d %s",
                log_tag,
                batch_no,
                len(batches),
                merged,
                len(groups),
                canonical_noun,
            )
        except Exception as batch_err:
            if _is_apoc_missing_error(batch_err):
                logger.warning(
                    "[%s] APOC unavailable (%s) — skipping the merge; install the APOC plugin to enable it. "
                    "%d pair(s) left untouched.",
                    log_tag,
                    batch_err,
                    len(pairs),
                )
                results["apoc_missing"] = 1
                return False
            results["errors"] += 1
            logger.error(
                "[%s] batch %d/%d FAILED (%d pairs rolled back): %s",
                log_tag,
                batch_no,
                len(batches),
                len(batch),
                batch_err,
                exc_info=True,
            )
        if batch_no < len(batches):
            query_pause()
    return True


def merge_alias_duplicate_actors(neo4j_client) -> Dict:
    """Fold duplicate ThreatActor nodes into their canonical node.

    Two rules propose (canonical ``c``, duplicate ``d``) pairs:

    * ATT&CK aliases (Cypher): ``"mitre_attck" IN c.source`` and NOT
      ``"mitre_attck" IN d.source`` (a MITRE-sourced node is never a duplicate
      — two canonical actors are never merged), ``toLower(trim(d.name)) =
      toLower(trim(x))`` for some ``x IN c.aliases``, and neither name is a
      placeholder (``_REJECTED_PLACEHOLDER_NAMES``). A duplicate whose name is
      an alias of MORE THAN ONE canonical actor is skipped and counted
      (``skipped_ambiguous``).
    * The canonical threat-actor reference (``src/canonical_threat_actors.py``,
      computed in Python from one read of the graph's actor names and
      sources): a node that is not MITRE-sourced and whose name resolves,
      unambiguously and not never_merge, to another canonical key that is a
      node on the graph (``reference_candidates``). The reference path can be
      overridden with ``EDGEGUARD_CANONICAL_THREAT_ACTORS``. When the file is
      missing, unreadable or inconsistent, or its data cannot be applied to
      the graph's names, the job logs ONE warning and runs on ATT&CK aliases
      alone.

    A duplicate the two rules give different canonicals is skipped
    (``skipped_conflict``), and so is a node that would be both a canonical
    and a duplicate in this run (``skipped_chain``): no chains, no cycles.
    With the reference loaded it also checks the ATT&CK-alias pairs, since a
    canonical's ``aliases`` include every name merged into it earlier: a
    duplicate the reference marks ambiguous or never_merge is skipped
    (``skipped_blocked``), and one it gives to another actor or keeps as an
    actor of its own is a conflict.

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
    touched here. ``build_campaign_nodes`` runs right after this job: no
    ThreatActor of the duplicate's name remains, so its Step 1b deletes that
    campaign with its links (2026-10-16; it was marked ``active = false`` and
    kept before), while the canonical's own campaign is (re)built with the
    merged aliases.

    Batching: ``_ACTOR_ALIAS_MERGE_BATCH_SIZE`` pairs per transaction,
    ``_ACTOR_ALIAS_MERGE_MAX_PAIRS_PER_RUN`` cap per run (idempotent —
    leftovers merge on the next run).

    Dry run: ``EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE=false`` logs the candidate
    count and the reference pairs, and merges nothing.

    APOC missing: logs a WARNING and returns (``apoc_missing = 1``) instead
    of failing the enrichment run. Any other per-batch failure is logged,
    counted in ``errors`` and the next batch proceeds (same best-effort
    shape as the per-tier handler in ``calibrate_cooccurrence_confidence``);
    whole-session failures re-raise per PR-N21.

    Returns ``{candidates, merged, skipped_ambiguous, errors,
    restamped_edges, apoc_missing, reference_candidates, skipped_conflict,
    skipped_chain, skipped_blocked}``.
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
        "reference_candidates": 0,
        "skipped_conflict": 0,
        "skipped_chain": 0,
        "skipped_blocked": 0,
    }
    placeholders = sorted(_REJECTED_PLACEHOLDER_NAMES)
    reference = _load_actor_reference()

    try:
        with neo4j_client.driver.session() as session:
            attack_rows = [
                {"duplicate_name": row["duplicate_name"], "canonical_names": row["canonical_names"]}
                for row in session.run(
                    _ACTOR_ALIAS_MERGE_CANDIDATES_CYPHER,
                    placeholders=placeholders,
                    mitre_source=_ACTOR_ALIAS_MERGE_MITRE_SOURCE,
                    timeout=NEO4J_READ_TIMEOUT,
                )
            ]
            reference_pairs: List[Tuple[str, str]] = []  # (duplicate_name, canonical_name)
            plan: Optional[MergePlan] = None
            if reference is not None:
                graph_actors = [
                    {"name": row["name"], "source": row["source"]}
                    for row in session.run(_ACTOR_ALIAS_MERGE_ACTORS_CYPHER, timeout=NEO4J_READ_TIMEOUT)
                ]
                try:
                    reference_pairs = reference_merge_candidates(
                        reference, graph_actors, mitre_source=_ACTOR_ALIAS_MERGE_MITRE_SOURCE
                    )
                    plan = plan_alias_merges(attack_rows, reference_pairs, reference=reference)
                except Exception as exc:  # the optional reference never fails enrichment
                    logger.warning(
                        "[ACTOR-ALIAS-MERGE] canonical reference unavailable (%s: %s); merging by MITRE aliases only",
                        type(exc).__name__,
                        exc,
                    )
                    reference_pairs, plan = [], None
            if plan is None:
                plan = plan_alias_merges(attack_rows, [])
            for dup_name, canonical_names in plan.ambiguous:
                logger.warning(
                    "[ACTOR-ALIAS-MERGE] skipping %r — alias of %d canonical actors %s (ambiguous)",
                    dup_name,
                    len(canonical_names),
                    canonical_names,
                )
            for dup_name, canonical_names in plan.conflicts:
                logger.warning(
                    "[ACTOR-ALIAS-MERGE] skipping %r — ATT&CK aliases and the canonical reference name "
                    "different canonical actors %s (conflict)",
                    dup_name,
                    canonical_names,
                )
            for dup_name, canonical in plan.chains:
                logger.warning(
                    "[ACTOR-ALIAS-MERGE] skipping %r -> %r — %r is also a canonical in this run (chain)",
                    dup_name,
                    canonical,
                    dup_name,
                )
            for dup_name, canonical in plan.blocked:
                logger.warning(
                    "[ACTOR-ALIAS-MERGE] skipping %r -> %r — the canonical reference marks %r ambiguous or "
                    "never_merge (blocked)",
                    dup_name,
                    canonical,
                    dup_name,
                )
            pairs = plan.pairs  # (canonical_name, duplicate_name)
            results["candidates"] = plan.candidates
            results["skipped_ambiguous"] = len(plan.ambiguous)
            results["reference_candidates"] = len(reference_pairs)
            results["skipped_conflict"] = len(plan.conflicts)
            results["skipped_chain"] = len(plan.chains)
            results["skipped_blocked"] = len(plan.blocked)
            reference_canonicals = plan.reference_canonicals

            if not pairs:
                logger.info(
                    "[ACTOR-ALIAS-MERGE] no alias-duplicate ThreatActor pairs (ambiguous skipped: %d, "
                    "conflicts: %d, chains: %d, blocked: %d)",
                    results["skipped_ambiguous"],
                    results["skipped_conflict"],
                    results["skipped_chain"],
                    results["skipped_blocked"],
                )
                return results

            if not _actor_alias_merge_enabled():
                logger.info(
                    "[ACTOR-ALIAS-MERGE] DRY RUN (%s=false): %d mergeable pair(s) (%d from ATT&CK aliases, %d "
                    "from the canonical reference), %d ambiguous, %d conflicts, %d chains, %d blocked skipped — "
                    "merging nothing. Sample: %s. Reference pairs (duplicate -> canonical): %s",
                    _ACTOR_ALIAS_MERGE_ENV_FLAG,
                    len(pairs),
                    plan.from_attack,
                    plan.from_reference,
                    results["skipped_ambiguous"],
                    results["skipped_conflict"],
                    results["skipped_chain"],
                    results["skipped_blocked"],
                    pairs[:10],
                    plan.reference_pairs,
                )
                return results

            pairs = _cap_merge_pairs(pairs, _ACTOR_ALIAS_MERGE_MAX_PAIRS_PER_RUN, "ACTOR-ALIAS-MERGE")
            if not _run_alias_merge_batches(
                session,
                pairs,
                statements=_ACTOR_ALIAS_MERGE_STATEMENTS,
                batch_size=_ACTOR_ALIAS_MERGE_BATCH_SIZE,
                apply_params={
                    "strategy": _ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY,
                    "mitre_source": _ACTOR_ALIAS_MERGE_MITRE_SOURCE,
                    "reference_canonicals": reference_canonicals,
                },
                results=results,
                log_tag="ACTOR-ALIAS-MERGE",
                canonical_noun="canonical actor(s)",
            ):
                return results
    except Exception as e:
        # PR-N21: whole-session failures (driver dead, candidate query
        # broken) must fail loudly — only per-batch and APOC-missing
        # conditions are handled above.
        logger.error(f"[ACTOR-ALIAS-MERGE] merge_alias_duplicate_actors FAILED: {e}", exc_info=True)
        raise

    logger.info(
        "[ACTOR-ALIAS-MERGE] complete — candidates=%d (reference %d) merged=%d skipped_ambiguous=%d "
        "skipped_conflict=%d skipped_chain=%d skipped_blocked=%d errors=%d restamped_edges=%d",
        results["candidates"],
        results["reference_candidates"],
        results["merged"],
        results["skipped_ambiguous"],
        results["skipped_conflict"],
        results["skipped_chain"],
        results["skipped_blocked"],
        results["errors"],
        results["restamped_edges"],
    )
    return results


# ---------------------------------------------------------------------------
# JOB 6: Malware ATT&CK-id twin merge (2026-10)
# ---------------------------------------------------------------------------
# OTX pulses name malware families as the MISP ATT&CK galaxy does, with the ATT&CK software id as
# a suffix ("Cobalt Strike - S0154"). Until 2026-10 the collector passed such a name through and it
# became a Malware node of its own ("cobalt strike - s0154") beside the node ATT&CK delivered
# ("cobalt strike"): on the graph of 2026-10-14, 136 twins held 16,005 INDICATES links, and the
# ATT&CK Cobalt Strike node showed 55 indicators instead of about 2,078. The collectors and the sync
# now name the node by the base name (``attack_software_names.split_attack_software_id``); this job
# folds the twins a graph built before that already holds, so no new baseline is needed.
#
# A non-MITRE node whose name, or an alias of its own name, ends with " - S####" folds into the
# MITRE-sourced Malware node of that ATT&CK id. The MITRE node carries no ``mitre_id``: its id is
# read from the record MITRE delivered (the ``raw_data`` of its SOURCED_FROM edge to the ATT&CK
# source, as ``scripts/build_canonical_threat_actors.py`` reads group ids), and when it cannot be
# read the node of the same base name is the target. A revoked software id is translated to its
# successor first (``attack_revoked``). A twin whose id and name lead to two MITRE nodes is skipped
# (``skipped_ambiguous``). ATT&CK software without a MITRE Malware node (chiefly the ATT&CK tools,
# such as Mimikatz S0002, which are ``Tool`` nodes) has no merge target; since the collectors name a
# family by its base name, a later pulse creates the non-MITRE node "mimikatz" beside the twin
# "mimikatz - s0002", and steps 9b / 2d would link every indicator written before to both. Such a
# twin therefore folds into the non-MITRE node of its base name when that node states no other id
# (``base_name_targets``); without one it is left as it is and counted (``no_target``) until a later
# pulse creates it. The merge itself is the actor alias merge's (``_run_alias_merge_batches``), with
# ``malware_types`` combined too; it runs before ``build_campaign_nodes``.

_MALWARE_TWIN_MERGE_ENV_FLAG = "EDGEGUARD_ENABLE_MALWARE_TWIN_MERGE"
_MALWARE_TWIN_MERGE_BATCH_SIZE = 200  # (target node, twin) pairs per transaction
_MALWARE_TWIN_MERGE_MAX_PAIRS_PER_RUN = 2000  # hard cap; the rest waits for the next run
# The actor merge's strategy plus the one list only Malware nodes carry. ``".*"`` stays the
# catch-all ("discard").
_MALWARE_TWIN_MERGE_PROPERTY_STRATEGY: Dict[str, str] = {
    **{k: v for k, v in _ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY.items() if k != ".*"},
    "malware_types": "combine",
    ".*": "discard",
}
_MALWARE_TWIN_MERGE_LIST_PROPS: Tuple[str, ...] = tuple(
    sorted(
        k
        for k, v in _MALWARE_TWIN_MERGE_PROPERTY_STRATEGY.items()
        if v == "combine" and k not in _ALIAS_MERGE_EDGE_ONLY_PROPS
    )
)

# Non-MITRE Malware nodes whose name or an alias carries an ATT&CK software id (``$suffixed``,
# ``attack_software_names.CYPHER_SUFFIXED_NAME``). A superset: ``plan_twin_folds`` decides.
_MALWARE_TWIN_CANDIDATES_CYPHER = (
    "MATCH (d:Malware)\n"
    "WHERE d.name IS NOT NULL\n"
    "  AND NOT $mitre_source IN coalesce(d.source, [])\n"
    "WITH d, coalesce(" + _list_or_wrapped("d.aliases") + ", []) AS aliases\n"
    "WHERE d.name =~ $suffixed OR any(x IN aliases WHERE toString(x) =~ $suffixed)\n"
    "RETURN d.name AS name, aliases\n"
    "ORDER BY name"
)

# The MITRE-sourced Malware nodes and the record MITRE delivered for each (its ATT&CK id is read
# from it in Python, ``attack_software_names.attack_software_id``).
_MALWARE_TWIN_ATTACK_NODES_CYPHER = """
MATCH (c:Malware)
WHERE $mitre_source IN coalesce(c.source, [])
OPTIONAL MATCH (c)-[sf:SOURCED_FROM]->(:Source {source_id: $mitre_source})
WITH c, head(collect(sf.raw_data)) AS attack_raw
RETURN c.name AS name, attack_raw
"""

# Re-checked at merge time, like the actor merge's guard: the canonical is MITRE-sourced, or a
# non-MITRE node the plan chose as the base-named target of a twin without a MITRE one
# (``$base_canonicals``); into such a node only a twin named "<its name> - s####" folds.
_MALWARE_TWIN_MERGE_STATEMENTS = _alias_merge_statements(
    "Malware",
    "$mitre_source IN coalesce(c.source, []) OR c.name IN $base_canonicals",
    _MALWARE_TWIN_MERGE_LIST_PROPS,
    duplicate_guard=(
        '($mitre_source IN coalesce(c.source, []) OR trim(apoc.text.replace(d.name, $software_id_suffix, "")) = c.name)'
    ),
)


def merge_malware_attack_twins(neo4j_client) -> Dict:
    """Fold Malware nodes named with an ATT&CK software id into the MITRE node of that id.

    Candidates: Malware nodes that are not MITRE-sourced and whose name, or an alias of their own
    name, ends with `` - S####`` (``attack_software_names.software_id_claims``). Target: the
    MITRE-sourced Malware node of that ATT&CK id (read from its ``SOURCED_FROM`` ``raw_data``; a revoked
    id is translated to its successor), or, when its id cannot be read, the one of the same base
    name; a twin with two such targets is skipped (``skipped_ambiguous``). A twin named with an id that
    has no MITRE target folds into the non-MITRE node of its base name when that node states no other
    id (``base_name_targets``); without one it is left unchanged and counted (``no_target``). The
    decision is ``plan_twin_folds``.

    The merge is the actor alias merge's: the twin's name joins the target's ``aliases`` and
    ``merged_from``, ``tlp`` becomes the most restrictive of the group, all relationships move
    (parallel ones collapse with the strongest evidence and the union of their provenance), their
    ``src_uuid`` / ``trg_uuid`` are re-stamped, and every list property stays a list. The target keeps
    its name and uuid. Batched (``_MALWARE_TWIN_MERGE_BATCH_SIZE`` pairs per transaction,
    ``_MALWARE_TWIN_MERGE_MAX_PAIRS_PER_RUN`` per run) and idempotent.

    Dry run: ``EDGEGUARD_ENABLE_MALWARE_TWIN_MERGE=false`` logs the pairs and merges nothing. APOC
    missing (the candidate read and the merge use it): a WARNING and ``apoc_missing = 1``; a failed
    batch is counted in ``errors``; any other failed read re-raises (PR-N21), as in
    ``merge_alias_duplicate_actors``.

    Returns ``{candidates, merged, base_name_targets, no_target, skipped_ambiguous, errors,
    restamped_edges, apoc_missing}``.
    """
    if not neo4j_client.driver:
        logger.error("merge_malware_attack_twins: no Neo4j connection")
        return {}

    results: Dict = {
        "candidates": 0,
        "merged": 0,
        "base_name_targets": 0,
        "no_target": 0,
        "skipped_ambiguous": 0,
        "errors": 0,
        "restamped_edges": 0,
        "apoc_missing": 0,
    }
    try:
        with neo4j_client.driver.session() as session:
            twins = [
                {"name": row["name"], "aliases": row["aliases"]}
                for row in session.run(
                    _MALWARE_TWIN_CANDIDATES_CYPHER,
                    mitre_source=_ACTOR_ALIAS_MERGE_MITRE_SOURCE,
                    suffixed=CYPHER_SUFFIXED_NAME,
                    timeout=NEO4J_READ_TIMEOUT,
                )
            ]
            if not twins:
                logger.info("[MALWARE-TWIN-MERGE] no Malware node carries an ATT&CK software id in its name")
                return results
            attack_ids = {
                row["name"]: attack_software_id(row["attack_raw"], row["name"])
                for row in session.run(
                    _MALWARE_TWIN_ATTACK_NODES_CYPHER,
                    mitre_source=_ACTOR_ALIAS_MERGE_MITRE_SOURCE,
                    timeout=NEO4J_READ_TIMEOUT,
                )
                if row["name"]
            }
            bases = twin_base_names(twins)
            base_nodes = (
                {
                    row["name"]: row["aliases"]
                    for row in session.run(
                        CYPHER_BASE_NODES_READ,
                        bases=bases,
                        mitre_source=_ACTOR_ALIAS_MERGE_MITRE_SOURCE,
                        timeout=NEO4J_READ_TIMEOUT,
                    )
                    if row["name"]
                }
                if bases
                else {}
            )
            plan = plan_twin_folds(twins, attack_ids, load_revoked_ids().software, base_nodes)
            results["candidates"] = plan.candidates
            results["base_name_targets"] = len(plan.base_pairs)
            results["no_target"] = len(plan.no_target)
            results["skipped_ambiguous"] = len(plan.ambiguous)
            if plan.base_pairs:
                logger.info(
                    "[MALWARE-TWIN-MERGE] %d twin(s) without a MITRE Malware node fold into the node of their "
                    "base name. Sample (node, twin): %s",
                    len(plan.base_pairs),
                    plan.base_pairs[:10],
                )
            if plan.no_target:
                logger.info(
                    "[MALWARE-TWIN-MERGE] %d node(s) name an ATT&CK software id no MITRE Malware node has, and "
                    "no node of their base name takes them (left as they are; ATT&CK tools are Tool nodes). "
                    "Sample: %s",
                    len(plan.no_target),
                    plan.no_target[:10],
                )
            for twin, targets in plan.ambiguous:
                logger.warning(
                    "[MALWARE-TWIN-MERGE] skipping %r — its ATT&CK id and base name lead to %d MITRE nodes %s (ambiguous)",
                    twin,
                    len(targets),
                    targets,
                )
            pairs = sorted(plan.pairs + plan.base_pairs)  # (target node name, twin name)
            if not pairs:
                logger.info(
                    "[MALWARE-TWIN-MERGE] no twin with a target (candidates: %d, no target: %d, ambiguous: %d)",
                    results["candidates"],
                    results["no_target"],
                    results["skipped_ambiguous"],
                )
                return results

            if not _env_flag_enabled(_MALWARE_TWIN_MERGE_ENV_FLAG):
                logger.info(
                    "[MALWARE-TWIN-MERGE] DRY RUN (%s=false): %d mergeable pair(s) (%d into a base-named node), "
                    "%d without a target, %d ambiguous — merging nothing. Sample (target node, twin): %s",
                    _MALWARE_TWIN_MERGE_ENV_FLAG,
                    len(pairs),
                    results["base_name_targets"],
                    results["no_target"],
                    results["skipped_ambiguous"],
                    pairs[:10],
                )
                return results

            pairs = _cap_merge_pairs(pairs, _MALWARE_TWIN_MERGE_MAX_PAIRS_PER_RUN, "MALWARE-TWIN-MERGE")
            if not _run_alias_merge_batches(
                session,
                pairs,
                statements=_MALWARE_TWIN_MERGE_STATEMENTS,
                batch_size=_MALWARE_TWIN_MERGE_BATCH_SIZE,
                apply_params={
                    "strategy": _MALWARE_TWIN_MERGE_PROPERTY_STRATEGY,
                    "mitre_source": _ACTOR_ALIAS_MERGE_MITRE_SOURCE,
                    "base_canonicals": sorted({node for node, _twin in plan.base_pairs}),
                    "software_id_suffix": CYPHER_SOFTWARE_ID_SUFFIX,
                },
                results=results,
                log_tag="MALWARE-TWIN-MERGE",
                canonical_noun="target Malware node(s)",
            ):
                return results
    except Exception as e:
        # The candidate read lists aliases through APOC functions: without APOC it fails here, before
        # any merge, and the job reports it as the merge does (a WARNING, ``apoc_missing``).
        if _is_apoc_missing_error(e):
            logger.warning(
                "[MALWARE-TWIN-MERGE] APOC unavailable (%s) — skipping the merge; install the APOC plugin to enable it.",
                e,
            )
            results["apoc_missing"] = 1
            return results
        # PR-N21: any other failed read (driver dead, query broken) fails the task loudly; only per-batch
        # and APOC-missing conditions are handled.
        logger.error(f"[MALWARE-TWIN-MERGE] merge_malware_attack_twins FAILED: {e}", exc_info=True)
        raise

    logger.info(
        "[MALWARE-TWIN-MERGE] complete — candidates=%d merged=%d base_name_targets=%d no_target=%d "
        "skipped_ambiguous=%d errors=%d restamped_edges=%d",
        results["candidates"],
        results["merged"],
        results["base_name_targets"],
        results["no_target"],
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
    Run all seven post-sync enrichment jobs in sequence.

    Order matters: ``merge_alias_duplicate_actors`` and ``merge_malware_attack_twins`` run
    BEFORE ``build_campaign_nodes`` so campaigns are built on merged actors and malware. Since
    2026-10-16 the aging job (``decay_ioc_confidence``) runs before the campaign builder too, so a
    campaign's indicators are those active after the aging. The aging runs at the database's
    current time, lifted to a node's ``aging_evaluated_at`` when that is later.

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

    logger.info("\n[1/7] Vulnerability↔CVE REFERS_TO Bridge...")
    summary["bridge"] = _timed("bridge", bridge_vulnerability_cve, neo4j_client)

    # Must precede build_campaign_nodes: campaigns are keyed on actor name.
    logger.info("\n[2/7] ThreatActor Alias-Duplicate Merge...")
    summary["actor_alias_merge"] = _timed("actor_alias_merge", merge_alias_duplicate_actors, neo4j_client)

    # 2026-10: also before build_campaign_nodes, so a campaign links the ATT&CK malware node, not a twin.
    logger.info("\n[3/7] Malware ATT&CK-id Twin Merge...")
    summary["malware_twin_merge"] = _timed("malware_twin_merge", merge_malware_attack_twins, neo4j_client)

    # 2026-10-16: before build_campaign_nodes, which links only active indicators.
    logger.info("\n[4/7] Indicator Aging...")
    summary["decay"] = _timed("decay", decay_ioc_confidence, neo4j_client)

    logger.info("\n[5/7] Campaign Node Builder...")
    summary["campaigns"] = _timed("campaigns", build_campaign_nodes, neo4j_client)

    logger.info("\n[6/7] Co-occurrence Confidence Calibration...")
    summary["calibration"] = _timed("calibration", calibrate_cooccurrence_confidence, neo4j_client)

    # FIRST EPSS, the one feed written straight to Neo4j. Flag-off = INFO line, no network call.
    # A feed outage is logged and skipped inside the job (never raises).
    logger.info("\n[7/7] EPSS scores...")
    if config.ENABLE_EPSS:
        summary["epss"] = _timed("epss", enrich_cve_epss, neo4j_client)
    else:
        logger.info("EPSS enrichment disabled (EDGEGUARD_ENABLE_EPSS=false) — skipping")
        summary["epss"] = {"skipped": "disabled"}

    # PR #33 round 13: explicit aggregated summary so an operator scanning logs
    # sees totals from all 7 jobs without grepping each function's output.
    def _sum(d):
        if isinstance(d, dict):
            return sum(v for v in d.values() if isinstance(v, (int, float)))
        return d if isinstance(d, (int, float)) else 0

    logger.info(
        "[ENRICHMENT SUMMARY] bridge=%s actor_alias_merge=%s malware_twin_merge=%s campaigns=%s calibration=%s "
        "decay=%s epss=%s",
        _sum(summary.get("bridge")),
        _sum(summary.get("actor_alias_merge")),
        # The twins merged, not a sum of its counts (candidates and twins without a target are no work).
        _sum({"merged": (summary.get("malware_twin_merge") or {}).get("merged", 0)}),
        _sum(summary.get("campaigns")),
        _sum(summary.get("calibration")),
        # 2026-10-16: the Indicators whose aging changed, not a sum of its counts (tier counts are state).
        _sum({"changed": (summary.get("decay") or {}).get("changed", 0)}),
        # The CVE nodes EPSS updated, not a sum of its counts: the feed's row count is not work done.
        _sum({"cves_updated": (summary.get("epss") or {}).get("cves_updated", 0)}),
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
