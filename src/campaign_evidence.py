"""Campaign evidence: what an EdgeGuard campaign rests on (2026-10).

A campaign is EdgeGuard's grouping of one threat actor's malware and those malware's active
indicators, not a source's claim. It rests on the links between its actor and a malware, each read in
the direction its claim is made:

* ``(Malware)-[:ATTRIBUTED_TO]->(ThreatActor)``: the malware is attributed to the actor;
* ``(ThreatActor)-[:USES_MALWARE]->(Malware)``: the actor uses the malware (MITRE's explicit
  ``uses`` relationships, ``mitre_explicit`` 0.95, ``build_relationships`` step 2b; curated-package
  claims, 0.85, ``relationship_provenance.CURATED_PREDICATES``).

An actor with either link has a campaign (``enrichment_jobs.build_campaign_nodes``, once a member
malware has an active indicator); a malware with either link to the actor is a member; an indicator
joins through ``INDICATES`` to a member malware. A campaign whose actor has neither link left is
deleted. The builder, the baseline postcheck (``dags/edgeguard_pipeline.py``, INV-1) and the
acceptance checks (``scripts/verify_fresh_baseline.py``) read the definition from this module, so
they cannot use different ones.

Standard library only: the acceptance script imports it without the driver or the configuration.
The fragments contain no quotes, so they also run inside the double-quoted statements of
``apoc.periodic.iterate``; ``evidence_types`` needs APOC.
"""

from __future__ import annotations

from typing import Tuple

# The relationship types a campaign rests on, between its actor and a malware.
CAMPAIGN_EVIDENCE_TYPES: Tuple[str, ...] = ("ATTRIBUTED_TO", "USES_MALWARE")


def evidence_links(actor: str, malware: str = ":Malware") -> str:
    """Cypher list of the evidence links between ``actor`` and ``malware`` (a bound variable, or
    ``":Malware"`` for any malware)."""
    return f"[({actor})<-[_ev:ATTRIBUTED_TO]-({malware}) | _ev] + [({actor})-[_ev:USES_MALWARE]->({malware}) | _ev]"


def member_malware(actor: str) -> str:
    """Cypher list of the malware with an evidence link to ``actor``, each once."""
    return (
        f"apoc.coll.toSet([({actor})<-[:ATTRIBUTED_TO]-(_mm:Malware) | _mm] + "
        f"[({actor})-[:USES_MALWARE]->(_mm:Malware) | _mm])"
    )


def has_evidence(actor: str, malware: str = ":Malware") -> str:
    """Cypher predicate: ``actor`` has an evidence link to ``malware`` (a bound variable, or
    ``":Malware"`` for any malware)."""
    return (
        f"(EXISTS {{ ({actor})<-[:ATTRIBUTED_TO]-({malware}) }} OR EXISTS {{ ({actor})-[:USES_MALWARE]->({malware}) }})"
    )


def indicator_paths(indicator: str, actor: str) -> str:
    """Cypher list of the paths from ``indicator`` to ``actor`` through a member malware, each as
    ``[INDICATES link, evidence link]``."""
    return (
        f"[({indicator})-[_xi:INDICATES]->(:Malware)-[_xa:ATTRIBUTED_TO]->({actor}) | [_xi, _xa]] + "
        f"[({indicator})-[_xi:INDICATES]->(:Malware)<-[_xa:USES_MALWARE]-({actor}) | [_xi, _xa]]"
    )


def evidence_types(links: str) -> str:
    """Cypher: the relationship types of the links in the list ``links``, each once, sorted, so
    the value does not depend on the order the links were read in."""
    return f"apoc.coll.sort(apoc.coll.toSet([_et IN {links} | type(_et)]))"


# The actors ``build_campaign_nodes`` builds a campaign for: an evidence link to a malware that an
# active indicator indicates. The baseline postcheck counts them (INV-1: such actors and no campaign
# mean the builder failed).
QUALIFYING_ACTORS_QUERY = (
    "MATCH (a:ThreatActor) "
    "WHERE EXISTS { MATCH (a)<-[:ATTRIBUTED_TO]-(:Malware)<-[:INDICATES]-(i:Indicator) WHERE i.active = true } "
    "OR EXISTS { MATCH (a)-[:USES_MALWARE]->(:Malware)<-[:INDICATES]-(i:Indicator) WHERE i.active = true } "
    "RETURN count(a) AS qualifying_actors"
)

# Acceptance (``scripts/verify_fresh_baseline.py``): every malware member of a campaign has an
# evidence link to the campaign's actor (``build_campaign_nodes`` Step 2b removes the others).
MALWARE_MEMBERSHIP_CHECK_QUERY = (
    "MATCH (m:Malware)-[r:PART_OF_CAMPAIGN]->(c:Campaign) "
    "RETURN count(r) AS malware_links, "
    "sum(CASE WHEN NOT EXISTS { MATCH (a:ThreatActor {name: c.actor_name}) WHERE "
    + has_evidence("a", "m")
    + " } THEN 1 ELSE 0 END) AS without_evidence"
)

# Acceptance: no campaign EdgeGuard built exists without evidence (its actor gone, or without either
# link; Step 1b deletes such campaigns), each has the RUNS of its actor, and no RUNS comes from an
# actor that is not the campaign's or has no evidence (Step 2c removes them).
CAMPAIGN_EVIDENCE_CHECK_QUERY = (
    "MATCH (c:Campaign) WHERE c.edgeguard_managed = true "
    "WITH count(c) AS campaigns, "
    "sum(CASE WHEN NOT EXISTS { MATCH (a:ThreatActor {name: c.actor_name}) WHERE "
    + has_evidence("a")
    + " } THEN 1 ELSE 0 END) AS without_evidence, "
    "sum(CASE WHEN NOT EXISTS { MATCH (:ThreatActor {name: c.actor_name})-[:RUNS]->(c) } THEN 1 ELSE 0 END) "
    "AS without_runs "
    "RETURN campaigns, without_evidence, without_runs, "
    "COUNT { MATCH (a:ThreatActor)-[:RUNS]->(rc:Campaign) WHERE NOT (coalesce(a.name = rc.actor_name, false) AND "
    + has_evidence("a")
    + ") } AS runs_without_evidence"
)
