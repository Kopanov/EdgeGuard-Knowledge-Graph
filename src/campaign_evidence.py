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
joins through ``INDICATES`` to a member malware. A campaign whose actor has no campaign evidence left
(no link, or since 2026-11-06 links to shared malware only that count for none of their indicators) is
deleted. The builder, the baseline postcheck (``dags/edgeguard_pipeline.py``, INV-1) and the
acceptance checks (``scripts/verify_fresh_baseline.py``) read the definition from this module, so
they cannot use different ones.

Shared malware (2026-11-06). A malware that many actors are linked to (Cobalt Strike, PlugX, a
leaked ransomware builder) says nothing about which of them an indicator of it belongs to: a link of
the actor to such a malware made every indicator of the family evidence of the actor's campaign
(30 ATT&CK groups that use Cobalt Strike each had all its 2,238 active indicators as candidates on the
730-day graph of 2026-11-03). A malware is shared when at least ``EDGEGUARD_CAMPAIGN_SHARED_MALWARE_ACTORS``
(default 7) distinct actors have either link to it, from any source; names that differ only by spaces,
hyphens, underscores or dots ("cobalt strike", "cobaltstrike") are one malware for that count, and every
such name is shared (``SHARED_MALWARE_QUERY``). An indicator that ``INDICATES`` a shared malware (a
source tagged it with the family, often beside other families) is evidence of an actor's campaign only
through a link that a record reporting it cites: one of the link's ``source_refs`` is on one of the
indicator's ``SOURCED_FROM`` edges (an OTX pulse that attributes the malware to the actor and lists the
indicator). That holds whichever member the indicator reaches, so a family does not come back through a
malware that is not shared and that a pulse lists beside it, or through an alias name the same indicator
carries. A version or suffix name a source gives on its own ("lockbit 3.0", "havoc demon") is a malware of
its own and counts by its own actors. A link to a shared
malware makes it a member only while it counts for one of its indicators, and RUNS and the campaign's TLP
rest on it only then; an ATT&CK ``uses`` or a curated claim cites no indicator's record, so a link of that
kind to a shared malware is no campaign evidence. Links to other malware count as before, for every
indicator that ``INDICATES`` no shared malware. The names of the shared malware reach every statement as
``$shared_malware``; an empty list (setting 0) turns the rule off. The acceptance checks judge each
campaign with the list the build recorded on it (``recorded_shared_malware``).

Standard library only: the acceptance script imports it without the driver or the configuration.
The fragments contain no quotes (but ``malware_key``, which only ``SHARED_MALWARE_QUERY`` reads), so
they also run inside the double-quoted statements of ``apoc.periodic.iterate``; ``evidence_types`` and
``member_malware`` need APOC.
"""

from __future__ import annotations

from typing import Any, Iterable, List, Mapping, Optional, Tuple

# The relationship types a campaign rests on, between its actor and a malware.
CAMPAIGN_EVIDENCE_TYPES: Tuple[str, ...] = ("ATTRIBUTED_TO", "USES_MALWARE")

# 2026-11-06: the setting and its default. On the 730-day graph of 2026-11-03 every malware with 7 or more
# actors is a family many groups use (commodity, open-source or leaked tooling, malware or ransomware sold
# as a service, the PlugX and ShadowPad families Chinese groups share) but InvisibleFerret, whose actors
# are mostly six names of one North Korean cluster that the canonical actor reference keeps apart. The
# number of actors cannot tell such a lineage from a commodity family, so 7 is a trade-off, not a
# boundary: at 6 BeaverTail, of the same cluster, would be shared too, and so would Mirai, Meterpreter
# and AnyDesk, which at 7 still fill the samples of campaigns linked to them (Mirai all 100 of APT28's).
SHARED_MALWARE_ACTORS_SETTING = "EDGEGUARD_CAMPAIGN_SHARED_MALWARE_ACTORS"
SHARED_MALWARE_ACTORS_DEFAULT = 7


def shared_malware_actors(value: Optional[str]) -> int:
    """The number of distinct actors from which a malware is shared, from the setting's text
    ``value``: unset, blank or not an integer gives the default; 0 or less gives 0 (the rule is off:
    every linked malware counts for all its indicators); 1 gives 2 (at 1 every linked malware would be
    shared)."""
    text = (value or "").strip()
    try:
        n = int(text) if text else SHARED_MALWARE_ACTORS_DEFAULT
    except ValueError:
        n = SHARED_MALWARE_ACTORS_DEFAULT
    return 0 if n <= 0 else max(2, n)


# The list of shared malware names the fragments below read: the run's list in the builder and INV-1;
# ``recorded_shared_malware`` in the acceptance checks.
SHARED = "$shared_malware"


def recorded_shared_malware(campaign: str) -> str:
    """Cypher: the shared malware the build that last wrote ``campaign`` judged with (2026-11-06,
    ``c.shared_malware``), else ``$shared_malware`` (a campaign a partner created, or one built before)."""
    return f"coalesce({campaign}.shared_malware, $shared_malware)"


def report_scoped(link: str, indicator: str) -> str:
    """Cypher predicate: ``indicator`` was reported in a record the evidence link ``link`` cites (one
    of the link's ``source_refs`` is on one of the indicator's ``SOURCED_FROM`` edges)."""
    return (
        f"EXISTS {{ MATCH ({indicator})-[_rs:SOURCED_FROM]->(:Source) "
        f"WHERE any(_rr IN coalesce(_rs.source_refs, []) WHERE _rr IN coalesce({link}.source_refs, [])) }}"
    )


def indicates_shared(indicator: str, shared: str = SHARED) -> str:
    """Cypher predicate: ``indicator`` ``INDICATES`` a shared malware, whichever malware it is reached
    through (2026-11-06)."""
    return f"EXISTS {{ MATCH ({indicator})-[:INDICATES]->(_sx:Malware) WHERE _sx.name IN {shared} }}"


def counts_for(link: str, indicator: str, shared: str = SHARED) -> str:
    """Cypher predicate: the evidence link ``link`` counts for ``indicator``, an indicator of the link's
    malware: always when the indicator ``INDICATES`` no shared malware, else when the link's record
    reported it."""
    return f"(NOT {indicates_shared(indicator, shared)} OR {report_scoped(link, indicator)})"


def link_counts(link: str, malware: str, shared: str = SHARED) -> str:
    """Cypher predicate: the evidence link ``link`` to ``malware`` is campaign evidence: the malware is
    not shared, or the link counts for one of its indicators (active or not)."""
    return (
        f"(NOT {malware}.name IN {shared} OR "
        f"EXISTS {{ MATCH ({malware})<-[:INDICATES]-(_si:Indicator) WHERE {report_scoped(link, '_si')} }})"
    )


def evidence_links(actor: str, malware: Optional[str] = None, shared: str = SHARED) -> str:
    """Cypher list of the evidence links between ``actor`` and ``malware`` (a bound variable, or any
    malware when None) that are campaign evidence (``link_counts``)."""
    node, name = (malware, malware) if malware else ("_em:Malware", "_em")
    return (
        f"[({actor})<-[_ev:ATTRIBUTED_TO]-({node}) WHERE {link_counts('_ev', name, shared)} | _ev] + "
        f"[({actor})-[_ev:USES_MALWARE]->({node}) WHERE {link_counts('_ev', name, shared)} | _ev]"
    )


def member_malware(actor: str, shared: str = SHARED) -> str:
    """Cypher list of the malware with an evidence link to ``actor`` that is campaign evidence, each once."""
    return (
        f"apoc.coll.toSet([({actor})<-[_mv:ATTRIBUTED_TO]-(_mm:Malware) WHERE {link_counts('_mv', '_mm', shared)} "
        f"| _mm] + [({actor})-[_mv:USES_MALWARE]->(_mm:Malware) WHERE {link_counts('_mv', '_mm', shared)} | _mm])"
    )


def has_evidence(actor: str, malware: Optional[str] = None, shared: str = SHARED) -> str:
    """Cypher predicate: ``actor`` has an evidence link to ``malware`` (a bound variable, or any malware
    when None) that is campaign evidence (``link_counts``)."""
    node, name = (malware, malware) if malware else ("_hm:Malware", "_hm")
    return (
        f"(EXISTS {{ MATCH ({actor})<-[_hv:ATTRIBUTED_TO]-({node}) WHERE {link_counts('_hv', name, shared)} }} OR "
        f"EXISTS {{ MATCH ({actor})-[_hv:USES_MALWARE]->({node}) WHERE {link_counts('_hv', name, shared)} }})"
    )


def indicator_joins(indicator: str, malware: str, actor: str, shared: str = SHARED) -> str:
    """Cypher predicate: ``indicator``, which ``INDICATES`` the member ``malware``, joins ``actor``'s
    campaign through it: the indicator ``INDICATES`` no shared malware, or an evidence link between the
    actor and the member counts for it (``counts_for``)."""
    return (
        f"(NOT {indicates_shared(indicator, shared)} OR "
        f"EXISTS {{ MATCH ({malware})-[_jv:ATTRIBUTED_TO]->({actor}) WHERE {report_scoped('_jv', indicator)} }} OR "
        f"EXISTS {{ MATCH ({actor})-[_jv:USES_MALWARE]->({malware}) WHERE {report_scoped('_jv', indicator)} }})"
    )


def indicator_paths(indicator: str, actor: str, shared: str = SHARED) -> str:
    """Cypher list of the paths from ``indicator`` to ``actor`` through a member malware, each as
    ``[INDICATES link, evidence link]``, through an evidence link that counts for the indicator."""
    return (
        f"[({indicator})-[_xi:INDICATES]->(_xm:Malware)-[_xa:ATTRIBUTED_TO]->({actor}) "
        f"WHERE {counts_for('_xa', indicator, shared)} | [_xi, _xa]] + "
        f"[({indicator})-[_xi:INDICATES]->(_xm:Malware)<-[_xa:USES_MALWARE]-({actor}) "
        f"WHERE {counts_for('_xa', indicator, shared)} | [_xi, _xa]]"
    )


def evidence_types(links: str) -> str:
    """Cypher: the relationship types of the links in the list ``links``, each once, sorted, so
    the value does not depend on the order the links were read in."""
    return f"apoc.coll.sort(apoc.coll.toSet([_et IN {links} | type(_et)]))"


# 2026-11-06: the characters by which spellings of one malware name differ ("cobalt strike" and
# "cobaltstrike", "lumma stealer" and "lummastealer", "winos4.0" and "winos 4.0"): names equal without
# them are one malware when the actors are counted. On the 730-day graph of 2026-11-03 six shared families
# had such a spelling linked to actors of its own (cobaltstrike, gh0strat, lummastealer, netsupportrat,
# quasar rat, valley rat), and the indicators of a campaign could be all of one of them.
MALWARE_NAME_SEPARATORS: Tuple[str, ...] = (" ", "-", "_", ".")


def malware_key(name: str) -> str:
    """Cypher: the malware name ``name`` lower-cased and without ``MALWARE_NAME_SEPARATORS``. It holds
    quotes, so only ``SHARED_MALWARE_QUERY`` reads it, never a statement of ``apoc.periodic.iterate``."""
    key = f"toLower({name})"
    for separator in MALWARE_NAME_SEPARATORS:
        key = f"replace({key}, '{separator}', '')"
    return key


# 2026-11-06: the shared malware, those with an evidence link from at least ``$min_actors`` distinct
# actors (both link types and every source together; an actor with both links counts once; the names
# of one ``malware_key`` together), most shared first, then by name. ``$min_actors`` 0 (the rule off)
# gives none. One row: ``malware``, a list of ``{name, names, actors}`` (``name`` the first of
# ``names``); ``shared_malware_names`` gives the ``$shared_malware`` of every other statement here.
SHARED_MALWARE_QUERY = (
    "MATCH (a:ThreatActor) "
    "UNWIND [(a)<-[:ATTRIBUTED_TO]-(_sm:Malware) | _sm] + [(a)-[:USES_MALWARE]->(_sm:Malware) | _sm] AS m "
    "WITH a, m.name AS name WHERE name IS NOT NULL "
    "WITH a, name, " + malware_key("name") + " AS key ORDER BY name "
    "WITH key, collect(DISTINCT name) AS names, count(DISTINCT a) AS actors "
    "WHERE $min_actors > 0 AND actors >= $min_actors "
    "WITH names, actors ORDER BY actors DESC, names[0] "
    "RETURN collect({name: names[0], names: names, actors: actors}) AS malware"
)


def shared_malware_names(malware: Optional[Iterable[Mapping[str, Any]]]) -> List[str]:
    """The names of the shared malware of ``SHARED_MALWARE_QUERY``'s ``malware`` (every spelling of
    each), the ``$shared_malware`` of the other statements."""
    names: List[str] = []
    for m in malware or []:
        for name in m.get("names") or [m.get("name")]:
            if name and name not in names:
                names.append(name)
    return names


# 2026-11-06: the evidence links per type (the builder's log line): all of them, those to a shared
# malware (``shared_links``), and of those, the links that count for an indicator of their own
# records (``report_scoped_links``). One row per type that has links.
SHARED_LINKS_QUERY = (
    "CALL { MATCH (m:Malware)-[l:ATTRIBUTED_TO]->(:ThreatActor) RETURN m, l "
    "UNION ALL MATCH (:ThreatActor)-[l:USES_MALWARE]->(m:Malware) RETURN m, l } "
    "WITH m, l, m.name IN $shared_malware AS shared "
    "WITH type(l) AS link_type, shared, CASE WHEN shared THEN EXISTS { MATCH (m)<-[:INDICATES]-(_si:Indicator) WHERE "
    + report_scoped("l", "_si")
    + " } ELSE false END AS scoped "
    "RETURN link_type, count(*) AS links, sum(CASE WHEN shared THEN 1 ELSE 0 END) AS shared_links, "
    "sum(CASE WHEN scoped THEN 1 ELSE 0 END) AS report_scoped_links ORDER BY link_type"
)

# The actors ``build_campaign_nodes`` builds a campaign for: an evidence link to a malware that an
# active indicator indicates, counting for that indicator (2026-11-06: for an indicator of a shared
# malware only when the link's record reported it). The baseline postcheck counts them (INV-1: such
# actors and no campaign mean the builder failed). Parameter: ``$shared_malware``.
QUALIFYING_ACTORS_QUERY = (
    "MATCH (a:ThreatActor) "
    "WHERE EXISTS { MATCH (a)<-[_ql:ATTRIBUTED_TO]-(m:Malware)<-[:INDICATES]-(i:Indicator) WHERE i.active = true AND "
    + counts_for("_ql", "i")
    + " } OR EXISTS { MATCH (a)-[_ql:USES_MALWARE]->(m:Malware)<-[:INDICATES]-(i:Indicator) WHERE i.active = true AND "
    + counts_for("_ql", "i")
    + " } RETURN count(a) AS qualifying_actors"
)

# 2026-11-06: the shared-malware rule each EdgeGuard campaign was built with (``build_campaign_nodes``
# records ``c.shared_malware_actors`` and ``c.shared_malware`` at the end of a run), one row per rule
# with its number of campaigns; ``min_actors`` null for the campaigns without one (built before).
RECORDED_SHARED_MALWARE_QUERY = (
    "MATCH (c:Campaign) WHERE c.edgeguard_managed = true "
    "WITH c.shared_malware_actors AS min_actors, c.shared_malware AS names, count(c) AS campaigns "
    "RETURN min_actors, names, campaigns ORDER BY campaigns DESC"
)

# Acceptance (``scripts/verify_fresh_baseline.py``): every malware member of a campaign has an
# evidence link to the campaign's actor (``build_campaign_nodes`` Step 2b removes the others).
# 2026-11-06: judged with the shared malware the campaign's build recorded (``$shared_malware``, the
# list when the check runs, for a campaign without one).
MALWARE_MEMBERSHIP_CHECK_QUERY = (
    "MATCH (m:Malware)-[r:PART_OF_CAMPAIGN]->(c:Campaign) "
    "RETURN count(r) AS malware_links, "
    "sum(CASE WHEN NOT EXISTS { MATCH (a:ThreatActor {name: c.actor_name}) WHERE "
    + has_evidence("a", "m", recorded_shared_malware("c"))
    + " } THEN 1 ELSE 0 END) AS without_evidence"
)

# Acceptance (2026-11-06): every indicator member of a campaign has a path to the campaign's actor
# through an evidence link that counts for it (``indicator_paths``; ``build_campaign_nodes`` Step 3a
# links only such indicators, Step 3b removes the rest), judged as the malware members are.
INDICATOR_MEMBERSHIP_CHECK_QUERY = (
    "MATCH (i:Indicator)-[r:PART_OF_CAMPAIGN]->(c:Campaign) "
    "RETURN count(r) AS indicator_links, "
    "sum(CASE WHEN NOT EXISTS { MATCH (a:ThreatActor {name: c.actor_name}) WHERE size("
    + indicator_paths("i", "a", recorded_shared_malware("c"))
    + ") > 0 } THEN 1 ELSE 0 END) AS without_evidence"
)

# Acceptance: no campaign EdgeGuard built exists without evidence (its actor gone, or without a link
# that is campaign evidence; Step 1b deletes such campaigns), each has the RUNS of its actor, and no
# RUNS comes from an actor that is not the campaign's or has no evidence (Step 2c removes them), judged
# as the malware members are (the RUNS by the list of the campaign it ends at).
CAMPAIGN_EVIDENCE_CHECK_QUERY = (
    "MATCH (c:Campaign) WHERE c.edgeguard_managed = true "
    "WITH count(c) AS campaigns, "
    "sum(CASE WHEN NOT EXISTS { MATCH (a:ThreatActor {name: c.actor_name}) WHERE "
    + has_evidence("a", shared=recorded_shared_malware("c"))
    + " } THEN 1 ELSE 0 END) AS without_evidence, "
    "sum(CASE WHEN NOT EXISTS { MATCH (:ThreatActor {name: c.actor_name})-[:RUNS]->(c) } THEN 1 ELSE 0 END) "
    "AS without_runs "
    "RETURN campaigns, without_evidence, without_runs, "
    "COUNT { MATCH (a:ThreatActor)-[:RUNS]->(rc:Campaign) WHERE NOT (coalesce(a.name = rc.actor_name, false) AND "
    + has_evidence("a", shared=recorded_shared_malware("rc"))
    + ") } AS runs_without_evidence"
)
