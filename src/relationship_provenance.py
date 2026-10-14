"""Relationship provenance: who asserts a link, which record, which MISP event (2026-10).

Every relationship EdgeGuard builds from threat-intelligence sources carries three
accumulating lists:

* ``r.sources`` — the feeds that assert it, as canonical ``source_registry`` ids
  (``mitre_attck``, ``alienvault_otx``, ``threatfox``, ``nvd``, …);
* ``r.source_refs`` — those feeds' own record ids, ``"<feed>:<id>"``
  (``alienvault_otx:<pulse id>``, ``threatfox:<IOC id>``, ``mitre_attck:G0016``);
* ``r.misp_event_ids`` — the MISP events that carried it.

Each write adds to the lists and never replaces them, so no feed can erase another's
claim, and a link can be traced from Neo4j back to the MISP event and the feed record.
The kind of evidence stays in ``r.match_type``. The MISP→Neo4j sync writes the lists on
the links it creates directly (``Neo4jClient.create_misp_relationships_batch``) and on
each node's per-source ``SOURCED_FROM`` edge. The fragments below let the post-sync
builders (``build_relationships``, ``enrichment_jobs``) copy them onto the links they
derive: from the subject node's ``SOURCED_FROM`` edges, or from the links a derived link
is built on.

All fragments use double quotes only: they run inside single-quoted
``apoc.periodic.iterate('outer', 'inner', ...)`` statements.
"""

from __future__ import annotations

from typing import Sequence

# Cap on ``r.misp_event_ids`` per edge; same value as
# ``build_relationships.CRITICAL_MAX_EVENT_IDS_PER_EDGE`` (pinned by a test).
MAX_EVENT_IDS_PER_EDGE = 200

MITRE_FEEDS = '["mitre_attck"]'
OTX_FEEDS = '["alienvault_otx"]'
# Feeds whose records set ``Indicator.malware_family`` (what Q9 matches): ThreatFox
# (``malware_printable``), MalwareBazaar (``signature``), Feodo Tracker (``malware``) and OTX
# (``OTX_META.malware_family``). URLhaus, SSL Blacklist and VirusTotal set none (VirusTotal's
# sandbox family and popular threat label feed zone detection and ``threat_label`` only).
FAMILY_LABEL_FEEDS = '["threatfox", "malwarebazaar", "feodo_tracker", "alienvault_otx"]'
# Variables bound by ``prov_with``; a later ``WITH`` must carry them through to the ``SET``.
PROV_VARS = "_feeds, _prov_refs, _prov_events"


def as_list(expr: str) -> str:
    """``expr`` as a list: ``[]`` for null, ``[x]`` for a scalar (defensive against legacy scalars)."""
    return f'CASE WHEN {expr} IS NULL THEN [] WHEN apoc.meta.cypher.type({expr}) STARTS WITH "LIST" THEN {expr} ELSE [{expr}] END'


def node_feeds(node_var: str) -> str:
    """Every feed the subject node came from (``<node>.source``)."""
    return as_list(f"{node_var}.source")


def family_feeds(node_var: str) -> str:
    """The subject's feeds that carry family labels; all of its feeds when none of them does."""
    feeds = node_feeds(node_var)
    return (
        f"CASE WHEN size([s IN {feeds} WHERE s IN {FAMILY_LABEL_FEEDS}]) > 0 "
        f"THEN [s IN {feeds} WHERE s IN {FAMILY_LABEL_FEEDS}] ELSE {feeds} END"
    )


def prov_with(node_var: str, feeds_expr: str, max_events: int = MAX_EVENT_IDS_PER_EDGE) -> str:
    """``WITH`` clauses binding ``_feeds``, ``_prov_refs`` and ``_prov_events`` for ``node_var``.

    ``feeds_expr`` is a Cypher list of canonical source ids. ``_prov_refs`` /
    ``_prov_events`` are the record ids and MISP event ids on the node's ``SOURCED_FROM``
    edges to those feeds; events are capped like every other ``r.misp_event_ids`` write.
    """
    return (
        f"WITH {node_var}, {feeds_expr} AS _feeds "
        f"WITH {node_var}, _feeds, "
        f"[({node_var})-[_sf:SOURCED_FROM]->(_src:Source) WHERE _src.source_id IN _feeds | _sf] AS _sfs "
        f"WITH {node_var}, _feeds, "
        "reduce(_acc = [], _x IN _sfs | _acc + coalesce(_x.source_refs, [])) AS _prov_refs, "
        "[_e IN reduce(_acc = [], _x IN _sfs | _acc + coalesce(_x.misp_event_ids, [])) "
        f"WHERE _e IS NOT NULL AND size(_e) > 0][0..{max_events}] AS _prov_events "
    )


def prov_set(rel_var: str = "r") -> str:
    """``SET`` items accumulating the provenance bound by ``prov_with`` (the lists only grow)."""
    return (
        f"{rel_var}.sources = apoc.coll.toSet(coalesce({rel_var}.sources, []) + _feeds), "
        f"{rel_var}.source_refs = apoc.coll.toSet(coalesce({rel_var}.source_refs, []) + _prov_refs), "
        f"{rel_var}.misp_event_ids = apoc.coll.toSet(coalesce({rel_var}.misp_event_ids, []) + _prov_events)"
    )


def inherited_prov_set(rel_var: str, edge_exprs: Sequence[str], max_events: int = MAX_EVENT_IDS_PER_EDGE) -> str:
    """``SET`` items for a link derived from other links: it inherits their provenance.

    ``edge_exprs`` are Cypher expressions yielding the source links (e.g. ``"_at"``), whose
    ``sources`` / ``source_refs`` / ``misp_event_ids`` are added to ``rel_var``'s.
    """

    def union(field: str) -> str:
        parts = " + ".join(f"coalesce({e}.{field}, [])" for e in edge_exprs)
        return f"apoc.coll.toSet(coalesce({rel_var}.{field}, []) + {parts})"

    return (
        f"{rel_var}.sources = {union('sources')}, "
        f"{rel_var}.source_refs = {union('source_refs')}, "
        f"{rel_var}.misp_event_ids = {union('misp_event_ids')}[0..{max_events}]"
    )


def aggregated_prov_set(rel_var: str, pattern: str, edge_var: str, max_events: int = MAX_EVENT_IDS_PER_EDGE) -> str:
    """``SET`` items for a link derived from every link matching ``pattern`` (e.g. a campaign).

    ``pattern`` is a Cypher path pattern binding ``edge_var``, read as a pattern
    comprehension, e.g. ``"(a)<-[_at:ATTRIBUTED_TO]-(:Malware)"`` with ``edge_var="_at"``.
    """

    def union(field: str) -> str:
        return (
            f"apoc.coll.toSet(coalesce({rel_var}.{field}, []) + "
            f"reduce(_acc = [], _x IN [{pattern} | coalesce({edge_var}.{field}, [])] | _acc + _x))"
        )

    return (
        f"{rel_var}.sources = {union('sources')}, "
        f"{rel_var}.source_refs = {union('source_refs')}, "
        f"{rel_var}.misp_event_ids = {union('misp_event_ids')}[0..{max_events}]"
    )
