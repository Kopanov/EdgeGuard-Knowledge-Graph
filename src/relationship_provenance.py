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

from typing import Dict, Sequence, Tuple, Union

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


def sorted_set(values: str) -> str:
    """Cypher: the values of the list ``values``, each once, null dropped, as sorted strings
    (2026-10-16), so a derived link's ``sources`` / ``source_refs`` do not depend on the order in
    which the links it rests on were created or read."""
    return f"apoc.coll.sort(apoc.coll.toSet([_sv IN {values} WHERE _sv IS NOT NULL | toString(_sv)]))"


def capped_event_ids(ids: str, max_events: int = MAX_EVENT_IDS_PER_EDGE) -> str:
    """Cypher: the MISP event ids of the list ``ids``, each once, at most ``max_events``, chosen and
    ordered by a fixed rule (2026-10-16): the numeric ids from the highest down (MISP numbers its
    events in creation order, so the newest are kept), then any id that is not a number, sorted.

    The cut of ``apoc.coll.toSet(...)[0..N]`` kept the first ids in the order the links were read,
    which is their creation order: two graphs built from the same MISP data in a different order (a
    full and an incremental sync) kept different ids once the union held more than ``N``. The top
    ``N`` by a fixed order is the same however the union is assembled, and an accumulating write
    that keeps the top ``N`` of its stored list and the incoming ids keeps the top ``N`` of all of
    them. Ids are compared as strings (an id stored as a number is read as its string)."""
    return (
        f"[_ids IN [apoc.coll.toSet([_ei IN {ids} WHERE _ei IS NOT NULL | toString(_ei)])] | "
        "([_en IN reverse(apoc.coll.sort(apoc.coll.toSet("
        "[_ei IN _ids WHERE toInteger(_ei) IS NOT NULL | toInteger(_ei)]))) | toString(_en)] "
        f"+ apoc.coll.sort([_ei IN _ids WHERE toInteger(_ei) IS NULL]))[0..{max_events}]][0]"
    )


def inherited_prov_set(
    rel_var: str, edge_exprs: Sequence[str], max_events: int = MAX_EVENT_IDS_PER_EDGE, replace: bool = False
) -> str:
    """``SET`` items for a link derived from other links: it inherits their provenance.

    ``edge_exprs`` are Cypher expressions yielding the source links (e.g. ``"_at"``), whose
    ``sources`` / ``source_refs`` / ``misp_event_ids`` are added to ``rel_var``'s. With
    ``replace`` (2026-10) they become ``rel_var``'s: a link that rests on exactly those links
    then names no evidence a later run removed or trimmed from them. The lists are sorted and the
    events capped by a fixed rule (``sorted_set``, ``capped_event_ids``; 2026-10-16), so the result
    does not depend on the order in which the links were created or read.
    """

    def union(field: str) -> str:
        parts = " + ".join(f"coalesce({e}.{field}, [])" for e in edge_exprs)
        # ``[] +`` keeps a list when a source link holds one of the lists as a plain string
        # (``sorted_set`` / ``capped_event_ids`` iterate over it and raise on a string; the
        # accumulating form is a list concatenation).
        own = "[] + " if replace else f"coalesce({rel_var}.{field}, []) + "
        return f"{own}{parts}"

    return (
        f"{rel_var}.sources = {sorted_set(union('sources'))}, "
        f"{rel_var}.source_refs = {sorted_set(union('source_refs'))}, "
        f"{rel_var}.misp_event_ids = {capped_event_ids(union('misp_event_ids'), max_events)}"
    )


def aggregated_prov_set(
    rel_var: str,
    pattern: str,
    edge_var: Union[str, Sequence[str]],
    max_events: int = MAX_EVENT_IDS_PER_EDGE,
    replace: bool = False,
) -> str:
    """``SET`` items for a link derived from every link matching ``pattern`` (e.g. a campaign).

    ``pattern`` is a Cypher path pattern binding ``edge_var``, read as a pattern
    comprehension, e.g. ``"(a)<-[_at:ATTRIBUTED_TO]-(:Malware)"`` with ``edge_var="_at"``; a
    pattern of several links names each of them (``["_xi", "_xa"]``). It may also be the head of
    a list comprehension over links already collected (2026-10-16), e.g. ``"_e IN links"`` with
    ``edge_var="_e"``, or ``"_p IN paths"`` with ``["_p[0]", "_p[1]"]``. With ``replace``
    (2026-10) the provenance of the matching links becomes ``rel_var``'s instead of being added
    to it, so a derived link follows the removal and trimming of the links it rests on. The lists
    are sorted and the events capped by a fixed rule (``sorted_set``, ``capped_event_ids``;
    2026-10-16): the pattern comprehension reads the links in the order they were created, so a
    cut of the unsorted union kept a different set of events on two graphs built from the same
    MISP data in a different order.
    """
    edge_vars = [edge_var] if isinstance(edge_var, str) else list(edge_var)

    def union(field: str) -> str:
        per_match = " + ".join(f"coalesce({e}.{field}, [])" for e in edge_vars)
        if len(edge_vars) > 1:
            # A list stored as a plain string (APOC ``combine``) must not meet another one: two
            # strings would concatenate into one value. ``[] +`` makes every operand a list element.
            per_match = "[] + " + per_match
        own = "" if replace else f"coalesce({rel_var}.{field}, []) + "
        return f"{own}reduce(_acc = [], _x IN [{pattern} | {per_match}] | _acc + _x)"

    return (
        f"{rel_var}.sources = {sorted_set(union('sources'))}, "
        f"{rel_var}.source_refs = {sorted_set(union('source_refs'))}, "
        f"{rel_var}.misp_event_ids = {capped_event_ids(union('misp_event_ids'), max_events)}"
    )


# ---------------------------------------------------------------------------
# Curated packages (2026-10)
# ---------------------------------------------------------------------------
# The claims a curated package may carry, by predicate and subject label:
# (relationship type, object label, object key). Shared by the MISP→Neo4j sync (which turns
# claims into relationships) and ``scripts/import_curated_package.py`` (which validates a
# package before it reaches MISP).
CURATED_PREDICATES: Dict[str, Dict[str, Tuple[str, str, str]]] = {
    "uses_technique": {"ThreatActor": ("EMPLOYS_TECHNIQUE", "Technique", "mitre_id")},
    "implements_technique": {"Malware": ("IMPLEMENTS_TECHNIQUE", "Technique", "mitre_id")},
    "uses_malware": {"ThreatActor": ("USES_MALWARE", "Malware", "name")},
    "uses_tool": {"ThreatActor": ("USES_TOOL", "Tool", "mitre_id")},
    "exploits": {"ThreatActor": ("EXPLOITS", "CVE", "cve_id"), "Malware": ("EXPLOITS", "CVE", "cve_id")},
}
CURATED_CLAIMS_PREFIX = "CURATED_CLAIMS:"
CURATED_CLAIM_CONFIDENCE = 0.85
