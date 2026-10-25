"""Which source's text a node's description is: a fixed source ranking (2026-10).

A ``CVE``, ``Vulnerability``, ``Malware``, ``ThreatActor``, ``Tool``, ``Technique`` or ``Tactic`` node
keeps one description: the text of the highest-ranked source whose record gave one. The node names that
source in ``description_source`` (its canonical id, ``source_registry.canonical_source_id``), so the
expert knows whose text it is and reaches it, and every other source's text, in MISP through the node's
``SOURCED_FROM`` edges (docs/RUNBOOK.md, "Retrieving raw MISP data from a Neo4j node").

Until 2026-10-16 NVD's record set a CVE's description and MITRE's record an entity's, and any other record
only filled an empty one: on a node without such a record the first source to arrive kept its text,
whatever came later, so the node depended on the order of the events in the sync.

The ranking, highest first:

- ``CVE`` and ``Vulnerability``: NVD, CISA KEV, CISA ICS, then every other source;
- ``Malware``, ``ThreatActor``, ``Tool``, ``Technique`` and ``Tactic``: MITRE ATT&CK, the curated sources
  (``source_type`` ``curated``), then every other source.

The ranking is total, so no two sources tie: inside a group of several sources (the curated sources,
every other source) the source with the higher registry ``reliability`` ranks higher, then the one whose
id sorts first. A source the registry does not know (``resilmesh``, the source name an external STIX
bundle gives), or one it registers with ``ranked_for_descriptions=False`` (``stix_import``, registered
2026-10-25 for its ``Source`` node only), ranks below every ranked one; two such sources are ordered by
id, the one that sorts first ranking higher.

A record sets the description when its source ranks at least as high as the source of the stored text:
the same source's revised record replaces its own text, a lower-ranked source never replaces a
higher-ranked one, and an empty stored description (null or ``''``) is filled by any record. A record
without text changes nothing. A node written before this ranking has a description but no
``description_source``; its text counts as the top source's, so only NVD's record (CVE, Vulnerability)
or MITRE's (the other labels) replaces it, and any other record fills only an empty description.

Order of arrival. MISP holds one attribute per source per CVE or entity: MISPWriter skips an attribute
whose (type, value) its source already holds in any event (cross-event deduplication,
``MISPWriter._get_existing_source_attribute_keys``) and in the event being written, and NVD's update
edits NVD's stored copies in place (``MISPWriter.plan_vulnerability_update``). Each source therefore
gives one text, the highest-ranked text wins whatever the order in which the sync merges the records,
and a full and an incremental sync, or the attribute and the STIX flow, give the same node. Where MISP
holds two attributes of one source for one node (the cross-event check switched off or its prefetch
failed, both logged; a MITRE technique, tactic or tool ATT&CK renamed, whose attribute value carries the
name), the one merged last is kept.

Neo4j evaluates the rule (``DescriptionRanking.set_cypher``; ``best_of_cypher`` for the nodes an alias or
twin merge folds together); ``replaces`` and ``best_of`` mirror them in Python for the tests, and
``tests/test_description_ranking_neo4j.py`` checks that each pair agrees on a real database. Standard library
and ``source_registry`` only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from source_registry import all_sources, canonical_source_id, curated_source_ids

# Source ids are inlined into Cypher as string literals; the registry only holds lowercase ASCII ids.
_SOURCE_ID_RE = re.compile(r"^[a-z0-9_.-]+$")

# The variable the ranked SET binds the decision to (``set_cypher``).
_REPLACES_VAR = "description_replaces"


@dataclass(frozen=True)
class RankedDescription:
    """A record's description: its text, the canonical id of its source and that source's rank."""

    text: str
    source: str
    rank: int


@dataclass(frozen=True)
class DescriptionRanking:
    """A fixed, total ranking of the sources of one kind of node's description.

    ``groups`` are the named groups of sources, highest first; every other ranked registered source
    follows them. ``ranks`` gives every registered source with ``ranked_for_descriptions`` a distinct
    rank, highest first from the number of such sources down to 1; an unregistered source, or one
    registered with ``ranked_for_descriptions=False``, ranks 0.
    """

    name: str
    labels: Tuple[str, ...]
    groups: Tuple[Tuple[str, ...], ...]
    ranks: Dict[str, int] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        group_of = {sid: i for i, group in enumerate(self.groups) for sid in group}
        # A source registered with ``ranked_for_descriptions=False`` ranks 0, as an unregistered one.
        registered = [src for src in all_sources() if src.ranked_for_descriptions]
        unknown = set(group_of) - {src.canonical_id for src in registered}
        if unknown:
            raise ValueError(f"description ranking {self.name!r}: unregistered sources {sorted(unknown)}")
        ordered = sorted(
            registered,
            key=lambda src: (group_of.get(src.canonical_id, len(self.groups)), -src.reliability, src.canonical_id),
        )
        ranks = {src.canonical_id: len(ordered) - i for i, src in enumerate(ordered)}
        for sid in ranks:
            if not _SOURCE_ID_RE.match(sid):
                raise ValueError(f"description ranking {self.name!r}: source id {sid!r} cannot be inlined")
        object.__setattr__(self, "ranks", ranks)

    @property
    def top_source(self) -> str:
        """The source whose record replaces a description written before the ranking (NVD, MITRE)."""
        return self.groups[0][0]

    @property
    def top_rank(self) -> int:
        return self.ranks[self.top_source]

    def rank(self, source: Optional[str]) -> int:
        """The rank of ``source`` (an id or an alias); 0 for a source the registry does not know."""
        return self.ranks.get(canonical_source_id(source) or "", 0)

    def record(self, text: object, source: Optional[str]) -> Optional[RankedDescription]:
        """The description a record of ``source`` gives, or None when it gives no text."""
        sid = canonical_source_id(source)
        if not isinstance(text, str) or not text.strip() or not sid:
            return None
        return RankedDescription(text=text, source=sid, rank=self.ranks.get(sid, 0))

    # ------------------------------------------------------------ the rule, in Python
    def stored_rank(self, description: object, source: Optional[str]) -> int:
        """The rank of a stored description: -1 when empty, the top rank when it names no source."""
        if description is None or description == "":
            return -1
        if source is None:
            return self.top_rank
        return self.ranks.get(source, 0)

    def replaces(self, stored_description: object, stored_source: Optional[str], record: RankedDescription) -> bool:
        """Whether ``record`` replaces the stored description (``set_cypher`` evaluates the same)."""
        stored = self.stored_rank(stored_description, stored_source)
        if record.rank != stored:
            return record.rank > stored
        # Equal ranks: the same registered source (each has its own rank), a description written before
        # the ranking and the top source, or two unregistered sources, ordered by id.
        return record.rank > 0 or record.source <= str(stored_source)

    def best_of(self, first: Mapping[str, Any], others: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
        """Of the node properties ``first`` and ``others``, the node whose description the ranking keeps
        when they are merged into one (``best_of_cypher`` evaluates the same)."""

        def key(node: Mapping[str, Any]) -> int:
            return self.stored_rank(node.get("description"), node.get("description_source"))

        best = first
        for node in others:
            if key(node) > key(best):
                best = node
            elif key(node) == key(best) and best is not first:
                pair = (str(node.get("description_source") or ""), str(node.get("name")))
                if pair < (str(best.get("description_source") or ""), str(best.get("name"))):
                    best = node
        return best

    # ------------------------------------------------------------ the rule, in Cypher
    def stored_rank_cypher(self, var: str) -> str:
        """Cypher expression: the rank of ``var``'s stored description (``stored_rank``)."""
        arms = " ".join(f"WHEN '{sid}' THEN {rank}" for sid, rank in sorted(self.ranks.items(), key=lambda kv: -kv[1]))
        return (
            f"CASE WHEN {var}.description IS NULL OR {var}.description = '' THEN -1 "
            f"WHEN {var}.description_source IS NULL THEN {self.top_rank} "
            f"ELSE CASE {var}.description_source {arms} ELSE 0 END END"
        )

    def replaces_cypher(self, var: str, text: str, source: str, rank: str) -> str:
        """Cypher predicate: a record with ``text`` from ``source`` of ``rank`` (Cypher expressions)
        replaces ``var``'s description (``replaces``). False when ``text`` is null or empty."""
        stored = self.stored_rank_cypher(var)
        return (
            f"({text} IS NOT NULL AND {text} <> '' AND ({rank} > {stored} OR ({rank} = {stored} "
            f"AND ({rank} > 0 OR {source} <= {var}.description_source))))"
        )

    def set_cypher(self, var: str, carry: str, text: str, source: str, rank: str) -> str:
        """Cypher clauses that apply the rule to ``var``: a ``WITH`` that decides once (``carry`` lists
        the variables the statement still needs, ``var`` among them), then the ``SET`` of the text and
        its source. Deciding first keeps the two properties together: a ``SET`` that tested each
        property in turn would see the other already changed."""
        return (
            f"WITH {carry}, {self.replaces_cypher(var, text, source, rank)} AS {_REPLACES_VAR}\n"
            f"SET {var}.description = CASE WHEN {_REPLACES_VAR} THEN {text} ELSE {var}.description END,\n"
            f"    {var}.description_source = CASE WHEN {_REPLACES_VAR} THEN {source} "
            f"ELSE {var}.description_source END"
        )

    def best_of_cypher(self, first: str, others: str) -> str:
        """Cypher expression: of the node ``first`` and the list of nodes ``others``, the one whose
        description the ranking keeps (its stored rank; equal ranks: the one whose source sorts first,
        then ``first``, then the node whose ``name`` sorts first). For merging nodes into one."""
        # Each candidate as [node, stored rank], so the rank is computed once per node.
        source_x, source_b = "coalesce(_dx[0].description_source, '')", "coalesce(_db[0].description_source, '')"
        beats = (
            f"_dx[1] > _db[1] OR (_dx[1] = _db[1] AND _db[0] <> {first} AND ({source_x} < {source_b} OR "
            f"({source_x} = {source_b} AND _dx[0].name < _db[0].name)))"
        )
        return (
            f"reduce(_db = [{first}, {self.stored_rank_cypher(first)}], "
            f"_dx IN [_dn IN {others} | [_dn, {self.stored_rank_cypher('_dn')}]] | "
            f"CASE WHEN {beats} THEN _dx ELSE _db END)[0]"
        )


# CVE and Vulnerability: NVD, CISA KEV, CISA ICS, then every other source.
CVE_DESCRIPTIONS = DescriptionRanking(
    name="cve",
    labels=("CVE", "Vulnerability"),
    groups=(("nvd",), ("cisa_kev",), ("cisa_ics",)),
)

# Malware, ThreatActor, Tool, Technique, Tactic: MITRE ATT&CK, the curated sources, then every other source.
ENTITY_DESCRIPTIONS = DescriptionRanking(
    name="entity",
    labels=("Malware", "ThreatActor", "Tool", "Technique", "Tactic"),
    groups=(("mitre_attck",), curated_source_ids()),
)

# The source a ResilMesh-native write (``Neo4jClient.merge_resilmesh_cve`` / ``merge_resilmesh_vulnerability``)
# names: the ResilMesh platform, the source the alert path writes as well. Not a registered feed, so it
# ranks below every one; its text is not in MISP.
RESILMESH_NATIVE_SOURCE = "resilmesh"


def ranking_for_label(label: str) -> Optional[DescriptionRanking]:
    """The ranking of ``label``'s descriptions, or None for a label without one."""
    for ranking in (CVE_DESCRIPTIONS, ENTITY_DESCRIPTIONS):
        if label in ranking.labels:
            return ranking
    return None
