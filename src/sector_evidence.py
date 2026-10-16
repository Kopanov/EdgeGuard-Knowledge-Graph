"""The evidence behind a link to a Sector: which label it carries and how confident it is (2026-10-16).

A link to a ``Sector`` node says one of two things:

* ``AFFECTS`` (``CVE`` or ``Vulnerability`` → ``Sector``): the vulnerable product is used in the sector;
* ``TARGETS`` (``Indicator``, ``ThreatActor`` or ``Malware`` → ``Sector``): the item was reported in
  connection with attacks on the sector.

The relationship types are unchanged (the ResilMesh contract). What a link rests on is its evidence
label, ``r.match_type``, with a confidence that follows from the label through one fixed table
(``LABEL_CONFIDENCE``), whoever writes the link: the MISP → Neo4j sync (one row per attribute and zone)
and ``build_relationships`` (Q7a-Q7d, from the node's zones) therefore agree.

* ``zone_classification`` (0.5): EdgeGuard's own inference from text (sector keywords in an NVD
  description, CPE vendors and products, the KEV vendor and product, OTX pulse text, a feed's malware
  family), and a foreign MISP zone tag.
* ``advisory_sector`` (0.9): CISA's ICS advisory names the sector in its "Critical infrastructure
  sectors" note, i.e. CISA states that the affected product is deployed there. It is a deployment
  statement, never a targeting claim: it is allowed on ``AFFECTS`` only, and the ``TARGETS`` map of
  ``STATEMENT_LABELS`` has no entry for it, so no writer can put it on a ``TARGETS`` link.

One link per (node, relationship type, sector) carries the strongest label among the records that gave
the sector, as for every other link type; ``r.sources`` names every feed that gave the sector, by
statement or by inference, and only those feeds. Which feed stated a sector is recorded on that feed's
``SOURCED_FROM`` edge of the node (``stated_zones``), next to the zones its records gave (``zones``).

``r.source_refs`` of a sector link cites only the records that gave the sector. A stating feed's records
can each state other sectors (a CVE named by an ICS advisory for Energy and a medical advisory for
Healthcare), so the feed's ``SOURCED_FROM`` edge also records which of its records stated which sector
(the edge property ``stated_refs``, entries ``"<zone>|<source ref>"`` built by ``stated_refs``), and a
sector link takes the feed's references for its sector from there (``zone_refs``). A feed that records none per sector (an inferring feed, or an
edge written before 2026-10-16) gives all of its references.

The confidence of the CISA label must stay above ``zone_classification``'s: the sync keeps the label of
the row with the higher confidence, so an equal value would let an inferred row take the label of a
stated link (asserted at import).

Standard library and ``source_registry`` only: the acceptance script reads the table.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from source_registry import get_source

ZONE_CLASSIFICATION = "zone_classification"
ADVISORY_SECTOR = "advisory_sector"

# The evidence labels a link to a Sector may carry, with the confidence each one gives the link.
LABEL_CONFIDENCE: Dict[str, float] = {
    ZONE_CLASSIFICATION: 0.5,
    ADVISORY_SECTOR: 0.9,
}

# Per relationship type: the feeds whose sector is their own statement, and the label it gives the link.
# ``TARGETS`` has none: a deployment sector is no targeting claim.
STATEMENT_LABELS: Dict[str, Dict[str, str]] = {
    "AFFECTS": {"cisa_ics": ADVISORY_SECTOR},
    "TARGETS": {},
}

# Feeds whose every specific zone is their own statement (no keyword detection runs on their records):
# CISA ICS maps the advisory's "Critical infrastructure sectors" note through a fixed table
# (``collectors.cisa_ics_collector.ICS_SECTOR_ZONE_MAP``).
STATING_FEEDS = frozenset({"cisa_ics"})

# The "no sector" marker: never a sector, never stated.
GLOBAL_ZONE = "global"

# Between the zone and the record reference in ``stated_refs`` (``"healthcare|cisa_ics:ICSMA-26-283-01"``).
# A zone never contains it, so the reference is everything after the first one.
STATED_REF_SEPARATOR = "|"


def _check_table() -> None:
    """Import-time checks of the table: a typo or a weak statement label fails at import, not in a run."""
    for feed in STATING_FEEDS | {f for labels in STATEMENT_LABELS.values() for f in labels}:
        src = get_source(feed)
        if src is None or src.canonical_id != feed:
            raise ValueError(f"sector_evidence: {feed!r} is not a canonical source_registry id")
    floor = LABEL_CONFIDENCE[ZONE_CLASSIFICATION]
    for rel_type, labels in STATEMENT_LABELS.items():
        for feed, label in labels.items():
            if label not in LABEL_CONFIDENCE:
                raise ValueError(f"sector_evidence: {rel_type} label {label!r} of {feed!r} has no confidence")
            if not LABEL_CONFIDENCE[label] > floor:
                raise ValueError(
                    f"sector_evidence: {label!r} must be above {ZONE_CLASSIFICATION!r} ({floor}): the sync keeps "
                    "the label of the row with the higher confidence"
                )
    if any(ADVISORY_SECTOR == label for label in STATEMENT_LABELS.get("TARGETS", {}).values()):
        raise ValueError("sector_evidence: advisory_sector is a deployment statement and never labels TARGETS")
    for label, value in LABEL_CONFIDENCE.items():
        if not (0.0 <= value <= 1.0) or '"' in label or "'" in label:
            raise ValueError(f"sector_evidence: label {label!r} / confidence {value!r} is invalid")


_check_table()


def _zone_list(zones: Any) -> List[str]:
    """``zones`` as a list of strings: ``[]`` for null, ``[x]`` for a single string."""
    if zones is None:
        return []
    if isinstance(zones, str):
        return [zones] if zones else []
    return [str(z) for z in zones if z is not None and str(z) != ""]


def stated_zones(source_id: Optional[str], zones: Any) -> List[str]:
    """The zones of a record that its feed states itself, sorted; ``[]`` for a feed that does not.

    For a feed of ``STATING_FEEDS`` every specific zone of the record (``global`` is no sector); for
    every other feed none, since EdgeGuard inferred them.
    """
    if source_id not in STATING_FEEDS:
        return []
    return sorted({z.lower() for z in _zone_list(zones) if z.lower() != GLOBAL_ZONE})


def link_evidence(
    source_id: Optional[str], zone: str, stated: Optional[Iterable[str]], rel_type: str
) -> Tuple[str, float]:
    """``(label, confidence)`` of the link ``rel_type`` to the sector ``zone`` that a record of ``source_id``
    gives, whose stated zones are ``stated``: the feed's statement label for ``rel_type`` when it stated
    the zone, otherwise ``zone_classification``."""
    label = STATEMENT_LABELS.get(rel_type, {}).get(source_id or "")
    if label is not None and zone in set(_zone_list(list(stated or []))):
        return label, LABEL_CONFIDENCE[label]
    return ZONE_CLASSIFICATION, LABEL_CONFIDENCE[ZONE_CLASSIFICATION]


def stated_refs(stated: Optional[Iterable[str]], refs_by_zone: Mapping[str, Iterable[str]]) -> List[str]:
    """Which of a record's references stated which of its stated zones, as sorted ``"<zone>|<ref>"`` strings.

    ``refs_by_zone`` maps a zone to the references of the records that gave it (CISA ICS: the advisories
    whose sector note names it, ``cisa_ics:<advisory id>``); only the zones in ``stated`` are kept. The
    writer accumulates the result on the feed's ``SOURCED_FROM`` edge (``stated_refs``), and ``zone_refs``
    reads it back for one sector.
    """
    stated_set = set(_zone_list(list(stated or [])))
    out = {
        f"{zone}{STATED_REF_SEPARATOR}{ref}"
        for zone, refs in refs_by_zone.items()
        if zone in stated_set
        for ref in refs
        if isinstance(ref, str) and ref
    }
    return sorted(out)


def zone_refs(stated: Optional[Iterable[str]], zone: str, default: Iterable[str]) -> List[str]:
    """The references behind the sector ``zone``: those ``stated`` (``stated_refs`` entries) records for
    the zone, in their sorted order, else ``default`` (all of the record's references: a feed that records
    none per sector, or a record written before 2026-10-16). The Cypher of
    ``relationship_provenance.zone_prov_with`` applies the same rule to a ``SOURCED_FROM`` edge."""
    prefix = f"{zone}{STATED_REF_SEPARATOR}"
    recorded = [x[len(prefix) :] for x in (stated or []) if isinstance(x, str) and x.startswith(prefix)]
    return recorded if recorded else list(default)


def cypher_params(rel_type: str) -> Dict[str, Any]:
    """The parameters the Cypher of ``label_with`` / ``label_set`` reads for ``rel_type``."""
    return {
        "sector_statements": dict(STATEMENT_LABELS[rel_type]),
        "sector_confidence": dict(LABEL_CONFIDENCE),
    }


def label_with(node_var: str, carry: str = "zone_name, _feeds, _prov_refs, _prov_events") -> str:
    """Cypher ``WITH``: binds ``_label``, the strongest statement label among the feeds that stated the
    sector (``_stated_by``, bound by ``relationship_provenance.zone_prov_with``), else
    ``zone_classification``. Reads ``$sector_statements`` / ``$sector_confidence`` (``cypher_params``).
    The feeds are read in sorted order, so a tie between two labels of equal confidence does not depend
    on the order of the node's ``SOURCED_FROM`` edges. Double quotes only (``apoc.periodic.iterate``)."""
    return (
        f"WITH {node_var}, {carry}, "
        f'reduce(_b = "{ZONE_CLASSIFICATION}", _f IN apoc.coll.sort(_stated_by) | '
        "CASE WHEN $sector_statements[_f] IS NOT NULL "
        "AND $sector_confidence[$sector_statements[_f]] > $sector_confidence[_b] "
        "THEN $sector_statements[_f] ELSE _b END) AS _label "
    )


def label_set(carry: str, rel_var: str = "r") -> str:
    """Cypher placed right after the ``MERGE`` of the link ``rel_var``: a ``WITH`` that keeps the stronger
    of the link's stored label and ``_label``, then the ``SET`` of the label and the confidence the
    table gives it (the caller continues the ``SET`` with ``, ...``). ``carry`` lists the variables the
    statement still needs, ``rel_var`` among them.

    A stored label outside the table (a curated or partner label) is kept with its confidence; a stored
    label of the table is kept only when it is stronger than the computed one, so a link CISA stated
    keeps ``advisory_sector`` on a graph whose ``SOURCED_FROM`` edges predate ``stated_zones``. A link
    without a label (written before every edge stated its evidence) takes the computed one. The
    confidence is the table's value of the label kept: an old ``zone_classification`` link at 1.0 comes
    back to 0.5."""
    r = rel_var
    return (
        f"WITH {carry}, CASE "
        f"WHEN {r}.match_type IS NOT NULL AND NOT {r}.match_type IN keys($sector_confidence) THEN {r}.match_type "
        f"WHEN {r}.match_type IS NOT NULL AND $sector_confidence[{r}.match_type] > $sector_confidence[_label] "
        f"THEN {r}.match_type ELSE _label END AS _kept "
        f"SET {r}.match_type = _kept, {r}.confidence_score = coalesce($sector_confidence[_kept], {r}.confidence_score)"
    )
