#!/usr/bin/env python3
"""Import a curated package into MISP as one EdgeGuard event (2026-10).

A curated package is a JSON file of claims about entities that already exist in the graph,
for example ``2026-10-20_EdgeGuard_CoreIdeas_package.json``::

    {
      "name": "2026-10-20_EdgeGuard_CoreIdeas_package",
      "source": "coreideas",
      "tlp": "amber",
      "entities": [
        {"kind": "threat_actor", "name": "apt29",
         "claims": [{"p": "uses_technique", "o": "T1566", "src": "coreideas", "id": "<record id>"}]},
        {"kind": "malware", "name": "emotet",
         "claims": [{"p": "exploits", "o": "CVE-2017-11882", "src": "misp_galaxy", "id": "<cluster uuid>"}]}
      ]
    }

``name`` must contain "EdgeGuard" (the MISP→Neo4j sync discovers EdgeGuard events by title).
``source`` is the package's source and must be a registered curated source
(``source_type="curated"`` in ``src/source_registry.py``: ``coreideas``, ``misp_galaxy``); its
``curated_label`` labels the links the claims create (``coreideas_curated``; ``curated_other``
for a source without one). ``tlp`` is required: the package's TLP level marks the link of every
claim (``r.tlp``) and the STIX relationship exported from it. ``name`` of an entity is the
canonical name of the existing node (the package builder aligns names). Each claim's ``src`` is
the source that asserts it (defaults to the package's source) and ``id`` that source's record
id. Predicates per subject: see ``relationship_provenance.CURATED_PREDICATES``.

A claim is rejected (reported, not imported) when its predicate does not fit its subject, it
has no object, its object id is malformed (technique ``T1234`` / ``T1234.123``, tool ``S1234``,
CVE ``CVE-YYYY-NNNN``; upper or lower case, as the sync matches them upper-case), or its source is
not a registered curated source: the claim's source goes into ``r.sources`` / ``r.source_refs``
and the STIX export, so no other name may reach them.

The event is created unpublished, for the creating organisation only, with the tags
``EdgeGuard``, the package source's ``source:*`` tag and ``tlp:<level>``. Each entity becomes one
``threat-actor`` / ``malware-type`` attribute, tagged with the same source and TLP, whose comment
carries its claims (``CURATED_CLAIMS:{...}``). The sync turns every claim into a relationship,
MATCHing both ends: a link the claim creates gets the package's curated label at confidence
0.85, an existing link keeps its label and confidence and gains the claim's provenance. The
attribute itself is not merged as a node, so a package never creates nodes and never changes
the node it names. Removing the layer: see ``docs/RUNBOOK.md``, "Importing a curated package".

Usage::

    python scripts/import_curated_package.py PACKAGE.json            # validate and summarise
    python scripts/import_curated_package.py PACKAGE.json --push     # create the MISP event

``--push`` reads ``MISP_URL`` / ``MISP_API_KEY`` (and ``EDGEGUARD_SSL_VERIFY``) like the
collectors, and refuses to create a second event with the same name.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from relationship_provenance import CURATED_CLAIMS_PREFIX, CURATED_PREDICATES  # noqa: E402
from source_registry import (  # noqa: E402
    canonical_source_id,
    curated_label_for,
    curated_source_ids,
    get_source,
    is_curated_source,
)

KINDS = {"threat_actor": ("ThreatActor", "threat-actor"), "malware": ("Malware", "malware-type")}
TLP_LEVELS = ("clear", "white", "green", "amber", "amber+strict", "red")
# The MISP comment column holds 64 KB; keep a margin for the JSON wrapper.
COMMENT_BUDGET = 60_000
# 2026-10: the id format of a claim's object, by object label, with the form shown in messages.
# Checked on the id as the sync keys it (trimmed, upper-case); a malformed id can match no node.
ID_FORMATS = {
    "Technique": (re.compile(r"T\d{4}(\.\d{3})?", re.ASCII), "T1234 or T1234.123"),
    "Tool": (re.compile(r"S\d{4}", re.ASCII), "S1234"),
    "CVE": (re.compile(r"CVE-\d{4}-\d{4,}", re.ASCII), "CVE-YYYY-NNNN"),
}


def _tlp_level(package: Dict[str, Any]) -> str:
    """The package's TLP level, lower-case (``""`` when it states none)."""
    return str(package.get("tlp") or "").strip().lower()


def _claim_problem(claim: Any, subject_label: str, default_src: Optional[str]) -> Optional[Tuple[str, str]]:
    """``(reason, message)`` when ``claim`` cannot be imported for a ``subject_label`` subject, else ``None``.

    ``default_src`` is the package's source, which asserts a claim that names none.
    """
    if not isinstance(claim, dict):
        return "shape", "not an object"
    predicate = str(claim.get("p") or "").strip().lower()
    if subject_label not in CURATED_PREDICATES.get(predicate, {}):
        return "predicate", f"predicate {predicate!r} not allowed for {subject_label}"
    obj = str(claim.get("o") or "").strip()
    if not obj:
        return "object", "no object"
    object_label = CURATED_PREDICATES[predicate][subject_label][1]
    id_format = ID_FORMATS.get(object_label)
    if id_format is not None and not id_format[0].fullmatch(obj.upper()):
        return "id", f"{object_label} id {obj!r} is malformed (expected {id_format[1]})"
    # 2026-10: only a registered curated source may assert a claim — the claim's source goes into
    # ``r.sources`` / ``r.source_refs`` and the STIX export, so no other name may reach them.
    source = canonical_source_id(claim.get("src")) or default_src
    if not is_curated_source(source):
        return "source", (
            f"source {source!r} is not a registered curated source (allowed: {', '.join(curated_source_ids())})"
        )
    return None


def validate(package: Any) -> Tuple[List[str], List[str], Dict[str, Any]]:
    """``(errors, warnings, summary)`` for a parsed package. Errors block ``--push``."""
    errors: List[str] = []
    warnings: List[str] = []
    if not isinstance(package, dict):
        return ["the package must be a JSON object"], warnings, {}
    name = str(package.get("name") or "").strip()
    if not name:
        errors.append("missing 'name'")
    elif "edgeguard" not in name.lower():
        errors.append(f"name {name!r} must contain 'EdgeGuard' — the sync discovers EdgeGuard events by title")
    source = canonical_source_id(package.get("source"))
    registered = get_source(source) if source else None
    if not source:
        errors.append("missing 'source'")
    elif registered is None:
        # 2026-10: the package's source asserts every claim that names none, so it must be a
        # registered curated source as well (before, any name was imported as ``curated_other``).
        errors.append(
            f"source {source!r} is not a registered curated source (allowed: {', '.join(curated_source_ids())}); "
            "register it in src/source_registry.py first"
        )
    elif registered.source_type != "curated":
        errors.append(f"source {source!r} is a feed ({registered.source_type}), not a curated source")
    tlp = package.get("tlp")
    # 2026-10: the level is required — it marks every claim's link (``r.tlp``) and the STIX
    # relationship built from it, so a package without one would export as the default.
    if tlp is None or not str(tlp).strip():
        errors.append(f"missing 'tlp': a curated package must state its TLP level ({', '.join(TLP_LEVELS)})")
    elif _tlp_level(package) not in TLP_LEVELS:
        errors.append(f"tlp {tlp!r} is not one of {', '.join(TLP_LEVELS)}")
    entities = package.get("entities")
    if not isinstance(entities, list) or not entities:
        errors.append("'entities' must be a non-empty list")
        entities = []

    by_predicate: Counter = Counter()
    by_source: Counter = Counter()
    skipped_by_reason: Counter = Counter()
    seen_subjects = set()
    kept = rejected = 0
    for n, entity in enumerate(entities):
        where = f"entities[{n}]"
        if not isinstance(entity, dict):
            errors.append(f"{where}: not an object")
            continue
        kind = entity.get("kind")
        subject = str(entity.get("name") or "").strip()
        if kind not in KINDS:
            errors.append(f"{where}: kind {kind!r} is not one of {', '.join(KINDS)}")
            continue
        if not subject:
            errors.append(f"{where}: no name")
            continue
        if (kind, subject.lower()) in seen_subjects:
            errors.append(f"{where}: {kind} {subject!r} appears twice — merge its claims into one entity")
        seen_subjects.add((kind, subject.lower()))
        claims = entity.get("claims") or []
        good = []
        for m, claim in enumerate(claims):
            problem = _claim_problem(claim, KINDS[kind][0], source)
            if problem is not None:
                rejected += 1
                skipped_by_reason[problem[0]] += 1
                warnings.append(f"{where}.claims[{m}] skipped: {problem[1]}")
                continue
            good.append(claim)
            by_predicate[str(claim.get("p")).strip().lower()] += 1
            by_source[canonical_source_id(claim.get("src")) or source or "?"] += 1
        kept += len(good)
        if len(_comment(good, source)) > COMMENT_BUDGET:
            errors.append(f"{where}: {len(good)} claims exceed the {COMMENT_BUDGET}-character comment budget")
        if not good:
            warnings.append(f"{where}: {kind} {subject!r} has no valid claim and is not imported")
    summary = {
        "name": name,
        "source": source,
        "label": curated_label_for(source),
        "entities": len(seen_subjects),
        "claims": kept,
        "claims_skipped": rejected,
        "claims_skipped_by_reason": dict(skipped_by_reason),
        "by_predicate": dict(by_predicate),
        "by_claim_source": dict(by_source),
    }
    return errors, warnings, summary


def _comment(claims: List[Dict[str, Any]], default_src: str | None = None) -> str:
    """``CURATED_CLAIMS:{"c": [...]}`` with every claim naming its source.

    A claim without ``src`` gets the package's source written out: the sync maps a
    ``source:*`` tag it does not know to ``misp``, so an unregistered package's own name
    would otherwise be lost from ``r.sources``.
    """
    compact = []
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        entry = {k: claim[k] for k in ("p", "o", "src", "id") if claim.get(k) not in (None, "")}
        if "src" not in entry and default_src:
            entry["src"] = default_src
        compact.append(entry)
    return CURATED_CLAIMS_PREFIX + json.dumps({"c": compact}, separators=(",", ":"), ensure_ascii=False)


def _index_infos(payload: Any) -> List[str]:
    """Event titles in a ``search_index`` answer: a list of events, ``{"response": [...]}``, or
    entries wrapped as ``{"Event": {...}}`` (MISP versions differ)."""
    if isinstance(payload, dict):
        payload = payload.get("response", [payload])
    infos: List[str] = []
    for entry in payload if isinstance(payload, list) else []:
        if not isinstance(entry, dict):
            continue
        wrapped = entry.get("Event")
        event: Dict[str, Any] = wrapped if isinstance(wrapped, dict) else entry
        info = event.get("info")
        if isinstance(info, str):
            infos.append(info)
    return infos


def build_event(package: Dict[str, Any]) -> Dict[str, Any]:
    """The MISP event (REST JSON) for a validated package."""
    source = canonical_source_id(package.get("source"))
    registered = get_source(source) if source else None
    source_tag = registered.misp_tag if registered else f"source:{source}"
    event_tags = [{"name": "EdgeGuard"}, {"name": source_tag}]
    # 2026-10: the TLP tag goes on every attribute as well as on the event — the sync reads an
    # attribute's own tags, and the level marks each claim's link (``r.tlp``) and its STIX SRO.
    attribute_tags = [{"name": source_tag}]
    if _tlp_level(package):
        event_tags.append({"name": f"tlp:{_tlp_level(package)}"})
        attribute_tags.append({"name": f"tlp:{_tlp_level(package)}"})
    attributes = []
    for entity in package.get("entities") or []:
        kind = entity.get("kind")
        if kind not in KINDS:
            continue
        good = [c for c in entity.get("claims") or [] if _claim_problem(c, KINDS[kind][0], source) is None]
        if not good:
            continue
        attributes.append(
            {
                "type": KINDS[kind][1],
                "value": str(entity["name"]).strip(),
                "comment": _comment(good, source),
                "to_ids": False,
                "Tag": [dict(tag) for tag in attribute_tags],
            }
        )
    return {
        "Event": {
            "info": str(package["name"]).strip(),
            "distribution": 0,  # this organisation only
            "threat_level_id": 4,  # undefined
            "analysis": 2,  # completed
            "published": False,
            "Tag": event_tags,
            "Attribute": attributes,
        }
    }


def _push(event: Dict[str, Any]) -> int:
    from pymisp import MISPEvent, PyMISP  # deferred: the dry run needs no MISP client

    url, key = os.environ.get("MISP_URL"), os.environ.get("MISP_API_KEY")
    if not url or not key:
        print("MISP_URL and MISP_API_KEY must be set for --push", file=sys.stderr)
        return 2
    verify = os.environ.get("EDGEGUARD_SSL_VERIFY", "true").strip().lower() not in ("0", "false", "no", "off")
    misp = PyMISP(url, key, ssl=verify)
    info = event["Event"]["info"]
    existing = misp.search_index(eventinfo=info, pythonify=False)
    if info in _index_infos(existing):
        print(f"an event named {info!r} already exists — delete it first or rename the package", file=sys.stderr)
        return 1
    misp_event = MISPEvent()
    misp_event.from_dict(**event)
    created = misp.add_event(misp_event, pythonify=False)
    if not isinstance(created, dict) or "errors" in created:
        print(f"MISP refused the event: {json.dumps(created)[:500]}", file=sys.stderr)
        return 1
    event_id = (created.get("Event") or {}).get("id")
    print(f"created MISP event {event_id} {info!r} with {len(event['Event']['Attribute'])} attributes")
    return 0


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("package", type=Path, help="the package JSON file")
    parser.add_argument("--push", action="store_true", help="create the MISP event (default: validate only)")
    args = parser.parse_args(argv)
    try:
        package = json.loads(args.package.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"cannot read {args.package}: {e}", file=sys.stderr)
        return 2
    errors, warnings, summary = validate(package)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    for w in warnings[:50]:
        print(f"warning: {w}", file=sys.stderr)
    if len(warnings) > 50:
        print(f"warning: … {len(warnings) - 50} more", file=sys.stderr)
    for err in errors:
        print(f"error: {err}", file=sys.stderr)
    if errors:
        return 1
    if not args.push:
        print("valid — dry run, nothing written (add --push to create the MISP event)")
        return 0
    return _push(build_event(package))


if __name__ == "__main__":
    sys.exit(main())
