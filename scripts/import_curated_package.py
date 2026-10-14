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
``source`` is the package's source (a registered curated source such as ``coreideas``; any
other name is imported with the label ``curated_other``). ``name`` of an entity is the
canonical name of the existing node (the package builder aligns names). Each claim's ``src``
is the source that asserts it (defaults to the package's source) and ``id`` that source's
record id. Predicates per subject: see ``relationship_provenance.CURATED_PREDICATES``.

The event is created unpublished, for the creating organisation only, with the tags
``EdgeGuard`` and the package source's ``source:*`` tag (plus ``tlp:<level>`` when given). Each
entity becomes one ``threat-actor`` / ``malware-type`` attribute whose comment carries its
claims (``CURATED_CLAIMS:{...}``). The sync turns every claim into a relationship labelled
with the package's curated label at confidence 0.85, MATCHing both ends; the attribute itself
is not merged as a node, so a package never creates nodes and never changes the node it names. Removing the layer later = deleting the
event and re-feeding.

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
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from relationship_provenance import CURATED_CLAIMS_PREFIX, CURATED_PREDICATES  # noqa: E402
from source_registry import canonical_source_id, curated_label_for, get_source  # noqa: E402

KINDS = {"threat_actor": ("ThreatActor", "threat-actor"), "malware": ("Malware", "malware-type")}
TLP_LEVELS = ("clear", "white", "green", "amber", "amber+strict", "red")
# The MISP comment column holds 64 KB; keep a margin for the JSON wrapper.
COMMENT_BUDGET = 60_000


def _claim_ok(claim: Any, subject_label: str) -> Tuple[bool, str]:
    if not isinstance(claim, dict):
        return False, "not an object"
    predicate = str(claim.get("p") or "").strip().lower()
    if subject_label not in CURATED_PREDICATES.get(predicate, {}):
        return False, f"predicate {predicate!r} not allowed for {subject_label}"
    if not str(claim.get("o") or "").strip():
        return False, "no object"
    return True, ""


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
        warnings.append(f"source {source!r} is not registered: the claims get the label 'curated_other'")
    elif registered.source_type != "curated":
        errors.append(f"source {source!r} is a feed ({registered.source_type}), not a curated source")
    tlp = package.get("tlp")
    if tlp is not None and str(tlp).lower() not in TLP_LEVELS:
        errors.append(f"tlp {tlp!r} is not one of {', '.join(TLP_LEVELS)}")
    entities = package.get("entities")
    if not isinstance(entities, list) or not entities:
        errors.append("'entities' must be a non-empty list")
        entities = []

    by_predicate: Counter = Counter()
    by_source: Counter = Counter()
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
            ok, why = _claim_ok(claim, KINDS[kind][0])
            if not ok:
                rejected += 1
                warnings.append(f"{where}.claims[{m}] skipped: {why}")
                continue
            good.append(claim)
            by_predicate[str(claim.get("p")).strip().lower()] += 1
            by_source[canonical_source_id(claim.get("src")) or source or "?"] += 1
        kept += len(good)
        if len(_comment(good)) > COMMENT_BUDGET:
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
        "by_predicate": dict(by_predicate),
        "by_claim_source": dict(by_source),
    }
    return errors, warnings, summary


def _comment(claims: List[Dict[str, Any]]) -> str:
    compact = [
        {k: claim[k] for k in ("p", "o", "src", "id") if claim.get(k) not in (None, "")}
        for claim in claims
        if isinstance(claim, dict)
    ]
    return CURATED_CLAIMS_PREFIX + json.dumps({"c": compact}, separators=(",", ":"), ensure_ascii=False)


def build_event(package: Dict[str, Any]) -> Dict[str, Any]:
    """The MISP event (REST JSON) for a validated package."""
    source = canonical_source_id(package.get("source"))
    registered = get_source(source) if source else None
    source_tag = registered.misp_tag if registered else f"source:{source}"
    event_tags = [{"name": "EdgeGuard"}, {"name": source_tag}]
    if package.get("tlp"):
        event_tags.append({"name": f"tlp:{str(package['tlp']).lower()}"})
    attributes = []
    for entity in package.get("entities") or []:
        kind = entity.get("kind")
        if kind not in KINDS:
            continue
        good = [c for c in entity.get("claims") or [] if _claim_ok(c, KINDS[kind][0])[0]]
        if not good:
            continue
        attributes.append(
            {
                "type": KINDS[kind][1],
                "value": str(entity["name"]).strip(),
                "comment": _comment(good),
                "to_ids": False,
                "Tag": [{"name": source_tag}],
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
    if any((e.get("info") or "") == info for e in (existing or []) if isinstance(e, dict)):
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
