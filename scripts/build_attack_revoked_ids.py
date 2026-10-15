#!/usr/bin/env python3
"""Build ``src/reference/attack_revoked_ids.json``: revoked MITRE ATT&CK ids and their successors (2026-10).

MITRE ATT&CK keeps replaced objects in its data. A revoked object carries ``revoked: true`` and a
``revoked-by`` relationship to the object that replaces it; its ATT&CK id stays in use in the
feeds (OTX pulses still name ``T1086`` for PowerShell, which ATT&CK moved to ``T1059.001``).
EdgeGuard translates a revoked technique id to its successor wherever a feed names a technique by
id (``src/attack_revoked.py``). This script builds the map that translation reads.

Input: the MITRE galaxies of MISP (MISP/misp-galaxy), captured from the EdgeGuard MISP instance
(``POST /galaxy_clusters/restSearch``) as ``misp_galaxy_<galaxy>_<YYYYMMDD>.json``. The newest file
of each of ``mitre-attack-pattern``, ``mitre-intrusion-set``, ``mitre-malware`` and ``mitre-tool``
is required; the newest ``mitre-ics-*`` files are read when present. In each galaxy cluster a
``GalaxyClusterRelation`` with ``referenced_galaxy_cluster_type == "revoked-by"`` names the
successor's cluster uuid, and the ATT&CK id is the suffix of the cluster value
(``"PowerShell - T1086"``).

The map lists every revoked technique (``T1234`` / ``T1234.123``), group (``G1234``) and software
(``S1234``) id with its successor id and both names. A chain (A revoked by B, B revoked by C) is
followed to its last element, which is recorded as the successor (``via`` lists the ids in between).
A revoked id is left out of the map, and listed under ``excluded`` with the reason, when its chain
loops, its successor is not in the inputs, the successor is another kind of object, the cluster
names two successors, or a cluster that is not revoked carries the same id. The output is sorted
and does not depend on the order of the clusters or of the input files.

Usage::

    python scripts/build_attack_revoked_ids.py RAW_DIR
    python scripts/build_attack_revoked_ids.py RAW_DIR --version 2026.10.15 --output src/reference/attack_revoked_ids.json

``RAW_DIR`` is the folder of the galaxy captures, e.g. ``Core-Ideas_CTI/data/open/raw``. A folder
inside a ``restricted`` tree is refused. See ``docs/RUNBOOK.md``, "Rebuilding the ATT&CK
revoked-id map", for when to rebuild.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO / "src" / "reference" / "attack_revoked_ids.json"

REQUIRED_GALAXIES = ("mitre-attack-pattern", "mitre-intrusion-set", "mitre-malware", "mitre-tool")
# ``mitre-ics-groups`` / ``mitre-ics-software``: read when present. Their clusters carry no ATT&CK
# id in the value today, so they add no entry, but a future capture may.
OPTIONAL_GALAXY_PREFIX = "mitre-ics-"
_CAPTURE_NAME = re.compile(r"^misp_galaxy_(?P<galaxy>[a-z0-9-]+)_(?P<date>\d{8})\.json$")
# The ATT&CK id is the suffix of the cluster value: "PowerShell - T1086", "APT34 - G0057".
_VALUE_WITH_ID = re.compile(r"^(?P<name>.+?) - (?P<id>[A-Z]{1,2}\d{4}(?:\.\d{3})?)$")
# The kinds of id the map holds (section name → full-match pattern).
SECTIONS: Dict[str, "re.Pattern[str]"] = {
    "techniques": re.compile(r"T\d{4}(?:\.\d{3})?"),
    "groups": re.compile(r"G\d{4}"),
    "software": re.compile(r"S\d{4}"),
}
REVOKED_BY = "revoked-by"

NOTICES = {
    "misp_galaxy": (
        "Built from the MITRE galaxies of MISP (https://github.com/MISP/misp-galaxy). The galaxy JSON "
        "files are dual-licensed under CC0 1.0 Universal and a BSD 2-Clause licence; this map uses them "
        "under CC0 1.0."
    ),
    "mitre_attack": (
        "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
    ),
}
DESCRIPTION = (
    "Revoked MITRE ATT&CK ids and the id that replaces each (techniques, groups, software). EdgeGuard "
    "translates a revoked technique id to its successor wherever a feed names a technique by id "
    "(src/attack_revoked.py)."
)


class BuildError(Exception):
    """The inputs cannot be read or do not form a map."""


def section_of(attack_id: str) -> Optional[str]:
    """The map section an ATT&CK id belongs to (``techniques`` / ``groups`` / ``software``), else ``None``."""
    for section, pattern in SECTIONS.items():
        if pattern.fullmatch(attack_id):
            return section
    return None


def _split_value(value: Any) -> Optional[Tuple[str, str]]:
    """``(name, ATT&CK id)`` from a cluster value such as ``"PowerShell - T1086"``."""
    match = _VALUE_WITH_ID.match(str(value or "").strip())
    if not match:
        return None
    return match.group("name").strip(), match.group("id")


def _version(cluster: Dict[str, Any]) -> int:
    try:
        return int(str(cluster.get("version") or "0"))
    except ValueError:
        return 0


def _external_ids(cluster: Dict[str, Any]) -> List[str]:
    return [
        str(el.get("value"))
        for el in cluster.get("GalaxyElement") or []
        if isinstance(el, dict) and el.get("key") == "external_id" and el.get("value")
    ]


def clusters_of(payload: Any) -> List[Dict[str, Any]]:
    """The galaxy clusters of a capture file (``{"payload": {"response": [...]}}``) or of a raw
    ``galaxy_clusters/restSearch`` answer (``{"response": [...]}`` or a list)."""
    if isinstance(payload, dict) and "payload" in payload:
        payload = payload["payload"]
    if isinstance(payload, dict):
        payload = payload.get("response", [])
    if not isinstance(payload, list):
        raise BuildError("no list of galaxy clusters found")
    out = []
    for entry in payload:
        cluster = entry.get("GalaxyCluster", entry) if isinstance(entry, dict) else None
        if isinstance(cluster, dict) and cluster.get("uuid"):
            out.append(cluster)
    return out


def build_map(clusters: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """The revoked-id sections, the excluded ids and the counts for a set of galaxy clusters.

    Pure function of the clusters (their order does not matter). Returns ``{"techniques": {...},
    "groups": {...}, "software": {...}, "excluded": [...], "counts": {...}, "notes": [...]}``.
    """
    # One cluster per uuid. MISP keeps an older copy of a renamed cluster under the same uuid
    # ("Windows Permissions - T1222.001" next to its earlier name); the highest version is current.
    by_uuid: Dict[str, Dict[str, Any]] = {}
    notes: List[str] = []
    for cluster in clusters:
        uuid = str(cluster["uuid"])
        kept = by_uuid.get(uuid)
        if kept is None:
            by_uuid[uuid] = cluster
            continue
        old, new = _split_value(kept.get("value")), _split_value(cluster.get("value"))
        if old and new and old[1] != new[1]:
            raise BuildError(f"cluster {uuid} carries two ATT&CK ids: {old[1]} and {new[1]}")
        if (_version(cluster), str(cluster.get("value"))) > (_version(kept), str(kept.get("value"))):
            by_uuid[uuid] = cluster

    ident: Dict[str, Tuple[str, str]] = {}  # uuid -> (name, ATT&CK id)
    for uuid, cluster in by_uuid.items():
        parsed = _split_value(cluster.get("value"))
        if parsed is None:
            continue
        ext = _external_ids(cluster)
        if ext and parsed[1] not in ext:
            notes.append(f"{parsed[1]}: value suffix differs from external_id {ext}; the value suffix is used")
        ident[uuid] = parsed

    successors: Dict[str, List[str]] = {}
    for uuid, cluster in by_uuid.items():
        targets = sorted(
            {
                str(rel.get("referenced_galaxy_cluster_uuid"))
                for rel in cluster.get("GalaxyClusterRelation") or []
                if isinstance(rel, dict)
                and rel.get("referenced_galaxy_cluster_type") == REVOKED_BY
                and rel.get("referenced_galaxy_cluster_uuid")
            }
        )
        if targets:
            successors[uuid] = targets

    live_ids = {attack_id for uuid, (_, attack_id) in ident.items() if uuid not in successors}
    sections: Dict[str, Dict[str, Dict[str, Any]]] = {name: {} for name in SECTIONS}
    excluded: List[Dict[str, str]] = []
    revoked_uuid_of: Dict[str, str] = {}

    def exclude(attack_id: str, reason: str) -> None:
        excluded.append({"id": attack_id, "reason": reason})

    for uuid in sorted(successors, key=lambda u: (ident.get(u, ("", ""))[1], u)):
        if uuid not in ident:
            notes.append(f"revoked cluster {uuid} has no ATT&CK id in its value; skipped")
            continue
        name, attack_id = ident[uuid]
        section = section_of(attack_id)
        if section is None:
            continue  # tactics, mitigations, campaigns: not translated
        if attack_id in revoked_uuid_of:
            exclude(attack_id, f"two revoked clusters carry this id ({revoked_uuid_of[attack_id]}, {uuid})")
            sections[section].pop(attack_id, None)
            continue
        revoked_uuid_of[attack_id] = uuid
        if attack_id in live_ids:
            exclude(attack_id, "a cluster that is not revoked carries the same id")
            continue
        # Follow the chain to its last element; a loop or a missing link excludes the id.
        path: List[str] = []
        seen = {uuid}
        current = uuid
        problem = None
        while current in successors:
            targets = successors[current]
            if len(targets) > 1:
                problem = f"cluster {current} is revoked by {len(targets)} clusters"
                break
            nxt = targets[0]
            if nxt in seen:
                problem = "the revoked-by chain loops: " + " -> ".join(
                    ident.get(u, ("", u))[1] or u for u in [uuid, *path, nxt]
                )
                break
            if nxt not in by_uuid:
                problem = f"successor cluster {nxt} is not in the inputs"
                break
            seen.add(nxt)
            path.append(nxt)
            current = nxt
        if problem is None and current not in ident:
            problem = f"successor cluster {current} has no ATT&CK id in its value"
        if problem is not None:
            exclude(attack_id, problem)
            continue
        successor_name, successor_id = ident[current]
        if section_of(successor_id) != section:
            exclude(attack_id, f"successor {successor_id} is not of the same kind")
            continue
        if successor_id == attack_id:
            exclude(attack_id, "successor carries the same id")
            continue
        entry: Dict[str, Any] = {"name": name, "successor": successor_id, "successor_name": successor_name}
        via = [ident[u][1] for u in path[:-1] if u in ident]
        if via:
            entry["via"] = via
        sections[section][attack_id] = entry

    for section in sections:
        sections[section] = dict(sorted(sections[section].items()))
    excluded.sort(key=lambda x: (x["id"], x["reason"]))
    counts = {name: len(entries) for name, entries in sections.items()}
    counts["via_chain"] = sum(1 for entries in sections.values() for e in entries.values() if "via" in e)
    counts["excluded"] = len(excluded)
    return {**sections, "excluded": excluded, "counts": counts, "notes": sorted(set(notes))}


def find_inputs(raw_dir: Path) -> List[Path]:
    """The newest capture of each required galaxy and of each ``mitre-ics-*`` galaxy in ``raw_dir``."""
    resolved = raw_dir.resolve()
    if "restricted" in resolved.parts:
        raise BuildError(f"{raw_dir} is inside a 'restricted' folder; only open data may be read")
    if not resolved.is_dir():
        raise BuildError(f"{raw_dir} is not a folder")
    newest: Dict[str, Tuple[str, Path]] = {}
    for path in resolved.iterdir():
        match = _CAPTURE_NAME.match(path.name)
        if not match or not path.is_file():
            continue
        galaxy = match.group("galaxy")
        if galaxy not in REQUIRED_GALAXIES and not galaxy.startswith(OPTIONAL_GALAXY_PREFIX):
            continue
        if galaxy not in newest or match.group("date") > newest[galaxy][0]:
            newest[galaxy] = (match.group("date"), path)
    missing = [g for g in REQUIRED_GALAXIES if g not in newest]
    if missing:
        raise BuildError(f"no capture for {', '.join(missing)} in {raw_dir}")
    return [newest[g][1] for g in sorted(newest)]


def read_input(path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """``(input record, clusters)`` for one capture file; the record names the file and its SHA-256."""
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except ValueError as e:
        raise BuildError(f"{path.name}: not JSON ({e})") from e
    try:
        clusters = clusters_of(payload)
    except BuildError as e:
        raise BuildError(f"{path.name}: {e}") from e
    match = _CAPTURE_NAME.match(path.name)
    request = payload.get("request", {}) if isinstance(payload, dict) else {}
    galaxy = request.get("galaxy", {}) if isinstance(request, dict) else {}
    record: Dict[str, Any] = {
        "file": path.name,
        "galaxy": match.group("galaxy") if match else str(galaxy.get("type") or ""),
        "galaxy_name": str(galaxy.get("name") or ""),
        "galaxy_version": str(galaxy.get("version") or ""),
        "misp_version": str(request.get("misp_version") or "") if isinstance(request, dict) else "",
        "captured_at": str(payload.get("captured_at") or "") if isinstance(payload, dict) else "",
        "clusters": len(clusters),
        "revoked_clusters": sum(
            1
            for c in clusters
            if any(
                isinstance(r, dict) and r.get("referenced_galaxy_cluster_type") == REVOKED_BY
                for r in c.get("GalaxyClusterRelation") or []
            )
        ),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    return record, clusters


def calver(day: date) -> str:
    """CalVer ``YYYY.M.D`` without leading zeros (``docs/VERSIONING.md``)."""
    return f"{day.year}.{day.month}.{day.day}"


def build_document(paths: Sequence[Path], version: str, generated_at: str) -> Dict[str, Any]:
    """The full map document for the capture files ``paths``."""
    records: List[Dict[str, Any]] = []
    clusters: List[Dict[str, Any]] = []
    for path in sorted(paths, key=lambda p: p.name):
        record, found = read_input(path)
        records.append(record)
        clusters.extend(found)
    built = build_map(clusters)
    return {
        "name": "attack_revoked_ids",
        "version": version,
        "generated_at": generated_at,
        "description": DESCRIPTION,
        "generator": "scripts/build_attack_revoked_ids.py",
        "notices": dict(NOTICES),
        "inputs": records,
        "counts": built["counts"],
        "excluded": built["excluded"],
        "notes": built["notes"],
        "techniques": built["techniques"],
        "groups": built["groups"],
        "software": built["software"],
    }


def render(document: Dict[str, Any]) -> str:
    """The document as JSON text: two-space indent, key order as built, newline at the end."""
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("raw_dir", type=Path, help="folder of the misp_galaxy_<galaxy>_<YYYYMMDD>.json captures")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="where to write the map")
    parser.add_argument("--version", default=None, help="CalVer of the map (default: today, YYYY.M.D)")
    parser.add_argument(
        "--generated-at",
        default=None,
        help="ISO-8601 UTC timestamp to record (default: now); fix it to reproduce a build byte for byte",
    )
    args = parser.parse_args(argv)
    now = datetime.now(timezone.utc)
    version = args.version or calver(now.date())
    generated_at = args.generated_at or now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    try:
        document = build_document(find_inputs(args.raw_dir), version, generated_at)
    except (BuildError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(document), encoding="utf-8")
    counts = document["counts"]
    print(
        f"wrote {args.output}: version {version}, {counts['techniques']} techniques, {counts['groups']} groups, "
        f"{counts['software']} software ({counts['via_chain']} through a chain), {counts['excluded']} excluded"
    )
    for item in document["excluded"]:
        print(f"excluded {item['id']}: {item['reason']}", file=sys.stderr)
    for note in document["notes"]:
        print(f"note: {note}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
