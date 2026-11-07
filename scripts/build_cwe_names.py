#!/usr/bin/env python3
"""Build ``src/reference/cwe_names.json``: the name of every CWE id, from MITRE's CWE list (2026-11-07).

NVD and CISA KEV name a CVE's weaknesses by id only (``CWE-89``). The NVD and KEV collectors write the names of a
record's CWE ids into its ``NVD_META`` (``cwe_names``, ``"CWE-89: <name>"``), so MISP holds them and the graph can
answer a question that names the weakness rather than its number. The names come from this pinned list, never
from a request at collection time (``src/cwe_names.py``).

Input: the CWE list in XML as MITRE publishes it (``https://cwe.mitre.org/data/xml/cwec_latest.xml.zip``, one
``cwec_v<version>.xml`` inside). Every ``Weakness`` and every ``Grouping`` (the CWE 5 name of the former
categories, such as ``CWE-264``, which NVD still assigns) gives one entry ``CWE-<ID>`` with its ``Name`` as MITRE
writes it, deprecated and obsolete entries included (NVD's older records name them). Views are left out: NVD
assigns none. NVD's placeholders ``NVD-CWE-noinfo`` and ``NVD-CWE-Other`` are not CWE entries and have no name.

The output carries the CWE version and release date of the input, the sha256 of the zip and of the XML, MITRE's
copyright designation and the CWE licence (the CWE Terms of Use require both in every copy), and how it was
built. The entries are sorted by number, so the output does not depend on the order of the XML.

**When to rebuild.** Only before a fresh baseline: a record's ``cwe_names`` are written at collection time, so a
list changed between baselines would leave MISP holding names of two CWE versions until every record is sent
again (``docs/RUNBOOK.md``).

Usage::

    python scripts/build_cwe_names.py CWEC_ZIP
    python scripts/build_cwe_names.py CWEC_ZIP --captured-at 2026-11-07 --output src/reference/cwe_names.json

Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO / "src" / "reference" / "cwe_names.json"
SOURCE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
TERMS_URL = "https://cwe.mitre.org/about/termsofuse.html"

# MITRE's copyright designation (the footer of every page of cwe.mitre.org) and the licence of the CWE Terms of
# Use, both as MITRE writes them (read on 2026-11-07). The licence asks for both in every copy.
CWE_COPYRIGHT = (
    "Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of "
    "The MITRE Corporation."
)
CWE_LICENSE = (
    "CWE™ is free to use by any organization or individual for any research, development, and/or commercial "
    "purposes, per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby grants you a non-exclusive, "
    "royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for "
    "such purposes is authorized on the condition that you reproduce MITRE’s copyright designation and this "
    "license in any such copy. CWE is a trademark of The MITRE Corporation."
)

_CWE_NAMESPACE = re.compile(r"^\{http://cwe\.mitre\.org/cwe-\d+\}")
_XML_NAME = re.compile(r"^cwec_v[0-9.]+\.xml$")
_ID = re.compile(r"^\d{1,6}$")
# The kinds of entry the list holds (XML element name, without the namespace).
ENTRY_KINDS = ("Weakness", "Grouping")


def _local(tag: str) -> str:
    return _CWE_NAMESPACE.sub("", tag)


def read_catalogue(xml_bytes: bytes) -> Dict[str, Any]:
    """The CWE version, release date and names of an XML CWE list: ``{"version", "date", "names", "counts"}``.

    Raises ``ValueError`` when the XML is not a CWE ``Weakness_Catalog``, carries no version, or names an id twice
    with two names."""
    root = ET.fromstring(xml_bytes)
    if _local(root.tag) != "Weakness_Catalog" or root.get("Name") != "CWE":
        raise ValueError(f"not a CWE list: root element {root.tag!r}")
    version = str(root.get("Version") or "").strip()
    if not version:
        raise ValueError("the CWE list names no version")
    names: Dict[int, str] = {}
    counts = {kind: 0 for kind in ENTRY_KINDS}
    for section in root:
        for entry in section:
            kind = _local(entry.tag)
            if kind not in ENTRY_KINDS:
                continue
            cwe_id, name = str(entry.get("ID") or "").strip(), " ".join(str(entry.get("Name") or "").split())
            if not _ID.match(cwe_id) or not name:
                raise ValueError(f"{kind} without a numeric ID and a name: ID={cwe_id!r}")
            number = int(cwe_id)
            if number in names and names[number] != name:
                raise ValueError(f"CWE-{number} is named twice: {names[number]!r} and {name!r}")
            names[number] = name
            counts[kind] += 1
    if not names:
        raise ValueError("the CWE list holds no weakness")
    return {
        "version": version,
        "date": str(root.get("Date") or "").strip(),
        "names": {f"CWE-{number}": names[number] for number in sorted(names)},
        "counts": {**counts, "names": len(names)},
    }


def build(zip_path: Path, captured_at: Optional[str] = None) -> Dict[str, Any]:
    """The reference document for the CWE list zip at ``zip_path`` (module docstring)."""
    zip_bytes = zip_path.read_bytes()
    with zipfile.ZipFile(zip_path) as archive:
        members = [name for name in archive.namelist() if _XML_NAME.match(Path(name).name)]
        if len(members) != 1:
            raise ValueError(f"{zip_path.name}: expected one cwec_v<version>.xml, found {members}")
        xml_bytes = archive.read(members[0])
    catalogue = read_catalogue(xml_bytes)
    return {
        "name": "cwe_names",
        "version": catalogue["version"],
        "cwe_release_date": catalogue["date"],
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "description": (
            "The name of every CWE weakness and grouping of MITRE's CWE list, by id. The NVD and CISA KEV collectors "
            "write the names of a record's CWE ids into its NVD_META (cwe_names, 'CWE-89: <name>'; src/cwe_names.py)."
        ),
        "generator": "scripts/build_cwe_names.py",
        "notices": {"cwe": f"{CWE_COPYRIGHT} {CWE_LICENSE} Terms of Use: {TERMS_URL}"},
        "inputs": [
            {
                "url": SOURCE_URL,
                "file": zip_path.name,
                "xml_file": Path(members[0]).name,
                "captured_at": captured_at or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "sha256": hashlib.sha256(zip_bytes).hexdigest(),
                "xml_sha256": hashlib.sha256(xml_bytes).hexdigest(),
            }
        ],
        "counts": catalogue["counts"],
        "notes": [
            "Every Weakness and every Grouping of the XML list, deprecated and obsolete entries included; views are "
            "left out. Names as MITRE writes them, whitespace runs folded to one space.",
            "NVD's placeholders NVD-CWE-noinfo and NVD-CWE-Other are not CWE entries and have no name.",
            "Changed only before a fresh baseline: the names are written into MISP at collection time, so a list "
            "changed between baselines leaves names of two CWE versions in MISP.",
        ],
        "names": catalogue["names"],
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("zip", type=Path, help="the CWE list zip (cwec_latest.xml.zip)")
    parser.add_argument("--captured-at", help="the day the zip was downloaded (YYYY-MM-DD; default today)")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    if "restricted" in args.zip.resolve().parts:
        parser.error("refusing to read from a 'restricted' folder")
    document = build(args.zip, args.captured_at)
    args.output.write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    lines: List[str] = [
        f"CWE {document['version']} ({document['cwe_release_date']}): {document['counts']['names']} names",
        f"written to {args.output}",
    ]
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
