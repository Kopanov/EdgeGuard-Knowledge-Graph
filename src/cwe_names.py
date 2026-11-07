"""CWE names from the pinned MITRE CWE list (2026-11-07).

NVD and CISA KEV name a CVE's weaknesses by id only. The NVD and KEV collectors put the names of a record's CWE ids
into its item (``cwe_names``, each ``"CWE-89: <name>"``, and ``cwe_names_version``, the CWE version that named
them), and MISPWriter writes both into the record's ``NVD_META``, so MISP holds the names and the sync only copies
them.

The list is ``src/reference/cwe_names.json``, built from MITRE's XML CWE list by ``scripts/build_cwe_names.py``. It
carries MITRE's copyright designation and the CWE licence (``notices.cwe``), which the CWE Terms of Use require in
every copy. It is changed only before a fresh baseline: a record's names are written at collection time, so a list
changed between baselines would leave MISP holding the names of two CWE versions.

The list is read once per process. When the file is missing or invalid, one warning is logged and no name is
given: a run never fails because of the list. An id the list does not hold (NVD's placeholders ``NVD-CWE-noinfo``
and ``NVD-CWE-Other``, an id newer than the list) gets no name.

Standard library only.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

LIST_PATH = Path(__file__).resolve().parent / "reference" / "cwe_names.json"
_ID_RE = re.compile(r"^CWE-(\d{1,6})$")

_lock = threading.Lock()
_loaded: Optional[Dict[str, Any]] = None


def _load() -> Dict[str, Any]:
    """``{"version": str, "names": {"CWE-89": name}}`` of the list file; empty names when it cannot be read."""
    global _loaded
    with _lock:
        if _loaded is None:
            try:
                document = json.loads(LIST_PATH.read_text(encoding="utf-8"))
                names = document["names"]
                version = document["version"]
                if not isinstance(names, dict) or not isinstance(version, str) or not version:
                    raise ValueError("names is not a map or version is missing")
                _loaded = {
                    "version": version,
                    "names": {str(k): str(v) for k, v in names.items() if isinstance(v, str) and v},
                }
            except (OSError, ValueError, KeyError, TypeError) as exc:
                logger.warning("CWE name list %s could not be read (%s): records get no CWE names", LIST_PATH, exc)
                _loaded = {"version": "", "names": {}}
        return _loaded


def list_version() -> str:
    """The CWE version of the pinned list (``"5.0"``); ``""`` when the list cannot be read."""
    return _load()["version"]


def cwe_names(cwe_ids: Iterable[Any]) -> List[str]:
    """``"CWE-89: <name>"`` for each id of ``cwe_ids`` the list names, in their order, each id once.

    An id is looked up as written (``CWE-89``), surrounding whitespace and case ignored; ``CWE-089`` is not an id
    the list holds and names nothing. Anything that is not such an id gets no name."""
    names = _load()["names"]
    out: List[str] = []
    seen = set()
    for value in cwe_ids or []:
        if not isinstance(value, str):
            continue
        match = _ID_RE.match(value.strip().upper())
        if not match:
            continue
        cwe_id = f"CWE-{match.group(1)}"
        name = names.get(cwe_id)
        if name and cwe_id not in seen:
            seen.add(cwe_id)
            out.append(f"{cwe_id}: {name}")
    return out


def item_fields(cwe_ids: Iterable[Any]) -> Dict[str, Any]:
    """The item keys of a record whose CWE ids are ``cwe_ids``: ``cwe_names`` and ``cwe_names_version``, or ``{}``
    when no id has a name (so a record without named weaknesses carries neither key)."""
    names = cwe_names(cwe_ids)
    return {"cwe_names": names, "cwe_names_version": list_version()} if names else {}
