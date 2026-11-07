"""The OTX collector reads the pulse's TLP under the name each OTX answer uses (2026-11-07).

OTX names the field by endpoint: the subscribed list (``/api/v1/pulses/subscribed``, read by every scheduled and
baseline run) answers ``tlp``, a pulse read by id (``/api/v1/pulses/{id}``, the retry list) answers ``TLP``
(``tests/fixtures/otx_pulse_keys_2026_11_07.json``). The collector read only ``TLP``, so every pulse of a window
reached MISP without its level and its items were written at the deployment default: on the 730-day test graph
(baseline of 2026-11-03 plus scheduled runs, measured 2026-11-07) all 146,934 OTX indicators were ``tlp = white``
and ``pulse_tlp`` was empty in the ``raw_data`` of each of their ``SOURCED_FROM`` edges. A green or amber pulse
would have been written as white.

The synthetic window pulses of the other OTX tests carry ``tlp``, the subscribed field.

Each answer shape is built from the recorded key list (only those keys), and run end to end on its own path:
the window (``_fetch_pulses``) for the subscribed shape, the retry list's fetch by id for the by-id shape. The
item carries the pulse's level and its MISP attribute the ``tlp:`` tag of that level.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from test_otx_fold_tlp import _collect as _collect_window  # noqa: E402  (the window path, no MISP)
from test_otx_fold_tlp import _tlp_tag_of  # noqa: E402
from test_otx_incremental_order import ROWS, _collect, _Otx, _recorded, _Writer  # noqa: E402  (the retry path)

from collectors import otx_collector as oc  # noqa: E402

_KEYS = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "otx_pulse_keys_2026_11_07.json").read_text(encoding="utf-8")
)


def _shaped(shape: str, pid: str, level: Any, ioc: str) -> Dict[str, Any]:
    """A pulse with exactly the keys of the recorded *shape* (``subscribed`` or ``by_id``), one IPv4 indicator,
    and *level* under that shape's TLP key."""
    now = datetime.now(timezone.utc).isoformat()
    filled: Dict[str, Any] = {
        "id": pid,
        "name": f"pulse {pid}",
        "description": "",
        "author_name": "example",
        "author": {"username": "example"},
        "created": now,
        "modified": now,
        "revision": 1,
        "public": 1,
        "adversary": "",
        "indicators": [{"type": "IPv4", "indicator": ioc, "description": "ioc", "created": now}],
        "more_indicators": False,
        "in_group": False,
        "is_subscribing": None,
    }
    pulse: Dict[str, Any] = {}
    for key in _KEYS[f"{shape}_keys"]:
        if key.lower() == "tlp":
            pulse[key] = level
        else:
            pulse[key] = filled.get(key, [])
    return pulse


def test_the_two_answers_name_the_field_differently():
    subscribed, by_id = set(_KEYS["subscribed_keys"]), set(_KEYS["by_id_keys"])
    assert "tlp" in subscribed and "TLP" not in subscribed
    assert "TLP" in by_id and "tlp" not in by_id
    assert _KEYS["subscribed_tlp_values"] == {"white": 40}


@pytest.mark.parametrize("shape", ["subscribed", "by_id"])
@pytest.mark.parametrize("level", ["green", "amber", "red"])
def test_the_level_is_read_under_either_name(shape, level):
    assert oc._pulse_tlp(_shaped(shape, "p1", level, "203.0.113.5")) == level


@pytest.mark.parametrize("shape", ["subscribed", "by_id"])
@pytest.mark.parametrize("stated", ["", "   ", None, 3])
def test_a_pulse_stating_no_level_gives_none(shape, stated):
    assert oc._pulse_tlp(_shaped(shape, "p1", stated, "203.0.113.5")) == ""


def test_a_window_pulse_reaches_misp_with_its_level():
    """The subscribed shape on the window path: the item carries ``amber`` and is written ``tlp:amber``
    (before the fix: an empty ``pulse_tlp``, written ``tlp:white``)."""
    items = _collect_window([_shaped("subscribed", "p1", "amber", "203.0.113.5")])
    (ioc,) = [i for i in items if i.get("value") == "203.0.113.5"]
    assert ioc["pulse_tlp"] == "amber"
    assert _tlp_tag_of(ioc) == ["tlp:amber"]


def test_a_window_pulse_without_a_level_is_written_at_the_default():
    items = _collect_window([_shaped("subscribed", "p1", "", "203.0.113.5")])
    (ioc,) = [i for i in items if i.get("value") == "203.0.113.5"]
    assert ioc["pulse_tlp"] == ""
    assert _tlp_tag_of(ioc) == ["tlp:white"]


def test_a_pulse_fetched_by_id_reaches_misp_with_its_level(caplog):
    """The by-id shape on the retry path: a listed pulse modified before the window is fetched by id, and its
    item carries the level the answer states under ``TLP``."""
    pid = "6abf0b86fb14812f2dc84fb2"
    pulse = _shaped("by_id", pid, "green", "198.51.100.200")
    pulse["modified"] = pulse["created"] = "2026-08-01T00:00:00"
    otx = _Otx(_recorded(range(60)))
    otx.by_id_only = {pid: pulse}
    writer = _Writer(failing=[])
    first_failed = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    state: Dict[str, Any] = {
        "otx_last_pulse_modified": ROWS[0]["modified"],
        "otx_retry_pulses": [{"id": pid, "first_failed_at": first_failed, "attempts": 1}],
    }
    _collect(otx, state, caplog, limit=20, writer=writer)

    assert otx.by_id_requests == [pid]
    (item,) = [i for i in writer.pushed if i.get("pulse_id") == pid]
    assert item["pulse_tlp"] == "green"
    assert _tlp_tag_of(item) == ["tlp:green"]
