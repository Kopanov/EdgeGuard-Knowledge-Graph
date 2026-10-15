"""The OTX same-run fold keeps the most restrictive TLP of the pulses (2026-10).

``_fold_duplicate_pulse_item`` merges the copies of one IOC (or family, actor, CVE) that several
pulses of a run list: report ids, techniques, families and pairs. It did not merge ``pulse_tlp``,
so the item kept the first pulse's level: an IOC listed first by a white pulse and then by an
amber one was pushed to MISP as ``tlp:white`` (and the reverse order as ``tlp:amber``). The fold
now keeps the most restrictive level, ranked as ``MISPWriter`` writes it (white / clear < green <
amber < amber+strict < red); a value outside the ladder ranks as the deployment default it would
be written as, so it never lowers a known level.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from collectors import otx_collector as oc  # noqa: E402
from collectors.misp_writer import MISPWriter, tlp_rank  # noqa: E402


def _pulse(pid, tlp, iocs, families=()):
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": pid,
        "name": f"pulse {pid}",
        "created": now,
        "modified": now,
        "adversary": "",
        "TLP": tlp,
        "attack_ids": [],
        "malware_families": list(families),
        "indicators": [{"type": "IPv4", "indicator": v, "description": "ioc"} for v in iocs],
    }


def _collect(pulses):
    c = oc.OTXCollector.__new__(oc.OTXCollector)
    c.api_key = "test-otx-key-64chars" + "a" * 44
    c.tag = "alienvault_otx"
    c.session = MagicMock()
    c.rate_limiter = MagicMock()
    c._last_http_status = 200
    c.circuit_breaker = MagicMock()
    c.circuit_breaker.can_execute.return_value = True
    c.misp_writer = None
    c.source_name = "otx"
    c.health_check = MagicMock(return_value=True)
    pages = iter([pulses])
    with (
        patch.object(c, "check_service_available", return_value=True),
        patch.object(c, "_fetch_pulses", side_effect=lambda **kw: next(pages, [])),
        patch("collectors.otx_collector.time.sleep", lambda *_a, **_k: None),
        patch("collectors.otx_collector.get_source_incremental", return_value={}),
        patch("collectors.otx_collector.update_source_incremental", lambda *_a, **_k: None),
    ):
        return c.collect(limit=10, push_to_misp=False)


def _tlp_tag_of(item):
    writer = MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)
    attr = writer.create_attribute(item) if "indicator_type" in item else writer.create_malware_attribute(item)
    return [t["name"] for t in attr["Tag"] if t["name"].startswith("tlp:")]


@pytest.mark.parametrize("order", [("white", "amber"), ("amber", "white")], ids=["white-first", "amber-first"])
def test_ioc_and_family_listed_by_white_and_amber_pulses_are_pushed_amber(order):
    items = _collect(
        [
            _pulse("p1", order[0], ["203.0.113.5"], ["Emotet"]),
            _pulse("p2", order[1], ["203.0.113.5"], ["Emotet"]),
        ]
    )
    ioc = [i for i in items if i.get("value") == "203.0.113.5"]
    assert len(ioc) == 1 and ioc[0]["pulse_tlp"] == "amber"
    assert _tlp_tag_of(ioc[0]) == ["tlp:amber"], "the MISP attribute carries the stricter level"
    family = [i for i in items if i.get("type") == "malware" and i.get("name") == "Emotet"]
    assert len(family) == 1 and family[0]["pulse_tlp"] == "amber"
    assert _tlp_tag_of(family[0]) == ["tlp:amber"]


@pytest.mark.parametrize(
    "first, second, expected",
    [
        ("green", "red", "red"),
        ("red", "green", "red"),
        ("amber", "amber+strict", "amber+strict"),
        ("clear", "green", "green"),
        ("TLP:AMBER", "white", "TLP:AMBER"),
        ("amber", "", "amber"),
        ("", "amber", "amber"),
        ("amber", "bogus", "amber"),
        ("bogus", "green", "green"),
        ("white", "clear", "white"),
    ],
)
def test_fold_keeps_the_most_restrictive_level_in_either_order(first, second, expected):
    kept = {"indicator_type": "ipv4", "value": "203.0.113.5", "pulse_id": "p1", "pulse_tlp": first}
    dup = {"indicator_type": "ipv4", "value": "203.0.113.5", "pulse_id": "p2", "pulse_tlp": second}
    unique = oc._dedupe_pulse_items([kept, dup])
    assert len(unique) == 1 and unique[0]["pulse_tlp"] == expected


def test_rank_follows_the_written_level(monkeypatch):
    import config

    assert [tlp_rank(x) for x in ("white", "clear", "green", "amber", "amber+strict", "red")] == [1, 1, 2, 3, 4, 5]
    assert tlp_rank("tlp:Red") == 5 and tlp_rank(None) == tlp_rank("white")
    monkeypatch.setattr(config, "EDGEGUARD_DEFAULT_TLP", "amber")
    assert tlp_rank("") == 3 and tlp_rank("bogus") == 3, "an unknown value is written as the default"
    kept = {"indicator_type": "ipv4", "value": "203.0.113.5", "pulse_id": "p1", "pulse_tlp": ""}
    dup = {"indicator_type": "ipv4", "value": "203.0.113.5", "pulse_id": "p2", "pulse_tlp": "white"}
    assert oc._dedupe_pulse_items([kept, dup])[0]["pulse_tlp"] == "", "white must not lower the amber default"
