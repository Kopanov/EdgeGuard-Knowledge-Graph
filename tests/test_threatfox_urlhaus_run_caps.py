"""ThreatFox and URLhaus per-run caps (2026-10).

The daily DAG passed ``get_effective_limit("threatfox" / "urlhaus")`` to ``collect()``; neither
source was in ``NO_LIMIT_SOURCES`` or ``OWN_RUN_CAP_SOURCES``, so both were cut at
``EDGEGUARD_INCREMENTAL_LIMIT`` (200). ThreatFox serves the IOCs of the last 7 days and URLhaus
its ``recent.csv`` export (about 63,000 URLs on 2026-10-24), about 1,100 new entries per day each,
and neither has a cursor: about 80% of each day's entries left the window without being collected.
Each source now has its own cap above its whole window (``EDGEGUARD_THREATFOX_MAX_PER_RUN`` 10,000,
``EDGEGUARD_URLHAUS_MAX_PER_RUN`` 100,000), and a run that reaches it keeps the newest entries
whatever order the feed returns them in, and says so in a warning.

Payload shapes: the ThreatFox ``get_iocs`` record and the URLhaus ``recent.csv`` header and row
layout as abuse.ch documents and serves them (fields the collectors read).
"""

from __future__ import annotations

import importlib
import logging
import os
import sys
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import collectors.global_feed_collector as gfc  # noqa: E402


def _threatfox_ioc(n: int, first_seen: str) -> Dict[str, Any]:
    """One ``get_iocs`` record (abuse.ch ThreatFox API v1)."""
    return {
        "id": str(1600000 + n),
        "ioc": f"198.51.100.{n % 250}:{4000 + n}",
        "threat_type": "botnet_cc",
        "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
        "ioc_type": "ip:port",
        "ioc_type_desc": "ip:port combination that is used for botnet Command&control (C&C)",
        "malware": "win.cobalt_strike",
        "malware_printable": "Cobalt Strike",
        "malware_alias": "Agentemis,BEACON,CobaltStrike,cobeacon",
        "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike",
        "confidence_level": 100,
        "first_seen": first_seen,
        "last_seen": None,
        "reference": "",
        "reporter": "abuse_ch",
        "tags": ["c2", "CobaltStrike"],
    }


_URLHAUS_BANNER = (
    "################################################################\n"
    "# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #\n"
    "# Last updated: 2026-10-15 07:05:08 (UTC)                      #\n"
    "#                                                              #\n"
    "# Terms Of Use: https://urlhaus.abuse.ch/api/                  #\n"
    "# For questions please contact urlhaus [at] abuse.ch           #\n"
    "################################################################\n"
    "#\n"
    "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
)


def _urlhaus_row(n: int, dateadded: str) -> str:
    return (
        f'"{3650000 + n}","{dateadded}","http://203.0.113.{n % 250}:{40000 + n}/i","online","{dateadded}",'
        f'"malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/{3650000 + n}/","geenensp"\n'
    )


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    """Code defaults for the generic limits and the two caps; no breaker / rate-limiter side effects."""
    import config

    monkeypatch.setattr(config, "INCREMENTAL_COLLECTION_LIMIT", 200)
    monkeypatch.setattr(config, "MAX_ENTRIES_PER_SOURCE", 0)
    monkeypatch.setattr(config, "THREATFOX_MAX_PER_RUN", 10000)
    monkeypatch.setattr(config, "URLHAUS_MAX_PER_RUN", 100000)
    for breaker in (gfc.THREATFOX_CIRCUIT_BREAKER, gfc.URLHAUS_CIRCUIT_BREAKER):
        monkeypatch.setattr(breaker, "can_execute", lambda: True)
        monkeypatch.setattr(breaker, "record_success", lambda: None)
        monkeypatch.setattr(breaker, "record_failure", lambda: None)
    monkeypatch.setattr(gfc.THREATFOX_RATE_LIMITER, "wait_if_needed", lambda: None)
    monkeypatch.setattr(gfc.URLHAUS_RATE_LIMITER, "wait_if_needed", lambda: None)
    yield


def _threatfox(iocs: List[Dict[str, Any]]) -> gfc.ThreatFoxCollector:
    c = gfc.ThreatFoxCollector.__new__(gfc.ThreatFoxCollector)
    c.source_name = "threatfox"
    c.api_key = "a" * 48
    c.base_url = "https://threatfox-api.abuse.ch/api/v1/"
    c.misp_writer = MagicMock()
    c.misp_writer.push_indicators.side_effect = lambda items, _src: (len(items), 0)
    c._fetch_iocs = lambda days: {"query_status": "ok", "data": iocs}  # type: ignore[method-assign]
    return c


def _urlhaus(text: str) -> gfc.URLhausCollector:
    c = gfc.URLhausCollector.__new__(gfc.URLhausCollector)
    c.api_key = "a" * 48
    c.urls = [f"https://urlhaus-api.abuse.ch/v2/files/exports/{c.api_key}/recent.csv"]
    c.source_name = "urlhaus"
    c.misp_writer = MagicMock()
    c.misp_writer.push_indicators.side_effect = lambda items, _src: (len(items), 0)
    c._fetch_feed = lambda url: text  # type: ignore[method-assign]
    return c


# --------------------------------------------------------------------------- config


@pytest.mark.parametrize("source", ["threatfox", "urlhaus", "ThreatFox", "URLhaus"])
def test_the_incremental_default_no_longer_applies(source):
    import config

    assert config.get_effective_limit(source) is None, "the collector applies its own per-run cap"
    assert config.resolve_collection_limit(None, source, baseline=False) is None
    assert config.get_effective_limit("otx") == 200, "other sources keep the incremental default"


def test_the_global_override_still_applies():
    import config

    with patch.object(config, "MAX_ENTRIES_PER_SOURCE", 75):
        assert config.get_effective_limit("threatfox") == 75
        assert config.get_effective_limit("urlhaus") == 75


def test_code_defaults_and_environment_override():
    import config

    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("EDGEGUARD_THREATFOX_MAX_PER_RUN", None)
        os.environ.pop("EDGEGUARD_URLHAUS_MAX_PER_RUN", None)
        fresh = importlib.reload(config)
        try:
            assert fresh.THREATFOX_MAX_PER_RUN == 10000
            assert fresh.URLHAUS_MAX_PER_RUN == 100000
            os.environ["EDGEGUARD_THREATFOX_MAX_PER_RUN"] = "1234"
            os.environ["EDGEGUARD_URLHAUS_MAX_PER_RUN"] = "0"
            fresh = importlib.reload(config)
            assert fresh.THREATFOX_MAX_PER_RUN == 1234
            assert fresh.URLHAUS_MAX_PER_RUN == 0
        finally:
            os.environ.pop("EDGEGUARD_THREATFOX_MAX_PER_RUN", None)
            os.environ.pop("EDGEGUARD_URLHAUS_MAX_PER_RUN", None)
            importlib.reload(config)


# --------------------------------------------------------------------------- ThreatFox


def test_threatfox_daily_run_is_not_cut_at_the_incremental_default():
    import config

    iocs = [_threatfox_ioc(n, f"2026-10-{8 + n % 7:02d} 10:{n % 60:02d}:00 UTC") for n in range(320)]
    c = _threatfox(iocs)
    # The daily DAG wrapper passes get_effective_limit(source).
    out = c.collect(limit=config.get_effective_limit("threatfox"), push_to_misp=False)
    assert len(out) == 320, "the whole window is collected, not the first 200"
    assert [i["ioc_id"] for i in out] == [ioc["id"] for ioc in iocs], "below the cap the feed order is kept"


def test_threatfox_capped_run_keeps_the_newest_iocs_whatever_the_feed_order(caplog, monkeypatch):
    import config

    monkeypatch.setattr(config, "THREATFOX_MAX_PER_RUN", 2)
    oldest_first = [
        _threatfox_ioc(1, "2026-10-09 08:00:00 UTC"),
        _threatfox_ioc(2, "2026-10-12 08:00:00 UTC"),
        _threatfox_ioc(3, "2026-10-15 06:30:00 UTC"),
        _threatfox_ioc(4, "2026-10-14 23:59:59 UTC"),
    ]
    for order in (oldest_first, list(reversed(oldest_first))):
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger=gfc.logger.name):
            st = _threatfox(order).collect(push_to_misp=True)
        assert st["success"] is True and st["count"] == 2
        kept = [i["first_seen"] for i in _threatfox(order).collect(push_to_misp=False)]
        assert kept == ["2026-10-15 06:30:00 UTC", "2026-10-14 23:59:59 UTC"]
        assert any(
            "lists 4 IOCs" in r.message and "cap of 2" in r.message and "2 older ones" in r.message
            for r in caplog.records
        ), "a truncating cap is logged with what it dropped"


def test_threatfox_lower_regular_limit_wins_and_zero_cap_means_no_cap(caplog, monkeypatch):
    import config

    iocs = [_threatfox_ioc(n, f"2026-10-14 0{n}:00:00 UTC") for n in range(5)]
    out = _threatfox(iocs).collect(limit=3, push_to_misp=False)
    assert [i["first_seen"] for i in out] == [f"2026-10-14 0{n}:00:00 UTC" for n in (4, 3, 2)]

    monkeypatch.setattr(config, "THREATFOX_MAX_PER_RUN", 0)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=gfc.logger.name):
        out = _threatfox(iocs).collect(push_to_misp=False)
    assert len(out) == 5
    assert not any("cap of" in r.message for r in caplog.records), "no cut, no warning"


# --------------------------------------------------------------------------- URLhaus


def test_urlhaus_daily_run_is_not_cut_at_the_incremental_default():
    import config

    rows = "".join(_urlhaus_row(n, f"2026-10-{1 + n % 14:02d} 12:00:{n % 60:02d}") for n in range(450))
    c = _urlhaus(_URLHAUS_BANNER + rows)
    st = c.collect(limit=config.get_effective_limit("urlhaus"), push_to_misp=True)
    assert st["count"] == 450, "the whole recent.csv window is collected, not the first 200"
    pushed = c.misp_writer.push_indicators.call_args[0][0]
    assert len(pushed) == 450 and pushed[0]["first_seen"] == "2026-10-01 12:00:00", "feed order kept below the cap"


def test_urlhaus_capped_run_keeps_the_newest_urls_whatever_the_feed_order(caplog, monkeypatch):
    import config

    monkeypatch.setattr(config, "URLHAUS_MAX_PER_RUN", 2)
    newest_first = [
        _urlhaus_row(4, "2026-10-15 07:01:04"),
        _urlhaus_row(3, "2026-10-14 22:10:00"),
        _urlhaus_row(2, "2026-09-20 03:00:00"),
        _urlhaus_row(1, "2026-09-16 01:00:00"),
    ]
    for order in (newest_first, list(reversed(newest_first))):
        caplog.clear()
        c = _urlhaus(_URLHAUS_BANNER + "".join(order))
        with caplog.at_level(logging.WARNING, logger=gfc.logger.name):
            st = c.collect(push_to_misp=True)
        assert st["count"] == 2
        pushed = c.misp_writer.push_indicators.call_args[0][0]
        assert [i["first_seen"] for i in pushed] == ["2026-10-15 07:01:04", "2026-10-14 22:10:00"]
        assert any(
            "recent.csv lists 4 URLs" in r.message and "cap of 2" in r.message and "2 older ones" in r.message
            for r in caplog.records
        )


def test_urlhaus_lower_regular_limit_wins_and_zero_cap_means_no_cap(monkeypatch):
    import config

    rows = "".join(_urlhaus_row(n, f"2026-10-1{n} 00:00:00") for n in range(5))
    out = _urlhaus(_URLHAUS_BANNER + rows).collect(limit=2, push_to_misp=False)
    assert [i["first_seen"] for i in out] == ["2026-10-14 00:00:00", "2026-10-13 00:00:00"]

    monkeypatch.setattr(config, "URLHAUS_MAX_PER_RUN", 0)
    out = _urlhaus(_URLHAUS_BANNER + rows).collect(push_to_misp=False)
    assert len(out) == 5


def test_rows_without_a_usable_date_go_last():
    from collectors.collector_utils import feed_time, newest_first

    rows = [["1", "not a date"], ["2", "2026-10-01 00:00:00"], ["3"], ["4", "2026-10-02 00:00:00"]]
    ordered = newest_first(rows, lambda p: feed_time(p[1]) if len(p) > 1 else None)
    assert [r[0] for r in ordered] == ["4", "2", "1", "3"], "dated rows newest first, undated in feed order"
