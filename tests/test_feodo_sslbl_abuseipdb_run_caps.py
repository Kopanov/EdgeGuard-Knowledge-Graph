"""Feodo Tracker, SSL Blacklist and AbuseIPDB per-run caps (2026-10).

The daily DAG passed ``get_effective_limit("feodo" / "sslbl" / "abuseipdb")`` to ``collect()``; the
three sources were in neither ``NO_LIMIT_SOURCES`` nor ``OWN_RUN_CAP_SOURCES``, so each run reported
only the first ``EDGEGUARD_INCREMENTAL_LIMIT`` (200) entries of a list that holds thousands (7,607
Feodo Tracker servers, 10,964 SSL Blacklist certificates, 10,000 AbuseIPDB addresses on the 730-day
baseline). The stored copies of the other entries were never reported again, so the refresh of
re-reported indicators (``MISPWriter._refresh_stored_copies``) never reached them and they aged while
the source still listed them. Each source now has its own cap sized to its list
(``EDGEGUARD_FEODO_MAX_PER_RUN`` 15,000, ``EDGEGUARD_SSLBL_MAX_PER_RUN`` 20,000,
``EDGEGUARD_ABUSEIPDB_MAX_PER_RUN`` 10,000); a run whose list is longer keeps the newest entries and
says so in a warning. AbuseIPDB stays at one blacklist request per run: the cap is that request's
``limit``, at most the 10,000 addresses one request returns on the free plan.

Payload shapes: the Feodo Tracker blocklist CSV (quoted fields, CRLF, as in
``tests/test_feodo_list_selection.py``), the SSL Blacklist CSV with the abuse.ch comment banner and
its commented column header, and the AbuseIPDB APIv2 ``GET /blacklist`` JSON answer.
"""

from __future__ import annotations

import importlib
import logging
import os
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

_TESTS = Path(__file__).resolve().parent
for _p in (_TESTS.parent / "src", _TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import collectors.abuseipdb_collector as aic  # noqa: E402
import collectors.finance_feed_collector as ffc  # noqa: E402

TODAY = date(2026, 10, 16)

_FEODO_BANNER = (
    "################################################################\r\n"
    "# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)          #\r\n"
    "# Last updated: 2026-03-04 14:28:39 UTC                        #\r\n"
    "################################################################\r\n"
    '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\r\n'
)

_SSLBL_BANNER = (
    "################################################################\r\n"
    "# abuse.ch SSLBL SSL Certificate Blacklist (SHA1 Fingerprints) #\r\n"
    "# Last updated: 2026-10-12 08:05:12 UTC                        #\r\n"
    "#                                                              #\r\n"
    "# Terms Of Use: https://sslbl.abuse.ch/blacklist/              #\r\n"
    "# For questions please contact sslbl [at] abuse.ch             #\r\n"
    "################################################################\r\n"
    "#\r\n"
    "# Listingdate,SHA1,Listingreason\r\n"
)


def _ip(n: int) -> str:
    return f"198.51.{100 + n // 250}.{n % 250 + 1}"


def _feodo_row(n: int, last_online: str, first_seen: str = "2024-05-01 10:00:00") -> str:
    return f'"{first_seen}","{_ip(n)}","443","offline","{last_online}","Emotet"\r\n'


def _sha1(n: int) -> str:
    return f"{n:040x}"


def _sslbl_row(n: int, listed: str) -> str:
    return f"{listed},{_sha1(n)},Vidar C&C\r\n"


def _blacklist_entry(n: int, last_reported: str) -> Dict[str, Any]:
    """One entry of the AbuseIPDB APIv2 ``GET /blacklist`` answer (JSON)."""
    return {
        "ipAddress": f"203.0.{113 + n // 250}.{n % 250 + 1}",
        "countryCode": "NL",
        "abuseConfidenceScore": 100,
        "lastReportedAt": last_reported,
    }


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    """Code defaults for the generic limits and the three caps; no breaker / rate-limiter side effects."""
    import config

    monkeypatch.setattr(config, "INCREMENTAL_COLLECTION_LIMIT", 200)
    monkeypatch.setattr(config, "MAX_ENTRIES_PER_SOURCE", 0)
    monkeypatch.setattr(config, "FEODO_MAX_PER_RUN", 15000)
    monkeypatch.setattr(config, "SSLBL_MAX_PER_RUN", 20000)
    monkeypatch.setattr(config, "ABUSEIPDB_MAX_PER_RUN", 10000)
    for breaker in (ffc.FEODO_CIRCUIT_BREAKER, ffc.SSLBL_CIRCUIT_BREAKER):
        monkeypatch.setattr(breaker, "can_execute", lambda: True)
        monkeypatch.setattr(breaker, "record_success", lambda: None)
        monkeypatch.setattr(breaker, "record_failure", lambda: None)
    monkeypatch.setattr(ffc.FEODO_RATE_LIMITER, "wait_if_needed", lambda: None)
    monkeypatch.setattr(ffc.SSLBL_RATE_LIMITER, "wait_if_needed", lambda: None)
    monkeypatch.setattr(ffc, "_utc_today", lambda: TODAY)
    yield


def _feodo(text: str, writer: Any = None) -> ffc.FeodoCollector:
    c = ffc.FeodoCollector(misp_writer=writer or MagicMock())
    c._fetch_raw = lambda url=None: text  # type: ignore[method-assign]
    if writer is None:
        c.misp_writer.push_indicators.side_effect = lambda items, _src: (len(items), 0)
    return c


def _sslbl(text: str) -> ffc.SSLBlacklistCollector:
    c = ffc.SSLBlacklistCollector(misp_writer=MagicMock())
    c.misp_writer.push_indicators.side_effect = lambda items, _src: (len(items), 0)
    c._fetch_raw = lambda: text  # type: ignore[method-assign]
    return c


class _Blacklist:
    """Stands in for ``AbuseIPDBCollector._make_request``: records each request, answers the blacklist."""

    def __init__(self, entries: List[Dict[str, Any]], honour_limit: bool = True):
        self.entries = entries
        self.honour_limit = honour_limit
        self.requests: List[tuple] = []

    def __call__(self, endpoint: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.requests.append((endpoint, dict(params)))
        data = self.entries[: params["limit"]] if self.honour_limit else list(self.entries)
        return {"meta": {"generatedAt": "2026-10-16T02:00:04+00:00"}, "data": data}


def _abuseipdb(api: _Blacklist) -> aic.AbuseIPDBCollector:
    c = aic.AbuseIPDBCollector(api_key="0f" * 40, misp_writer=MagicMock())
    c.misp_writer.push_indicators.side_effect = lambda items, _src: (len(items), 0)
    c._make_request = api  # type: ignore[method-assign]
    return c


# --------------------------------------------------------------------------- config


@pytest.mark.parametrize("source", ["feodo", "sslbl", "abuseipdb", "Feodo", "SSLBL", "AbuseIPDB"])
def test_the_incremental_default_no_longer_applies(source):
    import config

    assert config.get_effective_limit(source) is None, "the collector applies its own per-run cap"
    assert config.resolve_collection_limit(None, source, baseline=False) is None
    assert config.get_effective_limit("otx") == 200, "other sources keep the incremental default"


def test_the_global_override_still_applies():
    import config

    with patch.object(config, "MAX_ENTRIES_PER_SOURCE", 75):
        assert {s: config.get_effective_limit(s) for s in ("feodo", "sslbl", "abuseipdb")} == {
            "feodo": 75,
            "sslbl": 75,
            "abuseipdb": 75,
        }


def test_code_defaults_and_environment_override():
    import config

    names = ("EDGEGUARD_FEODO_MAX_PER_RUN", "EDGEGUARD_SSLBL_MAX_PER_RUN", "EDGEGUARD_ABUSEIPDB_MAX_PER_RUN")
    with patch.dict(os.environ, {}, clear=False):
        for name in names:
            os.environ.pop(name, None)
        fresh = importlib.reload(config)
        try:
            assert (fresh.FEODO_MAX_PER_RUN, fresh.SSLBL_MAX_PER_RUN, fresh.ABUSEIPDB_MAX_PER_RUN) == (
                15000,
                20000,
                10000,
            )
            os.environ.update(dict(zip(names, ("1234", "0", "500"), strict=True)))
            fresh = importlib.reload(config)
            assert (fresh.FEODO_MAX_PER_RUN, fresh.SSLBL_MAX_PER_RUN, fresh.ABUSEIPDB_MAX_PER_RUN) == (1234, 0, 500)
        finally:
            for name in names:
                os.environ.pop(name, None)
            importlib.reload(config)


# --------------------------------------------------------------------------- Feodo Tracker


def test_feodo_daily_run_is_not_cut_at_the_incremental_default():
    import config

    text = _FEODO_BANNER + "".join(_feodo_row(n, "2024-06-01") for n in range(320))
    c = _feodo(text)
    # The daily DAG wrapper passes get_effective_limit(source).
    st = c.collect(limit=config.get_effective_limit("feodo"), push_to_misp=True)
    assert st["success"] is True and st["count"] == 320, "the whole list is reported, not the first 200"
    pushed = c.misp_writer.push_indicators.call_args[0][0]
    assert [i["value"] for i in pushed] == [_ip(n) for n in range(320)], "below the cap the feed order is kept"


def test_feodo_capped_run_keeps_the_servers_seen_online_most_recently(caplog, monkeypatch):
    import config

    monkeypatch.setattr(config, "FEODO_MAX_PER_RUN", 2)
    rows = [
        _feodo_row(1, "2023-02-10"),
        _feodo_row(2, "2026-03-01"),
        _feodo_row(3, ""),  # never seen online: dated by first_seen
        _feodo_row(4, "2025-11-20"),
    ]
    for order in (rows, list(reversed(rows))):
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger=ffc.logger.name):
            out = _feodo(_FEODO_BANNER + "".join(order)).collect(push_to_misp=False, baseline=True)
        assert [i["value"] for i in out] == [_ip(2), _ip(4)], "latest last_online first, whatever the feed order"
        assert any(
            "complete history lists 4 servers" in r.message and "cap of 2" in r.message and "2 others" in r.message
            for r in caplog.records
        ), "a truncating cap is logged with what it dropped"


def test_feodo_lower_regular_limit_wins_and_zero_cap_means_no_cap(caplog, monkeypatch):
    import config

    text = _FEODO_BANNER + "".join(_feodo_row(n, f"2026-0{n + 1}-01") for n in range(5))
    out = _feodo(text).collect(limit=2, push_to_misp=False)
    assert [i["last_online"] for i in out] == ["2026-05-01", "2026-04-01"]

    monkeypatch.setattr(config, "FEODO_MAX_PER_RUN", 0)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=ffc.logger.name):
        out = _feodo(text).collect(push_to_misp=False)
    assert len(out) == 5
    assert not any("cap of" in r.message for r in caplog.records), "no cut, no warning"


def test_feodo_daily_run_refreshes_every_listed_server_misp_holds(monkeypatch):
    """End to end with the MISP writer: every server of the list MISP already holds is reported again,
    so each stored copy MISP last wrote 60 days ago is refreshed, not only the first 200."""
    from test_misp_reobserved_indicator_refresh import NOW, _Misp, _stored

    import config
    from collectors import misp_writer as mw

    monkeypatch.setattr(mw, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", True)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    for name in (
        "EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS",
        "EDGEGUARD_MISP_REFRESH_MAX_PER_RUN",
        "EDGEGUARD_MISP_REFRESH_MAX_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(mw.time, "sleep", lambda _s: None)

    servers = 250
    misp = _Misp(
        [
            _stored(_ip(n), f"u-{n}", last_seen=NOW - timedelta(days=400), written=NOW - timedelta(days=60))
            for n in range(servers)
        ]
    )
    writer = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
    writer.session = MagicMock()
    writer.session.post.side_effect = misp.post
    text = _FEODO_BANNER + "".join(_feodo_row(n, "2024-06-01") for n in range(servers))
    with (
        patch.object(mw.MISPWriter, "_get_or_create_event", return_value="50"),
        patch.object(mw.MISPWriter, "_push_batch", lambda _self, _event, batch: (len(batch), 0)),
    ):
        st = _feodo(text, writer=writer).collect(limit=config.get_effective_limit("feodo"), push_to_misp=True)
    assert st["success"] is True
    assert len(misp.edits) == servers, "every listed server MISP holds gets its stored copy refreshed"
    assert writer.stats["attributes_refreshed"] == servers


# --------------------------------------------------------------------------- SSL Blacklist


def test_sslbl_daily_run_is_not_cut_at_the_incremental_default():
    import config

    rows = "".join(_sslbl_row(n, f"2026-10-{1 + n % 12:02d} 06:{n % 60:02d}:13") for n in range(450))
    c = _sslbl(_SSLBL_BANNER + rows)
    st = c.collect(limit=config.get_effective_limit("sslbl"), push_to_misp=True)
    assert st["count"] == 450, "the whole blacklist is reported, not the first 200"
    pushed = c.misp_writer.push_indicators.call_args[0][0]
    assert pushed[0]["value"] == _sha1(0), "the first listing after the commented header is kept"
    assert [i["value"] for i in pushed] == [_sha1(n) for n in range(450)], "below the cap the feed order is kept"
    assert all(i["indicator_type"] == "x509-fingerprint-sha1" for i in pushed)


def test_sslbl_header_row_is_recognised_by_name_in_either_form():
    """The column header as a comment (the banner above) or as a plain row: no listing is lost."""
    body = "".join(_sslbl_row(n, "2026-10-12 06:41:13") for n in range(3))
    commented = _sslbl(_SSLBL_BANNER + body).collect(push_to_misp=False)
    plain = _sslbl("# comment\r\nListingdate,SHA1,Listingreason\r\n" + body).collect(push_to_misp=False)
    assert [i["value"] for i in commented] == [i["value"] for i in plain] == [_sha1(n) for n in range(3)]
    assert commented[0]["first_seen"] == "2026-10-12 06:41:13" and commented[0]["listing_reason"] == "vidar c&c"


def test_sslbl_capped_run_keeps_the_newest_listings(caplog, monkeypatch):
    import config

    monkeypatch.setattr(config, "SSLBL_MAX_PER_RUN", 2)
    rows = [
        _sslbl_row(1, "2026-10-12 06:41:13"),
        _sslbl_row(2, "2025-01-03 06:38:23"),
        _sslbl_row(3, "2026-10-11 22:10:00"),
        _sslbl_row(4, "2019-04-02 10:00:00"),
    ]
    for order in (rows, list(reversed(rows))):
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger=ffc.logger.name):
            out = _sslbl(_SSLBL_BANNER + "".join(order)).collect(push_to_misp=False)
        assert [i["first_seen"] for i in out] == ["2026-10-12 06:41:13", "2026-10-11 22:10:00"]
        assert any(
            "lists 4 certificates" in r.message and "cap of 2" in r.message and "2 older ones" in r.message
            for r in caplog.records
        )


def test_sslbl_lower_regular_limit_wins_and_zero_cap_means_no_cap(monkeypatch):
    import config

    body = "".join(_sslbl_row(n, f"2026-10-1{n} 00:00:00") for n in range(5))
    out = _sslbl(_SSLBL_BANNER + body).collect(limit=2, push_to_misp=False)
    assert [i["first_seen"] for i in out] == ["2026-10-14 00:00:00", "2026-10-13 00:00:00"]

    monkeypatch.setattr(config, "SSLBL_MAX_PER_RUN", 0)
    assert len(_sslbl(_SSLBL_BANNER + body).collect(push_to_misp=False)) == 5


# --------------------------------------------------------------------------- AbuseIPDB


def _entries(n: int) -> List[Dict[str, Any]]:
    start = datetime(2026, 10, 16, 1, 0, tzinfo=timezone.utc)
    return [_blacklist_entry(i, (start - timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%S+00:00")) for i in range(n)]


def test_abuseipdb_daily_run_asks_for_the_whole_blacklist_in_one_request():
    import config

    api = _Blacklist(_entries(320))
    c = _abuseipdb(api)
    st = c.collect(limit=config.get_effective_limit("abuseipdb"), push_to_misp=True)
    assert len(api.requests) == 1, "one blacklist request per run, as before"
    endpoint, params = api.requests[0]
    assert endpoint == aic.AbuseIPDBCollector.BLACKLIST_ENDPOINT
    assert params["limit"] == 10000, "the request asks for the plan's maximum, not 200"
    assert st["count"] == 320
    pushed = c.misp_writer.push_indicators.call_args[0][0]
    assert [i["value"] for i in pushed] == [e["ipAddress"] for e in _entries(320)], "the answer's order is kept"


@pytest.mark.parametrize(
    "cap, max_entries, expected",
    [(500, 0, 500), (0, 0, 10000), (10000, 75, 75)],
    ids=["own-cap", "zero-means-the-plan-maximum", "global-override-lower"],
)
def test_abuseipdb_request_limit_follows_the_cap(monkeypatch, cap, max_entries, expected):
    import config

    monkeypatch.setattr(config, "ABUSEIPDB_MAX_PER_RUN", cap)
    monkeypatch.setattr(config, "MAX_ENTRIES_PER_SOURCE", max_entries)
    api = _Blacklist(_entries(3))
    _abuseipdb(api).collect(limit=config.get_effective_limit("abuseipdb"), push_to_misp=False)
    assert [params["limit"] for _e, params in api.requests] == [expected]


def test_abuseipdb_cap_above_the_plan_maximum_asks_for_the_maximum(monkeypatch, caplog):
    import config

    monkeypatch.setattr(config, "ABUSEIPDB_MAX_PER_RUN", 50000)
    api = _Blacklist(_entries(3))
    with caplog.at_level(logging.WARNING, logger=aic.logger.name):
        _abuseipdb(api).collect(push_to_misp=False)
    assert [params["limit"] for _e, params in api.requests] == [10000], "never more than one request returns"
    assert any("per-run cap of 50000 is above the 10000" in r.message for r in caplog.records)


def test_abuseipdb_answer_longer_than_the_request_keeps_the_latest_reports(monkeypatch, caplog):
    import config

    monkeypatch.setattr(config, "ABUSEIPDB_MAX_PER_RUN", 2)
    entries = [
        _blacklist_entry(1, "2026-10-14T09:00:00+00:00"),
        _blacklist_entry(2, "2026-10-16T01:59:00+00:00"),
        _blacklist_entry(3, "2026-10-15T23:30:00+00:00"),
    ]
    with caplog.at_level(logging.WARNING, logger=aic.logger.name):
        out = _abuseipdb(_Blacklist(entries, honour_limit=False)).collect(push_to_misp=False)
    assert [i["value"] for i in out] == [entries[1]["ipAddress"], entries[2]["ipAddress"]]
    assert any("holds 3 addresses, more than the 2 requested" in r.message for r in caplog.records)


def test_abuseipdb_answer_filling_the_request_is_logged(monkeypatch, caplog):
    import config

    monkeypatch.setattr(config, "ABUSEIPDB_MAX_PER_RUN", 3)
    with caplog.at_level(logging.INFO, logger=aic.logger.name):
        out = _abuseipdb(_Blacklist(_entries(5))).collect(push_to_misp=False)
    assert len(out) == 3
    assert any("fills the request (3 addresses" in r.message for r in caplog.records)
