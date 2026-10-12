"""Feodo Tracker: list selection, CRLF-safe parsing, and the family / status path to MISP and Neo4j.

Baseline runs download the complete C2 history, regular runs the 30-day list. The fixture
reproduces the live download format (every field quoted, CRLF line endings): a hand-rolled
split once left the last column as ``QakBot"\r``, which only a live check revealed.
"""

from __future__ import annotations

import json
import logging
from datetime import date
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

TODAY = date(2026, 10, 13)

# Live format (verified 2026-10-12): comment block, quoted header row, quoted fields, CRLF.
CSV = (
    "################################################################\r\n"
    "# Feodo Tracker Botnet C2 IP Blocklist (CSV)                   #\r\n"
    "################################################################\r\n"
    '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\r\n'
    '"2024-05-01 10:00:00","203.0.113.10","443","offline","2024-06-01","Emotet"\r\n'
    '"2026-10-01 08:30:00","198.51.100.7","8080","online","2026-10-11","QakBot"\r\n'
    "# END 2 entries\r\n"
)


class FakeResponse:
    status_code = 200
    text = CSV

    def raise_for_status(self) -> None:
        return None


@pytest.fixture
def feodo(monkeypatch: pytest.MonkeyPatch):
    from collectors import finance_feed_collector as mod

    calls: List[Dict[str, Any]] = []

    def fake_request(method: str, url: str, **kwargs: Any) -> FakeResponse:
        calls.append({"method": method, "url": url})
        return FakeResponse()

    monkeypatch.setattr(mod, "request_with_rate_limit_retries", fake_request)
    monkeypatch.setattr(mod, "_utc_today", lambda: TODAY)  # 2026-10-13: the QakBot row was online two days earlier
    monkeypatch.setattr(mod.FEODO_RATE_LIMITER, "wait_if_needed", lambda: None)
    monkeypatch.setattr(mod.FEODO_CIRCUIT_BREAKER, "can_execute", lambda: True)
    writer = MagicMock()
    writer.push_indicators.return_value = (2, 0)
    collector = mod.FeodoCollector(misp_writer=writer)
    collector._test_calls = calls  # type: ignore[attr-defined]
    return collector


def test_list_url_selects_the_history_for_baselines_and_the_30_day_list_otherwise(feodo) -> None:
    assert feodo.list_url(True).endswith("/ipblocklist_aggressive.csv")
    assert feodo.list_url(False).endswith("/ipblocklist.csv")
    assert feodo.url == feodo.URL_RECENT and feodo.baseline_url == feodo.URL_AGGRESSIVE


def test_baseline_run_downloads_the_aggressive_list(feodo) -> None:
    items = feodo.collect(limit=None, push_to_misp=False, baseline=True)
    assert [c["url"] for c in feodo._test_calls] == [feodo.URL_AGGRESSIVE]
    assert [i["value"] for i in items] == ["203.0.113.10", "198.51.100.7"]
    assert items[0]["malware_family"] == "Emotet" and items[0]["status"] == "offline"
    assert items[1]["first_seen"] == "2026-10-01 08:30:00" and items[1]["port"] == "8080"
    assert all(i["indicator_type"] == "ipv4" and i["tag"] == "feodo_tracker" for i in items)


def test_regular_run_downloads_the_30_day_list(feodo) -> None:
    items = feodo.collect(limit=None, push_to_misp=False, baseline=False)
    assert [c["url"] for c in feodo._test_calls] == [feodo.URL_RECENT]
    assert len(items) == 2


def test_both_lists_share_the_parser_and_the_misp_push_path(feodo) -> None:
    status = feodo.collect(limit=None, push_to_misp=True, baseline=True)
    assert status["success"] is True and status["count"] == 2 and status["source"] == "feodo"
    pushed, source = feodo.misp_writer.push_indicators.call_args.args
    assert source == "feodo" and len(pushed) == 2


def test_limit_applies_to_the_history_download_too(feodo) -> None:
    items = feodo.collect(limit=1, push_to_misp=False, baseline=True)
    assert len(items) == 1 and feodo._test_calls[0]["url"] == feodo.URL_AGGRESSIVE


# ---------------------------------------------------------------------------
# Parsing: CRLF, quotes, header position
# ---------------------------------------------------------------------------


def test_last_column_is_clean_with_crlf_line_endings(feodo) -> None:
    items = feodo.collect(limit=None, push_to_misp=False, baseline=True)
    assert [i["malware_family"] for i in items] == ["Emotet", "QakBot"]
    for item in items:
        for key in ("value", "first_seen", "port", "status", "last_online", "malware_family"):
            assert '"' not in item[key] and "\r" not in item[key] and item[key] == item[key].strip(), (key, item[key])


def test_header_row_is_recognised_by_name_not_by_position(feodo, monkeypatch) -> None:
    """A download whose header sits in the comment block must not lose its first data row."""
    from collectors import finance_feed_collector as mod

    body = (
        '# "first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\r\n'
        '"2026-10-01 08:30:00","198.51.100.7","8080","online","2026-10-11","QakBot"\r\n'
        '"2026-10-02 09:00:00","198.51.100.8","443","offline","2026-10-03","Pikabot"\r\n'
    )

    class Resp(FakeResponse):
        text = body

    monkeypatch.setattr(mod, "request_with_rate_limit_retries", lambda *a, **k: Resp())
    items = feodo.collect(limit=None, push_to_misp=False, baseline=False)
    assert [i["value"] for i in items] == ["198.51.100.7", "198.51.100.8"]


def test_short_and_empty_rows_are_skipped_and_do_not_consume_the_limit(feodo, monkeypatch) -> None:
    from collectors import finance_feed_collector as mod

    body = (
        '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\r\n'
        '"broken","row"\r\n'
        '"2026-10-01 08:30:00","","8080","online","2026-10-11","QakBot"\r\n'
        '"2026-10-02 09:00:00","198.51.100.8","443","offline","2026-10-03","Pikabot"\r\n'
    )

    class Resp(FakeResponse):
        text = body

    monkeypatch.setattr(mod, "request_with_rate_limit_retries", lambda *a, **k: Resp())
    items = feodo.collect(limit=1, push_to_misp=False, baseline=False)
    assert [i["value"] for i in items] == ["198.51.100.8"], "the limit counts accepted rows"


# ---------------------------------------------------------------------------
# Recency, confidence and the metadata that travels to MISP and Neo4j
# ---------------------------------------------------------------------------


def test_only_recently_active_servers_are_detection_candidates(feodo) -> None:
    """Actionability follows ``last_online`` within 30 days of the collection day, not the status column."""
    from collectors import finance_feed_collector as mod

    historical, active = feodo.collect(limit=None, push_to_misp=False, baseline=True)
    assert historical["confidence_score"] == mod.FEODO_CONFIDENCE_HISTORICAL < 0.5 <= mod.FEODO_CONFIDENCE_ACTIVE
    assert historical["to_ids"] is False
    assert active["confidence_score"] == mod.FEODO_CONFIDENCE_ACTIVE and active["to_ids"] is True
    assert historical["tags"] == ["c2_status:offline", "port:443"]
    assert active["tags"] == ["c2_status:online", "port:8080"]
    assert active["reference"] == "https://feodotracker.abuse.ch/browse/host/198.51.100.7/"
    assert active["threat_type"] == "botnet_cc" and active["last_online"] == "2026-10-11"


def test_a_stale_online_status_is_not_treated_as_active(feodo, monkeypatch) -> None:
    """Measured 2026-10-12: the feed was frozen since March and its one "online" row was 7 months old."""
    from collectors import finance_feed_collector as mod

    body = (
        "# Last updated: 2026-03-04 14:28:39 UTC\r\n"
        '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\r\n'
        '"2025-12-30 13:56:31","50.16.16.211","443","online","2026-03-12","QakBot"\r\n'
        '"2026-09-20 10:00:00","198.51.100.9","443","offline","2026-09-20","QakBot"\r\n'
    )

    class Resp(FakeResponse):
        text = body

    monkeypatch.setattr(mod, "request_with_rate_limit_retries", lambda *a, **k: Resp())
    stale_online, recent_offline = feodo.collect(limit=None, push_to_misp=False, baseline=False)
    assert stale_online["status"] == "online" and stale_online["to_ids"] is False
    assert stale_online["confidence_score"] == mod.FEODO_CONFIDENCE_HISTORICAL
    assert recent_offline["status"] == "offline" and recent_offline["to_ids"] is True, "seen online 23 days ago"


@pytest.mark.parametrize(
    "last_online, today, expected",
    [
        ("2026-10-13", date(2026, 10, 13), True),
        ("2026-09-13", date(2026, 10, 13), True),  # exactly 30 days
        ("2026-09-12", date(2026, 10, 13), False),  # 31 days
        ("", date(2026, 10, 13), False),
        ("not-a-date", date(2026, 10, 13), False),
    ],
)
def test_recently_active_boundary(last_online, today, expected) -> None:
    from collectors.finance_feed_collector import feodo_is_recently_active

    assert feodo_is_recently_active(last_online, today) is expected


def test_stale_feed_header_is_logged(feodo, monkeypatch, caplog) -> None:
    from collectors import finance_feed_collector as mod

    assert mod.feodo_feed_last_updated("# Last updated: 2026-03-04 14:28:39 UTC   #\r\n").isoformat() == (
        "2026-03-04T14:28:39+00:00"
    )
    assert mod.feodo_feed_last_updated("no header") is None

    class Resp(FakeResponse):
        text = "# Last updated: 2026-03-04 14:28:39 UTC\r\n" + CSV

    monkeypatch.setattr(mod, "request_with_rate_limit_retries", lambda *a, **k: Resp())
    with caplog.at_level(logging.WARNING):
        feodo.collect(limit=None, push_to_misp=False, baseline=True)
    assert any(
        "last updated on 2026-03-04" in r.getMessage() and "223 days ago" in r.getMessage() for r in caplog.records
    )

    caplog.clear()

    class Fresh(FakeResponse):
        text = "# Last updated: 2026-10-12 23:00:00 UTC\r\n" + CSV

    monkeypatch.setattr(mod, "request_with_rate_limit_retries", lambda *a, **k: Fresh())
    with caplog.at_level(logging.WARNING):
        feodo.collect(limit=None, push_to_misp=False, baseline=True)
    assert not any("last updated on" in r.getMessage() for r in caplog.records), "a current feed is not reported"


# ---------------------------------------------------------------------------
# One record per address
# ---------------------------------------------------------------------------

REPEATED = (
    '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\r\n'
    '"2021-01-17 10:00:00","103.61.101.11","449","offline","2021-01-25","Dridex"\r\n'
    '"2021-01-18 09:00:00","103.61.101.11","447","offline","2021-03-02","TrickBot"\r\n'
    '"2021-01-18 09:30:00","103.61.101.11","449","offline","2021-03-02","TrickBot"\r\n'
    '"2022-11-17 08:00:00","12.172.173.82","995","offline","2023-08-25","QakBot"\r\n'
    '"2022-11-17 08:00:00","12.172.173.82","21","offline","2023-07-17","QakBot"\r\n'
    '"2023-05-01 00:00:00","192.0.2.44","443","offline","","Emotet"\r\n'
    '"2023-06-01 12:00:00","192.0.2.45","443","offline","2023-06-01","Emotet"\r\n'
)


@pytest.fixture
def repeated(feodo, monkeypatch):
    from collectors import finance_feed_collector as mod

    class Resp(FakeResponse):
        text = REPEATED

    monkeypatch.setattr(mod, "request_with_rate_limit_retries", lambda *a, **k: Resp())
    return {i["value"]: i for i in feodo.collect(limit=None, push_to_misp=False, baseline=True)}


def test_rows_of_one_address_are_merged_into_one_record(repeated) -> None:
    """MISP holds one attribute per value: without merging only the first row would survive."""
    assert list(repeated) == ["103.61.101.11", "12.172.173.82", "192.0.2.44", "192.0.2.45"]
    reused = repeated["103.61.101.11"]
    assert reused["first_seen"] == "2021-01-17 10:00:00", "earliest first-seen of the three rows"
    assert reused["last_online"] == "2021-03-02", "latest last-online of the three rows"
    assert reused["malware_family"] == "TrickBot", "family of the most recently active row, not of the first row"
    assert reused["tags"] == ["c2_status:offline", "port:447", "port:449", "family:TrickBot", "family:Dridex"]
    same_family = repeated["12.172.173.82"]
    assert same_family["tags"] == ["c2_status:offline", "port:21", "port:995"], (
        "ports sorted; no family label for one family"
    )
    assert same_family["port"] == "995" and same_family["last_online"] == "2023-08-25"


def test_limit_counts_addresses_not_rows(feodo, monkeypatch) -> None:
    from collectors import finance_feed_collector as mod

    class Resp(FakeResponse):
        text = REPEATED

    monkeypatch.setattr(mod, "request_with_rate_limit_retries", lambda *a, **k: Resp())
    items = feodo.collect(limit=2, push_to_misp=False, baseline=True)
    assert [i["value"] for i in items] == ["103.61.101.11", "12.172.173.82"]
    assert items[0]["last_online"] == "2021-03-02", "the first address still carries all three of its rows"


def test_last_seen_comes_from_last_online_and_never_precedes_first_seen(repeated) -> None:
    from collectors.finance_feed_collector import feodo_last_seen

    assert repeated["103.61.101.11"]["last_seen"] == "2021-03-02", "later day: the last-online date"
    assert repeated["192.0.2.45"]["last_seen"] == "2023-06-01 12:00:00", "same day: the first-seen timestamp"
    assert "last_seen" not in repeated["192.0.2.44"], "no last-online date: no last-seen claim"
    assert feodo_last_seen("2023-06-02 00:00:00", "2023-06-01") is None, (
        "earlier than first seen: inconsistent, omitted"
    )
    assert feodo_last_seen("", "2023-06-01") is None


def test_misp_attribute_carries_family_last_seen_and_confidence(feodo) -> None:
    from collectors.misp_writer import MISPWriter

    historical, active = feodo.collect(limit=None, push_to_misp=False, baseline=True)
    writer = MISPWriter.__new__(MISPWriter)

    attr = writer.create_attribute(active)
    assert attr is not None and attr["type"] == "ip-dst" and attr["value"] == "198.51.100.7"
    tags = [t["name"] for t in attr["Tag"]]
    assert "source:Feodo-Tracker" in tags and "confidence:medium" in tags
    assert attr["first_seen"] == "2026-10-01T08:30:00+00:00", "first_seen_utc is published with an explicit UTC offset"
    assert attr["last_seen"] == "2026-10-11T00:00:00+00:00", "last_online becomes the source-reported last-seen"
    assert attr["comment"].startswith("TF_META:"), "the family travels in the shared feed metadata comment"
    meta = json.loads(attr["comment"][len("TF_META:") :])
    assert meta["malware_family"] == "QakBot" and meta["threat_type"] == "botnet_cc"
    assert meta["reference"].endswith("/browse/host/198.51.100.7/") and meta["last_online"] == "2026-10-11"
    assert meta["tags"] == ["c2_status:online", "port:8080"]
    assert attr["to_ids"] is True, "a server seen online in the last 30 days is a detection candidate"

    old = writer.create_attribute(historical)
    assert "confidence:low" in [t["name"] for t in old["Tag"]]
    assert old["to_ids"] is False, "history: abuse.ch warns that the full list causes false positives"
    assert old["last_seen"] == "2024-06-01T00:00:00+00:00"


def test_detection_flag_stays_on_for_items_that_do_not_set_it() -> None:
    """The per-item override must not change any other source: the default remains ``to_ids=True``."""
    from collectors.misp_writer import MISPWriter

    writer = MISPWriter.__new__(MISPWriter)
    plain = {"indicator_type": "ipv4", "value": "198.51.100.9", "zone": ["global"], "tag": "threatfox"}
    assert writer.create_attribute(plain)["to_ids"] is True
    assert writer.create_attribute({**plain, "to_ids": False})["to_ids"] is False


def test_sync_rehydrates_family_last_online_and_the_activity_window(feodo) -> None:
    """``Indicator.malware_family`` drives the INDICATES edges; the last-seen claim bounds the activity window."""
    from collectors.misp_writer import MISPWriter
    from run_misp_to_neo4j import MISPToNeo4jSync

    historical, active = feodo.collect(limit=None, push_to_misp=False, baseline=True)
    writer = MISPWriter.__new__(MISPWriter)
    sync = MISPToNeo4jSync(neo4j_client=MagicMock())
    event = {"id": 9, "info": "EdgeGuard-feodo-2026-10-12", "date": "2026-10-12", "Tag": []}

    item, _rels = sync.parse_attribute({**writer.create_attribute(active), "uuid": "f1"}, event)
    assert item is not None and item["indicator_type"] == "ipv4" and item["value"] == "198.51.100.7"
    assert item["tag"] == "feodo_tracker" and item["malware_family"] == "QakBot"
    assert item["first_seen_at_source"] == "2026-10-01T08:30:00+00:00"
    assert item["last_seen_at_source"] == "2026-10-11T00:00:00+00:00"
    assert item["last_online"] == "2026-10-11", "→ Indicator.last_online"
    assert item["confidence_score"] == 0.5 and item["threat_type"] == "botnet_cc"
    assert item["tf_tags"] == ["c2_status:online", "port:8080"]

    old, _ = sync.parse_attribute({**writer.create_attribute(historical), "uuid": "f2"}, event)
    assert old is not None and old["malware_family"] == "Emotet" and old["confidence_score"] == 0.3
    assert old["last_seen_at_source"] == "2024-06-01T00:00:00+00:00"
