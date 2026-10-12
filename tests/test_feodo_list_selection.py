"""Feodo Tracker: list selection, CRLF-safe parsing, and the family / status path to MISP and Neo4j.

Baseline runs download the complete C2 history, regular runs the 30-day list. The fixture
reproduces the live download format (every field quoted, CRLF line endings): a hand-rolled
split once left the last column as ``QakBot"\r``, which only a live check revealed.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

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
# Status, confidence and the metadata that travels to MISP and Neo4j
# ---------------------------------------------------------------------------


def test_offline_servers_are_published_at_low_confidence(feodo) -> None:
    from collectors import finance_feed_collector as mod

    offline, online = feodo.collect(limit=None, push_to_misp=False, baseline=True)
    assert offline["confidence_score"] == mod.FEODO_CONFIDENCE_OFFLINE < 0.5 <= mod.FEODO_CONFIDENCE_ONLINE
    assert online["confidence_score"] == mod.FEODO_CONFIDENCE_ONLINE
    assert offline["tags"] == ["c2_status:offline", "port:443", "last_online:2024-06-01"]
    assert online["tags"] == ["c2_status:online", "port:8080", "last_online:2026-10-11"]
    assert online["reference"] == "https://feodotracker.abuse.ch/browse/host/198.51.100.7/"
    assert online["threat_type"] == "botnet_cc"


def test_misp_attribute_carries_family_status_and_confidence(feodo) -> None:
    from collectors.misp_writer import MISPWriter

    offline, online = feodo.collect(limit=None, push_to_misp=False, baseline=True)
    writer = MISPWriter.__new__(MISPWriter)

    attr = writer.create_attribute(online)
    assert attr is not None and attr["type"] == "ip-dst" and attr["value"] == "198.51.100.7"
    tags = [t["name"] for t in attr["Tag"]]
    assert "source:Feodo-Tracker" in tags and "confidence:medium" in tags
    assert attr["first_seen"] == "2026-10-01T08:30:00+00:00", "first_seen_utc is published with an explicit UTC offset"
    assert "last_seen" not in attr, "last_online is a date; it travels as a label, not as MISP last_seen"
    assert attr["comment"].startswith("TF_META:"), "the family travels in the shared abuse.ch metadata comment"
    meta = json.loads(attr["comment"][len("TF_META:") :])
    assert meta["malware_family"] == "QakBot" and meta["threat_type"] == "botnet_cc"
    assert meta["reference"].endswith("/browse/host/198.51.100.7/")
    assert meta["tags"] == ["c2_status:online", "port:8080", "last_online:2026-10-11"]

    assert attr["to_ids"] is True, "a server reported online is a detection candidate"

    old = writer.create_attribute(offline)
    assert "confidence:low" in [t["name"] for t in old["Tag"]]
    assert old["to_ids"] is False, (
        "an offline server is history: abuse.ch warns that the full list causes false positives"
    )


def test_detection_flag_stays_on_for_items_that_do_not_set_it() -> None:
    """The per-item override must not change any other source: the default remains ``to_ids=True``."""
    from collectors.misp_writer import MISPWriter

    writer = MISPWriter.__new__(MISPWriter)
    plain = {"indicator_type": "ipv4", "value": "198.51.100.9", "zone": ["global"], "tag": "threatfox"}
    assert writer.create_attribute(plain)["to_ids"] is True
    assert writer.create_attribute({**plain, "to_ids": False})["to_ids"] is False


def test_sync_rehydrates_the_family_so_indicates_edges_can_be_built(feodo) -> None:
    """``Indicator.malware_family`` is what ``build_relationships`` step 9 matches against Malware nodes."""
    from collectors.misp_writer import MISPWriter
    from run_misp_to_neo4j import MISPToNeo4jSync

    offline, online = feodo.collect(limit=None, push_to_misp=False, baseline=True)
    writer = MISPWriter.__new__(MISPWriter)
    sync = MISPToNeo4jSync(neo4j_client=MagicMock())
    event = {"id": 9, "info": "EdgeGuard-feodo-2026-10-12", "date": "2026-10-12", "Tag": []}

    item, _rels = sync.parse_attribute({**writer.create_attribute(online), "uuid": "f1"}, event)
    assert item is not None and item["indicator_type"] == "ipv4" and item["value"] == "198.51.100.7"
    assert item["tag"] == "feodo_tracker" and item["malware_family"] == "QakBot"
    assert item["first_seen_at_source"] == "2026-10-01T08:30:00+00:00"
    assert item["confidence_score"] == 0.5 and item["threat_type"] == "botnet_cc"
    assert item["tf_tags"] == ["c2_status:online", "port:8080", "last_online:2026-10-11"]

    old, _ = sync.parse_attribute({**writer.create_attribute(offline), "uuid": "f2"}, event)
    assert old is not None and old["malware_family"] == "Emotet" and old["confidence_score"] == 0.3
