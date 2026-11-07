"""List-source fields the collectors used to drop before MISP (2026-11-07).

    collector item -> MISPWriter.create_attribute (TF_META) -> MISPToNeo4jSync.parse_attribute

- ThreatFox: the records of one value are merged into one item (an ``ip:port`` IOC reported as
  ``IP:443`` and ``IP:8080`` is one MISP attribute carrying both ports, both record ids, both families);
  ``confidence_level`` is kept as ThreatFox's 0-100 integer.
- SSL Blacklist: ``Listingreason`` verbatim, the certificate page as ``reference``, the role
  (``threat_type``) apart from the family (``listing_family``); the generic "Malware C&C" is no family.
- Feodo Tracker: ``ports`` (ints), ``families``, ``c2_status`` as structured keys.
- AbuseIPDB: ``abuse_confidence_score`` (int) and ``ip_country_code``; no zero for a field the answer
  does not carry.
- MalwareBazaar / VirusTotal: the file's ``file_name``, ``file_md5``, ``file_sha1``, ``file_type``;
  VirusTotal's ``threat_category``, ``meaningful_name``, ``file_size`` and detection counts.
- Time-variant values carry ``as_of`` (they stay the first report's values in MISP).
- Comment budget: the largest real records fit unshrunk, an oversized block keeps its scalar keys and
  shrinks in the documented order, and the growth of the comment on a real batch is bounded.

Recorded payloads: ``tests/fixtures/list_sources_2026_11_07.json`` (SSL Blacklist and Feodo Tracker
downloads of 2026-11-07) and ``tests/fixtures/feed_family_labels_2026_11_01.json`` (ThreatFox and
MalwareBazaar records as stored). ThreatFox ``get_iocs`` records: the constructed
``tests/fixtures/threatfox_get_iocs_constructed_2026_11_07.json`` (the keyless exports are gone).
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

FIXTURES = Path(__file__).parent / "fixtures"
LISTS = json.loads((FIXTURES / "list_sources_2026_11_07.json").read_text(encoding="utf-8"))
TF_CONSTRUCTED = json.loads((FIXTURES / "threatfox_get_iocs_constructed_2026_11_07.json").read_text(encoding="utf-8"))
FAMILY_LABELS = json.loads((FIXTURES / "feed_family_labels_2026_11_01.json").read_text(encoding="utf-8"))

# The keys this change adds to an item (and SSL Blacklist's ``reference`` / ``threat_type``), for the
# footprint comparison with the item as the collectors built it before.
NEW_KEYS = (
    "ports",
    "ioc_ids",
    "families",
    "threat_types",
    "confidence_level",
    "c2_status",
    "listing_reason",
    "listing_family",
    "ip_country_code",
    "abuse_confidence_score",
    "file_name",
    "file_md5",
    "file_sha1",
    "file_type",
    "meaningful_name",
    "threat_category",
    "file_size",
    "detection_malicious",
    "detection_total",
)


def _is_utc_time(text: str) -> bool:
    stamp = datetime.fromisoformat(text)
    return stamp.utcoffset() is not None and stamp.utcoffset().total_seconds() == 0


def _meta(attr: Dict[str, Any]) -> Dict[str, Any]:
    assert attr["comment"].startswith("TF_META:"), attr["comment"][:80]
    return json.loads(attr["comment"][len("TF_META:") :])


@pytest.fixture
def writer():
    from collectors.misp_writer import MISPWriter

    return MISPWriter.__new__(MISPWriter)


@pytest.fixture
def quiet_feeds(monkeypatch):
    """No circuit-breaker or rate-limiter side effects for the abuse.ch collectors."""
    import collectors.finance_feed_collector as ffc
    import collectors.global_feed_collector as gfc

    for breaker in (ffc.FEODO_CIRCUIT_BREAKER, ffc.SSLBL_CIRCUIT_BREAKER, gfc.THREATFOX_CIRCUIT_BREAKER):
        monkeypatch.setattr(breaker, "can_execute", lambda: True)
        monkeypatch.setattr(breaker, "record_success", lambda: None)
        monkeypatch.setattr(breaker, "record_failure", lambda: None)
    for limiter in (ffc.FEODO_RATE_LIMITER, ffc.SSLBL_RATE_LIMITER, gfc.THREATFOX_RATE_LIMITER):
        monkeypatch.setattr(limiter, "wait_if_needed", lambda: None)
    return ffc, gfc


def _threatfox_items(gfc, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    c = gfc.ThreatFoxCollector.__new__(gfc.ThreatFoxCollector)
    c.source_name = "threatfox"
    c.api_key = "a" * 48
    c.base_url = "https://threatfox-api.abuse.ch/api/v1/"
    c.misp_writer = MagicMock()
    c._fetch_iocs = lambda days: {"query_status": "ok", "data": records}  # type: ignore[method-assign]
    return c.collect(push_to_misp=False)


def _sslbl_items(ffc) -> List[Dict[str, Any]]:
    c = ffc.SSLBlacklistCollector(misp_writer=MagicMock())
    c._fetch_raw = lambda: LISTS["sslbl_csv"]  # type: ignore[method-assign]
    return c.collect(push_to_misp=False)


def _feodo_items(ffc) -> List[Dict[str, Any]]:
    c = ffc.FeodoCollector(misp_writer=MagicMock())
    c._fetch_raw = lambda url=None: LISTS["feodo_aggressive_csv"]  # type: ignore[method-assign]
    return c.collect(push_to_misp=False, baseline=True)


# --------------------------------------------------------------------------- ThreatFox


def test_threatfox_two_ports_of_one_address_give_one_value_carrying_both(quiet_feeds, writer):
    _ffc, gfc = quiet_feeds
    items = _threatfox_items(gfc, TF_CONSTRUCTED["data"])
    assert [(i["indicator_type"], i["value"]) for i in items] == [
        ("ipv4", "198.51.100.23"),
        ("ipv4", "203.0.113.40"),
        ("domain", "delivery.example.test"),
    ], "one item per value, in the order the values first appear"
    ip = items[0]
    assert ip["ports"] == [443, 8080]
    assert ip["ioc_ids"] == ["3100001", "3100002"]
    assert ip["families"] == ["Nanocore RAT", "Cobalt Strike"], "the most recent record's family first"
    assert ip["threat_types"] == ["botnet_cc"]
    assert ip["confidence_level"] == 100 and ip["confidence_score"] == 1.0, "the highest level of the records"
    # Scalars: the most recent record (3100002); first_seen the earliest, last_seen the latest.
    assert (ip["ioc_id"], ip["malware_family"], ip["reporter"]) == ("3100002", "Nanocore RAT", "reporter-b")
    assert ip["first_seen"] == "2026-11-05 18:03:11 UTC" and ip["last_seen"] == "2026-11-06 22:00:00 UTC"
    assert ip["reference"] == "https://example.test/reports/c2-198-51-100-23", "the other record's reference"
    assert ip["malware_malpedia"] == "https://malpedia.caad.fkie.fraunhofer.de/details/win.nanocore"
    assert ip["tags"] == ["NanoCore", "c2", "CobaltStrike"]

    meta = _meta(writer.create_attribute(ip))
    assert meta["ports"] == [443, 8080] and meta["ioc_ids"] == ["3100001", "3100002"]
    assert meta["families"] == ["Nanocore RAT", "Cobalt Strike"] and meta["threat_types"] == ["botnet_cc"]
    assert meta["confidence_level"] == 100
    assert (meta["ioc_id"], meta["malware_family"], meta["threat_type"]) == ("3100002", "Nanocore RAT", "botnet_cc")
    assert "as_of" not in meta, "ThreatFox sends no time-variant value"


def test_threatfox_merge_does_not_depend_on_the_feed_order(quiet_feeds):
    _ffc, gfc = quiet_feeds
    forward = _threatfox_items(gfc, TF_CONSTRUCTED["data"])
    backward = _threatfox_items(gfc, list(reversed(TF_CONSTRUCTED["data"])))
    by_value = {i["value"]: i for i in backward}
    for item in forward:
        other = by_value[item["value"]]
        for key in ("ports", "ioc_ids", "families", "threat_types", "ioc_id", "malware_family", "first_seen"):
            assert item.get(key) == other.get(key), key


def test_threatfox_level_is_never_invented(quiet_feeds, writer):
    """A record with ``confidence_level: null`` raised a TypeError (``None / 100``); now it has no level."""
    _ffc, gfc = quiet_feeds
    item = next(i for i in _threatfox_items(gfc, TF_CONSTRUCTED["data"]) if i["value"] == "203.0.113.40")
    assert "confidence_level" not in item and item["confidence_score"] == 0.5
    assert item["ports"] == [2222] and item["tags"] == [] and item["reference"] == ""
    meta = _meta(writer.create_attribute(item))
    assert "confidence_level" not in meta and meta["ports"] == [2222]


def test_threatfox_domain_has_no_ports(quiet_feeds, writer):
    _ffc, gfc = quiet_feeds
    domain = _threatfox_items(gfc, TF_CONSTRUCTED["data"])[2]
    assert "ports" not in domain and domain["ioc_ids"] == ["3100004"] and domain["confidence_level"] == 50
    assert "ports" not in _meta(writer.create_attribute(domain))


# --------------------------------------------------------------------------- SSL Blacklist


@pytest.mark.parametrize(
    "reason, threat_type, family",
    [
        ("Vidar C&C", "botnet_cc", "Vidar"),
        ("Malware C&C", "botnet_cc", ""),
        ("Malware distribution", "payload_delivery", ""),
        ("ACRStealer malware distribution", "payload_delivery", "ACRStealer"),
        ("NetSupport RAT malware distribution", "payload_delivery", "NetSupport RAT"),
        ("Vawtrak MITM", "", "Vawtrak"),
        ("QuasarRAT", "", ""),
        ("doxbin.cy", "", ""),
        ("Sinkhole", "", ""),
        ("FIN7", "", ""),
        ("", "", ""),
    ],
)
def test_sslbl_role_is_kept_apart_from_the_family(reason, threat_type, family):
    import collectors.finance_feed_collector as ffc

    assert ffc.sslbl_listing(reason) == (threat_type, family)


def test_sslbl_reason_reference_role_and_family_reach_misp(quiet_feeds, writer):
    ffc, _gfc = quiet_feeds
    items = _sslbl_items(ffc)
    assert len(items) == 15
    reasons = {i["listing_reason"] for i in items}
    assert {"Vidar C&C", "Malware C&C", "NetSupport RAT malware distribution", "doxbin.cy"} <= reasons, "verbatim"

    page = LISTS["sslbl_certificate_page"]
    checked = next(i for i in items if i["value"] == page["sha1"])
    assert checked["reference"] == page["url"], "the page the site links for the certificate"
    assert checked["listing_reason"] == page["listing_reason"] == "Malware C&C"
    assert checked["threat_type"] == "botnet_cc" and "listing_family" not in checked, "the generic reason is no family"

    for item in items:
        meta = _meta(writer.create_attribute(item))
        assert meta["listing_reason"] == item["listing_reason"]
        assert meta["reference"] == f"https://sslbl.abuse.ch/ssl-certificates/sha1/{item['value']}/"
        expected_type, expected_family = ffc.sslbl_listing(item["listing_reason"])
        assert meta.get("threat_type", "") == expected_type
        assert meta.get("listing_family", "") == expected_family
        assert meta["malware_family"] == "", "the parsed family is never the family the sync links today"
        assert "as_of" not in meta

    vidar = next(i for i in items if i["listing_reason"] == "Vidar C&C")
    assert _meta(writer.create_attribute(vidar))["listing_family"] == "Vidar"


def test_sslbl_reason_with_a_comma_is_kept_whole(quiet_feeds):
    ffc, _gfc = quiet_feeds
    c = ffc.SSLBlacklistCollector(misp_writer=MagicMock())
    sha1 = "0123456789abcdef0123456789abcdef01234567"
    c._fetch_raw = lambda: f"# Listingdate,SHA1,Listingreason\r\n2026-11-07 07:00:00,{sha1},Foo, Bar C&C\r\n"  # type: ignore[method-assign]
    (item,) = c.collect(push_to_misp=False)
    assert item["listing_reason"] == "Foo, Bar C&C" and item["listing_family"] == "Foo, Bar"


# --------------------------------------------------------------------------- Feodo Tracker


def test_feodo_ports_families_and_status_are_structured(quiet_feeds, writer):
    ffc, _gfc = quiet_feeds
    items = {i["value"]: i for i in _feodo_items(ffc)}
    assert set(items) == {"12.172.173.82", "103.61.101.11", "195.159.28.230", "162.243.103.246"}
    busiest = _meta(writer.create_attribute(items["12.172.173.82"]))
    assert busiest["ports"] == [20, 21, 22, 443, 465, 990, 993, 995, 2087, 32101, 50001]
    assert busiest["families"] == ["QakBot"] and busiest["c2_status"] == "offline"
    assert _is_utc_time(busiest["as_of"]), "c2_status / last_online are dated"
    two = _meta(writer.create_attribute(items["103.61.101.11"]))
    assert two["ports"] == [447, 449] and two["families"] == ["TrickBot", "Dridex"]
    assert two["malware_family"] == "TrickBot"


# --------------------------------------------------------------------------- AbuseIPDB


def _abuseipdb():
    import collectors.abuseipdb_collector as aic

    return aic.AbuseIPDBCollector(api_key="0f" * 40, misp_writer=MagicMock())


# The blacklist entry shape of tests/test_abuseipdb_blacklist_cache.py and
# tests/test_feodo_sslbl_abuseipdb_run_caps.py (APIv2 ``GET /blacklist``).
BLACKLIST_ENTRY = {
    "ipAddress": "203.0.113.9",
    "countryCode": "NL",
    "abuseConfidenceScore": 100,
    "lastReportedAt": "2026-11-06T21:14:03+00:00",
}


def test_abuseipdb_score_and_country_are_structured_keys(writer):
    item = _abuseipdb()._format_blacklist_result(dict(BLACKLIST_ENTRY))
    assert item["abuse_confidence_score"] == 100 and item["ip_country_code"] == "NL"
    assert "targeted_countries" not in item and "country" not in item
    attr = writer.create_attribute(item)
    meta = _meta(attr)
    assert meta["abuse_confidence_score"] == 100 and meta["ip_country_code"] == "NL"
    assert _is_utc_time(meta["as_of"]), "the score changes at the source: dated"
    assert "targeted_countries" not in meta
    assert "confidence:high" in [t["name"] for t in attr["Tag"]]


def test_abuseipdb_fields_the_answer_lacks_are_not_zero(writer):
    item = _abuseipdb()._format_blacklist_result({"ipAddress": "203.0.113.10"})
    for key in ("abuse_confidence_score", "confidence_score", "total_reports", "num_distinct_users", "ip_country_code"):
        assert key not in item, key
    assert "0%" not in item["description"]
    attr = writer.create_attribute(item)
    assert "confidence:medium" in [t["name"] for t in attr["Tag"]], "the writer's default, not confidence:low"
    assert not attr["comment"].startswith("TF_META:"), "nothing structured to carry"


def test_abuseipdb_check_answer_without_counts_has_none_not_zero():
    result = _abuseipdb()._format_ip_result({"ipAddress": "203.0.113.11", "countryCode": "de"})
    assert result["abuse_confidence_score"] is None and "confidence_score" not in result
    assert result["total_reports"] is None and result["num_distinct_users"] is None
    assert result["ip_country_code"] == "DE"


# --------------------------------------------------------------------------- MalwareBazaar / VirusTotal


def test_malwarebazaar_file_facts_reach_misp(writer):
    import collectors.global_feed_collector as gfc

    row = {
        "first_seen_utc": "2026-10-12 19:25:15",
        "sha256_hash": "38CBDF411E85B4136C8D4B725F7B46530919D45799A8065965D408DB5EBCC15D",
        "md5_hash": "2CBDEEB34862D4F0A40AABCC3236B891",
        "sha1_hash": "d382bede96d914347228a5392812851da046858f",
        "reporter": "abuse_ch",
        "file_name": "net.arm5",
        "file_type_guess": "elf",
        "mime_type": "application/x-executable",
        "signature": "Mirai",
    }
    item = gfc.MalwareBazaarCollector(misp_writer=MagicMock()).build_item(row)
    meta = _meta(writer.create_attribute(item))
    assert meta["file_name"] == "net.arm5" and meta["file_type"] == "elf"
    assert meta["file_md5"] == "2cbdeeb34862d4f0a40aabcc3236b891"
    assert meta["file_sha1"] == "d382bede96d914347228a5392812851da046858f"
    assert "as_of" not in meta, "facts of the file do not change"

    bad = gfc.MalwareBazaarCollector(misp_writer=MagicMock()).build_item({**row, "md5_hash": "n/a", "sha1_hash": "xyz"})
    meta = _meta(writer.create_attribute(bad))
    assert "file_md5" not in meta and "file_sha1" not in meta


def _vt_object(**extra: Any) -> Dict[str, Any]:
    """The ``GET /files/{sha256}`` object shape of tests/test_source_graph_footprint.py."""
    sha = "b09fadd94d841637d7866f587280cfb6bfb6337d94e35c393ed5c38f5f9d5075"
    attrs = {
        "sha256": sha,
        "md5": "0" * 32,
        "sha1": "1" * 40,
        "last_analysis_stats": {"malicious": 48, "suspicious": 1, "undetected": 14, "harmless": 0},
        "first_submission_date": 1760290000,
        "last_submission_date": 1760300000,
        "type_description": "ELF",
        "size": 82344,
        "names": ["bot.arm7"],
        "meaningful_name": "bot.arm7",
        "popular_threat_classification": {
            "suggested_threat_label": "trojan.mirai/gafgyt",
            "popular_threat_category": [{"value": "trojan", "count": 31}],
        },
    }
    attrs.update(extra)
    return {"id": sha, "attributes": attrs}


def test_virustotal_category_file_facts_and_dated_counts_reach_misp(writer):
    from collectors.vt_collector import VTCollector

    item = VTCollector(misp_writer=MagicMock())._process_file(_vt_object())
    meta = _meta(writer.create_attribute(item))
    assert meta["threat_category"] == "trojan" and meta["meaningful_name"] == "bot.arm7"
    assert meta["file_type"] == "ELF" and meta["file_size"] == 82344
    assert meta["file_md5"] == "0" * 32 and meta["file_sha1"] == "1" * 40
    assert (meta["detection_malicious"], meta["detection_total"]) == (48, 63)
    assert _is_utc_time(meta["as_of"]), "the counts change at VirusTotal: dated"


def test_virustotal_zero_detections_are_kept(writer):
    """0 malicious engines is a reported value, not an absent one."""
    from collectors.vt_collector import VTCollector

    stats = {"malicious": 0, "suspicious": 0, "undetected": 60, "harmless": 2}
    item = VTCollector(misp_writer=MagicMock())._process_file(_vt_object(last_analysis_stats=stats))
    meta = _meta(writer.create_attribute(item))
    assert (meta["detection_malicious"], meta["detection_total"]) == (0, 62) and "as_of" in meta


def test_virustotal_absent_fields_are_not_invented():
    from collectors.vt_collector import VTCollector

    obj = _vt_object(type_description=None, size=None, last_analysis_stats={"malicious": 3})
    item = VTCollector(misp_writer=MagicMock())._process_file(obj)
    assert item["file_type"] == "" and item["file_size"] is None, "were 'unknown' and 0"
    assert "detection_malicious" not in item and "detection_total" not in item, "partial stats give no counts"
    assert "Type: unknown" not in item["description"]


# --------------------------------------------------------------------------- time-variant values


def test_urlhaus_status_is_dated_with_the_write_time(writer):
    item = {
        "indicator_type": "url",
        "value": "http://198.51.100.5/bins/x.sh",
        "zone": ["global"],
        "tag": "urlhaus",
        "source": ["urlhaus"],
        "url_status": "online",
        "reference": "https://urlhaus.abuse.ch/url/1/",
    }
    before = datetime.now(timezone.utc).replace(microsecond=0)
    meta = _meta(writer.create_attribute(item))
    after = datetime.now(timezone.utc)
    assert meta["url_status"] == "online"
    assert before <= datetime.fromisoformat(meta["as_of"]) <= after, "the time the attribute is built"


# --------------------------------------------------------------------------- comment budget


def _real_threatfox_and_bazaar_items() -> List[Dict[str, Any]]:
    """Collector items rebuilt from the ThreatFox and MalwareBazaar records stored on the test graph."""
    items = []
    for record in FAMILY_LABELS["records"]:
        if record["source_id"] not in ("threatfox", "malwarebazaar"):
            continue
        raw = json.loads(record["raw_data"])
        item = {
            "indicator_type": "sha256",
            "value": "0" * 64,
            "zone": raw.get("zone") or ["global"],
            "tag": record["source_id"],
            "source": [record["source_id"]],
            "confidence_score": raw.get("confidence_score") or 0.5,
            "malware_family": raw.get("malware_family") or "",
            "malware_malpedia": raw.get("malware_malpedia") or "",
            "reference": raw.get("reference") or "",
            "reporter": raw.get("reporter") or "",
            "tags": raw.get("tf_tags") or [],
            "threat_type": raw.get("threat_type") or "",
            "threat_type_desc": raw.get("threat_type_desc") or "",
            "ioc_id": raw.get("ioc_id") or "",
            "malware_alias": raw.get("malware_alias") or "",
        }
        if record["source_id"] == "threatfox":
            item.update(
                ioc_ids=[item["ioc_id"]],
                families=[item["malware_family"]],
                threat_types=[item["threat_type"]],
            )
        items.append(item)
    return items


def test_largest_real_records_fit_the_budget_unshrunk(quiet_feeds, writer, caplog):
    from collectors.misp_writer import _META_COMMENT_BUDGET
    from collectors.vt_collector import VTCollector

    ffc, gfc = quiet_feeds
    items = (
        _sslbl_items(ffc)
        + _feodo_items(ffc)
        + _threatfox_items(gfc, TF_CONSTRUCTED["data"])
        + _real_threatfox_and_bazaar_items()
        + [_abuseipdb()._format_blacklist_result(dict(BLACKLIST_ENTRY))]
        + [VTCollector(misp_writer=MagicMock())._process_file(_vt_object())]
    )
    with caplog.at_level(logging.WARNING):
        for item in items:
            attr = writer.create_attribute(item)
            assert len(attr["comment"]) <= _META_COMMENT_BUDGET
            meta = _meta(attr)
            for key in NEW_KEYS:
                if item.get(key) not in (None, "", []):
                    assert meta[key] == item[key], (item["value"], key)
    assert not [r for r in caplog.records if "shrunk" in r.getMessage()], "no real record needs shrinking"


def _oversized_threatfox_item() -> Dict[str, Any]:
    """A value at the bounds of what the sources allow (constructed): 300 records, every port distinct,
    20 tags of 64 characters, 40 families, a 2,000-character reference."""
    return {
        "indicator_type": "ipv4",
        "value": "198.51.100.99",
        "zone": ["global"],
        "tag": "threatfox",
        "source": ["threatfox"],
        "confidence_score": 1.0,
        "malware_family": "Cobalt Strike",
        "threat_type": "botnet_cc",
        "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
        "ioc_id": "3200299",
        "malware_alias": "Agentemis,BEACON,CobaltStrike,cobeacon",
        "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike",
        "reporter": "reporter-a",
        "reference": "https://example.test/" + "r" * 1980,
        "tags": [f"tag-{n:02d}-" + "x" * 56 for n in range(20)],
        "ports": list(range(1000, 1300)),
        "ioc_ids": [str(3200000 + n) for n in range(300)],
        "families": [f"Family number {n:02d} label" for n in range(40)],
        "threat_types": ["botnet_cc", "payload_delivery"],
        "confidence_level": 100,
    }


def test_oversized_block_keeps_its_scalars_and_shrinks_in_order(writer):
    from collectors.misp_writer import _META_COMMENT_BUDGET

    item = _oversized_threatfox_item()
    comment = writer.create_attribute(item)["comment"]
    assert len(comment) <= _META_COMMENT_BUDGET
    meta = json.loads(comment[len("TF_META:") :])  # valid JSON
    for key in ("malware_family", "threat_type", "ioc_id", "confidence_level", "malware_malpedia"):
        assert meta[key] == item[key], key
    # Lists go first (tags before the list-source lists), the record ids last; the record ids take back
    # what fits first.
    assert len(meta["tags"]) == 1
    assert len(meta["ioc_ids"]) > len(meta["ports"]) >= 1
    assert meta["ioc_ids"] == item["ioc_ids"][: len(meta["ioc_ids"])], "a shrunk list keeps its first entries"
    assert meta["threat_types"][0] == "botnet_cc" and meta["families"][0] == "Family number 00 label"


def test_moderately_oversized_block_shrinks_only_the_tags(writer):
    """Just over the budget: the feed's tags absorb it, the list-source lists stay whole."""
    from collectors.misp_writer import _META_COMMENT_BUDGET

    item = _oversized_threatfox_item()
    item.update(reference="https://example.test/r", ports=[443, 8080], ioc_ids=["1", "2"], families=["Cobalt Strike"])
    item["tags"] = [f"tag-{n:02d}-" + "x" * 56 for n in range(80)]
    comment = writer.create_attribute(item)["comment"]
    meta = json.loads(comment[len("TF_META:") :])
    assert len(comment) <= _META_COMMENT_BUDGET and 1 <= len(meta["tags"]) < 80
    assert meta["ports"] == [443, 8080] and meta["ioc_ids"] == ["1", "2"] and meta["families"] == ["Cobalt Strike"]


def test_long_file_names_shrink_after_the_lists(writer):
    from collectors.misp_writer import _META_COMMENT_BUDGET

    item = {
        "indicator_type": "sha256",
        "value": "a" * 64,
        "zone": ["global"],
        "tag": "malwarebazaar",
        "source": ["malwarebazaar"],
        "reference": "https://bazaar.abuse.ch/sample/" + "a" * 64 + "/",
        "file_name": "n" * 5000,
        "file_md5": "b" * 32,
        "file_sha1": "c" * 40,
        "file_type": "exe",
        "tags": ["exe"],
    }
    comment = writer.create_attribute(item)["comment"]
    meta = json.loads(comment[len("TF_META:") :])
    assert len(comment) <= _META_COMMENT_BUDGET
    assert 32 <= len(meta["file_name"]) < 5000 and meta["file_md5"] == "b" * 32 and meta["file_sha1"] == "c" * 40


def test_footprint_comment_growth_on_a_real_batch(quiet_feeds, writer):
    """Comment size per attribute before (the item without the new keys) and after, on the recorded batch.

    Measured on 2026-11-07: SSL Blacklist 18 -> 361 characters on average (plus 309 to 392: it had no
    TF_META, so the shared keys come with it), Feodo Tracker plus 65 to 116 (the address with 11 ports),
    ThreatFox plus 80 to 89 (the stored records carry no port and no ``confidence_level``; those add about
    40 more). The bounds leave a margin and fail when a key starts to repeat large text.
    """
    ffc, _gfc = quiet_feeds
    bounds = {"ssl_blacklist": 420, "feodo_tracker": 140, "threatfox": 120}
    batches = {
        "ssl_blacklist": _sslbl_items(ffc),
        "feodo_tracker": _feodo_items(ffc),
        "threatfox": [i for i in _real_threatfox_and_bazaar_items() if i["tag"] == "threatfox"],
    }
    for source, items in batches.items():
        assert items, source
        growth = []
        for item in items:
            before_item = {k: v for k, v in item.items() if k not in NEW_KEYS}
            if source == "ssl_blacklist":
                before_item.pop("reference", None)
                before_item.pop("threat_type", None)
            before = writer.create_attribute(before_item)["comment"]
            after = writer.create_attribute(item)["comment"]
            growth.append(len(after) - len(before))
        assert all(g > 0 for g in growth), (source, growth)
        assert max(growth) <= bounds[source], (source, max(growth), growth)
