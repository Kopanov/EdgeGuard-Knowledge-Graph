"""List-source fields the collectors used to drop before MISP (2026-11-07).

    collector item -> MISPWriter.create_attribute (TF_META) -> MISPToNeo4jSync.parse_attribute

- ThreatFox: the records of one value are merged into one item (an ``ip:port`` IOC reported as
  ``IP:443`` and ``IP:8080`` is one MISP attribute carrying both ports, both record ids, both families);
  ``confidence_level`` is kept as ThreatFox's 0-100 integer.
- SSL Blacklist: ``Listingreason`` verbatim, the certificate page as ``reference``, the role
  (``threat_type``) apart from the family (``listing_family``); a category word ("Malware C&C",
  "Ransomware C&C") is no family.
- Feodo Tracker: ``ports`` (ints), ``families``, ``c2_status`` as structured keys.
- AbuseIPDB: ``abuse_confidence_score`` (int) and ``ip_country_code``; no zero for a field the answer
  does not carry.
- MalwareBazaar / VirusTotal: the file's ``file_name``, ``file_md5``, ``file_sha1``, ``file_type``;
  VirusTotal's ``threat_category``, ``meaningful_name``, ``file_size`` and detection counts.
- Time-variant values carry ``as_of`` (they stay the first report's values in MISP).
- A value MISP already holds keeps the merged lists of the run that first wrote it.
- Comment budget: the recorded records (every SSL Blacklist reason form, the Feodo Tracker address with
  the most ports, one ThreatFox and one MalwareBazaar record per family label stored on the test graph, a
  recorded MalwareBazaar export row) and constructed ones (ThreatFox ``get_iocs`` records, a VirusTotal
  object, an AbuseIPDB blacklist entry, a file name of 255 characters) fit unshrunk; a constructed block
  at the sources' bounds keeps its scalar keys and shrinks in the documented order; the growth of the
  comment per source on a batch is bounded.

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
from datetime import datetime, timedelta, timezone
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

    for breaker in (
        ffc.FEODO_CIRCUIT_BREAKER,
        ffc.SSLBL_CIRCUIT_BREAKER,
        gfc.THREATFOX_CIRCUIT_BREAKER,
        gfc.URLHAUS_CIRCUIT_BREAKER,
    ):
        monkeypatch.setattr(breaker, "can_execute", lambda: True)
        monkeypatch.setattr(breaker, "record_success", lambda: None)
        monkeypatch.setattr(breaker, "record_failure", lambda: None)
    for limiter in (
        ffc.FEODO_RATE_LIMITER,
        ffc.SSLBL_RATE_LIMITER,
        gfc.THREATFOX_RATE_LIMITER,
        gfc.URLHAUS_RATE_LIMITER,
    ):
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
    assert ip["first_seen"] == "2026-11-05 18:03:11 UTC"
    assert ip["last_seen"] == "2026-11-06 22:00:00 UTC", "the latest of the records, not the primary record's"
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
        for key in (
            "ports",
            "ioc_ids",
            "families",
            "threat_types",
            "ioc_id",
            "malware_family",
            "first_seen",
            "last_seen",
            "confidence_level",
            "reporter",
            "reference",
            "malware_malpedia",
        ):
            assert item.get(key) == other.get(key), key


def _tf_record(ioc_id: str, ioc: str, family: str, first_seen: str, **extra: Any) -> Dict[str, Any]:
    """A ThreatFox ``get_iocs`` record (constructed: the field list of the constructed fixture)."""
    record = {
        "id": ioc_id,
        "ioc": ioc,
        "threat_type": "botnet_cc",
        "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
        "ioc_type": "ip:port",
        "malware_printable": family,
        "malware_alias": None,
        "malware_malpedia": "",
        "confidence_level": 50,
        "first_seen": first_seen,
        "last_seen": None,
        "reporter": "",
        "reference": "",
        "tags": None,
    }
    record.update(extra)
    return record


def _merge(gfc, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    collector = gfc.ThreatFoxCollector.__new__(gfc.ThreatFoxCollector)
    return gfc.threatfox_merge_iocs(records, collector._map_ioc_type)


@pytest.mark.parametrize("reverse", [False, True])
def test_threatfox_primary_reference_wins_whatever_the_feed_order(quiet_feeds, reverse):
    """Both records carry a reference: the most recent record's, listed second in the feed, is kept."""
    _ffc, gfc = quiet_feeds
    records = [
        _tf_record("10", "198.51.100.50:443", "Vidar", "2026-11-05 08:00:00 UTC", reference="https://example.test/old"),
        _tf_record("11", "198.51.100.50:80", "Vidar", "2026-11-06 08:00:00 UTC", reference="https://example.test/new"),
    ]
    (item,) = _merge(gfc, list(reversed(records)) if reverse else records)
    assert item["reference"] == "https://example.test/new" and item["ioc_id"] == "11"


@pytest.mark.parametrize("reverse", [False, True])
def test_threatfox_reporter_and_malpedia_fall_back_and_malpedia_keeps_to_the_primary_family(quiet_feeds, reverse):
    """The primary record (Vidar, id 22) has no reporter and no Malpedia page: the reporter comes from the
    most recent other record (Lumma, id 21); the Malpedia page only from a record of Vidar (id 20), never
    the Lumma page, which names another family."""
    _ffc, gfc = quiet_feeds
    vidar_page = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar"
    records = [
        _tf_record("20", "198.51.100.60:443", "Vidar", "2026-11-04 08:00:00 UTC", malware_malpedia=vidar_page),
        _tf_record(
            "21",
            "198.51.100.60:8443",
            "Lumma Stealer",
            "2026-11-05 08:00:00 UTC",
            reporter="reporter-l",
            malware_malpedia="https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma",
        ),
        _tf_record("22", "198.51.100.60:80", "Vidar", "2026-11-06 08:00:00 UTC"),
    ]
    (item,) = _merge(gfc, list(reversed(records)) if reverse else records)
    assert (item["ioc_id"], item["malware_family"]) == ("22", "Vidar")
    assert item["reporter"] == "reporter-l"
    assert item["malware_malpedia"] == vidar_page

    (alone,) = _merge(gfc, [r for r in records if r["id"] != "20"])
    assert alone["malware_family"] == "Vidar" and alone["malware_malpedia"] == "", "no page of another family"


@pytest.mark.parametrize("reverse", [False, True])
def test_threatfox_same_first_seen_makes_the_higher_id_primary(quiet_feeds, reverse):
    """Records of one submission share the second of ``first_seen``: the higher id is the primary record."""
    _ffc, gfc = quiet_feeds
    records = [
        _tf_record("21", "198.51.100.70:443", "Remcos", "2026-11-06 08:00:00 UTC"),
        _tf_record("20", "198.51.100.70:8080", "AsyncRAT", "2026-11-06 08:00:00 UTC"),
    ]
    (item,) = _merge(gfc, list(reversed(records)) if reverse else records)
    assert (item["ioc_id"], item["malware_family"]) == ("21", "Remcos")
    assert item["families"] == ["Remcos", "AsyncRAT"]


def test_threatfox_zones_come_from_every_family_of_the_value(quiet_feeds):
    """A sector named only by the other record's family (constructed family name) reaches the item."""
    _ffc, gfc = quiet_feeds
    records = [
        _tf_record("30", "198.51.100.80:443", "Cobalt Strike", "2026-11-06 08:00:00 UTC"),
        _tf_record("29", "198.51.100.80:8443", "Banking Trojan", "2026-11-05 08:00:00 UTC"),
    ]
    (item,) = _merge(gfc, records)
    assert item["malware_family"] == "Cobalt Strike"
    assert "finance" in item["zone"]
    (alone,) = _merge(gfc, records[:1])
    assert "finance" not in alone["zone"], "the sector comes from the second family"


def test_threatfox_record_ids_sort_by_number(quiet_feeds):
    _ffc, gfc = quiet_feeds
    records = [
        _tf_record("1000", "198.51.100.90:443", "Vidar", "2026-11-06 08:00:00 UTC"),
        _tf_record("999", "198.51.100.90:80", "Vidar", "2026-11-05 08:00:00 UTC"),
    ]
    (item,) = _merge(gfc, records)
    assert item["ioc_ids"] == ["999", "1000"]


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
        ("Ransomware C&C", "botnet_cc", ""),
        ("TA505 C&C", "botnet_cc", "TA505"),
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
    assert len(items) == 17
    reasons = {i["listing_reason"] for i in items}
    assert {"Vidar C&C", "Malware C&C", "NetSupport RAT malware distribution", "doxbin.cy"} <= reasons, "verbatim"
    ransomware = next(i for i in items if i["listing_reason"] == "Ransomware C&C")
    assert ransomware["threat_type"] == "botnet_cc" and "listing_family" not in ransomware, "a category, no family"
    ta505 = next(i for i in items if i["listing_reason"] == "TA505 C&C")
    assert ta505["listing_family"] == "TA505", "the list's own label, an actor here; kept in MISP only"

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


# --------------------------------------------------------------------------- input checks of the parsers


@pytest.mark.parametrize(
    "value, maximum, expected",
    [
        (85, 100, 85),
        ("85", 100, 85),
        (" 85 ", 100, 85),
        (85.0, 100, 85),
        (0, 100, 0),
        ("0", 100, 0),
        (100, 100, 100),
        (101, 100, None),
        (101, None, 101),
        (-1, 100, None),
        ("-1", 100, None),
        (85.5, 100, None),
        (True, 100, None),
        (False, None, None),
        (None, 100, None),
        ("", 100, None),
        ("n/a", 100, None),
    ],
)
def test_abuse_int_keeps_whole_non_negative_numbers_only(value, maximum, expected):
    import collectors.abuseipdb_collector as aic

    assert aic.abuse_int(value, maximum=maximum) == expected


@pytest.mark.parametrize(
    "value, expected",
    [("NL", "NL"), ("nl", "NL"), (" de ", "DE"), ("NLD", ""), ("n1", ""), ("N", ""), ("ÄÖ", ""), (None, ""), (12, "")],
)
def test_country_code_is_two_ascii_letters(value, expected):
    import collectors.abuseipdb_collector as aic

    assert aic.country_code(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [(85, 85), ("85", 85), (0, 0), (100, 100), (101, None), (-1, None), (True, None), (None, None), ("x", None)],
)
def test_threatfox_confidence_level_is_an_int_from_0_to_100(value, expected):
    import collectors.global_feed_collector as gfc

    assert gfc._threatfox_confidence_level(value) == expected


@pytest.mark.parametrize(
    "ioc_type, ioc, expected",
    [
        ("ip:port", "198.51.100.7:8080", 8080),
        ("ip:port", "198.51.100.7:1", 1),
        ("ip:port", "198.51.100.7:65535", 65535),
        ("ip:port", "198.51.100.7:0", None),
        ("ip:port", "198.51.100.7:65536", None),
        ("ip:port", "198.51.100.7:http", None),
        ("ip:port", "198.51.100.7", None),
        ("domain", "example.test:8080", None),
    ],
)
def test_threatfox_port_is_a_port_of_an_ip_port_ioc(ioc_type, ioc, expected):
    import collectors.global_feed_collector as gfc

    assert gfc._threatfox_port(ioc_type, ioc) == expected


def test_feodo_ports_outside_the_port_range_are_left_out(quiet_feeds):
    """Constructed rows in the Feodo Tracker CSV shape: ports 0 and 65536 name no port."""
    ffc, _gfc = quiet_feeds
    header = '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\r\n'
    rows = "".join(
        f'"2026-03-01 10:00:0{n}","198.51.100.31","{port}","offline","2026-03-02","QakBot"\r\n'
        for n, port in enumerate(("0", "443", "65536", "65535"))
    )
    c = ffc.FeodoCollector(misp_writer=MagicMock())
    c._fetch_raw = lambda url=None: header + rows  # type: ignore[method-assign]
    (item,) = c.collect(push_to_misp=False, baseline=True)
    assert item["ports"] == [443, 65535]


def test_writer_keeps_only_well_formed_list_source_values():
    """``_tf_meta_source_fields`` on a constructed item with malformed entries."""
    from collectors.misp_writer import _tf_meta_source_fields

    fields = _tf_meta_source_fields(
        {
            "ports": [443, 443, 0, 65536, True, "8080", 8080],
            "ioc_ids": [1, "1", " 2 ", "", None, True],
            "families": [" Vidar ", "Vidar", ""],
            "confidence_level": -1,
            "abuse_confidence_score": True,
            "file_size": False,
            "detection_total": 0,
            "detection_malicious": 3,
            "listing_reason": "  Vidar C&C  ",
            "ip_country_code": "   ",
        }
    )
    assert fields["ports"] == [443, 8080]
    assert fields["ioc_ids"] == ["1", "2"]
    assert fields["families"] == ["Vidar"]
    assert fields["detection_total"] == 0 and fields["detection_malicious"] == 3, "a reported 0 is kept"
    assert fields["listing_reason"] == "Vidar C&C"
    for key in ("confidence_level", "abuse_confidence_score", "file_size", "ip_country_code", "threat_types"):
        assert key not in fields, key


def test_virustotal_size_must_be_a_non_negative_int():
    from collectors.vt_collector import VTCollector

    collector = VTCollector(misp_writer=MagicMock())
    for size in (True, -5, "82344", 1.5):
        assert collector._process_file(_vt_object(size=size))["file_size"] is None, size
    assert collector._process_file(_vt_object(size=0))["file_size"] == 0


# --------------------------------------------------------------------------- MalwareBazaar / VirusTotal


# The Mirai row of the MalwareBazaar export recorded on 2026-10-12 (``SAMPLE_EXPORT`` in
# tests/test_malwarebazaar_collector.py), the fields ``build_item`` reads.
MB_EXPORT_ROW = {
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


def test_malwarebazaar_file_facts_reach_misp(writer):
    import collectors.global_feed_collector as gfc

    row = dict(MB_EXPORT_ROW)
    item = gfc.MalwareBazaarCollector(misp_writer=MagicMock()).build_item(row)
    meta = _meta(writer.create_attribute(item))
    assert meta["file_name"] == "net.arm5" and meta["file_type"] == "elf"
    assert meta["file_md5"] == "2cbdeeb34862d4f0a40aabcc3236b891"
    assert meta["file_sha1"] == "d382bede96d914347228a5392812851da046858f"
    assert "as_of" not in meta, "facts of the file do not change"

    collector = gfc.MalwareBazaarCollector(misp_writer=MagicMock())
    for md5, sha1 in (("n/a", "n/a"), ("not-a-hash", "xyz"), ("2cbdeeb34862d4f0a40aabcc3236b89", "d382bede" * 6)):
        meta = _meta(writer.create_attribute(collector.build_item({**row, "md5_hash": md5, "sha1_hash": sha1})))
        assert "file_md5" not in meta and "file_sha1" not in meta, (md5, sha1)


def _vt_object(**extra: Any) -> Dict[str, Any]:
    """The ``GET /files/{sha256}`` object shape of tests/test_source_graph_footprint.py.

    ``last_analysis_stats`` has the eight keys of the recorded VirusTotal objects (malicious, suspicious,
    undetected, harmless, timeout, confirmed-timeout, failure, type-unsupported); the counts are
    constructed, the four engine states without a verdict non-zero."""
    sha = "b09fadd94d841637d7866f587280cfb6bfb6337d94e35c393ed5c38f5f9d5075"
    attrs = {
        "sha256": sha,
        "md5": "0" * 32,
        "sha1": "1" * 40,
        "last_analysis_stats": {
            "malicious": 48,
            "suspicious": 1,
            "undetected": 14,
            "harmless": 0,
            "timeout": 2,
            "confirmed-timeout": 1,
            "failure": 3,
            "type-unsupported": 9,
        },
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
    assert (meta["detection_malicious"], meta["detection_total"]) == (48, 48 + 1 + 14 + 0), (
        "the engines that gave a verdict; timeout, confirmed-timeout, failure and type-unsupported are left out"
    )
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

    obj = _vt_object(type_description=None, size=None, last_analysis_stats={"malicious": 3}, md5="n/a", sha1="")
    item = VTCollector(misp_writer=MagicMock())._process_file(obj)
    assert item["file_type"] == "" and item["file_size"] is None, "were 'unknown' and 0"
    assert item["file_md5"] == "" and item["file_sha1"] == "", "only a digest of the right length is kept"
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


# --------------------------------------------------------------------------- a value MISP already holds


@pytest.mark.parametrize("written_days_ago", [2, 60])
def test_a_later_run_does_not_grow_the_lists_misp_holds(quiet_feeds, monkeypatch, written_days_ago):
    """The merge covers the records of one run. A first run reads only ``198.51.100.23:443``; a later run
    reads ``:443`` and ``:8080`` (another id and family) and merges them. MISP holds the value, so the item
    is not pushed again, and a copy past the refresh interval gets ``last_seen`` only: the stored
    ``TF_META`` keeps the first run's ports, ids and families (the documented limit)."""
    from test_misp_reobserved_indicator_refresh import NOW, _Misp, _push, _stored

    import collectors.misp_writer as mw

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

    _ffc, gfc = quiet_feeds
    tag = "source:ThreatFox"
    rec443, rec8080 = (
        next(r for r in TF_CONSTRUCTED["data"] if r["ioc"] == ioc)
        for ioc in ("198.51.100.23:443", "198.51.100.23:8080")
    )
    (first,) = _threatfox_items(gfc, [dict(rec443)])
    _result, pushed, _writer = _push([first], _Misp([], tag=tag))
    (written,) = pushed
    assert _meta(written)["ports"] == [443]

    later = _threatfox_items(gfc, [dict(rec443), dict(rec8080)])
    assert later[0]["ports"] == [443, 8080] and later[0]["families"] == ["Nanocore RAT", "Cobalt Strike"]
    row = _stored(
        written["value"],
        "u-tf",
        last_seen=None,
        written=NOW - timedelta(days=written_days_ago),
        info="EdgeGuard-threatfox-2026-11-05",
        attr_type=written["type"],
        tag=tag,
    )
    row["comment"] = written["comment"]
    misp = _Misp([row], tag=tag)
    result, pushed_later, _writer = _push(later, misp)
    assert pushed_later == [] and result == (0, 0), "a value MISP holds is not pushed again"
    if written_days_ago < 30:
        assert misp.edits == []
    else:
        assert [set(body["Attribute"]) for _uuid, body in misp.edits] == [{"last_seen"}], "never the comment"
    stored = _meta(misp.stored[0])
    assert stored["ports"] == [443] and stored["ioc_ids"] == ["3100001"] and stored["families"] == ["Cobalt Strike"]


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


def test_recorded_and_sample_records_fit_the_budget_unshrunk(quiet_feeds, writer, caplog):
    """The recorded records (every SSL Blacklist reason form, the Feodo Tracker address with the most
    ports, one ThreatFox and one MalwareBazaar record per family label stored on the test graph, a
    recorded MalwareBazaar export row) and the constructed ones fit unshrunk, every list-source key whole."""
    import collectors.global_feed_collector as gfc_module
    from collectors.misp_writer import _META_COMMENT_BUDGET
    from collectors.vt_collector import VTCollector

    ffc, gfc = quiet_feeds
    items = (
        _sslbl_items(ffc)
        + _feodo_items(ffc)
        + _threatfox_items(gfc, TF_CONSTRUCTED["data"])
        + _real_threatfox_and_bazaar_items()
        + [gfc_module.MalwareBazaarCollector(misp_writer=MagicMock()).build_item(dict(MB_EXPORT_ROW))]
        + [_abuseipdb()._format_blacklist_result(dict(BLACKLIST_ENTRY))]
        + [VTCollector(misp_writer=MagicMock())._process_file(_vt_object())]
    )
    compared: Dict[str, set] = {}
    with caplog.at_level(logging.WARNING):
        for item in items:
            attr = writer.create_attribute(item)
            assert len(attr["comment"]) <= _META_COMMENT_BUDGET
            meta = _meta(attr)
            for key in NEW_KEYS:
                if item.get(key) not in (None, "", []):
                    assert meta[key] == item[key], (item["value"], key)
                    compared.setdefault(item["tag"], set()).add(key)
    assert not [r for r in caplog.records if "shrunk" in r.getMessage()], "no record needs shrinking"
    assert {"file_name", "file_md5", "file_sha1", "file_type"} <= compared["malwarebazaar"]
    assert {"ports", "confidence_level", "ioc_ids", "families"} <= compared["threatfox"]
    assert {"listing_reason", "listing_family"} <= compared["ssl_blacklist"]


def test_file_name_at_the_file_system_limit_fits_whole(writer, caplog):
    """A MalwareBazaar file name of 255 characters (constructed: the usual file-system limit; the file names
    on the test graph were never stored, so their real size is unmeasured) is written whole."""
    import collectors.global_feed_collector as gfc
    from collectors.misp_writer import _META_COMMENT_BUDGET

    row = dict(MB_EXPORT_ROW, file_name="n" * 251 + ".exe", file_type_guess="exe")
    item = gfc.MalwareBazaarCollector(misp_writer=MagicMock()).build_item(row)
    with caplog.at_level(logging.WARNING):
        comment = writer.create_attribute(item)["comment"]
    assert len(comment) <= _META_COMMENT_BUDGET
    assert _meta({"comment": comment})["file_name"] == row["file_name"], "written whole"
    assert not [r for r in caplog.records if "shrunk" in r.getMessage()]


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


@pytest.mark.parametrize("source", ["virustotal", "ssl_blacklist"])
def test_long_meaningful_name_and_listing_reason_shrink_and_the_scalars_stay_whole(quiet_feeds, writer, source):
    """A constructed 5,000-character ``meaningful_name`` (VirusTotal) or ``listing_reason`` (SSL Blacklist)
    is shortened, never dropped, and the comment fits; the scalar keys stay whole."""
    from collectors.misp_writer import _META_COMMENT_BUDGET
    from collectors.vt_collector import VTCollector

    ffc, _gfc = quiet_feeds
    if source == "virustotal":
        item = VTCollector(misp_writer=MagicMock())._process_file(_vt_object(meaningful_name="m" * 5000))
        key = "meaningful_name"
        whole = ("file_md5", "file_sha1", "file_type", "threat_category", "file_size", "detection_malicious")
    else:
        vidar = next(i for i in _sslbl_items(ffc) if i["listing_reason"] == "Vidar C&C")
        item = dict(vidar, listing_reason="Vidar C&C " + "r" * 5000)
        key = "listing_reason"
        whole = ("threat_type", "listing_family")
    comment = writer.create_attribute(item)["comment"]
    meta = json.loads(comment[len("TF_META:") :])
    assert len(comment) <= _META_COMMENT_BUDGET
    assert 32 <= len(meta[key]) < len(item[key]) and item[key].startswith(meta[key])
    for name in whole:
        assert meta[name] == item[name], name


_URLHAUS_CSV_CONSTRUCTED = "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n" + "".join(
    f'"{3650000 + n}","2026-11-0{n} 12:00:00","http://203.0.113.{n}:{40000 + n}/i","{status}",'
    f'"2026-11-0{n} 12:00:00","malware_download","32-bit,elf,mips,Mozi",'
    f'"https://urlhaus.abuse.ch/url/{3650000 + n}/","reporter-u"\n'
    for n, status in ((1, "online"), (2, "offline"), (3, "online"))
)


def _urlhaus_items(gfc) -> List[Dict[str, Any]]:
    """URLhaus items from constructed ``recent.csv`` rows (the export needs the abuse.ch Auth-Key)."""
    c = gfc.URLhausCollector.__new__(gfc.URLhausCollector)
    c.api_key = "a" * 48
    c.urls = [f"https://urlhaus-api.abuse.ch/v2/files/exports/{c.api_key}/recent.csv"]
    c.source_name = "urlhaus"
    c.misp_writer = MagicMock()
    c._fetch_feed = lambda url: _URLHAUS_CSV_CONSTRUCTED  # type: ignore[method-assign]
    return c.collect(push_to_misp=False)


def test_footprint_comment_growth_per_source(quiet_feeds, writer, monkeypatch):
    """Comment size per attribute without the list-source keys and ``as_of`` and with them.

    Measured on 2026-11-07 (the item without the keys of ``NEW_KEYS`` and without ``as_of``, against the
    item as the collectors build it): SSL Blacklist 309 to 392 more characters (it has a ``TF_META``
    only through these keys, so the shared keys come with them), AbuseIPDB about 280 (the same), Feodo
    Tracker 103 to 154 (the address with 11 ports), ThreatFox 80 to 89 on the stored records and 103 to 160
    on the constructed ``get_iocs`` records (ports and ``confidence_level``), URLhaus 38 (``as_of`` only).
    The bounds leave a margin and fail when a key starts to repeat large text.
    """
    import collectors.misp_writer as mw

    ffc, gfc = quiet_feeds
    bounds = {
        "ssl_blacklist": (300, 420),
        "abuseipdb": (250, 320),
        "feodo_tracker": (90, 180),
        "threatfox": (60, 180),
        "urlhaus": (38, 38),
    }
    batches = {
        "ssl_blacklist": _sslbl_items(ffc),
        "abuseipdb": [_abuseipdb()._format_blacklist_result(dict(BLACKLIST_ENTRY))],
        "feodo_tracker": _feodo_items(ffc),
        "threatfox": [i for i in _real_threatfox_and_bazaar_items() if i["tag"] == "threatfox"]
        + _threatfox_items(gfc, TF_CONSTRUCTED["data"]),
        "urlhaus": _urlhaus_items(gfc),
    }
    time_variant = mw._TF_META_TIME_VARIANT
    for source, items in batches.items():
        assert items, source
        growth = []
        for item in items:
            before_item = {k: v for k, v in item.items() if k not in NEW_KEYS}
            if source == "ssl_blacklist":
                before_item.pop("reference", None)
                before_item.pop("threat_type", None)
            monkeypatch.setattr(mw, "_TF_META_TIME_VARIANT", ())
            before = writer.create_attribute(before_item)["comment"]
            monkeypatch.setattr(mw, "_TF_META_TIME_VARIANT", time_variant)
            after = writer.create_attribute(item)["comment"]
            growth.append(len(after) - len(before))
        low, high = bounds[source]
        assert min(growth) >= low and max(growth) <= high, (source, growth)
