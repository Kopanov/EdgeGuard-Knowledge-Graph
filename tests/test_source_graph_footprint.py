"""What each feed source writes to the graph, checked along the production path.

    collector item -> MISPWriter.create_attribute -> MISPToNeo4jSync.parse_attribute
                   -> Neo4jClient.merge_indicators_batch (the row handed to Cypher)

The Neo4j driver is replaced by a recorder, so each test asserts on the exact batch row the
MERGE query receives: the node key, the node properties and the SOURCED_FROM timestamps.
Before 2026-10-13 several properties that the REST and GraphQL APIs expose never left the
collector item (VirusTotal ``threat_label`` / ``yara_rules`` / ``sigma_rules``, URLhaus
``url_status`` / ``last_online``), and ThreatFox's ``first_seen`` was dropped because of its
`` UTC`` suffix; a trace of this path against the live feeds showed it.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

SHA = "b09fadd94d841637d7866f587280cfb6bfb6337d94e35c393ed5c38f5f9d5075"


@pytest.fixture
def path(monkeypatch: pytest.MonkeyPatch):
    """Returns ``run(collector_item) -> (misp_attribute, sync_item, batch_row)``."""
    import neo4j_client as nc
    from collectors.misp_writer import MISPWriter
    from run_misp_to_neo4j import MISPToNeo4jSync

    writer = MISPWriter.__new__(MISPWriter)
    sync = MISPToNeo4jSync(neo4j_client=MagicMock())
    captured: List[Dict[str, Any]] = []

    def recorder(driver, query, *, label, source_id, batch_len, query_kwargs, **_kw):
        captured.append({"query": query, "kwargs": query_kwargs})
        return True, batch_len

    monkeypatch.setattr(nc, "_execute_batch_with_retry", recorder)
    client = nc.Neo4jClient.__new__(nc.Neo4jClient)
    client.driver = object()

    def run(item: Dict[str, Any], source: Optional[str] = None):
        attr = writer.create_attribute(dict(item))
        assert attr is not None
        event = {"id": 77, "info": f"EdgeGuard-{source or item['tag']}-2026-10-13", "date": "2026-10-13", "Tag": []}
        sync_item, _rels = sync.parse_attribute({**attr, "uuid": "u-1"}, event)
        assert sync_item is not None
        captured.clear()
        ok, errors = client.merge_indicators_batch([dict(sync_item)], source_id=sync_item["tag"])
        assert (ok, errors) == (1, 0), "the batch must accept the row"
        row = dict(captured[0]["kwargs"]["batch"][0])
        row["raw_data"] = json.loads(row["raw_data"])
        return attr, sync_item, row

    run.query = lambda: captured[0]["query"]  # type: ignore[attr-defined]
    return run


def _vt_item(**extra: Any) -> Dict[str, Any]:
    from collectors.vt_collector import VTCollector

    vt = VTCollector(misp_writer=MagicMock())
    obj = {
        "id": SHA,
        "attributes": {
            "sha256": SHA,
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
            "crowdsourced_yara_results": [{"rule_name": "Mirai_Botnet_Malware"}, {"rule_name": "ELF_Generic"}],
            "sigma_analysis_results": [{"rule_title": "Suspicious Shell Download"}],
        },
    }
    obj["attributes"].update(extra)
    item = vt._process_file(obj)
    assert item is not None
    return item


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------


def test_virustotal_threat_label_and_rule_names_reach_the_node(path) -> None:
    attr, sync_item, row = path(_vt_item())
    assert attr["type"] == "sha256" and "source:VirusTotal" in [t["name"] for t in attr["Tag"]]
    assert (row["indicator_type"], row["value"]) == ("hash", SHA)
    assert row["source_id"] == "virustotal" and row["confidence"] == 0.8
    assert row["threat_label"] == "trojan.mirai/gafgyt"
    assert row["yara_rules"] == ["Mirai_Botnet_Malware", "ELF_Generic"]
    assert row["sigma_rules"] == ["Suspicious Shell Download"]
    assert row["first_seen_at_source"] == "2025-10-12T17:26:40+00:00"
    assert row["last_seen_at_source"] == "2025-10-12T20:13:20+00:00"


def test_virustotal_does_not_overwrite_the_family_or_reference_of_another_source(path) -> None:
    """The node is shared with the source that reported the hash; ``coalesce(item.x, n.x)`` lets the last
    writer win, so the corroborating source must not send those two properties at all."""
    _attr, _sync_item, row = path(_vt_item())
    assert "malware_family" not in row and "reference" not in row and "reporter" not in row
    query = path.query()
    assert "n.malware_family = coalesce(item.malware_family, n.malware_family)" in query
    assert "n.threat_label = coalesce(item.threat_label, n.threat_label)" in query


def test_virustotal_item_without_a_classification_keeps_a_plain_comment(path) -> None:
    item = _vt_item(popular_threat_classification={}, crowdsourced_yara_results=[], sigma_analysis_results=[])
    attr, _sync_item, row = path(item)
    assert not attr["comment"].startswith("TF_META:"), "nothing to carry: the description stays readable in MISP"
    assert "threat_label" not in row and "yara_rules" not in row


def test_one_hash_from_three_sources_is_one_node(path) -> None:
    mb = {
        "indicator_type": "sha256",
        "value": SHA.upper(),
        "zone": ["global"],
        "tag": "malwarebazaar",
        "source": ["malwarebazaar"],
        "first_seen": "2026-10-12T21:16:06+00:00",
        "confidence_score": 0.7,
        "malware_family": "Mirai",
        "reference": f"https://bazaar.abuse.ch/sample/{SHA}/",
        "reporter": "abuse_ch",
        "tags": ["elf"],
    }
    tf = {**mb, "tag": "threatfox", "source": ["threatfox"], "value": SHA, "first_seen": "2026-10-12 08:00:00 UTC"}
    keys = {(r["indicator_type"], r["value"]) for r in (path(mb)[2], path(tf)[2], path(_vt_item())[2])}
    assert keys == {("hash", SHA)}, "case-insensitive hash key: three SOURCED_FROM edges on one Indicator"


# ---------------------------------------------------------------------------
# MalwareBazaar, ThreatFox, URLhaus, Feodo
# ---------------------------------------------------------------------------


def test_malwarebazaar_family_reference_and_first_seen_reach_the_node(path) -> None:
    from collectors.global_feed_collector import MalwareBazaarCollector

    mb = MalwareBazaarCollector(api_key="", misp_writer=MagicMock())
    labelled = mb.build_item(
        {
            "first_seen_utc": "2026-10-12 21:16:06",
            "sha256_hash": SHA,
            "md5_hash": "0" * 32,
            "sha1_hash": "1" * 40,
            "reporter": "abuse_ch",
            "file_name": "bot.arm7",
            "file_type_guess": "elf",
            "mime_type": "application/x-executable",
            "signature": "Mirai",
        }
    )
    _attr, _sync_item, row = path(labelled)
    assert row["source_id"] == "malwarebazaar" and row["malware_family"] == "Mirai"
    assert row["reference"] == f"https://bazaar.abuse.ch/sample/{SHA}/" and row["reporter"] == "abuse_ch"
    assert row["first_seen_at_source"] == "2026-10-12T21:16:06+00:00" and row["last_seen_at_source"] is None
    assert row["raw_data"]["tf_tags"] == ["elf"], "the file type stays with the source record"

    unlabelled = mb.build_item({"first_seen_utc": "2026-10-12 21:16:06", "sha256_hash": SHA, "signature": "n/a"})
    _attr, _sync_item, row = path(unlabelled)
    assert "malware_family" not in row, "an unlabelled sample makes no family claim"


def test_threatfox_first_seen_with_utc_suffix_reaches_the_edge(path) -> None:
    """The ThreatFox API reports ``"2020-12-08 13:36:27 UTC"``; the suffix used to make the value unparseable."""
    item = {
        "indicator_type": "ipv4",
        "value": "203.0.113.50",
        "zone": ["global"],
        "tag": "threatfox",
        "source": ["threatfox"],
        "first_seen": "2026-10-12 08:00:00 UTC",
        "last_seen": "2026-10-12 09:30:00 UTC",
        "confidence_score": 0.75,
        "malware_family": "Cobalt Strike",
        "threat_type": "botnet_cc",
        "reference": "",
        "tags": ["c2"],
    }
    attr, _sync_item, row = path(item)
    assert attr["first_seen"] == "2026-10-12T08:00:00+00:00" and attr["last_seen"] == "2026-10-12T09:30:00+00:00"
    assert row["first_seen_at_source"] == "2026-10-12T08:00:00+00:00"
    assert row["last_seen_at_source"] == "2026-10-12T09:30:00+00:00"
    assert row["malware_family"] == "Cobalt Strike"


def test_urlhaus_status_and_last_online_reach_the_node(path) -> None:
    item = {
        "indicator_type": "url",
        "value": "http://198.51.100.20/bins/x86",
        "zone": ["global"],
        "tag": "urlhaus",
        "source": ["urlhaus"],
        "first_seen": "2026-09-01 22:30:17",
        "last_seen": "2026-09-01 23:10:00",
        "confidence_score": 0.6,
        "threat_type": "malware_download",
        "tags": "elf,mirai",
        "url_status": "online",
        "last_online": "2026-09-01 23:10:00",
        "reporter": "abuse_ch",
        "reference": "https://urlhaus.abuse.ch/url/3500000/",
    }
    _attr, _sync_item, row = path(item)
    assert row["url_status"] == "online" and row["last_online"] == "2026-09-01 23:10:00"
    assert row["last_seen_at_source"] == "2026-09-01T23:10:00+00:00"


def test_feodo_node_carries_family_last_online_and_the_activity_window(path, monkeypatch) -> None:
    from datetime import date

    from collectors import finance_feed_collector as mod

    class Resp:
        status_code = 200
        text = (
            '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\r\n'
            '"2021-01-17 10:00:00","103.61.101.11","449","offline","2021-01-25","Dridex"\r\n'
            '"2021-01-18 09:00:00","103.61.101.11","447","offline","2021-03-02","TrickBot"\r\n'
        )

        def raise_for_status(self) -> None:
            return None

    monkeypatch.setattr(mod, "request_with_rate_limit_retries", lambda *a, **k: Resp())
    monkeypatch.setattr(mod, "_utc_today", lambda: date(2026, 10, 13))
    monkeypatch.setattr(mod.FEODO_RATE_LIMITER, "wait_if_needed", lambda: None)
    monkeypatch.setattr(mod.FEODO_CIRCUIT_BREAKER, "can_execute", lambda: True)
    (item,) = mod.FeodoCollector(misp_writer=MagicMock()).collect(push_to_misp=False, baseline=True)

    attr, _sync_item, row = path(item, source="feodo")
    assert attr["to_ids"] is False
    assert (row["indicator_type"], row["value"], row["source_id"]) == ("ipv4", "103.61.101.11", "feodo_tracker")
    assert row["malware_family"] == "TrickBot" and row["last_online"] == "2021-03-02"
    assert row["confidence"] == 0.3
    assert row["first_seen_at_source"] == "2021-01-17T10:00:00+00:00"
    assert row["last_seen_at_source"] == "2021-03-02T00:00:00+00:00", "campaign windows end in 2021, not at import time"
    assert row["raw_data"]["tf_tags"] == [
        "c2_status:offline",
        "port:447",
        "port:449",
        "family:TrickBot",
        "family:Dridex",
    ]
    assert row["raw_data"]["threat_type"] == "botnet_cc"


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2020-12-08 13:36:27 UTC", "2020-12-08T13:36:27+00:00"),
        ("2020-12-08 13:36:27 utc", "2020-12-08T13:36:27+00:00"),
        ("2020-12-08 UTC", "2020-12-08T00:00:00+00:00"),
        ("2020-12-08 13:36:27", "2020-12-08T13:36:27+00:00"),
        ("2026-10-12 08:00:00+00:00", "2026-10-12T08:00:00+00:00"),  # aware, space separator: Cypher needs the T
        ("2026-10-12T08:00:00Z", "2026-10-12T08:00:00Z"),
        ("not a date UTC", None),
        (" UTC", None),
    ],
)
def test_coerce_iso_accepts_the_utc_suffix_and_always_emits_the_t_separator(value, expected) -> None:
    from source_truthful_timestamps import coerce_iso

    assert coerce_iso(value) == expected


def test_writer_drops_a_last_seen_that_precedes_first_seen() -> None:
    """MISP rejects such an attribute, and a rejected attribute counts against the push success rate."""
    from collectors.misp_writer import MISPWriter

    writer = MISPWriter.__new__(MISPWriter)
    base = {"indicator_type": "ipv4", "value": "198.51.100.30", "zone": ["global"], "tag": "urlhaus"}
    bad = writer.create_attribute({**base, "first_seen": "2026-10-12 10:00:00", "last_seen": "2026-10-11"})
    assert bad["first_seen"] == "2026-10-12T10:00:00+00:00" and "last_seen" not in bad
    equal = writer.create_attribute({**base, "first_seen": "2026-10-12 10:00:00", "last_seen": "2026-10-12 10:00:00"})
    assert equal["last_seen"] == equal["first_seen"], "equal timestamps are valid"
    good = writer.create_attribute({**base, "first_seen": "2026-10-12", "last_seen": "2026-10-12T08:00:00Z"})
    assert good["last_seen"] == "2026-10-12T08:00:00Z"
    only_last = writer.create_attribute({**base, "last_seen": "2026-10-11"})
    assert only_last["last_seen"] == "2026-10-11T00:00:00+00:00" and "first_seen" not in only_last


def test_an_inverted_pair_does_not_come_back_through_the_metadata_comment(path) -> None:
    """ThreatFox has a comment fallback for its timestamps: a last-seen the writer omitted from the
    native field must not return from ``TF_META`` and land on the SOURCED_FROM edge."""
    item = {
        "indicator_type": "ipv4",
        "value": "203.0.113.60",
        "zone": ["global"],
        "tag": "threatfox",
        "source": ["threatfox"],
        "first_seen": "2026-09-10 08:00:00 UTC",
        "last_seen": "2026-09-09 08:00:00 UTC",
        "confidence_score": 0.75,
        "malware_family": "Cobalt Strike",
        "reference": "https://threatfox.abuse.ch/ioc/1/",
        "tags": ["c2"],
    }
    attr, _sync_item, row = path(item)
    assert attr["first_seen"] == "2026-09-10T08:00:00+00:00" and "last_seen" not in attr
    assert json.loads(attr["comment"][len("TF_META:") :])["last_seen"] == "", "the comment agrees with the attribute"
    assert row["first_seen_at_source"] == "2026-09-10T08:00:00+00:00" and row["last_seen_at_source"] is None


def test_sync_drops_an_inverted_pair_written_by_someone_else() -> None:
    """Read-path guard: an attribute already in MISP (or pushed by another writer) with last < first."""
    from source_truthful_timestamps import extract_source_truthful_timestamps, iso_before

    attr = {"first_seen": "2026-09-10T08:00:00+00:00", "last_seen": "2026-09-09T08:00:00+00:00"}
    assert extract_source_truthful_timestamps(attr, "threatfox") == ("2026-09-10T08:00:00+00:00", None)
    meta_only = {"first_seen": "2026-09-10T08:00:00+00:00"}
    tf_meta = {"last_seen": "2026-09-09 08:00:00 UTC"}
    assert extract_source_truthful_timestamps(meta_only, "threatfox", tf_meta=tf_meta) == (
        "2026-09-10T08:00:00+00:00",
        None,
    )
    consistent = {"first_seen": "2026-09-10T08:00:00+00:00", "last_seen": "2026-09-10T08:00:00+00:00"}
    assert extract_source_truthful_timestamps(consistent, "threatfox")[1] == "2026-09-10T08:00:00+00:00"
    assert iso_before("2026-09-09", "2026-09-10T00:00:00Z") is True
    assert iso_before("garbage", "2026-09-10") is False and iso_before(None, "2026-09-10") is False


def test_optional_metadata_keys_are_written_only_when_present_and_stay_bounded() -> None:
    from collectors.misp_writer import MISPWriter

    writer = MISPWriter.__new__(MISPWriter)
    base = {
        "indicator_type": "sha256",
        "value": SHA,
        "zone": ["global"],
        "tag": "threatfox",
        "reference": "https://x.test/",
    }
    plain = json.loads(writer.create_attribute(base)["comment"][len("TF_META:") :])
    for key in ("url_status", "last_online", "threat_label", "yara_rules", "sigma_rules"):
        assert key not in plain, "ThreatFox metadata is unchanged when the item has none of the optional fields"

    rich = {
        **base,
        "threat_label": "x" * 500,
        "yara_rules": [f"rule_{i}" for i in range(60)] + ["", None],
        "sigma_rules": "nope",
    }
    meta = json.loads(writer.create_attribute(rich)["comment"][len("TF_META:") :])
    assert len(meta["threat_label"]) == 200 and len(meta["yara_rules"]) == 20
    assert "sigma_rules" not in meta, "a non-list value is ignored"

    huge = {**base, "yara_rules": ["r" * 200] * 20, "sigma_rules": ["s" * 200] * 20, "tags": ["t" * 300] * 40}
    comment = writer.create_attribute(huge)["comment"]
    assert len(comment) <= 4000 and json.loads(comment[len("TF_META:") :]), "shrunk to the budget, still valid JSON"


def test_sync_ignores_malformed_optional_metadata() -> None:
    from run_misp_to_neo4j import MISPToNeo4jSync

    sync = MISPToNeo4jSync(neo4j_client=MagicMock())
    meta = {
        "threat_label": ["not", "a", "string"],
        "yara_rules": "not-a-list",
        "sigma_rules": [1, None, " ok "],
        "url_status": "  ",
    }
    attr = {
        "type": "sha256",
        "value": SHA,
        "uuid": "u-2",
        "comment": "TF_META:" + json.dumps(meta),
        "Tag": [{"name": "source:VirusTotal"}, {"name": "confidence:high"}],
    }
    item, _rels = sync.parse_attribute(attr, {"id": 1, "info": "EdgeGuard-virustotal-2026-10-13", "Tag": []})
    assert item is not None
    assert "threat_label" not in item and "yara_rules" not in item and "url_status" not in item
    assert item["sigma_rules"] == ["ok"]
