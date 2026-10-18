"""Indicators and CVEs named in the same OTX report (2026-10-18).

An OTX pulse lists indicators and CVEs. Measured on the hosted data on 2026-10-18 (read-only): 312
OTX reports list CVEs (959 CVEs), 290 of them also list indicators (11,673 indicators), and the graph
linked none of them: the sync paired the items of one pulse only as Indicator -> Malware and Malware ->
ThreatActor, and a CVE item of a pulse did not even carry its pulse once read back from MISP (the
vulnerability branch of ``parse_attribute`` did not read ``OTX_META``, and MISPWriter wrote the
pulse's ``cve_references`` items with a plain note and no pulse id).

Now an indicator and a CVE named in the same pulse get ``(Indicator)-[:INDICATES]->(CVE)`` with the
same-report label and provenance as Indicator -> INDICATES -> Malware: ``match_type`` ``otx_pulse``,
confidence 0.6, ``sources ["alienvault_otx"]``, ``source_refs ["alienvault_otx:<pulse id>"]``, the
MISP event. It says "named in the same report", never "exploits": ``EXPLOITS`` stays the indicator's
own CVE claim (``cve_tag``). The CVE node is matched by ``cve_id`` and never created by the link. At
most ``_MAX_REPORT_CVES`` (50) CVEs per report are linked, as malware (50); indicators keep their cap
(2000).

Pinned here, from the collector's items through MISPWriter's attributes and the sync to the rows the
relationship writer receives and the Cypher it sends:

* the builder: pairs, caps, provenance, no link to a CVE outside the report, no ``EXPLOITS``;
* the sync reads the pulse of a CVE attribute (an OTX indicator of type CVE and a ``cve_references``
  item, both as MISPWriter writes them), in a full sync, an incremental sync (a changed indicator links
  to an unchanged CVE of its pulse and the other way round) and the paged path of a large event, and the
  caps pick the same CVEs and indicators of a pulse in a full and an incremental sync;
* the relationship writer routes the row to a template that MATCHes both ends and MERGEs only the link.
"""

from __future__ import annotations

import copy
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
for _p in (SRC, REPO_ROOT / "tests"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# test_graphql_api may register a MagicMock as sys.modules["neo4j_client"] — drop it.
for _mod in ("neo4j_client", "run_misp_to_neo4j"):
    if _mod in sys.modules:
        del sys.modules[_mod]

from collectors import otx_collector  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from neo4j_client import Neo4jClient  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

PULSE_A = "6a0f3c2e9b1d4e5f60718293"
PULSE_B = "6a1e4d3f8c2b5a6970819304"
EVENT = {"id": "4127", "info": "EdgeGuard-alienvault_otx-2026-10-18", "date": "2026-10-18", "Tag": []}

# A pulse as OTX's /api/v1/pulses/subscribed gives it: IPs, a domain, a hostname, a URL, hashes and
# two CVEs as indicators of type CVE, one more CVE among the pulse's ``cve_references``.
PULSE_WITH_CVES: Dict[str, Any] = {
    "id": PULSE_A,
    "name": "Ivanti Connect Secure exploitation drops a web shell",
    "created": "2026-10-16T09:12:44.512000",
    "modified": "2026-10-17T07:01:02.104000",
    "TLP": "green",
    "author_name": "AlienVault",
    "adversary": "",
    "tags": ["ivanti", "webshell"],
    "references": ["https://example.org/advisory"],
    "targeted_countries": [],
    "industries": [],
    "attack_ids": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
    "malware_families": [{"id": "GLASSTOKEN", "display_name": "GLASSTOKEN", "target": None}],
    "cve_references": ["CVE-2025-0282"],
    "indicators": [
        {"id": 1, "indicator": "203.0.113.17", "type": "IPv4", "created": "2026-10-16T09:12:45", "role": ""},
        {"id": 2, "indicator": "198.51.100.44", "type": "IPv4", "created": "2026-10-16T09:12:45", "role": "C2"},
        {"id": 3, "indicator": "update-check.example.net", "type": "domain", "created": "2026-10-16T09:12:45"},
        {"id": 4, "indicator": "vpn.portal-sync.example.org", "type": "hostname", "created": "2026-10-16T09:12:45"},
        {
            "id": 5,
            "indicator": "https://update-check.example.net/dana-na/auth/lastauthserverused.js",
            "type": "URL",
            "created": "2026-10-16T09:12:45",
        },
        {
            "id": 6,
            "indicator": "4bc3f6c1d0a5a1c2b7e8f90123456789abcdef0123456789abcdef0123456789",
            "type": "FileHash-SHA256",
            "created": "2026-10-16T09:12:45",
        },
        {
            "id": 7,
            "indicator": "0123456789ABCDEF0123456789ABCDEF",
            "type": "FileHash-MD5",
            "created": "2026-10-16T09:12:45",
        },
        {"id": 8, "indicator": "CVE-2024-21887", "type": "CVE", "created": "2026-10-16T09:12:45"},
        {"id": 9, "indicator": "CVE-2023-46805", "type": "CVE", "created": "2026-10-16T09:12:45"},
    ],
}
# A second pulse of the same day: one indicator, one CVE.
PULSE_OTHER: Dict[str, Any] = {
    "id": PULSE_B,
    "name": "Citrix NetScaler session hijacking",
    "created": "2026-10-16T11:00:00.000000",
    "modified": "2026-10-16T11:00:00.000000",
    "TLP": "white",
    "adversary": "",
    "malware_families": [],
    "attack_ids": [],
    "indicators": [
        {"id": 21, "indicator": "192.0.2.99", "type": "IPv4", "created": "2026-10-16T11:00:00"},
        {"id": 22, "indicator": "CVE-2023-4966", "type": "CVE", "created": "2026-10-16T11:00:00"},
    ],
}
A_INDICATORS = {
    "203.0.113.17",
    "198.51.100.44",
    "update-check.example.net",
    "vpn.portal-sync.example.org",
    "https://update-check.example.net/dana-na/auth/lastauthserverused.js",
    "4bc3f6c1d0a5a1c2b7e8f90123456789abcdef0123456789abcdef0123456789",
    # As the sync parses it; the relationship writer canonicalises the value (lower case) as the
    # indicator node's MERGE does (TestRelationshipWriter).
    "0123456789ABCDEF0123456789ABCDEF",
}
A_CVES = {"CVE-2024-21887", "CVE-2023-46805", "CVE-2025-0282"}


# ---------------------------------------------------------------- the chain: collector → MISP → sync
def _collect(*pulses: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The OTX collector's items for *pulses* (``collect(push_to_misp=False)``, as a run builds them)."""
    collector = otx_collector.OTXCollector.__new__(otx_collector.OTXCollector)
    collector.api_key = "a" * 64
    collector.tag = "alienvault_otx"
    collector.session = MagicMock()
    collector.rate_limiter = MagicMock()
    collector._last_http_status = 200
    collector.circuit_breaker = MagicMock()
    collector.misp_writer = None
    collector.source_name = "otx"
    pages = iter([[copy.deepcopy(p) for p in pulses]])
    with (
        patch.object(collector, "check_service_available", return_value=True),
        patch.object(collector, "_fetch_pulses", side_effect=lambda **_kw: next(pages, [])),
        patch.object(otx_collector.time, "sleep"),
        patch.object(otx_collector, "get_source_incremental", return_value={}),
        patch.object(otx_collector, "update_source_incremental"),
    ):
        return collector.collect(limit=10, push_to_misp=False, baseline=False)


def _attributes(items: List[Dict[str, Any]], timestamp: str = "1792000000") -> List[Dict[str, Any]]:
    """The MISP attributes MISPWriter writes for *items* (its routing in ``push_items``)."""
    writer = MISPWriter.__new__(MISPWriter)
    attrs: List[Dict[str, Any]] = []
    for n, item in enumerate(items):
        if "indicator_type" in item and "value" in item:
            attr = writer.create_attribute(item)
        elif item.get("type") == "vulnerability":
            attr = writer.create_vulnerability_attribute(item)
        elif item.get("type") == "malware":
            attr = writer.create_malware_attribute(item)
        elif item.get("type") == "actor":
            attr = writer.create_actor_attribute(item)
        else:
            continue
        assert attr is not None, item
        attr["uuid"] = f"00000000-0000-4000-8000-{n:012d}"
        attr["timestamp"] = timestamp
        attrs.append(attr)
    return attrs


def _syncer() -> MISPToNeo4jSync:
    """A sync whose Neo4j writes are recorded: nodes in ``written``, relationship rows in ``rels``."""
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    syncer.written = []
    syncer.rels = []
    syncer.sync_to_neo4j = lambda items: (syncer.written.extend(items), (len(items), 0, []))[1]
    syncer._create_relationships = lambda rels, source_id: (syncer.rels.extend(rels), len(rels))[1]
    return syncer


def _run_event(syncer: MISPToNeo4jSync, attrs: List[Dict[str, Any]]) -> None:
    syncer.fetch_event_details = lambda event_id: dict(EVENT, Attribute=attrs)
    syncer._process_single_event(EVENT["id"], EVENT["info"])


def _cve_links(rels: List[Dict[str, Any]]) -> Dict[tuple, Dict[str, Any]]:
    """The Indicator -> INDICATES -> CVE rows, by (indicator value, CVE id)."""
    out: Dict[tuple, Dict[str, Any]] = {}
    for r in rels:
        if r["rel_type"] == "INDICATES" and r["to_type"] == "CVE":
            key = (r["from_key"]["value"], r["to_key"]["cve_id"])
            assert key not in out, f"duplicate row {key}"
            out[key] = r
    return out


def _cve_item(cve_id: str, pulse: Any = PULSE_A, **extra) -> Dict[str, Any]:
    item = {"type": "vulnerability", "cve_id": cve_id, "tag": "alienvault_otx", "misp_event_id": "4127"}
    if pulse is not None:
        item["pulse_id"] = pulse
    item.update(extra)
    return item


def _ind(value: str, pulse: Any = PULSE_A, indicator_type: str = "ipv4", **extra) -> Dict[str, Any]:
    item = {"indicator_type": indicator_type, "value": value, "tag": "alienvault_otx", "misp_event_id": "4127"}
    if pulse is not None:
        item["pulse_id"] = pulse
    item.update(extra)
    return item


# ================================================================ 1. the builder
class TestBuilder:
    def test_the_cve_cap_is_fifty_like_malware(self):
        assert MISPToNeo4jSync._MAX_REPORT_CVES == 50
        assert MISPToNeo4jSync._MAX_REPORT_MALWARE == 50
        assert MISPToNeo4jSync._MAX_REPORT_INDICATORS == 2000

    def test_every_indicator_of_the_report_indicates_every_cve_of_it(self):
        items = [
            _ind("203.0.113.17"),
            _ind("update-check.example.net", indicator_type="domain"),
            _ind("4bc3f6c1d0a5a1c2b7e8f90123456789abcdef0123456789abcdef0123456789", indicator_type="hash"),
            _cve_item("CVE-2024-21887"),
            _cve_item("CVE-2023-46805"),
        ]
        links = _cve_links(MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships(items))
        assert len(links) == 3 * 2
        assert links[("203.0.113.17", "CVE-2024-21887")] == {
            "rel_type": "INDICATES",
            "from_type": "Indicator",
            "from_key": {"value": "203.0.113.17", "indicator_type": "ipv4"},
            "to_type": "CVE",
            "to_key": {"cve_id": "CVE-2024-21887"},
            "confidence": 0.6,
            "match_type": "otx_pulse",
            "report_id": PULSE_A,
            "source": "alienvault_otx",
            "source_refs": [f"alienvault_otx:{PULSE_A}"],
            "misp_event_id": "4127",
        }

    def test_the_label_and_confidence_are_the_same_report_ones(self):
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        rels = syncer._build_cross_item_relationships(
            [
                _ind("203.0.113.17"),
                _cve_item("CVE-2024-21887"),
                {"type": "malware", "name": "glasstoken", "pulse_id": PULSE_A},
            ]
        )
        by_target = {r["to_type"]: r for r in rels if r["rel_type"] == "INDICATES"}
        for key in ("confidence", "match_type", "report_id", "source", "source_refs", "misp_event_id"):
            assert by_target["CVE"][key] == by_target["Malware"][key], key

    def test_a_cve_of_another_report_or_of_none_is_not_linked(self):
        items = [
            _ind("203.0.113.17"),
            _cve_item("CVE-2024-21887"),
            _ind("192.0.2.99", pulse=PULSE_B),
            _cve_item("CVE-2023-4966", pulse=PULSE_B),
            _cve_item("CVE-2021-44228", pulse=None),
            _ind("192.0.2.200", pulse=None),
        ]
        links = _cve_links(MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships(items))
        assert set(links) == {("203.0.113.17", "CVE-2024-21887"), ("192.0.2.99", "CVE-2023-4966")}
        assert links[("192.0.2.99", "CVE-2023-4966")]["source_refs"] == [f"alienvault_otx:{PULSE_B}"]

    def test_a_cve_without_indicators_in_its_report_gives_nothing(self):
        items = [_cve_item("CVE-2024-21887"), {"type": "malware", "name": "glasstoken", "pulse_id": PULSE_A}]
        assert _cve_links(MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships(items)) == {}

    def test_never_exploits_from_the_same_report(self):
        items = [_ind("203.0.113.17"), _cve_item("CVE-2024-21887")]
        rels = MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships(items)
        assert {r["rel_type"] for r in rels} == {"INDICATES"}

    def test_a_cve_in_two_reports_is_linked_to_the_indicators_of_both(self):
        # One CVE attribute in the event, listed by both pulses (``report_ids``, the collector's dedup).
        items = [
            _ind("203.0.113.17"),
            _ind("192.0.2.99", pulse=PULSE_B),
            _cve_item("CVE-2024-21887", report_ids=[PULSE_B]),
        ]
        links = _cve_links(MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships(items))
        assert {k: v["report_id"] for k, v in links.items()} == {
            ("203.0.113.17", "CVE-2024-21887"): PULSE_A,
            ("192.0.2.99", "CVE-2024-21887"): PULSE_B,
        }

    def test_the_cve_id_is_the_node_key_and_a_report_names_a_cve_once(self):
        items = [_ind("203.0.113.17"), _cve_item("cve-2024-21887"), _cve_item("CVE-2024-21887"), _cve_item(" ")]
        links = _cve_links(MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships(items))
        assert set(links) == {("203.0.113.17", "CVE-2024-21887")}

    def test_a_vulnerability_item_keyed_by_value_is_linked(self):
        items = [_ind("203.0.113.17"), {"type": "vulnerability", "value": "CVE-2024-21887", "pulse_id": PULSE_A}]
        links = _cve_links(MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships(items))
        assert set(links) == {("203.0.113.17", "CVE-2024-21887")}

    def test_caps_keep_the_first_cves_and_indicators_and_are_logged(self, caplog):
        items = [_ind(f"10.0.{i // 256}.{i % 256}") for i in range(2003)] + [
            _cve_item(f"CVE-2026-{1000 + i}") for i in range(53)
        ]
        with caplog.at_level(logging.INFO, logger="run_misp_to_neo4j"):
            links = _cve_links(MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships(items))
        assert len(links) == 2000 * 50
        assert {cve for _, cve in links} == {f"CVE-2026-{1000 + i}" for i in range(50)}
        assert {value for value, _ in links} == {f"10.0.{i // 256}.{i % 256}" for i in range(2000)}
        messages = [r.getMessage() for r in caplog.records]
        assert f"Report {PULSE_A}: capping CVEs 53 -> 50" in messages
        assert any(m.startswith(f"Report {PULSE_A}: capping indicators 2003 -> 2000") for m in messages)

    def test_caps_apply_per_report(self, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_MAX_REPORT_CVES", 1)
        items = [
            _ind("203.0.113.17"),
            _cve_item("CVE-2024-21887"),
            _cve_item("CVE-2023-46805"),
            _ind("192.0.2.99", pulse=PULSE_B),
            _cve_item("CVE-2023-4966", pulse=PULSE_B),
        ]
        links = _cve_links(MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships(items))
        assert set(links) == {("203.0.113.17", "CVE-2024-21887"), ("192.0.2.99", "CVE-2023-4966")}


# ================================================================ 2. the CVE attribute carries its pulse
class TestCveAttributeCarriesItsPulse:
    def test_the_collector_gives_both_kinds_of_cve_item_the_pulse(self):
        items = _collect(PULSE_WITH_CVES)
        cves = {
            i.get("cve_id") or i.get("value"): i
            for i in items
            if i.get("type") == "vulnerability" or i.get("indicator_type") == "cve"
        }
        assert set(cves) == A_CVES
        assert {i["pulse_id"] for i in cves.values()} == {PULSE_A}

    def test_misp_writer_writes_the_pulse_on_a_cve_reference(self):
        (item,) = [i for i in _collect(PULSE_WITH_CVES) if i.get("type") == "vulnerability"]
        attr = MISPWriter.__new__(MISPWriter).create_vulnerability_attribute(item)
        assert attr["type"] == "vulnerability" and attr["value"] == "CVE-2025-0282"
        prefix, _, payload = attr["comment"].partition(":")
        assert prefix == "OTX_META"
        meta = json.loads(payload)
        assert meta["pulse_id"] == PULSE_A
        assert meta["pulse_name"] == PULSE_WITH_CVES["name"]

    def test_a_cve_without_a_pulse_keeps_its_plain_comment(self):
        attr = MISPWriter.__new__(MISPWriter).create_vulnerability_attribute(
            {"type": "vulnerability", "cve_id": "CVE-2025-0282", "tag": "cisa_kev", "description": "Stack overflow"}
        )
        assert not attr["comment"].startswith("OTX_META:")

    @pytest.mark.parametrize("kind", ["indicator_of_type_cve", "cve_reference"])
    def test_the_sync_reads_the_pulse_of_either_cve_attribute(self, kind):
        items = _collect(PULSE_WITH_CVES)
        if kind == "indicator_of_type_cve":
            item = next(i for i in items if i.get("indicator_type") == "cve" and i["value"] == "CVE-2024-21887")
        else:
            item = next(i for i in items if i.get("type") == "vulnerability")
        (attr,) = _attributes([item])
        assert attr["type"] == "vulnerability" and attr["comment"].startswith("OTX_META:")
        parsed, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(attr, EVENT)
        assert parsed["type"] == "vulnerability"
        assert parsed["pulse_id"] == PULSE_A
        # The CVE's record cites the pulse, as an OTX indicator's does.
        assert parsed["source_refs"] == [f"alienvault_otx:{PULSE_A}"]
        # The block is no description of the CVE.
        assert parsed["description"] is None

    def test_a_real_otx_cve_attribute_of_the_hosted_misp_names_its_pulses(self):
        # CVE-2025-21042 as the hosted MISP held it on 2026-10-14 (test_cvss_real_payloads.json): an OTX
        # indicator of type CVE, its OTX_META naming the pulse and five more pulses of the run.
        payloads = json.loads((REPO_ROOT / "tests" / "test_cvss_real_payloads.json").read_text())
        attr = copy.deepcopy(payloads["misp"]["CVE-2025-21042__source:AlienVault-OTX"])
        event = dict(attr.pop("_event"), Tag=[])
        parsed, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(attr, event)
        assert parsed["pulse_id"] == "6ac9eef4bcc05a59cd402770"
        assert parsed["report_ids"] == [
            "6ac4b1c8431cd87d87aa1784",
            "6a71a6ac7bd8297ea6d2093f",
            "6a71aa488c89bfcbd2814692",
            "69e1f0ddb1aa33b71576ca92",
            "6935407b67495bca10fca81f",
        ]
        # An indicator of one of the other pulses, in the same event, is linked to it.
        links = _cve_links(
            MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships(
                [parsed, _ind("203.0.113.80", pulse="6a71a6ac7bd8297ea6d2093f", misp_event_id="137")]
            )
        )
        assert set(links) == {("203.0.113.80", "CVE-2025-21042")}
        assert links[("203.0.113.80", "CVE-2025-21042")]["source_refs"] == ["alienvault_otx:6a71a6ac7bd8297ea6d2093f"]
        assert links[("203.0.113.80", "CVE-2025-21042")]["misp_event_id"] == "137"

    def test_the_other_pulses_of_the_run_are_read_too(self):
        attr = _attributes([_ind("CVE-2024-21887", indicator_type="cve", report_ids=[PULSE_B], pulse_name="x")])[0]
        parsed, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(attr, EVENT)
        assert parsed["pulse_id"] == PULSE_A and parsed["report_ids"] == [PULSE_B]

    @pytest.mark.parametrize(
        "comment",
        [
            "Referenced in OTX pulse: Ivanti Connect Secure exploitation",
            "CVE from alienvault_otx",
            'OTX_META:{"pulse_id": 17, "report_ids": "p"}',
            "OTX_META:null",
            "OTX_META:{not json",
            'NVD_META:{"description": "x"}',
        ],
    )
    def test_a_cve_attribute_without_a_readable_pulse_has_none(self, comment):
        attr = {
            "type": "vulnerability",
            "value": "CVE-2024-21887",
            "comment": comment,
            "uuid": "00000000-0000-4000-8000-000000000999",
            "Tag": [{"name": "source:AlienVault-OTX"}],
        }
        parsed, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(attr, EVENT)
        assert not parsed.get("pulse_id")
        assert not parsed.get("report_ids")


# ================================================================ 3. the sync, end to end
class TestSync:
    def test_full_sync_links_the_pulse_indicators_to_its_cves(self):
        syncer = _syncer()
        _run_event(syncer, _attributes(_collect(PULSE_WITH_CVES, PULSE_OTHER)))
        links = _cve_links(syncer.rels)
        expected = {(v, c) for v in A_INDICATORS for c in A_CVES} | {("192.0.2.99", "CVE-2023-4966")}
        assert set(links) == expected
        for (value, _cve), row in links.items():
            pulse = PULSE_B if value == "192.0.2.99" else PULSE_A
            assert row["match_type"] == "otx_pulse" and row["confidence"] == 0.6
            assert row["source"] == "alienvault_otx" and row["source_refs"] == [f"alienvault_otx:{pulse}"]
            assert row["misp_event_id"] == EVENT["id"]
        # The CVE items are written as CVE nodes, never as indicators.
        assert {i.get("cve_id") for i in syncer.written if i.get("type") == "vulnerability"} == A_CVES | {
            "CVE-2023-4966"
        }

    def test_incremental_a_new_indicator_links_to_an_unchanged_cve_of_its_pulse(self, monkeypatch):
        attrs = _attributes(_collect(PULSE_WITH_CVES, PULSE_OTHER), timestamp="1700000000")
        new = next(a for a in attrs if a["value"] == "203.0.113.17")
        new["timestamp"] = "1792000000"
        syncer = _syncer()
        syncer._attr_since = datetime.fromtimestamp(1791000000, tz=timezone.utc)
        _run_event(syncer, attrs)
        assert [i.get("value") for i in syncer.written] == ["203.0.113.17"], "only the changed attribute is written"
        links = _cve_links(syncer.rels)
        assert {("203.0.113.17", c) for c in A_CVES} <= set(links)
        # The unchanged items of the changed item's report join the build (their links are MERGEd again,
        # as for Indicator -> Malware); a report without a changed item is not rebuilt.
        assert set(links) == {(v, c) for v in A_INDICATORS for c in A_CVES}
        assert {r["report_id"] for r in links.values()} == {PULSE_A}

    def test_incremental_a_new_cve_links_to_the_unchanged_indicators_of_its_pulse(self):
        attrs = _attributes(_collect(PULSE_WITH_CVES, PULSE_OTHER), timestamp="1700000000")
        new = next(a for a in attrs if a["value"] == "CVE-2023-46805")
        new["timestamp"] = "1792000000"
        syncer = _syncer()
        syncer._attr_since = datetime.fromtimestamp(1791000000, tz=timezone.utc)
        _run_event(syncer, attrs)
        assert [i.get("cve_id") for i in syncer.written] == ["CVE-2023-46805"]
        links = _cve_links(syncer.rels)
        assert {(v, "CVE-2023-46805") for v in A_INDICATORS} <= set(links)
        assert {r["report_id"] for r in links.values()} == {PULSE_A}
        assert ("192.0.2.99", "CVE-2023-4966") not in links

    def test_the_paged_path_of_a_large_event_links_them_too(self, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 3)
        syncer = _syncer()
        _run_event(syncer, _attributes(_collect(PULSE_WITH_CVES, PULSE_OTHER)))
        expected = {(v, c) for v in A_INDICATORS for c in A_CVES} | {("192.0.2.99", "CVE-2023-4966")}
        assert set(_cve_links(syncer.rels)) == expected

    # A pulse over the CVE cap: the indicators of PULSE_WITH_CVES (two of them CVEs) and 55 more CVEs
    # among its ``cve_references``, 58 CVEs in all.
    BIG_PULSE_REFS = [f"CVE-2026-{1000 + n}" for n in range(55)]

    def _big_pulse_attrs(self) -> List[Dict[str, Any]]:
        pulse = dict(copy.deepcopy(PULSE_WITH_CVES), cve_references=list(self.BIG_PULSE_REFS))
        return _attributes(_collect(pulse), timestamp="1700000000")

    def _incremental(self, attrs: List[Dict[str, Any]], changed: List[str]) -> MISPToNeo4jSync:
        attrs = copy.deepcopy(attrs)
        for attr in attrs:
            if attr["value"] in changed:
                attr["timestamp"] = "1792000000"
        syncer = _syncer()
        syncer._attr_since = datetime.fromtimestamp(1791000000, tz=timezone.utc)
        _run_event(syncer, attrs)
        return syncer

    def test_the_caps_pick_the_same_cves_in_a_full_and_an_incremental_sync(self):
        # Review finding: the caps took the first CVEs of the build input, and an incremental run put the
        # changed items first, so a changed CVE beyond the first 50 of the event was linked as well and
        # the graph held links to 51 CVEs of the report.
        attrs = self._big_pulse_attrs()
        full = _syncer()
        _run_event(full, copy.deepcopy(attrs))
        full_links = set(_cve_links(full.rels))
        full_cves = {cve for _, cve in full_links}
        assert len(full_cves) == 50
        beyond = [c for c in self.BIG_PULSE_REFS if c not in full_cves]
        assert beyond, "the pulse is over the cap"
        for changed in ([beyond[-1]], [beyond[0], "203.0.113.17"], [sorted(full_cves)[0]]):
            incremental = self._incremental(attrs, changed)
            assert {i.get("cve_id") or i.get("value") for i in incremental.written} == set(changed)
            assert set(_cve_links(incremental.rels)) == full_links, changed

    def test_the_paged_path_picks_the_same_cves_in_an_incremental_sync(self, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 3)
        attrs = self._big_pulse_attrs()
        full = _syncer()
        _run_event(full, copy.deepcopy(attrs))
        full_links = set(_cve_links(full.rels))
        assert len({cve for _, cve in full_links}) == 50
        beyond = [c for c in self.BIG_PULSE_REFS if c not in {cve for _, cve in full_links}]
        # Four changed attributes, more than a page, so the incremental run takes the paged path too.
        changed = beyond[-2:] + ["203.0.113.17", "update-check.example.net"]
        incremental = self._incremental(attrs, changed)
        assert len(incremental.written) == 4
        assert set(_cve_links(incremental.rels)) == full_links

    def test_the_indicator_cap_picks_the_same_indicators_in_an_incremental_sync(self, monkeypatch):
        monkeypatch.setattr(MISPToNeo4jSync, "_MAX_REPORT_INDICATORS", 3)
        attrs = _attributes(_collect(PULSE_WITH_CVES), timestamp="1700000000")
        full = _syncer()
        _run_event(full, copy.deepcopy(attrs))
        full_links = set(_cve_links(full.rels))
        assert len({value for value, _ in full_links}) == 3
        late = [v for v in A_INDICATORS if v not in {value for value, _ in full_links}]
        incremental = self._incremental(attrs, late)
        assert set(_cve_links(incremental.rels)) == full_links

    def test_a_legacy_cve_note_without_a_pulse_is_not_linked(self):
        items = _collect(PULSE_WITH_CVES)
        attrs = _attributes(items)
        for attr in attrs:
            if attr["value"] == "CVE-2025-0282":
                attr["comment"] = f"Referenced in OTX pulse: {PULSE_WITH_CVES['name']}"
        syncer = _syncer()
        _run_event(syncer, attrs)
        assert {cve for _, cve in _cve_links(syncer.rels)} == A_CVES - {"CVE-2025-0282"}


# ================================================================ 4. the relationship writer
def _capturing_client():
    """A real Neo4jClient whose session records each ``rows=`` batch with its Cypher."""
    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    client._connection_healthy = True
    captured: List[tuple] = []

    def run(query, **kwargs):
        if kwargs.get("rows") is not None:
            captured.append((query, list(kwargs["rows"])))
        return MagicMock()

    session = MagicMock()
    session.run = run
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *a: False
    client.driver.session.return_value = session
    return client, captured


class TestRelationshipWriter:
    def _row(self, **changes) -> Dict[str, Any]:
        rels = MISPToNeo4jSync(neo4j_client=MagicMock())._build_cross_item_relationships(
            [
                _ind("0123456789ABCDEF0123456789ABCDEF", indicator_type="hash"),
                _cve_item("cve-2024-21887"),
            ]
        )
        (row,) = [r for r in rels if r["to_type"] == "CVE"]
        row.update(changes)
        return row

    def test_the_row_reaches_a_template_that_matches_both_ends(self):
        client, captured = _capturing_client()
        assert int(client.create_misp_relationships_batch([self._row()], source_id="misp")) == 1
        ((query, rows),) = captured
        flat = " ".join(query.split())
        assert "MATCH (i:Indicator {value: row.value})" in flat
        assert "MATCH (c:CVE {cve_id: row.cve_id})" in flat
        assert "MERGE (i)-[r:INDICATES]->(c)" in flat
        # The link never creates the CVE (or the indicator).
        assert "MERGE (c" not in flat and "MERGE (i:" not in flat and "CREATE" not in flat
        assert "r.edgeguard_managed = true" in flat
        assert "r.source_refs" in flat and "r.misp_event_ids" in flat and "r.match_type" in flat
        assert rows == [
            {
                "value": "0123456789abcdef0123456789abcdef",  # canonical, as merge_indicators_batch stores it
                "cve_id": "CVE-2024-21887",
                "source": "alienvault_otx",
                "source_refs": [f"alienvault_otx:{PULSE_A}"],
                "confidence": 0.6,
                "misp_event_id": "4127",
                "match_type": "otx_pulse",
            }
        ]

    def test_no_exploits_template_receives_the_row(self):
        client, captured = _capturing_client()
        client.create_misp_relationships_batch([self._row()], source_id="misp")
        assert not any("EXPLOITS" in q for q, _ in captured)
        assert not any("Vulnerability" in q for q, _ in captured)

    @pytest.mark.parametrize("change", [{"to_key": {"cve_id": " "}}, {"from_key": {"value": ""}}])
    def test_a_row_with_a_blank_end_is_dropped(self, change, caplog):
        client, captured = _capturing_client()
        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            client.create_misp_relationships_batch([self._row(**change)], source_id="misp")
        assert captured == []
        assert any("1/1 definitions dropped" in r.getMessage() for r in caplog.records)
