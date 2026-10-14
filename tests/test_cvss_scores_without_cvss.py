"""CVE scores without a CVSS behind them (2026-10).

Measured read-only on the hosted 730-day baseline (2026-10-14): MISPWriter tagged every CVE whose
score was 0 — an NVD record without CVSS 3.x or 2, with only a CVSS 4.0 or none at all — ``cvss:low``,
and the sync read that tag back as 3.0 / LOW: 14,451 CVEs, 73% of all LOW CVEs. In the same path the
sync never read CVSS 3.0 (1,266 approximated scores), an untagged OTX record erased the severity (493
CVEs), the CISA KEV collector derived 9.0 / 7.0 from ransomware use, the ICS collector defaulted to
7.0, and the record merged last set the node's score (302 CISA ICS CVSS 3.1 scores replaced by 3.0).

The rule now (``cvss_selection``): a CVE's score is the base score of its first CVSS in the order
v3.1 → v3.0 → v2 → v4.0, ``cvss_version`` names it, and a CVE without CVSS has no score and severity
UNKNOWN. ``merge_cve`` derives the node's values from the CVSS sub-nodes.

Fixtures are real (``test_cvss_real_payloads.json``): NVD CVE API 2.0 records fetched 2026-10-14, with
NVD's zone-less timestamps ("2026-10-13T19:20:52.743"), and attributes of the hosted MISP as written by
the pre-fix code (legacy ``cvss:low`` / ``severity:unknown`` tags included).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import neo4j_client  # noqa: E402
from collectors.cisa_collector import CISACollector  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from collectors.nvd_collector import NVDCollector  # noqa: E402
from cvss_selection import CVSS_VERSIONS, cvss_rating_tag, select_cvss, severity_from_score  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

PAYLOADS = json.loads((Path(__file__).resolve().parent / "test_cvss_real_payloads.json").read_text())
NVD = PAYLOADS["nvd"]
MISP = PAYLOADS["misp"]


# ---------------------------------------------------------------- helpers
def _nvd_collector() -> NVDCollector:
    c = NVDCollector.__new__(NVDCollector)
    c.base_url = "http://fake"
    c.api_key = "k"
    c._api_key_rejected = False
    c.tag = "nvd"
    c.misp_writer = MagicMock()
    c.source_name = "nvd"
    c.circuit_breaker = MagicMock()
    return c


def _collect(records: list) -> dict:
    """NVDCollector.collect() (incremental, no MISP push) over real NVD API records."""
    with (
        patch.object(NVDCollector, "_fetch_cves", return_value=records),
        patch.object(NVDCollector, "check_service_available", return_value=True),
    ):
        items = _nvd_collector().collect(limit=None, push_to_misp=False, baseline=False)
    assert isinstance(items, list)
    return {i["cve_id"]: i for i in items}


@pytest.fixture(scope="module")
def nvd_items() -> dict:
    return _collect(list(NVD.values()))


@pytest.fixture
def writer() -> MISPWriter:
    return MISPWriter.__new__(MISPWriter)  # attribute builders need no MISP connection


@pytest.fixture
def syncer() -> MISPToNeo4jSync:
    return MISPToNeo4jSync(neo4j_client=MagicMock())


def _tags(attribute: dict) -> list:
    return [t["name"] for t in attribute["Tag"]]


def _parse(syncer: MISPToNeo4jSync, attribute: dict) -> dict:
    event = {"id": attribute.get("event_id"), "info": (attribute.get("_event") or {}).get("info", ""), "Tag": []}
    item, _ = syncer.parse_attribute({k: v for k, v in attribute.items() if k != "_event"}, event)
    assert item is not None
    return item


def _recording_client():
    """A real Neo4jClient whose driver records every statement (no database)."""
    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = MagicMock()
    client._uri = "bolt://localhost:7687"
    session = MagicMock()
    result = MagicMock()
    result.single.return_value = None
    session.run.return_value = result
    client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return client, session


def _score_derivations(session) -> list:
    """cve_id of every ``_set_cve_score_from_cvss`` statement, in order."""
    return [
        c.kwargs.get("cve_id")
        for c in session.run.call_args_list
        if c.args and c.args[0] == neo4j_client._CVE_SCORE_FROM_CVSS_QUERY
    ]


# ---------------------------------------------------------------- 1. the rule
class TestSelectCvss:
    def test_version_order_is_v31_v30_v2_v40(self):
        assert [v.version for v in CVSS_VERSIONS] == ["3.1", "3.0", "2.0", "4.0"]

    def test_first_version_with_a_score_wins(self):
        payloads = {
            "cvss_v40_data": {"base_score": 7.0, "base_severity": "HIGH"},
            "cvss_v30_data": {"base_score": 6.6, "base_severity": "MEDIUM"},
        }
        assert select_cvss(payloads) == (6.6, "MEDIUM", "3.0")

    def test_cvss_40_only(self):
        assert select_cvss({"cvss_v40_data": {"base_score": 8.7, "base_severity": "HIGH"}}) == (8.7, "HIGH", "4.0")

    def test_no_cvss_is_no_score(self):
        unscored = (None, "UNKNOWN", None)
        assert select_cvss({}) == unscored
        assert select_cvss({"cvss_v31_data": None, "cvss_v40_data": None}) == unscored
        assert select_cvss({"cvss_v31_data": {}}) == unscored, "the NVD collector's empty payload"

    def test_zero_is_a_score(self):
        assert select_cvss({"cvss_v30_data": {"base_score": 0.0, "base_severity": "NONE"}}) == (0.0, "NONE", "3.0")
        assert select_cvss({"cvss_v31_data": {"base_score": 0.0}}) == (0.0, "NONE", "3.1")

    def test_cvss_2_rating_uses_nvds_cvss_2_scale(self):
        # Older NVD_META copies of CVSS 2 payloads have an empty base_severity.
        assert select_cvss({"cvss_v2_data": {"base_score": 10.0, "base_severity": ""}}) == (10.0, "HIGH", "2.0")
        assert severity_from_score(10.0, "3.1") == "CRITICAL"

    @pytest.mark.parametrize("bad", ["1e309", float("inf"), float("nan"), -0.1, 10.1, "n/a"])
    def test_rejected_scores_are_skipped_not_stored(self, bad):
        payloads = {
            "cvss_v31_data": {"base_score": bad},
            "cvss_v40_data": {"base_score": 5.4, "base_severity": "MEDIUM"},
        }
        assert select_cvss(payloads) == (5.4, "MEDIUM", "4.0")

    def test_a_non_rating_severity_is_replaced_by_the_rating_of_the_score(self):
        assert select_cvss({"cvss_v31_data": {"base_score": 9.8, "base_severity": "<script>"}}) == (
            9.8,
            "CRITICAL",
            "3.1",
        )

    def test_clamp_is_still_exported_by_neo4j_client(self):
        assert neo4j_client.clamp_cvss_score("1e309") is None and neo4j_client.clamp_cvss_score(7.5) == 7.5


class TestCvssRatingTag:
    def test_no_score_no_tag(self):
        assert cvss_rating_tag(None, "UNKNOWN") is None

    def test_zero_placeholder_of_older_producers_is_no_score(self):
        assert cvss_rating_tag(0.0, "UNKNOWN") is None
        assert cvss_rating_tag(0, "") is None

    def test_real_zero_is_none_not_low(self):
        assert cvss_rating_tag(0.0, "NONE") == "cvss:none"

    def test_rating_follows_the_cvss_severity(self):
        assert cvss_rating_tag(3.5, "LOW") == "cvss:low"
        assert cvss_rating_tag(10.0, "HIGH") == "cvss:high", "CVSS 2 has no CRITICAL"
        assert cvss_rating_tag(7.5, "UNKNOWN") == "cvss:high"


# ---------------------------------------------------------------- 2. NVD collector, real records
EXPECTED_NVD = {
    # cve_id: (cvss_score, severity, version) — the record's shape in the comment
    "CVE-2026-84994": (8.7, "HIGH", "4.0"),  # CNA CVSS 4.0 only, Awaiting Analysis
    "CVE-2026-102699": (None, "UNKNOWN", None),  # no metrics, Awaiting Analysis
    "CVE-2026-105151": (None, "UNKNOWN", None),  # Rejected
    "CVE-2025-59823": (9.9, "CRITICAL", "3.0"),  # CNA CVSS 3.0 only (the sync used to show 9.0)
    "CVE-2026-107153": (6.6, "MEDIUM", "3.0"),  # CVSS 4.0 7.0 and CVSS 3.0 6.6
    "CVE-2014-9323": (5.0, "MEDIUM", "2.0"),  # CVSS 2 only; rating on the metric object
    "CVE-2025-12843": (5.5, "MEDIUM", "3.1"),  # NVD CVSS 3.1 and CNA CVSS 4.0 6.9
    "CVE-2008-4250": (9.8, "CRITICAL", "3.1"),  # CISA-ADP CVSS 3.1 and NVD CVSS 2 10.0; on KEV
}


class TestNvdCollector:
    def test_fixture_timestamps_are_nvds_zone_less_form(self):
        assert NVD["CVE-2026-84994"]["cve"]["published"] == "2026-10-13T19:20:52.743"

    @pytest.mark.parametrize("cve_id", sorted(EXPECTED_NVD))
    def test_score_and_severity(self, nvd_items, cve_id):
        score, severity, _ = EXPECTED_NVD[cve_id]
        item = nvd_items[cve_id]
        assert (item["cvss_score"], item["severity"]) == (score, severity)

    def test_cvss_2_payload_carries_nvds_rating(self, nvd_items):
        assert nvd_items["CVE-2014-9323"]["cvss_v2_data"]["base_severity"] == "MEDIUM"

    @pytest.mark.parametrize("cve_id", sorted(EXPECTED_NVD))
    def test_writer_tags_only_a_real_cvss(self, nvd_items, writer, cve_id):
        score, severity, _ = EXPECTED_NVD[cve_id]
        tags = _tags(writer.create_vulnerability_attribute(dict(nvd_items[cve_id])))
        cvss_tags = [t for t in tags if t.startswith("cvss:")]
        assert cvss_tags == ([] if score is None else [f"cvss:{severity.lower()}"])
        assert f"severity:{severity.lower()}" in tags

    @pytest.mark.parametrize("cve_id", sorted(EXPECTED_NVD))
    def test_round_trip_through_misp_keeps_score_severity_and_version(self, nvd_items, writer, syncer, cve_id):
        attribute = writer.create_vulnerability_attribute(dict(nvd_items[cve_id]))
        item = _parse(syncer, attribute)
        assert (item["cvss_score"], item["severity"], item["cvss_version"]) == EXPECTED_NVD[cve_id]


# ---------------------------------------------------------------- 3. sync, real hosted MISP attributes
EXPECTED_MISP = {
    # attribute: (cvss_score, severity, cvss_version, known_ransomware_use)
    "CVE-2026-6039__source:NVD": (5.4, "MEDIUM", "4.0", None),  # tagged cvss:low, was 3.0 / LOW
    "CVE-2026-64019__nvd_no_cvss_active": (None, "UNKNOWN", None, None),  # was 3.0 / LOW
    "CVE-2026-54292__nvd_rejected": (None, "UNKNOWN", None, None),  # was 3.0 / LOW
    "CVE-2026-44956__source:NVD": (0.0, "NONE", "3.0", None),  # CVSS 3.0 0.0, was 3.0 / LOW
    "CVE-2025-7223__source:NVD": (7.8, "HIGH", "3.0", None),  # CVSS 3.0, was the tag value 7.5
    "CVE-2025-7223__source:CISA-ICS": (7.8, "HIGH", "3.1", None),
    "CVE-2025-14272__source:NVD": (8.3, "HIGH", "4.0", None),
    "CVE-2025-14272__source:CISA-ICS": (7.0, "HIGH", "3.1", None),
    "CVE-2025-21042__source:NVD": (8.8, "HIGH", "3.1", None),
    "CVE-2025-21042__source:CISA-KEV": (None, "UNKNOWN", None, None),  # tagged cvss:high, was 7.5
    "CVE-2025-21042__source:AlienVault-OTX": (None, "UNKNOWN", None, None),
    "CVE-2015-5477__source:CISA-KEV": (None, "UNKNOWN", None, None),
    "CVE-2015-5477__source:AlienVault-OTX": (None, "UNKNOWN", None, None),
    "CVE-2026-59310__kev_known": (None, "UNKNOWN", None, "Known"),  # tagged cvss:critical, was 9.0
    "CVE-2026-7891__ics_no_cvss": (None, "UNKNOWN", None, None),  # ICS default, was 7.5
}


class TestSyncOfHostedAttributes:
    def test_fixtures_carry_the_legacy_tags(self):
        assert {"severity:unknown", "cvss:low"} <= set(_tags(MISP["CVE-2026-6039__source:NVD"]))
        assert "cvss:critical" in _tags(MISP["CVE-2026-59310__kev_known"])
        assert set(EXPECTED_MISP) == set(MISP)

    @pytest.mark.parametrize("key", sorted(EXPECTED_MISP))
    def test_score_comes_from_nvd_meta_never_from_a_tag(self, syncer, key):
        item = _parse(syncer, MISP[key])
        got = (item["cvss_score"], item["severity"], item["cvss_version"], item["known_ransomware_use"])
        assert got == EXPECTED_MISP[key]

    def test_a_rejected_score_is_skipped_and_reported(self, syncer, caplog):
        attribute = dict(MISP["CVE-2025-14272__source:NVD"])
        meta = json.loads(attribute["comment"][len("NVD_META:") :])
        meta["cvss_v31_data"] = {"base_score": "1e309", "base_severity": "CRITICAL"}
        attribute["comment"] = "NVD_META:" + json.dumps(meta)
        with caplog.at_level("WARNING"):
            item = _parse(syncer, attribute)
        assert (item["cvss_score"], item["cvss_version"]) == (8.3, "4.0")
        assert any("rejected by clamp" in r.message for r in caplog.records)


# ---------------------------------------------------------------- 4. CISA KEV
class TestKevRansomwareUse:
    @staticmethod
    def _kev_item(use: str) -> dict:
        collector = CISACollector.__new__(CISACollector)
        collector.tag = "cisa_kev"
        entry = {
            "cveID": "CVE-2026-59310",
            "vendorProject": "Example",
            "product": "Example Gateway",
            "vulnerabilityName": "Example Gateway Command Injection",
            "shortDescription": "Command injection in the management interface.",
            "requiredAction": "Apply mitigations per vendor instructions.",
            "dateAdded": "2026-08-18",
            "dueDate": "2026-09-08",
            "knownRansomwareCampaignUse": use,
            "cwes": ["CWE-78"],
            "notes": "",
        }
        with patch.object(CISACollector, "_fetch_kev", return_value=[entry]):
            items = collector.collect(limit=None, push_to_misp=False, baseline=True)
        assert isinstance(items, list) and len(items) == 1
        return items[0]

    @pytest.mark.parametrize("use", ["Known", "Unknown"])
    def test_no_score_derived_from_ransomware_use(self, use):
        item = self._kev_item(use)
        assert (item["cvss_score"], item["severity"], item["known_ransomware_use"]) == (None, "UNKNOWN", use)

    @pytest.mark.parametrize("use", ["Known", "Unknown"])
    def test_ransomware_use_round_trips_without_a_cvss_tag(self, writer, syncer, use):
        attribute = writer.create_vulnerability_attribute(self._kev_item(use))
        tags = _tags(attribute)
        assert not [t for t in tags if t.startswith("cvss:")] and "CISA-KEV" in tags
        assert ("ransomware:known" in tags) == (use == "Known")
        item = _parse(syncer, attribute)
        assert (item["cvss_score"], item["severity"], item["known_ransomware_use"]) == (None, "UNKNOWN", use)


# ---------------------------------------------------------------- 5. merge_cve, every caller
class TestNodeScoreFromSubNodes:
    def test_cypher_follows_the_version_order_and_range(self):
        query = neo4j_client._CVE_SCORE_FROM_CVSS_QUERY
        positions = [query.index(f"[:{v.rel_type}]->(x:{v.label})") for v in CVSS_VERSIONS]
        assert positions == sorted(positions)
        assert query.count("x.base_score >= 0.0 AND x.base_score <= 10.0") == len(CVSS_VERSIONS)
        assert "SET c.cvss_score = best[0].base_score" in query and "c.cvss_version = best[1]" in query
        assert "WHEN best IS NULL THEN 'UNKNOWN'" in query

    def test_merge_cve_writes_ransomware_use_and_derives_the_score_last(self, syncer):
        client, session = _recording_client()
        item = _parse(syncer, MISP["CVE-2026-59310__kev_known"])
        assert client.merge_cve(item, source_id="cisa_kev")
        queries = [c.args[0] for c in session.run.call_args_list if c.args]
        merge = next(q for q in queries if "MERGE (n:CVE" in q)
        assert "n.known_ransomware_use = $known_ransomware_use" in merge
        assert "cvss_score" not in merge and "severity" not in merge
        assert queries[-1] == neo4j_client._CVE_SCORE_FROM_CVSS_QUERY
        assert _score_derivations(session) == ["CVE-2026-59310"]

    def test_merge_cve_derives_after_the_sub_nodes(self, syncer):
        client, session = _recording_client()
        client.merge_cve(_parse(syncer, MISP["CVE-2025-14272__source:NVD"]), source_id="nvd")
        queries = [c.args[0] for c in session.run.call_args_list if c.args]
        sub_node = max(i for i, q in enumerate(queries) if "MERGE (n:CVSSv40" in q)
        assert queries.index(neo4j_client._CVE_SCORE_FROM_CVSS_QUERY) > sub_node

    def test_sync_batch_paths_derive_every_cve(self, syncer):
        """Rich (CVSS sub-nodes) and plain (no CVSS) CVEs of one chunk, as the full sync merges them."""
        client, session = _recording_client()
        sync = MISPToNeo4jSync(neo4j_client=client)
        keys = [
            "CVE-2025-14272__source:CISA-ICS",
            "CVE-2025-14272__source:NVD",
            "CVE-2015-5477__source:CISA-KEV",
            "CVE-2026-54292__nvd_rejected",
        ]
        items = [_parse(syncer, MISP[k]) for k in keys]
        sync.sync_to_neo4j(items)
        assert sorted(_score_derivations(session)) == sorted(i["cve_id"] for i in items)

    def test_single_item_path_derives(self, syncer):
        client, session = _recording_client()
        sync = MISPToNeo4jSync(neo4j_client=client)
        assert sync._sync_single_item(_parse(syncer, MISP["CVE-2026-6039__source:NVD"])) is not False
        assert _score_derivations(session) == ["CVE-2026-6039"]

    def test_stix_import_derives(self):
        from run_pipeline import EdgeGuardPipeline

        client, session = _recording_client()
        pipeline = EdgeGuardPipeline()
        pipeline.neo4j = client
        bundle = {
            "type": "bundle",
            "objects": [{"type": "vulnerability", "id": "vulnerability--1", "name": "CVE-2025-21042"}],
        }
        pipeline.load_stix21_to_neo4j(bundle)
        assert _score_derivations(session) == ["CVE-2025-21042"]


# ---------------------------------------------------------------- 6. read paths
class TestReadPaths:
    def test_stix_extension_declares_the_new_properties(self):
        import stix_exporter

        promoted = dict(stix_exporter._VULNERABILITY_PROMOTED_FIELDS)
        assert promoted["cvss_version"] == "x_edgeguard_cvss_version"
        assert promoted["known_ransomware_use"] == "x_edgeguard_known_ransomware_use"
        assert {"x_edgeguard_cvss_version", "x_edgeguard_known_ransomware_use"} <= set(
            stix_exporter.EDGEGUARD_EXTENSION_PROPERTIES
        )

    def test_graphql_cve_reports_the_version(self):
        from graphql_api import _cve_effective_score_severity

        node = {"cvss_score": 5.4, "severity": "MEDIUM", "cvss_version": "4.0"}
        assert _cve_effective_score_severity(node, None, None, None, None) == (5.4, "MEDIUM", "4.0")
        unscored = {"cvss_score": None, "severity": "UNKNOWN"}
        assert _cve_effective_score_severity(unscored, None, None, None, None) == (None, "UNKNOWN", None)
        v30 = {"base_score": 7.8, "base_severity": "HIGH"}
        assert _cve_effective_score_severity({}, None, None, v30, None) == (7.8, "HIGH", "3.0")
