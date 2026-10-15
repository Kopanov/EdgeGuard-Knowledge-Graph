"""CISA's SSVC decision points from NVD's records, to the CVE node (2026-10).

NVD relays the SSVC decision that CISA's Vulnrichment program makes for a CVE (``metrics.ssvcV203``,
source CISA-ADP). The NVD collector reads it (``nvd_collector.cisa_ssvc``), the record carries it
through MISP (``NVD_META``), and ``merge_cve`` sets it on the node from NVD's record only and removes
what the record no longer has (``_replace_nvd_owned_cve_data``). Real payloads:
``tests/fixtures/nvd_incremental_2026_10_14.json``. The same path on a real Neo4j:
``tests/test_cve_epss_ssvc_neo4j.py``.
"""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from collectors.misp_writer import MISPWriter, nvd_meta_digest  # noqa: E402
from collectors.nvd_collector import CISA_ADP_NVD_SOURCE, NVDCollector, cisa_ssvc  # noqa: E402

FIXTURES = json.loads((Path(__file__).resolve().parent / "fixtures" / "nvd_incremental_2026_10_14.json").read_text())

# NVD's record of CVE-2021-44228 (Log4Shell), captured 2026-10-14.
LOG4SHELL = {
    "exploitation": "active",
    "automatable": "yes",
    "technical_impact": "total",
    "version": "2.0.3",
    "timestamp": "2025-02-04T14:25:34.416117Z",
}
SSVC_PROPERTIES = ("ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact", "ssvc_version", "ssvc_timestamp")
EVENT = {"id": "138", "info": "EdgeGuard-nvd-2026-10-13", "date": "2026-10-13", "Tag": [{"name": "EdgeGuard"}]}


def _record(cve_id: str) -> dict:
    return copy.deepcopy(FIXTURES["nvd"][cve_id])


def _item(record: dict) -> dict:
    collector = NVDCollector.__new__(NVDCollector)
    collector.tag = "nvd"
    return collector._vulnerability_item(record)


def _meta(comment: str) -> dict:
    assert comment.startswith("NVD_META:")
    return json.loads(comment[len("NVD_META:") :])


@pytest.fixture
def neo4j_session():
    with patch.dict(os.environ, {"NEO4J_PASSWORD": "test", "MISP_API_KEY": "test"}):
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        session = MagicMock()
        session.run.return_value.single.return_value = None
        client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
        client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
        return client, session


def _replace_call(session):
    """The ``_replace_nvd_owned_cve_data`` statement and its parameters; None when it did not run."""
    calls = [(c[0][0], c[1]) for c in session.run.call_args_list if "DETACH DELETE s" in c[0][0]]
    assert len(calls) <= 1
    return calls[0] if calls else None


def _synced_item(item: dict) -> dict:
    """*item* written to MISP and read back by the sync, as the incremental and baseline runs do."""
    from run_misp_to_neo4j import MISPToNeo4jSync

    attribute = MISPWriter(url="https://misp.test", api_key="test", verify_ssl=True).create_vulnerability_attribute(
        item
    )
    stored = copy.deepcopy(FIXTURES["misp"]["CVE-2025-0237"])  # a real NVD attribute of the hosted MISP
    stored.update(value=attribute["value"], comment=attribute["comment"])
    parsed, _relationships = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(stored, EVENT)
    assert parsed["nvd_record"] is True
    return parsed


class TestParser:
    def test_real_records(self):
        assert cisa_ssvc(_record("CVE-2021-44228")["cve"]["metrics"]) == LOG4SHELL
        assert cisa_ssvc(_record("CVE-1999-0024")["cve"]["metrics"]) == {
            "exploitation": "none",
            "automatable": "no",
            "technical_impact": "partial",
            "version": "2.0.3",
            "timestamp": "2025-07-10T16:10:34.895998Z",
        }
        for cve_id in ("CVE-2026-22314", "CVE-2026-93637"):  # NVD's record carries no SSVC
            assert cisa_ssvc(_record(cve_id)["cve"].get("metrics")) is None

    def test_the_collector_item_carries_it(self):
        assert _item(_record("CVE-2021-44228"))["ssvc"] == LOG4SHELL
        assert _item(_record("CVE-2026-22314"))["ssvc"] is None

    def test_only_cisa_and_its_latest_decision_count(self):
        metrics = _record("CVE-2021-44228")["cve"]["metrics"]
        cisa = metrics["ssvcV203"][0]
        assert cisa["source"] == CISA_ADP_NVD_SOURCE
        other = copy.deepcopy(cisa)
        other["source"] = "another-provider"
        other["ssvcData"].update(options=[{"exploitation": "none"}], timestamp="2026-10-01T00:00:00Z")
        older = copy.deepcopy(cisa)
        older["ssvcData"].update(options=[{"exploitation": "poc"}], timestamp="2024-01-01T00:00:00Z")
        metrics["ssvcV203"] = [older, other, cisa]
        assert cisa_ssvc(metrics) == LOG4SHELL
        # A later version of the metric is read the same way.
        assert cisa_ssvc({"ssvcV210": [cisa]}) == LOG4SHELL

    def test_values_outside_the_decision_points_are_left_out(self):
        metrics = _record("CVE-2021-44228")["cve"]["metrics"]
        data = metrics["ssvcV203"][0]["ssvcData"]
        data["options"] = [{"exploitation": " Active "}, {"automatable": "maybe"}, {"technicalImpact": 7}]
        assert cisa_ssvc(metrics) == {"exploitation": "active", "version": "2.0.3", "timestamp": LOG4SHELL["timestamp"]}
        data["options"] = [{"automatable": "maybe"}]
        assert cisa_ssvc(metrics) is None, "no decision point, no SSVC"

    @pytest.mark.parametrize(
        "metrics",
        [
            None,
            [],
            "ssvcV203",
            {"ssvcV203": "x"},
            {"ssvcV203": ["x", {"source": CISA_ADP_NVD_SOURCE}]},
            {"ssvcV203": [{"source": CISA_ADP_NVD_SOURCE, "ssvcData": "x"}]},
            {"ssvcV203": [{"source": CISA_ADP_NVD_SOURCE, "ssvcData": {"options": 5}}]},
            {"ssvcV203": [{"source": CISA_ADP_NVD_SOURCE, "ssvcData": {"options": "exploitation"}}]},
            {"ssvcV203": [{"source": CISA_ADP_NVD_SOURCE, "ssvcData": {"options": [None, {"exploitation": None}]}}]},
            {"cvssMetricV31": [{"source": CISA_ADP_NVD_SOURCE}]},
        ],
    )
    def test_malformed_shapes_never_raise(self, metrics):
        assert cisa_ssvc(metrics) is None


class TestThroughMisp:
    def test_nvd_meta_carries_it_and_the_sync_reads_it_back(self):
        item = _item(_record("CVE-2021-44228"))
        attribute = MISPWriter(url="https://misp.test", api_key="test", verify_ssl=True).create_vulnerability_attribute(
            item
        )
        assert _meta(attribute["comment"])["ssvc"] == LOG4SHELL
        assert _synced_item(item)["ssvc"] == LOG4SHELL

    def test_a_copy_written_before_ssvc_differs_only_where_cisa_decided(self):
        # The hosted baseline of 2026-10-13 wrote CVE-2025-0237 without the key. NVD's record has
        # CISA's decision, so the rebuilt copy differs by it, and by nothing else.
        stored = _meta(FIXTURES["misp"]["CVE-2025-0237"]["comment"])
        assert "ssvc" not in stored
        rebuilt = _item(_record("CVE-2025-0237"))
        assert rebuilt["ssvc"]["technical_impact"] == "total"
        writer = MISPWriter(url="https://misp.test", api_key="test", verify_ssl=True)
        meta = _meta(writer.create_vulnerability_attribute(rebuilt)["comment"])
        assert nvd_meta_digest(meta) != nvd_meta_digest(stored)
        assert nvd_meta_digest(dict(meta, ssvc=None)) == nvd_meta_digest(stored)

    def test_a_record_without_ssvc_changes_no_stored_copy(self):
        stored = _meta(FIXTURES["misp"]["CVE-2025-0237"]["comment"])
        assert nvd_meta_digest(dict(stored, ssvc=None)) == nvd_meta_digest(stored)

    @pytest.mark.parametrize("value", ["active", ["active"], 1])
    def test_the_sync_reads_only_an_object(self, value):
        item = _item(_record("CVE-2021-44228"))
        item["ssvc"] = value
        assert _synced_item(item)["ssvc"] is None


class TestOnTheNode:
    def test_an_nvd_record_sets_the_decision_on_any_node(self, neo4j_session):
        client, session = neo4j_session
        client.merge_cve(_synced_item(_item(_record("CVE-2021-44228"))), "nvd")
        query, params = _replace_call(session)
        assert {prop: params[prop] for prop in SSVC_PROPERTIES} == {
            "ssvc_exploitation": "active",
            "ssvc_automatable": "yes",
            "ssvc_technical_impact": "total",
            "ssvc_version": "2.0.3",
            "ssvc_timestamp": "2025-02-04T14:25:34.416117Z",
        }
        for prop in SSVC_PROPERTIES:
            # Not limited to nodes whose only source is NVD: no other source supplies SSVC.
            assert f"c.{prop} = ${prop}" in query
            assert f"c.{prop} = CASE WHEN nvd_only" not in query

    def test_an_nvd_record_without_it_removes_it(self, neo4j_session):
        client, session = neo4j_session
        record = _record("CVE-2021-44228")
        del record["cve"]["metrics"]["ssvcV203"]  # CISA withdrew its decision
        client.merge_cve(_synced_item(_item(record)), "nvd")
        _query, params = _replace_call(session)
        assert all(params[prop] is None for prop in SSVC_PROPERTIES), "a null SET removes the property"

    def test_another_source_never_touches_it(self, neo4j_session):
        client, session = neo4j_session
        client.merge_cve({"cve_id": "CVE-2021-44228", "cisa_exploit_add": "2021-12-10", "zone": ["global"]}, "cisa")
        assert _replace_call(session) is None
        assert not any("ssvc" in c[0][0] for c in session.run.call_args_list)

    @pytest.mark.parametrize(
        "ssvc, expected",
        [
            # MISP is an input boundary: values are checked again before they reach the node.
            (
                {"exploitation": "ACTIVE", "automatable": "sometimes", "technical_impact": "total", "version": "2.0.3"},
                {"ssvc_exploitation": "active", "ssvc_technical_impact": "total", "ssvc_version": "2.0.3"},
            ),
            ({"exploitation": "x" * 100, "timestamp": "2025-01-01T00:00:00Z"}, {}),
            ({"version": "2.0.3", "timestamp": "2025-01-01T00:00:00Z"}, {}),
            ({"exploitation": "poc", "timestamp": "t" * 65}, {"ssvc_exploitation": "poc"}),
            ("active", {}),
            (None, {}),
        ],
    )
    def test_values_are_checked_again_on_the_way_in(self, neo4j_session, ssvc, expected):
        client, session = neo4j_session
        item = _synced_item(_item(_record("CVE-2021-44228")))
        item["ssvc"] = ssvc
        client.merge_cve(item, "nvd")
        _query, params = _replace_call(session)
        assert {prop: params[prop] for prop in SSVC_PROPERTIES if params[prop] is not None} == expected
