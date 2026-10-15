"""FIRST EPSS and CISA's SSVC on the CVE nodes of a real Neo4j (2026-10).

``enrich_cve_epss`` runs as the enrichment task runs it, on a node EdgeGuard manages, on one a
partner created and on one whose CVE has left the feed. ``merge_cve`` writes an NVD record that
carries CISA's SSVC decision, one where CISA withdrew it, and a KEV record (which never touches it),
after the record went through MISP and the sync (``tests/test_cve_ssvc_from_nvd.py``). Same guards as
``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``, writes only
nodes labelled ``EdgeGuardIT``, refuses any other node.
"""

from __future__ import annotations

import gzip
import os
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import cve_feed_enrichment  # noqa: E402
import neo4j_client  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

SCORE_DATE = "2026-10-11T12:00:25Z"
FEED = (
    f"#model_version:v2026.06.15,score_date:{SCORE_DATE}\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.97565,0.99999\n"
    "CVE-2020-0001,0.00043,0.09500\n"
    "CVE-2026-99999,0.1,0.2\n"  # no node in the graph
)
EPSS = ("epss_score", "epss_percentile", "epss_score_date", "epss_model_version", "epss_updated_at")
SSVC = ("ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact", "ssvc_version", "ssvc_timestamp")

FIXTURE = f"""
CREATE (:Source:{LABEL} {{source_id: 'nvd'}})
CREATE (:Source:{LABEL} {{source_id: 'cisa'}})
CREATE (:CVE:{LABEL} {{cve_id: 'CVE-2021-44228', uuid: 'u-log4shell', edgeguard_managed: true, source: ['nvd']}})
CREATE (:CVE:{LABEL} {{cve_id: 'CVE-2020-0001', uuid: 'u-partner'}})
CREATE (:CVE:{LABEL} {{cve_id: 'CVE-1999-0024', uuid: 'u-left', edgeguard_managed: true, source: ['nvd'],
        epss_score: 0.5, epss_percentile: 0.5, epss_score_date: '2026-10-10T12:00:00Z',
        epss_model_version: 'v2026.06.15', epss_updated_at: datetime()}})
"""


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def client(raw_driver):
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(FIXTURE)
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()
    with raw_driver.session() as session:
        foreign = session.run(f"MATCH (n) WHERE NOT n:{LABEL} RETURN count(n) AS c").single()["c"]
    assert foreign == 0, "the test wrote a node without the test label"


def _cves(raw_driver):
    with raw_driver.session() as session:
        return {r["id"]: r["props"] for r in session.run("MATCH (c:CVE) RETURN c.cve_id AS id, properties(c) AS props")}


def test_epss_scores_existing_cves_marks_a_partner_node_and_clears_one_that_left(client, raw_driver, monkeypatch):
    monkeypatch.setattr(cve_feed_enrichment, "fetch_epss_bytes", lambda url: gzip.compress(FEED.encode()))
    monkeypatch.setattr(cve_feed_enrichment, "query_pause", lambda: None)
    first = cve_feed_enrichment.enrich_cve_epss(client)
    second = cve_feed_enrichment.enrich_cve_epss(client)  # the next run changes nothing
    assert (first["cves_updated"], first["cves_cleared"]) == (2, 1)
    assert (second["cves_updated"], second["cves_cleared"]) == (2, 0)

    cves = _cves(raw_driver)
    assert set(cves) == {"CVE-2021-44228", "CVE-2020-0001", "CVE-1999-0024"}, "no node is created"
    own, partner, left = cves["CVE-2021-44228"], cves["CVE-2020-0001"], cves["CVE-1999-0024"]
    assert (own["epss_score"], own["epss_percentile"]) == (0.97565, 0.99999)
    assert (own["epss_score_date"], own["epss_model_version"]) == (SCORE_DATE, "v2026.06.15")
    assert own["epss_updated_at"] is not None
    assert "edgeguard_enriched" not in own, "EdgeGuard's own node is not marked as a partner's"
    assert partner["epss_score"] == 0.00043 and partner["edgeguard_enriched"] is True
    assert "edgeguard_managed" not in partner, "the partner's node stays the partner's"
    assert not [prop for prop in EPSS if prop in left], "a CVE that left the feed loses its EPSS"


def test_an_nvd_record_sets_and_withdraws_ssvc_and_another_source_leaves_it(client, raw_driver):
    from test_cve_ssvc_from_nvd import _item, _record, _synced_item

    def nvd_record(with_ssvc: bool) -> dict:
        record = _record("CVE-2021-44228")
        if not with_ssvc:
            del record["cve"]["metrics"]["ssvcV203"]
        item = _synced_item(_item(record))
        # CVSS sub-nodes are another test's subject, and would be nodes without the test label.
        item.update(cvss_v40_data=None, cvss_v31_data=None, cvss_v30_data=None, cvss_v2_data=None)
        return item

    assert client.merge_cve(nvd_record(with_ssvc=True), "nvd")
    node = _cves(raw_driver)["CVE-2021-44228"]
    assert {prop: node.get(prop) for prop in SSVC} == {
        "ssvc_exploitation": "active",
        "ssvc_automatable": "yes",
        "ssvc_technical_impact": "total",
        "ssvc_version": "2.0.3",
        "ssvc_timestamp": "2025-02-04T14:25:34.416117Z",
    }

    client.merge_cve({"cve_id": "CVE-2021-44228", "cisa_exploit_add": "2021-12-10", "zone": ["global"]}, "cisa")
    node = _cves(raw_driver)["CVE-2021-44228"]
    assert node["ssvc_exploitation"] == "active", "a KEV record never touches CISA's SSVC decision"
    assert node["cisa_exploit_add"] == "2021-12-10"

    assert client.merge_cve(nvd_record(with_ssvc=False), "nvd")
    node = _cves(raw_driver)["CVE-2021-44228"]
    assert not [prop for prop in SSVC if prop in node], "a decision CISA withdrew leaves the node"
