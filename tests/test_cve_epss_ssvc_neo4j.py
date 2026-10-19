"""FIRST EPSS, CISA's SSVC and the CVE record's text on the CVE nodes of a real Neo4j (2026-10).

``enrich_cve_epss`` runs as the enrichment task runs it, on a node EdgeGuard manages, on one a
partner created and on one whose CVE has left the feed. ``merge_cve`` writes an NVD record that
carries CISA's SSVC decision, one where CISA withdrew it, and a KEV record (which never touches it),
after the record went through MISP and the sync (``tests/test_cve_ssvc_from_nvd.py``). The records of
one CVE from NVD, OTX, the KEV and CISA ICS (real hosted MISP attributes) are merged in several orders:
NVD's record sets ``published`` and ``last_modified``, any other record fills them only where the node has
none; the description follows the source ranking NVD > CISA KEV > CISA ICS > any other source with its
``description_source`` (2026-10-16), and an OTX pulse reference gives none
(``tests/test_cve_description_source.py``, every order: ``tests/test_description_ranking_neo4j.py``); a
ResilMesh-native write keeps the values it does not carry. Same guards as
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
CREATE (:Source:{LABEL} {{source_id: 'cisa_kev'}})
CREATE (:Source:{LABEL} {{source_id: 'cisa_ics'}})
CREATE (:Source:{LABEL} {{source_id: 'alienvault_otx'}})
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


# ---------------------------------------------------------------- the CVE record's text (2026-10)
RECORD_TEXT = ("description", "description_source", "published", "last_modified")


def _real_record(key: str) -> dict:
    """A real hosted MISP attribute (``test_cvss_real_payloads.json``) read by the sync, without its
    CVSS payloads: CVSS sub-nodes are another test's subject, and would be nodes without the test label."""
    from test_cve_description_source import synced_key

    item = synced_key(key)
    item.update(cvss_v40_data=None, cvss_v31_data=None, cvss_v30_data=None, cvss_v2_data=None)
    return item


def _create(raw_driver, label: str, cve_id: str, **props) -> None:
    """The node the merges below write to, with the test label (a MERGE would create one without)."""
    with raw_driver.session() as session:
        session.run(f"CREATE (n:{label}:{LABEL} {{cve_id: $cve_id}}) SET n += $props", cve_id=cve_id, props=props)


def _text(raw_driver, label: str, cve_id: str) -> dict:
    with raw_driver.session() as session:
        props = session.run(f"MATCH (n:{label} {{cve_id: $cve_id}}) RETURN properties(n) AS p", cve_id=cve_id).single()[
            "p"
        ]
    return {prop: props[prop] for prop in RECORD_TEXT if prop in props}


def _expected(item: dict) -> dict:
    """The node one record leaves on an empty CVE: its text with its source (2026-10-16), and its dates."""
    node = {prop: item[prop] for prop in RECORD_TEXT if item.get(prop)}
    if item.get("description"):
        node["description_source"] = item["tag"]
    return node


@pytest.mark.parametrize(
    "order",
    [
        ("NVD", "AlienVault-OTX", "CISA-KEV"),
        ("AlienVault-OTX", "CISA-KEV", "NVD"),
        ("CISA-KEV", "NVD", "AlienVault-OTX"),
    ],
)
def test_nvd_record_sets_the_cve_text_and_dates_in_any_order(client, raw_driver, order):
    _create(raw_driver, "CVE", "CVE-2025-21042")
    for source in order:
        item = _real_record(f"CVE-2025-21042__source:{source}")
        assert client.merge_cve(item, item["tag"])
    nvd = _real_record("CVE-2025-21042__source:NVD")
    assert _text(raw_driver, "CVE", "CVE-2025-21042") == _expected(nvd), order
    with raw_driver.session() as session:
        kev_date = session.run("MATCH (c:CVE {cve_id: 'CVE-2025-21042'}) RETURN c.cisa_exploit_add AS d").single()["d"]
    assert kev_date == _real_record("CVE-2025-21042__source:CISA-KEV")["cisa_exploit_add"], "the KEV fields still land"


def test_cisa_ics_dates_fill_and_nvd_record_replaces_them(client, raw_driver):
    _create(raw_driver, "CVE", "CVE-2025-14272")
    ics, nvd = _real_record("CVE-2025-14272__source:CISA-ICS"), _real_record("CVE-2025-14272__source:NVD")
    assert client.merge_cve(ics, "cisa_ics")
    assert _text(raw_driver, "CVE", "CVE-2025-14272") == _expected(ics), "alone, the advisory fills the node"
    assert client.merge_cve(nvd, "nvd")
    assert client.merge_cve(ics, "cisa_ics")
    assert _text(raw_driver, "CVE", "CVE-2025-14272") == _expected(nvd)


@pytest.mark.parametrize("legacy", [True, False], ids=["note", "otx_meta"])
@pytest.mark.parametrize("first", ["pulse_reference", "kev"])
def test_an_otx_pulse_reference_is_no_description_and_the_kev_text_fills(client, raw_driver, first, legacy):
    # The OTX collector's cve_references item as MISPWriter writes it: an OTX_META block naming the pulse
    # (2026-10-18), and as MISP still holds it from before ("Referenced in OTX pulse: <name>"). Merged first
    # on a CVE without an NVD record, the note used to stay, and CISA's KEV text never replaced it.
    from test_cve_description_source import otx_pulse_reference, synced

    _create(raw_driver, "CVE", "CVE-2015-5477")
    reference, kev = synced(otx_pulse_reference(legacy=legacy)), _real_record("CVE-2015-5477__source:CISA-KEV")
    for item in (reference, kev) if first == "pulse_reference" else (kev, reference):
        assert client.merge_cve(item, item["tag"])
    assert _text(raw_driver, "CVE", "CVE-2015-5477") == {
        "description": kev["description"],
        "description_source": "cisa_kev",
    }


def test_without_nvd_record_an_empty_description_is_filled_and_otx_adds_nothing(client, raw_driver):
    _create(raw_driver, "CVE", "CVE-2015-5477", description="")
    otx, kev = _real_record("CVE-2015-5477__source:AlienVault-OTX"), _real_record("CVE-2015-5477__source:CISA-KEV")
    assert client.merge_cve(otx, "alienvault_otx")
    assert _text(raw_driver, "CVE", "CVE-2015-5477") == {"description": ""}, "OTX's pulse JSON is not a description"
    assert client.merge_cve(kev, "cisa_kev")
    assert client.merge_cve(otx, "alienvault_otx")
    assert _text(raw_driver, "CVE", "CVE-2015-5477") == {
        "description": kev["description"],
        "description_source": "cisa_kev",
    }


def test_batch_and_resilmesh_paths_keep_nvd_text(client, raw_driver):
    _create(raw_driver, "Vulnerability", "CVE-2025-21042")
    kev, nvd = _real_record("CVE-2025-21042__source:CISA-KEV"), _real_record("CVE-2025-21042__source:NVD")
    otx = _real_record("CVE-2025-21042__source:AlienVault-OTX")
    for item in (kev, nvd, otx, kev):
        assert client.merge_vulnerabilities_batch([dict(item)], source_id=item["tag"]) == (1, 0)
    assert _text(raw_driver, "Vulnerability", "CVE-2025-21042") == _expected(nvd)

    _create(raw_driver, "CVE", "CVE-2025-21042")
    assert client.merge_cve(nvd, "nvd")
    assert client.merge_resilmesh_cve({"cve_id": "CVE-2025-21042", "description": "partner text"})
    assert client.merge_resilmesh_cve({"cve_id": "CVE-2025-21042"})  # used to remove all three
    assert _text(raw_driver, "CVE", "CVE-2025-21042") == _expected(nvd)
    # ... and NVD's lists, which a call without them also set to null.
    lists = ("cwe", "ref_tags", "cpe_type", "result_impacts")
    assert all(nvd[prop] for prop in lists), "the NVD record carries every list"
    with raw_driver.session() as session:
        stored = session.run("MATCH (c:CVE {cve_id: 'CVE-2025-21042'}) RETURN properties(c) AS p").single()["p"]
    assert {prop: stored.get(prop) for prop in lists} == {prop: nvd[prop] for prop in lists}

    # A ResilMesh-native Vulnerability write without a status keeps the stored one.
    assert client.merge_resilmesh_vulnerability({"cve_id": "CVE-2025-21042", "status": "open"})
    assert client.merge_resilmesh_vulnerability({"cve_id": "CVE-2025-21042"})
    with raw_driver.session() as session:
        status = session.run("MATCH (v:Vulnerability {cve_id: 'CVE-2025-21042'}) RETURN v.status AS s").single()["s"]
    assert status == "open"
