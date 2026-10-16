"""Export paths on a real Neo4j (2026-10).

What Cypher decides cannot be shown with a mocked session: the driver type of a ``datetime()``
property, the direction a pattern matches, ``ORDER BY`` with nulls, ``collect()`` order, ``=~``
and the labels a query reads. This module writes a small graph the way the writers shape it and
runs the export paths against it:

* the STIX exports of nodes whose timestamps were written with ``datetime()`` (they answered
  HTTP 500: the driver's ``isoformat()`` prints nine fractional digits, stix2 accepts six);
* the Graph Explorer's default view on ``(Indicator)-[:INDICATES]->(Malware)``;
* ``/search/indicator``: related nodes by kind, typed, directed, bounded per kind, and those of
  the indicator returned when one value is stored under two types;
* the Wazuh CDB export: newest entries first under the cap, nulls last, ties by key;
* md5 / sha1 / sha256 / sha512 filters on the stored ``hash`` indicators;
* GraphQL ``vulnerabilities`` on ``:CVE`` (the README example) and ``tlp``.

Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with
``EDGEGUARD_IT_NEO4J_URI``, writes only nodes labelled ``EdgeGuardIT``, refuses any other node.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import neo4j_client  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")


def _api_modules():
    """``query_api`` and ``graphql_api``. Without an API key both refuse to import as production,
    and the CI job sets no ``EDGEGUARD_ENV``: imported as ``dev``, the variable restored after."""
    previous = os.environ.get("EDGEGUARD_ENV")
    os.environ["EDGEGUARD_ENV"] = "dev"
    try:
        import graphql_api
        import query_api
    finally:
        if previous is None:
            os.environ.pop("EDGEGUARD_ENV", None)
        else:
            os.environ["EDGEGUARD_ENV"] = previous
    return query_api, graphql_api


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


# The shapes the writers create: (Indicator)-[:INDICATES]->(Malware), (Indicator)-[:EXPLOITS]->(CVE),
# (Indicator)-[:USES_TECHNIQUE]->(Technique), (Indicator)-[:TARGETS]->(Sector),
# (Indicator)-[:PART_OF_CAMPAIGN]->(Campaign), (Alert)-[:INVOLVES]->(Indicator),
# (Indicator)-[:SOURCED_FROM]->(Source), (Malware)-[:ATTRIBUTED_TO]->(ThreatActor),
# (ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique)-[:IN_TACTIC]->(Tactic), (ThreatActor)-[:RUNS]->(Campaign);
# timestamps written with datetime(), as merge_node_with_source and the batch writers do.
FIXTURE = f"""
CREATE (src:Source:{LABEL} {{source_id: 'threatfox', edgeguard_managed: true}})
CREATE (i:Indicator:{LABEL} {{indicator_type: 'ipv4', value: '203.0.113.5', uuid: 'u-i', edgeguard_managed: true,
        zone: ['energy'], tlp: 'amber', active: true, confidence_score: 0.8,
        first_imported_at: datetime('2026-10-15T08:00:00.123456789Z'), last_updated: datetime()}})
CREATE (m:Malware:{LABEL} {{name: 'emotet', uuid: 'u-m', edgeguard_managed: true, malware_types: ['trojan'],
        first_imported_at: datetime(), last_updated: datetime()}})
CREATE (a:ThreatActor:{LABEL} {{name: 'apt28', uuid: 'u-a', edgeguard_managed: true, aliases: ['APT28'],
        first_imported_at: datetime(), last_updated: datetime()}})
CREATE (t:Technique:{LABEL} {{mitre_id: 'T1059', name: 'Command and Scripting Interpreter', uuid: 'u-t',
        edgeguard_managed: true, tactic_phases: ['execution'], first_imported_at: datetime(), last_updated: datetime()}})
CREATE (tac:Tactic:{LABEL} {{mitre_id: 'TA0002', name: 'Execution', shortname: 'execution', uuid: 'u-tac',
        edgeguard_managed: true}})
CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2021-44228', uuid: 'u-c', edgeguard_managed: true, zone: ['healthcare'],
        description: 'Log4Shell', cvss_score: 10.0, severity: 'CRITICAL', cvss_version: '3.1', status: ['active'],
        published: '2021-12-10T10:15:09.143', tlp: 'white',
        first_imported_at: datetime('2026-10-14T07:30:00Z'), last_updated: datetime()}})
CREATE (camp:Campaign:{LABEL} {{name: 'apt28 campaign', uuid: 'u-camp', edgeguard_managed: true,
        first_seen: datetime('2023-01-01T00:00:00.987654321Z'), last_seen: datetime(), last_updated: datetime()}})
CREATE (sec:Sector:{LABEL} {{name: 'energy', edgeguard_managed: true}})
CREATE (al:Alert:{LABEL} {{alert_id: 'alert-1', edgeguard_managed: true}})
CREATE (i)-[:INDICATES {{sources: ['threatfox'], confidence_score: 0.8, match_type: 'malware_family'}}]->(m)
CREATE (i)-[:EXPLOITS {{sources: ['alienvault_otx'], confidence_score: 0.5}}]->(c)
CREATE (i)-[:USES_TECHNIQUE {{sources: ['alienvault_otx']}}]->(t)
CREATE (i)-[:TARGETS {{sources: ['threatfox']}}]->(sec)
CREATE (i)-[:PART_OF_CAMPAIGN {{match_type: 'campaign_grouping'}}]->(camp)
CREATE (al)-[:INVOLVES]->(i)
CREATE (i)-[:SOURCED_FROM {{source: 'threatfox',
        source_reported_first_at: datetime('2023-01-01T00:00:00.987654321Z'),
        source_reported_last_at: datetime()}}]->(src)
CREATE (m)-[:ATTRIBUTED_TO {{sources: ['threatfox'], confidence_score: 0.6}}]->(a)
CREATE (a)-[:EMPLOYS_TECHNIQUE {{sources: ['mitre_attck'], confidence_score: 0.95}}]->(t)
CREATE (t)-[:IN_TACTIC {{match_type: 'kill_chain_phase'}}]->(tac)
CREATE (a)-[:RUNS {{match_type: 'campaign_grouping'}}]->(camp)
WITH i
UNWIND range(1, 12) AS k
CREATE (x:Technique:{LABEL} {{mitre_id: 'T10' + right('0' + toString(k), 2), uuid: 'u-t' + toString(k),
        edgeguard_managed: true, name: 'technique ' + toString(k)}})
CREATE (i)-[:USES_TECHNIQUE {{sources: ['alienvault_otx']}}]->(x)
"""


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


@pytest.fixture
def rest(client, monkeypatch):
    from fastapi.testclient import TestClient

    query_api, _graphql_api = _api_modules()
    monkeypatch.setattr(query_api, "neo4j_client", client)
    monkeypatch.setattr(query_api, "_API_KEY", None)
    return TestClient(query_api.app)


# ---------------------------------------------------------------------------
# STIX: nodes written with datetime()
# ---------------------------------------------------------------------------

_FRACTION = re.compile(r"\.(\d+)")


def test_stix_exports_of_synced_nodes_parse_strictly(client, rest):
    import stix2

    from stix_exporter import StixExporter

    exporter = StixExporter(client)
    bundles = {
        "indicator": exporter.export_indicator("203.0.113.5"),
        "actor": exporter.export_threat_actor("APT28"),
        "technique": exporter.export_technique("T1059"),
        "cve": exporter.export_cve("CVE-2021-44228"),
    }
    for name, bundle in bundles.items():
        stix2.parse(bundle)  # strict: allow_custom defaults to False
        sdo_types = {o["type"] for o in bundle["objects"]}
        assert {"indicator", "malware", "intrusion-set", "attack-pattern", "vulnerability"} & sdo_types, name
        for obj in bundle["objects"]:
            for key in ("created", "modified", "valid_from"):
                fraction = _FRACTION.search(obj.get(key, ""))
                assert fraction is None or len(fraction.group(1)) <= 6, (name, obj["type"], key, obj[key])
    (indicator,) = [o for o in bundles["indicator"]["objects"] if o["type"] == "indicator"]
    assert indicator["created"] == "2026-10-15T08:00:00.123456Z"
    assert indicator["valid_from"] == "2023-01-01T00:00:00.987654Z"  # min(source_reported_first_at)
    (vulnerability,) = [o for o in bundles["cve"]["objects"] if o["type"] == "vulnerability"]
    assert vulnerability["created"] == "2026-10-14T07:30:00.000Z"
    for path in ("indicator/203.0.113.5", "actor/APT28", "technique/T1059", "cve/CVE-2021-44228"):
        resp = rest.get(f"/stix/export/{path}")
        assert resp.status_code == 200, (path, resp.text)


# ---------------------------------------------------------------------------
# Graph Explorer
# ---------------------------------------------------------------------------


def _edges(data):
    return {(e["data"]["source"], e["data"]["target"], e["data"]["type"]) for e in data["edges"]}


def test_explorer_default_view_shows_indicator_to_malware(rest):
    data = rest.get("/graph/explore").json()
    assert _edges(data) == {
        ("indicator:203.0.113.5", "malware:emotet", "INDICATES"),
        ("indicator:203.0.113.5", "sector:energy", "BELONGS_TO"),
    }
    assert {n["data"]["id"] for n in data["nodes"]} == {"indicator:203.0.113.5", "malware:emotet", "sector:energy"}
    assert rest.get("/graph/explore?view=attacks&zone=energy").json()["stats"] == {"nodes": 3, "edges": 2}
    assert rest.get("/graph/explore?view=attacks&zone=finance").json()["stats"] == {"nodes": 0, "edges": 0}


def test_explorer_vulnerabilities_view_pairs_a_description_with_its_own_source(raw_driver, rest):
    """2026-10-16: the CVE's twins are grouped by ``cve_id``; the view takes the description and its
    ``description_source`` from one node. Here the CVE node holds a description written before the ranking
    (no source) and its Vulnerability twin a source without a description: ``head(collect(...))`` of each
    property would pair the CVE's text with the twin's source."""
    with raw_driver.session() as session:
        session.run(
            f"CREATE (:Vulnerability:{LABEL} {{cve_id: 'CVE-2021-44228', uuid: 'u-v', edgeguard_managed: true, "
            "description_source: 'nvd', zone: ['healthcare']}})"
        )
    data = rest.get("/graph/explore?view=vulnerabilities").json()
    (node,) = [n["data"] for n in data["nodes"] if n["data"]["id"] == "vuln:CVE-2021-44228"]
    assert (node["description"], node["description_source"]) == ("Log4Shell", None)


def test_explorer_actors_view_follows_the_written_directions(rest):
    data = rest.get("/graph/explore?view=actors").json()
    assert _edges(data) == {
        ("actor:apt28", "technique:T1059", "EMPLOYS_TECHNIQUE"),
        ("technique:T1059", "tactic:Execution", "IN_TACTIC"),
    }


# ---------------------------------------------------------------------------
# /search/indicator
# ---------------------------------------------------------------------------


def test_search_returns_related_nodes_by_kind_typed_and_bounded(rest):
    body = rest.post("/search/indicator", json={"value": "203.0.113.5"}).json()
    assert body["found"] is True
    pairs = [(r["relationship_type"], r["direction"]) for r in body["relationships"]]
    keys = [
        n.get("mitre_id") or n.get("cve_id") or n.get("name") or n.get("alert_id") or n.get("source_id")
        for n in body["related"]
    ]
    techniques = [f"T10{k:02d}" for k in range(1, 11)]  # T1001..T1010: 10 of the 13 (bound per kind)
    assert keys == ["emotet", "CVE-2021-44228", *techniques, "apt28 campaign", "energy", "alert-1", "threatfox"]
    assert pairs == [
        ("INDICATES", "outgoing"),
        ("EXPLOITS", "outgoing"),
        *[("USES_TECHNIQUE", "outgoing")] * 10,
        ("PART_OF_CAMPAIGN", "outgoing"),
        ("TARGETS", "outgoing"),
        ("INVOLVES", "incoming"),
        ("SOURCED_FROM", "outgoing"),
    ]
    assert "Malware" in body["relationships"][0]["labels"]
    assert body == rest.post("/search/indicator", json={"value": "203.0.113.5"}).json(), "stable across calls"


# One value under two types: a ``hash`` node from before 2026-10 (SSL Blacklist fingerprints were
# file hashes) and the ``x509-fingerprint-sha1`` node the collector writes now. Only the certificate
# node indicates the family of the listing (the SSL Blacklist row of
# tests/test_ip_family_and_certificate_fingerprint_types.py: "Dridex C&C").
_FINGERPRINT = "0123456789abcdef0123456789abcdef01234567"
TWIN_FIXTURE = f"""
CREATE (:Indicator:{LABEL} {{indicator_type: 'hash', value: '{_FINGERPRINT}', uuid: 'u-twin-hash',
        edgeguard_managed: true, zone: ['finance']}})
CREATE (x:Indicator:{LABEL} {{indicator_type: 'x509-fingerprint-sha1', value: '{_FINGERPRINT}', uuid: 'u-twin-x509',
        edgeguard_managed: true, zone: ['finance']}})
CREATE (d:Malware:{LABEL} {{name: 'dridex', uuid: 'u-dridex', edgeguard_managed: true}})
CREATE (x)-[:INDICATES {{sources: ['ssl_blacklist'], confidence_score: 0.9}}]->(d)
"""


def test_search_returns_the_related_nodes_of_the_indicator_it_returns(raw_driver, rest):
    """The related lookup matched every node that stores the value: a search answered with the
    ``hash`` node listed the certificate node's malware as an ``outgoing`` INDICATES of it."""
    with raw_driver.session() as session:
        session.run(TWIN_FIXTURE)

    def search(**body):
        resp = rest.post("/search/indicator", json={"value": _FINGERPRINT.upper(), **body})
        assert resp.status_code == 200, resp.text
        return resp.json()

    typed = search(indicator_type="x509-fingerprint-sha1")
    assert typed["indicator"]["indicator_type"] == "x509-fingerprint-sha1"
    assert [n["name"] for n in typed["related"]] == ["dridex"]
    assert typed["relationships"] == [
        {"relationship_type": "INDICATES", "direction": "outgoing", "labels": sorted(["Malware", LABEL])}
    ]
    for body in ({"indicator_type": "hash"}, {"indicator_type": "sha1"}, {}):  # {}: inferred as hash
        legacy = search(**body)
        assert legacy["indicator"]["indicator_type"] == "hash", body
        assert legacy["related"] == [] and legacy["relationships"] == [], body


# ---------------------------------------------------------------------------
# Wazuh CDB: newest first under the cap
# ---------------------------------------------------------------------------

# 2026-10-16: an indicator is ordered by its latest report (``last_reported_at``), or when EdgeGuard
# created it (``first_imported_at``) when no report dated it; ``last_updated`` (the last database write,
# which a full sync moves) is not read.
CDB_FIXTURE = f"""
CREATE (:Indicator:{LABEL} {{indicator_type: 'domain', value: 'newest.example', edgeguard_managed: true,
        zone: ['finance'], last_reported_at: datetime('2026-10-15T09:00:00Z'),
        last_updated: datetime('2026-10-01T00:00:00Z')}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'domain', value: 'b-tie.example', edgeguard_managed: true,
        zone: ['finance'], last_reported_at: datetime('2026-10-14T09:00:00Z')}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'domain', value: 'a-tie.example', edgeguard_managed: true,
        zone: ['finance'], first_imported_at: datetime('2026-10-14T09:00:00Z')}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'domain', value: 'aaa-undated.example', edgeguard_managed: true,
        zone: ['finance'], last_updated: datetime('2026-10-16T00:00:00Z')}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'domain', value: 'retired.example', edgeguard_managed: true,
        zone: ['finance'], active: false, last_reported_at: datetime('2026-10-15T10:00:00Z')}})
"""


def test_wazuh_list_keeps_the_newest_entries_and_reports_the_cut(raw_driver, rest, monkeypatch):
    query_api, _graphql_api = _api_modules()
    with raw_driver.session() as session:
        session.run(CDB_FIXTURE)
    resp = rest.get("/export/wazuh/cdb?list=indicators&zone=finance")
    assert [line.split(":", 1)[0] for line in resp.text.splitlines()] == [
        "newest.example",
        "a-tie.example",
        "b-tie.example",
        "aaa-undated.example",  # no report time: last, not first (Cypher sorts null first descending)
    ]
    assert resp.headers["X-EdgeGuard-Truncated"] == "false"
    monkeypatch.setattr(query_api, "_CDB_EXPORT_MAX_ENTRIES", 3)
    resp = rest.get("/export/wazuh/cdb?list=indicators&zone=finance")
    assert [line.split(":", 1)[0] for line in resp.text.splitlines()] == [
        "newest.example",
        "a-tie.example",
        "b-tie.example",
    ]
    assert resp.headers["X-EdgeGuard-Truncated"] == "true"


# ---------------------------------------------------------------------------
# Digest-type filters on the stored ``hash`` indicators
# ---------------------------------------------------------------------------

# The Mirai sample of MalwareBazaar's recent export (tests/test_malwarebazaar_collector.py).
_MD5 = "2cbdeeb34862d4f0a40aabcc3236b891"
_SHA1 = "d382bede96d914347228a5392812851da046858f"
_SHA256 = "38cbdf411e85b4136c8d4b725f7b46530919d45799a8065965d408db5ebcc15d"
HASH_FIXTURE = f"""
CREATE (:Indicator:{LABEL} {{indicator_type: 'hash', value: '{_MD5}', edgeguard_managed: true, active: true,
        zone: ['healthcare']}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'hash', value: '{_SHA1}', edgeguard_managed: true, active: true,
        zone: ['healthcare']}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'hash', value: '{_SHA256}', edgeguard_managed: true, active: true,
        zone: ['healthcare']}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'hash', value: '{"z" * 64}', edgeguard_managed: true, active: true,
        zone: ['healthcare']}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'x509-fingerprint-sha1', value: '{"ab" * 20}', edgeguard_managed: true,
        active: true, zone: ['healthcare']}})
"""


def test_digest_type_filters_select_hash_indicators_by_length(client, raw_driver, rest, monkeypatch):
    _query_api, graphql_api = _api_modules()
    with raw_driver.session() as session:
        session.run(HASH_FIXTURE)

    def listed(indicator_type):
        body = rest.get(f"/indicators?indicator_type={indicator_type}&zone=healthcare").json()
        assert body["total"] == len(body["indicators"])
        return sorted(n["value"] for n in body["indicators"])

    assert listed("md5") == [_MD5]
    assert listed("sha1") == [_SHA1]  # not the 40-hex certificate fingerprint
    assert listed("sha256") == [_SHA256]  # not the 64-character non-hex value
    assert listed("sha512") == []
    assert listed("hash") == sorted([_MD5, _SHA1, _SHA256, "z" * 64])
    cdb = rest.get("/export/wazuh/cdb?list=indicators&zone=healthcare&indicator_type=sha256")
    assert [line.split(":", 1)[0] for line in cdb.text.splitlines()] == [_SHA256]

    monkeypatch.setattr(graphql_api, "_client", client)
    result = graphql_api.schema.execute_sync(
        '{ indicators(filter: {indicatorType: "sha1", zone: "healthcare"}) { value indicatorType } }'
    )
    assert result.errors is None, result.errors
    assert result.data == {"indicators": [{"value": _SHA1, "indicatorType": "hash"}]}


# ---------------------------------------------------------------------------
# GraphQL: vulnerabilities on :CVE, tlp
# ---------------------------------------------------------------------------

CVE_FIXTURE = f"""
CREATE (:CVE:{LABEL} {{cve_id: 'CVE-2026-1001', edgeguard_managed: true, zone: ['healthcare'], cvss_score: 5.0,
        severity: 'MEDIUM', cvss_version: '3.1', status: ['active']}})
CREATE (:CVE:{LABEL} {{cve_id: 'CVE-2026-1002', edgeguard_managed: true, zone: ['energy'], cvss_score: 9.8,
        severity: 'CRITICAL', cvss_version: '3.1', status: ['active']}})
CREATE (:CVE:{LABEL} {{cve_id: 'CVE-2026-22314', edgeguard_enriched: true, zone: ['healthcare'],
        severity: 'UNKNOWN', status: ['rejected']}})
CREATE (:CVE:{LABEL} {{cve_id: 'CVE-2026-1003', zone: ['healthcare'], cvss_score: 9.9, severity: 'CRITICAL'}})
CREATE (:Vulnerability:{LABEL} {{cve_id: 'CVE-2026-1004', edgeguard_managed: true, zone: ['healthcare'],
        cvss_score: 9.5, severity: 'CRITICAL'}})
"""

_README_QUERY = """
query {
  vulnerabilities(filter: { zone: "healthcare", minCvss: 9.0 }) {
    cveId description status severity cvssScore cvssVersion published tlp
  }
}
"""


def test_graphql_vulnerabilities_read_the_cve_nodes(client, raw_driver, monkeypatch):
    _query_api, graphql_api = _api_modules()
    with raw_driver.session() as session:
        session.run(CVE_FIXTURE)
    monkeypatch.setattr(graphql_api, "_client", client)
    result = graphql_api.schema.execute_sync(_README_QUERY)
    assert result.errors is None, result.errors
    # Not the energy CVE, not the 5.0 one, not the partner CVE without EdgeGuard flags, not the
    # :Vulnerability node.
    assert result.data == {
        "vulnerabilities": [
            {
                "cveId": "CVE-2021-44228",
                "description": "Log4Shell",
                "status": ["active"],
                "severity": "CRITICAL",
                "cvssScore": 10.0,
                "cvssVersion": "3.1",
                "published": "2021-12-10T10:15:09.143",
                "tlp": "white",
            }
        ]
    }
    result = graphql_api.schema.execute_sync('{ vulnerabilities(filter: {zone: "healthcare"}) { cveId cvssScore } }')
    assert result.errors is None, result.errors
    assert result.data["vulnerabilities"] == [
        {"cveId": "CVE-2021-44228", "cvssScore": 10.0},
        {"cveId": "CVE-2026-1001", "cvssScore": 5.0},
        {"cveId": "CVE-2026-22314", "cvssScore": None},  # an enriched partner CVE without CVSS
    ]
    result = graphql_api.schema.execute_sync('{ indicators(filter: {zone: "energy"}) { value tlp } }')
    assert result.data == {"indicators": [{"value": "203.0.113.5", "tlp": "amber"}]}
