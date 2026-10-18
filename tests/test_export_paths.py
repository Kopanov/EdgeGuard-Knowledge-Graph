"""Export paths (2026-10): STIX timestamps of driver temporals, the Graph Explorer's default view,
GraphQL ``vulnerabilities`` and ``tlp``, digest-type filters, ``/search/indicator`` related nodes,
the Wazuh CDB cap, ``/stix/types`` and the documentation of these routes.

Every defect was confirmed on main before the fix:

* STIX exports answered 500 for every node the sync wrote: Cypher ``datetime()`` reaches the
  exporter as ``neo4j.time.DateTime``, whose ``isoformat()`` prints nine fractional digits, and
  ``stix2`` 3.0.2 accepts at most six.
* ``GET /graph/explore`` (default view ``attacks``) matched ``(Malware)-[INDICATES|DROPS]->
  (Indicator)``; every writer creates ``(Indicator)-[:INDICATES]->(Malware)``.
* GraphQL ``vulnerabilities`` read ``:Vulnerability``; the sync writes ``:CVE``.
* GraphQL types had no ``tlp``.
* ``md5`` / ``sha1`` / ``sha256`` / ``sha512`` filters compared ``indicator_type`` exactly; the
  sync stores every file digest as ``hash``.
* ``/search/indicator`` related nodes: undirected, ``LIMIT 10``, no ``ORDER BY``, no type, and
  matched on the value alone (the neighbours of every type that stores it); the caller's type
  was ignored.
* The Wazuh CDB export kept the alphabetically first 50,000 entries without saying so.
* The Graph Explorer guide and README had readers open the page from disk, which the default
  CORS allowlist refuses; the demo page stated relationship directions no writer creates.

What Cypher itself decides (ordering, ``=~``, directions) is checked on a real Neo4j in
``tests/test_export_paths_neo4j.py``.
"""

from __future__ import annotations

import os
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
import stix2

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault("NEO4J_PASSWORD", "test-password")
os.environ.setdefault("EDGEGUARD_ENV", "dev")

from stub_cleanup import clear_graphql_api_magicmock_stubs  # noqa: E402

# These tests need the driver's real ``neo4j.time`` classes. ``tests/test_graphql_api.py`` stubs
# ``neo4j`` with mocks when it is collected first; the modules below then cache the mocks at import
# (``source_truthful_timestamps._NEO4J_TEMPORAL_TYPES``, ``query_api._neo4j_time``). Only in that
# case are the stubs removed and those modules imported afresh, so the usual collection order keeps
# the module objects every other test module already holds.
if any(isinstance(m, MagicMock) for k, m in list(sys.modules.items()) if k == "neo4j" or k.startswith("neo4j.")):
    clear_graphql_api_magicmock_stubs()
    for _cached in ("source_truthful_timestamps", "stix_exporter", "query_api", "graphql_api"):
        sys.modules.pop(_cached, None)

from fastapi.testclient import TestClient  # noqa: E402
from neo4j.time import Date as Neo4jDate  # noqa: E402
from neo4j.time import DateTime as Neo4jDateTime  # noqa: E402
from neo4j.time import Time as Neo4jTime  # noqa: E402

import graphql_api  # noqa: E402
import ioc_normalize  # noqa: E402
import query_api  # noqa: E402
import stix_exporter  # noqa: E402
from source_truthful_timestamps import iso_str  # noqa: E402
from stix_exporter import StixExporter, _stix_ts  # noqa: E402

# What ``datetime()`` stores: nanosecond precision. One value with a fraction beyond microseconds,
# one with none (``isoformat()`` printed ``.000000000`` for it too).
NS = Neo4jDateTime(2026, 10, 15, 8, 0, 0, 123456789, tzinfo=timezone.utc)
WHOLE = Neo4jDateTime(2026, 10, 14, 7, 30, 0, 0, tzinfo=timezone.utc)
SOURCE_FIRST = Neo4jDateTime(2023, 1, 1, 0, 0, 0, 987654321, tzinfo=timezone.utc)
_FRACTION = re.compile(r"\.(\d+)")


# ---------------------------------------------------------------------------
# 1. STIX timestamps of driver temporals
# ---------------------------------------------------------------------------


class TestIsoStr:
    def test_the_driver_type_prints_nine_fractional_digits(self):
        """The defect's premise, pinned so the tests below stay meaningful."""
        assert NS.isoformat() == "2026-10-15T08:00:00.123456789+00:00"
        assert WHOLE.isoformat() == "2026-10-14T07:30:00.000000000+00:00"

    def test_driver_temporals_are_converted_before_formatting(self):
        assert iso_str(NS) == "2026-10-15T08:00:00.123456+00:00"
        assert iso_str(WHOLE) == "2026-10-14T07:30:00+00:00"
        assert iso_str(Neo4jDate(2026, 10, 15)) == "2026-10-15"
        assert iso_str(Neo4jTime(8, 0, 0, 5000)) == "08:00:00.000005"

    def test_python_values_and_strings_are_unchanged(self):
        assert iso_str(datetime(2026, 10, 15, 8, 0, 0, 123456, tzinfo=timezone.utc)) == (
            "2026-10-15T08:00:00.123456+00:00"
        )
        assert iso_str(date(2026, 10, 15)) == "2026-10-15"
        assert iso_str("2021-12-10T10:15:09.143") == "2021-12-10T10:15:09.143"
        assert iso_str(None) is None and iso_str("  ") is None


class TestStixTs:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("2026-10-15T08:00:00.123456789+00:00", "2026-10-15T08:00:00.123456Z"),
            ("2026-10-15T08:00:00.000000000Z", "2026-10-15T08:00:00.000000Z"),
            ("2026-10-15T10:00:00.123456789+02:00", "2026-10-15T08:00:00.123456Z"),
            ("2026-10-15T08:00:00.000005000", "2026-10-15T08:00:00.000005Z"),
            ("2026-10-15T08:00:00.123+00:00", "2026-10-15T08:00:00.123Z"),
            ("2026-10-15T08:00:00+00:00", "2026-10-15T08:00:00Z"),
        ],
    )
    def test_fraction_beyond_six_digits_is_cut(self, raw, expected):
        out = _stix_ts(raw)
        assert out == expected
        # stix2 accepts the result; it rejects the inputs of the first four rows as given (more
        # than six fractional digits). Before 2026-10 the first two passed through unchanged.
        stix2.Indicator(pattern="[ipv4-addr:value = '203.0.113.5']", pattern_type="stix", valid_from=out)
        fraction = _FRACTION.search(raw)
        if fraction and len(fraction.group(1)) > 6:
            with pytest.raises(stix2.exceptions.InvalidValueError):
                stix2.Indicator(pattern="[ipv4-addr:value = '203.0.113.5']", pattern_type="stix", valid_from=raw)


# Real shapes: the documentation-range indicator and Log4Shell used across tests/test_stix_exporter.py.
_INDICATOR = {
    "value": "203.0.113.5",
    "indicator_type": "ipv4",
    "tlp": "amber",
    "zone": ["energy"],
    "edgeguard_managed": True,
    "first_imported_at": NS,
    "last_updated": WHOLE,
}
_MALWARE = {"name": "emotet", "malware_types": ["trojan"], "first_imported_at": WHOLE, "last_updated": NS}
_ACTOR = {"name": "apt28", "aliases": ["APT28", "Fancy Bear"], "first_imported_at": NS, "last_updated": NS}
_TECHNIQUE = {
    "mitre_id": "T1059",
    "name": "Command and Scripting Interpreter",
    "tactic_phases": ["execution"],
    "first_imported_at": WHOLE,
    "last_updated": NS,
}
_CVE = {
    "cve_id": "CVE-2021-44228",
    "description": "Log4Shell",
    "cvss_score": 10.0,
    "severity": "CRITICAL",
    "cvss_version": "3.1",
    "published": "2021-12-10T10:15:09.143",
    "status": ["active"],
    "tlp": "white",
    "first_imported_at": NS,
    "last_updated": WHOLE,
}
_CAMPAIGN = {"name": "apt28 campaign", "first_seen": SOURCE_FIRST, "last_seen": NS, "last_updated": NS}
_SECTOR = {"name": "energy"}


def _pair(node: Dict[str, Any]) -> Dict[str, Any]:
    return {"n": node, "r": {"sources": ["threatfox"], "confidence_score": 0.8}}


_MAIN_ROWS = {
    "export_indicator": {
        "seed": _INDICATOR,
        "malware": [_pair(_MALWARE)],
        "vulns": [{"n": _CVE, "r": [{"sources": ["alienvault_otx"]}]}],
        "techniques": [_pair(_TECHNIQUE)],
        "sectors": [_pair(_SECTOR)],
        "campaigns": [_pair(_CAMPAIGN)],
    },
    "export_threat_actor": {
        "seed": _ACTOR,
        "malware": [_pair(_MALWARE)],
        "actor_tech": [_pair(_TECHNIQUE)],
        "mal_tech": [{"m": _MALWARE, "t": _TECHNIQUE, "r": {"sources": ["mitre_attck"]}}],
        "campaigns": [_pair(_CAMPAIGN)],
        "uses_malware": [],
        "tools": [],
        "exploits": [_pair(_CVE)],
        "sectors": [_pair(_SECTOR)],
    },
    "export_technique": {
        "seed": _TECHNIQUE,
        "actors": [_pair(_ACTOR)],
        "malware": [_pair(_MALWARE)],
        "tools": [],
        "indicators": [_pair(_INDICATOR)],
        "parents": [],
        "subtechniques": [],
    },
    "export_cve": {
        "seed": _CVE,
        "indicators": [{"n": _INDICATOR, "r": [{"sources": ["alienvault_otx"]}]}],
        "threats": [{"n": _ACTOR, "r": [{"sources": ["coreideas"]}], "kind": "ThreatActor"}],
        "sectors": [{"n": _SECTOR, "r": [{}]}],
    },
}

# The SOURCED_FROM aggregates (``min`` / ``max`` over driver DateTimes), per label.
_AGGREGATES = {
    "Indicator": [
        {
            "indicator_type": "ipv4",
            "value": "203.0.113.5",
            "first_seen_at_source": SOURCE_FIRST,
            "last_seen_at_source": NS,
        }
    ],
    "ThreatActor": [{"name": "apt28", "first_seen_at_source": SOURCE_FIRST, "last_seen_at_source": NS}],
    "Technique": [{"mitre_id": "T1059", "first_seen_at_source": SOURCE_FIRST, "last_seen_at_source": WHOLE}],
    "Malware": [{"name": "emotet", "first_seen_at_source": WHOLE, "last_seen_at_source": NS}],
    "Vulnerability": [{"cve_id": "CVE-2021-44228", "first_seen_at_source": SOURCE_FIRST, "last_seen_at_source": NS}],
}
_IDENTIFIERS = {
    "export_indicator": "203.0.113.5",
    "export_threat_actor": "APT28",
    "export_technique": "T1059",
    "export_cve": "CVE-2021-44228",
}


def _mock_run(method: str):
    """A ``StixExporter._run`` replacement: the export query answers the method's row, each
    batched ``SOURCED_FROM`` aggregate statement the aggregates of its label."""

    def _run(self, cypher: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "SOURCED_FROM" in cypher:
            if "(n:CVE OR n:Vulnerability)" in cypher:
                return _AGGREGATES["Vulnerability"]
            label = re.search(r"MATCH \(n:(\w+)\)", cypher).group(1)
            return _AGGREGATES.get(label, [])
        return [_MAIN_ROWS[method]]

    return _run


_SDO_TIMESTAMPS = ("created", "modified", "valid_from")


@pytest.mark.parametrize("method", sorted(_MAIN_ROWS))
def test_exports_of_driver_datetimes_parse_strictly(monkeypatch, method):
    monkeypatch.setattr(StixExporter, "_run", _mock_run(method))
    bundle = getattr(StixExporter(object()), method)(_IDENTIFIERS[method])

    parsed = stix2.parse(bundle)  # strict: allow_custom defaults to False
    assert len(parsed.objects) == len(bundle["objects"])
    by_name = {o.get("name"): o for o in bundle["objects"]}
    # created / modified come from first_imported_at / last_updated with the fraction cut to six
    # digits — the exact values, not the export time. stix2 prints created / modified with at least
    # millisecond precision, so nanosecond 0 reads ``.000Z``. The indicator is checked below.
    # modified is the later of created and last_updated: the CVE's last_updated is earlier than its
    # first_imported_at, so its modified is its created (never before it).
    expected = {
        "emotet": ("2026-10-14T07:30:00.000Z", "2026-10-15T08:00:00.123456Z"),
        "apt28": ("2026-10-15T08:00:00.123456Z", "2026-10-15T08:00:00.123456Z"),
        "Command and Scripting Interpreter": ("2026-10-14T07:30:00.000Z", "2026-10-15T08:00:00.123456Z"),
        "CVE-2021-44228": ("2026-10-15T08:00:00.123456Z", "2026-10-15T08:00:00.123456Z"),
    }
    checked = 0
    for name, stamps in expected.items():
        if name in by_name:
            assert (by_name[name]["created"], by_name[name]["modified"]) == stamps, name
            checked += 1
    assert checked >= 2, list(by_name)  # every bundle holds at least two of the named SDOs
    for obj in bundle["objects"]:
        for key in _SDO_TIMESTAMPS:
            if key in obj:
                fraction = _FRACTION.search(obj[key])
                assert fraction is None or len(fraction.group(1)) <= 6, (obj["type"], key, obj[key])
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    if indicators:
        (indicator,) = indicators
        # valid_from = the earliest source claim (SOURCED_FROM min), nanoseconds cut.
        assert indicator["valid_from"] == "2023-01-01T00:00:00.987654Z"
        # 2026-10-16: an indicator's modified is the latest of created, last_recorded_at and
        # aging_since (``indicator_aging``), not last_updated, so it is never before created.
        assert (indicator["created"], indicator["modified"]) == (
            "2026-10-15T08:00:00.123456Z",
            "2026-10-15T08:00:00.123456Z",
        )
        assert indicator["x_edgeguard_first_imported_at"] == "2026-10-15T08:00:00.123456+00:00"
        assert "x_edgeguard_first_seen_inferred" not in indicator


def test_without_a_source_claim_valid_from_is_first_imported_at(monkeypatch):
    run = _mock_run("export_indicator")
    monkeypatch.setattr(StixExporter, "_run", lambda self, c, p: [] if "SOURCED_FROM" in c else run(self, c, p))
    bundle = StixExporter(object()).export_indicator("203.0.113.5", depth=1)
    stix2.parse(bundle)
    (indicator,) = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert indicator["valid_from"] == "2026-10-15T08:00:00.123456Z"
    assert indicator["x_edgeguard_first_seen_inferred"] is True


def test_the_stix_route_answers_200_for_driver_datetimes(monkeypatch):
    """The route mapped the exporter's InvalidValueError to HTTP 500 for every synced node."""
    monkeypatch.setattr(StixExporter, "_run", _mock_run("export_indicator"))
    monkeypatch.setattr(query_api, "_API_KEY", None)
    monkeypatch.setattr(query_api, "neo4j_client", _ConnectedClient(_Session()))
    resp = TestClient(query_api.app).get("/stix/export/indicator/203.0.113.5")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("application/stix+json")
    stix2.parse(resp.json())


# ---------------------------------------------------------------------------
# Fake driver for the REST and GraphQL routes
# ---------------------------------------------------------------------------


class _Result:
    def __init__(self, rows=None, single=None):
        self._rows = list(rows or [])
        self._single = single

    def single(self):
        return self._single

    def __iter__(self):
        return iter(self._rows)


class _Session:
    """Answers each statement with the first ``(marker, result)`` whose marker it contains, and
    with an empty result otherwise — so a statement in the wrong shape finds nothing."""

    def __init__(self, answers=()):
        self.answers = list(answers)
        self.calls: List[tuple] = []

    def run(self, query, **params):
        self.calls.append((query, params))
        for marker, result in self.answers:
            if marker in query:
                return result
        return _Result()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _ConnectedClient:
    def __init__(self, session):
        self._session = session
        self.driver = self

    def session(self, **kwargs):
        return self._session

    def is_connected(self):
        return True


def _rest(monkeypatch, session) -> TestClient:
    monkeypatch.setattr(query_api, "_API_KEY", None)
    monkeypatch.setattr(query_api, "neo4j_client", _ConnectedClient(session))
    return TestClient(query_api.app)


# ---------------------------------------------------------------------------
# 2. Graph Explorer views
# ---------------------------------------------------------------------------

_ATTACK_ROWS = [
    {
        "malware_name": "emotet",
        "malware_family": "emotet",
        "ind_value": "203.0.113.5",
        "ind_type": "ipv4",
        "ind_zones": ["energy", "finance"],
        "ind_confidence": 0.8,
        "ind_role": "c2",
        "ind_threat_label": "botnet_cc",
    },
    {
        "malware_name": "qakbot",
        "malware_family": "qakbot",
        "ind_value": "203.0.113.5",
        "ind_type": "ipv4",
        "ind_zones": ["energy", "finance"],
        "ind_confidence": 0.8,
        "ind_role": "c2",
        "ind_threat_label": "botnet_cc",
    },
]


def _assert_cytoscape_shape(data):
    ids = [n["data"]["id"] for n in data["nodes"]]
    assert len(ids) == len(set(ids))
    for edge in data["edges"]:
        assert edge["data"]["source"] in ids and edge["data"]["target"] in ids, edge
    keys = [(e["data"]["source"], e["data"]["target"], e["data"]["type"]) for e in data["edges"]]
    assert len(keys) == len(set(keys)), "an edge is listed once"
    assert data["stats"] == {"nodes": len(data["nodes"]), "edges": len(data["edges"])}


class TestGraphExplorer:
    def test_default_view_matches_the_direction_the_writers_create(self, monkeypatch):
        session = _Session([("(i:Indicator)-[:INDICATES]->(m:Malware)", _Result(_ATTACK_ROWS))])
        resp = _rest(monkeypatch, session).get("/graph/explore")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        _assert_cytoscape_shape(data)
        edges = {(e["data"]["source"], e["data"]["target"], e["data"]["type"]) for e in data["edges"]}
        assert edges == {
            ("indicator:203.0.113.5", "malware:emotet", "INDICATES"),
            ("indicator:203.0.113.5", "malware:qakbot", "INDICATES"),
            ("indicator:203.0.113.5", "sector:energy", "BELONGS_TO"),
            ("indicator:203.0.113.5", "sector:finance", "BELONGS_TO"),
        }
        types = {n["data"]["id"]: n["data"]["type"] for n in data["nodes"]}
        assert types["malware:emotet"] == "malware" and types["indicator:203.0.113.5"] == "indicator"
        assert types["sector:energy"] == "sector"
        (query, params), *_ = session.calls
        assert "DROPS" not in query and "(m:Malware)-[" not in query
        assert "(i.edgeguard_managed = true OR i.edgeguard_enriched = true)" in query
        assert params["limit"] == 100

    def test_zone_filter_applies_to_the_indicator(self, monkeypatch):
        session = _Session([("(i:Indicator)-[:INDICATES]->(m:Malware)", _Result(_ATTACK_ROWS[:1]))])
        resp = _rest(monkeypatch, session).get("/graph/explore?view=attacks&zone=energy")
        assert resp.status_code == 200 and resp.json()["stats"]["edges"] == 3
        query, params = session.calls[0]
        assert "$zone IN coalesce(i.zone, [])" in query and params["zone"] == "energy"

    def test_actors_view_follows_the_written_directions(self, monkeypatch):
        """``(ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique)-[:IN_TACTIC]->(Tactic)`` — the
        directions ``build_relationships`` writes; a technique of two actors adds its tactic edge
        once."""
        rows = [
            {
                "actor_name": a,
                "actor_zones": ["global"],
                "technique_id": "T1059",
                "technique_name": "CLI",
                "tactics": ["execution"],
            }
            for a in ("apt28", "apt29")
        ]
        marker = "MATCH (a:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t:Technique)"
        session = _Session([(marker, _Result(rows))])
        data = _rest(monkeypatch, session).get("/graph/explore?view=actors").json()
        assert "OPTIONAL MATCH (t)-[:IN_TACTIC]->(tac:Tactic)" in session.calls[0][0]
        _assert_cytoscape_shape(data)
        edges = sorted((e["data"]["source"], e["data"]["target"], e["data"]["type"]) for e in data["edges"])
        assert edges == [
            ("actor:apt28", "technique:T1059", "EMPLOYS_TECHNIQUE"),
            ("actor:apt29", "technique:T1059", "EMPLOYS_TECHNIQUE"),
            ("technique:T1059", "tactic:execution", "IN_TACTIC"),
        ]

    def test_vulnerabilities_view_returns_the_description_with_its_source(self, monkeypatch):
        """2026-10-16: a CVE node of the view carries ``description_source`` with the description, both
        taken from one node of the CVE's twins (``head(collect(...))`` of each would skip a null on one
        node and could pair one node's text with the other's source)."""
        row = {
            "cve_id": "CVE-2015-5477",
            "cvss_score": None,
            "severity": "UNKNOWN",
            "attack_vector": None,
            "zones": ["global"],
            "cisa_exploit_add": "2022-01-10",
            "cisa_action_due": "2022-07-10",
            "cisa_notes": "",
            "cisa_cwes": [],
            "version_constraints": None,
            "description": "KEV text",
            "description_source": "cisa_kev",
        }
        session = _Session([("WHERE (n:Vulnerability OR n:CVE)", _Result([row]))])
        data = _rest(monkeypatch, session).get("/graph/explore?view=vulnerabilities").json()
        node = next(n["data"] for n in data["nodes"] if n["data"]["id"] == "vuln:CVE-2015-5477")
        assert (node["description"], node["description_source"]) == ("KEV text", "cisa_kev")
        query = session.calls[0][0]
        # Of the twins, the one the source ranking keeps (run on a real Neo4j in
        # tests/test_export_paths_neo4j.py): ``head(...)`` took the twin the rows returned first.
        import query_api
        from description_ranking import CVE_DESCRIPTIONS

        assert f"{query_api._TWIN_DESCRIPTION} AS described" in query
        assert query_api._TWIN_DESCRIPTION.startswith(
            f"reduce(_best = null, _d IN collect([{CVE_DESCRIPTIONS.stored_rank_cypher('n')}, "
            "n.description_source, n.description]) | CASE WHEN _d[0] < 0 THEN _best "
        )
        # 2026-10-16: at an equal rank the twin that names a source wins (a null source sorts last), as
        # the write rule lets a named source's record replace a text without one.
        assert "(_d[0] = _best[0] AND ((_d[1] IS NOT NULL AND _best[1] IS NULL) OR " in query_api._TWIN_DESCRIPTION
        assert "coalesce(_d[1], '')" not in query_api._TWIN_DESCRIPTION
        assert "described[2] AS description" in query and "described[1] AS description_source" in query
        assert "head(collect(n.description))" not in query and "head([d IN collect(" not in query

    def test_the_page_styles_every_edge_type_the_api_emits(self):
        page = (ROOT / "docs" / "visualization.html").read_text()
        src = (ROOT / "src" / "query_api.py").read_text()
        explore = src[src.index("async def graph_explore(") : src.index("# Per-collection bound on related nodes")]
        emitted = set(re.findall(r'_add_edge\([^)]*"([A-Z_]+)"\)', explore))
        assert emitted == {"INDICATES", "BELONGS_TO", "EMPLOYS_TECHNIQUE", "IN_TACTIC", "IN_ZONE"}
        for edge_type in emitted:
            assert f'edge[type="{edge_type}"]' in page, edge_type
        assert 'edge[type="USES"]' not in page


# ---------------------------------------------------------------------------
# 3 + 4. GraphQL: vulnerabilities on :CVE, tlp on every node type
# ---------------------------------------------------------------------------

_README_QUERY = """
query {
  vulnerabilities(filter: { zone: "healthcare", minCvss: 9.0 }) {
    cveId description status severity cvssScore cvssVersion published tlp
  }
}
"""


class TestGraphqlVulnerabilities:
    def test_readme_example_reads_the_cve_nodes(self, monkeypatch):
        session = _Session([("MATCH (n:CVE)", _Result([{"n": _CVE}]))])
        monkeypatch.setattr(graphql_api, "_client", _ConnectedClient(session))
        result = graphql_api.schema.execute_sync(_README_QUERY)
        assert result.errors is None, result.errors
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
        query, params = session.calls[0]
        assert "MATCH (n:Vulnerability)" not in query
        assert "(n.edgeguard_managed = true OR n.edgeguard_enriched = true)" in query
        assert "$zone IN n.zone" in query and "n.cvss_score >= $min_cvss" in query
        assert (params["zone"], params["min_cvss"]) == ("healthcare", 9.0)

    def test_a_cve_without_cvss_has_a_null_score(self, monkeypatch):
        unscored = {
            "cve_id": "CVE-2026-22314",
            "severity": "UNKNOWN",
            "status": ["rejected"],
            "edgeguard_managed": True,
        }
        session = _Session([("MATCH (n:CVE)", _Result([{"n": unscored}]))])
        rows = graphql_api._resolve_vulnerabilities(_ConnectedClient(session), graphql_api.VulnerabilityFilter())
        (vuln,) = rows
        assert (vuln.cvss_score, vuln.cvss_version, vuln.severity, vuln.status) == (
            None,
            None,
            "UNKNOWN",
            ["rejected"],
        )
        assert "n.cvss_score >= $min_cvss" not in session.calls[0][0], "no score filter without minCvss"

    def test_no_resolver_reads_a_label_the_sync_does_not_write(self):
        src = (ROOT / "src" / "graphql_api.py").read_text()
        labels = set(re.findall(r"MATCH \(\w+:(\w+)", src)) | set(re.findall(r'_get_client\(\),\s*"(\w+)"', src))
        assert "Vulnerability" not in labels
        assert labels == {"CVE", "Indicator", "Tool", "ThreatActor", "Malware", "Technique", "Tactic", "Campaign"}


_TLP_NODES = {
    "threatActors": ("ThreatActor", {"name": "apt28", "tlp": "amber"}),
    "malware": ("Malware", {"name": "emotet", "tlp": "green"}),
    "techniques": ("Technique", {"mitre_id": "T1059", "name": "CLI", "tlp": "white"}),
    "tactics": ("Tactic", {"mitre_id": "TA0002", "name": "Execution", "tlp": "clear"}),
    "campaigns": ("Campaign", {"name": "apt28 campaign", "tlp": "red"}),
    "tools": ("Tool", {"mitre_id": "S0002", "name": "mimikatz", "tlp": "amber+strict"}),
    "indicators": ("Indicator", {"value": "203.0.113.5", "indicator_type": "ipv4", "tlp": "amber"}),
    "vulnerabilities": ("CVE", {"cve_id": "CVE-2021-44228", "tlp": "white"}),
}


class TestGraphqlDescriptionSource:
    """2026-10-16: every node type with a description returns the source the ranking kept
    (``description_source``), null when the node names none."""

    @pytest.mark.parametrize("field", sorted(set(_TLP_NODES) - {"campaigns", "indicators"}))
    def test_every_list_query_returns_the_description_source(self, monkeypatch, field):
        label, node = _TLP_NODES[field]
        node = dict(node, description="text", description_source="misp")
        session = _Session([(f"MATCH (n:{label})", _Result([{"n": node}, {"n": dict(node, description_source=None)}]))])
        monkeypatch.setattr(graphql_api, "_client", _ConnectedClient(session))
        result = graphql_api.schema.execute_sync(f"{{ {field} {{ description descriptionSource }} }}")
        assert result.errors is None, result.errors
        assert result.data == {
            field: [
                {"description": "text", "descriptionSource": "misp"},
                {"description": "text", "descriptionSource": None},
            ]
        }

    def test_cve_returns_its_description_source(self, monkeypatch):
        cve = {"cve_id": "CVE-2015-5477", "description": "KEV text", "description_source": "cisa_kev"}
        row = {"c": cve, "cv40": None, "cv31": None, "cv30": None, "cv2": None}
        session = _Session([("MATCH (c:CVE {cve_id: $cve_id})", _Result(single=row))])
        monkeypatch.setattr(graphql_api, "_client", _ConnectedClient(session))
        result = graphql_api.schema.execute_sync('{ cve(cveId: "CVE-2015-5477") { description descriptionSource } }')
        assert result.errors is None, result.errors
        assert result.data == {"cve": {"description": "KEV text", "descriptionSource": "cisa_kev"}}


class TestGraphqlTlp:
    @pytest.mark.parametrize("field", sorted(_TLP_NODES))
    def test_every_list_query_returns_the_node_tlp(self, monkeypatch, field):
        label, node = _TLP_NODES[field]
        session = _Session([(f"MATCH (n:{label})", _Result([{"n": node}]))])
        monkeypatch.setattr(graphql_api, "_client", _ConnectedClient(session))
        result = graphql_api.schema.execute_sync(f"{{ {field} {{ tlp }} }}")
        assert result.errors is None, result.errors
        assert result.data == {field: [{"tlp": node["tlp"]}]}

    def test_cve_returns_its_tlp_and_null_without_one(self, monkeypatch):
        for stored, expected in (({"tlp": "amber"}), "amber"), ({}, None):
            cve = {"cve_id": "CVE-2021-44228", **stored}
            row = {"c": cve, "cv40": None, "cv31": None, "cv30": None, "cv2": None}
            session = _Session([("MATCH (c:CVE {cve_id: $cve_id})", _Result(single=row))])
            monkeypatch.setattr(graphql_api, "_client", _ConnectedClient(session))
            result = graphql_api.schema.execute_sync('{ cve(cveId: "CVE-2021-44228") { cveId tlp } }')
            assert result.errors is None, result.errors
            assert result.data == {"cve": {"cveId": "CVE-2021-44228", "tlp": expected}}

    def test_every_node_type_declares_tlp(self):
        import graphql_schema

        for name in (
            "CVE",
            "Vulnerability",
            "Indicator",
            "ThreatActor",
            "Malware",
            "Technique",
            "Tactic",
            "Tool",
            "Campaign",
        ):
            fields = {f.name for f in getattr(graphql_schema, name).__strawberry_definition__.fields}
            assert "tlp" in fields, name
        for name in ("CVSSv2", "CVSSv30", "CVSSv31", "CVSSv40"):  # parts of a CVE: its tlp applies
            fields = {f.name for f in getattr(graphql_schema, name).__strawberry_definition__.fields}
            assert "tlp" not in fields, name


# ---------------------------------------------------------------------------
# 5. Digest-type filters
# ---------------------------------------------------------------------------

# The Mirai sample of MalwareBazaar's recent export (``tests/test_malwarebazaar_collector.py``,
# verified 2026-10-12): its sha256, md5 and sha1 as the sync stores them (lower case). The export
# carries no sha512; that one is the SHA-512 of the empty input.
_DIGESTS = {
    "md5": "2cbdeeb34862d4f0a40aabcc3236b891",
    "sha1": "d382bede96d914347228a5392812851da046858f",
    "sha256": "38cbdf411e85b4136c8d4b725f7b46530919d45799a8065965d408db5ebcc15d",
    "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
}


class TestDigestTypeFilter:
    @pytest.mark.parametrize("requested", ["md5", "sha1", "sha256", "sha512", "SHA256"])
    def test_digest_types_select_hash_by_length(self, requested):
        graph_type, pattern = ioc_normalize.indicator_type_filter(requested)
        assert graph_type == "hash"
        for algorithm, digest in _DIGESTS.items():
            # Cypher ``=~`` matches the whole value: re.fullmatch is the same test.
            assert bool(re.fullmatch(pattern, digest)) is (algorithm == requested.lower()), algorithm
            assert bool(re.fullmatch(pattern, digest.upper())) is (algorithm == requested.lower())
        assert not re.fullmatch(pattern, "z" * ioc_normalize.HEX_DIGEST_LENGTH_BY_TYPE[requested.lower()])

    @pytest.mark.parametrize("requested", ["hash", "ipv4", "domain", "x509-fingerprint-sha1", "url"])
    def test_other_types_are_compared_as_given(self, requested):
        assert ioc_normalize.indicator_type_filter(requested) == (requested, None)

    def test_rest_indicators(self, monkeypatch):
        session = _Session([("RETURN count(n) as total", _Result(single={"total": 0}))])
        client = _rest(monkeypatch, session)
        assert client.get("/indicators?indicator_type=sha256").status_code == 200
        for query, params in session.calls:
            assert "n.indicator_type = $indicator_type" in query
            assert "n.value =~ $indicator_value_pattern" in query
            assert params["indicator_type"] == "hash"
            assert params["indicator_value_pattern"] == "[0-9A-Fa-f]{64}"
        session.calls.clear()
        assert client.get("/indicators?indicator_type=hash").status_code == 200
        query, params = session.calls[0]
        assert params["indicator_type"] == "hash" and "indicator_value_pattern" not in params
        assert "=~" not in query

    def test_wazuh_export(self, monkeypatch):
        session = _Session()
        resp = _rest(monkeypatch, session).get("/export/wazuh/cdb?list=indicators&indicator_type=md5")
        assert resp.status_code == 200
        query, params = session.calls[0]
        assert "n.value =~ $indicator_value_pattern" in query
        assert (params["indicator_type"], params["indicator_value_pattern"]) == ("hash", "[0-9A-Fa-f]{32}")

    def test_graphql_indicators(self, monkeypatch):
        row = {"n": {"value": _DIGESTS["sha1"], "indicator_type": "hash", "active": True}}
        session = _Session([("MATCH (n:Indicator)", _Result([row]))])
        monkeypatch.setattr(graphql_api, "_client", _ConnectedClient(session))
        result = graphql_api.schema.execute_sync(
            '{ indicators(filter: {indicatorType: "sha1"}) { value indicatorType } }'
        )
        assert result.errors is None, result.errors
        assert result.data == {"indicators": [{"value": _DIGESTS["sha1"], "indicatorType": "hash"}]}
        query, params = session.calls[0]
        assert "n.value =~ $indicator_value_pattern" in query
        assert (params["indicator_type"], params["indicator_value_pattern"]) == ("hash", "[0-9A-Fa-f]{40}")


# ---------------------------------------------------------------------------
# 6. /search/indicator related nodes
# ---------------------------------------------------------------------------

_RELATED_ROWS = [
    {"related": {"name": "emotet"}, "relationship_type": "INDICATES", "direction": "outgoing", "labels": ["Malware"]},
    {
        "related": {"cve_id": "CVE-2021-44228", "last_updated": NS},
        "relationship_type": "EXPLOITS",
        "direction": "outgoing",
        "labels": ["Vulnerability", "CVE"],
    },
    {"related": {"alert_id": "a-1"}, "relationship_type": "INVOLVES", "direction": "incoming", "labels": ["Alert"]},
]


# The seed lookup of ``/search/indicator`` and the element id of the node it returns.
_SEED_MARKER = "RETURN n, elementId(n) AS element_id"
_SEED_ID = "4:0f3c9a52-7c1e-4d7b-9a51-2f1d3b8e6a10:42"


class TestSearchRelated:
    def test_related_nodes_carry_type_and_direction_in_the_same_order(self, monkeypatch):
        session = _Session(
            [
                (_SEED_MARKER, _Result(single={"n": _INDICATOR, "element_id": _SEED_ID})),
                ("UNWIND range(0, size(rows) - 1) AS position", _Result(_RELATED_ROWS)),
            ]
        )
        resp = _rest(monkeypatch, session).post("/search/indicator", json={"value": "203.0.113.5", "zone": "energy"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # ``related`` keeps its shape: the node properties (temporals as ISO strings).
        assert body["related"] == [
            {"name": "emotet"},
            {"cve_id": "CVE-2021-44228", "last_updated": "2026-10-15T08:00:00.123456789+00:00"},
            {"alert_id": "a-1"},
        ]
        assert body["relationships"] == [
            {"relationship_type": "INDICATES", "direction": "outgoing", "labels": ["Malware"]},
            {"relationship_type": "EXPLOITS", "direction": "outgoing", "labels": ["CVE", "Vulnerability"]},
            {"relationship_type": "INVOLVES", "direction": "incoming", "labels": ["Alert"]},
        ]
        # The related lookup is bound to the node returned as ``indicator``, not to every node that
        # stores the value under another type.
        query, params = session.calls[1]
        assert params == {
            "element_id": _SEED_ID,
            "zone": "energy",
            "per_kind": 10,
            "timeout": query_api._NEO4J_QUERY_TIMEOUT,
        }

    @pytest.mark.parametrize(
        "body, preferred",
        [
            ({"value": "203.0.113.5"}, "ipv4"),  # inferred from the value
            ({"value": "2CBDEEB34862D4F0A40AABCC3236B891", "indicator_type": "md5"}, "hash"),  # the graph type
            ({"value": "ab" * 20, "indicator_type": "x509-fingerprint-sha1"}, "x509-fingerprint-sha1"),
            ({"value": "ab" * 20, "indicator_type": "hash"}, "hash"),
        ],
    )
    def test_the_node_of_the_resolved_type_answers(self, monkeypatch, body, preferred):
        """One value may be stored under several types: the caller's type (mapped to the graph type,
        or inferred) ranks first, then the lowest type. The caller's type was ignored before."""
        session = _Session([(_SEED_MARKER, _Result(single={"n": _INDICATOR, "element_id": _SEED_ID}))])
        resp = _rest(monkeypatch, session).post("/search/indicator", json=body)
        assert resp.status_code == 200, resp.text
        seed_query, seed_params = session.calls[0]
        assert seed_params["preferred_type"] == preferred
        assert "ORDER BY CASE WHEN n.indicator_type = $preferred_type THEN 0 ELSE 1 END, n.indicator_type" in seed_query
        assert session.calls[1][1]["element_id"] == _SEED_ID

    def test_query_is_directed_ordered_and_bounded_per_kind(self):
        q = query_api._SEARCH_RELATED_CYPHER
        assert "MATCH (n:Indicator)-[r]-(related)\n    WHERE elementId(n) = $element_id" in q
        assert "$value" not in q
        assert "CASE WHEN startNode(r) = n THEN 'outgoing' ELSE 'incoming' END AS direction" in q
        priority = q[q.index("CASE kind") : q.index("END AS priority")]
        order = [
            priority.index(f"'{kind}'") for kind in ("Malware", "ThreatActor", "CVE", "Technique", "Campaign", "Sector")
        ]
        assert order == sorted(order)
        assert "WHEN related:CVE OR related:Vulnerability THEN 'CVE'" in q
        assert "ORDER BY priority, kind, relationship_type, direction" in q
        assert "[..$per_kind]" in q and "LIMIT 10" not in q
        assert q.rstrip().endswith("ORDER BY priority, kind, position")
        assert "(related.edgeguard_managed = true OR related.edgeguard_enriched = true)" in q

    def test_old_clients_still_validate(self):
        """Backward compatible: ``relationships`` is optional and defaults to empty."""
        body = query_api.IndicatorResponse(value="x", found=False)
        assert body.related == [] and body.relationships == []


# ---------------------------------------------------------------------------
# 7. Wazuh CDB: newest entries under the cap, a cut list reported
# ---------------------------------------------------------------------------


class TestWazuhCap:
    def test_a_list_beyond_the_cap_is_cut_and_reported(self, monkeypatch, caplog):
        monkeypatch.setattr(query_api, "_CDB_EXPORT_MAX_ENTRIES", 2)
        rows = [
            {"key": "203.0.113.7", "type": "ipv4", "confidence": 0.9},
            {"key": "203.0.113.5", "type": "ipv4", "confidence": 0.8},
            {"key": "203.0.113.6", "type": "ipv4", "confidence": 0.7},
        ]
        session = _Session([("MATCH (n:Indicator)", _Result(rows))])
        with caplog.at_level("WARNING", logger="query_api"):
            resp = _rest(monkeypatch, session).get("/export/wazuh/cdb?zone=energy")
        assert resp.status_code == 200
        # The query's order is kept (newest first): the third row is the one beyond the cap.
        assert resp.text == "203.0.113.7:type=ipv4 confidence=0.90\n203.0.113.5:type=ipv4 confidence=0.80\n"
        assert resp.headers["X-EdgeGuard-Truncated"] == "true"
        assert resp.headers["X-EdgeGuard-Entries"] == "2"
        assert any("truncated" in r.getMessage() and "energy" in r.getMessage() for r in caplog.records)
        query, params = session.calls[0]
        # 2026-10-16: indicators by their latest report (or when EdgeGuard created them).
        assert query.endswith(query_api._CDB_INDICATOR_ORDER_AND_LIMIT)
        assert "coalesce(n.last_reported_at, n.first_imported_at) DESC, key LIMIT $cap + 1" in query
        assert params["cap"] == 2

    def test_a_list_within_the_cap_is_complete(self, monkeypatch, caplog):
        monkeypatch.setattr(query_api, "_CDB_EXPORT_MAX_ENTRIES", 2)
        rows = [{"key": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0, "kev": "2021-12-10"}]
        session = _Session([("MATCH (n)", _Result(rows))])
        with caplog.at_level("WARNING", logger="query_api"):
            resp = _rest(monkeypatch, session).get("/export/wazuh/cdb?list=cves")
        assert resp.headers["X-EdgeGuard-Truncated"] == "false"
        assert resp.text == "CVE-2021-44228:severity=CRITICAL cvss=10.0 kev=2021-12-10\n"
        assert not [r for r in caplog.records if "truncated" in r.getMessage()]
        assert "n.last_updated DESC, key LIMIT $cap + 1" in session.calls[0][0]


# ---------------------------------------------------------------------------
# /stix/types names what the exports walk
# ---------------------------------------------------------------------------


class TestStixTypes:
    def test_relationship_mappings_are_the_exporter_table(self, monkeypatch):
        resp = _rest(monkeypatch, _Session()).get("/stix/types")
        data = resp.json()
        mappings = data["relationship_mappings"]
        assert len(mappings) == len(stix_exporter._SRO_BY_EDGE)
        exporter = StixExporter.__new__(StixExporter)
        exporter._marking_by_id = {}
        for row in mappings:
            key = (row["graph_relationship"], row["graph_source"], row["graph_target"])
            assert stix_exporter._SRO_BY_EDGE[key][0] == row["relationship_type"]
            # The row says what ``_edge_to_sro`` emits for that pair.
            src = f"{row['graph_source']}--00000000-0000-4000-8000-000000000001"
            tgt = f"{row['graph_target']}--00000000-0000-4000-8000-000000000002"
            sro = exporter._edge_to_sro(row["graph_relationship"], src, tgt)
            assert sro["source_ref"].split("--")[0] == row["source"]
            assert sro["target_ref"].split("--")[0] == row["target"]
            assert sro["relationship_type"] == row["relationship_type"]
        attributed = next(r for r in mappings if r["graph_relationship"] == "ATTRIBUTED_TO")
        assert (attributed["source"], attributed["target"]) == ("intrusion-set", "malware")

    def test_returns_name_the_2026_10_relationships(self, monkeypatch):
        data = _rest(monkeypatch, _Session()).get("/stix/types").json()
        returns = {t["name"]: t["returns"] for t in data["object_types"]}
        assert "PART_OF_CAMPAIGN" in returns["indicator"]
        for rel in ("USES_MALWARE", "USES_TOOL", "EXPLOITS", "TARGETS", "RUNS"):
            assert rel in returns["actor"], rel
        assert "SUBTECHNIQUE_OF" in returns["technique"]
        assert "threat actors and malware (EXPLOITS)" in returns["cve"]
        # Every graph relationship an export walks is in the table (IN_TACTIC is a kill-chain phase).
        walked = set(re.findall(r"\b[A-Z][A-Z_]{4,}\b", " ".join(returns.values())))
        assert walked <= {r["graph_relationship"] for r in data["relationship_mappings"]}, walked


# ---------------------------------------------------------------------------
# 8 + 9. Documentation of these routes
# ---------------------------------------------------------------------------


class TestDocumentation:
    def test_no_document_says_the_rest_health_check_always_answers_200(self):
        for rel in (
            "README.md",
            "docs/TECHNICAL_SPEC.md",
            "docs/ARCHITECTURE.md",
            "docs/DEPLOYMENT_READINESS_CHECKLIST.md",
            "docs/RESILMESH_INTEROPERABILITY.md",
        ):
            text = (ROOT / rel).read_text()
            for phrase in ("Always **HTTP 200**", "**HTTP 200** always", "always 200", "always returns **200**"):
                assert phrase not in text, (rel, phrase)

    def test_technical_spec_names_the_admin_body_and_summary_fields(self):
        spec = (ROOT / "docs" / "TECHNICAL_SPEC.md").read_text()
        admin = next(line for line in spec.splitlines() if line.startswith("| POST | `/admin/query`"))
        for field in query_api.GraphQueryRequest.model_fields:
            assert f"`{field}`" in admin, field
        summary = next(line for line in spec.splitlines() if line.startswith("| GET | `/actors/{name}/summary`"))
        assert "campaigns" in summary and "indicators" not in summary
        assert "campaigns" in query_api.ActorSummaryResponse.model_fields

    def test_the_default_cors_allowlist_stays_narrow_everywhere(self):
        """Every place that sets the default allowlist — both APIs, the compose default and the
        example ``.env`` — lists the same two origins: no wildcard, no ``null`` origin."""
        defaults = {
            "src/query_api.py": r'os\.getenv\("EDGEGUARD_CORS_ORIGINS", "([^"]*)"\)',
            "src/graphql_api.py": r'os\.getenv\("EDGEGUARD_CORS_ORIGINS", "([^"]*)"\)',
            "docker-compose.yml": r"EDGEGUARD_CORS_ORIGINS: \$\{EDGEGUARD_CORS_ORIGINS:-([^}]*)\}",
            ".env.example": r"(?m)^EDGEGUARD_CORS_ORIGINS=(.*)$",
        }
        for rel, pattern in defaults.items():
            found = re.findall(pattern, (ROOT / rel).read_text())
            assert len(found) == 1, (rel, found)
            origins = [o.strip() for o in found[0].split(",")]
            assert origins == ["http://localhost", "http://localhost:3000"], (rel, origins)
            assert not any("*" in o or o.lower() == "null" for o in origins), (rel, origins)

    def test_the_explorer_is_served_from_an_allowed_origin(self):
        """The guide, README and the demo page serve the page from an origin in the allowlist."""
        guide = (ROOT / "docs" / "GRAPH_EXPLORER.md").read_text()
        assert "--bind 127.0.0.1 --directory docs" in guide and "python3 -m http.server 3000" in guide
        assert "http://localhost:3000/visualization.html" in guide
        assert "EDGEGUARD_CORS_ORIGINS=http://localhost,http://localhost:3000," in guide
        assert "Or serve it via any static file server." not in guide
        assert "MATCH (i:Indicator)-[:INDICATES]->(m:Malware)" in guide
        assert "WHERE type(r) IN ['INDICATES', 'DROPS']" not in guide
        readme = (ROOT / "README.md").read_text()
        assert "open docs/visualization.html in browser" not in readme
        explorer_line = next(line for line in readme.splitlines() if line.startswith("Graph Explorer       →"))
        assert "http://localhost:3000/visualization.html" in explorer_line
        assert "python3 -m http.server 3000 --bind 127.0.0.1 --directory docs" in explorer_line
        demo = (ROOT / "docs" / "demo.html").read_text()
        assert "a page opened from disk is refused" in demo and "EDGEGUARD_CORS_ORIGINS" in demo

    def test_a_port_in_use_by_grafana_has_a_documented_alternative(self):
        """The monitoring stack binds Grafana to the explorer's default port; the guide, README and
        the example ``.env`` give another port and the origin to append."""
        compose = (ROOT / "docker-compose.monitoring.yml").read_text()
        assert '"127.0.0.1:3000:3000"' in compose, "premise: Grafana holds 127.0.0.1:3000"
        guide = (ROOT / "docs" / "GRAPH_EXPLORER.md").read_text()
        assert "python3 -m http.server 3001 --bind 127.0.0.1 --directory docs" in guide
        assert "EDGEGUARD_CORS_ORIGINS=http://localhost,http://localhost:3000,http://localhost:3001" in guide
        assert "http://localhost:3001/visualization.html" in guide
        readme = (ROOT / "README.md").read_text()
        assert "python3 -m http.server 3001 --bind 127.0.0.1 --directory docs" in readme
        assert "append `http://localhost:3001` to `EDGEGUARD_CORS_ORIGINS`" in readme
        assert "http://localhost:3001" in (ROOT / ".env.example").read_text()

    def test_the_guide_says_limit_caps_rows_not_nodes(self):
        guide = (ROOT / "docs" / "GRAPH_EXPLORER.md").read_text()
        assert "Maximum nodes returned" not in guide and "controls how many nodes the API returns" not in guide
        limit_row = next(line for line in guide.splitlines() if line.startswith("| `limit` |"))
        assert "Maximum rows the view reads, not nodes" in limit_row and "`stats.nodes` can exceed `limit`" in limit_row
        description = query_api.app.openapi()["paths"]["/graph/explore"]["get"]["parameters"]
        (limit,) = [p for p in description if p["name"] == "limit"]
        assert "Max rows the view reads" in limit["description"]

    def test_the_guide_names_the_label_that_carries_the_cve_score(self):
        guide = (ROOT / "docs" / "GRAPH_EXPLORER.md").read_text()
        assert "so CISA KEV fields on CVE nodes are found" not in guide
        assert "The MISP → Neo4j sync writes :CVE nodes, which carry the score, the" in guide

    def test_the_demo_page_states_the_written_directions(self):
        """``(Malware)-[:ATTRIBUTED_TO]->(ThreatActor)``, ``(Indicator)-[:INDICATES]->(Malware)``,
        ``(ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique)`` and ``(Indicator)-[:EXPLOITS]->`` a CVE or
        Vulnerability, as ``build_relationships`` writes them (2026-10: the page listed INDICATES to a
        Vulnerability, which no pipeline path writes, and no EXPLOITS row)."""
        demo = (ROOT / "docs" / "demo.html").read_text()
        rows = dict(re.findall(r"<td>([A-Z_]+)</td>\s*<td>([^<]+)</td>", demo))
        assert rows["ATTRIBUTED_TO"] == "Malware → ThreatActor"
        assert rows["INDICATES"] == "Indicator → Malware"
        assert rows["EXPLOITS"] == "Indicator → CVE / Vulnerability"
        assert rows["EMPLOYS_TECHNIQUE"] == "ThreatActor → Technique"
        assert "USES" not in rows
        assert "— Indicator → Malware</span>" not in demo
        build = (ROOT / "src" / "build_relationships.py").read_text()
        assert "MERGE (m)-[r:ATTRIBUTED_TO]->(a)" in build and "MERGE (i)-[r:INDICATES]->(m)" in build
        assert "MATCH (v:Vulnerability {cve_id: i.cve_id}) MERGE (i)-[r:EXPLOITS]->(v)" in build
        assert "MATCH (c:CVE {cve_id: i.cve_id}) MERGE (i)-[r:EXPLOITS]->(c)" in build

    def test_the_stix_export_docstring_names_what_stix_types_returns(self, monkeypatch):
        """The route's OpenAPI description and ``/stix/types`` describe the same neighbourhoods."""
        data = _rest(monkeypatch, _Session()).get("/stix/types").json()
        doc = " ".join((query_api.stix_export.__doc__ or "").split())
        for object_type in data["object_types"]:
            for relationship in set(re.findall(r"\b[A-Z][A-Z_]{4,}\b", object_type["returns"])):
                assert relationship in doc, (object_type["name"], relationship)
        assert "attributed malware + employed techniques + campaigns" not in doc
        assert "indicators that exploit it + affected sectors" not in doc

    def test_technical_spec_names_the_current_extension_definition(self):
        spec = (ROOT / "docs" / "TECHNICAL_SPEC.md").read_text()
        row = next(line for line in spec.splitlines() if line.startswith("| GET | `/stix/export/"))
        assert f"extension definition {stix_exporter._EXTENSION_VERSION}" in row
        assert "now 1.2.0" not in row
