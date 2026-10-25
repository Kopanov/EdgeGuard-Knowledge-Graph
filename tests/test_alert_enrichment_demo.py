"""Alert enrichment: CVE links as the graph writes them, the read-only enrichment, and the demo (2026-10).

* ``AlertProcessor._enrich_indicator`` looked CVEs up as ``(Indicator)-[:INDICATES]->(Vulnerability)``.
  The graph links an indicator to the CVE its own CVE tag names as ``(Indicator)-[:EXPLOITS]->`` a
  ``CVE`` and / or a ``Vulnerability`` node (``build_relationships`` steps 3a / 3b, the sync's
  EXPLOITS rows); the one writer of ``INDICATES`` to those labels has no caller. The CVE part of
  every enrichment was therefore empty.
* 2026-10-18: the enrichment also reads ``(Indicator)-[:INDICATES]->(CVE)``, a CVE named in the same OTX
  report as the indicator (the sync's report-scoped rows, ``match_type`` ``otx_pulse``), and each CVE entry
  names its links (``evidence``: relationship type, ``match_type``, meaning), so an alert tells a CVE named
  in the same report from the indicator's own CVE claim.
* ``AlertProcessor.enrich_alert_read_only`` returns the enrichment without the writes of
  ``process_alert`` and opens its sessions in read access mode.
* ``demo/alert_enrichment_demo.py`` replaces a mock that printed random values as a Neo4j
  enrichment: it builds alerts from a file or from real indicators (one read-only selection query)
  and prints what the processor returns. It never sends a write statement.

The fake graph below answers each enrichment statement only for the pattern the graph really
holds, so a query reading a relationship nothing writes gets nothing back; ``TestReadsHaveWriters``
ties each of those patterns to the statement in ``build_relationships`` / ``neo4j_client`` that
writes it. Like Neo4j, the fake answers an aggregate without grouping key (``RETURN collect(...)``)
with one row of empty lists when nothing matches.
"""

from __future__ import annotations

import copy
import importlib.util
import inspect
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from neo4j.exceptions import ServiceUnavailable

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from alert_processor import AlertProcessor, ResilMeshAlert, _graph_cves, _invalid_payload_reason  # noqa: E402

_DEMO_PATH = _ROOT / "demo" / "alert_enrichment_demo.py"
_spec = importlib.util.spec_from_file_location("alert_enrichment_demo", _DEMO_PATH)
assert _spec is not None and _spec.loader is not None
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)

_WRITE = re.compile(r"\b(MERGE|CREATE|SET|DELETE|DETACH|REMOVE|DROP)\b", re.IGNORECASE)

# The CVE statement of _enrich_indicator before 2026-10.
_OLD_CVE_QUERY = """
    MATCH (i:Indicator {value: $indicator})
    OPTIONAL MATCH (i)-[:INDICATES]->(v:Vulnerability)
    RETURN collect(DISTINCT v {
        .cve_id, .cvss_score, .severity
    }) as cves
"""

_INDICATOR = "198.51.100.7"

# The CVE statement's link conditions (2026-10-18): EXPLOITS to either node of a CVE id, INDICATES to the
# CVE node.
_CVE_READ = "OPTIONAL MATCH (i)-[r:EXPLOITS|INDICATES]->(v)"
_CVE_WHERE = 'WHERE (type(r) = "EXPLOITS" AND (v:CVE OR v:Vulnerability)) OR (type(r) = "INDICATES" AND v:CVE)'
_EXPLOITS_EVIDENCE = {"relationship": "EXPLOITS", "match_type": "cve_tag", "meaning": "the indicator's own CVE tag"}
_SAME_REPORT_EVIDENCE = {
    "relationship": "INDICATES",
    "match_type": "otx_pulse",
    "meaning": "named in the same OTX report as the indicator",
}
_GRAPH_CVE = {"cve_id": "CVE-2024-3400", "cvss_score": 10.0, "severity": "CRITICAL", "evidence": [_EXPLOITS_EVIDENCE]}


# ---------------------------------------------------------------------------
# Fake graph: one indicator, linked as the MISP -> Neo4j sync and build_relationships link it
# ---------------------------------------------------------------------------


class _Result:
    def __init__(self, records: Optional[List[Dict[str, Any]]] = None):
        self._records = records or []

    def single(self) -> Optional[Dict[str, Any]]:
        return self._records[0] if self._records else None

    def __iter__(self):
        return iter(self._records)


class _Graph:
    """Answers the enrichment statements for ``_INDICATOR`` only where the pattern is one the
    graph writes: ``INDICATES`` to Malware, ``ATTRIBUTED_TO`` to ThreatActor, ``EMPLOYS_TECHNIQUE``
    to Technique, ``EXPLOITS`` to CVE and Vulnerability, ``INDICATES`` to CVE. The CVE id is linked to
    both of its nodes with their real shapes: the CVE node's score with the matching severity, and a
    Vulnerability node holding an older score. With ``same_report`` (2026-10-18) the indicator's OTX
    pulse also names CVE-2024-21887 (a CVE node without CVSS) and CVE-2024-3400."""

    def __init__(self) -> None:
        self.statements: List[str] = []
        self.params: List[Dict[str, Any]] = []
        self.session_kwargs: List[Dict[str, Any]] = []
        self.fail_selection = False
        self.fail_enrichment = False
        self.same_report = False
        self.selection_rows = [
            {"value": _INDICATOR, "indicator_type": "ipv4", "zone": ["global", "energy"]},
            {"value": "evil.example", "indicator_type": "domain", "zone": ["global"]},
        ]

    def answer(self, query: str, params: Dict[str, Any]) -> _Result:
        self.params.append(params)
        if "EXISTS { MATCH (i)-[:INDICATES]->(:Malware) }" in query:
            if self.fail_selection:
                raise ServiceUnavailable("connection lost")
            zone = params["zone"]
            rows = [r for r in self.selection_rows if zone is None or zone in (r.get("zone") or [])]
            return _Result(rows[: params["limit"]])
        if self.fail_enrichment:
            raise ServiceUnavailable("connection lost")
        known = params.get("indicator") == _INDICATOR
        if "RETURN i {" in query:
            if not known:
                return _Result()  # grouped by i: no row when no Indicator node matches
            return _Result(
                [
                    {
                        "indicator": {"value": _INDICATOR, "zone": ["energy"], "confidence_score": 0.6},
                        "first_seen": "2026-09-01T00:00:00+00:00",
                        "last_seen": "2026-10-01T00:00:00+00:00",
                    }
                ]
            )
        if "AS cves" in query or "as cves" in query:
            flat = " ".join(query.split())
            if known and _CVE_READ in flat and _CVE_WHERE in flat:
                exploits = {"relationship": "EXPLOITS", "match_type": "cve_tag"}
                rows = [
                    {"cve_id": "CVE-2024-3400", "cvss_score": 7.5, "severity": "HIGH", "node_label": "Vulnerability"}
                    | exploits,
                    {"cve_id": "CVE-2024-3400", "cvss_score": 10.0, "severity": "CRITICAL", "node_label": "CVE"}
                    | exploits,
                ]
                if self.same_report:
                    same = {"relationship": "INDICATES", "match_type": "otx_pulse"}
                    rows += [
                        {"cve_id": "CVE-2024-3400", "cvss_score": 10.0, "severity": "CRITICAL", "node_label": "CVE"}
                        | same,
                        {"cve_id": "CVE-2024-21887", "cvss_score": None, "severity": "UNKNOWN", "node_label": "CVE"}
                        | same,
                    ]
                return _Result([{"cves": rows}])
            return _Result([{"cves": []}])
        if "as malware_list" in query:
            ok = known and "OPTIONAL MATCH (i)-[:INDICATES]->(m:Malware)" in query
            return _Result([{"malware_list": [{"name": "cobalt strike"}] if ok else []}])
        if "as actors" in query:
            ok = (
                known
                and "(m)-[:ATTRIBUTED_TO]->(a:ThreatActor)" in query
                and "(a)-[:EMPLOYS_TECHNIQUE]->(t:Technique)" in query
            )
            return _Result(
                [
                    {
                        "actors": [{"name": "apt29"}] if ok else [],
                        "techniques": [{"mitre_id": "T1071", "name": "Application Layer Protocol"}] if ok else [],
                    }
                ]
            )
        if "as assets" in query:
            # No Alert node (the demo alert was never recorded): one aggregate row of empty lists.
            return _Result([{"assets": [], "users": []}])
        if "RETURN i.zone as zone" in query:
            return _Result([{"zone": ["energy"]}] if known else [])
        raise AssertionError(f"unexpected statement: {query}")


class _Session:
    def __init__(self, graph: _Graph):
        self._graph = graph

    def run(self, query, parameters=None, **kwargs):
        kwargs.pop("timeout", None)
        self._graph.statements.append(query)
        return self._graph.answer(query, {**(parameters or {}), **kwargs})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Driver:
    def __init__(self, graph: _Graph):
        self._graph = graph

    def session(self, **kwargs):
        self._graph.session_kwargs.append(kwargs)
        return _Session(self._graph)


class _Client:
    """The ``Neo4jClient`` surface the processor and the demo use; the write path raises."""

    uri = "bolt://fake:7687"

    def __init__(self, graph: _Graph, *, reachable: bool = True, accepts: bool = True):
        self.graph = graph
        self.driver: Optional[_Driver] = None
        self.reachable = reachable
        self.accepts = accepts
        self.closed = False

    def connect(self) -> bool:
        if not self.reachable:
            raise ConnectionError("connection refused")
        if not self.accepts:
            return False
        self.driver = _Driver(self.graph)
        return True

    def close(self) -> None:
        self.closed = True

    def process_complete_resilmesh_alert(self, *args, **kwargs):
        raise AssertionError("write path called: process_complete_resilmesh_alert")

    def update_alert_enrichment_status(self, *args, **kwargs):
        raise AssertionError("write path called: update_alert_enrichment_status")


def _alert(indicator: str = _INDICATOR, **threat: Any) -> Dict[str, Any]:
    return {
        "alert_id": "a-1",
        "source": "wazuh",
        "zone": "energy",
        "timestamp": "2026-10-16T00:00:00+00:00",
        "threat": {"indicator": indicator, "type": "ip", **threat},
    }


def _connected_processor(graph: _Graph) -> AlertProcessor:
    client = _Client(graph)
    client.connect()
    return AlertProcessor(neo4j_client=client)


# ---------------------------------------------------------------------------
# CVE enrichment reads EXPLOITS to CVE / Vulnerability
# ---------------------------------------------------------------------------


class TestCveEnrichmentFollowsExploits:
    def test_the_fake_graph_gives_the_former_query_nothing(self):
        graph = _Graph()
        record = _Session(graph).run(_OLD_CVE_QUERY, indicator=_INDICATOR).single()
        assert record == {"cves": []}

    def test_cves_the_indicator_exploits_are_returned(self):
        response = _connected_processor(_Graph()).enrich_alert_read_only(_alert())
        assert response.enrichment["cves"] == [_GRAPH_CVE]
        assert response.query_metadata["cves_found"] == 1
        assert "Apply patch for CVE-2024-3400" in response.enrichment["recommendations"]

    def test_cves_named_in_the_same_report_are_returned_with_their_evidence(self):
        graph = _Graph()
        graph.same_report = True
        response = _connected_processor(graph).enrich_alert_read_only(_alert())
        assert response.enrichment["cves"] == [
            {
                "cve_id": "CVE-2024-21887",
                "cvss_score": None,
                "severity": "UNKNOWN",
                "evidence": [_SAME_REPORT_EVIDENCE],
            },
            # Both links of one CVE: the indicator's own claim first.
            dict(_GRAPH_CVE, evidence=[_EXPLOITS_EVIDENCE, _SAME_REPORT_EVIDENCE]),
        ]
        assert response.query_metadata["cves_found"] == 2
        recommendations = response.enrichment["recommendations"]
        assert "Apply patch for CVE-2024-21887 (named in the same OTX report as the indicator)" in recommendations
        assert "Apply patch for CVE-2024-3400" in recommendations

    def test_process_alert_reads_the_same_cves(self):
        graph = _Graph()
        client = _Client(graph)
        client.process_complete_resilmesh_alert = lambda alert_data: None
        client.update_alert_enrichment_status = lambda **kwargs: None
        processor = AlertProcessor(neo4j_client=client)
        response = processor.process_alert(_alert())
        assert response.enriched is True
        assert [c["cve_id"] for c in response.enrichment["cves"]] == ["CVE-2024-3400"]

    def test_a_cve_named_by_the_alert_is_kept_once(self):
        response = _connected_processor(_Graph()).enrich_alert_read_only(_alert(cve="CVE-2024-3400"))
        assert response.enrichment["cves"] == [{"cve_id": "CVE-2024-3400", "source": "alert"}]

    def test_the_cve_statement_reads_exploits_to_both_labels_and_indicates_to_cve(self):
        graph = _Graph()
        _connected_processor(graph).enrich_alert_read_only(_alert())
        cve_statements = [" ".join(q.split()) for q in graph.statements if "as cves" in q]
        assert len(cve_statements) == 1
        assert _CVE_READ in cve_statements[0] and _CVE_WHERE in cve_statements[0]
        # INDICATES only to the CVE node: nothing writes INDICATES to a Vulnerability.
        assert 'type(r) = "INDICATES" AND v:CVE)' in cve_statements[0]
        assert "relationship: type(r), match_type: r.match_type" in cve_statements[0]


class TestGraphCves:
    """Score and severity come as a pair from one node (2026-10). A ``CVE`` node is either
    ``{score, matching severity}`` or, without CVSS, ``{null, "UNKNOWN"}`` (``merge_cve``); a
    ``Vulnerability`` node can keep an older score (``merge_vulnerabilities_batch`` coalesces); a
    ``CVE`` node a partner wrote (``merge_resilmesh_cve``) can state neither."""

    def test_one_entry_per_cve_id_the_pair_from_one_node(self):
        rows = [
            {"cve_id": "CVE-2024-2", "cvss_score": 3.0, "severity": "LOW", "node_label": "Vulnerability"},
            {"cve_id": "CVE-2024-2", "cvss_score": None, "severity": "UNKNOWN", "node_label": "CVE"},
            {"cve_id": "CVE-2024-1", "cvss_score": 9.8, "severity": "CRITICAL", "node_label": "CVE"},
            {"cve_id": "CVE-2024-1", "cvss_score": 7.5, "severity": "HIGH", "node_label": "Vulnerability"},
            {"cve_id": "CVE-2024-3", "cvss_score": 6.1, "severity": "MEDIUM", "node_label": "Vulnerability"},
            {"cve_id": "CVE-2024-4", "cvss_score": None, "severity": None, "node_label": "CVE"},
            {"cve_id": "CVE-2024-4", "cvss_score": 5.0, "severity": "MEDIUM", "node_label": "Vulnerability"},
            None,
            {"cve_id": None, "node_label": "CVE"},
        ]
        assert _graph_cves(rows) == [
            {"cve_id": "CVE-2024-1", "cvss_score": 9.8, "severity": "CRITICAL", "evidence": []},
            # The CVE node's statement that no CVSS exists wins over the Vulnerability node's
            # older 3.0 (field by field this printed 3.0 beside UNKNOWN).
            {"cve_id": "CVE-2024-2", "cvss_score": None, "severity": "UNKNOWN", "evidence": []},
            {"cve_id": "CVE-2024-3", "cvss_score": 6.1, "severity": "MEDIUM", "evidence": []},
            {"cve_id": "CVE-2024-4", "cvss_score": 5.0, "severity": "MEDIUM", "evidence": []},
        ]

    def test_the_order_of_the_rows_does_not_matter(self):
        rows = [
            {"cve_id": "CVE-2024-2", "cvss_score": None, "severity": "UNKNOWN", "node_label": "CVE"},
            {"cve_id": "CVE-2024-2", "cvss_score": 3.0, "severity": "LOW", "node_label": "Vulnerability"},
        ]
        assert (
            _graph_cves(rows)
            == _graph_cves(list(reversed(rows)))
            == [{"cve_id": "CVE-2024-2", "cvss_score": None, "severity": "UNKNOWN", "evidence": []}]
        )

    def test_empty(self):
        assert _graph_cves([]) == []

    def test_the_evidence_of_one_cve_is_each_distinct_link_the_own_claim_first(self):
        """2026-10-18: one entry per CVE id names each (relationship, match_type) of its links once,
        whatever node or row carried it; a pair outside the table has no meaning."""
        rows = [
            {"cve_id": "CVE-2024-9", "node_label": "CVE", "relationship": "INDICATES", "match_type": "otx_pulse"},
            {
                "cve_id": "CVE-2024-9",
                "node_label": "Vulnerability",
                "relationship": "EXPLOITS",
                "match_type": "cve_tag",
            },
            {"cve_id": "CVE-2024-9", "node_label": "CVE", "relationship": "EXPLOITS", "match_type": "cve_tag"},
            {"cve_id": "CVE-2024-8", "node_label": "CVE", "relationship": "INDICATES", "match_type": None},
        ]
        entries = _graph_cves(rows)
        assert entries == _graph_cves(list(reversed(rows)))
        assert [e["evidence"] for e in entries] == [
            [{"relationship": "INDICATES", "match_type": None, "meaning": None}],
            [_EXPLOITS_EVIDENCE, _SAME_REPORT_EVIDENCE],
        ]


# ---------------------------------------------------------------------------
# enrich_alert_read_only
# ---------------------------------------------------------------------------


class TestEnrichAlertReadOnly:
    def test_no_write_statement_and_read_sessions_only(self):
        graph = _Graph()
        response = _connected_processor(graph).enrich_alert_read_only(_alert())
        assert response.enriched is True
        assert graph.statements, "the enrichment ran no statement"
        assert not [q for q in graph.statements if _WRITE.search(q)]
        assert graph.session_kwargs and all(kw.get("default_access_mode") == "READ" for kw in graph.session_kwargs)

    def test_values_come_from_the_graph(self):
        response = _connected_processor(_Graph()).enrich_alert_read_only(_alert())
        e = response.enrichment
        assert e["indicator"] == _INDICATOR and e["indicator_type"] == "ipv4"
        assert [m["name"] for m in e["known_malware"]] == ["cobalt strike"]
        assert [a["name"] for a in e["threat_actors"]] == ["apt29"]
        assert [t["mitre_id"] for t in e["techniques"]] == ["T1071"]
        assert e["confidence"] == 0.6
        assert e["first_seen"] == "2026-09-01T00:00:00+00:00"
        assert e["sectors_affected"] == ["energy"]
        assert response.query_metadata["indicator_found"] is True

    def test_an_indicator_the_graph_does_not_hold_is_not_found(self):
        response = _connected_processor(_Graph()).enrich_alert_read_only(_alert("203.0.113.9"))
        assert response.enriched is True
        assert response.query_metadata["indicator_found"] is False
        assert response.enrichment["known_malware"] == [] and response.enrichment["cves"] == []

    def test_a_malware_the_alert_names_is_listed_even_when_the_graph_lacks_the_indicator(self):
        """The malware query aggregates without grouping key, so Neo4j answers one row (empty
        list) for an absent indicator and the alert's malware is appended: ``malware_found`` is
        then true from the alert alone (docs/DEMO.md states it)."""
        response = _connected_processor(_Graph()).enrich_alert_read_only(_alert("203.0.113.9", malware="TrickBot"))
        assert response.query_metadata["indicator_found"] is False
        assert response.query_metadata["malware_found"] is True
        assert response.enrichment["known_malware"] == [
            {"name": "TrickBot", "family": None, "malware_types": [], "description": "From alert (not in graph)"}
        ]
        assert "Deploy signatures for TrickBot" in response.enrichment["recommendations"]

    def test_a_failed_query_is_not_reported_as_enriched(self):
        """2026-10: the defaults left by a failed query (nothing found, confidence 0.0) must not
        read as an answer from the graph."""
        graph = _Graph()
        graph.fail_enrichment = True
        response = _connected_processor(graph).enrich_alert_read_only(_alert())
        assert response.enriched is False
        assert response.query_metadata["error"] == "connection lost"
        assert response.query_metadata["indicator_found"] is False and response.enrichment["confidence"] == 0.0

    def test_process_alert_keeps_its_answer_to_a_failed_query(self):
        graph = _Graph()
        graph.fail_enrichment = True
        client = _Client(graph)
        client.process_complete_resilmesh_alert = lambda alert_data: None
        client.update_alert_enrichment_status = lambda **kwargs: None
        response = AlertProcessor(neo4j_client=client).process_alert(_alert())
        assert response.enriched is True and response.query_metadata["error"] == "connection lost"

    def test_the_callers_payload_is_not_modified(self):
        payload = _alert("198[.]51.100.7")
        before = copy.deepcopy(payload)
        response = _connected_processor(_Graph()).enrich_alert_read_only(payload)
        assert payload == before
        assert response.original_alert == before
        assert response.enrichment["indicator"] == _INDICATOR  # refanged like process_alert does

    def test_an_invalid_payload_is_rejected_before_any_statement(self):
        graph = _Graph()
        response = _connected_processor(graph).enrich_alert_read_only({"threat": {"indicator": _INDICATOR}})
        assert response.enriched is False and "alert_id" in response.query_metadata["error"]
        assert graph.statements == []

    def test_a_client_without_a_driver_is_connected(self):
        graph = _Graph()
        client = _Client(graph)
        response = AlertProcessor(neo4j_client=client).enrich_alert_read_only(_alert())
        assert client.driver is not None and response.enriched is True

    def test_process_alert_still_records_the_alert(self):
        graph = _Graph()
        client = _Client(graph)
        written: List[str] = []
        client.process_complete_resilmesh_alert = lambda alert_data: written.append("alert")
        client.update_alert_enrichment_status = lambda **kwargs: written.append("status")
        AlertProcessor(neo4j_client=client).process_alert(_alert())
        assert written == ["alert", "status"]
        assert all("default_access_mode" not in kw for kw in graph.session_kwargs)


# ---------------------------------------------------------------------------
# demo/alert_enrichment_demo.py
# ---------------------------------------------------------------------------


class TestDemoAlertBuilding:
    def test_built_alerts_pass_the_processors_validation(self):
        for n, row in enumerate(_Graph().selection_rows, 1):
            alert = demo.build_alert_from_indicator(row, n, "2026-10-16T00:00:00+00:00")
            assert _invalid_payload_reason(alert) is None
            parsed = ResilMeshAlert.from_dict(alert)
            assert parsed.alert_id == f"demo-graph-{n}"
            assert parsed.threat["indicator"] == row["value"] and parsed.threat["type"] == row["indicator_type"]

    def test_only_what_the_graph_holds(self):
        alert = demo.build_alert_from_indicator(_Graph().selection_rows[0], 1, "2026-10-16T00:00:00+00:00")
        assert set(alert["threat"]) == {"indicator", "type", "description"}
        assert "tags" not in alert

    @pytest.mark.parametrize(
        "zone, given, expected",
        [
            (["global", "energy"], None, "energy"),
            (["global"], None, "global"),
            ([], None, "global"),
            (None, None, "global"),
            ("finance", None, "finance"),
            (["energy"], "healthcare", "healthcare"),
        ],
    )
    def test_zone(self, zone, given, expected):
        row = {"value": "x.example", "indicator_type": "domain", "zone": zone}
        assert demo.build_alert_from_indicator(row, 1, "t", given)["zone"] == expected


class TestDemoSelectionQuery:
    def test_shape(self):
        q = demo.SELECTION_QUERY
        assert q.startswith("MATCH (i:Indicator)")
        assert "i.active = true" in q
        assert "EXISTS { MATCH (i)-[:INDICATES]->(:Malware) }" in q
        assert "$zone IS NULL OR $zone IN coalesce(i.zone, [])" in q
        assert q.rstrip().endswith("LIMIT $limit")
        # 2026-10-16: most recently reported first (indicator aging), not by the last database write.
        assert "ORDER BY coalesce(i.last_reported_at, i.first_imported_at) DESC, i.value" in q
        assert "last_updated" not in q
        assert not _WRITE.search(q)

    def test_runs_in_a_read_session_with_its_parameters(self):
        graph = _Graph()
        rows = demo.select_indicators(_Driver(graph), 1, "energy", "READ")
        assert rows == graph.selection_rows[:1]
        assert graph.session_kwargs == [{"default_access_mode": "READ"}]
        assert graph.statements == [demo.SELECTION_QUERY]
        assert graph.params == [{"limit": 1, "zone": "energy"}]

    def test_without_zone_the_parameter_is_null(self):
        graph = _Graph()
        demo.select_indicators(_Driver(graph), 2, None, "READ")
        assert graph.params == [{"limit": 2, "zone": None}]

    def test_the_documented_query_is_the_one_the_demo_runs(self):
        assert demo.SELECTION_QUERY in (_ROOT / "docs" / "DEMO.md").read_text()

    def test_help_shows_the_query(self, capsys):
        with pytest.raises(SystemExit) as exc:
            demo.main(["--help"])
        assert exc.value.code == 0
        assert demo.SELECTION_QUERY in capsys.readouterr().out


class TestDemoRun:
    def _run(self, argv, graph=None, capsys=None, **client_kwargs):
        graph = graph or _Graph()
        clients: List[_Client] = []

        def factory():
            clients.append(_Client(graph, **client_kwargs))
            return clients[0]

        code = demo.main(argv, client_factory=factory)
        out, err = capsys.readouterr()
        return code, out, err, graph, clients

    def test_from_graph_prints_the_processors_responses_and_never_writes(self, capsys):
        code, out, err, graph, clients = self._run(["--from-graph", "2"], capsys=capsys)
        assert code == demo.EXIT_OK
        responses = json.loads(out)
        assert [r["alert_id"] for r in responses] == ["demo-graph-1", "demo-graph-2"]
        first = responses[0]
        assert first["enriched"] is True
        assert first["enrichment"]["cves"] == [_GRAPH_CVE]
        assert responses[1]["query_metadata"]["indicator_found"] is False  # not linked in the fake graph
        assert not [q for q in graph.statements if _WRITE.search(q)]
        assert all(kw.get("default_access_mode") == "READ" for kw in graph.session_kwargs)
        assert clients[0].closed
        assert "Selected 2 indicator(s)" in err

    def test_zone_is_bound_into_the_selection(self, capsys):
        code, out, _err, graph, _clients = self._run(["--from-graph", "3", "--zone", "energy"], capsys=capsys)
        assert code == demo.EXIT_OK
        assert graph.params[0] == {"limit": 3, "zone": "energy"}
        responses = json.loads(out)
        assert [r["original_alert"]["zone"] for r in responses] == ["energy"]
        assert [r["enrichment"]["indicator"] for r in responses] == [_INDICATOR]

    def test_a_failed_selection_query(self, capsys):
        graph = _Graph()
        graph.fail_selection = True
        code, out, err, _graph, clients = self._run(["--from-graph", "1"], graph=graph, capsys=capsys)
        assert code == demo.EXIT_NEO4J and out == ""
        assert "The selection query failed (ServiceUnavailable: connection lost)" in err
        assert clients[0].closed

    def test_a_failed_enrichment_query_ends_the_run_as_a_failure(self, capsys):
        graph = _Graph()
        graph.fail_enrichment = True
        code, out, err, _graph, clients = self._run(["--from-graph", "1"], graph=graph, capsys=capsys)
        assert code == demo.EXIT_NEO4J
        (response,) = json.loads(out)
        assert response["enriched"] is False and response["query_metadata"]["error"] == "connection lost"
        assert "An enrichment query failed for alert(s) 'demo-graph-1'" in err
        assert clients[0].closed

    def test_an_alert_the_processor_raises_on(self, tmp_path, capsys):
        path = tmp_path / "alerts.json"
        bad = {"alert_id": "bad-1", "threat": {"indicator": "203.0.113.9", "cve": 2021}}
        path.write_text(json.dumps([{**_alert(), "alert_id": "ok-1"}, bad]))
        code, out, err, _graph, clients = self._run(["--alerts", str(path)], capsys=capsys)
        assert code == demo.EXIT_USAGE
        assert [r["alert_id"] for r in json.loads(out)] == ["ok-1"]
        assert "'bad-1' (AttributeError" in err
        assert clients[0].closed

    def test_a_rejected_alert_is_the_processors_answer_not_a_failure(self, tmp_path, capsys):
        path = tmp_path / "alerts.json"
        path.write_text(json.dumps([{"alert_id": "no-indicator", "threat": {}}]))
        code, out, err, *_ = self._run(["--alerts", str(path)], capsys=capsys)
        assert code == demo.EXIT_OK and "failed" not in err
        (response,) = json.loads(out)
        assert response["enriched"] is False and response["query_metadata"] == {"error": "No indicator in alert"}

    def test_alerts_file(self, tmp_path, capsys):
        path = tmp_path / "alerts.json"
        path.write_text(json.dumps([_alert(), {"threat": {"indicator": "1.2.3.4"}}]))
        code, out, _err, graph, _clients = self._run(["--alerts", str(path)], capsys=capsys)
        assert code == demo.EXIT_OK
        responses = json.loads(out)
        assert responses[0]["enriched"] is True
        assert responses[1]["enriched"] is False and "alert_id" in responses[1]["query_metadata"]["error"]
        assert not [q for q in graph.statements if _WRITE.search(q)]

    def test_a_single_alert_object(self, tmp_path, capsys):
        path = tmp_path / "alert.json"
        path.write_text(json.dumps(_alert()))
        code, out, *_ = self._run(["--alerts", str(path)], capsys=capsys)
        assert code == demo.EXIT_OK and len(json.loads(out)) == 1

    @pytest.mark.parametrize("content", ["[1, 2]", "not json", "[]"])
    def test_an_unusable_alert_file(self, tmp_path, capsys, content):
        path = tmp_path / "alerts.json"
        path.write_text(content)
        code, out, err, _graph, clients = self._run(["--alerts", str(path)], capsys=capsys)
        assert code == demo.EXIT_USAGE and out == "" and "Cannot read alerts" in err
        assert clients == []  # nothing connected

    def test_unreachable_neo4j(self, capsys):
        code, out, err, *_ = self._run(["--from-graph", "1"], capsys=capsys, reachable=False)
        assert code == demo.EXIT_NEO4J and out == ""
        assert "bolt://fake:7687 is unreachable" in err

    def test_refused_connection(self, capsys):
        code, out, err, *_ = self._run(["--from-graph", "1"], capsys=capsys, accepts=False)
        assert code == demo.EXIT_NEO4J and out == "" and "refused" in err

    def test_nothing_selected(self, capsys):
        graph = _Graph()
        graph.selection_rows = []
        code, out, err, *_ = self._run(["--from-graph", "3", "--zone", "finance"], graph=graph, capsys=capsys)
        assert code == demo.EXIT_NOTHING_SELECTED and out == "" and "in zone finance" in err

    def test_unknown_zone(self, capsys):
        code, out, err, *_ = self._run(["--from-graph", "1", "--zone", "retail"], capsys=capsys)
        assert code == demo.EXIT_USAGE and "Unknown zone" in err

    @pytest.mark.parametrize("argv", [[], ["--from-graph", "0"], ["--alerts", "a.json", "--zone", "energy"]])
    def test_usage_errors(self, argv, capsys):
        with pytest.raises(SystemExit) as exc:
            demo.main(argv, client_factory=lambda: pytest.fail("no client for a usage error"))
        assert exc.value.code == demo.EXIT_USAGE

    def test_connect_once_skips_the_pipeline_retries(self):
        calls: List[str] = []

        class _Retrying:
            def connect(self):
                calls.append("retrying")
                return True

        def _unwrapped(self):
            calls.append("once")
            return True

        _Retrying.connect.__wrapped__ = _unwrapped  # what functools.wraps sets on a decorated method
        assert demo._connect_once(_Retrying()) is True
        assert calls == ["once"]


def test_no_demo_script_draws_random_values():
    """A demo prints what the code returns: the script it replaced printed ``random`` values as an
    enrichment."""
    scripts = sorted((_ROOT / "demo").glob("*.py"))
    assert scripts
    for path in scripts:
        assert not re.search(r"^\s*(import random|from random import)", path.read_text(), re.MULTILINE), path.name


# ---------------------------------------------------------------------------
# The patterns the enrichment reads have writers
# ---------------------------------------------------------------------------


def _code_text(path: Path) -> str:
    """Source text with adjacent string literals joined and whitespace collapsed, so a Cypher
    statement split over several literals or lines reads as one string."""
    text = re.sub(r"\"\s*\+?\s*\"", "", path.read_text())
    return re.sub(r"\s+", " ", text)


class TestReadsHaveWriters:
    """Each relationship / label pair ``_enrich_indicator`` reads is MERGEd by
    ``build_relationships`` or ``neo4j_client`` (2026-10). The CVE read followed ``INDICATES`` to a
    ``Vulnerability``, which nothing on a pipeline path writes, and stayed empty unnoticed: renaming
    or retargeting a writer must fail here, not only empty the enrichment."""

    _READS_AND_WRITERS = [
        (
            "OPTIONAL MATCH (i)-[:INDICATES]->(m:Malware)",
            r"MATCH \(m:Malware[^)]*\)[^;]{0,200}?MERGE \(i\)-\[r:INDICATES\]->\(m\)",
        ),
        (
            "OPTIONAL MATCH (m)-[:ATTRIBUTED_TO]->(a:ThreatActor)",
            r"MATCH \(m:Malware\)[^;]{0,200}?MATCH \(a:ThreatActor\)[^;]{0,200}?MERGE \(m\)-\[r:ATTRIBUTED_TO\]->\(a\)",
        ),
        (
            "OPTIONAL MATCH (a)-[:EMPLOYS_TECHNIQUE]->(t:Technique)",
            r"MATCH \(a:ThreatActor[^)]*\)[^;]{0,200}?MATCH \(t:Technique[^)]*\) MERGE \(a\)-\[r:EMPLOYS_TECHNIQUE\]->\(t\)",
        ),
        (
            f"{_CVE_READ} {_CVE_WHERE}",
            re.escape("MATCH (v:Vulnerability {cve_id: i.cve_id}) MERGE (i)-[r:EXPLOITS]->(v)"),
        ),
        (
            f"{_CVE_READ} {_CVE_WHERE}",
            re.escape("MATCH (c:CVE {cve_id: i.cve_id}) MERGE (i)-[r:EXPLOITS]->(c)"),
        ),
        # 2026-10-18: the sync's same-report rows (``create_misp_relationships_batch``, an f-string template).
        (
            f"{_CVE_READ} {_CVE_WHERE}",
            r"MATCH \(i:Indicator \{\{?value: row\.value\}?\}\) MATCH \(c:CVE \{\{?cve_id: row\.cve_id\}?\}\) "
            r"MERGE \(i\)-\[r:INDICATES\]->\(c\)",
        ),
        (
            "OPTIONAL MATCH (i)-[r:SOURCED_FROM]->(:Source)",
            r"MATCH \(s:Source[^)]*\)[^;]{0,300}?MERGE \(n\)-\[r:SOURCED_FROM\]->\(s\)",
        ),
    ]

    @pytest.mark.parametrize("read, writer", _READS_AND_WRITERS)
    def test_read_pattern_has_a_writer(self, read, writer):
        reader = re.sub(r"\s+", " ", inspect.getsource(AlertProcessor._enrich_indicator))
        assert read in reader, f"_enrich_indicator no longer reads {read!r}: update this table"
        writers = _code_text(_ROOT / "src" / "build_relationships.py") + _code_text(_ROOT / "src" / "neo4j_client.py")
        assert re.search(writer, writers), f"nothing writes what {read!r} reads"

    def test_no_read_without_a_writer(self):
        """Every relationship type the enrichment follows is in the table, except the two it reads
        from the Alert node, which no code path writes (``assets`` / ``users`` are documented as
        always empty)."""
        reader = inspect.getsource(AlertProcessor._enrich_indicator)
        # 2026-10-18: one pattern may follow several types (``[r:EXPLOITS|INDICATES]``).
        followed = {t for group in re.findall(r"\((?:i|m|a)\)-\[r?:([A-Z_|]+)\]->", reader) for t in group.split("|")}
        alert_side = {"TARGETS", "INVOLVES_USER"}
        assert alert_side <= followed and "MATCH (a:Alert {alert_id: $alert_id})" in reader
        tabled = set()
        for read, _writer in self._READS_AND_WRITERS:
            match = re.search(r":([A-Z_|]+)\]", read)
            assert match is not None
            tabled.update(match.group(1).split("|"))
        assert followed - alert_side == tabled


# ---------------------------------------------------------------------------
# Demo material states only real behaviour
# ---------------------------------------------------------------------------


class TestDemoMaterial:
    def test_demo_md_sets_a_host_reachable_bolt_uri(self):
        """``.env`` names the Compose service (``bolt://neo4j:7687``), which the host cannot resolve."""
        assert "NEO4J_URI=bolt://neo4j:7687" in (_ROOT / ".env.example").read_text(), "premise"
        guide = (_ROOT / "docs" / "DEMO.md").read_text()
        source_line = guide.index("set -a && source .env && set +a")
        assert guide.index("export NEO4J_URI=bolt://localhost:7687", source_line) > source_line

    def test_demo_md_states_the_failure_exit_codes(self):
        guide = " ".join((_ROOT / "docs" / "DEMO.md").read_text().split())
        assert "an enrichment query failed" in guide and "`enriched: false`" in guide
        assert (
            "a malware the alert names is listed with the description `From alert (not in graph)` whether or not"
            in guide
        )
        assert "connection check (`RETURN 1`" in guide

    def test_demo_page_shows_no_invented_enrichment_or_latency(self):
        page = (_ROOT / "docs" / "demo.html").read_text()
        assert '"malware": ["Cobalt Strike"]' not in page and '"confidence": 0.85' not in page
        assert "&lt;150ms</span>" not in page and "<150ms typical" not in page
        assert "docs/DEMO.md" in page

    def test_demo_md_states_where_the_graph_cves_of_an_alert_come_from(self):
        """No collector writes the CVE tag on an indicator that ``(Indicator)-[:EXPLOITS]->`` rests on, so the
        CVEs an alert lists from the graph are those named in the same OTX report (``INDICATES``,
        ``otx_pulse``, 2026-10-18). The guide says so, keeps the statement that no feed gives an indicator's
        own CVE claim, shows the evidence in the output shape and how to pick such an indicator, and still
        offers the GraphQL step for ``<CVE id>``."""
        guide = " ".join((_ROOT / "docs" / "DEMO.md").read_text().split())
        assert "**CVEs from the graph: named in the same report.**" in guide
        assert "no feed gives one: EdgeGuard's collectors write no such tag" in guide
        assert "`(Indicator)-[:INDICATES]->(CVE)`" in guide and "named in the same OTX report as the indicator" in guide
        assert "`cves: []` with `cves_found: 0` otherwise" in guide
        assert '"cves_found": "<count>",' in guide and '"evidence": [{"relationship": "INDICATES"' in guide
        assert "MATCH (i:Indicator)-[r:INDICATES]->(:CVE)" in guide
        assert "**No CVEs from the graph.**" not in guide and '"cves": [],' not in guide
        assert "Take the identifiers (`<indicator>`, `<actor>`, `<CVE id>`) from the alert enrichment" not in guide
        assert "`<CVE id>` from a `cveId` that step 5 (GraphQL vulnerabilities) returns" in guide
        assert "the CVEs the indicator exploits, its confidence" not in guide

    def test_premise_no_collector_writes_an_indicator_cve_tag(self):
        """The guide's premise: the sync reads an indicator's CVE from an ``exploits:`` tag (or a
        ``cve="CVE-…"`` / ``cve:CVE-…`` tag) on its MISP attribute, and no collector writes one. A
        collector that starts writing one makes the guide's "no feed gives one" wrong."""
        sync = (_ROOT / "src" / "run_misp_to_neo4j.py").read_text()
        assert 'tag_name.startswith("exploits:")' in sync, "premise: the tag the sync reads"
        for path in sorted((_ROOT / "src" / "collectors").rglob("*.py")):
            text = path.read_text()
            assert "exploits:" not in text, f"{path.name} writes an exploits: tag; update docs/DEMO.md"
            assert 'cve="CVE-' not in text and "cve:CVE-" not in text, f"{path.name}: update docs/DEMO.md"

    def test_demo_md_alert_commands_discard_the_startup_warning(self):
        guide = (_ROOT / "docs" / "DEMO.md").read_text()
        assert "python demo/alert_enrichment_demo.py --from-graph 1 2>/dev/null | jq '.[0].enrichment'" in guide
        assert "python demo/alert_enrichment_demo.py --from-graph 3 --zone energy 2>/dev/null" in guide
        assert "read the exit code before showing a response" in " ".join(guide.split())

    def test_demo_md_url_encodes_the_stix_indicator(self):
        guide = (_ROOT / "docs" / "DEMO.md").read_text()
        assert '/stix/export/indicator/<indicator>"' not in guide
        assert "IND=$(jq -rn --arg v '<indicator>' '$v | @uri')" in guide
        assert '/stix/export/indicator/$IND"' in guide
