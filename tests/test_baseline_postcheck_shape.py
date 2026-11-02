"""The baseline postcheck's invariants INV-4 to INV-6 (2026-11-02, ``assert_baseline_postconditions``).

The postcheck passed every run whose sync connected: INV-3 (Source > 0) holds once ``ensure_sources`` ran, and no
invariant read a relationship family or what the collectors delivered. A run that lost ``IN_TACTIC``, the
``mitre_explicit`` technique links, every CVSS sub-node or a whole source ended green. These tests run the real
postcheck callable with a fake Bolt session that answers the statements of ``graph_shape_checks`` and a fake
task instance that answers Airflow 3's task states and the collectors' status XComs:

* the rows are those of the iMac 730-day graph of 2026-11-01 (read-only), the same statements with
  ``IN_TACTIC``, ``EMPLOYS_TECHNIQUE``, ``IMPLEMENTS_TECHNIQUE`` and the CVSS types read as absent, and the
  reduced graph of the in-process CLI baseline of 2026-10-31 (718 techniques without ``tactic_phases``, 187 MITRE
  actors without claims, 0 of 152,359 CVEs scored);
* the XComs are the collectors' return values in the 730-day run's task logs. The AbuseIPDB task log line was
  redacted in the copy; its XCom is the status the collector returns without a key.

Each invariant: it passes, it fails with a message that names it, its numbers and the recovery, and it is not
judged where it must not be (a limited run, no NVD delivery, no input).
"""

from __future__ import annotations

import copy
import os
import re
import sys
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from stub_cleanup import dag_module_import

_DAGS = os.path.join(os.path.dirname(__file__), "..", "dags")
_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
for _p in (_DAGS, _SRC):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import graph_shape_checks as gsc  # noqa: E402
from campaign_evidence import QUALIFYING_ACTORS_QUERY  # noqa: E402

RUN = "manual__2026-11-01T08:30:35.559036+00:00"
CHAIN = ("full_neo4j_sync", "build_relationships", "run_enrichment_jobs")


def _import_dag_module():
    for key in list(sys.modules):
        if key in ("edgeguard_pipeline", "airflow", "opentelemetry") or key.startswith(("airflow.", "opentelemetry.")):
            del sys.modules[key]
    import importlib

    with dag_module_import():
        return importlib.import_module("edgeguard_pipeline")


@pytest.fixture(scope="module")
def ep():
    return _import_dag_module()


# ---------------------------------------------------------------------------------------------------- fixtures

# The statements' rows on the 730-day graph (iMac, 2026-11-01 baseline, read 2026-11-02).
ROWS_730D: Dict[str, Any] = {
    "qualifying": {"qualifying_actors": 533},
    "campaigns": {"campaigns": 533},
    "indicators": {"n": 274865},
    "sources": {"n": 16},
    "in_tactic": {
        "techniques": 824,
        "with_phases": 824,
        "claims_with_target": 1024,
        "edge_missing": 0,
        "tactic_missing": 0,
        "examples": [],
    },
    "employs": {
        "claims": 4854,
        "claiming_actors": 177,
        "target_missing": 0,
        "claims_with_target": 4854,
        "edge_missing": 0,
        "examples": [],
        "mitre_nodes": 189,
    },
    "malware": {
        "claims": 10895,
        "claiming_malware": 752,
        "target_missing": 0,
        "claims_with_target": 10895,
        "edge_missing": 0,
        "examples": [],
        "mitre_nodes": 754,
    },
    "tool": {
        "claims": 869,
        "claiming_tools": 95,
        "target_missing": 0,
        "claims_with_target": 869,
        "edge_missing": 0,
        "examples": [],
        "mitre_nodes": 95,
    },
    "cve": {"nvd_cves_not_rejected": 146858, "nvd_cves_with_cvss": 142236},
    "source_rows": [
        {"source_id": "abuseipdb", "sourced_from": 0},
        {"source_id": "alienvault_otx", "sourced_from": 150615},
        {"source_id": "cisa_ics", "sourced_from": 4577},
        {"source_id": "cisa_kev", "sourced_from": 1766},
        {"source_id": "coreideas", "sourced_from": 0},
        {"source_id": "feodo_tracker", "sourced_from": 7607},
        {"source_id": "malwarebazaar", "sourced_from": 824},
        {"source_id": "misp", "sourced_from": 0},
        {"source_id": "misp_galaxy", "sourced_from": 0},
        {"source_id": "mitre_attck", "sourced_from": 1889},
        {"source_id": "nvd", "sourced_from": 151186},
        {"source_id": "ssl_blacklist", "sourced_from": 11120},
        {"source_id": "stix_import", "sourced_from": 0},
        {"source_id": "threatfox", "sourced_from": 9774},
        {"source_id": "urlhaus", "sourced_from": 99988},
        {"source_id": "virustotal", "sourced_from": 0},
    ],
}

# The same statements on the same graph with IN_TACTIC, EMPLOYS_TECHNIQUE, IMPLEMENTS_TECHNIQUE and the CVSS
# types read as absent (a run whose build_relationships steps or CVSS writes wrote nothing).
MASKED_730D: Dict[str, Any] = {
    "in_tactic": {
        "techniques": 824,
        "with_phases": 824,
        "claims_with_target": 1024,
        "edge_missing": 1024,
        "tactic_missing": 0,
        "examples": ["T1055.011", "T1053.005", "T1205.002", "T1560.001", "T1021.005"],
    },
    "employs": {
        "claims": 4854,
        "claiming_actors": 177,
        "target_missing": 0,
        "claims_with_target": 4854,
        "edge_missing": 4854,
        "examples": ["apt38 -> T1486", "apt38 -> T1055"],
        "mitre_nodes": 189,
    },
    "malware": {
        "claims": 10895,
        "claiming_malware": 752,
        "target_missing": 0,
        "claims_with_target": 10895,
        "edge_missing": 10895,
        "examples": ["hdoor -> T1046", "trickbot -> T1082"],
        "mitre_nodes": 754,
    },
    "tool": {
        "claims": 869,
        "claiming_tools": 95,
        "target_missing": 0,
        "claims_with_target": 869,
        "edge_missing": 869,
        "examples": ["Net -> T1201"],
        "mitre_nodes": 95,
    },
    "cve": {"nvd_cves_not_rejected": 146858, "nvd_cves_with_cvss": 0},
}

# The reduced graph of the in-process CLI baseline (2026-10-31): the STIX import wrote 718 techniques without
# kill-chain phases, 187 MITRE actors, 748 malware and 95 tools without claims, and no CVE score.
CLI_SHAPE: Dict[str, Any] = {
    "in_tactic": {
        "techniques": 718,
        "with_phases": 0,
        "claims_with_target": 0,
        "edge_missing": 0,
        "tactic_missing": 0,
        "examples": [],
    },
    "employs": {
        "claims": 0,
        "claiming_actors": 0,
        "target_missing": 0,
        "claims_with_target": 0,
        "edge_missing": 0,
        "examples": [],
        "mitre_nodes": 187,
    },
    "malware": {
        "claims": 0,
        "claiming_malware": 0,
        "target_missing": 0,
        "claims_with_target": 0,
        "edge_missing": 0,
        "examples": [],
        "mitre_nodes": 748,
    },
    "tool": {
        "claims": 0,
        "claiming_tools": 0,
        "target_missing": 0,
        "claims_with_target": 0,
        "edge_missing": 0,
        "examples": [],
        "mitre_nodes": 95,
    },
    "cve": {"nvd_cves_not_rejected": 152359, "nvd_cves_with_cvss": 0},
}

# What the collector tasks of the 730-day run returned (their task logs, "Done. Returned value was").
XCOMS_730D: Dict[str, Optional[dict]] = {
    "tier1_core.collect_cisa": {
        "source": "cisa_kev",
        "success": True,
        "count": 1766,
        "failed": 0,
        "timestamp": "2026-11-01T12:27:03.531265+00:00",
        "circuit_breaker_state": "CLOSED",
        "kev_update": {
            "catalogue": 1766,
            "catalogue_version": "2026.10.30 (2026-10-30T17:02:45.3665Z)",
            "scope": 1766,
            "added": 1766,
            "updated": 0,
            "unchanged": 0,
            "stored_not_updated": 0,
            "foreign_only": 0,
            "deferred": 0,
            "failed": 0,
            "not_written": [],
            "changed_keys": {},
            "stored_not_in_catalogue": 0,
            "stored_not_in_catalogue_ids": [],
            "stop_reasons": [],
        },
    },
    "tier1_core.collect_mitre": {
        "source": "mitre",
        "success": True,
        "count": 1891,
        "failed": 0,
        "timestamp": "2026-11-01T12:28:33.137800+00:00",
    },
    "tier1_core.collect_otx": {
        "source": "otx",
        "success": True,
        "count": 150857,
        "failed": 1857,
        "timestamp": "2026-11-01T14:39:11.236411+00:00",
        "circuit_breaker_state": "CLOSED",
    },
    "tier1_core.collect_nvd": {
        "source": "nvd",
        "success": True,
        "count": 151186,
        "failed": 0,
        "timestamp": "2026-11-01T16:00:50.903949+00:00",
        "circuit_breaker_state": "CLOSED",
    },
    # The collector's status without ABUSEIPDB_API_KEY (the copied log line was redacted).
    "tier2_feeds.collect_abuseipdb": {
        "source": "abuseipdb",
        "success": True,
        "count": 0,
        "failed": 0,
        "timestamp": "2026-11-01T16:01:03.100000+00:00",
        "skipped": True,
        "skip_reason": "ABUSEIPDB_API_KEY not set (optional — https://www.abuseipdb.com/api)",
        "skip_reason_class": "missing_abuseipdb_key",
    },
    "tier2_feeds.collect_threatfox": {
        "source": "threatfox",
        "success": True,
        "count": 10000,
        "failed": 0,
        "timestamp": "2026-11-01T16:05:18.165954+00:00",
    },
    "tier2_feeds.collect_urlhaus": {
        "source": "urlhaus",
        "success": True,
        "count": 99988,
        "failed": 0,
        "timestamp": "2026-11-01T16:43:54.842327+00:00",
    },
    "tier2_feeds.collect_feodo": {
        "source": "feodo",
        "success": True,
        "count": 7607,
        "failed": 0,
        "timestamp": "2026-11-01T16:04:22.558776+00:00",
    },
    "tier2_feeds.collect_sslblacklist": {
        "source": "sslbl",
        "success": True,
        "count": 11120,
        "failed": 0,
        "timestamp": "2026-11-01T16:06:04.075500+00:00",
    },
    "tier2_feeds.collect_cisa_ics": {
        "source": "cisa_ics",
        "success": True,
        "count": 4577,
        "failed": 0,
        "timestamp": "2026-11-01T16:11:37.688832+00:00",
        "circuit_breaker_state": "CLOSED",
        "stats": {
            "candidates": 1097,
            "attempted": 1097,
            "parsed_ok": 1097,
            "fetch_failed": 0,
            "malformed": 0,
            "outside_window": 106,
            "skipped_vulns": 0,
        },
    },
    "tier2_feeds.collect_malwarebazaar": {
        "source": "malwarebazaar",
        "success": True,
        "count": 824,
        "failed": 0,
        "timestamp": "2026-11-01T16:05:47.092475+00:00",
    },
}

# OTX without a key: the status the collector returns (``otx_collector``, ``missing_otx_key``).
OTX_SKIPPED = {
    "source": "otx",
    "success": True,
    "count": 0,
    "failed": 0,
    "timestamp": "2026-11-01T14:39:11.236411+00:00",
    "skipped": True,
    "skip_reason": "OTX_API_KEY not set",
    "skip_reason_class": "missing_otx_key",
}


def _rows(**override: Any) -> Dict[str, Any]:
    rows = copy.deepcopy(ROWS_730D)
    rows.update(copy.deepcopy(override))
    return rows


def _with_sourced_from(rows: Dict[str, Any], **edges: int) -> Dict[str, Any]:
    rows["source_rows"] = [
        dict(r, sourced_from=edges[r["source_id"]]) if r["source_id"] in edges else r for r in rows["source_rows"]
    ]
    return rows


# ---------------------------------------------------------------------------------------------------- harness


class _Result:
    def __init__(self, single: Optional[dict] = None, data: Optional[list] = None):
        self._single, self._data = single, data

    def single(self):
        return self._single

    def data(self):
        return list(self._data or [])


class _Session:
    """Answers the postcheck's statements by identity with the shared constants; any other statement fails."""

    def __init__(self, rows: Dict[str, Any]):
        self.rows = rows
        self.statements: List[str] = []
        self.parameters: Dict[str, Any] = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def run(self, query, parameters=None, **_kw):
        self.statements.append(query)
        self.parameters[query] = parameters
        by_statement = {
            QUALIFYING_ACTORS_QUERY: "qualifying",
            "MATCH (c:Campaign) RETURN count(c) AS campaigns": "campaigns",
            "MATCH (i:Indicator) RETURN count(i) AS n": "indicators",
            "MATCH (s:Source) RETURN count(s) AS n": "sources",
            gsc.IN_TACTIC_COMPLETE_QUERY: "in_tactic",
            gsc.EMPLOYS_TECHNIQUE_COMPLETE_QUERY: "employs",
            gsc.IMPLEMENTS_TECHNIQUE_COMPLETE_QUERIES["Malware"]: "malware",
            gsc.IMPLEMENTS_TECHNIQUE_COMPLETE_QUERIES["Tool"]: "tool",
            gsc.CVE_CVSS_COVERAGE_QUERY: "cve",
        }
        if query == gsc.SOURCE_SOURCED_FROM_QUERY:
            return _Result(data=self.rows["source_rows"])
        if query not in by_statement:
            raise AssertionError(f"unexpected statement: {query[:120]}")
        return _Result(single=self.rows[by_statement[query]])


def _ti(ep, xcoms: Dict[str, Optional[dict]], states: Optional[Dict[str, Optional[str]]] = None):
    """Airflow 3's task instance: no ``get_dagrun``; task states of this run and the collectors' XComs."""
    collector_states = {task: "success" for task in ep._BASELINE_COLLECTOR_TASKS.values()}
    collector_states.update(states or {})
    all_states = {**{task: "success" for task in CHAIN}, **collector_states}
    ti = MagicMock()
    ti.dag_id = "edgeguard_baseline"
    ti.run_id = RUN
    ti.get_task_states.side_effect = lambda dag_id, task_ids, run_ids: {RUN: {t: all_states.get(t) for t in task_ids}}
    ti.xcom_pull.side_effect = lambda task_ids=None, **_kw: xcoms.get(task_ids)
    del ti.get_dagrun
    return ti


class _Outcome:
    def __init__(self, error, session, log):
        self.error, self.session, self.log = error, session, log

    def lines(self, level: str) -> List[str]:
        out = []
        for call in getattr(self.log, level).call_args_list:
            msg, *args = call.args
            out.append(msg % tuple(args) if args else msg)
        return out

    @property
    def message(self) -> str:
        return str(self.error) if self.error else ""

    @property
    def violations(self) -> str:
        return "\n".join(self.lines("error"))


def _postcheck(
    ep,
    monkeypatch,
    rows: Dict[str, Any],
    xcoms: Optional[Dict[str, Optional[dict]]] = None,
    states: Optional[Dict[str, Optional[str]]] = None,
    conf: Optional[dict] = None,
    required: str = "",
    ti=None,
) -> _Outcome:
    monkeypatch.delenv("EDGEGUARD_BASELINE_COLLECTION_LIMIT", raising=False)
    monkeypatch.setenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", required)
    session = _Session(rows)
    client = MagicMock()
    client.driver.session.return_value = session
    ti = ti if ti is not None else _ti(ep, XCOMS_730D if xcoms is None else xcoms, states)
    log = MagicMock()
    with patch("neo4j_client.Neo4jClient", return_value=client), patch.object(ep, "logger", log):
        try:
            result = ep.assert_baseline_postconditions(ti=ti, task_instance=ti, dag_run=MagicMock(conf=conf or {}))
            assert result is None
            return _Outcome(None, session, log)
        except ep.AirflowException as exc:
            return _Outcome(exc, session, log)


LIMITED = {"collection_limit": 500}


# ---------------------------------------------------------------------------------------------------- the run


class TestThe730DayRun:
    def test_passes_and_reports_each_invariant(self, ep, monkeypatch):
        out = _postcheck(ep, monkeypatch, _rows())
        assert out.error is None
        info = "\n".join(out.lines("info"))
        assert "INV-4 ATT&CK shape (unlimited run; MITRE delivered 1891 items)" in info
        assert "IN_TACTIC 824 techniques, 824 with phases, 1,024 phases with a Tactic, 0 missing" in info
        assert "EMPLOYS_TECHNIQUE from ThreatActor 4,854 claims, 4,854 with a Technique, 0 missing" in info
        assert "INV-5 CVE score coverage: 142236 of 146858 non-rejected NVD CVEs have a CVSS sub-node (0.969)" in info
        assert "alienvault_otx 150,615/150,857" in info and "threatfox 9,774/10,000" in info
        # abuseipdb was skipped: listed, not judged.
        warnings = "\n".join(out.lines("warning"))
        assert "tier2_feeds.collect_abuseipdb" in warnings and "skipped (missing_abuseipdb_key)" in warnings

    def test_runs_the_statements_the_acceptance_script_runs(self, ep, monkeypatch):
        out = _postcheck(ep, monkeypatch, _rows())
        shared = {
            gsc.IN_TACTIC_COMPLETE_QUERY,
            gsc.EMPLOYS_TECHNIQUE_COMPLETE_QUERY,
            *gsc.IMPLEMENTS_TECHNIQUE_COMPLETE_QUERIES.values(),
            gsc.CVE_CVSS_COVERAGE_QUERY,
            gsc.SOURCE_SOURCED_FROM_QUERY,
        }
        assert shared <= set(out.session.statements)
        # INV-1 stays the first statement; the technique statements carry the revoked-id map the writers read.
        assert out.session.statements[0] == QUALIFYING_ACTORS_QUERY
        from attack_revoked import technique_successors

        assert out.session.parameters[gsc.EMPLOYS_TECHNIQUE_COMPLETE_QUERY] == gsc.technique_params(
            technique_successors()
        )

    def test_the_failure_names_the_invariants_and_the_held_lock(self, ep, monkeypatch):
        rows = _with_sourced_from(_rows(**copy.deepcopy(MASKED_730D)), alienvault_otx=0)
        out = _postcheck(ep, monkeypatch, rows)
        assert out.error is not None
        assert "violations) — INV-4, INV-5, INV-6." in out.message
        assert "The baseline lock stays held (baseline_release_lock runs only after a successful run)" in out.message
        assert "docs/RUNBOOK.md § 7d" in out.message


# ---------------------------------------------------------------------------------------------------- INV-4


class TestAttackShape:
    def test_missing_in_tactic_fails(self, ep, monkeypatch):
        out = _postcheck(ep, monkeypatch, _rows(in_tactic=MASKED_730D["in_tactic"]))
        assert out.error is not None and "(1 violations) — INV-4." in out.message
        assert (
            "[INV-4] IN_TACTIC: 1,024 of the 1,024 kill-chain phases whose Tactic exists have no IN_TACTIC link"
            in out.violations
        )
        assert "T1055.011" in out.violations
        assert "clear build_relationships with its downstream tasks (docs/RUNBOOK.md § 7d)" in out.violations

    @pytest.mark.parametrize(
        "key, label, rel_type, numbers",
        [
            ("employs", "ThreatActor", "EMPLOYS_TECHNIQUE", "4,854 of the 4,854"),
            ("malware", "Malware", "IMPLEMENTS_TECHNIQUE", "10,895 of the 10,895"),
            ("tool", "Tool", "IMPLEMENTS_TECHNIQUE", "869 of the 869"),
        ],
    )
    def test_missing_technique_links_fail(self, ep, monkeypatch, key, label, rel_type, numbers):
        out = _postcheck(ep, monkeypatch, _rows(**{key: MASKED_730D[key]}))
        assert out.error is not None and "(1 violations) — INV-4." in out.message
        assert (
            f"[INV-4] {rel_type} (mitre_explicit): {numbers} uses_techniques claims of {label} nodes whose Technique "
            "exists have no link" in out.violations
        )

    def test_missing_links_fail_a_limited_run_too(self, ep, monkeypatch):
        out = _postcheck(
            ep, monkeypatch, _rows(in_tactic=MASKED_730D["in_tactic"], tool=MASKED_730D["tool"]), conf=LIMITED
        )
        assert out.error is not None and "(2 violations) — INV-4." in out.message
        assert "INV-4 ATT&CK shape (limited run: links only;" in "\n".join(out.lines("info"))

    def test_lost_claims_fail_an_unlimited_run(self, ep, monkeypatch):
        rows = _rows(**{k: CLI_SHAPE[k] for k in ("in_tactic", "employs", "malware", "tool")})
        out = _postcheck(ep, monkeypatch, rows)
        assert out.error is not None and "(4 violations) — INV-4." in out.message
        assert (
            "[INV-4] tactic claims: of 718 techniques 0 carry tactic_phases, 0 phases reach a Tactic and 0 techniques "
            "with phases reach none" in out.violations
        )
        assert (
            "[INV-4] ThreatActor claims: 187 MITRE ThreatActor nodes and not one uses_techniques claim"
            in out.violations
        )
        assert "[INV-4] Malware claims: 748 MITRE Malware nodes" in out.violations
        assert "[INV-4] Tool claims: 95 MITRE Tool nodes" in out.violations
        assert "read the collect_mitre and full_neo4j_sync logs" in out.violations

    def test_lost_claims_are_not_judged_on_a_limited_run(self, ep, monkeypatch):
        rows = _rows(**{k: CLI_SHAPE[k] for k in ("in_tactic", "employs", "malware", "tool")})
        out = _postcheck(ep, monkeypatch, rows, conf=LIMITED)
        assert out.error is None

    def test_techniques_without_their_tactic_fail_an_unlimited_run(self, ep, monkeypatch):
        in_tactic = dict(ROWS_730D["in_tactic"], tactic_missing=3, examples=["T0807"])
        assert _postcheck(ep, monkeypatch, _rows(in_tactic=in_tactic)).error is not None
        assert _postcheck(ep, monkeypatch, _rows(in_tactic=in_tactic), conf=LIMITED).error is None

    def test_mitre_delivered_and_no_technique_fails_an_unlimited_run(self, ep, monkeypatch):
        empty = {"techniques": 0, "with_phases": 0, "claims_with_target": 0, "edge_missing": 0, "tactic_missing": 0}
        rows = _rows(in_tactic=empty, employs={"claims": 0, "mitre_nodes": 0}, malware={"claims": 0, "mitre_nodes": 0})
        rows["tool"] = {"claims": 0, "mitre_nodes": 0}
        out = _postcheck(ep, monkeypatch, rows)
        assert out.error is not None
        assert (
            "[INV-4] ATT&CK shape: the MITRE collector delivered 1,891 items in this run and the graph holds no "
            "Technique." in out.violations
        )
        # Not judged on a limited run, nor when the MITRE collector delivered nothing (no input).
        assert _postcheck(ep, monkeypatch, rows, conf=LIMITED).error is None
        no_mitre = dict(XCOMS_730D, **{"tier1_core.collect_mitre": None})
        assert (
            _postcheck(ep, monkeypatch, rows, xcoms=no_mitre, states={"tier1_core.collect_mitre": "failed"}).error
            is None
        )

    def test_claims_without_their_techniques_are_not_judged(self, ep, monkeypatch):
        # A limited collection: claims whose Technique is not in the graph are counted apart, never failed.
        employs = dict(ROWS_730D["employs"], target_missing=1200, claims_with_target=3654)
        malware = dict(ROWS_730D["malware"], target_missing=10895, claims_with_target=0)
        assert _postcheck(ep, monkeypatch, _rows(employs=employs, malware=malware), conf=LIMITED).error is None
        assert _postcheck(ep, monkeypatch, _rows(employs=employs, malware=malware)).error is None

    @pytest.mark.parametrize("shape", ["730d", "masked", "cli"])
    def test_an_unlimited_run_judges_as_the_acceptance_verdicts(self, ep, monkeypatch, shape):
        source = {"730d": ROWS_730D, "masked": MASKED_730D, "cli": CLI_SHAPE}[shape]
        rows = _rows(**{k: source[k] for k in ("in_tactic", "employs", "malware", "tool")})
        out = _postcheck(ep, monkeypatch, rows)
        expected_fail = gsc.in_tactic_verdict(rows["in_tactic"]) is False or any(
            gsc.technique_claims_verdict(rows[k]) is False for k in ("employs", "malware", "tool")
        )
        assert ("INV-4" in out.message) is expected_fail


# ---------------------------------------------------------------------------------------------------- INV-5


class TestCveScoreCoverage:
    def test_unscored_cves_fail(self, ep, monkeypatch):
        out = _postcheck(ep, monkeypatch, _rows(cve=MASKED_730D["cve"]))
        assert out.error is not None and "(1 violations) — INV-5." in out.message
        assert (
            "[INV-5] CVE score coverage: 0 of the 146,858 non-rejected NVD CVEs have a CVSS sub-node (0.000; at least "
            "0.5 required) after the NVD collector delivered 151,186 items in this run." in out.violations
        )
        assert "clear full_neo4j_sync with its downstream tasks" in out.violations

    def test_the_cli_shape_fails(self, ep, monkeypatch):
        out = _postcheck(ep, monkeypatch, _rows(cve=CLI_SHAPE["cve"]))
        assert "0 of the 152,359 non-rejected NVD CVEs" in out.violations

    @pytest.mark.parametrize("scored, fails", [(50, False), (49, True)])
    def test_half_of_them_pass(self, ep, monkeypatch, scored, fails):
        out = _postcheck(ep, monkeypatch, _rows(cve={"nvd_cves_not_rejected": 100, "nvd_cves_with_cvss": scored}))
        assert (out.error is not None) is fails

    def test_not_judged_under_100_cves(self, ep, monkeypatch):
        out = _postcheck(ep, monkeypatch, _rows(cve={"nvd_cves_not_rejected": 99, "nvd_cves_with_cvss": 0}))
        assert out.error is None
        assert "; not judged, too few CVEs" in "\n".join(out.lines("info"))

    @pytest.mark.parametrize(
        "xcom, state",
        [
            (None, "failed"),
            ({"source": "nvd", "success": True, "count": 0, "failed": 0}, "success"),
            # A cleared task keeps its earlier XCom: the state of this run decides.
            (XCOMS_730D["tier1_core.collect_nvd"], "upstream_failed"),
            # Cleared and not yet run again: no state in this run, the earlier XCom still there.
            (XCOMS_730D["tier1_core.collect_nvd"], None),
        ],
    )
    def test_not_judged_without_an_nvd_delivery(self, ep, monkeypatch, xcom, state):
        xcoms = dict(XCOMS_730D, **{"tier1_core.collect_nvd": xcom})
        ti = _ti(ep, xcoms, {"tier1_core.collect_nvd": state})
        out = _postcheck(ep, monkeypatch, _rows(cve=MASKED_730D["cve"]), ti=ti)
        assert out.error is None
        assert gsc.CVE_CVSS_COVERAGE_QUERY not in out.session.statements
        assert "[BASELINE-POSTCHECK] INV-5 CVE score coverage: not judged, the NVD collector delivered nothing" in (
            out.lines("info")
        )
        pulled = {c.kwargs.get("task_ids") for c in ti.xcom_pull.call_args_list}
        assert ("tier1_core.collect_nvd" in pulled) is (state == "success")


# ---------------------------------------------------------------------------------------------------- INV-6


class TestDelivery:
    def test_a_lost_otx_sync_fails(self, ep, monkeypatch):
        out = _postcheck(ep, monkeypatch, _with_sourced_from(_rows(), alienvault_otx=0))
        assert out.error is not None and "(1 violations) — INV-6." in out.message
        assert (
            "[INV-6] alienvault_otx: 0 SOURCED_FROM edges for the 150,857 items tier1_core.collect_otx delivered in "
            "this run (0.000; at least 0.9 required)." in out.violations
        )

    @pytest.mark.parametrize("edges, fails", [(9000, False), (8999, True)])
    def test_a_partial_loss_fails_below_nine_tenths(self, ep, monkeypatch, edges, fails):
        out = _postcheck(ep, monkeypatch, _with_sourced_from(_rows(), threatfox=edges))
        assert (out.error is not None) is fails
        if fails:
            assert "[INV-6] threatfox: 8,999 SOURCED_FROM edges for the 10,000 items" in out.violations

    def test_a_failed_collector_is_listed_not_judged(self, ep, monkeypatch):
        # collect_otx failed after a clear: its old XCom is still there and must not be read.
        out = _postcheck(
            ep, monkeypatch, _with_sourced_from(_rows(), alienvault_otx=0), states={"tier1_core.collect_otx": "failed"}
        )
        assert out.error is None
        table = [line for line in out.lines("warning") if "delivered nothing" in line]
        assert len(table) == 1
        assert re.search(r"\n  tier1_core\.collect_otx +task failed\n", table[0])
        assert re.search(r"\n  tier2_feeds\.collect_abuseipdb +skipped \(missing_abuseipdb_key\)", table[0])

    def test_without_airflow_states_the_xcom_decides(self, ep, monkeypatch):
        ti = _ti(ep, XCOMS_730D)
        ti.get_task_states.side_effect = RuntimeError("supervisor gone")
        # Chain states unavailable: the chain markers are read, then the collectors' XComs.
        markers = {"full_neo4j_sync": {"synced": True}, "build_relationships": {"built": True}}
        markers["run_enrichment_jobs"] = {"enriched": True}
        ti.xcom_pull.side_effect = lambda task_ids=None, **_kw: {**XCOMS_730D, **markers}.get(task_ids)
        out = _postcheck(ep, monkeypatch, _with_sourced_from(_rows(), alienvault_otx=0), ti=ti)
        assert "[INV-6] alienvault_otx: 0 SOURCED_FROM edges for the 150,857 items" in out.violations

    def test_a_skipped_status_is_not_judged_whatever_its_count(self, ep, monkeypatch):
        # ``make_status`` takes a count with ``skipped``: a skip is never judged as a delivery.
        from collectors.collector_utils import make_status

        skipped = make_status("otx", True, count=150857, skipped=True, skip_reason_class="otx_auth_denied")
        out = _postcheck(
            ep,
            monkeypatch,
            _with_sourced_from(_rows(), alienvault_otx=0),
            xcoms=dict(XCOMS_730D, **{"tier1_core.collect_otx": skipped}),
        )
        assert out.error is None
        assert "alienvault_otx" not in "\n".join(out.lines("info"))
        assert any("skipped (otx_auth_denied)" in line for line in out.lines("warning"))

    def test_a_failed_task_is_not_asked_for_its_xcom(self, ep, monkeypatch):
        # collect_sslblacklist was cleared and has not run again: no state in this run (None).
        states = {
            "tier1_core.collect_otx": "failed",
            "tier2_feeds.collect_feodo": "upstream_failed",
            "tier2_feeds.collect_sslblacklist": None,
        }
        ti = _ti(ep, XCOMS_730D, states)
        out = _postcheck(ep, monkeypatch, _rows(), ti=ti)
        assert out.error is None
        pulled = {c.kwargs.get("task_ids") for c in ti.xcom_pull.call_args_list}
        assert "tier1_core.collect_nvd" in pulled
        assert not pulled & set(states)
        table = [line for line in out.lines("warning") if "delivered nothing" in line]
        assert len(table) == 1
        assert re.search(r"\n  tier1_core\.collect_otx +task failed\n", table[0])
        assert re.search(r"\n  tier2_feeds\.collect_feodo +task upstream_failed\n", table[0])
        assert re.search(r"\n  tier2_feeds\.collect_sslblacklist +task not run(\n|$)", table[0])
        info = "\n".join(out.lines("info"))
        assert "feodo_tracker" not in info and "ssl_blacklist" not in info

    def test_a_failing_xcom_pull_leaves_the_collector_without_a_status(self, ep, monkeypatch):
        # API drift: the pull raises. The postcheck completes and lists each collector as without a status.
        ti = _ti(ep, XCOMS_730D)
        ti.xcom_pull.side_effect = TypeError("xcom_pull() got an unexpected keyword argument 'task_ids'")
        out = _postcheck(ep, monkeypatch, _rows(), ti=ti)
        assert out.error is None
        warnings = out.lines("warning")
        assert "[BASELINE-POSTCHECK] XCom pull for tier1_core.collect_otx failed: xcom_pull() got an unexpected " in (
            "\n".join(warnings)
        )
        table = [line for line in warnings if "delivered nothing" in line]
        assert len(table) == 1
        for task_id in ep._BASELINE_COLLECTOR_TASKS.values():
            assert re.search(rf"\n  {re.escape(task_id)} +no status returned(\n|$)", table[0]), task_id
        assert "no collector delivered" in "\n".join(out.lines("info"))

    def test_an_unknown_source_name_fails(self, ep, monkeypatch):
        renamed = dict(XCOMS_730D["tier2_feeds.collect_feodo"], source="feodo_v2")
        out = _postcheck(ep, monkeypatch, _rows(), xcoms=dict(XCOMS_730D, **{"tier2_feeds.collect_feodo": renamed}))
        assert (
            "[INV-6] tier2_feeds.collect_feodo delivered 7,607 items under the source name 'feodo_v2'" in out.violations
        )

    def test_a_required_source_that_did_not_deliver_fails(self, ep, monkeypatch):
        xcoms = dict(XCOMS_730D, **{"tier1_core.collect_otx": OTX_SKIPPED})
        rows = _with_sourced_from(_rows(), alienvault_otx=0)
        assert _postcheck(ep, monkeypatch, rows, xcoms=xcoms).error is None  # not required: a skip is allowed
        out = _postcheck(ep, monkeypatch, rows, xcoms=xcoms, required=" OTX , nvd")
        assert out.error is not None and "(1 violations) — INV-6." in out.message
        assert (
            "[INV-6] otx is named in EDGEGUARD_BASELINE_REQUIRED_SOURCES and alienvault_otx holds no SOURCED_FROM edge "
            "(tier1_core.collect_otx: skipped (missing_otx_key))." in out.violations
        )
        assert "required sources: nvd, otx" in "\n".join(out.lines("info"))

    def test_a_required_source_that_delivered_is_judged_once(self, ep, monkeypatch):
        # OTX delivered and none of it reached the graph: (a) reports it, (b) does not report it again.
        out = _postcheck(ep, monkeypatch, _with_sourced_from(_rows(), alienvault_otx=0), required="otx")
        assert out.error is not None and "(1 violations) — INV-6." in out.message
        assert "[INV-6] alienvault_otx: 0 SOURCED_FROM edges for the 150,857 items" in out.violations
        assert "otx is named in EDGEGUARD_BASELINE_REQUIRED_SOURCES" not in out.violations

    def test_a_required_source_with_data_from_before_passes(self, ep, monkeypatch):
        # An additive baseline: OTX was skipped in this run, the graph holds its earlier data.
        xcoms = dict(XCOMS_730D, **{"tier1_core.collect_otx": OTX_SKIPPED})
        assert _postcheck(ep, monkeypatch, _rows(), xcoms=xcoms, required="otx").error is None

    def test_a_required_source_without_a_baseline_collector_is_not_judged(self, ep, monkeypatch):
        out = _postcheck(ep, monkeypatch, _rows(), required="virustotal,mitre")
        assert out.error is None
        assert any("virustotal (EDGEGUARD_BASELINE_REQUIRED_SOURCES) is not judged" in x for x in out.lines("info"))
        # ``mitre`` is not a keyed source: source_key_check ignores it at the start, the postcheck too.
        assert "required sources: none" in "\n".join(out.lines("info"))

    def test_a_required_optional_source_that_was_skipped_fails(self, ep, monkeypatch):
        out = _postcheck(ep, monkeypatch, _rows(), required="abuseipdb")
        assert "abuseipdb is named in EDGEGUARD_BASELINE_REQUIRED_SOURCES and abuseipdb holds no" in out.violations
        assert _postcheck(ep, monkeypatch, _rows()).error is None


# ---------------------------------------------------------------------------------------------------- the DAG


def test_the_collector_map_is_the_dags_collector_tasks(ep):
    from source_registry import get_source

    tasks = {t for t in ep.baseline_dag.task_ids if t.startswith(("tier1_core.", "tier2_feeds."))}
    assert set(ep._BASELINE_COLLECTOR_TASKS.values()) == tasks
    for name in ep._BASELINE_COLLECTOR_TASKS:
        assert get_source(name) is not None, name
    # Each task's callable runs the collector under the name the map gives it.
    for name, task_id in ep._BASELINE_COLLECTOR_TASKS.items():
        callable_name = ep.baseline_dag.get_task(task_id).python_callable.__name__
        assert callable_name == f"run_baseline_{'sslblacklist' if name == 'sslbl' else name}", (name, callable_name)


def test_every_required_source_name_with_a_baseline_collector_resolves():
    from source_key_check import KEYED_SOURCES
    from source_registry import get_source

    keyed = {s for k in KEYED_SOURCES for s in k.sources}
    assert keyed - {"otx", "nvd", "threatfox", "urlhaus", "malwarebazaar", "abuseipdb"} == {"virustotal"}
    for name in keyed - {"virustotal"}:
        assert get_source(name) is not None


def test_the_runbook_section_the_failure_names_describes_every_invariant(ep):
    from pathlib import Path

    docs = Path(__file__).resolve().parent.parent / "docs"
    assert ep._POSTCHECK_RUNBOOK == "docs/RUNBOOK.md § 7d"
    runbook = (docs / "RUNBOOK.md").read_text().split("\n## History", 1)[0]
    section = runbook.split("**7d. Postcheck invariant violated.**", 1)[1].split("\n### 8.", 1)[0]
    for invariant in ("INV-1", "INV-2", "INV-3", "INV-4", "INV-5", "INV-6"):
        assert f"| {invariant} |" in section, invariant
    assert "baseline_release_lock" in section and "Accept the graph as it is" in section
    configuration = (docs / "CONFIGURATION.md").read_text().split("\n## History", 1)[0]
    assert "After the run, `baseline_postcheck` fails when a listed source" in configuration
