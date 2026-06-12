"""Tests for GET /export/wazuh/cdb — the first Wazuh integration deliverable
(2026-06, Stage-2): sector-specific IOC/CVE intelligence exported as
Wazuh-consumable CDB lists (one ``key:value`` per line; keys must not
contain ':').

Follows the mocked-client pattern of test_ioc_normalize_and_actor_summary.py.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault("NEO4J_PASSWORD", "test-password")
os.environ.setdefault("EDGEGUARD_ENV", "dev")

from fastapi.testclient import TestClient

import query_api

client = TestClient(query_api.app)


class _FakeResult:
    def __init__(self, rows=None, single_record=None):
        self._rows = rows or []
        self._single = single_record

    def single(self):
        return self._single

    def __iter__(self):
        return iter(self._rows)


class _FakeSession:
    def __init__(self, results=None):
        self.calls = []
        self._results = list(results or [])

    def run(self, query, **params):
        self.calls.append((query, params))
        return self._results.pop(0) if self._results else _FakeResult()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self, **kwargs):
        return self._session


class _FakeNeo4jClient:
    def __init__(self, session):
        self.driver = _FakeDriver(session)

    def is_connected(self):
        return True


def _install(monkeypatch, rows):
    session = _FakeSession(results=[_FakeResult(rows=rows)])
    monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(session))
    return session


_IND_ROWS = [
    {"key": "1.2.3.4", "type": "ipv4", "confidence": 0.8},
    {"key": "evil.com", "type": "domain", "confidence": 0.55},
]


class TestAuth:
    def test_missing_key_rejected_when_configured(self, monkeypatch):
        monkeypatch.setattr(query_api, "_API_KEY", "secret-key-123")
        _install(monkeypatch, _IND_ROWS)
        resp = client.get("/export/wazuh/cdb")
        assert resp.status_code == 401

    def test_valid_key_accepted(self, monkeypatch):
        monkeypatch.setattr(query_api, "_API_KEY", "secret-key-123")
        _install(monkeypatch, _IND_ROWS)
        resp = client.get("/export/wazuh/cdb", headers={"X-API-Key": "secret-key-123"})
        assert resp.status_code == 200


class TestIndicatorCdbFormat:
    def test_lines_are_key_colon_value(self, monkeypatch):
        _install(monkeypatch, _IND_ROWS)
        resp = client.get("/export/wazuh/cdb?list=indicators")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        lines = resp.text.strip().split("\n")
        assert lines == [
            "1.2.3.4:type=ipv4 confidence=0.80",
            "evil.com:type=domain confidence=0.55",
        ]

    def test_colon_keys_skipped_with_header(self, monkeypatch):
        # url + ipv6 keys contain ':' — CDB splits on the FIRST colon, so
        # exporting them would corrupt the key. They must be skipped and
        # counted, never emitted.
        rows = [
            {"key": "http://evil.com/x", "type": "url", "confidence": 0.9},
            {"key": "2001:db8::1", "type": "ipv6", "confidence": 0.9},
            {"key": "8.8.8.8", "type": "ipv4", "confidence": 0.9},
            {"key": None, "type": "ipv4", "confidence": 0.9},
            {"key": "   ", "type": "ipv4", "confidence": 0.9},
        ]
        _install(monkeypatch, rows)
        resp = client.get("/export/wazuh/cdb")
        assert resp.text == "8.8.8.8:type=ipv4 confidence=0.90\n"
        assert resp.headers["X-EdgeGuard-Entries"] == "1"
        assert resp.headers["X-EdgeGuard-Skipped"] == "4"

    def test_missing_confidence_omits_fragment(self, monkeypatch):
        _install(monkeypatch, [{"key": "evil.com", "type": "domain", "confidence": None}])
        resp = client.get("/export/wazuh/cdb")
        assert resp.text == "evil.com:type=domain\n"

    def test_value_side_sanitized(self, monkeypatch):
        # A weird stored type containing ':' must not produce a parsable
        # second colon group.
        _install(monkeypatch, [{"key": "evil.com", "type": "do:main", "confidence": 0.5}])
        resp = client.get("/export/wazuh/cdb")
        assert resp.text == "evil.com:type=do_main confidence=0.50\n"


class TestFilters:
    def test_zone_and_type_and_confidence_pass_through(self, monkeypatch):
        session = _install(monkeypatch, [])
        resp = client.get("/export/wazuh/cdb?list=indicators&zone=healthcare&indicator_type=ipv4&min_confidence=0.7")
        assert resp.status_code == 200
        query, params = session.calls[0]
        assert "$zone IN n.zone" in query
        assert "n.indicator_type = $indicator_type" in query
        assert "n.confidence_score >= $min_confidence" in query
        assert "n.edgeguard_managed = true" in query
        assert params["zone"] == "healthcare"
        assert params["indicator_type"] == "ipv4"
        assert params["min_confidence"] == 0.7

    def test_active_only_export(self, monkeypatch):
        # Operational blocklist: decay-retired indicators must drop out.
        session = _install(monkeypatch, [])
        client.get("/export/wazuh/cdb")
        query, _ = session.calls[0]
        assert "coalesce(n.active, true) = true" in query

    def test_capped_query(self, monkeypatch):
        session = _install(monkeypatch, [])
        client.get("/export/wazuh/cdb")
        query, params = session.calls[0]
        assert "LIMIT $cap" in query
        assert params["cap"] == query_api._CDB_EXPORT_MAX_ENTRIES


class TestCveCdbFormat:
    def test_cve_lines_with_kev(self, monkeypatch):
        rows = [
            {"key": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0, "kev": "2021-12-10"},
            {"key": "CVE-2026-1234", "severity": "HIGH", "cvss": 8.1, "kev": None},
            {"key": None, "severity": "LOW", "cvss": 2.0, "kev": None},
        ]
        session = _install(monkeypatch, rows)
        resp = client.get("/export/wazuh/cdb?list=cves&zone=energy")
        lines = resp.text.strip().split("\n")
        assert lines == [
            "CVE-2021-44228:severity=CRITICAL cvss=10.0 kev=2021-12-10",
            "CVE-2026-1234:severity=HIGH cvss=8.1",
        ]
        assert resp.headers["X-EdgeGuard-Skipped"] == "1"
        query, params = session.calls[0]
        assert "n:CVE" in query
        assert params["zone"] == "energy"
        # CVE query must not reference the indicator-only filter param.
        assert "indicator_type" not in params

    def test_cve_filename(self, monkeypatch):
        _install(monkeypatch, [])
        resp = client.get("/export/wazuh/cdb?list=cves&zone=energy")
        assert resp.headers["Content-Disposition"] == 'attachment; filename="edgeguard_energy_cves.cdb"'


class TestEdges:
    def test_empty_result_is_empty_200(self, monkeypatch):
        _install(monkeypatch, [])
        resp = client.get("/export/wazuh/cdb")
        assert resp.status_code == 200
        assert resp.text == ""
        assert resp.headers["X-EdgeGuard-Entries"] == "0"
        assert resp.headers["Content-Disposition"] == 'attachment; filename="edgeguard_all_indicators.cdb"'

    def test_invalid_list_rejected(self, monkeypatch):
        _install(monkeypatch, [])
        resp = client.get("/export/wazuh/cdb?list=bogus")
        assert resp.status_code == 422

    def test_invalid_zone_rejected(self, monkeypatch):
        _install(monkeypatch, [])
        resp = client.get("/export/wazuh/cdb?zone=mars")
        assert resp.status_code == 422

    def test_503_when_neo4j_down(self, monkeypatch):
        monkeypatch.setattr(query_api, "neo4j_client", None)
        resp = client.get("/export/wazuh/cdb")
        assert resp.status_code == 503


class TestSharedFilterHelpers:
    """The CDB export must reuse the EXACT filter logic of the JSON
    endpoints — pin the shared helpers so a fix in one path cannot
    silently miss the other (the reason the helpers were factored)."""

    def test_indicator_helper_used_by_both_routes(self):
        import inspect

        src_list = inspect.getsource(query_api.list_indicators)
        src_cdb = inspect.getsource(query_api.export_wazuh_cdb)
        assert "_indicator_filter_conditions(" in src_list
        assert "_indicator_filter_conditions(" in src_cdb

    def test_vulnerability_helper_used_by_both_routes(self):
        import inspect

        src_list = inspect.getsource(query_api.list_vulnerabilities)
        src_cdb = inspect.getsource(query_api.export_wazuh_cdb)
        assert "_vulnerability_filter_conditions(" in src_list
        assert "_vulnerability_filter_conditions(" in src_cdb
