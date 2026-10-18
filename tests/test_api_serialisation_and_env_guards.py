"""REST timestamps as ISO-8601, null-safe ordering, empty-environment guards (2026-10).

Measured before the fix: FastAPI's encoder fell back to ``vars()`` on ``neo4j.time`` objects, so
``last_updated`` left the REST API as ``{"_DateTime__date": {...}, "_DateTime__time": {...}}``.
Neo4j sorts NULL first in ``ORDER BY … DESC``, so unscored vulnerabilities led every ranked list.
An empty forwarded ``EDGEGUARD_GRAPHQL_MAX_DEPTH`` raised at import; an empty rate-limit string
reached ``Limiter.limit("")``.
"""

from __future__ import annotations

import inspect
import os
import re
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault("NEO4J_PASSWORD", "test-password")

from fastapi.testclient import TestClient  # noqa: E402
from neo4j.time import Date, DateTime, Duration, Time  # noqa: E402

import graphql_api  # noqa: E402
import query_api  # noqa: E402


class TestNodePropsSerialisation:
    def test_temporal_values_become_iso_strings(self):
        dt = DateTime(2026, 10, 11, 8, 30, 15, 500_000_000)
        props = query_api._node_props(
            {
                "last_updated": dt,
                "first_seen": Date(2026, 1, 2),
                "at": Time(1, 2, 3, 0),
                "ttl": Duration(days=1),
                "history": [dt, "x", 3],
                "value": "1.2.3.4",
                "confidence_score": 0.6,
                "active": True,
                "zone": ["energy"],
            }
        )
        assert props["last_updated"] == "2026-10-11T08:30:15.500000000"
        assert props["first_seen"] == "2026-01-02"
        assert props["at"] == "01:02:03.000000000"
        assert props["ttl"] == "P1D"
        assert props["history"] == ["2026-10-11T08:30:15.500000000", "x", 3]
        assert props["value"] == "1.2.3.4" and props["confidence_score"] == 0.6 and props["active"] is True
        assert props["zone"] == ["energy"]

    def test_none_and_timezone_aware(self):
        assert query_api._node_props(None) == {}
        from datetime import timedelta, timezone

        aware = DateTime(2026, 10, 11, 8, 0, 0, 0, tzinfo=timezone(timedelta(hours=2)))
        assert query_api._node_props({"t": aware})["t"] == "2026-10-11T08:00:00.000000000+02:00"

    def test_every_raw_record_dict_site_goes_through_the_helper(self):
        src = inspect.getsource(query_api)
        assert not re.search(r"\bdict\((?:record|r)\[\"(?:n|related|actor)\"\]", src), (
            "a REST endpoint still returns raw dict(record[...]) — route it through _node_props"
        )
        assert src.count("_node_props(") >= 8  # definition + 7 call sites

    def test_route_returns_iso_timestamps(self, monkeypatch):
        """End to end: ``GET /indicators`` with a fake driver whose record carries a Neo4j DateTime."""
        dt = DateTime(2026, 10, 11, 8, 30, 0, 0)
        record = {"n": {"value": "1.2.3.4", "indicator_type": "ipv4", "last_updated": dt, "first_imported_at": dt}}
        count = MagicMock()
        count.single.return_value = {"total": 1}
        session = MagicMock()
        session.run.side_effect = [iter([record]), count]
        fake_client = MagicMock()
        fake_client.is_connected.return_value = True
        fake_client.driver.session.return_value.__enter__.return_value = session
        monkeypatch.setattr(query_api, "neo4j_client", fake_client)
        monkeypatch.setattr(query_api, "_API_KEY", None)
        resp = TestClient(query_api.app).get("/indicators")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 1
        assert body["indicators"][0]["last_updated"] == "2026-10-11T08:30:00.000000000"
        assert "_DateTime__date" not in resp.text


class TestNullSafeOrdering:
    def test_rest_orders_with_coalesce(self):
        src = inspect.getsource(query_api)
        assert "ORDER BY n.cvss_score DESC" not in src
        assert "ORDER BY n.confidence_score DESC" not in src
        assert "ORDER BY coalesce(n.cvss_score, -1) DESC" in src
        assert "ORDER BY coalesce(n.confidence_score, -1) DESC" in src

    def test_graphql_orders_with_coalesce(self):
        src = inspect.getsource(graphql_api)
        assert "ORDER BY n.cvss_score DESC" not in src
        assert "ORDER BY n.confidence_score DESC" not in src
        assert src.count("ORDER BY coalesce(n.cvss_score, -1) DESC") == 1
        assert src.count("ORDER BY coalesce(n.confidence_score, -1) DESC") == 3


class TestEmptyEnvironmentGuards:
    @pytest.mark.parametrize(
        "raw, expected", [(None, "60/minute"), ("", "60/minute"), ("  ", "60/minute"), (" 5/minute ", "5/minute")]
    )
    def test_rate_limit_string(self, monkeypatch, raw, expected):
        if raw is None:
            monkeypatch.delenv("EDGEGUARD_RATE_LIMIT_READ", raising=False)
        else:
            monkeypatch.setenv("EDGEGUARD_RATE_LIMIT_READ", raw)
        assert query_api._env_rate_limit("EDGEGUARD_RATE_LIMIT_READ", "60/minute") == expected

    @pytest.mark.parametrize(
        "raw, expected",
        [
            (None, "120/minute"),
            ("", "120/minute"),
            ("  ", "120/minute"),
            (" 600/minute ", "600/minute"),
            ("10/second;600/minute", "10/second;600/minute"),
            ("abc", "120/minute"),
            ("600 a minute", "120/minute"),
        ],
    )
    def test_graphql_rate_limit_string(self, monkeypatch, raw, expected):
        if raw is None:
            monkeypatch.delenv("EDGEGUARD_RATE_LIMIT_GRAPHQL", raising=False)
        else:
            monkeypatch.setenv("EDGEGUARD_RATE_LIMIT_GRAPHQL", raw)
        assert graphql_api._graphql_rate_limit() == expected

    def test_the_graphql_limiter_and_routes_use_the_setting(self):
        src = inspect.getsource(graphql_api)
        assert 'default_limits=["120/minute"]' not in src
        assert '@limiter.limit("120/minute")' not in src
        assert "default_limits=[_GRAPHQL_RATE_LIMIT]" in src

    @pytest.mark.parametrize(
        "raw, expected", [(None, 8), ("", 8), (" ", 8), ("abc", 8), ("0", 8), ("-3", 8), ("12", 12), (" 6 ", 6)]
    )
    def test_graphql_max_depth(self, monkeypatch, raw, expected):
        if raw is None:
            monkeypatch.delenv("EDGEGUARD_GRAPHQL_MAX_DEPTH", raising=False)
        else:
            monkeypatch.setenv("EDGEGUARD_GRAPHQL_MAX_DEPTH", raw)
        assert graphql_api._env_graphql_max_depth() == expected

    def test_module_level_values_use_the_guards(self):
        assert "_env_rate_limit(" in inspect.getsource(query_api)
        assert 'int(os.getenv("EDGEGUARD_GRAPHQL_MAX_DEPTH"' not in inspect.getsource(graphql_api)
        assert 4 <= graphql_api._GRAPHQL_MAX_DEPTH <= 16
