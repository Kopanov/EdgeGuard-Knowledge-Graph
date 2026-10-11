"""Partner-surface hardening from the 2026-10 production-readiness check.

REST: ``/search/indicator`` applies its ``zone`` filter (it was accepted and ignored); a Neo4j
outage answers 503 instead of 500; Swagger / ReDoc / OpenAPI are hidden in prod with the OpenAPI
document available to key holders. GraphQL: alias amplification capped, ``limit`` / ``offset``
clamped, request body capped like the REST API.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from neo4j.exceptions import ServiceUnavailable

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault("NEO4J_PASSWORD", "test-password")

import graphql_api  # noqa: E402
import graphql_schema  # noqa: E402
import query_api  # noqa: E402

_SRC = Path(__file__).resolve().parent.parent / "src"


def _fake_client(session: MagicMock) -> MagicMock:
    client = MagicMock()
    client.is_connected.return_value = True
    client.driver.session.return_value.__enter__.return_value = session
    return client


class TestRestSearchZone:
    def test_zone_is_bound_and_applied_in_both_statements(self, monkeypatch):
        session = MagicMock()
        session.run.return_value.single.return_value = None  # not found → no related lookup
        monkeypatch.setattr(query_api, "neo4j_client", _fake_client(session))
        monkeypatch.setattr(query_api, "_API_KEY", None)
        resp = TestClient(query_api.app).post("/search/indicator", json={"value": "1.2.3.4", "zone": "energy"})
        assert resp.status_code == 200 and resp.json()["found"] is False
        first = session.run.call_args_list[0]
        assert "$zone IN coalesce(n.zone, [])" in first.args[0] and first.kwargs["zone"] == "energy"

    def test_without_zone_the_filter_is_a_no_op(self, monkeypatch):
        session = MagicMock()
        session.run.return_value.single.return_value = None
        monkeypatch.setattr(query_api, "neo4j_client", _fake_client(session))
        monkeypatch.setattr(query_api, "_API_KEY", None)
        TestClient(query_api.app).post("/search/indicator", json={"value": "1.2.3.4"})
        assert session.run.call_args_list[0].kwargs["zone"] is None
        assert "$zone IS NULL OR" in session.run.call_args_list[0].args[0]


class TestRestOutageStatus:
    def test_neo4j_unavailable_is_503(self, monkeypatch):
        session = MagicMock()
        session.run.side_effect = ServiceUnavailable("connection refused")
        monkeypatch.setattr(query_api, "neo4j_client", _fake_client(session))
        monkeypatch.setattr(query_api, "_API_KEY", None)
        resp = TestClient(query_api.app, raise_server_exceptions=False).get("/indicators")
        assert resp.status_code == 503 and "unavailable" in resp.json()["detail"].lower()

    def test_other_errors_stay_500(self, monkeypatch):
        session = MagicMock()
        session.run.side_effect = RuntimeError("boom")
        monkeypatch.setattr(query_api, "neo4j_client", _fake_client(session))
        monkeypatch.setattr(query_api, "_API_KEY", None)
        resp = TestClient(query_api.app, raise_server_exceptions=False).get("/indicators")
        assert resp.status_code == 500 and "boom" not in resp.text

    def test_every_handler_routes_through_the_helper(self):
        src = (_SRC / "query_api.py").read_text()
        assert src.count("_raise_api_error(") >= 11  # 8 uniform handlers + /query + /admin/query + definition
        assert 'except Exception:\n        logger.error("' not in src


def _load_prod_module(monkeypatch, name: str):
    """Load query_api / graphql_api as an independent module in prod mode (no shared state)."""
    monkeypatch.setenv("EDGEGUARD_ENV", "prod")
    monkeypatch.setenv("EDGEGUARD_API_KEY", "prod-test-key-1234567890")
    monkeypatch.setenv("EDGEGUARD_API_HOST", "127.0.0.1")
    monkeypatch.setenv("EDGEGUARD_GRAPHQL_HOST", "127.0.0.1")
    spec = importlib.util.spec_from_file_location(f"{name}_prod_test", _SRC / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod  # Strawberry resolves type hints through sys.modules
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(spec.name, None)
    return mod


class TestDocsHiddenInProd:
    @pytest.mark.parametrize("name", ["query_api", "graphql_api"])
    def test_swagger_and_redoc_hidden_openapi_behind_key(self, monkeypatch, name):
        mod = _load_prod_module(monkeypatch, name)
        assert mod.app.docs_url is None and mod.app.redoc_url is None and mod.app.openapi_url is None
        client = TestClient(mod.app, raise_server_exceptions=False)
        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404
        assert client.get("/openapi.json").status_code == 401
        ok = client.get("/openapi.json", headers={"X-API-Key": "prod-test-key-1234567890"})
        assert ok.status_code == 200 and "openapi" in ok.json()

    def test_dev_keeps_the_interactive_docs(self):
        assert query_api.app.docs_url == "/docs" and graphql_api.app.docs_url == "/docs"


class TestGraphQLLimits:
    def test_alias_limiter_is_installed_and_fires(self, monkeypatch):
        names = {type(e).__name__ for e in graphql_api._extensions}
        assert {"QueryDepthLimiter", "MaxAliasesLimiter"} <= names
        monkeypatch.setattr(graphql_api, "_API_KEY", None, raising=False)
        for attr in ("neo4j_client", "client"):
            if hasattr(graphql_api, attr):
                monkeypatch.setattr(graphql_api, attr, _fake_client(MagicMock()))
        aliases = " ".join(f"a{i}: tactics {{ __typename }}" for i in range(graphql_api._GRAPHQL_MAX_ALIASES + 5))
        resp = TestClient(graphql_api.app, raise_server_exceptions=False).post(
            "/graphql", json={"query": "{ " + aliases + " }"}
        )
        body = resp.json()
        assert body.get("errors"), body
        assert any("alias" in (e.get("message") or "").lower() for e in body["errors"])

    @pytest.mark.parametrize(
        "limit, offset, exp_limit, exp_offset",
        [
            (-5, -7, 1, 0),
            (0, 5, 1, 5),
            (10_000, 10**9, graphql_api._MAX_GRAPHQL_LIMIT, graphql_api._MAX_GRAPHQL_OFFSET),
            (20, 3, 20, 3),
        ],
    )
    def test_limit_and_offset_are_clamped(self, limit, offset, exp_limit, exp_offset):
        assert graphql_api._clamp_limit(limit) == exp_limit
        assert graphql_api._clamp_offset(offset) == exp_offset
        session = MagicMock()
        session.run.return_value = iter([])
        client = _fake_client(session)
        f = graphql_schema.IndicatorFilter(limit=limit, offset=offset)
        graphql_api._resolve_indicators(client, f)
        kwargs = session.run.call_args.kwargs
        assert kwargs["limit"] == exp_limit and kwargs["offset"] == exp_offset

    def test_body_cap_returns_413(self, monkeypatch):
        monkeypatch.setattr(graphql_api, "_MAX_BODY_BYTES", 64)
        resp = TestClient(graphql_api.app, raise_server_exceptions=False).post(
            "/graphql", json={"query": "{ __typename }", "pad": "x" * 500}
        )
        assert resp.status_code == 413

    @pytest.mark.parametrize("raw, expected", [(None, 15), ("", 15), ("abc", 15), ("0", 15), ("40", 40)])
    def test_alias_limit_env_guard(self, monkeypatch, raw, expected):
        if raw is None:
            monkeypatch.delenv("EDGEGUARD_GRAPHQL_MAX_ALIASES", raising=False)
        else:
            monkeypatch.setenv("EDGEGUARD_GRAPHQL_MAX_ALIASES", raw)
        assert graphql_api._env_positive_int("EDGEGUARD_GRAPHQL_MAX_ALIASES", 15) == expected
