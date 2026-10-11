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

    def test_fragment_spreads_cannot_multiply_root_fields(self, monkeypatch):
        """Bugbot on #151: aliases inside one fragment count once for MaxAliasesLimiter even when the
        fragment is spread many times; the root-field rule expands spreads before counting."""
        monkeypatch.setattr(graphql_api, "_API_KEY", None, raising=False)
        for attr in ("neo4j_client", "client"):
            if hasattr(graphql_api, attr):
                monkeypatch.setattr(graphql_api, attr, _fake_client(MagicMock()))
        spreads = " ".join("...F" for _ in range(graphql_api._GRAPHQL_MAX_ALIASES))
        query = "fragment F on Query { a: tactics { __typename } b: tactics { __typename } } query { " + spreads + " }"
        resp = TestClient(graphql_api.app, raise_server_exceptions=False).post("/graphql", json={"query": query})
        errors = resp.json().get("errors") or []
        assert any("root fields" in (e.get("message") or "") for e in errors), resp.json()
        small = TestClient(graphql_api.app, raise_server_exceptions=False).post(
            "/graphql",
            json={
                "query": "fragment F on Query { a: tactics { __typename } } query { ...F b: tactics { __typename } }"
            },
        )
        assert not any("root fields" in (e.get("message") or "") for e in (small.json().get("errors") or []))
        assert "MaxRootFieldsLimiter" in {type(e).__name__ for e in graphql_api._extensions}

    @pytest.mark.parametrize("shape", ["doubling", "linear"])
    def test_pathological_fragment_chains_are_rejected_quickly(self, monkeypatch, shape):
        """Bugbot on #151 round 2: doubling fragments were exponential and a long linear chain hit
        RecursionError before the cap applied. Both must now be rejected in well under a second."""
        import time

        monkeypatch.setattr(graphql_api, "_API_KEY", None, raising=False)
        for attr in ("neo4j_client", "client"):
            if hasattr(graphql_api, attr):
                monkeypatch.setattr(graphql_api, attr, _fake_client(MagicMock()))
        if shape == "doubling":
            parts = ["fragment F0 on Query { a: tactics { __typename } }"]
            parts += [f"fragment F{i} on Query {{ ...F{i - 1} ...F{i - 1} }}" for i in range(1, 40)]
            query = " ".join(parts) + " query { ...F39 }"
        else:
            parts = ["fragment F0 on Query { a: tactics { __typename } }"]
            parts += [f"fragment F{i} on Query {{ ...F{i - 1} }}" for i in range(1, 400)]
            query = " ".join(parts) + " query { ...F399 }"
        t0 = time.perf_counter()
        resp = TestClient(graphql_api.app, raise_server_exceptions=False).post("/graphql", json={"query": query})
        elapsed = time.perf_counter() - t0
        assert elapsed < 2.0, f"validation took {elapsed:.2f}s"
        assert resp.status_code in (200, 400)
        errors = resp.json().get("errors") or []
        assert any("Query rejected" in (e.get("message") or "") for e in errors), resp.json()

    def test_nesting_depth_is_checked_regardless_of_spread_order(self, monkeypatch):
        """Bugbot on #151 round 3: memoising by name only let a chain spread as F0, F1, …, Fn (each at
        root) escape the nesting check because every fragment was first seen on a short path."""
        monkeypatch.setattr(graphql_api, "_API_KEY", None, raising=False)
        parts = ["fragment F0 on Query { a: tactics { __typename } }"]
        parts += [f"fragment F{i} on Query {{ ...F{i - 1} }}" for i in range(1, 41)]
        query = " ".join(parts) + " query { " + " ".join(f"...F{i}" for i in range(41)) + " }"
        resp = TestClient(graphql_api.app, raise_server_exceptions=False).post("/graphql", json={"query": query})
        errors = resp.json().get("errors") or []
        assert any("nesting deeper" in (e.get("message") or "") for e in errors), resp.json()

    @pytest.mark.parametrize("length", [300, 3000])
    def test_long_linear_chains_never_exhaust_the_stack(self, monkeypatch, length):
        """Bugbot on #151 round 4: the nesting walk recursed the whole chain before comparing with the
        cap. It now stops at the cap, so even a 3,000-fragment chain is a budget rejection, not a 500."""
        monkeypatch.setattr(graphql_api, "_API_KEY", None, raising=False)
        parts = ["fragment F0 on Query { a: tactics { __typename } }"]
        parts += [f"fragment F{i} on Query {{ ...F{i - 1} }}" for i in range(1, length)]
        for root in (f"...F{length - 1}", " ".join(f"...F{i}" for i in range(length))):
            resp = TestClient(graphql_api.app, raise_server_exceptions=False).post(
                "/graphql", json={"query": " ".join(parts) + " query { " + root + " }"}
            )
            assert resp.status_code in (200, 400), resp.status_code
            errors = resp.json().get("errors") or []
            assert any("Query rejected" in (e.get("message") or "") for e in errors), resp.json()

    def test_deeply_nested_plain_fields_are_rejected_before_validation(self, monkeypatch):
        monkeypatch.setattr(graphql_api, "_API_KEY", None, raising=False)
        query = "query { tactics " + "{ a " * 80 + "{ __typename }" + " }" * 80 + " }"
        resp = TestClient(graphql_api.app, raise_server_exceptions=False).post("/graphql", json={"query": query})
        errors = resp.json().get("errors") or []
        assert any("selection nesting" in (e.get("message") or "") for e in errors), resp.json()

    def test_fragment_cycle_is_rejected_before_validation(self, monkeypatch):
        monkeypatch.setattr(graphql_api, "_API_KEY", None, raising=False)
        query = "fragment A on Query { ...B } fragment B on Query { ...A } query { ...A }"
        resp = TestClient(graphql_api.app, raise_server_exceptions=False).post("/graphql", json={"query": query})
        errors = resp.json().get("errors") or []
        assert any("fragment cycle" in (e.get("message") or "") for e in errors), resp.json()

    def test_expanded_count_is_linear_and_exact(self):
        from graphql import parse

        doc = parse(
            "fragment F on Query { a: tactics { __typename } b: tactics { __typename } } query { ...F ...F c: tactics { __typename } }"
        )
        count, problem = graphql_api._expanded_selection_count(doc, 10_000, 16)
        assert problem is None and count == 10  # fragment = 4 selections, spread twice, plus c + __typename

    def test_openapi_routes_are_rate_limited(self):
        for name in ("query_api", "graphql_api"):
            src = (_SRC / f"{name}.py").read_text()
            block = src[src.index('@app.get("/openapi.json"') :]
            assert "@limiter.limit(" in block[: block.index("async def openapi_document")]

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
