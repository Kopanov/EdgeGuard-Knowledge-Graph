"""The Neo4j address of the host-side scripts: no remote default.

``scripts/verify_fresh_baseline.py``, ``scripts/run_cypher_catalog_http.py`` and
``scripts/build_canonical_threat_actors.py`` send ``NEO4J_USER`` / ``NEO4J_PASSWORD`` as basic auth
to the Neo4j HTTP Query API. They resolve the address through one helper,
``src/neo4j_http_endpoint.py``: ``NEO4J_HTTP_URL``, then ``NEO4J_HTTP``, else the HTTP port the
``neo4j`` service of ``docker-compose.yml`` publishes on host loopback. A value that is not an
http(s) URL with a host is refused before any request. ``scripts/neo4j_wss_bridge.py`` has no local
equivalent and requires ``NEO4J_WSS_HOST``.

Every caller is driven end to end with ``urllib.request.urlopen`` replaced: the test reads the
request the script would send (address, credentials, User-Agent). Nothing is sent anywhere.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import re
import runpy
import sys
import types
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = _ROOT / "scripts"
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

LOCAL = "http://127.0.0.1:7474"
LOCAL_QUERY_URL = f"{LOCAL}/db/neo4j/query/v2"
REMOTE_MARK = "edgeguard.org"
TEST_USER = "neo4j"
TEST_PASSWORD = "unit-test-password"
EXPECTED_AUTH = "Basic " + base64.b64encode(f"{TEST_USER}:{TEST_PASSWORD}".encode()).decode()
_ENDPOINT_VARS = ("NEO4J_HTTP_URL", "NEO4J_HTTP", "NEO4J_HTTP_USER_AGENT", "NEO4J_DATABASE", "NEO4J_WSS_HOST")


@pytest.fixture
def clean_env(monkeypatch):
    for name in _ENDPOINT_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NEO4J_USER", TEST_USER)
    monkeypatch.setenv("NEO4J_PASSWORD", TEST_PASSWORD)
    return monkeypatch


class _Response:
    def __init__(self, payload: Dict[str, Any]) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False


@pytest.fixture
def sent(monkeypatch) -> List[urllib.request.Request]:
    """Every request a script hands to ``urlopen``; each answers with an empty result."""
    seen: List[urllib.request.Request] = []

    def fake_urlopen(req, timeout=None):  # noqa: ARG001 — signature of urlopen
        seen.append(req)
        return _Response({"data": {"fields": [], "values": []}})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return seen


def _load(script: str, monkeypatch) -> types.ModuleType:
    """A fresh copy of ``scripts/<script>.py``, registered only for the test (dataclasses resolve
    their annotations through ``sys.modules``)."""
    name = f"_endpoint_test_{script}"
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{script}.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, mod)
    spec.loader.exec_module(mod)
    return mod


def _query_verify(mod: types.ModuleType) -> None:
    mod._post("RETURN 1")


def _query_catalog(mod: types.ModuleType) -> None:
    fields, values, err = mod._post("RETURN 1", {})
    assert err is None, err


def _query_actor_export(mod: types.ModuleType) -> None:
    mod._http_query("RETURN 1")


CALLERS = {
    "verify_fresh_baseline": _query_verify,
    "run_cypher_catalog_http": _query_catalog,
    "build_canonical_threat_actors": _query_actor_export,
}


def _only_request(sent: List[urllib.request.Request]) -> urllib.request.Request:
    assert len(sent) == 1, [r.full_url for r in sent]
    return sent[0]


# --------------------------------------------------------------------------- the helper


@pytest.fixture
def endpoint():
    import neo4j_http_endpoint

    return neo4j_http_endpoint


class TestHelper:
    def test_unset_is_the_local_compose_address(self, endpoint):
        assert endpoint.base_url({}) == LOCAL
        assert endpoint.query_api_url({}) == LOCAL_QUERY_URL

    def test_empty_values_count_as_unset(self, endpoint):
        assert endpoint.base_url({"NEO4J_HTTP_URL": "", "NEO4J_HTTP": "  "}) == LOCAL

    def test_neo4j_http_url_first_then_neo4j_http(self, endpoint):
        both = {"NEO4J_HTTP_URL": "https://graph.example.test/", "NEO4J_HTTP": "http://other.example.test:7474"}
        assert endpoint.base_url(both) == "https://graph.example.test"
        assert endpoint.base_url({"NEO4J_HTTP": "http://other.example.test:7474/"}) == "http://other.example.test:7474"

    @pytest.mark.parametrize(
        "value", ["neo4j.example.test:7474", "graph.example.test", "ftp://graph.example.test", "http://"]
    )
    def test_a_value_that_is_no_http_url_is_refused(self, endpoint, value):
        with pytest.raises(endpoint.Neo4jHttpEndpointError, match="NEO4J_HTTP_URL"):
            endpoint.base_url({"NEO4J_HTTP_URL": value})

    def test_database_in_the_path(self, endpoint):
        assert endpoint.query_api_url({"NEO4J_DATABASE": "edgeguard"}) == f"{LOCAL}/db/edgeguard/query/v2"

    def test_request_carries_credentials_and_a_browser_user_agent(self, endpoint):
        env = {"NEO4J_USER": TEST_USER, "NEO4J_PASSWORD": TEST_PASSWORD}
        req = endpoint.query_request(b"{}", env)
        assert req.full_url == LOCAL_QUERY_URL
        assert req.get_method() == "POST"
        assert req.get_header("Authorization") == EXPECTED_AUTH
        assert req.get_header("Content-type") == "application/json"
        assert req.get_header("User-agent").startswith("Mozilla/5.0")
        assert "Python-urllib" not in req.get_header("User-agent")

    def test_user_agent_override(self, endpoint):
        req = endpoint.query_request(b"{}", {"NEO4J_HTTP_USER_AGENT": "edgeguard-test/1"})
        assert req.get_header("User-agent") == "edgeguard-test/1"

    def test_default_is_the_address_docker_compose_publishes(self, endpoint):
        """The default must be exactly the HTTP port the ``neo4j`` service publishes on host
        loopback; a change of the Compose mapping has to change the default."""
        compose = yaml.safe_load((_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        published = []
        for entry in compose["services"]["neo4j"]["ports"]:
            m = re.fullmatch(r"(127\.0\.0\.1):(\d+):7474", str(entry).strip())
            if m:
                published.append(f"http://{m.group(1)}:{m.group(2)}")
        assert published == [endpoint.LOCAL_COMPOSE_HTTP_URL]


def test_only_the_helper_reads_the_http_address():
    """No script or module reads ``NEO4J_HTTP_URL`` / ``NEO4J_HTTP`` / ``NEO4J_HTTP_USER_AGENT``
    itself (where a default of its own could return), and none names the remote host as a value."""
    read = re.compile(r"""(getenv\(|environ\.get\(|environ\[)\s*["']NEO4J_HTTP""")
    offenders = []
    for path in sorted([*_SCRIPTS.glob("*.py"), *_SRC.rglob("*.py")]):
        if path.name == "neo4j_http_endpoint.py":
            continue
        text = path.read_text(encoding="utf-8")
        if read.search(text) or re.search(r"""["'](?:https?://)?[\w.-]*edgeguard\.org""", text):
            offenders.append(str(path.relative_to(_ROOT)))
    assert offenders == []


# --------------------------------------------------------------------------- every caller, end to end


@pytest.mark.parametrize("script", sorted(CALLERS))
class TestCallers:
    def test_unset_sends_the_credentials_to_the_local_address_only(self, script, clean_env, sent):
        CALLERS[script](_load(script, clean_env))
        req = _only_request(sent)
        assert req.full_url == LOCAL_QUERY_URL
        assert REMOTE_MARK not in req.full_url
        assert req.get_header("Authorization") == EXPECTED_AUTH
        assert req.get_header("User-agent").startswith("Mozilla/5.0")

    def test_neo4j_http_url_is_used(self, script, clean_env, sent):
        clean_env.setenv("NEO4J_HTTP_URL", "https://graph.example.test:7473/")
        clean_env.setenv("NEO4J_HTTP", "http://ignored.example.test:7474")
        CALLERS[script](_load(script, clean_env))
        assert _only_request(sent).full_url == "https://graph.example.test:7473/db/neo4j/query/v2"

    def test_neo4j_http_is_used_without_neo4j_http_url(self, script, clean_env, sent):
        clean_env.setenv("NEO4J_HTTP", "http://graph.example.test:7474")
        CALLERS[script](_load(script, clean_env))
        assert _only_request(sent).full_url == "http://graph.example.test:7474/db/neo4j/query/v2"

    def test_the_address_comes_from_the_shared_helper(self, script, clean_env, sent):
        """Patching the helper's default moves every caller: none resolves the address itself."""
        import neo4j_http_endpoint

        clean_env.setattr(neo4j_http_endpoint, "LOCAL_COMPOSE_HTTP_URL", "http://127.0.0.9:17474")
        CALLERS[script](_load(script, clean_env))
        assert _only_request(sent).full_url == "http://127.0.0.9:17474/db/neo4j/query/v2"


class TestVerifyFreshBaselineMain:
    def test_unreachable_names_the_local_address(self, clean_env, monkeypatch, capsys):
        def refused(req, timeout=None):  # noqa: ARG001
            raise urllib.error.URLError("connection refused")

        monkeypatch.setattr(urllib.request, "urlopen", refused)
        monkeypatch.setattr(sys, "argv", ["verify_fresh_baseline.py"])
        rc = _load("verify_fresh_baseline", clean_env).main()
        err = capsys.readouterr().err
        assert rc == 2
        assert LOCAL_QUERY_URL in err
        assert REMOTE_MARK not in err

    def test_invalid_address_exits_2_before_any_request(self, clean_env, sent, monkeypatch, capsys):
        clean_env.setenv("NEO4J_HTTP_URL", "neo4j.example.test:7474")
        monkeypatch.setattr(sys, "argv", ["verify_fresh_baseline.py"])
        rc = _load("verify_fresh_baseline", clean_env).main()
        assert rc == 2
        assert sent == []
        assert "NEO4J_HTTP_URL" in capsys.readouterr().err


class TestCypherCatalogMain:
    def test_report_names_the_local_address(self, clean_env, sent, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(sys, "argv", ["run_cypher_catalog_http.py", "--out", str(tmp_path)])
        rc = _load("run_cypher_catalog_http", clean_env).main()
        assert rc == 0
        assert sent and {r.full_url for r in sent} == {LOCAL_QUERY_URL}
        meta = json.loads((tmp_path / "cypher_catalog_results.json").read_text())["meta"]
        assert meta["endpoint"] == LOCAL_QUERY_URL
        assert LOCAL_QUERY_URL in capsys.readouterr().out

    def test_invalid_address_exits_2_before_any_request(self, clean_env, sent, monkeypatch, capsys):
        clean_env.setenv("NEO4J_HTTP", "graph.example.test")
        monkeypatch.setattr(sys, "argv", ["run_cypher_catalog_http.py"])
        rc = _load("run_cypher_catalog_http", clean_env).main()
        assert rc == 2
        assert sent == []
        assert "NEO4J_HTTP" in capsys.readouterr().err


class TestActorExportMain:
    def test_export_records_the_local_address(self, clean_env, sent, tmp_path):
        out = tmp_path / "graph_threat_actors.json"
        rc = _load("build_canonical_threat_actors", clean_env).main(["--export-graph-actors", str(out)])
        assert rc == 0
        assert _only_request(sent).full_url == LOCAL_QUERY_URL
        assert json.loads(out.read_text())["url"] == LOCAL_QUERY_URL

    def test_invalid_address_exits_2_before_any_request(self, clean_env, sent, tmp_path, capsys):
        clean_env.setenv("NEO4J_HTTP_URL", "ftp://graph.example.test")
        out = tmp_path / "graph_threat_actors.json"
        rc = _load("build_canonical_threat_actors", clean_env).main(["--export-graph-actors", str(out)])
        assert rc == 2
        assert sent == []
        assert not out.exists()
        assert "NEO4J_HTTP_URL" in capsys.readouterr().err


# --------------------------------------------------------------------------- the Bolt-over-WebSocket bridge


class _FakeDriver:
    def __init__(self, uri: str, auth: Any, **kwargs: Any) -> None:
        self.uri, self.auth = uri, auth

    def verify_connectivity(self) -> None:
        return None

    def execute_query(self, *args: Any, **kwargs: Any):
        return [], None, None

    def close(self) -> None:
        return None


@pytest.fixture
def bridge_stubs(monkeypatch):
    """A stand-in ``websocket`` module and a driver factory that records every driver it hands out
    (the bridge passes the credentials to the driver, which sends them through the tunnel)."""
    import neo4j

    drivers: List[_FakeDriver] = []
    dialled: List[str] = []

    def driver(uri, auth=None, **kwargs):
        d = _FakeDriver(uri, auth, **kwargs)
        drivers.append(d)
        return d

    fake_ws = types.ModuleType("websocket")
    fake_ws.create_connection = lambda url, **kwargs: dialled.append(url)  # type: ignore[attr-defined]
    fake_ws.ABNF = types.SimpleNamespace(OPCODE_BINARY=2)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "websocket", fake_ws)
    monkeypatch.setattr(neo4j, "GraphDatabase", types.SimpleNamespace(driver=driver))
    return drivers, dialled


class TestWssBridge:
    def test_unset_host_exits_without_handing_out_the_credentials(self, clean_env, bridge_stubs, capsys):
        drivers, dialled = bridge_stubs
        with pytest.raises(SystemExit) as exit_info:
            runpy.run_path(str(_SCRIPTS / "neo4j_wss_bridge.py"), run_name="__main__")
        captured = capsys.readouterr()
        assert exit_info.value.code == 2
        assert drivers == [] and dialled == []
        assert "NEO4J_WSS_HOST" in captured.err
        assert REMOTE_MARK not in captured.out + captured.err

    def test_set_host_is_the_one_bridged(self, clean_env, bridge_stubs, monkeypatch, capsys):
        clean_env.setenv("NEO4J_WSS_HOST", "bolt.example.test")
        mod = _load("neo4j_wss_bridge", clean_env)
        hosts: List[str] = []

        class RecordingBridge(mod.Neo4jWssBridge):  # type: ignore[name-defined, misc]
            def __init__(self, hostname, auth):
                hosts.append(hostname)
                super().__init__(hostname, auth)

            def connect(self):
                self.driver = _FakeDriver("bolt://127.0.0.1:0", self.auth)
                return self.driver

        monkeypatch.setattr(mod, "Neo4jWssBridge", RecordingBridge)
        assert mod.main() == 0
        assert hosts == ["bolt.example.test"]
        assert "wss://bolt.example.test" in capsys.readouterr().out
