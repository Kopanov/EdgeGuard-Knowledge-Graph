"""Airflow REST client: Airflow 3 ``/api/v2`` with bearer tokens, ``v1`` compatibility,
credential discovery, run-id encoding, and the liveness safeguard's degraded-state report."""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml

import airflow_client

_ROOT = Path(__file__).resolve().parents[1]


class _Resp:
    def __init__(self, status: int = 200, body: Optional[Dict[str, Any]] = None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.content = json.dumps(self._body).encode()

    def json(self) -> Dict[str, Any]:
        return self._body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise airflow_client.requests.exceptions.HTTPError(f"{self.status_code}")


class _FakeHttp:
    """Records every request; answers from a (method, url-suffix) → response table."""

    def __init__(self):
        self.calls: List[Dict[str, Any]] = []
        self.routes: Dict[tuple, Any] = {}

    def route(self, method: str, suffix: str, response):
        self.routes[(method.upper(), suffix)] = response

    def __call__(self, method: str, url: str, **kwargs):
        self.calls.append({"method": method.upper(), "url": url, **kwargs})
        for (m, suffix), response in self.routes.items():
            if m == method.upper() and url.split("?")[0].endswith(suffix):
                return response() if callable(response) else response
        return _Resp(404, {"detail": "not found"})

    def of(self, method: str, suffix: str) -> List[Dict[str, Any]]:
        return [c for c in self.calls if c["method"] == method.upper() and c["url"].split("?")[0].endswith(suffix)]


@pytest.fixture
def http(monkeypatch):
    fake = _FakeHttp()
    monkeypatch.setattr(airflow_client.requests, "request", fake)
    airflow_client._reset_token_cache()
    airflow_client._cached_dag_ids = None
    for var in (
        "AIRFLOW_API_VERSION",
        "AIRFLOW_API_USER",
        "AIRFLOW_API_PASSWORD",
        "AIRFLOW__CORE__SIMPLE_AUTH_MANAGER_PASSWORDS_FILE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AIRFLOW_WEBSERVER_URL", "http://airflow.test:8082")
    monkeypatch.setenv("AIRFLOW_HOME", "/nonexistent-airflow-home")
    yield fake
    airflow_client._reset_token_cache()


def _runs_response():
    return _Resp(
        200,
        {
            "dag_runs": [{"dag_run_id": "manual__1", "state": "running", "start_date": "2026-10-11T03:00:00Z"}],
            "total_entries": 1,
        },
    )


class TestV2BearerFlow:
    def test_token_is_obtained_once_and_sent_as_bearer(self, http, monkeypatch):
        monkeypatch.setenv("AIRFLOW_API_USER", "admin")
        monkeypatch.setenv("AIRFLOW_API_PASSWORD", "secret-value")
        http.route("POST", "/auth/token", _Resp(201, {"access_token": "jwt-1"}))
        http.route("GET", "/api/v2/dags/edgeguard_pipeline/dagRuns", _runs_response)

        runs = airflow_client.list_dag_runs("edgeguard_pipeline", state="running")
        airflow_client.list_dag_runs("edgeguard_pipeline", state="queued")

        assert runs[0]["state"] == "running"
        tokens = http.of("POST", "/auth/token")
        assert len(tokens) == 1 and tokens[0]["json"] == {"username": "admin", "password": "secret-value"}
        assert "auth" not in tokens[0]
        gets = http.of("GET", "/api/v2/dags/edgeguard_pipeline/dagRuns")
        assert len(gets) == 2
        assert all(g["headers"]["Authorization"] == "Bearer jwt-1" for g in gets)
        assert gets[0]["params"]["state"] == "running" and gets[0]["params"]["order_by"] == "-start_date"
        assert all("auth" not in g for g in gets), "v2 must not send Basic credentials"

    def test_expired_token_is_refreshed_once_after_401(self, http, monkeypatch):
        monkeypatch.setenv("AIRFLOW_API_PASSWORD", "secret-value")
        issued = iter(["jwt-old", "jwt-new"])
        http.route("POST", "/auth/token", lambda: _Resp(201, {"access_token": next(issued)}))
        answers = iter([_Resp(401, {"detail": "expired"}), _runs_response()])
        http.route("GET", "/api/v2/dags/d/dagRuns", lambda: next(answers))

        runs = airflow_client.list_dag_runs("d")

        assert runs[0]["dag_run_id"] == "manual__1"
        gets = http.of("GET", "/api/v2/dags/d/dagRuns")
        assert [g["headers"]["Authorization"] for g in gets] == ["Bearer jwt-old", "Bearer jwt-new"]
        assert len(http.of("POST", "/auth/token")) == 2

    def test_rejected_credentials_become_an_error_envelope(self, http, monkeypatch):
        monkeypatch.setenv("AIRFLOW_API_PASSWORD", "wrong")
        http.route("POST", "/auth/token", _Resp(401, {"detail": "Invalid credentials"}))
        result = airflow_client._get("/dags")
        assert "error" in result and "rejected" in result["error"] and "admin" in result["error"]
        assert http.of("GET", "/api/v2/dags") == [], "no API call without a token"

    def test_missing_credentials_are_reported_without_calling_the_api(self, http):
        result = airflow_client.list_dag_runs("d")
        assert "error" in result[0] and "AIRFLOW_API_USER/AIRFLOW_API_PASSWORD" in result[0]["error"]
        assert http.calls == []

    def test_default_user_is_admin_for_v2(self, http, monkeypatch):
        monkeypatch.setenv("AIRFLOW_API_PASSWORD", "secret-value")
        http.route("POST", "/auth/token", _Resp(201, {"access_token": "t"}))
        http.route("GET", "/api/v2/dags", _Resp(200, {"dags": []}))
        airflow_client._get("/dags")
        assert http.of("POST", "/auth/token")[0]["json"]["username"] == "admin"


class TestCredentialDiscovery:
    def test_generated_password_file_is_used_when_env_password_is_unset(self, http, monkeypatch, tmp_path):
        (tmp_path / "simple_auth_manager_passwords.json.generated").write_text(json.dumps({"admin": "generated-pw"}))
        monkeypatch.setenv("AIRFLOW_HOME", str(tmp_path))
        monkeypatch.setenv("AIRFLOW_API_USER", "airflow")  # the compose default before this change; not in the file
        http.route("POST", "/auth/token", _Resp(201, {"access_token": "t"}))
        http.route("GET", "/api/v2/dags", _Resp(200, {"dags": []}))

        assert "error" not in airflow_client._get("/dags")
        assert http.of("POST", "/auth/token")[0]["json"] == {"username": "admin", "password": "generated-pw"}

    def test_explicit_file_override_and_preferred_user(self, http, monkeypatch, tmp_path):
        pw_file = tmp_path / "pw.json"
        pw_file.write_text(json.dumps({"admin": "a", "ops": "o"}))
        monkeypatch.setenv("AIRFLOW__CORE__SIMPLE_AUTH_MANAGER_PASSWORDS_FILE", str(pw_file))
        monkeypatch.setenv("AIRFLOW_API_USER", "ops")
        http.route("POST", "/auth/token", _Resp(201, {"access_token": "t"}))
        http.route("GET", "/api/v2/dags", _Resp(200, {"dags": []}))
        airflow_client._get("/dags")
        assert http.of("POST", "/auth/token")[0]["json"] == {"username": "ops", "password": "o"}

    def test_env_password_wins_over_the_file(self, http, monkeypatch, tmp_path):
        (tmp_path / "simple_auth_manager_passwords.json.generated").write_text(json.dumps({"admin": "generated-pw"}))
        monkeypatch.setenv("AIRFLOW_HOME", str(tmp_path))
        monkeypatch.setenv("AIRFLOW_API_PASSWORD", "env-pw")
        http.route("POST", "/auth/token", _Resp(201, {"access_token": "t"}))
        http.route("GET", "/api/v2/dags", _Resp(200, {"dags": []}))
        airflow_client._get("/dags")
        assert http.of("POST", "/auth/token")[0]["json"]["password"] == "env-pw"


class TestV1Compatibility:
    def test_v1_uses_basic_auth_and_the_v1_prefix(self, http, monkeypatch):
        monkeypatch.setenv("AIRFLOW_API_VERSION", "v1")
        monkeypatch.setenv("AIRFLOW_API_PASSWORD", "pw")
        http.route("GET", "/api/v1/dags/d/dagRuns", _runs_response)
        runs = airflow_client.list_dag_runs("d")
        assert runs[0]["state"] == "running"
        call = http.of("GET", "/api/v1/dags/d/dagRuns")[0]
        assert call["auth"] == ("airflow", "pw")
        assert "headers" not in call or "Authorization" not in (call.get("headers") or {})
        assert http.of("POST", "/auth/token") == []

    def test_unsupported_version_falls_back_to_v2(self, http, monkeypatch, caplog):
        monkeypatch.setenv("AIRFLOW_API_VERSION", "v9")
        with caplog.at_level(logging.WARNING, logger="airflow_client"):
            assert airflow_client._api_version() == "v2"
        assert any("AIRFLOW_API_VERSION" in r.message for r in caplog.records)


class TestHealthAndPaths:
    def test_health_v2_is_unauthenticated_monitor_endpoint(self, http):
        http.route(
            "GET",
            "/api/v2/monitor/health",
            _Resp(200, {"metadatabase": {"status": "healthy"}, "scheduler": {"status": "healthy"}}),
        )
        health = airflow_client.airflow_health()
        assert health["scheduler"]["status"] == "healthy"
        call = http.of("GET", "/api/v2/monitor/health")[0]
        assert call.get("auth") is None and "headers" not in call
        assert http.of("POST", "/auth/token") == []

    def test_health_v1_is_root_health(self, http, monkeypatch):
        monkeypatch.setenv("AIRFLOW_API_VERSION", "v1")
        http.route("GET", "/health", _Resp(200, {"metadatabase": {"status": "healthy"}}))
        assert "error" not in airflow_client.airflow_health()
        assert http.of("GET", "/health")[0]["url"] == "http://airflow.test:8082/health"

    def test_run_ids_are_percent_encoded_in_paths(self, http, monkeypatch):
        monkeypatch.setenv("AIRFLOW_API_PASSWORD", "pw")
        http.route("POST", "/auth/token", _Resp(201, {"access_token": "t"}))
        run_id = "scheduled__2026-10-11T03:00:00+00:00"
        http.route("GET", "/dagRuns/scheduled__2026-10-11T03%3A00%3A00%2B00%3A00", _Resp(200, {"state": "running"}))
        http.route("PATCH", "/dagRuns/scheduled__2026-10-11T03%3A00%3A00%2B00%3A00", _Resp(200, {"state": "failed"}))

        assert airflow_client.get_dag_run("edgeguard_daily", run_id)["state"] == "running"
        assert airflow_client.patch_dag_run_state("edgeguard_daily", run_id)["state"] == "failed"
        urls = [c["url"] for c in http.calls if "dagRuns" in c["url"]]
        assert all("+" not in u.split("/api/v2", 1)[1] for u in urls)

    def test_liveness_probe_encodes_the_run_id(self, http, monkeypatch):
        from parent_dag_liveness import _probe_dag_run_state

        monkeypatch.setenv("AIRFLOW_API_PASSWORD", "pw")
        http.route("POST", "/auth/token", _Resp(201, {"access_token": "t"}))
        http.route("GET", "/dagRuns/scheduled__2026-10-11T03%3A00%3A00%2B00%3A00", _Resp(200, {"state": "running"}))
        assert _probe_dag_run_state("edgeguard_daily", "scheduled__2026-10-11T03:00:00+00:00") == "running"

    def test_connection_error_is_an_error_envelope(self, http, monkeypatch):
        monkeypatch.setenv("AIRFLOW_API_PASSWORD", "pw")

        def boom(*_a, **_k):
            raise airflow_client.requests.exceptions.ConnectionError("refused")

        monkeypatch.setattr(airflow_client.requests, "request", boom)
        result = airflow_client._get("/dags")
        assert "Cannot connect" in result["error"]


class TestLivenessDegradedReport:
    def test_error_is_logged_once_after_consecutive_probe_failures_and_resets(self, monkeypatch, caplog):
        from unittest.mock import patch

        from parent_dag_liveness import make_liveness_callback

        monkeypatch.setenv("EDGEGUARD_PARENT_DAG_LIVENESS_CHECK", "true")
        cb = make_liveness_callback("dag_x", "run_y", throttle_sec=0)
        answers = iter([{"error": "401"}] * 4 + [{"state": "running"}] + [{"error": "401"}] * 3)
        with patch("airflow_client._get", side_effect=lambda *a, **k: next(answers)), caplog.at_level(logging.WARNING):
            for _ in range(8):
                cb()  # never raises: the safeguard stays fail-open
        errors = [
            r for r in caplog.records if r.levelno == logging.ERROR and "PARENT_DAG_LIVENESS_DEGRADED" in r.message
        ]
        assert len(errors) == 2, "one ERROR per streak of three failures (streak reset by the successful probe)"
        assert "dag_x/run_y" in errors[0].message


class TestDeploymentContract:
    def test_compose_defaults_match_the_client(self):
        compose = yaml.safe_load((_ROOT / "docker-compose.yml").read_text())
        env = compose["services"]["airflow"]["environment"]
        assert env["AIRFLOW_API_USER"] == "${AIRFLOW_API_USER:-admin}"
        assert "AIRFLOW_API_VERSION" in env

    def test_env_example_and_readme_document_the_v2_credentials(self):
        env_example = (_ROOT / ".env.example").read_text()
        for name in ("AIRFLOW_API_USER", "AIRFLOW_API_PASSWORD", "AIRFLOW_API_VERSION", "AIRFLOW_WEBSERVER_URL"):
            assert re.search(rf"^# ?{name}=", env_example, re.M), name
        readme = (_ROOT / "README.md").read_text()
        assert "/auth/token" in readme and "AIRFLOW_API_VERSION" in readme
        assert "basic-auth credentials" not in readme
