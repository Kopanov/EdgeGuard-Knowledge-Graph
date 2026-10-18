"""The running commit is visible, and the deploy instructions rebuild every image (2026-10-18).

``EDGEGUARD_GIT_SHA`` was read by ``src/query_api.py`` for the ``X-EdgeGuard-Git-Sha`` header of
STIX exports, but ``docker-compose.yml`` never forwarded it, so the commit a deployment serves could
not be read from outside. The REST and GraphQL ``/health`` responses now report it as ``git_sha``
(null when unset).

The launch checklist, the compose header and the Docker setup guide rebuilt only the Airflow image.
The ``api`` and ``graphql`` images copy ``src/`` at build time (``Dockerfile``), so REST, GraphQL and
STIX kept serving the old code after a deploy that followed them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import graphql_api
import package_meta
import query_api

_ROOT = Path(__file__).resolve().parents[1]


class _Client:
    def __init__(self, healthy: bool):
        self._healthy = healthy

    def is_connected(self) -> bool:
        return True

    def health_check(self) -> dict:
        return {"healthy": self._healthy}


class TestDeployedGitSha:
    @pytest.mark.parametrize("raw", [None, "", "   ", "\n"])
    def test_unset_or_blank_is_none(self, monkeypatch, raw):
        if raw is None:
            monkeypatch.delenv("EDGEGUARD_GIT_SHA", raising=False)
        else:
            monkeypatch.setenv("EDGEGUARD_GIT_SHA", raw)
        assert package_meta.deployed_git_sha() is None

    def test_value_is_stripped(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_GIT_SHA", " 6b6ea3f\n")
        assert package_meta.deployed_git_sha() == "6b6ea3f"


class TestRestHealth:
    @pytest.fixture(autouse=True)
    def _guard(self, monkeypatch):
        monkeypatch.setattr(query_api, "_API_KEY", None)
        monkeypatch.setattr(query_api, "_reconnect_in_progress", False)

    def test_healthy_response_names_the_commit(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_GIT_SHA", "6b6ea3f")
        monkeypatch.setattr(query_api, "neo4j_client", _Client(healthy=True))
        resp = TestClient(query_api.app).get("/health")
        assert resp.status_code == 200
        assert resp.json()["git_sha"] == "6b6ea3f"
        assert resp.json()["status"] == "ok"

    def test_degraded_response_names_the_commit_too(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_GIT_SHA", "6b6ea3f")
        monkeypatch.setattr(query_api, "neo4j_client", None)
        resp = TestClient(query_api.app).get("/health")
        assert resp.status_code == 503
        assert resp.json()["git_sha"] == "6b6ea3f"

    def test_unset_is_null_not_absent(self, monkeypatch):
        monkeypatch.delenv("EDGEGUARD_GIT_SHA", raising=False)
        monkeypatch.setattr(query_api, "neo4j_client", _Client(healthy=True))
        data = TestClient(query_api.app).get("/health").json()
        assert "git_sha" in data and data["git_sha"] is None

    def test_value_is_read_per_request(self, monkeypatch):
        monkeypatch.setattr(query_api, "neo4j_client", _Client(healthy=True))
        client = TestClient(query_api.app)
        monkeypatch.setenv("EDGEGUARD_GIT_SHA", "aaaaaaa")
        assert client.get("/health").json()["git_sha"] == "aaaaaaa"
        monkeypatch.setenv("EDGEGUARD_GIT_SHA", "bbbbbbb")
        assert client.get("/health").json()["git_sha"] == "bbbbbbb"


class TestGraphqlHealth:
    @pytest.mark.parametrize(
        "client, status",
        [(_Client(healthy=True), 200), (_Client(healthy=False), 503), (None, 503)],
        ids=["healthy", "unhealthy", "no-client"],
    )
    def test_every_state_names_the_commit(self, monkeypatch, client, status):
        monkeypatch.setenv("EDGEGUARD_GIT_SHA", "6b6ea3f")
        monkeypatch.setattr(graphql_api, "_client", client)
        resp = TestClient(graphql_api.app).get("/health")
        assert resp.status_code == status
        assert resp.json()["git_sha"] == "6b6ea3f"

    def test_unset_is_null_not_absent(self, monkeypatch):
        monkeypatch.delenv("EDGEGUARD_GIT_SHA", raising=False)
        monkeypatch.setattr(graphql_api, "_client", _Client(healthy=True))
        data = TestClient(graphql_api.app).get("/health").json()
        assert "git_sha" in data and data["git_sha"] is None


class TestStixHeaderUsesTheSameValue:
    def test_export_reads_the_shared_helper(self):
        src = (_ROOT / "src" / "query_api.py").read_text()
        assert "git_sha = deployed_git_sha()" in src
        assert 'os.environ.get("EDGEGUARD_GIT_SHA"' not in src


class TestDeployInstructionsRebuildEveryImage:
    """Each deploy instruction rebuilds every image and recreates every container."""

    FULL_REBUILD = re.compile(r"docker compose build(?: &&|\s*(?:#[^\n]*)?\n)\s*docker compose up -d --force-recreate")

    @pytest.mark.parametrize(
        "rel",
        ["docs/BASELINE_LAUNCH_CHECKLIST.md", "docs/DOCKER_SETUP_GUIDE.md", "README.md", "docs/SETUP_GUIDE.md"],
    )
    def test_document_rebuilds_every_image(self, rel):
        text = (_ROOT / rel).read_text()
        assert self.FULL_REBUILD.search(text), f"{rel}: no full rebuild (docker compose build + up -d --force-recreate)"
        assert "export EDGEGUARD_GIT_SHA=$(git rev-parse --short HEAD)" in text or rel == "docs/SETUP_GUIDE.md"

    def test_compose_header_rebuilds_every_image(self):
        header = (_ROOT / "docker-compose.yml").read_text().split("x-common-env:", 1)[0]
        assert re.search(r"^#\s+docker compose build\s+#", header, re.M), "header must build every image"
        assert re.search(r"^#\s+docker compose up -d --force-recreate\s", header, re.M)
        assert "export EDGEGUARD_GIT_SHA=$(git rev-parse --short HEAD)" in header

    def test_no_deploy_step_rebuilds_only_airflow(self):
        checklist = (_ROOT / "docs" / "BASELINE_LAUNCH_CHECKLIST.md").read_text()
        assert "docker compose build airflow && docker compose up -d --force-recreate airflow" not in checklist
        guide = (_ROOT / "docs" / "DOCKER_SETUP_GUIDE.md").read_text()
        assert "docker compose build airflow   # after clone" not in guide
        compose = (_ROOT / "docker-compose.yml").read_text()
        assert "docker compose build airflow             # bake Python deps" not in compose
        assert "After pulling code or changing that file: docker compose build airflow" not in compose
        readme = (_ROOT / "README.md").read_text()
        assert "run **`docker compose build airflow`** after dependency or **`src/`** logic changes" not in readme

    def test_env_example_documents_the_variable(self):
        assert re.search(r"^# EDGEGUARD_GIT_SHA=$", (_ROOT / ".env.example").read_text(), re.M)
