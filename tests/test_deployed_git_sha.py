"""The running commit is visible, and the deploy instructions rebuild every image (2026-10-18).

``EDGEGUARD_GIT_SHA`` was read by ``src/query_api.py`` for the ``X-EdgeGuard-Git-Sha`` header of
STIX exports, but ``docker-compose.yml`` never forwarded it, so the commit a deployment serves could
not be read from outside. The REST and GraphQL ``/health`` responses now report it as ``git_sha``
(null when unset).

The launch checklist, the compose header and the Docker setup guide rebuilt only the Airflow image.
The ``api`` and ``graphql`` images copy ``src/`` at build time (``Dockerfile``), so REST, GraphQL and
STIX kept serving the old code after a deploy that followed them.

The deployed commit lives in ``.env``, written by ``scripts/record_deployed_commit.sh``, which
``./install.sh`` (and so ``--update``, ``make update`` and ``edgeguard update``) runs after its pull.
Compose forwards it to ``api`` and ``graphql`` only: ``airflow`` does not read it, and a changed value
on ``airflow`` would recreate it (killing a running baseline). A value exported only in the deploying
shell made every later ``docker compose up -d`` from another shell see a different value; and ``./install.sh --update`` never set it, so a commit written into ``.env`` by hand
was reported after the next update as the deployed one.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

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
        assert "scripts/record_deployed_commit.sh" in text, f"{rel}: the deploy must record the commit in .env"

    @pytest.mark.parametrize(
        "rel",
        [
            "docs/BASELINE_LAUNCH_CHECKLIST.md",
            "docs/DOCKER_SETUP_GUIDE.md",
            "README.md",
            "docs/SETUP_GUIDE.md",
            "docker-compose.yml",
            ".env.example",
            "src/package_meta.py",
        ],
    )
    def test_no_instruction_exports_the_commit_in_a_shell(self, rel):
        """A shell-only value differs in every other shell, and Compose then recreates api and graphql."""
        text = (_ROOT / rel).read_text()
        assert not re.search(r"export EDGEGUARD_GIT_SHA=", text), rel

    def test_compose_header_rebuilds_every_image(self):
        header = (_ROOT / "docker-compose.yml").read_text().split("x-common-env:", 1)[0]
        assert re.search(r"^#\s+docker compose build\s+#", header, re.M), "header must build every image"
        assert re.search(r"^#\s+docker compose up -d --force-recreate\s", header, re.M)
        assert re.search(r"^#\s+scripts/record_deployed_commit\.sh\s", header, re.M)

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


# ---------------------------------------------------------------------------
# scripts/record_deployed_commit.sh and its call in install.sh
# ---------------------------------------------------------------------------

RECORD = _ROOT / "scripts" / "record_deployed_commit.sh"
_BASHES = sorted({p for p in (shutil.which("bash"), "/bin/bash") if p and os.path.exists(p)})
_needs_git = pytest.mark.skipif(not shutil.which("git"), reason="needs git")


def _git_env(tmp_path: Path) -> dict:
    """Git isolated from the host's configuration, with a fixed identity."""
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CEILING_DIRECTORIES": str(tmp_path),
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    }


def _git(env: dict, cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def _checkout(tmp_path: Path, env_text: Optional[str] = None) -> Path:
    """A directory laid out like the repository root: scripts/record_deployed_commit.sh and .env."""
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(RECORD, root / "scripts" / RECORD.name)
    if env_text is not None:
        (root / ".env").write_text(env_text)
    return root


def _record(bash: str, root: Path, *args: str, env: Optional[dict] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [bash, str(root / "scripts" / RECORD.name), *args],
        env=env or {"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.parametrize("bash", _BASHES)
class TestRecordDeployedCommit:
    def test_replaces_the_line_in_place_and_drops_further_ones(self, bash, tmp_path):
        root = _checkout(tmp_path, "A=1\nEDGEGUARD_GIT_SHA=0000000\nB=2\nEDGEGUARD_GIT_SHA=1111111\n")
        done = _record(bash, root, "6b6ea3f")
        assert done.returncode == 0, done.stderr
        assert (root / ".env").read_text() == "A=1\nEDGEGUARD_GIT_SHA=6b6ea3f\nB=2\n"

    def test_appends_when_absent_even_without_a_final_newline(self, bash, tmp_path):
        root = _checkout(tmp_path, "A=1\n# EDGEGUARD_GIT_SHA=\nB=2")
        assert _record(bash, root, "6b6ea3f").returncode == 0
        assert (root / ".env").read_text() == "A=1\n# EDGEGUARD_GIT_SHA=\nB=2\nEDGEGUARD_GIT_SHA=6b6ea3f\n"

    def test_a_second_run_leaves_the_file_unchanged(self, bash, tmp_path):
        """The same commit gives the same .env, so Compose sees no change and recreates nothing."""
        root = _checkout(tmp_path, "A=1\n")
        assert _record(bash, root, "6b6ea3f").returncode == 0
        first = (root / ".env").read_bytes()
        assert _record(bash, root, "6b6ea3f").returncode == 0
        assert (root / ".env").read_bytes() == first

    def test_keeps_the_mode_of_env(self, bash, tmp_path):
        root = _checkout(tmp_path, "SECRET=x\n")
        (root / ".env").chmod(0o600)
        assert _record(bash, root, "6b6ea3f").returncode == 0
        assert (root / ".env").stat().st_mode & 0o777 == 0o600

    @pytest.mark.parametrize("value", ["$(git rev-parse --short HEAD)", "HEAD", "6B6EA3F", "abc12", "6b6ea3g", ""])
    def test_rejects_a_value_that_is_not_a_commit_id(self, bash, tmp_path, value):
        root = _checkout(tmp_path, "A=1\n")
        done = _record(bash, root, value)
        assert done.returncode == 1
        assert "is not a commit id" in done.stderr
        assert (root / ".env").read_text() == "A=1\n"

    def test_fails_without_env(self, bash, tmp_path):
        root = _checkout(tmp_path)
        done = _record(bash, root, "6b6ea3f")
        assert done.returncode == 1 and ".env not found" in done.stderr

    def test_fails_without_a_commit_outside_a_git_checkout(self, bash, tmp_path):
        root = _checkout(tmp_path, "A=1\n")
        done = _record(bash, root, env=_git_env(tmp_path))
        assert done.returncode == 1 and "not a git checkout" in done.stderr
        assert (root / ".env").read_text() == "A=1\n"

    @_needs_git
    def test_records_the_checked_out_commit_by_default(self, bash, tmp_path):
        root = _checkout(tmp_path, "A=1\n")
        env = _git_env(tmp_path)
        _git(env, root, "init", "-q")
        _git(env, root, "add", "scripts")
        _git(env, root, "commit", "-q", "-m", "first")
        head = _git(env, root, "rev-parse", "--short", "HEAD")
        done = _record(bash, root, env=env)
        assert done.returncode == 0, done.stderr
        assert (root / ".env").read_text() == f"A=1\nEDGEGUARD_GIT_SHA={head}\n"


_FAKE_DOCKER = """#!/bin/sh
# Stands in for docker: logs each call with the EDGEGUARD_GIT_SHA it sees.
echo "$* | shell=${EDGEGUARD_GIT_SHA-<unset>}" >> "$DOCKER_LOG"
case "$*" in
    --version) echo "Docker version 27.0.0, build test" ;;
    "compose version --short") echo "2.29.0" ;;
    "compose version") echo "Docker Compose version v2.29.0" ;;
esac
exit 0
"""


@_needs_git
class TestInstallShRecordsTheCommit:
    """``./install.sh`` (Docker path) writes the commit into .env after its pull, before the build,
    and drops a shell value, which Compose would prefer to .env. Run with a stand-in for docker."""

    FILES = ("install.sh", "scripts/record_deployed_commit.sh", "docker-compose.yml", ".env.example")

    def _origin(self, tmp_path: Path, env: dict) -> Path:
        origin = tmp_path / "origin"
        for rel in self.FILES:
            (origin / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(_ROOT / rel, origin / rel)
        (origin / ".gitignore").write_text(".env\n")
        _git(env, origin, "init", "-q")
        _git(env, origin, "add", ".")
        _git(env, origin, "commit", "-q", "-m", "first")
        return origin

    def _install(self, tmp_path: Path, env: dict, cwd: Path, *args: str) -> subprocess.CompletedProcess:
        fake_bin = tmp_path / "fake-bin"
        fake_bin.mkdir(exist_ok=True)
        (fake_bin / "docker").write_text(_FAKE_DOCKER)
        (fake_bin / "docker").chmod(0o755)
        run_env = dict(env, PATH=f"{fake_bin}:{env['PATH']}", DOCKER_LOG=str(tmp_path / "docker.log"))
        run_env["EDGEGUARD_GIT_SHA"] = "fffffff"  # a stale value exported in the operator's shell
        return subprocess.run(
            ["bash", "install.sh", *args], cwd=cwd, env=run_env, capture_output=True, text=True, timeout=120
        )

    def test_update_records_the_pulled_commit_not_the_old_head(self, tmp_path):
        env = _git_env(tmp_path)
        origin = self._origin(tmp_path, env)
        clone = tmp_path / "clone"
        _git(env, tmp_path, "clone", "-q", str(origin), str(clone))
        old_head = _git(env, clone, "rev-parse", "--short", "HEAD")
        (clone / ".env").write_text(f"A=1\nEDGEGUARD_GIT_SHA={old_head}\n")
        (origin / "NEW").write_text("x\n")
        _git(env, origin, "add", "NEW")
        _git(env, origin, "commit", "-q", "-m", "second")
        new_head = _git(env, origin, "rev-parse", "--short", "HEAD")

        done = self._install(tmp_path, env, clone, "--update")
        assert done.returncode == 0, done.stdout + done.stderr
        assert new_head != old_head
        assert (clone / ".env").read_text() == f"A=1\nEDGEGUARD_GIT_SHA={new_head}\n"
        calls = (tmp_path / "docker.log").read_text().splitlines()
        build = [c for c in calls if c.startswith("compose build")]
        up = [c for c in calls if c.startswith("compose up -d")]
        assert build == ["compose build --pull --quiet | shell=<unset>"]
        assert up == ["compose up -d | shell=<unset>"]

    def test_first_install_records_the_commit(self, tmp_path):
        env = _git_env(tmp_path)
        origin = self._origin(tmp_path, env)
        head = _git(env, origin, "rev-parse", "--short", "HEAD")
        done = self._install(tmp_path, env, origin)
        assert done.returncode == 0, done.stdout + done.stderr
        lines = (origin / ".env").read_text().splitlines()
        assert [ln for ln in lines if ln.startswith("EDGEGUARD_GIT_SHA=")] == [f"EDGEGUARD_GIT_SHA={head}"]

    def test_without_git_it_warns_and_leaves_env_alone(self, tmp_path):
        env = _git_env(tmp_path)
        tarball = tmp_path / "tarball"
        for rel in self.FILES:
            (tarball / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(_ROOT / rel, tarball / rel)
        (tarball / ".env").write_text("A=1\nEDGEGUARD_GIT_SHA=0000000\n")
        done = self._install(tmp_path, env, tarball)
        assert done.returncode == 0, done.stdout + done.stderr
        assert "EDGEGUARD_GIT_SHA in .env not updated" in done.stdout + done.stderr
        assert (tarball / ".env").read_text() == "A=1\nEDGEGUARD_GIT_SHA=0000000\n"
        # The stale value exported in the operator's shell does not reach docker compose either.
        calls = (tmp_path / "docker.log").read_text().splitlines()
        compose = [c for c in calls if c.startswith(("compose build", "compose up"))]
        assert compose and all(c.endswith("| shell=<unset>") for c in compose), compose
