"""``./install.sh`` brings any ``.env`` to a startable state without breaking an existing deployment.

- The secrets the stack cannot start without (``EDGEGUARD_API_KEY``, ``AIRFLOW_API_AUTH_JWT_SECRET``,
  ``AIRFLOW_FERNET_KEY``) are generated whenever they are blank, also in a ``.env`` the operator
  prepared before the first run; values already set are kept.
- ``.env`` is written in place, so a symlinked ``.env`` stays a symlink, and a new ``.env`` is mode 600.
- ``NEO4J_PASSWORD=changeme`` is replaced only while the Neo4j data volume does not exist: Neo4j keeps
  the password of its first start, so replacing it later would lock the stack out.

Runs the real script in a temporary directory with a stand-in for docker.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_FILES = ("install.sh", "scripts/record_deployed_commit.sh", "docker-compose.yml", ".env.example", "Makefile")
_SECRETS = ("EDGEGUARD_API_KEY", "AIRFLOW_API_AUTH_JWT_SECRET", "AIRFLOW_FERNET_KEY")

# Stands in for docker. ``compose config --format json`` names the project; ``volume inspect``
# succeeds only for the volume named in FAKE_VOLUMES.
_FAKE_DOCKER = """#!/bin/sh
echo "$*" >> "$DOCKER_LOG"
case "$*" in
    --version) echo "Docker version 27.0.0, build test" ;;
    "compose version --short") echo "2.29.0" ;;
    "compose version") echo "Docker Compose version v2.29.0" ;;
    "compose config --format json") echo '{"name": "egtest"}' ;;
    info) [ -n "$FAKE_DAEMON_DOWN" ] && exit 1 ;;
    "volume inspect "*)
        for v in $FAKE_VOLUMES; do [ "volume inspect $v" = "$*" ] && exit 0; done
        exit 1 ;;
esac
exit 0
"""


def _workdir(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    for rel in _FILES:
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_ROOT / rel, work / rel)
    return work


def _install(tmp_path: Path, work: Path, volumes: str = "", **extra_env: str) -> subprocess.CompletedProcess:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(exist_ok=True)
    (fake_bin / "docker").write_text(_FAKE_DOCKER)
    (fake_bin / "docker").chmod(0o755)
    env = dict(
        os.environ,
        PATH=f"{fake_bin}:{os.environ['PATH']}",
        DOCKER_LOG=str(tmp_path / "docker.log"),
        FAKE_VOLUMES=volumes,
        **extra_env,
    )
    env.pop("EDGEGUARD_GIT_SHA", None)
    for key in _SECRETS:
        if key not in extra_env:
            env.pop(key, None)
    return subprocess.run(["bash", "install.sh"], cwd=work, env=env, capture_output=True, text=True, timeout=120)


def _values(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            out[key.strip()] = value
    return out


def _prepared_env(work: Path, **overrides: str) -> Path:
    """The template as an operator prepares it before the first run: own values, secrets untouched."""
    lines = (work / ".env.example").read_text().splitlines()
    for key, value in overrides.items():
        hits = [i for i, ln in enumerate(lines) if ln.startswith((f"{key}=", f"# {key}="))]
        for i in hits:
            lines[i] = f"{key}={value}"
        if not hits:
            lines.append(f"{key}={value}")
    env_file = work / ".env"
    env_file.write_text("\n".join(lines) + "\n")
    return env_file


def test_prepared_env_gets_the_missing_secrets(tmp_path):
    work = _workdir(tmp_path)
    _prepared_env(work, NEO4J_PASSWORD="operator-chosen")
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    values = _values(work / ".env")
    for key in _SECRETS:
        assert values.get(key), f"{key} still blank after install.sh"
    assert values["NEO4J_PASSWORD"] == "operator-chosen"


def test_secrets_already_set_are_kept(tmp_path):
    work = _workdir(tmp_path)
    _prepared_env(
        work,
        EDGEGUARD_API_KEY="k" * 64,
        AIRFLOW_FERNET_KEY="f" * 44,
        AIRFLOW_API_AUTH_JWT_SECRET="j" * 64,
        NEO4J_PASSWORD="operator-chosen",
    )
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    values = _values(work / ".env")
    assert values["EDGEGUARD_API_KEY"] == "k" * 64
    assert values["AIRFLOW_FERNET_KEY"] == "f" * 44
    assert values["AIRFLOW_API_AUTH_JWT_SECRET"] == "j" * 64


def test_symlinked_env_stays_a_symlink(tmp_path):
    work = _workdir(tmp_path)
    target = _prepared_env(work, NEO4J_PASSWORD="operator-chosen")
    real = tmp_path / "deployment.env"
    target.rename(real)
    (work / ".env").symlink_to(real)
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    assert (work / ".env").is_symlink()
    assert _values(real)["EDGEGUARD_API_KEY"], "the secret was not written through the symlink"


def test_new_env_is_private(tmp_path):
    work = _workdir(tmp_path)
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    assert stat.S_IMODE((work / ".env").stat().st_mode) == 0o600


def test_default_neo4j_password_is_replaced_before_the_first_start(tmp_path):
    work = _workdir(tmp_path)
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    password = _values(work / ".env")["NEO4J_PASSWORD"]
    assert password and password != "changeme"


def test_default_neo4j_password_is_kept_once_the_volume_exists(tmp_path):
    work = _workdir(tmp_path)
    _prepared_env(work)  # NEO4J_PASSWORD=changeme from the template
    done = _install(tmp_path, work, volumes="egtest_neo4j_data")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _values(work / ".env")["NEO4J_PASSWORD"] == "changeme"
    assert "NEO4J_PASSWORD" in done.stdout + done.stderr  # the operator is told why it was kept


@pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
def test_make_env_target_creates_a_private_file(tmp_path):
    work = _workdir(tmp_path)
    done = subprocess.run(["make", ".env"], cwd=work, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    assert stat.S_IMODE((work / ".env").stat().st_mode) == 0o600


def test_blank_api_key_is_kept_when_unauthenticated_mode_is_chosen(tmp_path):
    work = _workdir(tmp_path)
    _prepared_env(work, NEO4J_PASSWORD="operator-chosen", EDGEGUARD_ALLOW_UNAUTH="1", EDGEGUARD_ENV="dev")
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    values = _values(work / ".env")
    assert values["EDGEGUARD_API_KEY"] == ""
    assert "EDGEGUARD_ALLOW_UNAUTH" in done.stdout + done.stderr
    assert values["AIRFLOW_API_AUTH_JWT_SECRET"]  # the Airflow secrets are still generated


def test_secret_exported_in_the_shell_is_not_written(tmp_path):
    work = _workdir(tmp_path)
    _prepared_env(work, NEO4J_PASSWORD="operator-chosen")
    done = _install(tmp_path, work, AIRFLOW_FERNET_KEY="exported-in-shell")
    assert done.returncode == 0, done.stdout + done.stderr
    values = _values(work / ".env")
    assert values.get("AIRFLOW_FERNET_KEY", "") == ""
    assert "AIRFLOW_FERNET_KEY" in done.stdout + done.stderr
    assert values["EDGEGUARD_API_KEY"]


def test_default_neo4j_password_is_kept_when_docker_cannot_be_asked(tmp_path):
    work = _workdir(tmp_path)
    _prepared_env(work)  # NEO4J_PASSWORD=changeme from the template
    done = _install(tmp_path, work, FAKE_DAEMON_DOWN="1")
    assert _values(work / ".env")["NEO4J_PASSWORD"] == "changeme"


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can write a read-only file")
def test_unwritable_env_fails_and_names_the_saved_content(tmp_path):
    work = _workdir(tmp_path)
    env_file = _prepared_env(work, NEO4J_PASSWORD="operator-chosen")
    env_file.chmod(0o400)
    done = _install(tmp_path, work)
    assert done.returncode != 0
    assert "could not write .env" in done.stdout + done.stderr


def test_unauthenticated_mode_outside_a_non_production_env_still_gets_a_key(tmp_path):
    # The API honours EDGEGUARD_ALLOW_UNAUTH only outside production; unset EDGEGUARD_ENV is production.
    work = _workdir(tmp_path)
    _prepared_env(work, NEO4J_PASSWORD="operator-chosen", EDGEGUARD_ALLOW_UNAUTH="1")
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    assert _values(work / ".env")["EDGEGUARD_API_KEY"]


def test_a_secret_exported_empty_in_the_shell_is_not_written(tmp_path):
    work = _workdir(tmp_path)
    _prepared_env(work, NEO4J_PASSWORD="operator-chosen")
    done = _install(tmp_path, work, AIRFLOW_FERNET_KEY="")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _values(work / ".env").get("AIRFLOW_FERNET_KEY", "") == ""
