"""``./install.sh`` brings any ``.env`` to a startable state without breaking an existing deployment.

- The secrets the stack cannot start without (``EDGEGUARD_API_KEY``, ``AIRFLOW_API_AUTH_JWT_SECRET``,
  ``AIRFLOW_FERNET_KEY``) are generated whenever they are blank, also in a ``.env`` the operator
  prepared before the first run; values already set are kept.
- ``.env`` is written in place, so a symlinked ``.env`` stays a symlink, and a new ``.env`` is mode 600.
- A value set on any line of ``.env``, or a variable exported in the shell, is never generated or written.
- ``NEO4J_PASSWORD=changeme`` is replaced only while neither the Neo4j data volume nor the Neo4j container
  exists: Neo4j keeps the password of its first start, so replacing it later would lock the stack out.
- A generated secret never appears on a command line, and a ``.env`` other users can read is reported.

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

# Stands in for docker. ``compose config`` prints the resolved configuration as Compose does, with the
# project as the first top-level ``name:`` key and indented ``name:`` keys below it (the JSON form names
# another project, so a test notices which form was read); ``volume inspect`` and ``container inspect``
# succeed only for the names in FAKE_VOLUMES and FAKE_CONTAINERS.
_FAKE_DOCKER = """#!/bin/sh
echo "$*" >> "$DOCKER_LOG"
case "$*" in
    --version) echo "Docker version 27.0.0, build test" ;;
    "compose version --short") echo "2.29.0" ;;
    "compose version") echo "Docker Compose version v2.29.0" ;;
    "compose config")
        printf '%s\\n' 'name: egtest' 'services:' '  neo4j:' '    container_name: edgeguard_neo4j' \\
            'volumes:' '  neo4j_data:' '    name: egtest_neo4j_data' ;;
    "compose config --format json") echo '{"name": "not-the-yaml-project"}' ;;
    info) [ -n "$FAKE_DAEMON_DOWN" ] && exit 1 ;;
    "volume inspect "*)
        for v in $FAKE_VOLUMES; do [ "volume inspect $v" = "$*" ] && exit 0; done
        exit 1 ;;
    "container inspect "*)
        for c in $FAKE_CONTAINERS; do [ "container inspect $c" = "$*" ] && exit 0; done
        exit 1 ;;
esac
exit 0
"""
# Stands in for awk and records its command line, so a test can show that no secret was passed there.
_LOGGING_AWK = """#!/bin/sh
printf '%s\\n' "$*" >> "$AWK_LOG"
exec {real_awk} "$@"
"""


def _workdir(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    for rel in _FILES:
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_ROOT / rel, work / rel)
    return work


def _install(
    tmp_path: Path, work: Path, volumes: str = "", containers: str = "", **extra_env: str
) -> subprocess.CompletedProcess:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(exist_ok=True)
    (fake_bin / "docker").write_text(_FAKE_DOCKER)
    (fake_bin / "docker").chmod(0o755)
    real_awk = shutil.which("awk")
    assert real_awk, "awk not found"
    (fake_bin / "awk").write_text(_LOGGING_AWK.format(real_awk=real_awk))
    (fake_bin / "awk").chmod(0o755)
    env = dict(
        os.environ,
        PATH=f"{fake_bin}:{os.environ['PATH']}",
        DOCKER_LOG=str(tmp_path / "docker.log"),
        AWK_LOG=str(tmp_path / "awk.log"),
        FAKE_VOLUMES=volumes,
        FAKE_CONTAINERS=containers,
        **extra_env,
    )
    env.pop("EDGEGUARD_GIT_SHA", None)
    # The suite runs with NEO4J_PASSWORD set; like the secrets, it counts as exported only when a test passes it.
    for key in (*_SECRETS, "NEO4J_PASSWORD"):
        if key not in extra_env:
            env.pop(key, None)
    return subprocess.run(["bash", "install.sh"], cwd=work, env=env, capture_output=True, text=True, timeout=120)


def _assignments(path: Path, key: str) -> list[str]:
    """Every active assignment of ``key``, in file order (Compose uses the last one)."""
    return [ln.partition("=")[2] for ln in path.read_text().splitlines() if ln.startswith(f"{key}=")]


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
    assert "chmod 600 .env" not in done.stdout + done.stderr


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


@pytest.mark.parametrize("key", ["AIRFLOW_FERNET_KEY", "AIRFLOW_API_AUTH_JWT_SECRET"])
def test_operator_value_above_the_template_line_is_kept(tmp_path, key):
    # A block of the operator's own values at the top, the template's commented blank line further down.
    work = _workdir(tmp_path)
    env_file = _prepared_env(work, NEO4J_PASSWORD="operator-chosen")
    assert f"\n# {key}=\n" in env_file.read_text(), "the template no longer holds the commented placeholder"
    env_file.write_text(f"{key}=x\n" + env_file.read_text())
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    assert _assignments(env_file, key) == ["x"]
    assert not [ln for ln in done.stdout.splitlines() if "Generated" in ln and key in ln]


def test_operator_api_key_overridden_by_a_later_blank_line_is_reported_not_replaced(tmp_path):
    # The template's EDGEGUARD_API_KEY= is an active blank line, so a value set above it is not the one
    # Compose uses; the installer says so instead of writing a key the operator did not choose.
    work = _workdir(tmp_path)
    env_file = _prepared_env(work, NEO4J_PASSWORD="operator-chosen")
    env_file.write_text("EDGEGUARD_API_KEY=x\n" + env_file.read_text())
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    assert _assignments(env_file, "EDGEGUARD_API_KEY") == ["x", ""]
    assert "a later blank EDGEGUARD_API_KEY= line overrides it" in done.stdout + done.stderr


def test_neo4j_password_exported_in_the_shell_leaves_env_alone(tmp_path):
    work = _workdir(tmp_path)
    _prepared_env(work)  # NEO4J_PASSWORD=changeme from the template
    done = _install(tmp_path, work, NEO4J_PASSWORD="exported-in-shell")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _values(work / ".env")["NEO4J_PASSWORD"] == "changeme"
    assert "NEO4J_PASSWORD is exported in this shell" in done.stdout + done.stderr
    assert "Generated random NEO4J_PASSWORD" not in done.stdout


def test_default_neo4j_password_is_kept_while_the_neo4j_container_exists(tmp_path):
    # A container started under another project name has no volume under this project's name.
    work = _workdir(tmp_path)
    _prepared_env(work)  # NEO4J_PASSWORD=changeme from the template
    done = _install(tmp_path, work, containers="edgeguard_neo4j")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _values(work / ".env")["NEO4J_PASSWORD"] == "changeme"
    assert "data volume or container already exists" in done.stdout + done.stderr


def test_project_name_is_read_from_the_top_level_key(tmp_path):
    # The volume of project "egtest" exists; an indented name: key must not be taken for the project.
    work = _workdir(tmp_path)
    _prepared_env(work)
    done = _install(tmp_path, work, volumes="egtest_neo4j_data")
    calls = (tmp_path / "docker.log").read_text().splitlines()
    assert "volume inspect egtest_neo4j_data" in calls
    assert _values(work / ".env")["NEO4J_PASSWORD"] == "changeme", done.stdout + done.stderr


@pytest.mark.parametrize("env_name", ["Staging", "DEV", "Test"])
def test_unauthenticated_mode_env_name_is_compared_without_case(tmp_path, env_name):
    work = _workdir(tmp_path)
    _prepared_env(work, NEO4J_PASSWORD="operator-chosen", EDGEGUARD_ALLOW_UNAUTH="1", EDGEGUARD_ENV=env_name)
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    assert _values(work / ".env")["EDGEGUARD_API_KEY"] == ""


def test_generated_secrets_never_reach_a_command_line(tmp_path):
    # A new .env: the installer generates all five secrets, each written by awk.
    work = _workdir(tmp_path)
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    values = _values(work / ".env")
    generated = [values[k] for k in ("GRAFANA_ADMIN_PASSWORD", "NEO4J_PASSWORD", *_SECRETS)]
    assert all(v and v != "changeme" for v in generated), "a secret was not generated"
    awk_calls = (tmp_path / "awk.log").read_text()
    assert "EDGEGUARD_NEW_SECRET" in awk_calls  # the stand-in saw the rewrites
    for value in generated:
        assert value not in awk_calls
        assert value not in done.stdout + done.stderr


def test_secret_written_into_an_env_other_users_can_read_is_reported(tmp_path):
    work = _workdir(tmp_path)
    env_file = _prepared_env(work, NEO4J_PASSWORD="operator-chosen")
    env_file.chmod(0o644)
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    out = done.stdout + done.stderr
    assert out.count("chmod 600 .env") == 1  # once, although three secrets were written
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o644  # the operator's mode is not changed


def test_private_env_is_not_reported(tmp_path):
    work = _workdir(tmp_path)
    env_file = _prepared_env(work, NEO4J_PASSWORD="operator-chosen")
    env_file.chmod(0o600)
    done = _install(tmp_path, work)
    assert done.returncode == 0, done.stdout + done.stderr
    assert _values(env_file)["AIRFLOW_FERNET_KEY"]
    assert "chmod 600 .env" not in done.stdout + done.stderr
