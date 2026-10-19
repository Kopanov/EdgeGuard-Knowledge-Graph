"""``./install.sh`` reports the state the services actually reach after ``docker compose up -d``.

It used to print "EdgeGuard is running!" unconditionally, also while api and graphql crash-looped or
every service waited on an unhealthy Neo4j. Runs the real script with a stand-in docker whose
``compose ps`` output is scripted.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

_FAKE_DOCKER = """#!/bin/sh
echo "$*" >> "$DOCKER_LOG"
case "$*" in
    --version) echo "Docker version 27.0.0, build test" ;;
    "compose version --short") echo "2.29.0" ;;
    "compose version") echo "Docker Compose version v2.29.0" ;;
    "compose ps -a --format "*) [ -n "$FAKE_PS" ] && printf '%s\\n' "$FAKE_PS" ;;
esac
exit 0
"""

_HEALTHY = "\n".join(
    [
        "airflow|running|healthy|0",
        "airflow-init|exited||0",
        "api|running|healthy|0",
        "graphql|running|healthy|0",
        "metrics|running||0",
        "neo4j|running|healthy|0",
    ]
)


def _install(tmp_path: Path, fake_ps: str, env_text: str = "", wait: str = "2") -> subprocess.CompletedProcess:
    work = tmp_path / "work"
    work.mkdir()
    for rel in ("install.sh", ".env.example", "docker-compose.yml"):
        shutil.copy2(_ROOT / rel, work / rel)
    (work / ".env").write_text(env_text or (_ROOT / ".env.example").read_text())
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    (fake_bin / "docker").write_text(_FAKE_DOCKER)
    (fake_bin / "docker").chmod(0o755)
    env = dict(
        os.environ,
        PATH=f"{fake_bin}:{os.environ['PATH']}",
        DOCKER_LOG=str(tmp_path / "docker.log"),
        FAKE_PS=fake_ps,
        EDGEGUARD_INSTALL_WAIT_SEC=wait,
    )
    return subprocess.run(["bash", "install.sh"], cwd=work, env=env, capture_output=True, text=True, timeout=60)


def test_all_healthy_reports_running(tmp_path):
    done = _install(tmp_path, _HEALTHY)
    out = done.stdout + done.stderr
    assert done.returncode == 0, out
    assert "EdgeGuard is running!" in out
    assert "not healthy" not in out


def test_crash_looping_services_are_named_instead_of_running(tmp_path):
    ps = _HEALTHY.replace("api|running|healthy|0", "api|restarting||1").replace(
        "graphql|running|healthy|0", "graphql|restarting||1"
    )
    done = _install(tmp_path, ps)
    out = done.stdout + done.stderr
    assert done.returncode == 0, out
    assert "EdgeGuard is running!" not in out
    assert "not healthy" in out
    assert "api: restarting" in out and "graphql: restarting" in out
    # The template MISP values are the usual cause right after a first install.
    assert "MISP_API_KEY" in out


def test_services_stuck_in_created_are_named(tmp_path):
    ps = "\n".join(["neo4j|running|unhealthy|0", "airflow|created||0", "api|created||0", "graphql|created||0"])
    done = _install(tmp_path, ps)
    out = done.stdout + done.stderr
    assert "neo4j: running (unhealthy)" in out
    assert "airflow: created" in out


def test_next_steps_recreate_every_service_after_an_env_edit(tmp_path):
    done = _install(tmp_path, _HEALTHY)
    out = done.stdout + done.stderr
    assert "docker compose up -d airflow" not in out
    assert "docker compose up -d" in out


def test_unlisted_services_skip_the_wait(tmp_path):
    done = _install(tmp_path, "")
    out = done.stdout + done.stderr
    assert done.returncode == 0, out
    assert "skipped the health wait" in out


def test_a_wait_that_is_not_whole_seconds_falls_back_to_the_default(tmp_path):
    done = _install(tmp_path, _HEALTHY, wait="5m")
    out = done.stdout + done.stderr
    assert done.returncode == 0, out
    assert "EDGEGUARD_INSTALL_WAIT_SEC=5m" in out
    assert "EdgeGuard is running!" in out


def test_template_misp_values_end_the_wait_for_api_and_graphql_at_once(tmp_path):
    # They cannot start before MISP_URL / MISP_API_KEY are set, so waiting longer only delays the hint.
    ps = _HEALTHY.replace("api|running|healthy|0", "api|restarting||1").replace(
        "graphql|running|healthy|0", "graphql|restarting||1"
    )
    started = time.monotonic()
    done = _install(tmp_path, ps, wait="60")
    out = done.stdout + done.stderr
    assert time.monotonic() - started < 30, "waited for services that cannot start yet"
    assert "api: restarting" in out and "MISP_API_KEY" in out


def test_other_unhealthy_services_are_still_waited_for(tmp_path):
    ps = _HEALTHY.replace("neo4j|running|healthy|0", "neo4j|running|starting|0")
    started = time.monotonic()
    _install(tmp_path, ps, wait="4")
    assert time.monotonic() - started >= 4
