"""``./install.sh`` reports the state the services actually reach after ``docker compose up -d``.

It used to print "EdgeGuard is running!" unconditionally, also while api and graphql crash-looped or
every service waited on an unhealthy Neo4j. Runs the real script with a stand-in docker whose
``compose ps`` output and ``compose up -d`` / ``compose ps`` exit statuses are scripted.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

_FAKE_DOCKER = """#!/bin/sh
echo "$*" >> "$DOCKER_LOG"
case "$*" in
    --version) echo "Docker version 27.0.0, build test" ;;
    "compose version --short") echo "2.29.0" ;;
    "compose version") echo "Docker Compose version v2.29.0" ;;
    "compose up -d") exit "${FAKE_UP_RC:-0}" ;;
    "compose ps -a --format "*)
        [ -n "$FAKE_PS" ] && printf '%s\\n' "$FAKE_PS"
        exit "${FAKE_PS_RC:-0}" ;;
    "compose config --format json") [ -n "$FAKE_CONFIG" ] && printf '%s\\n' "$FAKE_CONFIG" ;;
esac
exit 0
"""

_PLACEHOLDER_HINT = "MISP_API_KEY is still a placeholder"

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


def _install(
    tmp_path: Path,
    fake_ps: str,
    env_text: str = "",
    wait: str = "2",
    config: str = "",
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
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
        FAKE_CONFIG=config,
    )
    # Compose (and the installer's placeholder check) prefers a shell MISP_API_KEY to .env; the test
    # runner's own value must not hide the .env under test.
    env.pop("MISP_API_KEY", None)
    env.update(extra_env or {})
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
    # The template MISP_API_KEY is the usual cause right after a first install.
    assert _PLACEHOLDER_HINT in out


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
    # The state is unknown, so the summary does not claim success.
    assert "EdgeGuard is running!" not in out
    assert "service health not checked: run docker compose ps" in out


def test_a_failing_state_check_is_not_reported_as_running(tmp_path):
    # For example a Compose that rejects the --format template, or a daemon error.
    done = _install(tmp_path, "", extra_env={"FAKE_PS_RC": "1"})
    out = done.stdout + done.stderr
    assert done.returncode == 0, out
    assert "EdgeGuard is running!" not in out
    assert "service health not checked: run docker compose ps" in out


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
    assert "api: restarting" in out and _PLACEHOLDER_HINT in out


_CRASH_LOOP = _HEALTHY.replace("api|running|healthy|0", "api|restarting||1").replace(
    "graphql|running|healthy|0", "graphql|restarting||1"
)


@pytest.mark.parametrize(
    "line",
    [
        "MISP_API_KEY=",
        'MISP_API_KEY=""',
        'MISP_API_KEY="your-misp-api-key-here"',
        "MISP_API_KEY='changeme'",
        "MISP_API_KEY=changeme   # set before the first start",
        "export MISP_API_KEY=YOUR_API_KEY_HERE",
        "MISP_API_KEY=your-misp-api-key-here\r",
    ],
)
def test_every_placeholder_src_config_rejects_is_recognised(tmp_path, line):
    # src/config.py refuses an empty key and these values; Compose removes the quotes and the comment.
    env_text = f"MISP_URL=https://misp.example.test\n{line}\n"
    started = time.monotonic()
    done = _install(tmp_path, _CRASH_LOOP, env_text=env_text, wait="60")
    out = done.stdout + done.stderr
    assert time.monotonic() - started < 30, "waited for services that cannot start yet"
    assert _PLACEHOLDER_HINT in out


def test_a_missing_key_line_counts_as_a_placeholder(tmp_path):
    done = _install(tmp_path, _CRASH_LOOP, env_text="MISP_URL=https://misp.example.test\n", wait="60")
    assert _PLACEHOLDER_HINT in done.stdout + done.stderr


def test_a_real_key_gets_no_hint_and_the_full_wait(tmp_path):
    # With a configured key a crash-looping api has another cause: wait for it and do not blame MISP.
    env_text = "MISP_URL=https://misp.example.test\nMISP_API_KEY=3f9c2a7be1d04c58a6e2b9d7c1f0e4a8\n"
    ps = _HEALTHY.replace("api|running|healthy|0", "api|restarting||1")
    started = time.monotonic()
    done = _install(tmp_path, ps, env_text=env_text, wait="3")
    out = done.stdout + done.stderr
    assert done.returncode == 0, out
    # Bash SECONDS counts whole seconds, so a 3-second deadline can end after a little over 2.
    assert time.monotonic() - started >= 2, "the wait was cut short"
    assert "api: restarting" in out
    assert "placeholder" not in out
    assert "EdgeGuard is running!" not in out


def test_a_real_key_exported_in_the_shell_takes_precedence_over_env(tmp_path):
    # Compose prefers the shell value to .env, so api starts although .env holds the template value.
    ps = _HEALTHY.replace("api|running|healthy|0", "api|running|starting|0")
    done = _install(tmp_path, ps, wait="2", extra_env={"MISP_API_KEY": "3f9c2a7be1d04c58a6e2b9d7c1f0e4a8"})
    out = done.stdout + done.stderr
    assert "api: running (starting)" in out
    assert "placeholder" not in out


def test_a_placeholder_exported_in_the_shell_is_recognised(tmp_path):
    env_text = "MISP_URL=https://misp.example.test\nMISP_API_KEY=3f9c2a7be1d04c58a6e2b9d7c1f0e4a8\n"
    done = _install(tmp_path, _CRASH_LOOP, env_text=env_text, wait="60", extra_env={"MISP_API_KEY": "changeme"})
    assert _PLACEHOLDER_HINT in done.stdout + done.stderr


def test_a_failed_up_still_prints_the_summary_and_keeps_its_status(tmp_path):
    # A dependency that stays unhealthy makes docker compose up -d fail; its dependents stay created.
    ps = "\n".join(["neo4j|running|unhealthy|0", "airflow|created||0", "api|created||0", "graphql|created||0"])
    started = time.monotonic()
    done = _install(tmp_path, ps, wait="60", extra_env={"FAKE_UP_RC": "1"})
    out = done.stdout + done.stderr
    assert done.returncode == 1, out
    # Checked once: services that up -d did not start do not start on their own.
    assert time.monotonic() - started < 30
    assert "docker compose up -d failed" in out
    assert "neo4j: running (unhealthy)" in out and "airflow: created" in out
    assert "docker compose logs" in out
    assert "EdgeGuard is running!" not in out


def test_a_failed_up_is_never_reported_as_running(tmp_path):
    done = _install(tmp_path, _HEALTHY, extra_env={"FAKE_UP_RC": "17"})
    out = done.stdout + done.stderr
    assert done.returncode == 17, out
    assert "EdgeGuard is running!" not in out
    assert "docker compose up -d failed" in out


def test_an_exited_one_shot_lists_its_exit_code(tmp_path):
    ps = _HEALTHY.replace("airflow-init|exited||0", "airflow-init|exited||1")
    done = _install(tmp_path, ps)
    out = done.stdout + done.stderr
    assert done.returncode == 0, out
    assert "airflow-init: exited (code 1)" in out


def test_other_unhealthy_services_are_still_waited_for(tmp_path):
    ps = _HEALTHY.replace("neo4j|running|healthy|0", "neo4j|running|starting|0")
    started = time.monotonic()
    done = _install(tmp_path, ps, wait="4")
    # Bash SECONDS counts whole seconds, so a 4-second deadline can end after a little over 3.
    assert time.monotonic() - started >= 3
    assert "neo4j: running" in done.stdout + done.stderr


def test_a_service_with_a_healthcheck_between_restarts_is_not_counted_as_done(tmp_path):
    # In a restart loop Compose reports the service as running with an empty Health for a moment.
    config = '{"services": {"api": {"healthcheck": {"test": ["CMD", "true"]}}, "metrics": {}}}'
    ps = _HEALTHY.replace("api|running|healthy|0", "api|running||0")
    done = _install(tmp_path, ps, config=config)
    out = done.stdout + done.stderr
    assert "api: running" in out
    assert "metrics" not in out.split("Not healthy")[-1]  # no healthcheck: running counts as done


def test_a_wait_with_a_leading_zero_is_read_as_decimal(tmp_path):
    done = _install(tmp_path, _HEALTHY, wait="08")
    out = done.stdout + done.stderr
    assert done.returncode == 0, out
    assert "EdgeGuard is running!" in out
