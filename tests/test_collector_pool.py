"""Pin: every collector task shares one Airflow pool, and the stack creates that pool.

Unbounded concurrent collectors (7 baseline tier-2 feeds at once; a daily catch-up run plus OTX,
VirusTotal and NVD) exhausted MISP php-fpm worker memory (HTTP 502) and the airflow container's
cgroup limit (SIGKILL). The pool bounds collectors across all DAGs.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parent.parent
_DAGS = str(_REPO / "dags")
if _DAGS not in sys.path:
    sys.path.insert(0, _DAGS)

POOL = "edgeguard_collectors"
COLLECTOR_IDS = {
    "collect_otx",
    "collect_nvd",
    "collect_cisa",
    "collect_mitre",
    "collect_cisa_ics",
    "collect_virustotal",
    "collect_abuseipdb",
    "collect_threatfox",
    "collect_urlhaus",
    "collect_feodo",
    "collect_sslblacklist",
    "collect_malwarebazaar",
}


def _dags():
    import edgeguard_pipeline as m

    return [
        m.dag,
        m.medium_freq_dag,
        m.low_freq_dag,
        m.daily_dag,
        m.neo4j_sync_dag,
        m.baseline_dag,
    ]


def _short(task_id: str) -> str:
    return task_id.rsplit(".", 1)[-1]


def test_every_collector_task_uses_the_pool():
    seen = 0
    for d in _dags():
        for tid, task in d.task_dict.items():
            if _short(tid).startswith("collect_"):
                seen += 1
                assert _short(tid) in COLLECTOR_IDS, f"{d.dag_id}.{tid}: unknown collector, add it to the pin"
                assert task.pool == POOL, f"{d.dag_id}.{tid} runs outside {POOL}"
    assert seen == 23  # 1 + 2 + 1 + 8 (daily) + 11 (baseline)


def test_non_collector_tasks_stay_out_of_the_pool():
    for d in _dags():
        for tid, task in d.task_dict.items():
            if not _short(tid).startswith("collect_"):
                assert task.pool != POOL, f"{d.dag_id}.{tid} is not a collector but uses {POOL}"


def test_slots_env_is_forwarded_with_default_4():
    data = yaml.safe_load((_REPO / "docker-compose.yml").read_text())
    value = str(data["x-common-env"]["EDGEGUARD_COLLECTOR_POOL_SLOTS"])
    assert value == "${EDGEGUARD_COLLECTOR_POOL_SLOTS:-4}"
    assert "EDGEGUARD_COLLECTOR_POOL_SLOTS" in data["services"]["airflow"]["environment"]


def _airflow_command() -> list[str]:
    data = yaml.safe_load((_REPO / "docker-compose.yml").read_text())
    return data["services"]["airflow"]["command"]


def test_airflow_service_creates_the_pool_with_the_configured_slots():
    script = _airflow_command()[-1].replace("$$", "$")
    assert 'slots="${EDGEGUARD_COLLECTOR_POOL_SLOTS:-4}"' in script
    assert re.search(rf'airflow pools set {POOL} "\$slots"', script)
    assert script.rstrip().endswith("exec airflow standalone")  # standalone stays the foreground process


def test_airflow_command_escapes_every_dollar_for_compose():
    # A single `$` would be interpolated by Compose from the host environment at `up` time.
    assert "$" not in _airflow_command()[-1].replace("$$", "")


# 2026-10: the startup command is run with a stub `airflow` (and a no-op `sleep`) so the slot
# validation, the logging and the detached retry loop are checked as behaviour, not as text.
_STUB_AIRFLOW = """#!/usr/bin/env bash
if [ "$1" = pools ]; then
  n=$(cat "$STUB_DIR/count" 2>/dev/null || echo 0)
  n=$((n + 1))
  echo "$n" > "$STUB_DIR/count"
  echo "$*" >> "$STUB_DIR/pool_calls"
  if [ "$n" -le "$FAIL_TIMES" ]; then
    if [ -n "$ERROR_TEXT" ]; then
      echo "$ERROR_TEXT" >&2
    else
      echo "detail line $n"
      echo "Database migration required (attempt $n)" >&2
    fi
    exit 1
  fi
  # Ancestors of the retry loop, recorded while the standalone stub is still alive.
  p=$PPID
  while [ -n "$p" ] && [ "$p" -gt 1 ]; do
    echo "$p" >> "$STUB_DIR/loop_ancestors"
    p=$(ps -o ppid= -p "$p" | tr -d ' ')
  done
  touch "$STUB_DIR/pool_done"
  exit 0
fi
echo "$$" > "$STUB_DIR/standalone_pid"
# Stay alive until the pool is set (at most 20 s), like the real long-running process.
for _ in $(seq 1 400); do
  [ -f "$STUB_DIR/pool_done" ] && exit 0
  "$REAL_SLEEP" 0.05
done
exit 1
"""


def _run_startup(
    tmp_path: Path, slots: str | None, fail_times: int = 0, error_text: str = ""
) -> tuple[subprocess.CompletedProcess, int]:
    real_sleep = shutil.which("sleep")
    if shutil.which("bash") is None or shutil.which("ps") is None or real_sleep is None:
        pytest.skip("bash, ps and sleep are needed to run the compose startup command")
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "airflow").write_text(_STUB_AIRFLOW)
    (stub / "sleep").write_text("#!/bin/sh\nexit 0\n")
    for name in ("airflow", "sleep"):
        (stub / name).chmod(0o755)
    env = {
        "PATH": f"{stub}{os.pathsep}{os.environ.get('PATH', '')}",
        "STUB_DIR": str(tmp_path),
        "FAIL_TIMES": str(fail_times),
        "REAL_SLEEP": real_sleep,
        "ERROR_TEXT": error_text,
    }
    if slots is not None:
        env["EDGEGUARD_COLLECTOR_POOL_SLOTS"] = slots
    command = [part.replace("$$", "$") for part in _airflow_command()]
    proc = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # The detached loop keeps the pipes open, so communicate() returns once it has finished too.
    stdout, stderr = proc.communicate(timeout=60)
    return subprocess.CompletedProcess(command, proc.returncode, stdout, stderr), proc.pid


def _pool_calls(tmp_path: Path) -> list[str]:
    return (tmp_path / "pool_calls").read_text().splitlines()


def test_startup_retries_until_the_pool_is_set_and_logs_the_outcome(tmp_path):
    result, pid = _run_startup(tmp_path, "6", fail_times=60)
    assert result.returncode == 0, result.stderr
    calls = _pool_calls(tmp_path)
    assert len(calls) == 61
    assert all(c.startswith(f"pools set {POOL} 6 ") for c in calls)
    # The last error line every 30 failed attempts, not on every attempt.
    errors = [line for line in result.stderr.splitlines() if "not set after" in line]
    assert errors == [
        f"[edgeguard] collector pool {POOL} not set after 30 attempts: Database migration required (attempt 30)",
        f"[edgeguard] collector pool {POOL} not set after 60 attempts: Database migration required (attempt 60)",
    ]
    # Success is logged exactly once.
    assert result.stdout.count(f"[edgeguard] collector pool {POOL} set to 6 slots") == 1
    # `exec` replaced bash with `airflow standalone` (same PID), and the retry loop is not its child.
    assert int((tmp_path / "standalone_pid").read_text()) == pid
    ancestors = {int(p) for p in (tmp_path / "loop_ancestors").read_text().split()}
    assert pid not in ancestors


# 2026-10: every SQLAlchemy error ends with a "(Background on this error at: ...)" link, after a
# blank line and, for statement errors, the [SQL: ...] and [parameters: ...] lines. The log names
# the exception line instead (the shapes below are those of `airflow pools set` 3.3.2 against an
# unreachable Postgres and an integer the pool column cannot hold); without an exception line it
# falls back to the last line that is neither blank nor the link.
_BACKGROUND = "(Background on this error at: https://sqlalche.me/e/21/e3q8)"
_REFUSED = (
    'sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) connection to server at "postgres", '
    "port 5432 failed: Connection refused"
)
_OUT_OF_RANGE = "sqlalchemy.exc.DataError: (psycopg2.errors.NumericValueOutOfRange) integer out of range"
_UNMIGRATED = (
    "2026-10-16T16:08:57.819488Z [error    ] Database migration required. Please run `airflow db migrate`. "
    "[airflow.utils.db] loc=db.py:997"
)


@pytest.mark.parametrize(
    ("error_text", "expected"),
    [
        (
            "\n".join(
                [
                    "Traceback (most recent call last):",
                    '  File "/opt/airflow/bin/airflow", line 8, in <module>',
                    "    sys.exit(main())",
                    _REFUSED,
                    "\tIs the server running on that host and accepting TCP/IP connections?",
                    "",
                    _BACKGROUND,
                ]
            ),
            _REFUSED,
        ),
        (
            "\n".join(
                [
                    "Traceback (most recent call last):",
                    _OUT_OF_RANGE,
                    "[SQL: UPDATE slot_pool SET slots=%(slots)s WHERE slot_pool.id = %(slot_pool_id)s]",
                    "[parameters: {'slots': 99999999999999999999, 'slot_pool_id': 2}]",
                    _BACKGROUND,
                ]
            ),
            _OUT_OF_RANGE,
        ),
        ("\n".join([_UNMIGRATED, "", _BACKGROUND, ""]), _UNMIGRATED),
    ],
    ids=["unreachable-db", "out-of-range", "no-exception-line"],
)
def test_startup_logs_the_cause_not_the_sqlalchemy_background_link(tmp_path, error_text, expected):
    result, _ = _run_startup(tmp_path, "4", fail_times=30, error_text=error_text)
    assert result.returncode == 0, result.stderr
    errors = [line for line in result.stderr.splitlines() if "not set after" in line]
    assert errors == [f"[edgeguard] collector pool {POOL} not set after 30 attempts: {expected}"]


@pytest.mark.parametrize("value", ["four", "0", "00", "-3", "2.5", "4 ", "4x"])
def test_startup_falls_back_to_4_slots_with_a_message_for_an_invalid_value(tmp_path, value):
    result, _ = _run_startup(tmp_path, value)
    assert result.returncode == 0, result.stderr
    assert f"EDGEGUARD_COLLECTOR_POOL_SLOTS='{value}' is not a positive integer; using 4" in result.stderr
    assert _pool_calls(tmp_path) == [
        f"pools set {POOL} 4 Collector tasks of all DAGs (bounds MISP and container memory pressure)"
    ]


@pytest.mark.parametrize(("value", "expected"), [(None, "4"), ("1", "1"), ("12", "12"), ("08", "08")])
def test_startup_uses_a_valid_value_without_a_message(tmp_path, value, expected):
    result, _ = _run_startup(tmp_path, value)
    assert result.returncode == 0, result.stderr
    assert "is not a positive integer" not in result.stderr
    assert [c.split()[3] for c in _pool_calls(tmp_path)] == [expected]


def test_env_example_documents_the_variable():
    assert "EDGEGUARD_COLLECTOR_POOL_SLOTS" in (_REPO / ".env.example").read_text()
