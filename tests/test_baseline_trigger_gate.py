"""``edgeguard baseline`` and ``edgeguard fresh-baseline``: the Airflow check before the trigger and the
REST trigger where no Compose ``airflow`` service runs.

The ``edgeguard_baseline`` DAG has ``max_active_runs=1``: a second trigger is not refused by Airflow but
queued, and a queued fresh baseline starts when the first run ends and wipes the graph that run built. A
trigger while the scheduler is stopped is accepted too and starts whenever the scheduler returns. Both
commands therefore read Airflow's health answer and the queued or running ``edgeguard_baseline`` runs first
(``_baseline_trigger_gate``), before the probes, the backup gate and the typed confirmation, and
``fresh-baseline`` reads them again after the confirmation. On a Compose host, a reading the REST API does
not give (no API credentials in the shell, or no API server) is taken inside the ``airflow`` container with
the ``airflow`` CLI, which needs no credentials. ``--skip-airflow-check`` stands in only for a reading that
neither gives.

Without a running Compose ``airflow`` service (a bare-metal Airflow, or the CLI inside the container) the
trigger goes through ``POST /api/v2/dags/edgeguard_baseline/dagRuns``. Airflow 3.3.2 requires the key
``logical_date`` in that body; the body is checked against the installed Airflow's own
``TriggerDAGRunPostBody``. A trigger that timed out is not sent again.

Real data: the health answers are those of the Airflow 3.3.2 standalone install of 2026-11-01 (the
scheduler stopped at 08:32, and the same install after its restart), and the run id is that of the 730-day
run of 2026-11-01 (its task logs). The output of the ``airflow`` CLI in the container is that of the
installed Airflow 3.3.2 CLI, captured on 2026-11-02 (below). Every Airflow call goes through the real
``airflow_client`` against a stand-in for ``requests.request``, and every ``docker`` command against a
stand-in for ``subprocess.run``; the commands run end to end.
"""

from __future__ import annotations

import argparse
import builtins
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import pytest
import requests
from airflow.api_fastapi.core_api.datamodels.dag_run import TriggerDAGRunPostBody

import airflow_client
import baseline_clean
import edgeguard

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
HEALTHY = json.loads((_FIXTURES / "airflow_health_healthy_2026_11_01.json").read_text())
UNHEALTHY = json.loads((_FIXTURES / "airflow_health_unhealthy_2026_11_01.json").read_text())
SCHEDULER_HEARTBEAT = "2026-11-01T08:32:14.421196+00:00"  # last scheduler heartbeat in UNHEALTHY
RUN_730D = "manual__2026-11-01T08:30:35.559036+00:00"  # the 730-day run of 2026-11-01
# Its start: between the run id's time and the first log line of its first task (08:30:38.65).
RUN_730D_START = "2026-11-01T08:30:36+00:00"
NEW_RUN = "manual__2026-11-02T09:00:00.000000+00:00"
RUNS_PATH = "/dags/edgeguard_baseline/dagRuns"
CHECK_RUNS = "edgeguard dag status --dag-id edgeguard_baseline"
NO_CHANGE = "No data was changed."
REFUSE_UNHEALTHY = "Not triggering edgeguard_baseline: with the scheduler or metadata database not healthy"
OVERRIDE_USED = "--skip-airflow-check passed, triggering anyway"

# Output of the installed Airflow 3.3.2 CLI, captured on 2026-11-02 with a temporary AIRFLOW_HOME holding an
# edgeguard_baseline DAG (the site-packages path is shortened). ``airflow dags list-runs <dag> -o json``
# prints a warning on stdout before the JSON list, and "" for a date not set; ``airflow jobs check`` prints
# "Found one alive job." and exits 0, or prints "No alive jobs found." on stderr and exits 1; a metadata
# database it cannot open ends both in a SQLAlchemy traceback (exit 1).
CLI_WARNING = (
    "2026-11-02T09:03:33.434294Z [warning  ] Could not import graphviz. Rendering graph to the graphical format "
    "will not be possible. \n"
    "You might need to install the graphviz package and necessary system packages.\n"
    "Run `pip install graphviz` to attempt to install it. [py.warnings] category=UserWarning "
    "filename=/home/airflow/.local/lib/python3.12/site-packages/airflow/cli/commands/dag_command.py lineno=57\n"
)
CLI_LIST_RUNS = CLI_WARNING + (
    '[{"dag_id": "edgeguard_baseline", "run_id": "manual__2026-11-02T09:03:32.391413+00:00", "state": "queued", '
    '"run_after": "2026-11-02T09:03:32.391413+00:00", "logical_date": "", "start_date": "", "end_date": ""}, '
    '{"dag_id": "edgeguard_baseline", "run_id": "manual__2026-11-02T09:03:25.295111+00:00", "state": "running", '
    '"run_after": "2026-11-02T09:03:25.295111+00:00", "logical_date": "", '
    '"start_date": "2026-11-02T09:03:42.693308+00:00", "end_date": ""}]\n'
)
CLI_NO_DAG = "DAG: edgeguard_baseline does not exist in 'dag' table\n"
CLI_SCHEDULER_ALIVE = "Found one alive job.\n"
CLI_SCHEDULER_DEAD = "No alive jobs found.\n"
CLI_DB_ERROR = (
    "Traceback (most recent call last):\n"
    '  File "/home/airflow/.local/lib/python3.12/site-packages/sqlalchemy/engine/default.py", line 869, in connect\n'
    "    return self.loaded_dbapi.connect(*cargs, **cparams)  # type: ignore[no-any-return]  # NOQA: E501\n"
    "           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n"
    "sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unable to open database file\n"
    "(Background on this error at: https://sqlalche.me/e/21/e3q8)\n"
)
DB_ERROR = "sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unable to open database file"
LIST_RUNS = ["dags", "list-runs", "edgeguard_baseline", "-o", "json"]
JOBS_CHECK = ["jobs", "check", "--job-type", "SchedulerJob"]


class _Resp:
    def __init__(self, status: int, body: Any):
        self.status_code = status
        self._body = body
        self.content = json.dumps(body).encode()

    def json(self) -> Any:
        return self._body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code} Client Error: {self._body}")


class FakeAirflow:
    """Stands in for ``requests.request`` as ``airflow_client`` calls it: the token, the health answer,
    the run list filtered by state, and the trigger, which Airflow 3.3.2's own body model validates."""

    def __init__(self, health: Any = None, runs: Optional[List[Dict[str, Any]]] = None):
        self.health = HEALTHY if health is None else health  # an exception instance is raised
        self.runs: List[Dict[str, Any]] = [dict(run) for run in (runs or [])]
        self.trigger_error: Optional[Exception] = None
        self.trigger_status = 200
        self.unreachable = False  # every request fails to connect
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, method: str, url: str, **kwargs):
        path = urlsplit(url).path
        self.calls.append({"method": method.upper(), "path": path, **kwargs})
        if self.unreachable:
            raise requests.exceptions.ConnectionError("connection refused")
        if path == "/auth/token":
            return _Resp(201, {"access_token": "token-for-the-test"})
        if path in ("/api/v2/monitor/health", "/health"):
            if isinstance(self.health, Exception):
                raise self.health
            return _Resp(200, self.health)
        if path.endswith(RUNS_PATH) and method.upper() == "GET":
            state = (kwargs.get("params") or {}).get("state")
            listed = [run for run in self.runs if state is None or run["state"] == state]
            return _Resp(200, {"dag_runs": listed, "total_entries": len(listed)})
        if path.endswith(RUNS_PATH) and method.upper() == "POST":
            if self.trigger_error is not None:
                raise self.trigger_error
            if self.trigger_status != 200:
                return _Resp(self.trigger_status, {"detail": "Dag with dag_id: 'edgeguard_baseline' not found"})
            body = kwargs["json"]
            if path.startswith("/api/v2/"):
                try:
                    TriggerDAGRunPostBody.model_validate(body)
                except ValueError as exc:  # pydantic's ValidationError
                    return _Resp(422, {"detail": str(exc)})
            run = {"dag_run_id": NEW_RUN, "state": "queued", "start_date": None, "conf": body.get("conf")}
            self.runs.append(run)
            return _Resp(200, run)
        return _Resp(404, {"detail": "Not Found"})

    def of(self, method: str, suffix: str) -> List[Dict[str, Any]]:
        return [c for c in self.calls if c["method"] == method and c["path"].endswith(suffix)]

    @property
    def triggers(self) -> List[Dict[str, Any]]:
        return self.of("POST", RUNS_PATH)


def _done(cmd, returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)


def _cli_run(run: Dict[str, Any]) -> Dict[str, str]:
    """A run of the fake store as ``airflow dags list-runs -o json`` renders it (Airflow 3.3.2)."""
    return {
        "dag_id": "edgeguard_baseline",
        "run_id": run["dag_run_id"],
        "state": run["state"],
        "run_after": run["dag_run_id"].split("__", 1)[1],
        "logical_date": "",
        "start_date": run.get("start_date") or "",
        "end_date": "",
    }


class FakeDocker:
    """Stands in for ``subprocess.run``: no ``docker`` command, or a Compose project whose services are
    listed, and the ``airflow`` CLI in its ``airflow`` container: ``dags trigger``, and the two reads of the
    trigger check, ``dags list-runs`` (the runs of ``store``, the metadata database the API reads too) and
    ``jobs check``, in the output shapes of the Airflow 3.3.2 CLI."""

    AIRFLOW_CLI = ["docker", "compose", "exec", "-T", "airflow", "airflow"]

    def __init__(self, services: Optional[List[str]] = None, store: Optional[FakeAirflow] = None):
        self.services = services  # None: no docker command on PATH
        self.store = store
        self.scheduler = "alive"  # airflow jobs check: "alive", "dead", "db-error" or "timeout"
        self.list_runs = "ok"  # airflow dags list-runs: "ok", "no-dag", "db-error" or "timeout"
        self.calls: List[List[str]] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if self.services is None:
            raise FileNotFoundError(2, "No such file or directory", "docker")
        if cmd[:3] == ["docker", "compose", "ps"]:
            return _done(cmd, 0, "".join(f"{s}\n" for s in self.services))
        if cmd[:6] != self.AIRFLOW_CLI:
            raise AssertionError(f"unexpected command {cmd}")
        sub = list(cmd[6:])
        if sub[:3] == ["dags", "trigger", "edgeguard_baseline"]:
            out = f"Triggered DAG <DAG: edgeguard_baseline> at 2026-11-02T09:00:00+00:00, run_id {NEW_RUN}\n"
            return _done(cmd, 0, out)
        if sub == LIST_RUNS:
            if self.list_runs == "timeout":
                raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
            if self.list_runs == "no-dag":
                return _done(cmd, 1, CLI_WARNING, CLI_NO_DAG)
            if self.list_runs == "db-error":
                return _done(cmd, 1, CLI_WARNING, CLI_DB_ERROR)
            runs = [_cli_run(run) for run in (self.store.runs if self.store else [])]
            return _done(cmd, 0, CLI_WARNING + json.dumps(runs) + "\n")
        if sub == JOBS_CHECK:
            if self.scheduler == "timeout":
                raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
            if self.scheduler == "dead":
                return _done(cmd, 1, "", CLI_SCHEDULER_DEAD)
            if self.scheduler == "db-error":
                return _done(cmd, 1, "", CLI_DB_ERROR)
            return _done(cmd, 0, CLI_SCHEDULER_ALIVE)
        raise AssertionError(f"unexpected command {cmd}")

    @property
    def execs(self) -> List[List[str]]:
        """Every ``docker compose exec``: the trigger and the reads."""
        return [c for c in self.calls if c[:3] == ["docker", "compose", "exec"]]

    @property
    def triggers(self) -> List[List[str]]:
        return [c for c in self.execs if c[6:8] == ["dags", "trigger"]]

    @property
    def reads(self) -> List[List[str]]:
        """The ``airflow`` commands the trigger check ran in the container."""
        return [c[6:] for c in self.execs if c[6:8] != ["dags", "trigger"]]


@pytest.fixture
def airflow(monkeypatch):
    fake = FakeAirflow()
    monkeypatch.setattr(airflow_client.requests, "request", fake)
    airflow_client._reset_token_cache()
    for var in ("AIRFLOW_API_VERSION", "AIRFLOW_API_USER", "AIRFLOW__CORE__SIMPLE_AUTH_MANAGER_PASSWORDS_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AIRFLOW_WEBSERVER_URL", "http://airflow.test:8082")
    monkeypatch.setenv("AIRFLOW_HOME", "/nonexistent-airflow-home")
    monkeypatch.setenv("AIRFLOW_API_PASSWORD", "test-password")
    monkeypatch.setitem(sys.modules, "airflow_client", airflow_client)
    yield fake
    airflow_client._reset_token_cache()


@pytest.fixture
def docker(monkeypatch, airflow):
    """No ``docker`` command by default (a bare-metal host, or the CLI inside the container). The container
    lists the runs of the same fake Airflow."""
    fake = FakeDocker(store=airflow)
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


@pytest.fixture
def stores(monkeypatch):
    """The probes of ``fresh-baseline`` find empty stores (the backup gate then has nothing to protect)."""
    calls: List[int] = []

    def _probe():
        calls.append(1)
        return baseline_clean.BaselineState(
            neo4j_count=0, neo4j_ok=True, misp_count=0, misp_ok=True, checkpoint_count=0, checkpoint_ok=True
        )

    monkeypatch.setattr(baseline_clean, "probe_baseline_state", _probe)
    monkeypatch.delenv("EDGEGUARD_LAST_BACKUP_AT", raising=False)
    return calls


@pytest.fixture
def no_prompt(monkeypatch):
    """Fails the test when the typed confirmation is asked for."""

    def _input(prompt=""):
        raise AssertionError("the typed confirmation was asked for")

    monkeypatch.setattr(builtins, "input", _input)


def _args(**overrides) -> argparse.Namespace:
    fields = dict(days=730, force=True, skip_backup_check=False, wipe_all=False, skip_airflow_check=False)
    fields.update(overrides)
    return argparse.Namespace(**fields)


COMMANDS = {"fresh-baseline": edgeguard.cmd_fresh_baseline, "baseline": edgeguard.cmd_baseline}


def _run(command: str, capsys, **overrides):
    code = COMMANDS[command](_args(**overrides))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ---------------------------------------------------------------------------
# A baseline run already queued or running
# ---------------------------------------------------------------------------


class TestPendingRun:
    @pytest.mark.parametrize("command", sorted(COMMANDS))
    @pytest.mark.parametrize(
        "run",
        [
            {"dag_run_id": RUN_730D, "state": "queued", "start_date": None},
            {"dag_run_id": RUN_730D, "state": "running", "start_date": RUN_730D_START},
        ],
        ids=["queued", "running"],
    )
    def test_refuses_before_the_probes_the_backup_gate_and_the_prompt(
        self, command, run, airflow, docker, stores, no_prompt, capsys
    ):
        airflow.runs = [dict(run)]
        code, out, _ = _run(command, capsys, force=False)
        assert code == 2
        assert airflow.triggers == [] and docker.calls == [] and stores == []
        assert "edgeguard_baseline already has 1 run(s) queued or running" in out
        line = next(ln for ln in out.splitlines() if RUN_730D in ln)
        assert run["state"] in line
        assert "max_active_runs=1" in out and "edgeguard dag kill --dag-id edgeguard_baseline" in out

    def test_the_override_does_not_skip_a_pending_run(self, airflow, docker, stores, no_prompt, capsys):
        airflow.runs = [{"dag_run_id": RUN_730D, "state": "running", "start_date": RUN_730D_START}]
        code, out, err = _run("fresh-baseline", capsys, skip_airflow_check=True)
        assert code == 2 and airflow.triggers == [] and docker.calls == [] and stores == []
        assert NO_CHANGE in err

    @pytest.mark.parametrize("command", sorted(COMMANDS))
    @pytest.mark.parametrize("services", [None, ["airflow", "airflow_postgres"]], ids=["no-docker", "compose"])
    def test_the_override_does_not_skip_a_pending_run_while_the_health_answer_is_missing(
        self, command, services, airflow, docker, stores, no_prompt, capsys
    ):
        """A refusal reason and a missing reading at once: the flag stands in for the health answer only, and
        on a Compose host the container is not asked for the scheduler (the answer is already no)."""
        docker.services = services
        airflow.health = requests.exceptions.ReadTimeout("read timed out")
        airflow.runs = [{"dag_run_id": RUN_730D, "state": "queued", "start_date": None}]
        code, out, _ = _run(command, capsys, skip_airflow_check=True)
        assert code == 2 and stores == []
        assert airflow.triggers == [] and docker.calls == []
        assert "already has 1 run(s) queued or running" in out and OVERRIDE_USED not in out

    def test_a_run_queued_while_the_prompt_was_open_refuses(self, airflow, docker, stores, monkeypatch, capsys):
        """The first reading is clean; another trigger arrives while the operator types the token."""

        def _input(prompt=""):
            airflow.runs.append({"dag_run_id": RUN_730D, "state": "queued", "start_date": None})
            return "FRESH-BASELINE"

        monkeypatch.setattr(builtins, "input", _input)
        code, out, err = _run("fresh-baseline", capsys, force=False)
        assert code == 2 and stores == [1]
        assert airflow.triggers == [] and docker.calls == []
        assert out.index("No edgeguard_baseline run queued or running.") < out.index("Checking Airflow again")
        assert out.index("Checking Airflow again") < out.index("already has 1 run(s) queued or running")
        assert NO_CHANGE in err

    def test_airflow_unreadable_after_the_prompt_refuses(self, airflow, docker, stores, monkeypatch, capsys):
        """The first reading is clean; Airflow stops answering while the operator types the token. The second
        check refuses like the first would: no reading, and no --skip-airflow-check."""

        def _input(prompt=""):
            airflow.unreachable = True
            return "FRESH-BASELINE"

        monkeypatch.setattr(builtins, "input", _input)
        code, out, err = _run("fresh-baseline", capsys, force=False)
        assert code == 2 and stores == [1]
        assert airflow.triggers == [] and docker.execs == []
        assert out.index("Checking Airflow again") < out.index("Airflow's state could not be read")
        assert OVERRIDE_USED not in out
        assert NO_CHANGE in err


# ---------------------------------------------------------------------------
# Scheduler or metadata database not healthy
# ---------------------------------------------------------------------------


class TestSchedulerNotHealthy:
    @pytest.mark.parametrize("command", sorted(COMMANDS))
    @pytest.mark.parametrize("skip_airflow_check", [False, True], ids=["plain", "override"])
    def test_the_stopped_scheduler_of_2026_11_01_refuses(
        self, command, skip_airflow_check, airflow, docker, stores, no_prompt, capsys
    ):
        airflow.health = UNHEALTHY
        code, out, _ = _run(command, capsys, skip_airflow_check=skip_airflow_check)
        assert code == 2
        assert airflow.triggers == [] and docker.calls == [] and stores == []
        assert f"Airflow scheduler unhealthy, last heartbeat {SCHEDULER_HEARTBEAT}" in out
        assert REFUSE_UNHEALTHY in out

    @pytest.mark.parametrize("command", sorted(COMMANDS))
    def test_the_override_does_not_skip_it_while_the_run_list_is_missing(
        self, command, airflow, docker, stores, no_prompt, monkeypatch, capsys
    ):
        """A Compose host whose shell has no AIRFLOW_API_PASSWORD, with the flag: the run list is missing, the
        stopped scheduler still refuses, and the container is not asked (the answer is already no)."""
        monkeypatch.delenv("AIRFLOW_API_PASSWORD")
        docker.services = ["airflow", "airflow_postgres"]
        airflow.health = UNHEALTHY
        code, out, _ = _run(command, capsys, skip_airflow_check=True)
        assert code == 2 and stores == []
        assert airflow.triggers == [] and docker.calls == []
        assert REFUSE_UNHEALTHY in out and OVERRIDE_USED not in out

    def test_an_unreadable_metadata_database_refuses(self, airflow, docker, stores, no_prompt, capsys):
        # Derived from Airflow 3.3.2's airflow/api/common/airflow_health.py: when the API server's job
        # queries fail, every component keeps its "unhealthy" default (as in test_airflow_scheduler_health.py).
        airflow.health = {
            "metadatabase": {"status": "unhealthy"},
            "scheduler": {"status": "unhealthy", "latest_scheduler_heartbeat": None},
            "triggerer": {"status": "unhealthy", "latest_triggerer_heartbeat": None},
            "dag_processor": {"status": "unhealthy", "latest_dag_processor_heartbeat": None},
        }
        code, out, _ = _run("baseline", capsys)
        assert code == 2 and airflow.triggers == [] and docker.calls == []
        assert "Airflow metadatabase unhealthy" in out and "restore the metadata database first" in out

    def test_a_dead_triggerer_alone_does_not_refuse(self, airflow, docker, capsys):
        """No EdgeGuard DAG defers a task: the triggerer is a warning, not a reason to refuse."""
        airflow.health = dict(HEALTHY, triggerer=UNHEALTHY["triggerer"])
        code, out, _ = _run("baseline", capsys)
        assert code == 0 and len(airflow.triggers) == 1


# ---------------------------------------------------------------------------
# Airflow not readable, and the override
# ---------------------------------------------------------------------------


class TestUnreadable:
    @pytest.mark.parametrize("command", sorted(COMMANDS))
    def test_no_answer_refuses_and_names_the_override(self, command, airflow, docker, stores, no_prompt, capsys):
        """No API server and no Compose airflow service: nothing gives a reading."""
        airflow.unreachable = True
        code, out, _ = _run(command, capsys)
        assert code == 2 and airflow.triggers == [] and docker.execs == [] and stores == []
        assert docker.calls == [["docker", "compose", "ps", "--services", "--status", "running"]]
        assert "Airflow's state could not be read" in out
        assert "health answer: Cannot connect to Airflow at http://airflow.test:8082." in out
        assert "edgeguard_baseline runs: Cannot connect to Airflow at http://airflow.test:8082" in out
        assert "--skip-airflow-check" in out and "AIRFLOW_WEBSERVER_URL" in out

    def test_a_run_list_without_credentials_refuses(self, airflow, docker, stores, no_prompt, monkeypatch, capsys):
        """A host without Docker whose shell lacks AIRFLOW_API_PASSWORD: health answers, the run list does not."""
        monkeypatch.delenv("AIRFLOW_API_PASSWORD")
        code, out, _ = _run("fresh-baseline", capsys)
        assert code == 2 and airflow.triggers == [] and docker.execs == [] and stores == []
        assert "Airflow components healthy" in out
        assert "edgeguard_baseline runs: Airflow API credentials are not set" in out
        assert "AIRFLOW_API_PASSWORD" in out and "--skip-airflow-check" in out

    def test_the_override_triggers_once_through_compose(self, airflow, docker, stores, monkeypatch, capsys, caplog):
        """No API credentials, and the run list in the container does not answer in time either."""
        monkeypatch.delenv("AIRFLOW_API_PASSWORD")
        docker.services = ["airflow", "airflow_postgres", "neo4j"]
        docker.list_runs = "timeout"
        code, out, _ = _run("fresh-baseline", capsys, skip_airflow_check=True)
        assert code == 0 and stores == [1]
        assert len(docker.triggers) == 1 and airflow.triggers == []
        assert f"Triggered: edgeguard_baseline [{NEW_RUN}]" in out
        assert "in the airflow container: no answer within 60s" in out
        assert OVERRIDE_USED in out
        assert any("--skip-airflow-check" in rec.getMessage() for rec in caplog.records)

    def test_the_override_with_no_answer_at_all(self, airflow, docker, capsys):
        """No API server, and both reads in the container time out."""
        airflow.unreachable = True
        docker.services = ["airflow"]
        docker.scheduler = docker.list_runs = "timeout"
        code, out, _ = _run("baseline", capsys, skip_airflow_check=True)
        assert code == 0 and len(docker.triggers) == 1
        assert out.count(OVERRIDE_USED) == 2  # health and run list


# ---------------------------------------------------------------------------
# A Compose host: what the REST API does not give is read in the airflow container
# ---------------------------------------------------------------------------


class TestReadInTheContainer:
    """The hosting setup: the CLI runs from the Compose directory on the host, and the shell has no
    AIRFLOW_API_PASSWORD (or the API server does not answer). The ``airflow`` CLI in the container reads
    the metadata database itself and needs no credentials."""

    @pytest.fixture
    def compose_without_credentials(self, airflow, docker, monkeypatch):
        monkeypatch.delenv("AIRFLOW_API_PASSWORD")
        docker.services = ["airflow", "airflow_postgres", "neo4j"]
        return docker

    def test_the_run_list_is_read_in_the_container_and_the_run_triggered(
        self, airflow, compose_without_credentials, stores, capsys
    ):
        docker = compose_without_credentials
        airflow.runs = [{"dag_run_id": RUN_730D, "state": "success", "start_date": RUN_730D_START}]
        code, out, _ = _run("fresh-baseline", capsys)
        assert code == 0, out
        assert docker.reads == [LIST_RUNS, LIST_RUNS]  # before the probes and again before the trigger
        assert len(docker.triggers) == 1 and airflow.triggers == []
        assert "edgeguard_baseline runs not read through the API (Airflow API credentials are not set" in out
        assert out.count("No edgeguard_baseline run queued or running.") == 2
        assert OVERRIDE_USED not in out and "Airflow's state could not be read" not in out
        assert f"Triggered: edgeguard_baseline [{NEW_RUN}]" in out

    @pytest.mark.parametrize("command", sorted(COMMANDS))
    @pytest.mark.parametrize(
        "run",
        [
            {"dag_run_id": RUN_730D, "state": "queued", "start_date": None},
            {"dag_run_id": RUN_730D, "state": "running", "start_date": RUN_730D_START},
        ],
        ids=["queued", "running"],
    )
    def test_a_run_listed_in_the_container_refuses(
        self, command, run, airflow, compose_without_credentials, stores, no_prompt, capsys
    ):
        docker = compose_without_credentials
        airflow.runs = [dict(run)]
        code, out, err = _run(command, capsys, skip_airflow_check=True)
        assert code == 2 and stores == []
        assert docker.triggers == [] and airflow.triggers == []
        assert "edgeguard_baseline already has 1 run(s) queued or running" in out
        line = next(ln for ln in out.splitlines() if RUN_730D in ln)
        assert run["state"] in line
        assert ("started 2026-11-01T08:30:36" if run["start_date"] else "started not yet") in line

    def test_without_an_api_server_the_scheduler_and_the_runs_are_read_in_the_container(self, airflow, docker, capsys):
        airflow.unreachable = True
        docker.services = ["airflow"]
        code, out, _ = _run("baseline", capsys)
        assert code == 0, out
        assert docker.reads == [JOBS_CHECK, LIST_RUNS] and len(docker.triggers) == 1
        assert "Airflow scheduler alive and metadata database reachable (Found one alive job.)" in out
        assert OVERRIDE_USED not in out

    def test_only_the_reading_the_api_does_not_give_is_taken_in_the_container(self, airflow, docker, capsys):
        """The health answer times out, the run list answers: the container checks the scheduler only."""
        airflow.health = requests.exceptions.ReadTimeout("read timed out")
        docker.services = ["airflow"]
        code, out, _ = _run("baseline", capsys)
        assert code == 0, out
        assert docker.reads == [JOBS_CHECK] and len(docker.triggers) == 1
        assert "Airflow health answer not read (read timed out); reading the scheduler in the Compose airflow" in out

    @pytest.mark.parametrize("command", sorted(COMMANDS))
    def test_no_alive_scheduler_in_the_container_refuses_even_with_the_override(
        self, command, airflow, docker, stores, no_prompt, capsys
    ):
        airflow.unreachable = True
        docker.services = ["airflow"]
        docker.scheduler = "dead"
        code, out, _ = _run(command, capsys, skip_airflow_check=True)
        assert code == 2 and stores == []
        assert docker.triggers == [] and airflow.triggers == []
        assert docker.reads == [JOBS_CHECK]  # the answer is no: the runs are not read
        assert "Airflow scheduler not alive (No alive jobs found.)" in out
        assert REFUSE_UNHEALTHY in out and "docker compose restart airflow" in out
        assert OVERRIDE_USED not in out

    def test_a_metadata_database_error_in_the_container_is_no_reading(self, airflow, docker, capsys):
        airflow.unreachable = True
        docker.services = ["airflow"]
        docker.scheduler = docker.list_runs = "db-error"
        code, out, _ = _run("baseline", capsys)
        assert code == 2 and docker.triggers == []
        assert "Airflow's state could not be read" in out
        in_container = f"; in the airflow container: exit 1: {DB_ERROR}"
        assert f"health answer: Cannot connect to Airflow at http://airflow.test:8082.{in_container}" in out
        assert (
            f"edgeguard_baseline runs: Cannot connect to Airflow at http://airflow.test:8082. Is it running?{in_container}"
            in out
        )
        assert "--skip-airflow-check" in out


class TestContainerReads:
    """The two reads alone, on the output of the Airflow 3.3.2 CLI."""

    @pytest.fixture
    def cli(self, monkeypatch):
        answers: Dict[str, Any] = {}
        calls: List[List[str]] = []

        def _run_cmd(cmd, **kwargs):
            calls.append(list(cmd))
            assert kwargs["timeout"] == 60
            answer = answers[" ".join(cmd[6:8])]
            if isinstance(answer, BaseException):
                raise answer
            return _done(cmd, *answer)

        monkeypatch.setattr(subprocess, "run", _run_cmd)
        return answers, calls

    def test_the_runs_as_listed_by_the_cli(self, cli):
        answers, calls = cli
        answers["dags list-runs"] = (0, CLI_LIST_RUNS)
        runs, reason = edgeguard._pending_runs_in_container()
        assert calls == [["docker", "compose", "exec", "-T", "airflow", "airflow", *LIST_RUNS]]
        assert reason == ""
        assert runs == [
            {"dag_run_id": "manual__2026-11-02T09:03:32.391413+00:00", "state": "queued", "start_date": None},
            {
                "dag_run_id": "manual__2026-11-02T09:03:25.295111+00:00",
                "state": "running",
                "start_date": "2026-11-02T09:03:42.693308+00:00",
            },
        ]

    def test_a_run_that_ended_is_not_pending(self, cli):
        answers, _ = cli
        listed = json.loads(CLI_LIST_RUNS.splitlines()[-1])
        for run in listed:
            run["state"] = "success"
        answers["dags list-runs"] = (0, CLI_WARNING + json.dumps(listed) + "\n")
        assert edgeguard._pending_runs_in_container() == ([], "")

    def test_no_run_at_all(self, cli):
        answers, _ = cli
        answers["dags list-runs"] = (0, CLI_WARNING + "[]\n")
        assert edgeguard._pending_runs_in_container() == ([], "")

    @pytest.mark.parametrize(
        ("answer", "reason"),
        [
            ((1, CLI_WARNING, CLI_NO_DAG), "exit 1: DAG: edgeguard_baseline does not exist in 'dag' table"),
            ((1, CLI_WARNING, CLI_DB_ERROR), f"exit 1: {DB_ERROR}"),
            ((0, CLI_WARNING), "the command printed no JSON list"),
            (subprocess.TimeoutExpired(["docker"], 60), "no answer within 60s"),
            (FileNotFoundError(2, "No such file or directory", "docker"), "docker compose exec failed: "),
        ],
        ids=["dag-not-registered", "database-error", "no-json", "timeout", "no-docker"],
    )
    def test_a_run_list_that_cannot_be_read(self, cli, answer, reason):
        answers, _ = cli
        answers["dags list-runs"] = answer
        runs, detail = edgeguard._pending_runs_in_container()
        assert runs is None and detail.startswith(reason)

    @pytest.mark.parametrize(
        ("answer", "expected"),
        [
            ((0, CLI_SCHEDULER_ALIVE), (True, "Found one alive job.")),
            ((1, "", CLI_SCHEDULER_DEAD), (False, "No alive jobs found.")),
            ((1, "", CLI_DB_ERROR), (None, f"exit 1: {DB_ERROR}")),
            (subprocess.TimeoutExpired(["docker"], 60), (None, "no answer within 60s")),
        ],
        ids=["alive", "dead", "database-error", "timeout"],
    )
    def test_the_scheduler_as_checked_by_the_cli(self, cli, answer, expected):
        answers, calls = cli
        answers["jobs check"] = answer
        assert edgeguard._scheduler_alive_in_container() == expected
        assert calls == [["docker", "compose", "exec", "-T", "airflow", "airflow", *JOBS_CHECK]]


# ---------------------------------------------------------------------------
# A healthy, idle Airflow: one trigger, through Compose or the REST API
# ---------------------------------------------------------------------------


class TestTrigger:
    def test_fresh_baseline_triggers_once_through_the_rest_api(self, airflow, docker, stores, capsys):
        code, out, _ = _run("fresh-baseline", capsys)
        assert code == 0, out
        assert len(airflow.triggers) == 1
        body = airflow.triggers[0]["json"]
        expected_conf = {"fresh_baseline": True, "baseline_days": 730, "backup_check_passed_cli": True}
        assert body == {"logical_date": None, "conf": expected_conf}
        TriggerDAGRunPostBody.model_validate(body)  # Airflow 3.3.2's own schema
        assert airflow.triggers[0]["path"] == "/api/v2/dags/edgeguard_baseline/dagRuns"
        assert airflow.triggers[0]["headers"] == {"Authorization": "Bearer token-for-the-test"}
        assert f"Triggered: edgeguard_baseline [{NEW_RUN}]" in out
        assert out.count("No edgeguard_baseline run queued or running.") == 2  # before the probes and again
        assert docker.calls == [["docker", "compose", "ps", "--services", "--status", "running"]]

    def test_baseline_triggers_once_through_the_rest_api(self, airflow, docker, capsys):
        code, out, _ = _run("baseline", capsys, days=7)
        assert code == 0, out
        assert [c["json"] for c in airflow.triggers] == [{"logical_date": None, "conf": {"baseline_days": 7}}]
        TriggerDAGRunPostBody.model_validate(airflow.triggers[0]["json"])
        assert f"Triggered: edgeguard_baseline [{NEW_RUN}]" in out

    def test_a_running_compose_airflow_service_triggers_through_docker(self, airflow, docker, stores, capsys):
        docker.services = ["airflow", "airflow_postgres"]
        code, out, _ = _run("fresh-baseline", capsys, wipe_all=True)
        assert code == 0 and airflow.triggers == [] and docker.reads == []
        (exec_call,) = docker.triggers
        assert exec_call[:9] == [
            "docker",
            "compose",
            "exec",
            "-T",
            "airflow",
            "airflow",
            "dags",
            "trigger",
            "edgeguard_baseline",
        ]
        conf = json.loads(exec_call[exec_call.index("--conf") + 1])
        assert conf == {
            "fresh_baseline": True,
            "baseline_days": 730,
            "wipe_scope": "all",
            "backup_check_passed_cli": True,
        }

    def test_v1_body_is_conf_alone(self, airflow, docker, monkeypatch, capsys):
        """Airflow 2 (``AIRFLOW_API_VERSION=v1``): HTTP Basic, ``/api/v1``, ``/health``, body without
        ``logical_date``."""
        monkeypatch.setenv("AIRFLOW_API_VERSION", "v1")
        code, _, _ = _run("baseline", capsys, days=30)
        assert code == 0
        (call,) = airflow.triggers
        assert call["path"] == "/api/v1/dags/edgeguard_baseline/dagRuns"
        assert call["json"] == {"conf": {"baseline_days": 30}}


class TestRestTriggerFailure:
    def test_a_timeout_is_not_retried_and_points_at_the_run_list(self, airflow, docker, capsys):
        airflow.trigger_error = requests.exceptions.ReadTimeout("read timed out")
        code, out, _ = _run("baseline", capsys)
        assert code == 2
        assert len(airflow.triggers) == 1
        assert "the run may have been created" in out and CHECK_RUNS in out
        assert "Do not trigger again before checking" in out

    def test_a_rejected_trigger_names_the_error_and_the_run_list(self, airflow, docker, capsys):
        airflow.trigger_status = 404
        code, out, _ = _run("baseline", capsys)
        assert code == 2 and len(airflow.triggers) == 1
        assert "Airflow REST trigger of edgeguard_baseline failed: 404" in out
        assert CHECK_RUNS in out and "may have been created" not in out


# ---------------------------------------------------------------------------
# The pieces: the Compose check, the client call and the flags
# ---------------------------------------------------------------------------


class TestComposeAirflowRunning:
    @pytest.mark.parametrize(
        ("services", "expected"),
        [
            (None, False),  # no docker command
            (["airflow", "airflow_postgres", "neo4j"], True),
            (["airflow_postgres", "neo4j"], False),  # a service whose name only contains "airflow"
            ([], False),  # no running service (or no Compose project here)
        ],
        ids=["no-docker", "airflow-running", "airflow-postgres-only", "none-running"],
    )
    def test_the_airflow_service_must_be_listed_as_running(self, services, expected, docker):
        docker.services = services
        assert edgeguard._compose_airflow_running() is expected
        assert docker.calls == [["docker", "compose", "ps", "--services", "--status", "running"]]

    def test_a_failing_or_hanging_compose_is_not_running(self, monkeypatch):
        monkeypatch.setattr(
            subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, stdout="airflow\n", stderr="")
        )
        assert edgeguard._compose_airflow_running() is False

        def _hang(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))

        monkeypatch.setattr(subprocess, "run", _hang)
        assert edgeguard._compose_airflow_running() is False


class TestClientTrigger:
    def test_a_read_timeout_is_marked_and_a_connection_error_is_not(self, airflow):
        airflow.trigger_error = requests.exceptions.ReadTimeout("read timed out")
        timed_out = airflow_client.trigger_dag_run("edgeguard_baseline", {"baseline_days": 7})
        assert timed_out["timed_out"] is True and "timed out" in timed_out["error"]
        airflow.trigger_error = requests.exceptions.ConnectionError("refused")
        refused = airflow_client.trigger_dag_run("edgeguard_baseline", {"baseline_days": 7})
        assert "timed_out" not in refused and "Cannot connect" in refused["error"]
        # A connect timeout is both a ConnectionError and a Timeout: the request never reached Airflow.
        airflow.trigger_error = requests.exceptions.ConnectTimeout("connect timed out")
        not_reached = airflow_client.trigger_dag_run("edgeguard_baseline", {"baseline_days": 7})
        assert "timed_out" not in not_reached and "Cannot connect" in not_reached["error"]
        assert len(airflow.triggers) == 3  # one request per call

    def test_the_new_run_is_returned(self, airflow):
        run = airflow_client.trigger_dag_run("edgeguard_baseline", {"baseline_days": 7})
        assert run["dag_run_id"] == NEW_RUN and run["state"] == "queued"


@pytest.mark.parametrize("command", ["baseline", "fresh-baseline"])
@pytest.mark.parametrize(("extra", "expected"), [([], False), (["--skip-airflow-check"], True)])
def test_the_flag_reaches_the_command(command, extra, expected, monkeypatch):
    seen: List[argparse.Namespace] = []
    target = "cmd_baseline" if command == "baseline" else "cmd_fresh_baseline"
    monkeypatch.setattr(edgeguard, target, lambda args: seen.append(args) or 0)
    monkeypatch.setattr(edgeguard, "_ensure_runtime_imports", lambda: None)  # no config load for parsing
    monkeypatch.setattr(sys, "argv", ["edgeguard", command, *extra])
    assert edgeguard.main() == 0
    assert seen[0].skip_airflow_check is expected
