"""Every baseline runs through the ``edgeguard_baseline`` DAG.

The in-process baseline of ``python src/run_pipeline.py`` is retired (``run_pipeline.py`` refuses ``--baseline``;
``tests/test_run_pipeline_collect_only.py``). These tests pin that ``scripts/preflight_baseline.sh`` assumes the
DAG launch path when none is given, refuses the retired ``cli`` launch path and, without Docker, says which checks
it could not run, that the MISP version warnings offer no ``run_pipeline.py`` workaround, and that the docs offer
no in-process baseline and send installs without Docker to the DAG.
"""

from __future__ import annotations

import argparse
import importlib.util
import logging
import os
import re
import shutil
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from stub_cleanup import dag_module_import

ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = ROOT / "scripts" / "preflight_baseline.sh"


class _Collect(logging.Handler):
    """Records the messages of one logger, independent of the root logger's configuration."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def _launch_path_block() -> str:
    script = PREFLIGHT.read_text()
    start = script.index('LAUNCH_PATH="${EDGEGUARD_PREFLIGHT_LAUNCH_PATH:-}"')
    end = script.index("# [1] required env vars present")
    return script[start:end]


def _resolve_launch_path(tmp_path, args, env_launch_path=None):
    """Run the argument handling of preflight_baseline.sh with recording pass/warn/fail."""
    harness = (
        "set -uo pipefail\n"
        'pass() { echo "PASS|$*"; }\nwarn() { echo "WARN|$*"; }\nfail() { echo "FAIL|$*"; }\n'
        + _launch_path_block()
        + 'echo "LAUNCH_PATH=$LAUNCH_PATH"\n'
    )
    env = {"PATH": os.environ.get("PATH", "")}
    if env_launch_path is not None:
        env["EDGEGUARD_PREFLIGHT_LAUNCH_PATH"] = env_launch_path
    done = subprocess.run(
        ["bash", "-c", harness, "preflight_baseline.sh", *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return done.returncode, done.stdout.splitlines()


class TestPreflightLaunchPath:
    def test_no_launch_path_assumes_the_dag_and_warns(self, tmp_path):
        code, out = _resolve_launch_path(tmp_path, [])
        assert code == 0
        warning, resolved = out
        assert resolved == "LAUNCH_PATH=dag"
        assert warning.startswith("WARN|no --launch-path given; assuming 'dag'")
        assert "edgeguard_baseline DAG" in warning

    @pytest.mark.parametrize(
        ("args", "env_launch_path"),
        [(["--launch-path=dag"], None), (["--launch-path", "dag"], None), ([], "dag"), (["--launch-path=dag"], "cli")],
    )
    def test_an_explicit_dag_launch_path_is_kept_without_a_warning(self, tmp_path, args, env_launch_path):
        code, out = _resolve_launch_path(tmp_path, args, env_launch_path)
        assert code == 0
        assert out == ["LAUNCH_PATH=dag"]

    @pytest.mark.parametrize(
        ("args", "env_launch_path"), [(["--launch-path", "cli"], None), (["--launch-path=cli"], None), ([], "cli")]
    )
    def test_the_retired_cli_launch_path_is_refused(self, tmp_path, args, env_launch_path):
        """The in-process baseline it checked is retired: ``run_pipeline.py`` refuses ``--baseline``."""
        code, out = _resolve_launch_path(tmp_path, args, env_launch_path)
        assert code == 1
        (failure,) = out
        assert failure.startswith("FAIL|--launch-path 'cli' is retired: run_pipeline.py refuses --baseline")
        assert "every baseline runs through the edgeguard_baseline DAG (--launch-path=dag" in failure

    def test_an_unknown_launch_path_fails(self, tmp_path):
        code, out = _resolve_launch_path(tmp_path, ["--launch-path=docker"])
        assert code == 1
        assert out == ["FAIL|invalid --launch-path 'docker' (must be 'dag')"]

    def test_help_prints_the_whole_header_with_the_launch_path_default(self, tmp_path):
        done = subprocess.run(
            ["bash", str(PREFLIGHT), "--help"], cwd=tmp_path, capture_output=True, text=True, timeout=60
        )
        assert done.returncode == 0, done.stderr
        lines = done.stdout.splitlines()
        assert lines[0].startswith("# preflight_baseline.sh")
        assert lines[-1].startswith("# See docs/RUNBOOK.md")
        text = " ".join(line.lstrip("#").strip() for line in lines)
        assert "./scripts/preflight_baseline.sh [--launch-path dag] [--strict]" in text
        assert 'script assumes "dag" and warns that it assumed it' in text
        assert (
            '"cli", the retired in-process baseline of src/run_pipeline.py (run_pipeline.py refuses --baseline), is refused'
            in text
        )


def _preflight_section(start: str, end: str) -> str:
    script = PREFLIGHT.read_text()
    return script[script.index(start) : script.index(end)]


def _run_without_docker(tmp_path, section: str, launch_path: str = "dag") -> list[str]:
    """Run one section of preflight_baseline.sh with a PATH that has no ``docker`` (an install without Docker)."""
    no_docker = tmp_path / "bin"
    no_docker.mkdir()
    harness = (
        f"set -uo pipefail\nLAUNCH_PATH={launch_path}\n"
        'pass() { echo "PASS|$*"; }\nwarn() { echo "WARN|$*"; }\nfail() { echo "FAIL|$*"; }\nhdr() { :; }\n' + section
    )
    bash = shutil.which("bash")
    assert bash is not None
    done = subprocess.run(
        [bash, "-c", harness], cwd=tmp_path, env={"PATH": str(no_docker)}, capture_output=True, text=True, timeout=60
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.splitlines()


class TestPreflightWithoutDocker:
    """On an install without Docker, checks [5] and [6] cannot read Airflow or the container; they say what to check."""

    _LAUNCH = ('hdr "[4][5]', "# [6] Airflow worker RAM")
    _MEMORY = ('hdr "[6] Airflow worker RAM"', "# [7] Prometheus alerts")

    def test_the_dag_path_names_the_pause_state_and_the_running_runs_it_could_not_check(self, tmp_path):
        out = _run_without_docker(tmp_path, _preflight_section(*self._LAUNCH))
        (warning,) = out  # no PASS: nothing about the scheduled DAGs was verified
        assert warning.startswith("WARN|docker not found; cannot verify that the 5 scheduled DAGs are paused")
        assert "have no running run" in warning
        assert "'airflow dags details <dag>' shows is_paused True" in warning
        assert "'airflow dags list-runs <dag> --state running -o json' prints []" in warning

    def test_the_memory_check_points_to_the_host_memory(self, tmp_path):
        (warning,) = _run_without_docker(tmp_path, _preflight_section(*self._MEMORY))
        assert warning.startswith("WARN|docker not available; skipping the memory check of the edgeguard_airflow")
        assert "check the memory of the host that runs Airflow: docs/MEMORY_TUNING.md" in warning


_MISP_ISSUE_SERVER = "2.4.160"  # below the 2.4.170 that PyMISP 2.5 expects


def _misp_version_issue(monkeypatch) -> str:
    """The issue ``MISPHealthCheck`` reports for a PyMISP 2.5 client and an older MISP server (its real text)."""
    import misp_health

    with monkeypatch.context() as patched:
        patched.setitem(sys.modules, "pymisp", types.SimpleNamespace(__version__="2.5.34.4"))
        compatible, issue = misp_health.MISPHealthCheck._check_version_compatibility(_MISP_ISSUE_SERVER)
    assert compatible is False and "Fix:" in issue
    return issue


def _incompatible_misp_health(monkeypatch, issue: str) -> None:
    class _Result(dict):
        details = {"version": _MISP_ISSUE_SERVER, "version_compatible": False, "issues": [issue]}

    class _Check:
        def __init__(self, *args, **kwargs):
            pass

        def check_health(self):
            return _Result()

    monkeypatch.setitem(sys.modules, "misp_health", types.SimpleNamespace(MISPHealthCheck=_Check))


class TestOperatorMessagesOfferNoCliWorkaround:
    """The MISP version warnings of ``edgeguard doctor`` and of the DAGs' MISP preflight name the fix, not
    ``run_pipeline.py``, which runs the collectors into MISP only."""

    def test_edgeguard_doctor(self, monkeypatch, capsys):
        import requests

        import edgeguard

        issue = _misp_version_issue(monkeypatch)
        for name in ("AIRFLOW_API_PASSWORD", "NATS_URL", "EDGEGUARD_BASELINE_DAYS"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(edgeguard, "test_misp_connection", lambda: (True, "MISP stub"))
        monkeypatch.setattr(edgeguard, "test_neo4j_connection", lambda: (False, "Neo4j stub"))
        monkeypatch.setattr(edgeguard, "_doctor_airflow_health", lambda *a, **k: None)
        monkeypatch.setattr(edgeguard, "validate_api_keys", lambda: (True, "keys stub"))
        monkeypatch.setattr(edgeguard, "check_disk_space", lambda: (True, "disk stub"))
        monkeypatch.setattr(edgeguard, "check_last_sync", lambda: (True, "sync stub"))
        monkeypatch.setattr(edgeguard, "load_sources", lambda: {})
        monkeypatch.setattr(edgeguard, "DEFAULT_SOURCES", {}, raising=False)
        monkeypatch.setattr(requests, "get", MagicMock(side_effect=requests.ConnectionError("no MISP in the test")))
        monkeypatch.setitem(
            sys.modules,
            "version_compatibility",
            types.SimpleNamespace(compare_pinned_vs_running=lambda **kw: []),
        )
        _incompatible_misp_health(monkeypatch, issue)

        edgeguard.cmd_doctor(argparse.Namespace(memory=False))
        out = capsys.readouterr().out.splitlines()
        (issue_line,) = [line for line in out if f"MISP {_MISP_ISSUE_SERVER}: " in line]
        assert issue in issue_line
        (hint,) = [line for line in out if "DAG parser to hang" in line]
        assert "fix the version mismatch named above" in hint
        assert not [line for line in out if "run_pipeline" in line]

    def test_the_dag_misp_preflight(self, monkeypatch):
        issue = _misp_version_issue(monkeypatch)
        if str(ROOT / "dags") not in sys.path:
            monkeypatch.syspath_prepend(str(ROOT / "dags"))
        spec = importlib.util.spec_from_file_location(
            "_dag_module_baseline_dag_only_test", ROOT / "dags" / "edgeguard_pipeline.py"
        )
        assert spec is not None and spec.loader is not None
        dag_module = importlib.util.module_from_spec(spec)
        with dag_module_import():
            spec.loader.exec_module(dag_module)

        monkeypatch.delenv("EDGEGUARD_SKIP_MISP_PREFLIGHT", raising=False)
        monkeypatch.setattr(dag_module, "check_misp_health", lambda *a, **k: True)
        _incompatible_misp_health(monkeypatch, issue)
        handler = _Collect()
        dag_module.logger.addHandler(handler)
        try:
            dag_module.assert_misp_preflight()
        finally:
            dag_module.logger.removeHandler(handler)

        assert f"MISP VERSION WARNING: {issue}" in handler.messages
        (hint,) = [m for m in handler.messages if "scheduler could hang" in m]
        assert "fix the version mismatch named above" in hint
        assert not [m for m in handler.messages if "run_pipeline" in m]


def _main_text_sections(text: str) -> list[str]:
    """The sections of a Markdown file before its History, split at headings outside code blocks."""
    main = text.split("\n## History", 1)[0]
    sections: list[list[str]] = [[]]
    in_fence = False
    for line in main.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
        elif not in_fence and re.match(r"#{1,6} ", line):
            sections.append([])
        sections[-1].append(line)
    return ["\n".join(lines) for lines in sections]


class TestDocs:
    def test_no_doc_offers_the_in_process_baseline(self):
        """No command line in a doc runs ``run_pipeline.py`` with a retired option, and every section that names
        ``run_pipeline.py`` together with ``--baseline`` says that it refuses it."""
        docs = sorted((ROOT / "docs").glob("*.md")) + [ROOT / "README.md"]
        retired = ("--baseline", "--fresh-baseline", "--stix-flow")
        commands: list[str] = []
        unlabelled: list[str] = []
        naming: set[str] = set()
        for path in docs:
            for section in _main_text_sections(path.read_text()):
                for line in section.splitlines():
                    if "run_pipeline.py" in line and line.lstrip().startswith(("python", "$ python", "./")):
                        if any(option in line for option in retired):
                            commands.append(f"{path.name}: {line.strip()}")
                if "run_pipeline" in section and "--baseline" in section:
                    naming.add(path.name)
                    if not any(
                        word in section for word in ("refuses", "refused", "exit with code 2", "exits 2", "retired")
                    ):
                        unlabelled.append(f"{path.name}: {section.splitlines()[0][:80]}")
        assert not commands, commands
        assert {"README.md", "AIRFLOW_DAGS.md", "BASELINE_SMOKE_TEST.md", "SETUP_GUIDE.md", "CLI.md"} <= naming
        assert not unlabelled, unlabelled

    def test_installs_without_docker_are_sent_to_the_dag_with_postgresql(self):
        readme = (ROOT / "README.md").read_text()
        (no_docker,) = [p for p in readme.split("\n\n") if p.startswith("Without Docker, Python 3.12")]
        assert "edgeguard_baseline" in no_docker and "PostgreSQL" in no_docker
        setup = (ROOT / "docs" / "SETUP_GUIDE.md").read_text()
        path_b = setup.split("## 4. Path B", 1)[1].split("\n## 5.", 1)[0]
        assert "**Airflow (optional):**" not in path_b
        assert "**Airflow (required for the baseline):**" in path_b
        assert "AIRFLOW__DATABASE__SQL_ALCHEMY_CONN" in path_b and "?timeout=60" in path_b
        assert "airflow dags trigger edgeguard_baseline" in path_b
        smoke = (ROOT / "docs" / "BASELINE_SMOKE_TEST.md").read_text()
        option_b = smoke.split("## Option B", 1)[1].split("\n## Checking the result", 1)[0]
        assert "airflow dags trigger edgeguard_baseline --conf" in option_b

    def test_env_example_names_a_postgresql_metadata_database_and_the_sqlite_caveat(self):
        env_example = (ROOT / ".env.example").read_text()
        assert re.search(
            r"^# AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=postgresql\+psycopg2://<airflow_user>:<airflow_password>@",
            env_example,
            re.M,
        )
        assert re.search(r"^# AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=sqlite:////.+\?timeout=60$", env_example, re.M)

    def test_install_sh_names_the_airflow_version_pyproject_pins(self):
        pyproject = (ROOT / "pyproject.toml").read_text()
        (pin,) = re.findall(r'"apache-airflow\[postgres\](~=[\d.]+)"', pyproject)
        install = (ROOT / "install.sh").read_text()
        echoed = re.findall(r"apache-airflow\[postgres\](~=[\d.]+)", install)
        assert echoed == [pin]

    def test_the_no_docker_route_is_complete(self):
        # Preflight checks [5] and [6] only warn without Docker: the checklist and the README say what to check.
        checklist = " ".join((ROOT / "docs" / "BASELINE_LAUNCH_CHECKLIST.md").read_text().split())
        step_1 = checklist.split("### [1] Live preflight run", 1)[1].split("### [2]", 1)[0]
        assert "Without Docker, checks [5] and [6] cannot read Airflow" in step_1
        assert "STRICT=1 cannot pass there" in step_1
        readme = (ROOT / "README.md").read_text()
        step_2 = readme.split("**2. Preflight.**", 1)[1].split("**3. Launch.**", 1)[0]
        assert "Without Docker, checks `[5]` and `[6]` cannot read Airflow" in step_2
        # A fresh trigger without Docker: the backup gate reads the environment of the Airflow processes.
        smoke = " ".join((ROOT / "docs" / "BASELINE_SMOKE_TEST.md").read_text().split())
        option_b = smoke.split("## Option B", 1)[1].split("## Checking the result", 1)[0]
        assert "`EDGEGUARD_LAST_BACKUP_AT`" in option_b and "followed by their restart" in option_b
        assert '`"skip_backup_check": true`' in option_b
        # The airflow commands read the metadata database setting too.
        env_example = (ROOT / ".env.example").read_text()
        assert "every `airflow` command you run (db migrate,\n# pools set, dags trigger)" in env_example
        # No doc calls Airflow optional or names run_pipeline.py as the baseline's orchestration.
        rates = (ROOT / "docs" / "DATA_SOURCES_RATE_LIMITS.md").read_text().split("\n## History", 1)[0]
        assert "# Airflow (optional)" not in rates
        assert 'export AIRFLOW__DATABASE__SQL_ALCHEMY_CONN="postgresql+psycopg2://' in rates
        flow = (ROOT / "docs" / "ARCHITECTURE_FLOW.md").read_text()
        baseline_files = flow.split("## 1. Baseline sequence", 1)[1].split("**Failure modes illuminated:**", 1)[0]
        assert "- `dags/edgeguard_pipeline.py` (the `edgeguard_baseline` DAG" in baseline_files
        assert "run_pipeline" not in baseline_files
