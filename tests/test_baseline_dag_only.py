"""Every baseline runs through the ``edgeguard_baseline`` DAG; the in-process CLI baseline is a development path.

``python src/run_pipeline.py --baseline`` loads Neo4j through its STIX import, whose nodes lack the lists
``build_relationships.py`` links by, so it builds a reduced graph while ending "successfully". These tests pin
that the CLI says so (``--help`` and a warning logged before the fresh-baseline wipe and before any collector),
that ``scripts/preflight_baseline.sh`` assumes the DAG launch path when none is given and, without Docker, says
which checks it could not run, that the MISP version warnings no longer offer ``run_pipeline.py`` as a
workaround, and that the docs which show the CLI command say what it builds and send installs without Docker to
the DAG.
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


@pytest.fixture
def pipeline_log():
    import run_pipeline

    handler = _Collect()
    run_pipeline.logger.addHandler(handler)
    previous = run_pipeline.logger.level
    run_pipeline.logger.setLevel(logging.INFO)
    try:
        yield handler.messages
    finally:
        run_pipeline.logger.removeHandler(handler)
        run_pipeline.logger.setLevel(previous)


def _bare_pipeline(connect_result: bool = False):
    """An ``EdgeGuardPipeline`` without collectors: ``_run_pipeline_inner`` needs only ``neo4j`` up to Step 1."""
    import run_pipeline

    pipeline = run_pipeline.EdgeGuardPipeline.__new__(run_pipeline.EdgeGuardPipeline)
    pipeline.neo4j = MagicMock()
    pipeline.neo4j.connect.return_value = connect_result
    return pipeline


def _warning_lines(messages: list[str]) -> list[str]:
    return [m for m in messages if m.startswith("[REDUCED-GRAPH]")]


class TestCliBaselineSaysItIsReduced:
    def test_help_text_of_baseline_names_the_reduced_graph_and_the_dag(self, monkeypatch, capsys):
        import run_pipeline

        pipeline_class = MagicMock()
        monkeypatch.setattr(run_pipeline, "EdgeGuardPipeline", pipeline_class)
        monkeypatch.setattr(sys, "argv", ["run_pipeline.py", "--help"])
        with pytest.raises(SystemExit) as exc:
            run_pipeline.main()
        assert exc.value.code == 0
        pipeline_class.assert_not_called()
        text = " ".join(capsys.readouterr().out.split())
        # The option's own help, between "--baseline " and the next option.
        baseline_help = text.split("--baseline ", 1)[1].split("--baseline-days", 1)[0]
        assert " ".join(run_pipeline.CLI_BASELINE_HELP_NOTE.split()) in baseline_help
        assert "Development only: builds a reduced graph" in baseline_help
        assert "no CVSS scores" in baseline_help
        assert "runs the edgeguard_baseline DAG" in baseline_help

    def test_fresh_baseline_logs_the_warning_before_the_wipe(self, monkeypatch, pipeline_log):
        import baseline_clean

        pipeline = _bare_pipeline()
        seen_at_wipe: list[list[str]] = []

        def fake_reset(**_kwargs):
            seen_at_wipe.append(list(pipeline_log))
            raise baseline_clean.BaselineCleanError("stopped by the test after the wipe call")

        monkeypatch.setattr(baseline_clean, "reset_baseline_data", fake_reset)
        assert pipeline._run_pipeline_inner(baseline=True, fresh_baseline=True, baseline_days=7) is False

        (before_wipe,) = seen_at_wipe
        import run_pipeline

        assert _warning_lines(before_wipe) == list(run_pipeline.CLI_BASELINE_WARNING_LINES)
        warning = " ".join(_warning_lines(before_wipe))
        for missing in ("IN_TACTIC", "USES_MALWARE", "USES_TOOL", "IMPLEMENTS_TECHNIQUE", "no CVSS scores"):
            assert missing in warning
        assert "edgeguard_baseline DAG" in warning
        # The refused clean stops the run before anything is collected or loaded.
        pipeline.neo4j.connect.assert_not_called()

    def test_fresh_baseline_logs_what_the_wipe_deleted(self, monkeypatch, pipeline_log):
        """2026-11-02: the counts the wipe reported (the 730-day run of 2026-11-01: 14 MISP events deleted,
        700 counted by the pre-wipe probe), not the probe's."""
        import baseline_clean

        before = baseline_clean.BaselineState(
            neo4j_count=145_429, neo4j_ok=True, misp_count=700, misp_ok=True, checkpoint_count=2, checkpoint_ok=True
        )
        after = baseline_clean.BaselineState(neo4j_ok=True, misp_ok=True, checkpoint_ok=True)
        result = baseline_clean.CleanResult(
            before=before,
            after=after,
            duration_seconds=117.7,
            verify_attempts=1,
            neo4j_nodes_deleted=145_429,
            misp_events_deleted=14,
        )
        monkeypatch.setattr(baseline_clean, "reset_baseline_data", lambda **_kw: result)
        assert _bare_pipeline()._run_pipeline_inner(baseline=True, fresh_baseline=True, baseline_days=7) is False
        assert (
            "Fresh-baseline clean complete: deleted 145429 Neo4j nodes, 14 MISP events, 2 checkpoint entries (117.7s)"
            in pipeline_log
        )

    def test_additive_baseline_logs_the_warning_before_it_collects(self, monkeypatch, pipeline_log):
        import baseline_checkpoint
        import run_pipeline

        monkeypatch.setattr(baseline_checkpoint, "get_baseline_status", lambda *a, **k: {})
        pipeline = _bare_pipeline()
        seen_at_connect: list[list[str]] = []

        def fake_connect():
            seen_at_connect.append(list(pipeline_log))
            return False  # Step 1 fails: the run ends before Step 2 collects anything

        pipeline.neo4j.connect.side_effect = fake_connect
        assert pipeline._run_pipeline_inner(baseline=True, fresh_baseline=False, baseline_days=7) is False
        (before_step_1,) = seen_at_connect
        assert _warning_lines(before_step_1) == list(run_pipeline.CLI_BASELINE_WARNING_LINES)

    def test_an_update_run_logs_no_baseline_warning(self, pipeline_log):
        pipeline = _bare_pipeline()
        assert pipeline._run_pipeline_inner(baseline=False) is False
        pipeline.neo4j.connect.assert_called_once()
        assert "UPDATE MODE: Collecting latest data only" in pipeline_log
        assert _warning_lines(pipeline_log) == []

    def test_step_5b_no_longer_claims_parity_with_the_dag(self):
        import inspect

        import run_pipeline

        source = inspect.getsource(run_pipeline.EdgeGuardPipeline._run_pipeline_inner)
        assert "Step 5b: build_relationships" in source
        assert "parity with DAG" not in source


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
        ("args", "env_launch_path", "expected"),
        [
            (["--launch-path=dag"], None, "dag"),
            (["--launch-path", "cli"], None, "cli"),
            ([], "cli", "cli"),
            (["--launch-path=dag"], "cli", "dag"),
        ],
    )
    def test_an_explicit_launch_path_is_kept_without_a_warning(self, tmp_path, args, env_launch_path, expected):
        code, out = _resolve_launch_path(tmp_path, args, env_launch_path)
        assert code == 0
        assert out == [f"LAUNCH_PATH={expected}"]

    def test_an_unknown_launch_path_fails(self, tmp_path):
        code, out = _resolve_launch_path(tmp_path, ["--launch-path=docker"])
        assert code == 1
        assert out == ["FAIL|invalid --launch-path 'docker' (must be 'cli' or 'dag')"]

    def test_help_prints_the_whole_header_with_the_launch_path_default(self, tmp_path):
        done = subprocess.run(
            ["bash", str(PREFLIGHT), "--help"], cwd=tmp_path, capture_output=True, text=True, timeout=60
        )
        assert done.returncode == 0, done.stderr
        lines = done.stdout.splitlines()
        assert lines[0].startswith("# preflight_baseline.sh")
        assert lines[-1].startswith("# See docs/RUNBOOK.md")
        text = " ".join(line.lstrip("#").strip() for line in lines)
        assert "./scripts/preflight_baseline.sh [--launch-path dag|cli] [--strict]" in text
        assert 'the script assumes "dag" and warns that it assumed it' in text
        assert "a development path that builds a reduced graph" in text


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

    def test_the_cli_path_keeps_its_lock_lines_and_warnings(self, tmp_path):
        out = _run_without_docker(tmp_path, _preflight_section(*self._LAUNCH), launch_path="cli")
        assert [line.split("|", 1)[0] for line in out] == ["PASS", "PASS", "WARN", "WARN"]
        assert "reduced graph" in out[2]
        assert out[3].startswith("WARN|docker not found; cannot verify that no scheduled DAG has a running run")

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
    ``run_pipeline.py``, whose STIX import builds a reduced graph."""

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
    def test_every_section_that_shows_the_cli_baseline_says_it_builds_a_reduced_graph(self):
        command = "python src/run_pipeline.py --baseline"
        docs = sorted((ROOT / "docs").glob("*.md")) + [ROOT / "README.md"]
        showing: set[str] = set()
        unlabelled: list[str] = []
        for path in docs:
            for section in _main_text_sections(path.read_text()):
                if command in section:
                    showing.add(path.name)
                    if "reduced graph" not in section:
                        unlabelled.append(f"{path.name}: {section.splitlines()[0][:80]}")
        assert {"README.md", "AIRFLOW_DAGS.md", "BASELINE_SMOKE_TEST.md", "SETUP_GUIDE.md", "CLI.md"} <= showing
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
        option_b = smoke.split("## Option B", 1)[1].split("\n## Option C", 1)[0]
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

    def test_the_short_lists_of_what_the_cli_baseline_lacks_agree(self):
        summary = (
            "(no ATT&CK tactic, software or technique-implementation links, no indicator-malware links or campaigns, "
            "few actor-technique or attribution links, no CVSS scores)"
        )
        for name in ("README.md", "docs/SETUP_GUIDE.md", "docs/RUNBOOK.md"):
            text = " ".join((ROOT / name).read_text().split())
            assert f"builds a reduced graph {summary}" in text, name
        import run_pipeline

        assert "no indicator-malware links or campaigns" in run_pipeline.CLI_BASELINE_HELP_NOTE
        dags_doc = (ROOT / "docs" / "AIRFLOW_DAGS.md").read_text()
        section = dags_doc.split("#### In-process CLI baseline (development only)", 1)[1].split("\n---", 1)[0]
        assert "`INDICATES` relationships" in section
        assert "File hashes, email addresses and certificate fingerprints are not loaded" in section

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
        option_b = smoke.split("## Option B", 1)[1].split("## Option C", 1)[0]
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
