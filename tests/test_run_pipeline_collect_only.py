"""``src/run_pipeline.py`` runs the collectors into MISP only; its in-process baseline and Neo4j load are retired.

The in-process baseline loaded Neo4j through a STIX 2.1 import that built a reduced graph, and its update mode
wrote the same reduced records, ATT&CK actor-technique links at confidence 0.7 and VirusTotal results straight
into Neo4j, bypassing MISP. Every baseline now runs through the ``edgeguard_baseline`` DAG, and the graph is built
from MISP by the modules the DAGs run (``run_misp_to_neo4j.py``, ``build_relationships.py``,
``enrichment_jobs.py``). These tests pin:

* ``--baseline``, ``--fresh-baseline``, ``--baseline-days`` and ``--stix-flow`` exit 2 with directions before the
  pipeline is built, its lock taken, anything wiped or a collector run: the ``edgeguard`` baseline commands on every
  install, ``airflow dags trigger`` as the raw alternative; the refusal and ``--help`` need no configuration (a
  shell without ``NEO4J_PASSWORD`` or the MISP settings, on which ``config`` cannot be imported);
* the update mode runs every enabled collector once, as the scheduled DAGs call it (the source's incremental
  limit, ``push_to_misp=True``, no baseline flag), under the pipeline lock, and opens no Neo4j driver; its exit
  status follows the collectors' results (the status dicts of the 730-day DAG run of 2026-11-01);
* no code path of the retired load is left (the STIX loader, the 0.7 helpers, the VirusTotal writer);
* no repository file names the deleted entry points (crontab.txt, the prototype shell scripts and compose file,
  ``run_pipeline_misp_spt.py``, ``enrichment.py``) outside the History sections, and no current text (docs, the
  Bugbot rules, code comments) describes the STIX import, the STIX flow or the in-process baseline as live, also
  in a phrase wrapped across lines or hyphenated;
* no text of ``src/``, ``dags/`` or ``scripts/`` tells the operator to use a retired option of ``run_pipeline.py``
  (``--fresh-baseline``, ``--baseline``, ``--baseline-days``, ``--stix-flow``) other than as refused or retired;
* ``.env.example`` offers the baseline item limit only under the environment name the code reads.
"""

from __future__ import annotations

import ast
import importlib
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import baseline_clean  # noqa: E402
import baseline_lock  # noqa: E402
import lock_files  # noqa: E402
import run_pipeline  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "collector_results_2026_11_01.jsonl"

# The collector classes ``EdgeGuardPipeline`` builds, by the task of the 730-day DAG run whose result is in the
# fixture (AbuseIPDB and the two VirusTotal collectors returned none there: no key).
_TASK_COLLECTOR = {
    "tier1_core.collect_cisa": "CISACollector",
    "tier1_core.collect_mitre": "MITRECollector",
    "tier1_core.collect_nvd": "NVDCollector",
    "tier1_core.collect_otx": "OTXCollector",
    "tier2_feeds.collect_cisa_ics": "CISAICSCollector",
    "tier2_feeds.collect_feodo": "FeodoCollector",
    "tier2_feeds.collect_sslblacklist": "SSLBlacklistCollector",
    "tier2_feeds.collect_malwarebazaar": "MalwareBazaarCollector",
    "tier2_feeds.collect_threatfox": "ThreatFoxCollector",
    "tier2_feeds.collect_urlhaus": "URLhausCollector",
}
# The allowlist names of those ten collectors (``EDGEGUARD_COLLECT_SOURCES``).
_ALLOWED = "otx,nvd,cisa,cisa_ics,mitre,feodo,sslbl,urlhaus,threatfox,malwarebazaar"


def _collector_results() -> dict[str, dict]:
    """``{collector class name: the status dict its task returned}``, from the task logs (JSON lines)."""
    results = {}
    for line in FIXTURE.read_text().splitlines():
        record = json.loads(line)
        prefix = "Done. Returned value was: "
        assert record["event"].startswith(prefix)
        results[_TASK_COLLECTOR[record["task_id"]]] = ast.literal_eval(record["event"][len(prefix) :])
    assert len(results) == 10
    return results


def _collector_classes() -> dict[str, type]:
    """Every collector class ``run_pipeline.py`` builds a collector from: its ``collectors.*`` imports, read from the
    source file (``EdgeGuardPipeline.__init__`` imports them after ``main`` has refused the retired options)."""
    classes = {}
    for node in ast.walk(ast.parse((ROOT / "src" / "run_pipeline.py").read_text())):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("collectors."):
            module = importlib.import_module(node.module)
            for alias in node.names:
                value = getattr(module, alias.name)
                if alias.name.endswith("Collector") and hasattr(value, "collect"):
                    classes[alias.name] = value
    assert len(classes) == 14, sorted(classes)
    return classes


class _Spies:
    """Records every action that a refused run must not take and an update run must take only in part."""

    def __init__(self) -> None:
        self.built: list[str] = []
        self.collected: list[tuple[str, dict]] = []
        self.lock_during_collect: list[str | None] = []
        self.drivers: list[tuple] = []
        self.wipes: list[dict] = []
        self.baseline_locks: list[tuple] = []


@pytest.fixture
def spies(monkeypatch):
    """Spy on the pipeline's construction, its collectors, Neo4j, the fresh-baseline wipe and the baseline lock."""
    import neo4j

    recorded = _Spies()
    results = _collector_results()

    real_init = run_pipeline.EdgeGuardPipeline.__init__

    def init(self, *args, **kwargs):
        recorded.built.append(type(self).__name__)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(run_pipeline.EdgeGuardPipeline, "__init__", init)

    for name, cls in _collector_classes().items():

        def collect(self, limit=None, push_to_misp=False, _name=name, **kwargs):
            recorded.collected.append((_name, {"limit": limit, "push_to_misp": push_to_misp, **kwargs}))
            path = lock_files.PIPELINE_LOCK_PATH
            recorded.lock_during_collect.append(Path(path).read_text() if os.path.exists(path) else None)
            return results.get(_name, {"source": _name, "success": True, "count": 0, "failed": 0})

        monkeypatch.setattr(cls, "collect", collect)

    def driver(*args, **kwargs):
        recorded.drivers.append(args)
        raise AssertionError("no Neo4j driver may be opened")

    monkeypatch.setattr(neo4j.GraphDatabase, "driver", driver)

    def reset(**kwargs):
        recorded.wipes.append(kwargs)
        raise baseline_clean.BaselineCleanError("stopped by the test")

    monkeypatch.setattr(baseline_clean, "reset_baseline_data", reset)

    real_acquire = baseline_lock.acquire_baseline_lock

    def acquire(*args, **kwargs):
        recorded.baseline_locks.append(args)
        return real_acquire(*args, **kwargs)

    monkeypatch.setattr(baseline_lock, "acquire_baseline_lock", acquire)
    return recorded


def _main(monkeypatch, argv: list[str]):
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py", *argv])
    return run_pipeline.main()


class TestRetiredOptionsAreRefused:
    @pytest.mark.parametrize(
        "argv",
        [
            ["--baseline"],
            ["--fresh-baseline"],
            ["--baseline", "--fresh-baseline"],
            ["--baseline", "--fresh-baseline", "--baseline-days", "7"],
            ["--baseline-days", "7"],
            ["--stix-flow"],
            ["--stix-flow", "--baseline"],
            ["--baseline-days", ""],
        ],
    )
    def test_exit_2_before_anything_runs(self, monkeypatch, capsys, spies, argv):
        lock = Path(lock_files.PIPELINE_LOCK_PATH)
        sentinel = Path(baseline_lock.baseline_lock_path())

        assert _main(monkeypatch, argv) == 2

        assert spies.built == [], "the pipeline was built"
        assert spies.collected == [], "a collector ran"
        assert spies.wipes == [], "the fresh-baseline wipe ran"
        assert spies.baseline_locks == [], "the baseline lock was taken"
        assert spies.drivers == [], "a Neo4j driver was opened"
        assert not lock.exists() and not sentinel.exists()
        captured = capsys.readouterr()
        assert captured.out == ""
        message = captured.err
        refused = [option for option in run_pipeline.RETIRED_OPTIONS if option in argv]
        assert message.startswith(f"run_pipeline.py: {', '.join(refused)} refused.\n")
        for direction in (
            # The edgeguard commands on every install (they trigger through the REST API without a running Compose
            # airflow service, and refuse while Airflow is unhealthy or a baseline run is pending).
            "A baseline runs through the edgeguard_baseline DAG. On every install, with Docker Compose or without it:\n"
            "  edgeguard fresh-baseline --days N",
            "edgeguard baseline --days N",
            "both refuse while the Airflow scheduler or metadata database is not healthy or an edgeguard_baseline run",
            "without a running Compose airflow service they trigger through the Airflow REST API",
            'docs/CLI.md, "Baseline triggers"',
            # The raw alternative: the additive and the fresh trigger, and where the fresh one's backup gate reads.
            "The raw trigger, without those checks, in the Airflow environment:",
            """airflow dags trigger edgeguard_baseline --conf '{"baseline_days": N}'""",
            """airflow dags trigger edgeguard_baseline --conf '{"fresh_baseline": true, "baseline_days": N}'""",
            "the backup gate runs in the baseline_clean task: EDGEGUARD_LAST_BACKUP_AT",
            "docs/BACKUP.md",
            "python src/run_misp_to_neo4j.py --full",
            "python src/build_relationships.py",
            "python src/enrichment_jobs.py",
        ):
            assert direction in message
        # The message of the retired STIX flow named a fallback that did not exist and the wrong package; the
        # edgeguard commands are no Compose-only path.
        assert "Falling back" not in message and "pip install" not in message
        assert "Compose install" not in message and "Without Docker" not in message

    @pytest.mark.parametrize("argv", [["--stix"], ["--stix-event", "42"], ["--stix-output", "bundle.json"], ["--base"]])
    def test_removed_and_abbreviated_options_are_argparse_errors(self, monkeypatch, spies, argv):
        """The MISP-event STIX file export (``--stix``, ``--stix-event``, ``--stix-output``) is gone, and no option
        is abbreviated (``--stix`` is not ``--stix-flow``, ``--base`` not ``--baseline``)."""
        with pytest.raises(SystemExit) as exc:
            _main(monkeypatch, argv)
        assert exc.value.code == 2
        assert spies.built == [] and spies.collected == []

    def test_help_names_the_retired_options(self, monkeypatch, capsys, spies):
        with pytest.raises(SystemExit) as exc:
            _main(monkeypatch, ["--help"])
        assert exc.value.code == 0
        text = " ".join(capsys.readouterr().out.split())
        assert "Writes nothing to Neo4j" in text
        assert f"retired options: {run_pipeline.RETIRED_OPTIONS_HELP}" in text
        for option in run_pipeline.RETIRED_OPTIONS:
            assert option in text
        assert spies.built == []


class TestTheRefusalNeedsNoConfiguration:
    """``config`` requires ``NEO4J_PASSWORD`` and the MISP settings when it is imported, and the collectors import
    it. ``main`` refuses the retired options and answers ``--help`` before either is imported, so both work on a
    shell without that configuration (they stopped with a ``RuntimeError`` traceback, exit 1)."""

    @staticmethod
    def _run(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
        # A clean environment: no NEO4J_* or MISP_* variable, no PYTHONPATH; the working directory is empty.
        env = {"PATH": os.defpath, "HOME": str(tmp_path)}
        return subprocess.run(
            [sys.executable, *args], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120, check=False
        )

    def test_config_cannot_be_imported_in_that_environment(self, tmp_path):
        """The control: without it the two tests below could pass on a shell that has the settings."""
        done = self._run(tmp_path, "-c", f"import sys; sys.path.insert(0, {str(ROOT / 'src')!r}); import config")
        assert done.returncode == 1
        assert "Required environment variable NEO4J_PASSWORD is not set." in done.stderr

    @pytest.mark.parametrize(
        "argv", [["--baseline"], ["--fresh-baseline", "--baseline-days", "7"], ["--stix-flow", "--baseline"]]
    )
    def test_the_refusal_prints_its_directions(self, tmp_path, argv):
        done = self._run(tmp_path, str(ROOT / "src" / "run_pipeline.py"), *argv)
        assert done.returncode == 2, done.stderr
        assert done.stdout == ""
        refused = [option for option in run_pipeline.RETIRED_OPTIONS if option in argv]
        assert (
            done.stderr == f"run_pipeline.py: {', '.join(refused)} refused.\n{run_pipeline.RETIRED_OPTIONS_MESSAGE}\n"
        )
        assert list(tmp_path.iterdir()) == [], "the refusal created a file"

    def test_help(self, tmp_path):
        done = self._run(tmp_path, str(ROOT / "src" / "run_pipeline.py"), "--help")
        assert done.returncode == 0, done.stderr
        text = " ".join(done.stdout.split())
        assert f"retired options: {run_pipeline.RETIRED_OPTIONS_HELP}" in text
        for option in run_pipeline.RETIRED_OPTIONS:
            assert option in text
        assert done.stderr == ""


class TestUpdateModeCollectsIntoMispOnly:
    def test_every_enabled_collector_runs_once_as_the_scheduled_dags_call_it(self, monkeypatch, capsys, spies):
        import config

        monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", _ALLOWED)
        log_lines: list[str] = []

        class _Handler(logging.Handler):
            def emit(self, record):
                log_lines.append(record.getMessage())

        handler = _Handler(level=logging.INFO)
        previous = run_pipeline.logger.level
        run_pipeline.logger.addHandler(handler)
        run_pipeline.logger.setLevel(logging.INFO)
        try:
            assert _main(monkeypatch, []) == 0
        finally:
            run_pipeline.logger.removeHandler(handler)
            run_pipeline.logger.setLevel(previous)

        assert spies.built == ["EdgeGuardPipeline"]
        assert spies.drivers == [], "the update mode opened a Neo4j driver"
        assert spies.wipes == [] and spies.baseline_locks == []
        results = _collector_results()
        assert sorted(name for name, _ in spies.collected) == sorted(results)
        sources = {
            "CISACollector": "cisa",
            "MITRECollector": "mitre",
            "NVDCollector": "nvd",
            "OTXCollector": "otx",
            "CISAICSCollector": "cisa_ics",
            "FeodoCollector": "feodo",
            "SSLBlacklistCollector": "sslbl",
            "MalwareBazaarCollector": "malwarebazaar",
            "ThreatFoxCollector": "threatfox",
            "URLhausCollector": "urlhaus",
        }
        for name, kwargs in spies.collected:
            # The scheduled DAGs' call: the incremental limit, push to MISP, no baseline flag or window.
            assert kwargs == {"limit": config.get_effective_limit(sources[name]), "push_to_misp": True}, name
        # Every collector ran under the pipeline lock of this process, which is gone afterwards.
        assert spies.lock_during_collect == [str(os.getpid())] * len(results)
        assert not Path(lock_files.PIPELINE_LOCK_PATH).exists()
        total = sum(result["count"] for result in results.values())
        assert total == 439_816
        assert f"\n[STATS] Total pushed to MISP: {total} items" in log_lines
        assert (
            "   • Succeeded (10): otx, nvd, cisa, cisa_ics, mitre, feodo, sslbl, urlhaus, threatfox, malwarebazaar"
            in log_lines
        )
        assert "Collection into MISP finished." in capsys.readouterr().out

    def test_a_collector_failure_exits_1(self, monkeypatch, capsys, spies):
        """A status dict with ``success`` False (OTX's of 2026-11-01, as a failed run returns it) fails the run;
        the other collectors still run."""
        failed = dict(_collector_results()["OTXCollector"], success=False, error="push failed")

        def otx_collect(self, limit=None, push_to_misp=False, **kwargs):
            spies.collected.append(("OTXCollector", {"limit": limit, "push_to_misp": push_to_misp, **kwargs}))
            return failed

        monkeypatch.setattr(_collector_classes()["OTXCollector"], "collect", otx_collect)
        monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", _ALLOWED)
        assert _main(monkeypatch, []) == 1
        assert len(spies.collected) == 10
        assert "Collection into MISP failed or was refused." in capsys.readouterr().out

    def test_a_collector_exception_exits_1(self, monkeypatch, spies):
        def raises(self, limit=None, push_to_misp=False, **kwargs):
            raise RuntimeError("feed down")

        monkeypatch.setattr(_collector_classes()["FeodoCollector"], "collect", raises)
        monkeypatch.setattr(run_pipeline, "_report_failure_with_metrics", MagicMock())
        monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", _ALLOWED)
        assert _main(monkeypatch, []) == 1
        run_pipeline._report_failure_with_metrics.assert_called_once()

    def test_skipped_sources_are_no_failure(self, monkeypatch, spies):
        """Sources outside ``EDGEGUARD_COLLECT_SOURCES`` (here all) are skipped, and the run succeeds."""
        monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", "none")
        assert _main(monkeypatch, []) == 0
        assert spies.collected == []


class TestTheRetiredLoadIsGone:
    def test_run_pipeline_has_no_neo4j_writer(self):
        source = (ROOT / "src" / "run_pipeline.py").read_text()
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        for name in ("neo4j_client", "Neo4jClient", "MISPToNeo4jSync", "enrichment import", "load_stix21_to_neo4j"):
            assert name not in code, name
        for attribute in (
            "load_stix21_to_neo4j",
            "_run_stix_flow",
            "_create_indicates_relationships",
            "_parse_stix_pattern",
            "_stix_zone_fields",
        ):
            assert not hasattr(run_pipeline.EdgeGuardPipeline, attribute), attribute
        for attribute in ("STIX_AVAILABLE", "STIX_IMPORT_SOURCE_ID", "CLI_BASELINE_WARNING_LINES", "SOURCE_ID_MAP"):
            assert not hasattr(run_pipeline, attribute), attribute

    def test_the_helpers_only_the_retired_load_called_are_gone(self):
        import config
        from neo4j_client import Neo4jClient

        for helper in (
            "create_actor_technique_relationship",
            "create_malware_actor_relationship",
            "create_indicator_malware_relationship",
        ):
            assert not hasattr(Neo4jClient, helper), helper
        assert not hasattr(config, "baseline_collection_limit_from_env")
        for path in ("src/enrichment.py", "src/run_pipeline_misp_spt.py"):
            assert not (ROOT / path).exists(), path


# The deleted entry points and how a file would name them. A name is matched only as a whole file name
# (``setup_and_run.sh`` is not ``run.sh``, ``cve_feed_enrichment.py`` not ``enrichment.py``).
_DELETED = {
    "crontab.txt": r"crontab\.txt",
    "src/run.sh": r"(?<![\w.-])run\.sh\b",
    "src/run_full.sh": r"(?<![\w.-])run_full\.sh\b",
    "src/setup_and_run.sh": r"(?<![\w.-])setup_and_run\.sh\b",
    "src/run_with_env.sh": r"(?<![\w.-])run_with_env\.sh\b",
    "src/check_progress.sh": r"(?<![\w.-])check_progress\.sh\b",
    "src/hourly_status.sh": r"(?<![\w.-])hourly_status\.sh\b",
    "src/neo4j/docker-compose.yml": r"(?<![\w.-])neo4j/docker-compose\.yml\b",
    "src/run_pipeline_misp_spt.py": r"run_pipeline_misp_spt",
    "src/enrichment.py": r"(?<![\w.-])enrichment\.py\b|\bfrom enrichment import\b|\bimport enrichment\b",
}
_SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "build",
    "dist",
    "logs",
    "checkpoints",
    "state",
}
_KEPT_DOT_DIRS = {".github", ".cursor"}


def _repository_texts():
    """``(relative path, text)`` of every text file of the repository, Markdown without its History section."""
    for directory, subdirectories, files in os.walk(ROOT):
        subdirectories[:] = [
            d
            for d in subdirectories
            if d not in _SKIP_DIRS and not d.endswith(".egg-info") and (not d.startswith(".") or d in _KEPT_DOT_DIRS)
        ]
        for name in files:
            path = Path(directory) / name
            try:
                text = path.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            if path.suffix == ".md":
                text = text.split("\n## History", 1)[0]
            yield path.relative_to(ROOT).as_posix(), text


def test_no_repository_file_names_a_deleted_entry_point():
    scanned: set[str] = set()
    found: list[str] = []
    patterns = {deleted: re.compile(pattern) for deleted, pattern in _DELETED.items()}
    this_file = Path(__file__).relative_to(ROOT).as_posix()
    for relative, text in _repository_texts():
        scanned.add(relative)
        if relative == this_file:
            continue
        for deleted, pattern in patterns.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                found.append(f"{relative}:{line}: {deleted}")
    # The walk reached the files that named them before.
    for expected in ("README.md", "Dockerfile", "src/setup.py", "docs/SECRETS_MANAGEMENT.md", "pyproject.toml"):
        assert expected in scanned, expected
    assert ".github/workflows/ci.yml" in scanned and ".cursor/BUGBOT.md" in scanned
    assert len(scanned) > 300
    assert not found, found
    for deleted in _DELETED:
        assert not (ROOT / deleted).exists(), deleted


@pytest.mark.parametrize(
    ("text", "deleted"),
    [
        ("bash src/run.sh", "src/run.sh"),
        ("`run_with_env.sh`", "src/run_with_env.sh"),
        ("crontab crontab.txt", "crontab.txt"),
        ("cd src/neo4j/docker-compose.yml", "src/neo4j/docker-compose.yml"),
        ("import run_pipeline_misp_spt as spt", "src/run_pipeline_misp_spt.py"),
        ("from enrichment import EnrichmentEngine", "src/enrichment.py"),
        ("`src/enrichment.py`", "src/enrichment.py"),
    ],
)
def test_the_scan_patterns_find_each_name(text, deleted):
    assert re.search(_DELETED[deleted], text)


@pytest.mark.parametrize(
    "text",
    [
        "src/setup_and_run.sh is gone",
        "src/cve_feed_enrichment.py",
        "tests/test_enrichment.py",
        "dry-run.sh",
        "run.shell",
    ],
)
def test_the_scan_patterns_match_whole_names_only(text):
    hits = [deleted for deleted, pattern in _DELETED.items() if re.search(pattern, text)]
    assert hits in ([], ["src/setup_and_run.sh"]), hits
    if "setup_and_run" not in text:
        assert hits == []


# Words that only ever named the retired Neo4j load of ``run_pipeline.py`` (its STIX 2.1 import, the STIX flow)
# or its in-process baseline, with a space or a hyphen between them and with or without the STIX version.
# Current text names them only as retired. The option ``--stix-flow`` is not a description of the load (the
# scan of the retired options below covers it).
_RETIRED_LOAD = re.compile(
    r"(?<!-)STIX(?: 2\.1)?[ -](?:flow|import|loader|re-import|pipeline import)\b|load_stix21|_run_stix_flow"
    r"|CLI[ -]baseline|in-process[ -](?:CLI[ -])?baseline",
    re.IGNORECASE,
)
# The registry's display name and MISP tag of the ``stix_import`` source, which is kept.
_RETIRED_LOAD_KEPT = {
    ("src/source_registry.py", 'display_name="STIX import"'),
    ("src/source_registry.py", 'misp_tag="source:STIX-Import"'),
}
# What a line starts with besides its text: indentation and the markers of a comment, a list item or a quote.
_LINE_MARKERS = re.compile(r"^\s*(?:(?:#+|//|\*|-|>)(?=\s|$)\s*)*")


def _names_the_retired_load_as_live(relative: str, context: str) -> bool:
    """``context``, the line or the wrapped lines a match spans, names the retired load and not as retired."""
    if not _RETIRED_LOAD.search(context) or re.search(r"retire", context, re.IGNORECASE):
        return False
    return not any(relative == path and kept in context for path, kept in _RETIRED_LOAD_KEPT)


def _retired_load_mentions(relative: str, text: str) -> list[tuple[int, str]]:
    """``(line number, context)`` of every mention of the retired load that ``text`` makes as live.

    A phrase wrapped across lines ("the STIX" / "import") is found: the lines of a paragraph (a run of non-blank
    lines, comment lines and other lines apart) are joined with single spaces, their markers and indentation
    stripped, before the pattern is matched. Whether a mention is retired is judged on the lines it spans, as
    for a mention on one line: "retired" elsewhere in a long paragraph or docstring does not excuse it."""
    mentions: list[tuple[int, str]] = []
    paragraph: list[tuple[int, str]] = []

    def close() -> None:
        if not paragraph:
            return
        starts, offset = [], 0
        for _, content in paragraph:
            starts.append(offset)
            offset += len(content) + 1
        joined = " ".join(content for _, content in paragraph)
        for match in _RETIRED_LOAD.finditer(joined):
            first = max(i for i, at in enumerate(starts) if at <= match.start())
            last = max(i for i, at in enumerate(starts) if at < match.end())
            context = " ".join(content for _, content in paragraph[first : last + 1])
            if _names_the_retired_load_as_live(relative, context):
                mentions.append((paragraph[first][0], context))
        paragraph.clear()

    previous_comment = None
    for number, line in enumerate(text.splitlines(), 1):
        comment = line.lstrip().startswith("#")
        content = " ".join(_LINE_MARKERS.sub("", line, count=1).split())
        if not content or comment is not previous_comment:
            close()
        previous_comment = comment
        if content:
            paragraph.append((number, content))
    close()
    return mentions


def test_no_current_text_describes_the_retired_load_as_live():
    """The docs (History sections and the historical records aside), the Bugbot rules and the code's comments name
    the STIX import, the STIX flow and the in-process baseline only as retired. A rule that still flagged a change
    against the STIX import's reduced CVE record, or a list of readers that still named the STIX flow, described a
    path that no longer exists. A phrase wrapped across lines counts as on one line."""
    scanned: set[str] = set()
    found: list[str] = []
    for relative, text in _repository_texts():
        if relative.startswith("tests/") or (relative.endswith(".md") and "**Historical record**" in text[:600]):
            continue
        scanned.add(relative)
        for number, context in _retired_load_mentions(relative, text):
            found.append(f"{relative}:{number}: {context[:160]}")
    for expected in (".cursor/BUGBOT.md", "docs/MISP_SOURCES.md", "src/neo4j_client.py", "dags/edgeguard_pipeline.py"):
        assert expected in scanned, expected
    assert not found, found


@pytest.mark.parametrize(
    ("relative", "line", "live"),
    [
        (".cursor/BUGBOT.md", "or replaces it with the reduced record of the STIX import (`run_pipeline`)", True),
        ("docs/MISP_SOURCES.md", "it, `edgeguard stats --misp` and the STIX flow take the source", True),
        ("src/baseline_lock.py", "EdgeGuard baseline lock — cross-process mutex between CLI baseline runs", True),
        ("dags/edgeguard_pipeline.py", "# lock (or the in-process baseline's) a run whose", True),
        ("src/neo4j_client.py", "single-item path (VirusTotal enrichment, STIX pipeline import,", True),
        ("docs/CLI.md", "the options of the retired in-process baseline and its STIX import into Neo4j", False),
        ("src/source_registry.py", '        display_name="STIX import",', False),
        ("src/other.py", '        display_name="STIX import",', True),
        ("src/source_registry.py", '        misp_tag="source:STIX-Import",', False),
        ("src/other.py", '        misp_tag="source:STIX-Import",', True),
        # The name the load went by in run_pipeline.py, with the STIX version, and hyphenated forms.
        (
            "docs/KNOWLEDGE_GRAPH.md",
            "The STIX 2.1 import of `run_pipeline.py` stores each CVE with a reduced record.",
            True,
        ),
        ("src/probe.py", "# the STIX 2.1 flow of run_pipeline.py loads the bundle", True),
        ("docs/RUNBOOK.md", "the STIX-import of the CLI writes the reduced record", True),
        ("dags/edgeguard_pipeline.py", "# The CLI-baseline of run_pipeline.py takes the lock too.", True),
        ("src/probe.py", "# the in-process-baseline holds the lock", True),
        ("src/probe.py", "# the in-process-CLI-baseline holds the lock", True),
        ("src/run_pipeline.py", 'help="the STIX 2.1 import into Neo4j (retired)")', False),
        # The retired option is no description of the load.
        ("docs/CLI.md", "`--baseline`, `--fresh-baseline`, `--baseline-days` and `--stix-flow` exit 2", False),
        ("docs/KNOWLEDGE_GRAPH.md", "`stix_import` is the source of the objects of an external STIX 2.1 bundle", False),
    ],
)
def test_the_retired_load_pattern(relative, line, live):
    assert _names_the_retired_load_as_live(relative, line) is live
    assert bool(_retired_load_mentions(relative, line)) is live


@pytest.mark.parametrize(
    ("text", "found"),
    [
        # A docstring that wraps the phrase (the probe of the review: the wrapped seen-dates docstring).
        ('    """on the edges of the STIX\n    import or another writer."""\n', [1]),
        # A comment block that wraps it, and a docstring that wraps the named writer of 2026-10.
        ("# where the CVE was seen; a STIX import of this\n# bundle", [1]),
        ("    # where the CVE was seen; a STIX\n    # import of this bundle", [1]),
        ("> the readers: the STIX\n> flow and the sync", [1]),
        ("    placeholder, which a STIX\n    import of the bundle (``run_pipeline``) stored.", [1]),
        ("* the in-process\n  baseline of run_pipeline.py", [1]),
        ("indicators of the single-item path (STIX pipeline\nimport, the sync's fallback)", [1]),
        # The version, or a hyphenated form, wrapped.
        ("    # the STIX 2.1\n    # import of run_pipeline.py", [1]),
        ("the STIX\n2.1 import stores the reduced record", [1]),
        ("# The in-process\n# CLI-baseline of run_pipeline.py takes the lock too.", [1]),
        # "retired" on a line the wrapped mention spans excuses it; elsewhere in the paragraph it does not.
        ("the in-process baseline (retired) and its STIX\nimport", []),
        ("the STIX\nimport, retired on 2026-11-02", []),
        ("the retired options.\nThe sync and the STIX\nimport", [2]),
        # A blank line, or a comment ending where code starts, is no wrap.
        ("the STIX\n\nimport json", []),
        ("# see the STIX\nimport json", []),
    ],
)
def test_wrapped_mentions_of_the_retired_load_are_found(text, found):
    assert [number for number, _ in _retired_load_mentions("src/probe.py", text)] == found


# The retired options of ``run_pipeline.py`` as a hint would give them (``--baseline`` alone: not ``--baseline-only``
# or another option that starts with it, not the ``edgeguard fresh-baseline`` subcommand).
_RETIRED_OPTION = re.compile(r"(?<![\w-])--(?:fresh-baseline|baseline(?:-days)?|stix-flow)(?![\w-])")


def _retired_option_hints(text: str) -> list[tuple[int, str]]:
    """``(line number, line)`` of every line of ``text`` that names a retired option and neither "retired" nor
    "refuse" (run_pipeline.py's refusal, as other files describe it)."""
    return [
        (number, line.strip())
        for number, line in enumerate(text.splitlines(), 1)
        if _RETIRED_OPTION.search(line) and not re.search(r"retire|refuse", line, re.IGNORECASE)
    ]


def test_no_code_text_tells_the_operator_to_use_a_retired_option():
    """No text of ``src/``, ``dags/`` or ``scripts/`` (log hints, messages, comments) tells the operator to use
    ``--fresh-baseline``, ``--baseline``, ``--baseline-days`` or ``--stix-flow``, which ``run_pipeline.py`` refuses
    (exit 2): the MISP writer's ``[DEDUP]`` warning told the operator to "Use --fresh-baseline to force
    re-collection". ``run_pipeline.py``, which defines and refuses them, is not scanned."""
    scanned: set[str] = set()
    found: list[str] = []
    for relative, text in _repository_texts():
        if not relative.startswith(("src/", "dags/", "scripts/")) or relative == "src/run_pipeline.py":
            continue
        scanned.add(relative)
        found.extend(f"{relative}:{number}: {line[:160]}" for number, line in _retired_option_hints(text))
    for expected in (
        "src/collectors/misp_writer.py",
        "src/edgeguard.py",
        "dags/edgeguard_pipeline.py",
        "scripts/preflight_baseline.sh",
    ):
        assert expected in scanned, expected
    assert not found, found


def _retired_option_hints_in_paragraphs(text: str) -> list[tuple[int, str]]:
    """``(line number, line)`` of every line of ``text`` that names a retired option in a paragraph (a run of
    non-blank lines) that says nowhere that the option is retired, refused or exits 2: a sentence of the docs
    wraps, so the line that names the option need not be the line that says it is refused."""
    found: list[tuple[int, str]] = []
    for block in re.split(r"\n[ \t]*\n", text):
        start = text.count("\n", 0, text.find(block)) + 1 if block else 0
        if not _RETIRED_OPTION.search(block) or re.search(
            r"retire|refuse|exits? (?:with code )?2", block, re.IGNORECASE
        ):
            continue
        found.extend(
            (start + offset, line.strip())
            for offset, line in enumerate(block.splitlines())
            if _RETIRED_OPTION.search(line)
        )
    return found


def test_no_doc_tells_the_operator_to_use_a_retired_option():
    """The docs' main text, the README, ``.env.example`` and the Bugbot rules name ``--fresh-baseline``,
    ``--baseline``, ``--baseline-days`` or ``--stix-flow`` only in a paragraph that says the option is retired or
    refused (History sections are not read; ``docs/flow_audits/`` holds dated audit records, not instructions)."""
    scanned: set[str] = set()
    found: list[str] = []
    for relative, text in _repository_texts():
        if relative.startswith("docs/flow_audits/"):
            continue
        if not (
            (relative.startswith("docs/") and relative.endswith(".md"))
            or relative in ("README.md", ".env.example", ".cursor/BUGBOT.md")
        ):
            continue
        scanned.add(relative)
        found.extend(f"{relative}:{number}: {line[:160]}" for number, line in _retired_option_hints_in_paragraphs(text))
    for expected in ("README.md", ".env.example", ".cursor/BUGBOT.md", "docs/CLI.md", "docs/RUNBOOK.md"):
        assert expected in scanned, expected
    assert not found, found


@pytest.mark.parametrize(
    ("text", "lines"),
    [
        ("Run `python src/run_pipeline.py --fresh-baseline` to start over.", [1]),
        ("python src/run_pipeline.py --baseline\n\nnothing else", [1]),
        ("`run_pipeline.py --baseline` and `--fresh-baseline`\nexit 2 and print the directions.", []),
        ("The CLI options `--baseline` and\n`--stix-flow` are refused (exit 2).", []),
        ("`--baseline-days` was retired on 2026-11-02.", []),
        ("A refusal elsewhere.\n\n`--fresh-baseline` starts a fresh run.", [3]),
        ("edgeguard fresh-baseline --days 730", []),
    ],
)
def test_the_paragraph_scan_of_retired_options(text, lines):
    assert [number for number, _ in _retired_option_hints_in_paragraphs(text)] == lines


@pytest.mark.parametrize(
    ("line", "hint"),
    [
        ('"This is normal on re-runs. Use --fresh-baseline to force re-collection.",', True),
        ("#   - ``python src/run_pipeline.py --baseline [--fresh-baseline] [--baseline-days N]``", True),
        ("    where ``--fresh-baseline`` on the CLI did the destructive clean but", True),
        ("Resuming baseline (add --fresh-baseline to restart from scratch)", True),
        ("python src/run_pipeline.py --stix-flow", True),
        ("# src/run_pipeline.py (run_pipeline.py refuses --baseline), is refused.", False),
        ("#   - ``python src/run_pipeline.py --baseline`` (retired 2026-11-02)", False),
        (
            "Use 'edgeguard fresh-baseline' (the edgeguard_baseline DAG with fresh_baseline) to force re-collection.",
            False,
        ),
        ("edgeguard baseline --days 730", False),
        ("--baseline-only and --baseline_days are other options", False),
    ],
)
def test_the_retired_option_pattern(line, hint):
    assert bool(_retired_option_hints(line)) is hint


def test_env_example_offers_the_baseline_item_limit_under_the_name_the_code_reads():
    """``BASELINE_COLLECTION_LIMIT`` is the Airflow Variable; no environment variable of that name is read since
    ``config.baseline_collection_limit_from_env`` left with the in-process baseline. The environment override is
    ``EDGEGUARD_BASELINE_COLLECTION_LIMIT`` (``baseline_config``, passed into the Airflow container by Compose)."""
    offered = re.findall(r"(?m)^#?\s*([A-Z0-9_]*BASELINE_COLLECTION_LIMIT)=", (ROOT / ".env.example").read_text())
    assert offered == ["EDGEGUARD_BASELINE_COLLECTION_LIMIT"]
    code = "\n".join(path.read_text() for folder in ("src", "dags") for path in (ROOT / folder).rglob("*.py"))
    assert not re.search(r"(?:getenv|environ\.get|environ\[)\(?\s*[\"']BASELINE_COLLECTION_LIMIT[\"']", code)
    assert 'os.getenv("EDGEGUARD_BASELINE_COLLECTION_LIMIT")' in (ROOT / "src" / "baseline_config.py").read_text()
    assert "EDGEGUARD_BASELINE_COLLECTION_LIMIT:" in (ROOT / "docker-compose.yml").read_text()
