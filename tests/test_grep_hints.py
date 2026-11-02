"""The grep commands EdgeGuard prints to find a log marker (2026-11).

The run summary of the MISP→Neo4j sync, the Slack alerts of a skipped or failed collector and a hint of
``scripts/verify_fresh_baseline.py`` name a log marker such as ``[ATTRIBUTION]`` and the grep command that finds
its lines. Quoted without ``-F``, grep reads the brackets as a bracket expression, one character of the set. On the
log of the full sync of the 730-day baseline of 2026-11-01 (4,564 lines) each such hint matched all 4,564 lines,
``grep '[BATCH-PERMANENT-FAILURE]'`` stopped with "invalid character range" (exit 2: the range ``T-F``), and
``grep '[nvd] FAILED'`` matched no ``[nvd] FAILED`` line, since the character before `` FAILED`` is ``]``, not one
of the set. With ``-F`` the same hints printed the lines of their marker and the run-summary line that names it:
28 lines for ``[ATTRIBUTION]`` (27 marker lines and the summary line), 3 for ``[MERGE-PLACEHOLDER-REJECTED]`` (2 and
the summary line) and 2 for ``[MERGE-REJECT]`` (2 marker lines); the other markers did not occur in that run. Every
hint now reads ``grep -F``.

Checked here: no grep hint in ``src/``, ``dags/``, ``scripts/`` or ``plugins/`` quotes a bracketed marker, in
single or double quotes, without ``-F``; and, run with the system grep over real lines of that log, the hints of
the collector failure alerts (the CLI path's ``report_collector_failure`` and the DAG's
``run_collector_with_metrics``) and of ``verify_fresh_baseline`` print exactly the lines of their markers. The hints
of the sync's run summary are run the same way in ``tests/test_cve_batch_writes.py``
(``TestTheRunSummaryReportsFallbacks``).

``fixtures/full_neo4j_sync_log_2026_11_01.jsonl`` holds 29 lines of that log, unchanged: 25 without a marker
(circuit-breaker set-up, health checks, connections; every hint without ``-F`` matched each of them), its
``[BASELINE]`` line (a marker no hint names) and its first ``[ATTRIBUTION]``, ``[MERGE-PLACEHOLDER-REJECTED]`` and
``[MERGE-REJECT]`` lines.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import logging
import re
import shlex
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Sequence, Tuple
from unittest.mock import MagicMock, patch

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
for _p in (ROOT / "src", ROOT / "dags", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

GREP = shutil.which("grep")
_LOG_LINES = (TESTS / "fixtures" / "full_neo4j_sync_log_2026_11_01.jsonl").read_text(encoding="utf-8").splitlines()
REAL_MARKER_LINES: Dict[str, List[str]] = {
    marker: [line for line in _LOG_LINES if json.loads(line)["event"].startswith(f"[{marker}]")]
    for marker in ("ATTRIBUTION", "MERGE-PLACEHOLDER-REJECTED", "MERGE-REJECT")
}
NOISE = [line for line in _LOG_LINES if not json.loads(line)["event"].startswith("[")]
# The ``[BASELINE]`` line of the sync: a bracketed marker that no hint names.
OTHER_MARKER_LINES = [line for line in _LOG_LINES if json.loads(line)["event"].startswith("[BASELINE]")]

# A grep command as the hints print it: ``grep``, then flags and patterns in single or double quotes (a
# backslash-escaped quote stays inside a double-quoted pattern, as in the shell).
_COMMAND = re.compile(r"""grep(?:\s+(?:-[A-Za-z]+|'[^']*'|"(?:[^"\\]|\\.)*"))+""")
# A bracketed log marker: ``[ATTRIBUTION]``, ``[CVE-BATCH-FALLBACK]``, or a source name an f-string fills in.
_MARKER = re.compile(r"\[(?:[A-Z]{2}[A-Z0-9_-]*|\{\w+\})\]")
_SCANNED = ("src", "dags", "scripts", "plugins")


def grep_commands(text: str) -> List[List[str]]:
    """The grep commands in ``text``, each split as the shell splits it."""
    return [shlex.split(match.group(0)) for match in _COMMAND.finditer(text)]


def log_line(event: str, level: str = "warning", logger_name: str = "run_misp_to_neo4j") -> str:
    """``event`` as one line of the Airflow task log, in the shape of the real lines of the fixture."""
    record = json.loads(REAL_MARKER_LINES["ATTRIBUTION"][0])
    record.update(event=event, level=level, logger=logger_name)
    return json.dumps(record, ensure_ascii=False)


def run_grep(command: Sequence[str], lines: Iterable[str], tmp_path: Path) -> Tuple[int, List[str]]:
    """Run ``command`` (``grep`` and its arguments) with the system grep over a log holding ``lines``."""
    assert GREP, "no grep on PATH"
    assert command[0] == "grep", command
    log = tmp_path / "task.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    done = subprocess.run([GREP, *command[1:], str(log)], capture_output=True, text=True, timeout=60)
    return done.returncode, done.stdout.splitlines()


def assert_finds_exactly(command: Sequence[str], wanted: Sequence[str], others: Sequence[str], tmp_path: Path):
    """``command`` exits 0 and prints exactly ``wanted``, from a log of real noise, ``wanted`` and ``others``."""
    assert wanted, "a hint is checked against at least one line of its marker"
    lines = NOISE[:13] + OTHER_MARKER_LINES + list(others) + list(wanted) + NOISE[13:]
    code, printed = run_grep(command, lines, tmp_path)
    assert (code, printed) == (0, [line for line in lines if line in wanted]), " ".join(command)


@contextlib.contextmanager
def logged(logger: logging.Logger) -> Iterator[List[str]]:
    """The messages ``logger`` logs in the block (a handler of its own: Airflow's logging set-up, once a DAG file
    is imported, does not pass them to pytest's handler)."""
    messages: List[str] = []
    handler = logging.Handler(logging.DEBUG)
    handler.emit = lambda record: messages.append(record.getMessage())  # type: ignore[method-assign]
    level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield messages
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)


def attack_value_line() -> str:
    """The ``[ATTACK-VALUE]`` line the sync logs for a value a MISP Import Regexp rule rewrote (2026-10-20)."""
    from run_misp_to_neo4j import MISPToNeo4jSync

    with logged(logging.getLogger("run_misp_to_neo4j")) as messages:
        MISPToNeo4jSync(neo4j_client=MagicMock())._skip_unreadable_attack_value(
            "T1059.00%WINDIR%\\Command Shell", str(uuid.uuid5(uuid.NAMESPACE_URL, "attack-value")), {"id": "138"}
        )
    (message,) = [m for m in messages if m.startswith("[ATTACK-VALUE]")]
    return log_line(message)


# ---------------------------------------------------------------------------------------------- the source scan
def _joined_literals(source: str) -> str:
    """``source`` with adjacent string literals joined, so a hint split over two literals reads as one."""
    return re.sub(r"([\"'])\s*\n\s*[rfbuRFBU]*\1", "", source)


def grep_hints(roots: Sequence[str] = _SCANNED) -> List[Tuple[str, List[str]]]:
    """Every grep command in the code that names a bracketed log marker: ``(file, the command split)``."""
    hints = []
    for root in roots:
        for path in sorted((ROOT / root).rglob("*")):
            if path.suffix not in (".py", ".sh") or "__pycache__" in path.parts:
                continue
            for command in grep_commands(_joined_literals(path.read_text(encoding="utf-8"))):
                if any(_MARKER.search(arg) for arg in command[1:] if not arg.startswith("-")):
                    hints.append((str(path.relative_to(ROOT)), command))
    return hints


def test_every_grep_hint_of_a_marker_reads_it_as_a_fixed_string():
    hints = grep_hints()
    without_f = [(path, " ".join(cmd)) for path, cmd in hints if not any(re.fullmatch(r"-\w*F\w*", a) for a in cmd)]
    assert without_f == [], "a bracketed marker is a bracket expression to grep without -F"
    markers = {m.group(0) for _path, cmd in hints for arg in cmd for m in _MARKER.finditer(arg)}
    assert {
        "[ATTRIBUTION]",
        "[CURATED]",
        "[ITEM-UNROUTABLE]",
        "[ATTACK-VALUE]",
        "[PAGED-FETCH-INCOMPLETE]",
        "[MERGE-PLACEHOLDER-REJECTED]",
        "[MERGE-RETURNED-FALSE]",
        "[MERGE-REJECT]",
        "[BATCH-PERMANENT-FAILURE]",
        "[CVE-BATCH-FALLBACK]",
        "[{source_name}]",
        "[{collector_name}]",
    } <= markers, "the scan reads every hint (none of them dropped out of it)"
    files = {path for path, _cmd in hints}
    assert {
        "src/run_misp_to_neo4j.py",
        "src/collector_failure_alerts.py",
        "dags/edgeguard_pipeline.py",
        "scripts/verify_fresh_baseline.py",
    } <= files


def test_the_scan_reads_f_strings_and_literals_split_over_lines():
    """The scan reads f-strings and a hint split over two string literals, flags and quoted patterns apart."""
    sample = (
        "f\"Full triage in Airflow logs (grep '[{source_name}] SKIPPED').\"\n"
        '"(%d CVEs; grep -F "\n    "\'[CVE-BATCH-FALLBACK]\'; nothing lost)"\n'
        "# grep the log for it\n"
    )
    commands = grep_commands(_joined_literals(sample))
    assert commands == [["grep", "[{source_name}] SKIPPED"], ["grep", "-F", "[CVE-BATCH-FALLBACK]"]]


def test_the_scan_reads_double_quoted_patterns():
    """A hint may quote its pattern in double quotes, as a shell script or a single-quoted Python string does."""
    sample = 'log \'Find them with: grep "[CURATED]" sync.log\'\ngrep -qE "\'<KEY>\'|\\"<KEY>\\"" alertmanager.yml\n'
    assert grep_commands(sample) == [["grep", "[CURATED]"], ["grep", "-qE", "'<KEY>'|\"<KEY>\""]]


def test_the_fixture_holds_the_lines_described():
    assert (len(_LOG_LINES), len(NOISE), len(OTHER_MARKER_LINES)) == (29, 25, 1)
    assert {marker: len(lines) for marker, lines in REAL_MARKER_LINES.items()} == {
        "ATTRIBUTION": 1,
        "MERGE-PLACEHOLDER-REJECTED": 1,
        "MERGE-REJECT": 1,
    }


def test_grep_without_f_does_not_find_the_markers(tmp_path):
    """What the hints did before -F, on the real log lines: every line, an error, or no line."""
    attribution = REAL_MARKER_LINES["ATTRIBUTION"]
    code, printed = run_grep(["grep", "[ATTRIBUTION]"], NOISE + OTHER_MARKER_LINES + attribution, tmp_path)
    expected = len(NOISE) + len(OTHER_MARKER_LINES) + len(attribution)
    assert (code, len(printed)) == (0, expected), "a bracket expression matches every line"
    code, _printed = run_grep(["grep", "[BATCH-PERMANENT-FAILURE]"], NOISE, tmp_path)
    assert code == 2, "the reversed range T-F is an error"
    header = log_line("[nvd] FAILED  reason=catastrophic_error  exc=KeyError", "error", "collector_failure_alerts")
    assert run_grep(["grep", "[nvd] FAILED"], NOISE + [header], tmp_path) == (1, [])
    assert run_grep(["grep", "-F", "[nvd] FAILED"], NOISE + [header], tmp_path) == (0, [header])


# ---------------------------------------------------------------------------------------------- collector alerts
def _failures() -> Dict[str, BaseException]:
    """A transient failure (the collector is skipped) and a catastrophic one (the task fails)."""
    return {"SKIPPED": ConnectionError("[Errno 61] Connection refused"), "FAILED": KeyError("pulses")}


class TestCollectorAlerts:
    """The Slack alert of a skipped or failed collector names the grep for the log block of that collector."""

    @staticmethod
    def _check(alerts: Dict[Tuple[str, str], str], blocks: Dict[Tuple[str, str], str], tmp_path: Path):
        assert set(alerts) == set(blocks) and len(alerts) == 4
        lines = {key: log_line(block, "error", "collector_failure_alerts") for key, block in blocks.items()}
        for key, alert in alerts.items():
            (command,) = grep_commands(alert)
            assert command[:2] == ["grep", "-F"], alert
            others = [line for other, line in lines.items() if other != key]
            others += [line for marker_lines in REAL_MARKER_LINES.values() for line in marker_lines]
            assert_finds_exactly(command, [lines[key]], others, tmp_path)

    def test_the_cli_path(self, monkeypatch, caplog, tmp_path):
        import collector_failure_alerts as alerts_module

        sent: List[str] = []
        monkeypatch.setattr(alerts_module, "send_slack_alert", lambda message, channel=None: sent.append(message))
        alerts, blocks = {}, {}
        for source in ("alienvault_otx", "nvd"):
            for status, exc in _failures().items():
                sent.clear()
                caplog.clear()
                with caplog.at_level(logging.WARNING, logger="collector_failure_alerts"):
                    alerts_module.report_collector_failure(source, exc, duration_s=1.0)
                (alert,) = sent
                (block,) = [r.getMessage() for r in caplog.records if r.getMessage().startswith(f"[{source}] ")]
                assert block.startswith(f"[{source}] {status}  "), block[:60]
                alerts[(source, status)], blocks[(source, status)] = alert, block
        self._check(alerts, blocks, tmp_path)

    def test_the_dag_path(self, tmp_path):
        from stub_cleanup import dag_module_import
        from test_dag_non_blocking_collectors import _import_dag_module

        with dag_module_import():
            ep = _import_dag_module()
        alerts, blocks = {}, {}
        sent: List[str] = []
        for source in ("alienvault_otx", "nvd"):
            for status, exc in _failures().items():

                class _Collector:
                    def __init__(self, *_a, **_kw):
                        pass

                    def collect(self, *_a, _exc=exc, **_kw):
                        raise _exc

                sent.clear()
                with (
                    patch.object(ep, "ensure_metrics_server", lambda: None),
                    patch.object(ep, "log_circuit_breaker_status", lambda: None),
                    patch.object(ep, "is_collector_enabled_by_allowlist", lambda _: True),
                    patch.object(ep, "send_slack_alert", lambda message, *_a, **_kw: sent.append(message)),
                    patch.object(ep, "set_source_health", MagicMock()),
                    patch.object(ep, "record_dag_run", MagicMock()),
                    patch.object(ep, "record_collection", MagicMock()),
                    patch.object(ep, "record_collection_duration", MagicMock()),
                    patch.object(ep, "record_collector_skip", MagicMock()),
                    patch.object(ep, "record_collector_outcome", MagicMock()),
                    patch.object(ep, "record_pipeline_error", MagicMock()),
                    patch.object(ep, "record_error", MagicMock()),
                    patch("baseline_lock.baseline_skip_reason", lambda **_kw: None, create=True),
                    logged(ep.logger) as messages,
                ):
                    if status == "FAILED":
                        with pytest.raises(KeyError):
                            ep.run_collector_with_metrics(source, _Collector, MagicMock(), limit=10)
                    else:
                        ep.run_collector_with_metrics(source, _Collector, MagicMock(), limit=10)
                (alert,) = sent
                (block,) = [m for m in messages if m.startswith(f"[{source}] ")]
                assert block.startswith(f"[{source}] {status}  "), block[:60]
                alerts[(source, status)], blocks[(source, status)] = alert, block
        self._check(alerts, blocks, tmp_path)


# ---------------------------------------------------------------------------------------------- verify_fresh_baseline
def test_the_verify_hint_finds_the_attack_value_lines(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "verify_fresh_baseline_grep_hint", ROOT / "scripts" / "verify_fresh_baseline.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (command,) = grep_commands(module._MANGLED_TOOLS_HINT)
    others = [line for marker_lines in REAL_MARKER_LINES.values() for line in marker_lines]
    assert_finds_exactly(command, [attack_value_line()], others, tmp_path)
