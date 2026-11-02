"""The parent re-logs a child's line at the child's level (2026-11-02).

``build_relationships.py`` runs as a child process (``subprocess_streaming.run_with_streaming_output``,
from the DAG and the CLI). The parent logged every line at INFO: the 730-day baseline of 2026-11-01
had 13 child WARNING lines (12 Neo4j notifications, one ``source_trust``) in its Airflow task log at
level ``info``. A line written in ``CHILD_LOG_FORMAT`` is now logged at its own level; any other line
(``print`` output, a traceback line) at INFO. ``build_relationships.py``'s ``__main__`` sets that format
whatever was configured before it. The lines below are the child's lines of that task log.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from subprocess_streaming import CHILD_LOG_FORMAT, child_line_level, run_with_streaming_output  # noqa: E402

# Lines of build_relationships.log (730-day baseline, 2026-11-01), without the parent's prefix.
SOURCE_TRUST_WARNING = (
    "2026-11-01 23:49:45,543 - source_trust - WARNING - MISP tag-impersonation defense is DISABLED "
    "(EDGEGUARD_ENV=dev) — all source-truthful claims accepted without creator-org verification."
)
NOTIFICATION_WARNING = (
    "2026-11-01 23:49:50,008 - neo4j.notifications - WARNING - Received notification from DBMS server: "
    "{severity: WARNING} {code: Neo.ClientNotification.Statement.UnknownPropertyKeyWarning} {category: "
    "UNRECOGNIZED} {title: The provided property key is not in the database} (the missing property name "
    "is: attributed_to)"
)
OK_LINE = (
    "2026-11-01 23:49:48,961 - __main__ - INFO -   [OK] Technique → Tactic: outer rows 824 in 1 batches, "
    "relationships created 1024, elapsed 2.8s"
)
PRINTED = ["==================================================", "EdgeGuard - Building Graph Relationships"]
# A child ERROR line in the same format (the 730-day run had none), and the traceback lines after it.
ERROR_LINE = "2026-11-02 00:13:09,605 - __main__ - ERROR - Error building relationships: Neo.TransientError"
TRACEBACK = ["Traceback (most recent call last):", '  File "build_relationships.py", line 1600, in build_relationships']


@pytest.mark.parametrize(
    "line, level",
    [
        (SOURCE_TRUST_WARNING, logging.WARNING),
        (NOTIFICATION_WARNING, logging.WARNING),
        (OK_LINE, logging.INFO),
        (ERROR_LINE, logging.ERROR),
        ("2026-11-02 00:13:09,605 - __main__ - CRITICAL - x", logging.CRITICAL),
        ("2026-11-02 00:13:09,605 - __main__ - DEBUG - x", logging.DEBUG),
        (PRINTED[0], logging.INFO),
        (PRINTED[1], logging.INFO),
        (TRACEBACK[0], logging.INFO),
        # Anchored to the prefix: a message or a printed line naming a level keeps INFO.
        ("2026-11-02 00:13:09,605 - __main__ - INFO - step - ERROR - in the message", logging.INFO),
        ("EdgeGuard - ERROR - printed by the child", logging.INFO),
        # The default ``LEVEL:name:message`` format is not read (``__main__`` sets CHILD_LOG_FORMAT).
        ("ERROR:__main__:Failed to connect to Neo4j", logging.INFO),
    ],
)
def test_the_level_is_read_from_the_format_prefix(line, level):
    assert child_line_level(line) == level


def test_the_parent_logs_each_child_line_at_its_level(tmp_path, caplog):
    lines = [SOURCE_TRUST_WARNING, *PRINTED, OK_LINE, NOTIFICATION_WARNING, ERROR_LINE, *TRACEBACK]
    path = tmp_path / "child.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    cmd = [sys.executable, "-c", "import sys; sys.stdout.write(open(sys.argv[1], encoding='utf-8').read())", str(path)]
    logger = logging.getLogger("test_child_levels")
    with caplog.at_level(logging.DEBUG, logger=logger.name):
        rc, tail = run_with_streaming_output(cmd, timeout=60, child_logger=logger, line_prefix="[build_relationships] ")
    assert rc == 0 and tail == lines
    logged = [(r.levelno, r.getMessage()) for r in caplog.records if r.name == logger.name]
    assert logged == [
        (logging.WARNING, "[build_relationships] " + SOURCE_TRUST_WARNING),
        (logging.INFO, "[build_relationships] " + PRINTED[0]),
        (logging.INFO, "[build_relationships] " + PRINTED[1]),
        (logging.INFO, "[build_relationships] " + OK_LINE),
        (logging.WARNING, "[build_relationships] " + NOTIFICATION_WARNING),
        (logging.ERROR, "[build_relationships] " + ERROR_LINE),
        (logging.INFO, "[build_relationships] " + TRACEBACK[0]),
        (logging.INFO, "[build_relationships] " + TRACEBACK[1]),
    ]


def test_build_relationships_writes_its_records_in_the_format_the_parent_reads(caplog):
    """The child as the DAG runs it, with the root logger configured before it (as an import that sets
    the default format would): its ERROR reaches the parent as an ERROR."""
    child = (
        "import logging, runpy, sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "logging.basicConfig(level=logging.INFO)\n"
        "import neo4j_client\n"
        "neo4j_client.Neo4jClient.connect = lambda self: False\n"
        f"runpy.run_path({str(SRC / 'build_relationships.py')!r}, run_name='__main__')\n"
    )
    logger = logging.getLogger("test_child_levels_build")
    with caplog.at_level(logging.DEBUG, logger=logger.name):
        rc, _tail = run_with_streaming_output([sys.executable, "-c", child], timeout=120, child_logger=logger)
    assert rc == 1
    records = [(r.levelno, r.getMessage()) for r in caplog.records if r.name == logger.name]
    errors = [message for level, message in records if level == logging.ERROR]
    assert len(errors) == 1 and errors[0].endswith(" - __main__ - ERROR - Failed to connect to Neo4j"), records
    assert (logging.INFO, "[child] EdgeGuard - Building Graph Relationships") in records


def test_the_format_is_the_one_build_relationships_sets():
    assert CHILD_LOG_FORMAT == "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    text = (SRC / "build_relationships.py").read_text(encoding="utf-8")
    main = text.split('if __name__ == "__main__":', 1)[1]
    assert "logging.basicConfig(level=logging.INFO, format=CHILD_LOG_FORMAT, force=True)" in main
