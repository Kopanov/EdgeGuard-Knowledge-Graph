"""Append-only audit trail for EdgeGuard's destructive graph operations (2026-10).

EdgeGuard may share its Neo4j database with ResilMesh. Every code path that deletes nodes —
the full wipe (``clear_all``), the edgeguard-only wipe (``clear_edgeguard_managed``) and the
CVSS de-duplication that runs with ``create_constraints`` — records one JSON line here and
increments the Prometheus counter ``edgeguard_destructive_ops_total{operation,target}``. The
fresh-baseline clean, ``edgeguard clear neo4j`` and ``scripts/clear_neo4j.py`` reach the first two.
A wipe attempt that fails after deleting something also records a line, with what it deleted and
``details.outcome = "failed"``; a retried wipe writes one line per attempt.
The trail answers "who deleted what, when, and how much" for the operator of a shared database
without reading application logs: each line names the process that ran the delete (``actor``:
operating-system user, host and program; for an Airflow task that is the worker, not the person
who triggered the run).

Path: ``EDGEGUARD_DESTRUCTIVE_OPS_AUDIT_PATH`` (default ``logs/destructive_ops.jsonl`` under
the working directory). Recording never raises: a failed write is logged and the operation
that called it proceeds. Set the variable to an empty string to disable the file (the counter
still increments).
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

AUDIT_PATH_ENV = "EDGEGUARD_DESTRUCTIVE_OPS_AUDIT_PATH"
DEFAULT_AUDIT_PATH = os.path.join("logs", "destructive_ops.jsonl")

_DESTRUCTIVE_OPS: Optional[Any] = None
try:  # optional, like every other metrics import in this code base
    from metrics_server import DESTRUCTIVE_OPS as _DESTRUCTIVE_OPS
except Exception:  # pragma: no cover — prometheus_client absent, an older metrics_server, or a duplicate
    # collector registration when the module is reached under two import paths; none may break a delete.
    _DESTRUCTIVE_OPS = None


def audit_path() -> Optional[Path]:
    """Resolved JSONL path, or ``None`` when the trail is disabled (variable set to empty)."""
    raw = os.getenv(AUDIT_PATH_ENV)
    if raw is None:
        return Path(DEFAULT_AUDIT_PATH)
    raw = raw.strip()
    return Path(raw) if raw else None


def _actor() -> Dict[str, str]:
    """The process that runs the delete: operating-system user, host and program name.

    Each part is left out when it cannot be read (a container user without a password-database
    entry has no name), so the audit line is still written.
    """
    actor: Dict[str, str] = {}
    try:
        actor["user"] = getpass.getuser()
    except (KeyError, OSError, ImportError) as exc:
        # No user name: a container user without a password-database entry (KeyError on older
        # Pythons, OSError from 3.13) or a platform without the pwd module. The line is still written.
        logger.debug("destructive-ops audit: operating-system user name unavailable (%s)", type(exc).__name__)
    except Exception as exc:  # noqa: BLE001 — recording never raises (the delete has already run)
        logger.warning(
            "destructive-ops audit: reading the operating-system user name failed (%s: %s); "
            "the line is written without it",
            type(exc).__name__,
            exc,
        )
    try:
        actor["host"] = socket.gethostname()
    except OSError:
        pass
    program = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    if program:
        actor["program"] = program
    return actor


def record_destructive_op(
    operation: str,
    *,
    target: str,
    affected: int,
    scope: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Append one audit line and bump the counter. Returns the record, or ``None`` if nothing was written.

    ``operation`` names the code path (``clear_all``, ``clear_edgeguard_managed``, ``cvss_dedup``),
    ``target`` the store (``neo4j``), ``affected`` the number of nodes removed, ``scope`` the
    Cypher-level selection the operation used; ``actor`` (added here) the process that ran it.
    """
    record: Dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "operation": operation,
        "target": target,
        "affected": int(affected),
        "actor": _actor(),
    }
    if scope:
        record["scope"] = scope
    if details:
        record["details"] = details

    if _DESTRUCTIVE_OPS is not None:
        try:
            _DESTRUCTIVE_OPS.labels(operation=operation, target=target).inc()
        except Exception as exc:  # pragma: no cover — metrics must never break a delete path
            logger.debug("destructive-ops counter not incremented: %s", exc)

    path = audit_path()
    if path is None:
        return record
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True, default=str) + "\n")
    except OSError as exc:
        logger.warning("destructive-ops audit line not written to %s: %s", path, exc)
        return None
    return record
