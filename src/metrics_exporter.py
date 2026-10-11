"""Prometheus exposition for the multi-process Airflow deployment (2026-10 production-readiness check).

Under Airflow's LocalExecutor every task is its own process, so metrics recorded by a task lived in a
registry Prometheus never scraped. With ``PROMETHEUS_MULTIPROC_DIR`` set, ``prometheus_client`` writes
every metric value to memory-mapped files in that directory instead; this module

* serves the aggregated view of those files (``serve`` — run as the ``metrics`` compose service), and
* compacts the directory (``compact_multiproc_dir``): files left by processes that have exited are
  merged into one file per metric type — counters, histograms and summaries summed per series,
  ``mostrecent`` gauges keeping the newest sample — so the directory does not grow without bound.
  Compaction must run in the same PID namespace as the task processes (an Airflow task calls it).

Gauges in this code base are declared with ``multiprocess_mode="mostrecent"`` so one series per label
set is exported with the latest value written by any process, which is the meaning every gauge here
has (last success time, health, state).
"""

from __future__ import annotations

import fcntl
import glob
import logging
import os
import time
from typing import Dict, Iterable, List, Optional, Set, Tuple

from prometheus_client import CollectorRegistry, start_http_server
from prometheus_client.mmap_dict import MmapedDict
from prometheus_client.multiprocess import MultiProcessCollector

logger = logging.getLogger(__name__)

MULTIPROC_ENV = "PROMETHEUS_MULTIPROC_DIR"
MERGED_TOKEN = "merged"
_SUMMABLE_TYPES = ("counter", "histogram", "summary")


def multiproc_dir() -> Optional[str]:
    """The multiprocess directory from the environment, or ``None`` when the mode is off."""
    raw = (os.getenv(MULTIPROC_ENV) or "").strip()
    return raw or None


def multiprocess_mode_active() -> bool:
    return multiproc_dir() is not None


def ensure_multiproc_dir() -> Optional[str]:
    """Create the directory if the mode is on (``prometheus_client`` needs it before the first metric)."""
    path = multiproc_dir()
    if path:
        os.makedirs(path, exist_ok=True)
    return path


def build_registry(path: Optional[str] = None) -> CollectorRegistry:
    """A registry that aggregates every process's files; ``path`` defaults to the environment."""
    registry = CollectorRegistry()
    MultiProcessCollector(registry, path=path or multiproc_dir())
    return registry


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _classify(filename: str) -> Tuple[Optional[str], Optional[int]]:
    """``(group, pid)`` for a metric file; ``group`` is None for files compaction leaves alone."""
    name = os.path.basename(filename)
    if not name.endswith(".db"):
        return None, None
    parts = name[:-3].split("_")
    group: Optional[str]
    if parts[0] in _SUMMABLE_TYPES and len(parts) == 2:
        group = parts[0]
    elif parts[0] == "gauge" and len(parts) == 3 and parts[1] == "mostrecent":
        group = "gauge_mostrecent"
    else:
        return None, None  # other gauge modes keep the library's own per-process semantics
    last = parts[-1]
    return group, (int(last) if last.isdigit() else None)


def _merge(group: str, inputs: Iterable[str]) -> Dict[str, Tuple[float, float]]:
    values: Dict[str, Tuple[float, float]] = {}
    for path in inputs:
        for key, value, timestamp, _pos in MmapedDict.read_all_values_from_file(path):
            if group == "gauge_mostrecent":
                ts = float(timestamp or 0.0)
                current = values.get(key)
                if current is None or ts >= current[1]:
                    values[key] = (value, ts)
            else:
                values[key] = (values.get(key, (0.0, 0.0))[0] + value, 0.0)
    return values


def compact_multiproc_dir(
    path: Optional[str] = None, live_pids: Optional[Set[int]] = None, min_files: int = 0
) -> Dict[str, object]:
    """Merge the files of exited processes into ``<type>_merged.db`` per type and delete them.

    ``live_pids`` overrides the liveness probe (tests); by default a file is considered live when
    ``os.kill(pid, 0)`` succeeds. Concurrent callers are serialised by a lock file; a caller that
    cannot take the lock returns immediately. Returns a small report dictionary.
    """
    directory = path or multiproc_dir()
    if not directory or not os.path.isdir(directory):
        return {"skipped": "no multiprocess directory"}
    files = glob.glob(os.path.join(directory, "*.db"))
    if len(files) < min_files:
        return {"skipped": f"{len(files)} files below the threshold of {min_files}"}
    with open(os.path.join(directory, ".compact.lock"), "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return {"skipped": "another compaction is running"}
        groups: Dict[str, List[str]] = {}
        for f in files:
            group, pid = _classify(f)
            if group is None:
                continue
            if pid is not None:
                alive = pid in live_pids if live_pids is not None else _pid_alive(pid)
                if alive:
                    continue
            groups.setdefault(group, []).append(f)
        merged_types = 0
        removed = 0
        for group, candidates in groups.items():
            merged_path = os.path.join(directory, f"{group}_{MERGED_TOKEN}.db")
            inputs = sorted(set(candidates) | ({merged_path} if os.path.exists(merged_path) else set()))
            if not any(p != merged_path for p in inputs):
                continue  # nothing new to fold in
            values = _merge(group, inputs)
            tmp = merged_path + ".tmp"
            if os.path.exists(tmp):
                os.remove(tmp)
            writer = MmapedDict(tmp)
            for key, (value, ts) in values.items():
                writer.write_value(key, value, ts)
            writer.close()
            os.replace(tmp, merged_path)
            merged_types += 1
            for p in inputs:
                if p != merged_path:
                    os.remove(p)
                    removed += 1
        return {
            "merged_types": merged_types,
            "removed_files": removed,
            "remaining_files": len(glob.glob(os.path.join(directory, "*.db"))),
        }


def serve(host: str, port: int) -> None:
    """Serve the aggregated ``/metrics`` endpoint until interrupted."""
    ensure_multiproc_dir()
    registry = build_registry()
    start_http_server(port, addr=host, registry=registry)
    logger.info("Multiprocess metrics exporter serving http://%s:%s/metrics from %s", host, port, multiproc_dir())
    while True:
        time.sleep(3600)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    if not multiprocess_mode_active():
        logger.error(
            "%s is not set — nothing to export; set it to the directory the task processes write to", MULTIPROC_ENV
        )
        return 2
    host = os.getenv("EDGEGUARD_METRICS_HOST", "127.0.0.1")
    try:
        port = int(os.getenv("EDGEGUARD_METRICS_PORT", "8001"))
    except ValueError:
        port = 8001
    serve(host, port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
