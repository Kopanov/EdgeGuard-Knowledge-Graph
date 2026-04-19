"""
Baseline checkpoint management for EdgeGuard pipeline.

Stores progress during baseline runs so they can be resumed if interrupted.

Safety properties:
- Writes are atomic (write-tmp → fsync → rename) to prevent corruption on crash.
- Path-traversal guard: EDGEGUARD_CHECKPOINT_DIR must stay inside the project root.
- Parse errors on load are logged (not silently swallowed) before returning {}.
"""

import fcntl
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Path setup ────────────────────────────────────────────────────────────────

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_default_checkpoint_dir = _PROJECT_ROOT / "checkpoints"

_raw_dir = os.getenv("EDGEGUARD_CHECKPOINT_DIR", str(_default_checkpoint_dir))
_candidate = Path(_raw_dir).resolve()

# Guard against path-traversal via env var.
#
# Production-test audit fix (Bug Hunter HIGH BH2-HIGH, post-PR-C-merge):
# the previous ``str(_candidate).startswith(str(_PROJECT_ROOT))`` check was a
# substring-prefix check, not a directory-prefix check. With
# ``_PROJECT_ROOT="/opt/edgeguard"``, an env var ``EDGEGUARD_CHECKPOINT_DIR=
# /opt/edgeguard-evil/state`` would PASS the guard because
# ``"/opt/edgeguard-evil/state".startswith("/opt/edgeguard")`` is True. The
# docstring above advertised "stays inside the project root" — it didn't.
# ``Path.is_relative_to`` (Python 3.9+; project requires 3.12+) is the correct
# directory-prefix check. Equality-with-root is also accepted.
if _candidate != _PROJECT_ROOT and not _candidate.is_relative_to(_PROJECT_ROOT):
    logger.warning(
        "EDGEGUARD_CHECKPOINT_DIR=%r is outside project root; reverting to default.",
        _raw_dir,
    )
    _candidate = _default_checkpoint_dir

CHECKPOINT_DIR = _candidate
CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
CHECKPOINT_FILE = CHECKPOINT_DIR / "baseline_checkpoint.json"


# ── Atomic write helper ───────────────────────────────────────────────────────


def _atomic_write(path: Path, data: dict) -> None:
    """Write *data* as JSON to *path* atomically (tmp → fsync → rename)."""
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(path)  # Atomic on POSIX; near-atomic on Windows
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


# ── Public API ────────────────────────────────────────────────────────────────


def load_checkpoint() -> dict:
    """Load checkpoint from file. Returns {} on missing or corrupt file."""
    if not CHECKPOINT_FILE.exists():
        return {}
    try:
        with open(CHECKPOINT_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Could not parse checkpoint file %s: %s — starting fresh.", CHECKPOINT_FILE, e)
        return {}


def save_checkpoint(data: dict) -> None:
    """Atomically save checkpoint to file."""
    try:
        _atomic_write(CHECKPOINT_FILE, data)
    except Exception as e:
        logger.warning("Could not save checkpoint: %s", e)


def get_source_checkpoint(source: str) -> dict:
    """Get checkpoint for a specific source."""
    return load_checkpoint().get(source, {})


def _checkpoint_lock_path() -> Path:
    """Return the path for the checkpoint advisory lock file."""
    return CHECKPOINT_FILE.with_suffix(".lock")


def update_source_checkpoint(
    source: str,
    page: int = None,
    items_collected: int = None,
    last_timestamp: str = None,
    completed: bool = False,
    extra: dict = None,
) -> None:
    """Update checkpoint for a specific source (load → modify → atomic-save).

    Uses an advisory file lock to prevent concurrent read-modify-write
    corruption when multiple Airflow workers access the same checkpoint.

    *extra* merges arbitrary fields into the source entry (e.g. NVD multi-window resume:
    ``nvd_window_idx``, ``nvd_start_index``).
    """
    lock_path = _checkpoint_lock_path()
    lock_path.touch(exist_ok=True)
    with open(lock_path, "r") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        checkpoints = load_checkpoint()

        if source not in checkpoints:
            checkpoints[source] = {
                "started_at": datetime.now(timezone.utc).isoformat(),
                "pages": [],
                "items_collected": 0,
                "completed": False,
            }

        entry = checkpoints[source]

        if page is not None:
            entry["current_page"] = page
            if page not in entry.get("pages", []):
                entry.setdefault("pages", []).append(page)

        if items_collected is not None:
            entry["items_collected"] = items_collected

        if last_timestamp:
            entry["last_timestamp"] = last_timestamp

        if extra:
            entry.update(extra)

        if completed:
            entry["completed"] = True
            entry["completed_at"] = datetime.now(timezone.utc).isoformat()
            entry.pop("nvd_window_idx", None)
            entry.pop("nvd_start_index", None)

        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        save_checkpoint(checkpoints)


def get_source_incremental(source: str) -> dict:
    """
    Per-source **incremental** state (separate from baseline pagination).

    Used for ``modified_since`` / ETag style dedup across scheduled runs.
    Stored under ``checkpoints[source]["incremental"]`` so baseline page counters stay independent.
    """
    return load_checkpoint().get(source, {}).get("incremental", {})


def update_source_incremental(source: str, **kwargs) -> None:
    """Merge *kwargs* into ``checkpoints[source]["incremental"]`` and save atomically.

    Uses the same advisory file lock as update_source_checkpoint.
    """
    lock_path = _checkpoint_lock_path()
    lock_path.touch(exist_ok=True)
    with open(lock_path, "r") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        checkpoints = load_checkpoint()
        if source not in checkpoints:
            checkpoints[source] = {
                "started_at": datetime.now(timezone.utc).isoformat(),
                "pages": [],
                "items_collected": 0,
                "completed": False,
            }
        entry = checkpoints[source]
        inc = entry.setdefault("incremental", {})
        inc.update({k: v for k, v in kwargs.items() if v is not None})
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        save_checkpoint(checkpoints)


def clear_checkpoint(source: str = None, *, include_incremental: bool = False) -> None:
    """Clear baseline checkpoint for *source*, or all baseline checkpoints if source is None.

    By default, preserves incremental state (``"incremental"`` sub-dict inside
    each source entry) so that scheduled runs don't lose their cursors after a
    fresh baseline.  Pass ``include_incremental=True`` to wipe everything
    (used by database wipe scripts that need a full reset).
    """
    if source:
        checkpoints = load_checkpoint()
        if source in checkpoints:
            if include_incremental:
                del checkpoints[source]
            else:
                # Preserve incremental sub-dict for this source
                inc = checkpoints[source].get("incremental") if isinstance(checkpoints[source], dict) else None
                if inc:
                    checkpoints[source] = {"incremental": inc}
                else:
                    del checkpoints[source]
            save_checkpoint(checkpoints)
    else:
        if include_incremental:
            # Full wipe — used by clear_misp.py / clear_neo4j.py
            if CHECKPOINT_FILE.exists():
                CHECKPOINT_FILE.unlink()
        else:
            checkpoints = load_checkpoint()
            # Keep only incremental state from each source
            preserved = {}
            for src, data in checkpoints.items():
                inc = data.get("incremental") if isinstance(data, dict) else None
                if inc:
                    preserved[src] = {"incremental": inc}
            if preserved:
                save_checkpoint(preserved)
            elif CHECKPOINT_FILE.exists():
                CHECKPOINT_FILE.unlink()


def get_baseline_status() -> dict:
    """Return a summary of all baseline checkpoints.

    Excludes entries that only contain incremental state (no baseline
    progress) — these are leftover from ``clear_checkpoint()`` which
    preserves incremental cursors.
    """
    checkpoints = load_checkpoint()
    result = {}
    for src, data in checkpoints.items():
        if not isinstance(data, dict):
            continue
        # Skip entries that only have incremental state (no baseline fields)
        has_baseline = any(k in data for k in ("page", "pages", "items_collected", "completed", "started_at"))
        if not has_baseline:
            continue
        result[src] = {
            "pages_collected": len(data.get("pages", [])),
            "items_collected": data.get("items_collected", 0),
            "completed": data.get("completed", False),
            "last_updated": data.get("updated_at", "unknown"),
        }
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "status":
            for src, info in get_baseline_status().items():
                print(
                    f"  {src}: {info['pages_collected']} pages, "
                    f"{info['items_collected']} items, completed={info['completed']}"
                )
        elif sys.argv[1] == "clear":
            clear_checkpoint()
            print("Checkpoints cleared.")
    else:
        print("Usage: python baseline_checkpoint.py [status|clear]")
