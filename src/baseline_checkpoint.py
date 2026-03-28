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
if not str(_candidate).startswith(str(_PROJECT_ROOT)):
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


def clear_checkpoint(source: str = None) -> None:
    """Clear checkpoint for *source*, or all checkpoints if source is None."""
    if source:
        checkpoints = load_checkpoint()
        if source in checkpoints:
            del checkpoints[source]
            save_checkpoint(checkpoints)
    else:
        if CHECKPOINT_FILE.exists():
            CHECKPOINT_FILE.unlink()


def get_baseline_status() -> dict:
    """Return a summary of all baseline checkpoints."""
    checkpoints = load_checkpoint()
    return {
        src: {
            "pages_collected": len(data.get("pages", [])),
            "items_collected": data.get("items_collected", 0),
            "completed": data.get("completed", False),
            "last_updated": data.get("updated_at", "unknown"),
        }
        for src, data in checkpoints.items()
    }


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
