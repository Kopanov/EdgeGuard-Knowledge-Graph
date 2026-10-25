"""
EdgeGuard's flock-style lock files: where they are, how a process holds one, and when one may go.

EdgeGuard has two kinds of lock files:

* **flock-style**: an empty file that a process locks with ``fcntl.flock``. Its presence means
  nothing; the kernel releases the lock when the holder closes the file or exits, so a free file
  blocks nobody. The MISP writer's event-creation lock (``misp_event_lock_path``) is one.
* **presence-based**: the file itself is the lock and records its holder
  (``checkpoints/pipeline.lock`` with a PID, ``checkpoints/baseline_in_progress.lock`` with holder
  metadata). Each has its own release and stale-lock procedure (``run_pipeline.py``,
  ``baseline_lock.py``); nothing here removes one.

``remove_if_unheld`` removes an flock-style file only while it holds the lock on it, so a file that a
process holds is never removed. A process that opened the file before the removal and was waiting
for the lock gets it once the remover lets go, on a file that the name no longer reaches, while a
process that opened the name after the removal locks a new file. ``exclusive_flock`` closes that gap:
once it has the lock it checks that the path still names the file it locked, and starts again on the
current file otherwise.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator, Tuple

MISP_EVENT_LOCK_DEFAULT = "/tmp/edgeguard_misp_get_or_create_event.lock"

# The presence-based lock of a CLI pipeline run, taken by ``EdgeGuardPipeline.run`` (``run_pipeline.py``).
# The run reads it when it starts, so tests set it to a temporary path instead of the checkout's.
PIPELINE_LOCK_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "checkpoints", "pipeline.lock"
)

# ``remove_if_unheld`` outcomes.
ABSENT = "absent"
REMOVED = "removed"
HELD = "held"
KEPT = "kept"


def misp_event_lock_path() -> str:
    """Path of the lock that serialises MISP event creation (``EDGEGUARD_MISP_EVENT_LOCK_PATH``)."""
    return os.environ.get("EDGEGUARD_MISP_EVENT_LOCK_PATH") or MISP_EVENT_LOCK_DEFAULT


def _names_file(fd: int, path: str) -> bool:
    """True when *path* names the file open on *fd*."""
    try:
        named = os.stat(path)
    except FileNotFoundError:
        return False
    held = os.fstat(fd)
    return (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)


@contextmanager
def exclusive_flock(path: str) -> Iterator[None]:
    """Hold an exclusive ``flock`` on the file *path* names, creating the file when it is missing.

    After the lock is taken the path is checked to still name the locked file; when it was removed
    in the meantime (by ``remove_if_unheld``) the lock is dropped and taken again on the current file.
    Without ``fcntl`` (not Unix) the context does not lock.
    """
    try:
        import fcntl
    except ImportError:
        yield
        return

    while True:
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o666)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if _names_file(fd, path):
                break
        except BaseException:
            os.close(fd)
            raise
        os.close(fd)
    try:
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def remove_if_unheld(path: str) -> Tuple[str, str]:
    """Remove the flock-style lock file *path* when no process holds it.

    The file is removed while this function holds the lock on it (``LOCK_EX | LOCK_NB``) and the lock
    is released afterwards. Returns ``(status, detail)``: ``ABSENT`` (no file), ``REMOVED``, ``HELD``
    (a process holds it; kept) or ``KEPT`` (it could not be checked or removed; *detail* says why).
    """
    try:
        import fcntl
    except ImportError:
        return KEPT, "file locks cannot be checked on this platform"
    try:
        fd = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        return ABSENT, ""
    except OSError as exc:
        return KEPT, f"could not open it ({exc})"
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return HELD, "a running process holds it"
        except OSError as exc:
            return KEPT, f"could not test its lock ({exc})"
        if not _names_file(fd, path):
            return KEPT, "the file was replaced while it was checked; run heal again"
        try:
            os.unlink(path)
        except FileNotFoundError:
            return ABSENT, ""
        except OSError as exc:
            return KEPT, f"no process holds it, but it could not be removed ({exc})"
        return REMOVED, "no process held it"
    finally:
        os.close(fd)  # releases the lock
