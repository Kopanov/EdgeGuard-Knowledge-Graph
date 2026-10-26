"""Where the baseline checkpoint directory and the CLI pipeline lock are created (2026-10-25).

``baseline_checkpoint`` created ``<repo>/checkpoints`` when it was imported, so every process that
imported it (the CLI, the DAG files, a test run) left the directory behind; it is now created by the
first checkpoint write. ``EdgeGuardPipeline.run`` took its lock at a path it built itself; it now reads
``lock_files.PIPELINE_LOCK_PATH`` when it starts, whose default is the same file, and the test suite
sets it to a temporary path (``tests/conftest.py::_pipeline_lock_outside_the_repo``).
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import lock_files  # noqa: E402
from run_pipeline import EdgeGuardPipeline  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"


def _load_copy(path: Path, name: str):
    """Execute *path* as a new module object that is not registered in ``sys.modules``."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_checkpoint_directory_is_created_by_the_first_write_not_at_import(tmp_path, monkeypatch):
    # A copy of the module under <tmp>/src has <tmp> as its project root and <tmp>/checkpoints as
    # its default directory, so the import runs without touching the checkout.
    (tmp_path / "src").mkdir()
    shutil.copy(SRC / "baseline_checkpoint.py", tmp_path / "src" / "baseline_checkpoint.py")
    monkeypatch.delenv("EDGEGUARD_CHECKPOINT_DIR", raising=False)
    module = _load_copy(tmp_path / "src" / "baseline_checkpoint.py", "baseline_checkpoint_copy")
    directory = tmp_path / "checkpoints"
    assert module.CHECKPOINT_DIR == directory
    assert not directory.exists()
    assert module.load_checkpoint() == {}
    assert not directory.exists()

    module.update_source_checkpoint("nvd", page=3, items_collected=6000)

    assert module.get_source_checkpoint("nvd")["current_page"] == 3
    assert sorted(p.name for p in directory.iterdir()) == ["baseline_checkpoint.json", "baseline_checkpoint.lock"]


def test_the_pipeline_lock_defaults_to_checkpoints_pipeline_lock_in_the_repository():
    # The path ``edgeguard heal``, ``edgeguard checkpoint clear`` and the documentation name. The test
    # suite sets the module's value for every test, so a new copy of the module gives the default.
    module = _load_copy(SRC / "lock_files.py", "lock_files_copy")
    assert module.PIPELINE_LOCK_PATH == str(REPO_ROOT / "checkpoints" / "pipeline.lock")


def test_the_pipeline_takes_its_lock_at_the_path_lock_files_names_when_it_starts(tmp_path, monkeypatch):
    lock = tmp_path / "pipeline.lock"
    lock.write_text("1")  # PID 1 is alive on every Unix host: the run must refuse to start
    monkeypatch.setattr(lock_files, "PIPELINE_LOCK_PATH", str(lock))
    pipeline = EdgeGuardPipeline()
    pipeline._run_pipeline_inner = MagicMock(side_effect=AssertionError("the run went past the lock"))

    assert pipeline.run() is False

    pipeline._run_pipeline_inner.assert_not_called()
    assert lock.read_text() == "1"
