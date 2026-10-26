"""``EDGEGUARD_CHECKPOINT_DIR`` and its guard (2026-10-25).

``baseline_checkpoint`` reads the variable once, at import, and accepts only a directory inside the
project root (``Path.is_relative_to`` after ``resolve()``); any other value falls back to
``<project root>/checkpoints`` with a warning. The suite points the loaded module at a temporary
directory (``tests/conftest.py``), so these tests load a copy of the module placed in a temporary
project root, under a name of its own: ``sys.modules`` and the checkout are not touched.
"""

from __future__ import annotations

import importlib.util
import logging
import shutil
import uuid
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parent.parent / "src" / "baseline_checkpoint.py"


def _load_copy(project_root: Path):
    """A copy of the module whose project root is *project_root*."""
    target = project_root / "src" / "baseline_checkpoint.py"
    target.parent.mkdir(parents=True)
    shutil.copy(SOURCE, target)
    spec = importlib.util.spec_from_file_location(f"_baseline_checkpoint_copy_{uuid.uuid4().hex}", target)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "value, honoured",
    [
        pytest.param("proj/state", True, id="inside-the-project"),
        pytest.param("proj", True, id="the-project-root"),
        pytest.param("proj-evil/state", False, id="sibling-sharing-the-prefix"),
        pytest.param("elsewhere/state", False, id="outside"),
        pytest.param("proj/link/state", False, id="symlink-inside-pointing-outside"),
    ],
)
def test_the_variable_is_honoured_inside_the_project_root_only(tmp_path, monkeypatch, caplog, value, honoured):
    project_root = (tmp_path / "proj").resolve()
    project_root.mkdir()
    (tmp_path / "outside").mkdir()
    (project_root / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    monkeypatch.setenv("EDGEGUARD_CHECKPOINT_DIR", str(tmp_path / value))

    with caplog.at_level(logging.WARNING):
        module = _load_copy(project_root)

    expected = (tmp_path / value).resolve() if honoured else project_root / "checkpoints"
    assert module.CHECKPOINT_DIR == expected
    assert module.CHECKPOINT_FILE == expected / "baseline_checkpoint.json"
    reverted = [r for r in caplog.records if "outside project root" in r.getMessage()]
    assert bool(reverted) is not honoured


def test_without_the_variable_the_checkpoints_are_in_the_project_root(tmp_path, monkeypatch):
    monkeypatch.delenv("EDGEGUARD_CHECKPOINT_DIR", raising=False)
    project_root = (tmp_path / "proj").resolve()
    module = _load_copy(project_root)
    assert module.CHECKPOINT_FILE == project_root / "checkpoints" / "baseline_checkpoint.json"
