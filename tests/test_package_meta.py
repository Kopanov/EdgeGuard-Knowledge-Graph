"""Tests for CalVer resolution in package_meta (no Docker / install.sh)."""

from __future__ import annotations

import importlib.metadata
import os
import re
from pathlib import Path

import pytest

import package_meta

REPO_ROOT = Path(__file__).resolve().parent.parent


def _expected_version_from_pyproject() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "pyproject.toml must contain a quoted version = line"
    return m.group(1)


def test_package_version_matches_pyproject_when_metadata_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the distribution is not installed, fall back to parsing pyproject.toml next to src/."""

    def _raise(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError()

    monkeypatch.setattr(importlib.metadata, "version", _raise)
    assert package_meta.package_version() == _expected_version_from_pyproject()


def test_package_version_uses_metadata_when_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """When importlib.metadata returns a value, use it (simulated editable/wheel install)."""

    def _fake_version(name: str) -> str:
        assert name == "edgeguard"
        return "2099.1.1"

    monkeypatch.setattr(importlib.metadata, "version", _fake_version)
    assert package_meta.package_version() == "2099.1.1"


def test_version_from_pyproject_returns_unknown_when_file_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    src_dir = os.path.dirname(os.path.abspath(package_meta.__file__))
    root = os.path.dirname(src_dir)
    expected_path = os.path.normpath(os.path.join(root, "pyproject.toml"))

    real_open = open

    def selective_open(path, *args, **kwargs):
        try:
            ap = os.path.normpath(os.path.abspath(str(path)))
        except Exception:
            return real_open(path, *args, **kwargs)
        if ap == expected_path:
            raise OSError("simulated missing pyproject")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", selective_open)
    assert package_meta._version_from_pyproject() == "unknown"
