"""
Distribution version (CalVer in pyproject.toml).

Used by APIs, alert payloads, and `edgeguard version` so a single bump updates all surfaces.
"""

from __future__ import annotations

import os


def package_version() -> str:
    """Return PEP 440 version from installed metadata, else parse pyproject.toml in repo root."""
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("edgeguard")
    except PackageNotFoundError:
        pass
    return _version_from_pyproject()


def _version_from_pyproject() -> str:
    src_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(src_dir)
    path = os.path.join(root, "pyproject.toml")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s.startswith("version") and "=" in s:
                    val = s.split("=", 1)[1].strip().split("#", 1)[0].strip()
                    if val.startswith(('"', "'")):
                        return val.strip('"').strip("'")
                    return val
    except OSError:
        pass
    return "unknown"
