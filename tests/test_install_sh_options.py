"""``./install.sh`` stops on an option it does not know, before it touches ``.env`` or docker.

A mistyped ``--update`` used to warn and then build and start the stack without pulling, and an
invented ``--dry-run`` installed for real.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

_FAKE_DOCKER = """#!/bin/sh
echo "$*" >> "$DOCKER_LOG"
case "$*" in
    --version) echo "Docker version 27.0.0, build test" ;;
    "compose version --short") echo "2.29.0" ;;
    "compose version") echo "Docker Compose version v2.29.0" ;;
esac
exit 0
"""


def _run(tmp_path: Path, *args: str) -> tuple[subprocess.CompletedProcess, Path]:
    work = tmp_path / "work"
    work.mkdir()
    for rel in ("install.sh", ".env.example", "docker-compose.yml"):
        shutil.copy2(_ROOT / rel, work / rel)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    (fake_bin / "docker").write_text(_FAKE_DOCKER)
    (fake_bin / "docker").chmod(0o755)
    log = tmp_path / "docker.log"
    env = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}", DOCKER_LOG=str(log))
    done = subprocess.run(["bash", "install.sh", *args], cwd=work, env=env, capture_output=True, text=True, timeout=60)
    return done, work


@pytest.mark.parametrize("option", ["--dry-run", "--upadte", "-x"])
def test_unknown_option_stops_before_any_change(tmp_path, option):
    done, work = _run(tmp_path, option)
    assert done.returncode == 2, done.stdout + done.stderr
    assert option in done.stderr
    assert not (work / ".env").exists()
    assert not (tmp_path / "docker.log").exists()


def test_help_still_prints_usage_and_exits_zero(tmp_path):
    done, work = _run(tmp_path, "--help")
    assert done.returncode == 0
    assert "--update" in done.stdout
    assert not (work / ".env").exists()
