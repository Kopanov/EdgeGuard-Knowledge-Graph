"""Lightweight edgeguard CLI tests: no full .env, mocked update (no install.sh execution)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Import after conftest adjusts sys.path
import edgeguard  # noqa: E402


def test_main_version_no_git_exits_zero(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(REPO_ROOT)
    monkeypatch.setattr(sys, "argv", ["edgeguard", "version", "--no-git"])
    assert edgeguard.main() == 0
    out = capsys.readouterr().out
    assert out.strip().startswith("edgeguard ")
    assert len(out.strip().split()) >= 2


def test_main_update_help_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["edgeguard", "update", "--help"])
    with pytest.raises(SystemExit) as exc:
        edgeguard.main()
    assert exc.value.code == 0


def test_main_version_help_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["edgeguard", "version", "--help"])
    with pytest.raises(SystemExit) as exc:
        edgeguard.main()
    assert exc.value.code == 0


def test_cmd_code_update_invokes_install_sh_python(monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not run install.sh; assert subprocess receives bash + install.sh --update --python."""
    monkeypatch.chdir(REPO_ROOT)
    calls: list[tuple[list[str], Optional[str]]] = []

    def _fake_call(cmd: list[str], cwd: str | None = None) -> int:
        calls.append((list(cmd), cwd))
        return 0

    monkeypatch.setattr(edgeguard.subprocess, "call", _fake_call)
    assert edgeguard.cmd_code_update(force_docker=False, force_python=True) == 0
    assert len(calls) == 1
    cmd, cwd = calls[0]
    assert cmd[0] == "bash"
    assert cmd[1].endswith("install.sh")
    assert cmd[2:] == ["--update", "--python"]
    assert cwd == str(REPO_ROOT)


def test_cmd_code_update_invokes_install_sh_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(REPO_ROOT)
    calls: list[list[str]] = []

    def _fake_call(cmd: list[str], cwd: str | None = None) -> int:
        calls.append(list(cmd))
        return 0

    monkeypatch.setattr(edgeguard.subprocess, "call", _fake_call)
    assert edgeguard.cmd_code_update(force_docker=False, force_python=False) == 0
    assert calls[0][2:] == ["--update"]


def test_cmd_code_update_returns_one_when_subprocess_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(REPO_ROOT)
    monkeypatch.setattr(edgeguard.subprocess, "call", lambda *a, **k: 1)
    assert edgeguard.cmd_code_update(force_docker=False, force_python=True) == 1


def test_cmd_code_update_fails_when_repo_root_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without a discoverable clone, update aborts (never calls install.sh)."""
    monkeypatch.setattr(edgeguard, "find_edgeguard_repo_root", lambda: None)
    assert edgeguard.cmd_code_update(force_docker=False, force_python=True) == 1


@patch("edgeguard.subprocess.call", return_value=0)
def test_main_update_delegates_to_subprocess(
    mock_call: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(REPO_ROOT)
    monkeypatch.setattr(sys, "argv", ["edgeguard", "update", "--python"])
    assert edgeguard.main() == 0
    assert mock_call.called
    cmd = mock_call.call_args[0][0]
    assert "install.sh" in cmd[1]
    assert "--update" in cmd
    assert "--python" in cmd


def test_setup_command_prints_install_guidance(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["edgeguard", "setup"])
    assert edgeguard.main() == 0
    out = capsys.readouterr().out
    assert "install.sh" in out
    assert "README.md" in out or "SETUP_GUIDE" in out
    assert "doctor" in out
