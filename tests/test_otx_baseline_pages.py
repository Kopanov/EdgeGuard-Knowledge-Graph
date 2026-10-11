"""OTX baseline page ceiling is an environment knob (2026-10), default 200 pages."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import config  # noqa: E402


def test_default_is_200():
    assert config.OTX_BASELINE_MAX_PAGES == 200


def test_env_override_and_bad_values(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_OTX_BASELINE_MAX_PAGES", "50")
    assert config._env_int("EDGEGUARD_OTX_BASELINE_MAX_PAGES", 200) == 50
    monkeypatch.setenv("EDGEGUARD_OTX_BASELINE_MAX_PAGES", "")
    assert config._env_int("EDGEGUARD_OTX_BASELINE_MAX_PAGES", 200) == 200
    monkeypatch.setenv("EDGEGUARD_OTX_BASELINE_MAX_PAGES", "many")
    assert config._env_int("EDGEGUARD_OTX_BASELINE_MAX_PAGES", 200) == 200


def test_collector_uses_the_knob_and_env_example_documents_it():
    src = (Path(__file__).resolve().parent.parent / "src" / "collectors" / "otx_collector.py").read_text()
    assert "max_pages = OTX_BASELINE_MAX_PAGES" in src
    assert "max_pages = 200" not in src
    env_example = (Path(__file__).resolve().parent.parent / ".env.example").read_text()
    assert "EDGEGUARD_OTX_BASELINE_MAX_PAGES=200" in env_example
