"""EDGEGUARD_COLLECT_SOURCES allowlist parsing and gating."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from collector_allowlist import (  # noqa: E402
    COLLECT_SOURCES_CANONICAL,
    collect_sources_allowlist_from_env,
    is_collector_enabled_by_allowlist,
)


@pytest.fixture
def clear_collect_sources_env(monkeypatch):
    monkeypatch.delenv("EDGEGUARD_COLLECT_SOURCES", raising=False)
    yield


def test_unset_means_all_enabled(clear_collect_sources_env):
    assert collect_sources_allowlist_from_env() is None
    assert is_collector_enabled_by_allowlist("otx") is True
    assert is_collector_enabled_by_allowlist("nvd") is True


def test_whitespace_unset(clear_collect_sources_env, monkeypatch):
    monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", "   ")
    assert collect_sources_allowlist_from_env() is None


def test_none_sentinel_disables_all(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", "none")
    assert collect_sources_allowlist_from_env() == frozenset()
    assert is_collector_enabled_by_allowlist("otx") is False


def test_subset_allowlist(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", "otx,nvd")
    assert collect_sources_allowlist_from_env() == frozenset({"otx", "nvd"})
    assert is_collector_enabled_by_allowlist("otx") is True
    assert is_collector_enabled_by_allowlist("mitre") is False


def test_case_insensitive(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", "OTX, NVD")
    assert collect_sources_allowlist_from_env() == frozenset({"otx", "nvd"})


def test_virustotal_enrich_in_canonical():
    assert "virustotal_enrich" in COLLECT_SOURCES_CANONICAL
    assert "virustotal" in COLLECT_SOURCES_CANONICAL


def test_unknown_tokens_dropped_fail_open(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", "not_a_real_collector")
    assert collect_sources_allowlist_from_env() is None
    assert is_collector_enabled_by_allowlist("otx") is True


def test_is_enabled_with_pre_parsed_allowlist(monkeypatch):
    """Second arg avoids re-parsing env each iteration (run_pipeline Step 2)."""
    monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", "otx")
    parsed = collect_sources_allowlist_from_env()
    assert parsed == frozenset({"otx"})
    assert is_collector_enabled_by_allowlist("otx", parsed) is True
    assert is_collector_enabled_by_allowlist("nvd", parsed) is False
    # Explicit empty set disables all without reading env
    assert is_collector_enabled_by_allowlist("otx", frozenset()) is False
