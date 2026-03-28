"""MISPHealthCheckResult dict-like API (Airflow DAG + legacy callers)."""

from __future__ import annotations

import pytest

from misp_health import MISPHealthCheckResult


def _sample() -> MISPHealthCheckResult:
    return MISPHealthCheckResult(
        healthy=False,
        status="degraded",
        checks={"api_connectivity": True, "database": True, "worker_status": False},
        details={"version": "2.4.124", "uptime": None, "issues": []},
        timestamp="2026-01-01T00:00:00",
        healthy_for_collection=True,
    )


def test_subscript_and_get() -> None:
    r = _sample()
    assert r["status"] == "degraded"
    assert r.get("healthy_for_collection") is True
    assert r.get("missing_key", 99) == 99


def test_contains_for_dag_membership_check() -> None:
    """edgeguard_pipeline uses ``if \"checks\" in result``."""
    r = _sample()
    assert "checks" in r
    assert "healthy_for_collection" in r
    assert "not_a_field" not in r


def test_contains_rejects_non_str() -> None:
    r = _sample()
    assert 1 not in r


def test_bad_key_subscript_raises() -> None:
    r = _sample()
    with pytest.raises(KeyError):
        _ = r["nope"]
