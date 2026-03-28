"""
Contract tests: MISPWriter MITRE tactics + run_collector_with_metrics return shape.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from collectors.misp_writer import MISPWriter


def test_create_tactic_attribute_text_value_and_tags():
    w = MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)
    tactic = {
        "type": "tactic",
        "mitre_id": "TA0001",
        "name": "Initial Access",
        "shortname": "initial-access",
        "zone": ["global"],
        "tag": "mitre_attck",
    }
    attr = w.create_tactic_attribute(tactic)
    assert attr is not None
    assert attr["type"] == "text"
    assert attr["value"] == "TA0001: Initial Access"
    assert attr["to_ids"] is False
    tag_names = [t["name"] for t in attr["Tag"]]
    assert any("mitre-tactic:initial-access" in tn for tn in tag_names)


def test_push_items_dispatches_tactic_to_misp_batch():
    w = MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)
    items = [
        {
            "type": "tactic",
            "mitre_id": "TA0001",
            "name": "Initial Access",
            "shortname": "initial-access",
            "zone": ["global"],
            "tag": "mitre_attck",
        },
    ]
    with (
        patch.object(w, "_get_or_create_event", return_value="42"),
        patch.object(w, "_push_batch", return_value=(1, 0)) as mock_batch,
        patch("collectors.misp_writer.MISP_PREFETCH_EXISTING_ATTRS", False),
    ):
        ok, fail = w.push_items(items, batch_size=50)
    assert ok == 1
    assert fail == 0
    mock_batch.assert_called()
    batch_args = mock_batch.call_args[0]
    assert batch_args[0] == "42"
    assert len(batch_args[1]) == 1
    assert batch_args[1][0]["type"] == "text"


def test_run_collector_with_metrics_rejects_non_dict_return():
    # test_graphql_api.py registers MagicMock placeholders for airflow.* so GraphQL
    # tests can import without Airflow; remove them so this test loads real Airflow.
    for key in list(sys.modules):
        if key == "edgeguard_pipeline" or key.startswith("airflow"):
            del sys.modules[key]

    root = Path(__file__).resolve().parents[1]
    dags_path = str(root / "dags")
    if dags_path not in sys.path:
        sys.path.insert(0, dags_path)

    import edgeguard_pipeline as ep
    from airflow.exceptions import AirflowException as AirflowExceptionFresh

    class BadCollector:
        def __init__(self, misp_writer=None, **kwargs):
            self.writer = misp_writer

        def collect(self, **kwargs):
            return []

    writer = MagicMock()
    with (
        patch.object(ep, "ensure_metrics_server", lambda: None),
        patch.object(ep, "log_circuit_breaker_status", lambda: None),
    ):
        with pytest.raises(AirflowExceptionFresh) as excinfo:
            ep.run_collector_with_metrics("bad", BadCollector, writer, limit=10)
        msg = str(excinfo.value)
        assert "list" in msg and "status dict" in msg


def test_run_collector_with_metrics_baseline_skips_unknown_collect_params():
    """Baseline mode must not pass baseline/baseline_days to collect() unless declared (Bugbot)."""
    for key in list(sys.modules):
        if key == "edgeguard_pipeline" or key.startswith("airflow"):
            del sys.modules[key]

    root = Path(__file__).resolve().parents[1]
    dags_path = str(root / "dags")
    if dags_path not in sys.path:
        sys.path.insert(0, dags_path)

    import edgeguard_pipeline as ep

    instances: list = []

    class LegacyCollector:
        def __init__(self, misp_writer=None, **kwargs):
            self.writer = misp_writer
            instances.append(self)

        def collect(self, limit=None, push_to_misp=True):
            self.last_collect = {"limit": limit, "push_to_misp": push_to_misp}
            return {"success": True, "count": 0, "skipped": True, "skip_reason": "test"}

    writer = MagicMock()
    with (
        patch.object(ep, "ensure_metrics_server", lambda: None),
        patch.object(ep, "log_circuit_breaker_status", lambda: None),
        patch.object(ep, "is_collector_enabled_by_allowlist", lambda name: True),
    ):
        ep.run_collector_with_metrics(
            "legacy",
            LegacyCollector,
            writer,
            limit=None,
            baseline=True,
            baseline_days=999,
        )

    assert instances, "collector should have been instantiated"
    assert set(instances[-1].last_collect.keys()) == {"limit", "push_to_misp"}
    assert instances[-1].last_collect["limit"] is None  # baseline-unlimited semantics


def test_run_collector_with_metrics_baseline_forwards_when_collect_accepts():
    for key in list(sys.modules):
        if key == "edgeguard_pipeline" or key.startswith("airflow"):
            del sys.modules[key]

    root = Path(__file__).resolve().parents[1]
    dags_path = str(root / "dags")
    if dags_path not in sys.path:
        sys.path.insert(0, dags_path)

    import edgeguard_pipeline as ep

    modern_instances: list = []

    class ModernCollector:
        def __init__(self, misp_writer=None, **kwargs):
            self.seen = None
            modern_instances.append(self)

        def collect(self, limit=None, push_to_misp=True, baseline=False, baseline_days=365):
            self.seen = {
                "limit": limit,
                "push_to_misp": push_to_misp,
                "baseline": baseline,
                "baseline_days": baseline_days,
            }
            return {"success": True, "count": 0}

    writer = MagicMock()
    with (
        patch.object(ep, "ensure_metrics_server", lambda: None),
        patch.object(ep, "log_circuit_breaker_status", lambda: None),
        patch.object(ep, "is_collector_enabled_by_allowlist", lambda name: True),
    ):
        ep.run_collector_with_metrics(
            "modern",
            ModernCollector,
            writer,
            limit=50,
            baseline=True,
            baseline_days=42,
        )

    assert modern_instances
    inst = modern_instances[-1]
    assert inst.seen["baseline"] is True
    assert inst.seen["baseline_days"] == 42
    assert inst.seen["limit"] == 50
