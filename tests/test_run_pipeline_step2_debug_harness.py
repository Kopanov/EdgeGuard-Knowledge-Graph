"""
Step 2 collection harness: mock Neo4j + collectors; full ``run()`` completes Steps 3–7
with lightweight mocks (no real graph / enrichment dependency).
"""

import logging
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from collectors.collector_utils import make_skipped_optional_source, make_status  # noqa: E402
from run_pipeline import EdgeGuardPipeline  # noqa: E402


def test_step2_branches_and_summary(caplog):
    """skip + fail dict + ok dict + bare dict + list + exception — logs and totals align."""
    caplog.set_level(logging.INFO)

    skip_d = make_skipped_optional_source("x", skip_reason="no key", skip_reason_class="missing_test_key")
    fail_d = make_status("y", False, count=0, error="boom")
    ok_d = make_status("z", True, count=7)
    bare_d = {"count": 3}  # no "success" key — falls through to OK path (contract: use make_status)

    def boom_collect(*_a, **_k):
        raise RuntimeError("collect boom")

    c_skip = MagicMock()
    c_skip.collect.return_value = skip_d
    c_fail = MagicMock()
    c_fail.collect.return_value = fail_d
    c_ok = MagicMock()
    c_ok.collect.return_value = ok_d
    c_bare = MagicMock()
    c_bare.collect.return_value = bare_d
    c_list = MagicMock()
    c_list.collect.return_value = [{"indicator_type": "ipv4", "value": "1.1.1.1"}]
    c_exc = MagicMock()
    c_exc.collect.side_effect = boom_collect

    p = EdgeGuardPipeline()
    p.neo4j.connect = MagicMock(return_value=True)
    p.neo4j.create_constraints = MagicMock()
    p.neo4j.create_indexes = MagicMock()
    p.neo4j.ensure_sources = MagicMock()
    p.neo4j.close = MagicMock()
    p.neo4j.get_stats = MagicMock(return_value={"by_zone": {}})
    p.neo4j.create_actor_technique_relationship = MagicMock(return_value=False)
    p.neo4j.create_malware_actor_relationship = MagicMock(return_value=False)
    p._create_indicates_relationships = MagicMock(return_value=0)

    p.collectors = {
        "misp": MagicMock(),
        "src_skip": c_skip,
        "src_fail": c_fail,
        "src_ok": c_ok,
        "src_bare": c_bare,
        "src_list": c_list,
        "src_exc": c_exc,
    }
    p.mitre_collector = MagicMock()
    p.mitre_collector.get_relationships.return_value = []

    assert p.run() is True
    p.neo4j.close.assert_called()

    text = caplog.text
    assert "[SKIP] src_skip:" in text
    assert "[ERR] src_fail:" in text and "boom" in text
    assert "[OK] src_ok: 7 items pushed to MISP" in text
    assert "[OK] src_bare: 3 items pushed to MISP" in text
    assert "[OK] src_list: 1 items pushed to MISP" in text
    assert "[ERR] src_exc collector failed:" in text and "RuntimeError" in text
    assert "Total pushed to MISP: 11 items" in text
    assert "Succeeded (3):" in text
    assert "src_ok" in text and "src_bare" in text and "src_list" in text
    assert "Skipped optional (1)" in text
    assert "Collector reported failure (1)" in text
    assert "Raised exception (1)" in text

    for c in (c_skip, c_fail, c_ok, c_bare, c_list, c_exc):
        assert c.collect.called
