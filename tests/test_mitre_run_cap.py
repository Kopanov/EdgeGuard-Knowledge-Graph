"""MITRE ATT&CK per-run cap (2026-10).

The scheduled DAG passed ``limit=get_effective_limit("mitre")``, the incremental default (200), since
mitre was not in ``OWN_RUN_CAP_SOURCES``. ``collect`` kept every tactic plus 50 % / 20 % / 15 % / 15 %
of the limit of techniques, groups, malware and tools (about 140 objects) and then stored the new
bundle's ETag, so every later run was answered "not modified" and the objects left out never reached
MISP. mitre now has its own cap (the bundle), and a run cut by an item limit does not store the ETag.

The bundle is synthetic and follows the mitre/cti STIX layout the collector parses.
"""

import os
import sys
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import config  # noqa: E402
from collectors import mitre_collector as mc  # noqa: E402

URL = "https://attack.example/enterprise-attack.json"
N_TECHNIQUES, N_GROUPS, N_MALWARE, N_TOOLS = 150, 60, 40, 40


def _ref(mitre_id: str) -> List[Dict[str, str]]:
    return [{"source_name": "mitre-attack", "external_id": mitre_id}]


def _obj(kind: str, n: int, **extra: Any) -> Dict[str, Any]:
    base = {
        "type": kind,
        "id": f"{kind}--00000000-0000-4000-8000-{n:012d}",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2021-01-01T00:00:00.000Z",
        "description": f"{kind} {n}",
    }
    base.update(extra)
    return base


def _bundle() -> Dict[str, Any]:
    objects = [
        _obj("x-mitre-tactic", 1, name="Execution", x_mitre_shortname="execution", external_references=_ref("TA0002"))
    ]
    objects += [
        _obj(
            "attack-pattern",
            n,
            name=f"Technique {n}",
            external_references=_ref(f"T{1000 + n}"),
            kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        )
        for n in range(N_TECHNIQUES)
    ]
    objects += [
        _obj("intrusion-set", n, name=f"Group {n}", aliases=[f"Group {n}"], external_references=_ref(f"G{1000 + n}"))
        for n in range(N_GROUPS)
    ]
    objects += [
        _obj("malware", n, name=f"Malware {n}", x_mitre_aliases=[f"Malware {n}"], external_references=_ref(f"S{n:04d}"))
        for n in range(N_MALWARE)
    ]
    objects += [
        _obj("tool", n, name=f"Tool {n}", x_mitre_aliases=[f"Tool {n}"], external_references=_ref(f"S{5000 + n}"))
        for n in range(N_TOOLS)
    ]
    return {"type": "bundle", "id": "bundle--synthetic", "objects": objects}


class _Resp:
    def __init__(self, payload: Dict[str, Any], etag: str):
        self._payload = payload
        self.status_code = 200
        self.headers = {"ETag": etag}

    def json(self) -> Dict[str, Any]:
        return self._payload


@pytest.fixture
def run(monkeypatch):
    """Run one scheduled ``collect`` against a changed bundle; return (pushed items, ETag updates)."""
    monkeypatch.setattr(mc.MITRE_RATE_LIMITER, "wait_if_needed", lambda: None)
    breaker = MagicMock()
    breaker.can_execute.return_value = True
    monkeypatch.setattr(mc, "MITRE_CIRCUIT_BREAKER", breaker)
    monkeypatch.setattr(mc, "MITRE_MAX_RELATIONSHIPS", 0)
    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", False, raising=False)
    monkeypatch.setattr(mc, "get_source_incremental", lambda *_a, **_k: {"mitre_bundle_etag": '"v1"'})
    etags: List[Dict[str, Any]] = []
    monkeypatch.setattr(mc, "update_source_incremental", lambda _source, **kw: etags.append(kw))
    monkeypatch.setattr(mc, "request_with_rate_limit_retries", lambda *_a, **_k: _Resp(_bundle(), '"v2"'))

    def _run():
        pushed: List[Dict[str, Any]] = []
        writer = MagicMock()

        def push_items(items, *_a, **_k):
            pushed.extend(items)
            return len(items), 0

        writer.push_items.side_effect = push_items
        collector = mc.MITRECollector(misp_writer=writer)
        collector.attack_url = URL
        status = collector.collect(limit=config.get_effective_limit("mitre"))
        return status, pushed, etags

    return _run


def test_mitre_has_its_own_run_cap(monkeypatch):
    monkeypatch.setattr(config, "MAX_ENTRIES_PER_SOURCE", 0)
    monkeypatch.setattr(config, "INCREMENTAL_COLLECTION_LIMIT", 200)
    assert "mitre" in config.OWN_RUN_CAP_SOURCES
    assert config.get_effective_limit("mitre") is None


def test_a_scheduled_run_pushes_every_object_of_a_changed_bundle_before_storing_its_etag(monkeypatch, run):
    monkeypatch.setattr(config, "MAX_ENTRIES_PER_SOURCE", 0)
    monkeypatch.setattr(config, "INCREMENTAL_COLLECTION_LIMIT", 200)
    status, pushed, etags = run()
    assert status["success"] is True
    assert len(pushed) == 1 + N_TECHNIQUES + N_GROUPS + N_MALWARE + N_TOOLS
    assert etags == [{"mitre_bundle_etag": '"v2"'}]


def test_a_run_cut_by_the_global_item_limit_does_not_store_the_etag(monkeypatch, run, caplog):
    monkeypatch.setattr(config, "MAX_ENTRIES_PER_SOURCE", 50)
    status, pushed, etags = run()
    assert status["success"] is True
    assert len(pushed) < 1 + N_TECHNIQUES + N_GROUPS + N_MALWARE + N_TOOLS
    assert etags == []
    assert any("ETag is not stored" in r.getMessage() for r in caplog.records)
