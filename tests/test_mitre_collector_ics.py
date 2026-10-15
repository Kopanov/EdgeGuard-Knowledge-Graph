"""MITRE ATT&CK for ICS opt-in ingestion (2026-10).

Covers ``collectors/mitre_collector.py``'s ``ENABLE_MITRE_ICS`` path with
mocked HTTP and tiny synthetic STIX bundles (the real ``ics-attack.json`` is
never read here):

(a) flag off  → only the Enterprise URL is fetched; every item carries
                ``attack_domain == "enterprise"``.
(b) flag on   → both bundles fetched; ICS techniques carry
                ``attack_domain == "ics"`` and non-empty ``tactic_phases`` taken
                from the ICS kill-chain name ``mitre-ics-attack``; ICS tactic
                items present with their TA01xx ids.
(c) ICS fetch raising → Enterprise items still returned, error metric path
                exercised, MITRE circuit breaker untouched.
(d) shared group / malware name across bundles → one item with UNIONED
                ``uses_techniques`` and ``attack_domain == "enterprise"``.
Plus: relationship cap is a TOTAL across bundles, health_check reports the
flag, 304 on Enterprise skips ICS, config defaults.
"""

import os
import sys
from copy import deepcopy
from unittest.mock import MagicMock

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from collectors import collector_utils as cu  # noqa: E402
from collectors import mitre_collector as mc  # noqa: E402

ENT_URL = "https://ent.example/enterprise-attack.json"
ICS_URL = "https://ics.example/ics-attack.json"

ICS_KILL_CHAIN = "mitre-ics-attack"
ENT_KILL_CHAIN = "mitre-attack"


# ---------------------------------------------------------------------------
# Synthetic STIX helpers
# ---------------------------------------------------------------------------


def _ext(mitre_id):
    return [{"source_name": "mitre-attack", "external_id": mitre_id}]


def _technique(stix_id, mitre_id, name, kill_chain_name, phases, description=""):
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "description": description,
        "external_references": _ext(mitre_id),
        "kill_chain_phases": [{"kill_chain_name": kill_chain_name, "phase_name": p} for p in phases],
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2021-01-01T00:00:00.000Z",
        "x_mitre_platforms": ["None"],
    }


def _tactic(stix_id, mitre_id, name, shortname):
    return {
        "type": "x-mitre-tactic",
        "id": stix_id,
        "name": name,
        "x_mitre_shortname": shortname,
        "description": f"{name} tactic",
        "external_references": _ext(mitre_id),
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2021-01-01T00:00:00.000Z",
    }


def _group(stix_id, name, aliases=None):
    return {
        "type": "intrusion-set",
        "id": stix_id,
        "name": name,
        "aliases": aliases or [name],
        "description": f"{name} description",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2021-01-01T00:00:00.000Z",
    }


def _malware(stix_id, name):
    return {
        "type": "malware",
        "id": stix_id,
        "name": name,
        "x_mitre_aliases": [name],
        "labels": ["malware"],
        "description": f"{name} description",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2021-01-01T00:00:00.000Z",
    }


def _rel(stix_id, src, tgt, rel_type="uses"):
    return {
        "type": "relationship",
        "id": stix_id,
        "relationship_type": rel_type,
        "source_ref": src,
        "target_ref": tgt,
    }


# Shared STIX ids: the real mitre/cti publishes the SAME intrusion-set /
# malware objects in both the enterprise-attack and ics-attack bundles
# (``x_mitre_domains`` lists both) — e.g. Sandworm Team, Stuxnet.
SANDWORM = "intrusion-set--381fcf73-60f6-4ab2-9991-6af3cbc35192"
STUXNET = "malware--088f1d6e-0783-47c6-9923-9c79b2af43d4"

ENT_T1059 = "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830"
ICS_T0800 = "attack-pattern--0b8b0fe2-9d6b-4a6d-b7d5-5c3a5a8c0001"
ICS_T0858 = "attack-pattern--0b8b0fe2-9d6b-4a6d-b7d5-5c3a5a8c0002"

ENTERPRISE_BUNDLE = {
    "type": "bundle",
    "id": "bundle--enterprise",
    "objects": [
        _technique(ENT_T1059, "T1059", "Command and Scripting Interpreter", ENT_KILL_CHAIN, ["execution"]),
        _tactic("x-mitre-tactic--ent-execution", "TA0002", "Execution", "execution"),
        _group(SANDWORM, "Sandworm Team", ["Sandworm Team", "ELECTRUM"]),
        _group("intrusion-set--ent-only", "APT28"),
        _malware(STUXNET, "Stuxnet"),
        _rel("relationship--e1", SANDWORM, ENT_T1059),
        _rel("relationship--e2", STUXNET, ENT_T1059),
    ],
}

ICS_BUNDLE = {
    "type": "bundle",
    "id": "bundle--ics",
    "objects": [
        _technique(ICS_T0800, "T0800", "Activate Firmware Update Mode", ICS_KILL_CHAIN, ["inhibit-response-function"]),
        _technique(ICS_T0858, "T0858", "Change Operating Mode", ICS_KILL_CHAIN, ["execution", "evasion"]),
        _tactic("x-mitre-tactic--ics-irf", "TA0107", "Inhibit Response Function", "inhibit-response-function"),
        # Same shortname as the Enterprise tactic, different id — must stay distinguishable.
        _tactic("x-mitre-tactic--ics-execution", "TA0104", "Execution", "execution"),
        _group(SANDWORM, "Sandworm Team", ["Sandworm Team", "ELECTRUM"]),
        _group("intrusion-set--ics-only", "CyberAv3ngers"),
        _malware(STUXNET, "Stuxnet"),
        _rel("relationship--i1", SANDWORM, ICS_T0800),
        _rel("relationship--i2", STUXNET, ICS_T0858),
        # Duplicate of an Enterprise edge — union must not double-count.
        _rel("relationship--i3", STUXNET, ICS_T0858),
    ],
}


class _Resp:
    headers: dict = {}

    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def _fake_http(calls, *, ics_exc=None, ent_status=200):
    """Return a ``request_with_rate_limit_retries`` stand-in keyed on URL."""

    def fake(method, url, **kwargs):
        calls.append(url)
        if url == ENT_URL:
            return _Resp(deepcopy(ENTERPRISE_BUNDLE), status_code=ent_status)
        if url == ICS_URL:
            if ics_exc is not None:
                raise ics_exc
            return _Resp(deepcopy(ICS_BUNDLE))
        raise AssertionError(f"unexpected URL fetched: {url}")

    return fake


@pytest.fixture
def collector(monkeypatch):
    """A MITRECollector with no network, no sleeps, no checkpoint I/O, mocked MISP."""
    monkeypatch.setattr(mc.MITRE_RATE_LIMITER, "wait_if_needed", lambda: None)
    breaker = MagicMock()
    breaker.can_execute.return_value = True
    monkeypatch.setattr(mc, "MITRE_CIRCUIT_BREAKER", breaker)
    monkeypatch.setattr(mc, "get_source_incremental", lambda *_a, **_k: {})
    monkeypatch.setattr(mc, "update_source_incremental", lambda *_a, **_k: None)
    monkeypatch.setattr(mc, "MITRE_MAX_RELATIONSHIPS", 0)
    # retry_with_backoff sleeps between attempts — make the failure test instant.
    monkeypatch.setattr(cu.time, "sleep", lambda _s: None)
    writer = MagicMock()
    writer.push_items.return_value = (0, 0)
    c = mc.MITRECollector(misp_writer=writer)
    c.attack_url = ENT_URL
    c.ics_attack_url = ICS_URL
    c._breaker = breaker  # test handle
    return c


def _by_type(items, typ):
    return [it for it in items if it["type"] == typ]


# ---------------------------------------------------------------------------
# (a) flag off
# ---------------------------------------------------------------------------


def test_flag_off_fetches_only_enterprise_and_marks_domain(collector, monkeypatch):
    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", False)
    calls = []
    monkeypatch.setattr(mc, "request_with_rate_limit_retries", _fake_http(calls))

    items = collector.collect(push_to_misp=False, baseline=True)

    assert calls == [ENT_URL]
    assert items, "Enterprise items expected"
    assert {it["attack_domain"] for it in items} == {"enterprise"}
    assert {it["mitre_id"] for it in _by_type(items, "technique")} == {"T1059"}
    assert {it["mitre_id"] for it in _by_type(items, "tactic")} == {"TA0002"}
    t1059 = _by_type(items, "technique")[0]
    assert t1059["tactic_phases"] == ["execution"]
    # Relationships also carry the marker.
    assert {r["attack_domain"] for r in collector.get_relationships()} == {"enterprise"}


# ---------------------------------------------------------------------------
# (b) flag on
# ---------------------------------------------------------------------------


def test_flag_on_fetches_both_and_ics_items_are_domain_tagged(collector, monkeypatch):
    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", True)
    calls = []
    monkeypatch.setattr(mc, "request_with_rate_limit_retries", _fake_http(calls))

    items = collector.collect(push_to_misp=False, baseline=True)

    assert calls == [ENT_URL, ICS_URL], "Enterprise first, then ICS"

    techniques = {it["mitre_id"]: it for it in _by_type(items, "technique")}
    assert set(techniques) == {"T1059", "T0800", "T0858"}
    assert techniques["T1059"]["attack_domain"] == "enterprise"
    assert techniques["T0800"]["attack_domain"] == "ics"
    assert techniques["T0858"]["attack_domain"] == "ics"
    # tactic_phases come from the ICS kill-chain name, not the Enterprise one.
    assert techniques["T0800"]["tactic_phases"] == ["inhibit-response-function"]
    assert techniques["T0858"]["tactic_phases"] == ["execution", "evasion"]

    tactics = {it["mitre_id"]: it for it in _by_type(items, "tactic")}
    assert set(tactics) == {"TA0002", "TA0107", "TA0104"}
    assert tactics["TA0002"]["attack_domain"] == "enterprise"
    assert tactics["TA0107"]["attack_domain"] == "ics"
    assert tactics["TA0107"]["shortname"] == "inhibit-response-function"
    # Same shortname, two domains → two distinct tactic items (the downstream
    # Technique→Tactic link must use attack_domain + shortname, not shortname alone).
    assert tactics["TA0104"]["shortname"] == "execution"
    assert tactics["TA0104"]["attack_domain"] == "ics"
    assert tactics["TA0002"]["shortname"] == "execution"

    # ICS-only actor present and tagged.
    actors = {it["name"]: it for it in _by_type(items, "actor")}
    assert actors["CyberAv3ngers"]["attack_domain"] == "ics"
    assert actors["APT28"]["attack_domain"] == "enterprise"

    # Item shape unchanged apart from the marker: every ICS technique still has
    # the keys the MISP writer reads today.
    for key in ("name", "description", "zone", "tag", "source", "first_seen", "last_seen", "platforms", "detection"):
        assert key in techniques["T0800"], key

    # Relationships merged and tagged per bundle.
    rels = collector.get_relationships()
    assert {r["attack_domain"] for r in rels} == {"enterprise", "ics"}
    assert any(r["target_mitre_id"] == "T0800" and r["attack_domain"] == "ics" for r in rels)


# ---------------------------------------------------------------------------
# (c) ICS fetch failure is isolated
# ---------------------------------------------------------------------------


def test_ics_fetch_failure_keeps_enterprise_items_and_records_metric(collector, monkeypatch):
    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", True)
    calls = []
    monkeypatch.setattr(
        mc,
        "request_with_rate_limit_retries",
        _fake_http(calls, ics_exc=requests.exceptions.ConnectionError("ics down")),
    )
    recorded = MagicMock()
    monkeypatch.setattr(mc, "_record_ics_failure", recorded)

    items = collector.collect(push_to_misp=False, baseline=True)

    # ICS was attempted (retry decorator retries ConnectionError) but never broke Enterprise.
    assert calls[0] == ENT_URL
    assert ICS_URL in calls
    assert {it["attack_domain"] for it in items} == {"enterprise"}
    assert {it["mitre_id"] for it in _by_type(items, "technique")} == {"T1059"}
    assert recorded.call_count == 1
    assert isinstance(recorded.call_args.args[0], requests.exceptions.ConnectionError)
    # Enterprise success is still recorded; an ICS outage must not trip the breaker.
    collector._breaker.record_success.assert_called_once()
    collector._breaker.record_failure.assert_not_called()


def test_ics_failure_with_push_returns_success_status_for_enterprise(collector, monkeypatch):
    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", True)
    calls = []
    monkeypatch.setattr(
        mc,
        "request_with_rate_limit_retries",
        _fake_http(calls, ics_exc=requests.exceptions.HTTPError("503")),
    )
    monkeypatch.setattr(mc, "_record_ics_failure", MagicMock())
    collector.misp_writer.push_items.return_value = (5, 0)

    status = collector.collect(push_to_misp=True, baseline=True)

    assert status["success"] is True
    pushed = collector.misp_writer.push_items.call_args.args[0]
    assert {it["attack_domain"] for it in pushed} == {"enterprise"}
    assert status["count"] == len(pushed)


def test_record_ics_failure_increments_pipeline_error_counter(monkeypatch):
    import metrics_server

    rec = MagicMock()
    monkeypatch.setattr(metrics_server, "record_pipeline_error", rec)

    mc._record_ics_failure(requests.exceptions.ConnectionError("boom"))

    rec.assert_called_once_with("collect_mitre_ics", "ConnectionError", "mitre")


def test_record_ics_failure_never_raises_when_metrics_unavailable(monkeypatch):
    import metrics_server

    monkeypatch.setattr(metrics_server, "record_pipeline_error", MagicMock(side_effect=RuntimeError("no prom")))
    mc._record_ics_failure(ValueError("x"))  # must not raise


# ---------------------------------------------------------------------------
# (d) shared objects across bundles → one item, unioned uses_techniques
# ---------------------------------------------------------------------------


def test_shared_group_and_malware_emitted_once_with_unioned_uses(collector, monkeypatch):
    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", True)
    monkeypatch.setattr(mc, "request_with_rate_limit_retries", _fake_http([]))

    items = collector.collect(push_to_misp=False, baseline=True)

    sandworm = [it for it in _by_type(items, "actor") if it["name"] == "Sandworm Team"]
    assert len(sandworm) == 1
    assert sandworm[0]["uses_techniques"] == ["T1059", "T0800"]
    # Shared object keeps Enterprise as canonical home.
    assert sandworm[0]["attack_domain"] == "enterprise"
    assert sandworm[0]["aliases"] == ["Sandworm Team", "ELECTRUM"]

    stuxnet = [it for it in _by_type(items, "malware") if it["name"] == "Stuxnet"]
    assert len(stuxnet) == 1
    # Duplicate ICS edge (i2 + i3 both → T0858) is not double-counted.
    assert stuxnet[0]["uses_techniques"] == ["T1059", "T0858"]
    assert stuxnet[0]["attack_domain"] == "enterprise"


def test_merge_is_defensive_about_duplicate_ids():
    primary = {
        "techniques": [{"mitre_id": "T1", "attack_domain": "enterprise"}],
        "tactics": [{"mitre_id": "TA1", "attack_domain": "enterprise"}],
        "actors": [],
        "malware": [],
        "tools": [{"name": "Tool", "uses_techniques": ["T1"], "attack_domain": "enterprise"}],
        "relationships": [{"type": "uses", "attack_domain": "enterprise"}],
    }
    secondary = {
        "techniques": [{"mitre_id": "T1", "attack_domain": "ics"}, {"mitre_id": "T0800", "attack_domain": "ics"}],
        "tactics": [{"mitre_id": "TA1", "attack_domain": "ics"}],
        "actors": [],
        "malware": [],
        "tools": [{"name": "Tool", "uses_techniques": ["T1", "T0800"], "attack_domain": "ics"}],
        "relationships": [{"type": "uses", "attack_domain": "ics"}],
    }
    merged = mc.MITRECollector._merge_domain_bundles(primary, secondary)
    assert [t["mitre_id"] for t in merged["techniques"]] == ["T1", "T0800"]
    assert merged["techniques"][0]["attack_domain"] == "enterprise"
    assert [t["mitre_id"] for t in merged["tactics"]] == ["TA1"]
    assert len(merged["tools"]) == 1
    assert merged["tools"][0]["uses_techniques"] == ["T1", "T0800"]
    assert merged["tools"][0]["attack_domain"] == "enterprise"
    assert len(merged["relationships"]) == 2
    # Primary input is not mutated structurally (lists copied).
    assert len(primary["techniques"]) == 1


# ---------------------------------------------------------------------------
# Cap, health, 304, config
# ---------------------------------------------------------------------------


def test_relationship_cap_is_total_across_bundles(collector, monkeypatch):
    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", True)
    monkeypatch.setattr(mc, "MITRE_MAX_RELATIONSHIPS", 2)
    monkeypatch.setattr(mc, "request_with_rate_limit_retries", _fake_http([]))

    collector.collect(push_to_misp=False, baseline=True)

    rels = collector.get_relationships()
    assert len(rels) == 2
    # Enterprise has exactly 2 ``uses`` edges, so the ICS budget is 0.
    assert {r["attack_domain"] for r in rels} == {"enterprise"}


def test_health_check_reports_ics_flag(collector, monkeypatch):
    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", True)
    hc = collector.health_check()
    assert hc["healthy"] is True
    assert hc["mitre_ics_enabled"] is True

    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", False)
    assert collector.health_check()["mitre_ics_enabled"] is False


def test_enterprise_304_skips_ics_fetch(collector, monkeypatch):
    """ICS has no ETag of its own: when Enterprise is unchanged (304) the ICS
    bundle is not fetched either (documented limitation; MITRE_FORCE_REFETCH
    or baseline mode forces both)."""
    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", True)
    monkeypatch.setattr(mc, "MITRE_USE_CONDITIONAL_GET", True)
    monkeypatch.setattr(mc, "get_source_incremental", lambda *_a, **_k: {"mitre_bundle_etag": '"v1"'})
    monkeypatch.delenv("MITRE_FORCE_REFETCH", raising=False)
    calls = []
    monkeypatch.setattr(mc, "request_with_rate_limit_retries", _fake_http(calls, ent_status=304))

    items = collector.collect(push_to_misp=False, baseline=False)

    assert items == []
    assert calls == [ENT_URL]


def test_enterprise_304_status_is_flagged_not_modified(collector, monkeypatch):
    """2026-10: the DAG records a 304 run as ``not_modified``, not as a run that collected
    nothing, so EdgeGuardNoIndicatorsCollected no longer fires for an unchanged bundle."""
    monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", False)
    monkeypatch.setattr(mc, "MITRE_USE_CONDITIONAL_GET", True)
    monkeypatch.setattr(mc, "get_source_incremental", lambda *_a, **_k: {"mitre_bundle_etag": '"v1"'})
    monkeypatch.delenv("MITRE_FORCE_REFETCH", raising=False)
    monkeypatch.setattr(mc, "request_with_rate_limit_retries", _fake_http([], ent_status=304))

    status = collector.collect(push_to_misp=True, baseline=False)

    assert status["success"] is True and status["count"] == 0 and status["not_modified"] is True
    collector.misp_writer.push_items.assert_not_called()

    monkeypatch.setattr(mc, "request_with_rate_limit_retries", _fake_http([]))
    changed = collector.collect(push_to_misp=True, baseline=False)
    assert changed["success"] is True and "not_modified" not in changed


def test_download_stix_bundle_defaults_to_enterprise_url(monkeypatch):
    seen = []

    def fake(method, url, **kwargs):
        seen.append(url)
        return _Resp({"objects": []})

    monkeypatch.setattr(mc, "request_with_rate_limit_retries", fake)
    c = mc.MITRECollector.__new__(mc.MITRECollector)
    c.attack_url = ENT_URL
    c.ics_attack_url = ICS_URL
    mc.MITRECollector._download_stix_bundle(c, etag=None)
    mc.MITRECollector._download_stix_bundle(c, etag=None, url=ICS_URL)
    assert seen == [ENT_URL, ICS_URL]


def test_config_defaults():
    import config

    assert isinstance(config.ENABLE_MITRE_ICS, bool)
    if not os.getenv("EDGEGUARD_ENABLE_MITRE_ICS"):
        assert config.ENABLE_MITRE_ICS is False, "ICS ingestion must be opt-in"
    if not os.getenv("MITRE_ICS_ATTACK_URL"):
        assert config.MITRE_ICS_ATTACK_URL == (
            "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
        )
    assert mc.ICS_KILL_CHAIN_NAME == "mitre-ics-attack"
    assert mc.ENTERPRISE_KILL_CHAIN_NAME == "mitre-attack"
