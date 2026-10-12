"""Monitoring wiring quick wins (2026-10 production-readiness check).

Cadence-aware stale alerts via a recording rule, an endpoint-down alert, no scrape jobs pointing at
exporters that do not exist, the Linux-resolvable scrape host, and a registry cross-check that
every ``edgeguard_*`` metric an alert expression references is defined.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

_ROOT = Path(__file__).resolve().parent.parent
_RULES = yaml.safe_load((_ROOT / "prometheus" / "alerts.yml").read_text())
_SCRAPE = yaml.safe_load((_ROOT / "prometheus" / "prometheus.yml").read_text())
_MON_COMPOSE = yaml.safe_load((_ROOT / "docker-compose.monitoring.yml").read_text())

# Every collector the scheduled DAGs run (dags/edgeguard_pipeline.py run_collector_with_metrics names).
_SCHEDULED_SOURCES = {
    "otx": 7200,  # every 30 min
    "cisa": 32400,  # every 4 h
    "virustotal": 32400,
    "nvd": 61200,  # every 8 h
    "mitre": 93600,  # daily
    "cisa_ics": 93600,
    "abuseipdb": 93600,
    "threatfox": 93600,
    "urlhaus": 93600,
    "feodo": 93600,
    "sslbl": 93600,
    "malwarebazaar": 93600,  # 2026-10, flag-guarded daily task
}


def _rules():
    for group in _RULES["groups"]:
        for rule in group["rules"]:
            yield rule


def _rule(name: str, key: str = "alert"):
    found = [r for r in _rules() if r.get(key) == name]
    assert len(found) == 1, (name, len(found))
    return found[0]


def test_dag_collectors_match_the_dag_module():
    src = (_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
    names = set(re.findall(r'run_collector_with_metrics\("([a-z_]+)"', src))
    assert set(_SCHEDULED_SOURCES) <= names, names - set(_SCHEDULED_SOURCES)


def test_recording_rule_maps_every_scheduled_source_to_twice_its_cadence():
    expr = _rule("edgeguard:collector_max_stale_seconds", key="record")["expr"]
    pairs = re.findall(r'label_replace\(vector\((\d+)\), "source", "([a-z_]+)"', expr)
    mapped = {source: int(seconds) for seconds, source in pairs}
    assert mapped == _SCHEDULED_SOURCES


def test_stale_alert_joins_on_the_recording_rule_and_has_a_catch_all():
    stale = _rule("EdgeGuardCollectionStale")["expr"]
    assert "edgeguard_last_success_timestamp" in stale
    assert "on (source) group_left" in stale and "edgeguard:collector_max_stale_seconds" in stale
    assert "> 3600" not in stale
    catch_all = _rule("EdgeGuardCollectionStaleUnmappedSource")["expr"]
    assert "unless on (source)" in catch_all and "93600" in catch_all


def test_no_indicators_window_covers_the_slowest_cadence():
    expr = _rule("EdgeGuardNoIndicatorsCollected")["expr"]
    assert "[26h]" in expr and "[1h]" not in expr
    assert "on (source)" in expr and "sum by (source)" in expr and "max by (source)" in expr


def test_metrics_endpoint_down_alert_exists():
    rule = _rule("EdgeGuardMetricsEndpointDown")
    assert rule["expr"].strip() == 'up{job="edgeguard"} == 0'
    assert rule["labels"]["severity"] == "warning"


def test_no_active_scrape_job_without_an_exporter():
    jobs = {j["job_name"] for j in _SCRAPE["scrape_configs"]}
    assert "edgeguard" in jobs
    assert not {"airflow", "neo4j", "misp-health"} & jobs


def test_prometheus_service_resolves_the_host_on_linux():
    prom = _MON_COMPOSE["services"]["prometheus"]
    assert "host.docker.internal:host-gateway" in prom.get("extra_hosts", [])


def test_every_edgeguard_metric_in_alert_expressions_is_defined():
    os.environ.setdefault("NEO4J_PASSWORD", "x")
    os.environ.setdefault("MISP_API_KEY", "x")
    from prometheus_client import REGISTRY

    import metrics_server  # noqa: F401

    defined = {getattr(c, "_name", None) for c in REGISTRY._names_to_collectors.values()}
    base = lambda n: re.sub(r"_(total|created|bucket|sum|count)$", "", n)  # noqa: E731
    defined_base = {base(n) for n in defined if n}
    referenced = set()
    for rule in _rules():
        # metric names only — label VALUES such as dag_id=~"edgeguard_baseline|edgeguard_daily" live
        # inside quoted strings, which are blanked out first
        unquoted = re.sub(r'"[^"]*"', '""', rule["expr"])
        referenced |= set(re.findall(r"\bedgeguard_[a-z0-9_]+", unquoted))
    missing = sorted(m for m in referenced if base(m) not in defined_base)
    assert not missing, missing
