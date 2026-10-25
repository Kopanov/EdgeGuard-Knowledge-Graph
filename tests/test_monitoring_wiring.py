"""Monitoring wiring quick wins (2026-10 production-readiness check).

Cadence-aware stale alerts via a recording rule, an endpoint-down alert, no scrape jobs pointing at
exporters that do not exist, the scrape path to the ``metrics`` service over the shared application
network, an Alertmanager configuration that loads without secrets, and a registry cross-check that
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
_APP_COMPOSE = yaml.safe_load((_ROOT / "docker-compose.yml").read_text())
_ALERTMANAGER = yaml.safe_load((_ROOT / "prometheus" / "alertmanager.yml").read_text())

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

# Sources stamped outside run_collector_with_metrics (2026-10): the MISP to Neo4j sync, every 72 h.
_SYNC_SOURCES = {"misp_to_neo4j": 352800}


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
    # Source names may contain digits (misp_to_neo4j); every branch of the expression must parse.
    pairs = re.findall(r'label_replace\(vector\((\d+)\), "source", "([a-z0-9_]+)"', expr)
    assert len(pairs) == expr.count("label_replace(")
    mapped = {source: int(seconds) for seconds, source in pairs}
    assert mapped == {**_SCHEDULED_SOURCES, **_SYNC_SOURCES}


def test_misp_to_neo4j_is_the_series_the_sync_stamps():
    """2026-10: unmapped, the series fell to the 26 h catch-all and fired about 46 h of every 72 h. The
    mapped limit is checked against the simulated sync schedule in tests/test_monitoring_signals.py."""
    sync_src = (_ROOT / "src" / "run_misp_to_neo4j.py").read_text()
    assert sync_src.count('record_collection_success("misp_to_neo4j")') >= 2, "the series the map covers"


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


def _edgeguard_targets():
    job = next(j for j in _SCRAPE["scrape_configs"] if j["job_name"] == "edgeguard")
    return [t for cfg in job["static_configs"] for t in cfg["targets"]]


def test_edgeguard_scrape_target_is_the_metrics_service_by_name():
    """2026-10: host.docker.internal:8001 was refused on Linux (the publish is 127.0.0.1 only)."""
    assert _edgeguard_targets() == ["metrics:8001"]
    metrics = _APP_COMPOSE["services"]["metrics"]
    assert metrics["environment"]["EDGEGUARD_METRICS_PORT"] == "8001"
    assert metrics["environment"]["EDGEGUARD_METRICS_HOST"] == "0.0.0.0", "reachable from peer containers"
    assert metrics["ports"] == ["127.0.0.1:8001:8001"], "the loopback publish stays for local access"


def test_prometheus_shares_the_application_network_with_the_metrics_service():
    prom = _MON_COMPOSE["services"]["prometheus"]
    assert "edgeguard_net" in prom["networks"] and "edgeguard_monitoring" in prom["networks"]
    assert "edgeguard_net" in _APP_COMPOSE["services"]["metrics"]["networks"]
    assert "edgeguard_net" in _APP_COMPOSE["networks"]
    # Declared once, in docker-compose.yml: a second declaration in the monitoring file would be merged
    # into it (an `external: true` next to driver/ipam is rejected by Compose; a bare entry diverges).
    assert "edgeguard_net" not in _MON_COMPOSE["networks"]
    # Kept for the optional host targets commented out in prometheus.yml.
    assert "host.docker.internal:host-gateway" in prom.get("extra_hosts", [])


def _undeclared_networks(*documents):
    services: dict = {}
    declared: set = set()
    for doc in documents:
        for name, service in doc.get("services", {}).items():
            services.setdefault(name, set()).update(service.get("networks", []) or [])
        declared |= set(doc.get("networks", {}) or {})
    return {(name, net) for name, nets in services.items() for net in nets if net not in declared}


def test_the_monitoring_file_resolves_only_together_with_the_application_file():
    """Started together (make monitoring) every network resolves; alone, Compose refuses the file."""
    assert _undeclared_networks(_APP_COMPOSE, _MON_COMPOSE) == set()
    assert _undeclared_networks(_MON_COMPOSE) == {("prometheus", "edgeguard_net")}
    makefile = (_ROOT / "Makefile").read_text()
    target = makefile.split("\nmonitoring: .env\n", 1)[1].split("\n\n", 1)[0]
    assert "-f docker-compose.yml -f docker-compose.monitoring.yml up -d" in target


def _slack_url_sources(config: dict) -> list:
    """(receiver, problem) for every Slack config that cannot load or has no URL source."""
    problems = []
    glob = config.get("global") or {}
    if "slack_api_url" in glob and not str(glob["slack_api_url"] or "").startswith(("https://", "http://")):
        problems.append(("global", "slack_api_url is not an http(s) URL"))
    global_source = str(glob.get("slack_api_url") or "").startswith(("https://", "http://")) or bool(
        glob.get("slack_api_url_file")
    )
    for receiver in config.get("receivers", []):
        for slack in receiver.get("slack_configs", []) or []:
            url = str(slack.get("api_url") or "")
            if "api_url" in slack and not url.startswith(("https://", "http://")):
                problems.append((receiver["name"], "api_url is not an http(s) URL"))
            if not (url.startswith(("https://", "http://")) or slack.get("api_url_file") or global_source):
                problems.append((receiver["name"], "no api_url, api_url_file or global Slack URL source"))
    return problems


def test_alertmanager_slack_configs_load_without_a_secret_in_the_file():
    """2026-10: `slack_api_url: ''` made Alertmanager v0.28 exit at startup (unsupported scheme)."""
    receivers_with_slack = [r["name"] for r in _ALERTMANAGER["receivers"] if r.get("slack_configs")]
    assert receivers_with_slack, "the check below must have Slack configs to inspect"
    assert _slack_url_sources(_ALERTMANAGER) == []
    # The shape that crash-looped, and Slack configs with no URL source at all, are both reported.
    broken = {**_ALERTMANAGER, "global": {**_ALERTMANAGER["global"], "slack_api_url": ""}}
    broken["global"].pop("slack_api_url_file", None)
    assert ("global", "slack_api_url is not an http(s) URL") in _slack_url_sources(broken)
    assert {name for name, _ in _slack_url_sources(broken)} >= set(receivers_with_slack)


def test_alertmanager_email_configs_use_only_alertmanager_fields():
    """2026-10: `subject:` / `body:` in email_configs made Alertmanager v0.28 refuse the file."""
    # EmailConfig fields of Alertmanager v0.28 (config/notifiers.go).
    known = {
        "send_resolved",
        "to",
        "from",
        "smarthost",
        "hello",
        "auth_username",
        "auth_password",
        "auth_password_file",
        "auth_secret",
        "auth_identity",
        "headers",
        "html",
        "text",
        "require_tls",
        "tls_config",
    }
    emails = [(r["name"], e) for r in _ALERTMANAGER["receivers"] for e in r.get("email_configs") or []]
    assert emails, "the check below must have email configs to inspect"
    assert [(name, sorted(set(e) - known)) for name, e in emails if set(e) - known] == []


def test_alertmanager_secret_file_is_mounted_and_never_committed():
    path = _ALERTMANAGER["global"]["slack_api_url_file"]
    mounts = _MON_COMPOSE["services"]["alertmanager"]["volumes"]
    secret_mounts = [m for m in mounts if m.split(":")[1] == os.path.dirname(path)]
    assert secret_mounts == ["./prometheus/secrets:/etc/alertmanager/secrets:ro"]
    ignore = (_ROOT / "prometheus" / "secrets" / ".gitignore").read_text().split()
    assert "*" in ignore and "!.gitignore" in ignore


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


def test_paged_fetch_shortfall_alert_reads_the_sync_gauge():
    """2026-10-25: an event fetched in pages with fewer attribute rows than the MISP index lists leaves the
    run green, and an incremental sync does not read the missed rows again; the warning is its signal."""
    rule = _rule("EdgeGuardSyncPagedFetchIncomplete")
    assert " ".join(rule["expr"].split()) == "edgeguard_sync_events_paged_incomplete > 0"
    assert rule["for"] == "10m" and rule["labels"]["severity"] == "warning"
    group = next(g for g in _RULES["groups"] if rule in g["rules"])
    assert group["name"] == "edgeguard_sync_integrity"
    description = " ".join(rule["annotations"]["description"].split())
    assert "[PAGED-FETCH-INCOMPLETE]" in description
    assert 'docs/RUNBOOK.md § "Large MISP events fetched in pages"' in description
    assert "request a full sync" in description and "the run is green" in description
    runbook = (_ROOT / "docs" / "RUNBOOK.md").read_text()
    section = runbook.split("## Large MISP events fetched in pages", 1)[1].split("\n## ", 1)[0]
    assert "`EdgeGuardSyncPagedFetchIncomplete`" in section and "edgeguard_sync_events_paged_incomplete" in section
    assert "no metric or alert reads it" not in section
    assert "| `EdgeGuardSyncPagedFetchIncomplete` |" in (_ROOT / "docs" / "PROMETHEUS_SETUP.md").read_text()


# ---------------------------------------------------------------------------------------------------
# Source label names (2026-10-25): every ``source`` value the scheduled collectors, the collectors
# themselves and the staleness rule use maps to a registered source (``src/source_registry.py``), so a
# renamed or removed source cannot linger in monitoring. Collector and job metrics carry the source's
# CLI name (``cli_id``); docs/PROMETHEUS_SETUP.md, "Source label values".

# Job names that are not a source's CLI name: the source a job belongs to, or None for a job of no
# source.
_JOB_LABELS = {
    "misp_to_neo4j": None,  # the MISP → Neo4j sync (edgeguard_last_success_timestamp, failures)
    "virustotal_enrich": "virustotal",  # VirusTotal's re-enrichment of hashes already in MISP
}
# Collector modules no DAG task runs (docs/DATA_SOURCES.md: placeholders).
_PLACEHOLDER_COLLECTORS = {"energy_placeholder", "healthcare_placeholder"}


def _dag_collector_names() -> list:
    """The collector name of every ``run_collector_with_metrics`` and ``run_baseline_collector`` call
    in the DAG module (scheduled and baseline runs). The one call that passes the baseline wrapper's
    own ``collector_name`` parameter on is skipped; any other name that is not a string literal fails."""
    import ast

    tree = ast.parse(_dag_text())
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) in (
            "run_collector_with_metrics",
            "run_baseline_collector",
        ):
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Name) and first.id == "collector_name":
                continue
            assert isinstance(first, ast.Constant) and isinstance(first.value, str), ast.dump(node)[:200]
            names.append(first.value)
    return names


def _collector_self_names() -> list:
    """Every ``self.source_name = <name>`` in ``src/collectors``: the name a collector stamps on
    ``edgeguard_last_success_timestamp`` / ``edgeguard_collection_failures_total`` itself. A module
    constant (``MALWAREBAZAAR_SOURCE_ID``) is resolved to its string."""
    import ast

    names = []
    for path in sorted((_ROOT / "src" / "collectors").glob("*.py")):
        tree = ast.parse(path.read_text())
        constants = {
            target.id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
            for target in node.targets
            if isinstance(target, ast.Name) and isinstance(node.value.value, str)
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr == "source_name":
                    value = node.value
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        names.append(value.value)
                    elif isinstance(value, ast.Name) and value.id in constants:
                        names.append(constants[value.id])
                    else:
                        raise AssertionError(f"{path.name}:{node.lineno}: source_name is not a string constant")
    return names


def _stale_rule_names() -> list:
    expr = _rule("edgeguard:collector_max_stale_seconds", key="record")["expr"]
    return re.findall(r'label_replace\(vector\(\d+\), "source", "([a-z0-9_]+)"', expr)


def _unmapped(names) -> list:
    """The names that resolve to no registered source and are no known job, in order."""
    from source_registry import get_source

    out = []
    for name in names:
        if name in _JOB_LABELS:
            owner = _JOB_LABELS[name]
            if owner is not None and get_source(owner) is None:
                out.append(name)
        elif get_source(name) is None:
            out.append(name)
    return out


def test_the_guard_flags_a_name_no_registered_source_has():
    """The check below can fail: a removed source (CyberCure, 2026-10-12) or a typo is flagged."""
    assert _unmapped(["otx", "cybercure", "otx_feed", "misp_to_neo4j"]) == ["cybercure", "otx_feed"]


def test_every_scheduled_collector_name_is_a_registered_sources_cli_name():
    names = _dag_collector_names()
    assert len(names) >= 13 and {"otx", "cisa", "mitre", "feodo", "sslbl"} <= set(names)
    assert set(names) >= set(re.findall(r'run_collector_with_metrics\("([a-z0-9_]+)"', _dag_text()))
    assert not _unmapped(names)
    from source_registry import get_source

    for name in names:
        if name not in _JOB_LABELS:
            assert get_source(name).cli_id == name, f"{name}: collector metrics carry the source's CLI name"


def test_every_collector_stamps_a_registered_sources_cli_name():
    """``edgeguard_last_success_timestamp`` is joined on ``source`` with the staleness rule: a collector
    stamping another spelling than the rule's would never be judged by its cadence."""
    names = [n for n in _collector_self_names() if n not in _PLACEHOLDER_COLLECTORS]
    assert len(names) >= 9
    assert not _unmapped(names)
    from source_registry import get_source

    for name in names:
        assert get_source(name).cli_id == name, f"{name}: a collector stamps the source's CLI name"


def test_every_staleness_rule_name_is_a_registered_source_or_a_job():
    names = _stale_rule_names()
    assert len(names) >= 13
    assert not _unmapped(names)
    scheduled = set(_dag_collector_names()) | set(_JOB_LABELS)
    assert set(names) <= scheduled, f"names no scheduled collector or job stamps: {set(names) - scheduled}"


def _dag_text() -> str:
    return (_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
