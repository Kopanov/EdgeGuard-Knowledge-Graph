"""Pin: every collector task shares one Airflow pool, and the stack creates that pool.

Unbounded concurrent collectors (7 baseline tier-2 feeds at once; a daily catch-up run plus OTX,
VirusTotal and NVD) exhausted MISP php-fpm worker memory (HTTP 502) and the airflow container's
cgroup limit (SIGKILL). The pool bounds collectors across all DAGs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parent.parent
_DAGS = str(_REPO / "dags")
if _DAGS not in sys.path:
    sys.path.insert(0, _DAGS)

POOL = "edgeguard_collectors"
COLLECTOR_IDS = {
    "collect_otx",
    "collect_nvd",
    "collect_cisa",
    "collect_mitre",
    "collect_cisa_ics",
    "collect_virustotal",
    "collect_abuseipdb",
    "collect_threatfox",
    "collect_urlhaus",
    "collect_feodo",
    "collect_sslblacklist",
    "collect_malwarebazaar",
}


def _dags():
    import edgeguard_pipeline as m

    return [
        m.dag,
        m.medium_freq_dag,
        m.low_freq_dag,
        m.daily_dag,
        m.neo4j_sync_dag,
        m.baseline_dag,
    ]


def _short(task_id: str) -> str:
    return task_id.rsplit(".", 1)[-1]


def test_every_collector_task_uses_the_pool():
    seen = 0
    for d in _dags():
        for tid, task in d.task_dict.items():
            if _short(tid).startswith("collect_"):
                seen += 1
                assert _short(tid) in COLLECTOR_IDS, f"{d.dag_id}.{tid}: unknown collector, add it to the pin"
                assert task.pool == POOL, f"{d.dag_id}.{tid} runs outside {POOL}"
    assert seen == 23  # 1 + 2 + 1 + 8 (daily) + 11 (baseline)


def test_non_collector_tasks_stay_out_of_the_pool():
    for d in _dags():
        for tid, task in d.task_dict.items():
            if not _short(tid).startswith("collect_"):
                assert task.pool != POOL, f"{d.dag_id}.{tid} is not a collector but uses {POOL}"


def test_slots_env_is_forwarded_with_default_4():
    data = yaml.safe_load((_REPO / "docker-compose.yml").read_text())
    value = str(data["x-common-env"]["EDGEGUARD_COLLECTOR_POOL_SLOTS"])
    assert value == "${EDGEGUARD_COLLECTOR_POOL_SLOTS:-4}"
    assert "EDGEGUARD_COLLECTOR_POOL_SLOTS" in data["services"]["airflow"]["environment"]


def test_airflow_service_creates_the_pool_with_the_configured_slots():
    data = yaml.safe_load((_REPO / "docker-compose.yml").read_text())
    command = data["services"]["airflow"]["command"]
    script = command[-1]
    assert re.search(
        rf'airflow pools set {POOL} "\$\{{EDGEGUARD_COLLECTOR_POOL_SLOTS:-4\}}"', script.replace("$$", "$")
    )
    assert script.rstrip().endswith("exec airflow standalone")  # standalone stays the foreground process


def test_env_example_documents_the_variable():
    assert "EDGEGUARD_COLLECTOR_POOL_SLOTS" in (_REPO / ".env.example").read_text()
