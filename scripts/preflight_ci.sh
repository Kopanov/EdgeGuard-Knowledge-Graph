#!/usr/bin/env bash
# CI/local preflight: syntax + unit tests + Airflow DagBag parse (no DB init required).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== compileall dags + src/collectors =="
python3 -m compileall -q dags src/collectors

echo "== pytest =="
export PYTHONPATH="${ROOT}/src:${PYTHONPATH:-}"
python3 -m pytest tests/ -q --tb=short

echo "== DagBag (set NEO4J_PASSWORD for clean config import) =="
export NEO4J_PASSWORD="${NEO4J_PASSWORD:-preflight_dummy_not_used}"
export AIRFLOW_HOME="${AIRFLOW_HOME:-/tmp/edgeguard_preflight_airflow}"
export AIRFLOW__CORE__LOAD_EXAMPLES="${AIRFLOW__CORE__LOAD_EXAMPLES:-false}"
python3 <<'PY'
import os
from airflow.models import DagBag

os.environ.setdefault("NEO4J_PASSWORD", "preflight_dummy")
dag_folder = os.path.join(os.getcwd(), "dags")
bag = DagBag(dag_folder=dag_folder, include_examples=False)
if bag.import_errors:
    for path, err in bag.import_errors.items():
        print(f"ERROR {path}:\n{err}")
    raise SystemExit(1)
print("DagBag OK:", sorted(bag.dag_ids))
PY

echo "== preflight_ci.sh done =="
