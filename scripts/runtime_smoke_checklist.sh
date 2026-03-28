#!/usr/bin/env bash
# Runtime smoke checklist (requires a running Docker stack + MISP on a shared network).
# This script does not start services; it documents and optionally probes them.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== EdgeGuard runtime smoke (manual + optional probes) ==="
echo ""
echo "1) From repo root, ensure stack is up:"
echo "   cd \"$ROOT\" && docker compose up -d"
echo ""
echo "2) MISP must resolve from the Airflow container (same Docker network or network connect)."
echo "   See docs/MISP_SOURCES.md (Troubleshooting)."
echo ""
echo "3) Trigger baseline smoke (Variables or env — see docs/BASELINE_SMOKE_TEST.md):"
echo "   docker exec edgeguard_airflow airflow dags trigger edgeguard_baseline"
echo ""
echo "4) Expectations:"
echo "   - On MISP push failure: task FAILED with AirflowException (not TypeError on set_source_health)."
echo "   - MITRE 400: check task log for MISP JSON body (misp_writer logs attribute types + response)."
echo ""

if docker info >/dev/null 2>&1; then
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^edgeguard_airflow$'; then
    echo "Optional: probing edgeguard_airflow health..."
    docker exec edgeguard_airflow curl -sf http://localhost:8082/health && echo " Airflow OK" || echo " Airflow health check failed"
  else
    echo "(edgeguard_airflow not running — skipping docker probes)"
  fi
else
  echo "(Docker not available — skipping probes)"
fi
