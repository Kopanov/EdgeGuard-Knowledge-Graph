"""
EdgeGuard — Airflow REST API client
====================================
Thin wrapper around the Airflow stable REST API (v1) for DAG status
querying and run management.  Used by the ``edgeguard`` CLI and could
be reused by monitoring scripts.

Requires:
    AIRFLOW_WEBSERVER_URL  (default http://edgeguard_airflow:8082 — Docker Compose DNS)
    AIRFLOW_API_USER       (optional — basic-auth username)
    AIRFLOW_API_PASSWORD   (optional — basic-auth password)
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Known DAG IDs — used as fallback when Airflow API is unreachable.
# Keep in sync with dags/edgeguard_pipeline.py DAG definitions.
_KNOWN_DAG_IDS = [
    "edgeguard_pipeline",
    "edgeguard_medium_freq",
    "edgeguard_low_freq",
    "edgeguard_daily",
    "edgeguard_neo4j_sync",
    "edgeguard_baseline",
]

_TIMEOUT = 15  # seconds
_cached_dag_ids: Optional[List[str]] = None


def get_edgeguard_dag_ids() -> List[str]:
    """Return EdgeGuard DAG IDs, auto-discovered from Airflow if reachable.

    Falls back to the hardcoded ``_KNOWN_DAG_IDS`` list if Airflow is
    unreachable.  Caches the result for the process lifetime.
    """
    global _cached_dag_ids
    if _cached_dag_ids is not None:
        return _cached_dag_ids

    try:
        result = _get("/dags", params={"dag_id_pattern": "edgeguard", "limit": 50})
        if "error" not in result:
            ids = [d["dag_id"] for d in result.get("dags", []) if d.get("dag_id", "").startswith("edgeguard")]
            if ids:
                _cached_dag_ids = ids
                return ids
    except Exception:
        pass

    _cached_dag_ids = list(_KNOWN_DAG_IDS)
    return _cached_dag_ids


# Backward-compatible alias
EDGEGUARD_DAG_IDS = _KNOWN_DAG_IDS  # used by existing callers; prefer get_edgeguard_dag_ids()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _base_url() -> str:
    return os.getenv("AIRFLOW_WEBSERVER_URL", "http://edgeguard_airflow:8082").rstrip("/")


def _auth() -> Optional[Tuple[str, str]]:
    user = os.getenv("AIRFLOW_API_USER", "airflow")
    password = os.getenv("AIRFLOW_API_PASSWORD")
    if password:
        return (user, password)
    return None


def _get(path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
    """GET request to Airflow API.  Returns parsed JSON or ``{"error": ...}``."""
    url = f"{_base_url()}/api/v1{path}"
    try:
        resp = requests.get(url, params=params, auth=_auth(), timeout=_TIMEOUT)
        if resp.status_code == 401:
            return {"error": "Airflow API returned 401 Unauthorized. Set AIRFLOW_API_USER/AIRFLOW_API_PASSWORD."}
        if resp.status_code == 403:
            return {"error": "Airflow API returned 403 Forbidden. Check user permissions."}
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        return {"error": f"Cannot connect to Airflow at {_base_url()}. Is it running?"}
    except requests.exceptions.Timeout:
        return {"error": f"Airflow API timed out ({_TIMEOUT}s)."}
    except Exception as e:
        return {"error": str(e)}


def _patch(path: str, body: Dict) -> Dict[str, Any]:
    """PATCH request to Airflow API."""
    url = f"{_base_url()}/api/v1{path}"
    try:
        resp = requests.patch(url, json=body, auth=_auth(), timeout=_TIMEOUT)
        if resp.status_code in (401, 403):
            return {"error": f"Airflow API returned {resp.status_code}. Check auth."}
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        return {"error": f"Cannot connect to Airflow at {_base_url()}."}
    except requests.exceptions.Timeout:
        return {"error": f"Airflow API timed out ({_TIMEOUT}s)."}
    except Exception as e:
        return {"error": str(e)}


def _post(path: str, body: Dict) -> Dict[str, Any]:
    """POST request to Airflow API."""
    url = f"{_base_url()}/api/v1{path}"
    try:
        resp = requests.post(url, json=body, auth=_auth(), timeout=_TIMEOUT)
        if resp.status_code in (401, 403):
            return {"error": f"Airflow API returned {resp.status_code}. Check auth."}
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        return {"error": f"Cannot connect to Airflow at {_base_url()}."}
    except requests.exceptions.Timeout:
        return {"error": f"Airflow API timed out ({_TIMEOUT}s)."}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def airflow_health() -> Dict[str, Any]:
    """Check Airflow scheduler and metadatabase health.

    Returns dict with 'metadatabase' and 'scheduler' status, or 'error'.
    """
    url = f"{_base_url()}/health"
    try:
        resp = requests.get(url, auth=_auth(), timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        return {"error": f"Cannot connect to Airflow at {_base_url()}."}
    except Exception as e:
        return {"error": str(e)}


def list_dag_runs(
    dag_id: str,
    state: Optional[str] = None,
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """List recent DAG runs for a specific DAG.

    Returns list of run dicts, or a single-element list with ``{"error": ...}``.
    """
    params: Dict[str, Any] = {"order_by": "-start_date", "limit": limit}
    if state:
        params["state"] = state
    result = _get(f"/dags/{dag_id}/dagRuns", params=params)
    if "error" in result:
        return [result]
    return result.get("dag_runs", [])


def list_all_active_dag_runs(
    dag_ids: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Collect running and queued DAG runs across all EdgeGuard DAGs."""
    ids = dag_ids or get_edgeguard_dag_ids()
    active: List[Dict[str, Any]] = []
    for dag_id in ids:
        for state in ("running", "queued"):
            runs = list_dag_runs(dag_id, state=state, limit=25)
            if runs and "error" not in runs[0]:
                for run in runs:
                    run["dag_id"] = dag_id  # ensure dag_id is on each run
                    active.append(run)
    return active


def patch_dag_run_state(dag_id: str, dag_run_id: str, state: str = "failed") -> Dict[str, Any]:
    """Force a DAG run into a specific state (typically 'failed')."""
    return _patch(f"/dags/{dag_id}/dagRuns/{dag_run_id}", {"state": state})


def clear_task_instances(dag_id: str, dag_run_id: str) -> Dict[str, Any]:
    """Clear (reset) task instances for a DAG run."""
    body = {
        "dry_run": False,
        "dag_run_id": dag_run_id,
        "reset_dag_runs": True,
        "only_running": False,
        "only_failed": False,
    }
    return _post(f"/dags/{dag_id}/clearTaskInstances", body)


def get_registered_dags() -> List[Dict[str, Any]]:
    """List EdgeGuard DAGs registered in Airflow."""
    result = _get("/dags", params={"dag_id_pattern": "edgeguard", "limit": 25})
    if "error" in result:
        return [result]
    return result.get("dags", [])


def format_duration(start_str: Optional[str], end_str: Optional[str] = None) -> str:
    """Human-readable duration from ISO timestamps."""
    if not start_str:
        return "—"
    try:
        start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_str.replace("Z", "+00:00")) if end_str else datetime.now(timezone.utc)
        delta = end - start
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h {minutes}m"
        if minutes > 0:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"
    except (ValueError, TypeError):
        return "—"
