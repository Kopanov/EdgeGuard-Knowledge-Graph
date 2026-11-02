"""
EdgeGuard — Airflow REST API client
====================================
Thin wrapper around the Airflow REST API used by the ``edgeguard`` CLI
(``dag status``, ``dag kill``, ``preflight``, ``doctor``, ``baseline``, ``fresh-baseline``), by the Airflow
component health collector of ``metrics_exporter.py``, which both metrics servers (``metrics_exporter.py`` and
``metrics_server.py``) serve, and by the orphan-process safeguard in ``parent_dag_liveness``.

API versions
------------
Airflow 3.x serves its public API at ``/api/v2`` behind JWT bearer tokens
issued by ``POST /auth/token``. Airflow 2.x serves ``/api/v1`` with HTTP
Basic authentication. The client speaks ``v2`` by default (the pinned image
is ``apache/airflow:3.3.2``); set ``AIRFLOW_API_VERSION=v1`` for an Airflow
2.x deployment.

Environment
-----------
AIRFLOW_WEBSERVER_URL   Base URL (default ``http://localhost:8082``: the API server
                        port published by docker-compose and, inside the Airflow
                        container, the standalone API server itself).
AIRFLOW_API_VERSION     ``v2`` (default) or ``v1``.
AIRFLOW_API_USER        User name (default ``admin``, the user ``airflow standalone``
                        creates with the Simple auth manager).
AIRFLOW_API_PASSWORD    Password. When unset, the client reads the password file the
                        Simple auth manager generates
                        (``<AIRFLOW_HOME>/simple_auth_manager_passwords.json.generated``,
                        override with ``AIRFLOW__CORE__SIMPLE_AUTH_MANAGER_PASSWORDS_FILE``),
                        which makes processes inside the Airflow container
                        self-sufficient. Without credentials every ``v2`` call fails
                        with an explicit error instead of an unauthenticated request.

Every public function that calls Airflow returns parsed JSON or ``{"error": <message>}``; it
never raises for transport or authentication failures. When Airflow did not answer within the
request timeout, the error also carries ``"timed_out": True``: the request may have reached Airflow.
``component_health`` reads the status of the scheduler, triggerer, DAG processor and metadata
database from a health answer. ``trigger_dag_run`` (used by ``edgeguard baseline`` and
``edgeguard fresh-baseline`` where no Compose ``airflow`` service runs) creates one DAG run.
"""

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

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
_SUPPORTED_VERSIONS = ("v1", "v2")
_DEFAULT_VERSION = "v2"
_DEFAULT_USER_V2 = "admin"
_DEFAULT_USER_V1 = "airflow"
_GENERATED_PASSWORDS_FILE = "simple_auth_manager_passwords.json.generated"
# Airflow's default JWT lifetime is 24 h; refresh well before that. A 401 also forces a refresh.
_TOKEN_TTL_SEC = 20 * 3600

_cached_dag_ids: Optional[List[str]] = None
_token_lock = threading.Lock()
_token: Optional[str] = None
_token_obtained_at: float = 0.0


class _AuthError(Exception):
    """Credentials missing or rejected; reported to callers as ``{"error": ...}``."""


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
# Configuration helpers
# ---------------------------------------------------------------------------


def _base_url() -> str:
    return os.getenv("AIRFLOW_WEBSERVER_URL", "http://localhost:8082").rstrip("/")


def _api_version() -> str:
    raw = (os.getenv("AIRFLOW_API_VERSION") or _DEFAULT_VERSION).strip().lower()
    if raw not in _SUPPORTED_VERSIONS:
        logger.warning("Ignoring unsupported AIRFLOW_API_VERSION=%r; using %s", raw, _DEFAULT_VERSION)
        return _DEFAULT_VERSION
    return raw


def _passwords_file() -> str:
    override = os.getenv("AIRFLOW__CORE__SIMPLE_AUTH_MANAGER_PASSWORDS_FILE")
    if override:
        return override
    return os.path.join(os.getenv("AIRFLOW_HOME", "/opt/airflow"), _GENERATED_PASSWORDS_FILE)


def _credentials_from_generated_file(preferred_user: Optional[str]) -> Optional[Tuple[str, str]]:
    """Credentials from the Simple auth manager's generated password file, or None."""
    path = _passwords_file()
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data:
        return None
    if preferred_user and isinstance(data.get(preferred_user), str):
        return preferred_user, data[preferred_user]
    if len(data) == 1:
        user, password = next(iter(data.items()))
        if isinstance(password, str):
            return str(user), password
    if isinstance(data.get(_DEFAULT_USER_V2), str):
        return _DEFAULT_USER_V2, data[_DEFAULT_USER_V2]
    return None


def _credentials() -> Optional[Tuple[str, str]]:
    """``(user, password)`` from the environment, else from the generated file, else None."""
    user = (os.getenv("AIRFLOW_API_USER") or "").strip() or None
    password = os.getenv("AIRFLOW_API_PASSWORD") or None
    if password:
        default_user = _DEFAULT_USER_V2 if _api_version() == "v2" else _DEFAULT_USER_V1
        return (user or default_user, password)
    found = _credentials_from_generated_file(user)
    if found is not None:
        logger.debug("Airflow API credentials read from %s (user=%s)", _passwords_file(), found[0])
    return found


def _auth() -> Optional[Tuple[str, str]]:
    """HTTP Basic credentials for the ``v1`` API (Airflow 2.x), or None."""
    return _credentials()


def _reset_token_cache() -> None:
    global _token, _token_obtained_at
    with _token_lock:
        _token = None
        _token_obtained_at = 0.0


def _bearer_token(force: bool = False) -> str:
    """A cached JWT for the ``v2`` API, obtained from ``POST /auth/token``.

    Raises :class:`_AuthError` when credentials are missing or rejected.
    """
    global _token, _token_obtained_at
    with _token_lock:
        if not force and _token and (time.monotonic() - _token_obtained_at) < _TOKEN_TTL_SEC:
            return _token
        creds = _credentials()
        if creds is None:
            raise _AuthError(
                "Airflow API credentials are not set. Set AIRFLOW_API_USER/AIRFLOW_API_PASSWORD "
                f"(or make {_passwords_file()} readable)."
            )
        user, password = creds
        resp = requests.request(
            "POST",
            f"{_base_url()}/auth/token",
            json={"username": user, "password": password},
            timeout=_TIMEOUT,
        )
        if resp.status_code in (401, 403):
            raise _AuthError(f"Airflow rejected the API credentials for user {user!r} ({resp.status_code}).")
        resp.raise_for_status()
        try:
            token = resp.json().get("access_token")
        except ValueError:
            token = None
        if not token:
            raise _AuthError("Airflow /auth/token returned no access_token.")
        _token = str(token)
        _token_obtained_at = time.monotonic()
        return _token


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


def _send(method: str, url: str, params: Optional[Dict], json_body: Optional[Dict]) -> requests.Response:
    """One request with version-appropriate authentication; retries once after a 401 on ``v2``."""
    if _api_version() == "v1":
        return requests.request(method, url, params=params, json=json_body, auth=_auth(), timeout=_TIMEOUT)
    headers = {"Authorization": f"Bearer {_bearer_token()}"}
    resp = requests.request(method, url, params=params, json=json_body, headers=headers, timeout=_TIMEOUT)
    if resp.status_code == 401:
        headers = {"Authorization": f"Bearer {_bearer_token(force=True)}"}
        resp = requests.request(method, url, params=params, json=json_body, headers=headers, timeout=_TIMEOUT)
    return resp


def _request(method: str, path: str, params: Optional[Dict] = None, json_body: Optional[Dict] = None) -> Dict[str, Any]:
    """Call ``/api/<version><path>``. Returns parsed JSON or ``{"error": ...}``."""
    url = f"{_base_url()}/api/{_api_version()}{path}"
    try:
        resp = _send(method, url, params, json_body)
        if resp.status_code == 401:
            return {"error": "Airflow API returned 401 Unauthorized. Set AIRFLOW_API_USER/AIRFLOW_API_PASSWORD."}
        if resp.status_code == 403:
            return {"error": "Airflow API returned 403 Forbidden. Check user permissions."}
        resp.raise_for_status()
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()
    except _AuthError as e:
        return {"error": str(e)}
    except requests.exceptions.ConnectionError:
        return {"error": f"Cannot connect to Airflow at {_base_url()}. Is it running?"}
    except requests.exceptions.Timeout:
        # A connect timeout is a ConnectionError (above); this one came while Airflow had the request,
        # so it may have been carried out.
        return {"error": f"Airflow API timed out ({_TIMEOUT}s).", "timed_out": True}
    except Exception as e:
        return {"error": str(e)}


def _get(path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
    """GET request to Airflow API.  Returns parsed JSON or ``{"error": ...}``."""
    return _request("GET", path, params=params)


def _patch(path: str, body: Dict) -> Dict[str, Any]:
    """PATCH request to Airflow API."""
    return _request("PATCH", path, json_body=body)


def _post(path: str, body: Dict) -> Dict[str, Any]:
    """POST request to Airflow API."""
    return _request("POST", path, json_body=body)


def _run_path(dag_id: str, dag_run_id: str) -> str:
    # Scheduled run ids contain ``+`` and ``:`` (``scheduled__2026-10-11T03:00:00+00:00``);
    # unencoded they do not round-trip through the path.
    return f"/dags/{quote(dag_id, safe='')}/dagRuns/{quote(dag_run_id, safe='')}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def airflow_health(timeout: Optional[float] = None) -> Dict[str, Any]:
    """Airflow's health answer: the status of the metadatabase, scheduler, triggerer and DAG processor.

    Returns the parsed JSON object, or ``{"error": ...}`` when Airflow does not answer with one.
    Airflow 3.x exposes the check at ``/api/v2/monitor/health`` without authentication; Airflow 2.x
    at ``/health``. Both answer HTTP 200 when a component is unhealthy: the state is in the body
    only, so a caller reads it with :func:`component_health`. ``timeout`` defaults to the client's
    request timeout.
    """
    if _api_version() == "v2":
        url = f"{_base_url()}/api/v2/monitor/health"
        auth = None
    else:
        url = f"{_base_url()}/health"
        auth = _auth()
    try:
        resp = requests.request("GET", url, auth=auth, timeout=_TIMEOUT if timeout is None else timeout)
        resp.raise_for_status()
        payload = resp.json()
    except requests.exceptions.ConnectionError:
        return {"error": f"Cannot connect to Airflow at {_base_url()}."}
    except Exception as e:
        return {"error": str(e)}
    if not isinstance(payload, dict):
        return {"error": f"Airflow health answer at {url} is not a JSON object."}
    return payload


# Components of the health answer, in report order. ``airflow standalone`` (the Compose service, or a
# bare-metal install that runs it) runs the scheduler, triggerer, DAG processor and API server as
# subprocesses and neither restarts nor exits when one of them dies, so the API server keeps answering
# while the scheduler is gone.
AIRFLOW_HEALTH_COMPONENTS = ("metadatabase", "scheduler", "triggerer", "dag_processor")
# Every Airflow deployment has these two. Airflow reports a ``null`` status for a triggerer or DAG
# processor of which it has recorded no job, one that does not run as a process of its own (Airflow 2
# parses the DAG files inside the scheduler unless ``[scheduler] standalone_dag_processor`` is set).
AIRFLOW_REQUIRED_COMPONENTS = ("metadatabase", "scheduler")
HEALTHY = "healthy"


@dataclass(frozen=True)
class AirflowComponentHealth:
    """What one :func:`airflow_health` answer says about each Airflow component.

    ``statuses`` holds the components the answer lists, with the status it reports (``None`` for a
    ``null`` status or an entry that is not an object); ``heartbeats`` the ``latest_<component>_heartbeat``
    values. ``error`` is set when the answer is not a health payload; the component maps are then empty.
    A component that is missing or has no status is never counted as healthy: a required one (metadata
    database, scheduler) is not healthy, a triggerer or DAG processor runs no job of its own
    (:meth:`without_job`).
    """

    error: Optional[str] = None
    statuses: Dict[str, Optional[str]] = field(default_factory=dict)
    heartbeats: Dict[str, Optional[str]] = field(default_factory=dict)

    @property
    def reachable(self) -> bool:
        return self.error is None

    def is_healthy(self, component: str) -> bool:
        return self.statuses.get(component) == HEALTHY

    def has_status(self, component: str) -> bool:
        return self.statuses.get(component) is not None

    def not_healthy(self) -> List[str]:
        """The components that are not reported healthy: a metadata database or scheduler that is
        unhealthy, without status or missing, and a triggerer or DAG processor with a status other than
        ``healthy``."""
        return [
            name
            for name in AIRFLOW_HEALTH_COMPONENTS
            if not self.is_healthy(name) and (name in AIRFLOW_REQUIRED_COMPONENTS or self.has_status(name))
        ]

    def without_job(self) -> List[str]:
        """The triggerer or DAG processor when the answer gives it no status or does not list it:
        Airflow has recorded no job of it, so it does not run as a process of its own."""
        return [
            name
            for name in AIRFLOW_HEALTH_COMPONENTS
            if name not in AIRFLOW_REQUIRED_COMPONENTS and not self.has_status(name)
        ]

    def latest_heartbeat(self, component: str) -> Optional[str]:
        return self.heartbeats.get(component)

    def describe(self, component: str) -> str:
        """``scheduler unhealthy, last heartbeat 2026-11-01T08:32:14+00:00 (3h 54m ago)``."""
        if component not in self.statuses:
            text = f"{component} not reported by Airflow"
        elif self.statuses[component] is None:
            text = f"{component} without status (no {component} job recorded)"
        else:
            text = f"{component} {self.statuses[component]}"
        heartbeat = self.heartbeats.get(component)
        if heartbeat:
            age = format_duration(heartbeat)
            text += f", last heartbeat {heartbeat}" + (f" ({age} ago)" if age != "—" else "")
        return text


def component_health(payload: Any) -> AirflowComponentHealth:
    """Read the component statuses of an :func:`airflow_health` answer.

    Airflow 3 (``/api/v2/monitor/health``) and Airflow 2 (``/health``) both answer
    ``{"<component>": {"status": "healthy" | "unhealthy" | null, "latest_<component>_heartbeat": ...}}``;
    Airflow 2 lists only the components it has. Never raises.
    """
    if not isinstance(payload, dict):
        return AirflowComponentHealth(error="Airflow health answer is not a JSON object")
    if "error" in payload:
        return AirflowComponentHealth(error=str(payload["error"]))
    statuses: Dict[str, Optional[str]] = {}
    heartbeats: Dict[str, Optional[str]] = {}
    for name in AIRFLOW_HEALTH_COMPONENTS:
        if name not in payload:
            continue
        entry = payload[name]
        status = entry.get("status") if isinstance(entry, dict) else None
        statuses[name] = status if isinstance(status, str) else None
        heartbeat = entry.get(f"latest_{name}_heartbeat") if isinstance(entry, dict) else None
        heartbeats[name] = heartbeat if isinstance(heartbeat, str) and heartbeat else None
    return AirflowComponentHealth(statuses=statuses, heartbeats=heartbeats)


def get_dag_run(dag_id: str, dag_run_id: str) -> Dict[str, Any]:
    """One DAG run (``state``, ``start_date``, ...), or ``{"error": ...}``."""
    return _get(_run_path(dag_id, dag_run_id))


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
    result = _get(f"/dags/{quote(dag_id, safe='')}/dagRuns", params=params)
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


def trigger_dag_run(dag_id: str, conf: Dict[str, Any]) -> Dict[str, Any]:
    """Create one manual run of ``dag_id`` with ``conf``: the new run (``dag_run_id``, ``state``, ...), or
    ``{"error": ...}``.

    Airflow 3's ``TriggerDAGRunPostBody`` requires the key ``logical_date`` (``null``: the run has no
    logical date) and refuses unknown keys; Airflow 2's ``v1`` body is ``conf`` alone. The request is
    sent once; a ``401`` only renews the token first and creates no run. An error with ``timed_out``
    means Airflow had the request and did not answer in time, so the run may exist: list the DAG's runs
    before triggering again.
    """
    body: Dict[str, Any] = {"logical_date": None, "conf": conf} if _api_version() == "v2" else {"conf": conf}
    return _post(f"/dags/{quote(dag_id, safe='')}/dagRuns", body)


def patch_dag_run_state(dag_id: str, dag_run_id: str, state: str = "failed") -> Dict[str, Any]:
    """Force a DAG run into a specific state (typically 'failed')."""
    return _patch(_run_path(dag_id, dag_run_id), {"state": state})


def clear_task_instances(dag_id: str, dag_run_id: str) -> Dict[str, Any]:
    """Clear (reset) task instances for a DAG run."""
    body = {
        "dry_run": False,
        "dag_run_id": dag_run_id,
        "reset_dag_runs": True,
        "only_running": False,
        "only_failed": False,
    }
    return _post(f"/dags/{quote(dag_id, safe='')}/clearTaskInstances", body)


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
