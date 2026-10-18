"""Compose deployment contract (2026-10): shared state directories, forwarded tuning knobs and
their defaults, the environment name, and the Neo4j database name reaching the sessions."""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest
import yaml

import neo4j_client as nc

_ROOT = Path(__file__).resolve().parents[1]


def _compose() -> dict:
    return yaml.safe_load((_ROOT / "docker-compose.yml").read_text())


def _default_of(value: str, name: str) -> str:
    m = re.fullmatch(r"\$\{" + re.escape(name) + r":-(.*)\}", str(value))
    assert m, f"{name} must be forwarded as ${{{name}:-<default>}}; got {value!r}"
    return m.group(1)


class TestSharedStateDirectories:
    def test_state_and_checkpoints_are_bind_mounted_read_write(self):
        volumes = _compose()["services"]["airflow"]["volumes"]
        assert "./state:/opt/airflow/state" in volumes
        assert "./checkpoints:/opt/airflow/checkpoints" in volumes

    def test_init_service_fixes_ownership_before_airflow_starts(self):
        compose = _compose()
        init = compose["services"]["airflow-init"]
        assert init["user"] == "0:0"
        assert init["image"] == compose["services"]["airflow"]["image"]
        script = "\n".join(init["command"])
        for path in ("/opt/airflow/state", "/opt/airflow/checkpoints"):
            assert path in script
        assert "chown -R 50000:0" in script and "mkdir -p" in script
        assert (
            "./state:/opt/airflow/state" in init["volumes"]
            and "./checkpoints:/opt/airflow/checkpoints" in init["volumes"]
        )
        assert compose["services"]["airflow"]["depends_on"]["airflow-init"] == {
            "condition": "service_completed_successfully"
        }

    def test_container_paths_match_the_code_defaults(self):
        """The DAG derives BASE_DIR from its own location and the lock module from src/..; with src
        and dags mounted under /opt/airflow both resolve to the mounted directories."""
        dag = (_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
        assert 'default_state_dir = os.path.join(BASE_DIR, "state")' in dag
        lock = (_ROOT / "src" / "baseline_lock.py").read_text()
        assert 'os.path.join(_repo_root(), "checkpoints", "baseline_in_progress.lock")' in lock

    def test_docs_describe_the_shared_directories(self):
        for rel in ("docs/AIRFLOW_DAGS.md", "docs/RUNBOOK.md", ".env.example"):
            text = (_ROOT / rel).read_text()
            assert "/opt/airflow/state" in text and "/opt/airflow/checkpoints" in text, rel
        assert "/ `dags/`)" not in (_ROOT / "docs" / "AIRFLOW_DAGS.md").read_text()


# (variable, compose default; None = empty allowed because the code tolerates an empty value)
AIRFLOW_KNOBS = [
    ("AIRFLOW_WEBSERVER_URL", "http://localhost:8082"),
    ("EDGEGUARD_MISP_PUSH_BATCH_SIZE", None),
    ("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", None),
    ("EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC", None),
    ("EDGEGUARD_MISP_EVENT_LOCK_PATH", "/tmp/edgeguard_misp_get_or_create_event.lock"),
    ("EDGEGUARD_MAX_EVENT_ATTRIBUTES", "50000"),
    ("EDGEGUARD_MISP_PAGE_SIZE", "500"),
    ("EDGEGUARD_MISP_MAX_PAGES", "100"),
    ("EDGEGUARD_MISP_RETRY_COOLDOWN_SEC", "15.0"),
    ("EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES", "4096"),
    ("EDGEGUARD_SYNC_INTERVAL_DAYS", "3"),
    ("EDGEGUARD_EARLIEST_IOC_DATE", None),
    ("EDGEGUARD_MITRE_MAX_RELATIONSHIPS", None),
    ("EDGEGUARD_SUBPROCESS_TAIL_LINES", None),
    ("EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC", None),
    ("EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION", None),
]

COMMON = [
    ("EDGEGUARD_ENV", None),
    ("NEO4J_DATABASE", None),
    ("EDGEGUARD_CORS_ORIGINS", "http://localhost,http://localhost:3000"),
    ("EDGEGUARD_MAX_BODY_BYTES", None),
    # 2026-10-18: the deployed commit, reported by both /health responses and the STIX header.
    ("EDGEGUARD_GIT_SHA", None),
]


class TestKnobForwarding:
    @pytest.mark.parametrize("name, default", AIRFLOW_KNOBS, ids=[n for n, _ in AIRFLOW_KNOBS])
    def test_airflow_service_forwards_the_knob(self, name, default):
        env = _compose()["services"]["airflow"]["environment"]
        assert name in env, f"{name} is read by src/ but never reached the airflow container"
        assert _default_of(env[name], name) == (default or "")

    @pytest.mark.parametrize("name, default", COMMON, ids=[n for n, _ in COMMON])
    def test_common_env_forwards_the_variable_to_every_service(self, name, default):
        compose = _compose()
        assert _default_of(compose["x-common-env"][name], name) == (default or "")
        for svc in ("airflow", "api", "graphql"):
            assert name in compose["services"][svc]["environment"], f"{name} missing on {svc}"

    def test_graphql_depth_cap_is_forwarded(self):
        env = _compose()["services"]["graphql"]["environment"]
        assert _default_of(env["EDGEGUARD_GRAPHQL_MAX_DEPTH"], "EDGEGUARD_GRAPHQL_MAX_DEPTH") == ""

    def test_int_and_float_parsed_knobs_carry_the_code_default(self):
        """A set-but-empty value would raise at import for these; compose must pass the code default."""
        src = (_ROOT / "src" / "run_misp_to_neo4j.py").read_text()
        env = _compose()["services"]["airflow"]["environment"]
        for name, caster in (
            ("EDGEGUARD_MAX_EVENT_ATTRIBUTES", "int"),
            ("EDGEGUARD_MISP_PAGE_SIZE", "int"),
            ("EDGEGUARD_MISP_MAX_PAGES", "int"),
            ("EDGEGUARD_MISP_RETRY_COOLDOWN_SEC", "float"),
            ("EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES", "int"),
            ("EDGEGUARD_SYNC_INTERVAL_DAYS", "int"),
        ):
            m = re.search(caster + r'\(os\.(?:getenv|environ\.get)\("' + name + r'",\s*"([^"]+)"\)\)', src)
            assert m, f"{name}: expected {caster}(os.getenv(..., default)) in run_misp_to_neo4j.py"
            assert _default_of(env[name], name) == m.group(1), f"{name}: compose default drifted from the code default"

    def test_cors_default_matches_both_api_modules(self):
        default = _default_of(_compose()["x-common-env"]["EDGEGUARD_CORS_ORIGINS"], "EDGEGUARD_CORS_ORIGINS")
        for rel in ("src/query_api.py", "src/graphql_api.py"):
            src = (_ROOT / rel).read_text()
            m = re.search(r'os\.getenv\("EDGEGUARD_CORS_ORIGINS",\s*"([^"]+)"\)', src)
            assert m and m.group(1) == default, rel

    def test_environment_name_keeps_the_fail_closed_default(self):
        """Empty must stay empty: config.is_production_env() treats unset or empty as production."""
        assert _compose()["x-common-env"]["EDGEGUARD_ENV"] == "${EDGEGUARD_ENV:-}"
        from config import is_production_env

        assert is_production_env.__doc__ and "Fail-closed" in is_production_env.__doc__


class TestDocumentedDefaults:
    def test_push_batch_default_matches_the_code(self):
        from collectors.misp_writer import MISPWriter

        code_default = inspect.signature(MISPWriter.push_items).parameters["batch_size"].default
        env_example = (_ROOT / ".env.example").read_text()
        m = re.search(r"^# EDGEGUARD_MISP_PUSH_BATCH_SIZE=(\d+)", env_example, re.M)
        assert m and int(m.group(1)) == code_default

    def test_sync_chunk_comment_matches_the_code(self):
        compose_text = (_ROOT / "docker-compose.yml").read_text()
        assert "items per Python sync chunk (default 500 in code)" in compose_text
        assert "(default 1000)" not in compose_text.split("EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE")[0].splitlines()[-1]

    def test_no_stale_three_second_pause_claim(self):
        text = (_ROOT / "docs" / "AIRFLOW_DAGS.md").read_text()
        assert "3s pause" not in text and "3 s pause" not in text
        assert "EDGEGUARD_QUERY_PAUSE_SECONDS" in text

    def test_dag_docstring_does_not_claim_the_refresh_variable_drives_scheduling(self):
        dag = (_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
        assert "How often to fetch sources and push to MISP" not in dag
        assert "MISP_REFRESH_INTERVAL: informational only" in dag

    def test_env_example_documents_the_database_name(self):
        assert re.search(r"^# NEO4J_DATABASE=", (_ROOT / ".env.example").read_text(), re.M)


class TestDatabaseNameReachesSessions:
    class _Raw:
        def __init__(self):
            self.calls = []

        def session(self, **kwargs):
            self.calls.append(kwargs)
            return _Ctx()

    def test_configured_database_is_passed_to_every_session(self, monkeypatch):
        monkeypatch.setenv("NEO4J_DATABASE", "edgeguard")
        raw = self._Raw()
        driver = nc._TimeoutDriver(raw, database=nc._configured_database())
        driver.session()
        driver.session(database="other")
        assert raw.calls == [{"database": "edgeguard"}, {"database": "other"}]

    def test_unset_or_empty_keeps_the_server_default(self, monkeypatch):
        for value in (None, "", "  "):
            if value is None:
                monkeypatch.delenv("NEO4J_DATABASE", raising=False)
            else:
                monkeypatch.setenv("NEO4J_DATABASE", value)
            assert nc._configured_database() is None
        raw = self._Raw()
        nc._TimeoutDriver(raw).session()
        assert raw.calls == [{}]

    def test_connect_wires_the_configured_database(self):
        assert "database=_configured_database()" in inspect.getsource(inspect.unwrap(nc.Neo4jClient.connect))

    def test_session_kwargs_follow_the_variable(self, monkeypatch):
        monkeypatch.setenv("NEO4J_DATABASE", "edgeguard")
        assert nc.session_kwargs() == {"database": "edgeguard"}
        monkeypatch.delenv("NEO4J_DATABASE")
        assert nc.session_kwargs() == {}

    def test_cli_and_version_probe_sessions_use_the_helper(self):
        cli = (_ROOT / "src" / "edgeguard.py").read_text()
        assert cli.count("driver.session(**session_kwargs())") == 2, "both raw CLI sessions must pass the database"
        assert "driver.session()" not in cli
        probe = (_ROOT / "src" / "version_compatibility.py").read_text()
        assert 'driver.session(default_access_mode="READ", **session_kw)' in probe
        assert "except ImportError as exc:" in probe and "logger.warning(" in probe, (
            "import failure is reported, not swallowed"
        )
        assert "except Exception:\n            return {}" not in probe


class _Ctx:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, *a, **k):
        return []
