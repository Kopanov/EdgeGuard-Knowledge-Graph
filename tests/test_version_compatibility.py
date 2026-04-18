"""PR #36 — tests for ``src/version_compatibility.py``.

Covers:
  * Each ``get_*_version()`` is best-effort and returns ``None`` instead
    of raising on any failure (Vanko's "doctor must not crash" contract)
  * ``compare_version`` correctly classifies match / minor drift /
    major drift / unknown
  * ``compare_pinned_vs_running`` produces the deterministic ordered
    report doctor + validate iterate
  * ``RECOMMENDED_VERSIONS`` stays in sync with ``docker-compose.yml``
    and ``requirements.txt`` (regression: bump the pin without bumping
    this table → test fails)
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---------------------------------------------------------------------------
# Best-effort capture functions — must NEVER raise
# ---------------------------------------------------------------------------


def test_get_neo4j_driver_version_returns_string_or_none():
    """If neo4j is installed (it is in dev), we get a string; if not, None.
    Either way: no exception escapes."""
    from version_compatibility import get_neo4j_driver_version

    result = get_neo4j_driver_version()
    assert result is None or isinstance(result, str)


def test_get_neo4j_driver_version_swallows_import_error():
    """Simulate neo4j not installed (slim container scenario) — must
    return None, NOT raise ImportError up to doctor."""
    # Patch builtins.__import__ to raise on neo4j specifically
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def _bomb_neo4j(name, *args, **kwargs):
        if name == "neo4j":
            raise ImportError("simulated: neo4j not installed")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=_bomb_neo4j):
        # Force a re-evaluation by re-importing
        import importlib

        import version_compatibility

        importlib.reload(version_compatibility)
        result = version_compatibility.get_neo4j_driver_version()

    # Reload again to restore the real import
    import importlib

    import version_compatibility

    importlib.reload(version_compatibility)

    assert result is None, "missing neo4j must yield None, not raise"


def test_get_neo4j_server_version_calls_dbms_components():
    """Verify the canonical Cypher (`CALL dbms.components() YIELD versions`)
    is what gets executed, and the first version string from the row is
    returned. Pins the contract so a future refactor doesn't switch to a
    different procedure that may not exist on older Neo4j."""
    from version_compatibility import get_neo4j_server_version

    fake_client = MagicMock()
    fake_client.connect.return_value = True
    fake_client.run.return_value = [{"versions": ["2026.03.1"]}]
    fake_client.close = MagicMock()

    def factory():
        return fake_client

    result = get_neo4j_server_version(neo4j_client_factory=factory)

    assert result == "2026.03.1"
    fake_client.run.assert_called_once()
    cypher = fake_client.run.call_args[0][0]
    assert "dbms.components()" in cypher
    assert "versions" in cypher
    fake_client.close.assert_called_once(), "client must be closed even on success"


def test_get_neo4j_server_version_returns_none_on_connection_failure():
    """Neo4j down → factory's connect() returns False → must return None,
    NOT raise. This is the doctor-friendly failure mode: there's already
    a separate doctor check for "Neo4j connection" — version-capture
    failure shouldn't double-report."""
    from version_compatibility import get_neo4j_server_version

    fake_client = MagicMock()
    fake_client.connect.return_value = False

    result = get_neo4j_server_version(neo4j_client_factory=lambda: fake_client)
    assert result is None


def test_get_neo4j_server_version_default_path_uses_fast_driver_not_neo4jclient_connect():
    """PR #36 commit X (bugbot MED) regression pin.

    Background: ``Neo4jClient.connect()`` is decorated with
    ``@retry_with_backoff(max_retries=5, base_delay=2)`` → up to ~62
    seconds of exponential backoff when Neo4j is unreachable. When
    ``get_neo4j_server_version()`` was called WITHOUT a factory (the
    production path from doctor/validate), it instantiated
    ``Neo4jClient()`` and called ``connect()``, paying that 62-second
    retry cycle as a SECOND probe (doctor/validate already did the
    first probe upstream). Bug report: doctor wall-clock roughly
    doubled on a Neo4j outage for zero diagnostic value.

    Fix: the default-factory path now goes through
    ``_get_neo4j_server_version_fast()`` which uses the Neo4j driver
    DIRECTLY with ``connection_timeout=2.0`` so a probe against a down
    Neo4j fails in seconds, not minutes.

    Pin: source-grep the production branch routes to the fast helper,
    and that the fast helper sets a tight ``connection_timeout``.
    """
    import inspect

    import version_compatibility

    src = inspect.getsource(version_compatibility.get_neo4j_server_version)
    assert "_get_neo4j_server_version_fast" in src, (
        "get_neo4j_server_version's default-factory branch MUST route to the fast driver path "
        "to avoid the @retry_with_backoff(5, 2) ~62s cycle on a Neo4j outage. "
        "If this assertion fails, doctor/validate hangs for ~minute on a downed Neo4j."
    )
    fast_src = inspect.getsource(version_compatibility._get_neo4j_server_version_fast)
    assert "connection_timeout" in fast_src, (
        "_get_neo4j_server_version_fast must set connection_timeout to fail fast on a down Neo4j"
    )


def test_get_neo4j_server_version_returns_none_when_run_raises():
    """Cypher execution raises (e.g. `CALL dbms.components()` not
    available on a non-standard Neo4j fork) → must return None."""
    from version_compatibility import get_neo4j_server_version

    fake_client = MagicMock()
    fake_client.connect.return_value = True
    fake_client.run.side_effect = RuntimeError("simulated cypher failure")

    result = get_neo4j_server_version(neo4j_client_factory=lambda: fake_client)
    assert result is None


def test_get_neo4j_server_version_closes_client_even_on_exception():
    """Resource hygiene: a Cypher exception must not leak the connection."""
    from version_compatibility import get_neo4j_server_version

    fake_client = MagicMock()
    fake_client.connect.return_value = True
    fake_client.run.side_effect = RuntimeError("boom")

    get_neo4j_server_version(neo4j_client_factory=lambda: fake_client)
    fake_client.close.assert_called_once()


def test_get_airflow_version_via_subprocess_fallback():
    """If airflow isn't importable but the binary is on PATH, parse the
    subprocess output. We do NOT exercise the import path here because
    it depends on whether airflow is installed in the dev env — which
    it is in our DAG-test path. This subprocess-only path is what would
    fire on a CLI host without the airflow package."""
    from version_compatibility import get_airflow_version

    fake_completed = MagicMock()
    fake_completed.returncode = 0
    fake_completed.stdout = "Airflow build banner\n3.2.0\nmore noise\n"

    # Force the import path to fail so we hit the subprocess fallback
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def _no_airflow_import(name, *args, **kwargs):
        if name == "airflow":
            raise ImportError("simulated")
        return real_import(name, *args, **kwargs)

    with (
        patch("builtins.__import__", side_effect=_no_airflow_import),
        patch("subprocess.run", return_value=fake_completed),
    ):
        result = get_airflow_version()

    assert result == "3.2.0"


def test_get_airflow_version_returns_none_when_neither_probe_works():
    """Neither importable nor binary → None. Doctor renders this as
    info, not warn."""
    from version_compatibility import get_airflow_version

    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def _no_airflow_import(name, *args, **kwargs):
        if name == "airflow":
            raise ImportError("simulated")
        return real_import(name, *args, **kwargs)

    with (
        patch("builtins.__import__", side_effect=_no_airflow_import),
        patch("subprocess.run", side_effect=FileNotFoundError("airflow binary not found")),
    ):
        result = get_airflow_version()

    assert result is None


def test_get_misp_server_version_uses_misp_health_check():
    """Reuses ``MISPHealthCheck.check_health()`` rather than duplicating
    the API call. Patch the health check to return a known version + a
    matching ``details`` dict shape."""
    from version_compatibility import get_misp_server_version

    fake_result = MagicMock()
    fake_result.details = {"version": "2.4.180"}

    fake_check = MagicMock()
    fake_check.return_value.check_health.return_value = fake_result

    with patch.dict(sys.modules, {"misp_health": MagicMock(MISPHealthCheck=fake_check)}):
        result = get_misp_server_version()

    assert result == "2.4.180"


def test_get_misp_server_version_returns_none_when_check_raises():
    """MISP unreachable → check_health raises → must return None."""
    from version_compatibility import get_misp_server_version

    fake_check = MagicMock()
    fake_check.return_value.check_health.side_effect = ConnectionError("simulated")

    with patch.dict(sys.modules, {"misp_health": MagicMock(MISPHealthCheck=fake_check)}):
        result = get_misp_server_version()

    assert result is None


# ---------------------------------------------------------------------------
# compare_version: 4 outcome classes
# ---------------------------------------------------------------------------


def test_compare_version_ok_on_exact_major_minor_match():
    from version_compatibility import compare_version

    status, msg = compare_version("neo4j_driver", "5.27.1")
    assert status == "ok", msg
    assert "matches recommended" in msg


def test_compare_version_ok_ignores_patch_drift():
    """Patch drift is fine — the project's ~= policy explicitly allows it."""
    from version_compatibility import compare_version

    # Recommended is "5.27"; running "5.27.999" should still be OK
    status, _ = compare_version("neo4j_driver", "5.27.999")
    assert status == "ok"


def test_compare_version_warn_on_minor_drift():
    from version_compatibility import compare_version

    # Recommended "5.27", running "5.28" → minor drift
    status, msg = compare_version("neo4j_driver", "5.28.0")
    assert status == "warn"
    assert "minor drift" in msg


def test_compare_version_warn_on_major_drift_calls_out_breaking_changes():
    """Major drift wording must alert the operator to verify call sites —
    that's the actionable instruction. A bare warning without context
    fails its purpose."""
    from version_compatibility import compare_version

    status, msg = compare_version("neo4j_driver", "6.1.0")
    assert status == "warn"
    assert "MAJOR" in msg
    assert "breaking" in msg.lower() or "verify" in msg.lower()


def test_compare_version_unknown_when_running_is_none():
    """Running version not detected (component not installed) → unknown,
    NOT warn. Slack about a missing optional dep is noise."""
    from version_compatibility import compare_version

    status, msg = compare_version("neo4j_driver", None)
    assert status == "unknown"
    assert "not detected" in msg


def test_compare_version_unknown_for_unregistered_component():
    """Bug guard: if doctor asks about a component we never registered,
    say so — don't silently 'ok'."""
    from version_compatibility import compare_version

    status, _ = compare_version("totally_made_up_component", "1.2.3")
    assert status == "unknown"


def test_compare_version_unknown_when_running_unparseable():
    """Some fork or dev build returns a non-semver string. Don't crash;
    don't lie about the comparison."""
    from version_compatibility import compare_version

    status, _ = compare_version("neo4j_driver", "git-snapshot-abc123")
    assert status == "unknown"


# ---------------------------------------------------------------------------
# compare_pinned_vs_running: full report shape
# ---------------------------------------------------------------------------


def test_compare_pinned_vs_running_returns_one_row_per_recommended_component():
    """Doctor iterates this list and renders each row. Order matters
    (we display in ``order`` from the function); count must match the
    recommended-versions table so nothing is missed."""
    from version_compatibility import RECOMMENDED_VERSIONS, compare_pinned_vs_running

    # Inject a stub Neo4j factory so server probe doesn't try a real
    # connection in test env.
    fake_client = MagicMock()
    fake_client.connect.return_value = False  # don't bother running cypher

    rows = compare_pinned_vs_running(neo4j_client_factory=lambda: fake_client)
    components = {r[0] for r in rows}
    assert components == set(RECOMMENDED_VERSIONS.keys()), (
        f"every recommended-versions entry must appear exactly once in the report; "
        f"got {components}, expected {set(RECOMMENDED_VERSIONS.keys())}"
    )


def test_compare_pinned_vs_running_each_row_has_ok_warn_or_unknown_status():
    from version_compatibility import compare_pinned_vs_running

    fake_client = MagicMock()
    fake_client.connect.return_value = False
    rows = compare_pinned_vs_running(neo4j_client_factory=lambda: fake_client)
    for component, status, message in rows:
        assert status in {"ok", "warn", "unknown"}, f"{component}: bad status {status!r}"
        assert isinstance(message, str) and message, f"{component}: empty message"


# ---------------------------------------------------------------------------
# RECOMMENDED_VERSIONS must stay in sync with the actual pin files
# ---------------------------------------------------------------------------


def test_recommended_neo4j_server_matches_docker_compose_pin():
    """Bumping ``docker-compose.yml`` neo4j image without updating
    ``RECOMMENDED_VERSIONS["neo4j_server"]`` would silently make the
    drift warning lie. Pin them together."""
    from version_compatibility import RECOMMENDED_VERSIONS, read_docker_compose_neo4j_image

    tag = read_docker_compose_neo4j_image()
    assert tag, "docker-compose.yml must declare a neo4j image — couldn't parse the pin"
    recommended = RECOMMENDED_VERSIONS["neo4j_server"]
    assert tag.startswith(recommended), (
        f"docker-compose.yml pins neo4j:{tag} but RECOMMENDED_VERSIONS['neo4j_server'] is "
        f"{recommended!r}. They must agree on major.minor — bump both in the same PR."
    )


def test_recommended_neo4j_driver_matches_requirements_pin():
    from version_compatibility import RECOMMENDED_VERSIONS, read_requirements_pin

    pin = read_requirements_pin("requirements.txt", "neo4j")
    assert pin, "requirements.txt must declare neo4j ~=N.M"
    recommended = RECOMMENDED_VERSIONS["neo4j_driver"]
    assert pin.startswith(recommended), (
        f"requirements.txt pins neo4j~={pin} but RECOMMENDED_VERSIONS['neo4j_driver']={recommended!r}"
    )


def test_recommended_neo4j_driver_matches_airflow_image_requirements_pin():
    """Same pin must appear in requirements-airflow-docker.txt (the
    ones baked into the Airflow image). If they drift, scheduler workers
    end up on a different driver line than the CLI — silently."""
    from version_compatibility import RECOMMENDED_VERSIONS, read_requirements_pin

    pin = read_requirements_pin("requirements-airflow-docker.txt", "neo4j")
    if pin is None:
        # File optional in some setups; only enforce if it exists.
        import pytest

        pytest.skip("requirements-airflow-docker.txt not present")
    recommended = RECOMMENDED_VERSIONS["neo4j_driver"]
    assert pin.startswith(recommended), (
        f"requirements-airflow-docker.txt pins neo4j~={pin}; CLI requirements.txt + "
        f"RECOMMENDED_VERSIONS['neo4j_driver']={recommended!r} — keep them aligned."
    )


def test_recommended_pymisp_matches_requirements_pin():
    from version_compatibility import RECOMMENDED_VERSIONS, read_requirements_pin

    pin = read_requirements_pin("requirements.txt", "pymisp")
    assert pin, "requirements.txt must pin pymisp"
    recommended = RECOMMENDED_VERSIONS["pymisp"]
    assert pin.startswith(recommended)


def test_recommended_airflow_matches_requirements_pin():
    """PR #36 commit X (bugbot MED) regression pin.

    Was previously blocked because ``read_requirements_pin``'s regex
    didn't tolerate pip extras syntax — ``apache-airflow[postgres]~=3.2``
    returned None and the test couldn't be written. With the regex
    fix, this test now closes the only remaining gap in the
    ``RECOMMENDED_VERSIONS`` ↔ pin-files sync coverage.
    """
    from version_compatibility import RECOMMENDED_VERSIONS, read_requirements_pin

    pin = read_requirements_pin("requirements.txt", "apache-airflow")
    assert pin, (
        "requirements.txt must pin apache-airflow (with [postgres] extras) — "
        "if this fails, either the pin was removed OR the extras-syntax regex regressed"
    )
    recommended = RECOMMENDED_VERSIONS["airflow"]
    assert pin.startswith(recommended), (
        f"requirements.txt pins apache-airflow~={pin}, but RECOMMENDED_VERSIONS['airflow']={recommended!r}. "
        "Bump both together or doctor's drift warning lies."
    )


def test_read_requirements_pin_handles_pip_extras_syntax():
    """Pure-function pin: ``read_requirements_pin`` MUST recognize
    ``<package>[<extras>]~=<version>`` (pip extras form). Was a Tier-S
    bugbot finding because the previous regex silently returned None
    on any package with extras (apache-airflow being the most common
    example). Includes a synthetic temp-file fixture so the test
    doesn't depend on the real requirements.txt always pinning
    apache-airflow with extras.
    """
    import tempfile
    from pathlib import Path

    import version_compatibility

    with tempfile.TemporaryDirectory() as td:
        # Place a fake requirements file under a temporary repo root.
        # The function reads relative to ``_REPO_ROOT``, so monkeypatch via
        # the module attribute.
        fake_req = Path(td) / "fake-requirements.txt"
        fake_req.write_text(
            "# header\napache-airflow[postgres]~=3.2\nneo4j~=5.27\nstuff[a,b,c]  ~=  1.2\nno-extras~=9.9\n"
        )
        original_root = version_compatibility._REPO_ROOT
        version_compatibility._REPO_ROOT = td
        try:
            assert version_compatibility.read_requirements_pin("fake-requirements.txt", "apache-airflow") == "3.2"
            assert version_compatibility.read_requirements_pin("fake-requirements.txt", "stuff") == "1.2"
            # No-extras form still works (regression: the new (?:\[...\])?
            # group is optional, not required)
            assert version_compatibility.read_requirements_pin("fake-requirements.txt", "no-extras") == "9.9"
            assert version_compatibility.read_requirements_pin("fake-requirements.txt", "neo4j") == "5.27"
        finally:
            version_compatibility._REPO_ROOT = original_root
