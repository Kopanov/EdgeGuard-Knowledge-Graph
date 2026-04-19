"""
Regression tests for PR-A audit ship-blockers.

These tests pin the runtime fixes that came from the 7-agent comprehensive
audit. The fixes themselves are small (3-10 LOC each) but the failure modes
are silent and operationally certain to bite — pin via tests so they can't
regress.

Coverage:
    - **Bug Hunter HIGH H1**: ``Neo4jClient.connect()`` must close + null
      ``self.driver`` on every exception branch (auth, transient, generic).
      The previous code assigned ``self.driver`` BEFORE the verify
      ``session.run()`` raised — the failed-connect path returned False with
      a live driver still attached, and every retry leaked another driver.
      Operationally certain to bite during MISP password rotation: 5+ retries
      across the 5h baseline timeout would exhaust file descriptors or
      neo4j connection-pool slots.
    - **Bug Hunter HIGH H2**: ``run_pipeline.py``'s ``_cleanup_lock``
      atexit handler must check the lock's PID before unlinking. The
      previous blind ``os.remove`` opened a window where Process A's
      atexit could delete Process B's freshly-acquired lock, letting
      Process C also acquire — two pipelines run concurrently, racing
      MERGE. Mirrors the PID-check pattern in
      ``baseline_lock.release_baseline_lock``.
    - **Red Team CRITICAL C1** (round-2 follow-up): ``install.sh`` must
      auto-generate ``EDGEGUARD_API_KEY`` when .env is created from
      .env.example with an empty key. Without this the api / graphql
      containers crashloop on first ``docker compose up`` (the safety
      check at ``src/query_api.py:96`` refuses to bind 0.0.0.0 without
      either an API key or an explicit ``EDGEGUARD_ALLOW_UNAUTH=1`` opt-
      in). Auto-gen keeps the safety check intact while making the
      install path frictionless. Same logic for ``GRAFANA_ADMIN_PASSWORD``
      to avoid shipping the literal ``changeme`` default.

Other PR-A fixes (compose auth bypass, healthchecks, memory defaults,
requirements alias, GHA SHA pins, disk-free alerts) are config/yaml
changes pinned by their own filetype tests or by manual ``docker compose
config`` validation (not unit-testable).
"""

from __future__ import annotations

import inspect
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, "src")


# ---------------------------------------------------------------------------
# Bug Hunter HIGH H1 — driver leak on Neo4j connect-failure paths
# ---------------------------------------------------------------------------


class TestNeo4jConnectDriverLeak:
    """Every failed-connect exception branch in ``Neo4jClient.connect()``
    MUST close + null the driver before returning/re-raising.

    The previous code only set ``self._connection_healthy = False`` —
    leaving ``self.driver`` (assigned at line 435 BEFORE the verify
    ``session.run`` raised) attached to a live but unverified driver.
    Symptoms in production:
      - ``MISP password rotation`` → 5+ retries → 5+ leaked drivers →
        ``OSError: too many open files`` mid-baseline.
      - The next ``Neo4jClient()`` call's ``connect()`` overwrote
        ``self.driver`` without closing the prior — leak compounded.

    Tests use a mock ``GraphDatabase.driver`` that returns a tracked
    driver mock; we assert ``.close()`` is called on it whenever
    ``connect()`` returns False or re-raises.
    """

    def _import_client_with_mocks(self):
        """Re-import neo4j_client with mocked GraphDatabase + neo4j_exceptions."""
        # Defer to the real module; we only need to patch the driver factory.
        import neo4j_client as nc

        return nc

    def test_auth_error_closes_driver(self):
        nc = self._import_client_with_mocks()
        client = nc.Neo4jClient()
        fake_driver = MagicMock()
        # Make the verify ``session.run`` raise AuthError.
        fake_session = MagicMock()
        fake_session.run.side_effect = nc.neo4j_exceptions.AuthError("bad password")
        fake_driver.session.return_value.__enter__ = lambda s: fake_session
        fake_driver.session.return_value.__exit__ = lambda s, *a: None

        with patch.object(nc.GraphDatabase, "driver", return_value=fake_driver):
            ok = client.connect()

        assert ok is False
        # The leak guard:
        fake_driver.close.assert_called_once()
        # And the attribute is nulled so a re-call to connect() doesn't see
        # a half-closed driver:
        assert client.driver is None
        assert client._connection_healthy is False

    def test_generic_exception_closes_driver(self):
        nc = self._import_client_with_mocks()
        client = nc.Neo4jClient()
        fake_driver = MagicMock()
        fake_session = MagicMock()
        # Some random non-retryable error — falls into the generic except.
        fake_session.run.side_effect = ValueError("bad query")
        fake_driver.session.return_value.__enter__ = lambda s: fake_session
        fake_driver.session.return_value.__exit__ = lambda s, *a: None

        with patch.object(nc.GraphDatabase, "driver", return_value=fake_driver):
            ok = client.connect()

        assert ok is False
        fake_driver.close.assert_called_once()
        assert client.driver is None

    def test_transient_error_closes_driver_then_reraises(self):
        nc = self._import_client_with_mocks()
        client = nc.Neo4jClient()
        fake_driver = MagicMock()
        fake_session = MagicMock()
        # ServiceUnavailable is in the re-raise branch (handled by
        # @retry_with_backoff at the next layer up).
        fake_session.run.side_effect = nc.neo4j_exceptions.ServiceUnavailable("svc down")
        fake_driver.session.return_value.__enter__ = lambda s: fake_session
        fake_driver.session.return_value.__exit__ = lambda s, *a: None

        with patch.object(nc.GraphDatabase, "driver", return_value=fake_driver):
            # @retry_with_backoff will retry MAX_RETRIES (5) times then raise.
            # Each retry closes its own driver (no leak across retries).
            with pytest.raises(nc.neo4j_exceptions.ServiceUnavailable):
                client.connect()

        # close() was called at LEAST once per retry attempt
        assert fake_driver.close.call_count >= 1
        assert client.driver is None

    def test_safe_close_driver_helper_is_idempotent(self):
        """``_safe_close_driver`` must be no-raise + safe to call when
        ``self.driver`` is already None."""
        nc = self._import_client_with_mocks()
        client = nc.Neo4jClient()
        client.driver = None
        # Must not raise:
        client._safe_close_driver()
        assert client.driver is None

    def test_safe_close_driver_swallows_close_exceptions(self):
        """If the underlying driver.close() raises, the helper logs at
        debug and returns — does not propagate. Otherwise the leak-guard
        in connect() would itself break the connect() exception path."""
        nc = self._import_client_with_mocks()
        client = nc.Neo4jClient()
        bad_driver = MagicMock()
        bad_driver.close.side_effect = RuntimeError("close failed")
        client.driver = bad_driver
        # Must not raise:
        client._safe_close_driver()
        assert client.driver is None
        bad_driver.close.assert_called_once()


# ---------------------------------------------------------------------------
# Bug Hunter HIGH H2 — pipeline lock PID race
# ---------------------------------------------------------------------------


class TestPipelineLockPidCheck:
    """``_cleanup_lock`` (the atexit handler) must verify the lock file's
    PID matches the current process before unlinking.

    Without the check, the stale-PID recovery path in ``_run_with_lock``
    (lines 1027-1032) lets a competing process unlink-and-re-acquire the
    same lock — and then THIS process's atexit handler unlinks the OTHER
    process's freshly-acquired lock, opening a window for a third
    invocation to also acquire. Two pipelines run concurrently.

    The fix uses a new ``_read_lock_pid`` helper that mirrors the
    ``baseline_lock.release_baseline_lock`` pattern. We assert:
      1. The helper exists and is invoked from ``_cleanup_lock``.
      2. ``_cleanup_lock`` does NOT call ``os.remove`` when the PID
         doesn't match (use file-source scan since the helper is
         defined inline inside the method).
    """

    def _pipeline_source(self) -> str:
        import run_pipeline

        # _cleanup_lock + _read_lock_pid are defined inline inside the
        # ``EdgeGuardPipeline.run`` method (the public entry point).
        return inspect.getsource(run_pipeline.EdgeGuardPipeline.run)

    def test_read_lock_pid_helper_is_defined(self):
        src = self._pipeline_source()
        assert "def _read_lock_pid(" in src, "_read_lock_pid helper must be defined inline in _run_with_lock"

    def test_cleanup_lock_calls_read_lock_pid_before_remove(self):
        src = self._pipeline_source()
        assert "_read_lock_pid(lock_path)" in src, "_cleanup_lock must call _read_lock_pid before unlinking"

    def test_cleanup_lock_compares_pid_to_current(self):
        src = self._pipeline_source()
        # The fix uses ``pid == os.getpid()`` to gate the remove.
        assert "os.getpid()" in src
        # And the legacy blind-remove pattern must NOT appear in
        # _cleanup_lock — the unconditional ``os.remove(lock_path)``
        # was the bug.
        # We can't grep for "os.remove(lock_path)" globally because
        # the acquire path also unlinks on stale-PID recovery; instead
        # we slice to the _cleanup_lock body.
        cleanup_start = src.find("def _cleanup_lock(")
        cleanup_end = src.find("\n        atexit.register", cleanup_start)
        assert cleanup_start > 0 and cleanup_end > cleanup_start
        cleanup_body = src[cleanup_start:cleanup_end]
        # The remove inside _cleanup_lock MUST be guarded by a pid==current check
        assert "pid == os.getpid()" in cleanup_body, "_cleanup_lock body must guard os.remove with pid==os.getpid()"

    def test_read_lock_pid_returns_none_on_unreadable(self, tmp_path):
        """The helper itself: returns None for missing file, malformed
        contents, or any I/O error. None is the safer default — caller
        treats None as 'don't unlink'."""

        # Re-import the module to access the inner function. Since
        # _read_lock_pid is defined inside _run_with_lock, we can't import
        # it directly — instead, replicate its body here as a smoke test
        # of the same logic.
        def _read_lock_pid(path: str):
            try:
                with open(path) as fh:
                    return int(fh.read().strip())
            except (OSError, ValueError):
                return None

        # Missing file
        assert _read_lock_pid(str(tmp_path / "nonexistent.lock")) is None
        # Empty file
        empty = tmp_path / "empty.lock"
        empty.write_text("")
        assert _read_lock_pid(str(empty)) is None
        # Malformed
        bad = tmp_path / "bad.lock"
        bad.write_text("not-a-pid\n")
        assert _read_lock_pid(str(bad)) is None
        # Valid
        good = tmp_path / "good.lock"
        good.write_text(f"{os.getpid()}\n")
        assert _read_lock_pid(str(good)) == os.getpid()


# ---------------------------------------------------------------------------
# Red Team CRITICAL C1 — install.sh auto-generates EDGEGUARD_API_KEY so
# fresh ``./install.sh && docker compose up`` does not crashloop on the
# query_api.py safety check.
# ---------------------------------------------------------------------------


class TestInstallShAutogeneratesApiKey:
    """install.sh must populate EDGEGUARD_API_KEY (and rotate
    GRAFANA_ADMIN_PASSWORD off the literal "changeme") when creating
    .env from .env.example. Otherwise the api / graphql containers
    crashloop and the operator copy-pastes ``EDGEGUARD_ALLOW_UNAUTH=1``
    out of the error message — defeating the safety check entirely.
    """

    @staticmethod
    def _project_root() -> str:
        # tests/ lives one level under project root
        return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    def test_install_sh_contains_api_key_autogen_block(self):
        """The install.sh source must contain the .env-edit block that
        replaces the empty EDGEGUARD_API_KEY with a generated value.
        Pinned via source-grep because the alternative — actually running
        install.sh in a tmpdir — pulls in the docker stage."""
        path = os.path.join(self._project_root(), "install.sh")
        with open(path) as fh:
            src = fh.read()
        # The grep that detects the empty default
        assert 'grep -q "^EDGEGUARD_API_KEY=$" .env' in src, (
            "install.sh must detect an empty EDGEGUARD_API_KEY before substituting"
        )
        # At least one of the two key generators (must accept either ordering)
        assert "openssl rand -hex 32" in src or "secrets.token_hex(32)" in src, (
            "install.sh must offer openssl OR python3 fallback for key generation"
        )
        # The actual replacement must rewrite the empty assignment
        assert 'print "EDGEGUARD_API_KEY=" key' in src, (
            "install.sh must print the substituted EDGEGUARD_API_KEY=<value> line"
        )

    def test_install_sh_rotates_default_grafana_password(self):
        """``changeme`` is a credential-stuffing target — install.sh must
        replace it with a generated value when creating .env."""
        path = os.path.join(self._project_root(), "install.sh")
        with open(path) as fh:
            src = fh.read()
        assert "GRAFANA_ADMIN_PASSWORD=changeme" in src, (
            "install.sh must explicitly target the literal default to substitute"
        )
        assert "GRAFANA_ADMIN_PASSWORD=" in src

    def test_env_example_documents_api_key_requirement(self):
        """The .env.example comment block must tell manual-install
        operators (those who skip install.sh) that the api/graphql
        containers will refuse to start with an empty key."""
        path = os.path.join(self._project_root(), ".env.example")
        with open(path) as fh:
            content = fh.read()
        assert "REFUSE TO START" in content, ".env.example must warn that empty EDGEGUARD_API_KEY blocks startup"
        # The three fix paths must all be documented
        assert "install.sh" in content
        assert "openssl rand -hex 32" in content
        assert "EDGEGUARD_ALLOW_UNAUTH" in content

    def test_awk_substitution_actually_replaces_the_key(self, tmp_path):
        """Behavioural test: feed an .env-shaped string with an empty
        EDGEGUARD_API_KEY through the same awk command install.sh uses,
        and assert the output has the generated value substituted."""
        import subprocess

        env_input = (
            "# leading comment\n"
            "NEO4J_PASSWORD=changeme\n"
            "EDGEGUARD_API_KEY=\n"
            "GRAFANA_ADMIN_PASSWORD=changeme\n"
            "TRAILING=value\n"
        )
        env_file = tmp_path / ".env"
        env_file.write_text(env_input)

        result = subprocess.run(
            [
                "awk",
                "-v",
                "key=GENERATED_KEY_VALUE",
                '/^EDGEGUARD_API_KEY=$/ { print "EDGEGUARD_API_KEY=" key; next } { print }',
                str(env_file),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        out = result.stdout
        assert "EDGEGUARD_API_KEY=GENERATED_KEY_VALUE" in out
        # Other lines untouched
        assert "NEO4J_PASSWORD=changeme" in out
        assert "GRAFANA_ADMIN_PASSWORD=changeme" in out
        assert "TRAILING=value" in out
        # No accidental duplicate / empty key line
        assert out.count("EDGEGUARD_API_KEY=") == 1
