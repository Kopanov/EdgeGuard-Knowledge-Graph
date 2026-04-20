"""
Regression tests for PR-F8 — audit follow-ups on already-merged PR-F5.

Background
----------

The multi-agent audit (2026-04-20) found two high-severity issues in
already-merged PR-F5 (#64):

  * **B2 (Cross-Checker HIGH #1):** ``edgeguard doctor --memory`` probe
    reads ``NEO4J_server_memory_heap_max_size`` (single underscore);
    docker-compose sets ``NEO4J_server_memory_heap_max__size`` (double
    underscore — Neo4j's `__→_` and `_→.` env-var convention). Also
    ``server_memory_transaction_total_max`` vs the correct
    ``dbms_memory_transaction_total_max`` (Neo4j 5.x splits ``dbms.*``
    from ``server.*`` namespaces). Result: the probe NEVER matches
    reality and reports "? unknown" regardless of operator config —
    silently defeating PR-F5's entire operator-visibility goal.

  * **B3 (Logic Tracker HIGH):** the PR-F5 conf-typo validator logs
    WARN but the DAG proceeds. Operator typo'd
    ``{"fresh": true, "days": 730}`` → 3 warning log lines, the DAG
    runs ADDITIVE (green, no wipe, no error), and the misconfiguration
    goes undiagnosed for days. The exact 2026-04-19 incident the PR
    claimed to close.

This file pins the B2 + B3 fixes:

  * B2: ``_MEMORY_RECOMMENDATIONS`` declares a tuple of env-var
    candidates per row (Neo4j-internal + operator-facing wrapper); the
    probe tries each in order, first match wins. Both
    ``NEO4J_server_memory_heap_max__size`` (what the container sets)
    and ``NEO4J_HEAP_MAX`` (what operators set in .env) are accepted.

  * B3: ``_fail_fast_on_typo_d_fresh_baseline()`` raises
    ``AirflowException`` when a conf key typo-maps to ``fresh_baseline``
    with a truthy value AND the canonical key is missing. Non-destructive
    typos (``days`` → ``baseline_days``) still fall through to WARN.
"""

from __future__ import annotations

import sys

sys.path.insert(0, "src")
sys.path.insert(0, "dags")


# ===========================================================================
# B2: _MEMORY_RECOMMENDATIONS env-var names match docker-compose.yml
# ===========================================================================


class TestMemoryRecommendationsEnvNames:
    """The probe's env-var candidates MUST include the names Neo4j
    actually sets inside the container per docker-compose.yml:96-100."""

    def test_neo4j_heap_accepts_double_underscore_name(self):
        """Compose sets ``NEO4J_server_memory_heap_max__size`` (double
        underscore before ``size``) — not the old single-underscore
        name. The probe row MUST include this in its candidates."""
        from edgeguard import _MEMORY_RECOMMENDATIONS

        heap_row = next(r for r in _MEMORY_RECOMMENDATIONS if r["key"] == "neo4j_heap")
        env_vars = heap_row.get("env_vars", ())
        assert "NEO4J_server_memory_heap_max__size" in env_vars, (
            "neo4j_heap MUST accept the double-underscore name that compose actually sets"
        )

    def test_neo4j_tx_memory_accepts_dbms_prefix(self):
        """Compose sets ``NEO4J_dbms_memory_transaction_total_max`` (``dbms``
        prefix, not ``server``) per Neo4j 5.x's split between ``dbms.*`` and
        ``server.*`` config namespaces."""
        from edgeguard import _MEMORY_RECOMMENDATIONS

        tx_row = next(r for r in _MEMORY_RECOMMENDATIONS if r["key"] == "neo4j_tx_memory")
        env_vars = tx_row.get("env_vars", ())
        assert "NEO4J_dbms_memory_transaction_total_max" in env_vars, (
            "neo4j_tx_memory MUST use `dbms_` prefix (per Neo4j 5.x) — NOT `server_`"
        )

    def test_all_rows_have_env_vars_tuple_not_single(self):
        """Each recommendation row MUST use the new plural ``env_vars``
        tuple, not the old singular ``env_var`` string. This pattern
        change enables accepting multiple candidate names per row
        (Neo4j-internal + operator-facing wrapper)."""
        from edgeguard import _MEMORY_RECOMMENDATIONS

        for rec in _MEMORY_RECOMMENDATIONS:
            assert "env_vars" in rec, f"recommendation row {rec.get('key')!r} missing 'env_vars' tuple"
            assert isinstance(rec["env_vars"], tuple), (
                f"row {rec['key']!r} env_vars must be a tuple, got {type(rec['env_vars']).__name__}"
            )
            assert len(rec["env_vars"]) >= 1, f"row {rec['key']!r} env_vars must have ≥1 candidate"
            # Old singular field must be gone to prevent accidental drift
            assert "env_var" not in rec, (
                f"row {rec['key']!r} still has singular 'env_var' — should use 'env_vars' tuple"
            )

    def test_each_row_also_accepts_operator_facing_wrapper(self):
        """Operators typically set the SHORT wrapper variables in .env
        (``NEO4J_HEAP_MAX``, ``NEO4J_PAGECACHE``, ``NEO4J_TX_MEMORY_MAX``).
        The probe should accept those TOO, so running
        ``edgeguard doctor --memory`` from the host shell (where the
        long Neo4j-internal names aren't set) still works."""
        from edgeguard import _MEMORY_RECOMMENDATIONS

        expected_wrappers = {
            "neo4j_heap": "NEO4J_HEAP_MAX",
            "neo4j_page_cache": "NEO4J_PAGECACHE",
            "neo4j_tx_memory": "NEO4J_TX_MEMORY_MAX",
        }
        for key, wrapper in expected_wrappers.items():
            row = next(r for r in _MEMORY_RECOMMENDATIONS if r["key"] == key)
            assert wrapper in row["env_vars"], (
                f"row {key!r} should accept operator-facing wrapper {wrapper!r} as a fallback "
                f"for operators running the probe from the host shell"
            )


class TestMemoryProbeFirstMatchWins:
    """The render path tries each env_vars candidate in order; first
    non-empty value wins."""

    def test_internal_name_wins_when_both_set(self, monkeypatch):
        """When both the Neo4j-internal name and the operator-facing
        wrapper are set, the Neo4j-internal name (first in the tuple)
        should win — because that's what the container actually reads."""
        from edgeguard import _MEMORY_RECOMMENDATIONS

        # Simulate: inside-container env has the Neo4j-internal name set;
        # host env has the wrapper set to a different value
        heap_row = next(r for r in _MEMORY_RECOMMENDATIONS if r["key"] == "neo4j_heap")
        internal_name = heap_row["env_vars"][0]
        wrapper_name = heap_row["env_vars"][1]
        assert internal_name != wrapper_name  # sanity

        monkeypatch.setenv(internal_name, "12G")  # container-side
        monkeypatch.setenv(wrapper_name, "4G")  # host .env side

        # Use the render iteration logic inline (matches what
        # _doctor_memory_check does at the render site).
        raw = None
        for candidate in heap_row["env_vars"]:
            import os

            val = os.environ.get(candidate)
            if val:
                raw = val
                break
        assert raw == "12G", f"internal name should win; got {raw!r}"


# ===========================================================================
# B3: fail-fast on typo'd fresh_baseline
# ===========================================================================


def _import_dag_module():
    """Import the DAG module to get access to its validator helpers.
    Skips if the DAG module can't be loaded (e.g., Airflow unavailable)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("_dag_module_for_test", "dags/edgeguard_pipeline.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        import pytest

        pytest.skip(f"DAG module not importable in this environment: {e}")
    return module


class TestFailFastOnFreshBaselineTypo:
    """Pin the B3 fail-fast contract: a typo'd key that maps to
    ``fresh_baseline`` with a truthy value MUST raise
    AirflowException, not log-and-continue."""

    def test_fresh_truthy_raises(self):
        """``{"fresh": true}`` (typo) must refuse to run."""
        from airflow.exceptions import AirflowException

        mod = _import_dag_module()
        import pytest

        with pytest.raises(AirflowException, match="typo'd destructive key"):
            mod._fail_fast_on_typo_d_fresh_baseline({"fresh": True})

    def test_destructive_truthy_raises(self):
        """``{"destructive": 1}`` (alternate typo) must also refuse."""
        from airflow.exceptions import AirflowException

        mod = _import_dag_module()
        import pytest

        with pytest.raises(AirflowException):
            mod._fail_fast_on_typo_d_fresh_baseline({"destructive": 1})

    def test_wipe_str_truthy_raises(self):
        """``{"wipe": "yes"}`` — str truthy via the same semantics as
        _baseline_clean's fresh_baseline parser."""
        from airflow.exceptions import AirflowException

        mod = _import_dag_module()
        import pytest

        with pytest.raises(AirflowException):
            mod._fail_fast_on_typo_d_fresh_baseline({"wipe": "yes"})

    def test_fresh_falsy_does_not_raise(self):
        """Operator explicitly set false — they're confirming additive.
        Don't refuse; fall through to the WARN path."""
        mod = _import_dag_module()
        mod._fail_fast_on_typo_d_fresh_baseline({"fresh": False})  # no raise
        mod._fail_fast_on_typo_d_fresh_baseline({"fresh": "false"})
        mod._fail_fast_on_typo_d_fresh_baseline({"fresh": 0})
        mod._fail_fast_on_typo_d_fresh_baseline({"fresh": ""})

    def test_canonical_key_present_does_not_raise_even_if_typo_also_present(self):
        """If ``fresh_baseline`` is already in the conf, respect the
        operator's explicit intent — don't second-guess their typo."""
        mod = _import_dag_module()
        mod._fail_fast_on_typo_d_fresh_baseline({"fresh": True, "fresh_baseline": False})  # canonical wins → no raise

    def test_non_destructive_typo_does_not_raise(self):
        """Typos for non-destructive keys (``days`` → ``baseline_days``)
        fall through to WARN — non-destructive defaults are recoverable."""
        mod = _import_dag_module()
        mod._fail_fast_on_typo_d_fresh_baseline({"days": 730})  # no raise
        mod._fail_fast_on_typo_d_fresh_baseline({"limit": 100})
        mod._fail_fast_on_typo_d_fresh_baseline({"completely_unknown_key": "anything"})

    def test_empty_and_non_dict_conf_is_noop(self):
        mod = _import_dag_module()
        mod._fail_fast_on_typo_d_fresh_baseline({})  # no raise
        mod._fail_fast_on_typo_d_fresh_baseline(None)  # type: ignore[arg-type]
        mod._fail_fast_on_typo_d_fresh_baseline("not-a-dict")  # type: ignore[arg-type]

    def test_exception_message_guides_operator(self):
        """The exception message MUST give the operator everything they
        need to fix the conf — the typo'd key, the suggestion, an
        example corrected conf, and a pointer to the docs."""
        from airflow.exceptions import AirflowException

        mod = _import_dag_module()
        import pytest

        with pytest.raises(AirflowException) as excinfo:
            mod._fail_fast_on_typo_d_fresh_baseline({"fresh": True})
        msg = str(excinfo.value)
        assert "'fresh'" in msg, "message must quote the typo'd key"
        assert "'fresh_baseline'" in msg, "message must suggest the canonical key"
        assert "baseline_days" in msg, "message must show the full corrected conf shape"
        assert "docs/AIRFLOW_DAGS.md" in msg, "message must point operators at the authoritative key list"
        assert "2026-04-19" in msg, "message must reference the incident that motivated this check"


class TestIsTruthyConfValue:
    """The shared truthy-parsing helper mirrors ``_baseline_clean``'s
    fresh_baseline parse so the fail-fast decision matches the actual
    consumption behavior."""

    def test_python_true(self):
        mod = _import_dag_module()
        assert mod._is_truthy_conf_value(True) is True

    def test_python_false(self):
        mod = _import_dag_module()
        assert mod._is_truthy_conf_value(False) is False

    def test_int_one(self):
        mod = _import_dag_module()
        assert mod._is_truthy_conf_value(1) is True

    def test_int_other(self):
        mod = _import_dag_module()
        # Only EXACT 1 counts (mirrors the parse at _baseline_clean:2266)
        assert mod._is_truthy_conf_value(2) is False
        assert mod._is_truthy_conf_value(0) is False

    def test_string_truthy_case_insensitive(self):
        mod = _import_dag_module()
        for raw in ("true", "True", "TRUE", "1", "yes", "YES", "on", "On", " true ", "  1  "):
            assert mod._is_truthy_conf_value(raw) is True, f"{raw!r} should be truthy"

    def test_string_falsy(self):
        mod = _import_dag_module()
        for raw in ("false", "False", "0", "no", "off", "", "  ", "random"):
            assert mod._is_truthy_conf_value(raw) is False, f"{raw!r} should be falsy"


# ===========================================================================
# Source-pin: _baseline_clean calls the fail-fast helper
# ===========================================================================


class TestBaselineCleanWiresFailFast:
    """``_baseline_clean`` MUST invoke ``_fail_fast_on_typo_d_fresh_baseline``
    BEFORE consuming ``fresh_baseline``. Source-pin to prevent accidental
    removal in a future refactor."""

    def test_baseline_clean_calls_fail_fast_helper(self):
        with open("dags/edgeguard_pipeline.py") as fh:
            src = fh.read()
        idx = src.find("def _baseline_clean(")
        assert idx > 0
        end = src.find("\ndef ", idx + 1)
        body = src[idx:end]
        assert "_fail_fast_on_typo_d_fresh_baseline(conf)" in body, (
            "_baseline_clean must invoke _fail_fast_on_typo_d_fresh_baseline(conf)"
        )
        # The fail-fast must be BEFORE the raw_fresh parse — otherwise
        # a truthy typo could still get consumed on the destructive path
        fail_fast_idx = body.find("_fail_fast_on_typo_d_fresh_baseline(conf)")
        raw_fresh_idx = body.find('raw_fresh = conf.get("fresh_baseline"')
        assert fail_fast_idx > 0 and raw_fresh_idx > 0
        assert fail_fast_idx < raw_fresh_idx, (
            "fail-fast must run BEFORE fresh_baseline parse — otherwise typo could slip through"
        )


# ===========================================================================
# Documentation traceability
# ===========================================================================


class TestDocsDocumentEnvVarMapping:
    def test_memory_tuning_explains_neo4j_env_convention(self):
        """docs/MEMORY_TUNING.md MUST explain the double-underscore /
        dbms-vs-server convention so operators know the .env key names
        aren't arbitrary. Without this, the next doc reader will
        'correct' the compose file back to the single-underscore form."""
        with open("docs/MEMORY_TUNING.md") as fh:
            content = fh.read()
        # The Cross-Checker audit fix — both the mapping rules AND the
        # wrapper-variable-recommendation must be present
        assert "__" in content, "doc must explain the `__` mapping rule"
        assert "dbms" in content.lower(), "doc must explain the dbms vs server namespace split"
        # The operator-facing wrapper names should be the ones in the .env snippet
        assert "NEO4J_HEAP_MAX" in content
        assert "NEO4J_TX_MEMORY_MAX" in content
