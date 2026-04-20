"""
Regression tests for PR-F5 — baseline DAG conf typo / unknown-key validation.

Background
----------

On 2026-04-19 an operator triggered a fresh baseline via the Airflow UI
with ``{"days": 730}`` instead of ``{"baseline_days": 730}`` AND missing
``fresh_baseline: true`` entirely. Both consumers
(``get_baseline_config`` and ``_baseline_clean``) silently fell through
to defaults — additive mode (no wipe), default 730-day window. The
operator believed they had triggered a destructive run with custom
depth; in reality they had triggered an additive run with the default
depth and no destructive guard.

PR-F5 closes that silent-fallthrough gap by emitting a WARNING log line
for every key in ``dag_run.conf`` that isn't on the known-good list.
Common typos get a "did you mean?" suggestion.

What these tests pin
--------------------

  - Known keys never warn
  - Unknown keys with a known-typo mapping get a "did you mean?" warning
  - Unknown keys without a typo mapping get a generic warning
  - Empty / non-dict conf is a safe no-op (no crash, no spurious warnings)
  - Source-pin: the validator is called from BOTH consumption sites
    (get_baseline_config + _baseline_clean) so future contributors don't
    add a third consumer that bypasses validation
"""

from __future__ import annotations

import logging
import sys

sys.path.insert(0, "src")
sys.path.insert(0, "dags")


# Importing the DAG file at top-level requires Airflow at test time.
# Use the same source-pin pattern as other DAG tests
# (test_pr_f4_tier1_sequential.py, test_baseline_dag_timeouts.py).
DAG_PATH = "dags/edgeguard_pipeline.py"


def _read_dag_source() -> str:
    with open(DAG_PATH) as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# Source-pin: the validator function exists and is called from every
# documented dag_run.conf consumption site.
# ---------------------------------------------------------------------------


class TestValidatorIsWiredAtEverySite:
    """The 2026-04-19 incident bit because validation was missing
    entirely. These tests pin that EVERY conf-consuming function calls
    the validator — so a future contributor can't accidentally skip it
    on a new conf-consumer."""

    def test_validator_function_exists(self):
        src = _read_dag_source()
        assert "def _validate_baseline_dag_conf(" in src, "PR-F5 validator function MUST exist"

    def test_validator_called_from_get_baseline_config(self):
        src = _read_dag_source()
        idx = src.find("def get_baseline_config(")
        assert idx > 0
        # Find the function body until the next top-level def
        end = src.find("\ndef ", idx + 1)
        body = src[idx:end]
        assert "_validate_baseline_dag_conf(" in body, (
            "PR-F5 contract: get_baseline_config must call the validator "
            "to surface typo / unknown-key warnings before consuming conf"
        )

    def test_validator_called_from_baseline_clean(self):
        src = _read_dag_source()
        idx = src.find("def _baseline_clean(")
        assert idx > 0
        end = src.find("\ndef ", idx + 1)
        body = src[idx:end]
        assert "_validate_baseline_dag_conf(" in body, (
            "PR-F5 contract: _baseline_clean (the destructive task) MUST "
            "validate conf before consuming fresh_baseline — silent typos "
            "in the destructive flag is exactly the failure mode this fixes"
        )

    def test_validator_called_from_baseline_start_summary(self):
        src = _read_dag_source()
        idx = src.find("def _baseline_start_summary(")
        assert idx > 0
        end = src.find("\ndef ", idx + 1)
        body = src[idx:end]
        assert "_validate_baseline_dag_conf(" in body, (
            "PR-F5 contract: _baseline_start_summary reads clear_checkpoints directly from conf — must validate too"
        )


# ---------------------------------------------------------------------------
# Behavioral tests — the validator's actual logic
# ---------------------------------------------------------------------------


def _import_validator():
    """Import the validator from the DAG module by path. Avoids
    triggering Airflow imports at test-collection time."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("_dag_module_for_test", DAG_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        # If Airflow isn't available at test time, skip the behavioral
        # tests rather than fail. The source-pin tests above cover the
        # contract independently.
        import pytest

        pytest.skip(f"DAG module not importable in this environment: {e}")
    return module._validate_baseline_dag_conf, module._KNOWN_BASELINE_CONF_KEYS, module._BASELINE_CONF_TYPO_MAP


class TestValidatorBehavior:
    def test_known_keys_produce_no_warning(self, caplog):
        validator, known_keys, _ = _import_validator()
        conf = {key: "any-value" for key in known_keys}
        with caplog.at_level(logging.WARNING):
            caplog.clear()
            validator(conf, source_label="test")
        # Filter to ONLY warnings from this validator (its grep marker is
        # the contract); other libs may emit unrelated WARNING records
        # during test runs (Airflow init, SQLAlchemy, etc.).
        ours = [r for r in caplog.records if "[BASELINE_CONF]" in r.message]
        assert not ours, f"known keys should never produce [BASELINE_CONF] warnings; got: {[r.message for r in ours]}"

    def test_typo_key_produces_did_you_mean_suggestion(self, caplog):
        validator, _, typo_map = _import_validator()
        # Pick a deterministic typo with a known suggestion
        assert "days" in typo_map and typo_map["days"] == "baseline_days"
        with caplog.at_level(logging.WARNING):
            validator({"days": 730}, source_label="test")
        msgs = " ".join(r.message for r in caplog.records if r.levelno >= logging.WARNING)
        assert "[BASELINE_CONF]" in msgs, "warning must carry the [BASELINE_CONF] grep marker"
        assert "'days'" in msgs and "'baseline_days'" in msgs, (
            "did-you-mean warning must mention both the typo'd key and the suggestion"
        )
        # The 2026-04-19 incident motivation should be in the message
        assert "SILENTLY IGNORED" in msgs

    def test_unknown_key_without_typo_produces_generic_warning(self, caplog):
        validator, known_keys, _ = _import_validator()
        # Pick a key that's clearly not in the typo map
        with caplog.at_level(logging.WARNING):
            validator({"completely_made_up_key_xyz": "value"}, source_label="test")
        msgs = " ".join(r.message for r in caplog.records if r.levelno >= logging.WARNING)
        assert "[BASELINE_CONF]" in msgs
        assert "completely_made_up_key_xyz" in msgs
        # Should list known keys in the warning so the operator can reorient
        for key in known_keys:
            assert key in msgs, f"generic warning must list known key {key!r} for operator guidance"

    def test_typo_map_covers_the_documented_2026_04_19_incident(self):
        """Bravo's investigation surfaced ``{"days": 730}`` as the
        specific typo. PR-F5 MUST map that exact case."""
        _, _, typo_map = _import_validator()
        assert typo_map.get("days") == "baseline_days", (
            "the 2026-04-19 incident typo (days → baseline_days) must be in the typo map"
        )

    def test_typo_lookup_is_case_and_whitespace_tolerant(self, caplog):
        """Operators occasionally type ``{"  Days  ": 730}`` due to
        copy-paste from chat. The validator should still suggest the fix."""
        validator, _, _ = _import_validator()
        with caplog.at_level(logging.WARNING):
            validator({"  Days  ": 730}, source_label="test")
        msgs = " ".join(r.message for r in caplog.records if r.levelno >= logging.WARNING)
        assert "'baseline_days'" in msgs, "case+whitespace-tolerant typo lookup must still suggest baseline_days"

    def test_empty_conf_is_no_op(self, caplog):
        validator, _, _ = _import_validator()
        # Filter to only warnings carrying our validator's grep marker —
        # other libs (Airflow init, SQLAlchemy) may emit WARNING records
        # during the same test that have nothing to do with our validator.
        with caplog.at_level(logging.WARNING):
            caplog.clear()
            validator({}, source_label="test")
            validator(None, source_label="test")  # type: ignore[arg-type]
            validator("not-a-dict", source_label="test")  # type: ignore[arg-type]
        ours = [r for r in caplog.records if "[BASELINE_CONF]" in r.message]
        assert not ours, (
            "empty/None/non-dict conf must be a safe no-op (no crash, no spurious "
            f"[BASELINE_CONF] warnings); got: {[r.message for r in ours]}"
        )

    def test_source_label_appears_in_warning(self, caplog):
        """The source_label argument lets operators trace WHICH
        consumer flagged the typo (helps diagnose multi-step DAG runs)."""
        validator, _, _ = _import_validator()
        with caplog.at_level(logging.WARNING):
            validator({"unknown_xyz": 1}, source_label="my_unique_call_site")
        msgs = " ".join(r.message for r in caplog.records if r.levelno >= logging.WARNING)
        assert "my_unique_call_site" in msgs


# ---------------------------------------------------------------------------
# Documentation traceability — the operator-facing docs MUST list the
# known keys (so an operator reading docs/AIRFLOW_DAGS.md sees what's
# accepted before they trigger).
# ---------------------------------------------------------------------------


class TestDocsListAcceptedConfKeys:
    def test_airflow_dags_md_documents_all_known_keys(self):
        with open("docs/AIRFLOW_DAGS.md") as fh:
            content = fh.read()
        # The new "Baseline DAG conf — accepted keys (PR-F5)" subsection
        # must exist with all known keys + the [BASELINE_CONF] grep marker.
        assert "Baseline DAG conf — accepted keys" in content
        assert "[BASELINE_CONF]" in content, (
            "docs must mention the [BASELINE_CONF] log marker so operators know what to grep for"
        )
        for key in ("fresh_baseline", "baseline_days", "collection_limit", "clear_checkpoints"):
            assert f"`{key}`" in content, f"docs must document the {key!r} conf key"
