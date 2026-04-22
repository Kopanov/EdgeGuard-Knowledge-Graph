"""
PR-N22 — historical CVE date backfill regression pins.

Covers ``scripts/backfill_cve_dates_from_nvd_meta.py``, which reads MISP
NVD_META (written at ingest by MISPWriter for NVD-sourced CVEs) and
backfills ``c.published`` / ``c.last_modified`` on Neo4j CVE nodes that
were ingested before PR-N19 Fix #1 (when the write path silently dropped
those fields).

The script is:
  - Idempotent — safe to re-run without double-writes
  - Non-destructive — uses ``coalesce`` so an existing non-NULL value
    from a post-PR-N19 baseline is preserved (not overwritten)
  - Bounded — batch_size + rate_limit flags
  - Operator-friendly — dry-run mode, progress logs, exit-code distinction

These tests pin:
  1. The script exists + is executable
  2. The NVD_META parser is correct + safe against malformed input
  3. The date extractor normalizes empty/missing to None
  4. The Cypher write uses ``coalesce`` (idempotency guard)
  5. RUNBOOK documents the migration (when/how/verify/idempotency)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
DOCS = REPO_ROOT / "docs"

# The script lives in scripts/ and imports neo4j/requests at module load;
# tests that exercise parser functions bypass the driver import by
# reading the module source directly.
BACKFILL_SCRIPT = SCRIPTS / "backfill_cve_dates_from_nvd_meta.py"


# ===========================================================================
# Fix #1 — script exists + is executable
# ===========================================================================


class TestBackfillScriptExistsAndIsExecutable:
    def test_script_exists(self):
        assert BACKFILL_SCRIPT.exists(), "scripts/backfill_cve_dates_from_nvd_meta.py must exist"

    def test_script_is_executable(self):
        """Operators run it directly — chmod +x is part of the
        deliverable, not 'python3 script.py'."""
        assert os.access(BACKFILL_SCRIPT, os.X_OK), "backfill script must be chmod +x"

    def test_script_has_shebang(self):
        content = BACKFILL_SCRIPT.read_text()
        assert content.startswith("#!/usr/bin/env python3"), "script must start with ``#!/usr/bin/env python3`` shebang"


# ===========================================================================
# Fix #2 — NVD_META parser contract
# ===========================================================================


# Dynamically load the script module so we can exercise ``parse_nvd_meta``
# + ``extract_dates`` without requiring neo4j/requests to be importable
# at test time. The ``neo4j`` + ``requests`` imports happen at module
# load; if they fail, tests still pin the source shape.
def _load_backfill_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location("backfill_cve_dates", BACKFILL_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    # Make sure the ``src/`` sibling is on the path so any downstream
    # imports (if the script grows) work.
    src_path = str(REPO_ROOT / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def backfill_module():
    """Load the script as a module. Skips tests if neo4j/requests aren't
    installed (which is unusual in this repo — both are hard deps — but
    keeps CI from failing on a minimal env)."""
    try:
        return _load_backfill_module()
    except ImportError as e:
        pytest.skip(f"backfill module imports not available: {e}")


class TestNvdMetaParser:
    """``parse_nvd_meta`` must handle:
    - Happy path (prefix + valid JSON)
    - Missing prefix (not NVD_META-tagged comment)
    - Empty / None input
    - Malformed JSON (soft-fail to empty dict, not crash)
    """

    def test_parses_valid_nvd_meta(self, backfill_module):
        meta = backfill_module.parse_nvd_meta(
            'NVD_META:{"published": "2021-12-10T10:15:09.143", "last_modified": "2024-04-03T17:02:49.887"}'
        )
        assert meta.get("published") == "2021-12-10T10:15:09.143"
        assert meta.get("last_modified") == "2024-04-03T17:02:49.887"

    def test_missing_prefix_returns_empty(self, backfill_module):
        # Old-style comments without the NVD_META prefix: not an error,
        # just no data to backfill.
        assert backfill_module.parse_nvd_meta("Log4Shell description") == {}
        assert backfill_module.parse_nvd_meta("") == {}

    def test_none_input_returns_empty(self, backfill_module):
        """Defensive: MISP comment can be None on some attribute shapes."""
        assert backfill_module.parse_nvd_meta(None) == {}

    def test_non_string_returns_empty(self, backfill_module):
        """Defensive: if MISP ever returns a structured comment, don't crash."""
        assert backfill_module.parse_nvd_meta({"some": "dict"}) == {}
        assert backfill_module.parse_nvd_meta(12345) == {}

    def test_malformed_json_returns_empty(self, backfill_module):
        """JSON corruption in the comment → skip the CVE, don't crash."""
        assert backfill_module.parse_nvd_meta("NVD_META:{not valid json") == {}
        assert backfill_module.parse_nvd_meta("NVD_META:not-json-at-all") == {}


class TestDateExtractor:
    """``extract_dates`` must normalize empty strings / missing keys to
    None so callers can use a simple ``if v is not None`` guard."""

    def test_both_fields_present(self, backfill_module):
        pub, mod = backfill_module.extract_dates({"published": "2021-12-10T10:15:09", "last_modified": "2024-04-03"})
        assert pub == "2021-12-10T10:15:09"
        assert mod == "2024-04-03"

    def test_empty_strings_normalize_to_none(self, backfill_module):
        # Empty string is what MISP stores when the field is missing
        # upstream — we must not pass "" into the Cypher SET (would
        # set the node to an empty string, not NULL).
        pub, mod = backfill_module.extract_dates({"published": "", "last_modified": ""})
        assert pub is None
        assert mod is None

    def test_missing_keys_return_none(self, backfill_module):
        pub, mod = backfill_module.extract_dates({"other_field": "value"})
        assert pub is None
        assert mod is None

    def test_one_field_present_one_missing(self, backfill_module):
        pub, mod = backfill_module.extract_dates({"published": "2021-12-10"})
        assert pub == "2021-12-10"
        assert mod is None


# ===========================================================================
# Fix #3 — Idempotency: the Cypher write uses coalesce
# ===========================================================================


class TestIdempotencyCypher:
    """The UPDATE Cypher must use ``coalesce(c.published, $published)`` so
    an already-populated value (from a post-PR-N19 baseline) is never
    overwritten by the script."""

    def test_update_cypher_uses_coalesce_for_published(self):
        src = BACKFILL_SCRIPT.read_text()
        assert "c.published = coalesce(c.published, $published)" in src, (
            "UPDATE Cypher must use ``coalesce`` on ``published`` to preserve any "
            "value already written by a post-PR-N19 baseline"
        )

    def test_update_cypher_uses_coalesce_for_last_modified(self):
        src = BACKFILL_SCRIPT.read_text()
        assert "c.last_modified = coalesce(c.last_modified, $last_modified)" in src, (
            "UPDATE Cypher must use ``coalesce`` on ``last_modified`` to preserve any "
            "value already written by a post-PR-N19 baseline"
        )

    def test_fetch_cypher_filters_to_null_candidates_only(self):
        """The fetch step must only return CVEs with at least one NULL
        date field — otherwise re-runs would reprocess everything."""
        src = BACKFILL_SCRIPT.read_text()
        assert "c.published IS NULL OR c.last_modified IS NULL" in src, (
            "fetch step must filter to candidates missing at least one date"
        )

    def test_fetch_cypher_requires_misp_attr_id(self):
        """CVEs without ``misp_attribute_ids`` can't be backfilled (no
        upstream source to read from). Must be filtered out of the
        candidate set — otherwise the script spins on them every run."""
        src = BACKFILL_SCRIPT.read_text()
        assert "size(coalesce(c.misp_attribute_ids, [])) > 0" in src, (
            "fetch step must require at least one misp_attribute_ids entry"
        )


# ===========================================================================
# Fix #4 — CLI contract
# ===========================================================================


class TestCliContract:
    """The script's CLI must expose the flags the operator runbook
    describes (``--dry-run``, ``--batch-size``, ``--rate-limit``,
    ``--max-cves``) and its exit codes must distinguish error-free
    completion from partial failure."""

    def test_dry_run_flag_exists(self):
        src = BACKFILL_SCRIPT.read_text()
        assert '"--dry-run"' in src, "script must accept --dry-run flag"

    def test_batch_size_flag_exists(self):
        src = BACKFILL_SCRIPT.read_text()
        assert '"--batch-size"' in src, "script must accept --batch-size flag"

    def test_rate_limit_flag_exists(self):
        src = BACKFILL_SCRIPT.read_text()
        assert '"--rate-limit"' in src, "script must accept --rate-limit flag"

    def test_max_cves_flag_exists(self):
        """Smoke-test convenience: cap processed count so an operator
        can verify behavior on 10 CVEs before committing to the full run."""
        src = BACKFILL_SCRIPT.read_text()
        assert '"--max-cves"' in src, "script must accept --max-cves flag"

    def test_exit_code_1_on_errors(self):
        src = BACKFILL_SCRIPT.read_text()
        # Must return 1 if any unrecoverable error; 0 on clean run.
        assert "return 1 if summary.get(" in src, "script must return exit 1 when errors > 0"


# ===========================================================================
# Fix #5 — RUNBOOK documents the migration
# ===========================================================================


class TestRunbookDocumentsBackfill:
    def _runbook(self) -> str:
        return (DOCS / "RUNBOOK.md").read_text()

    def test_runbook_has_backfill_section(self):
        rb = self._runbook()
        assert "PR-N22" in rb and "backfill" in rb.lower(), (
            "RUNBOOK must have a PR-N22 backfill section so operators can find it"
        )

    def test_runbook_shows_dry_run_first(self):
        """The operator protocol must emphasize dry-run first — a 100K-CVE
        real-run with a misconfigured env var would be painful."""
        rb = self._runbook()
        assert "--dry-run" in rb, "RUNBOOK must show --dry-run as the first step"
        dry_run_pos = rb.find("--dry-run")
        real_run_pos = rb.find("./scripts/backfill_cve_dates_from_nvd_meta.py --batch-size")
        # Dry-run must appear BEFORE the real-run command in the RUNBOOK order.
        if real_run_pos != -1:
            assert dry_run_pos < real_run_pos, "RUNBOOK must document dry-run BEFORE the real-run command"

    def test_runbook_documents_idempotency(self):
        rb = self._runbook()
        assert "idempotent" in rb.lower() or "idempotenc" in rb.lower(), (
            "RUNBOOK must explicitly state the script is idempotent so operators feel safe re-running"
        )

    def test_runbook_shows_verify_cypher(self):
        """Operators need post-migration verification queries — paste-ready
        Cypher for 'did this actually work?'"""
        rb = self._runbook()
        assert "still_null" in rb or "Verify success" in rb, (
            "RUNBOOK must include a verification Cypher block (e.g. count of still-NULL CVEs)"
        )
