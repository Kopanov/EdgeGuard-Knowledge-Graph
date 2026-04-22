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
# Bugbot round 1 (PR #106) — 4 legit findings must stay closed
# ===========================================================================


class TestBugbotRound1Fixes:
    """Bugbot caught 4 real bugs on the first-pass PR-N22 commit:
    - HIGH:   dry-run infinite loop (no writes → same batch re-fetched)
    - HIGH:   normal-mode infinite loop on unresolvable CVEs
    - HIGH:   SSL verify defaulted to INSECURE when env unset
    - MEDIUM: urllib3 disable_warnings unconditional
    """

    def _src(self) -> str:
        return BACKFILL_SCRIPT.read_text()

    def test_fetch_uses_cursor_pagination(self):
        """HIGH × 2: both infinite-loop modes (--dry-run + unresolvable
        CVEs) are caused by the WHERE filter never changing for failed
        attempts. Fix: cursor-based pagination via
        ``c.cve_id > $last_cve_id ORDER BY c.cve_id LIMIT $batch_size``.
        Every fetch returns the NEXT batch regardless of write success."""
        src = self._src()
        assert "c.cve_id > $last_cve_id" in src, (
            "fetch query must use cursor pagination (c.cve_id > $last_cve_id) — "
            "without this, dry-run AND unresolvable-CVE normal-mode runs infinite-loop"
        )
        assert "ORDER BY c.cve_id" in src, "cursor pagination requires deterministic ordering by cve_id"

    def test_backfill_driver_advances_cursor(self):
        """The Python-side driver must advance ``last_cve_id`` to the
        LAST cve_id in the returned batch so the next iteration fetches
        past it. Regression pin against someone "simplifying" the driver
        back to the no-cursor loop."""
        src = self._src()
        # The assignment pattern we need to see inside backfill()
        assert 'last_cve_id = candidates[-1]["cve_id"]' in src or 'last_cve_id = candidates[-1]["cve_id"]' in src, (
            "backfill driver must advance last_cve_id to candidates[-1]['cve_id'] after each batch"
        )

    def test_ssl_verify_defaults_to_secure(self):
        """HIGH: pre-fix ``_ssl_verify_enabled`` returned False when env
        var was unset. Project convention (src/config.py:434) defaults
        to True (secure). Mirror the config.py function exactly."""
        src = self._src()
        # The implementation must have an explicit ``return True`` fall-through
        # (the "neither env set" case). Anchor on the function body.
        start = src.find("def _ssl_verify_enabled")
        end = src.find("\ndef ", start + 1)
        body = src[start:end]
        assert "return True" in body, (
            "_ssl_verify_enabled must default to True (secure) when env vars unset — "
            "matching src/config.py:edgeguard_ssl_verify_from_env"
        )
        # Must iterate both env var names (canonical + fallback), matching
        # the config.py precedence.
        assert '"EDGEGUARD_SSL_VERIFY"' in body and '"SSL_VERIFY"' in body, (
            "_ssl_verify_enabled must check both EDGEGUARD_SSL_VERIFY (canonical) "
            "and SSL_VERIFY (fallback) in that order"
        )

    def test_urllib3_disable_warnings_guarded_by_ssl_verify(self):
        """MEDIUM: urllib3.disable_warnings was called UNCONDITIONALLY at
        module load. Other EdgeGuard files gate this behind
        ``if not SSL_VERIFY:`` so the warning stays visible when TLS IS
        being verified (then it's a real signal). Pin via AST — only
        look at actual ``Expr(Call(urllib3.disable_warnings))`` nodes
        at module top-level, not at docstring/comment mentions."""
        import ast

        tree = ast.parse(self._src())
        # Find top-level ``Expr`` statements whose value is a Call to
        # ``urllib3.disable_warnings``. If any exists at module level
        # (NOT inside an ``If``), the guard is missing.
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                func = node.value.func
                if isinstance(func, ast.Attribute) and func.attr == "disable_warnings":
                    raise AssertionError(
                        "urllib3.disable_warnings called at module top-level without an ``if not "
                        "_ssl_verify_enabled()`` guard. This was Bugbot round 1 MEDIUM — "
                        "unconditional suppression hides real TLS-misconfig warnings."
                    )
        # Positive: the guarded call must exist somewhere. Walk all Ifs
        # at module level and confirm at least one has a disable_warnings
        # call in its body.
        found_guarded = False
        for node in tree.body:
            if isinstance(node, ast.If):
                # The test condition should reference _ssl_verify_enabled
                test_src = ast.unparse(node.test)
                if "_ssl_verify_enabled" not in test_src:
                    continue
                for stmt in node.body:
                    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                        fn = stmt.value.func
                        if isinstance(fn, ast.Attribute) and fn.attr == "disable_warnings":
                            found_guarded = True
                            break
        assert found_guarded, "urllib3.disable_warnings must be inside an ``if not _ssl_verify_enabled():`` block"


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


# ===========================================================================
# Bugbot round 2 (PR #106) — 4 new findings addressed
# ===========================================================================


class TestBugbotRound2Fixes:
    """Bugbot's re-review of the round-1 fix commit flagged 4 new real bugs:
    - MEDIUM: --max-cves cap not enforced within a batch
    - LOW: progress rate uses wrong time reference
    - MEDIUM: Neo4j username hardcoded, ignores NEO4J_USER
    - MEDIUM: parse_nvd_meta can return non-dict, crashing extract_dates
    """

    def _src(self) -> str:
        return BACKFILL_SCRIPT.read_text()

    def test_max_cves_enforced_within_batch(self):
        """MEDIUM: pre-fix the max_cves check only fired at the TOP of the
        while-loop. With ``--max-cves=10`` and ``--batch-size=100`` the
        first batch would process all 100 before the check — defeating
        the smoke-test cap."""
        src = self._src()
        # The fix adds a second max_cves check inside the for-loop.
        # Count ``max_cves is not None`` occurrences in backfill() — must
        # be at least 2 (outer while + inner for).
        body = src[src.find("def backfill") : src.find("\ndef ", src.find("def backfill") + 5)]
        check_count = body.count("max_cves is not None and summary[")
        assert check_count >= 2, (
            f"max_cves must be checked BOTH at the while-loop top AND inside the for-loop; "
            f"found only {check_count} checks (need >= 2 for per-iteration enforcement)"
        )

    def test_progress_rate_uses_run_started_at(self):
        """LOW: the pre-fix progress log divided by ``time.monotonic() -
        last_fetch_at`` where last_fetch_at was ~ms ago, producing absurd
        rates like "40000 CVE/s". Fix uses ``run_started_at`` (captured
        once before the loop)."""
        src = self._src()
        assert "run_started_at = time.monotonic()" in src, (
            "backfill() must capture run_started_at before the loop for accurate rate calculation"
        )
        # Negative: the pre-fix denominator pattern must NOT appear.
        assert 'summary["processed"] / max(time.monotonic() - last_fetch_at' not in src, (
            "pre-fix rate calculation (time since last_fetch_at) is the Bugbot round 2 regression shape"
        )
        # Positive: the progress log must use run_started_at-based denominator.
        assert "time.monotonic() - run_started_at" in src, (
            "progress log must compute elapsed from run_started_at, not last_fetch_at"
        )

    def test_neo4j_user_from_env_not_hardcoded(self):
        """MEDIUM: pre-fix used ``auth=("neo4j", neo4j_password)`` — hardcoded
        the username. Must read ``NEO4J_USER`` env var (default "neo4j")
        matching src/config.py convention."""
        src = self._src()
        # Negative: hardcoded literal must NOT appear.
        assert 'auth=("neo4j", neo4j_password)' not in src, (
            'hardcoded ``auth=("neo4j", neo4j_password)`` ignores NEO4J_USER env var. '
            "Bugbot round 2, PR #106, Medium severity."
        )
        # Positive: must read NEO4J_USER env + use it in auth.
        assert '"NEO4J_USER"' in src or "'NEO4J_USER'" in src, (
            "script must read NEO4J_USER env var (default 'neo4j') like src/config.py"
        )
        assert "auth=(neo4j_user, neo4j_password)" in src, (
            "Neo4j driver must be constructed with (neo4j_user, neo4j_password)"
        )

    def test_parse_nvd_meta_rejects_non_dict(self):
        """MEDIUM: pre-fix ``parse_nvd_meta`` returned ``json.loads(...)``
        directly — could yield list/string/int/bool. A truthy non-dict
        would pass the ``if not nvd_meta:`` guard, then extract_dates
        would call ``.get()`` on it and raise AttributeError OUTSIDE
        the per-CVE try/except, crashing the entire backfill."""
        src = self._src()
        # Positive: the fix must narrow to dict with an isinstance check.
        assert "isinstance(parsed, dict)" in src or "isinstance(nvd_meta, dict)" in src, (
            "parse_nvd_meta must narrow return type to dict — json.loads can yield any JSON type"
        )

    def test_parse_nvd_meta_behavior_non_dict_inputs(self):
        """Behavioral pin for Bugbot round 2 parse_nvd_meta fix."""
        backfill_module = _load_backfill_module()
        # List payload → {} (not [1,2,3])
        assert backfill_module.parse_nvd_meta("NVD_META:[1,2,3]") == {}
        # String payload → {}
        assert backfill_module.parse_nvd_meta('NVD_META:"just a string"') == {}
        # Integer payload → {}
        assert backfill_module.parse_nvd_meta("NVD_META:42") == {}
        # Boolean payload → {}
        assert backfill_module.parse_nvd_meta("NVD_META:true") == {}
        # Dict payload → passes through
        result = backfill_module.parse_nvd_meta('NVD_META:{"published":"2021-01-01"}')
        assert result == {"published": "2021-01-01"}
