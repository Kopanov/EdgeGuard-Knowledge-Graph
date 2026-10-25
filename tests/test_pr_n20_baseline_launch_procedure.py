"""
PR-N20 — 730-day baseline launch procedure + follow-ups.

After PR-N19 merged, a 3-agent readiness audit surfaced three actionable
items that needed to ship before launching the 730-day baseline:

1. **Launch-path documentation gap.** Three xfails in
   ``tests/test_tier1_sequential_robustness.py`` pin Issue #57 — the
   Airflow DAG baseline path does NOT call ``acquire_baseline_lock()``.
   Over the ~26h baseline, the 4 scheduled incremental DAGs race the
   baseline for MISP + Neo4j writes, reproducing the 2026-04-19
   MISP-PHP-FPM exhaustion + 14.7% NVD loss. ``docs/RUNBOOK.md`` didn't
   surface the workaround. Fix: add a dedicated "Baseline launch path"
   section with explicit CLI vs DAG+pause procedures.

2. **Preflight script missing.** Operators had no single command to
   verify env vars + Neo4j + MISP reachability + DAG pause state + RAM
   + alerts + sentinel cleanup + kill-switch defaults before kicking
   off the 26h run. Fix: add ``scripts/preflight_baseline.sh``.

3. **``merge_vulnerability`` single-row path symmetry gap.** PR-N19
   Fix #1 fixed the MISP-sourced CVE date-drop, but the NVD-sourced
   ``merge_vulnerability`` single-row path (used by the alert pipeline
   and ``_sync_single_item`` fallback) still dropped ``published`` /
   ``last_modified``. Same bug shape as the one PR-N19 closed for
   ``merge_cve``. Fix: symmetric promotion in ``merge_vulnerability``.

Additionally: add a MISP-retrieval-paths section to the RUNBOOK
answering the operator question "how do I use a Neo4j node to fetch
the raw MISP data?" (`n.misp_attribute_ids[]` → MISP API).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
DOCS = REPO_ROOT / "docs"
SCRIPTS = REPO_ROOT / "scripts"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n20")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n20")

from description_ranking import CVE_DESCRIPTIONS  # noqa: E402  (2026-10-16: the description's source ranking)

# ===========================================================================
# Fix #1 — RUNBOOK has the launch-path section (CLI vs DAG+pause)
# ===========================================================================


class TestFix1RunbookLaunchPath:
    def _runbook(self) -> str:
        return (DOCS / "RUNBOOK.md").read_text()

    def test_runbook_has_baseline_launch_path_section(self):
        """Pin that the CLI-vs-DAG decision is surfaced in the RUNBOOK,
        not only in docs/flow_audits/ where an operator might miss it."""
        rb = self._runbook()
        assert "Baseline launch path" in rb, (
            "RUNBOOK must surface the baseline launch-path decision (CLI vs DAG+pause). "
            "Issue #57 / docs/flow_audits/01_baseline_sequence.md Finding 1."
        )

    def test_runbook_documents_cli_launch_option(self):
        rb = self._runbook()
        section = rb.split("#### What about the CLI commands?", 1)[1].split("\n---", 1)[0]
        # The CLI wrappers trigger the baseline DAG (which holds the lock);
        # the legacy in-process path takes the in-process baseline_lock, and
        # every scheduled DAG then self-skips via baseline_skip_reason().
        assert "edgeguard baseline --days N" in section and "edgeguard fresh-baseline" in section, (
            "RUNBOOK must document the CLI launch commands"
        )
        assert "trigger" in section and "`edgeguard_baseline` DAG" in section, (
            "RUNBOOK must say that the CLI wrappers trigger the edgeguard_baseline DAG"
        )
        assert "python src/run_pipeline.py --baseline" in section, (
            "RUNBOOK must name the legacy in-process path that takes the in-process baseline_lock"
        )

    def test_runbook_documents_dag_pause_option(self):
        rb = self._runbook()
        # DAG path requires pre-pausing 4 incremental DAGs for the ~26h window.
        for dag in [
            "edgeguard_daily",
            "edgeguard_medium_freq",
            "edgeguard_pipeline",
            "edgeguard_low_freq",
        ]:
            assert dag in rb, f"RUNBOOK must name {dag} in the DAG-pause procedure"
        assert "airflow dags pause" in rb, "RUNBOOK must show the `airflow dags pause` command"
        assert "airflow dags unpause" in rb, "RUNBOOK must show how to restore after baseline completes"

    def test_runbook_explains_the_root_cause_of_the_launch_path_constraint(self):
        rb = self._runbook()
        section = rb.split("### ⚠️ Baseline launch path", 1)[1].split("\n#### ", 1)[0]
        # The root cause, so ops readers understand why the scheduled DAGs must not write during a baseline.
        assert "concurrent writers exhaust MISP's PHP-FPM workers" in section, (
            "RUNBOOK must explain the root cause of the launch-path constraint"
        )

    def test_runbook_references_preflight_script(self):
        rb = self._runbook()
        assert "preflight_baseline.sh" in rb, (
            "RUNBOOK must reference the preflight script so operators know there's a one-shot check"
        )


# ===========================================================================
# Fix #2 — preflight_baseline.sh exists + has the expected check matrix
# ===========================================================================


class TestFix2PreflightScript:
    def _script(self) -> str:
        return (SCRIPTS / "preflight_baseline.sh").read_text()

    def test_preflight_script_exists(self):
        path = SCRIPTS / "preflight_baseline.sh"
        assert path.exists(), "scripts/preflight_baseline.sh must exist"
        # Must be executable — operators run it directly.
        assert os.access(path, os.X_OK), "preflight_baseline.sh must be executable (chmod +x)"

    def test_preflight_covers_required_env_vars(self):
        src = self._script()
        for var in ["NEO4J_PASSWORD", "MISP_API_KEY", "MISP_URL"]:
            assert var in src, f"preflight must check that {var} is set"

    def test_preflight_checks_neo4j_reachability(self):
        src = self._script()
        assert "Neo4j" in src and ("cypher-shell" in src or "bolt://" in src), (
            "preflight must verify Neo4j is reachable"
        )

    def test_preflight_checks_misp_reachability(self):
        src = self._script()
        assert ("/servers/getVersion" in src or "MISP" in src) and "curl" in src, (
            "preflight must hit a MISP API endpoint to verify auth works"
        )

    def test_preflight_checks_dag_pause_on_dag_launch_path(self):
        src = self._script()
        # The DAG path is the one that NEEDS the pause-check. Confirm the
        # script knows how to verify each of the 4 incrementals.
        for dag in [
            "edgeguard_daily",
            "edgeguard_medium_freq",
            "edgeguard_pipeline",
            "edgeguard_low_freq",
        ]:
            assert dag in src, f"preflight must verify {dag} pause-state on --launch-path=dag"

    def test_preflight_checks_prometheus_alerts(self):
        src = self._script()
        assert "promtool" in src or "alerts.yml" in src, (
            "preflight must verify Prometheus alert rules parse (promtool check rules)"
        )

    def test_preflight_exits_nonzero_on_failure(self):
        src = self._script()
        assert "exit 1" in src, "preflight must exit 1 when any hard-fail check fails"
        assert "exit 0" in src, "preflight must exit 0 on all-green"

    def test_preflight_env_var_loop_reports_value_length_not_name_length(self):
        """Bugbot round 1 (PR #104, Medium severity): the env-var loop used
        ``${#var}`` which measures the length of the variable NAME
        ("NEO4J_PASSWORD" = 14 chars), not the indirectly-referenced VALUE.
        The printed copy said "value not echoed" so the reported count
        had to correspond to the value; a 40-char API key printed "12
        chars" misleading operators about credential state.

        Pin: the env-var loop MUST (a) capture the indirect value into a
        local like ``var_value="${!var:-}"``, and (b) measure
        ``${#var_value}``. Regression-guard against a literal ``${#var}``
        re-appearing inside that loop."""
        src = self._script()
        # Isolate the env-var loop so we don't false-fail on similar
        # constructs elsewhere in the script (if any are added later).
        # Rough anchor: the loop starts after the "[1] required env vars" header.
        loop_start = src.find("for var in NEO4J_PASSWORD MISP_API_KEY MISP_URL")
        assert loop_start != -1, "env-var loop anchor missing"
        loop_end = src.find("done", loop_start)
        assert loop_end != -1, "env-var loop terminator missing"
        loop_body = src[loop_start:loop_end]

        # Positive: the loop must capture the indirect reference into a
        # local variable (any name is fine as long as it's used below).
        assert '"${!var' in loop_body, (
            'env-var loop must capture the indirect reference (``"${!var..}"``) into a local before measuring length'
        )
        # Negative: ``${#var}`` (measuring the name) must NOT appear inside
        # the loop body. This is the exact Bugbot-flagged regression shape.
        assert "${#var}" not in loop_body, (
            "env-var loop reports ${#var} (length of NAME, always 8/12/14) instead of the VALUE length. "
            'Capture ``var_value="${!var:-}"`` first, then measure ``${#var_value}``. '
            "Bugbot round 1, PR #104, Medium severity."
        )
        # Positive: the correct form (value-length) must appear.
        assert "${#var_value}" in loop_body or "${#value}" in loop_body, (
            "env-var loop must report the VALUE length (e.g. ``${#var_value}``) after capturing the indirect reference"
        )

    def test_preflight_does_not_embed_neo4j_password_in_command_line(self):
        """Bugbot round 2 (PR #104, Low severity): NEO4J_PASSWORD was
        interpolated directly into ``NEO4J_CMD`` (`-p ${NEO4J_PASSWORD:-test}`).
        Visible to any user on the host via ``ps aux`` or
        ``/proc/*/cmdline``, and risks word-splitting on spaces/metachars.

        Fix: build NEO4J_CMD as a bash array without ``-p``. For docker
        path use ``-e NEO4J_PASSWORD`` (by name, no =value) to forward the
        env var; for host path cypher-shell reads NEO4J_PASSWORD from env.

        Pin the absence of the regression shape."""
        src = self._script()
        # Negative: the exact regression shape (``-p`` followed by an
        # interpolation of NEO4J_PASSWORD into the command string) must
        # NOT appear.
        assert "-p ${NEO4J_PASSWORD" not in src, (
            "cypher-shell invocation must NOT interpolate NEO4J_PASSWORD into argv "
            "(use ``-e NEO4J_PASSWORD`` + no ``-p`` flag; cypher-shell reads NEO4J_PASSWORD "
            "from env automatically). Bugbot round 2, PR #104, Low severity."
        )
        assert '-p "$NEO4J_PASSWORD' not in src, (
            "cypher-shell invocation must NOT take the password as a command-line argument — "
            "use the NEO4J_PASSWORD env var forwarding instead"
        )
        # Positive: the new array-based invocation must use -e NEO4J_PASSWORD
        # (env-var forwarding) for the docker path.
        assert "-e NEO4J_PASSWORD" in src, (
            "preflight must forward NEO4J_PASSWORD via ``docker compose exec -e NEO4J_PASSWORD`` "
            "(by name, not by value) to keep it out of argv"
        )

    def test_preflight_honors_ssl_verify_for_misp_probe(self):
        """Bugbot round 2 (PR #104, Medium severity): the MISP probe used
        ``curl -k`` unconditionally, sending MISP_API_KEY over an
        unverified TLS connection even when EDGEGUARD_SSL_VERIFY=true was
        set project-wide. MitM risk for credential interception.

        Fix: read EDGEGUARD_SSL_VERIFY / SSL_VERIFY by the project rule
        (``src/tls_verify.py``; fail-closed since 2026-10-23, behaviour in
        ``tests/test_ssl_verify_setting.py``), and only add ``-k`` when
        verification is off."""
        src = self._script()
        # Positive: script must reference the canonical env var.
        assert "EDGEGUARD_SSL_VERIFY" in src, (
            "preflight must honor EDGEGUARD_SSL_VERIFY for the MISP probe (project canonical TLS-verify knob)"
        )
        # Positive: must also fall back to the legacy SSL_VERIFY name
        # (matches src/config.py semantics).
        assert "SSL_VERIFY" in src, "preflight must also respect the legacy SSL_VERIFY fallback"
        # Positive: should only pass -k conditionally (not as a fixed
        # curl arg). The fix uses a bash array CURL_TLS_FLAG that's
        # empty when verification is enabled.
        assert "CURL_TLS_FLAG" in src, (
            "preflight must build a conditional TLS flag array (e.g. CURL_TLS_FLAG) "
            "that stays empty when verification is enabled"
        )
        # Negative: the exact regression shape — curl -k as a hard-coded
        # argument in the MISP probe — must NOT appear.
        assert "curl -k -s -o" not in src, (
            "preflight must NOT hard-code ``curl -k`` in the MISP probe — that would send "
            "MISP_API_KEY over unverified TLS regardless of EDGEGUARD_SSL_VERIFY. "
            "Bugbot round 2, PR #104, Medium severity."
        )

    def test_preflight_tls_flag_is_bash3_2_compatible(self):
        """Bugbot round 3 (PR #104, Low severity): the earlier round-2
        fix used a bash array ``CURL_TLS_FLAG=()`` expanded as
        ``"${CURL_TLS_FLAG[@]}"``. Under bash < 4.4 with ``set -u``
        active, an EMPTY-array expansion raises "unbound variable"
        and aborts the script. This affects macOS's default bash 3.2
        — a common operator workstation — on the RECOMMENDED
        production path (``EDGEGUARD_SSL_VERIFY=true``).

        Fix: plain string ``CURL_TLS_FLAG_STR`` (always set; empty
        string when verification enabled) expanded UNQUOTED so empty
        → nothing in argv. Safe across bash 3.2+.

        Pin: (a) no empty-array regression shape present,
        (b) the plain-string variant IS present."""
        src = self._script()
        # Strip comment-only lines so the rationale comment (which
        # describes the regression shape) doesn't false-fail the
        # negative assertion.
        code_only = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        # Negative: the empty-array pattern ``CURL_TLS_FLAG=()`` must
        # NOT appear in actual code.
        assert "CURL_TLS_FLAG=()" not in code_only, (
            "empty-array ``CURL_TLS_FLAG=()`` is the Bugbot round 3 regression shape "
            "(crashes bash < 4.4 under set -u when expanded)"
        )
        # Also negative: the array expansion ``"${CURL_TLS_FLAG[@]}"``
        # must not appear in code (same class of bug).
        assert '"${CURL_TLS_FLAG[@]}"' not in code_only, (
            "array expansion ``${CURL_TLS_FLAG[@]}`` on a possibly-empty array is unsafe under set -u in bash < 4.4"
        )
        # Positive: the string-variant must be present and USED in code.
        assert "CURL_TLS_FLAG_STR" in code_only, (
            "fix uses a plain string ``CURL_TLS_FLAG_STR`` (always set) that's safe to expand unquoted across bash 3.2+"
        )


# ===========================================================================
# Fix #3 — merge_vulnerability promotes published + last_modified (symmetry
# with post-PR-N19 merge_cve)
# ===========================================================================


class TestFix3MergeVulnerabilitySymmetry:
    """2026-10: as on ``merge_cve``, NVD's record sets the dates (``extra_props``) and any other
    record fills them where the node has none (``fill_props``); the description goes with its source
    and rank to the source ranking (``description``, 2026-10-16)."""

    @staticmethod
    def _merge(data: dict, source_id: str = "nvd") -> dict:
        from neo4j_client import Neo4jClient

        c = Neo4jClient.__new__(Neo4jClient)
        c.driver = MagicMock()
        c.merge_node_with_source = MagicMock(return_value=True)
        assert c.merge_vulnerability(data, source_id=source_id) is True
        return c.merge_node_with_source.call_args.kwargs

    _DATA = {
        "cve_id": "CVE-2024-12345",
        "description": "Symmetry test",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "published": "2024-02-14T12:00:00.000",
        "last_modified": "2024-03-01T08:30:00.000",
    }

    def test_merge_vulnerability_nvd_record_sets_published_and_last_modified(self):
        """Behavioral pin: NVD's record passes both dates to extra_props (same shape as merge_cve)."""
        kwargs = self._merge({**self._DATA, "nvd_record": True})
        extra_props = kwargs.get("extra_props") or {}
        assert extra_props.get("published") == "2024-02-14T12:00:00.000", (
            f"merge_vulnerability must pass NVD's published to extra_props; got {extra_props.get('published')!r}"
        )
        assert extra_props.get("last_modified") == "2024-03-01T08:30:00.000"
        assert "description" not in extra_props
        assert kwargs["description"] == CVE_DESCRIPTIONS.record("Symmetry test", "nvd")
        assert not kwargs.get("fill_props")

    def test_merge_vulnerability_other_record_fills_published_and_last_modified(self):
        kwargs = self._merge(dict(self._DATA), source_id="cisa_kev")
        assert kwargs["fill_props"] == {
            "published": "2024-02-14T12:00:00.000",
            "last_modified": "2024-03-01T08:30:00.000",
        }
        assert kwargs["description"] == CVE_DESCRIPTIONS.record("Symmetry test", "cisa_kev")
        assert (kwargs.get("extra_props") or {}).get("cvss_score") == 7.5


# ===========================================================================
# Fix #4 — RUNBOOK documents how to retrieve raw MISP data from a Neo4j node
# ===========================================================================


class TestFix4RunbookMispRetrievalPaths:
    def _runbook(self) -> str:
        return (DOCS / "RUNBOOK.md").read_text()

    def test_runbook_documents_misp_retrieval_section(self):
        rb = self._runbook()
        assert "Retrieving raw MISP data from a Neo4j node" in rb, (
            "RUNBOOK must document the three MISP-retrieval paths (attribute UUID, event ID, raw JSON on edge)"
        )

    def test_runbook_clarifies_node_uuid_is_not_misp_link(self):
        """The user's audit question conflated n.uuid (deterministic UUIDv5
        for cross-environment identity) with the MISP back-pointer
        (misp_attribute_ids[]). Pin the clarifying paragraph."""
        rb = self._runbook()
        assert "n.uuid" in rb and "deterministic" in rb.lower() and "NOT" in rb, (
            "RUNBOOK must clarify that n.uuid is a deterministic UUIDv5 for cross-env identity, "
            "NOT a foreign key into MISP"
        )

    def test_runbook_documents_all_three_retrieval_paths(self):
        rb = self._runbook()
        assert "misp_attribute_ids" in rb, "Path 1 — MISP attribute UUID"
        assert "misp_event_ids" in rb, "Path 2 — MISP event ID"
        assert "SOURCED_FROM" in rb and "raw_data" in rb, "Path 3 — raw JSON on SOURCED_FROM edge"

    def test_runbook_documents_misp_api_fetch_shape(self):
        rb = self._runbook()
        # Operator needs to know the HTTP endpoint + header shape.
        assert "/attributes/" in rb, "RUNBOOK must show the MISP /attributes/<uuid> endpoint"
        assert "/events/" in rb, "RUNBOOK must show the MISP /events/<id> endpoint"
        assert "Authorization" in rb, "RUNBOOK must show the Authorization header for MISP API"


# ===========================================================================
# Fix #5 — README.md surfaces the launch procedure for colleagues
# ===========================================================================


class TestFix5ReadmeLaunchProcedure:
    """Colleagues new to the project read the README first, not RUNBOOK.
    Pin that the baseline-launch options + the MISP retrieval paths live
    at the README level so they can't get lost in deep docs."""

    def _readme(self) -> str:
        return (REPO_ROOT / "README.md").read_text()

    def test_readme_has_baseline_launch_section(self):
        rd = self._readme()
        assert "Running the 730-day baseline" in rd, (
            "README must have a top-level 'Running the 730-day baseline' section "
            "so colleagues see the launch-path decision without hunting through docs/"
        )

    def test_readme_documents_cli_and_dag_options(self):
        """PR-J1 docs audit (2026-04-28): the original PR-N20 test pinned
        ``Option A`` + ``Option B`` + ``python -m edgeguard baseline`` —
        but the CLI baseline subcommand NEVER EXISTED in
        ``src/edgeguard.py`` (verified by ``grep "add_parser"``). PR-J1
        fixed the README to document the DAG-only launch path. Test
        updated to match: README must document the DAG launch path with
        ``airflow dags pause`` (defense-in-depth) followed by
        ``airflow dags trigger edgeguard_baseline``. The CLI subcommand
        pin is dropped (it never matched code reality at HEAD)."""
        rd = self._readme()
        assert "airflow dags pause" in rd, "README must show the DAG pause command"
        assert "airflow dags trigger edgeguard_baseline" in rd, (
            "README must show the DAG trigger command (the canonical baseline launch path)"
        )

    def test_readme_references_preflight_script(self):
        rd = self._readme()
        assert "preflight_baseline.sh" in rd, (
            "README must point to scripts/preflight_baseline.sh as the pre-kickoff check"
        )

    def test_readme_explains_the_launch_path_rationale(self):
        """The 'why' matters as much as the 'what': the README explains the
        baseline lock (the mutex the ``edgeguard_baseline`` DAG holds for the
        whole run and the scheduled DAGs honour) and why pausing the
        scheduled DAGs is still recommended before a destructive
        ``fresh-baseline``, so colleagues can make the right launch-path
        choice."""
        rd = self._readme()
        section = rd.split("### How the baseline lock protects the run", 1)[1].split("\n### ", 1)[0]
        assert "baseline_acquire_lock" in section and "baseline_release_lock" in section, (
            "README must explain that the baseline DAG acquires and releases the baseline lock itself"
        )
        assert "checkpoints/baseline_in_progress.lock" in section, "README must name the lock sentinel"
        assert "reason `baseline_in_progress`" in section, (
            "README must explain that the scheduled DAGs skip while the baseline holds the lock"
        )
        # 2026-10-25: pausing does not stop a task that is already running (the lock is read when a task
        # starts); the README said such a task "completes its current write", as if pausing covered it.
        assert "keeps running to its end" in section and "has a running run" in section, (
            "README must explain why pausing is recommended before a fresh-baseline and what it does not stop"
        )
        assert "completes its current write" not in section

    def test_readme_documents_misp_retrieval_paths(self):
        rd = self._readme()
        assert "misp_attribute_ids" in rd, "README must show Path 1 (attribute UUID)"
        assert "misp_event_ids" in rd, "README must show Path 2 (event ID)"
        assert "SOURCED_FROM" in rd and "raw_data" in rd, "README must show Path 3 (raw JSON on edge)"

    def test_readme_clarifies_node_uuid_is_not_misp_link(self):
        """The user's original question conflated n.uuid with the MISP
        back-pointer. Pin the clarifying note at the README level."""
        rd = self._readme()
        assert "`n.uuid` is not a MISP key: it is a deterministic UUIDv5" in rd, (
            "README must clarify n.uuid is a deterministic UUIDv5 for cross-env identity, NOT a foreign key into MISP"
        )

    def test_quick_start_points_to_the_baseline_procedure(self):
        """The Quick start must point readers at the baseline procedure
        before they hit the `airflow dags trigger edgeguard_baseline`
        button: its last step links the section by its anchor."""
        rd = self._readme()
        assert "\n## Running the 730-day baseline\n" in rd, "README must keep the baseline section heading"
        quick_start = rd.split("\n## Quick start\n", 1)[1].split("\n## ", 1)[0]
        assert "(#running-the-730-day-baseline)" in quick_start, (
            "The Quick start must link the baseline procedure before readers trigger the baseline"
        )


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_neo4j_client_imports(self):
        import neo4j_client  # noqa: F401
