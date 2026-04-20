"""
Regression tests for PR-F9 — six quick-win fixes from the 2026-04-20
comprehensive multi-agent audit.

Each fix is a small (<1h) change that closes a real finding:

  1. **GraphQL ``tools`` limit cap** (Red Team HIGH) — ``tools`` resolver
     lacked the ``_MAX_GRAPHQL_LIMIT=500`` cap every other resolver
     applies; ``tools(limit: 99999999)`` was a trivial DoS.
  2. **Backup-gate docstring 24h → 240h** (Cross-Checker HIGH) — the
     ``_check_recent_backup_timestamp`` docstring was stale; actual
     default has been 240h (10 days) since PR-F2 round-3.
  3. **AIRFLOW_DAGS.md UNIQUE-constraint table** (Cross-Checker HIGH) —
     the table claimed ``+ source`` on 5 labels; actual constraints
     dedup by natural key only (source lives on the SOURCED_FROM edge).
  4. **Dead placeholder DAG functions deleted** (Maintainer MED) —
     ``run_energy_placeholder`` / ``run_healthcare_placeholder`` were
     no-op stubs never wired into any task, but documented as if they
     were features.
  5. **``curl --netrc-file`` replacement** (Red Team HIGH) — Neo4j
     password leaked into ``/proc/<pid>/cmdline`` + ``ps auxw`` via
     ``curl -u user:$PWD`` in DAG quality check + check_progress.sh.
  6. **Airflow 3.x command + `.gitignore` cache hygiene** (Cross-Checker
     LOW) — the AIRFLOW_DAGS.md Manual Run section showed the
     Airflow-2.x ``airflow webserver -p 8080`` command; `.mypy_cache/`
     and `.ruff_cache/` weren't gitignored.

Each fix is pinned here against future regression.
"""

from __future__ import annotations

import sys

sys.path.insert(0, "src")


# ===========================================================================
# Fix 1: GraphQL `tools` resolver limit cap
# ===========================================================================


class TestGraphQLToolsLimitCap:
    """The ``tools`` resolver MUST apply the same ``_MAX_GRAPHQL_LIMIT``
    cap every other resolver uses. Red Team audit found this as a
    trivial DoS on the public GraphQL surface."""

    def test_tools_resolver_uses_max_graphql_limit_cap(self):
        """Source-pin: the ``tools`` resolver's ``params`` dict MUST
        build ``limit`` via ``min(..., _MAX_GRAPHQL_LIMIT)`` — matching
        the pattern used by vulnerabilities / malwares / actors."""
        with open("src/graphql_api.py") as fh:
            src = fh.read()
        # Find the tools resolver body
        idx = src.find("def tools(")
        assert idx > 0
        # Function body ends at the next ``@strawberry.field`` or ``def`` block
        end = src.find("\n    @strawberry.field", idx + 1)
        if end < 0:
            end = src.find("\n    def ", idx + 1)
        body = src[idx:end]

        # Must clamp the limit via _MAX_GRAPHQL_LIMIT (same pattern as
        # siblings at graphql_api.py:271, 328, 400)
        assert "_MAX_GRAPHQL_LIMIT" in body, (
            "tools resolver must reference _MAX_GRAPHQL_LIMIT (Red Team HIGH: trivial DoS)"
        )
        assert "min(" in body and "limit" in body, (
            "tools resolver must clamp the limit via ``min(..., _MAX_GRAPHQL_LIMIT)``"
        )


# ===========================================================================
# Fix 2: Backup-gate docstring 24h → 240h
# ===========================================================================


class TestBackupGateDocstring:
    """The ``_check_recent_backup_timestamp`` docstring must match the
    actual default (240h / 10 days since PR-F2 round-3)."""

    def test_docstring_says_240h_not_24h(self):
        with open("src/edgeguard.py") as fh:
            src = fh.read()
        idx = src.find("def _check_recent_backup_timestamp(")
        assert idx > 0
        # Find the docstring after the signature line
        docstring_start = src.find('"""', idx)
        docstring_end = src.find('"""', docstring_start + 3)
        docstring = src[docstring_start:docstring_end]
        # The docstring MUST mention 240h (or the 10-day equivalent);
        # MUST NOT say default 24h (the pre-PR-F2 value).
        assert "240h" in docstring or "10 days" in docstring, "docstring must mention the 240h / 10-day default"
        # Defensive: reject the stale "default 24h" phrasing
        assert "default 24h" not in docstring, (
            "docstring must not advertise the pre-PR-F2 24h default "
            "(the actual code default is 240h — see `EDGEGUARD_BACKUP_MAX_AGE_HOURS` in _check_recent_backup_timestamp)"
        )

    def test_inline_comment_in_cmd_fresh_baseline_matches_docstring(self):
        """The comment block in ``cmd_fresh_baseline`` that explains the
        backup gate must also reference the current default, not the
        pre-F2 value."""
        with open("src/edgeguard.py") as fh:
            src = fh.read()
        idx = src.find("def cmd_fresh_baseline(")
        assert idx > 0
        end = src.find("\ndef ", idx + 1)
        body = src[idx:end]
        # The comment shouldn't claim "The 24h window is a default" anymore
        assert "The 24h window is a default" not in body, (
            "cmd_fresh_baseline comment must not claim 24h default — the actual default is 240h since PR-F2"
        )


# ===========================================================================
# Fix 3: AIRFLOW_DAGS.md UNIQUE-constraint table
# ===========================================================================


class TestAirflowDagsUniqueConstraintTable:
    """The AIRFLOW_DAGS.md Deduplication table must reflect the actual
    Neo4j constraints — source/provenance lives on the SOURCED_FROM
    edge, NOT in the node key."""

    def test_table_does_not_claim_source_is_part_of_unique_key(self):
        with open("docs/AIRFLOW_DAGS.md") as fh:
            content = fh.read()
        # Grab the Deduplication section (up to the next ## header)
        dedup_idx = content.find("### Deduplication")
        assert dedup_idx > 0, "Deduplication section missing"
        section_end = content.find("\n## ", dedup_idx + 1)
        if section_end < 0:
            section_end = len(content)
        section = content[dedup_idx:section_end]

        # The old wrong pattern: e.g., ``Indicator`: value + source``
        wrong_patterns = [
            "`Indicator`: value + source",
            "`Vulnerability`: cve_id + source",
            "`ThreatActor`: name + source",
            "`Technique`: mitre_id + source",
            "`Malware`: name + source",
        ]
        for pattern in wrong_patterns:
            assert pattern not in section, (
                f"Deduplication section still claims source is part of the unique key: {pattern!r}. "
                "Actual constraints (src/neo4j_client.py:749-792) dedup by natural key only; "
                "source lives on the SOURCED_FROM edge."
            )

    def test_table_describes_natural_key_only_dedup(self):
        with open("docs/AIRFLOW_DAGS.md") as fh:
            content = fh.read()
        dedup_idx = content.find("### Deduplication")
        assert dedup_idx > 0
        section_end = content.find("\n## ", dedup_idx + 1)
        section = content[dedup_idx:section_end]
        # The fix: doc must reference the source-truthful architecture
        # so readers understand why source ISN'T in the key
        assert "SOURCED_FROM" in section, (
            "Deduplication section must explain that source/provenance lives on the SOURCED_FROM edge"
        )


# ===========================================================================
# Fix 4: Dead placeholder DAG functions
# ===========================================================================


class TestDeadPlaceholdersRemoved:
    """``run_energy_placeholder`` and ``run_healthcare_placeholder`` were
    deleted — they returned ``{"count": 0}``, were never wired into any
    PythonOperator task, and were never imported elsewhere."""

    def test_placeholder_functions_removed(self):
        with open("dags/edgeguard_pipeline.py") as fh:
            src = fh.read()
        assert "def run_energy_placeholder(" not in src, (
            "run_energy_placeholder was deleted in PR-F9 — no-op stub with no callers"
        )
        assert "def run_healthcare_placeholder(" not in src, (
            "run_healthcare_placeholder was deleted in PR-F9 — no-op stub with no callers"
        )


# ===========================================================================
# Fix 5: curl --netrc-file replacement
# ===========================================================================


class TestCurlNetrcReplacement:
    """Neo4j password must NOT appear in ``curl -u user:$PWD`` form
    anywhere (would leak into ``/proc/<pid>/cmdline``). Use
    ``--netrc-file`` with a 0600 file + trap cleanup instead."""

    def test_dag_quality_check_uses_netrc_not_argv_password(self):
        with open("dags/edgeguard_pipeline.py") as fh:
            src = fh.read()
        # Find the check_neo4j_quality_task bash_command block
        idx = src.find("check_neo4j_quality_task =")
        assert idx > 0
        end = src.find("\n)", idx)
        block = src[idx:end]

        # The password-in-argv pattern must be gone
        assert 'curl -s -u "${NEO4J_USER}:${NEO4J_PWD}"' not in block, (
            "DAG quality check must NOT use ``curl -u user:$PWD`` — password leaks into "
            "/proc/cmdline. Use --netrc-file instead."
        )
        # Must use the netrc approach
        assert "--netrc-file" in block, "DAG quality check must use ``curl --netrc-file``"
        # Must have a cleanup trap
        assert "trap " in block, "netrc file MUST be cleaned up via ``trap``, even on crash / signal"
        # chmod 600 is required so the file isn't world-readable
        assert "chmod 600" in block, "netrc file must be chmod 600"

    def test_check_progress_sh_uses_netrc_not_argv_password(self):
        with open("src/check_progress.sh") as fh:
            content = fh.read()
        assert 'curl -s -u "neo4j:${NEO4J_PASSWORD' not in content, (
            "check_progress.sh must NOT embed password in curl argv"
        )
        assert "--netrc-file" in content, "check_progress.sh must use --netrc-file"
        assert "chmod 600" in content
        assert "trap " in content


# ===========================================================================
# Fix 6: Airflow 3.x command + gitignore cache hygiene
# ===========================================================================


class TestAirflowRunDocsReflectv3:
    """The AIRFLOW_DAGS.md ``Manual Run`` section must not show the
    Airflow-2.x ``airflow webserver -p 8080`` command (removed in
    Airflow 3.x, replaced with ``airflow standalone`` / ``api-server``)."""

    def test_no_airflow_2x_webserver_command_in_docs(self):
        with open("docs/AIRFLOW_DAGS.md") as fh:
            content = fh.read()
        assert "airflow webserver -p 8080" not in content, (
            "AIRFLOW_DAGS.md must not reference ``airflow webserver`` — that subcommand "
            "was removed in Airflow 3.x. Use ``airflow standalone`` or ``docker compose up -d airflow``."
        )

    def test_manual_run_section_uses_docker_compose(self):
        with open("docs/AIRFLOW_DAGS.md") as fh:
            content = fh.read()
        idx = content.find("### Manual Run")
        assert idx > 0, "Manual Run section missing"
        section_end = content.find("\n### ", idx + 1)
        section = content[idx:section_end]
        # The canonical path is the compose stack
        assert "docker compose" in section, "Manual Run section must use the canonical docker-compose-based path"


class TestGitignoreCacheHygiene:
    """``.mypy_cache/`` and ``.ruff_cache/`` generate on every test run
    and should never be committed. Pin that they're gitignored."""

    def test_mypy_and_ruff_caches_ignored(self):
        with open(".gitignore") as fh:
            content = fh.read()
        assert ".mypy_cache/" in content, ".mypy_cache/ must be gitignored"
        assert ".ruff_cache/" in content, ".ruff_cache/ must be gitignored"
