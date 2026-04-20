"""
Regression tests for PR-F5 — ``edgeguard doctor --memory`` diagnostic.

Background
----------

PR-F4 (#60) addressed the symptom of MISP HTTP 500s under concurrent
write pressure by sequencing tier-1 collectors. Bravo's investigation
also surfaced that the Neo4j tx-memory bump (4G → 8G) and MISP PHP
memory_limit recommendations weren't visible to operators — they had
to dig into source comments to find them.

PR-F5 adds ``edgeguard doctor --memory`` to surface actual vs
recommended memory settings side-by-side, so operators can see whether
their MISP HTTP 500s are caused by mis-sized Neo4j transactions or
under-provisioned host RAM. See ``docs/MEMORY_TUNING.md`` for the
recommendation rationale.

What these tests pin
--------------------

  - The argparse flag is wired (--memory)
  - The pure helpers (memory parsing + verdict computation) behave
    correctly across the value-shape matrix
  - The probe helpers degrade gracefully (no crash) when docker /
    /proc/meminfo / sysctl are unavailable
  - The recommendations table includes the Neo4j tx-memory entry that
    motivated the PR (the 8G recommendation from the 2026-04-18 incident)
"""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, "src")


# ---------------------------------------------------------------------------
# Argparse wiring
# ---------------------------------------------------------------------------


class TestArgparseFlag:
    def test_doctor_subparser_has_memory_flag(self):
        """Source-pin: the ``--memory`` flag MUST be registered on the
        doctor subparser."""
        with open("src/edgeguard.py") as fh:
            src = fh.read()
        idx = src.find('subparsers.add_parser("doctor"')
        assert idx > 0
        # Look at the next ~600 chars for the --memory wiring
        block = src[idx : idx + 600]
        assert '"--memory"' in block, "doctor subparser must register the --memory flag"
        assert "doctor_parser" in block, "should use a named parser variable to attach add_argument"


# ---------------------------------------------------------------------------
# Pure helpers — _parse_memory_value_to_gb
# ---------------------------------------------------------------------------


class TestParseMemoryValueToGB:
    """``_parse_memory_value_to_gb`` is the workhorse for converting
    Neo4j-style memory strings to a comparable GB float."""

    @pytest.mark.parametrize(
        "raw,expected_gb",
        [
            ("4G", 4.0),
            ("8g", 8.0),
            ("512M", 0.5),
            ("1024k", 1.0 / 1024),
            ("2T", 2048.0),
            (" 8G ", 8.0),  # whitespace tolerated
            ("0G", 0.0),
        ],
    )
    def test_suffixed_values_parse_correctly(self, raw, expected_gb):
        from edgeguard import _parse_memory_value_to_gb

        result = _parse_memory_value_to_gb(raw)
        assert result is not None
        assert abs(result - expected_gb) < 1e-6, f"{raw!r} → {result}, expected {expected_gb}"

    def test_bare_number_treated_as_bytes(self):
        from edgeguard import _parse_memory_value_to_gb

        # 1 GB in bytes
        assert abs(_parse_memory_value_to_gb(str(1024**3)) - 1.0) < 1e-6

    @pytest.mark.parametrize("raw", [None, "", "not-a-number", "abc", "  "])
    def test_unparseable_returns_none(self, raw):
        from edgeguard import _parse_memory_value_to_gb

        assert _parse_memory_value_to_gb(raw) is None


# ---------------------------------------------------------------------------
# Pure helpers — _verdict_for_memory
# ---------------------------------------------------------------------------


class TestVerdictForMemory:
    """The verdict function is the pure logic that maps actual vs
    min/recommended thresholds to a four-state outcome."""

    @pytest.mark.parametrize(
        "current,min_gb,rec_gb,expected",
        [
            (10.0, 4.0, 8.0, "ok"),  # at/above recommended
            (8.0, 4.0, 8.0, "ok"),  # exactly recommended
            (6.0, 4.0, 8.0, "warn"),  # at/above min, below rec
            (4.0, 4.0, 8.0, "warn"),  # exactly min
            (2.0, 4.0, 8.0, "fail"),  # below min
            (None, 4.0, 8.0, "unknown"),  # probe failed
        ],
    )
    def test_verdict_matrix(self, current, min_gb, rec_gb, expected):
        from edgeguard import _verdict_for_memory

        assert _verdict_for_memory(current, min_gb, rec_gb) == expected


# ---------------------------------------------------------------------------
# Recommendations table — surfaces the incident-driven thresholds
# ---------------------------------------------------------------------------


class TestRecommendationsTable:
    def test_neo4j_tx_memory_recommends_8g(self):
        """The 2026-04-18 build_relationships incident bumped the
        recommendation from 4G to 8G. Pin it so a future contributor
        can't quietly regress the recommendation."""
        from edgeguard import _MEMORY_RECOMMENDATIONS

        rows = [r for r in _MEMORY_RECOMMENDATIONS if r["key"] == "neo4j_tx_memory"]
        assert len(rows) == 1, "exactly one neo4j_tx_memory row expected"
        assert rows[0]["rec_gb"] == 8.0
        assert rows[0]["min_gb"] >= 4.0

    def test_neo4j_heap_recommends_at_least_4g_minimum(self):
        from edgeguard import _MEMORY_RECOMMENDATIONS

        rows = [r for r in _MEMORY_RECOMMENDATIONS if r["key"] == "neo4j_heap"]
        assert len(rows) == 1
        assert rows[0]["min_gb"] >= 4.0
        assert rows[0]["rec_gb"] >= rows[0]["min_gb"]

    def test_every_row_has_the_required_keys(self):
        """Each row MUST have label / env_var / min_gb / rec_gb /
        rationale — the doctor renderer + the docs table both consume
        these fields."""
        from edgeguard import _MEMORY_RECOMMENDATIONS

        for row in _MEMORY_RECOMMENDATIONS:
            for required in ("key", "label", "env_var", "min_gb", "rec_gb", "rationale"):
                assert required in row, f"row {row.get('key')!r} missing required field {required!r}"


# ---------------------------------------------------------------------------
# Probe helpers — graceful degradation when external probes fail
# ---------------------------------------------------------------------------


class TestProbesDegradeGracefully:
    """The probes shell out to docker / read /proc / call sysctl. They
    MUST return None / empty dict on any failure — never raise. A
    crash in the diagnostic itself would mask the underlying issue
    the diagnostic was supposed to surface."""

    def test_neo4j_probe_returns_empty_when_docker_missing(self):
        from edgeguard import _probe_neo4j_memory_via_docker

        with patch("shutil.which", return_value=None):
            assert _probe_neo4j_memory_via_docker() == {}

    def test_neo4j_probe_returns_empty_on_docker_error(self):
        import subprocess

        from edgeguard import _probe_neo4j_memory_via_docker

        with (
            patch("shutil.which", return_value="/usr/bin/docker"),
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 10)),
        ):
            # Must not raise
            assert _probe_neo4j_memory_via_docker() == {}

    def test_host_ram_probe_returns_none_when_unavailable(self):
        import subprocess

        from edgeguard import _probe_host_ram_gb

        # /proc/meminfo missing AND sysctl fails → None
        def _open_raises(*args, **kwargs):
            raise FileNotFoundError("simulated missing /proc/meminfo")

        with (
            patch("builtins.open", side_effect=_open_raises),
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("sysctl", 5)),
        ):
            assert _probe_host_ram_gb() is None

    def test_host_ram_probe_parses_proc_meminfo(self, tmp_path):
        """Pin the parsing logic for the Linux path."""
        from edgeguard import _probe_host_ram_gb

        # 16 GB in kB = 16777216
        meminfo = "MemTotal:       16777216 kB\nMemFree:         8388608 kB\n"

        from io import StringIO

        def fake_open(path, *args, **kwargs):
            if path == "/proc/meminfo":
                return StringIO(meminfo)
            raise FileNotFoundError(path)

        with patch("builtins.open", side_effect=fake_open):
            ram_gb = _probe_host_ram_gb()
        assert ram_gb is not None
        assert abs(ram_gb - 16.0) < 0.1, f"expected ~16G; got {ram_gb}"


# ---------------------------------------------------------------------------
# Documentation traceability
# ---------------------------------------------------------------------------


class TestMemoryTuningDocExists:
    def test_doc_exists_and_documents_recommendations(self):
        with open("docs/MEMORY_TUNING.md") as fh:
            content = fh.read()
        # The recommendations table must list every row that's in
        # _MEMORY_RECOMMENDATIONS — checked by content match for the
        # most-incident-driven entries.
        assert "Neo4j heap" in content
        assert "Neo4j page cache" in content
        assert "Neo4j tx memory" in content
        assert "MISP PHP" in content
        # The 2026-04-18 incident motivation must be discoverable
        assert "MemoryLimitExceededException" in content
        # The PR-F4 cross-link (the incident that established the
        # MISP PHP memory recommendation) must be present
        assert "PR-F4" in content or "#60" in content

    def test_doctor_command_help_references_memory_tuning_doc(self):
        """The argparse help string for --memory must point to the doc
        so an operator running ``edgeguard doctor --help`` can find the
        rationale without grepping source."""
        with open("src/edgeguard.py") as fh:
            src = fh.read()
        idx = src.find('"--memory"')
        assert idx > 0
        # Look at the next ~500 chars for the help text
        block = src[idx : idx + 500]
        assert "MEMORY_TUNING.md" in block, "doctor --memory help must reference docs/MEMORY_TUNING.md"
