"""
PR-N14 — pre-baseline adversarial-input bounds bundle.

Five findings from the 7-agent pre-baseline audit's Red-Team pass.
Each is an adversarial-input class where a compromised or malconfigured
feed could corrupt the graph at scale during the 730-day baseline.

## Fix #1 — CVSS bounds clamp (inf / nan / negative / >10)

An attacker-controlled NVD_META with ``base_score: "1e309"`` reached
``float(...)`` → Python ``inf`` → pinned ``n.cvss_score = Infinity``.
GraphQL ``vulnerabilities(min_cvss: 9.0) ORDER BY DESC`` permanently
placed the forged CVE at the top of the triage queue; STIX export
emitted invalid JSON.

Fix: ``clamp_cvss_score(value)`` helper rejects non-finite + out-of-
[0.0, 10.0]. Applied at ``run_misp_to_neo4j.py`` base_score parse.

## Fix #2 — confidence bounds clamp [0.0, 1.0]

``r.confidence_score`` is max-wins CASE-updated in every upsert. A
source shipping ``confidence_score: "1e309"`` would pin the edge
confidence to inf permanently, defeating calibrator demotion.

Fix: ``clamp_confidence_score(value)`` helper. Applied in
``merge_node_with_source`` and both batched UNWIND paths.

## Fix #3 — accumulating-array cardinality cap + placeholder filter

``n.aliases[]``, ``n.malware_types[]``, ``n.uses_techniques[]``,
``n.tactic_phases[]`` are accumulated (deduplicated) across sources.
A compromised feed shipping ``aliases=["a1",...,"a100000"]`` repeatedly
grows the array unboundedly; ``calibrate_cooccurrence_confidence`` +
Q2/Q9 alias-match then OOM-crash the entire enrichment pass.

Fix: ``_sanitize_array_value`` helper in ``merge_node_with_source``:
- Drops placeholder entries (``"unknown"``/``"apt"``/etc.) from
  ``aliases`` specifically — mirrors PR-N10's node-name reject.
- Truncates entries >200 chars.
- Caps at 50 items per incoming list (p99 alias count in
  MITRE/Malpedia is ~30; generous).

## Fix #4 — STIX re-import honest-NULL

``run_pipeline.py`` re-imports STIX bundles back into EdgeGuard (e.g.
ResilMesh feedback loop). Three sites substituted
``datetime.now(...).isoformat()`` when STIX lacked ``created`` /
``modified`` fields. Re-importing CVE-2013 today stamped
``first_seen=2026-04-21``, poisoning calibrator age math (PR-N5 C7
violation).

Fix: pass None through (honest-NULL). The merge layer's ``ON CREATE
SET`` clauses stamp server-side timestamps correctly without forging
the source's ``first_seen``.

## Fix #5 — past-date clamp on source-truthful timestamps

``_clamp_future_to_now`` rejected future dates but had no LOWER bound.
A compromised feed emitting ``first_seen: "0001-01-01"`` would pin a
campaign's ``c.first_seen`` to year 0001, dropping it from every
age-filtered recent-threat dashboard. Effectively a "hide in plain
sight" attack.

Fix: new earliest-allowed-date floor (default 1995-01-01,
configurable via ``EDGEGUARD_EARLIEST_IOC_DATE``). Pre-floor values
return None (honest-NULL).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n14")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n14")


# ===========================================================================
# Fix #1 — clamp_cvss_score
# ===========================================================================


class TestFix1CvssClamp:
    def test_rejects_infinity(self):
        from neo4j_client import clamp_cvss_score

        assert clamp_cvss_score(float("inf")) is None
        assert clamp_cvss_score(float("-inf")) is None
        assert clamp_cvss_score("1e309") is None, "string that parses to inf must be rejected"

    def test_rejects_nan(self):
        from neo4j_client import clamp_cvss_score

        assert clamp_cvss_score(float("nan")) is None

    def test_rejects_out_of_range(self):
        from neo4j_client import clamp_cvss_score

        assert clamp_cvss_score(-0.1) is None
        assert clamp_cvss_score(10.1) is None
        assert clamp_cvss_score(100) is None
        assert clamp_cvss_score(-1000) is None

    def test_accepts_valid_range(self):
        from neo4j_client import clamp_cvss_score

        assert clamp_cvss_score(0.0) == 0.0
        assert clamp_cvss_score(9.8) == 9.8
        assert clamp_cvss_score(10.0) == 10.0
        assert clamp_cvss_score("7.5") == 7.5  # string parse OK

    def test_none_and_unparseable_return_none(self):
        from neo4j_client import clamp_cvss_score

        assert clamp_cvss_score(None) is None
        assert clamp_cvss_score("not a number") is None
        assert clamp_cvss_score("") is None
        assert clamp_cvss_score([]) is None


# ===========================================================================
# Fix #2 — clamp_confidence_score
# ===========================================================================


class TestFix2ConfidenceClamp:
    def test_rejects_infinity_and_nan(self):
        from neo4j_client import clamp_confidence_score

        assert clamp_confidence_score(float("inf")) is None
        assert clamp_confidence_score(float("nan")) is None
        assert clamp_confidence_score("1e309") is None

    def test_rejects_out_of_range(self):
        from neo4j_client import clamp_confidence_score

        assert clamp_confidence_score(-0.01) is None
        assert clamp_confidence_score(1.01) is None
        assert clamp_confidence_score(1e10) is None

    def test_accepts_valid_range(self):
        from neo4j_client import clamp_confidence_score

        assert clamp_confidence_score(0.0) == 0.0
        assert clamp_confidence_score(0.5) == 0.5
        assert clamp_confidence_score(1.0) == 1.0
        assert clamp_confidence_score("0.75") == 0.75

    def test_merge_node_applies_clamp_with_fallback(self):
        """Regression pin: the merge_node_with_source read site uses
        the clamp + falls back to 0.5 on rejection."""
        src = (SRC / "neo4j_client.py").read_text()
        # The read site must include both the clamp call and the 0.5 fallback.
        idx = src.find("def merge_node_with_source")
        assert idx != -1
        block = src[idx : idx + 12000]  # full function
        assert "clamp_confidence_score(_claimed_conf)" in block, (
            "merge_node_with_source must clamp confidence via helper"
        )
        assert "confidence = _clamped_conf if _clamped_conf is not None else 0.5" in block, (
            "merge_node_with_source must fall back to 0.5 on clamp reject"
        )


# ===========================================================================
# Fix #3 — accumulating-array cardinality cap + placeholder filter
# ===========================================================================


class TestFix3ArrayBounds:
    def test_sanitizer_exists_in_merge_node(self):
        """Helper must be defined inside merge_node_with_source (Cypher
        string builder scope)."""
        src = (SRC / "neo4j_client.py").read_text()
        assert "_sanitize_array_value" in src, "sanitizer helper must exist"
        assert "_MAX_ARRAY_ITEMS = 50" in src, "cap constant must be 50 (p99 ≈ 30)"
        assert "_MAX_ARRAY_ITEM_LEN = 200" in src, "per-entry length cap must be 200"

    def test_aliases_drops_placeholder_entries(self):
        """AST/regex pin: the placeholder filter uses is_placeholder_name
        and is scoped to the aliases prop (only — other arrays like
        uses_techniques are MITRE IDs that shouldn't be placeholder-
        filtered)."""
        src = (SRC / "neo4j_client.py").read_text()
        idx = src.find("_sanitize_array_value")
        assert idx != -1
        block = src[idx : idx + 3000]
        assert 'if prop == "aliases" and is_placeholder_name(' in block, (
            "placeholder filter must be scoped to aliases prop"
        )

    def test_cardinality_truncation_emits_warn(self):
        """If an incoming list exceeds the cap, a WARN must fire so
        operators see the compromised-feed signal."""
        src = (SRC / "neo4j_client.py").read_text()
        idx = src.find("_sanitize_array_value")
        assert idx != -1
        block = src[idx : idx + 3000]
        assert "logger.warning" in block
        assert "exceeds cap" in block


# ===========================================================================
# Fix #4 — STIX re-import honest-NULL
# ===========================================================================


class TestFix4StixReimportHonestNull:
    def test_no_wall_clock_substitution_for_indicator_reimport(self):
        """Prior code: ``obj.get("created", datetime.now(...).isoformat())``.
        Must now pass None through."""
        src = (REPO_ROOT / "src" / "run_pipeline.py").read_text()
        # The three problem sites at ~L471, ~L498, ~L628 must NOT use
        # ``datetime.now(...)`` as a default for STIX ``created`` / ``modified``.
        # Check that ``obj.get("created", datetime.now`` pattern is gone.
        assert 'obj.get("created", datetime.now' not in src, (
            "regression: STIX ``created`` must not default to wall-clock NOW (PR-N5 C7 violation)"
        )
        assert 'obj.get("modified", datetime.now' not in src, (
            "regression: STIX ``modified`` must not default to wall-clock NOW"
        )

    def test_observable_reimport_uses_none_not_now(self):
        """The ipv4-addr observable path at ~L628 used to hard-code
        ``datetime.now(...)``. Must now pass None."""
        src = (REPO_ROOT / "src" / "run_pipeline.py").read_text()
        # Find the STIX observables block
        idx = src.find('obj_type in ["ipv4-addr", "ipv6-addr", "domain-name", "url"]')
        assert idx != -1, "STIX observable block not found"
        block = src[idx : idx + 2500]
        # The observable MERGE must NOT have wall-clock-NOW for first_seen.
        # It's fine to reference datetime elsewhere in the function.
        assert '"first_seen": datetime.now(' not in block, (
            "STIX observable MERGE must pass None for first_seen, not wall-clock NOW"
        )
        assert '"last_updated": datetime.now(' not in block, (
            "STIX observable MERGE must pass None for last_updated, not wall-clock NOW"
        )


# ===========================================================================
# Fix #5 — past-date clamp on source-truthful timestamps
# ===========================================================================


class TestFix5PastDateClamp:
    def test_rejects_year_0001(self, monkeypatch):
        """Adversarial: feed claims IOC first-seen in year 0001 to hide
        from recent-threat dashboards. Must return None (honest-NULL)."""
        monkeypatch.delenv("EDGEGUARD_EARLIEST_IOC_DATE", raising=False)
        from source_truthful_timestamps import _clamp_future_to_now

        assert _clamp_future_to_now("0001-01-01T00:00:00+00:00") is None
        assert _clamp_future_to_now("1969-12-31T23:59:59+00:00") is None

    def test_accepts_modern_timestamps(self, monkeypatch):
        monkeypatch.delenv("EDGEGUARD_EARLIEST_IOC_DATE", raising=False)
        from source_truthful_timestamps import _clamp_future_to_now

        # 2020 is well after the 1995 floor — must pass through
        assert _clamp_future_to_now("2020-06-15T12:00:00+00:00") == "2020-06-15T12:00:00+00:00"
        # Exactly at the default floor (inclusive or not? we use <
        # earliest, so 1995-01-01 itself passes)
        assert _clamp_future_to_now("1995-01-01T00:00:00+00:00") == "1995-01-01T00:00:00+00:00"

    def test_env_var_overrides_floor(self, monkeypatch):
        """Operator tuning: an import of a 1970s-era corpus needs a
        looser floor. EDGEGUARD_EARLIEST_IOC_DATE accepts this."""
        monkeypatch.setenv("EDGEGUARD_EARLIEST_IOC_DATE", "1970-01-01")
        from source_truthful_timestamps import _clamp_future_to_now

        # Now 1975 is allowed
        assert _clamp_future_to_now("1975-07-04T00:00:00+00:00") == "1975-07-04T00:00:00+00:00"
        # But 1960 still rejected
        assert _clamp_future_to_now("1960-01-01T00:00:00+00:00") is None

    def test_invalid_env_var_falls_back_to_default(self, monkeypatch, caplog):
        import logging

        monkeypatch.setenv("EDGEGUARD_EARLIEST_IOC_DATE", "not-a-date")
        from source_truthful_timestamps import _clamp_future_to_now

        with caplog.at_level(logging.WARNING, logger="source_truthful_timestamps"):
            # Invalid env → fall back to default 1995-01-01
            assert _clamp_future_to_now("1990-01-01T00:00:00+00:00") is None
            assert _clamp_future_to_now("2000-01-01T00:00:00+00:00") == "2000-01-01T00:00:00+00:00"
        assert any("not a valid ISO date" in r.message for r in caplog.records), "invalid env var must warn"

    def test_future_clamp_behaviour_preserved(self, monkeypatch):
        """Future-date clamping (pre-PR-N14 behaviour) must still work."""
        monkeypatch.delenv("EDGEGUARD_EARLIEST_IOC_DATE", raising=False)
        from source_truthful_timestamps import _clamp_future_to_now

        future = "2099-01-01T00:00:00+00:00"
        clamped = _clamp_future_to_now(future)
        assert clamped != future  # was clamped
        assert clamped is not None  # future becomes NOW, not None


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_neo4j_client_exports_new_helpers(self):
        from neo4j_client import clamp_confidence_score, clamp_cvss_score  # noqa: F401

    def test_source_truthful_earliest_helper_exists(self):
        from source_truthful_timestamps import _earliest_allowed_date

        result = _earliest_allowed_date()
        from datetime import datetime

        assert isinstance(result, datetime)

    def test_run_pipeline_imports(self):
        # run_pipeline sits at src/run_pipeline.py; verify it imports
        # cleanly after the STIX re-import edit.
        import run_pipeline  # noqa: F401

    def test_run_misp_to_neo4j_imports(self):
        import run_misp_to_neo4j  # noqa: F401
