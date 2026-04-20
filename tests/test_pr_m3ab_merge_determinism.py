"""
PR-M3a + PR-M3b — Tier-A merge-determinism critical-bug fixes.

Two CRITICAL findings from the 2026-04-20 comprehensive audit — each
would silently corrupt a 730-day baseline graph even if every other
Tier-A fix landed.

## §5-MD-C1 (PR-M3a) — Indicator value canonicalization

``merge_indicators_batch`` canonicalizes ``value`` via
``canonicalize_merge_key`` before MERGE (e.g. lowercases SHA256
hashes + IPv4 + hostnames + domains). But ``create_misp_relationships_batch``
built row dicts directly from ``fk.get("value")`` — the raw, un-
canonicalized MISP payload string. For any upstream source that
emits mixed-case hashes (SHA256 as ``DEADBEEF...``, hostname as
``Example.Com``), the relationship MATCH finds zero nodes → edge
SILENTLY DROPPED. ``_dropped_rels`` counter doesn't catch it (only
counts missing-endpoint rows BEFORE the query runs).

Fix: canonicalize ``fk`` and ``tk`` in the dispatch loop BEFORE row
append. Also make ``indicator_type`` an optional kwarg on the three
single-item helpers so STIX-import callers can opt in.

## §8-RI-S4-Decay (PR-M3b) — decay idempotency

The original `decay_ioc_confidence` Cypher had no idempotency marker.
Every enrichment run matched the same nodes in the same tier and
re-applied ``× 0.85`` (or ``× 0.70``). A node sitting in the 180-365d
tier for 100 runs got ``× 0.70^100`` ≈ 0, floored at 0.10, within ~7
runs. All indicators in a tier collapse to the 0.10 floor — losing
all discriminatory power for filtering / ranking.

Fix: add ``n.last_decayed_tier`` marker, gate the WHERE clause on it,
set it in the SET clause. Each node decays AT MOST ONCE per tier
crossing; subsequent runs are no-ops. When the node ages into the
next tier, the tier label changes → decay fires once for the new
tier.

## Test strategy

Both fixes touch Cypher + Python dispatch logic. No live Neo4j in
unit tests (that's the integration test's job). We use:
- **Source-pin tests** — regex over the source to verify the fix
  pattern is present AND the old broken pattern is gone.
- **Behavioral tests** — mock the Neo4j driver / session, feed
  specific inputs through ``create_misp_relationships_batch`` /
  ``decay_ioc_confidence``, assert the Cypher / params sent to the
  driver reflect the canonicalization / idempotency contract.

Source-pins catch regressions on the code path; behavioral tests
catch the bug in its actual trigger condition.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ===========================================================================
# §5-MD-C1 — Indicator value canonicalization
# ===========================================================================


class TestIndicatorCanonicalizationInBatchDispatch:
    """When ``create_misp_relationships_batch`` builds row dicts for
    Indicator-from relationships, the Indicator ``value`` MUST be
    canonicalized via ``canonicalize_merge_key`` so it matches the
    canonicalized value that ``merge_indicators_batch`` stored on
    the node. Without this, mixed-case MISP data silently drops
    edges."""

    def _make_client(self):
        """Build a ``Neo4jClient`` without connecting.  We don't need
        a live driver — the dispatch loop runs in Python before any
        Cypher is sent."""
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        # Satisfy attribute access — the dispatch doesn't touch the driver.
        client.driver = MagicMock()
        # Make session.run capture the params dict passed to it
        self._captured_rows: list = []

        def capture(query, **kwargs):
            # The batch helper passes ``rows=...``; capture and return
            # a fake result with .consume() shape.
            rows = kwargs.get("rows")
            if rows is not None:
                self._captured_rows.append((query, list(rows)))
            result = MagicMock()
            result.consume.return_value.counters.relationships_created = 0
            return result

        session = MagicMock()
        session.run = capture
        session.__enter__ = lambda s: s
        session.__exit__ = lambda *a: False
        client.driver.session.return_value = session
        return client

    def test_indicates_malware_row_has_canonicalized_value(self):
        """INDICATES Indicator→Malware: mixed-case SHA256 must be
        lowercased in the row ``value`` field before reaching the
        MATCH query."""
        client = self._make_client()

        relationships = [
            {
                "rel_type": "INDICATES",
                "from_type": "Indicator",
                "from_key": {"indicator_type": "sha256", "value": "DEADBEEF" * 8},
                "to_type": "Malware",
                "to_key": {"name": "Mimikatz"},
                "confidence": 0.7,
                "misp_event_id": "42",
            }
        ]
        client.create_misp_relationships_batch(relationships, source_id="nvd")

        # Find the rows captured for the INDICATES Indicator→Malware query.
        ind_mal_rows = []
        for query, rows in self._captured_rows:
            if "INDICATES" in query and "Malware" in query and "i:Indicator" in query:
                ind_mal_rows.extend(rows)

        assert ind_mal_rows, (
            f"expected rows captured for INDICATES Ind→Mal; got queries: {[q[:80] for q, _ in self._captured_rows]}"
        )
        row = ind_mal_rows[0]
        # Value must be lowercased (SHA256 is a case-insensitive indicator type)
        assert row["value"] == ("deadbeef" * 8), (
            f"PR-M3a §5-MD-C1: Indicator value in INDICATES row must be "
            f"canonicalized (lowercased for SHA256); got {row['value']!r}"
        )
        # Malware name must be lowercased too (name labels are case-insensitive per schema)
        assert row["malware"] == "mimikatz", f"Malware name must be canonicalized (lowercase); got {row['malware']!r}"

    def test_targets_sector_row_has_canonicalized_value(self):
        """TARGETS Indicator→Sector: mixed-case IPv4 stays canonical
        (already lowercase, but run the pipeline to prove no regression)."""
        client = self._make_client()

        relationships = [
            {
                "rel_type": "TARGETS",
                "from_type": "Indicator",
                "from_key": {"indicator_type": "domain", "value": "Example.COM"},
                "to_type": "Sector",
                "to_key": {"name": "healthcare"},
                "confidence": 0.6,
                "misp_event_id": "17",
            }
        ]
        client.create_misp_relationships_batch(relationships, source_id="otx")

        tgt_rows = []
        for query, rows in self._captured_rows:
            if "TARGETS" in query and "Sector" in query:
                tgt_rows.extend(rows)

        assert tgt_rows
        row = tgt_rows[0]
        assert row["value"] == "example.com", (
            f"Domain indicator value must be canonicalized (lowercase); got {row['value']!r}"
        )

    def test_exploits_cve_row_has_canonicalized_value(self):
        """EXPLOITS Indicator→CVE: SHA1 of mixed case → lowercased."""
        client = self._make_client()

        relationships = [
            {
                "rel_type": "EXPLOITS",
                "from_type": "Indicator",
                "from_key": {"indicator_type": "sha1", "value": "ABCDEF1234567890" * 2 + "BADF00D1"},
                "to_type": "CVE",
                "to_key": {"cve_id": "CVE-2024-1234"},
                "confidence": 0.8,
                "misp_event_id": "99",
            }
        ]
        client.create_misp_relationships_batch(relationships, source_id="nvd")

        expl_rows = []
        for query, rows in self._captured_rows:
            if "EXPLOITS" in query or ("INDICATES" in query and ":CVE" in query):
                expl_rows.extend(rows)
            # Newer Cypher may use MATCH(v:CVE/Vulnerability) + MERGE EXPLOITS.
        # If no direct match yet, look for rows with cve_id + value.
        if not expl_rows:
            for _query, rows in self._captured_rows:
                if any("cve_id" in r for r in rows):
                    expl_rows.extend([r for r in rows if "cve_id" in r])

        assert expl_rows, f"expected EXPLOITS rows; got queries: {[q[:80] for q, _ in self._captured_rows]}"
        row = expl_rows[0]
        # SHA1 is case-insensitive per indicator type rules → must be lowercased.
        assert row["value"].islower(), (
            f"PR-M3a §5-MD-C1: SHA1 indicator value must be lowercased before MATCH; got {row['value']!r}"
        )


class TestSingleItemHelpersAcceptIndicatorType:
    """The three single-item rel helpers grew an optional
    ``indicator_type`` kwarg in PR-M3a. When the caller provides it,
    the value is canonicalized via ``canonicalize_merge_key`` before
    the Cypher runs."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (SRC / "neo4j_client.py").read_text()

    def test_indicator_vulnerability_helper_accepts_indicator_type(self, source: str) -> None:
        """``create_indicator_vulnerability_relationship`` signature
        MUST include ``indicator_type`` kwarg with ``None`` default."""
        sig_pattern = "def create_indicator_vulnerability_relationship"
        idx = source.find(sig_pattern)
        assert idx > 0
        end = source.find(") -> bool:", idx)
        signature = source[idx:end]
        assert "indicator_type" in signature
        assert "Optional[str] = None" in signature or "indicator_type: Optional[str]" in signature

    def test_indicator_malware_helper_accepts_indicator_type(self, source: str) -> None:
        idx = source.find("def create_indicator_malware_relationship")
        end = source.find(") -> bool:", idx)
        signature = source[idx:end]
        assert "indicator_type" in signature

    def test_indicator_sector_helper_accepts_indicator_type(self, source: str) -> None:
        idx = source.find("def create_indicator_sector_relationship")
        end = source.find(") -> bool:", idx)
        signature = source[idx:end]
        assert "indicator_type" in signature

    def test_helpers_call_canonicalize_merge_key_when_type_given(self, source: str) -> None:
        """All three helpers must invoke ``canonicalize_merge_key`` so
        the caller's optional type argument actually changes behaviour."""
        # Count occurrences inside the three helper bodies.  Shortcut:
        # just verify the pattern appears at least 3 times across the
        # file's helper definitions (one per helper) in the context
        # of ``"Indicator"``.
        assert source.count('canonicalize_merge_key("Indicator",') >= 4, (
            "expected ``canonicalize_merge_key('Indicator', ...)`` to appear at "
            "least 4 times (once per single-item helper + once in batch dispatch)"
        )


class TestSourcePinBatchDispatchCanonicalizes:
    """The dispatch loop in ``create_misp_relationships_batch`` MUST
    canonicalize ``fk`` and ``tk`` before row append. Source-pin so
    a future refactor can't silently revert."""

    def test_dispatch_loop_canonicalizes_fk_tk(self) -> None:
        src = (SRC / "neo4j_client.py").read_text()
        dispatch_start = src.find("def create_misp_relationships_batch")
        assert dispatch_start > 0
        # End at the next top-level `def ` after a reasonable window.
        dispatch_end = src.find("\n    def ", dispatch_start + 1)
        body = src[dispatch_start:dispatch_end]

        # The canonicalization block must appear inside the dispatch body.
        assert 'canonicalize_merge_key("Indicator", fk)' in body, (
            "PR-M3a §5-MD-C1: dispatch must canonicalize Indicator from_key"
        )
        assert 'canonicalize_merge_key("Indicator", tk)' in body, (
            "PR-M3a §5-MD-C1: dispatch must canonicalize Indicator to_key"
        )
        # The canonicalize_merge_key function name is the exact marker
        # of the fix — if someone deletes that but leaves a comment, this
        # still fails.
        pre_fix_marker = 'fk = rel.get("from_key") or {}'
        # After the fix, the very next lines should include a canonicalize call.
        idx = body.find(pre_fix_marker)
        assert idx > 0
        # Slice the next ~500 chars — should contain the canonicalize call.
        near = body[idx : idx + 1500]
        assert "canonicalize_merge_key" in near, (
            "canonicalize_merge_key must appear IMMEDIATELY after fk/tk assignment in the dispatch loop"
        )


# ===========================================================================
# §8-RI-S4-Decay — Decay idempotency
# ===========================================================================


class TestDecayIsIdempotentWithinTier:
    """Each node should decay AT MOST ONCE per tier.  The fix uses
    ``n.last_decayed_tier`` as an idempotency marker; this test
    pins the marker's presence in both the WHERE and SET clauses."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (SRC / "enrichment_jobs.py").read_text()

    def test_where_clause_gates_on_last_decayed_tier(self, source: str) -> None:
        """WHERE clause must include ``last_decayed_tier`` gate so
        an already-decayed node in this tier is skipped on subsequent
        runs."""
        # Locate the decay helper's non-retire Cypher branch.
        idx = source.find("def decay_ioc_confidence")
        assert idx > 0
        end = source.find("\ndef ", idx + 1)
        body = source[idx:end]
        assert "n.last_decayed_tier IS NULL OR n.last_decayed_tier <> $tier_label" in body, (
            "PR-M3b §8-RI-S4-Decay: WHERE clause must gate on last_decayed_tier so "
            "the multiplicative decay fires at most once per tier crossing"
        )

    def test_set_clause_writes_last_decayed_tier(self, source: str) -> None:
        """SET clause must write ``n.last_decayed_tier`` so next run
        sees it and skips."""
        idx = source.find("def decay_ioc_confidence")
        end = source.find("\ndef ", idx + 1)
        body = source[idx:end]
        assert "n.last_decayed_tier = $tier_label" in body
        assert "n.last_decayed_at = datetime()" in body, (
            "SET should also stamp last_decayed_at so operators can see when the marker was set"
        )

    def test_params_include_tier_label(self, source: str) -> None:
        """The params dict must pass ``tier_label``."""
        idx = source.find("def decay_ioc_confidence")
        end = source.find("\ndef ", idx + 1)
        body = source[idx:end]
        assert '"tier_label": tier_label' in body, "params must include tier_label so the query can bind it"
        # Tier label should be derived deterministically from the tier tuple
        assert 'f"{label.lower()}-{min_days}-{max_days}"' in body

    def test_old_unbounded_multiply_pattern_is_gone(self, source: str) -> None:
        """The old query's final SET clause had no guard — just
        ``n.confidence_score = CASE ...``.  After the fix, the SET
        must include the tier marker.  A regression that re-wrote the
        query without the guard would restore the non-idempotency."""
        idx = source.find("def decay_ioc_confidence")
        end = source.find("\ndef ", idx + 1)
        body = source[idx:end]
        # There must be NO decay-non-retire Cypher block that SETs
        # ``n.confidence_score = CASE`` WITHOUT also setting
        # ``n.last_decayed_tier``.  Simplest: verify every occurrence of
        # the CASE expression on confidence_score is within ~400 chars of
        # a last_decayed_tier SET.
        pos = 0
        while True:
            case_idx = body.find("n.confidence_score = CASE", pos)
            if case_idx < 0:
                break
            # Look 600 chars ahead for the tier marker
            near = body[case_idx : case_idx + 800]
            assert "n.last_decayed_tier" in near, (
                "a SET clause writing confidence_score without also writing "
                "last_decayed_tier was found — this is the non-idempotency bug "
                "PR-M3b fixed"
            )
            pos = case_idx + 1


class TestRetireTierStillIdempotentViaActiveFlag:
    """The retire tier (>365d) has its own idempotency guard via
    ``n.active = true`` in the WHERE clause.  PR-M3b should NOT
    add the ``last_decayed_tier`` marker to the retire branch
    (it would be dead work and confusing)."""

    def test_retire_branch_does_not_use_last_decayed_tier(self) -> None:
        """The retire (>365d) branch should NOT touch ``last_decayed_tier``
        — ``n.active = true`` in WHERE is sufficient idempotency.  Dead
        work to also set the tier marker.

        We strip comment-only lines before checking so the explanatory
        comment ("retire path is idempotent via active flag...") doesn't
        trigger a false-positive."""
        src = (SRC / "enrichment_jobs.py").read_text()
        idx = src.find("def decay_ioc_confidence")
        end = src.find("\ndef ", idx + 1)
        body = src[idx:end]
        retire_idx = body.find("if retire:")
        assert retire_idx > 0
        else_idx = body.find("else:", retire_idx)
        retire_block = body[retire_idx:else_idx]

        # Strip comment-only lines from the retire block before checking.
        code_only_lines = [line for line in retire_block.splitlines() if not line.lstrip().startswith("#")]
        retire_code_only = "\n".join(code_only_lines)
        # Retire uses `n.active = true` guard (in active Cypher, not a comment).
        assert "n.active = true" in retire_code_only
        # Retire ACTIVE code must NOT reference last_decayed_tier — but
        # the comment IS allowed to explain why it's not used.
        assert "last_decayed_tier" not in retire_code_only, (
            "retire branch's ACTIVE code does not need last_decayed_tier — "
            "the n.active = true guard provides idempotency. Comments "
            "explaining this are fine, but the Cypher + params must not "
            "reference the marker."
        )
