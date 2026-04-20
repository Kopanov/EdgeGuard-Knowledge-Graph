"""
Regression tests for PR-G1 — three baseline-killer defensive fixes from
the 2026-04-20 comprehensive multi-agent audit.

These fixes all landed as one PR because each is a small defensive patch
on a path that runs during every baseline / incremental sync:

  * P0-3 (Bug Hunter HIGH) — ``_attribute_to_stix21`` MITRE tool + tactic
    branches raised NameError on ``tag`` (the loop variable leaked from
    an earlier branch only when ``attr_tags`` was non-empty), AND
    returned dicts without an ``id`` field so the caller's
    ``object_refs.append(stix_obj["id"])`` raised KeyError on every
    MITRE tool/tactic regardless of tags, AND the returned shape had
    ``mitre_id`` / ``zone`` / ``source`` / ``confidence_score`` at top
    level — none of which are valid STIX 2.1 SDO fields.

  * P0-4 (Bug Hunter HIGH) — four ``item.get(k, default)[:N]`` call sites
    in the error-recovery branches of ``_sync_single_item`` and the
    CVE / actor / tool batch handlers. ``dict.get(k, default)`` returns
    ``None`` — not the default — when the key is present with a None
    value, so ``None[:N]`` crashed the error-recovery path and aborted
    the whole sync after most of the work had already succeeded.

  * P0-5 (Bug Hunter HIGH) — NVD checkpoint ``page`` was computed as
    ``wi * 5000 + (idx // batch_size) + 1`` with ``batch_size = 2000``;
    the hard-coded ``5000`` was a stale constant and made the page
    counter jump from ~60 (end of window 0) to 5001 (start of window
    1). ``edgeguard baseline status`` reported meaningless page numbers.

Each fix is source-pinned here against future regression. The STIX
rewrites are also exercised behaviourally so we know they produce valid
STIX 2.1 SDOs and don't NameError on empty tags.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, "src")

REPO_ROOT = Path(__file__).resolve().parent.parent


# ===========================================================================
# Fix 1 (P0-4): NoneType slicing in error handlers
# ===========================================================================


class TestNoneTypeSlicingInErrorHandlers:
    """Every ``[:N]`` slice in an except-clause of ``run_misp_to_neo4j.py``
    MUST guard with ``or`` chaining against a present-but-None key.

    The old ``item.get("value", item.get("name", "N/A"))[:50]`` pattern
    crashed the error-recovery path itself when the key existed with a
    None value, aborting the whole sync mid-run (Bug Hunter HIGH)."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (REPO_ROOT / "src" / "run_misp_to_neo4j.py").read_text()

    def test_item_value_fallback_uses_or_chain(self, source: str) -> None:
        """The catchall branch in the single-item sync loop MUST use
        ``(item.get("value") or item.get("name") or "N/A")[:50]`` —
        not the broken ``item.get("value", item.get("name", "N/A"))[:50]``
        pattern that crashes on present-but-None keys."""
        good = '(item.get("value") or item.get("name") or "N/A")[:50]'
        bad = 'item.get("value", item.get("name", "N/A"))[:50]'
        assert good in source, (
            "catchall single-item error handler must use or-chain fallback "
            "so a present-but-None 'value' key doesn't crash the error path"
        )
        assert bad not in source, "the broken get(k, default)[:50] pattern must not reappear — see PR-G1 for why"

    def test_plain_cve_error_uses_or_chain(self, source: str) -> None:
        """Plain-CVE retry except-clause MUST use ``(vuln.get("cve_id")
        or "?")[:20]``."""
        assert '(vuln.get("cve_id") or "?")[:20]' in source
        assert 'vuln.get("cve_id", "?")[:20]' not in source

    def test_actor_error_uses_or_chain(self, source: str) -> None:
        """Actor batch except-clause MUST use ``(actor.get("name") or
        "unknown")[:30]``."""
        assert '(actor.get("name") or "unknown")[:30]' in source
        assert 'actor.get("name", "unknown")[:30]' not in source

    def test_tool_error_uses_or_chain(self, source: str) -> None:
        """Tool batch except-clause MUST use ``(tool.get("name") or
        "unknown")[:30]``."""
        assert '(tool.get("name") or "unknown")[:30]' in source
        assert 'tool.get("name", "unknown")[:30]' not in source

    def test_or_chain_actually_handles_none(self) -> None:
        """Behavioral check: the ``or`` pattern produces a valid string
        when the key is present with a None value. This is the core
        guarantee the source-pins above protect."""
        item = {"value": None, "name": None}
        # Old broken pattern would raise TypeError here:
        # (item.get("value", item.get("name", "N/A"))[:50])
        # New pattern falls through to "N/A":
        assert (item.get("value") or item.get("name") or "N/A")[:50] == "N/A"

        item_value_set = {"value": "203.0.113.5"}
        assert (item_value_set.get("value") or item_value_set.get("name") or "N/A")[:50] == "203.0.113.5"


# ===========================================================================
# Fix 2 (P0-3): STIX MITRE tool / tactic branches were broken
# ===========================================================================


class TestStixMitreToolTacticRewrite:
    """The MITRE tool + tactic branches of ``_attribute_to_stix21`` MUST
    return valid STIX 2.1 SDOs — not Neo4j-shaped dicts — and MUST NOT
    reference an undefined ``tag`` name (Bug Hunter HIGH)."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (REPO_ROOT / "src" / "run_misp_to_neo4j.py").read_text()

    def test_tool_branch_does_not_reference_undefined_tag(self, source: str) -> None:
        """The tool-branch return block MUST NOT include the broken
        ``"tag": tag`` or ``"source": [tag]`` — ``tag`` is not bound at
        this scope and raises NameError when ``attr_tags`` is empty."""
        # The old broken shape had these fields at the top level of the
        # returned dict.  Make sure neither resurfaces.
        # Note: ``"source": [tag]`` (with the undefined `tag` name) is
        # the specific NameError source; grep for it precisely.
        assert '"source": [tag]' not in source
        assert '"tag": tag,' not in source

    def test_tool_branch_returns_valid_stix21_tool_sdo(self, source: str) -> None:
        """The tool-branch return MUST include ``spec_version`` and an
        ``id`` of the form ``"tool--{attr_uuid}"`` — matching every
        other SDO branch in the function."""
        # Find the tool_match block
        tool_idx = source.find("if tool_match:")
        assert tool_idx > 0
        # End of the block = start of the tactic block
        tactic_idx = source.find("# Check if this is a MITRE tactic", tool_idx)
        assert tactic_idx > tool_idx
        tool_block = source[tool_idx:tactic_idx]
        assert '"type": "tool"' in tool_block
        assert '"spec_version": "2.1"' in tool_block
        assert '"id": f"tool--{attr_uuid}"' in tool_block
        assert '"external_references"' in tool_block
        assert "mitre-attack" in tool_block

    def test_tactic_branch_returns_valid_stix21_sdo(self, source: str) -> None:
        """Tactic branch MUST emit an ``attack-pattern`` SDO with
        ``spec_version`` + ``id`` + ``external_references`` (STIX 2.1
        has no first-class tactic SDO, so we use ``attack-pattern`` and
        mark the kind under ``x_edgeguard_mitre_kind``)."""
        tactic_idx = source.find("if tactic_match:")
        assert tactic_idx > 0
        # End of block is the next elif/else/return None at function scope
        # — grab a reasonable window.
        tactic_block = source[tactic_idx : tactic_idx + 2000]
        assert '"type": "attack-pattern"' in tactic_block
        assert '"spec_version": "2.1"' in tactic_block
        assert '"id": f"attack-pattern--{attr_uuid}"' in tactic_block
        assert '"x_edgeguard_mitre_kind": "tactic"' in tactic_block

    def test_tool_branch_uses_x_edgeguard_for_edgeguard_specific_fields(self, source: str) -> None:
        """``uses_techniques`` is EdgeGuard-specific, not STIX-standard,
        so it MUST live under the ``x_edgeguard_*`` prefix per STIX 2.1
        §3.1.1 custom-property convention — NOT as a top-level field."""
        tool_idx = source.find("if tool_match:")
        tactic_idx = source.find("# Check if this is a MITRE tactic", tool_idx)
        tool_block = source[tool_idx:tactic_idx]
        assert "x_edgeguard_uses_techniques" in tool_block
        # And the old STIX-illegal top-level ``"uses_techniques":`` must
        # be gone (would be a top-level dict key, caught by a bare-word
        # search distinguishing it from the x_edgeguard_ prefix).
        assert '"uses_techniques":' not in tool_block.replace('"x_edgeguard_uses_techniques":', "")

    def test_tool_branch_does_not_leak_neo4j_fields(self, source: str) -> None:
        """Top-level ``confidence_score`` / ``zone`` / ``mitre_id`` are
        Neo4j-internal concerns and aren't valid STIX 2.1 SDO fields."""
        tool_idx = source.find("if tool_match:")
        tactic_idx = source.find("# Check if this is a MITRE tactic", tool_idx)
        tool_block = source[tool_idx:tactic_idx]
        for bad in ['"confidence_score":', '"zone":', '"mitre_id":']:
            assert bad not in tool_block, (
                f"top-level {bad} is invalid STIX 2.1 — move EdgeGuard fields under x_edgeguard_* or drop"
            )


class TestStixAttributeConversionDoesNotCrash:
    """Behavioral check: exercise ``_attribute_to_stix21`` with inputs
    that previously crashed (empty ``attr_tags`` on a MITRE tool/tactic)
    and assert we now get back valid STIX 2.1 SDOs instead of a NameError
    or a KeyError one level up."""

    def _make_syncer(self):
        """Build a MISPToNeo4jSync without touching Neo4j or MISP."""
        # Avoid importing the whole module's side effects — just the class.
        import importlib
        from unittest.mock import patch

        with (
            patch.dict(
                "os.environ",
                {
                    "NEO4J_URI": "bolt://localhost:7687",
                    "NEO4J_USER": "neo4j",
                    "NEO4J_PASSWORD": "x",
                    "MISP_URL": "https://localhost",
                    "MISP_API_KEY": "x",
                },
                clear=False,
            ),
            patch("neo4j_client.Neo4jClient") as _,
        ):
            mod = importlib.import_module("run_misp_to_neo4j")
            importlib.reload(mod)
            # Bypass __init__ to avoid driver wiring — just bind the
            # method off the class.
            syncer = mod.MISPToNeo4jSync.__new__(mod.MISPToNeo4jSync)
            return syncer

    def test_tool_with_empty_tags_returns_valid_stix(self) -> None:
        """Pre-fix: empty ``attr_tags`` meant the old ``for tag in attr_tags``
        loop body never ran, ``tag`` was never bound, and ``"tag": tag``
        raised NameError. Post-fix: branch must return a valid STIX tool
        SDO with id + spec_version + external_references."""
        syncer = self._make_syncer()
        attr = {
            "type": "text",
            "value": "S0002: Mimikatz",
            "uuid": "11111111-1111-1111-1111-111111111111",
            "Tag": [],  # <-- the NameError trigger
            "comment": "",
        }
        result = syncer._attribute_to_stix21(attr, "event-uuid-abc", event_zones=["global"])
        assert result is not None
        assert result["type"] == "tool"
        assert result["spec_version"] == "2.1"
        assert result["id"] == "tool--11111111-1111-1111-1111-111111111111"
        # The caller does ``object_refs.append(result["id"])`` — that
        # must not KeyError.
        assert "id" in result
        # Must have the MITRE ID reference, not a top-level mitre_id.
        assert "mitre_id" not in result
        refs = result.get("external_references") or []
        assert any(r.get("external_id") == "S0002" and r.get("source_name") == "mitre-attack" for r in refs)

    def test_tactic_with_empty_tags_returns_valid_stix(self) -> None:
        """Tactic branch was identically broken. Same NameError trigger,
        same KeyError-on-caller."""
        syncer = self._make_syncer()
        attr = {
            "type": "text",
            "value": "TA0001: Initial Access",
            "uuid": "22222222-2222-2222-2222-222222222222",
            "Tag": [],
            "comment": "",
        }
        result = syncer._attribute_to_stix21(attr, "event-uuid-xyz", event_zones=["global"])
        assert result is not None
        assert result["type"] == "attack-pattern"
        assert result["spec_version"] == "2.1"
        assert result["id"] == "attack-pattern--22222222-2222-2222-2222-222222222222"
        assert result.get("x_edgeguard_mitre_kind") == "tactic"
        refs = result.get("external_references") or []
        assert any(r.get("external_id") == "TA0001" and r.get("source_name") == "mitre-attack" for r in refs)

    def test_tool_with_mitre_uses_techniques_comment_parses(self) -> None:
        """The MITRE_USES_TECHNIQUES comment format must still parse,
        with the result stashed under ``x_edgeguard_uses_techniques``
        (not at top level, per STIX 2.1 custom-property rules)."""
        syncer = self._make_syncer()
        attr = {
            "type": "text",
            "value": "S0002: Mimikatz",
            "uuid": "33333333-3333-3333-3333-333333333333",
            "Tag": [],
            "comment": 'MITRE_USES_TECHNIQUES:{"t":["T1003","T1056"]}\nFree-form description here',
        }
        result = syncer._attribute_to_stix21(attr, "event-uuid-abc", event_zones=["global"])
        assert result is not None
        assert result["x_edgeguard_uses_techniques"] == ["T1003", "T1056"]
        assert "uses_techniques" not in result  # top-level leaked field
        assert result["description"] == "Free-form description here"


# ===========================================================================
# Fix 3 (P0-5): NVD checkpoint page-numbering
# ===========================================================================


class TestNvdCheckpointPageMath:
    """NVD baseline MUST NOT use the stale ``wi * 5000`` hard-coded
    multiplier for ``page`` — it produced nonsense page numbers when
    ``batch_size = 2000`` (Bug Hunter HIGH)."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (REPO_ROOT / "src" / "collectors" / "nvd_collector.py").read_text()

    def test_old_broken_page_formula_is_gone(self, source: str) -> None:
        """Neither of the two old broken ``page=`` expressions may
        appear as a live kwarg — only in the explanatory comment that
        documents what the audit found. We strip comment lines before
        checking to avoid a false-positive from our own prose."""
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        assert "wi * 5000 + (idx // batch_size) + 1" not in code, (
            "the old wi*5000-based page kwarg must not reappear in code"
        )
        assert "page=len(windows) * 5000" not in code, (
            "the old final-page expression ``page=len(windows) * 5000`` must not reappear in code"
        )

    def test_total_batches_counter_exists_and_is_used(self, source: str) -> None:
        """The replacement is a monotonic per-API-call counter called
        ``total_batches_done``. It MUST be defined once (seeded from
        checkpoint), incremented per successful batch, and used as the
        ``page`` kwarg in BOTH update_source_checkpoint call sites in
        the baseline block."""
        assert "total_batches_done" in source
        assert "total_batches_done += 1" in source
        assert "page=total_batches_done" in source
        # Two call sites must use the new formula (inner + final).
        assert source.count("page=total_batches_done") >= 2

    def test_counter_seeds_from_current_page_not_page(self, source: str) -> None:
        """Bugbot round-1 catch: ``update_source_checkpoint`` persists
        the ``page=`` kwarg under ``entry["current_page"]``
        (``baseline_checkpoint.py:135``) — NOT under ``"page"``. The
        seed MUST read ``current_page`` so resume actually recovers
        the counter; reading ``"page"`` would always return 0 and the
        counter would restart from scratch on every run."""
        assert 'checkpoint.get("current_page")' in source, (
            "seed must read the ``current_page`` key the writer stores, "
            "not the legacy ``page`` key which always returns 0"
        )
        # And the old broken expression must be gone.
        assert 'int(checkpoint.get("page", 0) or 0)' not in source, (
            'the original broken seed pinned ``.get("page", 0)`` which '
            "always returned 0 because the writer persists under "
            "``current_page`` — Bugbot caught this; don't let it regress"
        )

    def test_seed_recovers_persisted_page_end_to_end(self, tmp_path, monkeypatch) -> None:
        """End-to-end: persist a fake NVD checkpoint via the real
        ``update_source_checkpoint`` API, then read back the value the
        nvd_collector seed expression would read.  This proves the
        seed + writer key agree, closing the class of bug Bugbot
        caught at the source level (writer persists under
        ``current_page`` but seed was reading ``page``)."""
        import importlib

        # The checkpoint module stays under the project root by design
        # (path-traversal guard at baseline_checkpoint.py:34-42), so we
        # set EDGEGUARD_CHECKPOINT_DIR to a path inside the repo that's
        # safe to write to. ``tmp_path`` is guaranteed clean per-test.
        project_root = REPO_ROOT
        safe_dir = project_root / ".pytest_checkpoint_tmp"
        safe_dir.mkdir(exist_ok=True)
        monkeypatch.setenv("EDGEGUARD_CHECKPOINT_DIR", str(safe_dir))

        # Reload so the module re-reads the env var + rebuilds
        # ``CHECKPOINT_FILE`` at the redirected path.
        import baseline_checkpoint

        importlib.reload(baseline_checkpoint)
        try:
            # Wipe any stale state from a previous test run.
            if baseline_checkpoint.CHECKPOINT_FILE.exists():
                baseline_checkpoint.CHECKPOINT_FILE.unlink()

            # Simulate what the NVD collector writes on each batch.
            baseline_checkpoint.update_source_checkpoint(
                "nvd",
                page=42,
                items_collected=84000,
                extra={"nvd_window_idx": 3, "nvd_start_index": 4000},
            )

            # Now read back and apply the nvd_collector's seed expression.
            ckpt = baseline_checkpoint.get_source_checkpoint("nvd")
            seeded = int(ckpt.get("current_page") or (max(ckpt.get("pages") or [0]) if ckpt.get("pages") else 0) or 0)
            assert seeded == 42, (
                f"seed expression must recover the persisted ``page`` value; got {seeded}. "
                f"checkpoint keys present: {sorted(ckpt.keys())}"
            )
        finally:
            # Clean up so this test leaves no artefacts in the repo.
            if baseline_checkpoint.CHECKPOINT_FILE.exists():
                baseline_checkpoint.CHECKPOINT_FILE.unlink()
            lock = baseline_checkpoint.CHECKPOINT_FILE.with_suffix(".lock")
            if lock.exists():
                lock.unlink()
            if safe_dir.exists() and not any(safe_dir.iterdir()):
                safe_dir.rmdir()
            # Reload the module one more time so subsequent tests see
            # the normal project-default checkpoint path again.
            importlib.reload(baseline_checkpoint)
