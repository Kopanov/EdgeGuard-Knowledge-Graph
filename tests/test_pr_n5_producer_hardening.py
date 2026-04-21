"""
PR-N5 — Producer hardening bundle.

Addresses four Tier-B / Tier-C findings from the 7-agent comprehensive
audit (``docs/flow_audits/09_comprehensive_audit.md``):

  B4 [MED]  ``attr.get("value", "").lower()`` crashes on int-typed MISP
            value (Bug Hunter F3). One bad upstream attribute kills an
            entire batch mid-flight.  Fix: defensive ``str(... or "")``
            coerce at the two parse-entry points
            (misp_collector.py:280, run_misp_to_neo4j.py:1409).

  B5 [MED]  Checkpoint lock race: ``touch() + open("r")`` is non-atomic
            (Bug Hunter F10). An aggressive cleanup between the two
            syscalls can unlink the lock file, defeating the mutex and
            corrupting checkpoint state under concurrent writers. Fix:
            ``os.open(path, O_CREAT | O_RDWR)`` single atomic syscall.

  C5 [MED]  Campaign zone reduce iterates ``collect(DISTINCT i)``
            without ORDER BY (Devil's Advocate F3). ``apoc.coll.toSet``
            preserves insertion order, so ``c.zone`` flickers between
            different permutations of the same zone set across enrichment
            runs — triggering spurious MERGE-detects-change on every
            run. Fix: wrap in ``apoc.coll.sort()`` for deterministic
            alphabetical order.

  C7 [MED]  No collector-level runtime guard for the PR-M2 honest-NULL
            invariant (Devil's Advocate F5). A future collector that
            manufactures ``datetime.now()`` substitutes instead of
            passing NULL through would corrupt downstream consumers
            silently.  Fix: ``_validate_honest_null`` helper in MISPWriter
            that flags ``first_seen`` / ``last_seen`` values within
            ±5 min of wall-clock NOW and emits both a WARN and the
            ``edgeguard_misp_honest_null_violation_total`` Prometheus
            counter.

## Test strategy

Source pins for each fix + behavioural tests where feasible without a
live MISP / Neo4j backend. B5's atomic lock is exercised against a real
tempdir; the other three are source-pin + unit-level behavioural.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n5")


# ===========================================================================
# B4 — str-coerce attr value
# ===========================================================================


class TestB4StrCoerceAttrValue:
    """Pin the defensive ``str(attr.get("value", "") or "")`` pattern
    at the two parse-entry points. Pre-fix, an int-typed MISP value
    would crash ``.lower()`` / ``re.match`` mid-batch."""

    def test_misp_collector_str_coerces(self):
        src = (SRC / "collectors" / "misp_collector.py").read_text()
        assert 'attr_value = str(attr.get("value", "") or "")' in src, (
            "misp_collector.py:280 must str-coerce attr.value to survive "
            "upstream int/None values without crashing .lower() downstream"
        )

    def test_run_misp_to_neo4j_str_coerces(self):
        src = (SRC / "run_misp_to_neo4j.py").read_text()
        assert 'value = str(attr.get("value", "") or "")' in src, (
            "run_misp_to_neo4j.py (STIX build path) must str-coerce attr.value "
            "so re.match() and STIX SCO value fields don't crash on int input"
        )

    def test_b4_behaviour_int_value_does_not_crash_lower(self):
        """Direct behavioural check: given ``attr = {"value": 12345}``,
        the coerce pattern must produce a string that survives
        ``.lower()`` — NOT raise AttributeError."""
        attr = {"value": 12345}
        # The exact pattern shipped in the fix
        attr_value = str(attr.get("value", "") or "")
        # Must not raise
        result = attr_value.lower()
        assert result == "12345", f"expected '12345', got {result!r}"

    def test_b4_behaviour_none_value_coerces_to_empty(self):
        """``None`` in Python's ``or`` chain falls to ``""`` — lower()
        works on empty string, no crash."""
        attr = {"value": None}
        attr_value = str(attr.get("value", "") or "")
        assert attr_value == ""
        assert attr_value.lower() == ""  # no crash

    def test_b4_behaviour_missing_value_coerces_to_empty(self):
        """No ``value`` key at all — default ``""`` kicks in."""
        attr = {}
        attr_value = str(attr.get("value", "") or "")
        assert attr_value == ""


# ===========================================================================
# B5 — atomic checkpoint lock
# ===========================================================================


class TestB5AtomicCheckpointLock:
    """Pin the atomic-acquire helper + removal of the prior
    ``touch() + open("r")`` pattern."""

    def _read(self) -> str:
        return (SRC / "baseline_checkpoint.py").read_text()

    def test_atomic_helper_exists(self):
        src = self._read()
        assert "def _atomic_acquire_lock_fd(" in src, (
            "B5 fix: _atomic_acquire_lock_fd helper must exist as the single chokepoint for atomic lock acquisition"
        )
        # Must use O_CREAT | O_RDWR (single-syscall create-or-open)
        assert "os.O_CREAT | os.O_RDWR" in src, "B5: helper must use O_CREAT | O_RDWR"

    def test_no_racy_touch_then_open_pattern(self):
        """The prior pattern ``lock_path.touch(exist_ok=True)`` followed
        by ``open(lock_path, "r")`` must not appear in **executable**
        code.

        Parse the module with ``ast`` and walk call nodes rather than
        string-matching, so the breadcrumb mention in
        ``_atomic_acquire_lock_fd``'s docstring (which intentionally
        quotes the old broken pattern to explain why we're not using it)
        doesn't false-match."""
        import ast

        src = self._read()
        tree = ast.parse(src)

        # Walk every Attribute access; flag any `<x>.touch(exist_ok=True)`
        # that's an actual function call, not a string.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "touch":
                    # Confirm the kwarg is exist_ok=True to match the specific pattern
                    for kw in node.keywords or []:
                        if kw.arg == "exist_ok" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            raise AssertionError(
                                f"B5 regression at line {node.lineno}: found "
                                f"executable `.touch(exist_ok=True)` call — the "
                                f"non-atomic pattern must be fully removed from "
                                f"active code; use _atomic_acquire_lock_fd"
                            )

    def test_update_source_checkpoint_uses_atomic_helper(self):
        src = self._read()
        # Both public APIs that take the lock must route through the
        # atomic helper, not re-invent the touch+open sequence.
        assert "update_source_checkpoint" in src
        assert "update_source_incremental" in src
        # Two call sites minimum (both updaters)
        assert src.count("_atomic_acquire_lock_fd(lock_path)") >= 2, (
            "B5: both update_source_checkpoint and update_source_incremental must use the atomic helper"
        )

    def test_b5_behaviour_lock_acquires_when_file_missing(self, tmp_path):
        """Real-filesystem check: the helper must create-and-open in a
        single atomic step, even when the path doesn't exist."""
        import fcntl

        # Import the helper directly
        from baseline_checkpoint import _atomic_acquire_lock_fd

        lock_path = tmp_path / "foo.lock"
        assert not lock_path.exists(), "precondition: lock file must not exist"

        fd = _atomic_acquire_lock_fd(lock_path)
        try:
            assert lock_path.exists(), "helper must create the file"
            # flock should work on the returned fd
            fcntl.flock(fd, fcntl.LOCK_EX)
            # Release & close
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def test_b5_behaviour_lock_reacquires_after_external_unlink(self, tmp_path):
        """The pre-fix bug was: between touch() and open("r"), an
        external unlink could vanish the file. Our atomic helper must
        handle that gracefully on subsequent acquisition (create again).
        This test simulates tmpwatch / systemd-tmpfiles removing the
        file between acquisitions."""
        from baseline_checkpoint import _atomic_acquire_lock_fd

        lock_path = tmp_path / "foo2.lock"

        # Acquire once, close
        fd = _atomic_acquire_lock_fd(lock_path)
        os.close(fd)
        assert lock_path.exists()

        # External agent unlinks the file
        lock_path.unlink()
        assert not lock_path.exists()

        # Re-acquire — must not raise; the O_CREAT re-creates it
        fd2 = _atomic_acquire_lock_fd(lock_path)
        try:
            assert lock_path.exists()
        finally:
            os.close(fd2)


# ===========================================================================
# C5 — Campaign zone deterministic ordering
# ===========================================================================


class TestC5CampaignZoneOrdering:
    """Pin ``apoc.coll.sort()`` wrap on the Campaign zone reduce so
    ``c.zone`` doesn't flicker across enrichment runs."""

    def _read(self) -> str:
        return (SRC / "enrichment_jobs.py").read_text()

    def test_all_zones_wrapped_in_sort(self):
        src = self._read()
        assert "apoc.coll.sort(" in src, "C5 fix: must use apoc.coll.sort for deterministic zone ordering"
        # The sort must wrap the toSet+reduce combo, not appear somewhere
        # unrelated. Look for the specific ordering.
        idx = src.find("AS all_zones")
        assert idx != -1
        # Scan backwards 600 chars for the sort wrapping the toSet
        window = src[max(0, idx - 600) : idx + 50]
        assert "apoc.coll.sort(" in window and "apoc.coll.toSet(" in window, (
            "C5 regression: the all_zones reduce must be wrapped "
            "apoc.coll.sort(apoc.coll.toSet(reduce(...))) for deterministic order"
        )
        # Order: sort should be OUTSIDE toSet (sorts the dedupe'd result)
        sort_idx = window.find("apoc.coll.sort(")
        toset_idx = window.find("apoc.coll.toSet(")
        assert sort_idx < toset_idx, "sort must wrap toSet (sort(toSet(...)))"


# ===========================================================================
# C7 — honest-NULL validator
# ===========================================================================


class TestC7HonestNullValidator:
    """Pin the validator helper + its integration into the timestamp
    chokepoint + the Prometheus metric."""

    def _src(self) -> str:
        return (SRC / "collectors" / "misp_writer.py").read_text()

    def _metrics(self) -> str:
        return (SRC / "metrics_server.py").read_text()

    def test_validator_helper_defined(self):
        src = self._src()
        assert "def _validate_honest_null(" in src, "C7: _validate_honest_null helper must be defined in misp_writer.py"

    def test_validator_called_from_timestamp_chokepoint(self):
        """The single chokepoint ``_apply_source_truthful_timestamps`` must
        call ``_validate_honest_null`` so EVERY collector's items flow
        through the guard."""
        src = self._src()
        apply_idx = src.find("def _apply_source_truthful_timestamps(")
        assert apply_idx != -1
        next_def_idx = src.find("\ndef ", apply_idx + 1)
        block = src[apply_idx : next_def_idx if next_def_idx != -1 else apply_idx + 3000]
        assert "_validate_honest_null(item)" in block, (
            "C7 regression: _apply_source_truthful_timestamps must call "
            "_validate_honest_null(item) so every collector's timestamps "
            "flow through the guard"
        )

    def test_validator_emits_warn_not_exception(self):
        """Implementation guard: the validator must NOT raise — the
        point is detection, not breaking a live push."""
        src = self._src()
        helper_idx = src.find("def _validate_honest_null(")
        assert helper_idx != -1
        next_def_idx = src.find("\ndef ", helper_idx + 1)
        body = src[helper_idx : next_def_idx if next_def_idx != -1 else helper_idx + 3500]
        assert "logger.warning(" in body, "C7: validator must logger.warning"
        # No `raise` statements in the validator body (allowed only for
        # re-raise after our own handling — here we must never raise)
        active = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))
        assert "\n            raise" not in active and "\n        raise" not in active, (
            "C7: validator must NOT raise; detection only, don't break pushes"
        )

    def test_honest_null_counter_declared_in_metrics_server(self):
        m = self._metrics()
        assert "MISP_HONEST_NULL_VIOLATIONS = Counter(" in m
        assert '"edgeguard_misp_honest_null_violation_total"' in m
        # Bounded labels (cardinality discipline from PR-N4 round 2)
        assert '["source", "field"]' in m

    def test_honest_null_counter_imported_optionally(self):
        """The counter import must be inside the optional try/except so
        MISPWriter still works on systems without prometheus_client."""
        src = self._src()
        assert "MISP_HONEST_NULL_VIOLATIONS as _MISP_HONEST_NULL_VIOLATIONS" in src
        assert "_MISP_HONEST_NULL_VIOLATIONS = None" in src, (
            "C7: optional-import graceful degradation — _MISP_HONEST_NULL_VIOLATIONS "
            "must be None when prometheus_client isn't available"
        )

    def test_c7_behaviour_validator_warns_on_now_timestamp(self, caplog):
        """Drive the validator with a wall-clock-NOW-ish timestamp and
        assert the WARN fires. This is the scenario the guard exists
        to catch: a collector silently manufacturing a NOW() substitute
        instead of passing NULL."""
        import logging
        from datetime import datetime, timezone

        from collectors.misp_writer import _validate_honest_null

        # Build an item with first_seen = NOW (simulates manufactured substitute)
        now_iso = datetime.now(timezone.utc).isoformat()
        item = {
            "type": "ipv4",
            "indicator_type": "ipv4",
            "value": "198.51.100.77",
            "tag": "otx",
            "first_seen": now_iso,
        }
        with caplog.at_level(logging.WARNING):
            _validate_honest_null(item)

        assert any("honest-NULL" in rec.message for rec in caplog.records), (
            f"C7 behaviour: validator must WARN on a NOW-adjacent first_seen. "
            f"Got logs: {[r.message for r in caplog.records]}"
        )

    def test_c7_behaviour_validator_quiet_on_old_timestamp(self, caplog):
        """The validator must NOT warn on a legitimate historical claim
        (e.g. a CVE published in 2021 whose ``first_seen`` reflects the
        real source timestamp). False-positive rate must stay low or
        operators will learn to ignore the warning."""
        import logging

        from collectors.misp_writer import _validate_honest_null

        # An old CVE — source-truthful first_seen from 2021
        item = {
            "type": "vulnerability",
            "cve_id": "CVE-2021-44228",
            "value": "CVE-2021-44228",
            "tag": "nvd",
            "first_seen": "2021-12-09T00:00:00Z",
        }
        with caplog.at_level(logging.WARNING):
            _validate_honest_null(item)

        assert not any("honest-NULL" in rec.message for rec in caplog.records), (
            f"C7 false-positive: validator must stay quiet on legitimate "
            f"historical claims. Got logs: {[r.message for r in caplog.records]}"
        )

    def test_c7_behaviour_validator_quiet_on_null(self, caplog):
        """The HAPPY path: ``first_seen`` is None / absent (collector
        correctly passed NULL through). Validator must be silent."""
        import logging

        from collectors.misp_writer import _validate_honest_null

        item = {"type": "domain", "value": "example.test", "tag": "otx"}  # no first_seen
        with caplog.at_level(logging.WARNING):
            _validate_honest_null(item)

        assert not any("honest-NULL" in rec.message for rec in caplog.records), (
            "C7: validator must be silent when first_seen is absent (honest-NULL case)"
        )
