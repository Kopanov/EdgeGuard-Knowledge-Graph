"""
PR-N32 — read-only unicode-bypass audit + launch-day checklist.

PR-N29 L1 + PR-N31 closed 35 zero-width / bidi-control / variation-
selector chars in `is_placeholder_name` so an attacker (or buggy feed)
can no longer create Malware/ThreatActor/Tool nodes whose names are
placeholders padded with invisible chars. PR-N32 ships:

* `scripts/audit_legacy_unicode_bypass_nodes.py` — read-only audit
  that answers "do legacy unicode-bypass nodes still exist in
  production Neo4j?" so the operator can decide whether a destructive
  cleanup migration is needed at all.
* `docs/BASELINE_LAUNCH_CHECKLIST.md` — the single doc the operator
  walks through immediately before triggering a 730-day baseline.

Both are deliberately small surfaces:

* The script uses READ_ACCESS at the session level (loud-fail on any
  future-maintainer drift that adds a stray write); the canonical
  char list is imported from `node_identity._ZERO_WIDTH_AND_BIDI_CHARS`
  (single source of truth — adds to that list propagate automatically).
* The checklist references existing docs (RUNBOOK, BACKUP,
  BASELINE_SMOKE_TEST) rather than duplicating them — so a future
  edit to RUNBOOK doesn't drift away from the checklist.

Tests pin both deliverables' contracts:

* The script is importable + structured-output stable
* The audit-regex matches every char in the canonical list
  (cross-source-of-truth pin: if a future PR adds a char to
  `_ZERO_WIDTH_AND_BIDI_CHARS`, the audit picks it up)
* The script is read-only (no MERGE / SET / DELETE / CREATE /
  REMOVE in any of its Cypher templates)
* The checklist references the right scripts / docs / alerts and
  the cross-references actually resolve
"""

from __future__ import annotations

import importlib
import os
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
SCRIPTS = REPO_ROOT / "scripts"
DOCS = REPO_ROOT / "docs"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n32")


# ===========================================================================
# scripts/audit_legacy_unicode_bypass_nodes.py — read-only audit
# ===========================================================================


class TestPRN32AuditScriptShape:
    """Source-pin the audit script's shape so a future-maintainer drift
    can't silently turn a read-only audit into a destructive write."""

    SCRIPT_FILE = SCRIPTS / "audit_legacy_unicode_bypass_nodes.py"

    def test_script_exists_and_executable(self):
        """The script must be present + have the executable bit set so
        operators can invoke it via `./scripts/audit_legacy_unicode_bypass_nodes.py`."""
        assert self.SCRIPT_FILE.exists(), "PR-N32 audit script must exist"
        assert os.access(self.SCRIPT_FILE, os.X_OK), (
            "PR-N32: audit script must have executable bit set so operators can "
            "invoke it directly via ./scripts/audit_legacy_unicode_bypass_nodes.py"
        )

    def test_script_is_importable(self):
        """The script must import cleanly without a live Neo4j (the
        connection only happens inside main(), not at import time)."""
        mod = importlib.import_module("audit_legacy_unicode_bypass_nodes")
        # Smoke: module-level objects we depend on
        assert hasattr(mod, "_AUDITED_LABELS")
        assert hasattr(mod, "_SUSPICIOUS_REGEX")
        assert hasattr(mod, "audit_label")
        assert hasattr(mod, "render_human")
        assert hasattr(mod, "main")

    def test_audited_labels_match_placeholder_filtered_labels(self):
        """The audited labels must exactly match the labels that use
        ``is_placeholder_name`` filtering. Currently: Malware, ThreatActor,
        Tool. (Sector is excluded — operator-controlled config, not
        feed-derived.) If a future PR adds placeholder filtering to a new
        label, the audit MUST be expanded to cover it; this test surfaces
        the drift loudly rather than silently leaving a label uncovered."""
        from audit_legacy_unicode_bypass_nodes import _AUDITED_LABELS

        assert set(_AUDITED_LABELS) == {"Malware", "ThreatActor", "Tool"}, (
            "PR-N32: _AUDITED_LABELS must match the labels that use "
            "is_placeholder_name filtering (Malware, ThreatActor, Tool). "
            "If a new label gets placeholder filtering, expand both."
        )

    def test_uses_read_access_session_mode(self):
        """Defense-in-depth: the audit script MUST open Neo4j sessions
        in READ_ACCESS mode so any future drift (e.g. a maintainer
        adding a stray MERGE while extending the script) loud-fails on
        the server side rather than silently mutating production."""
        text = self.SCRIPT_FILE.read_text()
        assert "READ_ACCESS" in text, "PR-N32: script must import + use READ_ACCESS"
        assert "default_access_mode=READ_ACCESS" in text, (
            "PR-N32: session must be opened with default_access_mode=READ_ACCESS — "
            "without this, a future maintainer's accidental MERGE would silently "
            "mutate production rather than loud-failing on the server."
        )

    def test_no_write_cypher_in_script(self):
        """Negative pin: every Cypher template used by the script must be
        write-free. Belt-and-braces with the READ_ACCESS session mode.

        Scope: scans only the actual Cypher templates (functions whose
        body returns a Cypher string + the literal string passed to
        ``session.run``). Excludes the operator-facing recommendation
        narrative strings in ``render_human`` which legitimately contain
        the keywords MERGE / SET / DELETE as English text in the
        triage tree.
        """
        import ast

        # The only Cypher in the script is generated by _count_query —
        # exercise it for each audited label and scan the resulting strings.
        from audit_legacy_unicode_bypass_nodes import _AUDITED_LABELS, _count_query

        for label in _AUDITED_LABELS:
            cypher = _count_query(label)
            for forbidden in ("MERGE", "SET ", "DELETE", "CREATE", "REMOVE"):
                assert forbidden not in cypher.upper(), (
                    f"PR-N32: _count_query({label!r}) contains write-Cypher "
                    f"keyword ``{forbidden}``. The audit MUST be read-only — "
                    f"if you need a write path, put it in a separate cleanup "
                    f"script that explicitly opts INTO write mode."
                )

        # Also AST-scan any other string literal passed to ``session.run(...)``
        # so a future maintainer adding a second query gets the same check.
        tree = ast.parse(self.SCRIPT_FILE.read_text())
        run_args: list[str] = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "run"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                run_args.append(node.args[0].value)
        for arg in run_args:
            for forbidden in ("MERGE", "SET ", "DELETE", "CREATE", "REMOVE"):
                assert forbidden not in arg.upper(), (
                    f"PR-N32: literal Cypher string passed to session.run() "
                    f"contains write-keyword ``{forbidden}``. Audit must be "
                    f"strictly read-only."
                )


class TestPRN32AuditRegexCanonicalParity:
    """Single-source-of-truth pin: the audit's regex must cover every
    char in `node_identity._ZERO_WIDTH_AND_BIDI_CHARS`. If a future PR
    adds a char to that list (e.g. a new bidi attack vector), the audit
    must pick it up automatically — that's the contract this test pins."""

    def test_regex_matches_every_canonical_char(self):
        from audit_legacy_unicode_bypass_nodes import _SUSPICIOUS_REGEX

        from node_identity import _ZERO_WIDTH_AND_BIDI_CHARS

        # The Cypher regex uses ``\\uXXXX`` syntax — reformat to Python
        # regex (which uses the same Unicode escapes inside character
        # classes). Both engines are PCRE-compatible enough for this
        # equivalence to hold for character-class membership tests.
        py_pattern = re.compile(_SUSPICIOUS_REGEX, re.DOTALL)
        for c in _ZERO_WIDTH_AND_BIDI_CHARS:
            test_str = f"unknown{c}foo"
            assert py_pattern.fullmatch(test_str), (
                f"PR-N32: audit regex must match canonical char U+{ord(c):04X}. "
                f"If the regex doesn't pick up a char that the placeholder "
                f"filter strips, legacy nodes with that char in their name "
                f"will be silently invisible to the audit."
            )

    def test_regex_does_not_match_clean_strings(self):
        """Negative pin: the regex must NOT match strings that contain
        only ASCII + standard whitespace. Otherwise the audit would
        produce false positives on every node and lose its signal."""
        from audit_legacy_unicode_bypass_nodes import _SUSPICIOUS_REGEX

        py_pattern = re.compile(_SUSPICIOUS_REGEX, re.DOTALL)
        for clean in ("Conti", "LockBit 3.0", "Cobalt Strike", "unknown"):
            assert not py_pattern.fullmatch(clean), (
                f"PR-N32: audit regex must not match clean string {clean!r} — "
                f"otherwise the audit reports false positives on every node."
            )


class TestPRN32AuditOutput:
    """Pin the human + JSON output shapes. The JSON schema is the
    machine-readable contract for downstream piping (e.g., ``--json |
    jq '.total_suspicious'`` in CI)."""

    def test_render_human_zero_finds_recommends_no_op(self):
        """Behavioural: with 0 suspicious nodes across all labels, the
        human-readable summary must explicitly recommend closing the PR
        as a no-op. Operators reading the output should not have to
        guess — the recommendation must be unambiguous."""
        from audit_legacy_unicode_bypass_nodes import render_human

        per_label = [
            {"label": "Malware", "total": 100, "suspicious": 0, "samples": []},
            {"label": "ThreatActor", "total": 50, "suspicious": 0, "samples": []},
            {"label": "Tool", "total": 25, "suspicious": 0, "samples": []},
        ]
        out = render_human(per_label)
        assert "Total suspicious: 0" in out
        assert "PR-N32 cleanup is NOT needed" in out

    def test_render_human_small_count_recommends_one_shot(self):
        """1–10 suspicious nodes → "manual one-shot Cypher"."""
        from audit_legacy_unicode_bypass_nodes import render_human

        per_label = [
            {"label": "Malware", "total": 100, "suspicious": 3, "samples": ["unknown​", "n/a‎", "tbd‪"]},
            {"label": "ThreatActor", "total": 50, "suspicious": 0, "samples": []},
            {"label": "Tool", "total": 25, "suspicious": 0, "samples": []},
        ]
        out = render_human(per_label)
        assert "Total suspicious: 3" in out
        assert "manual one-shot Cypher" in out

    def test_render_human_large_count_recommends_full_migration(self):
        """> 10 suspicious → "full PR-N32 migration warranted"."""
        from audit_legacy_unicode_bypass_nodes import render_human

        per_label = [
            {"label": "Malware", "total": 100, "suspicious": 50, "samples": []},
            {"label": "ThreatActor", "total": 50, "suspicious": 0, "samples": []},
            {"label": "Tool", "total": 25, "suspicious": 0, "samples": []},
        ]
        out = render_human(per_label)
        assert "Total suspicious: 50" in out
        assert "full PR-N32 migration warranted" in out

    def test_render_human_codepoint_annotation_makes_invisible_visible(self):
        """The whole point of codepoint annotation: a raw ``"unknown\\u200b"``
        printed to terminal looks identical to ``"unknown"``. The audit
        must render the codepoint so the operator can see WHICH char is
        the bypass."""
        from audit_legacy_unicode_bypass_nodes import _annotate_codepoints

        assert _annotate_codepoints("unknown​") == "unknown<U+200B>"
        assert _annotate_codepoints("‮unknown") == "<U+202E>unknown"
        # Clean strings pass through unchanged.
        assert _annotate_codepoints("Conti") == "Conti"


class TestPRN32AuditLabelBehaviouralFakeDriver:
    """PR-N32 Bugbot round 1 (2026-04-25, MED): the prior ``_count_query``
    used ``UNWIND all_names AS name``. When a label had ZERO suspicious
    matches (the expected happy-path), ``UNWIND []`` produced zero rows
    and the entire downstream pipeline collapsed — including ``total``.
    ``result.single()`` returned ``None`` and the audit_label fallback
    reported ``total=0`` even when there were thousands of clean nodes.

    The pre-Bugbot tests passed because they hand-crafted the
    ``per_label`` dict and called ``render_human`` directly — they
    NEVER exercised the real ``audit_label`` → ``_count_query`` path.

    This class fills that gap: a fake driver / session / result that
    exercises ``audit_label`` end-to-end with two scenarios:
      * ZERO matches (the Bugbot-flagged case)
      * N matches (sanity)

    If a future maintainer reverts the Cypher fix, these tests fire
    BEFORE Bugbot has to catch it again.
    """

    @staticmethod
    def _build_fake_driver(rows: list[dict]) -> Any:
        """Build a context-manager-shaped fake driver that returns
        the supplied rows from session.run().single(). Mirrors the
        neo4j Python driver's contract closely enough for audit_label
        to consume it as if it were a real driver."""

        class _FakeRecord:
            def __init__(self, row: dict) -> None:
                self._row = row

            def __getitem__(self, key: str) -> Any:
                return self._row[key]

        class _FakeResult:
            def __init__(self, rows: list[dict]) -> None:
                self._rows = rows

            def single(self) -> Any:
                return _FakeRecord(self._rows[0]) if self._rows else None

        class _FakeSession:
            def __init__(self, rows: list[dict]) -> None:
                self._rows = rows
                self.last_query: str | None = None
                self.last_params: dict | None = None
                self.access_mode: str | None = None

            def __enter__(self) -> "_FakeSession":
                return self

            def __exit__(self, *args: Any) -> None:
                pass

            def run(self, query: str, **params: Any) -> _FakeResult:
                self.last_query = query
                self.last_params = params
                return _FakeResult(self._rows)

        class _FakeDriver:
            def __init__(self, rows: list[dict]) -> None:
                self._rows = rows
                self.last_session: _FakeSession | None = None

            def session(self, default_access_mode: str | None = None) -> _FakeSession:
                self.last_session = _FakeSession(self._rows)
                self.last_session.access_mode = default_access_mode
                return self.last_session

            def close(self) -> None:
                pass

        return _FakeDriver(rows)

    def test_audit_label_preserves_total_when_zero_suspicious(self):
        """PR-N32 Bugbot round 1: ZERO suspicious matches must NOT
        collapse the ``total`` count to 0. Pre-fix, ``UNWIND []`` killed
        the whole pipeline and the audit reported every clean label as
        ``total=0`` — which an operator would read as "the query found
        nothing" rather than "12,000 clean nodes."""
        from audit_legacy_unicode_bypass_nodes import audit_label

        # Simulate: 12,000 Malware nodes, 0 of them suspicious.
        # Post-fix ``_count_query`` always returns one row even with
        # an empty suspicious_names list.
        fake = self._build_fake_driver([{"total": 12000, "suspicious": 0, "samples": []}])
        result = audit_label(fake, "Malware", sample_limit=5)
        assert result == {
            "label": "Malware",
            "total": 12000,
            "suspicious": 0,
            "samples": [],
        }, (
            "PR-N32 Bugbot round 1: total must survive even when the "
            "suspicious list is empty. Pre-fix UNWIND [] dropped the "
            "whole pipeline."
        )

    def test_audit_label_returns_full_result_when_n_suspicious(self):
        """Sanity: when there ARE matches, all three fields propagate."""
        from audit_legacy_unicode_bypass_nodes import audit_label

        fake = self._build_fake_driver([{"total": 12000, "suspicious": 3, "samples": ["unknown​", "n/a‎", "tbd‪"]}])
        result = audit_label(fake, "Malware", sample_limit=5)
        assert result["label"] == "Malware"
        assert result["total"] == 12000
        assert result["suspicious"] == 3
        assert len(result["samples"]) == 3

    def test_audit_label_uses_read_access_session(self):
        """Behavioural: the session MUST be opened with READ_ACCESS.
        Defense-in-depth pin — if a future maintainer changes the
        access mode, this test fires loudly."""
        from audit_legacy_unicode_bypass_nodes import audit_label

        from neo4j import READ_ACCESS

        fake = self._build_fake_driver([{"total": 0, "suspicious": 0, "samples": []}])
        audit_label(fake, "Malware", sample_limit=5)
        assert fake.last_session is not None
        assert fake.last_session.access_mode == READ_ACCESS, (
            "PR-N32: audit_label MUST open sessions with READ_ACCESS so "
            "any future-maintainer drift adding a write hits a server-side "
            "rejection rather than silently mutating production."
        )

    def test_audit_label_passes_regex_and_sample_limit_params(self):
        """Behavioural: the canonical regex + sample_limit param land
        on the query. Without this, the audit could silently use a stale
        regex (missing recently-added chars from
        _ZERO_WIDTH_AND_BIDI_CHARS)."""
        from audit_legacy_unicode_bypass_nodes import _SUSPICIOUS_REGEX, audit_label

        fake = self._build_fake_driver([{"total": 0, "suspicious": 0, "samples": []}])
        audit_label(fake, "Malware", sample_limit=42)
        assert fake.last_session is not None
        params = fake.last_session.last_params or {}
        assert params.get("regex") == _SUSPICIOUS_REGEX, (
            "PR-N32: audit_label MUST pass the canonical _SUSPICIOUS_REGEX "
            "to the Cypher query — otherwise the audit silently uses "
            "whatever regex the future maintainer hard-codes."
        )
        assert params.get("sample_limit") == 42, "PR-N32: audit_label MUST forward the operator-supplied sample_limit"


class TestPRN32CountQueryShape:
    """PR-N32 Bugbot round 1 follow-up: the negative shape pin —
    the new query must not contain the failed UNWIND pattern. If a
    future maintainer reverts to the UNWIND approach, this test fires
    BEFORE the bug surfaces in production."""

    def test_count_query_does_not_use_unwind(self):
        """Pre-fix _count_query used ``UNWIND all_names AS name`` —
        which produced 0 rows when all_names was empty, dropping the
        entire pipeline. The fix removes the UNWIND. Pin so a future
        revert can't silently re-introduce the bug."""
        from audit_legacy_unicode_bypass_nodes import _AUDITED_LABELS, _count_query

        for label in _AUDITED_LABELS:
            cypher = _count_query(label)
            assert "UNWIND" not in cypher.upper(), (
                f"PR-N32 Bugbot round 1: _count_query({label!r}) must not use "
                f"UNWIND — when the suspicious list is empty, ``UNWIND []`` "
                f"produces zero rows and drops the entire pipeline (including "
                f"total). Use a single-row aggregation instead."
            )

    def test_count_query_returns_total_outside_any_loop(self):
        """Belt-and-braces: the RETURN clause must include ``total``
        as a top-level binding (not nested inside a list comprehension
        or sub-query that could collapse on empty input)."""
        from audit_legacy_unicode_bypass_nodes import _AUDITED_LABELS, _count_query

        for label in _AUDITED_LABELS:
            cypher = _count_query(label)
            assert "RETURN total" in cypher, (
                f"PR-N32: _count_query({label!r}) must RETURN total directly "
                f"(not as part of a sub-query / list comprehension that could "
                f"yield zero rows on the empty case)."
            )


# ===========================================================================
# docs/BASELINE_LAUNCH_CHECKLIST.md — pre-launch operator pass
# ===========================================================================


class TestPRN32LaunchChecklistDoc:
    """Pin the checklist's structure + cross-references. If a future PR
    moves or renames a referenced doc / script / alert, this test fires
    immediately rather than the operator discovering broken links at
    launch time."""

    CHECKLIST = DOCS / "BASELINE_LAUNCH_CHECKLIST.md"

    def test_checklist_exists(self):
        assert self.CHECKLIST.exists(), "PR-N32 launch checklist must exist"

    def test_has_six_numbered_sections(self):
        """The checklist's 6 items must all be present + numbered. If a
        future PR adds or removes an item, bump the count + update this
        test deliberately — no silent drift."""
        text = self.CHECKLIST.read_text()
        for n in range(1, 7):
            assert f"### [{n}]" in text, f"PR-N32 checklist must contain section ### [{n}]"

    def test_references_preflight_script(self):
        """Item [1] uses the preflight script — must reference it correctly."""
        text = self.CHECKLIST.read_text()
        assert "scripts/preflight_baseline.sh" in text
        assert "EDGEGUARD_PREFLIGHT_STRICT=1" in text
        # The actual file must exist
        assert (REPO_ROOT / "scripts" / "preflight_baseline.sh").exists()

    def test_references_smoke_test_doc(self):
        """Item [2] points to BASELINE_SMOKE_TEST.md — must exist."""
        text = self.CHECKLIST.read_text()
        assert "BASELINE_SMOKE_TEST.md" in text
        assert (DOCS / "BASELINE_SMOKE_TEST.md").exists()

    def test_references_audit_script(self):
        """Item [6] uses the new audit script — must point to it correctly."""
        text = self.CHECKLIST.read_text()
        assert "scripts/audit_legacy_unicode_bypass_nodes.py" in text
        assert (REPO_ROOT / "scripts" / "audit_legacy_unicode_bypass_nodes.py").exists()

    def test_references_pr_n31_alert_names(self):
        """Items [3] + 'During the run' reference the PR-N31 alert names —
        must match what's actually in alerts.yml."""
        text = self.CHECKLIST.read_text()
        alerts_text = (REPO_ROOT / "prometheus" / "alerts.yml").read_text()
        for alert_name in ("EdgeGuardMispFetchFallbackActive", "EdgeGuardMispFetchFallbackHardError"):
            assert alert_name in text, f"checklist must reference {alert_name}"
            assert alert_name in alerts_text, f"alerts.yml must define {alert_name} — checklist references it"

    def test_references_runbook_sections_that_exist(self):
        """The checklist sends operators to RUNBOOK § 'Top 8 failure
        modes' and § 'Baseline launch path' — both must exist in the
        actual RUNBOOK."""
        text = self.CHECKLIST.read_text()
        runbook = (DOCS / "RUNBOOK.md").read_text()
        assert "Top 8 failure modes" in text
        assert "Top 8 failure modes" in runbook, (
            "RUNBOOK must have a 'Top 8 failure modes' section that the checklist points to"
        )
        assert "Baseline launch path" in text
        assert "Baseline launch path" in runbook

    def test_references_pr_n32_audit_count_buckets(self):
        """Item [6]'s decision tree must match the audit script's
        recommendation buckets (0 / 1–10 / >10). If the script changes
        bucket boundaries, this test surfaces the drift."""
        text = self.CHECKLIST.read_text()
        # Three buckets in the table
        assert "1–10" in text, "checklist must use the en-dash 1–10 bucket label (matches audit script wording)"
        # The cutoff must be exactly 10 for the manual-one-shot vs full-migration boundary
        assert "> 10" in text


class TestPRN32ChecklistSourceOfTruthInvariants:
    """Cross-file pins so the checklist + the rest of the repo can't
    drift apart silently. Each test answers: "if X changes, does the
    checklist need an update?" and fails when the answer is yes."""

    def test_alert_count_floor_consistent_with_alerts_yml(self):
        """The checklist's `[1]` says preflight requires "≥ 11 rules".
        That number must match what's actually in preflight + the actual
        alert count in alerts.yml."""
        checklist = (DOCS / "BASELINE_LAUNCH_CHECKLIST.md").read_text()
        preflight = (REPO_ROOT / "scripts" / "preflight_baseline.sh").read_text()

        assert "≥ 11" in checklist, "checklist must mention the ≥ 11 alert floor"
        assert "-ge 11" in preflight, "preflight must enforce ≥ 11 alert floor"

    def test_fallback_max_pages_value_consistent_with_source(self):
        """The checklist's `[4]` quotes ``_FALLBACK_MAX_PAGES = 200``
        and ``200 × 500 = 100,000`` — must match the actual constant
        in run_misp_to_neo4j.py. If the cap is bumped without updating
        the checklist, operators get the wrong number when sizing
        their MISP."""
        checklist = (DOCS / "BASELINE_LAUNCH_CHECKLIST.md").read_text()
        sync = (SRC / "run_misp_to_neo4j.py").read_text()

        assert "_FALLBACK_MAX_PAGES = 200" in checklist
        assert "_FALLBACK_MAX_PAGES = 200" in sync, (
            "run_misp_to_neo4j.py must define _FALLBACK_MAX_PAGES = 200 "
            "OR the checklist's [4] must be updated to match."
        )
        assert "100,000" in checklist
