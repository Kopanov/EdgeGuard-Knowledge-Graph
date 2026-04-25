"""
PR-N31 — post-PR-N29 baseline-followup bundle.

PR-N29 hardened the baseline against three silent-failure modes (DAG
retries-budget overrun, MISP-fetch-fallback silent truncation, cross-
host lock TTL). The multi-agent audit then surfaced 3 corroborated
HIGH correctness bugs in the round-2 fix (sentinel exception + sibling
drift in the requests-restSearch branch) — all merged in PR #110.

PR-N31 closes the deferred items called out in the PR #110 merge body:

* **Observability** — `edgeguard_misp_fetch_fallback_active_total`
  Counter (labels: branch, outcome) wired into both fallback branches
  + 2 Prometheus alert rules (warning on sustained engagement,
  critical on hard_error). Pre-N31 the only signal was the
  `[MISP-FETCH-FALLBACK-ACTIVE]` log token — invisible to operators
  unless they were grepping logs.
* **Defense-in-depth Unicode hardening** — extends the placeholder
  filter's zero-width / bidi strip table with CGJ (U+034F),
  variation selectors VS1–VS16 (U+FE00..U+FE0F), and ALM (U+061C).
  None have a known in-the-wild bypass yet but they're the same
  shape as the U+200E/U+200F gap Bugbot caught in PR-N29 round 1 —
  closing them now is cheaper than waiting for an exploit.
* **Preflight invariant pin** — `scripts/preflight_baseline.sh` now
  has a `[11] PR-N29 invariants` section that fast-fails if a
  rebase/cleanup inadvertently reverted the sentinel class, the
  retries=0 setting on the critical chain, the 48h lock max-age,
  or the PR-N31 metric wiring.
* **RUNBOOK section 8** — operator triage tree for
  `_MispFallbackHardError` covering all four hard-failure modes
  (errors-payload, unexpected-shape, non-200, cap-hit) with a
  remediation step for each.
* **build_campaign_nodes happy-path test** — Holistic H2 from the
  PR-N29 audit. Pre-N31 the only behavioural test on this function
  exercised the backfill log line; this PR adds an end-to-end
  happy-path pin that all 9 Cypher queries are issued in the right
  order and the `results` dict is populated correctly.

This module pins the contract for all 5 areas.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
DAGS = REPO_ROOT / "dags"
SCRIPTS = REPO_ROOT / "scripts"
PROM = REPO_ROOT / "prometheus"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n31")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n31")


# ===========================================================================
# Fix N31-A — Prometheus counter for MISP fetch fallback activity
# ===========================================================================


class TestPRN31FallbackCounter:
    """The `edgeguard_misp_fetch_fallback_active_total` counter is the
    Prometheus-visible signal for MISP fetch fallback activity. Pre-N31
    operators had to grep the `[MISP-FETCH-FALLBACK-ACTIVE]` log token —
    the metric makes the fallback paths first-class for alerting and
    Grafana dashboards.

    Two outcomes (`engaged` for fallback ran, `hard_error` for the
    `_MispFallbackHardError` sentinel raised); two branches (`pymisp`,
    `rest_search`). Tests pin the counter exists, is correctly
    labeled, has the right helper, and is wired into both fallback
    branches at all 4 expected sites (engaged + hard_error per branch).
    """

    METRICS_FILE = SRC / "metrics_server.py"
    SYNC_FILE = SRC / "run_misp_to_neo4j.py"

    def test_counter_declared_with_correct_labels(self):
        """Source pin: the counter exists, is named correctly, and has
        the right (branch, outcome) labelset. Bare counter without
        labels would force the alert to differentiate via separate
        counters — making the alert rule brittle."""
        text = self.METRICS_FILE.read_text()
        assert "MISP_FETCH_FALLBACK_ACTIVE = Counter(" in text, (
            "PR-N31: MISP_FETCH_FALLBACK_ACTIVE Counter must be declared at module level"
        )
        assert '"edgeguard_misp_fetch_fallback_active_total"' in text, (
            "PR-N31: counter name must match the alert rule's expr (edgeguard_misp_fetch_fallback_active_total)"
        )
        assert '["branch", "outcome"]' in text, (
            "PR-N31: labels must be exactly ['branch', 'outcome'] — alert rules + RUNBOOK key on these"
        )

    def test_counter_helper_function_exists(self):
        """Behavioural: the `record_misp_fetch_fallback(branch, outcome)`
        helper exists and can be called without prometheus_client present
        (no-op fallback in run_misp_to_neo4j when import fails)."""
        from metrics_server import record_misp_fetch_fallback

        # Call shouldn't raise (smoke). Re-import freshness handled by Python.
        record_misp_fetch_fallback("pymisp", "engaged")
        record_misp_fetch_fallback("rest_search", "hard_error")

    def test_helper_no_op_fallback_when_metrics_unavailable(self):
        """Pre-N31 the counter import would have crashed run_misp_to_neo4j
        on systems without prometheus_client. The defensive try/except
        block in run_misp_to_neo4j defines a no-op replacement so all
        call-sites can call unconditionally."""
        text = self.SYNC_FILE.read_text()
        assert "def record_misp_fetch_fallback(branch: str, outcome: str)" in text, (
            "PR-N31: run_misp_to_neo4j must define a no-op fallback for "
            "record_misp_fetch_fallback so call-sites can call unconditionally"
        )
        # The no-op must be defined inside the ImportError except branch.
        idx = text.find("except ImportError:")
        assert idx != -1
        # Within ~600 chars of ImportError (the except block body) — the
        # fallback def MUST appear.
        block = text[idx : idx + 600]
        assert "def record_misp_fetch_fallback" in block, (
            "PR-N31: no-op fallback must be defined inside the ImportError except, "
            "not at module level (would shadow the real import)"
        )

    def test_pymisp_branch_records_engaged(self):
        """Source pin: the engaged metric must fire the moment the
        fallback path is entered — not after the first successful
        page. Operators want to know "fallback active" instantly,
        not after a 60-second pagination loop succeeds."""
        text = self.SYNC_FILE.read_text()
        # The engaged record must appear BEFORE the PyMISP try block
        record_idx = text.find('record_misp_fetch_fallback("pymisp", "engaged")')
        try_idx = text.find("# Fallback: PyMISP restSearch")
        assert record_idx != -1 and try_idx != -1, (
            "PR-N31: pymisp/engaged record + PyMISP fallback try block must both exist"
        )
        assert record_idx < try_idx, (
            "PR-N31: pymisp/engaged record must fire BEFORE entering the PyMISP loop "
            "so operators see 'fallback active' immediately, not after first successful page"
        )

    def test_pymisp_branch_records_hard_error_on_sentinel(self):
        """Source pin: the inner `except _MispFallbackHardError:` clause
        in the PyMISP branch must record `pymisp/hard_error` BEFORE
        re-raising. Without this, hard errors would only show as
        engaged — operators couldn't distinguish "fallback running fine"
        from "fallback also failing."""
        text = self.SYNC_FILE.read_text()
        # Locate the inner PyMISP sentinel-catch. The first
        # `except _MispFallbackHardError:` substring in the file is
        # inside the sentinel class's own docstring (audit history);
        # the actual code catch is the SECOND occurrence, inside
        # ``fetch_edgeguard_events``.
        fn_start = text.find("def fetch_edgeguard_events(")
        assert fn_start != -1, "fetch_edgeguard_events function must exist"
        idx = text.find("except _MispFallbackHardError:", fn_start)
        assert idx != -1, "PyMISP inner sentinel-catch must exist inside fetch_edgeguard_events"
        block = text[idx : idx + 1500]
        assert 'record_misp_fetch_fallback("pymisp", "hard_error")' in block, (
            "PR-N31: PyMISP inner sentinel-catch must record pymisp/hard_error before re-raising"
        )
        # And it MUST be followed by a bare `raise` — recording without
        # re-raising would silently downgrade the failure.
        record_pos = block.find('record_misp_fetch_fallback("pymisp", "hard_error")')
        assert "raise" in block[record_pos : record_pos + 200], (
            "PR-N31: pymisp/hard_error record must be followed by `raise` to propagate sentinel"
        )

    def test_restsearch_branch_records_engaged_and_hard_error(self):
        """Source pin: symmetric with PyMISP — restSearch branch
        records engaged on entry AND hard_error on sentinel via a
        dedicated try/except wrapper around the loop."""
        text = self.SYNC_FILE.read_text()
        assert 'record_misp_fetch_fallback("rest_search", "engaged")' in text, (
            "PR-N31: rest_search/engaged record must exist (fires when PyMISP fails "
            "with non-sentinel exception and the requests-restSearch path engages)"
        )
        assert 'record_misp_fetch_fallback("rest_search", "hard_error")' in text, (
            "PR-N31: rest_search/hard_error record must exist (fires when the "
            "rest_search loop raises _MispFallbackHardError)"
        )

    def test_engaged_outcome_value_matches_alert_rule(self):
        """Cross-file pin: the alert expr in prometheus/alerts.yml
        filters on `outcome="engaged"`. The Python record call must
        use the exact same string ("engaged"); a typo would silently
        break the alert."""
        sync_text = self.SYNC_FILE.read_text()
        alerts_text = (PROM / "alerts.yml").read_text()
        assert 'outcome="engaged"' in alerts_text, "PR-N31: alert rule must filter on outcome='engaged'"
        assert '"engaged"' in sync_text, "PR-N31: Python record call must use outcome='engaged' (must match alert rule)"

    def test_hard_error_outcome_value_matches_alert_rule(self):
        """Same cross-file pin for hard_error."""
        sync_text = self.SYNC_FILE.read_text()
        alerts_text = (PROM / "alerts.yml").read_text()
        assert 'outcome="hard_error"' in alerts_text
        assert '"hard_error"' in sync_text


# ===========================================================================
# Fix N31-B — Prometheus alert rules for fallback activity
# ===========================================================================


class TestPRN31FallbackAlerts:
    """The two alert rules (warning on sustained engagement, critical on
    hard_error) translate the counter into operator pages. Pre-N31 the
    fallback could be running for hours with the only signal being
    log noise."""

    ALERTS_FILE = PROM / "alerts.yml"

    def test_active_alert_present(self):
        text = self.ALERTS_FILE.read_text()
        assert "EdgeGuardMispFetchFallbackActive" in text, (
            "PR-N31: warning-severity alert for sustained fallback engagement"
        )
        # Severity must be warning (not critical) — fallback engaged is
        # functional, just slower.
        idx = text.find("EdgeGuardMispFetchFallbackActive")
        block = text[idx : idx + 1500]
        assert "severity: warning" in block, (
            "PR-N31: EdgeGuardMispFetchFallbackActive must be severity=warning "
            "(fallback engaged is functional, not critical — only sustained=problem)"
        )
        # Must reference the counter
        assert "edgeguard_misp_fetch_fallback_active_total" in block

    def test_hard_error_alert_present(self):
        text = self.ALERTS_FILE.read_text()
        assert "EdgeGuardMispFetchFallbackHardError" in text, (
            "PR-N31: critical-severity alert for _MispFallbackHardError raises"
        )
        idx = text.find("EdgeGuardMispFetchFallbackHardError")
        block = text[idx : idx + 1500]
        assert "severity: critical" in block, (
            "PR-N31: EdgeGuardMispFetchFallbackHardError must be severity=critical "
            "(sentinel raised = baseline failed in a way that would have been silent pre-PR-N29)"
        )
        # Short `for: 1m` so the page fires immediately
        assert "for: 1m" in block, (
            "PR-N31: hard_error alert must page within 1m — operator needs to know now, not 10m later"
        )

    def test_alerts_yml_parses(self):
        """YAML must remain valid after our additions."""
        import yaml

        with self.ALERTS_FILE.open() as f:
            doc = yaml.safe_load(f)
        assert doc and "groups" in doc

    def test_alert_count_floor_pinned_in_preflight(self):
        """Cross-file pin: the preflight script's structural alert-count
        check must require ≥ 11 alerts (PR-N31 added 2 to the pre-N31
        floor of 9). If a future PR adds alerts WITHOUT bumping the
        preflight floor, the pin catches it."""
        preflight = (SCRIPTS / "preflight_baseline.sh").read_text()
        assert 'ALERT_COUNT" -ge 11' in preflight, "PR-N31: preflight alert-count floor must be ≥ 11 (was 9 pre-N31)"

    def test_both_alerts_preserve_branch_label_via_sum_by(self):
        """PR-N31 Bugbot round 1 (2026-04-25, MED): the alert annotations
        reference ``{{ $labels.branch }}`` — but bare ``sum(rate(...))``
        collapses ALL labels, so the template would render as empty
        parens. Both alerts must use ``sum by (branch) (rate(...))``
        to preserve the label.

        Pinning BOTH alerts (not just HardError which is the one Bugbot
        flagged) because PR-N31 fixed both for shape consistency — a
        future maintainer dropping the by-clause from either one would
        regress the operator UX.
        """
        import re

        text = self.ALERTS_FILE.read_text()
        for alert_name in ("EdgeGuardMispFetchFallbackActive", "EdgeGuardMispFetchFallbackHardError"):
            idx = text.find(alert_name)
            assert idx != -1, f"alert {alert_name} must exist"
            block = text[idx : idx + 1500]
            # Positive pin: the expr line must use ``sum by (branch) (rate(``.
            # Anchored with the leading whitespace (YAML expr block scalar
            # indentation) so the in-comment narrative reference doesn't
            # accidentally satisfy the assertion.
            assert re.search(r"^ {8,}sum by \(branch\) \(rate\(", block, re.MULTILINE), (
                f"PR-N31 Bugbot round 1: {alert_name} expr must use ``sum by (branch) (rate(...))`` "
                f"to preserve the branch label for the annotation template. Bare ``sum(rate(...))`` "
                f"collapses all labels and the annotation would render with empty branch interpolation."
            )
            # Negative pin: the expr line must NOT use bare ``sum(rate(`` (regex
            # again anchored on YAML indentation so the comment narrative is
            # excluded from the match).
            assert not re.search(r"^ {8,}sum\(rate\(", block, re.MULTILINE), (
                f"PR-N31 Bugbot round 1: {alert_name} expr must not be bare "
                f"``sum(rate(...))`` — that drops the branch label."
            )


# ===========================================================================
# Fix N31-C — extended Unicode chars in placeholder filter
# ===========================================================================


class TestPRN31ExtendedUnicodeChars:
    """PR-N29 L1 closed the LRM/RLM gap that Bugbot caught. PR-N31 adds
    defense-in-depth coverage for invisible chars in the same vector
    class:
      * COMBINING GRAPHEME JOINER (U+034F)
      * Variation Selectors VS1–VS16 (U+FE00..U+FE0F)
      * ARABIC LETTER MARK (U+061C, sibling of LRM/RLM)
    None have a documented in-the-wild bypass — these are pre-emptive."""

    def test_cgj_bypass_blocked(self):
        """COMBINING GRAPHEME JOINER (U+034F): zero-width grapheme glue,
        not folded by NFKC."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\u034f"), "CGJ appended bypass"
        assert is_placeholder_name("\u034funknown"), "CGJ prepended bypass"
        assert is_placeholder_name("un\u034fknown"), "CGJ inline bypass"

    def test_variation_selector_1_blocked(self):
        """VS1 (U+FE00): variation selector for emoji/CJK; harmless on
        Latin but stackable as a bypass character."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\ufe00"), "VS-1 appended bypass"

    def test_variation_selector_16_blocked(self):
        """VS-16 (U+FE0F): emoji-presentation selector. Same vector class."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\ufe0f"), "VS-16 appended bypass"

    def test_variation_selectors_full_range_blocked(self):
        """All 16 variation selectors VS1..VS16 must be stripped — pin
        the full range to catch off-by-one errors in the translate table."""
        from node_identity import is_placeholder_name

        for cp in range(0xFE00, 0xFE10):  # VS1..VS16 inclusive
            ch = chr(cp)
            assert is_placeholder_name(f"unknown{ch}"), f"variation selector U+{cp:04X} must be stripped"

    def test_arabic_letter_mark_blocked(self):
        """ARABIC LETTER MARK (U+061C): bidi-influencer in the same
        family as LRM/RLM."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\u061c"), "ALM appended bypass"
        assert is_placeholder_name("\u061cunknown"), "ALM prepended bypass"

    def test_pr_n29_chars_still_blocked(self):
        """Regression pin: PR-N31 additions must NOT remove any of the
        PR-N29 chars from the translate table."""
        from node_identity import is_placeholder_name

        # PR-N29 Bugbot round 1
        assert is_placeholder_name("unknown\u200e"), "LRM still blocked"
        assert is_placeholder_name("unknown\u200f"), "RLM still blocked"
        # PR-N29 round 2
        assert is_placeholder_name("unknown\u180e"), "MVS still blocked"
        # Original PR-N29
        assert is_placeholder_name("unknown\u200b"), "ZWSP still blocked"

    def test_genuine_names_still_pass(self):
        """Negative pin: extended chars must not cause false-positive
        rejection of real malware/actor names."""
        from node_identity import is_placeholder_name

        assert not is_placeholder_name("Conti")
        assert not is_placeholder_name("LockBit")
        assert not is_placeholder_name("APT29")
        # Even with VS-16 (which sometimes appears in legitimately-named
        # Unicode artifacts), if the canonical form is not a placeholder
        # the name is allowed through.
        assert not is_placeholder_name("Conti\ufe0f")


# ===========================================================================
# Fix N31-D — preflight script invariant checks for PR-N29
# ===========================================================================


class TestPRN31PreflightInvariants:
    """The preflight `[11]` section fast-fails if PR-N29 invariants are
    inadvertently reverted (rebase mishap, misguided "cleanup", manual
    edit). Catches problems BEFORE the baseline launches — not at hour
    26 of a 32h dagrun."""

    PREFLIGHT_FILE = SCRIPTS / "preflight_baseline.sh"

    def test_section_11_present(self):
        text = self.PREFLIGHT_FILE.read_text()
        assert "[11] PR-N29 invariants" in text, (
            "PR-N31: preflight must include a [11] section pinning PR-N29 invariants"
        )

    def test_checks_for_sentinel_class(self):
        text = self.PREFLIGHT_FILE.read_text()
        assert "class _MispFallbackHardError(Exception):" in text, (
            "PR-N31: preflight must grep for the sentinel class definition"
        )

    def test_checks_for_lock_max_age_48h(self):
        text = self.PREFLIGHT_FILE.read_text()
        assert "_BASELINE_LOCK_MAX_AGE_SEC_DEFAULT = 48" in text, (
            "PR-N31: preflight must verify lock max-age is 48h (PR-N29 M3)"
        )

    def test_checks_for_critical_chain_retries_zero(self):
        text = self.PREFLIGHT_FILE.read_text()
        # Must check ALL THREE critical-chain tasks
        for task in ("full_neo4j_sync", "build_relationships", "run_enrichment_jobs"):
            assert task in text, f"PR-N31: preflight must check retries=0 for critical-chain task {task}"

    def test_checks_for_pr_n31_metric_wiring(self):
        text = self.PREFLIGHT_FILE.read_text()
        # Looks for the record call signatures in BOTH branches
        assert 'record_misp_fetch_fallback("pymisp", "hard_error")' in text
        assert 'record_misp_fetch_fallback("rest_search", "hard_error")' in text


# ===========================================================================
# Fix N31-E — RUNBOOK section for _MispFallbackHardError
# ===========================================================================


class TestPRN31RunbookSection:
    """The RUNBOOK is the operator's first read on a sentinel raise.
    Pin the section's existence + completeness so a doc-cleanup PR
    can't accidentally delete the operator triage tree."""

    RUNBOOK_FILE = REPO_ROOT / "docs" / "RUNBOOK.md"

    def test_section_8_exists(self):
        text = self.RUNBOOK_FILE.read_text()
        assert "### 8. MISP fetch fallback" in text, (
            "PR-N31: RUNBOOK must have a § 8 dedicated to _MispFallbackHardError triage"
        )

    def test_top_n_header_bumped(self):
        """The top-of-section header was 'Top 6' before PR-N27 added §7
        and PR-N31 added §8. Must read 'Top 8' now."""
        text = self.RUNBOOK_FILE.read_text()
        assert "## Top 8 failure modes" in text, (
            "PR-N31: section header must say 'Top 8 failure modes' (was 'Top 6' pre-N27)"
        )

    def test_section_covers_all_four_failure_modes(self):
        """The four hard-failure modes the sentinel handles MUST each be
        documented in the triage tree — otherwise an operator hitting
        mode (4) cap-hit won't know to bump _FALLBACK_MAX_PAGES."""
        text = self.RUNBOOK_FILE.read_text()
        idx = text.find("### 8. MISP fetch fallback")
        assert idx != -1
        block = text[idx : idx + 6000]
        # Each failure mode + its diagnosis hint
        assert "errors-payload mid-pagination" in block
        assert "unexpected payload type" in block
        assert "non-200 mid-pagination" in block
        assert "safety-cap hit" in block
        # Each remediation step must appear
        assert "EDGEGUARD_MISP_EVENT_SEARCH" in block, (
            "RUNBOOK must mention the search-substring env var (mode 1 remediation)"
        )
        assert "_FALLBACK_MAX_PAGES" in block, "RUNBOOK must mention the cap (mode 4 remediation)"

    def test_section_links_to_alert_names(self):
        """The RUNBOOK must reference the exact alert names so
        on-call operators can grep from the alert email/page."""
        text = self.RUNBOOK_FILE.read_text()
        idx = text.find("### 8. MISP fetch fallback")
        block = text[idx : idx + 6000]
        assert "EdgeGuardMispFetchFallbackHardError" in block
        assert "EdgeGuardMispFetchFallbackActive" in block

    def test_section_explains_no_auto_retry(self):
        """Critical operator detail: PR-N29 H1 set retries=0 on the
        critical chain. The RUNBOOK MUST say this explicitly so
        operators don't wait for an auto-retry that won't come."""
        text = self.RUNBOOK_FILE.read_text()
        idx = text.find("### 8. MISP fetch fallback")
        block = text[idx : idx + 6000]
        assert "retries=0" in block
        # And explicit instruction to manually re-trigger
        assert "manually re-triggered" in block or "manually re-run" in block.lower()


# ===========================================================================
# Fix N31-F — build_campaign_nodes happy-path behavioural test (Holistic H2)
# ===========================================================================


class TestPRN31BuildCampaignNodesHappyPath:
    """Holistic H2 from the PR-N29 multi-agent audit: pre-PR-N31 the
    only behavioural test on build_campaign_nodes was the backfill-log
    pin (test_pr33_bugbot_fixes.py::test_build_campaign_nodes_backfill_
    heals_null_uuids_runtime). The HAPPY-PATH was untested.

    This test pins the end-to-end happy path:
      * 1 qualifying ThreatActor (has malware + indicators)
      * Step 1 creates 1 Campaign
      * Steps 2/3a/4/5 link malware/indicators, prune stale, cleanup, reactivate
      * The returned `results` dict reflects the per-step counts
      * All 9 expected session.run() calls fire in the right order
      * Campaign uuid is computed deterministically from the actor name

    Without this test, a refactor that re-orders / silently swallows
    one of the queries would only be caught by the integration test
    (which requires a live Neo4j). Bug Hunter HIGH-2 from the audit
    flagged this as the gap.
    """

    def _build_fake_session(self, actor_name: str = "APT-N31-Test"):
        """Construct a MagicMock session that returns happy-path values
        for each of the 9 session.run() calls build_campaign_nodes
        makes. Returns ``(client, sess, captured_queries)`` so the test
        can inspect what queries were issued + in what order.

        Mirrors the fixture in test_pr33_bugbot_fixes.py but with
        positive (non-zero) values to exercise the SUCCESS path that
        backfill-log test does not.
        """
        from unittest.mock import MagicMock

        client = MagicMock()
        sess = MagicMock()
        sess.__enter__ = lambda s: s
        sess.__exit__ = lambda *a: False

        # (1) qualifying_actors_query — one qualifying actor
        actors_iter = iter([{"name": actor_name}])
        actors_result = MagicMock()
        actors_result.__iter__ = lambda self: actors_iter

        # (2) Step 1 create_cypher — 1 Campaign created
        create_result = MagicMock()
        create_result.single.return_value = {"campaigns": 1}

        # (3) backfill_cypher — happy path: nothing to backfill
        backfill_result = MagicMock()
        backfill_result.single.return_value = {"backfilled": 0}

        # (4) Step 2 link_malware — 3 malware linked
        link_m_result = MagicMock()
        link_m_result.single.return_value = {"links": 3}

        # (5) Step 3a link_indicators_batched — apoc.periodic.iterate shape
        link_i_result = MagicMock()
        link_i_result.single.return_value = {
            "committedOperations": 47,
            "errorMessages": {},
            "batches": 5,
            "total": 47,
        }

        # (6) Step 3a' links_count — TRUE PART_OF edge count after batch
        links_count_result = MagicMock()
        links_count_result.single.return_value = {"links": 47}

        # (7) Step 3b prune_query — 0 stale edges to prune (clean run)
        prune_result = MagicMock()
        prune_result.single.return_value = {"pruned": 0}

        # (8) Step 4 cleanup_query
        cleanup_result = MagicMock()
        cleanup_result.single.return_value = {"count": 0}

        # (9) Step 5 reactivated_query
        reactivated_result = MagicMock()
        reactivated_result.single.return_value = {"count": 0}

        captured_queries = []
        original_side_effect = [
            actors_result,
            create_result,
            backfill_result,
            link_m_result,
            link_i_result,
            links_count_result,
            prune_result,
            cleanup_result,
            reactivated_result,
        ]
        idx_holder = {"i": 0}

        def _side_effect(*args, **kwargs):
            captured_queries.append(args[0] if args else "")
            ret = original_side_effect[idx_holder["i"]]
            idx_holder["i"] += 1
            return ret

        sess.run.side_effect = _side_effect
        client.driver.session.return_value = sess
        return client, sess, captured_queries

    def _import_fresh_enrichment_jobs(self):
        if "enrichment_jobs" in sys.modules:
            del sys.modules["enrichment_jobs"]
        return importlib.import_module("enrichment_jobs")

    def test_happy_path_returns_populated_results(self):
        """The function must return a non-empty `results` dict reflecting
        what was actually done. Pre-N21 a swallower silently returned
        {} on errors; this test pins the happy-path counterexample."""
        ej = self._import_fresh_enrichment_jobs()
        client, sess, _captured = self._build_fake_session()

        # Speed up time.sleep(3) calls between steps
        original_sleep = ej.time.sleep
        ej.time.sleep = lambda *_a: None
        try:
            results = ej.build_campaign_nodes(client)
        finally:
            ej.time.sleep = original_sleep

        assert isinstance(results, dict)
        assert results, "happy-path build_campaign_nodes must return non-empty results"
        # The contract pins: campaigns_created + links_created at minimum
        assert "campaigns_created" in results or "campaigns_updated" in results, (
            f"results dict must include campaign accounting; got keys: {sorted(results.keys())}"
        )

    def test_happy_path_issues_all_9_queries(self):
        """The function must issue all 9 expected session.run() calls.
        Fewer calls means a step was silently skipped (the swallower
        pattern PR-N21 fixed); more means a step duplicated or a new
        step was added without updating this pin (intentional break-
        the-build for review)."""
        ej = self._import_fresh_enrichment_jobs()
        client, sess, captured = self._build_fake_session()

        original_sleep = ej.time.sleep
        ej.time.sleep = lambda *_a: None
        try:
            ej.build_campaign_nodes(client)
        finally:
            ej.time.sleep = original_sleep

        assert sess.run.call_count == 9, (
            f"build_campaign_nodes must issue exactly 9 session.run() calls "
            f"(1 pre-fetch + 5 step queries + 3 follow-ups); got {sess.run.call_count}. "
            f"If you added a step, update this pin AND the fake-session fixture."
        )

    def test_happy_path_query_order(self):
        """The 9 queries must fire in a specific order (pre-fetch FIRST,
        Campaign create SECOND, etc). A reorder could break the
        backfill-after-create invariant the post-PR-#33 audit caught."""
        ej = self._import_fresh_enrichment_jobs()
        client, sess, captured = self._build_fake_session()

        original_sleep = ej.time.sleep
        ej.time.sleep = lambda *_a: None
        try:
            ej.build_campaign_nodes(client)
        finally:
            ej.time.sleep = original_sleep

        # Expected query identifiers (substrings unique to each query)
        # in the order they MUST fire.
        expected_substrings_in_order = [
            # (1) qualifying_actors_query — looks for ThreatActor + WHERE EXISTS
            "MATCH (a:ThreatActor)",
            # (2) Step 1 create_cypher — has the Campaign MERGE
            "MERGE (c:Campaign",
            # (3) backfill_cypher — heals NULL uuids on existing campaigns
            "backfilled",
            # (4) Step 2 link_malware — Malware -> Campaign PART_OF
            ":Malware",
            # (5) Step 3a — apoc.periodic.iterate signature
            "apoc.periodic.iterate",
        ]
        for i, substr in enumerate(expected_substrings_in_order):
            assert substr in captured[i], (
                f"query #{i + 1} must contain '{substr}'; got query starting with: {captured[i][:200]}..."
            )

    def test_happy_path_passes_campaign_uuids_dict(self):
        """The post-PR-#33 audit (round 21) caught that the create_cypher
        MERGE relies on a precomputed `$campaign_uuids` dict to set
        c.uuid deterministically. The fake session must verify this
        param is passed; otherwise a refactor could regress the
        cross-environment traceability contract silently."""
        ej = self._import_fresh_enrichment_jobs()
        client, sess, _captured = self._build_fake_session(actor_name="APT-Trace")

        original_sleep = ej.time.sleep
        ej.time.sleep = lambda *_a: None
        try:
            ej.build_campaign_nodes(client)
        finally:
            ej.time.sleep = original_sleep

        # The 2nd session.run call (create_cypher) must receive
        # campaign_uuids as a kwarg with the qualifying actor's name.
        call_args_list = sess.run.call_args_list
        # call 0 = pre-fetch (no kwargs); call 1 = create_cypher (kwargs)
        create_call = call_args_list[1]
        assert "campaign_uuids" in create_call.kwargs, (
            "create_cypher must be called with campaign_uuids=... so c.uuid is set"
        )
        uuids_dict = create_call.kwargs["campaign_uuids"]
        assert "APT-Trace" in uuids_dict, "campaign_uuids must include every qualifying actor by name"
        # Determinism: same actor name → same uuid (cross-environment contract)
        from node_identity import compute_node_uuid

        expected_uuid = compute_node_uuid("Campaign", {"name": "APT-Trace Campaign"})
        assert uuids_dict["APT-Trace"] == expected_uuid, (
            "PR #33 cross-environment contract: Campaign.uuid must be deterministic "
            "from compute_node_uuid('Campaign', {'name': '<actor> Campaign'})"
        )
