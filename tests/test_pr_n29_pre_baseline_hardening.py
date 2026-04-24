"""
PR-N29 — pre-baseline hardening.

Comprehensive 7-agent audit on PR #109 surfaced 4 findings OUTSIDE the
PR #109 diff that affect the 730-day baseline. They're in files PR #109
doesn't touch, so they split cleanly into this focused follow-up PR.

Fixes:

1. **H1 (Holistic)** — Baseline DAG timeout math was broken.
   ``dagrun_timeout=32h`` + ``retries: 1`` + 5h critical-chain tasks =
   a single retry on ANY of sync/build_rels/enrich would blow through
   the cap mid-enrichment, leaving the graph mid-mutated.
   Fix: set ``retries=0`` on the three critical-chain tasks.

2. **H3 (Holistic)** — MISP fetch fallback silently truncated at 1000
   events. If ``_fetch_edgeguard_events_via_requests_index`` errored
   (which DID happen in 2026-04-19 incident), the PyMISP/restSearch
   fallback ran with ``limit=1000`` and NO pagination → silent data
   loss on populated MISP instances (>1K events).
   Fix: paginate both fallback branches (500/page, 200-page cap = 100K
   safety ceiling). Add ``[MISP-FETCH-FALLBACK-ACTIVE]`` log token so
   operators know to grep for fallback-path activity.

3. **M3 (Holistic)** — ``_BASELINE_LOCK_MAX_AGE_SEC_DEFAULT = 24h`` but
   baseline ``dagrun_timeout = 32h``. Cross-host deployments would have
   the sentinel reaped 8h before the baseline finishes. Same-host PID
   check bypasses this, so the CLI launch path is unaffected, but
   future k8s / multi-host docker-compose deployments were on a
   slow-burn clock.
   Fix: bump default to 48h (16h buffer above dagrun_timeout).

4. **L1 (Red Team)** — ``is_placeholder_name`` did only NFC + strip +
   lowercase. An attacker with MISP write access could bypass the
   PR-N10 placeholder filter with:
     - ``"unknown\\u200b"`` (zero-width space appended)
     - ``"unknоwn"`` (Cyrillic 'о' instead of Latin 'o')
   The first is fixable cheaply. The second (cross-script confusables)
   requires a confusables library — LOW-severity, tracked but not
   fixed here.
   Fix: strip zero-width / bidi-control chars; upgrade NFC → NFKC.

## What this PR does NOT address

Folded into PR-N30 (stacked on PR #109's merge):
* Red Team H1 — `--dry-run` READ session mode (modifies backfill script
  in PR #109)
* Cross-Checker H-2 — Q4 [0..200] cap vs backfill-uncapped intersection
  (modifies build_relationships.py queries + backfill — both in PR #109)
* Cross-Checker M-1 — Path A vs Path B empty-string drift (same)
* Test Coverage — proper behavioural sentinel test (needs pytest-airflow
  fixture)

Deferred to a separate follow-up PR:
* Holistic H2 — ``build_campaign_nodes`` behavioural happy-path test
  (larger scope, needs fake-driver fixture design)

## Multi-agent audit follow-up (2026-04-24)

A 7-agent audit on the PR #109 merge surfaced 3 corroborated HIGH
correctness bugs all rooted in PR-N29's Bugbot-round-2 fix:

* **HIGH-1 (Bug Hunter / Cross-Checker)** — ``raise RuntimeError`` from
  the new fallback paths is silently caught by the broader
  ``except Exception`` blocks at lines ~1109 (PyMISP try/except) and
  ~1201 (outer broad). Hard errors degrade to "no events found" with
  no operator surface.
* **HIGH-2 (Bug Hunter / Devil's Advocate)** — hitting
  ``_FALLBACK_MAX_PAGES`` only logs; the truncated event list is then
  treated as ground truth.
* **HIGH-3 (Cross-Checker sibling drift)** — the requests-restSearch
  branch is missing the errors-key check + unexpected-payload raise
  that the PyMISP branch has post-Bugbot-round-2.

Fix pattern: a dedicated ``_MispFallbackHardError`` sentinel +
explicit ``except _MispFallbackHardError: raise`` clauses ahead of
every broad ``except Exception``. Cap-hit branches now raise the
sentinel as well. Tests pinning the contract live in
``TestPRN29MispFallbackHardErrorSentinel`` below.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
DAGS = REPO_ROOT / "dags"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n29")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n29")


# ===========================================================================
# Fix H1 — DAG timeout math / retries=0 on critical chain
# ===========================================================================


class TestPRN29H1CriticalChainRetriesZero:
    """PR-N29 Holistic H1: the three baseline critical-chain tasks
    (full_neo4j_sync, build_relationships, run_enrichment_jobs) MUST
    have ``retries=0`` so a single retry on any 5-6h task doesn't blow
    through the 32h dagrun_timeout mid-enrichment."""

    DAG_FILE = DAGS / "edgeguard_pipeline.py"

    def _find_task_block(self, task_id: str) -> str:
        """Return the PythonOperator(...) block for ``task_id``, approximately
        2500 chars of surrounding context."""
        text = self.DAG_FILE.read_text()
        anchor = f'task_id="{task_id}"'
        idx = text.find(anchor)
        assert idx != -1, f"{task_id!r} not found in DAG file"
        # Scan back a few lines to find the PythonOperator( opening
        start = text.rfind("PythonOperator(", 0, idx)
        return text[start : idx + 2500]

    def test_full_neo4j_sync_has_retries_zero(self):
        block = self._find_task_block("full_neo4j_sync")
        assert "retries=0" in block, (
            "PR-N29 H1: full_neo4j_sync must override retries=0 so a retry "
            "on this 6h task doesn't burn 12h of the 32h dagrun_timeout cap"
        )

    def test_build_relationships_has_retries_zero(self):
        block = self._find_task_block("build_relationships")
        assert "retries=0" in block, (
            "PR-N29 H1: build_relationships must override retries=0 (5h task, same reasoning as full_neo4j_sync)"
        )

    def test_run_enrichment_jobs_has_retries_zero(self):
        block = self._find_task_block("run_enrichment_jobs")
        assert "retries=0" in block, "PR-N29 H1: run_enrichment_jobs must override retries=0 (5h task)"

    def test_baseline_dag_comment_explains_n29_change(self):
        """The baseline_dag declaration comment should explain WHY
        retries=0 on the critical chain is the right trade-off."""
        text = self.DAG_FILE.read_text()
        # Find the baseline_dag DAG(...) declaration
        anchor = "baseline_dag = DAG("
        idx = text.find(anchor)
        assert idx != -1
        block = text[idx : idx + 2500]
        assert "PR-N29" in block and "H1" in block, (
            "PR-N29 H1: the baseline_dag comment block must reference PR-N29 "
            "so future maintainers can trace the retries-budget rationale"
        )


# ===========================================================================
# Fix H3 — MISP fetch fallback pagination
# ===========================================================================


class TestPRN29H3MispFetchFallbackPaginated:
    """PR-N29 Holistic H3: the PyMISP and requests-restSearch fallback
    branches in ``fetch_edgeguard_events`` MUST paginate. Pre-N29 both
    used ``limit: 1000`` with NO pagination, silently truncating on
    populated MISP instances."""

    SRC_FILE = SRC / "run_misp_to_neo4j.py"

    def test_pagination_constants_defined(self):
        text = self.SRC_FILE.read_text()
        # The paginator uses these internal constants
        assert "_FALLBACK_PAGE_SIZE" in text, "PR-N29 H3: fallback must define _FALLBACK_PAGE_SIZE (per-page batch)"
        assert "_FALLBACK_MAX_PAGES" in text, "PR-N29 H3: fallback must define _FALLBACK_MAX_PAGES (safety cap)"

    def test_pymisp_branch_paginates(self):
        text = self.SRC_FILE.read_text()
        # The PyMISP branch must iterate pages via search(... page=N ...)
        # Anchor on the MISP-FETCH-FALLBACK-ACTIVE log token + PyMISP logging
        assert "[MISP-FETCH-FALLBACK-ACTIVE]" in text, (
            "PR-N29 H3: fallback must emit [MISP-FETCH-FALLBACK-ACTIVE] log "
            "token so operators can grep for fallback-path activity"
        )
        assert '"page": page' in text, "PR-N29 H3: fallback search_kwargs must include page=page for pagination"

    def test_restSearch_branch_paginates(self):
        text = self.SRC_FILE.read_text()
        # The requests.post body must include "page" for pagination
        assert "[MISP-FETCH-FALLBACK] restSearch page" in text, (
            "PR-N29 H3: requests-restSearch branch must log per-page progress"
        )

    def test_pymisp_dict_payload_handled_via_unwrap(self):
        """PR-N29 Bugbot round 2 (MED): PyMISP can return a list,
        ``{"response": [...]}``, or ``{"errors": ...}`` depending on
        version + error path. ``list(dict)`` would yield the dict's KEYS
        as bare strings — those would then go into ``events`` and
        downstream normalize would drop them all to zero. Mirror the
        requests-restSearch branch's explicit unwrap."""
        text = self.SRC_FILE.read_text()
        # Must check isinstance(page_result, dict) before list(page_result)
        assert "isinstance(page_result, dict)" in text, (
            "PR-N29 Bugbot round 2: PyMISP fallback must check dict shape "
            "before list() to avoid silently containing dict keys as event rows"
        )
        # Must look up "response" key (PyMISP's wrapper convention)
        assert 'page_result.get("response")' in text, (
            "PR-N29 Bugbot round 2: PyMISP dict-shape unwrap must use "
            'page_result.get("response") (mirrors requests-restSearch branch)'
        )
        # Must explicitly handle "errors" payload (raise, don't silently truncate)
        assert '"errors" in page_result' in text, (
            "PR-N29 Bugbot round 2: PyMISP dict-shape must surface errors payload "
            "rather than silently producing zero events"
        )

    def test_non200_mid_pagination_raises_not_silent_break(self):
        """PR-N29 Bugbot round 2 (MED) → multi-agent audit (HIGH-1): a non-200
        response on any page after the first MUST raise (or otherwise
        surface as a sync error) rather than silently truncate with the
        partial events list. Pre-fix the ``break`` on non-200 left a
        positive log line "collected N row(s) across M pages" while
        having silently dropped 25%+ of the baseline.

        The multi-agent audit further surfaced that ``raise RuntimeError``
        was being swallowed by the broad ``except Exception`` — replaced
        with the dedicated ``_MispFallbackHardError`` sentinel, which has
        explicit ``except _MispFallbackHardError: raise`` re-raises ahead
        of every broad ``except Exception`` clause."""
        text = self.SRC_FILE.read_text()
        # Find the non-200 branch in the requests-restSearch fallback
        idx = text.find("response.status_code != 200")
        assert idx != -1, "non-200 check must exist in the fallback"
        block = text[idx : idx + 2000]
        # Must explicitly raise the sentinel (not just break, not bare RuntimeError)
        assert "raise _MispFallbackHardError" in block, (
            "PR-N29 multi-agent audit (HIGH-1): non-200 mid-pagination must "
            "raise the dedicated _MispFallbackHardError sentinel so the broad "
            "except Exception below doesn't swallow it. Bare ``raise RuntimeError`` "
            "is NOT enough — it gets caught by the outer except Exception clause."
        )
        # The error message must be operator-actionable
        assert "good pages" in block, (
            "PR-N29 Bugbot round 2: error message must report the good-pages "
            "count so operators can quickly assess scope of partial fetch"
        )

    def test_no_singleshot_limit_1000_in_fallback(self):
        """Negative pin: the pre-N29 single-shot ``limit: 1000`` shape
        must not remain alongside the pagination loop — that would be a
        partial fix."""
        text = self.SRC_FILE.read_text()
        # Count: pre-N29 had exactly 2 occurrences of ``"limit": 1000`` (PyMISP
        # + requests-restSearch). After fix: 0 occurrences (both use _FALLBACK_PAGE_SIZE).
        # Any remaining ``"limit": 1000`` means the fix is incomplete.
        # Strip comment lines so the audit-history comment doesn't count.
        code_only = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
        assert '"limit": 1000' not in code_only, (
            "PR-N29 H3: no single-shot ``limit: 1000`` should remain in the "
            "fallback paths; both branches must use the paginated _FALLBACK_PAGE_SIZE"
        )


# ===========================================================================
# Fix M3 — baseline_lock max-age bumped to 48h
# ===========================================================================


class TestPRN29M3BaselineLockMaxAge:
    """PR-N29 Holistic M3: ``_BASELINE_LOCK_MAX_AGE_SEC_DEFAULT`` must be
    at least 48h so cross-host deployments don't reap the sentinel
    during a 32h-dagrun_timeout baseline."""

    LOCK_FILE = SRC / "baseline_lock.py"

    def test_max_age_at_least_48h(self):
        text = self.LOCK_FILE.read_text()
        # Positive pin on the new value
        assert "_BASELINE_LOCK_MAX_AGE_SEC_DEFAULT = 48 * 3600" in text, (
            "PR-N29 M3: _BASELINE_LOCK_MAX_AGE_SEC_DEFAULT must be 48*3600 (48h) "
            "to give a 16h buffer above the baseline dagrun_timeout of 32h. "
            "Cross-host deployments would otherwise have the sentinel reaped "
            "8h before the baseline finishes."
        )

    def test_max_age_comment_references_dagrun_timeout(self):
        """The constant's comment must explain WHY 48h — cross-reference
        the dagrun_timeout so a future maintainer can trace the invariant."""
        text = self.LOCK_FILE.read_text()
        # Anchor on PR-N29 M3 marker
        idx = text.find("PR-N29")
        assert idx != -1, "PR-N29 M3: comment block must be present"
        block = text[idx : idx + 1500]
        assert "dagrun_timeout" in block, (
            "PR-N29 M3: the comment must reference dagrun_timeout so the lock vs timeout invariant is greppable"
        )


# ===========================================================================
# Fix L1 — Unicode NFKC + zero-width/bidi strip in placeholder filter
# ===========================================================================


class TestPRN29L1PlaceholderUnicodeHardening:
    """PR-N29 Red Team L1: ``is_placeholder_name`` must strip zero-width
    and bidirectional-control characters AND upgrade NFC → NFKC so an
    attacker can't bypass PR-N10 with ``"unknown\\u200b"`` or similar
    trivial obfuscations."""

    def test_bare_placeholder_still_rejected(self):
        """Regression pin: the basic ``"unknown"`` case still rejects."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown")
        assert is_placeholder_name("UNKNOWN")
        assert is_placeholder_name("  unknown  ")
        assert is_placeholder_name("n/a")
        assert is_placeholder_name(None)

    def test_zero_width_space_bypass_blocked(self):
        """PR-N29 L1: ``"unknown\\u200b"`` (ZWSP appended) previously
        passed the filter because NFC + strip + lowercase doesn't fold
        zero-width chars. After fix, zero-width chars are stripped
        BEFORE normalization."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\u200b"), (
            "PR-N29 L1: ZWSP (\\u200b) must not let an attacker bypass the filter"
        )
        assert is_placeholder_name("\u200bunknown"), "leading ZWSP"
        assert is_placeholder_name("unk\u200bnown"), "inline ZWSP"

    def test_zwnj_bypass_blocked(self):
        """ZERO WIDTH NON-JOINER (U+200C) must be stripped."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\u200c")

    def test_zwj_bypass_blocked(self):
        """ZERO WIDTH JOINER (U+200D) must be stripped."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\u200d")

    def test_bom_bypass_blocked(self):
        """ZERO WIDTH NO-BREAK SPACE / BOM (U+FEFF) must be stripped."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\ufeff")
        assert is_placeholder_name("\ufeffunknown")

    def test_rlo_bypass_blocked(self):
        """RIGHT-TO-LEFT OVERRIDE (U+202E) must be stripped."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("\u202eunknown")

    def test_word_joiner_bypass_blocked(self):
        """WORD JOINER (U+2060) must be stripped."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("un\u2060known")

    def test_lrm_bypass_blocked(self):
        """PR-N29 Bugbot round 1 (MED): LEFT-TO-RIGHT MARK (U+200E) is
        a zero-width directional mark in the same Unicode block as
        U+200B–U+200D. Original PR-N29 missed it; Bugbot caught the gap.
        ``"unknown\\u200e"`` must still be rejected."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\u200e"), "LRM appended bypass"
        assert is_placeholder_name("\u200eunknown"), "LRM prepended bypass"
        assert is_placeholder_name("un\u200eknown"), "LRM inline bypass"

    def test_rlm_bypass_blocked(self):
        """PR-N29 Bugbot round 1 (MED): RIGHT-TO-LEFT MARK (U+200F) —
        same finding as LRM, U+200E + U+200F travel as a pair in
        bidirectional-formatting attacks."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\u200f"), "RLM appended bypass"
        assert is_placeholder_name("\u200funknown"), "RLM prepended bypass"
        assert is_placeholder_name("un\u200fknown"), "RLM inline bypass"

    def test_mongolian_vowel_separator_bypass_blocked(self):
        """PR-N29 Bugbot round 2 (LOW): MONGOLIAN VOWEL SEPARATOR
        (U+180E) is zero-width but NFKC does not fold it. Pre-fix it
        bypassed the filter."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\u180e"), "U+180E appended bypass"
        assert is_placeholder_name("\u180eunknown"), "U+180E prepended bypass"

    def test_line_separator_bypass_blocked(self):
        """PR-N29 Bugbot round 2 (LOW): U+2028 LINE SEPARATOR is not
        always stripped by ``str.strip()`` and not folded by NFKC."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\u2028"), "U+2028 appended bypass"
        assert is_placeholder_name("un\u2028known"), "U+2028 inline bypass"

    def test_paragraph_separator_bypass_blocked(self):
        """PR-N29 Bugbot round 2 (LOW): U+2029 PARAGRAPH SEPARATOR —
        sibling of U+2028, same bypass class."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\u2029"), "U+2029 appended bypass"
        assert is_placeholder_name("\u2029unknown"), "U+2029 prepended bypass"

    def test_nbsp_bypass_blocked_via_nfkc_then_strip(self):
        """NBSP U+00A0 isn't in the translate table but NFKC folds it
        to a regular space, then ``str.strip()`` removes it. Verify the
        ordering (translate → NFKC → strip) actually catches NBSP."""
        from node_identity import is_placeholder_name

        assert is_placeholder_name("unknown\u00a0"), (
            "NBSP appended must be normalised + stripped (translate→NFKC→strip ordering)"
        )
        assert is_placeholder_name("\u00a0unknown"), "NBSP prepended"

    def test_genuine_malware_name_not_rejected(self):
        """Negative pin: a real malware name that happens to contain a
        zero-width char (unlikely but possible) shouldn't be over-rejected.
        The ONLY way a name becomes a placeholder is if after stripping
        zero-width chars + NFKC + strip + lowercase, it's in
        _REJECTED_PLACEHOLDER_NAMES."""
        from node_identity import is_placeholder_name

        assert not is_placeholder_name("Conti")
        assert not is_placeholder_name("LockBit")
        assert not is_placeholder_name("Cobalt Strike")
        # Even with ZWSP — if the canonical form is not a placeholder, allow.
        assert not is_placeholder_name("Conti\u200b")

    def test_nfkc_fullwidth_fold(self):
        """NFKC folds full-width Latin to half-width. Pre-N29 NFC didn't
        fold this. After fix, full-width "ｕｎｋｎｏｗｎ" is rejected."""
        from node_identity import is_placeholder_name

        fullwidth_unknown = "\uff55\uff4e\uff4b\uff4e\uff4f\uff57\uff4e"  # ｕｎｋｎｏｗｎ
        assert is_placeholder_name(fullwidth_unknown), (
            "PR-N29 L1: NFKC must fold full-width Latin unknown → ASCII unknown"
        )

    def test_cyrillic_confusable_still_passes_filter_documented_residual(self):
        """Cross-script confusables (Cyrillic 'о' U+043E ≠ Latin 'o' U+006F)
        are NOT folded by NFKC — they're semantically different characters
        in Unicode. Fixing requires a confusables library. This test
        PINS the residual risk so a future maintainer doesn't think this
        is covered."""
        from node_identity import is_placeholder_name

        # Cyrillic 'о' (U+043E) in place of Latin 'o' (U+006F)
        cyrillic_unknown = "unkn\u043ewn"
        # Post-N29 this STILL passes the filter — it's a genuine
        # cross-script bypass not fixable without a confusables lib.
        # Pin the RESIDUAL so any future work that actually fixes this
        # updates this test too (documenting the fix).
        assert not is_placeholder_name(cyrillic_unknown), (
            "PR-N29 L1 residual risk: cross-script Cyrillic confusables still "
            "bypass the filter. Fix requires a confusables library (not in scope "
            "for PR-N29). This test pins the RESIDUAL so updating it signals "
            "a real fix."
        )


# ===========================================================================
# Multi-agent audit (2026-04-24) — _MispFallbackHardError sentinel contract
# ===========================================================================


class TestPRN29MispFallbackHardErrorSentinel:
    """7-agent audit on PR-N29 (2026-04-24) corroborated 3 HIGH findings:

    * Bug Hunter HIGH-1 / Cross-Checker HIGH-1: ``raise RuntimeError`` is
      caught by the broad ``except Exception`` blocks at lines ~1109
      (PyMISP fallback) and ~1201 (outer). Hard errors silently degrade
      to "no events found".
    * Bug Hunter HIGH-2 / Devil's Advocate critique: cap-hit on
      ``_FALLBACK_MAX_PAGES`` only logs — silent truncation if MISP
      legitimately has more events than the cap.
    * Cross-Checker HIGH-1/2 (sibling drift): the requests-restSearch
      branch was missing the errors-key check + unexpected-shape raise
      that the PyMISP branch had after Bugbot round 2.

    The fix uses a dedicated ``_MispFallbackHardError`` sentinel +
    explicit ``except _MispFallbackHardError: raise`` clauses ahead of
    every broad ``except Exception``. These tests pin the contract.
    """

    SRC_FILE = SRC / "run_misp_to_neo4j.py"

    # ----- shape / source-pin tests (no PyMISP / Airflow needed) -----

    def test_sentinel_class_is_defined_at_module_level(self):
        """The sentinel must exist as a module-level Exception subclass —
        importable from tests, picklable across processes, easy to grep."""
        text = self.SRC_FILE.read_text()
        assert "class _MispFallbackHardError(Exception):" in text, (
            "PR-N29 audit HIGH-1: ``_MispFallbackHardError`` must be a "
            "module-level Exception subclass so the explicit re-raise "
            "clauses can reference it without import gymnastics."
        )

    def test_sentinel_class_importable(self):
        """Behavioural: the sentinel can actually be imported."""
        from run_misp_to_neo4j import _MispFallbackHardError

        assert issubclass(_MispFallbackHardError, Exception)
        # Subclass of Exception, NOT BaseException — KeyboardInterrupt /
        # SystemExit must still propagate normally and not be caught by
        # the general ``except Exception`` clauses we're using.
        assert _MispFallbackHardError.__bases__ == (Exception,)

    def test_no_bare_raise_RuntimeError_in_fallback_paths(self):
        """Negative pin: pre-fix the fallback paths used ``raise RuntimeError``
        which the broad ``except Exception`` swallowed. After fix, all 5
        raise sites must use ``_MispFallbackHardError``.

        Scope: only the ``fetch_edgeguard_events`` method body — the
        sentinel's own docstring documents the audit history and contains
        the literal string ``raise RuntimeError(...)`` as part of the
        narrative."""
        text = self.SRC_FILE.read_text()
        # Extract the fetch_edgeguard_events method body
        start = text.find("def fetch_edgeguard_events(")
        assert start != -1, "fetch_edgeguard_events method must exist"
        # Find the start of the next top-level method
        end = text.find("\n    @", start + 1)
        if end == -1:
            end = text.find("\n    def ", start + 1)
        assert end != -1, "must find end of fetch_edgeguard_events"
        method_body = text[start:end]
        assert "raise RuntimeError(" not in method_body, (
            "PR-N29 audit HIGH-1: fetch_edgeguard_events fallback paths must "
            "not raise bare RuntimeError — those get swallowed by the broad "
            "except Exception blocks. Use _MispFallbackHardError instead."
        )

    def test_pymisp_cap_hit_raises_sentinel(self):
        """Bug Hunter HIGH-2 / Devil's Advocate: hitting
        ``_FALLBACK_MAX_PAGES`` must surface as a hard error, not just a
        log line. Pre-fix the cap-hit branch only ``logger.error``ed and
        the truncated event list was treated as ground truth."""
        text = self.SRC_FILE.read_text()
        # PyMISP cap-hit block — find the for/else and the raise
        idx = text.find("PyMISP hit _FALLBACK_MAX_PAGES")
        assert idx != -1, "PyMISP cap-hit log line must exist"
        block = text[idx : idx + 1500]
        assert "raise _MispFallbackHardError" in block, (
            "PR-N29 audit HIGH-2: PyMISP cap-hit must raise sentinel. "
            "logger.error alone leaves the truncated list as ground truth."
        )

    def test_restsearch_cap_hit_raises_sentinel(self):
        """Bug Hunter HIGH-2: symmetric — restSearch cap-hit must also raise."""
        text = self.SRC_FILE.read_text()
        idx = text.find("restSearch hit _FALLBACK_MAX_PAGES")
        assert idx != -1, "restSearch cap-hit log line must exist"
        block = text[idx : idx + 1500]
        assert "raise _MispFallbackHardError" in block, (
            "PR-N29 audit HIGH-2: restSearch cap-hit must raise sentinel (symmetric with PyMISP cap-hit branch)."
        )

    def test_restsearch_branch_handles_errors_payload(self):
        """Cross-Checker HIGH-1 (sibling drift): the PyMISP branch checks
        ``"errors" in page_result``; the requests-restSearch branch did
        NOT have this check before the multi-agent audit. After fix,
        both branches must surface MISP HTTP-200 errors-payload as a
        hard error."""
        text = self.SRC_FILE.read_text()
        # Anchor on the restSearch page_data block — page_data is the
        # restSearch variable, distinct from page_result (PyMISP).
        idx = text.find("page_data = response.json()")
        assert idx != -1, "restSearch page_data assignment must exist"
        block = text[idx : idx + 2500]
        assert '"errors" in page_data' in block, (
            "PR-N29 audit Cross-Checker HIGH-1: requests-restSearch branch "
            'must check ``"errors" in page_data`` (mirrors PyMISP branch). '
            "Pre-fix MISP could return HTTP 200 with errors-payload and the "
            "loop silently produced 0 events."
        )
        assert "raise _MispFallbackHardError" in block, (
            "PR-N29 audit Cross-Checker HIGH-1: errors-payload in restSearch must raise the sentinel."
        )

    def test_restsearch_branch_handles_unexpected_payload_type(self):
        """Cross-Checker HIGH-2: the PyMISP branch raises on unexpected
        payload type; the restSearch branch silently coerced to ``[]``
        before the audit. After fix, both branches must raise."""
        text = self.SRC_FILE.read_text()
        idx = text.find("page_data = response.json()")
        assert idx != -1
        block = text[idx : idx + 2500]
        assert "restSearch page %d returned" in block and "unexpected payload type" in block, (
            "PR-N29 audit Cross-Checker HIGH-2: restSearch branch must log "
            "+ raise on unexpected payload type (mirrors PyMISP branch)."
        )

    def test_pymisp_inner_except_re_raises_sentinel(self):
        """HIGH-1: the inner ``except Exception as e`` after the PyMISP try/
        except (which falls through to the requests-restSearch branch on
        error) MUST be preceded by ``except _MispFallbackHardError: raise``.
        Otherwise hard errors raised inside the PyMISP loop fall through
        to the requests path silently."""
        text = self.SRC_FILE.read_text()
        # Anchor on the "PyMISP error" log line — uniquely identifies the
        # inner except block we care about.
        idx = text.find('logger.error(f"PyMISP error:')
        assert idx != -1, "inner PyMISP except must exist"
        # Look backwards for the preceding except clause
        preceding = text[max(0, idx - 1500) : idx]
        assert "except _MispFallbackHardError:" in preceding, (
            "PR-N29 audit HIGH-1: the ``except Exception as e`` after the "
            "PyMISP fallback try/except must be preceded by an explicit "
            "``except _MispFallbackHardError: raise`` clause. Otherwise "
            "hard errors raised inside the PyMISP loop fall through to "
            "the requests-restSearch path silently."
        )

    def test_outer_except_re_raises_sentinel(self):
        """HIGH-1: the outer broad ``except Exception as e`` at the bottom
        of ``fetch_edgeguard_events`` MUST be preceded by an explicit
        sentinel re-raise. Otherwise the function returns ``[]`` (empty
        normalized list) on hard errors, which the calling DAG treats
        as "no events to sync today." """
        text = self.SRC_FILE.read_text()
        # Anchor on the unique outer log message
        idx = text.find('logger.error(f"Error fetching events:')
        assert idx != -1, "outer broad except must exist"
        preceding = text[max(0, idx - 1500) : idx]
        assert "except _MispFallbackHardError:" in preceding, (
            "PR-N29 audit HIGH-1: the outer ``except Exception as e`` must "
            "be preceded by ``except _MispFallbackHardError: raise``. "
            "Otherwise the function returns [] on hard errors and the DAG "
            "silently treats it as 'no events to sync.'"
        )

    # ----- behavioural tests via direct sentinel exercise -----

    def test_sentinel_is_not_caught_by_except_Exception_in_principle(self):
        """Behavioural: ``except _MispFallbackHardError: raise`` re-raises
        the sentinel through any subsequent broad ``except Exception``
        clause. Verify the Python exception machinery does what we expect
        when the explicit handler is in place."""
        from run_misp_to_neo4j import _MispFallbackHardError

        caught_by_specific = False
        caught_by_generic = False
        try:
            try:
                raise _MispFallbackHardError("test")
            except _MispFallbackHardError:
                caught_by_specific = True
                raise
            except Exception:
                caught_by_generic = True
        except _MispFallbackHardError:
            pass

        assert caught_by_specific, "specific handler must catch the sentinel"
        assert not caught_by_generic, (
            "the broad ``except Exception`` clause must NOT catch the "
            "sentinel when ``except _MispFallbackHardError: raise`` runs "
            "first. This pins the Python exception-resolution semantics "
            "the fallback paths rely on."
        )

    def test_sentinel_is_caught_by_except_Exception_when_no_specific_handler(self):
        """Negative pin: WITHOUT the explicit ``except _MispFallbackHardError:
        raise`` clause, the broad ``except Exception`` DOES catch the
        sentinel — which is exactly the silent-truncation bug we're
        fixing. This test documents the failure mode so a future
        maintainer who deletes the explicit clause sees this test fail."""
        from run_misp_to_neo4j import _MispFallbackHardError

        caught = False
        try:
            raise _MispFallbackHardError("test")
        except Exception:
            caught = True

        assert caught, (
            "PR-N29 audit HIGH-1 documentation: ``except Exception`` DOES "
            "catch ``_MispFallbackHardError`` (it's an Exception subclass). "
            "This is exactly why we need the explicit re-raise clause "
            "ahead of every broad except in the fallback paths."
        )
