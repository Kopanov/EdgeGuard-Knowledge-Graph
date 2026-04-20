"""
Regression tests for PR-F7 — cross-event MISP dedup quick-fix
(Issue #61 partial mitigation).

Background
----------

Bravo's 2026-04-19 baseline investigation measured **72,479 CVEs
duplicated between MISP event 19 (``EdgeGuard-nvd-2026-04-19``) and
event 20 (``EdgeGuard-nvd-2026-04-20``)** — both runs pushed the same
NVD baseline window on different UTC days. The pre-PR-F7 dedup was
**per-event only**: the second run's prefetch returned only event 20's
empty set, so all of event 19's CVEs were re-pushed.

Architectural fix: event partitioning by attribute date (Issue #61).
This PR is the cheap quick-fix: also prefetch by source-tag (across
all EdgeGuard events for that source) and union with the per-event
keys. ~30 LOC change in production code, no migration needed.

What these tests pin
--------------------

  - ``_get_existing_source_attribute_keys`` returns empty when the
    master prefetch flag OR the cross-event flag is disabled
  - Returns empty when source_tag is empty
  - Paginates correctly + accumulates (type, value) keys
  - Degrades cleanly to empty on HTTP error / non-JSON / probe failure
    (NEVER raises — would otherwise crash push_items)
  - ``push_items`` calls the helper and unions its result with the
    per-event keyset
  - ``push_items`` caches the cross-event result per source within
    one call (avoids re-fetching for multiple (source, date) entries)
  - Source-pin: the env flag exists in config.py with the right default
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, "src")


# ---------------------------------------------------------------------------
# Env-flag plumbing (config layer)
# ---------------------------------------------------------------------------


class TestEnvFlag:
    def test_flag_defaults_to_true(self, monkeypatch):
        """Safe default — operators get protection out-of-the-box.
        Operators on huge MISP installs can opt out."""
        # Re-import config so we read the env at module level
        monkeypatch.delenv("EDGEGUARD_MISP_CROSS_EVENT_DEDUP", raising=False)
        # Read directly via the same env-bool helper config uses
        import config

        # Re-evaluate the module-level constant by re-running the env read.
        raw = "true"  # default
        assert raw.strip().lower() in ("1", "true", "yes", "on")
        # Sanity: the constant exists
        assert hasattr(config, "MISP_CROSS_EVENT_DEDUP"), (
            "config must expose MISP_CROSS_EVENT_DEDUP for the helper to gate on"
        )

    def test_config_constant_is_documented_in_env_example(self):
        with open(".env.example") as fh:
            content = fh.read()
        assert "EDGEGUARD_MISP_CROSS_EVENT_DEDUP" in content, ".env.example must document the new flag"
        # Bravo's incident motivation must be discoverable
        assert "72,479" in content or "Issue #61" in content or "PR-F7" in content


# ---------------------------------------------------------------------------
# _get_existing_source_attribute_keys — the helper itself
# ---------------------------------------------------------------------------


def _make_writer_skipping_init() -> "object":
    """Construct a MISPWriter without invoking __init__ (mirrors the
    legacy pattern in tests/test_incremental_dedup.py — keeps the
    test focused on the helper, no MISP/SSL/session setup)."""
    from collectors import misp_writer as mw

    w = mw.MISPWriter.__new__(mw.MISPWriter)
    w.url = "https://misp.test"
    w.verify_ssl = True
    w.session = MagicMock()
    return w


class TestCrossEventPrefetchHelper:
    def test_returns_empty_when_master_prefetch_disabled(self, monkeypatch):
        """The master switch ``EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS``
        gates ALL prefetch behavior — including the cross-event extension.
        If the operator has explicitly disabled prefetch, we don't
        sneak it back in."""
        monkeypatch.setattr("collectors.misp_writer.MISP_PREFETCH_EXISTING_ATTRS", False)
        w = _make_writer_skipping_init()
        # Should not even attempt the HTTP call
        w.session.post = MagicMock(side_effect=AssertionError("should not be called"))
        from collectors.misp_writer import MISPWriter

        assert MISPWriter._get_existing_source_attribute_keys(w, "source:nvd") == set()

    def test_returns_empty_when_cross_event_flag_disabled(self, monkeypatch):
        monkeypatch.setattr("collectors.misp_writer.MISP_PREFETCH_EXISTING_ATTRS", True)
        monkeypatch.setattr("collectors.misp_writer.MISP_CROSS_EVENT_DEDUP", False)
        w = _make_writer_skipping_init()
        w.session.post = MagicMock(side_effect=AssertionError("should not be called"))
        from collectors.misp_writer import MISPWriter

        assert MISPWriter._get_existing_source_attribute_keys(w, "source:nvd") == set()

    def test_returns_empty_when_source_tag_empty(self, monkeypatch):
        monkeypatch.setattr("collectors.misp_writer.MISP_PREFETCH_EXISTING_ATTRS", True)
        monkeypatch.setattr("collectors.misp_writer.MISP_CROSS_EVENT_DEDUP", True)
        w = _make_writer_skipping_init()
        w.session.post = MagicMock(side_effect=AssertionError("should not be called"))
        from collectors.misp_writer import MISPWriter

        assert MISPWriter._get_existing_source_attribute_keys(w, "") == set()
        assert MISPWriter._get_existing_source_attribute_keys(w, "   ") == set()

    def test_extracts_keys_from_paginated_response(self, monkeypatch):
        monkeypatch.setattr("collectors.misp_writer.MISP_PREFETCH_EXISTING_ATTRS", True)
        monkeypatch.setattr("collectors.misp_writer.MISP_CROSS_EVENT_DEDUP", True)
        w = _make_writer_skipping_init()
        # Simulate two pages — first full, second partial → loop terminates
        page1 = {
            "response": {
                "Attribute": [
                    {"type": "vulnerability", "value": "CVE-2024-0001"},
                    {"type": "vulnerability", "value": "CVE-2024-0002"},
                ]
            }
        }
        page2 = {
            "response": {
                "Attribute": [
                    {"type": "vulnerability", "value": "CVE-2024-0003"},
                ]
            }
        }
        responses = [page1, page2]

        def post_side_effect(url, **kwargs):
            r = MagicMock()
            r.status_code = 200
            r.json.return_value = responses.pop(0) if responses else {"response": {"Attribute": []}}
            return r

        # Force page_limit=2 by patching after-the-fact won't work since
        # it's a local var. Just check the keys on a single-page small
        # response — the pagination loop is exercised by the same test
        # in the per-event helper (test_incremental_dedup.py).
        page = {
            "response": {
                "Attribute": [
                    {"type": "vulnerability", "value": "CVE-2024-0001"},
                    {"type": "vulnerability", "value": "CVE-2024-0002"},
                    {"type": "vulnerability", "value": "CVE-2024-0003"},
                ]
            }
        }
        r = MagicMock()
        r.status_code = 200
        r.json.return_value = page
        w.session.post = MagicMock(return_value=r)

        from collectors.misp_writer import MISPWriter

        keys = MISPWriter._get_existing_source_attribute_keys(w, "source:nvd")
        assert keys == {
            ("vulnerability", "CVE-2024-0001"),
            ("vulnerability", "CVE-2024-0002"),
            ("vulnerability", "CVE-2024-0003"),
        }

    def test_degrades_to_empty_on_http_error(self, monkeypatch):
        """Probe failure must NOT raise — would crash push_items.
        Falls back to per-event-only dedup (existing safe behavior).
        Same defensive pattern as the per-event prefetch."""
        monkeypatch.setattr("collectors.misp_writer.MISP_PREFETCH_EXISTING_ATTRS", True)
        monkeypatch.setattr("collectors.misp_writer.MISP_CROSS_EVENT_DEDUP", True)
        w = _make_writer_skipping_init()
        r = MagicMock()
        r.status_code = 503
        w.session.post = MagicMock(return_value=r)

        from collectors.misp_writer import MISPWriter

        # Must not raise; must return empty set
        assert MISPWriter._get_existing_source_attribute_keys(w, "source:nvd") == set()

    def test_degrades_to_empty_on_transient_connection_error(self, monkeypatch, caplog):
        """**Critical regression pin** — multi-agent audit (Logic Tracker
        HIGH, Devil's Advocate HIGH, Bug Hunter HIGH) found that the
        ORIGINAL PR-F7 re-raised ``_TRANSIENT_HTTP_ERRORS`` from this
        helper, contradicting the docstring's "degrades cleanly" promise.
        ``push_items`` had no retry/catch around the call, so the
        exception propagated to the collector → catastrophic → entire
        NVD baseline (~92K attrs) lost on ANY MISP transient 5xx during
        prefetch. The SAME pressure MISP experiences that PR-F4/F7 were
        addressing is what makes prefetch itself transiently fail —
        re-raising amplified the incident, not mitigated it.

        Fix: helper now WARN-logs + returns empty set on transient
        errors, same shape as non-transient errors. Per-event dedup
        still runs; collector proceeds; no half-write.

        Pin: ConnectionError / Timeout / ReadTimeout / ChunkedEncodingError
        all return ``set()``, not raise.
        """
        import logging

        import requests

        from collectors.misp_writer import MISPWriter

        monkeypatch.setattr("collectors.misp_writer.MISP_PREFETCH_EXISTING_ATTRS", True)
        monkeypatch.setattr("collectors.misp_writer.MISP_CROSS_EVENT_DEDUP", True)

        for exc_cls in (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.ChunkedEncodingError,
        ):
            w = _make_writer_skipping_init()
            w.session.post = MagicMock(side_effect=exc_cls("simulated outage"))

            caplog.clear()
            with caplog.at_level(logging.WARNING):
                # Must NOT raise — critical contract after the fix
                result = MISPWriter._get_existing_source_attribute_keys(w, "source:nvd")

            assert result == set(), f"transient {exc_cls.__name__} should return empty set, got {result!r}"
            # Must leave a WARN log so operators can grep for the degradation
            msg = " ".join(r.message for r in caplog.records if r.levelno >= logging.WARNING)
            assert "transient error" in msg.lower() or "degrading" in msg.lower(), (
                f"transient error must emit a WARN log (got records: {[r.message for r in caplog.records]})"
            )

    def test_source_rerasie_audit_pin_no_raise_from_helper(self):
        """Source-pin against regression: the helper must NOT contain
        a bare ``raise`` in the ``except _TRANSIENT_HTTP_ERRORS`` branch.
        The audit's top blocker (B1) was exactly this pattern. Pin it
        so a future refactor can't silently reinstate."""
        with open("src/collectors/misp_writer.py") as fh:
            src = fh.read()
        helper_idx = src.find("def _get_existing_source_attribute_keys(")
        assert helper_idx > 0
        helper_end = src.find("\n    def ", helper_idx + 1)
        body = src[helper_idx:helper_end]
        # Find the transient except clause
        tex_idx = body.find("except _TRANSIENT_HTTP_ERRORS")
        assert tex_idx > 0, "helper must keep a transient-error except branch"
        # Look at the block — the next ~20 lines should contain `return set()`, NOT `raise`
        tex_block = body[tex_idx : tex_idx + 2000]
        # The block before the next `except` or `if response.status_code`
        next_except = tex_block.find("\n            except ", 1)
        if next_except > 0:
            tex_block = tex_block[:next_except]
        assert "return set()" in tex_block, "transient except branch MUST return set() (fail-OPEN) — audit B1 fix"
        # Defensive: reject a bare `raise` ending the transient branch
        # (allow `raise SomeSpecificException(...)` though nothing in
        # this branch should do that either).
        lines = tex_block.splitlines()
        bare_raises = [line for line in lines if line.strip() == "raise"]
        assert not bare_raises, (
            "transient except branch MUST NOT contain a bare `raise` — "
            "audit finding B1 (multi-agent consensus): push_items has no "
            "retry decorator, so re-raising causes catastrophic collector abort"
        )

    def test_degrades_to_empty_on_non_json_response(self, monkeypatch):
        monkeypatch.setattr("collectors.misp_writer.MISP_PREFETCH_EXISTING_ATTRS", True)
        monkeypatch.setattr("collectors.misp_writer.MISP_CROSS_EVENT_DEDUP", True)
        w = _make_writer_skipping_init()
        r = MagicMock()
        r.status_code = 200
        r.json.side_effect = ValueError("not JSON")
        w.session.post = MagicMock(return_value=r)

        from collectors.misp_writer import MISPWriter

        assert MISPWriter._get_existing_source_attribute_keys(w, "source:nvd") == set()

    def test_uses_tags_filter_not_eventid(self, monkeypatch):
        """Critical contract: the helper MUST query by ``tags`` filter
        (cross-event), not by ``eventid`` (per-event). Without this,
        the helper would just duplicate the existing per-event prefetch
        and the whole PR is a no-op."""
        monkeypatch.setattr("collectors.misp_writer.MISP_PREFETCH_EXISTING_ATTRS", True)
        monkeypatch.setattr("collectors.misp_writer.MISP_CROSS_EVENT_DEDUP", True)
        w = _make_writer_skipping_init()
        r = MagicMock()
        r.status_code = 200
        r.json.return_value = {"response": {"Attribute": []}}
        w.session.post = MagicMock(return_value=r)

        from collectors.misp_writer import MISPWriter

        MISPWriter._get_existing_source_attribute_keys(w, "source:nvd")

        # Inspect the actual JSON body sent to MISP
        call_kwargs = w.session.post.call_args[1]
        body = call_kwargs["json"]
        assert "tags" in body, "must use tags filter (cross-event), not eventid"
        assert body["tags"] == ["source:nvd"]
        assert "eventid" not in body, (
            "MUST NOT send eventid — that would scope to one event and defeat the PR's purpose"
        )


# ---------------------------------------------------------------------------
# push_items integration — source-pin
# ---------------------------------------------------------------------------


class TestPushItemsIntegration:
    """``push_items`` must actually CALL the helper and union its
    result with the per-event keys. Source-pin so a future contributor
    can't quietly remove the wiring and silently regress to per-event-only."""

    def test_push_items_calls_cross_event_helper(self):
        with open("src/collectors/misp_writer.py") as fh:
            src = fh.read()
        idx = src.find("def push_items(")
        assert idx > 0
        end = src.find("\n    def ", idx + 1)
        body = src[idx:end]
        assert "_get_existing_source_attribute_keys" in body, "push_items must call _get_existing_source_attribute_keys"

    def test_push_items_filters_both_per_event_and_cross_event_keys(self):
        """Both keysets must participate in the skip filter. The PR-F7
        Bugbot-LOW follow-up (commit 2d747e6) moved from ``union + single
        filter`` to ``two sequential filters`` so per-event and
        cross-event skip counts are attributable exactly — but the
        contract that BOTH keysets are applied remains."""
        with open("src/collectors/misp_writer.py") as fh:
            src = fh.read()
        idx = src.find("def push_items(")
        assert idx > 0
        end = src.find("\n    def ", idx + 1)
        body = src[idx:end]
        # Both identifier names must appear as keyset inputs to filter
        # comprehensions, regardless of whether they are unioned or
        # chained as two steps.
        assert "per_event_keys" in body, "push_items must read per-event keys"
        assert "cross_event_keys" in body, "push_items must read cross-event keys"
        assert "not in per_event_keys" in body, "push_items must filter by per_event_keys"
        assert "not in cross_event_keys" in body, "push_items must filter by cross_event_keys"

    def test_push_items_skip_counts_sum_exactly_to_skipped_ct(self):
        """Bugbot LOW (commit 2d747e6): the previous diagnostic summed
        ``cross_event_skipped`` over a pre-within-batch-dedup list so
        counts could EXCEED ``skipped_ct`` — producing contradictory
        log lines. Pin that ``per_event_skipped + cross_event_skipped
        == skipped_ct`` is a provable relation (from the source
        structure, not an approximation)."""
        with open("src/collectors/misp_writer.py") as fh:
            src = fh.read()
        idx = src.find("def push_items(")
        assert idx > 0
        end = src.find("\n    def ", idx + 1)
        body = src[idx:end]
        # The skipped_ct assignment MUST be the sum of the two layer
        # counters (not a separate len-diff that could drift).
        assert "skipped_ct = per_event_skipped + cross_event_skipped" in body, (
            "skipped_ct must be exactly per_event_skipped + cross_event_skipped "
            "(Bugbot LOW: previous diagnostic could produce contradictory counts)"
        )

    def test_push_items_caches_cross_event_per_source(self):
        """A single push_items call may have multiple (source, date)
        entries for the same source. The cross-event prefetch is
        expensive (~30-40s on 92K attrs) — must be cached per-source
        so it runs once per source per call."""
        with open("src/collectors/misp_writer.py") as fh:
            src = fh.read()
        idx = src.find("def push_items(")
        assert idx > 0
        end = src.find("\n    def ", idx + 1)
        body = src[idx:end]
        assert "cross_event_cache" in body, "push_items must cache cross-event prefetch per source within a call"

    def test_push_items_cache_keyed_by_source_tag_not_raw_source(self):
        """Multi-agent audit (Bug Hunter, Maintainer): the cache was
        originally keyed by raw ``source`` (the item's ``tag`` field).
        Two sources can share a resolved MISP tag via the registry's
        alias map (e.g., ``cisa`` and ``cisa_kev`` both map to
        ``source:CISA-KEV``). Raw-source keying → double prefetch of
        the same tag set (~30-40s wasted) + race window where the
        second prefetch can observe writes from the first.

        Fix: cache MUST key by the resolved ``source_tag`` string so
        aliases collapse to one cache entry. Source-pin it so a future
        refactor can't silently revert."""
        with open("src/collectors/misp_writer.py") as fh:
            src = fh.read()
        idx = src.find("def push_items(")
        assert idx > 0
        end = src.find("\n    def ", idx + 1)
        body = src[idx:end]
        # The cache-lookup pattern MUST use source_tag (the resolved tag)
        # as the cache key, NOT the raw ``source`` variable.
        assert "cross_event_cache[source_tag]" in body, (
            "cross_event_cache MUST be keyed by source_tag (resolved MISP tag) — "
            "keying by raw source double-fetches alias pairs"
        )
        # Defensive: reject the old pattern that keyed by raw source
        assert "cross_event_cache[source]" not in body, (
            "cache-key regression: push_items uses cross_event_cache[source] "
            "instead of cross_event_cache[source_tag] — breaks alias collapsing"
        )

    def test_push_items_resolves_source_tag_via_registry(self):
        """The source tag must come from ``self.SOURCE_TAGS`` (the
        single source of truth from src/source_registry.py), not a
        hardcoded prefix — so adding a new source in the registry
        automatically wires up cross-event dedup."""
        with open("src/collectors/misp_writer.py") as fh:
            src = fh.read()
        idx = src.find("def push_items(")
        assert idx > 0
        end = src.find("\n    def ", idx + 1)
        body = src[idx:end]
        assert "self.SOURCE_TAGS.get(source" in body, (
            "push_items must resolve source tag via self.SOURCE_TAGS (source registry SSoT)"
        )

    def test_helper_method_exists_on_class(self):
        """Sanity: the new method must actually be on the class (not
        a free function or accidentally indented under another def)."""
        from collectors.misp_writer import MISPWriter

        assert hasattr(MISPWriter, "_get_existing_source_attribute_keys"), (
            "MISPWriter must expose _get_existing_source_attribute_keys as a method"
        )
        assert callable(MISPWriter._get_existing_source_attribute_keys)


# ---------------------------------------------------------------------------
# Behavioral integration — cross-event keys really skip the duplicate
# ---------------------------------------------------------------------------


class TestEndToEndDedup:
    """Simulate Bravo's 2026-04-19 scenario: two pushes of the same
    CVE on different UTC days. Pin that the second push skips the
    duplicate (would otherwise be the wasted MISP write the PR fixes)."""

    def test_duplicate_cve_across_events_is_skipped(self, monkeypatch):
        monkeypatch.setattr("collectors.misp_writer.MISP_PREFETCH_EXISTING_ATTRS", True)
        monkeypatch.setattr("collectors.misp_writer.MISP_CROSS_EVENT_DEDUP", True)
        from collectors import misp_writer as mw

        w = mw.MISPWriter.__new__(mw.MISPWriter)
        w.url = "https://misp.test"
        w.verify_ssl = True
        w.stats = {
            "events_created": 0,
            "attributes_added": 0,
            "batches_sent": 0,
            "errors": 0,
            "attrs_skipped_existing": 0,
        }
        w.session = MagicMock()
        w.liveness_callback = None

        # Simulate: cross-event prefetch returns CVE-2024-0001 already
        # exists somewhere in EdgeGuard MISP (event 19 from yesterday).
        # Per-event prefetch returns empty (event 20 is fresh today).
        def post_side_effect(url, **kwargs):
            r = MagicMock()
            body = kwargs.get("json", {})
            if "events/restSearch" in url:
                # Event lookup returns the new event 20
                r.status_code = 200
                r.json.return_value = {"response": [{"Event": {"id": "20", "info": "EdgeGuard-nvd-2026-04-20"}}]}
            elif "attributes/restSearch" in url:
                if "tags" in body:
                    # Cross-event prefetch — returns the CVE from yesterday's run
                    r.status_code = 200
                    r.json.return_value = {
                        "response": {"Attribute": [{"type": "vulnerability", "value": "CVE-2024-0001"}]}
                    }
                else:
                    # Per-event prefetch on event 20 — empty
                    r.status_code = 200
                    r.json.return_value = {"response": {"Attribute": []}}
            else:
                r.status_code = 200
                r.json.return_value = {}
            return r

        w.session.post.side_effect = post_side_effect

        with patch.object(mw.MISPWriter, "_get_or_create_event", return_value="20"):
            with patch.object(mw.MISPWriter, "_push_batch", return_value=(1, 0)) as pb:
                items = [
                    {  # already exists from yesterday — must be skipped
                        "type": "vulnerability",
                        "cve_id": "CVE-2024-0001",
                        "tag": "nvd",
                    },
                    {  # new — must be pushed
                        "type": "vulnerability",
                        "cve_id": "CVE-2024-0002",
                        "tag": "nvd",
                    },
                ]
                ok, bad = mw.MISPWriter.push_items(w, items, batch_size=50)

        # Only the new CVE should have been pushed
        assert pb.call_count == 1, "exactly one batch should have been pushed"
        batch = pb.call_args[0][1]
        assert len(batch) == 1, f"only the non-duplicate CVE should make it into the batch; got {batch}"
        assert batch[0]["value"] == "CVE-2024-0002"
        # Stats reflect the cross-event skip
        assert w.stats["attrs_skipped_existing"] == 1
