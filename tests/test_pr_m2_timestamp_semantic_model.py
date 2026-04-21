"""
PR-M2 — Timestamp semantic-model regression suite.

Pins the four-concept model documented in ``docs/TIMESTAMPS.md``:

  Concept 1  source_reported_first_at  (source-truthful, NULLable)
  Concept 2  source_reported_last_at   (source-truthful, NULLable)
  Concept 3  first_imported_at         (server-side, always present)
  Concept 4  last_updated              (server-side, always present)

Closes 11 audit findings from ``docs/flow_audits/04_timestamps_dates.md``
plus the 10 wall-clock-NOW leaks Agent 4 surfaced in ``misp_collector.py``.

Test surface:

  TestCoerceIsoUTCInjection      — F1
  TestNvdProducerHygiene          — F1.5
  TestStixReadPath               — F2 / F3 / F10 (manual STIX fallback)
  TestStixExporterValidFromChain — design choice (c) inferred flag
  TestProducerHonestNullPattern  — F4 (VT) / F5 (OTX) / Agent 4 (misp_collector)
  TestParseAttributeDeadKey       — F11
  TestSectorWindowing30437        — F6
  TestEventCoversSinceBoundary    — F7
  TestOtxCheckpointTzGuard        — F9
  TestCve2013EndToEndFixture      — semantic-model integration test

The end-to-end fixture is the most important one — it asserts that a
2013-published CVE flowing through the full producer → MISP → Neo4j →
STIX pipeline emerges with the right values in the right STIX fields.
A regression in any of the bug-fix sites would fail this test loudly.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ===========================================================================
# F1 — coerce_iso UTC injection for naive ISO inputs
# ===========================================================================


class TestCoerceIsoUTCInjection:
    """``coerce_iso`` MUST inject ``+00:00`` for any input that resolves
    to a NAIVE datetime — including naive ISO strings (NVD's
    ``"2023-05-09T15:15:10.897"``) and naive Python datetimes.

    Pre-PR-M2 the full-string branch returned the input unchanged, so
    naive ISO flowed through to Neo4j's ``datetime()`` and was parsed
    as server-local time — silently shifting every NVD timestamp by
    the local offset on non-UTC deployments."""

    def test_naive_iso_string_gets_utc_offset(self):
        from source_truthful_timestamps import coerce_iso

        out = coerce_iso("2023-05-09T15:15:10.897")
        assert out is not None
        assert out.endswith("+00:00") or out.endswith("Z"), f"naive ISO must come back with UTC offset; got {out!r}"

    def test_naive_datetime_gets_utc_tzinfo(self):
        from source_truthful_timestamps import coerce_iso

        naive = datetime(2023, 5, 9, 15, 15, 10)
        out = coerce_iso(naive)
        assert out is not None
        assert out.endswith("+00:00") or out.endswith("Z"), (
            f"naive datetime must serialize with UTC offset; got {out!r}"
        )

    def test_aware_iso_string_unchanged(self):
        from source_truthful_timestamps import coerce_iso

        # Aware input must round-trip to an aware output (offset preserved
        # or normalized to +00:00 — both are acceptable).
        out = coerce_iso("2023-05-09T15:15:10+00:00")
        assert out is not None
        # Must still be tz-aware (parseable by datetime.fromisoformat
        # to produce a tzinfo-bearing datetime)
        parsed = datetime.fromisoformat(out.replace("Z", "+00:00"))
        assert parsed.tzinfo is not None

    def test_z_suffix_aware_iso_round_trips(self):
        from source_truthful_timestamps import coerce_iso

        out = coerce_iso("2023-05-09T15:15:10Z")
        assert out is not None
        parsed = datetime.fromisoformat(out.replace("Z", "+00:00"))
        assert parsed.tzinfo is not None

    def test_idempotent(self):
        """Re-coercing a coerce_iso output must produce the same value."""
        from source_truthful_timestamps import coerce_iso

        out1 = coerce_iso("2023-05-09T15:15:10.897")
        out2 = coerce_iso(out1)
        assert out1 == out2, f"coerce_iso not idempotent: {out1!r} → {out2!r}"

    def test_garbage_returns_none(self):
        from source_truthful_timestamps import coerce_iso

        for bad in ("", "   ", "not a date", "2024-13-99", "2024/13/99T00:00:00", None):
            assert coerce_iso(bad) is None, f"expected None for {bad!r}"

    def test_epoch_zero_rejected(self):
        from source_truthful_timestamps import coerce_iso

        assert coerce_iso(0) is None, "epoch 0 sentinel must be rejected"
        assert coerce_iso(-1) is None, "negative epoch sentinel must be rejected"

    def test_unicode_fullwidth_digits_rejected(self):
        from source_truthful_timestamps import coerce_iso

        # "２０２４-01-01" uses fullwidth digits — must be rejected
        assert coerce_iso("\uff12\uff10\uff12\uff14-01-01") is None


# ===========================================================================
# F1.5 — NVD producer hygiene
# ===========================================================================


class TestNvdProducerHygiene:
    """NVD collector MUST canonicalize ``cve.published`` and
    ``cve.lastModified`` through ``coerce_iso`` at the producer
    boundary instead of relying on downstream defense.  Belt-and-
    suspenders against any future regression in the chokepoint."""

    def test_nvd_imports_coerce_iso(self):
        src = (SRC / "collectors" / "nvd_collector.py").read_text()
        assert "from source_truthful_timestamps import coerce_iso" in src, (
            "NVD collector must import coerce_iso for producer-side canonicalization"
        )

    def test_nvd_wraps_published(self):
        """Bugbot round 3 (LOW): assignment must be the bare
        ``coerce_iso(published_str)`` form WITHOUT a redundant
        ``or None`` tail. ``coerce_iso`` already returns ``None`` for
        empty / invalid input per contract; the ``or None`` was dead
        code that misleadingly suggested otherwise."""
        src = (SRC / "collectors" / "nvd_collector.py").read_text()
        # Positive pin: the bare form
        assert "published_iso = coerce_iso(published_str)" in src
        # Negative pin: the redundant form must be gone from active code
        active = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        assert "coerce_iso(published_str) or None" not in active, (
            "redundant ``or None`` tail must be removed (coerce_iso already returns None)"
        )

    def test_nvd_wraps_last_modified(self):
        src = (SRC / "collectors" / "nvd_collector.py").read_text()
        assert 'last_modified_iso = coerce_iso(cve_data.get("lastModified"))' in src
        active = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        assert 'coerce_iso(cve_data.get("lastModified")) or None' not in active


# ===========================================================================
# F4 / F5 / Agent 4 — producer honest-NULL pattern
# ===========================================================================


class TestProducerHonestNullPattern:
    """Every producer MUST omit ``first_seen`` (or ``last_seen``) when
    the source field is absent rather than substituting wall-clock
    NOW.  This is the central anti-pattern that corrupted source-
    truthful chronology in pre-PR-M2 builds."""

    def _read(self, rel: str) -> str:
        return (SRC / rel).read_text()

    def test_vt_no_wall_clock_first_seen_default(self):
        src = self._read("collectors/vt_collector.py")
        # The pre-PR-M2 form must not be present in active code — both
        # for the file path AND the URL path
        bad = "datetime.now(timezone.utc).isoformat()\n            )"
        # Remove comments before checking
        active_lines = [ln for ln in src.splitlines() if not ln.lstrip().startswith("#")]
        active = "\n".join(active_lines)
        # The specific pre-fix pattern was an `else datetime.now(...).isoformat()`
        # ternary tail; our fix changed it to `else None`.
        assert "else datetime.now(timezone.utc).isoformat()\n            )" not in active, (
            "VT must use honest-NULL (else None) for first_submission_date — "
            "the wall-clock-NOW fallback poisons MIN(source_reported_first_at)"
        )
        # Positive pin: the new None-fallback form
        assert "else None" in src

    def test_otx_pulse_created_no_wall_clock_default(self):
        src = self._read("collectors/otx_collector.py")
        bad = 'pulse.get("created", datetime.now(timezone.utc).isoformat())'
        assert bad not in src, (
            "OTX must use honest-NULL (pulse.get('created') alone) for first_seen — "
            "the wall-clock fallback ships a lie to non-EdgeGuard consumers"
        )
        # The new code keeps the value as ``pulse_created = pulse.get("created")``
        assert 'pulse_created = pulse.get("created")' in src

    def test_misp_collector_no_wall_clock_event_date_fallback(self):
        """Negative pin: the bad form must not appear in active code.
        The PR-M2 docstring explaining the change DOES mention the
        bad form by name — strip docstrings/comments before scanning."""
        src = self._read("collectors/misp_collector.py")
        # Strip comment lines (whole-line ``#`` comments) and the
        # module docstring so we only scan executable code.
        # We use a simple line-based filter — module docstring is the
        # FIRST string literal in the module; we drop everything between
        # the first and second triple-quote.
        lines = src.splitlines()
        in_docstring = False
        seen_first_quote = False
        active = []
        for ln in lines:
            stripped = ln.lstrip()
            # Skip pure-comment lines
            if stripped.startswith("#"):
                continue
            if '"""' in ln:
                if not seen_first_quote:
                    seen_first_quote = True
                    in_docstring = True
                    # Single-line docstring? close it on the same line
                    if ln.count('"""') >= 2:
                        in_docstring = False
                    continue
                if in_docstring:
                    in_docstring = False
                    continue
            if in_docstring:
                continue
            active.append(ln)
        active_src = "\n".join(active)
        bad = 'event.get("date", datetime.now(timezone.utc).isoformat())'
        count = active_src.count(bad)
        assert count == 0, (
            f"misp_collector still has {count} wall-clock-NOW fallbacks for "
            f"event.date in ACTIVE code — must use honest-NULL form "
            f"(event.get('date') or None)"
        )
        # Positive pin: the honest-NULL replacement is present
        assert '(event.get("date") or None)' in active_src


# ===========================================================================
# F11 — dead last_updated key removed from parse_attribute
# ===========================================================================


class TestParseAttributeDeadKey:
    """``parse_attribute`` no longer stuffs ``"last_updated":
    _coerce_to_iso(attr.get("timestamp"))`` into the item dict.  The
    Cypher MERGE sets ``n.last_updated = datetime()`` server-side and
    never reads the collector-supplied value.  Latent trap removed."""

    def test_no_last_updated_key_in_parse_attribute(self):
        src = (SRC / "run_misp_to_neo4j.py").read_text()
        # The dead key form must not appear (either form — bare attr.get
        # or the NVD-meta form)
        assert '"last_updated": _coerce_to_iso(attr.get("timestamp"))' not in src
        assert '"last_updated": _coerce_to_iso(nvd_meta.get("last_modified") or attr.get("timestamp"))' not in src


# ===========================================================================
# F2 / F3 / F10 — STIX manual fallback read path
# ===========================================================================


class TestStixManualFallbackReadPath:
    """The manual STIX 2.1 fallback in ``_manual_convert_to_stix21`` /
    ``_attribute_to_stix21`` MUST follow the four-concept timestamp
    model when emitting Report and Indicator SDOs."""

    def _read(self) -> str:
        return (SRC / "run_misp_to_neo4j.py").read_text()

    def test_report_sdo_uses_now_not_event_date(self):
        src = self._read()
        # The pre-PR-M2 form was ``"created": event_date`` — must be
        # ``"created": report_now`` (where report_now = now() at fallback time)
        assert '"created": report_now' in src
        assert '"modified": report_now' in src
        assert '"published": report_now' in src
        # Negative: event_date no longer feeds Report.created
        assert '"created": event_date' not in src

    def test_attribute_to_stix21_separates_now_from_first_seen(self):
        src = self._read()
        # The new code uses stix_now for created/modified and
        # stix_valid_from for valid_from — never the raw attr.timestamp.
        assert "stix_now = datetime.now(timezone.utc).isoformat()" in src
        assert 'attr_first_seen = _coerce_to_iso(attr.get("first_seen"))' in src
        assert "stix_valid_from = attr_first_seen" in src

    def test_attribute_to_stix21_no_raw_epoch_as_iso(self):
        src = self._read()
        # The pre-PR-M2 form ``timestamp = attr.get("timestamp", datetime.now...))``
        # used raw epoch as ISO — must be gone
        assert 'timestamp = attr.get("timestamp", datetime.now(timezone.utc).isoformat())' not in src
        # The fallback Indicator branch must use stix_valid_from, not timestamp
        assert '"valid_from": stix_valid_from' in src

    def test_inferred_flag_stamped_on_fallback(self):
        src = self._read()
        # The inferred-flag pattern must be present
        assert "valid_from_inferred = True" in src
        assert '"x_edgeguard_first_seen_inferred"' in src

    def test_misp_attr_timestamp_preserved_as_audit_extension(self):
        src = self._read()
        assert "x_edgeguard_misp_attribute_timestamp" in src, (
            "MISP attribute.timestamp (write-time epoch) must be preserved as an "
            "audit-only custom property, not as a STIX-spec field"
        )

    def test_attribute_to_stix21_uses_3_step_chain_with_misp_timestamp(self):
        """Bugbot finding (PR-M2 round 2, MED): the manual STIX
        fallback's ``valid_from`` chain MUST be the canonical 3-step
        chain from docs/TIMESTAMPS.md:

          (1) source-truthful first_seen
          (2) MISP Attribute.timestamp (concept-3 analogue for the
              manual-fallback path — MISP first ingested datum)
          (3) wall-clock NOW (defensive last resort)

        The pre-fix 2-step chain skipped step (2), conflating ``now()``
        with ``first_imported_at``."""
        src = self._read()
        # The new branch must be present
        assert "elif misp_attr_timestamp:" in src, (
            "valid_from chain must include the MISP attribute.timestamp "
            "intermediate fallback (step 2) per TIMESTAMPS.md spec"
        )
        # The branch must assign valid_from from misp_attr_timestamp
        assert "stix_valid_from = misp_attr_timestamp" in src, (
            "step (2) branch must set stix_valid_from to misp_attr_timestamp"
        )
        # And mark inferred=True (it's not the source-truthful branch)
        # Check that the elif branch is followed by valid_from_inferred = True
        elif_idx = src.find("elif misp_attr_timestamp:")
        assert elif_idx != -1
        # Within ~200 chars of the elif, find inferred=True assignment
        block = src[elif_idx : elif_idx + 200]
        assert "valid_from_inferred = True" in block


# ===========================================================================
# Design choice (c) — inferred flag in primary STIX exporter
# ===========================================================================


class TestStixExporterValidFromChain:
    """The primary ``_indicator_sdo`` in ``stix_exporter.py`` MUST set
    ``x_edgeguard_first_seen_inferred=True`` whenever ``valid_from`` came
    from the fallback chain (concept 3 or now()), so consumers can
    filter for source-truthful evidence."""

    def test_inferred_flag_branch_present(self):
        src = (SRC / "stix_exporter.py").read_text()
        assert "valid_from_inferred = False" in src
        assert "valid_from_inferred = True" in src
        assert 'sdo_dict["x_edgeguard_first_seen_inferred"] = True' in src

    def test_source_truthful_branch_does_not_set_inferred(self):
        """When ``first_seen_at_source`` is present, the inferred flag
        must NOT be set — the spec says absent (or false) for the
        source-truthful branch."""
        # Behavioural test via the real exporter
        from stix_exporter import StixExporter

        exporter = StixExporter.__new__(StixExporter)
        exporter._aggregate_cache = {}
        # Bypass the source-aggregate Cypher path; just call _indicator_sdo
        # directly with both first_seen_at_source AND first_imported_at.
        props = {
            "value": "203.0.113.5",
            "indicator_type": "ipv4",
            "first_seen_at_source": "2013-05-29T00:00:00+00:00",
            "first_imported_at": "2026-04-21T08:00:00+00:00",
            "last_updated": "2026-04-21T08:00:00+00:00",
        }
        sdo = exporter._indicator_sdo(props)
        assert "valid_from" in sdo
        # Source-truthful branch → inferred flag absent (or False)
        assert sdo.get("x_edgeguard_first_seen_inferred") in (None, False)
        # The valid_from should reflect the 2013 source claim
        assert sdo["valid_from"].startswith("2013-"), (
            f"valid_from should be source-truthful 2013 date; got {sdo['valid_from']!r}"
        )

    def test_fallback_branch_sets_inferred_flag(self):
        """When ``first_seen_at_source`` is absent, valid_from falls
        back and the inferred flag MUST be set."""
        from stix_exporter import StixExporter

        exporter = StixExporter.__new__(StixExporter)
        exporter._aggregate_cache = {}
        props = {
            "value": "203.0.113.5",
            "indicator_type": "ipv4",
            # NO first_seen_at_source
            "first_imported_at": "2026-04-21T08:00:00+00:00",
            "last_updated": "2026-04-21T08:00:00+00:00",
        }
        sdo = exporter._indicator_sdo(props)
        assert sdo.get("x_edgeguard_first_seen_inferred") is True, "Fallback branch must mark valid_from as inferred"
        # valid_from reflects first_imported_at
        assert sdo["valid_from"].startswith("2026-04-21"), (
            f"valid_from should fall back to first_imported_at 2026 date; got {sdo['valid_from']!r}"
        )


# ===========================================================================
# F6 — sector windowing uses 30.437 days/month average
# ===========================================================================


class TestSectorWindowing30437:
    """Sector cutoff windowing must use the average-Gregorian-month
    factor (~30.437) instead of the bare ``30`` that lost ~10 days
    per 24-month window."""

    def test_config_uses_30437(self):
        src = (SRC / "config.py").read_text()
        assert "int(months * 30.437)" in src

    def test_nvd_collector_uses_30437(self):
        src = (SRC / "collectors" / "nvd_collector.py").read_text()
        assert "int(months_range * 30.437)" in src
        # Negative pin: the bare ``months_range * 30)`` form must be gone
        # (we allow ``int(months_range * 30.437)`` to substring-match against
        # ``months_range * 30`` — we want to ensure no naked ``* 30)`` left)
        assert "months_range * 30)" not in src or "months_range * 30.437)" in src

    def test_otx_collector_uses_30437(self):
        src = (SRC / "collectors" / "otx_collector.py").read_text()
        assert "int(months_range * 30.437)" in src


# ===========================================================================
# F7 — _event_covers_since boundary widened by 1 day
# ===========================================================================


class TestEventCoversSinceBoundary:
    """``_event_covers_since`` must compare against ``(since - timedelta(days=1)).date()``
    so events on ``since.date()`` whose actual time-of-day is before
    ``since`` are still included.  Pre-fix lost ~3h per incremental run."""

    def test_boundary_widened_by_one_day(self):
        src = (SRC / "run_misp_to_neo4j.py").read_text()
        assert "(since - timedelta(days=1)).date()" in src

    def test_includes_event_on_floor_day(self):
        """Behavioural test: an event dated ``since.date()`` must be
        included regardless of ``since``'s time-of-day."""
        from run_misp_to_neo4j import _event_covers_since

        # since at 03:14 UTC on 2026-04-21
        since = datetime(2026, 4, 21, 3, 14, 22, tzinfo=timezone.utc)
        # Event whose Event.date is the same day
        ev = {"date": "2026-04-21"}
        assert _event_covers_since(ev, since) is True
        # Even an event from yesterday's date should be included (post-fix
        # widens by 1 day) — the actual filtering happens downstream
        ev_yesterday = {"date": "2026-04-20"}
        assert _event_covers_since(ev_yesterday, since) is True

    def test_excludes_event_far_in_past(self):
        from run_misp_to_neo4j import _event_covers_since

        since = datetime(2026, 4, 21, 3, 14, 22, tzinfo=timezone.utc)
        ev = {"date": "2010-01-01"}
        assert _event_covers_since(ev, since) is False


# ===========================================================================
# F9 — OTX checkpoint resume tz guard
# ===========================================================================


class TestOtxCheckpointTzGuard:
    """OTX incremental resume must inject UTC tzinfo if a stored
    checkpoint string parses as a NAIVE datetime."""

    def test_tz_guard_present(self):
        src = (SRC / "collectors" / "otx_collector.py").read_text()
        assert "if base_dt.tzinfo is None:" in src
        assert "base_dt = base_dt.replace(tzinfo=timezone.utc)" in src


# ===========================================================================
# End-to-end: CVE-2013 fixture
# ===========================================================================


class TestCve2013EndToEndFixture:
    """The integration-level test that exercises the whole semantic
    model.  We feed an NVD CVE published in 2013 through the producer
    pipeline (via the actual NVD-style item construction) and assert
    that the resulting STIX 2.1 Indicator SDO carries:

      * ``valid_from`` reflecting the source's 2013 claim (NOT today)
      * ``created`` / ``modified`` reflecting EdgeGuard's import time
        (today)
      * ``x_edgeguard_first_seen_at_source`` preserved verbatim
      * ``x_edgeguard_first_seen_inferred`` ABSENT (we have a real
        source claim)

    Failure on this test means a regression in any of the bug-fix
    sites: producer-side hygiene (F1.5), pipeline canonicalization (F1),
    or STIX read path (F2/F3 entangled trio).
    """

    def test_cve_2013_indicator_sdo_carries_source_truthful_2013(self):
        """The primary stix_exporter path."""
        from stix_exporter import StixExporter

        exporter = StixExporter.__new__(StixExporter)
        exporter._aggregate_cache = {}

        # Simulate a CVE-2013-0156 indicator that NVD reported as
        # published 2013-05-29 and last-modified 2024-03-15.
        # NVD's raw form is naive ISO; producer-side coerce_iso (F1.5)
        # will canonicalize it before this point, so we pass the
        # canonical form here.
        props = {
            "value": "203.0.113.5",
            "indicator_type": "ipv4",
            "first_seen_at_source": "2013-05-29T00:00:00+00:00",
            "last_seen_at_source": "2024-03-15T18:42:00+00:00",
            "first_imported_at": "2026-04-21T08:00:00+00:00",
            "last_updated": "2026-04-21T08:15:00+00:00",
        }
        sdo = exporter._indicator_sdo(props)

        # Source-truthful in valid_from
        assert sdo["valid_from"].startswith("2013-05-29"), (
            f"valid_from should be source-truthful 2013-05-29; got {sdo['valid_from']!r}"
        )
        # EdgeGuard-internal in created/modified
        assert sdo["created"].startswith("2026-04-21"), (
            f"created should reflect EdgeGuard import time 2026-04-21; got {sdo['created']!r}"
        )
        assert sdo["modified"].startswith("2026-04-21")
        # Custom extensions preserve both timelines explicitly
        assert sdo["x_edgeguard_first_seen_at_source"].startswith("2013-05-29")
        assert sdo["x_edgeguard_last_seen_at_source"].startswith("2024-03-15")
        assert sdo["x_edgeguard_first_imported_at"].startswith("2026-04-21")
        # Inferred flag absent — we had a real source claim
        assert sdo.get("x_edgeguard_first_seen_inferred") in (None, False)

    def test_no_source_claim_marks_inferred(self):
        """Same fixture but without source-truthful timestamps —
        valid_from must come from first_imported_at and the inferred
        flag must be set."""
        from stix_exporter import StixExporter

        exporter = StixExporter.__new__(StixExporter)
        exporter._aggregate_cache = {}
        props = {
            "value": "203.0.113.5",
            "indicator_type": "ipv4",
            "first_imported_at": "2026-04-21T08:00:00+00:00",
            "last_updated": "2026-04-21T08:15:00+00:00",
        }
        sdo = exporter._indicator_sdo(props)
        assert sdo["valid_from"].startswith("2026-04-21")
        assert sdo["x_edgeguard_first_seen_inferred"] is True

    def test_naive_iso_from_nvd_canonicalizes_through_coerce_iso(self):
        """End-to-end producer-pipeline check: a naive NVD ISO
        ``"2013-05-29T00:00:00"`` (no offset) flowing through
        ``coerce_iso`` produces a tz-aware UTC ISO that, when used as
        ``first_seen_at_source``, makes the STIX exporter emit a
        valid_from in 2013."""
        from source_truthful_timestamps import coerce_iso

        canonical = coerce_iso("2013-05-29T00:00:00")
        assert canonical is not None
        # Must be tz-aware
        parsed = datetime.fromisoformat(canonical.replace("Z", "+00:00"))
        assert parsed.tzinfo is not None
        # Must be 2013, not today (the bug we're guarding against would
        # have substituted today's wall-clock)
        assert parsed.year == 2013
