"""PR follow-up — Prometheus counters for the source-truthful pipeline.

Spawned-task chip 5b from the PR #41 audit closed an observability gap:
zero counters in ``src/metrics_server.py`` matched ``first_seen``,
``first_imported``, ``source_reported``, or ``source_truthful``. Operators
had no signal on:

- which sources actually supply per-source first/last_seen vs. emit
  honest-NULL (Layer 1 + Layer 2 both empty)
- the failure-mode distribution of ``coerce_iso``
  (sentinel epochs vs. malformed strings vs. overflow)
- upstream feed bugs producing future-dated timestamps that get clamped

This module pins the four new counters (defined in
``src/metrics_server.py``) and the wiring at three sites in
``src/source_truthful_timestamps.py``:

1. ``extract_source_truthful_timestamps`` — accept/drop per (source, field)
2. ``coerce_iso`` — failure-mode counter (no source context)
3. ``_clamp_future_to_now`` — future-clamp counter

Test strategy: snapshot the counter value before each invocation and
assert the post-call delta. We pull the value via
``Counter._value.get()`` (private API but stable; same approach the
prometheus_client docs use in their own examples). Snapshotting is
required because the global registry persists across tests in the same
process — comparing absolute values would couple tests to execution
order.
"""

from __future__ import annotations

import os
import sys
from typing import Dict

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---------------------------------------------------------------------------
# Helpers — snapshot a counter family by label-set so we can assert deltas
# ---------------------------------------------------------------------------


def _counter_value(counter, **labels) -> float:
    """Read the current numeric value of a Counter cell.

    ``Counter._value.get()`` is technically private but documented as the
    stable read API in prometheus_client's own README + tests; the public
    ``generate_latest()`` returns a serialized text payload that requires
    parsing.
    """
    if labels:
        cell = counter.labels(**labels)
    else:
        cell = counter
    # ``_value`` is a ``Value`` object; ``.get()`` returns the float.
    return float(cell._value.get())


def _snapshot(counter, label_combos) -> Dict[tuple, float]:
    """Snapshot multiple label-sets of one counter family."""
    out: Dict[tuple, float] = {}
    for combo in label_combos:
        if isinstance(combo, dict):
            out[tuple(sorted(combo.items()))] = _counter_value(counter, **combo)
        else:
            out[combo] = _counter_value(counter)
    return out


# ===========================================================================
# 1. extract_source_truthful_timestamps — accept + drop counters
# ===========================================================================


def test_extract_emits_accepted_counter_for_present_first_seen_and_last_seen():
    """Reliable source supplies both timestamps → two ACCEPTED increments
    (one per field), zero DROPPED increments."""
    from metrics_server import SOURCE_TRUTHFUL_CLAIM_ACCEPTED, SOURCE_TRUTHFUL_CLAIM_DROPPED
    from source_truthful_timestamps import extract_source_truthful_timestamps

    before_first = _counter_value(SOURCE_TRUTHFUL_CLAIM_ACCEPTED, source_id="nvd", field="first_seen")
    before_last = _counter_value(SOURCE_TRUTHFUL_CLAIM_ACCEPTED, source_id="nvd", field="last_seen")
    before_drop = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED,
        source_id="nvd",
        reason="no_data_from_source",
        field="first_seen",
    )

    out = extract_source_truthful_timestamps(
        {"first_seen": "2024-01-01T00:00:00+00:00", "last_seen": "2024-06-01T00:00:00+00:00"},
        source_id="nvd",
    )
    assert out[0] is not None and out[1] is not None

    after_first = _counter_value(SOURCE_TRUTHFUL_CLAIM_ACCEPTED, source_id="nvd", field="first_seen")
    after_last = _counter_value(SOURCE_TRUTHFUL_CLAIM_ACCEPTED, source_id="nvd", field="last_seen")
    after_drop = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED,
        source_id="nvd",
        reason="no_data_from_source",
        field="first_seen",
    )
    assert after_first - before_first == 1.0, "first_seen ACCEPTED counter should have incremented by 1"
    assert after_last - before_last == 1.0, "last_seen ACCEPTED counter should have incremented by 1"
    assert after_drop - before_drop == 0.0, "no_data_from_source DROPPED counter should NOT have incremented"


def test_extract_emits_no_data_counter_for_reliable_source_with_None_values():
    """Reliable source on the allowlist but supplies neither value
    (honest-NULL) → two no_data_from_source DROPPED increments, zero
    ACCEPTED increments."""
    from metrics_server import SOURCE_TRUTHFUL_CLAIM_ACCEPTED, SOURCE_TRUTHFUL_CLAIM_DROPPED
    from source_truthful_timestamps import extract_source_truthful_timestamps

    before_drop_first = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="cisa_kev", reason="no_data_from_source", field="first_seen"
    )
    before_drop_last = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="cisa_kev", reason="no_data_from_source", field="last_seen"
    )
    before_accept = _counter_value(SOURCE_TRUTHFUL_CLAIM_ACCEPTED, source_id="cisa_kev", field="first_seen")

    out = extract_source_truthful_timestamps({}, source_id="cisa_kev")
    assert out == (None, None)

    after_drop_first = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="cisa_kev", reason="no_data_from_source", field="first_seen"
    )
    after_drop_last = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="cisa_kev", reason="no_data_from_source", field="last_seen"
    )
    after_accept = _counter_value(SOURCE_TRUTHFUL_CLAIM_ACCEPTED, source_id="cisa_kev", field="first_seen")
    assert after_drop_first - before_drop_first == 1.0
    assert after_drop_last - before_drop_last == 1.0
    assert after_accept - before_accept == 0.0


def test_extract_emits_source_not_in_allowlist_counter_per_field_for_unreliable_source():
    """PR #42 audit M3 (Logic Tracker): unreliable source (OTX) →
    TWO source_not_in_allowlist DROPPED increments, one per field
    (first_seen + last_seen). The earlier draft of this test asserted
    a single field='both' emit; the per-field-symmetric emit makes
    the documented PromQL acceptance-rate query
    ``accepted{field=X} / sum without(reason)(accepted+dropped){field=X}``
    correct (the relay drop now appears in the same field-bucketed
    denominator as the no_data drop).

    no_data_from_source counters MUST NOT fire — we never even
    attempt Layer-1/Layer-2 extraction for unreliable sources.
    """
    from metrics_server import SOURCE_TRUTHFUL_CLAIM_DROPPED
    from source_truthful_timestamps import extract_source_truthful_timestamps

    before_first = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="otx", reason="source_not_in_allowlist", field="first_seen"
    )
    before_last = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="otx", reason="source_not_in_allowlist", field="last_seen"
    )
    before_no_data = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="otx", reason="no_data_from_source", field="first_seen"
    )

    out = extract_source_truthful_timestamps(
        {"first_seen": "2024-01-01T00:00:00Z", "last_seen": "2024-06-01T00:00:00Z"},
        source_id="otx",
    )
    assert out == (None, None)

    after_first = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="otx", reason="source_not_in_allowlist", field="first_seen"
    )
    after_last = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="otx", reason="source_not_in_allowlist", field="last_seen"
    )
    after_no_data = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="otx", reason="no_data_from_source", field="first_seen"
    )
    assert after_first - before_first == 1.0, "source_not_in_allowlist must fire for field=first_seen"
    assert after_last - before_last == 1.0, "source_not_in_allowlist must fire for field=last_seen"
    assert after_no_data - before_no_data == 0.0, "no_data_from_source must NOT fire for unreliable sources"


def test_extract_layer2_fallback_counts_as_accepted_not_dropped():
    """Layer 1 returns None but Layer 2 (NVD_META.published) fills in →
    the call counts as ACCEPTED, NOT as no_data_from_source. Counter is
    emitted AFTER both layers run, so a Layer-2 fallback that fills in
    a missing Layer-1 value MUST count as accepted."""
    from metrics_server import SOURCE_TRUTHFUL_CLAIM_ACCEPTED, SOURCE_TRUTHFUL_CLAIM_DROPPED
    from source_truthful_timestamps import extract_source_truthful_timestamps

    before_accept = _counter_value(SOURCE_TRUTHFUL_CLAIM_ACCEPTED, source_id="nvd", field="first_seen")
    before_drop = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="nvd", reason="no_data_from_source", field="first_seen"
    )

    out = extract_source_truthful_timestamps(
        {},  # Layer 1: empty
        source_id="nvd",
        nvd_meta={"published": "2024-03-15T10:00:00+00:00"},  # Layer 2 supplies
    )
    assert out[0] is not None  # first_seen WAS resolved via Layer 2

    after_accept = _counter_value(SOURCE_TRUTHFUL_CLAIM_ACCEPTED, source_id="nvd", field="first_seen")
    after_drop = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="nvd", reason="no_data_from_source", field="first_seen"
    )
    assert after_accept - before_accept == 1.0, "Layer-2 fallback MUST count as accepted"
    assert after_drop - before_drop == 0.0, "Layer-2 fallback MUST NOT also fire the dropped counter"


# ===========================================================================
# 2. coerce_iso — failure-mode counter (no source_id label)
# ===========================================================================


def test_coerce_iso_emits_sentinel_epoch_counter_for_zero_epoch():
    """``coerce_iso(0)`` rejects (0 is below _INT_EPOCH_FLOOR=1) and
    increments the sentinel_epoch counter."""
    from metrics_server import SOURCE_TRUTHFUL_COERCE_REJECTED
    from source_truthful_timestamps import coerce_iso

    before = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="sentinel_epoch")
    assert coerce_iso(0) is None
    after = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="sentinel_epoch")
    assert after - before == 1.0


def test_coerce_iso_emits_sentinel_epoch_counter_for_negative_epoch():
    """``coerce_iso(-1)`` also rejects with sentinel_epoch."""
    from metrics_server import SOURCE_TRUTHFUL_COERCE_REJECTED
    from source_truthful_timestamps import coerce_iso

    before = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="sentinel_epoch")
    assert coerce_iso(-1) is None
    after = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="sentinel_epoch")
    assert after - before == 1.0


def test_coerce_iso_emits_sentinel_epoch_counter_for_above_ceil():
    """An int above the year-9999 ceiling rejects with sentinel_epoch
    (the bound check classifies all out-of-range int/float values
    uniformly under sentinel_epoch — overflow is reserved for the
    OverflowError exception path)."""
    from metrics_server import SOURCE_TRUTHFUL_COERCE_REJECTED
    from source_truthful_timestamps import coerce_iso

    before = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="sentinel_epoch")
    # Just above the 9999-12-31 ceil (253_402_300_799)
    assert coerce_iso(253_402_300_800) is None
    after = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="sentinel_epoch")
    assert after - before == 1.0


def test_coerce_iso_emits_malformed_string_counter_for_invalid_calendar():
    """``coerce_iso("2024-13-99")`` is shape-valid (10 chars, hyphen
    positions correct, all digits) but calendar-invalid → rejects with
    malformed_string."""
    from metrics_server import SOURCE_TRUTHFUL_COERCE_REJECTED
    from source_truthful_timestamps import coerce_iso

    before = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="malformed_string")
    assert coerce_iso("2024-13-99") is None
    after = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="malformed_string")
    assert after - before == 1.0


def test_coerce_iso_emits_malformed_string_counter_for_unparseable_full_string():
    """``coerce_iso("not a date")`` fails the full-string fromisoformat
    branch → rejects with malformed_string."""
    from metrics_server import SOURCE_TRUTHFUL_COERCE_REJECTED
    from source_truthful_timestamps import coerce_iso

    before = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="malformed_string")
    assert coerce_iso("not a date at all") is None
    after = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="malformed_string")
    assert after - before == 1.0


def test_coerce_iso_does_not_emit_for_None():
    """``None`` is a legitimate honest-NULL input, not a parse failure.
    No counter should fire."""
    from metrics_server import SOURCE_TRUTHFUL_COERCE_REJECTED
    from source_truthful_timestamps import coerce_iso

    before_sent = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="sentinel_epoch")
    before_mal = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="malformed_string")
    before_over = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="overflow")

    assert coerce_iso(None) is None

    assert _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="sentinel_epoch") - before_sent == 0.0
    assert _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="malformed_string") - before_mal == 0.0
    assert _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="overflow") - before_over == 0.0


def test_coerce_iso_does_not_emit_for_valid_iso():
    """A clean valid input must NOT fire any of the rejection counters."""
    from metrics_server import SOURCE_TRUTHFUL_COERCE_REJECTED
    from source_truthful_timestamps import coerce_iso

    before_sent = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="sentinel_epoch")
    before_mal = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="malformed_string")

    out = coerce_iso("2024-01-01T00:00:00+00:00")
    assert out == "2024-01-01T00:00:00+00:00"

    assert _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="sentinel_epoch") - before_sent == 0.0
    assert _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="malformed_string") - before_mal == 0.0


# ===========================================================================
# 3. _clamp_future_to_now — future-clamp counter
# ===========================================================================


def test_future_clamp_counter_increments_on_future_dated_value():
    """A 5-year-future ISO timestamp routed through the helper module's
    public extract path triggers the clamp + counter."""
    from metrics_server import SOURCE_TRUTHFUL_FUTURE_CLAMP
    from source_truthful_timestamps import _clamp_future_to_now

    before = _counter_value(SOURCE_TRUTHFUL_FUTURE_CLAMP)
    out = _clamp_future_to_now("2099-01-01T00:00:00+00:00")
    assert out is not None and not out.startswith("2099")  # was clamped to now
    after = _counter_value(SOURCE_TRUTHFUL_FUTURE_CLAMP)
    assert after - before == 1.0


def test_future_clamp_counter_does_not_increment_for_past_value():
    """Past-dated values pass through unchanged; counter must NOT fire."""
    from metrics_server import SOURCE_TRUTHFUL_FUTURE_CLAMP
    from source_truthful_timestamps import _clamp_future_to_now

    before = _counter_value(SOURCE_TRUTHFUL_FUTURE_CLAMP)
    out = _clamp_future_to_now("2020-01-01T00:00:00+00:00")
    assert out == "2020-01-01T00:00:00+00:00"
    after = _counter_value(SOURCE_TRUTHFUL_FUTURE_CLAMP)
    assert after - before == 0.0


def test_future_clamp_counter_does_not_increment_for_unparseable_value():
    """Unparseable input is left alone and the counter must NOT fire
    (clamp helper only counts SUCCESSFUL clamps, not parse failures —
    those are handled by coerce_iso's malformed_string counter)."""
    from metrics_server import SOURCE_TRUTHFUL_FUTURE_CLAMP
    from source_truthful_timestamps import _clamp_future_to_now

    before = _counter_value(SOURCE_TRUTHFUL_FUTURE_CLAMP)
    out = _clamp_future_to_now("not a date")
    assert out == "not a date"  # passed through
    after = _counter_value(SOURCE_TRUTHFUL_FUTURE_CLAMP)
    assert after - before == 0.0


# ===========================================================================
# 4. _safe_source_label — cardinality control on the source_id label
# ===========================================================================


def test_safe_source_label_accepts_allowlisted_sources():
    """Every reliable source identifier must pass through the
    cardinality guard unchanged (lowercased)."""
    from metrics_server import _safe_source_label

    for src in ("nvd", "cisa", "cisa_kev", "mitre_attck", "virustotal", "abuseipdb", "threatfox"):
        assert _safe_source_label(src) == src.lower()


def test_safe_source_label_collapses_unknown_sources_to_other():
    """A source_id outside the allowlist MUST collapse to ``<other>`` —
    prevents an attacker (or a buggy collector) from blowing up
    Prometheus storage by emitting a fresh source label per attribute."""
    from metrics_server import _safe_source_label

    assert _safe_source_label("totally_made_up_source") == "<other>"
    assert _safe_source_label("UPPERCASE_SOURCE") == "<other>"


def test_safe_source_label_collapses_None_and_empty_to_unknown():
    """``None`` / empty / whitespace-only → ``<unknown>``."""
    from metrics_server import _safe_source_label

    assert _safe_source_label(None) == "<unknown>"
    assert _safe_source_label("") == "<unknown>"
    assert _safe_source_label("   ") == "<unknown>"


# ===========================================================================
# 5. End-to-end smoke test — counter values reachable via /metrics endpoint
# ===========================================================================


def test_new_counters_appear_in_generate_latest_output():
    """The four new counter families must appear in the Prometheus text
    payload that the metrics endpoint serves. Catches a regression where
    a future refactor moves the Counter definitions out of the registry
    that ``generate_latest()`` walks."""
    from prometheus_client import generate_latest

    payload = generate_latest().decode("utf-8")
    assert "edgeguard_source_truthful_claim_accepted_total" in payload
    assert "edgeguard_source_truthful_claim_dropped_total" in payload
    assert "edgeguard_source_truthful_coerce_rejected_total" in payload
    assert "edgeguard_source_truthful_future_clamp_total" in payload


# ===========================================================================
# 6. Cross-module parity (PR #42 audit M1) — allowlist drift detector
# ===========================================================================


def test_source_label_allowlist_mirrors_reliable_first_seen_sources():
    """PR #42 audit M1 (Cross-Checker): the metrics ``_SOURCE_LABEL_ALLOWLIST``
    MUST be a SUPERSET of ``_RELIABLE_FIRST_SEEN_SOURCES`` so every reliable
    source resolves to its own Prometheus cell (rather than collapsing
    into ``<other>``).

    Drift is silent: the previous draft included ``sslbl`` even though
    no source emits that tag, and any new source added to the reliable
    allowlist would have been missed. This test catches the next drift
    automatically.
    """
    from metrics_server import _REJECTED_ON_PURPOSE_SOURCES, _source_label_allowlist
    from source_truthful_timestamps import _RELIABLE_FIRST_SEEN_SOURCES

    allowlist = _source_label_allowlist()
    missing = set(_RELIABLE_FIRST_SEEN_SOURCES) - allowlist
    assert not missing, (
        f"_SOURCE_LABEL_ALLOWLIST is missing reliable sources: {missing}. "
        "Every source on the source-truthful allowlist MUST appear here so "
        "its metric label resolves to its own cell, not <other>."
    )
    # Symmetric: every metric-allowlisted entry must be either a reliable
    # source OR an explicitly-rejected relay (otherwise it's dead weight).
    extras = allowlist - set(_RELIABLE_FIRST_SEEN_SOURCES) - _REJECTED_ON_PURPOSE_SOURCES
    assert not extras, (
        f"_SOURCE_LABEL_ALLOWLIST has extras not in either canonical set: {extras}. "
        "Allowlist composition is RELIABLE ∪ REJECTED_ON_PURPOSE — anything else is drift."
    )


# ===========================================================================
# 7. PR #42 audit M2 — bounded enum guards on reason/field labels
# ===========================================================================


def test_drop_counter_clamps_unknown_reason_to_other():
    """An out-of-band reason value (future caller passes
    ``reason="garbage"``) MUST clamp to ``<other>`` rather than create
    a new Prometheus cell — otherwise cardinality grows unbounded."""
    from metrics_server import (
        SOURCE_TRUTHFUL_CLAIM_DROPPED,
        record_source_truthful_claim_dropped,
    )

    before = _counter_value(SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="nvd", reason="<other>", field="first_seen")
    record_source_truthful_claim_dropped("nvd", "totally_made_up_reason", "first_seen")
    after = _counter_value(SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="nvd", reason="<other>", field="first_seen")
    assert after - before == 1.0


def test_coerce_counter_clamps_unknown_reason_to_other():
    """Same protection on ``record_source_truthful_coerce_rejected``."""
    from metrics_server import (
        SOURCE_TRUTHFUL_COERCE_REJECTED,
        record_source_truthful_coerce_rejected,
    )

    before = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="<other>")
    record_source_truthful_coerce_rejected("garbage_reason_not_in_enum")
    after = _counter_value(SOURCE_TRUTHFUL_COERCE_REJECTED, reason="<other>")
    assert after - before == 1.0


def test_drop_counter_clamps_unknown_field_to_other():
    """The ``field`` label is also enum-guarded — ``"both"`` (the legacy
    pre-M3 value) and any other out-of-band value collapse to
    ``<other>`` so we'd see the regression as a metric blip rather
    than as silent cardinality drift."""
    from metrics_server import (
        SOURCE_TRUTHFUL_CLAIM_DROPPED,
        record_source_truthful_claim_dropped,
    )

    before = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="nvd", reason="no_data_from_source", field="<other>"
    )
    record_source_truthful_claim_dropped("nvd", "no_data_from_source", "both")  # legacy field value
    after = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="nvd", reason="no_data_from_source", field="<other>"
    )
    assert after - before == 1.0


def test_drop_counter_clamps_empty_field_to_unknown():
    """Empty / None field → ``<unknown>`` (distinguishable from
    ``<other>``: empty means missing data, other means out-of-band
    value)."""
    from metrics_server import (
        SOURCE_TRUTHFUL_CLAIM_DROPPED,
        record_source_truthful_claim_dropped,
    )

    before = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="nvd", reason="no_data_from_source", field="<unknown>"
    )
    record_source_truthful_claim_dropped("nvd", "no_data_from_source", "")
    after = _counter_value(
        SOURCE_TRUTHFUL_CLAIM_DROPPED, source_id="nvd", reason="no_data_from_source", field="<unknown>"
    )
    assert after - before == 1.0
