"""Chip 5e — defense-in-depth against MISP tag impersonation.

The source-truthful timestamp pipeline (PR #41) trusts the source
identity carried in MISP attribute tags. Without an additional check
on the parent event's creator org, an attacker who can write to MISP
(compromised user, third-party feed pushing into a shared MISP) can
stamp ``original_source: "nvd"`` on a forged attribute and have
EdgeGuard treat it as authoritative NVD data — corrupting the
``MIN(r.source_reported_first_at)`` aggregate that EdgeGuard exports
to ResilMesh.

This module verifies the trust check fires correctly:

A. **`is_attribute_creator_trusted`** unit-level decisions for every
   reason in the ``TRUST_REASON_*`` enum.
B. **End-to-end** behavior of ``extract_source_truthful_timestamps``
   with the trust check active — refuses spoofed claims and emits
   the Prometheus rejection counter.
C. **Backward-compat** — when neither allowlist env var is configured,
   the trust check is BYPASSED and behavior matches pre-chip-5e.
"""

from __future__ import annotations

import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _counter_value(counter, **labels) -> float:
    """Snapshot one cell of a Prometheus Counter — same pattern as
    ``tests/test_source_truthful_metrics.py``."""
    cell = counter.labels(**labels) if labels else counter
    return float(cell._value.get())


def _reload_trust_env(monkeypatch, *, uuids: str = "", names: str = "") -> None:
    """Set the two allowlist env vars and force the source_trust module
    to re-read them. Production code captures them at import time, so
    tests need this helper to mutate them between cases."""
    monkeypatch.setenv("EDGEGUARD_TRUSTED_MISP_ORG_UUIDS", uuids)
    monkeypatch.setenv("EDGEGUARD_TRUSTED_MISP_ORG_NAMES", names)
    from source_trust import _reload_env

    _reload_env()


# ---------------------------------------------------------------------------
# A. is_attribute_creator_trusted — unit decisions
# ---------------------------------------------------------------------------


def test_trust_check_disabled_when_neither_env_var_configured(monkeypatch):
    """The most important backward-compat invariant: when an operator
    has not configured EITHER allowlist env var, the trust check
    returns trusted=True with the disabled reason. NO behavior
    change relative to pre-chip-5e."""
    _reload_trust_env(monkeypatch, uuids="", names="")
    from source_trust import TRUST_REASON_DISABLED, is_attribute_creator_trusted

    # Spoofed event — but trust check is OFF, so it passes.
    spoofed = {"id": "1", "Orgc": {"uuid": "attacker-uuid", "name": "Attacker"}}
    trusted, reason = is_attribute_creator_trusted(spoofed)
    assert trusted is True
    assert reason == TRUST_REASON_DISABLED


def test_trust_check_disabled_returns_true_even_for_None_event(monkeypatch):
    """When the trust check is disabled, even a None event passes —
    callers without an event context (CLI / tests) keep working."""
    _reload_trust_env(monkeypatch, uuids="", names="")
    from source_trust import TRUST_REASON_DISABLED, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted(None)
    assert trusted is True
    assert reason == TRUST_REASON_DISABLED


def test_uuid_match_when_allowlist_configured(monkeypatch):
    """Configured UUID allowlist + matching event Orgc.uuid → TRUSTED."""
    _reload_trust_env(monkeypatch, uuids="trusted-uuid-1,trusted-uuid-2")
    from source_trust import TRUST_REASON_UUID_MATCH, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted({"id": "1", "Orgc": {"uuid": "trusted-uuid-1", "name": "Whatever"}})
    assert trusted is True
    assert reason == TRUST_REASON_UUID_MATCH


def test_uuid_match_is_case_insensitive(monkeypatch):
    """UUIDs from MISP UI may have different casing than what the
    operator pasted into the env var. Comparison must lowercase
    both sides so a paste-and-go workflow works."""
    _reload_trust_env(monkeypatch, uuids="ABC-123-DEF")
    from source_trust import TRUST_REASON_UUID_MATCH, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted({"id": "1", "Orgc": {"uuid": "abc-123-def"}})
    assert trusted is True
    assert reason == TRUST_REASON_UUID_MATCH


def test_name_match_when_only_name_allowlist_configured(monkeypatch):
    """Some MISP deployments don't expose Orgc.uuid cleanly via the
    REST API — name allowlist is the fallback."""
    _reload_trust_env(monkeypatch, names="EdgeGuard Collectors,Internal Threat Intel")
    from source_trust import TRUST_REASON_NAME_MATCH, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted(
        {"id": "1", "Orgc": {"uuid": "irrelevant-uuid", "name": "EdgeGuard Collectors"}}
    )
    assert trusted is True
    assert reason == TRUST_REASON_NAME_MATCH


def test_name_match_is_case_insensitive(monkeypatch):
    _reload_trust_env(monkeypatch, names="EdgeGuard")
    from source_trust import TRUST_REASON_NAME_MATCH, is_attribute_creator_trusted

    for query in ("edgeguard", "EDGEGUARD", "  EdGeGuArD  "):
        trusted, reason = is_attribute_creator_trusted({"id": "1", "Orgc": {"name": query}})
        assert trusted is True, f"case-insensitive name match failed for {query!r}"
        assert reason == TRUST_REASON_NAME_MATCH


def test_uuid_check_takes_precedence_over_name_check(monkeypatch):
    """When both allowlists are configured AND the UUID matches, the
    UUID-match reason is returned (not the name-match reason). UUIDs
    are more authoritative — the name-match fallback should only
    fire when the UUID check is inconclusive."""
    _reload_trust_env(monkeypatch, uuids="trusted-uuid-1", names="Trusted Name")
    from source_trust import TRUST_REASON_UUID_MATCH, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted(
        {"id": "1", "Orgc": {"uuid": "trusted-uuid-1", "name": "Trusted Name"}}
    )
    assert trusted is True
    assert reason == TRUST_REASON_UUID_MATCH


def test_rejected_when_neither_uuid_nor_name_matches(monkeypatch):
    """The signal that fires for spoofing attempts: trust check is
    configured + creator org info is present but doesn't match
    either allowlist."""
    _reload_trust_env(monkeypatch, uuids="trusted-uuid-1", names="Trusted Name")
    from source_trust import TRUST_REASON_NOT_ALLOWLISTED, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted({"id": "999", "Orgc": {"uuid": "attacker-uuid", "name": "Attacker"}})
    assert trusted is False
    assert reason == TRUST_REASON_NOT_ALLOWLISTED


def test_rejected_when_event_info_missing_orgc(monkeypatch):
    """Event has no Orgc field at all → REJECT (cannot verify
    provenance, must fail safe)."""
    _reload_trust_env(monkeypatch, uuids="trusted-uuid-1")
    from source_trust import TRUST_REASON_CREATOR_MISSING, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted({"id": "1"})
    assert trusted is False
    assert reason == TRUST_REASON_CREATOR_MISSING


def test_rejected_when_event_info_is_None(monkeypatch):
    """A None event_info with the trust check configured → REJECT
    (caller passed nothing; we have no info to verify)."""
    _reload_trust_env(monkeypatch, uuids="trusted-uuid-1")
    from source_trust import TRUST_REASON_CREATOR_MISSING, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted(None)
    assert trusted is False
    assert reason == TRUST_REASON_CREATOR_MISSING


def test_rejected_when_orgc_is_present_but_empty_dict(monkeypatch):
    """Defensive: ``Orgc: {}`` carries no useful info — reject."""
    _reload_trust_env(monkeypatch, uuids="trusted-uuid-1")
    from source_trust import TRUST_REASON_CREATOR_MISSING, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted({"id": "1", "Orgc": {}})
    assert trusted is False
    assert reason == TRUST_REASON_CREATOR_MISSING


def test_rejected_when_orgc_uuid_and_name_are_both_blank(monkeypatch):
    """Defensive: ``Orgc: {"uuid": "", "name": ""}`` is treated the
    same as missing — operators can't allowlist an empty string."""
    _reload_trust_env(monkeypatch, uuids="trusted-uuid-1", names="Trusted")
    from source_trust import TRUST_REASON_CREATOR_MISSING, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted({"id": "1", "Orgc": {"uuid": "", "name": "  "}})
    assert trusted is False
    assert reason == TRUST_REASON_CREATOR_MISSING


def test_orgc_with_only_name_matches_name_allowlist(monkeypatch):
    """An event whose Orgc has only ``name`` (no UUID) MUST still
    trust-check successfully against the name allowlist."""
    _reload_trust_env(monkeypatch, uuids="trusted-uuid-1", names="EdgeGuard Collectors")
    from source_trust import TRUST_REASON_NAME_MATCH, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted({"id": "1", "Orgc": {"name": "EdgeGuard Collectors"}})
    assert trusted is True
    assert reason == TRUST_REASON_NAME_MATCH


def test_csv_env_handles_whitespace_and_empty_segments(monkeypatch):
    """Operators commonly paste comma-separated lists with trailing
    whitespace or accidental empty entries. Parser must tolerate."""
    _reload_trust_env(monkeypatch, uuids=" uuid-a , , uuid-b ,")
    from source_trust import trusted_uuids_snapshot

    assert trusted_uuids_snapshot() == frozenset({"uuid-a", "uuid-b"})


# ---------------------------------------------------------------------------
# B. End-to-end via extract_source_truthful_timestamps
# ---------------------------------------------------------------------------


def test_extract_drops_claim_when_creator_not_allowlisted(monkeypatch):
    """The integration test that catches the chip 5e regression class.

    Trust check configured + reliable source + spoofed creator org →
    extractor returns (None, None) AND the rejection counter
    increments."""
    _reload_trust_env(monkeypatch, uuids="trusted-uuid-1")
    from metrics_server import SOURCE_TRUTHFUL_CREATOR_REJECTED
    from source_trust import TRUST_REASON_NOT_ALLOWLISTED
    from source_truthful_timestamps import extract_source_truthful_timestamps

    before = _counter_value(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="nvd", reason=TRUST_REASON_NOT_ALLOWLISTED)

    out = extract_source_truthful_timestamps(
        {"first_seen": "2024-01-01T00:00:00+00:00", "last_seen": "2024-06-01T00:00:00+00:00"},
        source_id="nvd",
        event_info={"id": "999", "Orgc": {"uuid": "attacker-uuid", "name": "Attacker"}},
    )
    assert out == (None, None), "spoofed claim must be dropped — got %r" % (out,)

    after = _counter_value(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="nvd", reason=TRUST_REASON_NOT_ALLOWLISTED)
    assert after - before == 1.0, "rejection counter must increment"


def test_extract_proceeds_when_creator_is_trusted(monkeypatch):
    """Trust check configured + reliable source + trusted creator org →
    extractor returns the legitimate values (no rejection)."""
    _reload_trust_env(monkeypatch, uuids="edgeguard-collector-org-uuid")
    from metrics_server import SOURCE_TRUTHFUL_CREATOR_REJECTED
    from source_truthful_timestamps import extract_source_truthful_timestamps

    before_total = sum(
        _counter_value(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="nvd", reason=r)
        for r in ("creator_org_not_allowlisted", "creator_org_missing")
    )

    out = extract_source_truthful_timestamps(
        {"first_seen": "2024-01-01T00:00:00+00:00", "last_seen": "2024-06-01T00:00:00+00:00"},
        source_id="nvd",
        event_info={"id": "1", "Orgc": {"uuid": "edgeguard-collector-org-uuid", "name": "EdgeGuard"}},
    )
    assert out[0] is not None and out[1] is not None

    after_total = sum(
        _counter_value(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="nvd", reason=r)
        for r in ("creator_org_not_allowlisted", "creator_org_missing")
    )
    assert after_total - before_total == 0.0, "no rejection counter should fire"


def test_extract_drops_claim_when_creator_org_missing(monkeypatch):
    """Trust check configured + reliable source + event has no Orgc →
    extractor returns (None, None) AND the missing-creator counter
    fires (different label than the spoofing case so operators can
    distinguish 'we couldn't verify' from 'we verified and rejected')."""
    _reload_trust_env(monkeypatch, uuids="trusted-uuid-1")
    from metrics_server import SOURCE_TRUTHFUL_CREATOR_REJECTED
    from source_trust import TRUST_REASON_CREATOR_MISSING
    from source_truthful_timestamps import extract_source_truthful_timestamps

    before = _counter_value(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="cisa_kev", reason=TRUST_REASON_CREATOR_MISSING)

    out = extract_source_truthful_timestamps(
        {"first_seen": "2024-01-01T00:00:00+00:00"},
        source_id="cisa_kev",
        event_info={"id": "1"},  # no Orgc at all
    )
    assert out == (None, None)

    after = _counter_value(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="cisa_kev", reason=TRUST_REASON_CREATOR_MISSING)
    assert after - before == 1.0


# ---------------------------------------------------------------------------
# C. Backward-compat — trust check disabled or event_info omitted
# ---------------------------------------------------------------------------


def test_extract_proceeds_normally_when_trust_check_is_disabled(monkeypatch):
    """The most important backward-compat test: when neither env var
    is configured (default), even a SPOOFED creator org is accepted —
    extractor returns the values as before. Operators who haven't
    enabled the defense get pre-chip-5e behavior."""
    _reload_trust_env(monkeypatch, uuids="", names="")
    from source_truthful_timestamps import extract_source_truthful_timestamps

    out = extract_source_truthful_timestamps(
        {"first_seen": "2024-01-01T00:00:00+00:00", "last_seen": "2024-06-01T00:00:00+00:00"},
        source_id="nvd",
        event_info={"id": "999", "Orgc": {"uuid": "attacker-uuid", "name": "Attacker"}},
    )
    assert out[0] is not None and out[1] is not None


def test_extract_proceeds_normally_when_event_info_is_None(monkeypatch):
    """Backward-compat for callers (CLI, synthetic tests) that don't
    plumb the parent event through. Even with the trust check
    configured, a None event_info SKIPS the check (rather than
    rejecting)."""
    _reload_trust_env(monkeypatch, uuids="trusted-uuid-1")
    from source_truthful_timestamps import extract_source_truthful_timestamps

    out = extract_source_truthful_timestamps(
        {"first_seen": "2024-01-01T00:00:00+00:00", "last_seen": "2024-06-01T00:00:00+00:00"},
        source_id="nvd",
        event_info=None,
    )
    assert out[0] is not None and out[1] is not None


def test_extract_returns_None_None_for_unreliable_source_regardless_of_trust(monkeypatch):
    """The unreliable-source filter (Layer 1: not on the allowlist)
    runs BEFORE the trust check. An OTX claim returns (None, None)
    even if the OTX event has a trusted creator — the source's
    first_seen field semantically means the wrong thing."""
    _reload_trust_env(monkeypatch, uuids="trusted-uuid-1")
    from source_truthful_timestamps import extract_source_truthful_timestamps

    out = extract_source_truthful_timestamps(
        {"first_seen": "2024-01-01T00:00:00+00:00"},
        source_id="otx",
        event_info={"id": "1", "Orgc": {"uuid": "trusted-uuid-1"}},
    )
    assert out == (None, None)


# ---------------------------------------------------------------------------
# D. Counter visibility — rejection counter appears in the metrics endpoint
# ---------------------------------------------------------------------------


def test_creator_rejected_counter_appears_in_generate_latest_output():
    """The rejection counter MUST appear in the Prometheus text payload
    that the metrics endpoint serves. Catches a regression where a
    future refactor moves the Counter definition out of the registry."""
    from prometheus_client import generate_latest

    payload = generate_latest().decode("utf-8")
    assert "edgeguard_source_truthful_creator_rejected_total" in payload
