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
    spoofed = {"id": "1", "Orgc": {"uuid": "99999999-9999-9999-9999-999999999999", "name": "Attacker"}}
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
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222")
    from source_trust import TRUST_REASON_UUID_MATCH, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted(
        {"id": "1", "Orgc": {"uuid": "11111111-1111-1111-1111-111111111111", "name": "Whatever"}}
    )
    assert trusted is True
    assert reason == TRUST_REASON_UUID_MATCH


def test_uuid_match_is_case_insensitive(monkeypatch):
    """UUIDs from MISP UI may have different casing than what the
    operator pasted into the env var. Comparison must lowercase
    both sides so a paste-and-go workflow works."""
    _reload_trust_env(monkeypatch, uuids="ABCDEF12-3456-7890-1234-567890ABCDEF")
    from source_trust import TRUST_REASON_UUID_MATCH, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted(
        {"id": "1", "Orgc": {"uuid": "abcdef12-3456-7890-1234-567890abcdef"}}
    )
    assert trusted is True
    assert reason == TRUST_REASON_UUID_MATCH


def test_name_match_when_only_name_allowlist_configured(monkeypatch):
    """Some MISP deployments don't expose Orgc.uuid cleanly via the
    REST API — name allowlist is the fallback."""
    _reload_trust_env(monkeypatch, names="EdgeGuard Collectors,Internal Threat Intel")
    from source_trust import TRUST_REASON_NAME_MATCH, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted(
        # Non-UUID-format value here is intentional: it normalizes to None
        # via the strict UUID validator (PR #44 audit H2), so the lookup
        # falls through to the name-allowlist check.
        {"id": "1", "Orgc": {"uuid": "not-a-real-uuid", "name": "EdgeGuard Collectors"}}
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
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111", names="Trusted Name")
    from source_trust import TRUST_REASON_UUID_MATCH, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted(
        {"id": "1", "Orgc": {"uuid": "11111111-1111-1111-1111-111111111111", "name": "Trusted Name"}}
    )
    assert trusted is True
    assert reason == TRUST_REASON_UUID_MATCH


def test_rejected_when_neither_uuid_nor_name_matches(monkeypatch):
    """The signal that fires for spoofing attempts: trust check is
    configured + creator org info is present but doesn't match
    either allowlist."""
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111", names="Trusted Name")
    from source_trust import TRUST_REASON_NOT_ALLOWLISTED, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted(
        {"id": "999", "Orgc": {"uuid": "99999999-9999-9999-9999-999999999999", "name": "Attacker"}}
    )
    assert trusted is False
    assert reason == TRUST_REASON_NOT_ALLOWLISTED


def test_rejected_when_event_info_missing_orgc(monkeypatch):
    """Event has no Orgc field at all → REJECT (cannot verify
    provenance, must fail safe)."""
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111")
    from source_trust import TRUST_REASON_CREATOR_MISSING, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted({"id": "1"})
    assert trusted is False
    assert reason == TRUST_REASON_CREATOR_MISSING


def test_rejected_when_event_info_is_None(monkeypatch):
    """A None event_info with the trust check configured → REJECT
    (caller passed nothing; we have no info to verify)."""
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111")
    from source_trust import TRUST_REASON_CREATOR_MISSING, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted(None)
    assert trusted is False
    assert reason == TRUST_REASON_CREATOR_MISSING


def test_rejected_when_orgc_is_present_but_empty_dict(monkeypatch):
    """Defensive: ``Orgc: {}`` carries no useful info — reject."""
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111")
    from source_trust import TRUST_REASON_CREATOR_MISSING, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted({"id": "1", "Orgc": {}})
    assert trusted is False
    assert reason == TRUST_REASON_CREATOR_MISSING


def test_rejected_when_orgc_uuid_and_name_are_both_blank(monkeypatch):
    """Defensive: ``Orgc: {"uuid": "", "name": ""}`` is treated the
    same as missing — operators can't allowlist an empty string."""
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111", names="Trusted")
    from source_trust import TRUST_REASON_CREATOR_MISSING, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted({"id": "1", "Orgc": {"uuid": "", "name": "  "}})
    assert trusted is False
    assert reason == TRUST_REASON_CREATOR_MISSING


def test_orgc_with_only_name_matches_name_allowlist(monkeypatch):
    """An event whose Orgc has only ``name`` (no UUID) MUST still
    trust-check successfully against the name allowlist."""
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111", names="EdgeGuard Collectors")
    from source_trust import TRUST_REASON_NAME_MATCH, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted({"id": "1", "Orgc": {"name": "EdgeGuard Collectors"}})
    assert trusted is True
    assert reason == TRUST_REASON_NAME_MATCH


def test_csv_env_handles_whitespace_and_empty_segments(monkeypatch):
    """Operators commonly paste comma-separated lists with trailing
    whitespace or accidental empty entries. Parser must tolerate."""
    # Two valid UUIDs separated by whitespace + an empty segment.
    _reload_trust_env(
        monkeypatch, uuids=" 11111111-1111-1111-1111-111111111111 , , 22222222-2222-2222-2222-222222222222 ,"
    )
    from source_trust import trusted_uuids_snapshot

    assert trusted_uuids_snapshot() == frozenset(
        {"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"}
    )


def test_trusted_names_snapshot_returns_normalized_allowlist(monkeypatch):
    """Bugbot LOW (2026-04-19): the ``trusted_names_snapshot()``
    introspection helper had no in-repo callers, flagged as dead
    code. Symmetric with ``trusted_uuids_snapshot()`` (already
    exercised above) — both are part of the public surface for
    operator monitoring / debugging tooling. This test pins the
    NFKC-normalized + casefolded behavior so the helper stays
    correct when callers (Prometheus exporter, doctor command,
    etc.) consume it.
    """
    # Mix casing + a fullwidth-Latin variant + whitespace — verify
    # all three normalize to the same casefolded ASCII equivalents.
    _reload_trust_env(
        monkeypatch,
        names="EdgeGuard Collectors,  STRASSE CYBER ,\uff21\uff23\uff2d\uff25",
    )
    from source_trust import trusted_names_snapshot

    snapshot = trusted_names_snapshot()
    # All three normalized to lowercase ASCII; fullwidth ＡＣＭＥ → "acme"
    assert snapshot == frozenset({"edgeguard collectors", "strasse cyber", "acme"})


def test_trusted_names_snapshot_is_empty_when_env_unset(monkeypatch):
    """When the env var is empty, the snapshot returns an empty
    frozenset (not None). Pins the type contract for callers."""
    _reload_trust_env(monkeypatch, names="")
    from source_trust import trusted_names_snapshot

    snap = trusted_names_snapshot()
    assert isinstance(snap, frozenset)
    assert len(snap) == 0


# ---------------------------------------------------------------------------
# B. End-to-end via extract_source_truthful_timestamps
# ---------------------------------------------------------------------------


def test_extract_drops_claim_when_creator_not_allowlisted(monkeypatch):
    """The integration test that catches the chip 5e regression class.

    Trust check configured + reliable source + spoofed creator org →
    extractor returns (None, None) AND the rejection counter
    increments."""
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111")
    from metrics_server import SOURCE_TRUTHFUL_CREATOR_REJECTED
    from source_trust import TRUST_REASON_NOT_ALLOWLISTED
    from source_truthful_timestamps import extract_source_truthful_timestamps

    before = _counter_value(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="nvd", reason=TRUST_REASON_NOT_ALLOWLISTED)

    out = extract_source_truthful_timestamps(
        {"first_seen": "2024-01-01T00:00:00+00:00", "last_seen": "2024-06-01T00:00:00+00:00"},
        source_id="nvd",
        event_info={"id": "999", "Orgc": {"uuid": "99999999-9999-9999-9999-999999999999", "name": "Attacker"}},
    )
    assert out == (None, None), "spoofed claim must be dropped — got %r" % (out,)

    after = _counter_value(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="nvd", reason=TRUST_REASON_NOT_ALLOWLISTED)
    assert after - before == 1.0, "rejection counter must increment"


def test_extract_proceeds_when_creator_is_trusted(monkeypatch):
    """Trust check configured + reliable source + trusted creator org →
    extractor returns the legitimate values (no rejection)."""
    _reload_trust_env(monkeypatch, uuids="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    from metrics_server import SOURCE_TRUTHFUL_CREATOR_REJECTED
    from source_truthful_timestamps import extract_source_truthful_timestamps

    before_total = sum(
        _counter_value(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="nvd", reason=r)
        for r in ("creator_org_not_allowlisted", "creator_org_missing")
    )

    out = extract_source_truthful_timestamps(
        {"first_seen": "2024-01-01T00:00:00+00:00", "last_seen": "2024-06-01T00:00:00+00:00"},
        source_id="nvd",
        event_info={"id": "1", "Orgc": {"uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "name": "EdgeGuard"}},
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
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111")
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
        event_info={"id": "999", "Orgc": {"uuid": "99999999-9999-9999-9999-999999999999", "name": "Attacker"}},
    )
    assert out[0] is not None and out[1] is not None


def test_extract_proceeds_normally_when_event_info_is_None(monkeypatch):
    """Backward-compat for callers (CLI, synthetic tests) that don't
    plumb the parent event through. Even with the trust check
    configured, a None event_info SKIPS the check (rather than
    rejecting)."""
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111")
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
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111")
    from source_truthful_timestamps import extract_source_truthful_timestamps

    out = extract_source_truthful_timestamps(
        {"first_seen": "2024-01-01T00:00:00+00:00"},
        source_id="otx",
        event_info={"id": "1", "Orgc": {"uuid": "11111111-1111-1111-1111-111111111111"}},
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


# ===========================================================================
# E. PR #44 audit fixes — Unicode / UUID-format / log-injection / etc.
# ===========================================================================


def test_h1_nfkc_homoglyph_cyrillic_e_does_not_match_ascii_name(monkeypatch):
    """PR #44 audit H1 (Red Team): a Unicode homoglyph in the Orgc.name
    (Cyrillic 'е' U+0435 vs ASCII 'e') MUST NOT match the ASCII
    allowlist entry. NFKC doesn't catch Cyrillic look-alikes (they're
    visually identical but have no NFKC compatibility decomposition
    to ASCII), so the byte-level comparison MUST reject them.

    This is the documented limitation: NFKC + casefold defends against
    fullwidth Latin / German ß / Turkish dotless-i; ops are advised
    to use UUID allowlist for the strongest defense."""
    _reload_trust_env(monkeypatch, names="EdgeGuard Collectors")
    from source_trust import TRUST_REASON_NOT_ALLOWLISTED, is_attribute_creator_trusted

    # 'e' in EdgeGuard replaced with Cyrillic small letter 'ie' U+0435
    homoglyph_name = "Edg\u0435Guard Collectors"  # noqa: RUF001 — intentional homoglyph
    trusted, reason = is_attribute_creator_trusted({"id": "1", "Orgc": {"name": homoglyph_name}})
    assert trusted is False
    assert reason == TRUST_REASON_NOT_ALLOWLISTED


def test_h1_nfkc_fullwidth_latin_matches_ascii_name(monkeypatch):
    """PR #44 audit H1 (Red Team): NFKC normalization MUST fold
    fullwidth Latin characters to their ASCII compatibility form.
    An attacker registering an org named "ＥｄｇｅＧｕａｒｄ" (fullwidth)
    SHOULD match the ASCII allowlist after NFKC."""
    _reload_trust_env(monkeypatch, names="edgeguard")
    from source_trust import TRUST_REASON_NAME_MATCH, is_attribute_creator_trusted

    fullwidth_name = "\uff25\uff44\uff47\uff45\uff27\uff55\uff41\uff52\uff44"  # ＥｄｇｅＧｕａｒｄ
    trusted, reason = is_attribute_creator_trusted({"id": "1", "Orgc": {"name": fullwidth_name}})
    assert trusted is True
    assert reason == TRUST_REASON_NAME_MATCH


def test_h1_nfkc_german_eszett_casefolds_to_ss(monkeypatch):
    """PR #44 audit H1 (Red Team): ``casefold`` (vs ``lower``) folds
    German ß to ss. An operator registering "Strasse Cyber" SHOULD
    match an event whose Orgc.name is "Straße Cyber" (and vice-versa)."""
    _reload_trust_env(monkeypatch, names="strasse cyber")
    from source_trust import TRUST_REASON_NAME_MATCH, is_attribute_creator_trusted

    trusted, reason = is_attribute_creator_trusted({"id": "1", "Orgc": {"name": "Straße Cyber"}})
    assert trusted is True
    assert reason == TRUST_REASON_NAME_MATCH


def test_h2_uuid_format_validation_rejects_arbitrary_string_in_env(monkeypatch, caplog):
    """PR #44 audit H2 (Red Team / Bug Hunter): the env var allowlist
    parser MUST reject non-UUID strings. Misconfigured entries
    (operator pastes a name into the UUID env var) become a spoofing
    vector: a federated MISP peer whose Orgc.uuid happens to equal
    the misconfigured string would be falsely trusted.

    Verify a WARNING is logged so misconfiguration is loud, and that
    invalid entries are dropped from the allowlist."""
    import logging

    caplog.set_level(logging.WARNING, logger="source_trust")
    _reload_trust_env(monkeypatch, uuids="not-a-uuid,11111111-1111-1111-1111-111111111111,also-bad")
    from source_trust import trusted_uuids_snapshot

    # Only the one valid UUID survives
    assert trusted_uuids_snapshot() == frozenset({"11111111-1111-1111-1111-111111111111"})
    # And the dropped entries are loudly logged
    assert any("entries dropped" in rec.message for rec in caplog.records)


def test_h2_uuid_format_validation_rejects_attacker_orgc_uuid(monkeypatch):
    """PR #44 audit H2: an attacker-controlled MISP event whose
    Orgc.uuid is a free-text string (not UUID format) MUST be rejected
    as creator_org_missing — the strict UUID validator returns None
    so the lookup misses, then the no-name-match-either path triggers
    REJECT."""
    _reload_trust_env(monkeypatch, uuids="11111111-1111-1111-1111-111111111111")
    from source_trust import TRUST_REASON_CREATOR_MISSING, is_attribute_creator_trusted

    # Free-text Orgc.uuid (attacker-controlled)
    trusted, reason = is_attribute_creator_trusted(
        {"id": "1", "Orgc": {"uuid": "edgeguard collectors"}}  # not a UUID
    )
    assert trusted is False
    assert reason == TRUST_REASON_CREATOR_MISSING


def test_h3_log_injection_orgc_name_with_newlines_is_sanitized():
    """PR #44 audit H3 (Red Team / Cross-Checker): an attacker-controlled
    Orgc.name containing CR/LF MUST be sanitized before logging — a
    raw newline would split the WARNING into two lines, allowing
    forged log entries in a SIEM."""
    from source_trust import safe_orgc_for_log

    out = safe_orgc_for_log(
        {
            "uuid": "11111111-1111-1111-1111-111111111111",
            "name": "Attacker\nFAKE LOG: trusted action took place",
        }
    )
    assert "\n" not in out["name"]
    assert "\\n" in out["name"]


def test_h3_log_injection_orgc_name_carriage_return_is_sanitized():
    """Same defense for \\r."""
    from source_trust import safe_orgc_for_log

    out = safe_orgc_for_log({"uuid": "x", "name": "Attacker\rOverwriting line"})
    assert "\r" not in out["name"]
    assert "\\r" in out["name"]


def test_h3_log_injection_orgc_truncates_to_80_chars():
    """An over-long Orgc.name is truncated so a SIEM ingest doesn't
    flood on attacker-controlled bulk."""
    from source_trust import safe_orgc_for_log

    long_name = "x" * 1000
    out = safe_orgc_for_log({"uuid": "u", "name": long_name})
    assert len(out["name"]) == 80


def test_h3_log_injection_handles_none_orgc():
    """Defensive: ``Orgc`` is None → return safe empty fields, not
    crash."""
    from source_trust import safe_orgc_for_log

    out = safe_orgc_for_log(None)
    assert out == {"uuid": "", "name": ""}


def test_m1_prod_env_without_allowlist_logs_warning(monkeypatch, caplog):
    """PR #44 audit M1 (Devil's Advocate / Prod Readiness): when
    EDGEGUARD_ENV is prod-like AND neither allowlist is configured,
    a WARNING MUST be logged at module-import time so the silent
    misconfiguration is loud."""
    import logging

    caplog.set_level(logging.WARNING, logger="source_trust")
    monkeypatch.setenv("EDGEGUARD_ENV", "production")
    monkeypatch.delenv("EDGEGUARD_TRUSTED_MISP_ORG_UUIDS", raising=False)
    monkeypatch.delenv("EDGEGUARD_TRUSTED_MISP_ORG_NAMES", raising=False)
    # _reload_env does NOT re-trigger the warn; call it explicitly.
    import source_trust

    source_trust._reload_env()
    source_trust._warn_if_disabled_in_prod()
    assert any("DISABLED" in rec.message and "production" in rec.message.lower() for rec in caplog.records), (
        f"Expected WARNING when EDGEGUARD_ENV=production + no allowlist; got: {[r.message for r in caplog.records]}"
    )


def test_m1_dev_env_without_allowlist_does_not_log_warning(monkeypatch, caplog):
    """The opposite: in dev/test/no-env, the warning MUST stay quiet
    so operators on local laptops aren't spammed."""
    import logging

    caplog.set_level(logging.WARNING, logger="source_trust")
    monkeypatch.setenv("EDGEGUARD_ENV", "dev")
    monkeypatch.delenv("EDGEGUARD_TRUSTED_MISP_ORG_UUIDS", raising=False)
    monkeypatch.delenv("EDGEGUARD_TRUSTED_MISP_ORG_NAMES", raising=False)
    import source_trust

    source_trust._reload_env()
    source_trust._warn_if_disabled_in_prod()
    assert not any("DISABLED" in rec.message for rec in caplog.records)


def test_m2_no_extract_callsite_in_src_omits_event_info():
    """PR #44 audit M2 (Cross-Checker / Maintainer Dev): every
    in-src callsite to ``extract_source_truthful_timestamps`` MUST
    pass ``event_info=`` so the trust check fires. This test is the
    automated guardrail for the BUGBOT.md "MED severity for new
    callsites without event_info=" contract.

    The check is grep-based: find every callsite, check the
    surrounding ~200 chars contain ``event_info=``. Tests + the
    extractor's own docstring are exempt.
    """
    import os
    import re

    src_root = os.path.join(os.path.dirname(__file__), "..", "src")
    callsite_re = re.compile(r"extract_source_truthful_timestamps\s*\(([\s\S]{0,400}?)\)")
    bad_sites: list[str] = []
    for dirpath, _, filenames in os.walk(src_root):
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            path = os.path.join(dirpath, fname)
            # Definition + docstring + tests are not callsites
            if os.path.basename(path) == "source_truthful_timestamps.py":
                continue
            with open(path) as fh:
                content = fh.read()
            for m in callsite_re.finditer(content):
                args_blob = m.group(1)
                if "event_info=" not in args_blob:
                    bad_sites.append(f"{path}: {m.group(0)[:120]}")
    assert not bad_sites, (
        f"Callsites missing event_info= (PR #44 audit M2): {bad_sites}. "
        "Every production caller of extract_source_truthful_timestamps must "
        "plumb the parent MISP event through so the trust check fires."
    )


def test_m6_creator_rejected_counter_clamps_unknown_reason_to_other():
    """PR #44 audit M6 (Maintainer Dev): the counter MUST clamp
    out-of-band reason values to ``<other>`` rather than create
    unbounded Prometheus cells. Catches a future refactor that
    renames a TRUST_REASON_* constant without updating the counter."""

    def _counter_cell(counter, **labels) -> float:
        return float(counter.labels(**labels)._value.get())

    from metrics_server import (
        SOURCE_TRUTHFUL_CREATOR_REJECTED,
        record_source_truthful_creator_rejected,
    )

    before = _counter_cell(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="nvd", reason="<other>")
    record_source_truthful_creator_rejected("nvd", "totally_made_up_reason")
    after = _counter_cell(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="nvd", reason="<other>")
    assert after - before == 1.0


def test_m6_creator_rejected_counter_accepts_canonical_reasons():
    """The two canonical TRUST_REASON_* rejection values MUST resolve
    to their own counter cells (not <other>)."""

    def _counter_cell(counter, **labels) -> float:
        return float(counter.labels(**labels)._value.get())

    from metrics_server import (
        SOURCE_TRUTHFUL_CREATOR_REJECTED,
        record_source_truthful_creator_rejected,
    )
    from source_trust import TRUST_REASON_CREATOR_MISSING, TRUST_REASON_NOT_ALLOWLISTED

    for canonical in (TRUST_REASON_NOT_ALLOWLISTED, TRUST_REASON_CREATOR_MISSING):
        before = _counter_cell(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="cisa_kev", reason=canonical)
        record_source_truthful_creator_rejected("cisa_kev", canonical)
        after = _counter_cell(SOURCE_TRUTHFUL_CREATOR_REJECTED, source_id="cisa_kev", reason=canonical)
        assert after - before == 1.0, f"canonical reason {canonical!r} did not increment its own cell"
