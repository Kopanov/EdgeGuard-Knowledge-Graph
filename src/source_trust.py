"""Defense-in-depth: MISP tag-impersonation check for source-truthful claims.

Closes spawned-task chip 5e from the PR #41 audit. The S5 reliable-source
allowlist (``source_truthful_timestamps._RELIABLE_FIRST_SEEN_SOURCES``)
trusts the source identity carried in MISP attribute tags
(``raw_data.original_source`` / the source_id resolved from event tags).
That trust is binary: if the tag claims ``original_source: "nvd"`` and
``"nvd"`` is on the allowlist, EdgeGuard stamps the claim onto
``r.source_reported_first_at`` / ``r.source_reported_last_at``.

Threat model
------------
The MISP write surface is wider than EdgeGuard's collector accounts:

* A compromised MISP user account in a shared MISP deployment.
* A third-party feed pushing into a MISP that EdgeGuard also reads.
* An internal user manually adding an attribute and (mis)tagging it
  with a "trusted" source name.

Any of those produces a MISP attribute that LOOKS like authoritative
NVD / CISA / MITRE data to the source-truthful extractor. The forged
``original_source`` then anchors ``MIN(r.source_reported_first_at)``
permanently — corrupting the timeline EdgeGuard exports to ResilMesh
consumers (STIX ``valid_from``, alert enrichment, campaign
aggregates). The corruption is silent: the IOC ingest succeeds, the
edge stamp succeeds, and the only signal is the wrong date appearing
months later when an analyst notices.

Mitigation strategy (this module)
---------------------------------
**Verify the attribute's parent event was created by an EdgeGuard-
trusted MISP organization** before honoring its source-truthful claim.
The MISP event dict carries:

* ``event_info["Orgc"]["uuid"]`` — UUID of the **creator organization**
  (the org whose user wrote the original event; preserved across MISP
  shares — most authoritative signal).
* ``event_info["Orgc"]["name"]`` — human name of the creator org
  (fallback when an operator's MISP doesn't expose UUIDs cleanly,
  e.g. a federated peering).

Operators configure two env vars:

* ``EDGEGUARD_TRUSTED_MISP_ORG_UUIDS`` — comma-separated list of
  trusted creator-org UUIDs. Most authoritative; resists name-rename
  attacks and is what we recommend.
* ``EDGEGUARD_TRUSTED_MISP_ORG_NAMES`` — comma-separated list of
  trusted creator-org names (case-insensitive). Useful for
  deployments without stable UUIDs.

If a source-truthful claim arrives from an event whose ``Orgc`` is
NOT on either allowlist:

1. The claim is REJECTED — ``extract_source_truthful_timestamps``
   returns ``(None, None)`` and the SOURCED_FROM edge keeps its prior
   value (or stays NULL).
2. A WARNING is logged with full context (source_id, claimed values,
   creator org).
3. The Prometheus counter
   ``edgeguard_source_truthful_creator_rejected_total`` increments
   so operators can alert on the spoofing-attempt rate.

The IOC itself is STILL ingested and a ``:Source`` edge is still
created — only the source-truthful TIMESTAMPS are refused. The
honest-NULL principle (PR #41) ensures this is safe: NULL means
"we don't have a meaningful claim from this source," and the MIN /
MAX CASE on the edge preserves any prior legitimate value.

Backward compatibility
----------------------
**When neither allowlist env var is configured (the default), the
trust check is BYPASSED entirely.** ``is_attribute_creator_trusted``
returns ``(True, "trust_check_disabled")`` and behavior is identical
to pre-chip-5e. This is critical for:

* Pre-release / dev / test environments where operators haven't
  registered their EdgeGuard MISP user yet.
* Operators who deliberately want to ingest source-truthful claims
  from federated MISP peers without per-org allowlisting (the
  threat model is theirs to accept).

Production operators who want the defense MUST configure the env
vars. ``edgeguard doctor`` (TODO follow-up) should warn if neither
env var is set in a non-dev environment.

Future work — out of scope here
-------------------------------
* Cross-check the import path: if a MISP attribute claims
  ``original_source: "nvd"`` but the import was driven by the OTX
  collector, that's still a relay (legitimate) but a lower-confidence
  signal. PR #41 partially handles this via the
  ``raw_data.original_source`` extraction layer, but no metric tracks
  the relay rate.
* Per-attribute creator-user check (vs. per-event creator-org).
  PyMISP attribute objects don't carry creator_user directly; the
  per-event ``Orgc`` is the closest authoritative signal.
* Web of trust for federated MISP deployments. Out of scope.
"""

from __future__ import annotations

import logging
import os
import re
import unicodedata
from typing import Any, Dict, FrozenSet, Optional, Tuple

logger = logging.getLogger(__name__)


# Strict UUID format: 8-4-4-4-12 hex digits with hyphens. Anchored at
# both ends so a string like "abc-123-def" or accidentally-pasted
# whitespace doesn't sneak through.
_UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


# ---------------------------------------------------------------------------
# Env-driven allowlists — loaded ONCE at module import time
# ---------------------------------------------------------------------------
#
# Why module-level constants and not per-call env reads:
#
# * parse_attribute is in the hot loop (~M attributes per baseline).
#   Reading os.getenv per call is measurable CPU.
# * Reloading the allowlist would silently invalidate any in-flight
#   ingestion mid-batch, producing inconsistent results within one
#   sync run. Module-level capture pins the allowlist for the
#   lifetime of the process — operator restart applies changes.
#
# Misconfigured / typo'd UUIDs become "no UUIDs trusted" rather
# than crashing — let the ingest run; the WARNING log + Prometheus
# counter will alert operators that the trust check is firing
# rejections at 100%, which is the signal they need to fix the env.


def _parse_csv_env_uuids(name: str) -> FrozenSet[str]:
    """Parse a comma-separated UUID env var into a validated frozenset.

    PR #44 audit H2 (Red Team / Bug Hunter): each entry MUST match the
    canonical 8-4-4-4-12 UUID shape. Misconfigured entries (e.g. a
    name accidentally pasted into the UUID env var) get logged at
    WARNING and dropped — they would otherwise become a spoofing vector
    if a federated MISP peer's ``Orgc.uuid`` happened to equal the
    misconfigured string.

    Empty / unset → empty frozenset. Whitespace-tolerant.
    """
    raw = os.getenv(name, "")
    if not raw:
        return frozenset()
    parts = [p.strip().lower() for p in raw.split(",") if p.strip()]
    valid: set[str] = set()
    invalid: list[str] = []
    for p in parts:
        if _UUID_REGEX.match(p):
            valid.add(p)
        else:
            invalid.append(p)
    if invalid:
        logger.warning(
            "EDGEGUARD_TRUSTED_MISP_ORG_UUIDS: %d entries dropped — not a "
            "valid 8-4-4-4-12 UUID. Misconfigured entries are dangerous "
            "(could match a federated peer's Orgc.uuid by coincidence). "
            "Examples (truncated): %s",
            len(invalid),
            ", ".join(repr(p[:40]) for p in invalid[:5]),
        )
    return frozenset(valid)


def _parse_csv_env_names(name: str) -> FrozenSet[str]:
    """Parse a comma-separated NAME env var into a normalized frozenset.

    PR #44 audit H1 (Red Team): apply Unicode NFKC normalization +
    ``casefold`` (not just ``lower``) so homoglyph attacks
    ("EdgеGuard" with Cyrillic ``е``) and fullwidth-Latin variants
    are folded to the same byte sequence as the canonical name. Note
    that NFKC won't catch every homoglyph (e.g. Greek lookalikes that
    aren't in NFKC compatibility decompositions) — operators are
    advised in ``.env.example`` to prefer the UUID allowlist.

    Empty / unset → empty frozenset. Comma-in-name is unsupported
    (split character collision); documented in ``.env.example``.
    """
    raw = os.getenv(name, "")
    if not raw:
        return frozenset()
    parts = [_normalize_name(p) for p in raw.split(",")]
    return frozenset(p for p in parts if p)


def _normalize_name(value: Optional[str]) -> Optional[str]:
    """NFKC + casefold + strip — case-insensitive comparison key for org
    names. Returns ``None`` for None / empty / whitespace-only.

    PR #44 audit H1 (Red Team): NFKC catches Unicode compatibility
    homoglyphs (fullwidth Latin, ligatures, etc.); ``casefold`` is
    stronger than ``lower`` for Unicode case folding (e.g. German ß
    folds to ``ss``, Turkish dotless-i is handled).
    """
    if not value:
        return None
    s = unicodedata.normalize("NFKC", str(value)).strip().casefold()
    return s or None


_TRUSTED_CREATOR_ORG_UUIDS: FrozenSet[str] = _parse_csv_env_uuids("EDGEGUARD_TRUSTED_MISP_ORG_UUIDS")
_TRUSTED_CREATOR_ORG_NAMES: FrozenSet[str] = _parse_csv_env_names("EDGEGUARD_TRUSTED_MISP_ORG_NAMES")


# PR #44 audit M1 (Devil's Advocate / Prod Readiness): when the
# defense is disabled, log a WARNING at module import so the
# misconfiguration is loud, not silent.
#
# PR-I (2026-04-20 multi-agent audit Red Team #4): the original
# implementation gated the warning on ``EDGEGUARD_ENV ∈ {prod,
# staging}``. That meant dev — which is ``EDGEGUARD_ENV``'s default
# in ``config.py`` — silently accepted the disabled-defense state
# without any log signal at all. Every new deployment inherited
# "defense off + no warning" until an operator remembered to flip
# the env var. Widen the warning to fire in ALL envs: humans see
# the WARNING once per process in the log, and the companion
# Prometheus gauge ``edgeguard_misp_tag_impersonation_defense_disabled``
# (set in ``src/metrics_server.py``) exposes the state to alert
# rules so a missed log line can't mask a production gap.
#
# An accompanying planned change (see docs/SECURITY_ROADMAP.md) will
# flip the ``prod``/``staging`` default to fail-closed — refuse to
# boot unless the allowlists are configured OR
# ``EDGEGUARD_ALLOW_UNTRUSTED_MISP=1`` is set explicitly. That
# requires an operator-migration window which this observability
# layer provides.
def _log_defense_state() -> None:
    env = os.getenv("EDGEGUARD_ENV", "").strip().lower() or "unset"
    uuid_count = len(_TRUSTED_CREATOR_ORG_UUIDS)
    name_count = len(_TRUSTED_CREATOR_ORG_NAMES)
    if _TRUSTED_CREATOR_ORG_UUIDS or _TRUSTED_CREATOR_ORG_NAMES:
        logger.info(
            "MISP tag-impersonation defense ACTIVE (EDGEGUARD_ENV=%s, trusted_uuids=%d, trusted_names=%d).",
            env,
            uuid_count,
            name_count,
        )
    else:
        logger.warning(
            "MISP tag-impersonation defense is DISABLED (EDGEGUARD_ENV=%s) — "
            "all source-truthful claims accepted without creator-org "
            "verification. Set EDGEGUARD_TRUSTED_MISP_ORG_UUIDS "
            "(recommended) and/or EDGEGUARD_TRUSTED_MISP_ORG_NAMES to "
            "your EdgeGuard collector org's identifier(s). Without the "
            "allowlist, any MISP user / federated peer can spoof "
            "source_id='nvd' and silently corrupt "
            "MIN(r.source_reported_first_at). Planned: fail-closed in "
            "prod/staging — see docs/SECURITY_ROADMAP.md. Gauge: "
            "edgeguard_misp_tag_impersonation_defense_disabled.",
            env,
        )


_log_defense_state()


def is_trust_check_configured() -> bool:
    """Public: ``True`` iff at least one allowlist env var is non-empty.

    Exposed as a public API (no leading underscore) so other modules —
    notably ``src/metrics_server.py`` which mirrors this state into the
    ``edgeguard_misp_tag_impersonation_defense_disabled`` Prometheus
    gauge — can read it without reaching into private names. The
    private ``_trust_check_configured`` alias is retained for
    backward-compat with existing callers inside this module.
    """
    return _trust_check_configured()


# Trust-check decision reasons (also appears as the ``reason`` Prometheus
# label on ``edgeguard_source_truthful_creator_rejected_total``). Bounded
# enum so operator alerts can be specific.
TRUST_REASON_DISABLED = "trust_check_disabled"
TRUST_REASON_UUID_MATCH = "creator_org_in_uuid_allowlist"
TRUST_REASON_NAME_MATCH = "creator_org_in_name_allowlist"
TRUST_REASON_NOT_ALLOWLISTED = "creator_org_not_allowlisted"
TRUST_REASON_CREATOR_MISSING = "creator_org_missing"

# Bugbot LOW (2026-04-19): the ``_VALID_TRUST_REASONS`` frozenset that
# previously aggregated all five constants was unused — the metrics
# counter (M6 from the original audit) imports the two REJECTION
# constants directly via
# ``frozenset({TRUST_REASON_NOT_ALLOWLISTED, TRUST_REASON_CREATOR_MISSING})``.
# Removed to avoid carrying dead surface area; if a caller ever needs
# the full set, build it inline at the call site.


def _trust_check_configured() -> bool:
    """``True`` iff at least one allowlist env var is non-empty.

    When neither is configured, the trust check is BYPASSED — the
    module returns "trusted, disabled" for every input. Documented
    as the backward-compat path; operators who deliberately want
    the defense MUST configure at least one allowlist.
    """
    return bool(_TRUSTED_CREATOR_ORG_UUIDS or _TRUSTED_CREATOR_ORG_NAMES)


def _normalize_uuid(value: Optional[str]) -> Optional[str]:
    """Strict UUID lookup key. ``None`` / empty / non-UUID → ``None``.

    PR #44 audit H2 (Red Team): only accept canonical 8-4-4-4-12
    hex+hyphen UUID strings. An attacker-controlled MISP event whose
    ``Orgc.uuid`` is a free-text string (e.g. ``"edgeguard collectors"``)
    must NOT compare-equal to a misconfigured allowlist entry — return
    None so the lookup misses and the event REJECTs at the
    creator_org_missing path.
    """
    if not value:
        return None
    s = str(value).strip().lower()
    if not s or not _UUID_REGEX.match(s):
        return None
    return s


def is_attribute_creator_trusted(event_info: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    """Decide whether the parent event's creator org is on the allowlist.

    Returns ``(trusted, reason)`` where ``reason`` is one of the
    ``TRUST_REASON_*`` constants.

    Resolution order:

    1. **Trust check disabled** — neither allowlist env var configured
       → ``(True, TRUST_REASON_DISABLED)``. Backward-compat path.
    2. **Creator org UUID matches** ``EDGEGUARD_TRUSTED_MISP_ORG_UUIDS``
       → ``(True, TRUST_REASON_UUID_MATCH)``. Most authoritative;
       UUIDs are preserved across MISP shares.
    3. **Creator org name matches** ``EDGEGUARD_TRUSTED_MISP_ORG_NAMES``
       (case-insensitive) → ``(True, TRUST_REASON_NAME_MATCH)``. Use
       when the MISP deployment doesn't expose UUIDs cleanly.
    4. **No creator info on the event** → ``(False, TRUST_REASON_CREATOR_MISSING)``.
       The event is missing ``Orgc`` (or it's empty). Cannot verify
       provenance — REJECT to be safe.
    5. **Creator info present but not on either allowlist** →
       ``(False, TRUST_REASON_NOT_ALLOWLISTED)``. The signal that
       fires for spoofing attempts.

    Parameters
    ----------
    event_info : Optional[Dict[str, Any]]
        The MISP event dict (the parent of the attribute being parsed).
        Expected to expose ``event_info["Orgc"]["uuid"]`` and
        ``event_info["Orgc"]["name"]``. ``None`` is treated the same
        as missing creator info (REJECT) when the trust check is
        configured.
    """
    if not _trust_check_configured():
        return True, TRUST_REASON_DISABLED

    if not isinstance(event_info, dict):
        return False, TRUST_REASON_CREATOR_MISSING

    orgc = event_info.get("Orgc") or {}
    if not isinstance(orgc, dict):
        return False, TRUST_REASON_CREATOR_MISSING

    # PR #44 audit H2: UUIDs go through strict format validation —
    # a non-UUID value (e.g. attacker-controlled free-text) returns
    # None and falls through to the name check or REJECT.
    creator_uuid = _normalize_uuid(orgc.get("uuid"))
    # PR #44 audit H1: names go through NFKC + casefold to defeat
    # Unicode confusables (homoglyphs / fullwidth Latin / German ß /
    # Turkish dotless-i).
    creator_name = _normalize_name(orgc.get("name"))

    if not creator_uuid and not creator_name:
        return False, TRUST_REASON_CREATOR_MISSING

    if creator_uuid and creator_uuid in _TRUSTED_CREATOR_ORG_UUIDS:
        return True, TRUST_REASON_UUID_MATCH

    if creator_name and creator_name in _TRUSTED_CREATOR_ORG_NAMES:
        return True, TRUST_REASON_NAME_MATCH

    return False, TRUST_REASON_NOT_ALLOWLISTED


def safe_orgc_for_log(orgc: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Sanitize an MISP ``Orgc`` dict for safe inclusion in WARNING logs.

    PR #44 audit H3 (Red Team / Cross-Checker): ``Orgc.name`` is
    attacker-controllable (federated MISP peer). Logged verbatim it
    can carry CR/LF for log injection or excessive length to flood
    the SIEM. This helper:

    * Strips newlines / carriage returns / tabs (escaped to literal
      ``\\n`` / ``\\r`` / ``\\t`` so the log line stays one line).
    * Truncates each field to 80 chars.
    * Returns a fresh dict (not a reference into the caller's dict).
    """
    if not isinstance(orgc, dict):
        return {"uuid": "", "name": ""}

    def _safe_field(value: Any) -> str:
        s = str(value or "")[:80]
        return s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

    return {
        "uuid": _safe_field(orgc.get("uuid")),
        "name": _safe_field(orgc.get("name")),
    }


# ---------------------------------------------------------------------------
# Test / introspection helpers
# ---------------------------------------------------------------------------


def _reload_env() -> None:
    """Re-read env vars and reset the module-level allowlists.

    **Test-only.** Production code MUST treat the allowlists as
    immutable for the lifetime of the process (see the comment block
    above on why). Tests use this helper to flip the allowlist
    between cases via ``monkeypatch.setenv`` + ``_reload_env``.

    Uses the validated parsers (``_parse_csv_env_uuids`` rejects
    non-UUID entries; ``_parse_csv_env_names`` applies NFKC + casefold).
    """
    global _TRUSTED_CREATOR_ORG_UUIDS, _TRUSTED_CREATOR_ORG_NAMES
    _TRUSTED_CREATOR_ORG_UUIDS = _parse_csv_env_uuids("EDGEGUARD_TRUSTED_MISP_ORG_UUIDS")
    _TRUSTED_CREATOR_ORG_NAMES = _parse_csv_env_names("EDGEGUARD_TRUSTED_MISP_ORG_NAMES")


def trusted_uuids_snapshot() -> FrozenSet[str]:
    """Return the current trusted-UUID allowlist (introspection helper)."""
    return _TRUSTED_CREATOR_ORG_UUIDS


def trusted_names_snapshot() -> FrozenSet[str]:
    """Return the current trusted-name allowlist (introspection helper)."""
    return _TRUSTED_CREATOR_ORG_NAMES
