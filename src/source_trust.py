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
from typing import Any, Dict, FrozenSet, Optional, Tuple

logger = logging.getLogger(__name__)


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


def _parse_csv_env(name: str) -> FrozenSet[str]:
    """Parse a comma-separated env var into a normalized frozenset.

    Empty / unset → empty frozenset. Each entry is stripped + lowercased
    so the comparison is case-insensitive (org names) / canonicalized
    (UUIDs). UUID format is NOT validated — operators can paste raw
    output from MISP's UI and we'll match string-equality after lower.
    """
    raw = os.getenv(name, "")
    if not raw:
        return frozenset()
    parts = [p.strip().lower() for p in raw.split(",")]
    return frozenset(p for p in parts if p)


_TRUSTED_CREATOR_ORG_UUIDS: FrozenSet[str] = _parse_csv_env("EDGEGUARD_TRUSTED_MISP_ORG_UUIDS")
_TRUSTED_CREATOR_ORG_NAMES: FrozenSet[str] = _parse_csv_env("EDGEGUARD_TRUSTED_MISP_ORG_NAMES")


# Trust-check decision reasons (also appears as the ``reason`` Prometheus
# label on ``edgeguard_source_truthful_creator_rejected_total``). Bounded
# enum so operator alerts can be specific.
TRUST_REASON_DISABLED = "trust_check_disabled"
TRUST_REASON_UUID_MATCH = "creator_org_in_uuid_allowlist"
TRUST_REASON_NAME_MATCH = "creator_org_in_name_allowlist"
TRUST_REASON_NOT_ALLOWLISTED = "creator_org_not_allowlisted"
TRUST_REASON_CREATOR_MISSING = "creator_org_missing"

_VALID_TRUST_REASONS: FrozenSet[str] = frozenset(
    {
        TRUST_REASON_DISABLED,
        TRUST_REASON_UUID_MATCH,
        TRUST_REASON_NAME_MATCH,
        TRUST_REASON_NOT_ALLOWLISTED,
        TRUST_REASON_CREATOR_MISSING,
    }
)


def _trust_check_configured() -> bool:
    """``True`` iff at least one allowlist env var is non-empty.

    When neither is configured, the trust check is BYPASSED — the
    module returns "trusted, disabled" for every input. Documented
    as the backward-compat path; operators who deliberately want
    the defense MUST configure at least one allowlist.
    """
    return bool(_TRUSTED_CREATOR_ORG_UUIDS or _TRUSTED_CREATOR_ORG_NAMES)


def _normalize(value: Optional[str]) -> Optional[str]:
    """Lowercased + stripped lookup key. ``None`` / empty → ``None``."""
    if not value:
        return None
    s = str(value).strip().lower()
    return s or None


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

    creator_uuid = _normalize(orgc.get("uuid"))
    creator_name = _normalize(orgc.get("name"))

    if not creator_uuid and not creator_name:
        return False, TRUST_REASON_CREATOR_MISSING

    if creator_uuid and creator_uuid in _TRUSTED_CREATOR_ORG_UUIDS:
        return True, TRUST_REASON_UUID_MATCH

    if creator_name and creator_name in _TRUSTED_CREATOR_ORG_NAMES:
        return True, TRUST_REASON_NAME_MATCH

    return False, TRUST_REASON_NOT_ALLOWLISTED


# ---------------------------------------------------------------------------
# Test / introspection helpers
# ---------------------------------------------------------------------------


def _reload_env() -> None:
    """Re-read env vars and reset the module-level allowlists.

    **Test-only.** Production code MUST treat the allowlists as
    immutable for the lifetime of the process (see the comment block
    above on why). Tests use this helper to flip the allowlist
    between cases via ``monkeypatch.setenv`` + ``_reload_env``.
    """
    global _TRUSTED_CREATOR_ORG_UUIDS, _TRUSTED_CREATOR_ORG_NAMES
    _TRUSTED_CREATOR_ORG_UUIDS = _parse_csv_env("EDGEGUARD_TRUSTED_MISP_ORG_UUIDS")
    _TRUSTED_CREATOR_ORG_NAMES = _parse_csv_env("EDGEGUARD_TRUSTED_MISP_ORG_NAMES")


def trusted_uuids_snapshot() -> FrozenSet[str]:
    """Return the current trusted-UUID allowlist (introspection helper)."""
    return _TRUSTED_CREATOR_ORG_UUIDS


def trusted_names_snapshot() -> FrozenSet[str]:
    """Return the current trusted-name allowlist (introspection helper)."""
    return _TRUSTED_CREATOR_ORG_NAMES
