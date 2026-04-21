"""
PR-N2 — UUID namespace parity between ``node_identity`` and ``stix_exporter``.

Surfaced by Devil's Advocate F2 in the comprehensive 7-agent audit
(see ``docs/flow_audits/09_comprehensive_audit.md`` Tier B).

## The risk PR-N2 closes

``src/node_identity.py`` and ``src/stix_exporter.py`` BOTH declare
the same UUID literal ``5f2e1f9a-6a1b-5e0f-9b25-ed9ea2d574cb`` as the
deterministic-uuid namespace. The duplication is intentional (each
module reads correctly in isolation), but pre-PR-N2 NOTHING enforced
that the two literals stayed identical. A routine refactor that
edited one without the other would have silently broken every
Neo4j↔STIX cross-reference:

  * ``compute_node_uuid("Indicator", {...})`` produces ``n.uuid``
    using ``EDGEGUARD_NODE_UUID_NAMESPACE``
  * ``_deterministic_id("indicator", "...")`` produces the STIX SDO
    id UUID portion using ``EDGEGUARD_STIX_NAMESPACE``

When these two namespaces match (the design invariant), a ResilMesh
consumer reading STIX bundle ``indicator--abc-123-...`` can map back
to Neo4j ``n.uuid = "abc-123-..."`` for the same logical entity. When
they diverge, every cross-reference is broken and recovery requires a
graph-wide migration: re-stamp every node + re-export every bundle.

## What PR-N2 enforces

1. **Runtime guard at module-load time** in ``stix_exporter.py``:
   importing the module raises ``RuntimeError`` if the two literals
   differ. Uses an explicit ``raise`` rather than ``assert`` so the
   check fires even with Python's ``-O`` flag enabled.

2. **End-to-end parity check** in this test: compute the UUID of a
   sample logical entity using BOTH paths and assert they're
   byte-equal.

3. **Drift simulation**: monkeypatch one of the literals and verify
   the runtime guard would have fired (re-importing the module
   raises).
"""

from __future__ import annotations

import importlib
import sys
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ===========================================================================
# Direct equality of the two namespace constants
# ===========================================================================


class TestUuidNamespaceConstantsAreEqual:
    """The two ``UUID(...)`` literals declared in ``node_identity.py``
    and ``stix_exporter.py`` must be byte-equal at the value level."""

    def test_constants_are_equal(self):
        from node_identity import EDGEGUARD_NODE_UUID_NAMESPACE
        from stix_exporter import EDGEGUARD_STIX_NAMESPACE

        assert EDGEGUARD_STIX_NAMESPACE == EDGEGUARD_NODE_UUID_NAMESPACE, (
            f"UUID namespace drift detected: "
            f"node_identity={EDGEGUARD_NODE_UUID_NAMESPACE} vs "
            f"stix_exporter={EDGEGUARD_STIX_NAMESPACE}. "
            "These MUST be identical for cross-system Neo4j↔STIX traceability."
        )

    def test_constants_have_documented_value(self):
        """The frozen value documented in node_identity.py's FROZEN block."""
        from node_identity import EDGEGUARD_NODE_UUID_NAMESPACE

        assert str(EDGEGUARD_NODE_UUID_NAMESPACE) == "5f2e1f9a-6a1b-5e0f-9b25-ed9ea2d574cb", (
            "EDGEGUARD_NODE_UUID_NAMESPACE has changed value — this is a "
            "FROZEN constant per node_identity.py. Changing it invalidates "
            "every node uuid + every STIX SDO id ever produced. If you "
            "genuinely need migration, follow the playbook in node_identity.py's "
            "FROZEN block."
        )


# ===========================================================================
# End-to-end parity: same logical entity → same UUID via both paths
# ===========================================================================


class TestNeo4jStixUuidParityE2E:
    """Compute the UUID of a sample Indicator via the Neo4j-side
    ``compute_node_uuid`` AND the STIX-side ``_deterministic_id``,
    and assert the UUID portion matches.

    This is the actual cross-system traceability invariant — without
    it, a ResilMesh consumer reading a STIX bundle cannot map back
    to the originating Neo4j node by uuid."""

    def test_indicator_uuid_parity(self):
        from node_identity import compute_node_uuid
        from stix_exporter import _deterministic_id

        # Sample logical Indicator: ipv4 address
        ind_type = "ipv4"
        value = "203.0.113.5"

        # Neo4j-side: compute_node_uuid uses the canonical natural-key map
        node_uuid_str = compute_node_uuid("Indicator", {"indicator_type": ind_type, "value": value})

        # STIX-side: _deterministic_id needs the joined natural_key
        # (mimicking the exporter's own call site at stix_exporter.py
        # ``_indicator_sdo`` which does
        # ``f"{canonicalize_field_value(ind_type)}|{canonicalize_field_value(value)}"``)
        from node_identity import canonicalize_field_value

        stix_id = _deterministic_id(
            "indicator",
            f"{canonicalize_field_value(ind_type)}|{canonicalize_field_value(value)}",
        )
        # STIX ID format: "indicator--<uuid>"
        assert stix_id.startswith("indicator--")
        stix_uuid_str = stix_id.split("--", 1)[1]

        assert stix_uuid_str == node_uuid_str, (
            f"Cross-system UUID parity broken: Neo4j n.uuid={node_uuid_str!r} "
            f"vs STIX SDO id UUID portion={stix_uuid_str!r}. ResilMesh consumers "
            "reading the STIX bundle cannot cross-reference back to Neo4j."
        )

    def test_cve_uuid_parity(self):
        """Same parity check for a Vulnerability (different label, exercises
        a different natural-key path)."""
        from node_identity import canonicalize_field_value, compute_node_uuid
        from stix_exporter import _deterministic_id

        cve_id = "CVE-2013-0156"
        node_uuid_str = compute_node_uuid("Vulnerability", {"cve_id": cve_id})
        stix_id = _deterministic_id("vulnerability", canonicalize_field_value(cve_id))
        stix_uuid_str = stix_id.split("--", 1)[1]
        assert stix_uuid_str == node_uuid_str, (
            f"CVE cross-system UUID parity broken: node={node_uuid_str!r} vs STIX={stix_uuid_str!r}"
        )


# ===========================================================================
# Runtime guard fires on simulated drift
# ===========================================================================


class TestRuntimeGuardFiresOnDrift:
    """The import-time guard in ``stix_exporter.py`` must raise
    ``RuntimeError`` if someone edits one of the two literals without
    the other.

    We simulate drift by monkeypatching ``node_identity``'s constant
    BEFORE re-importing ``stix_exporter`` from a fresh module state.
    """

    def test_guard_raises_on_drift(self, monkeypatch):
        # We need to manipulate the module cache: remove stix_exporter
        # from sys.modules, monkeypatch node_identity's constant, then
        # re-import stix_exporter and confirm it raises.
        import node_identity

        # Cache the real value so we can restore later
        real_value = node_identity.EDGEGUARD_NODE_UUID_NAMESPACE

        # Drift simulation: replace node_identity's constant with a
        # different UUID
        drifted_uuid = uuid.UUID("00000000-0000-0000-0000-000000000001")
        monkeypatch.setattr(node_identity, "EDGEGUARD_NODE_UUID_NAMESPACE", drifted_uuid)

        # Drop stix_exporter from sys.modules so the next import
        # re-executes the module body (and the parity guard).
        # Save a reference so we can restore the cached module after.
        saved_stix_exporter = sys.modules.pop("stix_exporter", None)
        try:
            with pytest.raises(RuntimeError) as exc_info:
                importlib.import_module("stix_exporter")
            # Verify the error message names both constants and both
            # divergent values
            err = str(exc_info.value)
            assert "namespace drift" in err.lower() or "FATAL" in err
            assert "stix_exporter" in err
            assert "node_identity" in err
            assert "5f2e1f9a-6a1b-5e0f-9b25-ed9ea2d574cb" in err
            assert "00000000-0000-0000-0000-000000000001" in err
        finally:
            # Restore the real cached module + real value so other
            # tests don't see the drifted state
            sys.modules.pop("stix_exporter", None)
            if saved_stix_exporter is not None:
                sys.modules["stix_exporter"] = saved_stix_exporter
            node_identity.EDGEGUARD_NODE_UUID_NAMESPACE = real_value
            # Force a fresh import of stix_exporter so subsequent
            # tests in this run get a module bound to the real value
            importlib.import_module("stix_exporter")


# ===========================================================================
# Source-pin: the guard pattern is present in stix_exporter.py
# ===========================================================================


class TestSourceContainsRuntimeGuard:
    """Ensure the runtime guard pattern stays in ``stix_exporter.py``
    — a future cleanup that removed the guard while keeping the
    constants would silently re-introduce the drift risk."""

    def test_stix_exporter_has_parity_check(self):
        src = (SRC / "stix_exporter.py").read_text()
        # The import alias used by the guard
        assert (
            "from node_identity import EDGEGUARD_NODE_UUID_NAMESPACE as _EDGEGUARD_NODE_UUID_NAMESPACE_FOR_PARITY_CHECK"
            in src
        ), "Parity-check import must be present"
        # The explicit raise (not assert)
        assert "raise RuntimeError(" in src
        # Some discriminating message text
        assert "UUID namespace drift" in src

    def test_guard_uses_raise_not_assert(self):
        """``assert`` is stripped by Python's ``-O`` flag — must use
        explicit ``raise``."""
        src = (SRC / "stix_exporter.py").read_text()
        # Find the parity check region
        assert "PR-N2" in src
        # Find the guard block
        idx = src.find("EDGEGUARD_STIX_NAMESPACE != _EDGEGUARD_NODE_UUID_NAMESPACE_FOR_PARITY_CHECK")
        assert idx != -1, "Parity check expression missing"
        # Within ~600 chars of the check, find ``raise`` (not ``assert``)
        block = src[idx : idx + 600]
        assert "raise RuntimeError" in block, "guard must use explicit raise, not assert"
