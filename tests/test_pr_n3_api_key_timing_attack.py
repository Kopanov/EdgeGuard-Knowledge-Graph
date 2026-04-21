"""
PR-N3 — API key timing-attack hardening (``hmac.compare_digest``).

Closes Red Team B7 from the comprehensive 7-agent audit
(``docs/flow_audits/09_comprehensive_audit.md`` Tier B).

## The risk PR-N3 closes

Before PR-N3, both ``query_api._verify_api_key`` and
``graphql_api._verify_api_key`` used naive ``!=`` string comparison:

    if _API_KEY and x_api_key != _API_KEY:
        raise HTTPException(401, ...)

Python's ``!=`` operator on strings short-circuits at the first byte
mismatch, so the response time leaks information about how many
prefix bytes of the candidate key matched. An attacker on a
low-latency network (LAN, Docker network, K8s pod-to-pod) can
recover the API key one byte at a time by:

  1. Send candidates ``"a..."``, ``"b..."``, …, ``"z..."`` and
     measure response times.
  2. Whichever prefix takes microseconds longer to reject wins
     (it matched and the comparison ran further before failing).
  3. Repeat for the next byte.

This is the canonical timing side-channel. ``hmac.compare_digest``
runs in time independent of input content — that's its only
purpose.

## What PR-N3 enforces

1. Both verify functions use ``hmac.compare_digest(reference, candidate)``
   instead of ``!=``.

2. ``None`` candidate (missing header) is rejected explicitly BEFORE
   invoking ``compare_digest`` — passing ``None`` would crash with a
   ``TypeError`` since ``compare_digest`` expects str-or-bytes.

3. Both reference and candidate are wrapped in ``str()`` so a
   misbehaving client sending bytes doesn't crash the function.

4. Source-pin: the pre-fix ``!=`` comparison form must not return.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ===========================================================================
# Source pins — both verify_api_key functions use hmac.compare_digest
# ===========================================================================


class TestQueryApiUsesConstantTimeCompare:
    """``query_api._verify_api_key`` must use ``hmac.compare_digest``
    (constant-time) instead of ``!=`` (short-circuit, timing-leaky)."""

    def _read(self) -> str:
        return (SRC / "query_api.py").read_text()

    def test_imports_hmac(self):
        src = self._read()
        assert "import hmac" in src, "query_api must import hmac for constant-time comparison"

    def test_uses_compare_digest(self):
        src = self._read()
        # Active code only (skip comment lines)
        active = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        assert "hmac.compare_digest(" in active, (
            "query_api._verify_api_key must use hmac.compare_digest for "
            "constant-time API-key comparison (defeats timing side-channel)"
        )

    def test_no_naive_neq_compare_in_verify(self):
        """The pre-fix ``x_api_key != _API_KEY`` form must not appear
        in active (non-comment) code anywhere in query_api.py."""
        src = self._read()
        active = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        assert "x_api_key != _API_KEY" not in active, (
            "Regression: pre-fix naive ``!=`` API-key comparison is back. "
            "Use hmac.compare_digest instead — it's constant-time and "
            "defeats the timing side-channel that leaks the API key one "
            "byte at a time."
        )

    def test_handles_none_x_api_key(self):
        """The fix must guard against ``x_api_key is None`` BEFORE
        calling compare_digest (which crashes on None)."""
        src = self._read()
        active = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        assert "x_api_key is None" in active, (
            "verify_api_key must explicitly check ``x_api_key is None`` "
            "before calling hmac.compare_digest (which raises TypeError "
            "on None inputs)"
        )


class TestGraphqlApiUsesConstantTimeCompare:
    """Same invariant for ``graphql_api._verify_api_key``."""

    def _read(self) -> str:
        return (SRC / "graphql_api.py").read_text()

    def test_imports_hmac(self):
        src = self._read()
        assert "import hmac" in src

    def test_uses_compare_digest(self):
        src = self._read()
        active = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        assert "hmac.compare_digest(" in active

    def test_no_naive_neq_compare_in_verify(self):
        src = self._read()
        active = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        assert "x_api_key != EDGEGUARD_API_KEY" not in active, (
            "Regression: pre-fix naive ``!=`` API-key comparison is back "
            "in graphql_api. Use hmac.compare_digest instead."
        )

    def test_handles_none_x_api_key(self):
        src = self._read()
        active = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        assert "x_api_key is None" in active


# ===========================================================================
# Behavioural — verify_api_key actually rejects bad inputs cleanly
# ===========================================================================


class TestVerifyApiKeyBehavioural:
    """End-to-end check via FastAPI's HTTPException: the verify
    function must:
      * accept the correct key (no exception)
      * reject a wrong key (HTTPException 401)
      * reject a None header (HTTPException 401, NOT TypeError on
        compare_digest)
      * pass-through when EDGEGUARD_API_KEY is unset (no auth required)
    """

    def test_query_api_accepts_correct_key(self, monkeypatch):
        # Set the reference key BEFORE re-importing (the module reads
        # EDGEGUARD_API_KEY at import time)
        monkeypatch.setenv("EDGEGUARD_API_KEY", "test-secret-12345")
        # Force re-import to pick up the env value
        sys.modules.pop("query_api", None)
        import query_api as qa

        # Correct key — must not raise
        qa._verify_api_key("test-secret-12345")

    def test_query_api_rejects_wrong_key(self, monkeypatch):
        import pytest
        from fastapi import HTTPException

        monkeypatch.setenv("EDGEGUARD_API_KEY", "test-secret-12345")
        sys.modules.pop("query_api", None)
        import query_api as qa

        with pytest.raises(HTTPException) as exc_info:
            qa._verify_api_key("wrong-key")
        assert exc_info.value.status_code == 401

    def test_query_api_rejects_missing_header_no_typeerror(self, monkeypatch):
        """The original bug shape: ``hmac.compare_digest(None, key)``
        would raise ``TypeError``. The fix must reject None as 401,
        not crash with TypeError."""
        import pytest
        from fastapi import HTTPException

        monkeypatch.setenv("EDGEGUARD_API_KEY", "test-secret-12345")
        sys.modules.pop("query_api", None)
        import query_api as qa

        with pytest.raises(HTTPException) as exc_info:
            qa._verify_api_key(None)
        assert exc_info.value.status_code == 401

    def test_query_api_passthrough_when_no_key_configured(self, monkeypatch):
        """Without EDGEGUARD_API_KEY set, every request is unauth'd
        (the prod safety check at module-load fires elsewhere — here
        we just confirm verify is a no-op)."""
        monkeypatch.delenv("EDGEGUARD_API_KEY", raising=False)
        sys.modules.pop("query_api", None)
        import query_api as qa

        # No exception with any input
        qa._verify_api_key(None)
        qa._verify_api_key("anything")

    def test_query_api_resists_byte_input_without_crash(self, monkeypatch):
        """Misbehaving client sends a bytes header instead of str —
        must reject cleanly (401), not crash (TypeError)."""
        import pytest
        from fastapi import HTTPException

        monkeypatch.setenv("EDGEGUARD_API_KEY", "test-secret-12345")
        sys.modules.pop("query_api", None)
        import query_api as qa

        # If anything weird comes in, verify still behaves cleanly
        with pytest.raises(HTTPException):
            qa._verify_api_key(b"test-secret-12345")  # bytes, wrong type

    def test_graphql_api_accepts_correct_key(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_API_KEY", "test-secret-67890")
        sys.modules.pop("graphql_api", None)
        import graphql_api as ga

        ga._verify_api_key("test-secret-67890")

    def test_graphql_api_rejects_missing_header_no_typeerror(self, monkeypatch):
        import pytest
        from fastapi import HTTPException

        monkeypatch.setenv("EDGEGUARD_API_KEY", "test-secret-67890")
        sys.modules.pop("graphql_api", None)
        import graphql_api as ga

        with pytest.raises(HTTPException) as exc_info:
            ga._verify_api_key(None)
        assert exc_info.value.status_code == 401
