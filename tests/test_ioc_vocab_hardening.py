"""Post-#126 IOC type-vocabulary hardening (2026-06).

Two residual risks from the robustness audit of PR #126:

1. ``node_identity._CASE_INSENSITIVE_INDICATOR_TYPES`` still carried the
   legacy raw-vocab entries ``btc``/``xmr``/``eth``. Dormant (every caller
   collapses btc→bitcoin via TYPE_MAPPING / _GRAPH_TYPE_MAP before reaching
   ``canonicalize_merge_key``), but a future direct caller passing the raw
   type would have lowercase-corrupted a Base58/EIP-55 address on write —
   contradicting the rationale documented in the same set ("lowercasing
   breaks the Base58 checksum"). Entries REMOVED; pinned here.

2. ``Neo4jClient.create_indicator_from_alert`` had a private local type map
   — the last unguarded copy of the type vocabulary — which had ALREADY
   drifted from the sync's TYPE_MAPPING: sha256/md5 stayed granular (sync
   collapses both to "hash") and "ip" blanket-mapped to ipv4 (IPv6 alerts
   mistyped). Since the Indicator MERGE key is (indicator_type, value), a
   caller bypassing alert_processor's pre-resolution MERGEd duplicate nodes.
   The map is replaced by ``ioc_normalize.canonicalize_lookup`` (the same
   layer every read entrypoint uses); end-to-end parity pinned here.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from node_identity import _CASE_INSENSITIVE_INDICATOR_TYPES, canonicalize_merge_key  # noqa: E402

# A real (well-known genesis-era) Base58 address shape — mixed case is the point.
_BASE58_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
_EIP55_ETH = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


class TestCryptoRawVocabRemoved:
    """Pin the REMOVAL of btc/xmr/eth from the case-folding set."""

    def test_raw_crypto_types_not_in_fold_set(self):
        for raw in ("btc", "xmr", "eth"):
            assert raw not in _CASE_INSENSITIVE_INDICATOR_TYPES, (
                f"'{raw}' must stay OUT of _CASE_INSENSITIVE_INDICATOR_TYPES — "
                "cryptocurrency addresses are case-sensitive (Base58 / EIP-55); "
                "folding corrupts the address"
            )

    def test_collapsed_bitcoin_type_not_in_fold_set(self):
        # The collapsed graph type must stay excluded too (PR #126 decision).
        assert "bitcoin" not in _CASE_INSENSITIVE_INDICATOR_TYPES

    def test_merge_key_preserves_base58_case_for_raw_btc_type(self):
        # THE failure mode the removal closes: a direct caller passing the
        # raw "btc" vocab no longer gets its address lowercased.
        out = canonicalize_merge_key("indicator", {"indicator_type": "btc", "value": _BASE58_BTC})
        assert out["value"] == _BASE58_BTC

    def test_merge_key_preserves_eip55_case_for_raw_eth_type(self):
        out = canonicalize_merge_key("indicator", {"indicator_type": "eth", "value": _EIP55_ETH})
        assert out["value"] == _EIP55_ETH

    def test_hash_still_folds(self):
        # Guard against over-removal: hex digests stay case-insensitive.
        digest = "DEADBEEF" * 8
        out = canonicalize_merge_key("indicator", {"indicator_type": "hash", "value": digest})
        assert out["value"] == digest.lower()


@pytest.fixture
def mock_neo4j_client():
    """Real Neo4jClient with a mocked driver/session (same pattern as
    tests/test_node_property_promotion.py)."""
    with patch.dict(os.environ, {"NEO4J_PASSWORD": "test", "MISP_API_KEY": "test"}):
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        client._uri = "bolt://localhost:7687"
        mock_session = MagicMock()
        mock_run = MagicMock()
        mock_run.single.return_value = None
        mock_session.run.return_value = mock_run
        client.driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
        return client, mock_session


def _merged_params(session):
    """(indicator_type, value) bound into the MERGE by the last run call."""
    kwargs = session.run.call_args.kwargs
    return kwargs["indicator_type"], kwargs["value"]


class TestCreateIndicatorFromAlertVocabParity:
    """create_indicator_from_alert must key the same (indicator_type, value)
    the MISP sync MERGEd — no more private drifted map."""

    def test_hostname_resolves_to_domain_and_folds(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        assert client.create_indicator_from_alert("EvIl.CoM", "hostname", "global") is True
        assert _merged_params(session) == ("domain", "evil.com")

    def test_sha256_collapses_to_hash(self, mock_neo4j_client):
        # The OLD local map kept sha256 granular — the sync stores "hash".
        client, session = mock_neo4j_client
        digest = "A" * 64
        client.create_indicator_from_alert(digest, "sha256", "global")
        assert _merged_params(session) == ("hash", digest.lower())

    def test_md5_collapses_to_hash(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        digest = "B" * 32
        client.create_indicator_from_alert(digest, "md5", "global")
        assert _merged_params(session) == ("hash", digest.lower())

    def test_btc_collapses_to_bitcoin_without_folding(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        client.create_indicator_from_alert(_BASE58_BTC, "btc", "global")
        assert _merged_params(session) == ("bitcoin", _BASE58_BTC)

    def test_ip_type_resolves_ipv6_by_value_shape(self, mock_neo4j_client):
        # The OLD local map blanket-mapped ip→ipv4.
        client, session = mock_neo4j_client
        client.create_indicator_from_alert("2001:db8::1", "ip", "global")
        itype, _ = _merged_params(session)
        assert itype == "ipv6"

    def test_misp_text_type_keys_unknown(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        client.create_indicator_from_alert("free form note", "text", "global")
        itype, _ = _merged_params(session)
        assert itype == "unknown"

    def test_defanged_typeless_value_refangs_and_infers(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        client.create_indicator_from_alert("EvIl[.]CoM", None, "global")
        assert _merged_params(session) == ("domain", "evil.com")

    def test_empty_value_never_merges(self, mock_neo4j_client):
        client, session = mock_neo4j_client
        assert client.create_indicator_from_alert("   ", "domain", "global") is False
        session.run.assert_not_called()

    def test_bare_defang_token_never_merges(self, mock_neo4j_client):
        # "[.]" refangs to "." — no alphanumeric content, no merge key.
        client, session = mock_neo4j_client
        assert client.create_indicator_from_alert("[.]", None, "global") is False
        session.run.assert_not_called()

    def test_every_sync_type_mapping_entry_agrees_end_to_end(self, mock_neo4j_client):
        """Drift guard at the WRITE path: for every entry in the sync's
        TYPE_MAPPING, the type bound into the alert-path MERGE equals the
        graph type the sync would store. This replaces the old unguarded
        local map with an executable invariant."""
        from run_misp_to_neo4j import MISPToNeo4jSync

        client, session = mock_neo4j_client
        for misp_type, graph_type in MISPToNeo4jSync.TYPE_MAPPING.items():
            session.run.reset_mock()
            client.create_indicator_from_alert("samplevalue123", misp_type, "global")
            itype, _ = _merged_params(session)
            assert itype == graph_type, (
                f"alert path stores '{misp_type}' as '{itype}' but the sync "
                f"stores '{graph_type}' — duplicate-node drift reintroduced"
            )
