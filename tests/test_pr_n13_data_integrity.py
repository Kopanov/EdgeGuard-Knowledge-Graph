"""
PR-N13 — pre-baseline data-integrity bundle.

Six findings from the pre-baseline 7-agent audit's Data-Integrity pass.
Each is a silent-data-loss or hub-collapse vector that would manifest
at scale during the 730-day baseline.

## Fix #1 — None-guard on merge_indicator + merge_indicators_batch value

Pre-PR-N13, ``merge_indicator({"indicator_type": None, "value": None})``
canonicalized to ``{"indicator_type": None, "value": None}`` and reached
Cypher as ``MERGE (i:Indicator {indicator_type: null, value: null})``,
which collapses EVERY None-keyed row into one sentinel hub node. A
single malformed OTX pulse at scale (400K indicators/day) could poison
a production hub node that downstream cross-joins for thousands of
spurious relationships. ``merge_ip`` / ``merge_host`` already had this
guard (PR #N, 2025); ``merge_indicator`` did not.

Fix: early reject if ``nonempty_graph_string(value)`` or
``nonempty_graph_string(indicator_type)`` returns None, with a
MERGE-REJECT log line. Applied to both the single-item path
(``merge_indicator``) and the batch path
(``merge_indicators_batch`` pre-Cypher filter).

## Fix #2 — None-guard on merge_technique / merge_tactic / merge_tool

Same vector on MITRE ATT&CK IDs. A MITRE tag without ``mitre_id``
(malformed ingest, partial dictionary) silently hijacks the
``(Technique {mitre_id: null})`` sentinel node — every None-keyed
Technique row after that collapses into it. Mirrors the PR-N10
placeholder-name guard for Malware / Actor.

## Fix #3 — NVD_META carries ``version_constraints`` + ``status``

Same silent-drop class as PR-N10 Fix #3 (OTX_META malware_family).
NVD collector emits per-CPE ``version_constraints`` and the
``status=["active"]`` / ``["rejected"]`` field. NVD_META in
``misp_writer.py`` omitted both. ``merge_cve`` in neo4j_client
already reads both when present. Net: every NVD-sourced CVE
reached Neo4j with ``version_constraints=None`` and (more
critically) ``status`` defaulted to active — a withdrawn CVE
silently lands as if active.

## Fix #4 — TF_META carries ``threat_type`` + ``ioc_id`` + ``malware_alias``

ThreatFox collector emits three fields that were being dropped:
- ``threat_type`` — payload / C2 / exfil category
- ``ioc_id`` — canonical ThreatFox ID (stable cross-day dedup key)
- ``malware_alias`` — alternate names (feeds Q2 / Q9 alias-match)

Loss of ``ioc_id`` in particular broke ThreatFox re-ingest dedup
across daily CSV exports, so the same IOC was re-created fresh
every day.

## Fix #5 — OTX_META carries ``pulse_id`` + ``indicator_role`` + ``is_active``

OTX collector emits:
- ``pulse_id`` — native OTX pulse UUID (cross-deployment dedup key)
- ``indicator_role`` — "C2" / "dropper" — DRIVES Neo4j property
  mapping live-wired at ``merge_indicators_batch:~L2169``. Every
  OTX Indicator was missing this because OTX_META didn't carry it.
- ``is_active`` — source-side activity state

## Fix #6 — Rehydration for all new fields

``run_misp_to_neo4j.py`` pulls the new fields out of the parsed
meta dicts and promotes them to the item dict that reaches
``merge_indicator`` / ``merge_cve``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n13")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n13")


# ===========================================================================
# Fix #1 — merge_indicator None-guard
# ===========================================================================


class TestFix1MergeIndicatorNoneGuard:
    def test_merge_indicator_rejects_none_value(self, caplog):
        import logging

        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()

        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            result = client.merge_indicator({"indicator_type": "ipv4", "value": None})
        assert result is False, "merge_indicator must reject value=None"
        assert any("MERGE-REJECT" in r.message for r in caplog.records), "must emit [MERGE-REJECT] warning"

    def test_merge_indicator_rejects_empty_value(self):
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        for bad in ["", " ", "\t", "\n", "   "]:
            assert client.merge_indicator({"indicator_type": "ipv4", "value": bad}) is False, (
                f"must reject whitespace-only value {bad!r}"
            )

    def test_merge_indicator_rejects_none_type(self):
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        for bad in [None, "", "  "]:
            assert client.merge_indicator({"indicator_type": bad, "value": "203.0.113.5"}) is False, (
                f"must reject indicator_type={bad!r}"
            )

    def test_merge_indicators_batch_skips_none_value_rows(self, caplog):
        """Batch path must filter None/empty BEFORE Cypher — otherwise
        the UNWIND collapses every None-keyed row into one sentinel."""

        src = (SRC / "neo4j_client.py").read_text()
        # AST pin: the nonempty_graph_string filter must appear inside
        # the merge_indicators_batch row loop (surfaced via a MERGE-REJECT
        # log line).
        assert 'logger.warning(\n                            "[MERGE-REJECT] merge_indicators_batch:' in src, (
            "batch path must emit MERGE-REJECT on None/empty value"
        )
        # And `nonempty_graph_string(item.get("value"))` must be called.
        assert 'nonempty_graph_string(item.get("value"))' in src, "batch path must call nonempty_graph_string on value"
        assert 'nonempty_graph_string(item.get("indicator_type"))' in src, (
            "batch path must call nonempty_graph_string on indicator_type"
        )


# ===========================================================================
# Fix #2 — MITRE merge None-guards
# ===========================================================================


class TestFix2MitreNoneGuards:
    def _client(self):
        from neo4j_client import Neo4jClient

        c = Neo4jClient.__new__(Neo4jClient)
        c.driver = MagicMock()
        return c

    def test_merge_technique_rejects_none_mitre_id(self, caplog):
        import logging

        c = self._client()
        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            result = c.merge_technique({"name": "Foo", "mitre_id": None})
        assert result is False
        assert any("MERGE-REJECT" in r.message and "Technique" in r.message for r in caplog.records)

    def test_merge_tactic_rejects_empty_mitre_id(self):
        c = self._client()
        for bad in [None, "", "   ", "\t"]:
            assert c.merge_tactic({"mitre_id": bad, "name": "Foo"}) is False

    def test_merge_tool_rejects_none_mitre_id(self):
        c = self._client()
        for bad in [None, "", "   "]:
            assert c.merge_tool({"mitre_id": bad, "name": "Foo"}) is False

    def test_merge_technique_accepts_valid_mitre_id(self):
        """Sanity: legitimate mitre_id passes through to the
        merge_node_with_source call."""
        c = self._client()
        # merge_node_with_source reads self.driver — we stubbed it with
        # MagicMock that has truthy __bool__, so the merge returns truthy.
        # The test is really: does the code path NOT early-return False?
        # We monkeypatch merge_node_with_source to return a sentinel.
        c.merge_node_with_source = MagicMock(return_value=True)
        assert c.merge_technique({"mitre_id": "T1566", "name": "Phishing"}) is True
        c.merge_node_with_source.assert_called_once()
        call_args = c.merge_node_with_source.call_args
        # key_props is third positional arg
        key_props = call_args[0][1]
        assert key_props == {"mitre_id": "T1566"}


# ===========================================================================
# Fix #3 — NVD_META carries version_constraints + status
# ===========================================================================


class TestFix3NvdMetaCompletion:
    def test_nvd_meta_includes_version_constraints(self):
        src = (SRC / "collectors" / "misp_writer.py").read_text()
        # Find the NVD_META block and scan for version_constraints.
        # Use a wide window since the block includes ~20 fields + a
        # breadcrumb comment.
        idx = src.find('"cvss_v40_data": vuln.get("cvss_v40_data")')
        assert idx != -1, "NVD_META block not found"
        block = src[idx : idx + 4000]
        assert '"version_constraints": vuln.get("version_constraints"' in block, (
            "NVD_META must include version_constraints (Fix #3)"
        )

    def test_nvd_meta_includes_status(self):
        src = (SRC / "collectors" / "misp_writer.py").read_text()
        idx = src.find('"cvss_v40_data": vuln.get("cvss_v40_data")')
        assert idx != -1
        block = src[idx : idx + 4000]
        assert '"status": vuln.get("status"' in block, "NVD_META must include status (Fix #3)"

    def test_run_misp_to_neo4j_rehydrates_version_constraints(self):
        """Rehydration pin — the value must reach the item dict."""
        src = (SRC / "run_misp_to_neo4j.py").read_text()
        # Find the NVD item-build block (has cvss_v40_data immediately before)
        idx = src.find('"cvss_v40_data": nvd_meta.get("cvss_v40_data"')
        assert idx != -1, "NVD item-build block not found"
        block = src[idx : idx + 2000]
        assert '"version_constraints": nvd_meta.get("version_constraints"' in block, (
            "run_misp_to_neo4j must rehydrate version_constraints from NVD_META"
        )
        assert '"status": nvd_meta.get("status"' in block, "run_misp_to_neo4j must rehydrate status from NVD_META"


# ===========================================================================
# Fix #4 — TF_META completion
# ===========================================================================


class TestFix4TfMetaCompletion:
    def test_tf_meta_includes_new_fields(self):
        src = (SRC / "collectors" / "misp_writer.py").read_text()
        # Find TF_META's anchor field and scan forward
        idx = src.find('"malware_malpedia": indicator.get("malware_malpedia"')
        assert idx != -1
        block = src[idx : idx + 3500]
        for field in ("threat_type", "ioc_id", "malware_alias"):
            assert f'"{field}": indicator.get("{field}"' in block, f"TF_META must include {field} (Fix #4)"

    def test_tf_meta_rehydration(self):
        src = (SRC / "run_misp_to_neo4j.py").read_text()
        # Find the TF rehydrate block
        idx = src.find('item["malware_malpedia"] = tf_meta.get("malware_malpedia"')
        assert idx != -1
        block = src[idx : idx + 2500]
        for field in ("threat_type", "ioc_id", "malware_alias"):
            assert f'item["{field}"] = tf_meta.get("{field}"' in block, (
                f"run_misp_to_neo4j must rehydrate {field} from TF_META"
            )


# ===========================================================================
# Fix #5 — OTX_META completion
# ===========================================================================


class TestFix5OtxMetaCompletion:
    def test_otx_meta_includes_new_fields(self):
        src = (SRC / "collectors" / "misp_writer.py").read_text()
        idx = src.find('"attack_ids": indicator.get("attack_ids"')
        assert idx != -1
        block = src[idx : idx + 3500]
        for field in ("pulse_id", "indicator_role", "is_active"):
            assert f'"{field}": indicator.get("{field}"' in block, f"OTX_META must include {field} (Fix #5)"

    def test_otx_meta_rehydration(self):
        src = (SRC / "run_misp_to_neo4j.py").read_text()
        # Find the OTX rehydrate block — uses malware_family as anchor
        idx = src.find('item["malware_family"] = otx_meta.get("malware_family"')
        assert idx != -1
        block = src[idx : idx + 2500]
        for field in ("pulse_id", "indicator_role", "is_active"):
            assert f'item["{field}"] = otx_meta.get("{field}"' in block, (
                f"run_misp_to_neo4j must rehydrate {field} from OTX_META"
            )


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_neo4j_client_imports(self):
        import neo4j_client  # noqa: F401

    def test_misp_writer_imports(self):
        from collectors import misp_writer  # noqa: F401

    def test_run_misp_to_neo4j_imports(self):
        import run_misp_to_neo4j  # noqa: F401
