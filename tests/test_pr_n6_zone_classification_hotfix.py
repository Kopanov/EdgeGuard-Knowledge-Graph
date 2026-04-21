"""
PR-N6 — Zone classification Tier-A hotfix bundle.

Four findings from the 5-agent zone-classification audit (run 2026-04-21,
synthesis at the end of PR #89's cycle). All four are strongest-signal
cross-agent-corroborated findings:

  #1 [HIGH]  VALID_ZONES whitelist bypass at 4 call sites.
            (Bug Hunter H2 + H3, Cross-Checker F1 + F2)
            A MISP user / federated peer adding ``zone:malware`` or
            ``zone:<typo>`` tags silently corrupts Neo4j + STIX output
            — no downstream filter catches it because the only existing
            filter lived inside ``detect_zones_from_text``.

  #2 [HIGH]  ``EDGEGUARD_ZONE_*_THRESHOLD=inf`` silently disables
            classification.  (Bug Hunter H1)
            ``max(0.1, float('inf'))`` returns ``inf``; every weighted
            score falls below threshold → every item routes to
            ``["global"]``. Same class of bug as PR-N4 R5 NaN-bypass
            in MISP backoff settings.

  #4 [HIGH]  OTX ``_industry_map`` dictionary drifts from
            ``SECTOR_KEYWORDS``.  (Maintainer #1, Cross-Checker F4)
            A second keyword source of truth hidden inside
            otx_collector.py, containing vocabulary absent from
            ``config.py`` ("pharmaceutical", "utilities", "oil",
            "gas", "insurance"). Future vocabulary refinements in
            the canonical dict silently skipped OTX ingestion.

  #5 [MED]   ``sector:`` tag prefix accepted in one reader, not others.
            (Cross-Checker F4)
            ``run_misp_to_neo4j.extract_zones_from_tags`` read both
            ``zone:`` and ``sector:``. ``misp_collector._extract_zones_from_tags``
            and the manual-STIX fallback read only ``zone:``. Any
            feed using ``sector:`` produced divergent Neo4j vs STIX
            output on the same attribute.

## Test strategy

Mix of source pins and behavioural tests. The env-override tests
(finding #2) reload ``config`` so the new env value is read; callers
are responsible for restoring the env after the test.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n6")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n6")


# ===========================================================================
# Finding #1 — VALID_ZONES whitelist closed across all 4 extraction sites
# ===========================================================================


class TestFinding1ValidZonesWhitelist:
    """The ``VALID_ZONES`` whitelist must be applied consistently at
    every zone-extraction site. Pre-fix 4 sites bypassed it."""

    def test_module_load_asserts_sector_keywords_is_subset(self):
        """Implicit invariant made explicit: ``SECTOR_KEYWORDS.keys() <=
        VALID_ZONES``. Pre-fix a maintainer could add a key to
        ``SECTOR_KEYWORDS`` without updating ``VALID_ZONES`` and the
        drift would be silent (the VALID_ZONES filter in
        detect_zones_from_text would silently drop the new key's matches).
        Module-load assertion now makes the contract load-bearing."""
        src = (SRC / "config.py").read_text()
        assert "set(SECTOR_KEYWORDS.keys()) <= VALID_ZONES" in src, (
            "module-load assertion on SECTOR_KEYWORDS ⊆ VALID_ZONES must exist"
        )

    def test_detect_zones_from_item_filters_through_valid_zones(self):
        """Audit finding #1 site 3: ``detect_zones_from_item`` previously
        did NOT filter through VALID_ZONES before returning — it relied
        on the implicit invariant SECTOR_KEYWORDS ⊆ VALID_ZONES.
        Making the filter explicit closes the drift risk."""
        src = (SRC / "config.py").read_text()
        fn_idx = src.find("def detect_zones_from_item(")
        assert fn_idx != -1
        next_fn = src.find("\ndef ", fn_idx + 1)
        body = src[fn_idx : next_fn if next_fn != -1 else len(src)]
        # Filter must appear within the function body
        assert "z in VALID_ZONES" in body, "detect_zones_from_item must filter matched zones through VALID_ZONES"

    def test_misp_collector_tag_reader_filters_through_valid_zones(self):
        """Audit finding #1 site 1: ``_extract_zones_from_tags`` in
        misp_collector.py previously accepted ``zone:<anything>``
        verbatim. Must now filter through VALID_ZONES."""
        src = (SRC / "collectors" / "misp_collector.py").read_text()
        fn_idx = src.find("def _extract_zones_from_tags(")
        assert fn_idx != -1
        next_fn = src.find("\n    def ", fn_idx + 1)
        body = src[fn_idx : next_fn if next_fn != -1 else len(src)]
        assert "VALID_ZONES" in body, "misp_collector._extract_zones_from_tags must filter through VALID_ZONES"
        # And the filter must be a membership check on the extracted zone
        assert "in VALID_ZONES" in body, "filter must be 'zone_name in VALID_ZONES' membership check"

    def test_run_misp_to_neo4j_stix_fallback_filters_through_valid_zones(self):
        """Audit finding #1 site 2: the attribute-level manual-STIX
        fallback in ``_attribute_to_stix21`` previously read
        ``zone:<anything>`` verbatim and emitted STIX labels. Must
        now filter through VALID_ZONES."""
        src = (SRC / "run_misp_to_neo4j.py").read_text()
        # Find the attribute-tag zone loop by its distinctive
        # ``labels.append(f"zone:{zone_name}")`` line
        marker = 'labels.append(f"zone:{zone_name}")'
        idx = src.find(marker)
        assert idx != -1
        block = src[max(0, idx - 800) : idx]
        assert "VALID_ZONES" in block, "the manual-STIX fallback zone loop must filter through VALID_ZONES"

    def test_stix_exporter_extract_zones_defense_in_depth_filter(self):
        """Audit finding #1 site 4: ``_extract_zones`` in stix_exporter.py
        reads zones from Neo4j and emits STIX labels/custom props.
        Must filter through VALID_ZONES as defense-in-depth — if any
        upstream write path ever slips an unvalidated zone through,
        this is the last stop before ResilMesh sees it."""
        src = (SRC / "stix_exporter.py").read_text()
        fn_idx = src.find("def _extract_zones(")
        assert fn_idx != -1
        next_fn = src.find("\ndef ", fn_idx + 1)
        body = src[fn_idx : next_fn if next_fn != -1 else len(src)]
        assert "VALID_ZONES" in body, "stix_exporter._extract_zones must filter through VALID_ZONES"

    # --- Behavioural ---

    def test_behaviour_misp_collector_drops_malicious_tag(self):
        """A MISP tag ``zone:malware`` (attacker-controlled or typo)
        must be dropped, not emitted as a zone."""
        from collectors.misp_collector import MISPCollector

        tags = [{"name": "zone:malware"}, {"name": "zone:healthcare"}]
        zones = MISPCollector._extract_zones_from_tags(tags)
        assert "malware" not in zones, "malicious zone tag must be filtered"
        assert "healthcare" in zones, "legitimate zone must pass through"

    def test_behaviour_misp_collector_drops_typo_tag(self):
        """A MISP tag ``zone:healthcares`` (typo) must be dropped."""
        from collectors.misp_collector import MISPCollector

        tags = [{"name": "zone:healthcares"}]
        zones = MISPCollector._extract_zones_from_tags(tags)
        assert zones == [], f"typo'd zone must not pass; got {zones}"

    def test_behaviour_stix_exporter_drops_non_canonical_zone(self):
        """A Neo4j node with ``zone: ["malware", "finance"]`` (some
        data corruption) must emit only ``["finance"]`` to STIX —
        plus a WARN log (checked in test_behaviour_stix_exporter_warns_on_drop)."""
        from stix_exporter import _extract_zones

        props = {"zone": ["malware", "finance"]}
        result = _extract_zones(props)
        assert result == ["finance"], f"expected ['finance'], got {result}"


# ===========================================================================
# Finding #2 — inf / NaN threshold bypass
# ===========================================================================


class TestFinding2InfNaNThresholdBypass:
    """``EDGEGUARD_ZONE_*_THRESHOLD=inf`` / ``NaN`` previously slipped
    past the ``max(0.1, float('inf')) == inf`` guard and silently
    disabled all classification."""

    def test_bounded_env_float_helper_exists(self):
        src = (SRC / "config.py").read_text()
        assert "def _bounded_env_float(" in src, "PR-N6 #2: bounded helper must exist"
        assert "math.isfinite" in src, "helper must use math.isfinite"

    def test_thresholds_use_bounded_helper(self):
        src = (SRC / "config.py").read_text()
        assert '_bounded_env_float("EDGEGUARD_ZONE_DETECT_THRESHOLD"' in src
        assert '_bounded_env_float("EDGEGUARD_ZONE_ITEM_THRESHOLD"' in src
        # The old buggy idiom must be fully removed
        assert 'max(0.1, _env_float("EDGEGUARD_ZONE_DETECT_THRESHOLD"' not in src, (
            "PR-N6 #2 regression: the old max(0.1, _env_float(...)) idiom let inf slip through — must stay removed"
        )

    def test_behaviour_inf_env_falls_back_to_default(self, monkeypatch):
        """Setting the env var to ``inf`` must NOT propagate inf into
        ``ZONE_DETECT_THRESHOLD`` — must fall back to 1.5 default."""
        monkeypatch.setenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", "inf")
        import config

        importlib.reload(config)
        assert config.ZONE_DETECT_THRESHOLD == 1.5, (
            f"inf env must fall back to 1.5 default; got {config.ZONE_DETECT_THRESHOLD}"
        )
        # Reset for other tests
        monkeypatch.delenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", raising=False)
        importlib.reload(config)

    def test_behaviour_nan_env_falls_back_to_default(self, monkeypatch):
        """NaN must also fall back to default."""
        monkeypatch.setenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", "NaN")
        import config

        importlib.reload(config)
        assert config.ZONE_DETECT_THRESHOLD == 1.5, (
            f"NaN env must fall back to 1.5 default; got {config.ZONE_DETECT_THRESHOLD}"
        )
        monkeypatch.delenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", raising=False)
        importlib.reload(config)

    def test_behaviour_neg_inf_env_falls_back_to_default(self, monkeypatch):
        """-inf must fall back too (math.isfinite rejects both ±inf)."""
        monkeypatch.setenv("EDGEGUARD_ZONE_ITEM_THRESHOLD", "-inf")
        import config

        importlib.reload(config)
        assert config.ZONE_ITEM_COMBINED_THRESHOLD == 1.5
        monkeypatch.delenv("EDGEGUARD_ZONE_ITEM_THRESHOLD", raising=False)
        importlib.reload(config)

    def test_behaviour_out_of_range_env_falls_back(self, monkeypatch):
        """Values outside [0.1, 100.0] must fall back — sanity envelope."""
        monkeypatch.setenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", "1000.0")
        import config

        importlib.reload(config)
        assert config.ZONE_DETECT_THRESHOLD == 1.5
        monkeypatch.delenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", raising=False)
        importlib.reload(config)

    def test_behaviour_valid_env_takes_effect(self, monkeypatch):
        """Positive: a valid value in range IS applied."""
        monkeypatch.setenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", "2.5")
        import config

        importlib.reload(config)
        assert config.ZONE_DETECT_THRESHOLD == 2.5, (
            f"valid env value must be applied; got {config.ZONE_DETECT_THRESHOLD}"
        )
        monkeypatch.delenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", raising=False)
        importlib.reload(config)

    # --- Bugbot PR-N6 R1 MED regression pins: WARN-on-rejection ---

    def test_r1_warn_on_nan(self, monkeypatch, caplog):
        """Bugbot PR-N6 R1 MED (2026-04-21): ``_bounded_env_float`` must
        emit ``logger.warning`` on every rejection path. Pre-fix the
        docstring CLAIMED WARN-on-rejection but the implementation was
        silent — operator setting
        ``EDGEGUARD_ZONE_DETECT_THRESHOLD=inf`` would silently fall
        back to default with no log signal."""
        import logging

        monkeypatch.setenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", "NaN")
        with caplog.at_level(logging.WARNING, logger="config"):
            import config

            importlib.reload(config)

        assert any(
            "non-finite" in rec.message and "EDGEGUARD_ZONE_DETECT_THRESHOLD" in rec.message for rec in caplog.records
        ), f"R1: NaN must trigger a WARN naming the env var; got logs: {[r.message for r in caplog.records]}"

        monkeypatch.delenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", raising=False)
        importlib.reload(config)

    def test_r1_warn_on_inf(self, monkeypatch, caplog):
        """±inf must also WARN."""
        import logging

        monkeypatch.setenv("EDGEGUARD_ZONE_ITEM_THRESHOLD", "inf")
        with caplog.at_level(logging.WARNING, logger="config"):
            import config

            importlib.reload(config)

        assert any(
            "non-finite" in rec.message and "EDGEGUARD_ZONE_ITEM_THRESHOLD" in rec.message for rec in caplog.records
        ), f"R1: inf must trigger a WARN; got logs: {[r.message for r in caplog.records]}"

        monkeypatch.delenv("EDGEGUARD_ZONE_ITEM_THRESHOLD", raising=False)
        importlib.reload(config)

    def test_r1_warn_on_out_of_range(self, monkeypatch, caplog):
        """Out-of-range value (above ceiling) must WARN."""
        import logging

        monkeypatch.setenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", "500.0")
        with caplog.at_level(logging.WARNING, logger="config"):
            import config

            importlib.reload(config)

        assert any("out of valid range" in rec.message for rec in caplog.records), (
            f"R1: out-of-range must trigger a WARN; got logs: {[r.message for r in caplog.records]}"
        )

        monkeypatch.delenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", raising=False)
        importlib.reload(config)

    def test_r1_warn_on_unparseable(self, monkeypatch, caplog):
        """Unparseable ``abc123`` must WARN on the parse-fail path."""
        import logging

        monkeypatch.setenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", "abc123")
        with caplog.at_level(logging.WARNING, logger="config"):
            import config

            importlib.reload(config)

        assert any("not a valid float" in rec.message for rec in caplog.records), (
            f"R1: unparseable must trigger a WARN; got logs: {[r.message for r in caplog.records]}"
        )

        monkeypatch.delenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", raising=False)
        importlib.reload(config)

    def test_r1_no_warn_on_valid(self, monkeypatch, caplog):
        """Negative: a valid value must NOT trigger any WARN from
        ``_bounded_env_float``."""
        import logging

        monkeypatch.setenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", "3.0")
        with caplog.at_level(logging.WARNING, logger="config"):
            import config

            importlib.reload(config)

        # Must not have any bounded_env_float rejection log
        relevant = [
            r.message
            for r in caplog.records
            if "EDGEGUARD_ZONE_DETECT_THRESHOLD" in r.message
            and any(tag in r.message for tag in ("not a valid float", "non-finite", "out of valid range"))
        ]
        assert not relevant, f"R1 false-positive: valid value should not WARN; got: {relevant}"

        monkeypatch.delenv("EDGEGUARD_ZONE_DETECT_THRESHOLD", raising=False)
        importlib.reload(config)


# ===========================================================================
# Finding #4 — OTX industry map unification
# ===========================================================================


class TestFinding4OtxIndustryMapUnification:
    """The OTX ``_industry_map`` previously lived inline inside
    ``otx_collector.py``. Moved to ``config.OTX_INDUSTRY_ZONE_ALIASES``
    so it's visible to SECTOR_KEYWORDS maintainers."""

    def test_canonical_const_exists_in_config(self):
        src = (SRC / "config.py").read_text()
        assert "OTX_INDUSTRY_ZONE_ALIASES" in src, (
            "PR-N6 #4: canonical OTX_INDUSTRY_ZONE_ALIASES const must be in config.py"
        )
        # Must preserve all the known aliases
        for alias in ("pharmaceutical", "utilities", "oil", "gas", "insurance"):
            assert f'"{alias}"' in src, f"PR-N6 #4: alias {alias!r} must be preserved"

    def test_otx_collector_imports_shared_const(self):
        src = (SRC / "collectors" / "otx_collector.py").read_text()
        assert "OTX_INDUSTRY_ZONE_ALIASES" in src, "otx_collector must import the shared const"
        # Old inline dict must be gone
        assert "local_industry_map = {" not in src  # historical variant
        # The distinctive inline literal should no longer appear in executable code
        assert "_industry_map = {" not in src, (
            "PR-N6 #4 regression: inline _industry_map must be removed; use config.OTX_INDUSTRY_ZONE_ALIASES"
        )

    def test_module_load_asserts_otx_targets_are_valid_zones(self):
        """Every OTX alias target must be a canonical EdgeGuard zone.
        Pre-fix nothing caught a future ``{"transport": "transport"}``
        entry that would silently emit out-of-whitelist zones."""
        src = (SRC / "config.py").read_text()
        assert "set(OTX_INDUSTRY_ZONE_ALIASES.values()) <= VALID_ZONES" in src, (
            "module-load assertion on OTX targets ⊆ VALID_ZONES must exist"
        )

    def test_behaviour_const_has_expected_mappings(self):
        from config import OTX_INDUSTRY_ZONE_ALIASES

        # Spot-check the known aliases resolve to the right zone
        assert OTX_INDUSTRY_ZONE_ALIASES["pharmaceutical"] == "healthcare"
        assert OTX_INDUSTRY_ZONE_ALIASES["utilities"] == "energy"
        assert OTX_INDUSTRY_ZONE_ALIASES["oil"] == "energy"
        assert OTX_INDUSTRY_ZONE_ALIASES["gas"] == "energy"
        assert OTX_INDUSTRY_ZONE_ALIASES["insurance"] == "finance"
        assert OTX_INDUSTRY_ZONE_ALIASES["banking"] == "finance"


# ===========================================================================
# Finding #5 — sector: prefix parity across readers
# ===========================================================================


class TestFinding5SectorPrefixConsistency:
    """All three zone-tag readers must accept BOTH ``zone:`` and
    ``sector:`` prefixes (matching the most permissive reader,
    ``run_misp_to_neo4j.extract_zones_from_tags``).  Pre-fix the other
    two readers only accepted ``zone:``, causing silent divergence."""

    def test_misp_collector_accepts_sector_prefix(self):
        src = (SRC / "collectors" / "misp_collector.py").read_text()
        fn_idx = src.find("def _extract_zones_from_tags(")
        assert fn_idx != -1
        next_fn = src.find("\n    def ", fn_idx + 1)
        body = src[fn_idx : next_fn if next_fn != -1 else len(src)]
        assert '"sector:"' in body, "misp_collector reader must accept sector: prefix"

    def test_run_misp_to_neo4j_stix_fallback_accepts_sector_prefix(self):
        src = (SRC / "run_misp_to_neo4j.py").read_text()
        marker = 'labels.append(f"zone:{zone_name}")'
        idx = src.find(marker)
        assert idx != -1
        block = src[max(0, idx - 800) : idx]
        assert '"sector:"' in block, "manual-STIX fallback must accept sector: prefix"

    def test_behaviour_misp_collector_reads_sector_tag(self):
        """Given a MISP tag ``sector:healthcare``, the reader must
        produce ``["healthcare"]``."""
        from collectors.misp_collector import MISPCollector

        tags = [{"name": "sector:healthcare"}]
        zones = MISPCollector._extract_zones_from_tags(tags)
        assert "healthcare" in zones, f"sector:healthcare must be read; got {zones}"

    def test_behaviour_misp_collector_sector_also_whitelist_filtered(self):
        """``sector:malware`` (invalid) must still be filtered."""
        from collectors.misp_collector import MISPCollector

        tags = [{"name": "sector:malware"}]
        zones = MISPCollector._extract_zones_from_tags(tags)
        assert zones == [], "sector: prefix must still obey VALID_ZONES"


# ===========================================================================
# Cross-cutting: integration check on the fix bundle
# ===========================================================================


class TestPRN6Integration:
    """End-to-end check that the 4 fixes work together — a tag list
    containing a mix of legitimate, typo'd, mixed-prefix, and malicious
    tags produces the expected output at the first-stop reader."""

    def test_mixed_tag_list_full_normalization(self):
        from collectors.misp_collector import MISPCollector

        tags = [
            {"name": "zone:healthcare"},  # legitimate
            {"name": "sector:finance"},  # sector: prefix, legitimate
            {"name": "zone:malware"},  # attacker-controlled, must drop
            {"name": "zone:healthcares"},  # typo, must drop
            {"name": "sector:retail"},  # valid prefix, out-of-whitelist, must drop
            {"name": "tlp:white"},  # unrelated prefix, must ignore
            {"name": "zone:ENERGY"},  # uppercase, must normalize to lowercase
        ]
        zones = MISPCollector._extract_zones_from_tags(tags)
        # Order of list is insertion-order; verify set equality
        assert set(zones) == {"healthcare", "finance", "energy"}, (
            f"integration: expected {{healthcare, finance, energy}}, got {set(zones)}"
        )
