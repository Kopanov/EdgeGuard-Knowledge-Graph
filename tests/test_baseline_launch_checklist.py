"""Structure and cross-references of ``docs/BASELINE_LAUNCH_CHECKLIST.md``.

The checklist is the single document the operator walks through immediately before triggering a
730-day baseline. It points to other documents, scripts and alert rules rather than repeating them, so
these tests fail when one of those targets moves or changes a value the checklist quotes.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
DOCS = REPO_ROOT / "docs"
CHECKLIST = DOCS / "BASELINE_LAUNCH_CHECKLIST.md"


class TestLaunchChecklistDoc:
    def test_checklist_exists(self):
        assert CHECKLIST.exists(), "the launch checklist must exist"

    def test_has_six_numbered_sections(self):
        """The six items are present and numbered; adding or removing one updates this count."""
        text = CHECKLIST.read_text()
        for n in range(1, 7):
            assert f"### [{n}]" in text, f"checklist must contain section ### [{n}]"
        assert "### [7]" not in text

    def test_references_preflight_script(self):
        """Item [1] runs the preflight script."""
        text = CHECKLIST.read_text()
        assert "scripts/preflight_baseline.sh" in text
        assert "EDGEGUARD_PREFLIGHT_STRICT=1" in text
        assert (REPO_ROOT / "scripts" / "preflight_baseline.sh").exists()

    def test_references_smoke_test_doc(self):
        """Item [2] points to BASELINE_SMOKE_TEST.md."""
        text = CHECKLIST.read_text()
        assert "BASELINE_SMOKE_TEST.md" in text
        assert (DOCS / "BASELINE_SMOKE_TEST.md").exists()

    def test_references_fallback_alert_names(self):
        """Item [3] and "During the run" name the fallback alerts defined in alerts.yml."""
        text = CHECKLIST.read_text()
        alerts_text = (REPO_ROOT / "prometheus" / "alerts.yml").read_text()
        for alert_name in ("EdgeGuardMispFetchFallbackActive", "EdgeGuardMispFetchFallbackHardError"):
            assert alert_name in text, f"checklist must reference {alert_name}"
            assert alert_name in alerts_text, f"alerts.yml must define {alert_name}"

    def test_references_runbook_sections_that_exist(self):
        """The checklist sends operators to RUNBOOK § 'Top 8 failure modes' and § 'Baseline launch path'."""
        text = CHECKLIST.read_text()
        runbook = (DOCS / "RUNBOOK.md").read_text()
        for section in ("Top 8 failure modes", "Baseline launch path"):
            assert section in text
            assert section in runbook, f"RUNBOOK must have the section {section!r} the checklist points to"


class TestChecklistValuesMatchTheirSources:
    def test_alert_count_floor_consistent_with_preflight(self):
        """Item [1] says preflight requires at least 11 alert rules; the preflight enforces that floor."""
        checklist = CHECKLIST.read_text()
        preflight = (REPO_ROOT / "scripts" / "preflight_baseline.sh").read_text()
        assert "≥ 11" in checklist, "checklist must mention the ≥ 11 alert floor"
        assert "-ge 11" in preflight, "preflight must enforce the ≥ 11 alert floor"

    def test_fallback_max_pages_value_consistent_with_source(self):
        """Item [4] quotes ``_FALLBACK_MAX_PAGES = 200`` and ``200 × 500 = 100,000``; the sync defines it."""
        checklist = CHECKLIST.read_text()
        sync = (SRC / "run_misp_to_neo4j.py").read_text()
        assert "_FALLBACK_MAX_PAGES = 200" in checklist
        assert "_FALLBACK_MAX_PAGES = 200" in sync, (
            "run_misp_to_neo4j.py must define _FALLBACK_MAX_PAGES = 200 or the checklist's [4] must be updated"
        )
        assert "100,000" in checklist

    def test_section_references_name_the_fresh_baseline_item(self):
        """The wipe is step 4 of item [6]; the acceptance script's hint names the same item."""
        checklist = CHECKLIST.read_text()
        assert "### [6] Fresh baseline" in checklist
        assert "§ [6] step 4" in checklist
        verify = (REPO_ROOT / "scripts" / "verify_fresh_baseline.py").read_text()
        assert "BASELINE_LAUNCH_CHECKLIST.md § [6], step 1" in verify
