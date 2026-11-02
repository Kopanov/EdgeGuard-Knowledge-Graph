"""The ``[ENRICHMENT SUMMARY]`` line names one number per job (2026-11-02).

It added up every number of a job's result for the bridge, the alias merge and the campaign builder: the
730-day baseline of 2026-11-01 logged ``actor_alias_merge=2265`` for 79 merges (candidates, merges,
restamped edges and reference candidates added up) and ``campaigns=44595`` for 533 campaigns and 44,062
links. The result dicts below are the ones that run logged.
"""

from __future__ import annotations

import inspect
import logging
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import enrichment_jobs  # noqa: E402

# The jobs' results of the 730-day baseline (run_enrichment_jobs.log, 2026-11-01).
SUMMARY_730_DAY = {
    "bridge": {"linked": 0, "errors": 0},
    "actor_alias_merge": {
        "candidates": 79,
        "merged": 79,
        "skipped_ambiguous": 0,
        "errors": 0,
        "restamped_edges": 2028,
        "apoc_missing": 0,
        "reference_candidates": 79,
        "skipped_conflict": 0,
        "skipped_chain": 0,
        "skipped_blocked": 0,
    },
    "malware_twin_merge": {
        "candidates": 4,
        "merged": 0,
        "base_name_targets": 0,
        "no_target": 4,
        "skipped_ambiguous": 0,
        "errors": 0,
        "restamped_edges": 0,
        "apoc_missing": 0,
    },
    "decay": {
        "as_of": None,
        "changed": 0,
        "tiers": {"tier_0": 141303, "tier_1": 9534, "tier_2": 29525, "tier_3": 94503},
    },
    "campaigns": {
        "campaigns_created": 533,
        "campaigns_updated": 0,
        "links_created": 44062,
        "campaigns_deleted": 0,
        "malware_links_pruned": 0,
        "runs_removed": 0,
        "links_pruned": 0,
        "campaigns_deactivated": 0,
    },
    "epss": {
        "rows_in_feed": 398784,
        "cves_updated": 148175,
        "cves_cleared": 0,
        "rows_skipped": 0,
        "score_date": "2026-11-01T12:00:16Z",
        "model_version": "v2026.06.15",
    },
}


def test_one_named_number_per_job():
    assert enrichment_jobs.enrichment_summary_line(SUMMARY_730_DAY) == (
        "bridge_linked=0 actor_alias_merged=79 malware_twins_merged=0 campaigns_built=533 campaign_links=44062 "
        "decay_changed=0 epss_cves_updated=148175"
    )


def test_keys_added_to_a_result_do_not_change_its_number():
    """The campaign builder's sector labels (2026-11-02) are counts of their own, not campaigns."""
    summary = {**SUMMARY_730_DAY, "campaigns": {**SUMMARY_730_DAY["campaigns"], "sector_labels_added": 433}}
    assert "campaigns_built=533 campaign_links=44062 " in enrichment_jobs.enrichment_summary_line(summary)


def test_errors_are_named_only_when_there_are_some():
    summary = {**SUMMARY_730_DAY, "bridge": {"linked": 4, "errors": 2}, "actor_alias_merge": {"merged": 1, "errors": 1}}
    line = enrichment_jobs.enrichment_summary_line(summary)
    assert line.startswith("bridge_linked=4 actor_alias_merged=1 ")
    assert line.endswith(" bridge_errors=2 actor_alias_merge_errors=1")
    assert "_errors=" not in enrichment_jobs.enrichment_summary_line(SUMMARY_730_DAY)


def test_a_skipped_or_missing_job_counts_zero():
    summary = {**SUMMARY_730_DAY, "epss": {"skipped": "disabled"}}
    del summary["bridge"]
    line = enrichment_jobs.enrichment_summary_line(summary)
    assert line.startswith("bridge_linked=0 ") and line.endswith(" epss_cves_updated=0")


def test_the_runner_logs_the_line(monkeypatch, caplog):
    jobs = {
        "bridge_vulnerability_cve": "bridge",
        "merge_alias_duplicate_actors": "actor_alias_merge",
        "merge_malware_attack_twins": "malware_twin_merge",
        "decay_ioc_confidence": "decay",
        "build_campaign_nodes": "campaigns",
        "enrich_cve_epss": "epss",
    }
    for function, job in jobs.items():
        monkeypatch.setattr(enrichment_jobs, function, lambda _client, _job=job: SUMMARY_730_DAY[_job])
    monkeypatch.setattr(enrichment_jobs.config, "ENABLE_EPSS", True)
    with caplog.at_level(logging.INFO, logger=enrichment_jobs.logger.name):
        enrichment_jobs.run_all_enrichment_jobs(object())
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("[ENRICHMENT SUMMARY]")]
    assert lines == ["[ENRICHMENT SUMMARY] " + enrichment_jobs.enrichment_summary_line(SUMMARY_730_DAY)]


def test_no_number_adds_up_a_whole_result():
    source = inspect.getsource(enrichment_jobs.run_all_enrichment_jobs)
    assert "_sum(" not in source and "sum(" not in inspect.getsource(enrichment_jobs.enrichment_summary_line)
