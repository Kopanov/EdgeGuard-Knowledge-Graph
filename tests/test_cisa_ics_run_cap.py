"""CISA ICS per-run cap (2026-10).

The daily DAG passed ``limit=get_effective_limit("cisa_ics")``, the incremental default (200), since
cisa_ics was not in ``OWN_RUN_CAP_SOURCES``. ``collect`` reads the advisories changed since its cursor
(minus 24 h) oldest first and stopped once 200 (advisory, CVE) items were read: an advisory naming
200 or more CVEs (350-378 on three advisories of the 2026-10-16 baseline) cut the run at itself, the
cursor moved to it, and every later run re-read it first and stopped there again. Every run succeeded;
the cut CVEs and every newer advisory never reached MISP. cisa_ics now has its own cap,
``CISA_ICS_MAX_ADVISORIES_PER_RUN`` (advisory files per run), so the DAG passes no item limit.

The ``changes.csv`` rows and CSAF documents follow the cisagov/CSAF layout the collector reads.
"""

import os
import sys
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import config  # noqa: E402
from collectors import cisa_ics_collector as ics  # noqa: E402

BIG = "2026/icsa-26-288-01.json"  # an advisory naming 250 CVEs (third-party components)
NEW = "2026/icsa-26-289-01.json"  # changed a day later, one CVE


def _doc(adv_id: str, released: str, cves: List[str]) -> Dict[str, Any]:
    return {
        "document": {
            "title": f"Advisory {adv_id}",
            "tracking": {"id": adv_id, "initial_release_date": released, "current_release_date": released},
            "notes": [{"title": "Critical infrastructure sectors", "text": "Energy"}],
        },
        "product_tree": {},
        "vulnerabilities": [{"cve": c} for c in cves],
    }


DOCS = {
    BIG: _doc("ICSA-26-288-01", "2026-10-15T00:00:00Z", [f"CVE-2026-{10000 + n}" for n in range(250)]),
    NEW: _doc("ICSA-26-289-01", "2026-10-16T00:00:00Z", ["CVE-2026-99999"]),
}
CHANGES = f'"{BIG}","2026-10-15T00:00:00Z"\n"{NEW}","2026-10-16T00:00:00Z"\n'


def test_cisa_ics_has_its_own_run_cap(monkeypatch):
    monkeypatch.setattr(config, "MAX_ENTRIES_PER_SOURCE", 0)
    assert "cisa_ics" in config.OWN_RUN_CAP_SOURCES
    assert config.get_effective_limit("cisa_ics") is None


def test_daily_runs_get_past_an_advisory_with_more_cves_than_the_incremental_limit(monkeypatch):
    monkeypatch.setattr(config, "MAX_ENTRIES_PER_SOURCE", 0)
    monkeypatch.setattr(config, "INCREMENTAL_COLLECTION_LIMIT", 200)
    cursor = {"cisa_ics_last_change_ts": "2026-10-14T00:00:00Z"}
    pushed: List[str] = []

    def run():
        writer = MagicMock()

        def push_items(items, *a, **k):
            new = [i["cve_id"] for i in items if i["cve_id"] not in pushed]
            pushed.extend(new)
            return len(new), 0

        writer.push_items.side_effect = push_items
        collector = ics.CISAICSCollector(misp_writer=writer)

        def fake_get(url):
            r = MagicMock()
            r.status_code = 200
            path = url[len(collector.base_url) :]
            if path == ics.CHANGES_FILE:
                r.text = CHANGES
            else:
                r.json.return_value = DOCS[path]
            return r

        with (
            patch.object(config, "ENABLE_CISA_ICS", True),
            patch.object(collector, "_get", side_effect=fake_get),
            patch.object(ics, "get_source_incremental", lambda _s: dict(cursor)),
            patch.object(ics, "update_source_incremental", lambda _s, **kw: cursor.update(kw)),
        ):
            # The limit the daily DAG passes (dags/edgeguard_pipeline.py run_cisa_ics_collection).
            return collector.collect(limit=config.get_effective_limit("cisa_ics"), push_to_misp=True, baseline=False)

    statuses = [run() for _ in range(2)]

    assert all(st["success"] for st in statuses)
    assert cursor["cisa_ics_last_change_ts"] == "2026-10-16T00:00:00Z"
    assert "CVE-2026-99999" in pushed
    assert all(f"CVE-2026-{10000 + n}" in pushed for n in range(250)), "no CVE of the big advisory is cut"
