"""CISA ICS report records (2026-11-07): ``CISAICSCollector.parse_advisory_record`` and the record push of ``collect``.

One report record per CSAF advisory (``report_records``, schema ``edgeguard.report.v1``, source ``cisa_ics``): the
advisory summary, sectors, countries deployed, vendor headquarters, TLP, dates, revision, vendors, products, and per
CVE the whole vulnerability note, the remediations, the affected products and the CWE. ``collect`` pushes the records
with ``MISPWriter.push_reports`` before the CVE items and before the return of a run without items; a record whose
push fails waits on ``report_pending`` (baselines included) and does not hold the cursor. Also here: the sector-list
split (``"..., and Energy"``), the whole vulnerability note in ``NVD_META``.

Fixture: ``tests/fixtures/cisa_ics_csaf_2026_11_07.json``, real CSAF advisories recorded from cisagov/CSAF on
2026-11-07 (its ``_provenance`` names each and the one reduction). No advisory of 2024-2026 names no CVE (1,389
read), so the advisory without a CVE is constructed from a recorded one with its ``vulnerabilities`` emptied, and
says so where it is built.

No network and no MISP: HTTP goes through a fake ``request_with_rate_limit_retries``, the writer is a mock whose
``push_reports`` answers as ``MISPWriter.push_reports`` does. The cursor and ``report_pending`` live in the per-test
checkpoint file (``tests/conftest.py``).
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import collectors.cisa_ics_collector as mod  # noqa: E402
from baseline_checkpoint import get_source_incremental, update_source_incremental  # noqa: E402
from resilience import CircuitBreaker  # noqa: E402

# The report_records module the collector uses, whatever another test module re-imported.
rr = mod.report_records

_FIXTURE = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "cisa_ics_csaf_2026_11_07.json").read_text(encoding="utf-8")
)
ADVISORIES: Dict[str, Dict[str, Any]] = _FIXTURE["advisories"]
BASE = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/"

COMOS = "2025/icsa-25-317-15.json"  # two CVEs, a vulnerability note of 1,501 characters
DICOM = "2024/icsma-24-058-01.json"  # a medical advisory
XMC20 = "2025/icsa-25-016-07.json"  # version '1.0.0', no_fix_planned, no product_name branch
NX = "2026/icsa-26-043-08.json"  # five revisions
MODICON = "2024/icsa-24-354-07.json"  # sectors '..., and Energy'
SCALANCE = "2024/icsa-24-165-12.json"  # 'Nuclear Reactors, Materials, and Waste'
EWON = "2024/icsa-24-291-04.json"  # sectors '..., and Food and Agriculture'
BPL = "2024/icsma-24-254-01.json"  # 'Healthcare and Public Health Sector'
ROCKWELL = "2025/icsa-25-226-26.json"  # each CVE affects another product
SIMATIC = "2026/icsa-26-134-10.json"  # the longest vulnerability note of 2024-2026 (reduced to that CVE)
COUNTRIES = "2026/icsa-26-148-05.json"  # countries 'India, Nepal, United Arab Emirates, Gambia'
TWO_HQ = "2026/icsa-26-300-02.json"  # two notes 'Company headquarters location' (reduced to its first CVE)

_FROZEN_NOW = _dt.datetime(2026, 11, 7, 12, 0, tzinfo=_dt.timezone.utc)
CHANGED = "2026-11-06T06:00:00.000000Z"  # inside the 30-day look-back of a run without a cursor
NEWER = "2026-11-07T06:00:00.000000Z"


class _FrozenDatetime(_dt.datetime):
    @classmethod
    def now(cls, tz=None):  # noqa: D401 - datetime API
        return _FROZEN_NOW.astimezone(tz) if tz else _FROZEN_NOW.replace(tzinfo=None)


def advisory(path: str) -> Dict[str, Any]:
    return copy.deepcopy(ADVISORIES[path])


def without_cves(path: str) -> Dict[str, Any]:
    """Constructed: the recorded advisory with an empty ``vulnerabilities`` list (no recorded advisory of
    2024-2026 names no CVE)."""
    data = advisory(path)
    data["vulnerabilities"] = []
    return data


def note_text(data: Dict[str, Any], title: str) -> str:
    """A document note's text as the record holds it (line ends as ``\\n``, trimmed)."""
    for note in data["document"]["notes"]:
        if (note.get("title") or "").strip().lower() == title.lower():
            return note["text"].replace("\r\n", "\n").replace("\r", "\n").strip()
    raise KeyError(title)


def vuln_note(data: Dict[str, Any], cve: str) -> str:
    for vuln in data["vulnerabilities"]:
        if vuln.get("cve") == cve:
            for note in vuln["notes"]:
                if note["category"] in ("summary", "description"):
                    return note["text"].replace("\r\n", "\n").replace("\r", "\n").strip()
    raise KeyError(cve)


class _Response:
    def __init__(self, status_code: int = 200, text: str = "", payload: Any = None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text else (json.dumps(payload) if payload is not None else "")
        self.headers: Dict[str, str] = {}

    def json(self) -> Any:
        return self._payload if self._payload is not None else json.loads(self.text)


class _HTTP:
    """Answers GETs by path below ``BASE``; an unknown path answers 404. Records the paths asked for."""

    def __init__(self, routes: Dict[str, Any]):
        self.routes = routes
        self.paths: List[str] = []

    def __call__(self, method: str, url: str, **_kw: Any) -> _Response:
        assert url.startswith(BASE), url
        path = url[len(BASE) :]
        self.paths.append(path)
        if path not in self.routes:
            return _Response(status_code=404, text="not found")
        value = self.routes[path]
        return _Response(text=value) if isinstance(value, str) else _Response(payload=value)

    def advisories(self) -> List[str]:
        return [p for p in self.paths if p.endswith(".json")]


def changes(*rows: tuple) -> str:
    return "".join(f'"{path}","{ts}"\n' for path, ts in rows)


def push_answer(
    records: List[Dict[str, Any]], *, failed: Optional[set] = None, skipped_reason: Optional[str] = None
) -> Dict[str, Any]:
    """``MISPWriter.push_reports``'s stats: every record added, but those in *failed* (HTTP 500) and, with
    *skipped_reason*, all of them untried."""
    failed = failed or set()
    stats: Dict[str, Any] = {"settled": [], "failed": [], "skipped": [], "reports_added": 0, "reports_failed": 0}
    for record in records:
        ref = record["record_ref"]
        if skipped_reason:
            stats["skipped"].append({"record_ref": ref, "reason": skipped_reason})
        elif ref in failed:
            stats["failed"].append({"record_ref": ref, "reason": "HTTP 500", "permanent": False})
            stats["reports_failed"] += 1
        else:
            stats["settled"].append(ref)
            stats["reports_added"] += 1
    stats["reports_skipped"] = len(stats["skipped"])
    return stats


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Flag on, a fresh breaker, no pauses, the clock frozen, default knobs. The cursor and report_pending use the
    per-test checkpoint file."""
    import config

    monkeypatch.setattr(config, "ENABLE_CISA_ICS", True)
    monkeypatch.setattr(mod, "datetime", _FrozenDatetime)
    monkeypatch.setattr(mod, "CISA_ICS_CIRCUIT_BREAKER", CircuitBreaker("cisa_ics_records", failure_threshold=3))
    monkeypatch.setattr(mod.CISA_ICS_RATE_LIMITER, "wait_if_needed", lambda: None)
    monkeypatch.setattr("collectors.collector_utils.time.sleep", lambda _s: None)
    monkeypatch.setattr(mod, "CISA_ICS_MAX_ADVISORIES_PER_RUN", 1200)
    monkeypatch.setattr(mod, "CISA_ICS_MIN_EXPECTED_ADVISORIES", 50)


def collector(monkeypatch, http: _HTTP, *, failed: Optional[set] = None, skipped_reason: Optional[str] = None):
    monkeypatch.setattr(mod, "request_with_rate_limit_retries", http)
    writer = MagicMock()
    writer.push_items.side_effect = lambda items, *a, **k: (len(items), 0)
    writer.push_reports.side_effect = lambda source, records, **k: push_answer(
        records, failed=failed, skipped_reason=skipped_reason
    )
    return mod.CISAICSCollector(misp_writer=writer)


def pushed_records(c: mod.CISAICSCollector) -> List[Dict[str, Any]]:
    return [r for call in c.misp_writer.push_reports.call_args_list for r in call.args[1]]


def pushed_items(c: mod.CISAICSCollector) -> List[Dict[str, Any]]:
    return [i for call in c.misp_writer.push_items.call_args_list for i in call.args[0]]


def cursor() -> Optional[str]:
    return get_source_incremental("cisa_ics").get("cisa_ics_last_change_ts")


def pending() -> Dict[str, Dict[str, Any]]:
    return {e["record_ref"]: e for e in rr.load_report_pending("cisa_ics")}


# --------------------------------------------------------------------------- #
# The record of an advisory
# --------------------------------------------------------------------------- #


class TestParseAdvisoryRecord:
    def record(self, path: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        c = mod.CISAICSCollector(misp_writer=MagicMock())
        return c.parse_advisory_record(data if data is not None else advisory(path), path)

    def test_an_icsa_gives_the_advisory_facts_and_each_cve_its_whole_note(self):
        data = advisory(COMOS)
        record = self.record(COMOS)
        assert record["schema"] == "edgeguard.report.v1" and record["source"] == "cisa_ics"
        assert record["record_ref"] == "cisa_ics:ICSA-25-317-15"
        assert record["url"] == "https://www.cisa.gov/news-events/ics-advisories/icsa-25-317-15"
        assert record["csaf_url"] == BASE + COMOS  # CISA's own self reference, not Siemens' CSAF file
        assert record["title"] == "Siemens COMOS" and record["kind"] == "ICSA" and record["publisher"] == "CISA"
        # The converted advisory's "Summary" note (category summary), whole.
        assert record["description"] == note_text(data, "Summary") and len(record["description"]) == 220
        assert record["tlp"] == "white"
        assert (record["published"], record["last_modified"]) == ("2025-11-11T00:00:00+00:00",) * 2
        assert (record["revision"], record["version"]) == (1, "1")
        assert record["vendors"] == ["Siemens"] and record["products"] == ["Siemens COMOS"]
        assert record["deployment_sectors"] == ["Critical Manufacturing"]
        assert record["deployment_countries"] == ["Worldwide"] and record["vendor_headquarters"] == "Germany"
        assert record["cve_ids"] == ["CVE-2023-45133", "CVE-2024-0056"]
        first = record["vulnerabilities"][0]
        assert first["cve_id"] == "CVE-2023-45133"
        assert first["summary"] == vuln_note(data, "CVE-2023-45133") and len(first["summary"]) == 1501
        assert first["remediations"] == [
            {"category": "vendor_fix", "details": data["vulnerabilities"][0]["remediations"][0]["details"]}
        ]
        assert first["affected_products"] == ["COMOS"]
        assert first["cwes"] == [{"id": "CWE-184", "name": "Incomplete List of Disallowed Inputs"}]
        assert set(record) == {"schema", "source", "record_ref", "digest", *rr.record_fields("cisa_ics")}
        assert rr.record_from_content(rr.render_content(record)) == record

    def test_a_medical_advisory_is_an_icsma_with_its_page_and_resolved_products(self):
        data = advisory(DICOM)
        record = self.record(DICOM)
        assert record["kind"] == "ICSMA" and record["record_ref"] == "cisa_ics:ICSMA-24-058-01"
        assert record["url"] == "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-058-01"
        # CISA's summary of 2024 advisories is the note "Risk evaluation" (category summary).
        assert record["description"] == note_text(data, "Risk evaluation")
        assert record["deployment_sectors"] == ["Healthcare and Public Health"]
        assert record["vendor_headquarters"] == "Cyprus"
        (vuln,) = record["vulnerabilities"]
        assert vuln["affected_products"] == ["Santesoft Sante DICOM Viewer Pro: <=14.0.3"]  # product_id resolved
        assert sorted({r["category"] for r in vuln["remediations"]}) == ["mitigation", "vendor_fix"]
        assert len(vuln["remediations"]) == 5

    def test_revision_counts_the_revision_history_and_version_is_the_tracking_version(self):
        nx = self.record(NX)
        assert len(advisory(NX)["document"]["tracking"]["revision_history"]) == 5
        assert (nx["revision"], nx["version"]) == (5, "5")
        assert (nx["published"], nx["last_modified"]) == ("2026-02-10T00:00:00+00:00", "2026-03-12T06:00:00+00:00")
        # tracking.version '1.0.0' (72 of the 1,389 advisories of 2024-2026): no whole number, the count is 1
        xmc = self.record(XMC20)
        assert (xmc["revision"], xmc["version"]) == (1, "1.0.0")

    def test_no_fix_planned_is_kept_with_its_details_and_a_tree_without_products_gives_its_families(self):
        data = advisory(XMC20)
        (vuln,) = self.record(XMC20)["vulnerabilities"]
        no_fix = [r for r in vuln["remediations"] if r["category"] == "no_fix_planned"]
        source = [r for r in data["vulnerabilities"][0]["remediations"] if r["category"] == "no_fix_planned"]
        assert len(no_fix) == 1 and no_fix[0]["details"] == source[0]["details"].strip()
        assert self.record(XMC20)["products"] == ["Hitachi Energy XMC20"]  # its product_family branch
        assert vuln["affected_products"] == [
            "XMC20 R15A and older including all subversions",
            "XMC20 R15B",
            "XMC20 R16A",
            "XMC20 R16B Revision C (cent2_r16b04_02, co5ne_r16b04_02) and older including all subversions",
        ]

    def test_each_cve_lists_only_the_products_its_product_status_names(self):
        record = self.record(ROCKWELL)
        assert record["products"] == ["Rockwell Automation 5094-IF8", "Rockwell Automation 5094-IY8"]
        by_cve = {v["cve_id"]: v["affected_products"] for v in record["vulnerabilities"]}
        assert by_cve == {
            "CVE-2025-9041": ["Rockwell Automation 5094-IF8: V2.011"],
            "CVE-2025-9042": ["Rockwell Automation 5094-IY8: V2.011"],
        }

    def test_the_countries_note_is_a_list_and_several_headquarters_notes_are_joined(self):
        assert self.record(COUNTRIES)["deployment_countries"] == ["Gambia", "India", "Nepal", "United Arab Emirates"]
        assert self.record(COUNTRIES)["vendor_headquarters"] == "India"
        assert self.record(TWO_HQ)["vendor_headquarters"] == "Japan, United States"

    def test_the_csaf_url_is_the_advisory_s_own_reference_whatever_mirror_was_read(self):
        c = mod.CISAICSCollector(misp_writer=MagicMock())
        c.base_url = "https://mirror.example/csaf/"
        record = c.parse_advisory_record(advisory(COMOS), COMOS)
        assert record["csaf_url"] == BASE + COMOS
        # A document without such a reference names the file read.
        data = advisory(COMOS)
        data["document"]["references"] = [r for r in data["document"]["references"] if not r["url"].endswith(".json")]
        assert c.parse_advisory_record(data, COMOS)["csaf_url"] == "https://mirror.example/csaf/" + COMOS

    def test_an_advisory_without_a_cve_still_gives_its_record(self):
        record = self.record(DICOM, without_cves(DICOM))  # constructed: the recorded advisory, no vulnerability
        assert record["record_ref"] == "cisa_ics:ICSMA-24-058-01"
        assert record["cve_ids"] == [] and record["vulnerabilities"] == []
        assert record["description"] == note_text(advisory(DICOM), "Risk evaluation")

    def test_a_payload_parse_advisory_refuses_is_refused(self):
        c = mod.CISAICSCollector(misp_writer=MagicMock())
        with pytest.raises(ValueError, match="document"):
            c.parse_advisory_record({"vulnerabilities": []}, "2026/x.json")


# --------------------------------------------------------------------------- #
# Sector notes
# --------------------------------------------------------------------------- #


class TestSectorNotes:
    @pytest.mark.parametrize(
        "path, sectors, zones",
        [
            (MODICON, ["Commercial Facilities", "Critical Manufacturing", "Energy"], ["energy"]),
            (EWON, ["Water and Wastewater Systems", "Energy", "Food and Agriculture"], ["energy"]),
            (
                SCALANCE,
                ["Chemical", "Critical Manufacturing", "Energy", "Nuclear Reactors, Materials, and Waste"],
                ["energy"],
            ),
            (BPL, ["Healthcare and Public Health Sector"], ["healthcare"]),
        ],
    )
    def test_the_recorded_sector_notes_give_their_sectors_and_zones(self, path, sectors, zones):
        data = advisory(path)
        assert mod.parse_sectors(data["document"]) == sectors
        c = mod.CISAICSCollector(misp_writer=MagicMock())
        items, _ = c.parse_advisory(data, path)
        assert all(i["ics_sectors"] == sectors and i["zone"] == zones for i in items) and items
        assert c.parse_advisory_record(data, path)["deployment_sectors"] == sorted(sectors)

    def test_the_last_item_of_a_list_loses_its_conjunction_and_a_name_with_and_stays_whole(self):
        assert note_text(advisory(MODICON), "Critical infrastructure sectors").endswith(", and Energy")
        assert mod.split_note_list("Critical Manufacturing, Energy, and Water and Wastewater Systems") == [
            "Critical Manufacturing",
            "Energy",
            "Water and Wastewater Systems",
        ]
        assert mod.split_note_list("Energy, & Dams") == ["Energy", "Dams"]
        assert mod.split_note_list(" , Energy,, Energy ") == ["Energy"]


# --------------------------------------------------------------------------- #
# The whole vulnerability note in MISP
# --------------------------------------------------------------------------- #


def test_the_whole_vulnerability_note_reaches_nvd_meta_with_every_other_key():
    from collectors.misp_writer import MISPWriter

    data = advisory(SIMATIC)
    note = vuln_note(data, "CVE-2025-23143")
    assert len(note) > 3900
    c = mod.CISAICSCollector(misp_writer=MagicMock())
    (item,) = mod.merge_items_per_cve(c.parse_advisory(data, SIMATIC)[0])
    raw = next(n["text"] for n in data["vulnerabilities"][0]["notes"] if n["category"] == "summary").strip()
    assert item["description"] == f"ICSA-26-134-10: {data['document']['title']} — {raw}"
    writer = MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)
    attr = writer.create_vulnerability_attribute(item)
    meta = json.loads(attr["comment"][len("NVD_META:") :])
    assert meta["description"] == item["description"]
    assert meta["advisory_ids"] == ["ICSA-26-134-10"] and meta["cwe"] == ["CWE-476"]
    assert meta["ics_sectors"] == ["Critical Manufacturing"] and meta["advisory_zones"] == {"ICSA-26-134-10": []}
    assert meta["cvss_v31_data"]["base_score"] == item["cvss_score"] and meta["published"] == item["published"]
    assert meta["reference_urls"] == ["https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-10"]


# --------------------------------------------------------------------------- #
# The record push in collect()
# --------------------------------------------------------------------------- #


class TestCollectPushesRecords:
    def test_an_advisory_without_a_cve_gets_its_record_before_the_return_without_items(self, monkeypatch):
        http = _HTTP({"changes.csv": changes((DICOM, CHANGED)), DICOM: without_cves(DICOM)})
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        assert st["success"] is True and st["count"] == 0
        assert [r["record_ref"] for r in pushed_records(c)] == ["cisa_ics:ICSMA-24-058-01"]
        c.misp_writer.push_items.assert_not_called()
        assert st["report_counts"]["records"] == 1 and st["report_counts"]["reports_added"] == 1
        assert st["stats"]["records"] == 1
        assert cursor() == CHANGED

    def test_the_records_go_before_the_cve_items_and_in_batches(self, monkeypatch):
        monkeypatch.setattr(mod, "REPORT_BATCH", 2)
        http = _HTTP(
            {
                "changes.csv": changes((COMOS, CHANGED), (NX, CHANGED), (ROCKWELL, CHANGED)),
                COMOS: advisory(COMOS),
                NX: advisory(NX),
                ROCKWELL: advisory(ROCKWELL),
            }
        )
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        names = [call[0] for call in c.misp_writer.mock_calls if call[0] in ("push_reports", "push_items")]
        assert names == ["push_reports", "push_reports", "push_items"]
        assert [len(call.args[1]) for call in c.misp_writer.push_reports.call_args_list] == [2, 1]
        assert sorted(r["record_ref"] for r in pushed_records(c)) == [
            "cisa_ics:ICSA-25-226-26",
            "cisa_ics:ICSA-25-317-15",
            "cisa_ics:ICSA-26-043-08",
        ]
        assert st["success"] is True and st["count"] == 5 and st["report_counts"]["records"] == 3

    def test_a_record_whose_push_failed_waits_on_report_pending_and_the_cursor_moves(self, monkeypatch):
        http = _HTTP({"changes.csv": changes((COMOS, CHANGED)), COMOS: advisory(COMOS)})
        c = collector(monkeypatch, http, failed={"cisa_ics:ICSA-25-317-15"})
        st = c.collect(push_to_misp=True, baseline=False)
        entry = pending()["cisa_ics:ICSA-25-317-15"]
        assert entry["attempts"] == 1 and entry["last_reason"] == "HTTP 500"
        assert st["success"] is True and st["report_counts"]["reports_failed"] == 1
        assert st["report_counts"]["pending"] == 1
        assert cursor() == CHANGED  # report_pending keeps the record; the cursor is not held for it

    def test_a_baseline_keeps_a_failed_record_on_report_pending_and_sets_no_cursor(self, monkeypatch):
        http = _HTTP({"index.txt": f"{NX}\n{MODICON}\n", NX: advisory(NX), MODICON: advisory(MODICON)})
        c = collector(monkeypatch, http, failed={"cisa_ics:ICSA-26-043-08"})
        st = c.collect(push_to_misp=True, baseline=True, baseline_days=730)
        assert st["success"] is True
        assert list(pending()) == ["cisa_ics:ICSA-26-043-08"]
        assert cursor() is None

    def test_untried_records_are_listed_and_the_later_batches_are_not_pushed(self, monkeypatch):
        monkeypatch.setattr(mod, "REPORT_BATCH", 1)
        http = _HTTP(
            {"changes.csv": changes((COMOS, CHANGED), (NX, CHANGED)), COMOS: advisory(COMOS), NX: advisory(NX)}
        )
        c = collector(monkeypatch, http, skipped_reason="the task's end is near")
        st = c.collect(push_to_misp=True, baseline=False)
        assert c.misp_writer.push_reports.call_count == 1
        entries = pending()
        assert set(entries) == {"cisa_ics:ICSA-25-317-15", "cisa_ics:ICSA-26-043-08"}
        assert all("last_tried_at" not in e and e["last_reason"] == "the task's end is near" for e in entries.values())
        assert st["report_counts"]["reports_skipped"] == 2

    def test_a_list_that_cannot_be_saved_holds_the_cursor(self, monkeypatch):
        http = _HTTP({"changes.csv": changes((COMOS, CHANGED)), COMOS: advisory(COMOS)})
        c = collector(monkeypatch, http, failed={"cisa_ics:ICSA-25-317-15"})
        saving = rr.note_report_push
        monkeypatch.setattr(rr, "note_report_push", MagicMock(side_effect=OSError("disk full")))
        st = c.collect(push_to_misp=True, baseline=False)
        assert st["report_counts"]["pending_saved"] is False
        assert cursor() is None
        # Control: once the list saves, the same run moves the cursor.
        monkeypatch.setattr(rr, "note_report_push", saving)
        c.collect(push_to_misp=True, baseline=False)
        assert cursor() == CHANGED

    def test_a_run_without_records_still_settles_the_list_once(self, monkeypatch):
        spy = MagicMock(wraps=rr.note_report_push)
        monkeypatch.setattr(rr, "note_report_push", spy)
        http = _HTTP({"changes.csv": ""})
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        c.misp_writer.push_reports.assert_not_called()
        assert spy.call_count == 1 and spy.call_args.args[1]["failed"] == []
        assert st["report_counts"]["records"] == 0

    def test_without_push_to_misp_nothing_is_pushed_and_the_records_are_kept(self, monkeypatch):
        http = _HTTP({"changes.csv": changes((COMOS, CHANGED)), COMOS: advisory(COMOS)})
        c = collector(monkeypatch, http)
        items = c.collect(push_to_misp=False, baseline=False)
        assert len(items) == 2
        c.misp_writer.push_reports.assert_not_called()
        assert [r["record_ref"] for r in c.last_records] == ["cisa_ics:ICSA-25-317-15"]


# --------------------------------------------------------------------------- #
# Records on report_pending
# --------------------------------------------------------------------------- #


def put_on_pending(*refs: str) -> None:
    update_source_incremental(
        "cisa_ics",
        report_pending=[
            {"record_ref": ref, "first_failed_at": "2026-11-06T00:00:00+00:00", "attempts": 1, "last_reason": "x"}
            for ref in refs
        ],
    )


class TestPendingRecords:
    def test_the_advisory_of_a_pending_record_is_read_for_its_record_only(self, monkeypatch):
        put_on_pending("cisa_ics:ICSA-25-317-15")
        http = _HTTP(
            {
                # COMOS changed before the look-back: the listing names it, the window does not select it.
                "changes.csv": changes((NX, CHANGED), (COMOS, "2026-09-01T00:00:00.000000Z")),
                NX: advisory(NX),
                COMOS: advisory(COMOS),
            }
        )
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        assert http.advisories() == [NX, COMOS]
        assert sorted(r["record_ref"] for r in pushed_records(c)) == [
            "cisa_ics:ICSA-25-317-15",
            "cisa_ics:ICSA-26-043-08",
        ]
        assert {i["cve_id"] for i in pushed_items(c)} == {"CVE-2026-22923"}  # the pending advisory's items stay out
        assert pending() == {}
        assert st["stats"]["pending_fetched"] == 1 and st["stats"]["attempted"] == 1
        assert cursor() == CHANGED

    def test_a_pending_record_the_listing_no_longer_names_leaves_the_list(self, monkeypatch):
        put_on_pending("cisa_ics:ICSA-99-001-01")
        http = _HTTP({"changes.csv": changes((NX, CHANGED)), NX: advisory(NX)})
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        assert pending() == {} and st["stats"]["pending_not_listed"] == 1
        assert http.advisories() == [NX]

    def test_a_pending_advisory_that_cannot_be_fetched_counts_as_a_try_and_holds_nothing(self, monkeypatch):
        put_on_pending("cisa_ics:ICSA-25-317-15")
        http = _HTTP({"changes.csv": changes((NX, CHANGED), (COMOS, "2026-09-01T00:00:00.000000Z")), NX: advisory(NX)})
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        entry = pending()["cisa_ics:ICSA-25-317-15"]
        assert entry["attempts"] == 2 and "last_tried_at" in entry and "fetched" in entry["last_reason"]
        assert st["stats"]["fetch_failed"] == 0 and st["stats"]["pending_failed"] == 1
        assert cursor() == CHANGED

    def test_a_baseline_window_applies_to_an_advisory_without_a_cve(self, monkeypatch):
        # Constructed: the recorded DICOM advisory (2024-02-27, before the 730-day cutoff 2024-11-07) without its
        # vulnerability; NX (2026-02-10) is inside the window.
        http = _HTTP({"index.txt": f"{NX}\n{DICOM}\n", NX: advisory(NX), DICOM: without_cves(DICOM)})
        monkeypatch.setattr(mod, "FILENAME_DATE_MARGIN_DAYS", 400)
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=True, baseline_days=730)
        assert DICOM in http.advisories()
        assert [r["record_ref"] for r in pushed_records(c)] == ["cisa_ics:ICSA-26-043-08"]
        assert st["stats"]["outside_window"] == 1

    def test_a_baseline_writes_a_pending_record_outside_its_window_and_no_other(self, monkeypatch):
        put_on_pending("cisa_ics:ICSMA-24-058-01")
        # The frozen clock puts the 730-day cutoff at 2024-11-07: DICOM (2024-02-27) and SCALANCE (2024-06-11)
        # are outside it, NX inside.
        http = _HTTP(
            {
                "index.txt": f"{NX}\n{DICOM}\n{SCALANCE}\n",
                NX: advisory(NX),
                DICOM: advisory(DICOM),
                SCALANCE: advisory(SCALANCE),
            }
        )
        monkeypatch.setattr(mod, "FILENAME_DATE_MARGIN_DAYS", 400)  # both old files are fetched
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=True, baseline_days=730)
        assert sorted(r["record_ref"] for r in pushed_records(c)) == [
            "cisa_ics:ICSA-26-043-08",
            "cisa_ics:ICSMA-24-058-01",
        ]
        assert {i["cve_id"] for i in pushed_items(c)} == {"CVE-2026-22923"}
        assert st["stats"]["outside_window"] == 2 and pending() == {}
