"""CISA ICS report records (2026-11-07): ``CISAICSCollector.parse_advisory_record`` and the record push of ``collect``.

One report record per CSAF advisory (``report_records``, schema ``edgeguard.report.v1``, source ``cisa_ics``): the
advisory summary, sectors, countries deployed, vendor headquarters, TLP, dates, revision, vendors, products, and per
CVE the whole vulnerability note, the remediations, the affected products and the CWE. ``collect`` pushes the records
with ``MISPWriter.push_reports`` after the CVE items and before the return of a run without items; a record whose
push fails waits on ``report_pending`` (baselines included) and does not hold the cursor. Also here: the sector-list
split (``"..., and Energy"``), the countries list, the record caps, the whole vulnerability note in ``NVD_META``.

Fixtures: ``tests/fixtures/cisa_ics_csaf_2026_11_07.json`` and ``tests/fixtures/cisa_ics_csaf_more_2026_11_07.json``,
real CSAF advisories recorded from cisagov/CSAF on 2026-11-07 (their ``_provenance`` names each and the two
reductions). No advisory of 2024-2026 names no CVE (1,389 read), so the advisory without a CVE is constructed from a
recorded one with its ``vulnerabilities`` emptied, and says so where it is built; other constructed inputs say so
too.

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
import requests

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import collectors.cisa_ics_collector as mod  # noqa: E402
from baseline_checkpoint import get_source_incremental, update_source_incremental  # noqa: E402
from resilience import CircuitBreaker  # noqa: E402

# The report_records module the collector uses, whatever another test module re-imported.
rr = mod.report_records

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
ADVISORIES: Dict[str, Dict[str, Any]] = {
    **json.loads((_FIXTURES / "cisa_ics_csaf_2026_11_07.json").read_text(encoding="utf-8"))["advisories"],
    **json.loads((_FIXTURES / "cisa_ics_csaf_more_2026_11_07.json").read_text(encoding="utf-8"))["advisories"],
}
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
RELATIONSHIPS = "2024/icsa-24-326-03.json"  # affected products that only product_tree.relationships name
DETAILS_ONLY = "2025/icsa-25-093-01.json"  # CVE-2024-11499: its description in a single 'details' note
DETAILS_AND_SCORE = "2025/icsa-25-037-02.json"  # CVE-2024-2658: a 'details' description, then a 'details' score
MIDDLE_EAST = "2024/icsa-24-291-05.json"  # countries 'Europe, the Middle East and Asia.'

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
    """Answers GETs by path below ``BASE``; an unknown path answers 404, a route holding an exception raises it.
    Records the paths asked for."""

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
        if isinstance(value, BaseException):
            raise value
        if isinstance(value, _Response):
            return value
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
        # Its only note is of category description: the summary falls back to it.
        assert [n["category"] for n in data["vulnerabilities"][0]["notes"]] == ["description"]
        assert vuln["summary"] == vuln_note(data, "CVE-2024-2461") and vuln["summary"]
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

    def test_a_part_holding_a_name_with_commas_and_other_words_keeps_them(self):
        # Constructed: no sector note of 2024-2026 adds words to this name (only the exact name occurs).
        assert mod.split_note_list("Energy, Nuclear Reactors, Materials, and Waste Sector") == [
            "Energy",
            "Nuclear Reactors, Materials, and Waste Sector",
        ]
        assert mod.split_note_list("Energy, and the Nuclear Reactors, Materials, and Waste") == [
            "Energy",
            "the Nuclear Reactors, Materials, and Waste",
        ]


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

    def test_the_records_go_after_the_cve_items_and_in_batches(self, monkeypatch):
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
        # An item batch's answer carries every report of the event: the records come after the items.
        assert names == ["push_items", "push_reports", "push_reports"]
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


def _ago(days: float) -> str:
    """An ISO time *days* before the real clock: ``report_records`` dates ``report_pending`` by the real clock (the
    tests freeze only the collector's)."""
    return (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=days)).isoformat()


def put_on_pending(*refs: str, days_ago: float = 1) -> None:
    update_source_incremental(
        "cisa_ics",
        report_pending=[
            {"record_ref": ref, "first_failed_at": _ago(days_ago), "attempts": 1, "last_reason": "x"} for ref in refs
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

    def test_a_pending_record_the_listing_does_not_name_is_a_failed_try(self, monkeypatch, caplog):
        put_on_pending("cisa_ics:ICSA-99-001-01")
        http = _HTTP({"changes.csv": changes((NX, CHANGED)), NX: advisory(NX)})
        c = collector(monkeypatch, http)
        with caplog.at_level("WARNING"):
            st = c.collect(push_to_misp=True, baseline=False)
        entry = pending()["cisa_ics:ICSA-99-001-01"]
        assert entry["attempts"] == 2 and "last_tried_at" in entry and "does not name" in entry["last_reason"]
        assert st["stats"]["pending_not_listed"] == 1 and st["report_counts"]["reports_failed"] == 1
        assert http.advisories() == [NX]
        assert any(
            r.levelname == "WARNING" and "[REPORT-PENDING]" in r.getMessage() and "ICSA-99-001-01" in r.getMessage()
            for r in caplog.records
        )
        assert cursor() == CHANGED

    def test_a_not_listed_record_past_the_deadline_is_given_up_with_an_error_and_the_metric(self, monkeypatch, caplog):
        import metrics_server

        monkeypatch.setenv("EDGEGUARD_REPORT_PENDING_MAX_DAYS", "7")
        metric = MagicMock()
        monkeypatch.setattr(metrics_server, "record_report_pending", metric)
        put_on_pending("cisa_ics:ICSA-99-001-01", days_ago=8)
        http = _HTTP({"changes.csv": changes((NX, CHANGED)), NX: advisory(NX)})
        c = collector(monkeypatch, http)
        with caplog.at_level("ERROR"):
            st = c.collect(push_to_misp=True, baseline=False)
        assert pending() == {} and st["report_counts"]["given_up"] == 1
        assert any(
            r.levelname == "ERROR"
            and "[REPORT-GAVE-UP] cisa_ics" in r.getMessage()
            and "ICSA-99-001-01" in r.getMessage()
            for r in caplog.records
        )
        assert metric.call_args.args[0] == "cisa_ics" and metric.call_args.args[3] == 1

    @pytest.mark.parametrize(
        "listing",
        [
            "",
            # Constructed: a listing whose rows no longer have the YYYY/<file>.json form.
            '"white/2025/icsa-25-317-15.json","2026-11-06T06:00:00.000000Z"\n',
        ],
    )
    def test_a_listing_without_a_row_leaves_the_pending_records_untouched(self, monkeypatch, caplog, listing):
        put_on_pending("cisa_ics:ICSA-25-317-15")
        before = pending()["cisa_ics:ICSA-25-317-15"]
        http = _HTTP({"changes.csv": listing})
        c = collector(monkeypatch, http)
        with caplog.at_level("WARNING"):
            st = c.collect(push_to_misp=True, baseline=False)
        assert pending() == {"cisa_ics:ICSA-25-317-15": before}
        assert st["stats"]["pending_not_listed"] == 0 and st["report_counts"]["reports_failed"] == 0
        assert http.advisories() == []
        assert any("[REPORT-PENDING]" in r.getMessage() and "no advisory" in r.getMessage() for r in caplog.records)

    def test_a_pending_advisory_that_cannot_be_fetched_counts_as_a_try_and_holds_nothing(self, monkeypatch):
        put_on_pending("cisa_ics:ICSA-25-317-15")
        http = _HTTP({"changes.csv": changes((NX, CHANGED), (COMOS, "2026-09-01T00:00:00.000000Z")), NX: advisory(NX)})
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        entry = pending()["cisa_ics:ICSA-25-317-15"]
        assert entry["attempts"] == 2 and "last_tried_at" in entry and "fetched" in entry["last_reason"]
        assert st["stats"]["fetch_failed"] == 0 and st["stats"]["pending_failed"] == 1
        assert st["report_counts"]["reports_failed"] == 1 and st["report_counts"]["given_up"] == 0
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
        assert st["stats"]["pending_not_listed"] == 0

    def test_a_baseline_reads_a_pending_record_listed_outside_its_years(self, monkeypatch):
        put_on_pending("cisa_ics:ICSA-25-317-15")
        # A 300-day baseline from the frozen clock selects 2026 only: COMOS (2025) is listed, not selected.
        http = _HTTP({"index.txt": f"{NX}\n{COMOS}\n", NX: advisory(NX), COMOS: advisory(COMOS)})
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=True, baseline_days=300)
        assert http.advisories() == [NX, COMOS]
        assert sorted(r["record_ref"] for r in pushed_records(c)) == [
            "cisa_ics:ICSA-25-317-15",
            "cisa_ics:ICSA-26-043-08",
        ]
        assert {i["cve_id"] for i in pushed_items(c)} == {"CVE-2026-22923"}
        assert st["stats"]["pending_fetched"] == 1 and st["stats"]["pending_not_listed"] == 0
        assert pending() == {}

    def test_a_pending_advisory_that_is_malformed_counts_as_a_try(self, monkeypatch):
        put_on_pending("cisa_ics:ICSA-25-317-15")
        http = _HTTP(
            {
                "changes.csv": changes((NX, CHANGED), (COMOS, "2026-09-01T00:00:00.000000Z")),
                NX: advisory(NX),
                COMOS: {"document": {}},  # constructed: a payload without a vulnerabilities list
            }
        )
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        entry = pending()["cisa_ics:ICSA-25-317-15"]
        assert entry["attempts"] == 2 and "last_tried_at" in entry and "malformed" in entry["last_reason"]
        assert st["stats"]["pending_failed"] == 1 and st["stats"]["malformed"] == 0
        assert cursor() == CHANGED

    def test_one_run_reads_at_most_report_pending_per_run_records(self, monkeypatch):
        monkeypatch.setattr(mod, "REPORT_PENDING_PER_RUN", 1)
        put_on_pending("cisa_ics:ICSA-25-317-15", "cisa_ics:ICSA-25-226-26")
        old = "2026-09-01T00:00:00.000000Z"
        http = _HTTP(
            {
                "changes.csv": changes((NX, CHANGED), (COMOS, old), (ROCKWELL, old)),
                NX: advisory(NX),
                COMOS: advisory(COMOS),
                ROCKWELL: advisory(ROCKWELL),
            }
        )
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        assert len(http.advisories()) == 2 and st["stats"]["pending_fetched"] == 1
        assert len(pending()) == 1

    def test_the_item_limit_does_not_stop_the_pending_reads(self, monkeypatch):
        put_on_pending("cisa_ics:ICSA-25-317-15")
        http = _HTTP(
            {
                "changes.csv": changes((NX, CHANGED), (COMOS, "2026-09-01T00:00:00.000000Z")),
                NX: advisory(NX),
                COMOS: advisory(COMOS),
            }
        )
        c = collector(monkeypatch, http)
        st = c.collect(limit=1, push_to_misp=True, baseline=False)
        assert http.advisories() == [NX, COMOS] and st["stats"]["pending_fetched"] == 1
        assert "cisa_ics:ICSA-25-317-15" in {r["record_ref"] for r in pushed_records(c)}
        assert pending() == {}

    def test_a_pending_record_past_the_run_cap_moves_no_cursor(self, monkeypatch):
        """A capped run reads a pending record's advisory past the cap for its record only; its change time must not
        become the cursor, which would pass the advisories the cap left unread and the pending advisory's items."""
        monkeypatch.setattr(mod, "CISA_ICS_MAX_ADVISORIES_PER_RUN", 1)
        put_on_pending("cisa_ics:ICSA-26-043-08")  # NX
        t1, t2, t3 = "2026-11-01T00:00:00.000000Z", "2026-11-02T00:00:00.000000Z", "2026-11-03T00:00:00.000000Z"
        http = _HTTP(
            {
                "changes.csv": changes((COMOS, t1), (ROCKWELL, t2), (NX, t3)),
                COMOS: advisory(COMOS),
                ROCKWELL: advisory(ROCKWELL),
                NX: advisory(NX),
            }
        )
        c = collector(monkeypatch, http)
        c.collect(push_to_misp=True, baseline=False)
        assert http.advisories() == [COMOS, NX]
        assert "cisa_ics:ICSA-26-043-08" in {r["record_ref"] for r in pushed_records(c)}
        assert cursor() == t1

    def test_an_advisory_the_item_limit_skips_is_still_read_for_its_pending_record(self, monkeypatch):
        """Constructed: an item limit of 1 (only an override such as ``EDGEGUARD_MAX_ENTRIES`` sets one for CISA ICS).
        NX's items reach it; COMOS, selected by the run and so not queued as a pending read, has its record on
        report_pending and is read for that record only; ROCKWELL, without one, is not read. The cursor stays at
        NX, the last advisory read for its items."""
        t1, t2, t3 = "2026-11-01T00:00:00.000000Z", "2026-11-02T00:00:00.000000Z", "2026-11-03T00:00:00.000000Z"
        put_on_pending("cisa_ics:ICSA-25-317-15")  # COMOS
        http = _HTTP(
            {
                "changes.csv": changes((NX, t1), (COMOS, t2), (ROCKWELL, t3)),
                NX: advisory(NX),
                COMOS: advisory(COMOS),
                ROCKWELL: advisory(ROCKWELL),
            }
        )
        c = collector(monkeypatch, http)
        st = c.collect(limit=1, push_to_misp=True, baseline=False)
        assert http.advisories() == [NX, COMOS]
        assert {i["cve_id"] for i in pushed_items(c)} == {"CVE-2026-22923"}, "COMOS's items stay out"
        assert sorted(r["record_ref"] for r in pushed_records(c)) == [
            "cisa_ics:ICSA-25-317-15",
            "cisa_ics:ICSA-26-043-08",
        ]
        assert pending() == {} and st["stats"]["pending_fetched"] == 1
        assert cursor() == t1

    def test_failing_pending_reads_stop_after_their_own_streak_and_the_run_goes_on(self, monkeypatch, caplog):
        # Constructed: five pending records whose advisories the listing names (outside the look-back) and that
        # answer HTTP 404; the run's own advisory is read first and fetched.
        monkeypatch.setattr(mod, "MAX_CONSECUTIVE_FETCH_FAILURES", 3)
        old = "2026-09-01T00:00:00.000000Z"
        missing = [f"2025/icsa-25-001-0{n}.json" for n in range(1, 6)]
        put_on_pending(*(f"cisa_ics:ICSA-25-001-0{n}" for n in range(1, 6)))
        http = _HTTP({"changes.csv": changes((NX, CHANGED), *((p, old) for p in missing)), NX: advisory(NX)})
        c = collector(monkeypatch, http)
        with caplog.at_level("WARNING"):
            st = c.collect(push_to_misp=True, baseline=False)
        assert st["success"] is True and st["stats"]["fetch_failed"] == 0
        assert st["stats"]["pending_fetched"] == 3 and st["stats"]["pending_failed"] == 3
        assert http.advisories()[0] == NX and len(http.advisories()) == 4
        assert sorted(e["attempts"] for e in pending().values()) == [1, 1, 2, 2, 2]
        assert {i["cve_id"] for i in pushed_items(c)} == {"CVE-2026-22923"}
        assert [r["record_ref"] for r in pushed_records(c)] == ["cisa_ics:ICSA-26-043-08"]
        assert any(
            r.levelname == "WARNING" and "[REPORT-PENDING]" in r.getMessage() and "2 record(s) left" in r.getMessage()
            for r in caplog.records
        )
        assert cursor() == CHANGED

    def test_a_breaker_the_pending_reads_open_stops_them_and_the_run_still_pushes(self, monkeypatch, caplog):
        """Constructed: two pending records whose advisories answer HTTP 503. The retries of the first read open the
        breaker (three failures); the second pending read is not tried, and the run pushes the items and the record
        of the advisory it read itself."""
        old = "2026-09-01T00:00:00.000000Z"
        down = ["2025/icsa-25-001-01.json", "2025/icsa-25-001-02.json"]
        put_on_pending("cisa_ics:ICSA-25-001-01", "cisa_ics:ICSA-25-001-02")
        http = _HTTP(
            {
                "changes.csv": changes((NX, CHANGED), *((p, old) for p in down)),
                NX: advisory(NX),
                **{p: _Response(status_code=503, text="unavailable") for p in down},
            }
        )
        c = collector(monkeypatch, http)
        with caplog.at_level("WARNING"):
            st = c.collect(push_to_misp=True, baseline=False)
        assert st["success"] is True and st["stats"]["fetch_failed"] == 0
        assert st["stats"]["pending_fetched"] == 1 and st["stats"]["pending_failed"] == 1
        assert down[1] not in http.paths
        assert {i["cve_id"] for i in pushed_items(c)} == {"CVE-2026-22923"}
        assert [r["record_ref"] for r in pushed_records(c)] == ["cisa_ics:ICSA-26-043-08"]
        assert set(pending()) == {"cisa_ics:ICSA-25-001-01", "cisa_ics:ICSA-25-001-02"}
        assert any(
            r.levelname == "WARNING" and "[REPORT-PENDING]" in r.getMessage() and "circuit breaker" in r.getMessage()
            for r in caplog.records
        )
        assert cursor() == CHANGED

    def test_a_breaker_open_during_the_run_s_own_reads_still_aborts_before_the_push(self, monkeypatch):
        """Constructed: the run's own advisories answer HTTP 503, so the breaker opens among them; the run aborts
        before any push and raises the transient error, as before."""
        down = [f"2026/icsa-26-001-0{n}.json" for n in range(1, 3)]
        http = _HTTP(
            {
                "changes.csv": changes(*((p, CHANGED) for p in down)),
                **{p: _Response(status_code=503, text="unavailable") for p in down},
            }
        )
        c = collector(monkeypatch, http)
        with pytest.raises(mod.CISAICSTransientError, match="aborting before push"):
            c.collect(push_to_misp=True, baseline=False)
        assert down[1] not in http.paths
        c.misp_writer.push_items.assert_not_called()
        c.misp_writer.push_reports.assert_not_called()

    @pytest.mark.parametrize(
        "error",
        [
            requests.exceptions.ChunkedEncodingError("Connection broken: IncompleteRead"),
            requests.exceptions.TooManyRedirects("Exceeded 30 redirects."),
            RecursionError("maximum recursion depth exceeded while decoding a JSON object"),
        ],
        ids=lambda e: type(e).__name__,
    )
    def test_any_error_of_a_pending_read_is_a_failed_try_and_the_run_still_pushes(self, monkeypatch, error):
        """Constructed: the pending record's advisory read raises an error outside the run's own fetch errors (a
        broken body is retried, then raised; a redirect loop; a body JSON cannot hold). It counts as a failed try,
        and the run pushes the items and the record of the advisory it read itself."""
        put_on_pending("cisa_ics:ICSA-25-317-15")
        http = _HTTP(
            {
                "changes.csv": changes((NX, CHANGED), (COMOS, "2026-09-01T00:00:00.000000Z")),
                NX: advisory(NX),
                COMOS: error,
            }
        )
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        assert st["success"] is True and st["stats"]["pending_failed"] == 1 and st["stats"]["fetch_failed"] == 0
        assert {i["cve_id"] for i in pushed_items(c)} == {"CVE-2026-22923"}
        assert [r["record_ref"] for r in pushed_records(c)] == ["cisa_ics:ICSA-26-043-08"]
        entry = pending()["cisa_ics:ICSA-25-317-15"]
        assert entry["attempts"] == 2 and type(error).__name__ in entry["last_reason"]
        assert cursor() == CHANGED

    def test_an_error_outside_the_fetch_errors_on_the_run_s_own_read_still_raises(self, monkeypatch):
        """The run's own reads keep their errors: one outside the timeout, connection, HTTP and JSON errors raises
        out of the run, as before report_pending."""
        http = _HTTP(
            {"changes.csv": changes((NX, CHANGED)), NX: requests.exceptions.TooManyRedirects("Exceeded 30 redirects.")}
        )
        c = collector(monkeypatch, http)
        with pytest.raises(requests.exceptions.TooManyRedirects):
            c.collect(push_to_misp=True, baseline=False)
        c.misp_writer.push_items.assert_not_called()

    @pytest.mark.parametrize("field", ["notes", "references", "remediations", "product_status"])
    def test_a_pending_advisory_whose_lists_are_not_lists_is_a_failed_try(self, monkeypatch, field):
        """Constructed: the pending record's advisory is a CSAF file whose list field holds a number (schema-invalid
        CSAF). Reading it fails with a TypeError; that is a failed try, not the end of the run."""
        bad = copy.deepcopy(advisory(COMOS))
        if field in ("notes", "references"):
            bad["document"][field] = 5
        elif field == "remediations":
            bad["vulnerabilities"][0]["remediations"] = 5
        else:
            bad["vulnerabilities"][0]["product_status"] = {"known_affected": 5}
        put_on_pending("cisa_ics:ICSA-25-317-15")
        http = _HTTP(
            {
                "changes.csv": changes((NX, CHANGED), (COMOS, "2026-09-01T00:00:00.000000Z")),
                NX: advisory(NX),
                COMOS: bad,
            }
        )
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        assert st["success"] is True and st["stats"]["pending_failed"] == 1
        assert [r["record_ref"] for r in pushed_records(c)] == ["cisa_ics:ICSA-26-043-08"]
        assert pending()["cisa_ics:ICSA-25-317-15"]["attempts"] == 2
        assert cursor() == CHANGED

    def test_a_pending_file_naming_another_advisory_gives_that_record_and_its_entry_leaves(self, monkeypatch, caplog):
        """Constructed: the entry is kept under a file name (a failed fetch), and the file it names holds COMOS
        (tracking.id ICSA-25-317-15). The record is written under COMOS's id, and the entry, which no file bears,
        leaves the list instead of being read on every run and never given up."""
        stray = "2025/icsa-25-001-01.json"
        put_on_pending("cisa_ics:ICSA-25-001-01")
        http = _HTTP(
            {
                "changes.csv": changes((NX, CHANGED), (stray, "2026-09-01T00:00:00.000000Z")),
                NX: advisory(NX),
                stray: advisory(COMOS),
            }
        )
        c = collector(monkeypatch, http)
        with caplog.at_level("WARNING"):
            st = c.collect(push_to_misp=True, baseline=False)
        assert st["success"] is True
        assert sorted(r["record_ref"] for r in pushed_records(c)) == [
            "cisa_ics:ICSA-25-317-15",
            "cisa_ics:ICSA-26-043-08",
        ]
        assert pending() == {}
        assert any("[REPORT-PENDING]" in r.getMessage() and "ICSA-25-001-01" in r.getMessage() for r in caplog.records)

    def test_a_breaker_the_run_s_own_last_read_opened_is_named_so(self, monkeypatch, caplog):
        """Constructed: the run's own last advisory answers HTTP 503 and its retries open the breaker; the pending
        reads that follow are not tried, the WARNING says the breaker was open after the run's own reads, and the
        failed read holds the cursor."""
        down = "2026/icsa-26-001-01.json"
        put_on_pending("cisa_ics:ICSA-25-317-15")
        http = _HTTP(
            {
                "changes.csv": changes(
                    (NX, CHANGED), (down, "2026-11-06T07:00:00.000000Z"), (COMOS, "2026-09-01T00:00:00.000000Z")
                ),
                NX: advisory(NX),
                down: _Response(status_code=503, text="unavailable"),
                COMOS: advisory(COMOS),
            }
        )
        c = collector(monkeypatch, http)
        with caplog.at_level("WARNING"):
            st = c.collect(push_to_misp=True, baseline=False)
        assert st["success"] is True and st["stats"]["fetch_failed"] == 1 and st["stats"]["pending_fetched"] == 0
        assert COMOS not in http.paths
        assert any("after the run's own reads" in r.getMessage() for r in caplog.records)
        assert cursor() is None

    def test_a_pending_read_that_succeeds_ends_the_pending_streak(self, monkeypatch):
        # Constructed: pending records read in record-reference order, two whose advisories answer HTTP 404, then
        # COMOS (fetched), then two more answering HTTP 404; no three failures in a row, so every record is tried.
        monkeypatch.setattr(mod, "MAX_CONSECUTIVE_FETCH_FAILURES", 3)
        old = "2026-09-01T00:00:00.000000Z"
        missing = ["2025/icsa-25-001-01.json", "2025/icsa-25-001-02.json"]
        later = ["2025/icsa-25-318-01.json", "2025/icsa-25-318-02.json"]
        refs = [f"cisa_ics:{mod._listed_record_key(p).upper()}" for p in [*missing, COMOS, *later]]
        put_on_pending(*refs)
        http = _HTTP(
            {
                "changes.csv": changes((NX, CHANGED), *((p, old) for p in [*missing, COMOS, *later])),
                NX: advisory(NX),
                COMOS: advisory(COMOS),
            }
        )
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        assert http.advisories() == [NX, *missing, COMOS, *later]
        assert st["stats"]["pending_fetched"] == 5 and st["stats"]["pending_failed"] == 4
        assert {ref: e["attempts"] for ref, e in pending().items()} == {
            ref: 2 for ref in refs if ref != "cisa_ics:ICSA-25-317-15"
        }

    def test_a_pending_read_after_failing_window_reads_does_not_abort_the_run(self, monkeypatch):
        # Constructed: two advisories of the window that answer HTTP 404, then a pending record whose advisory
        # answers HTTP 404 too; three failures in a row, but only two of the run's own reads.
        monkeypatch.setattr(mod, "MAX_CONSECUTIVE_FETCH_FAILURES", 3)
        gone = ["2026/icsa-26-300-91.json", "2026/icsa-26-300-92.json"]
        put_on_pending("cisa_ics:ICSA-25-001-01")
        http = _HTTP(
            {
                "changes.csv": changes(
                    (NX, CHANGED), *((p, CHANGED) for p in gone), ("2025/icsa-25-001-01.json", "2026-09-01T00:00:00Z")
                ),
                NX: advisory(NX),
            }
        )
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        assert st["stats"]["fetch_failed"] == 2 and st["stats"]["pending_failed"] == 1
        assert pending()["cisa_ics:ICSA-25-001-01"]["attempts"] == 2
        assert {"cisa_ics:ICSA-26-300-91", "cisa_ics:ICSA-26-300-92"} <= set(pending())
        assert cursor() is None

    def test_a_list_that_cannot_be_read_does_not_stop_the_run(self, monkeypatch):
        monkeypatch.setattr(rr, "pending_record_refs", MagicMock(side_effect=OSError("unreadable")))
        http = _HTTP({"changes.csv": changes((COMOS, CHANGED)), COMOS: advisory(COMOS)})
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        assert st["success"] is True and st["count"] == 2
        assert [r["record_ref"] for r in pushed_records(c)] == ["cisa_ics:ICSA-25-317-15"]


# --------------------------------------------------------------------------- #
# Records the run cannot build or read
# --------------------------------------------------------------------------- #


class TestRecordsNotBuiltOrRead:
    def test_a_record_that_cannot_be_built_waits_on_report_pending(self, monkeypatch):
        monkeypatch.setattr(rr, "build_record", MagicMock(side_effect=ValueError("no record")))
        http = _HTTP({"changes.csv": changes((COMOS, CHANGED)), COMOS: advisory(COMOS)})
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        entry = pending()["cisa_ics:ICSA-25-317-15"]
        assert entry["attempts"] == 1 and "built" in entry["last_reason"]
        assert st["report_counts"]["reports_failed"] == 1 and st["report_counts"]["records"] == 0
        c.misp_writer.push_reports.assert_not_called()
        assert st["count"] == 2  # the CVE items are pushed
        assert cursor() == CHANGED

    def test_an_over_long_advisory_id_gives_no_record_and_waits_on_report_pending(self, monkeypatch):
        data = advisory(COMOS)
        data["document"]["tracking"]["id"] = "ICSA-" + "X" * 409  # constructed: longer than a record id may be
        http = _HTTP({"changes.csv": changes((COMOS, CHANGED)), COMOS: data})
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=False)
        (entry,) = pending().values()
        assert entry["attempts"] == 1 and "built" in entry["last_reason"]
        assert st["report_counts"]["reports_failed"] == 1

    def test_a_baseline_lists_an_advisory_of_the_window_that_could_not_be_fetched(self, monkeypatch):
        # COMOS (2025-11-11, inside the 730-day window) answers 404 on the baseline.
        http = _HTTP({"index.txt": f"{NX}\n{COMOS}\n", NX: advisory(NX)})
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=True, baseline_days=730)
        assert st["stats"]["fetch_failed"] == 1 and list(pending()) == ["cisa_ics:ICSA-25-317-15"]
        assert cursor() is None
        # The next scheduled run reads it for its record only, though it changed before the look-back.
        http = _HTTP(
            {
                "changes.csv": changes((NX, CHANGED), (COMOS, "2025-11-11T00:00:00.000000Z")),
                NX: advisory(NX),
                COMOS: advisory(COMOS),
            }
        )
        c = collector(monkeypatch, http)
        c.collect(push_to_misp=True, baseline=False)
        assert "cisa_ics:ICSA-25-317-15" in {r["record_ref"] for r in pushed_records(c)}
        assert {i["cve_id"] for i in pushed_items(c)} == {"CVE-2026-22923"}
        assert pending() == {}

    def test_a_baseline_does_not_list_an_advisory_outside_the_window_that_could_not_be_fetched(self, monkeypatch):
        # DICOM's file name dates it 2024-02-27, before the 730-day cutoff 2024-11-07; the margin makes it fetched.
        monkeypatch.setattr(mod, "FILENAME_DATE_MARGIN_DAYS", 400)
        http = _HTTP({"index.txt": f"{NX}\n{DICOM}\n", NX: advisory(NX)})
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=True, baseline_days=730)
        assert st["stats"]["fetch_failed"] == 1 and DICOM in http.advisories()
        assert pending() == {}

    def test_a_baseline_does_not_list_a_record_outside_the_window_that_could_not_be_built(self, monkeypatch):
        monkeypatch.setattr(mod, "FILENAME_DATE_MARGIN_DAYS", 400)
        data = advisory(DICOM)
        data["document"]["tracking"]["id"] = "ICSMA-" + "X" * 409  # constructed: no record can be built
        http = _HTTP({"index.txt": f"{NX}\n{DICOM}\n", NX: advisory(NX), DICOM: data})
        c = collector(monkeypatch, http)
        st = c.collect(push_to_misp=True, baseline=True, baseline_days=730)
        assert st["stats"]["outside_window"] == 1 and pending() == {}

    def test_a_list_that_cannot_be_saved_holds_the_cursor_on_a_run_without_items(self, monkeypatch):
        # Constructed: the recorded DICOM advisory without its vulnerability, so the run has no CVE item and returns
        # before the item push; its record's push fails and report_pending cannot be saved.
        http = _HTTP({"changes.csv": changes((DICOM, CHANGED)), DICOM: without_cves(DICOM)})
        c = collector(monkeypatch, http, failed={"cisa_ics:ICSMA-24-058-01"})
        saving = rr.note_report_push
        monkeypatch.setattr(rr, "note_report_push", MagicMock(side_effect=OSError("disk full")))
        st = c.collect(push_to_misp=True, baseline=False)
        c.misp_writer.push_items.assert_not_called()
        assert st["count"] == 0 and st["report_counts"]["pending_saved"] is False
        assert cursor() is None
        # Control: once the list saves, the same run moves the cursor.
        monkeypatch.setattr(rr, "note_report_push", saving)
        c.collect(push_to_misp=True, baseline=False)
        assert list(pending()) == ["cisa_ics:ICSMA-24-058-01"]
        assert cursor() == CHANGED


# --------------------------------------------------------------------------- #
# Notes and products the record reads
# --------------------------------------------------------------------------- #


def _record(path: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    c = mod.CISAICSCollector(misp_writer=MagicMock())
    return c.parse_advisory_record(data if data is not None else advisory(path), path)


def _details_text(data: Dict[str, Any], cve: str, title: str) -> str:
    vuln = next(v for v in data["vulnerabilities"] if v.get("cve") == cve)
    return next(n["text"] for n in vuln["notes"] if n["category"] == "details" and n["title"] == title).strip()


class TestNotesAndProducts:
    def test_a_description_filed_as_a_details_note_is_the_summary(self):
        data = advisory(DETAILS_ONLY)
        by_cve = {v["cve_id"]: v["summary"] for v in _record(DETAILS_ONLY)["vulnerabilities"]}
        assert by_cve["CVE-2024-11499"] == _details_text(data, "CVE-2024-11499", "CVE description")
        assert by_cve["CVE-2024-10037"] == vuln_note(data, "CVE-2024-10037")  # its description note
        data = advisory(DETAILS_AND_SCORE)
        (vuln,) = _record(DETAILS_AND_SCORE)["vulnerabilities"]
        assert vuln["summary"] == _details_text(data, "CVE-2024-2658", "Vulnerability Details")

    def test_a_score_note_is_no_summary(self):
        data = advisory(XMC20)
        description = vuln_note(data, "CVE-2024-2461")
        vuln = data["vulnerabilities"][0]
        # Constructed: an SSVC details note before the description note (as in ICSA-25-322-01).
        vuln["notes"].insert(0, {"category": "details", "title": "SSVC", "text": "SSVC: Exploitation: none"})
        assert mod.vulnerability_summary(vuln) == description and description
        # Constructed: only score notes give no summary.
        vuln["notes"] = [
            {"category": "details", "title": "SSVC", "text": "SSVC: Exploitation: none"},
            {"category": "details", "title": "CVSS v4.0  Score", "text": "CVSS v4.0 base score 8.7"},
        ]
        assert mod.vulnerability_summary(vuln) == ""

    def test_affected_products_named_only_by_relationships_are_resolved(self):
        by_cve = {v["cve_id"]: v["affected_products"] for v in _record(RELATIONSHIPS)["vulnerabilities"]}
        assert by_cve == {
            "CVE-2024-8933": [
                "EcoStruxure™ Control Expert Versions prior to 16.2 HF003",
                "Modicon M340 CPU Firmware Versions prior to SV3.70 installed on Modicon M340 CPU Controller "
                "(part numbers BMXP34*)",
                "Modicon MC80 Firmware All Versions installed on Modicon MC80 Controller (part numbers BMKC80)",
                "Modicon Momentum Unity M1E Processor Firmware Versions prior to SV2.90 installed on Modicon Momentum "
                "Unity M1E Processor Controller (171CBU*)",
            ],
            "CVE-2024-8935": [
                "EcoStruxure™ Control Expert Versions prior to 16.2 HF003",
                "Modicon M340 CPU Firmware Versions since SV3.60 and prior to SV3.70 installed on Modicon M340 CPU "
                "Controller (part numbers BMXP34*)",
            ],
        }

    def test_a_top_level_full_product_name_is_resolved(self):
        # Constructed: CSAF 2.0, 3.2.2.2; no CISA advisory of 2024-2026 (1,389 read) uses top-level
        # full_product_names.
        tree = {"full_product_names": [{"product_id": "CSAFPID-9001", "name": "Constructed product"}]}
        assert mod.product_id_names(tree) == {"CSAFPID-9001": "Constructed product"}

    def test_the_countries_note_ends_its_sentence_and_joins_its_last_names_with_and(self):
        assert note_text(advisory(MIDDLE_EAST), "Countries/areas deployed") == "Europe, the Middle East and Asia."
        assert _record(MIDDLE_EAST)["deployment_countries"] == ["Asia", "Europe", "the Middle East"]
        assert mod.split_countries_note("Bosnia and Herzegovina, Serbia") == ["Bosnia and Herzegovina", "Serbia"]
        assert mod.split_countries_note("Jamaica and Trinidad and Tobago") == ["Jamaica", "Trinidad and Tobago"]
        assert mod.split_countries_note("U.S.") == ["U.S."]
        assert mod.split_countries_note("Worldwide") == ["Worldwide"]


# --------------------------------------------------------------------------- #
# Record caps
# --------------------------------------------------------------------------- #


class TestRecordCaps:
    """The record caps sit above the real advisories: of the 1,389 of 2024-2026, ICSA-26-113-03 gives 85 distinct
    remediations (82 vendor_fix, 3 mitigation) for each CVE, ICSA-24-235-03 644 affected products for
    CVE-2023-34873, ICSA-24-193-05 497 products. The lists here are constructed to those sizes and above."""

    def test_85_remediations_of_one_cve_are_all_kept(self, caplog):
        data = advisory(COMOS)
        vuln = data["vulnerabilities"][0]
        vuln["remediations"] = [  # constructed
            *({"category": "vendor_fix", "details": f"Product {n}: update to V{n}.1"} for n in range(82)),
            *({"category": "mitigation", "details": f"Mitigation {n}"} for n in range(3)),
        ]
        with caplog.at_level("WARNING"):
            record = _record(COMOS, data)
        kept = record["vulnerabilities"][0]["remediations"]
        assert len(kept) == 85 and sum(r["category"] == "vendor_fix" for r in kept) == 82
        assert not [r for r in caplog.records if "[REPORTS]" in r.getMessage()]

    def test_644_affected_products_of_one_cve_and_600_products_are_all_kept(self):
        fields = {
            "record_id": "ICSA-00-000-00",
            "products": [f"Vendor Product {n:04d}" for n in range(600)],  # constructed
            "vulnerabilities": [
                {"cve_id": "CVE-2023-34873", "affected_products": [f"Product {n:04d} firmware" for n in range(644)]}
            ],
        }
        record = rr.build_record("cisa_ics", fields)
        assert len(record["products"]) == 600
        assert len(record["vulnerabilities"][0]["affected_products"]) == 644
        assert rr.list_cuts("cisa_ics", fields) == []

    def test_no_recorded_advisory_reaches_a_cap(self, caplog):
        with caplog.at_level("WARNING"):
            for path in ADVISORIES:
                _record(path)
        assert not [r for r in caplog.records if "[REPORTS]" in r.getMessage()]

    def test_a_list_a_cap_cuts_is_named_and_logged(self, monkeypatch, caplog):
        monkeypatch.setattr(rr, "_MAX_REMEDIATIONS", 3)
        with caplog.at_level("WARNING"):
            record = _record(DICOM)  # 5 remediations
        (vuln,) = record["vulnerabilities"]
        assert len(vuln["remediations"]) == 3
        (line,) = [r for r in caplog.records if "[REPORTS]" in r.getMessage()]
        assert line.levelname == "WARNING"
        assert line.getMessage() == (
            f"[REPORTS] CISA ICS cisa_ics:ICSMA-24-058-01: the record keeps 3 of the 5 "
            f"vulnerabilities[{vuln['cve_id']}].remediations (its cap)"
        )
