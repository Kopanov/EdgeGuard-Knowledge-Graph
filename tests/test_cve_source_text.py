"""CVE source text in MISP (2026-11-07): the NVD and CISA KEV records' whole texts and new source facts in
``NVD_META``, within a byte budget.

- No collector cuts a CVE text before MISP: NVD's description (cut at 1,000 characters before) and KEV's
  ``shortDescription`` (cut at 500) reach ``NVD_META.description`` whole; the sync caps what the graph holds
  (``text_caps``), so the graph never holds more than ``CVE_DESCRIPTION_CAP``.
- New ``NVD_META`` keys: NVD's ``nvd_vuln_status``, ``references`` (each URL once, with its tags), the CNA's
  ``affected`` vendor / product pairs (at most 20, placeholders dropped), ``cvss_scorers`` (who scored each CVSS
  payload, Primary or Secondary); KEV's ``cisa_notes``, ``cisa_cwes`` and ``cisa_forensic_triage``; for both,
  ``cwe_names`` from the pinned MITRE CWE list (``src/reference/cwe_names.json``) and ``cwe_names_version``.
- The comment stays within ``NVD_META_BUDGET_BYTES``, under MISP's comment column (``MISP_COMMENT_COLUMN_BYTES``,
  taken as MySQL ``TEXT``); over the budget whole list entries go (``_fit_nvd_meta``), never a part of a URL.
- The sync reads an ``NVD_META`` with the new keys as before and lifts none of them yet: the item, and so the graph
  write, is the one the same record without them gives.

Records: ``tests/fixtures/cve_source_text_2026_11_07.json`` and ``tests/fixtures/nvd_cve_2023_44487_2026_11_07.json``,
real answers of the NVD CVE API 2.0 and the CISA KEV catalogue recorded on 2026-11-07 (their ``_provenance`` names
each record and why it is there). Values built for a test that no source gives are marked "constructed".
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
REPO = TESTS.parent
for _p in (REPO / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from fake_bolt import FakeBolt  # noqa: E402

import cwe_names  # noqa: E402
import neo4j_client as nc  # noqa: E402
from collectors import misp_writer as mw  # noqa: E402
from collectors.cisa_collector import CISACollector  # noqa: E402
from collectors.misp_writer import (  # noqa: E402
    MISP_COMMENT_COLUMN_BYTES,
    NVD_META_BUDGET_BYTES,
    NVD_META_SOURCE_TEXT_KEYS,
    KnownAttribute,
    MISPWriter,
    nvd_meta_digest,
    nvd_meta_of_comment,
)
from collectors.nvd_collector import (  # noqa: E402
    NVDCollector,
    nvd_affected,
    nvd_cvss_scorers,
    nvd_references,
    nvd_vuln_status,
)
from collectors.vulnerability_update import meta_changed_keys  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402
from text_caps import CVE_DESCRIPTION_CAP, cap_text  # noqa: E402

FIXTURE = json.loads((TESTS / "fixtures" / "cve_source_text_2026_11_07.json").read_text(encoding="utf-8"))
LARGEST = json.loads((TESTS / "fixtures" / "nvd_cve_2023_44487_2026_11_07.json").read_text(encoding="utf-8"))
NVD = {record["cve"]["id"]: record for record in FIXTURE["nvd"] + LARGEST["nvd"]}
KEV = {entry["cveID"]: entry for entry in FIXTURE["kev"]}
WRITER = MISPWriter.__new__(MISPWriter)
NVD_EVENT = {"id": "601", "info": "EdgeGuard-nvd-2026-11-07", "Tag": []}
KEV_EVENT = {"id": "602", "info": "EdgeGuard-CISA-2026-11-07", "Tag": []}
NEW_KEYS = NVD_META_SOURCE_TEXT_KEYS
BATCH_CVE = "MERGE (n:CVE {cve_id: row.cve_id})"
SINGLE_EDGE = "MERGE (n)-[r:SOURCED_FROM]->(s)"


def _nvd_text(cve_id: str) -> str:
    return next(d["value"] for d in NVD[cve_id]["cve"]["descriptions"] if d["lang"] == "en")


def _nvd_item(cve_id: str) -> Dict[str, Any]:
    collector = NVDCollector.__new__(NVDCollector)
    collector.tag = collector.source_name = "nvd"
    return collector._vulnerability_item(NVD[cve_id])


def _kev_item(cve_id: str) -> Dict[str, Any]:
    collector = CISACollector.__new__(CISACollector)
    collector.tag = "cisa_kev"
    return collector._kev_item(KEV[cve_id])


def _attribute(item: Dict[str, Any], event_id: str) -> Dict[str, Any]:
    attribute = WRITER.create_vulnerability_attribute(dict(item))
    attribute.update(uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, item["cve_id"])), event_id=event_id, timestamp="1")
    return attribute


def _meta(attribute: Dict[str, Any]) -> Dict[str, Any]:
    meta = nvd_meta_of_comment(attribute["comment"])
    assert meta is not None, "the comment is a readable NVD_META"
    return meta


def _comment_bytes(attribute: Dict[str, Any]) -> int:
    return len(attribute["comment"].encode("utf-8"))


def _size(meta: Dict[str, Any]) -> int:
    return len(mw._render_nvd_meta(meta).encode("utf-8"))


def _words(prefix: str, count: int) -> str:
    """Constructed text of words of different lengths (``note0 note1 ... note10 ...``), so a cut at a fixed number
    of characters lands inside a word."""
    return " ".join(f"{prefix}{i}" for i in range(count))


def _cut_at_a_word_end(kept: str, source: str) -> bool:
    return (
        0 < len(kept) < len(source)
        and source.startswith(kept)
        and source[len(kept)].isspace()
        and not kept[-1].isspace()
    )


# The keys the last resort of the byte budget keeps whatever their size (docs/MISP_SOURCES.md, "Byte budget").
CORE_KEYS = {
    "published",
    "last_modified",
    "description",
    "status",
    "cisa_exploit_add",
    "cvss_v40_data",
    "cvss_v31_data",
    "cvss_v30_data",
    "cvss_v2_data",
}
# Constructed: one reference of each kind, every key tag (Exploit, Patch, Vendor Advisory, Mitigation) on its own.
KINDS_OF_REFERENCES = [
    {"url": "https://example.org/0"},
    {"url": "https://example.org/1", "tags": ["Third Party Advisory"]},
    {"url": "https://example.org/2", "tags": ["Mitigation"]},
    {"url": "https://example.org/3"},
    {"url": "https://example.org/4", "tags": ["Vendor Advisory"]},
    {"url": "https://example.org/5", "tags": ["Mailing List"]},
    {"url": "https://example.org/6", "tags": ["Exploit", "Third Party Advisory"]},
    {"url": "https://example.org/7", "tags": ["Patch"]},
]
# Untagged first, then tags without a key tag, then key tags; each kind from the end.
KINDS_DROP_ORDER = [3, 0, 5, 1, 7, 6, 4, 2]


@pytest.fixture(scope="module")
def builder():
    spec = importlib.util.spec_from_file_location("build_cwe_names", REPO / "scripts" / "build_cwe_names.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch):
    monkeypatch.setattr(nc.time, "sleep", lambda *_a, **_k: None)


@pytest.fixture
def bolt():
    opened = []

    def start(*rules):
        server = FakeBolt(list(rules))
        client = nc.Neo4jClient(uri=server.uri, user="neo4j", password="pw")
        opened.append((server, client))
        assert client.connect() is True
        return server, client

    yield start
    for server, client in opened:
        client.close()
        server.close()


def _statements(server: FakeBolt, marker: str) -> List[Dict[str, Any]]:
    return [params for query, params in zip(server.runs, server.parameters, strict=True) if marker in query]


# ------------------------------------------------------------------------------------------ whole texts in MISP
class TestWholeTextInMisp:
    @pytest.mark.parametrize("cve_id", ["CVE-2022-46169", "CVE-2018-0151"])
    def test_the_nvd_description_reaches_misp_whole(self, cve_id):
        text = _nvd_text(cve_id)
        assert len(text) > 1000
        item = _nvd_item(cve_id)
        assert item["description"] == text
        assert _meta(_attribute(item, "601"))["description"] == text

    @pytest.mark.parametrize("cve_id", ["CVE-2026-20127", "CVE-2013-3918"])
    def test_the_kev_short_description_reaches_misp_whole(self, cve_id):
        text = KEV[cve_id]["shortDescription"]
        assert len(text) > 500
        item = _kev_item(cve_id)
        assert item["description"] == text
        assert _meta(_attribute(item, "602"))["description"] == text

    def test_the_kev_notes_reach_misp_whole(self):
        notes = KEV["CVE-2025-39682"]["notes"]
        assert len(notes) == 870
        assert _meta(_attribute(_kev_item("CVE-2025-39682"), "602"))["cisa_notes"] == notes

    def test_the_kev_vendor_and_product_reach_misp_whole(self):
        """CVE-2020-11261: a product of 179 characters, the only ``vendorProject`` or ``product`` of the catalogue
        over 100 characters; ``NVD_META`` holds it whole, with no ``...``."""
        entry = KEV["CVE-2020-11261"]
        assert len(entry["product"]) == 179
        meta = _meta(_attribute(_kev_item("CVE-2020-11261"), "602"))
        assert meta["product"] == entry["product"] and not meta["product"].endswith("...")
        assert meta["vendor"] == entry["vendorProject"]

    def test_vendor_and_product_lose_only_control_characters_and_non_bmp_characters(self):
        # Constructed: no recorded name holds either.
        item = dict(_kev_item("CVE-2024-3400"), vendor=" Acme\x07 Corp\U0001f600 ", product="Series " * 40)
        meta = _meta(_attribute(item, "602"))
        assert meta["vendor"] == "Acme Corp" and meta["product"] == ("Series " * 40).strip()

    def test_the_cisa_ics_first_product_reaches_misp_whole(self):
        """Constructed advisory (CSAF 2.0 shape): a first product name of 149 characters."""
        from collectors.cisa_ics_collector import CISAICSCollector

        product = "Example Series " * 10
        advisory = {
            "document": {
                "title": "Example Controls Example Series",
                "tracking": {"id": "ICSA-26-999-02", "initial_release_date": "2026-11-05T06:00:00.000000Z"},
                "distribution": {"tlp": {"label": "WHITE"}},
            },
            "product_tree": {
                "branches": [
                    {
                        "category": "vendor",
                        "name": "Example Controls",
                        "branches": [{"category": "product_name", "name": product.strip()}],
                    }
                ]
            },
            "vulnerabilities": [{"cve": "CVE-2026-99998", "notes": [{"category": "summary", "text": "A note."}]}],
        }
        (item,), _ = CISAICSCollector(misp_writer=MagicMock()).parse_advisory(advisory, "2026/y.json")
        meta = _meta(_attribute(item, "603"))
        assert len(product.strip()) == 149 and meta["product"] == product.strip()
        assert meta["vendor"] == "Example Controls"

    def test_characters_outside_the_basic_multilingual_plane_are_stripped(self):
        # Constructed: no recorded CVE text holds one. JSON escapes them, so MISP would store the escape and the
        # graph the character; the text MISP holds is the source's without them, as in every MISP text.
        item = dict(
            _kev_item("CVE-2024-3400"), description="Flag \U0001f1fa\U0001f1f8 text", cisa_notes="a \U0001f600 b"
        )
        meta = _meta(_attribute(item, "602"))
        assert meta["description"] == "Flag  text" and meta["cisa_notes"] == "a  b"

    def test_the_cisa_ics_note_reaches_misp_whole(self):
        """Constructed advisory (CSAF 2.0 shape): a vulnerability note of 1,200 characters (the longest live note
        measured on 2026-11-07 has 1,189), which the ICS collector cut at 1,000 with its header before."""
        from collectors.cisa_ics_collector import CISAICSCollector

        note = ("The device accepts a crafted request on its management port. " * 20).strip()
        assert len(note) > 1000
        advisory = {
            "document": {
                "title": "Example Controls Example Series",
                "tracking": {"id": "ICSA-26-999-01", "initial_release_date": "2026-11-05T06:00:00.000000Z"},
                "distribution": {"tlp": {"label": "WHITE"}},
            },
            "vulnerabilities": [
                {"cve": "CVE-2026-99999", "notes": [{"category": "summary", "title": "Summary", "text": note}]}
            ],
        }
        (item,), skipped = CISAICSCollector(misp_writer=MagicMock()).parse_advisory(advisory, "2026/x.json")
        assert skipped == 0
        assert item["description"] == f"ICSA-26-999-01: Example Controls Example Series \u2014 {note}"
        assert _meta(_attribute(item, "603"))["description"] == item["description"]
        ranked = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(
            _attribute(item, "603"), {"id": "603", "info": "EdgeGuard-cisa_ics-2026-11-07", "Tag": []}
        )[0]
        assert ranked["description"] == item["description"], "the sync reads the whole text; its writes cap it"


# ------------------------------------------------------------------------------------------ capped text in the graph
class TestCappedTextInTheGraph:
    def test_the_nvd_text_is_read_whole_and_written_capped(self, bolt):
        text = _nvd_text("CVE-2022-46169")
        item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(
            _attribute(_nvd_item("CVE-2022-46169"), "601"), NVD_EVENT
        )
        assert item["description"] == text, "the sync reads the whole text from MISP"
        capped, truncated, full_length = cap_text(text, CVE_DESCRIPTION_CAP)
        assert truncated and full_length == len(text) and len(capped) <= CVE_DESCRIPTION_CAP
        server, client = bolt()
        assert MISPToNeo4jSync(neo4j_client=client)._sync_to_neo4j_chunk([item]) == (1, 0)
        ((row,),) = [p["rows"] for p in _statements(server, BATCH_CVE)]
        assert row["description"] == capped and text.startswith(capped)
        ((edge_row,),) = [p["rows"] for p in _statements(server, SINGLE_EDGE) if "rows" in p]
        assert json.loads(edge_row["raw_data"])["description"] == capped

    def test_the_kev_text_reaches_the_graph_within_the_cve_cap(self, bolt):
        """A CVE only KEV names: its 821 characters are within ``CVE_DESCRIPTION_CAP`` and reach the node whole."""
        text = KEV["CVE-2026-20127"]["shortDescription"]
        item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(
            _attribute(_kev_item("CVE-2026-20127"), "602"), KEV_EVENT
        )
        assert item["description"] == text and item["source"] == ["cisa_kev"]
        server, client = bolt()
        assert MISPToNeo4jSync(neo4j_client=client)._sync_to_neo4j_chunk([item]) == (1, 0)
        ((row,),) = [p["rows"] for p in _statements(server, BATCH_CVE)]
        assert row["description"] == text and len(text) <= CVE_DESCRIPTION_CAP


# ------------------------------------------------------------------------------------------ new NVD keys
class TestNvdKeys:
    def test_the_first_v31_metric_is_the_cnas_and_says_so(self):
        """CVE-2024-3400 lists the vendor's v3.1 metric (Secondary) before NVD's (Primary): the payload the score
        comes from stays the first, and ``cvss_scorers`` names its scorer and type."""
        metrics = NVD["CVE-2024-3400"]["cve"]["metrics"]["cvssMetricV31"]
        assert [(m["source"], m["type"]) for m in metrics] == [
            ("psirt@paloaltonetworks.com", "Secondary"),
            ("nvd@nist.gov", "Primary"),
        ]
        meta = _meta(_attribute(_nvd_item("CVE-2024-3400"), "601"))
        assert meta["cvss_scorers"] == {
            "cvss_v31_data": {"scored_by": "psirt@paloaltonetworks.com", "score_type": "Secondary"}
        }
        assert meta["cvss_v31_data"]["vector_string"] == metrics[0]["cvssData"]["vectorString"]
        assert "scored_by" not in meta["cvss_v31_data"], "the payload itself is unchanged"

    def test_nvds_own_score_is_primary(self):
        meta = _meta(_attribute(_nvd_item("CVE-2014-6271"), "601"))
        assert meta["cvss_scorers"] == {
            "cvss_v31_data": {"scored_by": "nvd@nist.gov", "score_type": "Primary"},
            "cvss_v2_data": {"scored_by": "nvd@nist.gov", "score_type": "Primary"},
        }

    def test_the_analysis_state_is_kept_beside_the_resilmesh_status(self):
        meta = _meta(_attribute(_nvd_item("CVE-2024-3400"), "601"))
        assert NVD["CVE-2024-3400"]["cve"]["vulnStatus"] == "Analyzed"
        assert meta["nvd_vuln_status"] == "Analyzed" and meta["status"] == ["active"]

    def test_references_keep_their_tags_each_url_once(self):
        refs = NVD["CVE-2024-3400"]["cve"]["references"]
        meta = _meta(_attribute(_nvd_item("CVE-2024-3400"), "601"))
        assert len(refs) == 9 and len(meta["references"]) == 5
        assert [r["url"] for r in meta["references"]] == list(dict.fromkeys(r["url"] for r in refs))
        for entry in meta["references"]:
            expected = list(dict.fromkeys(t for r in refs if r["url"] == entry["url"] for t in r.get("tags", [])))
            assert entry.get("tags", []) == expected
        unit42 = next(r for r in meta["references"] if r["url"] == "https://unit42.paloaltonetworks.com/cve-2024-3400/")
        assert "Exploit" in unit42["tags"]
        assert meta["reference_urls"] == [r["url"] for r in refs][:10], "the key the sync reads is unchanged"

    def test_the_collector_gives_each_url_once(self):
        refs = nvd_references(NVD["CVE-2024-3400"]["cve"])
        assert [r["url"] for r in refs] == list(
            dict.fromkeys(r["url"] for r in NVD["CVE-2024-3400"]["cve"]["references"])
        )
        assert len(refs) == 5

    def test_a_reference_url_too_long_is_left_out_whole(self):
        # Constructed: a URL longer than the CVE format allows is left out, never cut.
        record = json.loads(json.dumps(NVD["CVE-2023-29492"]))
        long_url = "https://example.org/" + "a" * 2100
        record["cve"]["references"].append({"url": long_url, "source": "x", "tags": ["Exploit"]})
        collector = NVDCollector.__new__(NVDCollector)
        collector.tag = collector.source_name = "nvd"
        meta = _meta(_attribute(collector._vulnerability_item(record), "601"))
        assert all(r["url"] != long_url and not long_url.startswith(r["url"]) for r in meta["references"])

    def test_the_cnas_pairs_without_the_adp_container(self):
        """CVE-2024-3400: the CNA (psirt@paloaltonetworks.com) names three products; the CISA-ADP container names
        them again in CPE words ("paloaltonetworks" / "pan-os") and is left out."""
        meta = _meta(_attribute(_nvd_item("CVE-2024-3400"), "601"))
        assert meta["affected"] == [
            {"vendor": "Palo Alto Networks", "product": "PAN-OS"},
            {"vendor": "Palo Alto Networks", "product": "Cloud NGFW"},
            {"vendor": "Palo Alto Networks", "product": "Prisma Access"},
        ]
        adp = [a for a in NVD["CVE-2024-3400"]["cve"]["affected"] if a["source"] != "psirt@paloaltonetworks.com"]
        assert any(d["vendor"] == "paloaltonetworks" for a in adp for d in a["affectedData"])

    def test_placeholders_are_no_names(self):
        (cna,) = NVD["CVE-2018-0151"]["cve"]["affected"]
        assert [(d["vendor"], d["product"]) for d in cna["affectedData"]] == [("n/a", "Cisco IOS and IOS XE")]
        assert _meta(_attribute(_nvd_item("CVE-2018-0151"), "601"))["affected"] == [{"product": "Cisco IOS and IOS XE"}]
        # CVE-2023-29492: the CNA (cve@mitre.org) names neither; the CISA-ADP container's CPE words do not count.
        cna, adp = NVD["CVE-2023-29492"]["cve"]["affected"]
        assert cna["source"] == NVD["CVE-2023-29492"]["cve"]["sourceIdentifier"] != adp["source"]
        assert [(d["vendor"], d["product"]) for d in cna["affectedData"]] == [("n/a", "n/a")]
        assert [(d["vendor"], d["product"]) for d in adp["affectedData"]] == [("novisurvey", "novi_survey")]
        assert "affected" not in _meta(_attribute(_nvd_item("CVE-2023-29492"), "601"))

    def test_a_package_only_entry_keeps_its_package_name(self):
        """CVE-2025-10854: the CNA names the product only as a PyPI package (``collectionURL`` + ``packageName``),
        the record's only product identity (it has no configurations)."""
        cve = NVD["CVE-2025-10854"]["cve"]
        ((data,),) = [a["affectedData"] for a in cve["affected"]]
        assert "vendor" not in data and "product" not in data and data["packageName"] == "txtai"
        assert not cve.get("configurations")
        assert nvd_affected(cve) == [{"product": "txtai"}]
        assert _meta(_attribute(_nvd_item("CVE-2025-10854"), "601"))["affected"] == [{"product": "txtai"}]

    def test_a_real_product_comes_before_the_package_name(self):
        """CVE-2023-40660: the upstream entry names only the package ``OpenSC``; the Red Hat entries name a product
        and a package (``opensc``) and keep the product."""
        assert nvd_affected(NVD["CVE-2023-40660"]["cve"]) == [
            {"product": "OpenSC"},
            {"vendor": "Red Hat", "product": "Red Hat Enterprise Linux 8"},
            {"vendor": "Red Hat", "product": "Red Hat Enterprise Linux 9"},
            {"vendor": "Red Hat", "product": "Red Hat Enterprise Linux 7"},
        ]

    def test_every_placeholder_in_any_case_and_an_overlong_name_are_no_names(self):
        # Constructed: the recorded records hold only "n/a".
        long_name = "N" * 257
        cve = {
            "sourceIdentifier": "cna@example.org",
            "affected": [
                {
                    "source": "cna@example.org",
                    "affectedData": [
                        {"vendor": "Unknown", "product": "Widget"},
                        {"vendor": "UNKNOWN", "product": "*"},
                        {"vendor": "-", "product": "Gadget"},
                        {"vendor": "N/A", "product": "Tool"},
                        {"vendor": "Acme", "product": long_name},
                        {"vendor": long_name, "product": "N" * 256},
                        {"vendor": "*", "packageName": "unknown"},
                        {"collectionURL": "https://example.org", "packageName": "pkg"},
                    ],
                }
            ],
        }
        assert nvd_affected(cve) == [
            {"product": "Widget"},
            {"product": "Gadget"},
            {"product": "Tool"},
            {"vendor": "Acme"},
            {"product": "N" * 256},
            {"product": "pkg"},
        ]

    def test_the_collectors_string_bounds(self):
        # Constructed: no recorded state, scorer or type comes near its bound.
        assert nvd_vuln_status({"vulnStatus": "S" * 32}) == "S" * 32
        assert nvd_vuln_status({"vulnStatus": "S" * 33}) == ""
        metrics = {
            "cvssMetricV31": [{"source": "s" * 129, "type": "Primary"}],
            "cvssMetricV30": [{"source": "nvd@nist.gov", "type": "T" * 33}],
            "cvssMetricV2": [{"source": "s" * 128, "type": "T" * 32}],
        }
        assert nvd_cvss_scorers(metrics) == {
            "cvss_v31_data": {"score_type": "Primary"},
            "cvss_v30_data": {"scored_by": "nvd@nist.gov"},
            "cvss_v2_data": {"scored_by": "s" * 128, "score_type": "T" * 32},
        }

    def test_at_most_twenty_pairs(self):
        cve = NVD["CVE-2023-28229"]["cve"]
        pairs = list(
            dict.fromkeys(
                (d["vendor"], d["product"])
                for a in cve["affected"]
                if a["source"] == cve["sourceIdentifier"]
                for d in a["affectedData"]
            )
        )
        assert len(pairs) == 22
        assert [(p["vendor"], p["product"]) for p in nvd_affected(cve)] == pairs[:20], "the collector keeps 20"
        meta = _meta(_attribute(_nvd_item("CVE-2023-28229"), "601"))
        assert [(p["vendor"], p["product"]) for p in meta["affected"]] == pairs[:20]
        # The writer bounds an item's pairs as well (constructed: an item with all 22).
        item = dict(_nvd_item("CVE-2023-28229"), affected=[{"vendor": v, "product": p} for v, p in pairs])
        assert len(_meta(_attribute(item, "601"))["affected"]) == 20

    def test_cwe_names_from_the_pinned_list(self):
        meta = _meta(_attribute(_nvd_item("CVE-2024-3400"), "601"))
        assert meta["cwe"] == ["CWE-20", "CWE-77"]
        assert meta["cwe_names"] == [
            "CWE-20: Improper Input Validation",
            "CWE-77: Improper Neutralization of Special Elements used in a Command",
        ]
        assert meta["cwe_names_version"] == "5.0"

    def test_the_listed_keys_are_exactly_the_facts_the_writer_adds(self):
        """``NVD_META_SOURCE_TEXT_KEYS`` against the writer: over every recorded NVD record and KEV entry, clearing
        the listed facts of an item removes exactly the listed keys, and each listed key is written for some record.
        Against a copy MISP stored on 2026-10-13 (before these keys), every key the writer adds now is listed, but
        for ``ssvc`` and ``known_ransomware_use``, keys of their own that copy predates."""
        items = [_nvd_item(cve_id) for cve_id in NVD] + [_kev_item(cve_id) for cve_id in KEV]
        added = set()
        for item in items:
            cleared = dict(item, **{key: None for key in NVD_META_SOURCE_TEXT_KEYS})
            gained = set(_meta(_attribute(item, "601"))) - set(_meta(_attribute(cleared, "601")))
            assert gained <= set(NVD_META_SOURCE_TEXT_KEYS), item["cve_id"]
            added |= gained
        assert added == set(NVD_META_SOURCE_TEXT_KEYS)
        stored_fixture = json.loads(
            (TESTS / "fixtures" / "nvd_incremental_2026_10_14.json").read_text(encoding="utf-8")
        )
        stored = nvd_meta_of_comment(stored_fixture["misp"]["CVE-2025-0237"]["comment"])
        collector = NVDCollector.__new__(NVDCollector)
        collector.tag = collector.source_name = "nvd"
        current = _meta(_attribute(collector._vulnerability_item(stored_fixture["nvd"]["CVE-2025-0237"]), "601"))
        new_since = set(current) - set(stored) - {"ssvc", "known_ransomware_use"}
        assert new_since and new_since <= set(NVD_META_SOURCE_TEXT_KEYS)

    def test_the_order_of_the_cwe_lists_is_no_change(self):
        """``cwe`` is compared without its order (NVD built it from a set before 2026-10), so are the names made from
        it and KEV's own ids: a stored copy that lists them in another order needs no edit."""
        meta = _meta(_attribute(_nvd_item("CVE-2022-46169"), "601"))
        assert len(meta["cwe_names"]) == 3
        reordered = dict(meta, cwe=meta["cwe"][::-1], cwe_names=meta["cwe_names"][::-1])
        assert nvd_meta_digest(reordered) == nvd_meta_digest(meta)
        kev = _meta(_attribute(dict(_kev_item("CVE-2024-3400")), "602"))
        assert nvd_meta_digest(dict(kev, cisa_cwes=kev["cisa_cwes"][::-1])) == nvd_meta_digest(kev)
        assert nvd_meta_digest(dict(meta, cwe_names=meta["cwe_names"][:2])) != nvd_meta_digest(meta)

    def test_a_cwe_version_without_names_is_not_written(self):
        # Constructed: an item that carries the version but no name.
        item = dict(_nvd_item("CVE-2023-29492"), cwe_names=[], cwe_names_version="5.0")
        meta = _meta(_attribute(item, "601"))
        assert "cwe_names" not in meta and "cwe_names_version" not in meta

    def test_a_record_without_the_new_facts_gets_no_new_key(self):
        """Constructed item without the new keys (an older item shape): its NVD_META, and so its digest, is the
        one it had."""
        item = {k: v for k, v in _nvd_item("CVE-2023-29492").items() if k not in NEW_KEYS}
        meta = _meta(_attribute(item, "601"))
        assert not set(NEW_KEYS) & set(meta)


# ------------------------------------------------------------------------------------------ the writer's own checks
class TestWriterChecks:
    """The writer checks every value again, whatever the collector did: constructed items passed straight to
    ``create_vulnerability_attribute``, each value at or just over its bound."""

    @staticmethod
    def _meta_of(**facts: Any) -> Dict[str, Any]:
        return _meta(_attribute(dict(_nvd_item("CVE-2023-29492"), **facts), "601"))

    def test_a_url_listed_again_merges_its_tags(self):
        url = "https://example.org/advisory"
        refs = [{"url": url, "tags": ["Patch"]}, {"url": " " + url, "tags": ["Exploit", "Patch"]}, {"url": "  "}]
        assert self._meta_of(references=refs)["references"] == [{"url": url, "tags": ["Patch", "Exploit"]}]

    def test_an_overlong_url_or_tag_is_left_out_and_twenty_tags_are_kept(self):
        long_url = "https://example.org/" + "a" * 2029
        assert len(long_url) == 2049
        tags = [f"Tag {i}" for i in range(25)] + ["T" * 65]
        refs = [
            {"url": long_url, "tags": ["Exploit"]},
            {"url": "https://example.org/short", "tags": ["T" * 65, *tags]},
            {"url": "https://example.org/" + "b" * 2028},
        ]
        assert self._meta_of(references=refs)["references"] == [
            {"url": "https://example.org/short", "tags": tags[:20]},
            {"url": "https://example.org/" + "b" * 2028},
        ]

    def test_at_most_a_thousand_urls_and_a_kept_url_still_merges(self):
        refs = [{"url": f"h:{i}"} for i in range(1001)] + [{"url": "h:0", "tags": ["Exploit"]}]
        kept = self._meta_of(references=refs)["references"]
        assert len(kept) == 1000 and kept[0] == {"url": "h:0", "tags": ["Exploit"]}
        assert kept[-1] == {"url": "h:999"}

    def test_affected_names_pairs_and_shapes(self):
        pairs = [
            {"vendor": "V" * 257, "product": "P" * 256},
            "Acme Widget",
            {"vendor": "Acme", "product": "Widget"},
            {"vendor": " Acme ", "product": "Widget"},
            {"vendor": "", "product": None},
        ]
        assert self._meta_of(affected=pairs)["affected"] == [
            {"product": "P" * 256},
            {"vendor": "Acme", "product": "Widget"},
        ]

    def test_short_strings_over_their_bound_are_left_out(self):
        meta = self._meta_of(
            nvd_vuln_status="S" * 33,
            cisa_forensic_triage="Y" * 17,
            cwe_names=["CWE-20: Improper Input Validation"],
            cwe_names_version="V" * 33,
        )
        assert not {"nvd_vuln_status", "cisa_forensic_triage", "cwe_names_version"} & set(meta)
        assert meta["cwe_names"] == ["CWE-20: Improper Input Validation"]
        meta = self._meta_of(nvd_vuln_status=" " + "S" * 32, cisa_forensic_triage="Y" * 16)
        assert meta["nvd_vuln_status"] == "S" * 32 and meta["cisa_forensic_triage"] == "Y" * 16

    def test_cwe_names_and_ids_are_bounded_whole(self):
        names = ["CWE-1: " + "n" * 293, "CWE-2: " + "n" * 294] + [f"CWE-{i}: name" for i in range(3, 63)]
        assert len(names[0]) == 300 and len(names[1]) == 301
        meta = self._meta_of(cwe_names=names, cwe_names_version="5.0")
        assert meta["cwe_names"] == [names[0], *names[2:51]] and len(meta["cwe_names"]) == 50
        ids = ["CWE-20", "CWE-20", "CWE-" + "9" * 13] + [f"CWE-{i}" for i in range(100, 160)]
        assert self._meta_of(cisa_cwes=ids)["cisa_cwes"] == ["CWE-20", *ids[3:52]]

    def test_cvss_scorers_over_their_bound_are_left_out(self):
        scorers = {
            "cvss_v31_data": {"scored_by": "s" * 129, "score_type": "T" * 33},
            "cvss_v2_data": {"scored_by": "nvd@nist.gov", "score_type": "Primary"},
            "cvss_v30_data": {"scored_by": "s" * 128, "score_type": "T" * 32},
            "other": {"scored_by": "nvd@nist.gov"},
        }
        assert self._meta_of(cvss_scorers=scorers)["cvss_scorers"] == {
            "cvss_v30_data": {"scored_by": "s" * 128, "score_type": "T" * 32},
            "cvss_v2_data": {"scored_by": "nvd@nist.gov", "score_type": "Primary"},
        }

    def test_the_kev_collector_passes_raw_values_and_the_writer_bounds_them(self):
        """The KEV collector copies ``forensicTriage`` and ``cwes`` as CISA gives them: the writer's check is the
        only one on that path."""
        entry = dict(KEV["CVE-2025-39682"], forensicTriage="Yes, see the advisory", cwes=["CWE-754", "CWE-" + "7" * 13])
        collector = CISACollector.__new__(CISACollector)
        collector.tag = "cisa_kev"
        item = collector._kev_item(entry)
        assert item["cisa_forensic_triage"] == entry["forensicTriage"] and item["cisa_cwes"] == entry["cwes"]
        meta = _meta(_attribute(item, "602"))
        assert "cisa_forensic_triage" not in meta and meta["cisa_cwes"] == ["CWE-754"]


# ------------------------------------------------------------------------------------------ new KEV keys
class TestKevKeys:
    def test_notes_cwes_and_forensic_triage(self):
        entry = KEV["CVE-2025-39682"]
        assert entry["forensicTriage"] == "Yes"
        meta = _meta(_attribute(_kev_item("CVE-2025-39682"), "602"))
        assert meta["cisa_forensic_triage"] == "Yes"
        assert meta["cisa_cwes"] == entry["cwes"] == ["CWE-754"]
        assert meta["cisa_notes"] == entry["notes"]
        assert meta["cwe_names"] == ["CWE-754: Improper Check for Unusual or Exceptional Conditions"]

    def test_labelled_notes_are_kept_as_text(self):
        notes = KEV["CVE-2026-19868"]["notes"]
        assert "BOD 26-04: https://" in notes
        meta = _meta(_attribute(_kev_item("CVE-2026-19868"), "602"))
        assert meta["cisa_notes"] == notes and meta["cisa_forensic_triage"] == "No"

    def test_an_entry_without_cwes(self):
        meta = _meta(_attribute(_kev_item("CVE-2013-3918"), "602"))
        assert KEV["CVE-2013-3918"]["cwes"] == []
        assert "cisa_cwes" not in meta and "cwe_names" not in meta and "cwe_names_version" not in meta

    def test_a_change_to_the_notes_is_an_edit(self):
        """A stored copy written without the new keys differs from the item: the KEV edit path rewrites it and
        names the keys that changed."""
        item = _kev_item("CVE-2025-39682")
        older = {k: v for k, v in item.items() if k not in NEW_KEYS}
        stored_attr = WRITER.create_vulnerability_attribute(dict(older))
        stored_meta = nvd_meta_of_comment(stored_attr["comment"])
        stored = KnownAttribute(
            uuid="u-1",
            event_id="602",
            meta_digest=nvd_meta_digest(stored_meta),
            tags=tuple(t["name"] for t in stored_attr["Tag"]),
            meta=stored_meta,
        )
        ((_, changes),) = WRITER.plan_vulnerability_update(dict(item), [stored])
        assert set(meta_changed_keys(stored_meta, nvd_meta_of_comment(changes["comment"]))) == {
            "cisa_notes",
            "cisa_cwes",
            "cisa_forensic_triage",
            "cwe_names",
            "cwe_names_version",
        }
        same = KnownAttribute(
            uuid="u-2",
            event_id="602",
            meta_digest=nvd_meta_digest(nvd_meta_of_comment(changes["comment"])),
            tags=stored.tags,
        )
        assert WRITER.plan_vulnerability_update(dict(item), [same]) == []


# ------------------------------------------------------------------------------------------ the byte budget
class TestBudget:
    def test_the_budget_is_under_the_comment_column(self):
        assert NVD_META_BUDGET_BYTES < MISP_COMMENT_COLUMN_BYTES == 65_535

    @pytest.mark.parametrize(
        "cve_id, references, urls, at_least",
        [
            # The most references of NVD's KEV page (1,769 records on 2026-11-07).
            ("CVE-2014-6271", 341, 171, 24_000),
            # The largest comment of that page: 26,598 bytes measured on 2026-11-07.
            ("CVE-2023-44487", 292, 173, 26_500),
        ],
    )
    def test_the_largest_real_records_fit_whole(self, cve_id, references, urls, at_least, caplog):
        """Every URL kept with its tags, nothing shrunk: the budget sits above the largest real record."""
        refs = NVD[cve_id]["cve"]["references"]
        assert len(refs) == references
        with caplog.at_level(logging.WARNING, logger=mw.logger.name):
            attribute = _attribute(_nvd_item(cve_id), "601")
        meta = _meta(attribute)
        assert len(meta["references"]) == len({r["url"] for r in refs}) == urls
        assert at_least < _comment_bytes(attribute) <= NVD_META_BUDGET_BYTES < MISP_COMMENT_COLUMN_BYTES
        assert not [r for r in caplog.records if "[NVD_META]" in r.getMessage()], "nothing was shrunk"

    @pytest.mark.parametrize("budget", [6_000, 12_000, 18_000])
    def test_the_shrink_order_on_the_largest_real_record(self, budget, caplog):
        item = _nvd_item("CVE-2014-6271")
        full = WRITER.create_vulnerability_attribute(dict(item))
        full_meta = _meta(full)
        with caplog.at_level(logging.WARNING, logger=mw.logger.name):
            comment = mw._fit_nvd_meta(full_meta, budget=budget, ref="CVE-2014-6271")
        assert len(comment.encode("utf-8")) <= budget
        meta = nvd_meta_of_comment(comment)
        assert meta is not None, "the JSON is intact"
        kept = meta["references"]
        assert 0 < len(kept) < len(full_meta["references"])
        # Whole entries only, in their order; every other key as it was.
        assert all(entry in full_meta["references"] for entry in kept)
        positions = [full_meta["references"].index(entry) for entry in kept]
        assert positions == sorted(positions)
        assert {k: v for k, v in meta.items() if k != "references"} == {
            k: v for k, v in full_meta.items() if k != "references"
        }
        # The untagged go first, a key tag (Exploit, Patch, Vendor Advisory, Mitigation) last.
        dropped = [e for e in full_meta["references"] if e not in kept]

        def kind(entry):
            tags = entry.get("tags", [])
            return 0 if not tags else 2 if {"Exploit", "Patch", "Vendor Advisory", "Mitigation"} & set(tags) else 1

        assert max(kind(e) for e in dropped) <= min(kind(e) for e in kept)
        # As few as make it fit: keeping one more does not fit (the order rebuilt here, not read from the writer).
        order = sorted(range(len(full_meta["references"])), key=lambda i: (kind(full_meta["references"][i]), -i))
        one_more = [full_meta["references"][i] for i in sorted(set(range(len(order))) - set(order[: len(dropped) - 1]))]
        assert len(mw._render_nvd_meta(dict(meta, references=one_more)).encode("utf-8")) > budget
        (line,) = [r.getMessage() for r in caplog.records if "[NVD_META]" in r.getMessage()]
        assert "CVE-2014-6271" in line and f"references {len(dropped)} of 171" in line
        assert "http" not in line, "the log names counts, never content"

    def test_a_worst_case_record_stays_under_the_column(self):
        """Constructed: 1,000 references of 2,000-character URLs (about 2 MB) and 20 long pairs."""
        urls = [f"https://example.org/{i:04d}/" + "p" * 1975 for i in range(1000)]
        item = dict(
            _nvd_item("CVE-2024-3400"),
            references=[{"url": url, "tags": ["Exploit"] if i % 7 == 0 else []} for i, url in enumerate(urls)],
            affected=[{"vendor": f"V{i}" + "v" * 250, "product": f"P{i}" + "q" * 250} for i in range(20)],
        )
        attribute = WRITER.create_vulnerability_attribute(item)
        assert _comment_bytes(attribute) <= NVD_META_BUDGET_BYTES
        meta = _meta(attribute)
        assert meta["references"] and all(r["url"] in urls for r in meta["references"]), "URLs are kept whole"
        assert all("Exploit" in r.get("tags", []) for r in meta["references"]), "tagged references are kept longest"
        assert len(meta["affected"]) == 20, "the next list is not touched while dropping references suffices"
        assert meta["description"] == _nvd_text("CVE-2024-3400")

    def test_the_lists_shrink_in_order(self):
        """Constructed: when no reference is left and the comment is still over, the CNA pairs go next, from the
        end."""
        meta = dict(
            _meta(_attribute(_nvd_item("CVE-2023-29492"), "601")),
            references=[{"url": "https://example.org/r"}],
            affected=[{"vendor": f"Vendor {i}", "product": "x" * 200} for i in range(20)],
        )
        size_without_refs = len(mw._render_nvd_meta({k: v for k, v in meta.items() if k != "references"}).encode())
        budget = size_without_refs - 1000
        comment = mw._fit_nvd_meta(meta, budget=budget, ref="CVE-2023-29492")
        out = nvd_meta_of_comment(comment)
        assert len(comment.encode()) <= budget and "references" not in out
        assert out["affected"] == meta["affected"][: len(out["affected"])] and 0 < len(out["affected"]) < 20
        assert out["cwe_names"] == meta["cwe_names"]

    def test_the_last_resort_keeps_the_json_and_the_record(self, caplog):
        """Constructed: a description far beyond any CVE record (over 100,000 characters) is cut at a word end, the
        only case a source text is cut; the record keeps its id fields and scores."""
        source = _words("word", 15_000)
        assert len(source) > 100_000
        item = dict(_nvd_item("CVE-2024-3400"), description=source)
        with caplog.at_level(logging.ERROR, logger=mw.logger.name):
            attribute = WRITER.create_vulnerability_attribute(item)
        meta = _meta(attribute)
        assert _comment_bytes(attribute) <= NVD_META_BUDGET_BYTES
        assert _cut_at_a_word_end(meta["description"], source)
        assert meta["cvss_v31_data"] and meta["published"]
        assert any("[NVD_META]" in r.getMessage() and r.levelno == logging.ERROR for r in caplog.records)

    def test_a_cut_ends_at_a_word_end(self):
        assert mw._cut_at_word("alpha beta", 20) == "alpha beta"
        assert mw._cut_at_word("alpha beta gamma", 12) == "alpha beta"
        assert mw._cut_at_word("alpha beta", 5) == "alpha"
        assert mw._cut_at_word("alpha\nbeta", 8) == "alpha"
        assert mw._cut_at_word("alpha  beta", 7) == "alpha"
        assert mw._cut_at_word("alphabeta", 5) == "alpha", "a text without whitespace is cut where it must be"

    def test_the_last_resort_cuts_the_kev_notes(self, caplog):
        """Constructed: KEV notes far over the budget are cut at a word end; the description stays whole and only
        the lists go (``cwe_names`` with its version)."""
        notes = _words("note", 12_000)
        meta = dict(_meta(_attribute(_kev_item("CVE-2025-39682"), "602")), cisa_notes=notes)
        with caplog.at_level(logging.ERROR, logger=mw.logger.name):
            comment = mw._fit_nvd_meta(meta, ref="CVE-2025-39682")
        out = nvd_meta_of_comment(comment)
        assert len(comment.encode("utf-8")) <= NVD_META_BUDGET_BYTES
        assert _cut_at_a_word_end(out["cisa_notes"], notes)
        assert out["description"] == meta["description"]
        assert set(out) == set(meta) - {"cwe_names", "cwe_names_version"}
        assert any("[NVD_META]" in r.getMessage() and r.levelno == logging.ERROR for r in caplog.records)

    def test_the_longer_text_is_cut_first(self):
        """Constructed: a description of about 4,000 characters (a CVE record's bound) beside notes far over the
        budget: cutting the notes fits, so the description stays whole."""
        description, notes = _words("desc", 500), _words("note", 12_000)
        assert 3_500 < len(description) <= 4_096
        meta = dict(_meta(_attribute(_kev_item("CVE-2025-39682"), "602")), description=description, cisa_notes=notes)
        out = nvd_meta_of_comment(mw._fit_nvd_meta(meta, ref="CVE-2025-39682"))
        assert out["description"] == description and _cut_at_a_word_end(out["cisa_notes"], notes)

    @staticmethod
    def _small_record() -> Dict[str, Any]:
        """CVE-2024-3400's NVD_META with a constructed description too short for the last resort to cut."""
        return dict(_meta(_attribute(_nvd_item("CVE-2024-3400"), "601")), description="A short description.")

    def test_the_last_resort_drops_the_largest_key_first(self, caplog):
        """Constructed: a huge ``cisa_required_action`` and an ``ssvc`` of about 1 KB; dropping the largest key is
        enough, so ``ssvc`` stays."""
        meta = dict(
            self._small_record(),
            cisa_required_action=_words("act", 700),
            ssvc={"exploitation": "active", "note": "s" * 1_000},
        )
        expected = {
            k: v
            for k, v in meta.items()
            if k not in {"references", "affected", "version_constraints", "cwe_names", "cwe_names_version"}
            and k != "cisa_required_action"
        }
        with caplog.at_level(logging.ERROR, logger=mw.logger.name):
            comment = mw._fit_nvd_meta(meta, budget=_size(expected), ref="CVE-2024-3400")
        assert nvd_meta_of_comment(comment) == expected
        assert any("[NVD_META]" in r.getMessage() and r.levelno == logging.ERROR for r in caplog.records)

    def test_the_last_resort_keeps_every_core_key(self, caplog):
        """Constructed: a budget only the core keys fit: every other key goes, the CVSS payloads and dates stay."""
        meta = self._small_record()
        core = {k: v for k, v in meta.items() if k in CORE_KEYS}
        assert {"published", "last_modified", "description", "status", "cvss_v31_data"} <= set(core)
        with caplog.at_level(logging.ERROR, logger=mw.logger.name):
            comment = mw._fit_nvd_meta(meta, budget=_size(core) + 2, ref="CVE-2024-3400")
        assert nvd_meta_of_comment(comment) == core
        assert any("[NVD_META]" in r.getMessage() and r.levelno == logging.ERROR for r in caplog.records)

    def test_the_cna_pairs_go_before_the_version_ranges(self):
        """Constructed: 20 pairs and 10 version ranges; once the references and the pairs are gone, the ranges go
        from the end, as few as make the comment fit."""
        meta = dict(
            _meta(_attribute(_nvd_item("CVE-2023-29492"), "601")),
            references=[{"url": "https://example.org/r"}],
            affected=[{"vendor": f"Vendor {i}", "product": "x" * 200} for i in range(20)],
            version_constraints=[
                {"cpe": f"cpe:2.3:a:example:product_{i}:*:*:*:*:*:*:*:*" + "x" * 80, "version_end": f"{i}.0"}
                for i in range(10)
            ],
        )
        budget = _size({k: v for k, v in meta.items() if k not in {"references", "affected"}}) - 400
        out = nvd_meta_of_comment(mw._fit_nvd_meta(meta, budget=budget, ref="CVE-2023-29492"))
        assert "references" not in out and "affected" not in out
        kept = out["version_constraints"]
        assert 0 < len(kept) < 10 and kept == meta["version_constraints"][: len(kept)]
        assert out["cwe_names"] == meta["cwe_names"] and out["description"] == meta["description"]

    def test_the_cwe_version_goes_with_the_last_cwe_name(self):
        """Constructed budget: the comment fits only without every CWE name; the version goes with them and the
        last resort does not run."""
        meta = {
            k: v
            for k, v in _meta(_attribute(_nvd_item("CVE-2022-46169"), "601")).items()
            if k not in {"references", "affected", "version_constraints"}
        }
        assert len(meta["cwe_names"]) == 3 and meta["cwe_names_version"]
        expected = {k: v for k, v in meta.items() if k not in {"cwe_names", "cwe_names_version"}}
        out = nvd_meta_of_comment(mw._fit_nvd_meta(meta, budget=_size(expected), ref="CVE-2022-46169"))
        assert out == expected

    def test_the_reference_drop_order_by_kind(self):
        assert mw._reference_drop_order(KINDS_OF_REFERENCES) == KINDS_DROP_ORDER

    @pytest.mark.parametrize("dropped", [1, 3, 5])
    def test_the_references_kept_by_kind(self, dropped):
        meta = dict(_meta(_attribute(_nvd_item("CVE-2023-29492"), "601")), references=KINDS_OF_REFERENCES)
        expected = [r for i, r in enumerate(KINDS_OF_REFERENCES) if i not in KINDS_DROP_ORDER[:dropped]]
        comment = mw._fit_nvd_meta(meta, budget=_size(dict(meta, references=expected)), ref="CVE-2023-29492")
        assert nvd_meta_of_comment(comment)["references"] == expected


# ------------------------------------------------------------------------------------------ the sync
class TestSyncReadsTheNewKeys:
    @pytest.mark.parametrize("cve_id", ["CVE-2024-3400", "CVE-2014-6271", "CVE-2023-28229"])
    def test_the_item_is_the_one_without_the_new_keys(self, cve_id, caplog):
        """The sync lifts none of the new keys yet: an attribute with them gives the item the same attribute
        without them gives, so the graph write is unchanged, and nothing is logged about the CVSS payloads."""
        attribute = _attribute(_nvd_item(cve_id), "601")
        meta = _meta(attribute)
        assert {"nvd_vuln_status", "references", "cvss_scorers", "cwe_names", "cwe_names_version"} <= set(meta)
        stripped = dict(
            attribute,
            comment="NVD_META:" + json.dumps({k: v for k, v in meta.items() if k not in NEW_KEYS}),
        )
        sync = MISPToNeo4jSync(neo4j_client=MagicMock())
        with caplog.at_level(logging.WARNING):
            item, _ = sync.parse_attribute(attribute, NVD_EVENT)
        assert not [r for r in caplog.records if "[META]" in r.getMessage()]
        bare, _ = sync.parse_attribute(stripped, NVD_EVENT)
        assert item == bare
        assert item["description"] == _nvd_text(cve_id) and item["cvss_v31_data"]["base_score"]

    def test_a_kev_attribute_with_the_new_keys(self):
        attribute = _attribute(_kev_item("CVE-2025-39682"), "602")
        meta = _meta(attribute)
        stripped = dict(
            attribute, comment="NVD_META:" + json.dumps({k: v for k, v in meta.items() if k not in NEW_KEYS})
        )
        sync = MISPToNeo4jSync(neo4j_client=MagicMock())
        item, _ = sync.parse_attribute(attribute, KEV_EVENT)
        bare, _ = sync.parse_attribute(stripped, KEV_EVENT)
        assert item == bare and item["cisa_exploit_add"] == KEV["CVE-2025-39682"]["dateAdded"]


# ------------------------------------------------------------------------------------------ the CWE list
class TestCweList:
    def test_the_shipped_list(self, builder):
        document = json.loads((REPO / "src" / "reference" / "cwe_names.json").read_text(encoding="utf-8"))
        assert document["version"] == cwe_names.list_version() == "5.0"
        assert document["cwe_release_date"] == "2026-10-28"
        notice = document["notices"]["cwe"]
        assert "Copyright © 2006–2026, The MITRE Corporation." in notice
        assert "reproduce MITRE’s copyright designation and this license in any such copy" in notice
        (source,) = document["inputs"]
        assert source["url"] == builder.SOURCE_URL and len(source["sha256"]) == 64
        names = document["names"]
        assert document["counts"]["names"] == len(names) == 1415
        assert list(names) == sorted(names, key=lambda k: int(k.split("-")[1]))
        assert names["CWE-264"] == "Permissions, Privileges, and Access Controls", "a former category NVD assigns"

    def test_every_cwe_id_of_the_recorded_records_has_a_name(self):
        ids = {
            d["value"]
            for record in NVD.values()
            for w in record["cve"].get("weaknesses", [])
            for d in w["description"]
            if d["value"].startswith("CWE-")
        } | {c for entry in KEV.values() for c in entry["cwes"]}
        assert ids and len(cwe_names.cwe_names(sorted(ids))) == len(ids)

    def test_ids_without_a_name(self):
        assert cwe_names.cwe_names(["NVD-CWE-noinfo", "NVD-CWE-Other", "CWE-089", "CWE-99999", 89, None]) == []
        assert cwe_names.cwe_names([" cwe-89 ", "CWE-89"]) == [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
        ]
        assert cwe_names.item_fields(["NVD-CWE-noinfo"]) == {}

    def test_an_unreadable_list_gives_no_names(self, monkeypatch, tmp_path, caplog):
        monkeypatch.setattr(cwe_names, "LIST_PATH", tmp_path / "missing.json")
        monkeypatch.setattr(cwe_names, "_loaded", None)
        with caplog.at_level(logging.WARNING, logger=cwe_names.logger.name):
            assert cwe_names.cwe_names(["CWE-20"]) == [] and cwe_names.list_version() == ""
        assert any("CWE name list" in r.getMessage() for r in caplog.records)
        meta = _meta(_attribute(_nvd_item("CVE-2024-3400"), "601"))
        assert "cwe_names" not in meta and "cwe_names_version" not in meta

    def test_the_builder_reads_weaknesses_and_groupings_only(self, builder):
        # Constructed XML in the CWE 5 schema's shape.
        xml = (
            '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8" Name="CWE" Version="9.9" Date="2030-01-01">'
            '<Weaknesses><Weakness ID="89" Name="SQL  name" Status="Stable"/>'
            '<Weakness ID="132" Name="DEPRECATED: Old" Status="Deprecated"/></Weaknesses>'
            '<Groupings><Grouping ID="264" Name="Permissions" Status="Obsolete"/></Groupings>'
            '<Views><View ID="1000" Name="Research Concepts"/></Views></Weakness_Catalog>'
        )
        out = builder.read_catalogue(xml.encode())
        assert out["version"] == "9.9" and out["date"] == "2030-01-01"
        assert out["names"] == {"CWE-89": "SQL name", "CWE-132": "DEPRECATED: Old", "CWE-264": "Permissions"}
        assert out["counts"] == {"Weakness": 2, "Grouping": 1, "names": 3}

    @pytest.mark.parametrize(
        "xml, message",
        [
            ('<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8" Name="CWE"/>', "no version"),
            ('<Other Name="CWE" Version="1"/>', "not a CWE list"),
            (
                '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8" Name="CWE" Version="1"><Weaknesses>'
                '<Weakness ID="1" Name="a"/></Weaknesses><Groupings><Grouping ID="1" Name="b"/></Groupings>'
                "</Weakness_Catalog>",
                "named twice",
            ),
        ],
    )
    def test_the_builder_refuses_a_list_it_cannot_trust(self, builder, xml, message):
        with pytest.raises(ValueError, match=message):
            builder.read_catalogue(xml.encode())
