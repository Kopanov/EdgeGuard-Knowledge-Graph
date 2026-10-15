"""A CVE's description and dates come from NVD's record (2026-10).

``merge_cve`` wrote ``description``, ``published`` and ``last_modified`` from whatever record was merged
last. An OTX pulse indicator of type CVE reaches MISP with an ``OTX_META`` comment, and the sync took the
raw comment as the description, so the CVE showed ``OTX_META:{"attack_ids": [...], ...}``; an OTX pulse
reference stored "Referenced in OTX pulse: <name>", a KEV record CISA's short description and a CISA
ICS record the advisory's dates. Which one a CVE showed depended on the order of the events in the sync
(smallest first), and the CVEs several feeds name are the ones a demonstration shows.

The rule now: NVD's record (``nvd_record``, set by the sync for an NVD attribute with ``NVD_META``) sets
the three properties; any other record fills them only where the node has none; a comment that is a
metadata block never becomes a description (``run_misp_to_neo4j._comment_description``), and neither
does a vulnerability comment that only says where the CVE was seen: the OTX pulse reference and
MISPWriter's "CVE from <source>" placeholder (``_vulnerability_comment_description``). Taken as one, the
pulse reference was the first text to reach a CVE without an NVD record, and CISA's KEV text could
then never replace it.

Fixtures are real: the ``misp`` attributes of ``test_cvss_real_payloads.json`` (hosted MISP, read on
2026-10-14) — CVE-2025-21042 from OTX, NVD and the KEV, CVE-2015-5477 from OTX and the KEV (outside the
NVD window), CVE-2025-14272 and CVE-2025-7223 from NVD and CISA ICS. The OTX pulse reference and the
``MITRE_*`` blocks are written by the OTX collector and MISPWriter's own builders; the remaining blocks
without a real attribute (``MITRE_TACTIC_PHASES`` without a description, ``CURATED_CLAIMS``, an unknown
``*_META``) are literals of the same shape. The same rule on a real Neo4j:
``tests/test_cve_epss_ssvc_neo4j.py``.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from test_cve_attack_vector import _otx_cve_item  # noqa: E402  (the OTX collector's cve_references item)

import neo4j_client  # noqa: E402
from collectors import misp_writer  # noqa: E402
from run_misp_to_neo4j import (  # noqa: E402
    _METADATA_COMMENT_RE,
    MISPToNeo4jSync,
    _comment_description,
    _vulnerability_comment_description,
)

MISP = json.loads((Path(__file__).resolve().parent / "test_cvss_real_payloads.json").read_text())["misp"]
RECORD_TEXT = ("description", "published", "last_modified")
WRITER = misp_writer.MISPWriter.__new__(misp_writer.MISPWriter)

# An OTX malware family and an ATT&CK technique as MISPWriter writes them: the ``MITRE_*`` block, then the
# entity's description on the next line when it has one.
OTX_MALWARE = {
    "name": "Mirai",
    "malware_types": ["unknown"],
    "family": "Mirai",
    "zone": ["global"],
    "tag": "alienvault_otx",
    "reported_techniques": ["T1059"],
    "pulse_id": "6ac84a155bb626a3710179b9",
}
MITRE_TECHNIQUE = {
    "mitre_id": "T1059",
    "name": "Command and Scripting Interpreter",
    "tactic_phases": ["execution"],
    "zone": ["global"],
    "tag": "mitre_attck",
}


def attribute(key: str) -> dict:
    return copy.deepcopy(MISP[key])


def otx_pulse_reference(description: str | None = None) -> dict:
    """The MISP attribute MISPWriter writes for the OTX collector's ``cve_references`` item (CVE-2015-5477
    in pulse "BIND TKEY exploitation"); *description* replaces the item's text when given."""
    item = _otx_cve_item()
    if description is not None:
        item["description"] = description
    return WRITER.create_vulnerability_attribute(item)


def synced(attr: dict) -> dict:
    """*attr* read by the sync, as a full or incremental run reads it."""
    event = {"id": attr.get("event_id"), "info": (attr.get("_event") or {}).get("info", ""), "Tag": []}
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(
        {k: v for k, v in attr.items() if k != "_event"}, event
    )
    assert item is not None
    return item


def synced_key(key: str) -> dict:
    return synced(attribute(key))


def _with_comment_meta(attr: dict, **changes) -> dict:
    """*attr* with keys of its comment's JSON block changed (``None`` removes a key)."""
    prefix, _, payload = attr["comment"].partition(":")
    meta = json.loads(payload)
    for key, value in changes.items():
        if value is None:
            meta.pop(key, None)
        else:
            meta[key] = value
    attr["comment"] = f"{prefix}:{json.dumps(meta)}"
    return attr


def _recording_client():
    """A real Neo4jClient whose driver records every statement (no database)."""
    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = MagicMock()
    client._uri = "bolt://localhost:7687"
    session = MagicMock()
    session.run.return_value.single.return_value = None
    client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return client, session


def _node_statement(session, label: str):
    """The node MERGE statement of the last ``merge_node_with_source`` call and its parameters."""
    calls = [c for c in session.run.call_args_list if c.args and f"MERGE (n:{label} {{cve_id: $cve_id}})" in c.args[0]]
    assert calls, f"no {label} MERGE statement"
    return calls[-1].args[0], calls[-1].kwargs


_SET = re.compile(r"n\.(description|published|last_modified) = \$(\w+)")
_FILL = re.compile(
    r"n\.(description|published|last_modified) = "
    r"CASE WHEN n\.\1 IS NULL OR n\.\1 = '' THEN \$(\w+) ELSE n\.\1 END"
)


def _apply(node: dict, query: str, params: dict) -> None:
    """What the statement does to the three properties of *node*: a plain SET replaces, the
    set-if-absent CASE fills an absent or empty value. Any other form of assignment fails the test."""
    assigned = re.findall(r"n\.(description|published|last_modified) = (?!'')", query)  # not the IS-empty test
    plain, fill = _SET.findall(query), _FILL.findall(query)
    assert sorted(assigned) == sorted([p for p, _ in plain] + [p for p, _ in fill]), query
    for prop, param in plain:
        node[prop] = params[param]
    for prop, param in fill:
        if node.get(prop) in (None, ""):
            node[prop] = params[param]


def _merged(*keys: str) -> dict:
    """The CVE node's three properties after ``merge_cve`` of the synced attributes, in order."""
    return _merged_items(*(synced_key(key) for key in keys))


def _merged_items(*items: dict) -> dict:
    """The CVE node's three properties after ``merge_cve`` of the synced items, in order."""
    client, session = _recording_client()
    node: dict = {}
    for item in items:
        assert client.merge_cve(item, source_id=item["tag"])
        _apply(node, *_node_statement(session, "CVE"))
    return node


def _record_text(item: dict) -> dict:
    return {prop: item[prop] for prop in RECORD_TEXT if item.get(prop)}


# ---------------------------------------------------------------- the sync never stores a block
class TestCommentDescription:
    def test_a_plain_comment_is_the_description(self):
        # MISPWriter's comment for a vulnerability item without NVD_META that names a vendor and product.
        plain = "Vendor: ISC | Product: BIND | named in ISC BIND allows remote attackers to cause a denial of service."
        assert _comment_description(plain) == plain
        assert _vulnerability_comment_description(plain) == plain
        assert _comment_description("") is None and _comment_description(None) is None

    @pytest.mark.parametrize(
        "comment",
        [
            attribute("CVE-2015-5477__source:AlienVault-OTX")["comment"],  # real, "description": ""
            misp_writer._fit_meta_comment("TF_META:", {"malware_family": "Mirai", "threat_type": "botnet_cc"}),
            WRITER.create_malware_attribute(dict(OTX_MALWARE, description=""))["comment"],
            WRITER.create_technique_attribute(dict(MITRE_TECHNIQUE, description=""))["comment"],
            'CURATED_CLAIMS:{"c": [{"p": "exploits", "o": "CVE-2015-5477"}]}',
            'FUTURE_FEED_META:{"pulse_name": "x"}',
            attribute("CVE-2015-5477__source:CISA-KEV")["comment"][:120],  # NVD_META cut mid-JSON
            "OTX_META:not json",
        ],
        ids=[
            "otx_real",
            "tf_meta",
            "mitre_uses",
            "mitre_phases",
            "curated",
            "other_meta",
            "nvd_meta_cut",
            "unreadable",
        ],
    )
    def test_a_metadata_block_without_its_own_description_gives_none(self, comment):
        assert _METADATA_COMMENT_RE.match(comment)
        assert _comment_description(comment) is None

    def test_a_block_gives_its_own_description_field(self):
        otx = _with_comment_meta(attribute("CVE-2015-5477__source:AlienVault-OTX"), description="Exploited by FishHub")
        assert _comment_description(otx["comment"]) == "Exploited by FishHub"

    @pytest.mark.parametrize(
        ("comment", "description"),
        [
            (
                WRITER.create_malware_attribute(dict(OTX_MALWARE, description="Mirai botnet C2 servers"))["comment"],
                "Mirai botnet C2 servers",
            ),
            (
                WRITER.create_technique_attribute(
                    dict(MITRE_TECHNIQUE, description="Adversaries may abuse command and script interpreters")
                )["comment"],
                "Adversaries may abuse command and script interpreters",
            ),
        ],
        ids=["mitre_uses", "mitre_phases"],
    )
    def test_a_mitre_block_gives_the_description_written_after_it(self, comment, description):
        # MISPWriter writes the entity's description on the line after the block's JSON; the block
        # itself is never part of it.
        assert _METADATA_COMMENT_RE.match(comment) and comment.endswith("\n" + description)
        assert _comment_description(comment) == description


class TestProvenanceNotes:
    """A vulnerability comment that only says where the CVE was seen is no description."""

    def test_the_otx_pulse_reference_and_the_placeholder_as_written(self):
        assert otx_pulse_reference()["comment"] == "Referenced in OTX pulse: BIND TKEY exploitation"
        assert otx_pulse_reference(description="")["comment"] == "CVE from alienvault_otx"

    @pytest.mark.parametrize("description", [None, ""], ids=["pulse_reference", "placeholder"])
    def test_neither_becomes_a_description(self, description):
        attr = otx_pulse_reference(description)
        assert _comment_description(attr["comment"]) == attr["comment"], "the generic helper keeps plain text"
        assert _vulnerability_comment_description(attr["comment"]) is None
        item = synced(attr)
        assert item["cve_id"] == "CVE-2015-5477" and item["tag"] == "alienvault_otx"
        assert item["description"] is None and not item["nvd_record"]

    def test_a_cut_pulse_name_is_still_the_note(self):
        attr = otx_pulse_reference("Referenced in OTX pulse: " + "x" * 300)
        assert attr["comment"].endswith("...")  # MISPWriter cuts the item's text at 200 characters
        assert synced(attr)["description"] is None

    @pytest.mark.parametrize("first", ["pulse_reference", "kev"])
    def test_cisa_kev_text_fills_a_cve_an_otx_pulse_named_first(self, first):
        # CVE-2015-5477 on the hosted MISP: only OTX and KEV attributes, no NVD record. Before, the pulse
        # reference merged first stayed, and the KEV text could never replace it.
        reference, kev = synced(otx_pulse_reference()), synced_key("CVE-2015-5477__source:CISA-KEV")
        order = (reference, kev) if first == "pulse_reference" else (kev, reference)
        assert _merged_items(*order) == {"description": kev["description"]}

    def test_the_stix_vulnerability_carries_neither(self):
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        for description in (None, ""):
            attr = otx_pulse_reference(description)
            attr["uuid"] = "6f1f2d0e-0000-4000-8000-000000000001"
            obj = syncer._attribute_to_stix21(attr, "00000000-0000-4000-8000-000000000000", ["global"])
            assert obj["type"] == "vulnerability" and "description" not in obj


class TestSyncedDescription:
    @pytest.mark.parametrize("key", sorted(MISP))
    def test_no_real_attribute_gives_a_metadata_block_as_description(self, key):
        description = synced_key(key)["description"]
        assert description is None or not _METADATA_COMMENT_RE.match(description), description[:80]

    @pytest.mark.parametrize("key", ["CVE-2015-5477__source:AlienVault-OTX", "CVE-2025-21042__source:AlienVault-OTX"])
    def test_an_otx_pulse_indicator_gives_no_description(self, key):
        # Before 2026-10 both CVEs got their ``OTX_META:{...}`` JSON as the description.
        item = synced_key(key)
        assert item["description"] is None
        assert not item["nvd_record"]

    def test_an_otx_block_with_a_description_gives_it(self):
        otx = _with_comment_meta(attribute("CVE-2025-21042__source:AlienVault-OTX"), description="Samsung RCE")
        assert synced(otx)["description"] == "Samsung RCE"

    def test_nvd_meta_without_a_description_or_unreadable_gives_none(self):
        no_description = _with_comment_meta(attribute("CVE-2025-21042__source:NVD"), description=None)
        assert synced(no_description)["description"] is None
        cut = attribute("CVE-2025-21042__source:NVD")
        cut["comment"] = cut["comment"][:200]
        assert synced(cut)["description"] is None

    def test_record_text_of_each_source(self):
        nvd = synced_key("CVE-2025-21042__source:NVD")
        assert nvd["nvd_record"] is True
        assert nvd["description"].startswith("Out-of-bounds write in libimagecodec.quram.so")
        kev = synced_key("CVE-2025-21042__source:CISA-KEV")
        assert kev["nvd_record"] is False
        assert kev["description"].startswith("Samsung mobile devices contain an out-of-bounds write")
        ics = synced_key("CVE-2025-14272__source:CISA-ICS")
        assert ics["nvd_record"] is False
        assert (ics["published"], ics["last_modified"]) == ("2026-06-16T06:00:00+00:00", "2026-06-16T06:00:00+00:00")

    def test_the_stix_vulnerability_never_carries_a_block(self):
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())

        def sdo(key: str) -> dict:
            attr = {k: v for k, v in attribute(key).items() if k != "_event"}
            obj = syncer._attribute_to_stix21(attr, "00000000-0000-4000-8000-000000000000", ["global"])
            assert obj["type"] == "vulnerability"
            return obj

        assert "description" not in sdo("CVE-2015-5477__source:AlienVault-OTX")
        assert (
            sdo("CVE-2025-21042__source:NVD")["description"] == synced_key("CVE-2025-21042__source:NVD")["description"]
        )


# ---------------------------------------------------------------- merge_cve: NVD sets, others fill
class TestMergeCveStatements:
    def test_nvd_record_sets_the_three_properties(self):
        client, session = _recording_client()
        nvd = synced_key("CVE-2025-21042__source:NVD")
        client.merge_cve(nvd, source_id="nvd")
        query, params = _node_statement(session, "CVE")
        for prop in RECORD_TEXT:
            assert f"n.{prop} = ${prop}" in query
            assert params[prop] == nvd[prop]
        assert "$fill_" not in query

    @pytest.mark.parametrize(
        "key", ["CVE-2025-21042__source:CISA-KEV", "CVE-2025-14272__source:CISA-ICS", "CVE-2025-7223__source:CISA-ICS"]
    )
    def test_another_record_only_fills(self, key):
        client, session = _recording_client()
        item = synced_key(key)
        client.merge_cve(item, source_id=item["tag"])
        query, params = _node_statement(session, "CVE")
        for prop, value in _record_text(item).items():
            assert (
                f"n.{prop} = CASE WHEN n.{prop} IS NULL OR n.{prop} = '' THEN $fill_{prop} ELSE n.{prop} END" in query
            )
            assert params[f"fill_{prop}"] == value
            assert f"n.{prop} = ${prop}" not in query

    def test_an_otx_pulse_indicator_writes_none_of_them(self):
        client, session = _recording_client()
        client.merge_cve(synced_key("CVE-2015-5477__source:AlienVault-OTX"), source_id="alienvault_otx")
        query, _params = _node_statement(session, "CVE")
        assert not re.search(r"n\.(description|published|last_modified) =", query)


class TestMergeOrder:
    """The node after the records of one CVE in each order the sync can merge them."""

    NVD_21042 = "CVE-2025-21042__source:NVD"

    @pytest.mark.parametrize(
        "order",
        [
            ("NVD", "AlienVault-OTX", "CISA-KEV"),  # NVD then OTX; KEV after NVD
            ("AlienVault-OTX", "CISA-KEV", "NVD"),  # OTX then NVD
            ("CISA-KEV", "NVD", "AlienVault-OTX"),
        ],
    )
    def test_nvd_text_wins_in_any_order(self, order):
        node = _merged(*(f"CVE-2025-21042__source:{source}" for source in order))
        assert node == _record_text(synced_key(self.NVD_21042))

    @pytest.mark.parametrize("cve_id", ["CVE-2025-14272", "CVE-2025-7223"])
    def test_ics_dates_fill_and_nvd_replaces_them(self, cve_id):
        nvd, ics = synced_key(f"{cve_id}__source:NVD"), synced_key(f"{cve_id}__source:CISA-ICS")
        assert (ics["published"], ics["last_modified"]) != (nvd["published"], nvd["last_modified"])
        assert _merged(f"{cve_id}__source:CISA-ICS") == _record_text(ics), "alone, ICS fills the node"
        for order in (
            (f"{cve_id}__source:CISA-ICS", f"{cve_id}__source:NVD"),
            (f"{cve_id}__source:NVD", f"{cve_id}__source:CISA-ICS"),
        ):
            assert _merged(*order) == _record_text(nvd), order

    @pytest.mark.parametrize(
        "order",
        [
            ("CVE-2015-5477__source:AlienVault-OTX", "CVE-2015-5477__source:CISA-KEV"),
            ("CVE-2015-5477__source:CISA-KEV", "CVE-2015-5477__source:AlienVault-OTX"),
        ],
    )
    def test_without_an_nvd_record_the_kev_text_fills_and_otx_adds_nothing(self, order):
        node = _merged(*order)
        assert node == {"description": synced_key("CVE-2015-5477__source:CISA-KEV")["description"]}

    def test_an_empty_stored_description_counts_as_absent(self):
        node = {"description": ""}
        client, session = _recording_client()
        kev = synced_key("CVE-2015-5477__source:CISA-KEV")
        client.merge_cve(kev, source_id="cisa_kev")
        _apply(node, *_node_statement(session, "CVE"))
        assert node["description"] == kev["description"]


# ---------------------------------------------------------------- the other write paths
class TestOtherWritePaths:
    def test_merge_vulnerability_follows_the_same_rule(self):
        client, session = _recording_client()
        node: dict = {}
        for key in ("CVE-2025-21042__source:NVD", "CVE-2025-21042__source:CISA-KEV"):
            item = synced_key(key)
            assert client.merge_vulnerability(item, source_id=item["tag"])
            _apply(node, *_node_statement(session, "Vulnerability"))
        assert node == _record_text(synced_key("CVE-2025-21042__source:NVD"))

    def test_merge_node_with_source_sets_a_property_in_both_dicts_once(self):
        client, session = _recording_client()
        client.merge_node_with_source(
            "CVE",
            {"cve_id": "CVE-2025-21042"},
            {"cve_id": "CVE-2025-21042"},
            "nvd",
            extra_props={"description": "NVD"},
            fill_props={"description": "other", "published": "", "last_modified": None},
        )
        query, params = _node_statement(session, "CVE")
        assert query.count("n.description =") == 1 and "n.description = $description" in query
        assert "n.published" not in query and "n.last_modified" not in query
        assert not [p for p in params if p.startswith("fill_")]

    def test_batch_rows_from_nvd_set_and_other_rows_fill(self):
        client, session = _recording_client()
        nvd, kev = synced_key("CVE-2025-21042__source:NVD"), synced_key("CVE-2025-21042__source:CISA-KEV")
        client.merge_vulnerabilities_batch([nvd], source_id="nvd")
        client.merge_vulnerabilities_batch([kev], source_id="cisa_kev")
        batch_calls = [c for c in session.run.call_args_list if c.args and "UNWIND $batch as item" in c.args[0]]
        assert len(batch_calls) == 2
        query = batch_calls[0].args[0]
        for prop in RECORD_TEXT:
            assert (
                f"n.{prop} = CASE WHEN item.nvd_record THEN coalesce(item.{prop}, n.{prop}) "
                f"ELSE CASE WHEN n.{prop} IS NULL OR n.{prop} = '' THEN item.{prop} ELSE n.{prop} END END"
            ) in query
            assert f"n.{prop} = coalesce(item.{prop}, n.{prop})" not in query
        rows = [c.kwargs["batch"][0] for c in batch_calls]
        assert [row["nvd_record"] for row in rows] == [True, False]
        assert rows[0]["description"] == nvd["description"] and rows[1]["description"] == kev["description"]

    @pytest.mark.parametrize("method", ["merge_resilmesh_cve", "merge_resilmesh_vulnerability"])
    def test_resilmesh_native_writes_only_fill(self, method):
        client, session = _recording_client()
        assert getattr(client, method)({"cve_id": "CVE-2025-21042", "name": "x", "status": ["active"]})
        query = session.run.call_args_list[-1].args[0]
        var = "c" if method == "merge_resilmesh_cve" else "v"
        props = RECORD_TEXT if method == "merge_resilmesh_cve" else ("description",)
        for prop in props:
            assert (
                f"{var}.{prop} = CASE WHEN {var}.{prop} IS NULL OR {var}.{prop} = '' THEN ${prop} ELSE {var}.{prop} END"
            ) in query
            # A call without the property used to remove NVD's value (SET to null).
            assert f"{var}.{prop} = ${prop}" not in query

    @pytest.mark.parametrize(
        ("method", "props"),
        [
            ("merge_resilmesh_cve", ("cpe_type", "result_impacts", "ref_tags", "cwe")),
            ("merge_resilmesh_vulnerability", ("status",)),
        ],
    )
    def test_resilmesh_native_writes_keep_what_the_call_omits(self, method, props):
        # A call without NVD's lists (or a Vulnerability's status) used to SET them to null.
        client, session = _recording_client()
        assert getattr(client, method)({"cve_id": "CVE-2025-21042"})
        query, params = session.run.call_args_list[-1].args[0], session.run.call_args_list[-1].kwargs
        var = "c" if method == "merge_resilmesh_cve" else "v"
        for prop in props:
            assert f"{var}.{prop} = coalesce(${prop}, {var}.{prop})" in query
            assert f"{var}.{prop} = ${prop}" not in query
            assert params[prop] is None


# ---------------------------------------------------------------- the opt-in STIX flow
class TestStixImport:
    """``run_pipeline.load_stix21_to_neo4j`` (MISP → STIX → Neo4j, ``--stix-flow``): the vulnerability SDO
    carries no NVD record, so every CVE it names, NVD's included, only fills the description."""

    def test_an_nvd_sdo_only_fills_the_description(self):
        from run_pipeline import EdgeGuardPipeline

        client, session = _recording_client()
        pipeline = EdgeGuardPipeline()
        pipeline.neo4j = client
        attr = {k: v for k, v in attribute("CVE-2025-21042__source:NVD").items() if k != "_event"}
        sdo = MISPToNeo4jSync(neo4j_client=MagicMock())._attribute_to_stix21(
            attr, "00000000-0000-4000-8000-000000000000", ["global"]
        )
        sdo["x_edgeguard_source"] = "nvd"  # as the STIX flow stamps the objects of an NVD event
        with patch.object(client, "merge_cve", wraps=client.merge_cve) as merge_cve:
            pipeline.load_stix21_to_neo4j({"type": "bundle", "objects": [sdo]})
        ((data,), kwargs) = merge_cve.call_args
        assert kwargs["source_id"] == "nvd"
        assert data["description"] == synced_key("CVE-2025-21042__source:NVD")["description"]
        assert not data.get("nvd_record")
        query, params = _node_statement(session, "CVE")
        assert (
            "n.description = CASE WHEN n.description IS NULL OR n.description = '' "
            "THEN $fill_description ELSE n.description END"
        ) in query
        assert "n.description = $description" not in query
        assert params["fill_description"] == data["description"]
