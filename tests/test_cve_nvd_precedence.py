"""NVD's record before any other on a CVE's shared data (2026-10).

Two writes of ``merge_cve`` let the record merged last decide what a CVE shows, so the result depended
on the order of the events in the sync:

- **CVSS sub-nodes.** NVD and CISA ICS write the same ``CVSSv31`` / ``CVSSv30`` sub-node of a CVE (one per
  CVE and version). Each write set its whole payload, so the last one won, and the CISA ICS payload carried
  impact and exploitability sub-scores of 0.0 the advisory never gave (CSAF has none). On the hosted graph
  of 2026-10-16 the 2,681 shared CVSSv31 sub-nodes held NVD's values only because the sync processed NVD's
  events last; 1,114 CVSSv31 and 25 CVSSv30 sub-nodes CISA ICS alone asserted showed 0.0 / 0.0. Now a
  sub-node NVD has asserted (``'nvd'`` in ``sources`` of its ``HAS_CVSS_*`` edge) takes another feed's
  value only for a property it lacks, so the node holds NVD's payload in any order; a sub-node only
  another feed asserted is still updated by it. The sub-scores: ``test_cisa_ics_collector.py``.
- **List properties.** ``cwe``, ``ref_tags``, ``cpe_type``, ``result_impacts``, ``reference_urls`` and
  ``affected_products`` of any record were set over NVD's (a CISA ICS record: one advisory URL, product
  names, CISA's CWE). Now NVD's record sets them and any other record only fills a list the node does not
  have, as for the dates.

An NVD record without a CVSS version takes NVD out of ``sources`` of a sub-node CISA ICS also asserted, so
CISA ICS's next record sets its values again (``TestCvssVersionNvdWithdrew``), and the sync checks NVD_META's
CVSS payloads when it reads them, so a malformed payload is no CVSS write error (``TestMalformedCvssPayload``).

These tests check the statements; ``tests/test_cve_nvd_precedence_neo4j.py`` runs them on Neo4j.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import neo4j_client  # noqa: E402
from collectors.cisa_ics_collector import extract_cvss  # noqa: E402

LISTS = ("cwe", "ref_tags", "cpe_type", "result_impacts", "reference_urls", "affected_products")
MISP = json.loads((TESTS / "test_cvss_real_payloads.json").read_text())["misp"]

NVD_V31 = {
    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "scope": "UNCHANGED",
    "confidentiality_impact": "HIGH",
    "integrity_impact": "HIGH",
    "availability_impact": "HIGH",
    "base_score": 9.8,
    "base_severity": "CRITICAL",
    "impact_score": 5.9,
    "exploitability_score": 3.9,
}


def _recording_client():
    """A real Neo4jClient whose sessions record every statement (no database)."""
    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = MagicMock()
    session = MagicMock()
    client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return client, session


def _ics_v31() -> dict:
    """The CVSSv31 payload the CISA ICS collector builds from a CSAF ``cvss_v3`` block."""
    block = {
        "baseScore": 4.6,
        "baseSeverity": "MEDIUM",
        "vectorString": "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
        "version": "3.1",
    }
    return extract_cvss({"scores": [{"cvss_v3": block}]})["cvss_v31_data"]


class TestSharedCvssSubNode:
    def _write(self, tag: str, payload: dict):
        client, session = _recording_client()
        assert client._merge_cvss_node("CVE-2026-1000", tag, "CVSSv31", "HAS_CVSS_v31", payload) is True
        ((query,), params) = session.run.call_args
        return query, params

    def test_another_feed_only_fills_a_sub_node_nvd_asserted(self):
        query, params = self._write("cisa_ics", _ics_v31())
        assert params["feed"] == "cisa_ics"
        guard = re.search(
            r"WITH cve, n, \(\$feed <> 'nvd' AND EXISTS \{\s*MATCH \(cve\)-\[x:HAS_CVSS_v31\]->\(n\)\s*"
            r"WHERE 'nvd' IN coalesce\(x\.sources, \[n\.tag\]\)\s*\}\) AS nvd_owned",
            query,
        )
        assert guard, "no NVD guard: the CISA ICS payload replaces NVD's (the last writer wins)"
        written = [k for k in _ics_v31() if _ics_v31()[k] is not None]
        assert "base_score" in written and "vector_string" in written
        for prop in written:
            assert (
                f"n.{prop} = CASE WHEN nvd_owned THEN "
                f"CASE WHEN n.{prop} IS NULL OR n.{prop} = '' THEN ${prop} ELSE n.{prop} END ELSE ${prop} END"
            ) in query, prop
            assert re.search(rf"n\.{prop} = \${prop}\b", query) is None, f"{prop} is set unguarded"
        # The guard sits before the payload SET and after the MERGE's own SET clauses.
        assert query.index("AS nvd_owned") < query.index("n.base_score = CASE")
        assert query.index("ON MATCH SET") < query.index("AS nvd_owned")
        # Provenance is unchanged: the edge still names every feed that asserted the score.
        assert "r1.sources = " in query and "r2.sources = " in query

    def test_nvd_payload_is_never_held_back(self):
        """NVD's write passes ``$feed = 'nvd'``, which makes ``nvd_owned`` false: NVD sets its payload."""
        query, params = self._write("nvd", NVD_V31)
        assert params["feed"] == "nvd"
        assert "($feed <> 'nvd' AND EXISTS" in query
        assert {k: params[k] for k in NVD_V31} == NVD_V31

    def test_a_missing_sub_score_is_not_written(self):
        query, params = self._write("cisa_ics", _ics_v31())
        for prop in ("impact_score", "exploitability_score"):
            assert prop not in params and f"n.{prop}" not in query, prop


def _merge_cve_props(record: dict, source_id: str):
    """``extra_props`` (set) and ``fill_props`` (set only where the node has none) of ``merge_cve``."""
    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = MagicMock()
    with patch.object(client, "merge_node_with_source", return_value=False) as merge:
        client.merge_cve(record, source_id=source_id)
    kwargs = merge.call_args.kwargs
    return kwargs["extra_props"] or {}, kwargs["fill_props"] or {}


def _synced(key: str) -> dict:
    from test_cve_description_source import synced_key

    return synced_key(key)


class TestCveListProperties:
    def test_a_cisa_ics_record_only_fills_the_lists(self):
        # Real hosted MISP attribute (CVE-2025-7223, CISA ICS advisory ICSA-25-238-01), read by the sync.
        ics = _synced("CVE-2025-7223__source:CISA-ICS")
        assert ics["tag"] == "cisa_ics" and not ics.get("nvd_record")
        extra, fill = _merge_cve_props(ics, "cisa_ics")
        for prop in ("cwe", "result_impacts", "reference_urls", "affected_products"):
            assert prop not in extra, f"{prop}: the advisory's list replaces NVD's"
            assert fill[prop] == ics[prop], prop

    def test_the_nvd_record_sets_the_lists(self):
        nvd = _synced("CVE-2025-7223__source:NVD")
        assert nvd["nvd_record"] is True
        extra, fill = _merge_cve_props(nvd, "nvd")
        for prop in LISTS:
            assert extra[prop] == nvd[prop], prop
            assert prop not in fill, prop

    @pytest.mark.parametrize("source_id", ["cisa_kev", "alienvault_otx", "misp"])
    def test_any_other_record_only_fills_the_lists(self, source_id):
        record = {"cve_id": "CVE-2026-1000", "tag": source_id, "cwe": ["CWE-79"], "reference_urls": ["https://x.test"]}
        extra, fill = _merge_cve_props(record, source_id)
        assert "cwe" not in extra and "reference_urls" not in extra
        assert fill["cwe"] == ["CWE-79"] and fill["reference_urls"] == ["https://x.test"]

    def test_an_nvd_record_without_the_flag_still_sets_the_lists(self):
        """An item of the NVD source without ``nvd_record`` (a test fixture or a direct caller) is NVD's
        record; in production the lists come only with ``NVD_META``, which sets the flag."""
        extra, fill = _merge_cve_props({"cve_id": "CVE-2026-1000", "tag": "nvd", "cwe": ["CWE-79"]}, "nvd")
        assert extra["cwe"] == ["CWE-79"] and "cwe" not in fill


class TestCvssVersionNvdWithdrew:
    """An NVD record without a CVSS version takes NVD out of the sub-node another feed also asserted
    (2026-10). Until then ``'nvd'`` stayed in ``sources`` of its ``HAS_CVSS_*`` edges, so the sub-node
    counted as NVD's for good: the other feed's records only filled it, and NVD's withdrawn payload kept
    scoring the CVE, while a rebuild from the same records gives the other feed's payload."""

    def _statement(self, record: dict):
        client, session = _recording_client()
        assert client._replace_nvd_owned_cve_data("CVE-2026-1000", record) is True
        ((query,), params) = session.run.call_args
        return query, params

    def test_nvd_leaves_the_sources_and_events_of_a_shared_sub_node(self):
        query, params = self._statement({"nvd_record": True, "misp_event_id": "120", "cvss_v40_data": {"x": 1}})
        assert params["absent_rel_types"] == ["HAS_CVSS_v31", "HAS_CVSS_v30", "HAS_CVSS_v2"]
        assert params["nvd_event_id"] == "120"
        release = re.search(
            r"WITH DISTINCT c\s+OPTIONAL MATCH \(c\)-\[r:HAS_CVSS_v40\|HAS_CVSS_v31\|HAS_CVSS_v30\|HAS_CVSS_v2\]-\(s\)\s+"
            r"WHERE type\(r\) IN \$absent_rel_types AND s\.cve_id = \$cve_id\s+"
            r"AND 'nvd' IN r\.sources AND any\(feed IN r\.sources WHERE feed <> 'nvd'\)\s+"
            r"SET r\.sources = \[feed IN r\.sources WHERE feed <> 'nvd'\],\s+"
            r"r\.misp_event_ids = \[event IN r\.misp_event_ids WHERE event <> \$nvd_event_id\]",
            query,
        )
        assert release, "NVD stays in the sources of a sub-node another feed asserted"
        # The release runs after the removal of the sub-nodes only NVD asserted, which it never touches.
        assert query.index("DETACH DELETE s") < query.index("WITH DISTINCT c")

    def test_a_record_without_an_event_keeps_every_event(self):
        """No MISP event id: ``event <> ''`` keeps every event (``event <> null`` would drop them all)."""
        _, params = self._statement({"nvd_record": True})
        assert params["nvd_event_id"] == ""


class TestMalformedCvssPayload:
    """A CVSS payload of ``NVD_META`` is checked when the sync reads the attribute (2026-10): one that is not
    a JSON object counts as absent, and an entry that is not a property a CVSS sub-node can hold is dropped,
    each with a WARNING naming the CVE. Without the check, ``_merge_cvss_node`` failed on such a payload, and
    since ``merge_cve`` counts a failed CVSS sub-write as an error, one attribute failed every sync until its
    MISP comment was edited (the sync: ``test_neo4j_write_results.py``)."""

    KEY = "CVE-2025-7223__source:NVD"  # real hosted attribute; NVD gives CVSS 3.0 only

    def _real_v30(self) -> dict:
        from test_cve_description_source import attribute

        return json.loads(attribute(self.KEY)["comment"][len("NVD_META:") :])["cvss_v30_data"]

    def _read(self, caplog, **changes):
        from test_cve_description_source import _with_comment_meta, attribute, synced

        with caplog.at_level(logging.WARNING, logger="run_misp_to_neo4j"):
            item = synced(_with_comment_meta(attribute(self.KEY), **changes))
        return item, [r.getMessage() for r in caplog.records if "[META] NVD_META.cvss" in r.getMessage()]

    def test_the_collectors_payload_passes_unchanged(self, caplog):
        item, warnings = self._read(caplog)
        assert item["cvss_v30_data"] == self._real_v30() and item["cvss_v31_data"] is None
        assert warnings == []

    @pytest.mark.parametrize("value", ["CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", ["7.8"], 7.8])
    def test_a_payload_that_is_not_an_object_counts_as_absent(self, caplog, value):
        item, warnings = self._read(caplog, cvss_v30_data=value)
        assert item["cvss_v30_data"] is None
        assert item["nvd_record"] is True, "still NVD's record: the version counts as absent"
        assert (item["cvss_score"], item["cvss_version"]) == (None, None)
        (line,) = warnings
        assert f"NVD_META.cvss_v30_data of CVE-2025-7223 is a JSON {type(value).__name__}" in line

    def test_entries_that_are_not_properties_are_dropped(self, caplog):
        payload = {
            **self._real_v30(),
            "base_score": {"value": 7.8},  # a map: Neo4j stores no map as a property
            "bad key": "x",  # not a property name: the writer's injection guard refuses it
            "refs": ["a"],  # no CVSS property is a list
            "big": 2**64,  # beyond Neo4j's integer range
            "uuid": "attacker-chosen",  # the sub-node's identity, which the writer sets
            "timeout": 1,  # an argument of ``session.run``: the write failed with a TypeError
        }
        item, warnings = self._read(caplog, cvss_v30_data=payload)
        expected = {k: v for k, v in self._real_v30().items() if k != "base_score"}
        assert item["cvss_v30_data"] == expected
        (line,) = warnings
        assert line.endswith(
            "of CVE-2025-7223: entries that are not CVSS properties dropped: "
            "bad key, base_score, big, refs, timeout, uuid"
        )

    def test_a_payload_is_written_as_checked(self):
        """What remains is what ``_merge_cvss_node`` writes, and it writes it: an entry the check drops failed
        the write (the injection guard, a ``timeout`` argument given twice) or replaced the sub-node's uuid."""
        from test_cve_description_source import _with_comment_meta, attribute, synced

        payload = {**self._real_v30(), "bad key": "x", "timeout": 1, "uuid": "attacker-chosen"}
        item = synced(_with_comment_meta(attribute(self.KEY), cvss_v30_data=payload))
        client, session = _recording_client()
        assert client._merge_cvss_node("CVE-2025-7223", "nvd", "CVSSv30", "HAS_CVSS_v30", item["cvss_v30_data"])
        ((query,), params) = session.run.call_args
        assert params["cvss_uuid"] == neo4j_client.compute_node_uuid("CVSSv30", {"cve_id": "CVE-2025-7223"})
        assert "n.uuid = CASE" not in query and "uuid" not in item["cvss_v30_data"]
