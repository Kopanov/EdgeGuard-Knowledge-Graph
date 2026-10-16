"""2026-10 aging logic check (how the updates and the aging of the weights work).

Two fixes:
1. Aging and reactivation. Since 2026-10-16 one rule ages every Indicator, whoever supplied it
   (``indicator_aging``): every Indicator write records its report forward only and splices the
   single definition of the rule, so a newer report reactivates a decay-retired node in the same
   write and a re-sync of unchanged data changes nothing; a manual decommission (``retired_at``
   without the ``'decay'`` tag) wins. No other label ages: ``active = true`` on create only, no
   ``active`` / ``retired_*`` / decay property on MATCH. (Before 2026-10-16 every node write
   reactivated a decay-retired node and restored its confidence, so a full sync undid the decay.)
2. The sync's edge SET never lowers an edge: ``match_type`` follows the stronger evidence and
   ``confidence_score`` keeps the maximum (the TLP ladder rule, applied to edges).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import indicator_aging as ia  # noqa: E402
import neo4j_client as nc  # noqa: E402
from enrichment_jobs import _ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY as _STRATEGY  # noqa: E402

_CLIENT_SRC = (_SRC / "neo4j_client.py").read_text()
_ENRICH_SRC = (_SRC / "enrichment_jobs.py").read_text()

_LIFECYCLE_PROPS = ("active", "retired_at", "retired_by", "last_decayed", "aging_", "source_confidence")


def _client():
    client = nc.Neo4jClient.__new__(nc.Neo4jClient)
    client.driver = MagicMock()
    client._connection_healthy = True
    session = MagicMock()
    session.run.return_value.single.return_value = None
    client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return client, session


def _cyphers(session):
    return "\n".join(c.args[0] for c in session.run.call_args_list if c.args)


def _node_merge(session, label):
    return next(c.args[0] for c in session.run.call_args_list if c.args and f"MERGE (n:{label} " in c.args[0])


def _assert_rule_in_its_own_clause(query: str, var: str, recorded: tuple) -> None:
    """2026-10-16: the aging map is applied once, in a ``SET`` clause of its own that follows the
    ``SET`` clause recording ``recorded`` (``source_confidence`` and, on a report, the report items).
    A clause reads the node as the previous clause left it; items of one clause would depend on the
    order in which Neo4j applies them."""
    clause = ia.aging_set_clause(var, ia.WRITE_AS_OF)
    assert clause == f"SET {ia.aging_set_item(var, ia.WRITE_AS_OF)}"
    assert query.count(ia.aging_set_item(var, ia.WRITE_AS_OF)) == 1, "the rule is applied once"
    start = query.index(clause)
    line_start = query.rfind("\n", 0, start) + 1
    assert not query[line_start:start].strip(), "the aging clause begins its own line"
    lines = [ln.strip() for ln in query[:line_start].splitlines()]
    code = [ln for ln in lines if ln and not ln.startswith("//")]
    assert not code[-1].endswith(","), "the clause before it is complete: the rule is no item of it"
    head = max(i for i, ln in enumerate(code) if ln.startswith("SET "))
    previous = "\n".join(code[head:])
    for fragment in recorded:
        assert fragment in previous, f"recorded in the SET clause before the rule: {fragment[:60]}"


class TestDecayTagsItsRetirements:
    def test_the_rule_tags_its_retirements_decay(self):
        body = ia.aging_map("n", "datetime()")
        assert "retired_by: CASE WHEN" in body and "THEN 'decay' ELSE null END" in body
        assert "retired_at: CASE WHEN" in body and "_basis + duration({days: 730})" in body

    def test_alias_merge_treats_retired_by_as_a_node_local_scalar(self):
        assert _STRATEGY["retired_by"] == "discard" and _STRATEGY["retired_at"] == "discard"
        assert "last_decayed_tier" not in _STRATEGY and "last_decayed_at" not in _STRATEGY


class TestEveryIndicatorWriteAppliesTheOneRule:
    """The old per-write reactivation (``retired_by = 'decay'`` cleared on every write, the decay tier
    reset, confidence restored by max-wins) is gone; every Indicator write splices the one rule."""

    def test_old_reactivation_text_is_gone(self):
        assert not hasattr(nc, "_reactivation_clauses")
        code = "\n".join(line for line in _CLIENT_SRC.splitlines() if not line.lstrip().startswith("#"))
        assert not re.search(r"retired_by, ''\) = 'decay' THEN null", code)
        assert "last_decayed_tier" not in code
        assert "last_decayed" not in _ENRICH_SRC.split("def decay_ioc_confidence", 1)[1].split("\ndef ", 1)[0]

    def test_indicator_batch_splices_the_rule_last(self):
        client, session = _client()
        client.merge_indicators_batch(
            [{"indicator_type": "ipv4", "value": "203.0.113.5", "tag": "otx", "zone": ["global"]}], source_id="misp"
        )
        cy = _cyphers(session)
        node_set = cy.split("MERGE (n)-[r:SOURCED_FROM]->(s)", 1)[0]
        assert ia.source_confidence_item("n", "item.confidence") in node_set
        assert ia.node_report_items("n", "item.report", "item.source_id") in node_set
        _assert_rule_in_its_own_clause(
            node_set,
            "n",
            (
                ia.source_confidence_item("n", "item.confidence"),
                ia.node_report_items("n", "item.report", "item.source_id"),
            ),
        )
        assert node_set.split("WITH n, item", 1)[0].rstrip().endswith(ia.aging_set_clause("n", ia.WRITE_AS_OF)), (
            "the rule is the last node clause before WITH"
        )
        assert "n.confidence_score = CASE" not in node_set, "confidence_score comes from the rule only"
        assert ia.edge_report_items("r", "item.report", "item.source_id") in cy

    def test_single_indicator_merge_splices_the_rule(self):
        client, session = _client()
        client.merge_indicator(
            {"indicator_type": "ipv4", "value": "203.0.113.6", "tag": "stix_import", "zone": ["global"]},
            source_id="stix_import",
        )
        node = _node_merge(session, "Indicator")
        assert ia.source_confidence_item("n", "$confidence") in node
        assert ia.node_report_items("n", "$report", "$source_id") in node
        _assert_rule_in_its_own_clause(
            node,
            "n",
            (ia.source_confidence_item("n", "$confidence"), ia.node_report_items("n", "$report", "$source_id")),
        )
        sourced = next(
            c.args[0] for c in session.run.call_args_list if c.args and "MERGE (n)-[r:SOURCED_FROM]" in c.args[0]
        )
        assert ia.edge_report_items("r", "$report", "$source_id") in sourced

    def test_alert_path_and_its_fallback_splice_the_rule(self):
        client, session = _client()
        session.run.side_effect = [RuntimeError("primary failed"), MagicMock()]
        assert client.create_indicator_from_alert("203.0.113.9", "ipv4", "global", alert_data={"a": 1}) is True
        primary, fallback = (c.args[0] for c in session.run.call_args_list)
        for call in session.run.call_args_list:
            assert call.kwargs[ia.AS_OF_PARAM] is None, "outside a DAG run: the time of the write"
        for query in (primary, fallback):
            assert ia.source_confidence_item("i", "$confidence_score") in query
            _assert_rule_in_its_own_clause(query, "i", (ia.source_confidence_item("i", "$confidence_score"),))
            assert "last_reported_at:" not in query, "an alert records no report"
            assert "i.confidence_score = CASE" not in query

    def test_a_sync_of_a_run_ages_its_writes_at_the_run_time(self):
        """2026-10-16: the sync's writes evaluate the rule at the DAG run's time, the time that run's
        aging job uses (``WRITE_AS_OF`` with ``$aging_as_of``); without one, at the write's own time.
        Before, the writes used ``datetime()`` and the job the run's ``data_interval_end``: a node that
        crossed a tier or the retirement day in between was moved forward by the write and back by
        the job."""
        assert ia.WRITE_AS_OF == "coalesce(datetime($aging_as_of), datetime())"
        client, session = _client()
        assert client.aging_as_of is None
        client.set_aging_as_of("2026-10-16T03:00:00Z")
        assert client.aging_as_of == "2026-10-16T03:00:00+00:00"
        client.merge_indicators_batch(
            [{"indicator_type": "ipv4", "value": "203.0.113.5", "tag": "otx", "zone": ["global"]}], source_id="misp"
        )
        batch = next(c for c in session.run.call_args_list if c.args and "UNWIND $batch as item" in c.args[0])
        assert batch.kwargs[ia.AS_OF_PARAM] == "2026-10-16T03:00:00+00:00"
        client.merge_indicator(
            {"indicator_type": "ipv4", "value": "203.0.113.6", "tag": "otx", "zone": ["global"]}, source_id="misp"
        )
        single = next(c for c in session.run.call_args_list if c.args and "MERGE (n:Indicator " in c.args[0])
        assert single.kwargs[ia.AS_OF_PARAM] == "2026-10-16T03:00:00+00:00"
        client.set_aging_as_of(None)
        assert client.aging_as_of is None

    def test_a_single_merge_with_more_items_still_ends_its_clause_before_the_rule(self):
        """``merge_node_with_source`` appends the MISP ids, ``extra_props`` and ``fill_props`` to its SET
        clause after the report items: the rule's clause follows all of them."""
        client, session = _client()
        client.merge_indicator(
            {
                "indicator_type": "ipv4",
                "value": "203.0.113.7",
                "tag": "otx",
                "zone": ["global"],
                "misp_event_id": "41",
                "misp_attribute_id": "9",
                "tlp": "amber",
            },
            source_id="misp",
        )
        node = _node_merge(session, "Indicator")
        assert node.index("n.misp_attribute_ids = ") < node.index(ia.aging_set_clause("n", ia.WRITE_AS_OF))
        _assert_rule_in_its_own_clause(node, "n", ("n.misp_event_ids = ", "n.misp_attribute_ids = "))

    def test_manual_decommission_still_wins(self):
        body = ia.aging_map("n", "datetime()")
        manual = ia.manual_decommission_expr("n")
        assert manual == "(n.retired_at IS NOT NULL AND coalesce(n.retired_by, 'manual') <> 'decay')"
        for key in ("active", "retired_at", "retired_by"):
            assert f"{key}: CASE WHEN _age IS NULL OR {manual} THEN n.{key}" in body, key


class TestOtherLabelsGetNoLifecycleOnMatch:
    """CVE, CVSS, Vulnerability, Malware, ThreatActor, Technique, Tactic and Tool never age:
    ``active = true`` on create only, nothing on MATCH (a CASM- or ISIM-created node keeps its own
    lifecycle)."""

    def _assert_create_only(self, query: str, var: str = "n"):
        on_create, rest = query.split("ON MATCH SET", 1)
        assert f"{var}.active = true" in on_create
        for prop in _LIFECYCLE_PROPS:
            assert f"{var}.{prop}" not in rest, prop

    def test_actor_cve_malware_technique_vulnerability(self):
        client, session = _client()
        client.merge_actor({"name": "apt28", "tag": "mitre_attck", "zone": ["global"]}, source_id="mitre_attck")
        self._assert_create_only(_node_merge(session, "ThreatActor"))
        client.merge_cve({"cve_id": "CVE-2024-3400", "zone": ["global"]}, source_id="nvd")
        self._assert_create_only(_node_merge(session, "CVE"))
        client.merge_malware({"name": "emotet", "zone": ["global"]}, source_id="mitre_attck")
        self._assert_create_only(_node_merge(session, "Malware"))
        client.merge_vulnerability({"cve_id": "CVE-2024-3400"}, source_id="nvd")
        self._assert_create_only(_node_merge(session, "Vulnerability"))

    def test_vulnerability_batch(self):
        client, session = _client()
        nc_exec = nc._execute_batch_with_retry
        seen = []
        try:
            nc._execute_batch_with_retry = lambda driver, query, **kw: seen.append(query) or (True, kw["batch_len"])
            client.merge_vulnerabilities_batch([{"cve_id": "CVE-2024-3400", "zone": ["global"]}], source_id="nvd")
        finally:
            nc._execute_batch_with_retry = nc_exec
        self._assert_create_only(seen[0])

    def test_partner_label_helpers_write_no_lifecycle(self):
        """The ResilMesh-model helpers (no caller in the pipeline) write no EdgeGuard lifecycle
        property: an IP, Host or partner Vulnerability / CVE keeps the partner's own lifecycle."""
        client, session = _client()
        client.merge_ip({"address": "203.0.113.40", "version": 4, "tag": ["dmz"], "status": "known"})
        client.merge_host({"hostname": "gw01"})
        client.merge_resilmesh_vulnerability(
            {"cve_id": "CVE-2023-4966", "description": "Citrix Bleed", "status": ["estimated"]}
        )
        client.merge_resilmesh_cve({"cve_id": "CVE-2023-4966", "description": "Citrix Bleed"})
        writes = [c.args[0] for c in session.run.call_args_list if c.args and "MERGE" in c.args[0]]
        assert len(writes) >= 4
        for query in writes:
            for prop in _LIFECYCLE_PROPS:
                assert f".{prop}" not in query, (prop, query[:80])

    def test_a_deprecated_attack_object_keeps_its_flag_and_no_lifecycle_write(self):
        """The ATT&CK ``x_mitre_deprecated`` rule (``n.deprecated = true``, node and links kept) is a
        lifecycle of its own and still holds; no aging property is written on the match path."""
        client, session = _client()
        client.merge_technique(
            {"mitre_id": "T1086", "name": "PowerShell", "deprecated": True, "zone": ["global"]},
            source_id="mitre_attck",
        )
        query = _node_merge(session, "Technique")
        assert "n.deprecated = $deprecated" in query
        self._assert_create_only(query)

    def test_no_label_but_indicator_carries_the_rule(self):
        assert "MATCH (n:Indicator)" in _ENRICH_SRC.split("def _aging_job_statements", 1)[1].split("\ndef ", 1)[0]
        assert '("Vulnerability",' not in _ENRICH_SRC.split("def decay_ioc_confidence", 1)[1].split("\ndef ", 1)[0]


class TestSyncEdgesNeverDowngrade:
    def _set_clause(self):
        start = _CLIENT_SRC.index('f"SET r.sources = {sources_dedup},')
        return _CLIENT_SRC[start : start + 1800]

    def test_confidence_keeps_the_maximum(self):
        body = self._set_clause()
        assert (
            "r.confidence_score = CASE WHEN r.confidence_score IS NULL OR {confidence_expr} > r.confidence_score"
            in body
        )
        assert "THEN {confidence_expr} ELSE r.confidence_score END" in body
        assert 'f"            r.confidence_score = {confidence_expr},' not in body, (
            "the unconditional overwrite is gone"
        )

    def test_label_follows_the_stronger_evidence_and_is_evaluated_first(self):
        body = self._set_clause()
        assert "r.match_type = CASE WHEN r.confidence_score IS NULL OR {confidence_expr} >= r.confidence_score" in body
        assert "THEN coalesce(row.match_type, r.match_type) ELSE r.match_type END" in body
        assert body.index("r.match_type = CASE") < body.index("r.confidence_score = CASE"), (
            "match_type must read the previous confidence"
        )

    def test_rendered_query_carries_both_ladders(self):
        client, session = _client()
        client.create_misp_relationships_batch(
            [
                {
                    "rel_type": "INDICATES",
                    "from_type": "Indicator",
                    "from_key": {"value": "203.0.113.5", "indicator_type": "ipv4"},
                    "to_type": "Malware",
                    "to_key": {"name": "emotet"},
                    "confidence": 0.6,
                    "match_type": "otx_pulse",
                    "misp_event_id": "7",
                }
            ],
            source_id="misp",
        )
        cy = _cyphers(session)
        assert "ELSE r.confidence_score END" in cy and "ELSE r.match_type END" in cy
