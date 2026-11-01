"""The batched CVE write (2026-11): ``Neo4jClient.merge_cves_batch`` and the sync's use of it.

Until 2026-11 the sync wrote each CVE with ``merge_cve``: a read and five to nine auto-commit statements per CVE
(about 8 NVD CVEs per second in the 7-day baseline of 2026-11-01 on the test instance, which put the full sync of a
730-day MISP at about 5.7 h, about 5.2 h of it CVEs, against the 6 h limit of ``full_neo4j_sync``).
``merge_cves_batch`` writes up to ``CVE_BATCH_SIZE`` CVEs in one transaction of one UNWIND statement per write, from
rows holding the values ``merge_cve`` gives its statements.

This module checks, without a database, that each row holds exactly those values for every real record of the
fixtures (``TestRowsAreMergeCveParameters``), that the node statement assigns each property in the clause the single
write uses, the statements and the one explicit transaction a batch sends, its retry and its fallback to ``merge_cve``
(``tests/fake_bolt.py``), how a fallback is counted and logged (stats, metric, ``[NEO4J-TIMEOUT]``), and the sync's
accounting and run summary. That the statements leave the graph as ``merge_cve`` leaves it is shown on a real Neo4j
by ``tests/test_cve_batch_sync_neo4j.py``.
"""

from __future__ import annotations

import copy
import inspect
import json
import logging
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from fake_bolt import FakeBolt, count, fail  # noqa: E402

import neo4j_client as nc  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from collectors.nvd_collector import NVDCollector  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

DEADLOCK = "Neo.TransientError.Transaction.DeadlockDetected"  # retryable
TYPE_ERROR = "Neo.ClientError.Statement.TypeError"  # terminal

BATCH_NODE = "MERGE (n:CVE {cve_id: row.cve_id})"
SINGLE_NODE = "MERGE (n:CVE {cve_id: $cve_id})"
BATCH_SCORE = "UNWIND $cve_ids AS cve_id\nMATCH (c:CVE"
BATCH_AUDIT = "MATCH (n:CVE {cve_id: cve_id})\nRETURN"
BATCH_SOURCED_FROM = "MERGE (n)-[r:SOURCED_FROM]->(s)"


# ---------------------------------------------------------------------------------------------- real records
def _nvd_items() -> List[Dict[str, Any]]:
    """The sync's items of the NVD fixture: NVD API records -> NVDCollector -> MISPWriter -> parse_attribute."""
    records = json.loads((TESTS / "fixtures" / "nvd_cve_batch_2026_11_01.json").read_text())["nvd"]
    collector = NVDCollector.__new__(NVDCollector)
    collector.base_url, collector.api_key, collector._api_key_rejected = "http://fake", "k", False
    collector.tag = collector.source_name = "nvd"
    collector.misp_writer, collector.circuit_breaker = MagicMock(), MagicMock()
    with (
        patch.object(NVDCollector, "_fetch_modified_cves", return_value=(list(records.values()), True)),
        patch.object(NVDCollector, "check_service_available", return_value=True),
    ):
        items = collector.collect(limit=None, push_to_misp=False, baseline=False)
    writer, syncer = MISPWriter.__new__(MISPWriter), MISPToNeo4jSync(neo4j_client=MagicMock())
    event = {"id": "501", "info": "EdgeGuard-nvd-2026-11-01", "Tag": []}
    parsed = []
    for item in items:
        attribute = writer.create_vulnerability_attribute(item)
        attribute.update(uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, item["cve_id"])), event_id="501", timestamp="1")
        parsed.append(syncer.parse_attribute(attribute, event)[0])
    return parsed


def _hosted_items() -> List[Dict[str, Any]]:
    """The sync's items of the CVE attributes of the hosted MISP in the fixtures (NVD, KEV, CISA ICS, OTX)."""
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    items = []
    for path in (
        TESTS / "test_cvss_real_payloads.json",
        TESTS / "fixtures" / "nvd_incremental_2026_10_14.json",
        TESTS / "fixtures" / "kev_revisions_2026_10_16.json",
    ):
        for attribute in json.loads(path.read_text())["misp"].values():
            event = attribute.get("_event") or {}
            item, _ = syncer.parse_attribute(
                {k: v for k, v in attribute.items() if k != "_event"},
                {"id": attribute.get("event_id"), "info": event.get("info", ""), "Tag": []},
            )
            if item:
                items.append(item)
    return items


@pytest.fixture(scope="module")
def real_items() -> List[Dict[str, Any]]:
    items = _nvd_items() + _hosted_items()
    # A caller other than the sync may pass a source list and a tag of its own (the sync's are the source id).
    return items + [dict(items[0], source=["alienvault_otx", "nvd"], tag="otx")]


# ---------------------------------------------------------------------------------------------- 1. the rows
class _Recorder:
    """A driver whose sessions record every statement and its parameters (no database)."""

    def __init__(self):
        self.calls: List[Tuple[str, Dict[str, Any]]] = []

    def session(self, *_a, **_k):
        recorder = self

        class _Result:
            def single(self):
                return None

            def consume(self):
                return MagicMock()

        class _Session:
            def run(self, query, *_a, **params):
                params.pop("timeout", None)
                recorder.calls.append((str(query), params))
                return _Result()

            def __enter__(self):
                return self

            def __exit__(self, *_a):
                return False

        return _Session()


def _merge_cve_parameters(data: Dict[str, Any], source_id: str) -> Dict[str, Any]:
    """The parameters of each statement ``merge_cve`` sends for the record, by statement."""
    client = nc.Neo4jClient.__new__(nc.Neo4jClient)
    client.driver = _Recorder()
    assert client.merge_cve(copy.deepcopy(data), source_id=source_id) is True
    found: Dict[str, Any] = {"cvss": {}}
    for query, params in client.driver.calls:
        if SINGLE_NODE in query:
            found["node"] = params
        elif "MERGE (n)-[r:SOURCED_FROM]->(s)" in query:
            found["edge"] = params
        elif "AS nvd_only" in query:
            found["nvd"] = params
        elif "MERGE (n:CVSSv" in query:
            label = query.split("MERGE (n:", 1)[1].split(" ", 1)[0]
            found["cvss"][label] = params
    return found


def _single_node_statements(real_items: List[Dict[str, Any]], source_id: str) -> Tuple[str, str]:
    """The node statement and the read before it that ``merge_cve`` sends for a real record given every property
    ``merge_cve`` writes (TLP, a MISP attribute id, a description and each of ``_CVE_NODE_PROPS``)."""
    data = dict(real_items[0], tlp="amber", misp_attribute_id="9", description="text", known_ransomware_use="Known")
    for prop in nc._CVE_NODE_PROPS:
        if not data.get(prop):
            data[prop] = ["x"] if prop in nc._NVD_OWNED_CVE_LISTS + ("status",) else "2026-10-01"
    client = nc.Neo4jClient.__new__(nc.Neo4jClient)
    client.driver = _Recorder()
    client.merge_cve(data, source_id=source_id)
    (single,) = [q for q, _ in client.driver.calls if SINGLE_NODE in q]
    (read,) = [q for q, _ in client.driver.calls if "as existing_confidence" in q]
    return single, read


def _assignment_clauses(statement: str) -> Dict[str, set]:
    """For each node property a statement assigns (``n.<prop> = …`` as an item of a ``SET`` list), the clauses
    that assign it: ``ON CREATE SET``, ``ON MATCH SET`` or ``SET`` (every write; the ``SET`` after ``WITH`` too).
    A comparison inside an expression (``n.cwe = ''``) is not an item, so it is not counted."""
    text = re.sub(r"//[^\n]*", "", statement)  # comments
    keywords = list(re.finditer(r"ON CREATE SET|ON MATCH SET|\bSET\b|\bWITH\b", text))
    clauses: Dict[str, set] = {}
    for keyword, following in zip(keywords, keywords[1:] + [None], strict=True):
        if keyword.group() == "WITH":
            continue
        segment = text[keyword.start() : following.start() if following else len(text)]
        for prop in re.findall(r"(?:\bSET\s+|,\s*)n\.(\w+)\s*=", segment):
            clauses.setdefault(prop, set()).add(keyword.group())
    return clauses


class TestRowsAreMergeCveParameters:
    """For every real record, the batch's rows (``_prepare_cve_write``) hold the values ``merge_cve`` passes its
    statements: the node's (its set and filled properties, TLP and ranked description included), the
    ``SOURCED_FROM`` edge's, each CVSS sub-node's and NVD's data."""

    def test_every_record(self, real_items):
        assert len(real_items) > 70
        for item in real_items:
            source_id = item.get("tag", "misp")
            single = _merge_cve_parameters(item, source_id)
            row = nc._prepare_cve_write(copy.deepcopy(item), source_id)
            assert row is not None, item["cve_id"]

            node = dict(single["node"])
            expected_node = {
                "cve_id": node.pop("cve_id"),
                "node_uuid": node.pop("node_uuid"),
                "confidence": node.pop("confidence"),
                "source_array": node.pop("source_array"),
                "zone": node.pop("zone"),
                "tag_array": node.pop("tag_array"),
                "tag_value": node.pop("tag_value"),
                "source_id": node.pop("source_id"),
                "misp_event_id": node.pop("misp_event_id", None),
                "misp_attribute_id": node.pop("misp_attribute_id", None),
                "tlp": node.pop("tlp", None),
                "description": node.pop("ranked_description", None),
                "description_source": node.pop("ranked_description_source", None),
                "description_rank": node.pop("ranked_description_rank", None),
                "fill_props": {k[len("fill_") :]: node.pop(k) for k in list(node) if k.startswith("fill_")},
            }
            expected_node["set_props"] = node  # what is left: the properties the record sets
            assert row["node"] == expected_node, item["cve_id"]
            assert set(node) <= set(nc._CVE_NODE_PROPS)
            assert row["edge"] == single["edge"], item["cve_id"]
            assert {label: {**r["cvss"], **{k: v for k, v in r.items() if k != "cvss"}} for label, r in row["cvss"].items()} == single["cvss"]  # fmt: skip
            assert row["nvd"] == single.get("nvd"), item["cve_id"]

    def test_the_records_cover_what_a_row_can_carry(self, real_items):
        """Not vacuous: the records set and fill properties, carry TLP, descriptions of several sources, every
        CVSS version and NVD's data with SSVC."""
        rows = [nc._prepare_cve_write(copy.deepcopy(i), i.get("tag", "misp")) for i in real_items]
        assert any(r["node"]["fill_props"] for r in rows) and any(r["node"]["set_props"] for r in rows)
        assert any(r["node"]["tlp"] for r in rows)
        assert {r["node"]["description_source"] for r in rows} >= {"nvd", "cisa_kev", "cisa_ics"}
        assert {label for r in rows for label in r["cvss"]} == {"CVSSv40", "CVSSv31", "CVSSv30", "CVSSv2"}
        assert any(r["nvd"] and r["nvd"]["ssvc_exploitation"] for r in rows)
        assert any("status" in r["node"]["set_props"] for r in rows)

    def test_cve_node_props_lists_every_property_the_records_give(self, real_items):
        for item in real_items:
            for source_id in (item.get("tag", "misp"), "cisa_kev", "nvd", "alienvault_otx"):
                extra, fill = nc._cve_node_props(dict(item), source_id)
                assert set(extra) | set(fill) <= set(nc._CVE_NODE_PROPS)

    @pytest.mark.parametrize("source_id", ["nvd", "cisa_kev", "alienvault_otx"])
    def test_the_node_statement_assigns_what_the_single_write_assigns(self, real_items, source_id):
        """The batch's node statement is written for CVEs (a CASE per row where ``merge_node_with_source`` adds a
        clause per record), so a property the single write gains must reach it too: for a record carrying every
        property ``merge_cve`` writes, both statements assign the same node properties, and the read before the
        write returns the same ones."""
        single, read = _single_node_statements(real_items, source_id)

        def assigned(statement: str) -> set:
            return set(re.findall(r"\bn\.(\w+)\s*=", statement))

        assert assigned(nc._CVE_BATCH_NODE_QUERY) == assigned(single)
        assert {"tlp", "misp_attribute_ids", "description", *nc._CVE_NODE_PROPS} <= assigned(single)
        assert set(re.findall(r"\bn\.(\w+)", nc._CVE_BATCH_AUDIT_QUERY)) == set(re.findall(r"\bn\.(\w+)", read))

    @pytest.mark.parametrize("source_id", ["nvd", "cisa_kev", "alienvault_otx"])
    def test_each_property_is_assigned_in_the_clause_the_single_write_uses(self, real_items, source_id):
        """2026-11: where a property is assigned matters as much as that it is: ``first_imported_at`` is set when
        the node is created only, ``last_updated`` on every write. Both statements give each property the same
        clauses (``ON CREATE SET``, ``ON MATCH SET`` or ``SET``, which runs on every write)."""
        single, _read = _single_node_statements(real_items, source_id)
        batch = _assignment_clauses(nc._CVE_BATCH_NODE_QUERY)
        assert batch == _assignment_clauses(single)
        # The write-time stamps of the node, named: what the parity test on a real Neo4j compares by presence only.
        assert batch["first_imported_at"] == {"ON CREATE SET"}
        assert batch["last_updated"] == {"SET"}
        # Not vacuous: the split finds the create-only, match-only and every-write items of the statement.
        assert {p for p, c in batch.items() if c == {"ON CREATE SET"}} == {
            "first_imported_at",
            "edgeguard_managed",
            "active",
        }
        assert batch["edgeguard_enriched"] == {"ON MATCH SET"} and batch["uuid"] == {"ON CREATE SET", "SET"}
        assert {"confidence_score", "source", "tlp", "description", *nc._CVE_NODE_PROPS} <= {
            p for p, c in batch.items() if c == {"SET"}
        }

    @pytest.mark.parametrize(
        "change",
        [
            {"cve_id": None, "value": None, "type": "vulnerability"},  # no resolvable CVE id
            {"cvss_v31_data": "CVSS:3.1/AV:N"},  # a payload that is not a dict
            {"cvss_v31_data": {"base_score": 9.8, "uuid": "x"}},  # a payload naming a parameter
            {"cvss_v31_data": {"base_score": 9.8, "self": "x"}},  # an argument of session.run (2026-11)
            {"cvss_v31_data": {"base score": 9.8}},  # not a property name
        ],
    )
    def test_a_record_the_batch_does_not_write_as_merge_cve_gets_no_row(self, real_items, change):
        item = dict(real_items[0], **change)
        assert nc._prepare_cve_write(item, "nvd") is None


# ---------------------------------------------------------------------------------------------- 2. the writes
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


def _cve(n: int, **extra) -> Dict[str, Any]:
    return {
        "type": "vulnerability",
        "cve_id": f"CVE-2026-{1000 + n}",
        "tag": "nvd",
        "zone": ["global"],
        "nvd_record": True,
        "misp_event_id": "501",
        "cwe": ["CWE-79"],
        "cvss_v31_data": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "base_score": 9.8},
        **extra,
    }


def _records(*items: Dict[str, Any]) -> List[Tuple[Dict[str, Any], str]]:
    return [(item, item.get("tag", "misp")) for item in items]


def _transactions(events: List[Tuple[str, Any]]) -> Tuple[List[Tuple[Dict[str, Any], List[str], str]], List[str]]:
    """The explicit transactions in ``FakeBolt.events``, each as ``(BEGIN's extra, its statements, how it ended)``
    (``COMMIT``, ``ROLLBACK``, or ``RESET``, with which the driver ends a transaction a statement of which failed),
    and the statements run outside a transaction (auto-commit)."""
    transactions: List[Tuple[Dict[str, Any], List[str], str]] = []
    auto_commit: List[str] = []
    current = None
    for name, payload in events:
        if name == "BEGIN":
            current = (payload or {}, [])
        elif name == "RUN" and current is not None:
            current[1].append(payload)
        elif name == "RUN":
            auto_commit.append(payload)
        elif current is not None:  # COMMIT, ROLLBACK, RESET
            transactions.append((current[0], current[1], name))
            current = None
    assert current is None, "a transaction was left open"
    return transactions, auto_commit


def _fallback_count(reason: str) -> float:
    """``edgeguard_neo4j_cve_batch_fallback_total{reason}`` as the metrics endpoint reports it."""
    from prometheus_client import REGISTRY

    return REGISTRY.get_sample_value("edgeguard_neo4j_cve_batch_fallback_total", {"reason": reason}) or 0.0


FALLBACK_REASONS = ("non_retryable", "retries_exhausted", "batch_writer_error")
TIMED_OUT = "Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration"


class TestOneTransactionPerBatch:
    def test_a_batch_is_one_statement_per_write(self, bolt):
        server, client = bolt()
        records = _records(_cve(1), _cve(2, cvss_v40_data={"base_score": 9.3}), _cve(3, nvd_record=False))
        assert client.merge_cves_batch(records) == [True, True, True]
        assert count(server.runs, "MATCH (n:CVE {cve_id: cve_id})\nRETURN") == 1  # the read before the write
        for statement in (BATCH_NODE, "MERGE (n)-[r:SOURCED_FROM]->(s)", "MERGE (n:CVSSv40", "MERGE (n:CVSSv31"):
            assert count(server.runs, statement) == 1, statement
        assert count(server.runs, "AS nvd_only") == 1 and count(server.runs, BATCH_SCORE) == 1
        assert count(server.runs, SINGLE_NODE) == 0, "no CVE was written alone"
        nvd = next(p for q, p in zip(server.runs, server.parameters, strict=True) if "AS nvd_only" in q)
        assert [r["cve_id"] for r in nvd["rows"]] == ["CVE-2026-1001", "CVE-2026-1002"]  # NVD's records only

    def test_the_statements_of_a_batch_are_one_explicit_transaction(self, bolt):
        """2026-11: one BEGIN, every statement of the batch, one COMMIT; the transaction carries the timeout, which
        covers its statements together. Nothing is written in auto-commit statements."""
        server, client = bolt()
        start = len(server.events)  # after the connection check
        assert client.merge_cves_batch(_records(_cve(1), _cve(2, nvd_record=False))) == [True, True]
        transactions, auto_commit = _transactions(server.events[start:])
        assert auto_commit == []
        ((begin, statements, end),) = transactions
        assert end == "COMMIT"
        assert begin.get("tx_timeout") == nc.NEO4J_READ_TIMEOUT * 1000  # milliseconds
        # The read, the node, SOURCED_FROM, CVSS v3.1, NVD's data and the score, in merge_cve's order.
        heads = [BATCH_AUDIT, BATCH_NODE, BATCH_SOURCED_FROM, "MERGE (n:CVSSv31", "AS nvd_only", BATCH_SCORE]
        assert [next(h for h in heads if h in s) for s in statements] == heads

    def test_batches_hold_at_most_cve_batch_size(self, bolt, monkeypatch):
        monkeypatch.setattr(nc, "CVE_BATCH_SIZE", 2)
        server, client = bolt()
        assert client.merge_cves_batch(_records(*(_cve(i) for i in range(5)))) == [True] * 5
        assert count(server.runs, BATCH_NODE) == 3

    def test_a_cve_held_twice_starts_the_next_batch_in_order(self, bolt):
        """KEV's record of CVE-2026-1001 after NVD's: written in the next batch, after it, as merge_cve writes
        them in turn; CVE-2026-1002 joins the second batch."""
        server, client = bolt()
        kev = _cve(1, tag="cisa_kev", nvd_record=False, cisa_exploit_add="2026-10-01")
        assert client.merge_cves_batch(_records(_cve(1), kev, _cve(2))) == [True, True, True]
        batches = [p["rows"] for q, p in zip(server.runs, server.parameters, strict=True) if BATCH_NODE in q]
        assert [[(r["cve_id"], r["source_id"]) for r in rows] for rows in batches] == [
            [("CVE-2026-1001", "nvd")],
            [("CVE-2026-1001", "cisa_kev"), ("CVE-2026-1002", "nvd")],
        ]

    def test_a_record_without_a_cve_id_is_false_and_writes_nothing(self, bolt, caplog):
        server, client = bolt()
        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            results = client.merge_cves_batch(_records(_cve(1), {"type": "vulnerability", "tag": "nvd"}, _cve(2)))
        assert results == [True, False, True]
        assert any("merge_cve: missing resolvable cve_id" in r.getMessage() for r in caplog.records)
        assert count(server.runs, SINGLE_NODE) == 0

    def test_a_record_the_batch_cannot_hold_is_written_by_merge_cve_in_its_place(self, bolt):
        server, client = bolt()
        odd = _cve(2, cvss_v31_data={"base_score": 9.8, "uuid": "x"})
        assert client.merge_cves_batch(_records(_cve(1), odd, _cve(3))) == [True, True, True]
        order = [q for q in server.runs if BATCH_NODE in q or SINGLE_NODE in q]
        assert [BATCH_NODE in q for q in order] == [True, False, True]

    def test_a_payload_entry_named_like_an_argument_of_session_run_gets_merge_cves_result(self, bolt):
        """2026-11: ``merge_cve`` passes a CVSS payload to ``session.run`` as keyword arguments, so an entry named
        ``self`` fails its CVSS write (False); the batch nests the payload in its rows and had written it. Such a
        record is now written by ``merge_cve``, so both give the same result. The sync drops the entry when it reads
        the attribute (``_meta_cvss_payload``), so only a direct caller meets it."""
        _server, client = bolt()
        odd = _cve(2, cvss_v31_data={"base_score": 9.8, "self": "x"})
        assert client.merge_cves_batch(_records(odd)) == [client.merge_cve(copy.deepcopy(odd), source_id="nvd")]
        named = inspect.signature(nc._TimeoutSession.run).parameters.values()
        arguments = {p.name for p in named if p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)}
        assert arguments == {"self", "query", "parameters", "timeout"}
        assert arguments <= nc.CVSS_PAYLOAD_RESERVED_NAMES


class TestRetryAndFallback:
    def test_a_deadlock_retries_the_whole_batch(self, bolt):
        server, client = bolt(fail(BATCH_NODE, DEADLOCK))
        assert client.merge_cves_batch(_records(_cve(1), _cve(2))) == [True, True]
        assert count(server.runs, BATCH_NODE) == 2 and count(server.committed, BATCH_NODE) == 1
        assert count(server.runs, SINGLE_NODE) == 0

    @pytest.mark.parametrize("rule", [fail(BATCH_SCORE, TYPE_ERROR), fail(BATCH_NODE, DEADLOCK, times=4)])
    def test_a_failed_batch_is_written_by_merge_cve(self, bolt, caplog, rule):
        """A terminal error, or a retryable one that outlasts the retries: the transaction wrote nothing and
        each CVE is written alone, with merge_cve's result."""
        server, client = bolt(rule)
        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            assert client.merge_cves_batch(_records(_cve(1), _cve(2))) == [True, True]
        assert count(server.runs, SINGLE_NODE) == 2
        (line,) = [r for r in caplog.records if "[CVE-BATCH-FALLBACK]" in r.getMessage()]
        assert "batched write of 2 CVEs failed" in line.getMessage()
        assert line.levelno == logging.WARNING, "every CVE is still written: a warning, as the sync's own marker"

    def test_a_failed_statement_rolls_the_whole_batch_back(self, bolt):
        """2026-11: the node statement succeeded and the SOURCED_FROM statement after it failed: the transaction
        ends without a COMMIT (the driver resets the connection, which rolls it back), so neither statement's
        writes stay, and merge_cve then writes each CVE in auto-commit statements of its own."""
        server, client = bolt(fail(BATCH_SOURCED_FROM, TYPE_ERROR))
        start = len(server.events)
        assert client.merge_cves_batch(_records(_cve(1), _cve(2))) == [True, True]
        transactions, auto_commit = _transactions(server.events[start:])
        ((_begin, statements, end),) = transactions
        assert end in ("ROLLBACK", "RESET"), end
        assert [BATCH_NODE in s for s in statements[1:]] == [True, False] and BATCH_SOURCED_FROM in statements[2]
        assert count(server.committed, BATCH_NODE) == 1, "the node statement itself succeeded"
        assert count(auto_commit, SINGLE_NODE) == 2 and count(auto_commit, BATCH_NODE) == 0

    def test_a_batch_at_its_transaction_timeout_logs_the_timeout_line(self, bolt, caplog):
        """2026-11: the batch's statements bypass the session proxy that logs ``[NEO4J-TIMEOUT]``, so the batch
        names itself: once, with its size and the setting that limits it; its CVEs are then written alone."""
        server, client = bolt(fail(BATCH_NODE, TIMED_OUT))
        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            assert client.merge_cves_batch(_records(_cve(1), _cve(2))) == [True, True]
        (timeout,) = [r for r in caplog.records if "[NEO4J-TIMEOUT]" in r.getMessage()]
        assert timeout.levelno == logging.ERROR
        assert "[CVE-BATCH] batched write of 2 CVEs" in timeout.getMessage()
        assert f"{nc.NEO4J_READ_TIMEOUT} s transaction timeout" in timeout.getMessage()
        assert "EDGEGUARD_NEO4J_READ_TIMEOUT" in timeout.getMessage()
        assert count(server.runs, BATCH_NODE) == 1, "a timeout is not retried"
        assert count(server.runs, SINGLE_NODE) == 2

    def test_a_batch_that_does_not_time_out_logs_no_timeout_line(self, bolt, caplog):
        _server, client = bolt(fail(BATCH_NODE, TYPE_ERROR))
        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            assert client.merge_cves_batch(_records(_cve(1))) == [True]
        assert not [r for r in caplog.records if "[NEO4J-TIMEOUT]" in r.getMessage()]

    @pytest.mark.parametrize(
        "statement, code, times, reason",
        [(BATCH_SCORE, TYPE_ERROR, 1, "non_retryable"), (BATCH_NODE, DEADLOCK, 4, "retries_exhausted")],
    )
    def test_a_fallback_is_counted_with_its_reason(self, bolt, statement, code, times, reason):
        """2026-11: each batch that falls back adds one to ``edgeguard_neo4j_cve_batch_fallback_total{reason}`` and
        reports its CVEs to the caller (``on_fallback``)."""
        assert nc._record_cve_batch_fallback is not None, "prometheus_client is a declared dependency"
        before = {r: _fallback_count(r) for r in FALLBACK_REASONS}
        _server, client = bolt(fail(statement, code, times=times))
        reported: List[int] = []
        assert client.merge_cves_batch(_records(_cve(1), _cve(2), _cve(3)), on_fallback=reported.append) == [True] * 3
        assert reported == [3]
        after = {r: _fallback_count(r) for r in FALLBACK_REASONS}
        assert {r: after[r] - before[r] for r in FALLBACK_REASONS} == {
            r: (1.0 if r == reason else 0.0) for r in FALLBACK_REASONS
        }

    def test_batches_that_are_written_count_nothing(self, bolt, monkeypatch):
        """Control: a retried deadlock that clears, and batches that commit, are no fallback."""
        monkeypatch.setattr(nc, "CVE_BATCH_SIZE", 2)
        before = {r: _fallback_count(r) for r in FALLBACK_REASONS}
        _server, client = bolt(fail(BATCH_NODE, DEADLOCK))
        reported: List[int] = []
        assert (
            client.merge_cves_batch(_records(*(_cve(i) for i in range(5))), on_fallback=reported.append) == [True] * 5
        )
        assert reported == []
        assert {r: _fallback_count(r) for r in FALLBACK_REASONS} == before

    def test_merge_cve_results_and_exceptions_are_returned_per_record(self, bolt):
        """After a failed batch: a CVE whose retries run out returns the exception merge_cve raised, one whose
        own write fails terminally returns False, the other is True."""
        server, client = bolt(
            fail(BATCH_NODE, TYPE_ERROR),
            fail("SET c.cvss_score = best[0].base_score", DEADLOCK, times=4),  # the first CVE's score
            fail("MERGE (n:CVSSv31", TYPE_ERROR),  # the second CVE's CVSS (the first has none)
        )
        plain = {k: v for k, v in _cve(1).items() if k != "cvss_v31_data"}
        results = client.merge_cves_batch(_records(plain, _cve(2), _cve(3)))
        assert isinstance(results[0], nc.neo4j_exceptions.TransientError)
        assert results[1:] == [False, True]

    def test_the_clamp_warning_is_logged_once_per_record(self, bolt, caplog):
        _server, client = bolt()
        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            assert client.merge_cves_batch(_records(_cve(1, confidence_score="1e309"))) == [True]
        lines = [r.getMessage() for r in caplog.records if "confidence_score rejected by clamp" in r.getMessage()]
        assert lines == ["confidence_score rejected by clamp for CVE/nvd (claimed='1e309') — falling back to 0.5. "
                         "Compromised feed?"]  # fmt: skip


# ---------------------------------------------------------------------------------------------- 3. the sync
class TestTheSyncWritesCvesInBatches:
    def test_a_chunk_of_rich_and_plain_cves_is_two_batches(self, bolt):
        server, client = bolt()
        sync = MISPToNeo4jSync(neo4j_client=client)
        plain = {k: v for k, v in _cve(3).items() if k != "cvss_v31_data"}
        assert sync._sync_to_neo4j_chunk([_cve(1), _cve(2), plain]) == (3, 0)
        assert sync.stats["vulnerabilities_synced"] == 3
        assert count(server.runs, BATCH_NODE) == 2 and count(server.runs, SINGLE_NODE) == 0
        assert sync.stats["cve_batch_fallbacks"] == 0 and sync.stats["cve_batch_fallback_cves"] == 0

    def test_a_batch_that_falls_back_is_counted_in_the_sync_stats(self, bolt):
        """2026-11: the rich CVEs' batch fails on the server and is written one CVE at a time; the plain CVEs' batch
        is written. The stats count one fallback of two CVEs; the CVEs count as synced, not as errors."""
        server, client = bolt(fail("MERGE (n:CVSSv31 {cve_id: row.cve_id})", TYPE_ERROR))
        sync = MISPToNeo4jSync(neo4j_client=client)
        plain = {k: v for k, v in _cve(3).items() if k != "cvss_v31_data"}
        assert sync._sync_to_neo4j_chunk([_cve(1), _cve(2), plain]) == (3, 0)
        assert sync.stats["vulnerabilities_synced"] == 3
        assert sync.stats["cve_batch_fallbacks"] == 1 and sync.stats["cve_batch_fallback_cves"] == 2
        assert count(server.runs, SINGLE_NODE) == 2 and count(server.committed, BATCH_NODE) == 2

    def test_a_batch_that_raises_is_written_one_cve_at_a_time(self, caplog):
        """The rest of the chunk is written whatever ``merge_cves_batch`` meets; each CVE gets merge_cve's result.
        2026-11: logged at WARNING like the client's fallback, counted in the stats and the metric."""
        neo4j = MagicMock()
        neo4j.merge_cves_batch.side_effect = RuntimeError("unexpected")
        neo4j.merge_cve.side_effect = [True, False, nc.neo4j_exceptions.TransientError("lock")]
        sync = MISPToNeo4jSync(neo4j_client=neo4j)
        before = _fallback_count("batch_writer_error")
        with caplog.at_level(logging.WARNING, logger="run_misp_to_neo4j"):
            results = sync._merge_cves([_cve(1), _cve(2), _cve(3)])
        assert results[:2] == [True, False] and isinstance(results[2], nc.neo4j_exceptions.TransientError)
        assert [c.kwargs["source_id"] for c in neo4j.merge_cve.call_args_list] == ["nvd"] * 3
        (line,) = [r for r in caplog.records if "[CVE-BATCH-FALLBACK]" in r.getMessage()]
        assert "merge_cves_batch raised RuntimeError" in line.getMessage() and "the 3 CVEs" in line.getMessage()
        assert line.levelno == logging.WARNING
        assert sync.stats["cve_batch_fallbacks"] == 1 and sync.stats["cve_batch_fallback_cves"] == 3
        assert _fallback_count("batch_writer_error") == before + 1

    def test_the_sync_hands_its_counter_to_the_batch_writer(self):
        """The client's fallbacks reach the stats through ``on_fallback``: a batch writer reporting one fallback of
        two CVEs is counted once."""
        neo4j = MagicMock()

        def batch(records, on_fallback=None, **_kw):
            on_fallback(2)
            return [True] * len(records)

        neo4j.merge_cves_batch.side_effect = batch
        sync = MISPToNeo4jSync(neo4j_client=neo4j)
        assert sync._merge_cves([_cve(1), _cve(2)]) == [True, True]
        assert sync.stats["cve_batch_fallbacks"] == 1 and sync.stats["cve_batch_fallback_cves"] == 2

    def test_an_exception_result_is_an_error_in_both_loops(self, caplog):
        """``_merge_cves`` returns the exception merge_cve raised for a CVE (2026-11); each loop raises it again where
        it counts and logs an error, so it is never counted as synced (an exception object is truthy). The other CVEs
        of the chunk are counted as before: True synced, False an error with [MERGE-RETURNED-FALSE]."""
        rich = [_cve(1), _cve(2), _cve(3)]
        plain = [{k: v for k, v in _cve(n).items() if k != "cvss_v31_data"} for n in (4, 5, 6)]
        neo4j = MagicMock()
        neo4j.merge_cves_batch.side_effect = [
            [True, False, nc.neo4j_exceptions.TransientError("rich lock")],
            [True, nc.neo4j_exceptions.TransientError("plain lock"), False],
        ]
        sync = MISPToNeo4jSync(neo4j_client=neo4j)
        with caplog.at_level(logging.WARNING, logger="run_misp_to_neo4j"):
            assert sync._sync_to_neo4j_chunk(rich + plain) == (2, 4)
        assert sync.stats["vulnerabilities_synced"] == 2
        messages = [r.getMessage() for r in caplog.records]
        assert [m for m in messages if m.startswith("merge_cve error for")] == [
            "merge_cve error for CVE-2026-1003: rich lock"
        ]
        assert [m for m in messages if "Error syncing plain CVE" in m] == [
            "[WARN] Error syncing plain CVE (CVE-2026-1005): TransientError: plain lock"
        ]
        assert [m.split(" source=")[0] for m in messages if "[MERGE-RETURNED-FALSE]" in m] == [
            "[MERGE-RETURNED-FALSE] rich CVE CVE-2026-1002",
            "[MERGE-RETURNED-FALSE] plain CVE CVE-2026-1006",
        ]

    def test_a_client_with_the_wrong_number_of_results_fails_the_chunk(self):
        neo4j = MagicMock()
        neo4j.merge_cves_batch.return_value = [True]
        with pytest.raises(RuntimeError, match="returned 1 results for 2 CVEs"):
            MISPToNeo4jSync(neo4j_client=neo4j)._merge_cves([_cve(1), _cve(2)])


# ---------------------------------------------------------------------------------------------- 4. the run summary
# The CVE attributes of event 138 ("EdgeGuard-nvd-2026-10-13") as the hosted MISP held them on 2026-10-14: 5 with CVSS,
# 2 without.
_EVENT_138 = [
    {k: v for k, v in attribute.items() if k != "_event"}
    for attribute in json.loads((TESTS / "test_cvss_real_payloads.json").read_text())["misp"].values()
    if attribute["event_id"] == "138"
]


class TestTheRunSummaryReportsFallbacks:
    """2026-11: the real ``run()`` over the real event, MISP faked below the event fetch, Neo4j a fake server. The run
    summary always reports the CVE batches written one CVE at a time (0 when none fell back); a fallback leaves the
    run green, since every CVE is written."""

    @pytest.fixture
    def run_sync(self, bolt, monkeypatch):
        import run_misp_to_neo4j

        monkeypatch.setenv("EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC", "0")
        monkeypatch.setattr(run_misp_to_neo4j.time, "sleep", lambda *_a, **_k: None)
        outcomes: Dict[str, Any] = {"success": 0, "failure": []}
        monkeypatch.setattr(
            run_misp_to_neo4j, "record_collection_success", lambda *_a, **_k: outcomes.__setitem__("success", 1)
        )
        monkeypatch.setattr(
            run_misp_to_neo4j, "record_collection_failure", lambda _s, msg=None: outcomes["failure"].append(msg)
        )
        monkeypatch.setitem(run_misp_to_neo4j.INDEX_FETCH_STATE, "truncated", False)

        def run(*rules) -> Tuple[MISPToNeo4jSync, bool, Dict[str, Any]]:
            _server, client = bolt(*rules)
            sync = MISPToNeo4jSync(neo4j_client=client)
            monkeypatch.setattr(sync, "check_services_available", lambda: (True, "ok"))
            monkeypatch.setattr(sync, "connect", lambda: True)
            info = "EdgeGuard-nvd-2026-10-13"
            monkeypatch.setattr(
                sync,
                "fetch_edgeguard_events",
                lambda since=None, sector=None: [{"id": "138", "info": info, "attribute_count": str(len(_EVENT_138))}],
            )
            monkeypatch.setattr(
                sync, "fetch_event_details", lambda _id: {"id": "138", "info": info, "Attribute": _EVENT_138, "Tag": []}
            )
            return sync, sync.run(incremental=False), outcomes

        return run

    @staticmethod
    def _summary(caplog) -> List[logging.LogRecord]:
        return [r for r in caplog.records if r.getMessage().startswith("CVE batches written one CVE at a time")]

    def test_a_fallback_is_in_the_run_summary(self, run_sync, caplog):
        with caplog.at_level(logging.INFO):
            sync, ok, outcomes = run_sync(fail(BATCH_NODE, TYPE_ERROR))  # the first batch: the 5 CVEs with CVSS
        assert ok is True and outcomes == {"success": 1, "failure": []}
        assert sync.stats["vulnerabilities_synced"] == 7 and sync.stats["errors"] == 0
        assert sync.stats["cve_batch_fallbacks"] == 1 and sync.stats["cve_batch_fallback_cves"] == 5
        (line,) = self._summary(caplog)
        assert line.getMessage().startswith(
            "CVE batches written one CVE at a time after a failed batched write: 1 (5 CVEs; grep '[CVE-BATCH-FALLBACK]'"
        )
        assert line.levelno == logging.WARNING

    def test_a_run_without_fallbacks_reports_zero(self, run_sync, caplog):
        with caplog.at_level(logging.INFO):
            sync, ok, _outcomes = run_sync()
        assert ok is True and sync.stats["vulnerabilities_synced"] == 7
        (line,) = self._summary(caplog)
        assert line.getMessage().startswith(
            "CVE batches written one CVE at a time after a failed batched write: 0 (0 CVEs"
        )
        assert line.levelno == logging.INFO
