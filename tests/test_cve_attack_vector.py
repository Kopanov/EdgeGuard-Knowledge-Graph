"""A CVE's attack vector (2026-10).

Measured on the hosted graph (2026-10-15): ``CVE.attack_vector`` mixed the letters of NVD's vector
strings (N 93,479, L 25,227, A 3,065, P 786), NVD's words (NETWORK 3,305, LOCAL 1,575,
ADJACENT_NETWORK 223, PHYSICAL 62) and an invented UNKNOWN (14,210). 147 CVEs showed NETWORK while
their CVSS 3.1 sub-node said LOCAL, ADJACENT_NETWORK or PHYSICAL, so ``attack_vector = 'NETWORK'``
missed most network-exploitable CVEs. The NVD collector sent the letter of the CVSS 3.x vector's
``AV`` metric (UNKNOWN without CVSS 3.x), the KEV and OTX collectors an invented NETWORK, MISPWriter
wrote UNKNOWN into NVD_META, the sync defaulted to UNKNOWN or NETWORK, and ``merge_cve`` wrote the
record's value, so the record merged last won.

The rule now follows the one for the score (``cvss_selection``): the attack vector of the CVSS that
gives the score, in NVD's words, null without CVSS. ``merge_cve`` derives the node's value from the
CVSS sub-nodes (``_CVE_SCORE_FROM_CVSS_QUERY``). The tests evaluate that Cypher with
``CypherExpression``, an evaluator for the expressions it uses; on 2026-10-15 Neo4j 2026.02 gave the
same results for the literal cases of ``TestDerivationCypher`` (a read-only RETURN query).

Fixtures are real (``test_cvss_real_payloads.json``): NVD CVE API 2.0 records, and attributes of the
hosted MISP written by the pre-fix code.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import neo4j_client  # noqa: E402
from collectors import otx_collector  # noqa: E402
from collectors.cisa_collector import CISACollector  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from collectors.nvd_collector import NVDCollector  # noqa: E402
from cvss_selection import (  # noqa: E402
    ATTACK_VECTOR_SPELLINGS,
    CVSS_VERSIONS,
    cvss_attack_vector,
    normalize_attack_vector,
    payload_attack_vector,
)
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

PAYLOADS = json.loads((Path(__file__).resolve().parent / "test_cvss_real_payloads.json").read_text())
NVD = PAYLOADS["nvd"]
MISP = PAYLOADS["misp"]
WORDS = {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}


# ---------------------------------------------------------------- helpers
def _vector(cve_id: str, metric: str) -> str:
    """``vectorString`` of the first ``metric`` (``cvssMetricV31`` …) of an NVD record of the fixture."""
    return NVD[cve_id]["cve"]["metrics"][metric][0]["cvssData"]["vectorString"]


def _nvd_item(cve_id: str) -> dict:
    collector = NVDCollector.__new__(NVDCollector)
    collector.tag = "nvd"
    return collector._vulnerability_item(copy.deepcopy(NVD[cve_id]))


def _meta(attribute: dict) -> dict:
    comment = attribute["comment"]
    assert comment.startswith("NVD_META:")
    return json.loads(comment[len("NVD_META:") :])


def _write(item: dict) -> dict:
    return MISPWriter.__new__(MISPWriter).create_vulnerability_attribute(dict(item))


def _parse(attribute: dict) -> dict:
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    event = {"id": attribute.get("event_id"), "info": (attribute.get("_event") or {}).get("info", ""), "Tag": []}
    item, _ = syncer.parse_attribute({k: v for k, v in attribute.items() if k != "_event"}, event)
    assert item is not None
    return item


def _stored(payload: dict) -> dict:
    """The CVSS sub-node ``_merge_cvss_node`` stores for a payload: None and "" are not set."""
    return {k: v for k, v in payload.items() if v is not None and v != ""}


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


def _kev_item() -> dict:
    collector = CISACollector.__new__(CISACollector)
    collector.tag = "cisa_kev"
    entry = {
        "cveID": "CVE-2015-5477",
        "vendorProject": "ISC",
        "product": "BIND",
        "vulnerabilityName": "ISC BIND Denial-of-Service Vulnerability",
        "shortDescription": "named in ISC BIND allows remote attackers to cause a denial of service.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dateAdded": "2022-03-25",
        "dueDate": "2022-04-15",
        "knownRansomwareCampaignUse": "Unknown",
        "cwes": ["CWE-617"],
        "notes": "",
    }
    with patch.object(CISACollector, "_fetch_kev", return_value=[entry]):
        items = collector.collect(limit=None, push_to_misp=False, baseline=True)
    assert isinstance(items, list) and len(items) == 1
    return items[0]


def _otx_cve_item() -> dict:
    collector = otx_collector.OTXCollector.__new__(otx_collector.OTXCollector)
    collector.api_key = "a" * 64
    collector.tag = "alienvault_otx"
    collector.session = MagicMock()
    collector.rate_limiter = MagicMock()
    collector._last_http_status = 200
    collector.circuit_breaker = MagicMock()
    collector.misp_writer = None
    collector.source_name = "otx"
    pulse = {
        "id": "6aa4409a4290cc035d81500c",
        "name": "BIND TKEY exploitation",
        "created": "2026-10-01T08:00:00",
        "modified": "2026-10-02T08:00:00",
        "TLP": "white",
        "cve_references": ["CVE-2015-5477"],
        "indicators": [],
    }
    pages = iter([[pulse]])
    with (
        patch.object(collector, "check_service_available", return_value=True),
        patch.object(collector, "_fetch_pulses", side_effect=lambda **_kw: next(pages, [])),
        patch.object(otx_collector.time, "sleep"),
        patch.object(otx_collector, "get_source_incremental", return_value={}),
        patch.object(otx_collector, "update_source_incremental"),
    ):
        items = collector.collect(limit=10, push_to_misp=False, baseline=False)
    (item,) = [i for i in items if i.get("type") == "vulnerability"]
    return item


# ---------------------------------------------------------------- a Cypher expression evaluator
_KEYWORDS = {"CASE", "WHEN", "THEN", "ELSE", "END", "IS", "NOT", "NULL", "IN", "WHERE", "STARTS", "WITH"}
_TOKEN = re.compile(r"\s*(?:'([^']*)'|(\d+)|([A-Za-z_]\w*)|(\S))")
_Fn = Callable[[Dict[str, Any]], Any]


def _to_string_or_null(value: Any) -> Optional[str]:
    if value is None or isinstance(value, (list, dict)):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


_FUNCTIONS: Dict[str, Callable[..., Any]] = {
    "coalesce": lambda *args: next((a for a in args if a is not None), None),
    "toUpper": lambda s: None if s is None else s.upper(),
    "trim": lambda s: None if s is None else s.strip(),
    "toStringOrNull": _to_string_or_null,
    "split": lambda s, sep: None if s is None or sep is None else s.split(sep),
    "head": lambda items: items[0] if items else None,
    "substring": lambda s, start: None if s is None else s[start:],
}


def _equals(a: Any, b: Any) -> Optional[bool]:
    return None if a is None or b is None else a == b


class CypherExpression:
    """Evaluates the Cypher expressions the attack-vector derivation is built from, with Cypher's
    null semantics: simple and searched CASE, ``IS [NOT] NULL``, ``=``, ``STARTS WITH``, list
    comprehensions, ``list[i]``, ``map.key`` and the functions in ``_FUNCTIONS``. Anything else is a
    ``SyntaxError`` or a ``KeyError``, so a construct the evaluator does not know cannot pass."""

    def __init__(self, text: str):
        self._tokens: List[Tuple[str, Any]] = []
        for match in _TOKEN.finditer(text.strip()):
            string, number, word, other = match.groups()
            if string is not None:
                self._tokens.append(("str", string))
            elif number is not None:
                self._tokens.append(("num", int(number)))
            elif word is not None:
                self._tokens.append(("kw", word.upper()) if word.upper() in _KEYWORDS else ("id", word))
            else:
                self._tokens.append(("op", other))
        self._i = 0
        self._fn = self._expr()
        if self._i != len(self._tokens):
            raise SyntaxError(f"not an expression from token {self._i}: {self._tokens[self._i : self._i + 5]}")

    def __call__(self, **variables: Any) -> Any:
        return self._fn(variables)

    def _peek(self) -> Tuple[Optional[str], Any]:
        return self._tokens[self._i] if self._i < len(self._tokens) else (None, None)

    def _accept(self, kind: str, value: Any) -> bool:
        if self._peek() == (kind, value):
            self._i += 1
            return True
        return False

    def _take(self, kind: str, value: Any = None) -> Any:
        token = self._peek()
        if token[0] != kind or (value is not None and token[1] != value):
            raise SyntaxError(f"expected {kind} {value!r} at token {self._i}, got {token}")
        self._i += 1
        return token[1]

    def _expr(self) -> _Fn:
        left = self._postfix()
        if self._accept("kw", "IS"):
            negate = self._accept("kw", "NOT")
            self._take("kw", "NULL")
            return lambda env: (left(env) is None) != negate
        if self._accept("op", "="):
            right = self._postfix()
            return lambda env: _equals(left(env), right(env))
        if self._accept("kw", "STARTS"):
            self._take("kw", "WITH")
            prefix = self._postfix()

            def starts_with(env: Dict[str, Any]) -> Optional[bool]:
                value, start = left(env), prefix(env)
                return None if value is None or start is None else value.startswith(start)

            return starts_with
        return left

    def _postfix(self) -> _Fn:
        node = self._primary()
        while True:
            if self._accept("op", "["):
                index = self._expr()
                self._take("op", "]")
                node = self._indexed(node, index)
            elif self._accept("op", "."):
                node = self._property(node, self._take("id"))
            else:
                return node

    @staticmethod
    def _indexed(base: _Fn, index: _Fn) -> _Fn:
        def run(env: Dict[str, Any]) -> Any:
            items, i = base(env), index(env)
            if items is None or i is None:
                return None
            return items[i] if -len(items) <= i < len(items) else None

        return run

    @staticmethod
    def _property(base: _Fn, name: str) -> _Fn:
        def run(env: Dict[str, Any]) -> Any:
            value = base(env)
            return None if value is None else value.get(name)

        return run

    def _primary(self) -> _Fn:
        kind, value = self._peek()
        if kind in ("str", "num"):
            self._i += 1
            return lambda env: value
        if self._accept("kw", "NULL"):
            return lambda env: None
        if (kind, value) == ("kw", "CASE"):
            return self._case()
        if (kind, value) == ("op", "["):
            return self._comprehension()
        if kind == "id":
            self._i += 1
            if not self._accept("op", "("):
                return lambda env: env[value]
            args = [] if self._peek() == ("op", ")") else [self._expr()]
            while self._accept("op", ","):
                args.append(self._expr())
            self._take("op", ")")
            function = _FUNCTIONS[value]
            return lambda env: function(*[arg(env) for arg in args])
        raise SyntaxError(f"unexpected token {self._i}: {(kind, value)}")

    def _case(self) -> _Fn:
        self._take("kw", "CASE")
        subject = None if self._peek() == ("kw", "WHEN") else self._expr()
        branches = []
        while self._accept("kw", "WHEN"):
            when = self._expr()
            self._take("kw", "THEN")
            branches.append((when, self._expr()))
        otherwise: _Fn = self._expr() if self._accept("kw", "ELSE") else (lambda env: None)
        self._take("kw", "END")

        def run(env: Dict[str, Any]) -> Any:
            tested = subject(env) if subject else None
            for when, then in branches:
                if (_equals(tested, when(env)) if subject else when(env)) is True:
                    return then(env)
            return otherwise(env)

        return run

    def _comprehension(self) -> _Fn:
        self._take("op", "[")
        variable = self._take("id")
        self._take("kw", "IN")
        source = self._expr()
        where = self._expr() if self._accept("kw", "WHERE") else None
        project = self._expr() if self._accept("op", "|") else None
        self._take("op", "]")

        def run(env: Dict[str, Any]) -> Any:
            items = source(env)
            if items is None:
                return None
            out = []
            for item in items:
                scope = {**env, variable: item}
                if where is None or where(scope) is True:
                    out.append(project(scope) if project else item)
            return out

        return run


def _derivation() -> CypherExpression:
    """The attack-vector expression of the statement ``merge_cve`` runs last (it ends the SET)."""
    query = neo4j_client._CVE_SCORE_FROM_CVSS_QUERY
    assert "c.attack_vector = " in query, "merge_cve must derive the attack vector with the score"
    return CypherExpression(query.split("c.attack_vector = ", 1)[1])


# ---------------------------------------------------------------- 1. the helper
class TestNormalizeAttackVector:
    @pytest.mark.parametrize(
        "value, word",
        [
            ("NETWORK", "NETWORK"),
            ("ADJACENT_NETWORK", "ADJACENT_NETWORK"),
            ("LOCAL", "LOCAL"),
            ("PHYSICAL", "PHYSICAL"),
            ("ADJACENT", "ADJACENT_NETWORK"),  # CVSS 4.0's word
            ("network", "NETWORK"),
            (" Local ", "LOCAL"),
        ],
    )
    def test_words(self, value, word):
        assert normalize_attack_vector(value) == word

    @pytest.mark.parametrize(
        "letter, word",
        [("N", "NETWORK"), ("A", "ADJACENT_NETWORK"), ("L", "LOCAL"), ("P", "PHYSICAL"), ("n", "NETWORK")],
    )
    def test_letters_of_the_vector_strings(self, letter, word):
        # What the NVD collector sent until 2026-10 (93,479 CVE nodes showed "N").
        assert normalize_attack_vector(letter) == word

    @pytest.mark.parametrize(
        "vector, word",
        [
            (_vector("CVE-2008-4250", "cvssMetricV2"), "NETWORK"),  # AV:N/AC:L/Au:N/C:C/I:C/A:C
            (_vector("CVE-2014-9323", "cvssMetricV2").replace("AV:N", "AV:A"), "ADJACENT_NETWORK"),
            (_vector("CVE-2026-107153", "cvssMetricV30"), "PHYSICAL"),
            (_vector("CVE-2025-12843", "cvssMetricV31"), "LOCAL"),
            (_vector("CVE-2026-84994", "cvssMetricV40"), "NETWORK"),
            (_vector("CVE-2025-12843", "cvssMetricV40").replace("/AV:L/", "/AV:A/"), "ADJACENT_NETWORK"),
            # Only the metric named AV counts, not CVSS 4.0's modified attack vector MAV.
            (_vector("CVE-2026-107153", "cvssMetricV40").replace("MAV:X", "MAV:N"), "PHYSICAL"),
        ],
        ids=["v2", "v2-adjacent", "v3.0", "v3.1", "v4.0", "v4.0-adjacent", "v4.0-mav"],
    )
    def test_vector_strings_of_cvss_2_3x_and_40(self, vector, word):
        assert normalize_attack_vector(vector) == word

    @pytest.mark.parametrize("value", [None, "", "UNKNOWN", "X", "AV:X", "CVSS:3.1/AC:L/PR:N", ["NETWORK"]])
    def test_anything_else_is_none(self, value):
        assert normalize_attack_vector(value) is None

    def test_every_spelling_is_one_of_nvds_words(self):
        assert set(ATTACK_VECTOR_SPELLINGS.values()) == WORDS
        assert all(ATTACK_VECTOR_SPELLINGS[word] == word for word in WORDS)


class TestCvssAttackVector:
    """The attack vector of the payload ``select_cvss`` picks, as the sync reads NVD_META."""

    def test_the_payload_that_gives_the_score(self):
        v31_local = _meta(MISP["CVE-2025-7223__source:CISA-ICS"])["cvss_v31_data"]
        v40_network = _meta(MISP["CVE-2025-14272__source:NVD"])["cvss_v40_data"]
        assert cvss_attack_vector({"cvss_v31_data": v31_local, "cvss_v40_data": v40_network}) == "LOCAL"
        assert cvss_attack_vector({"cvss_v40_data": v40_network}) == "NETWORK"

    def test_a_payload_whose_score_is_rejected_is_skipped_as_by_select_cvss(self):
        v31_local = dict(_meta(MISP["CVE-2025-7223__source:CISA-ICS"])["cvss_v31_data"], base_score="1e309")
        v40_network = _meta(MISP["CVE-2025-14272__source:NVD"])["cvss_v40_data"]
        assert cvss_attack_vector({"cvss_v31_data": v31_local, "cvss_v40_data": v40_network}) == "NETWORK"

    def test_cvss_2_reads_access_vector_then_the_vector_string(self):
        v2 = _nvd_item("CVE-2014-9323")["cvss_v2_data"]
        assert (v2["access_vector"], v2["vector_string"][:5]) == ("NETWORK", "AV:N/")
        assert cvss_attack_vector({"cvss_v2_data": v2}) == "NETWORK"
        assert cvss_attack_vector({"cvss_v2_data": dict(v2, access_vector="ADJACENT_NETWORK")}) == "ADJACENT_NETWORK"
        assert cvss_attack_vector({"cvss_v2_data": dict(v2, access_vector="")}) == "NETWORK"

    def test_no_cvss_is_none(self):
        assert cvss_attack_vector({}) is None
        kev_meta = _meta(MISP["CVE-2026-59310__kev_known"])
        assert kev_meta["attack_vector"] == "NETWORK", "the KEV collector's invented value"
        assert cvss_attack_vector(kev_meta) is None


# ---------------------------------------------------------------- 2. the node: merge_cve's Cypher
_V31 = _stored(_meta(MISP["CVE-2025-7223__source:CISA-ICS"])["cvss_v31_data"])  # AV:L, attack_vector LOCAL
_V30 = _stored(_meta(MISP["CVE-2025-7223__source:NVD"])["cvss_v30_data"])  # AV:L, attack_vector LOCAL
_V2 = _stored(_nvd_item("CVE-2014-9323")["cvss_v2_data"])  # AV:N, access_vector NETWORK
_V40 = _stored(_meta(MISP["CVE-2026-6039__source:NVD"])["cvss_v40_data"])  # AV:L, no attack_vector field


class TestDerivationCypher:
    def test_text(self):
        query = neo4j_client._CVE_SCORE_FROM_CVSS_QUERY
        assert "c.attack_vector = " in query
        derived = query.split("c.attack_vector = ", 1)[1]
        assert derived.startswith("CASE WHEN best IS NULL THEN null ELSE coalesce(")
        assert (
            "CASE best[1] WHEN '3.1' THEN best[0].attack_vector WHEN '3.0' THEN best[0].attack_vector "
            "WHEN '2.0' THEN best[0].access_vector END"
        ) in derived
        assert (
            "head([m IN split(trim(toStringOrNull(best[0].vector_string)), '/') "
            "WHERE m STARTS WITH 'AV:' | substring(m, 3)])"
        ) in derived
        for spelling, word in ATTACK_VECTOR_SPELLINGS.items():
            assert derived.count(f"WHEN '{spelling}' THEN '{word}'") == 2, "for the field and for the vector"
        # One statement with the score, from the same ``best``: derived after the sub-nodes, last in merge_cve.
        assert query.index("c.severity = ") < query.index("c.attack_vector = ")

    @pytest.mark.parametrize(
        "version, node, word",
        [
            ("3.1", _V31, "LOCAL"),
            ("3.1", dict(_V31, attack_vector="L"), "LOCAL"),  # a letter in the field
            ("3.1", dict(_V31, vector_string="CVSS:3.1/AV:N/AC:L"), "LOCAL"),  # the field comes first
            ("3.1", {k: v for k, v in _V31.items() if k != "attack_vector"}, "LOCAL"),  # else the vector
            ("3.0", _V30, "LOCAL"),
            ("3.0", dict(_V30, attack_vector="PHYSICAL"), "PHYSICAL"),
            ("2.0", _V2, "NETWORK"),
            ("2.0", dict(_V2, access_vector="ADJACENT_NETWORK"), "ADJACENT_NETWORK"),  # access_vector, not the vector
            ("2.0", dict(_V2, attack_vector="PHYSICAL"), "NETWORK"),  # CVSS 2 has no attack_vector field
            ("4.0", _V40, "LOCAL"),  # the vector string's AV metric
            ("4.0", dict(_V40, attack_vector="NETWORK"), "LOCAL"),  # CVSS 4.0 reads only the vector string
            ("4.0", dict(_V40, vector_string=_V40["vector_string"].replace("/AV:L/", "/AV:A/")), "ADJACENT_NETWORK"),
            ("3.1", {"base_score": 5.5}, None),  # neither field nor vector
        ],
    )
    def test_case_logic_for_each_version(self, version, node, word):
        assert _derivation()(best=[node, version]) == word

    def test_null_without_cvss(self):
        assert _derivation()(best=None) is None

    def test_node_and_sync_agree_on_every_real_payload(self):
        """Each CVSS payload of the fixtures, stored as merge_cve stores it: the node's value is the
        sync's (``payload_attack_vector``) and one of NVD's words."""
        cases = []
        for cve_id in NVD:
            item = _nvd_item(cve_id)
            cases += [(cve_id, v, item[v.payload_key]) for v in CVSS_VERSIONS if item.get(v.payload_key)]
        for key, attribute in MISP.items():
            if attribute["comment"].startswith("NVD_META:"):
                meta = _meta(attribute)
                cases += [(key, v, meta[v.payload_key]) for v in CVSS_VERSIONS if meta.get(v.payload_key)]
        assert len(cases) >= 15 and {v.version for _k, v, _p in cases} == {"3.1", "3.0", "2.0", "4.0"}
        derivation = _derivation()
        for key, version, payload in cases:
            node = _stored(payload)
            derived = derivation(best=[node, version.version])
            assert derived == payload_attack_vector(node, version) and derived in WORDS, (key, version.version)

    def test_cvss_40_gives_nvds_own_attack_vector(self):
        """The collector keeps no attack_vector field for CVSS 4.0; the vector string must give the
        value NVD states in cvssData.attackVector."""
        derivation = _derivation()
        checked = 0
        for cve_id, record in NVD.items():
            metrics = record["cve"].get("metrics", {})
            if metrics.get("cvssMetricV40"):
                stated = metrics["cvssMetricV40"][0]["cvssData"]["attackVector"]
                node = _stored(_nvd_item(cve_id)["cvss_v40_data"])
                assert "attack_vector" not in node
                assert derivation(best=[node, "4.0"]) == normalize_attack_vector(stated), cve_id
                checked += 1
        assert checked == 3


class TestMergeCve:
    def test_the_record_value_is_not_written_and_the_node_value_is_derived_last(self):
        client, session = _recording_client()
        item = _parse(MISP["CVE-2025-7223__source:NVD"])
        assert (item["cvss_version"], item["attack_vector"]) == ("3.0", "LOCAL")
        assert client.merge_cve(item, source_id="nvd")
        queries = [c.args[0] for c in session.run.call_args_list if c.args]
        merge = next(q for q in queries if "MERGE (n:CVE" in q)
        assert "attack_vector" not in merge, "the record merged last must not set the node's attack vector"
        assert queries[-1] == neo4j_client._CVE_SCORE_FROM_CVSS_QUERY and "c.attack_vector = " in queries[-1]


# ---------------------------------------------------------------- 3. the sync
EXPECTED_SYNC = {
    # attribute of the hosted MISP: item attack_vector (NVD_META's own value in the comment)
    "CVE-2026-6039__source:NVD": "LOCAL",  # CVSS 4.0 AV:L (UNKNOWN)
    "CVE-2025-7223__source:NVD": "LOCAL",  # CVSS 3.0 (L)
    "CVE-2025-7223__source:CISA-ICS": "LOCAL",  # CVSS 3.1 (LOCAL)
    "CVE-2026-44956__source:NVD": "NETWORK",  # CVSS 3.0 scored 0.0 (N)
    "CVE-2015-5477__source:AlienVault-OTX": None,  # no NVD_META (the sync used NETWORK)
    "CVE-2015-5477__source:CISA-KEV": None,  # no CVSS (NETWORK)
    "CVE-2025-21042__source:AlienVault-OTX": None,
    "CVE-2025-21042__source:NVD": "NETWORK",  # CVSS 3.1 (N)
    "CVE-2025-21042__source:CISA-KEV": None,  # (NETWORK)
    "CVE-2025-14272__source:NVD": "NETWORK",  # CVSS 4.0 AV:N (UNKNOWN)
    "CVE-2025-14272__source:CISA-ICS": "NETWORK",  # CVSS 3.1 (NETWORK)
    "CVE-2026-54292__nvd_rejected": None,  # (UNKNOWN)
    "CVE-2026-64019__nvd_no_cvss_active": None,  # (UNKNOWN)
    "CVE-2026-59310__kev_known": None,  # (NETWORK)
    "CVE-2026-7891__ics_no_cvss": None,  # (NETWORK, the ICS default)
}


class TestSyncItem:
    def test_an_nvd_record_with_cvss_31_local(self):
        """NVD's record of CVE-2025-12843 (CVSS 3.1 AV:L) through the collector, MISPWriter and the sync."""
        attribute = _write(_nvd_item("CVE-2025-12843"))
        assert _meta(attribute)["attack_vector"] == "LOCAL"
        item = _parse(attribute)
        assert (item["cvss_version"], item["attack_vector"]) == ("3.1", "LOCAL")
        # The pre-fix collector wrote the letter into NVD_META; the sync reads the CVSS, not that key.
        legacy = dict(attribute, comment="NVD_META:" + json.dumps(dict(_meta(attribute), attack_vector="L")))
        assert _parse(legacy)["attack_vector"] == "LOCAL"

    def test_a_kev_record_without_cvss_has_none(self):
        attribute = MISP["CVE-2015-5477__source:CISA-KEV"]
        assert _meta(attribute)["attack_vector"] == "NETWORK", "invented by the pre-fix KEV collector"
        assert _parse(attribute)["attack_vector"] is None
        assert _parse(_write(_kev_item()))["attack_vector"] is None

    def test_an_otx_reference_has_none(self):
        attribute = MISP["CVE-2015-5477__source:AlienVault-OTX"]
        assert not attribute["comment"].startswith("NVD_META:")
        assert _parse(attribute)["attack_vector"] is None

    def test_every_hosted_attribute(self):
        assert set(EXPECTED_SYNC) == set(MISP)
        assert {key: _parse(attribute)["attack_vector"] for key, attribute in MISP.items()} == EXPECTED_SYNC


# ---------------------------------------------------------------- 4. collectors and MISPWriter
EXPECTED_NVD = {
    # cve_id: item attack_vector (the pre-fix value)
    "CVE-2008-4250": "NETWORK",  # CVSS 3.1 gives the score (N)
    "CVE-2014-9323": "NETWORK",  # CVSS 2 only (UNKNOWN)
    "CVE-2025-12843": "LOCAL",  # CVSS 3.1 (L)
    "CVE-2025-59823": "NETWORK",  # CVSS 3.0 only (N)
    "CVE-2026-102699": None,  # no CVSS (UNKNOWN)
    "CVE-2026-105151": None,  # rejected (UNKNOWN)
    "CVE-2026-107153": "PHYSICAL",  # CVSS 3.0 gives the score, CVSS 4.0 too (P)
    "CVE-2026-84994": "NETWORK",  # CVSS 4.0 only (UNKNOWN)
}


class TestCollectorsAndWriter:
    def test_nvd_items_carry_nvds_word_for_the_cvss_that_gives_the_score(self):
        assert {cve_id: _nvd_item(cve_id)["attack_vector"] for cve_id in NVD} == EXPECTED_NVD

    def test_nvd_meta_carries_the_same(self):
        assert {cve_id: _meta(_write(_nvd_item(cve_id)))["attack_vector"] for cve_id in NVD} == EXPECTED_NVD

    def test_kev_and_otx_items_name_no_attack_vector(self):
        assert "attack_vector" not in _kev_item()
        assert "attack_vector" not in _otx_cve_item()

    def test_writer_writes_null_instead_of_unknown_and_nvds_word_for_a_letter(self):
        meta = _meta(_write(_kev_item()))
        assert "attack_vector" in meta and meta["attack_vector"] is None
        assert _meta(_write(dict(_nvd_item("CVE-2025-12843"), attack_vector="L")))["attack_vector"] == "LOCAL"
