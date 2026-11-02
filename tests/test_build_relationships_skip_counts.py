"""What ``build_relationships`` counts and logs (2026-11-02).

* The technique steps translate a revoked ATT&CK id before they match it. The six ``[SKIP]`` counts
  re-bound the UNWIND variable to the translated id (``UNWIND x AS tid WITH coalesce(..., tid) AS
  tid WHERE NOT EXISTS {...}``); on Neo4j 2026.03.1 a subquery in that ``WHERE`` reads the UNWIND
  binding, the untranslated id, so every revoked id whose successor exists counted as a skip (the
  730-day baseline of 2026-11-01 logged 44,268 for step 8; 21,207 rows lack a technique). No
  statement re-binds a name to an expression of itself any more; the Neo4j behaviour is in
  ``tests/test_build_relationships_skip_counts_neo4j.py``.
* A ``[SKIP]`` count that fails is logged at WARNING (it was DEBUG, and its line went missing).
* Step 2 (``Malware.attributed_to``, which no writer produces) keeps its slot and runs no query.
* The summary line reports the relationships the steps created and the outer rows apart; the outer
  rows were logged as ``total_edges``. The figures come from the 730-day log's ``[OK]`` lines.
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import build_relationships as br  # noqa: E402

# --------------------------------------------------------------------------- statements as they run


class _Client:
    """Answers every read with one row that satisfies the readers of the run's set-up (folded names,
    the pulses naming several actors) and the pre-counts."""

    def connect(self):
        return True

    def close(self):
        pass

    def run(self, query, *args, **kwargs):
        return [{"count": 0, "c": 0, "reports": [], "pulses": [], "indicators": 0}]


def _sent_statements(monkeypatch) -> List[Tuple[str, str, Optional[str]]]:
    """Every (label, outer, inner, skip) the run hands to ``_safe_run_batched``, without a database."""
    sent: list = []

    def _batched(client, label, outer, inner, stats, key, batch_size=5000, skip_query=None, params=None):
        sent.append((label, outer, inner, skip_query))
        stats[key] = 0
        return True

    monkeypatch.setattr(br, "Neo4jClient", _Client)
    monkeypatch.setattr(br, "_safe_run_batched", _batched)
    monkeypatch.setattr(br, "query_pause", lambda: None)
    br.build_relationships()
    return sent


# --------------------------------------------------------------------------- re-binding detector

_TOKEN = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|\$?[A-Za-z_][A-Za-z0-9_]*|\S")
# A projection item starts after a top-level comma or one of these keywords.
_ITEM_START = {"WITH", "RETURN", "UNWIND", "DISTINCT", "YIELD", "WHERE", "MATCH", "MERGE", "SET", "CALL", "AND"}


def _rebinds(statement: str) -> List[str]:
    """The names a statement binds with ``AS name`` to an expression that reads ``name`` itself
    (``coalesce($m[toString(tid)], tid) AS tid``). Map keys (``{mitre_id: tid}`` names ``mitre_id``),
    properties (``a.tid``), parameters (``$tid``) and string literals are not reads of the name."""
    tokens = _TOKEN.findall(statement)
    found = []
    for i, token in enumerate(tokens):
        if token.upper() != "AS" or i + 1 >= len(tokens):
            continue
        name = tokens[i + 1]
        depth = 0
        j = i - 1
        expression: List[Tuple[int, str]] = []
        while j >= 0:
            t = tokens[j]
            if t in ")]}":
                depth += 1
            elif t in "([{":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and (t == "," or t.upper() in _ITEM_START):
                break
            expression.append((j, t))
            j -= 1
        for k, t in expression:
            if t != name:
                continue
            before = tokens[k - 1] if k > 0 else ""
            after = tokens[k + 1] if k + 1 < len(tokens) else ""
            if before != "." and after != ":":
                found.append(name)
                break
    return found


class TestTheDetector:
    """The detector flags the statements as they were before 2026-11-02 and passes them as they are."""

    OLD_SKIP = (
        "MATCH (a:ThreatActor) WHERE size(coalesce(a.reported_techniques, [])) > 0 "
        "UNWIND a.reported_techniques AS tid "
        "WITH coalesce($revoked[toString(tid)], tid) AS tid WHERE NOT EXISTS { MATCH (t:Technique {mitre_id: tid}) } "
        "RETURN count(*) AS c"
    )
    OLD_LINK = (
        "UNWIND i.attack_ids AS tech_id WITH i, tech_id AS _cited, coalesce($revoked[toString(tech_id)], tech_id) "
        "AS tech_id, _prov_sources MATCH (t:Technique {mitre_id: tech_id}) RETURN t"
    )

    def test_it_flags_the_old_skip_and_link_statements(self):
        assert _rebinds(self.OLD_SKIP) == ["tid"]
        assert _rebinds(self.OLD_LINK) == ["tech_id"]

    def test_it_passes_the_renamed_forms_and_ordinary_projections(self):
        assert (
            _rebinds(
                self.OLD_SKIP.replace("AS tid ", "AS _cited ", 1).replace(
                    "toString(tid)], tid)", "toString(_cited)], _cited)"
                )
            )
            == []
        )
        assert _rebinds("WITH $a AS a MATCH (t:Technique {mitre_id: a.tid}) RETURN count(*) AS c") == []
        assert _rebinds("WITH r, 'r' AS r2 RETURN r.c AS c") == []


def test_no_statement_rebinds_a_name_to_an_expression_of_itself(monkeypatch):
    sent = _sent_statements(monkeypatch)
    assert len(sent) == 19
    found = {
        (label, kind): names
        for label, outer, inner, skip in sent
        for kind, statement in (("outer", outer), ("inner", inner), ("skip", skip))
        if statement and (names := _rebinds(statement))
    }
    assert found == {}


TECHNIQUE_SKIPS = {
    "ThreatActor → Technique (ATT&CK explicit)": ("a.uses_techniques", "tid"),
    "ThreatActor → Technique (reported)": ("a.reported_techniques", "tid"),
    "Malware → Technique (MITRE explicit)": ("m.uses_techniques", "tid"),
    "Malware → Technique (reported)": ("m.reported_techniques", "tid"),
    "Indicator → Technique (attack_ids)": ("i.attack_ids", "tech_id"),
    "Tool → Technique (MITRE explicit)": ("tool.uses_techniques", "tid"),
}


def test_the_technique_skip_counts_match_the_translated_id(monkeypatch):
    skips = {label: skip for label, _o, _i, skip in _sent_statements(monkeypatch) if label in TECHNIQUE_SKIPS}
    assert set(skips) == set(TECHNIQUE_SKIPS)
    for label, (prop, var) in TECHNIQUE_SKIPS.items():
        assert (
            f"UNWIND {prop} AS _cited WITH coalesce($revoked[toString(_cited)], _cited) AS {var} "
            f"WHERE NOT EXISTS {{ MATCH (t:Technique {{mitre_id: {var}}}) }}"
        ) in " ".join(skips[label].split()), label


def test_the_link_statements_record_the_cited_id(monkeypatch):
    """The link statements translate the id the same way and keep the cited id for ``r.cited_ids``."""
    inners = {label: inner for label, _o, inner, _s in _sent_statements(monkeypatch) if label in TECHNIQUE_SKIPS}
    for label, (prop, var) in TECHNIQUE_SKIPS.items():
        assert f"UNWIND {prop} AS _cited WITH " in inners[label], label
        assert f", _cited, coalesce($revoked[toString(_cited)], _cited) AS {var}, " in inners[label], label
        assert f"MATCH (t:Technique {{mitre_id: {var}}})" in inners[label], label
        assert f"r.cited_ids = CASE WHEN {var} = _cited THEN r.cited_ids" in inners[label], label


# --------------------------------------------------------------------------- step 2


def test_step_2_keeps_its_slot_and_runs_no_query(monkeypatch, caplog):
    with caplog.at_level(logging.INFO, logger=br.logger.name):
        sent = _sent_statements(monkeypatch)
    statements = [s for _label, outer, inner, skip in sent for s in (outer, inner, skip) if s]
    assert not [s for s in statements if re.search(r"\.attributed_to\b", s)], (
        "no statement reads a node's attributed_to"
    )
    assert "Malware → ThreatActor" not in [label for label, *_ in sent]
    banners = [r.getMessage() for r in caplog.records if r.getMessage().startswith("[LINK] 2/20 ")]
    assert banners == [
        "[LINK] 2/20 Malware → ThreatActor (exact name match): [SKIP] no writer produces Malware.attributed_to; "
        "no query runs"
    ]


# --------------------------------------------------------------------------- a failed [SKIP] count


class _ApocClient:
    """``client.run``: the skip count raises (or answers ``skip``), the pre-count answers ``rows``, and the
    ``apoc.periodic.iterate`` call answers ``apoc_row``."""

    def __init__(self, apoc_row: Dict, skip_error: Optional[Exception] = None, skip: int = 0):
        self.apoc_row = apoc_row
        self.skip_error = skip_error
        self.skip = skip

    def run(self, query, params=None):
        if "apoc.periodic.iterate" in query:
            return [self.apoc_row]
        if query.startswith("CALL {"):
            return [{"c": self.apoc_row["count"]}]
        if self.skip_error is not None:
            raise self.skip_error
        return [{"c": self.skip}]


def _apoc_row(rows: int, created: Optional[int], batches: int = 1, errors: Optional[Dict] = None) -> Dict:
    stats = {} if created is None else {"relationshipsCreated": created}
    return {
        "count": rows,
        "batches": batches,
        "errorMessages": errors or {},
        "failedBatches": 1 if errors else 0,
        "failedOperations": 0,
        "wasTerminated": False,
        "batch": {"failed": 1 if errors else 0, "errors": errors or {}},
        "operations": {"failed": 0, "errors": {}},
        "updateStatistics": stats,
    }


def test_a_failed_skip_count_is_a_warning(caplog):
    client = _ApocClient(_apoc_row(130419, 1565094, 27), skip_error=RuntimeError("Neo.ClientError.Statement"))
    stats = br._StepStats()
    with caplog.at_level(logging.DEBUG, logger=br.logger.name):
        assert br._safe_run_batched(client, "Indicator → Technique (attack_ids)", "o", "i", stats, "k", skip_query="s")
    (line,) = [r for r in caplog.records if "count of input rows without a target failed" in r.getMessage()]
    assert line.levelno == logging.WARNING
    assert "Indicator → Technique (attack_ids)" in line.getMessage() and "RuntimeError" in line.getMessage()


def test_a_skip_count_is_logged_with_its_reason(caplog):
    client = _ApocClient(_apoc_row(130419, 1565094, 27), skip=21207)
    with caplog.at_level(logging.INFO, logger=br.logger.name):
        br._safe_run_batched(
            client, "Indicator → Technique (attack_ids)", "o", "i", br._StepStats(), "k", skip_query="s"
        )
    assert "  [SKIP] Indicator → Technique (attack_ids): 21207 input rows had no matching target node" in [
        r.getMessage()[
            : len("  [SKIP] Indicator → Technique (attack_ids): 21207 input rows had no matching target node")
        ]
        for r in caplog.records
    ]


# --------------------------------------------------------------------------- the summary line

# The ``[OK]`` lines of build_relationships on the 730-day baseline of 2026-11-01 (task log
# build_relationships.log): label, outer rows, relationships created. Left out: step 2 ("Malware →
# ThreatActor", 0 rows, 0 created), which runs no query now, and step 2d's removal and trim (0 rows, 0
# created each), which run only when pulses name several actors and the reference is loaded.
OK_LINES_730_DAY = [
    ("Technique → Tactic", 824, 1024),
    ("Technique → Technique (SUBTECHNIQUE_OF)", 506, 506),
    ("ThreatActor → Malware (USES_MALWARE)", 151, 692),
    ("ThreatActor → Tool (USES_TOOL)", 105, 475),
    ("Malware → ThreatActor (same pulse)", 3022, 106),
    ("Indicator → Vulnerability (EXPLOITS)", 0, 0),
    ("Indicator → CVE (EXPLOITS)", 0, 0),
    ("ThreatActor → Technique (ATT&CK explicit)", 177, 4854),
    ("ThreatActor → Technique (reported)", 643, 13265),
    ("Malware → Technique (MITRE explicit)", 752, 10895),
    ("Malware → Technique (reported)", 2817, 63103),
    ("Indicator -> Sector (TARGETS)", 274865, 0),
    ("Vulnerability/CVE -> Sector (AFFECTS)", 152530, 0),
    ("ThreatActor -> Sector (TARGETS)", 841, 477),
    ("Malware -> Sector (TARGETS)", 3648, 1905),
    ("Indicator → Technique (attack_ids)", 130419, 1565094),
    ("Indicator → Malware (family match)", 16886, 13201),
    ("Indicator → Malware (same pulse)", 76406, 17184),
    ("Tool → Technique (MITRE explicit)", 95, 869),
]


class _RunClient:
    """A database that answers each step's ``apoc.periodic.iterate`` with the 730-day figures of that step."""

    def __init__(self, figures: Dict[str, Tuple[int, int]], partial: str = ""):
        self.figures = figures
        self.partial = partial
        self.label = ""

    def connect(self):
        return True

    def close(self):
        pass

    def run(self, query, *args, **kwargs):
        if "apoc.periodic.iterate" in query:
            rows, created = self.figures[self.label]
            errors = {"MemoryLimitExceededException": 1} if self.label == self.partial else None
            return [_apoc_row(rows, created, errors=errors)]
        return [{"count": 0, "c": 0, "reports": [], "pulses": [], "indicators": 0}]


def _run_with_figures(monkeypatch, partial: str = ""):
    figures = {label: (rows, created) for label, rows, created in OK_LINES_730_DAY}
    client = _RunClient(figures, partial)
    real = br._safe_run_batched

    def _batched(c, label, *args, **kwargs):
        client.label = label
        return real(c, label, *args, **kwargs)

    gauge: Dict[str, int] = {}
    monkeypatch.setattr(br, "Neo4jClient", lambda: client)
    monkeypatch.setattr(br, "_safe_run_batched", _batched)
    monkeypatch.setattr(br, "query_pause", lambda: None)
    monkeypatch.setattr(br, "_METRICS_AVAILABLE", True)
    monkeypatch.setattr(br, "record_neo4j_relationships", lambda stats: gauge.update(stats), raising=False)
    return br.build_relationships(), gauge


def _summary(caplog) -> str:
    (line,) = [r.getMessage() for r in caplog.records if r.getMessage().startswith("[BUILD_RELATIONSHIPS SUMMARY]")]
    return line


def test_the_summary_names_created_relationships_and_outer_rows(monkeypatch, caplog):
    with caplog.at_level(logging.INFO, logger=br.logger.name):
        ok, gauge = _run_with_figures(monkeypatch)
    assert ok is True
    line = _summary(caplog)
    # 1,693,650 created and 664,687 outer rows, as the 730-day [OK] lines add up; the line said
    # total_edges=664687.
    assert line.startswith(
        "[BUILD_RELATIONSHIPS SUMMARY] relationships_created=1693650 outer_rows=664687 failures=0/20 "
    )
    assert "total_edges" not in line
    assert "indicator_uses_technique=130419/1565094" in line
    assert "indicator_targets_sector=274865/0" in line
    assert "[PARTIAL]" not in line
    # The gauge keeps the outer rows per step key.
    assert gauge["indicator_uses_technique"] == 130419 and gauge["indicator_targets_sector"] == 274865
    assert "attributed_to" not in gauge and "multi_zone_indicators" not in gauge


def test_a_partial_step_is_marked(monkeypatch, caplog):
    with caplog.at_level(logging.INFO, logger=br.logger.name):
        ok, _gauge = _run_with_figures(monkeypatch, partial="Indicator → Technique (attack_ids)")
    assert ok is False
    line = _summary(caplog)
    assert "failures=1/20" in line
    assert "indicator_uses_technique=130419/1565094[PARTIAL]" in line
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert (
        "relationships_created includes rolled-back batches of the [PARTIAL] step(s): indicator_uses_technique"
        in warnings
    )


def test_summary_counts_of_two_730_day_steps():
    """Step 8 and step 7a as the 730-day log reported them: 130,419 rows and 1,565,094 links; 274,865
    rows and no link (the sync had written them)."""
    stats = br._StepStats()
    br._safe_run_batched(_ApocClient(_apoc_row(130419, 1565094, 27)), "8", "o", "i", stats, "indicator_uses_technique")
    br._safe_run_batched(_ApocClient(_apoc_row(274865, 0, 55)), "7a", "o", "i", stats, "indicator_targets_sector")
    assert br._summary_counts(stats) == (
        1565094,
        405284,
        "indicator_targets_sector=274865/0, indicator_uses_technique=130419/1565094",
    )
    assert dict(stats) == {"indicator_uses_technique": 130419, "indicator_targets_sector": 274865}


def test_a_created_count_apoc_did_not_report_is_shown_as_unknown():
    stats = br._StepStats()
    br._safe_run_batched(_ApocClient(_apoc_row(824, None)), "1", "o", "i", stats, "in_tactic")
    assert br._summary_counts(stats) == (0, 824, "in_tactic=824/-")


def test_a_plain_dict_records_rows_only():
    stats: Dict[str, int] = {}
    br._safe_run_batched(_ApocClient(_apoc_row(824, 1024)), "1", "o", "i", stats, "in_tactic")
    assert stats == {"in_tactic": 824}


def test_step_2d_removals_and_trims_are_not_outer_rows_of_links():
    """They change existing links: listed in ``per_query``, left out of ``outer_rows`` (as of ``total_edges``)."""
    stats = br._StepStats()
    br._safe_run_batched(_ApocClient(_apoc_row(3022, 106)), "2d", "o", "i", stats, "attributed_to_pulse")
    removed = "attributed_to_several_actor_pulses_removed"
    br._safe_run_batched(_ApocClient(_apoc_row(12, 0)), "2d removed", "o", "i", stats, removed)
    assert br._summary_counts(stats) == (106, 3022, f"attributed_to_pulse=3022/106, {removed}=12/0")
