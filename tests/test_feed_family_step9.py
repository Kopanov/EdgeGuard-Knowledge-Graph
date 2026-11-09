"""``build_relationships`` step 9 with the feed families resolved once per run (2026-11-02).

Step 9 links an indicator to the Malware nodes its feed's family label names. Since 2026-11-02 the labels are
resolved in Python (``family_resolution.resolve_feed_families``) into ``$family_targets``, keyed by the label as
stored; the inner statement looks each label up and finds the nodes by their indexed name, and the skip
statement counts the outer statement's indicators whose label has no entry. These tests run the step as
``build_relationships()`` renders it, with a client that answers the two reads with the rows of the 730-day
graph (``tests/fixtures/feed_family_labels_2026_11_01.json``). The statements run on a database in
``tests/test_feed_family_resolution_neo4j.py``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

import pytest
from build_rel_queries import assigned_query

import build_relationships
import family_resolution as fr

FIXTURE = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "feed_family_labels_2026_11_01.json").read_text(encoding="utf-8")
)
STEP_9 = "Indicator → Malware (family match)"


class _Client:
    """Answers the two reads of step 9 with the 730-day rows (or raises), every other statement with a count row."""

    def __init__(self, families=None, malware=None, fail: bool = False):
        self.families = FIXTURE["families"] if families is None else families
        self.malware = FIXTURE["malware"] if malware is None else malware
        self.fail = fail

    def connect(self):
        return True

    def close(self):
        pass

    def run(self, query, parameters=None, **kw):
        if query in (fr.CYPHER_FEED_FAMILIES_READ, fr.CYPHER_MALWARE_NAMES_READ) and self.fail:
            raise RuntimeError("Neo4j unavailable")
        if query == fr.CYPHER_FEED_FAMILIES_READ:
            return [dict(r) for r in self.families]
        if query == fr.CYPHER_MALWARE_NAMES_READ:
            return [dict(r) for r in self.malware]
        return [{"count": 0, "c": 0}]


def _steps(monkeypatch, client: _Client) -> Dict[str, Any]:
    """Run ``build_relationships()`` with ``client``; every step it hands to ``_safe_run_batched``, by label, and
    the run's result."""
    steps: Dict[str, Dict[str, Any]] = {}

    def _batched(client, label, outer, inner, stats, key, batch_size=5000, skip_query=None, params=None):
        steps[label] = {"outer": outer, "inner": inner, "skip": skip_query, "params": params, "key": key}
        return True

    monkeypatch.setattr(build_relationships, "Neo4jClient", lambda: client)
    monkeypatch.setattr(build_relationships, "_safe_run_batched", _batched)
    monkeypatch.setattr(build_relationships, "query_pause", lambda: None)
    ok = build_relationships.build_relationships()
    return {"ok": ok, "steps": steps}


def test_the_step_runs_with_the_map_the_resolver_builds(monkeypatch):
    run = _steps(monkeypatch, _Client())
    step = run["steps"][STEP_9]
    expected = fr.resolve_feed_families([r["family"] for r in FIXTURE["families"]], FIXTURE["malware"]).targets
    assert step["params"] == {"family_targets": expected}
    assert step["params"]["family_targets"]["SalatStealer"] == ["salat stealer"]
    assert step["params"]["family_targets"]["Formbook"] == ["formbook", "xloader"]
    assert "Unknown Loader" not in step["params"]["family_targets"]
    assert (step["outer"], step["inner"], step["skip"]) == (
        assigned_query("_q9_outer"),
        assigned_query("_q9_inner"),
        assigned_query("_q9_skip"),
    )
    assert step["key"] == "indicates_family" and run["ok"] is True


def test_an_unreadable_graph_fails_the_step_and_does_not_run_it(monkeypatch, caplog):
    """An empty map would link nothing and look like success: the step is not run and counts as failed."""
    with caplog.at_level(logging.ERROR, logger="build_relationships"):
        run = _steps(monkeypatch, _Client(fail=True))
    assert STEP_9 not in run["steps"]
    assert "Indicator → Malware (same pulse)" in run["steps"], "the other steps still run"
    assert run["ok"] is False
    assert any("step 9 not run" in r.getMessage() for r in caplog.records)


def test_an_ambiguous_label_is_logged_and_linked_to_none(monkeypatch, caplog):
    malware = [m for m in FIXTURE["malware"] if m["name"] in ("cobalt strike beacon", "cobaltstrike beacon", "emotet")]
    families = [{"family": "CobaltStrike-Beacon", "indicators": 4}, {"family": "Emotet", "indicators": 598}]
    with caplog.at_level(logging.INFO, logger="build_relationships"):
        run = _steps(monkeypatch, _Client(families=families, malware=malware))
    assert run["steps"][STEP_9]["params"] == {"family_targets": {"Emotet": ["emotet"]}}
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING and "step 9" in r.getMessage()]
    assert warnings == [
        "[LINK] step 9: family 'CobaltStrike-Beacon' (4 indicators): without separators it is the name of 2 "
        "Malware nodes (cobalt strike beacon, cobaltstrike beacon); linked to none"
    ]


def _redline_malware():
    """The 1 Nov rows of the ATT&CK node "redline stealer" (with the ``mitre_id`` the read returns since 2026-11-08,
    constructed: S1240) and of its OTX-only twin "red line stealer"; "RedLineStealer" is the MalwareBazaar label
    step 9 of the 8 Nov run reported as ambiguous."""
    rows = {m["name"]: dict(m) for m in FIXTURE["malware"] if m["name"] in ("redline stealer", "red line stealer")}
    rows["redline stealer"]["mitre_id"] = "S1240"
    return list(rows.values())


def test_a_label_of_an_attack_node_and_its_otx_only_twin_links_the_attack_node(monkeypatch, caplog):
    families = [{"family": "RedLineStealer", "indicators": 1}]
    with caplog.at_level(logging.INFO, logger="build_relationships"):
        run = _steps(monkeypatch, _Client(families=families, malware=_redline_malware()))
    assert run["steps"][STEP_9]["params"] == {"family_targets": {"RedLineStealer": ["redline stealer"]}}
    step_9 = [r for r in caplog.records if "step 9: family" in r.getMessage()]
    assert [(r.levelno, r.getMessage()) for r in step_9] == [
        (
            logging.INFO,
            "[LINK] step 9: family 'RedLineStealer' (1 indicators): without separators it is the name of 2 Malware "
            "nodes; linked to the ATT&CK node redline stealer, not to the OTX-only red line stealer",
        )
    ]


def test_the_same_label_without_the_attack_id_stays_ambiguous(monkeypatch, caplog):
    """Negative: the rows as read before the read returned ``mitre_id`` keep the warning and link nothing."""
    malware = [{k: v for k, v in m.items() if k != "mitre_id"} for m in _redline_malware()]
    families = [{"family": "RedLineStealer", "indicators": 1}]
    with caplog.at_level(logging.INFO, logger="build_relationships"):
        run = _steps(monkeypatch, _Client(families=families, malware=malware))
    assert run["steps"][STEP_9]["params"] == {"family_targets": {}}
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING and "step 9" in r.getMessage()]
    assert warnings == [
        "[LINK] step 9: family 'RedLineStealer' (1 indicators): without separators it is the name of 2 "
        "Malware nodes (red line stealer, redline stealer); linked to none"
    ]


def test_the_inner_statement_finds_each_node_by_its_name():
    inner = assigned_query("_q9_inner")
    assert "UNWIND coalesce($family_targets[i.malware_family], []) AS mname MATCH (m:Malware {name: mname}) " in inner
    assert "MATCH (m:Malware) " not in inner and "m.family" not in inner and "m.aliases" not in inner
    assert 'r.match_type = "malware_family"' in inner and "0.8 > r.confidence_score THEN 0.8" in inner


def test_the_skip_statement_counts_the_outer_rows_without_an_entry():
    """Skip parity by construction: the skip statement is the outer statement's filter and "no entry"."""
    outer, skip = assigned_query("_q9_outer"), assigned_query("_q9_skip")
    outer_filter = outer[len("MATCH (i:Indicator) ") : outer.index(" RETURN i")]
    assert skip == (
        "MATCH (i:Indicator) "
        + outer_filter
        + " AND size(coalesce($family_targets[i.malware_family], [])) = 0 RETURN count(i) AS c"
    )
    # the placeholders the outer leaves out include the three ThreatFox generic labels
    for label in ("unknown malware", "unknown loader", "unknown rat", "unknown stealer"):
        assert f'"{label}"' in outer_filter


@pytest.mark.parametrize("rows", [[], [{"family": None, "indicators": 3}], [{"count": 0, "c": 0}]])
def test_rows_without_a_label_resolve_to_an_empty_map(rows):
    params = build_relationships._family_target_params(_Client(families=rows))
    assert params == {"family_targets": {}}


def test_the_reads_are_the_resolver_module_reads():
    """The step and the acceptance check read the same rows."""
    assert build_relationships._FEED_FAMILIES_READ is fr.CYPHER_FEED_FAMILIES_READ
    assert build_relationships._MALWARE_NAMES_READ is fr.CYPHER_MALWARE_NAMES_READ
