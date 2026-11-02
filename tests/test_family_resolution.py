"""Feed family labels resolved to Malware nodes (2026-11-02, ``src/family_resolution.py``).

``build_relationships`` step 9 links an indicator to the Malware nodes its feed's family label names
(``Indicator.malware_family``: ThreatFox, MalwareBazaar, Feodo Tracker). The labels are resolved once per run
by ``resolve_feed_families``: the name or an alias, stripped and lower-cased; only when that finds no node, the
one node whose name without whitespace, hyphens, underscores and dots is the label's. The acceptance check
``family_indicates_complete`` resolves them with the same function.

Fixtures: ``tests/fixtures/feed_family_labels_2026_11_01.json``, read from the 730-day baseline graph of
2026-11-01: every family label with its indicators, the Malware nodes that decide how a label resolves (name,
aliases, source as stored), every Tool node, and the ``SOURCED_FROM`` raw_data of one indicator per label of
interest. The measured effect on that graph: the 13,205 pairs the exact rule linked stay, the separator-free
rule adds 695 (seven labels, one node each), and 2,687 indicators keep a label that names no node.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

import family_resolution as fr
from node_identity import is_placeholder_name

TESTS = Path(__file__).resolve().parent
FIXTURE = json.loads((TESTS / "fixtures" / "feed_family_labels_2026_11_01.json").read_text(encoding="utf-8"))
LABELS: Dict[str, int] = {row["family"]: row["indicators"] for row in FIXTURE["families"]}
NODES: List[Dict[str, Any]] = FIXTURE["malware"]


def _label(family_on_indicator: str, source_id: str) -> str:
    """The family label of the feed record (its ``SOURCED_FROM`` raw_data) of the indicator that carries
    ``family_on_indicator``."""
    record = next(
        r for r in FIXTURE["records"] if r["family_on_indicator"] == family_on_indicator and r["source_id"] == source_id
    )
    return json.loads(record["raw_data"])["malware_family"]


def _node(name: str) -> Dict[str, Any]:
    return next(dict(n) for n in NODES if n["name"] == name)


def test_standard_library_and_node_identity_only():
    """The acceptance script imports the module outside the pipeline's environment."""
    tree = ast.parse((TESTS.parent / "src" / "family_resolution.py").read_text())
    imported = {
        alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    } | {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    assert imported <= {"__future__", "re", "dataclasses", "typing", "node_identity"}, imported


def test_the_730_day_labels_resolve_as_measured():
    resolution = fr.resolve_feed_families(list(LABELS), NODES)
    assert len(LABELS) == 159 and sum(LABELS.values()) == 17762
    assert len(resolution.targets) == 108
    assert sum(LABELS[label] * len(nodes) for label, nodes in resolution.targets.items()) == 13900
    assert resolution.separator_free_matches == {
        "MilleniumRAT": "millenium rat",
        "Nanocore RAT": "nanocorerat",
        "PureLogsStealer": "purelogs stealer",
        "RaspberryRobin": "raspberry robin",
        "SalatStealer": "salat stealer",
        "Venom RAT": "venomrat",
        "WARDENStealer": "warden stealer",
    }
    assert sum(LABELS[label] for label in resolution.separator_free_matches) == 695
    assert resolution.ambiguous == {}
    assert resolution.placeholders == ["Unknown Loader", "Unknown RAT", "Unknown Stealer", "Unknown malware"]
    assert (len(resolution.unresolved), sum(LABELS[label] for label in resolution.unresolved)) == (47, 2687)
    # the exact rule alone (the rule of before) links the 13,205 pairs the graph held
    exact = {k: v for k, v in resolution.targets.items() if k not in resolution.separator_free_matches}
    assert sum(LABELS[label] * len(nodes) for label, nodes in exact.items()) == 13205


def test_the_summary_counts_what_is_judged_and_what_is_not():
    summary = fr.resolve_feed_families(list(LABELS), NODES).summary(LABELS)
    assert summary["claims"] == 16560  # step 9's outer rows: every label but the placeholders
    assert summary["target_missing"] == 2687  # step 9's [SKIP] count
    assert summary["placeholder_indicators"] == 876 + 287 + 21 + 18
    assert summary["unresolved_families"] == 47
    assert list(summary["unresolved"].items())[:3] == [
        ("IClickFix", 2296),
        ("php.shin_webshell", 140),
        ("stealler", 46),
    ]
    assert summary["ambiguous"] == {}
    assert len(fr.resolve_feed_families(list(LABELS), NODES).summary(LABELS, limit=5)["unresolved"]) == 5


def test_salatstealer_reaches_the_node_named_with_a_space():
    """ThreatFox writes "SalatStealer"; the node OTX created is "salat stealer"."""
    label = _label("SalatStealer", "threatfox")
    resolution = fr.resolve_feed_families([label], [_node("salat stealer")])
    assert resolution.targets == {"SalatStealer": ["salat stealer"]}
    assert resolution.separator_free_matches == {"SalatStealer": "salat stealer"}


def test_formbook_links_its_own_node_and_the_attack_node_it_is_an_alias_of():
    label = _label("Formbook", "malwarebazaar")
    resolution = fr.resolve_feed_families([label], [_node("formbook"), _node("xloader")])
    assert resolution.targets == {"Formbook": ["formbook", "xloader"]}
    assert resolution.separator_free_matches == {}


def test_an_exact_match_wins_and_no_separator_free_spelling_is_added():
    """ "Cobalt Strike" names the ATT&CK node; the OTX node "cobaltstrike" is the same name without the space,
    and is not linked: the separator-free rule runs only when the exact one finds nothing."""
    label = _label("Cobalt Strike", "threatfox")
    resolution = fr.resolve_feed_families([label], [_node("cobalt strike"), _node("cobaltstrike")])
    assert resolution.targets == {"Cobalt Strike": ["cobalt strike"]}
    assert resolution.separator_free_matches == {}


def test_a_separator_free_label_several_nodes_carry_names_none():
    """No label of the 730-day graph is ambiguous; the stored nodes "cobalt strike beacon" / "cobaltstrike beacon"
    and the three "dark crystal rat" spellings are what one would meet."""
    nodes = [_node(n) for n in ("cobalt strike beacon", "cobaltstrike beacon", "dark crystal rat", "darkcrystal rat")]
    nodes.append(_node("darkcrystalrat"))
    resolution = fr.resolve_feed_families(["CobaltStrike-Beacon", "Dark_Crystal.RAT", "DarkCrystalRAT"], nodes)
    assert resolution.ambiguous == {
        "CobaltStrike-Beacon": ["cobalt strike beacon", "cobaltstrike beacon"],
        "Dark_Crystal.RAT": ["dark crystal rat", "darkcrystal rat", "darkcrystalrat"],
    }
    # an exact name decides before any ambiguity
    assert resolution.targets == {"DarkCrystalRAT": ["darkcrystalrat"]}
    summary = resolution.summary({"CobaltStrike-Beacon": 4, "Dark_Crystal.RAT": 1, "DarkCrystalRAT": 2})
    assert (summary["claims"], summary["target_missing"]) == (7, 5)


def test_the_separator_free_rule_reads_names_never_aliases():
    """The ATT&CK node "cobalt strike" carries the alias "Cobalt Strike - S0154"; a label that is that alias
    without separators is not resolved through it (aliases are trusted only as written)."""
    resolution = fr.resolve_feed_families(["CobaltStrike-S0154", "Cobalt Strike - S0154"], [_node("cobalt strike")])
    assert resolution.targets == {"Cobalt Strike - S0154": ["cobalt strike"]}
    assert resolution.unresolved == ["CobaltStrike-S0154"]


@pytest.mark.parametrize(
    "family, malpedia_id",
    [
        ("Unknown Loader", "unknown_loader"),
        ("Unknown RAT", "unknown_rat"),
        ("Unknown Stealer", "unknown_stealer"),
        ("Unknown malware", "unknown"),
    ],
)
def test_threatfox_generic_labels_are_placeholders(family, malpedia_id):
    """ThreatFox gives these labels a Malpedia id that names no family: they name no node, also when a node of
    that name exists from before the placeholder list held them."""
    record = next(r for r in FIXTURE["records"] if r["family_on_indicator"] == family and r["source_id"] == "threatfox")
    raw = json.loads(record["raw_data"])
    assert raw["malware_malpedia"].rsplit("/", 1)[1] == malpedia_id
    assert is_placeholder_name(raw["malware_family"])
    resolution = fr.resolve_feed_families([raw["malware_family"]], [{"name": family.lower(), "aliases": None}])
    assert resolution.targets == {} and resolution.placeholders == [family]


def test_each_stored_spelling_of_a_label_is_its_own_key():
    """The map is keyed by the label as stored (step 9 looks it up as it is): both spellings of the graph map."""
    resolution = fr.resolve_feed_families(["CoinMiner", "Coinminer", "ArcaneStealer "], [_node("coinminer")])
    assert resolution.targets == {"CoinMiner": ["coinminer"], "Coinminer": ["coinminer"]}
    assert resolution.unresolved == ["ArcaneStealer "]


def test_tool_named_malware_on_the_730_day_graph():
    pairs = fr.tool_named_malware(NODES, FIXTURE["tools"])
    assert len(pairs) == 26 and sum(p["exact_name"] for p in pairs) == 23
    assert {"malware": "quasar rat", "tool": "QuasarRAT", "tool_id": "S0262", "exact_name": False} in pairs
    assert {"malware": "asyncrat", "tool": "AsyncRAT", "tool_id": "S1087", "exact_name": True} in pairs
    counts = FIXTURE["tool_named_indicates"]
    assert sum(counts[p["malware"]] for p in pairs) == 12807
    assert sum(counts[p["malware"]] for p in pairs if p["exact_name"]) == 11646


def test_tool_named_malware_leaves_out_mitre_malware_and_tools_not_from_mitre():
    tools = [dict(t) for t in FIXTURE["tools"] if t["name"] in ("AsyncRAT", "Mimikatz")]
    malware = [_node("asyncrat"), _node("async rat"), {"name": "mimikatz", "source": ["mitre_attck"]}]
    assert [p["malware"] for p in fr.tool_named_malware(malware, tools)] == ["async rat", "asyncrat"]
    tools = [dict(t, source=["alienvault_otx"]) if t["name"] == "AsyncRAT" else t for t in tools]
    assert fr.tool_named_malware(malware, tools) == []
