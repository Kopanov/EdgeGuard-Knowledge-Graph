"""Pins for the 2026-10-10 four-reviewer audit of the fresh-baseline train (PRs #135–#143).

Each class names the finding it closes. Behavioural tests where the code can be driven
offline; text pins only for Cypher that needs a live graph (and then with the reason).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

_REPO = Path(__file__).resolve().parent.parent
_SRC = _REPO / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_CLIENT = (_SRC / "neo4j_client.py").read_text()


# --------------------------------------------------------------------------- D5 / D4: sector edges
class TestSectorEdgesNeverTargetGlobalAndAreInferences:
    """The old graph carried 137,948 CVE→global AFFECTS and 131,650 Indicator→global TARGETS edges at
    confidence 1.0 (measured 2026-10-10). `global` means "no sector". Since 2026-10-16 the confidence of
    a sector link follows from its evidence label through one table (``sector_evidence``): a keyword
    inference is ``zone_classification`` at 0.5, never 1.0, and a stated sector keeps its own label and
    value instead of being reset to 0.5 on every run. Text pins on the rendered statements: they run
    only through apoc.periodic.iterate on a live graph (behaviour: tests/test_sector_evidence_neo4j.py)."""

    @pytest.mark.parametrize("name", ["_Q7A_STATEMENTS", "_Q7B_STATEMENTS", "_Q7C_STATEMENTS", "_Q7D_STATEMENTS"])
    def test_global_is_excluded_and_confidence_follows_the_label(self, name):
        import build_relationships as br

        body = getattr(br, name).inner
        assert '_z <> "global"' in body, f"{name} must never link the global pseudo-sector"
        assert "r.confidence_score = coalesce($sector_confidence[_kept], r.confidence_score)" in body
        assert "r.confidence_score = 0.5" not in body, "no unconditional reset: it erased a stated sector's 0.9"
        assert "r.confidence_score = 1.0" not in body
        assert getattr(br, name).params["sector_confidence"] == {
            "zone_classification": 0.5,
            "otx_industries": 0.6,
            "advisory_sector": 0.9,
        }

    def test_acceptance_script_polices_global_edges(self):
        script = (_REPO / "scripts" / "verify_fresh_baseline.py").read_text()
        assert (
            "(g:Sector {name: 'global'})" in script
            and 'rep.add("no_global_sector_edges", r.get("c") == 0, r)' in script
        )


# --------------------------------------------------------------------------- A1: per-property array caps
class TestAccumulatingArraysKeepTheWriterSizes:
    """`_MAX_ARRAY_ITEMS = 50` was applied to every accumulating list: MITRE groups carry up to 130
    techniques (27 of 172 exceed 50) and the node kept the first 50 → ~670 `mitre_explicit` edges could
    never exist. Technique / software / report lists now have their own ceilings; aliases keep 50."""

    def _client(self):
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        client._connection_healthy = True
        session = MagicMock()
        session.run.return_value.single.return_value = None
        client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
        client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
        return client, session

    def _params(self, session, prop):
        for call in session.run.call_args_list:
            if prop in call.kwargs:
                return call.kwargs
        raise AssertionError(f"no run() call carried {prop}: {[list(c.kwargs) for c in session.run.call_args_list]}")

    def test_uses_techniques_keeps_130_entries_but_aliases_still_cap_at_50(self):
        client, session = self._client()
        client.merge_node_with_source(
            "ThreatActor",
            {"name": "apt28"},
            {"name": "apt28", "tag": "mitre_attck", "zone": ["global"]},
            "mitre_attck",
            extra_props={
                "uses_techniques": [f"T1{i:03d}" for i in range(130)],
                "aliases": [f"alias-{i}" for i in range(60)],
            },
        )
        kw = self._params(session, "uses_techniques")
        assert len(kw["uses_techniques"]) == 130
        assert len(kw["aliases"]) == 50, "the adversarial alias cap from PR-N14 is unchanged"

    @pytest.mark.parametrize(
        "prop, n", [("reported_techniques", 400), ("pulse_ids", 300), ("uses_malware", 200), ("uses_tools", 120)]
    )
    def test_other_lists_match_the_writer_caps(self, prop, n):
        client, session = self._client()
        client.merge_node_with_source(
            "Malware",
            {"name": "x"},
            {"name": "x", "tag": "t", "zone": ["global"]},
            "alienvault_otx",
            extra_props={prop: [f"v{i}" for i in range(n)]},
        )
        assert len(self._params(session, prop)[prop]) == n

    def test_caps_are_not_below_what_the_misp_writer_sends(self):
        from collectors import misp_writer as mw

        caps = dict(re.findall(r'"(\w+)": (\d+),\s*\n', _CLIENT.split("_ARRAY_ITEM_CAPS = {", 1)[1].split("}", 1)[0]))
        assert int(caps["uses_techniques"]) >= 400 and int(caps["reported_techniques"]) >= 400, (
            "writer caps t/rt at 400"
        )
        assert int(caps["uses_malware"]) >= 200 and int(caps["uses_tools"]) >= 200, "writer caps m/s at 200"
        assert mw._MAX_REPORT_IDS == 500


# --------------------------------------------------------------------------- A4: actor hygiene
class TestParentheticalActorNames:
    """27 of 815 non-MITRE actors on the hosted graph were `name (alias)`; one was split inside the
    parenthesis into a ThreatActor called `security)`."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("apt28 (fancy bear)", ["apt28"]),
            ("kimsuky (apt43)", ["kimsuky"]),
            ("apt-c-00 (ocean lotus)", ["apt-c-00"]),
            ("mois (ministry of intelligence and security)", ["mois"]),
            ("sidecopy, transparent tribe (apt36)", ["sidecopy", "transparent tribe"]),
            ("NoName057(16)", ["NoName057(16)"]),  # real group name: no whitespace before "("
            ("team (2024)", ["team (2024)"]),  # digits only inside → not an alias
            ("x (y)", ["x (y)"]),  # head too short to be a name
            ("apt28 and apt29", ["apt28", "apt29"]),
            ("apt28 (fancy bear) and apt29 (cozy bear)", ["apt28", "apt29"]),  # Bugbot on #144: sides too
            ("sidecopy & transparent tribe (apt36)", ["sidecopy", "transparent tribe"]),
            ("lazarus group / hidden cobra", ["lazarus group", "hidden cobra"]),
        ],
    )
    def test_clean_actor_names(self, raw, expected):
        from actor_name_hygiene import clean_actor_names

        assert clean_actor_names(raw) == expected


# --------------------------------------------------------------------------- Bugbot on #144: meta comments stay valid JSON
class TestMetaCommentsNeverBreakTheJson:
    """The 500-id report list can overflow the 4000-char comment budget; a string slice cut the JSON
    mid-token and the parser dropped the whole block. Lists are halved instead, JSON stays valid."""

    def _writer(self):
        from collectors.misp_writer import MISPWriter

        return MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)

    def test_many_report_ids_shrink_but_the_comment_stays_parseable(self):
        import json

        ind = {
            "indicator_type": "ipv4",
            "value": "203.0.113.5",
            "zone": ["global"],
            "tag": "alienvault_otx",
            "source": ["alienvault_otx"],
            "confidence_score": 0.5,
            "pulse_id": "p0",
            "attack_ids": ["T1059"],
            "description": "d" * 600,
            "report_ids": [f"0123456789abcdef0123456789abcdef{i:04d}" for i in range(500)],
        }
        attr = self._writer().create_attribute(ind)
        comment = attr["comment"]
        assert comment.startswith("OTX_META:") and len(comment) <= 4000
        meta = json.loads(comment[len("OTX_META:") :])
        assert meta["pulse_id"] == "p0" and meta["attack_ids"] == ["T1059"], "the small fields survive"
        assert 1 <= len(meta["report_ids"]) < 500 and meta["report_ids"][0].endswith("0000"), "oldest-first prefix kept"

    def test_small_comment_is_untouched(self):
        import json

        ind = {
            "indicator_type": "ipv4",
            "value": "203.0.113.5",
            "zone": ["global"],
            "tag": "alienvault_otx",
            "source": ["alienvault_otx"],
            "confidence_score": 0.5,
            "pulse_id": "p0",
            "attack_ids": ["T1059"],
            "report_ids": ["p1", "p2"],
        }
        meta = json.loads(self._writer().create_attribute(ind)["comment"][len("OTX_META:") :])
        assert meta["report_ids"] == ["p1", "p2"]

    def test_fit_helper_drops_optional_keys_as_last_resort(self):
        import json

        from collectors.misp_writer import _fit_meta_comment

        out = _fit_meta_comment(
            "X:", {"pulse_id": "p", "description": "x" * 5000, "report_ids": ["a"] * 300}, budget=300
        )
        assert len(out) <= 300 and json.loads(out[2:])["pulse_id"] == "p"


# --------------------------------------------------------------------------- A6 / D9: evidence labels, alert TLP
class TestEveryEdgeRowCarriesAnEvidenceLabel:
    def test_the_five_parser_rows_now_carry_match_type(self):
        src = (_SRC / "run_misp_to_neo4j.py").read_text()
        assert src.count("# 2026-10 audit: every edge carries an evidence label") == 5
        for rel, label in (
            ("EXPLOITS", "cve_tag"),
            ("INDICATES", "misp_attribute_tag"),
        ):
            assert re.search(rf'"rel_type": "{rel}".*?"match_type": "{label}"', src, re.S), (rel, label)
        # 2026-10-18: the three rows of a ``sector:`` / ``target-sector:`` tag take the label table's
        # inference (``zone_classification`` at 0.5), not the attribute's confidence
        from run_misp_to_neo4j import _tag_sector_evidence

        for rel in ("AFFECTS", "TARGETS"):
            assert re.search(
                rf'_tag_sector_evidence\(source_id, target_sector, "{rel}"\).*?"rel_type": "{rel}".*?"match_type": _label',
                src,
                re.S,
            ), rel
            assert _tag_sector_evidence("misp", "energy", rel) == ("zone_classification", 0.5)
        assert src.count("_tag_sector_evidence(source_id, target_sector,") == 3

    def test_alert_created_indicators_carry_tlp_and_marker_on_both_queries(self):
        from neo4j_client import _alert_default_tlp

        assert _CLIENT.count("i.tlp = coalesce(i.tlp, $tlp)") == 2, "primary and fallback MERGE"
        assert '"tlp": _alert_default_tlp(),' in _CLIENT
        fallback = _CLIENT.split("fallback_query = f", 1)[1].split('"""', 2)[1]
        assert "i.edgeguard_managed = true" in fallback
        assert _alert_default_tlp() in {"white", "clear", "green", "amber", "amber+strict", "red"}
        with patch.dict(os.environ, {"EDGEGUARD_DEFAULT_TLP": "green"}):
            import importlib

            import config as cfg

            importlib.reload(cfg)
            try:
                assert _alert_default_tlp() == "green"
            finally:
                os.environ.pop("EDGEGUARD_DEFAULT_TLP", None)
                importlib.reload(cfg)


# --------------------------------------------------------------------------- B4: compose forwarding of the audit's extra variables
class TestComposeForwardsTrustAllowlistAndAirflowApiCredentials:
    def _compose(self):
        return yaml.safe_load((_REPO / "docker-compose.yml").read_text())

    def test_trust_allowlist_is_shared_by_all_services(self):
        d = self._compose()
        for svc in ("airflow", "api", "graphql"):
            env = d["services"][svc]["environment"]
            assert env["EDGEGUARD_TRUSTED_MISP_ORG_UUIDS"] == "${EDGEGUARD_TRUSTED_MISP_ORG_UUIDS:-}"
            assert env["EDGEGUARD_TRUSTED_MISP_ORG_NAMES"] == "${EDGEGUARD_TRUSTED_MISP_ORG_NAMES:-}"

    def test_airflow_api_credentials_reach_only_the_airflow_service(self):
        d = self._compose()
        af = d["services"]["airflow"]["environment"]
        # ``admin`` is the user ``airflow standalone`` creates (Airflow 3 Simple auth manager).
        assert af["AIRFLOW_API_USER"] == "${AIRFLOW_API_USER:-admin}"
        assert af["AIRFLOW_API_PASSWORD"] == "${AIRFLOW_API_PASSWORD:-}"
        assert af["EDGEGUARD_PARENT_DAG_LIVENESS_CHECK"] == "${EDGEGUARD_PARENT_DAG_LIVENESS_CHECK:-true}", (
            "empty would disable the safeguard"
        )
        for svc in ("api", "graphql"):
            assert "AIRFLOW_API_PASSWORD" not in d["services"][svc]["environment"]


# --------------------------------------------------------------------------- C2: the 18-step runner, behaviourally
class TestBuildRelationshipsWiring:
    """Replaces three text pins (`'"uses_malware"' in text`, …) with the real call sequence."""

    def _run(self):
        import build_relationships as br

        calls = []

        # ``params``: the technique steps pass the revoked ATT&CK ids as ``$revoked`` (2026-10).
        def fake_batched(client, label, outer, inner, stats, key, batch_size=5000, skip_query=None, params=None):
            calls.append((label, key, skip_query is not None))
            stats[key] = 0
            return True

        with (
            patch.object(br, "Neo4jClient") as nc,
            patch.object(br, "_safe_run_batched", fake_batched),
            patch.object(br, "query_pause", lambda: None),
        ):
            nc.return_value.connect.return_value = True
            nc.return_value.run.return_value = [{"c": 0}]
            ok = br.build_relationships()
        return ok, calls

    def test_twenty_distinct_steps_in_order_with_skip_queries_where_designed(self):
        ok, calls = self._run()
        assert ok is not False
        keys = [k for _, k, _ in calls]
        assert len(calls) == 20 and len(set(keys)) == 20, keys
        assert keys[:6] == [
            "in_tactic",
            "subtechnique_of",
            "attributed_to",
            "uses_malware",
            "uses_tool",
            "attributed_to_pulse",
        ], keys[:6]
        assert keys.index("indicates_family") + 1 == keys.index("indicates_pulse"), "9b runs right after 9"
        skip = {k: s for _, k, s in calls}
        assert skip["uses_malware"] and skip["uses_tool"], "R6 steps skip when no claim is pending"
        assert not skip["in_tactic"] and not skip["subtechnique_of"], "cheap full passes have no skip query"
        assert {"uses_malware", "uses_tool", "subtechnique_of", "indicates_pulse", "attributed_to_pulse"} <= set(keys)
        assert skip["indicates_pulse"] and not skip["attributed_to_pulse"]
        # 2026-10-16: the sector steps count the node sectors no feed gave
        for key in (
            "indicator_targets_sector",
            "vuln_affects_sector",
            "actor_targets_sector",
            "malware_targets_sector",
        ):
            assert skip[key], key


# --------------------------------------------------------------------------- B6: dependency pin parity
def test_pyproject_carries_the_fastapi_exclusion_like_the_requirements_files():
    py = (_REPO / "pyproject.toml").read_text()
    assert "fastapi>=0.115,!=0.136.3,<1.0" in py
    assert "fastapi>=0.115,!=0.136.3,<1.0" in (_REPO / "requirements.txt").read_text()


def test_every_dependency_list_sets_the_certifi_floor():
    # GHSA-6q48-6c7w-9gw2: certifi before 2026.10.19 bundles emSign roots whose intermediate CA keys
    # were compromised. A requirement line, not a comment: `certifi>=...` or `"certifi>=...",`.
    line = re.compile(r'^\s*"?certifi>=2026\.10\.19"?,?\s*(#.*)?$', re.MULTILINE)
    for name in ("pyproject.toml", "requirements.txt", "requirements-airflow-docker.txt"):
        assert line.search((_REPO / name).read_text()), name
