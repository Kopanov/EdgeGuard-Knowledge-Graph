"""EdgeGuard — READ-side normalization layer + /actors/{name}/summary tests.

Covers:
  - ``src/ioc_normalize.py`` unit behavior (refang, indicator/CVE/MITRE
    normalization, idempotency, weird-input no-throw)
  - API wiring: /search/indicator binds the NORMALIZED $value,
    /stix/export/cve/{id} canonicalizes the identifier, GraphQL ``cve``
    resolver normalizes its input
  - /actors/{name}/summary: happy path, 404, alias resolution, 503
  - alert_processor: every Cypher $indicator binding is normalized
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Ensure env vars are set before importing query_api (which reads them at
# import time). EDGEGUARD_ENV must be a non-prod allowlist value — query_api
# fails closed (RuntimeError) when unset+no API key (PR-N24 secure defaults).
os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault("NEO4J_PASSWORD", "test-password")
os.environ.setdefault("EDGEGUARD_ENV", "dev")

from fastapi.testclient import TestClient

import alert_processor
import query_api
from ioc_normalize import (
    infer_indicator_type,
    normalize_cve_id,
    normalize_indicator_value,
    normalize_mitre_technique_id,
    refang,
)

client = TestClient(query_api.app)


# ---------------------------------------------------------------------------
# Fakes — capture every (cypher, params) bound through session.run()
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, single_record=None, rows=None):
        self._single = single_record
        self._rows = rows or []

    def single(self):
        return self._single

    def __iter__(self):
        return iter(self._rows)


class _FakeSession:
    def __init__(self, results=None):
        self.calls = []
        self._results = list(results or [])

    def run(self, query, **params):
        self.calls.append((query, params))
        return self._results.pop(0) if self._results else _FakeResult()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self, **kwargs):
        return self._session


class _FakeNeo4jClient:
    def __init__(self, session):
        self.driver = _FakeDriver(session)

    def is_connected(self):
        return True


class _FakeAlertNeo4jClient(_FakeNeo4jClient):
    """Adds the AlertProcessor-facing surface on top of the query fake."""

    def connect(self):
        return True

    def __init__(self, session):
        super().__init__(session)
        self.written_alert = None

    def process_complete_resilmesh_alert(self, alert_data):
        # Capture the payload the real write path consumes — the indicator
        # type + value that create_indicator_from_alert would MERGE.
        self.written_alert = {
            "type": alert_data.get("threat", {}).get("type"),
            "indicator": alert_data.get("threat", {}).get("indicator"),
        }

    def update_alert_enrichment_status(self, **kwargs):
        pass

    def close(self):
        pass


# ---------------------------------------------------------------------------
# Unit — refang
# ---------------------------------------------------------------------------


class TestRefang:
    def test_scheme_and_bracket_dot(self):
        assert refang("hxxp://evil[.]com/path") == "http://evil.com/path"

    def test_hxxps_scheme(self):
        assert refang("hxxps://evil(.)com") == "https://evil.com"

    def test_bracket_colon_then_scheme(self):
        # [:] must resolve before the scheme rewrite sees hxxp://
        assert refang("hxxp[:]//evil{.}com") == "http://evil.com"

    def test_curly_paren_square_dots(self):
        assert refang("1.2.3[.]4") == "1.2.3.4"
        assert refang("a(.)b{.}c[.]d") == "a.b.c.d"

    def test_at_variants(self):
        assert refang("user [at] example[.]com") == "user@example.com"
        assert refang("user(at)example.com") == "user@example.com"
        assert refang("user[@]example.com") == "user@example.com"
        assert refang("user [AT] example.com") == "user@example.com"

    def test_exotic_scheme_not_rewritten(self):
        assert refang("meow://evil.com") == "meow://evil.com"

    def test_hxxp_without_scheme_separator_untouched(self):
        assert refang("hxxp_in_a_word") == "hxxp_in_a_word"

    def test_zero_width_and_bidi_stripped(self):
        # ZERO WIDTH SPACE + RIGHT-TO-LEFT MARK — reuses node_identity's table
        assert refang("evil\u200b.com\u200f") == "evil.com"

    def test_surrounding_whitespace_stripped(self):
        assert refang("  evil.com  ") == "evil.com"

    def test_idempotent(self):
        samples = [
            "hxxps://evil[.]com/Path",
            "user [at] example[.]com",
            "[[.]]",  # nested defang — fixpoint loop keeps a single call idempotent
            "plain.example.com",
        ]
        for s in samples:
            once = refang(s)
            assert refang(once) == once

    def test_non_str_returned_unchanged(self):
        assert refang(None) is None
        assert refang(123) == 123
        assert refang(["evil[.]com"]) == ["evil[.]com"]


# ---------------------------------------------------------------------------
# Unit — normalize_indicator_value
# ---------------------------------------------------------------------------


class TestNormalizeIndicatorValue:
    def test_case_insensitive_type_lowercases(self):
        assert normalize_indicator_value("domain", "EvIl[.]CoM") == "evil.com"

    def test_md5_type_lowercases(self):
        assert normalize_indicator_value("md5", "A" * 32) == "a" * 32

    def test_url_preserves_case(self):
        # url is case-sensitive on the write side — must not be folded
        assert normalize_indicator_value("url", "hxxp://EVIL[.]com/Path") == "http://EVIL.com/Path"

    def test_email_preserves_case(self):
        assert normalize_indicator_value("email", "Admin[@]Example.com") == "Admin@Example.com"

    def test_hex_hash_heuristic_when_type_none(self):
        for length in (32, 40, 64, 128):
            assert normalize_indicator_value(None, "AB" * (length // 2)) == "ab" * (length // 2)

    def test_hex_heuristic_skips_wrong_length(self):
        assert normalize_indicator_value(None, "ABCDEF") == "ABCDEF"

    def test_hex_heuristic_skips_non_hex(self):
        assert normalize_indicator_value(None, "Z" * 64) == "Z" * 64

    def test_unknown_type_uses_hex_heuristic(self):
        # 'file_hash' (ResilMesh alerts) and generic 'hash' are not write-side
        # types — route through the heuristic, do NOT depend on 'hash' being
        # added to node_identity's set by the parallel change.
        assert normalize_indicator_value("file_hash", "B" * 40) == "b" * 40
        assert normalize_indicator_value("hash", "C" * 64) == "c" * 64

    def test_nfc_normalization(self):
        # NFD 'e' + combining acute must collapse to the composed NFC form
        assert normalize_indicator_value("domain", "Cafe\u0301.com") == "caf\u00e9.com"

    def test_non_str_returned_unchanged(self):
        assert normalize_indicator_value("domain", None) is None
        assert normalize_indicator_value(None, 42) == 42

    def test_idempotent(self):
        once = normalize_indicator_value("domain", "EvIl[.]CoM")
        assert normalize_indicator_value("domain", once) == once


# ---------------------------------------------------------------------------
# Unit — normalize_cve_id
# ---------------------------------------------------------------------------


class TestNormalizeCveId:
    def test_canonical_passthrough(self):
        assert normalize_cve_id("CVE-2021-44228") == "CVE-2021-44228"

    def test_lowercase_with_spaces(self):
        assert normalize_cve_id("cve 2021 44228") == "CVE-2021-44228"

    def test_en_dash(self):
        assert normalize_cve_id("CVE–2021–44228") == "CVE-2021-44228"

    def test_em_dash(self):
        assert normalize_cve_id("CVE—2021—44228") == "CVE-2021-44228"

    def test_underscores(self):
        assert normalize_cve_id("cve_2021_44228") == "CVE-2021-44228"

    def test_embedded_in_text(self):
        assert normalize_cve_id("Apache Log4j (CVE-2021-44228) RCE") == "CVE-2021-44228"

    def test_long_sequence_number(self):
        assert normalize_cve_id("cve-2024-123456") == "CVE-2024-123456"

    def test_no_match_returns_none(self):
        assert normalize_cve_id("no cve here") is None
        assert normalize_cve_id("CVE-21-1234") is None  # 2-digit year is not a CVE id
        assert normalize_cve_id("") is None

    def test_non_str_returns_none(self):
        assert normalize_cve_id(None) is None
        assert normalize_cve_id(20211234) is None


# ---------------------------------------------------------------------------
# Unit — normalize_mitre_technique_id
# ---------------------------------------------------------------------------


class TestNormalizeMitreTechniqueId:
    def test_technique(self):
        assert normalize_mitre_technique_id("T1059") == "T1059"

    def test_sub_technique(self):
        assert normalize_mitre_technique_id("t1059.001") == "T1059.001"

    def test_space_between_t_and_digits(self):
        assert normalize_mitre_technique_id("T 1059") == "T1059"

    def test_embedded_in_text(self):
        assert normalize_mitre_technique_id("uses T1547.010 for persistence") == "T1547.010"

    def test_tactic_id_is_not_a_technique(self):
        assert normalize_mitre_technique_id("TA0001") is None

    def test_no_match_returns_none(self):
        assert normalize_mitre_technique_id("nothing here") is None
        assert normalize_mitre_technique_id("") is None

    def test_non_str_returns_none(self):
        assert normalize_mitre_technique_id(None) is None
        assert normalize_mitre_technique_id(1059) is None


class TestInferIndicatorType:
    def test_domain(self):
        assert infer_indicator_type("evil.com") == "domain"
        assert infer_indicator_type("sub.domain.co.uk") == "domain"
        assert infer_indicator_type("EvIl[.]CoM") == "domain"  # refanged first

    def test_ipv4(self):
        assert infer_indicator_type("1.2.3.4") == "ipv4"
        assert infer_indicator_type("1.2.3[.]4") == "ipv4"

    def test_ipv6(self):
        assert infer_indicator_type("2001:db8::1") == "ipv6"

    def test_url(self):
        assert infer_indicator_type("https://evil.com/path") == "url"
        assert infer_indicator_type("hxxp://evil[.]com/x") == "url"

    def test_email(self):
        assert infer_indicator_type("user@evil.com") == "email"

    def test_hash(self):
        assert infer_indicator_type("D" * 64) == "hash"
        assert infer_indicator_type("a" * 32) == "hash"

    def test_ambiguous_returns_none(self):
        # A bare word, an IP-with-bad-octet, a path — none claimed.
        assert infer_indicator_type("justaword") is None
        assert infer_indicator_type("999.999.999.999") is None
        assert infer_indicator_type("/etc/passwd") is None
        assert infer_indicator_type("C:\\\\Windows\\\\System32") is None

    def test_bare_filename_is_not_a_domain(self):
        """#5: a typeless filename must NOT be mislabeled 'domain' (would
        yield a bogus DNS-sinkhole recommendation + a mistyped node)."""
        for fn in ("pos-malware.exe", "emotet-payload.dll", "report.pdf", "invoice.docx", "dropper.bin"):
            assert infer_indicator_type(fn) is None, fn
        # …but a real multi-label host is still a domain.
        assert infer_indicator_type("mail.evil.com") == "domain"

    def test_non_str_returns_none(self):
        assert infer_indicator_type(None) is None
        assert infer_indicator_type(1234) is None


class TestMitreTechniqueBoundary:
    def test_overlong_input_does_not_truncate_to_a_different_technique(self):
        """#8: 'T10590' must NOT silently resolve to the real technique
        'T1059' — over-long numeric runs fail to match instead."""
        assert normalize_mitre_technique_id("T10590") is None
        assert normalize_mitre_technique_id("T1059.0012") is None

    def test_valid_ids_still_parse(self):
        assert normalize_mitre_technique_id("T1059") == "T1059"
        assert normalize_mitre_technique_id("T1059.001") == "T1059.001"


# ---------------------------------------------------------------------------
# API — /search/indicator binds the normalized $value
# ---------------------------------------------------------------------------


class TestSearchIndicatorNormalization:
    def test_refangs_and_lowercases_before_match(self, monkeypatch):
        session = _FakeSession(results=[_FakeResult(single_record=None)])
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(session))

        resp = client.post("/search/indicator", json={"value": "EvIl[.]CoM", "indicator_type": "domain"})
        assert resp.status_code == 200
        data = resp.json()
        # Raw value echoed for transparency; normalized form surfaced too
        assert data["found"] is False
        assert data["value"] == "EvIl[.]CoM"
        assert data["normalized_value"] == "evil.com"
        # The Cypher MATCH must have bound the NORMALIZED value
        assert session.calls, "no Cypher executed"
        assert session.calls[0][1]["value"] == "evil.com"

    def test_hex_hash_heuristic_without_type(self, monkeypatch):
        session = _FakeSession(results=[_FakeResult(single_record=None)])
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(session))

        resp = client.post("/search/indicator", json={"value": "A" * 64})
        assert resp.status_code == 200
        assert session.calls[0][1]["value"] == "a" * 64

    def test_typeless_uppercase_domain_is_inferred_and_folded(self, monkeypatch):
        """#3 (Bugbot 'search skips type inference'): a typeless uppercase
        domain must infer 'domain' and fold to the stored lowercase key —
        so the same paste that enriches on ingest also resolves on search."""
        session = _FakeSession(results=[_FakeResult(single_record=None)])
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(session))

        resp = client.post("/search/indicator", json={"value": "EVIL.COM"})
        assert resp.status_code == 200
        assert resp.json()["normalized_value"] == "evil.com"
        assert session.calls[0][1]["value"] == "evil.com"

    def test_empty_value_short_circuits_without_query(self, monkeypatch):
        """#3 (Bugbot 'search allows empty normalized key'): a whitespace/
        zero-width-only value normalizes to '' — must return found=false
        WITHOUT running a MATCH {value: ''} that could false-match a legacy
        empty-key node."""
        session = _FakeSession(results=[_FakeResult(single_record=None)])
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(session))

        resp = client.post("/search/indicator", json={"value": "  ​ \t "})
        assert resp.status_code == 200
        assert resp.json()["found"] is False
        assert not session.calls, "no Cypher should run for an empty normalized key"


# ---------------------------------------------------------------------------
# API — STIX cve export canonicalizes the identifier
# ---------------------------------------------------------------------------


class TestStixCveExportNormalization:
    def _install_fake_exporter(self, monkeypatch, captured):
        import stix_exporter

        class _FakeExporter:
            MEDIA_TYPE = stix_exporter.StixExporter.MEDIA_TYPE

            def __init__(self, neo4j_client):
                pass

            def export_cve(self, cve_id, depth=2):
                captured["cve_id"] = cve_id
                return {"type": "bundle", "objects": []}

            def export_indicator(self, value, depth=2):
                captured["indicator_value"] = value
                return {"type": "bundle", "objects": []}

        monkeypatch.setattr(stix_exporter, "StixExporter", _FakeExporter)

    def test_spaced_lowercase_identifier_uppercased(self, monkeypatch):
        captured = {}
        self._install_fake_exporter(monkeypatch, captured)
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(_FakeSession()))

        resp = client.get("/stix/export/cve/cve%202021%2044228")
        assert resp.status_code == 200
        assert captured["cve_id"] == "CVE-2021-44228"

    def test_en_dash_identifier_canonicalized(self, monkeypatch):
        captured = {}
        self._install_fake_exporter(monkeypatch, captured)
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(_FakeSession()))

        resp = client.get("/stix/export/cve/CVE–2021–44228")
        assert resp.status_code == 200
        assert captured["cve_id"] == "CVE-2021-44228"

    def test_unrecognized_identifier_falls_back_to_raw(self, monkeypatch):
        captured = {}
        self._install_fake_exporter(monkeypatch, captured)
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(_FakeSession()))

        resp = client.get("/stix/export/cve/not-a-cve")
        assert resp.status_code == 200
        assert captured["cve_id"] == "not-a-cve"

    def test_indicator_export_normalizes_identifier(self, monkeypatch):
        """Bugbot: object_type=indicator must go through the same
        canonicalize_lookup path as /search/indicator — defanged/mixed-case
        IOC paste resolves to the stored key."""
        captured = {}
        self._install_fake_exporter(monkeypatch, captured)
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(_FakeSession()))

        resp = client.get("/stix/export/indicator/EvIl[.]CoM")
        assert resp.status_code == 200
        assert captured["indicator_value"] == "evil.com"

    def test_indicator_export_rejects_empty_normalized_key(self, monkeypatch):
        """Bugbot: a whitespace-only identifier normalizes to '' — must be
        rejected (400) without calling the exporter, mirroring the
        /search/indicator empty-key guard."""
        captured = {}
        self._install_fake_exporter(monkeypatch, captured)
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(_FakeSession()))

        resp = client.get("/stix/export/indicator/%20%20")
        assert resp.status_code == 400
        assert "indicator_value" not in captured, "exporter must not be called for an empty key"


# ---------------------------------------------------------------------------
# GraphQL — cve resolver normalizes its input
# ---------------------------------------------------------------------------


class TestGraphqlCveNormalization:
    def test_resolver_receives_canonical_cve_id(self, monkeypatch):
        import graphql_api

        captured = {}

        def _fake_resolve(neo4j, cve_id):
            captured["cve_id"] = cve_id
            return None

        monkeypatch.setattr(graphql_api, "_resolve_cve", _fake_resolve)
        monkeypatch.setattr(graphql_api, "_client", object())

        result = graphql_api.schema.execute_sync('{ cve(cveId: "cve 2021 44228") { cveId } }')
        assert result.errors is None
        assert captured["cve_id"] == "CVE-2021-44228"


# ---------------------------------------------------------------------------
# API — /actors/{name}/summary
# ---------------------------------------------------------------------------


def _actor_record(resolved_by_name=True):
    """Shape of the single row returned by _ACTOR_SUMMARY_CYPHER."""
    return {
        "actor": {
            "name": "apt28",
            "aliases": ["APT28", "Fancy Bear"],
            "description": "GRU-attributed espionage group",
            "sophistication": "advanced",
            "motivation": None,
            "primary_motivation": "espionage",
            "confidence_score": 0.9,
            "zone": ["global"],
            "source": ["otx"],
        },
        "resolved_by_name": resolved_by_name,
        "malware": ["x-agent", "zebrocy"],
        "malware_total": 12,
        "techniques": [{"mitre_id": "T1059", "name": "Command and Scripting Interpreter"}],
        "technique_total": 25,
        "campaigns": ["grizzly steppe"],
        "campaign_total": 2,
    }


class TestActorSummary:
    def test_happy_path(self, monkeypatch):
        session = _FakeSession(results=[_FakeResult(single_record=_actor_record())])
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(session))

        resp = client.get("/actors/APT28/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "apt28"
        assert data["aliases"] == ["APT28", "Fancy Bear"]
        assert data["resolved_by"] == "name"
        assert data["motivation"] == "espionage"  # falls back to primary_motivation
        assert data["malware"] == ["x-agent", "zebrocy"]
        assert data["malware_total"] == 12
        assert data["techniques"] == [{"mitre_id": "T1059", "name": "Command and Scripting Interpreter"}]
        assert data["technique_total"] == 25
        assert data["campaigns"] == ["grizzly steppe"]
        assert data["campaign_total"] == 2

    def test_name_always_bound_as_parameter(self, monkeypatch):
        session = _FakeSession(results=[_FakeResult(single_record=_actor_record())])
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(session))

        client.get("/actors/APT28/summary")
        cypher, params = session.calls[0]
        assert params["name"] == "APT28"
        assert "$name" in cypher
        assert "APT28" not in cypher  # never interpolated (Cypher-injection rule)
        assert "toLower(trim($name))" in cypher

    def test_query_prefers_canonical_name_over_alias_match(self, monkeypatch):
        """Bugbot 'actor summary picks arbitrary match': when two actors
        share an alias, a canonical-NAME hit must deterministically win.
        Pin the rank-then-name ORDER BY (not the old bare ORDER BY a.name)."""
        session = _FakeSession(results=[_FakeResult(single_record=_actor_record())])
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(session))
        client.get("/actors/apt28/summary")
        cypher, _params = session.calls[0]
        assert "_match_rank" in cypher and "ORDER BY _match_rank" in cypher, (
            "actor-summary tiebreak must rank canonical-name matches before alias-only matches"
        )
        # The bare nondeterministic form must be gone.
        assert "WITH a ORDER BY a.name LIMIT 1" not in cypher

    def test_404_when_no_actor_matches(self, monkeypatch):
        session = _FakeSession(results=[_FakeResult(single_record=None)])
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(session))

        resp = client.get("/actors/no-such-actor/summary")
        assert resp.status_code == 404

    def test_alias_resolution_path(self, monkeypatch):
        session = _FakeSession(results=[_FakeResult(single_record=_actor_record(resolved_by_name=False))])
        monkeypatch.setattr(query_api, "neo4j_client", _FakeNeo4jClient(session))

        resp = client.get("/actors/Fancy%20Bear/summary")
        assert resp.status_code == 200
        assert resp.json()["resolved_by"] == "alias"

    def test_503_when_neo4j_disconnected(self, monkeypatch):
        monkeypatch.setattr(query_api, "neo4j_client", None)
        resp = client.get("/actors/apt28/summary")
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# alert_processor — bound $indicator is normalized
# ---------------------------------------------------------------------------


class TestAlertProcessorNormalization:
    def _process(self, threat):
        session = _FakeSession()
        fake = _FakeAlertNeo4jClient(session)
        processor = alert_processor.AlertProcessor(neo4j_client=fake)
        alert = {
            "alert_id": "test-norm-001",
            "source": "wazuh",
            "zone": "healthcare",
            "timestamp": "2026-06-11T00:00:00+00:00",
            "threat": threat,
        }
        result = processor.process_alert(alert)
        self._last_fake = fake
        return session, result

    def test_domain_indicator_refanged_and_lowercased(self):
        session, result = self._process({"indicator": "EvIl[.]CoM", "type": "domain"})
        assert result.enriched is True
        bound = [params["indicator"] for _q, params in session.calls if "indicator" in params]
        assert bound, "no Cypher call bound $indicator"
        assert all(v == "evil.com" for v in bound)
        # Enrichment payload echoes the graph-canonical identity
        assert result.enrichment["indicator"] == "evil.com"

    def test_file_hash_indicator_lowercased_via_heuristic(self):
        session, _result = self._process({"indicator": "D" * 64, "type": "file_hash"})
        bound = [params["indicator"] for _q, params in session.calls if "indicator" in params]
        assert bound and all(v == "d" * 64 for v in bound)

    def test_missing_type_and_unknown_type_normalize_identically(self):
        """Bugbot: a defanged value with NO type vs an explicit
        type='unknown' must produce the same canonical indicator — and with
        type inference, a domain-shaped value resolves to a folded domain so
        it dedups with MISP-synced (domain, value) nodes."""
        s_missing, _ = self._process({"indicator": "EvIl[.]CoM"})
        s_unknown, _ = self._process({"indicator": "EvIl[.]CoM", "type": "unknown"})
        miss = [p["indicator"] for _q, p in s_missing.calls if "indicator" in p]
        unk = [p["indicator"] for _q, p in s_unknown.calls if "indicator" in p]
        assert miss and unk
        # Inferred as a domain → folded; both paths agree.
        assert miss == unk == ["evil.com"] * len(miss)

    def test_unknown_type_domain_inferred_and_node_typed(self):
        """Bugbot 'unknown alert type breaks domain parity': a typeless
        domain alert must persist under (indicator_type='domain', folded
        value), matching MISP sync — not (unknown, mixed-case)."""
        self._process({"indicator": "EvIl.CoM", "type": "unknown"})
        written = self._last_fake.written_alert
        assert written == {"type": "domain", "indicator": "evil.com"}, (
            "typeless domain alert must be written as (domain, folded value) to dedup with MISP"
        )

    def test_whitespace_only_indicator_is_not_enriched(self):
        """A whitespace/zero-width-only value normalizes to '' — enrichment
        must be skipped (no empty-key lookup), but the Alert node is still
        written (the indicator MERGE no-ops on the empty value)."""
        _session, result = self._process({"indicator": "  ​ \t ", "type": "domain"})
        assert result.enriched is False
        # Alert node still recorded; the indicator written is empty.
        assert self._last_fake.written_alert == {"type": "domain", "indicator": ""}

    def test_indicatorless_alert_still_writes_alert_node(self):
        """#2 regression: a host-only / CVE-only alert (no IOC indicator)
        must still persist its Alert node — moving the empty guard ahead of
        the write silently dropped legitimate indicatorless alerts."""
        _session, result = self._process({"hostname": "srv-01", "cve": "CVE-2021-44228", "severity": 9})
        assert result.enriched is False  # nothing to enrich
        assert self._last_fake.written_alert is not None, (
            "process_complete_resilmesh_alert must run so the Alert node is recorded"
        )
        assert self._last_fake.written_alert.get("indicator") in (None, "")

    def test_degraded_response_carries_verbatim_original_alert(self):
        """Bugbot: enriched=False responses (e.g. indicatorless alert whose
        Alert node WAS persisted) must carry the RAW original_alert snapshot
        like the success path — not an empty dict, and not the
        normalization-mutated payload."""
        _session, result = self._process({"hostname": "srv-01", "indicator": "  ", "type": "domain"})
        assert result.enriched is False
        assert result.original_alert, "degraded response must include the original alert payload"
        # Verbatim pre-normalization value, not the mutated "" form.
        assert result.original_alert["threat"]["indicator"] == "  "

    def test_inferred_ipv4_still_gets_block_recommendation(self):
        """Bugbot 'inferred types skip recommendations': a typeless IP alert
        infers type 'ipv4' — _generate_recommendations must recognize the
        canonical name, not only the legacy 'ip' label, or the primary
        block guidance silently disappears."""
        _session, result = self._process({"indicator": "203.0.113.7"})
        recs = result.enrichment.get("recommendations", [])
        assert any("Block IP 203.0.113.7" in r for r in recs), recs

    def test_inferred_hash_still_gets_block_recommendation(self):
        _session, result = self._process({"indicator": "d" * 64})
        recs = result.enrichment.get("recommendations", [])
        assert any("Block file hash" in r for r in recs), recs
