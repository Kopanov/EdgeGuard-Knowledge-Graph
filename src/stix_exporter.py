"""Graph → STIX 2.1 exporter for ResilMesh integration.

This module is a **prototype** proposal implementation — see
``docs/STIX21_EXPORTER_PROPOSAL.md`` for design notes, open questions and
the list of follow-ups. It builds STIX 2.1 bundles centred on a single
seed object (indicator / threat actor / technique / CVE) plus the
immediate threat-intel neighbourhood, so ResilMesh can enrich an asset
with "what do we know about this indicator/actor/etc." without pulling
the whole graph.

Key design decisions (see proposal doc for justification):
- Uses the ``stix2`` SDK (already pinned in ``pyproject.toml``) for object
  construction so we get ID generation, timestamp formatting and schema
  validation for free.
- STIX IDs are **deterministic** (UUIDv5 over the node's natural key) so
  re-exports of the same graph state produce the same bundle — ResilMesh
  can diff bundles safely.
- All Cypher queries filter on ``x.edgeguard_managed = true`` (strict
  equality — null fails) so we never leak ResilMesh-owned
  asset/vulnerability nodes into an outbound bundle. Originally written
  as ``coalesce(x.edgeguard_managed, true) = true``, which defaulted
  missing properties to ``true`` and let ResilMesh-owned nodes pass the
  filter — fixed in the bugbot pass on PR #25.
- Backward compatibility with the legacy ``USES`` relationship type is
  preserved alongside the new ``EMPLOYS_TECHNIQUE`` /
  ``IMPLEMENTS_TECHNIQUE`` edges introduced by PR #24.
- ATT&CK tactics are emitted as ``kill_chain_phases`` on the
  ``attack-pattern`` SDO, not as standalone objects (per STIX 2.1 ATT&CK
  convention).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Iterable, List, Optional

import stix2

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Deterministic IDs
# ---------------------------------------------------------------------------

# Fixed namespace so UUIDv5 is stable across processes/machines. This
# value is arbitrary but MUST NOT change — doing so would break ID
# stability for ResilMesh consumers that cache by STIX ID.
EDGEGUARD_STIX_NAMESPACE = uuid.UUID("5f2e1f9a-6a1b-5e0f-9b25-ed9ea2d574cb")


def _deterministic_id(obj_type: str, natural_key: str) -> str:
    """Return a deterministic STIX 2.1 ID for ``obj_type`` + ``natural_key``.

    STIX IDs look like ``indicator--<uuid>``; we use UUIDv5 with a fixed
    namespace so the same (type, key) pair always yields the same ID.
    """
    if not natural_key:
        natural_key = f"__missing__:{obj_type}"
    name = f"{obj_type}:{natural_key}".lower()
    return f"{obj_type}--{uuid.uuid5(EDGEGUARD_STIX_NAMESPACE, name)}"


# ---------------------------------------------------------------------------
# Pattern helper — reuse the escape + type mapping from MISPToNeo4jSync
# instead of re-implementing it. We instantiate the class lazily with
# ``__new__`` to avoid triggering its heavy ``__init__`` (which would try
# to connect to MISP).
# ---------------------------------------------------------------------------

_pattern_helper: Any = None


def _get_pattern_helper() -> Any:
    """Return a bare instance of MISPToNeo4jSync for pattern helpers.

    We only need ``_value_to_stix_pattern``/``_escape_stix_value``; both
    are pure and do not touch ``self``'s network state, so skipping
    ``__init__`` is safe.
    """
    global _pattern_helper
    if _pattern_helper is None:
        from run_misp_to_neo4j import MISPToNeo4jSync

        _pattern_helper = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    return _pattern_helper


def _build_pattern(indicator_type: Optional[str], value: str) -> str:
    """Build a STIX 2.1 pattern literal for an indicator row.

    Falls back to a generic ``artifact`` match if the MISP type is not
    recognised — that way we never drop an indicator just because its
    type is exotic; the proposal lists pattern coverage as a follow-up.
    """
    helper = _get_pattern_helper()
    pattern = helper._value_to_stix_pattern(indicator_type or "", value)
    if pattern:
        return pattern
    # Fallback: emit a valid but coarse pattern. STIX requires a pattern
    # on indicator SDOs so we must not return None here.
    safe = helper._escape_stix_value(value)
    return f"[artifact:payload_bin = '{safe}']"


# ---------------------------------------------------------------------------
# Main exporter
# ---------------------------------------------------------------------------


class StixExporter:
    """Build STIX 2.1 bundles from the EdgeGuard threat-intel graph.

    Each ``export_*`` method returns a ``dict`` (the serialised bundle)
    ready to be handed to a FastAPI response. Returning a dict rather
    than a ``stix2.Bundle`` instance keeps the API layer free of a hard
    dependency on the SDK's object classes.
    """

    # MIME type ResilMesh expects for STIX 2.1 payloads.
    MEDIA_TYPE = "application/stix+json;version=2.1"

    def __init__(self, neo4j_client: Any) -> None:
        """Wrap a connected Neo4jClient (or any object exposing ``.driver``)."""
        self.client = neo4j_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export_indicator(self, value: str) -> Dict[str, Any]:
        """Bundle one indicator + its 1-hop neighbourhood.

        Neighbourhood: INDICATES→Malware, EXPLOITS→CVE/Vulnerability,
        USES_TECHNIQUE→Technique, TARGETS→Sector.
        """
        rows = self._run(
            """
            MATCH (i:Indicator {value: $value})
            WHERE i.edgeguard_managed = true
            OPTIONAL MATCH (i)-[rim:INDICATES]->(m:Malware)
              WHERE m.edgeguard_managed = true
            OPTIONAL MATCH (i)-[rie:EXPLOITS]->(v)
              WHERE (v:CVE OR v:Vulnerability)
                AND v.edgeguard_managed = true
            OPTIONAL MATCH (i)-[rit:USES_TECHNIQUE|USES]->(t:Technique)
              WHERE t.edgeguard_managed = true
            OPTIONAL MATCH (i)-[ris:TARGETS]->(s:Sector)
              WHERE s.edgeguard_managed = true
            RETURN i AS seed,
                   collect(DISTINCT m) AS malware,
                   collect(DISTINCT v) AS vulns,
                   collect(DISTINCT t) AS techniques,
                   collect(DISTINCT s) AS sectors
            """,
            {"value": value},
        )
        if not rows:
            return self._empty_bundle()
        row = rows[0]
        seed = row["seed"]
        if seed is None:
            return self._empty_bundle()

        objects: Dict[str, Dict[str, Any]] = {}
        seed_sdo = self._node_to_sdo("Indicator", dict(seed))
        self._add(objects, seed_sdo)

        for m in _nonnull(row["malware"]):
            m_sdo = self._node_to_sdo("Malware", dict(m))
            self._add(objects, m_sdo)
            self._add(
                objects,
                self._edge_to_sro("indicates", seed_sdo["id"], m_sdo["id"]),
            )
        for v in _nonnull(row["vulns"]):
            v_sdo = self._node_to_sdo("Vulnerability", dict(v))
            self._add(objects, v_sdo)
            # STIX has no "exploits" vocab term; "indicates" is the closest
            # defined value and matches the Indicator→Vulnerability semantics.
            self._add(
                objects,
                self._edge_to_sro("indicates", seed_sdo["id"], v_sdo["id"]),
            )
        for t in _nonnull(row["techniques"]):
            t_sdo = self._node_to_sdo("Technique", dict(t))
            self._add(objects, t_sdo)
            # Indicator→Technique: STIX 2.1 vocabulary for indicator
            # source_ref allows "indicates". We use "indicates" here
            # (not "uses") — see proposal doc §5.
            self._add(
                objects,
                self._edge_to_sro("indicates", seed_sdo["id"], t_sdo["id"]),
            )
        for s in _nonnull(row["sectors"]):
            s_sdo = self._node_to_sdo("Sector", dict(s))
            self._add(objects, s_sdo)
            self._add(
                objects,
                self._edge_to_sro("targets", seed_sdo["id"], s_sdo["id"]),
            )

        return self._bundle(objects.values())

    def export_threat_actor(self, name: str) -> Dict[str, Any]:
        """Bundle centred on a ThreatActor + attributed malware + TTPs + campaigns."""
        rows = self._run(
            """
            MATCH (a:ThreatActor)
            WHERE (a.name = $name OR $name IN coalesce(a.aliases, []))
              AND a.edgeguard_managed = true
            OPTIONAL MATCH (m:Malware)-[ram:ATTRIBUTED_TO]->(a)
              WHERE m.edgeguard_managed = true
            OPTIONAL MATCH (a)-[rat:EMPLOYS_TECHNIQUE|USES]->(t:Technique)
              WHERE t.edgeguard_managed = true
            OPTIONAL MATCH (m)-[rmt:IMPLEMENTS_TECHNIQUE|USES]->(mt:Technique)
              WHERE mt.edgeguard_managed = true
            OPTIONAL MATCH (c:Campaign)-[rca:ATTRIBUTED_TO]->(a)
              WHERE c.edgeguard_managed = true
            RETURN a AS seed,
                   collect(DISTINCT m) AS malware,
                   collect(DISTINCT t) AS actor_tech,
                   collect(DISTINCT {m: m, t: mt}) AS mal_tech,
                   collect(DISTINCT c) AS campaigns
            """,
            {"name": name},
        )
        if not rows:
            return self._empty_bundle()
        row = rows[0]
        seed = row["seed"]
        if seed is None:
            return self._empty_bundle()

        objects: Dict[str, Dict[str, Any]] = {}
        seed_sdo = self._node_to_sdo("ThreatActor", dict(seed))
        self._add(objects, seed_sdo)

        mal_ids: Dict[str, str] = {}
        for m in _nonnull(row["malware"]):
            md = dict(m)
            m_sdo = self._node_to_sdo("Malware", md)
            self._add(objects, m_sdo)
            mal_ids[md.get("name", "")] = m_sdo["id"]
            self._add(
                objects,
                self._edge_to_sro("attributed-to", m_sdo["id"], seed_sdo["id"]),
            )

        for t in _nonnull(row["actor_tech"]):
            t_sdo = self._node_to_sdo("Technique", dict(t))
            self._add(objects, t_sdo)
            self._add(
                objects,
                self._edge_to_sro("uses", seed_sdo["id"], t_sdo["id"]),
            )
        for pair in row["mal_tech"] or []:
            m = pair.get("m") if isinstance(pair, dict) else None
            t = pair.get("t") if isinstance(pair, dict) else None
            if not m or not t:
                continue
            md = dict(m)
            td = dict(t)
            m_sdo_id = mal_ids.get(md.get("name", "")) or self._add(
                objects, self._node_to_sdo("Malware", md)
            )
            t_sdo = self._node_to_sdo("Technique", td)
            self._add(objects, t_sdo)
            self._add(
                objects,
                self._edge_to_sro("uses", m_sdo_id, t_sdo["id"]),
            )
        for c in _nonnull(row["campaigns"]):
            c_sdo = self._node_to_sdo("Campaign", dict(c))
            self._add(objects, c_sdo)
            self._add(
                objects,
                self._edge_to_sro("attributed-to", c_sdo["id"], seed_sdo["id"]),
            )

        return self._bundle(objects.values())

    def export_technique(self, mitre_id: str) -> Dict[str, Any]:
        """Bundle centred on a Technique + everything that uses it."""
        rows = self._run(
            """
            MATCH (t:Technique {mitre_id: $mid})
            WHERE t.edgeguard_managed = true
            OPTIONAL MATCH (a:ThreatActor)-[:EMPLOYS_TECHNIQUE|USES]->(t)
              WHERE a.edgeguard_managed = true
            OPTIONAL MATCH (m:Malware)-[:IMPLEMENTS_TECHNIQUE|USES]->(t)
              WHERE m.edgeguard_managed = true
            OPTIONAL MATCH (tool:Tool)-[:IMPLEMENTS_TECHNIQUE|USES]->(t)
              WHERE tool.edgeguard_managed = true
            OPTIONAL MATCH (i:Indicator)-[:USES_TECHNIQUE|USES]->(t)
              WHERE i.edgeguard_managed = true
            RETURN t AS seed,
                   collect(DISTINCT a) AS actors,
                   collect(DISTINCT m) AS malware,
                   collect(DISTINCT tool) AS tools,
                   collect(DISTINCT i) AS indicators
            """,
            {"mid": mitre_id},
        )
        if not rows:
            return self._empty_bundle()
        row = rows[0]
        seed = row["seed"]
        if seed is None:
            return self._empty_bundle()

        objects: Dict[str, Dict[str, Any]] = {}
        seed_sdo = self._node_to_sdo("Technique", dict(seed))
        self._add(objects, seed_sdo)

        for a in _nonnull(row["actors"]):
            a_sdo = self._node_to_sdo("ThreatActor", dict(a))
            self._add(objects, a_sdo)
            self._add(objects, self._edge_to_sro("uses", a_sdo["id"], seed_sdo["id"]))
        for m in _nonnull(row["malware"]):
            m_sdo = self._node_to_sdo("Malware", dict(m))
            self._add(objects, m_sdo)
            self._add(objects, self._edge_to_sro("uses", m_sdo["id"], seed_sdo["id"]))
        for tool in _nonnull(row["tools"]):
            tool_sdo = self._node_to_sdo("Tool", dict(tool))
            self._add(objects, tool_sdo)
            self._add(objects, self._edge_to_sro("uses", tool_sdo["id"], seed_sdo["id"]))
        for i in _nonnull(row["indicators"]):
            i_sdo = self._node_to_sdo("Indicator", dict(i))
            self._add(objects, i_sdo)
            self._add(objects, self._edge_to_sro("indicates", i_sdo["id"], seed_sdo["id"]))

        return self._bundle(objects.values())

    def export_cve(self, cve_id: str) -> Dict[str, Any]:
        """Bundle centred on a CVE/Vulnerability + exploiting indicators + affected sectors."""
        rows = self._run(
            """
            MATCH (v)
            WHERE (v:CVE OR v:Vulnerability)
              AND v.cve_id = $cve_id
              AND v.edgeguard_managed = true
            OPTIONAL MATCH (i:Indicator)-[:EXPLOITS]->(v)
              WHERE i.edgeguard_managed = true
            OPTIONAL MATCH (v)-[:AFFECTS]->(s:Sector)
              WHERE s.edgeguard_managed = true
            RETURN v AS seed,
                   collect(DISTINCT i) AS indicators,
                   collect(DISTINCT s) AS sectors
            """,
            {"cve_id": cve_id},
        )
        if not rows:
            return self._empty_bundle()
        row = rows[0]
        seed = row["seed"]
        if seed is None:
            return self._empty_bundle()

        objects: Dict[str, Dict[str, Any]] = {}
        seed_sdo = self._node_to_sdo("Vulnerability", dict(seed))
        self._add(objects, seed_sdo)

        for i in _nonnull(row["indicators"]):
            i_sdo = self._node_to_sdo("Indicator", dict(i))
            self._add(objects, i_sdo)
            self._add(objects, self._edge_to_sro("indicates", i_sdo["id"], seed_sdo["id"]))
        for s in _nonnull(row["sectors"]):
            s_sdo = self._node_to_sdo("Sector", dict(s))
            self._add(objects, s_sdo)
            self._add(objects, self._edge_to_sro("targets", seed_sdo["id"], s_sdo["id"]))

        return self._bundle(objects.values())

    # ------------------------------------------------------------------
    # Node → SDO mapping
    # ------------------------------------------------------------------

    def _node_to_sdo(self, label: str, props: Dict[str, Any]) -> Dict[str, Any]:
        """Turn a Neo4j node dict into a STIX 2.1 SDO dict.

        We build objects through the stix2 SDK so the library enforces
        schema and emits correct timestamps, then serialise back to a
        plain dict for the bundle (``stix2.parsing.dict_to_stix2`` would
        round-trip but the dict form is what FastAPI serialises anyway).
        """
        label = label.lower()
        if label == "indicator":
            return self._indicator_sdo(props)
        if label == "malware":
            return self._malware_sdo(props)
        if label == "threatactor":
            return self._actor_sdo(props)
        if label == "technique":
            return self._technique_sdo(props)
        if label == "tool":
            return self._tool_sdo(props)
        if label == "campaign":
            return self._campaign_sdo(props)
        if label in ("cve", "vulnerability"):
            return self._vulnerability_sdo(props)
        if label == "sector":
            return self._sector_sdo(props)
        # Unknown — never happens with well-formed graph, but fail soft.
        return {
            "type": "x-edgeguard-unknown",
            "id": _deterministic_id("x-edgeguard-unknown", str(props)),
            "spec_version": "2.1",
        }

    # ---- per-type constructors ----------------------------------------

    def _indicator_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        value = props.get("value", "")
        ind_type = props.get("indicator_type", "")
        pattern = _build_pattern(ind_type, value)
        stix_id = _deterministic_id("indicator", f"{ind_type}|{value}")
        obj = stix2.Indicator(
            id=stix_id,
            pattern=pattern,
            pattern_type="stix",
            valid_from=props.get("first_seen") or "1970-01-01T00:00:00Z",
            name=props.get("name") or f"{ind_type}:{value}",
            indicator_types=_listify(props.get("indicator_classification") or ["malicious-activity"]),
            allow_custom=True,
        )
        return _to_dict(obj)

    def _malware_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        name = props.get("name", "")
        stix_id = _deterministic_id("malware", name)
        malware_types = _listify(props.get("malware_types") or ["unknown"])
        is_family = any(
            "family" in (mt or "").lower() for mt in malware_types
        ) or bool(props.get("is_family"))
        obj = stix2.Malware(
            id=stix_id,
            name=name,
            is_family=is_family,
            malware_types=malware_types,
            aliases=_listify(props.get("aliases")),
            description=props.get("description"),
            allow_custom=True,
        )
        return _to_dict(obj)

    def _actor_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        name = props.get("name", "")
        # Default to intrusion-set (group convention, matches MITRE ATT&CK).
        stix_id = _deterministic_id("intrusion-set", name)
        obj = stix2.IntrusionSet(
            id=stix_id,
            name=name,
            aliases=_listify(props.get("aliases")),
            description=props.get("description"),
            allow_custom=True,
        )
        return _to_dict(obj)

    def _technique_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        mitre_id = props.get("mitre_id") or props.get("external_id") or ""
        name = props.get("name", mitre_id)
        stix_id = _deterministic_id("attack-pattern", mitre_id or name)

        kcp: List[Dict[str, str]] = []
        # Tactic → kill_chain_phases. We accept either a list of phases
        # stored on the node or the legacy ``tactic_phases`` property.
        phases = props.get("tactic_phases") or props.get("kill_chain_phases") or []
        for phase in phases:
            if isinstance(phase, dict):
                name_ = phase.get("phase_name") or phase.get("name")
            else:
                name_ = str(phase)
            if name_:
                kcp.append({"kill_chain_name": "mitre-attack", "phase_name": str(name_).lower()})

        ext_refs = []
        if mitre_id:
            ext_refs.append(
                {
                    "source_name": "mitre-attack",
                    "external_id": mitre_id,
                    "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}",
                }
            )

        kwargs: Dict[str, Any] = {
            "id": stix_id,
            "name": name,
            "description": props.get("description"),
            "allow_custom": True,
        }
        if kcp:
            kwargs["kill_chain_phases"] = kcp
        if ext_refs:
            kwargs["external_references"] = ext_refs
        obj = stix2.AttackPattern(**kwargs)
        return _to_dict(obj)

    def _tool_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        name = props.get("name", "")
        stix_id = _deterministic_id("tool", name)
        obj = stix2.Tool(
            id=stix_id,
            name=name,
            tool_types=_listify(props.get("tool_types") or ["unknown"]),
            description=props.get("description"),
            aliases=_listify(props.get("aliases")),
            allow_custom=True,
        )
        return _to_dict(obj)

    def _campaign_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        name = props.get("name", "")
        stix_id = _deterministic_id("campaign", name)
        obj = stix2.Campaign(
            id=stix_id,
            name=name,
            description=props.get("description"),
            aliases=_listify(props.get("aliases")),
            allow_custom=True,
        )
        return _to_dict(obj)

    def _vulnerability_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = props.get("cve_id") or props.get("name") or ""
        stix_id = _deterministic_id("vulnerability", cve_id)
        ext_refs = []
        if cve_id:
            ext_refs.append(
                {
                    "source_name": "cve",
                    "external_id": cve_id,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
            )
        kwargs: Dict[str, Any] = {
            "id": stix_id,
            "name": cve_id,
            "description": props.get("description"),
            "allow_custom": True,
        }
        if ext_refs:
            kwargs["external_references"] = ext_refs
        obj = stix2.Vulnerability(**kwargs)
        return _to_dict(obj)

    def _sector_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        name = props.get("name") or props.get("sector") or ""
        stix_id = _deterministic_id("identity", f"sector|{name}")
        obj = stix2.Identity(
            id=stix_id,
            name=name,
            identity_class="class",
            sectors=[name] if name else None,
            allow_custom=True,
        )
        return _to_dict(obj)

    # ------------------------------------------------------------------
    # Edge → SRO
    # ------------------------------------------------------------------

    def _edge_to_sro(
        self, relationship_type: str, source_ref: str, target_ref: str
    ) -> Dict[str, Any]:
        """Build a deterministic Relationship SRO between two SDOs."""
        stix_id = _deterministic_id(
            "relationship", f"{source_ref}|{relationship_type}|{target_ref}"
        )
        obj = stix2.Relationship(
            id=stix_id,
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            allow_custom=True,
        )
        return _to_dict(obj)

    # ------------------------------------------------------------------
    # Bundle assembly
    # ------------------------------------------------------------------

    def _add(
        self, objects: Dict[str, Dict[str, Any]], sdo: Optional[Dict[str, Any]]
    ) -> Optional[str]:
        """Insert a SDO/SRO into the bundle dict, keyed by its STIX id."""
        if not sdo:
            return None
        objects.setdefault(sdo["id"], sdo)
        return sdo["id"]

    def _bundle(self, objects: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        bundle_id = "bundle--" + str(uuid.uuid4())
        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": list(objects),
        }

    def _empty_bundle(self) -> Dict[str, Any]:
        return self._bundle([])

    # ------------------------------------------------------------------
    # Neo4j helper
    # ------------------------------------------------------------------

    def _run(self, cypher: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run a Cypher query, returning a list of row dicts.

        Sessions are opened with ``default_access_mode="READ"`` so Neo4j
        itself rejects any accidental write from this API surface — the
        same defense-in-depth pattern used by the graph-explore and
        admin-query endpoints in ``query_api.py``. The STIX exporter is a
        strictly read-only consumer; a bug that produced a MERGE/CREATE
        here should fail at the driver rather than silently mutate the
        shared graph that ResilMesh also writes to.
        """
        driver = getattr(self.client, "driver", None)
        if driver is None:
            logger.warning("StixExporter: Neo4j driver not connected")
            return []
        with driver.session(default_access_mode="READ") as session:
            result = session.run(cypher, **params)
            return [dict(record) for record in result]


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _listify(value: Any) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        out = [str(v) for v in value if v is not None]
        return out or None
    return [str(value)]


def _nonnull(items: Any) -> List[Any]:
    """Drop None entries from a collect() result."""
    return [x for x in (items or []) if x is not None]


def _to_dict(stix_obj: Any) -> Dict[str, Any]:
    """Serialise a stix2 SDO/SRO to a plain dict."""
    # stix2 objects expose ``serialize`` (json) and ``.get`` on __dict__.
    # The simplest stable round-trip is ``json.loads(obj.serialize())``.
    import json

    return json.loads(stix_obj.serialize())
