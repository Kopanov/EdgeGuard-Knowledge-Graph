"""Aging of Indicator nodes: one rule for every supplier (2026-10-16).

Aging depends on the kind of fact, not on who supplied it or who created the node. An indicator
(an IP, domain, URL or hash said to be malicious) is a time-bound claim, so every ``Indicator``
node ages the same way, whichever source reported it and whether EdgeGuard created the node
(``edgeguard_managed``) or wrote onto a node another system created (``edgeguard_enriched``); no
aging statement reads either marker. Catalogue and reference facts (CVE, CVSS, Vulnerability,
Malware, ThreatActor, Technique, Tactic, Tool, Sector, Source, Alert) never age by time, and
EdgeGuard writes no lifecycle property onto them when it matches a node (``active = true`` is set
on create only), so a node another system created keeps its own lifecycle.

The basis
---------
For one MISP report of an indicator, ``T`` is the attribute's MISP timestamp (when MISP recorded
it) and ``L`` the source's own last-report date carried in the attribute's ``last_seen``, capped
at ``T``. The report time is ``min(T, coalesce(L, T))`` (``misp_report_times`` in
``run_misp_to_neo4j``). The node keeps, forward only, the latest report time over every source
(``last_reported_at``, with ``last_reported_source``, ``last_reported_ref`` = the MISP attribute
uuid and ``last_reported_basis`` = ``source_date`` or ``misp_recorded``) and the latest MISP record
time (``last_recorded_at``); a report with an older or equal time changes none of them (an equal
time with a smaller attribute uuid takes the reference, so the result does not depend on the order
of arrival). The basis of aging is ``coalesce(last_reported_at, first_imported_at)``:
``first_imported_at`` (set once, when EdgeGuard creates the node) dates a node no MISP report
dated. ``aging_basis`` names it: ``last_reported_basis`` for a reported node, ``first_imported``
otherwise; the rule derives it from the stored report like every other aging property, so the job
corrects a stale value. ``last_updated`` (the last database write) is not read.

The rule
--------
``confidence_score = max(0.10, round(source_confidence * factor, 2))`` with the factor of the
tier the age (whole days from the basis to the evaluation time) has reached: 1.00 below the
first tier day, then the factors of ``EDGEGUARD_AGING_FACTORS`` from the days of
``EDGEGUARD_AGING_TIER_DAYS`` (defaults 0.85 from 90 days, 0.70 from 180, 0.55 from 365). From
``EDGEGUARD_AGING_RETIRE_DAYS`` (default 730) the node is retired: ``active = false``,
``retired_by = 'decay'``, ``retired_at = basis + retire days``; below it ``active = true`` and a
decay retirement is cleared. A manual decommission (``retired_at`` set, ``retired_by`` other than
``'decay'``) is kept. The value is recomputed from ``source_confidence`` (the highest confidence a
source gave, never an aged value), so missed or repeated runs give the same result. A node
written before 2026-10-16 has no ``source_confidence`` until its next write: its
``confidence_score`` is kept as stored (it may carry the old decay, so it is neither aged again
nor copied into ``source_confidence``), and readers show ``coalesce(source_confidence,
confidence_score)``.

Each aged node shows ``aging_basis``, ``aging_tier`` (0 below the first tier day, then 1, 2, ...),
``aging_factor`` and ``aging_since`` (when the current state began: the basis plus the first day
of the tier, or plus the retire days once retired).

One definition
--------------
``aging_map`` is the single Cypher definition of the rule. Every Indicator write applies it
(``Neo4jClient.merge_indicators_batch``, ``merge_node_with_source`` for the label Indicator,
``create_indicator_from_alert``) in a ``SET`` clause of its own (``aging_set_clause``) after the
clause that records the report and ``source_confidence``: a clause reads the node as the previous
clause left it, so the rule sees the report of the same write (a newer report reactivates the node
in that write) without depending on the order in which one ``SET`` clause applies its items.
``enrichment_jobs.decay_ioc_confidence`` applies it to every Indicator with the time of the DAG
run and writes a node when any of its ``AGING_FIELDS`` differs from the stored value. A write
evaluates it at ``WRITE_AS_OF``: the DAG run's evaluation time when the sync of a run writes
(``Neo4jClient.set_aging_as_of``; the time the run's job uses, so the sync's writes and the job
never disagree in between), the time of the write otherwise (the alert path, the command-line
writers). ``node_report_items`` / ``edge_report_items`` are the forward-only report properties of
the node and of its ``SOURCED_FROM`` edge. Tests pin every splice.

Standard library only; the fragments use single quotes only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Mapping, Optional, Tuple

TIER_DAYS_ENV = "EDGEGUARD_AGING_TIER_DAYS"
FACTORS_ENV = "EDGEGUARD_AGING_FACTORS"
RETIRE_DAYS_ENV = "EDGEGUARD_AGING_RETIRE_DAYS"

DEFAULT_TIER_DAYS: Tuple[int, ...] = (90, 180, 365)
DEFAULT_FACTORS: Tuple[float, ...] = (0.85, 0.70, 0.55)
DEFAULT_RETIRE_DAYS = 730

# The lowest confidence aging gives: an aged indicator stays queryable and ranked.
CONFIDENCE_FLOOR = 0.10

# ``aging_basis`` values: which time the node's age counts from.
BASIS_SOURCE_DATE = "source_date"  # the source's own last-report date (MISP last_seen), capped at T
BASIS_MISP_RECORDED = "misp_recorded"  # the MISP record time T (no source date, or one later than T)
BASIS_FIRST_IMPORTED = "first_imported"  # no MISP report dated the node: when EdgeGuard created it
AGING_BASES: Tuple[str, ...] = (BASIS_SOURCE_DATE, BASIS_MISP_RECORDED, BASIS_FIRST_IMPORTED)

# ``retired_by`` of a retirement this rule made (and clears when the node is reported again).
RETIRED_BY_DECAY = "decay"

# 2026-10-16: the time an Indicator write evaluates the rule at, and the parameter that carries it.
# Within a DAG run the sync writes hours after the run's due time and the run's job then evaluates
# the rule at that due time (``data_interval_end``): a write evaluated at its own time could retire a
# node that crossed the retirement day in between, and the job reactivate it (a STIX consumer keeping
# the highest ``modified`` kept the retired version). The sync of a run therefore passes the run's
# evaluation time; a writer outside a run passes none, and the write's own time applies.
AS_OF_PARAM = "aging_as_of"
WRITE_AS_OF = f"coalesce(datetime(${AS_OF_PARAM}), datetime())"


def evaluation_time(value: Any = None) -> datetime:
    """An evaluation time of the rule as an aware UTC datetime.

    ``value`` is the DAG run's ``data_interval_end`` (``run_after`` for a manual run; Airflow passes
    pendulum datetimes), raised to the aging clock's mark when that is later (``enrichment_as_of`` in
    the DAG), an ISO-8601 string, or None for now (the command line). A naive datetime is UTC.
    """
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, str):
        value = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if not isinstance(value, datetime):
        raise TypeError(f"aging as_of must be a datetime or an ISO-8601 string, not {type(value).__name__}")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    # A plain datetime: pendulum's subclass would otherwise reach the driver as its own type.
    return datetime.fromtimestamp(value.timestamp(), tz=timezone.utc)


@dataclass(frozen=True)
class AgingPolicy:
    """The tiers and the retirement age (validated by ``load_aging_policy``)."""

    tier_days: Tuple[int, ...] = DEFAULT_TIER_DAYS
    factors: Tuple[float, ...] = DEFAULT_FACTORS
    retire_days: int = DEFAULT_RETIRE_DAYS

    def tier(self, age_days: Optional[int]) -> int:
        """The tier an age in whole days has reached (0 below the first tier day)."""
        if age_days is None:
            return 0
        return sum(1 for day in self.tier_days if day <= age_days)

    def factor(self, tier: int) -> float:
        """The factor of a tier (1.0 for tier 0)."""
        return ((1.0,) + tuple(self.factors))[tier]

    def tier_start(self, tier: int) -> int:
        """The first day of a tier, counted from the basis (0 for tier 0)."""
        return ((0,) + tuple(self.tier_days))[tier]

    def confidence(self, source_confidence: float, age_days: int) -> float:
        """Python form of the rule's confidence (rounded half up, as Cypher ``round(x, 2)``)."""
        value = Decimal(repr(float(source_confidence) * self.factor(self.tier(age_days))))
        rounded = float(value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
        return max(CONFIDENCE_FLOOR, rounded)


def _parse_list(raw: str, name: str, cast):
    parts = [p.strip() for p in raw.split(",")]
    if not parts or any(not p for p in parts):
        raise ValueError(f"{name}={raw!r}: expected a comma-separated list of numbers")
    try:
        return tuple(cast(p) for p in parts)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r}: expected a comma-separated list of numbers") from exc


def load_aging_policy(environ: Optional[Mapping[str, str]] = None) -> AgingPolicy:
    """The aging policy from ``EDGEGUARD_AGING_TIER_DAYS`` (default ``90,180,365``),
    ``EDGEGUARD_AGING_FACTORS`` (default ``0.85,0.70,0.55``) and ``EDGEGUARD_AGING_RETIRE_DAYS``
    (default ``730``), read at call time; an unset or empty variable takes its default.

    Raises ``ValueError`` when the days are not positive and strictly ascending, the factors are
    not one per tier in (0, 1], or the retire days are not above the last tier day: a wrong
    setting stops the write that needs it instead of aging the graph by an unintended rule.
    """
    env = os.environ if environ is None else environ
    raw_days = (env.get(TIER_DAYS_ENV) or "").strip()
    raw_factors = (env.get(FACTORS_ENV) or "").strip()
    raw_retire = (env.get(RETIRE_DAYS_ENV) or "").strip()
    tier_days = _parse_list(raw_days, TIER_DAYS_ENV, int) if raw_days else DEFAULT_TIER_DAYS
    factors = _parse_list(raw_factors, FACTORS_ENV, float) if raw_factors else DEFAULT_FACTORS
    try:
        retire_days = int(raw_retire) if raw_retire else DEFAULT_RETIRE_DAYS
    except ValueError as exc:
        raise ValueError(f"{RETIRE_DAYS_ENV}={raw_retire!r}: expected a whole number of days") from exc

    if not tier_days or tier_days[0] <= 0 or any(b <= a for a, b in zip(tier_days, tier_days[1:], strict=False)):
        raise ValueError(f"{TIER_DAYS_ENV}={raw_days!r}: the days must be positive and strictly ascending")
    if len(factors) != len(tier_days):
        raise ValueError(
            f"{FACTORS_ENV}={raw_factors!r}: one factor per tier day is needed ({len(tier_days)} tier days)"
        )
    if any(not (0.0 < f <= 1.0) for f in factors):
        raise ValueError(f"{FACTORS_ENV}={raw_factors!r}: every factor must be in (0, 1]")
    if retire_days <= tier_days[-1]:
        raise ValueError(
            f"{RETIRE_DAYS_ENV}={retire_days}: the retirement age must be above the last tier day ({tier_days[-1]})"
        )
    return AgingPolicy(tier_days=tuple(tier_days), factors=tuple(factors), retire_days=retire_days)


def _num(value: float) -> str:
    """A number as a Cypher float literal."""
    return repr(float(value))


def basis_expr(var: str) -> str:
    """Cypher: the time the node's age counts from (null when it has neither time)."""
    return f"coalesce({var}.last_reported_at, {var}.first_imported_at)"


def manual_decommission_expr(var: str) -> str:
    """Cypher predicate: the node was retired by hand (``retired_at`` without the decay tag)."""
    return f"({var}.retired_at IS NOT NULL AND coalesce({var}.retired_by, 'manual') <> '{RETIRED_BY_DECAY}')"


def aging_map(var: str, as_of: str, policy: Optional[AgingPolicy] = None) -> str:
    """Cypher map of the aging properties of the Indicator ``var`` at ``as_of`` (a Cypher
    DateTime expression: ``WRITE_AS_OF`` in a write, ``datetime($as_of)`` in the job).

    The single definition of the rule (module docstring); its keys are ``AGING_FIELDS``. A write
    applies it in its own clause (``aging_set_clause``) after the clause that records the report
    and ``source_confidence``, so a newer report reactivates the node in the same write; ``+=``
    evaluates the whole map before it assigns, so every entry reads the lifecycle stored before
    this clause. A node with neither ``last_reported_at`` nor ``first_imported_at`` keeps every
    value (EdgeGuard holds no time for it).
    """
    p = policy or load_aging_policy()
    days = ", ".join(str(d) for d in p.tier_days)
    factors = ", ".join(_num(f) for f in (1.0,) + tuple(p.factors))
    starts = ", ".join(str(d) for d in (0,) + tuple(p.tier_days))
    retire = p.retire_days
    v = var
    keep = f"_age IS NULL OR {manual_decommission_expr(v)}"
    factor = f"[{factors}][_tier]"
    return (
        f"[_basis IN [{basis_expr(v)}] | [_age IN [duration.inDays(_basis, {as_of}).days] | "
        f"[_tier IN [size([_t IN [{days}] WHERE _t <= _age])] | {{"
        f"aging_basis: CASE WHEN _age IS NULL THEN {v}.aging_basis "
        f"WHEN {v}.last_reported_at IS NULL THEN '{BASIS_FIRST_IMPORTED}' "
        f"ELSE coalesce({v}.last_reported_basis, {v}.aging_basis) END, "
        f"aging_tier: CASE WHEN _age IS NULL THEN {v}.aging_tier ELSE _tier END, "
        f"aging_factor: CASE WHEN _age IS NULL THEN {v}.aging_factor ELSE {factor} END, "
        f"aging_since: CASE WHEN _age IS NULL THEN {v}.aging_since "
        f"WHEN _age >= {retire} AND NOT {manual_decommission_expr(v)} THEN _basis + duration({{days: {retire}}}) "
        f"ELSE _basis + duration({{days: [{starts}][_tier]}}) END, "
        f"confidence_score: CASE WHEN _age IS NULL OR {v}.source_confidence IS NULL THEN {v}.confidence_score "
        f"WHEN {v}.source_confidence * {factor} < {_num(CONFIDENCE_FLOOR)} THEN {_num(CONFIDENCE_FLOOR)} "
        f"ELSE round({v}.source_confidence * {factor}, 2) END, "
        f"active: CASE WHEN {keep} THEN {v}.active WHEN _age >= {retire} THEN false ELSE true END, "
        f"retired_at: CASE WHEN {keep} THEN {v}.retired_at "
        f"WHEN _age >= {retire} THEN _basis + duration({{days: {retire}}}) ELSE null END, "
        f"retired_by: CASE WHEN {keep} THEN {v}.retired_by WHEN _age >= {retire} THEN '{RETIRED_BY_DECAY}' ELSE null END"
        f"}}][0]][0]][0]"
    )


def aging_set_item(var: str, as_of: str, policy: Optional[AgingPolicy] = None) -> str:
    """The ``SET`` item that applies the rule to ``var`` (``aging_set_clause`` wraps it)."""
    return f"{var} += {aging_map(var, as_of, policy)}"


def aging_set_clause(var: str, as_of: str, policy: Optional[AgingPolicy] = None) -> str:
    """The ``SET`` clause that applies the rule to the Indicator ``var`` (2026-10-16).

    Spliced after the clause holding ``source_confidence_item`` and ``node_report_items``, never
    into it: the rule reads ``last_reported_at``, ``last_reported_basis`` and ``source_confidence``,
    and a later clause sees what an earlier clause wrote, whereas items of one ``SET`` clause would
    rely on the order in which Neo4j applies them."""
    return f"SET {aging_set_item(var, as_of, policy)}"


# The properties the rule sets (the keys of ``aging_map``); the job writes a node when any differs.
AGING_FIELDS: Tuple[str, ...] = (
    "aging_basis",
    "aging_tier",
    "aging_factor",
    "aging_since",
    "confidence_score",
    "active",
    "retired_at",
    "retired_by",
)


def changed_predicate(var: str, map_var: str) -> str:
    """Cypher predicate: a value of ``AGING_FIELDS`` in the map ``map_var`` differs from the stored
    one (a null and a value differ; two nulls do not), so the job writes only nodes whose aging
    changes, and every node with a stale aging property (``aging_basis`` among them)."""
    fields = ", ".join(f"'{f}'" for f in AGING_FIELDS)
    return (
        f"any(_k IN [{fields}] WHERE NOT coalesce({var}[_k] = {map_var}[_k], "
        f"{var}[_k] IS NULL AND {map_var}[_k] IS NULL))"
    )


def _newer_report(target: str, reported_at: str, ref: str, source: str) -> str:
    """Cypher predicate: the incoming report is newer than the one ``target`` holds; an equal time
    wins with the smaller reference (then source), so the arrival order does not matter."""
    t = target
    return (
        f"({reported_at} IS NOT NULL AND ({t}.last_reported_at IS NULL "
        f"OR datetime({reported_at}) > {t}.last_reported_at "
        f"OR (datetime({reported_at}) = {t}.last_reported_at "
        f"AND (coalesce({ref}, '') < coalesce({t}.last_reported_ref, '') "
        f"OR (coalesce({ref}, '') = coalesce({t}.last_reported_ref, '') "
        f"AND coalesce({source}, '') < coalesce({t}.last_reported_source, ''))))))"
    )


def _forward_recorded(target: str, recorded_at: str) -> str:
    t = target
    return (
        f"{t}.last_recorded_at = CASE WHEN {recorded_at} IS NULL THEN {t}.last_recorded_at "
        f"WHEN {t}.last_recorded_at IS NULL OR datetime({recorded_at}) > {t}.last_recorded_at "
        f"THEN datetime({recorded_at}) ELSE {t}.last_recorded_at END"
    )


def node_report_items(var: str, row: str, source: str) -> str:
    """``SET`` items recording one report on the Indicator ``var``, forward only: the latest MISP
    record time, and the latest report time with its source, reference and kind
    (``last_reported_basis``) when the report is newer (``_newer_report``). ``row`` is the Cypher
    map holding ``recorded_at``, ``reported_at``, ``report_ref`` and ``reported_basis`` (``item`` in
    a batch, a parameter map otherwise); ``source`` the source id expression. The clause holding
    them precedes ``aging_set_clause``, which derives ``aging_basis`` from the kind."""
    newer = _newer_report(var, f"{row}.reported_at", f"{row}.report_ref", source)
    return (
        f"{_forward_recorded(var, f'{row}.recorded_at')}, "
        f"{var} += CASE WHEN {newer} THEN {{last_reported_at: datetime({row}.reported_at), "
        f"last_reported_source: {source}, last_reported_ref: {row}.report_ref, "
        f"last_reported_basis: {row}.reported_basis}} ELSE {{}} END"
    )


def edge_report_items(rel: str, row: str, source: str) -> str:
    """``SET`` items recording one report on an Indicator's ``SOURCED_FROM`` edge ``rel`` (the
    report times of that one source), with the same forward-only rules as ``node_report_items``."""
    newer = _newer_report(rel, f"{row}.reported_at", f"{row}.report_ref", source)
    return (
        f"{_forward_recorded(rel, f'{row}.recorded_at')}, "
        f"{rel} += CASE WHEN {newer} THEN {{last_reported_at: datetime({row}.reported_at), "
        f"last_reported_source: {source}, last_reported_ref: {row}.report_ref}} ELSE {{}} END"
    )


def source_confidence_item(var: str, incoming: str) -> str:
    """``SET`` item: ``source_confidence`` keeps the highest confidence a source gave (incoming
    values only; never filled from an aged ``confidence_score``)."""
    return (
        f"{var}.source_confidence = CASE WHEN {incoming} IS NULL THEN {var}.source_confidence "
        f"WHEN {var}.source_confidence IS NULL OR {incoming} > {var}.source_confidence "
        f"THEN {incoming} ELSE {var}.source_confidence END"
    )


# The report keys an Indicator item carries from the sync (``run_misp_to_neo4j.misp_report_times``).
REPORT_KEYS: Tuple[str, ...] = ("recorded_at", "reported_at", "report_ref", "reported_basis")


def report_row(item: Mapping[str, object]) -> dict:
    """The report keys of an item, each ``None`` when absent (writers without a MISP report)."""
    return {key: (item.get(key) or None) for key in REPORT_KEYS}
