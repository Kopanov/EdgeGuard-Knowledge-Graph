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
``aging_factor``, ``aging_since`` (when the current state began: the basis plus the first day
of the tier, or plus the retire days once retired) and ``aging_evaluated_at`` (below).

One definition
--------------
``aging_map`` is the single Cypher definition of the rule. Every Indicator write applies it
(``Neo4jClient.merge_indicators_batch``, ``merge_node_with_source`` for the label Indicator,
``create_indicator_from_alert``) in a ``SET`` clause of its own (``aging_set_clause``) after the
clause that records the report and ``source_confidence``: a clause reads the node as the previous
clause left it, so the rule sees the report of the same write (a newer report reactivates the node
in that write) without depending on the order in which one ``SET`` clause applies its items.
``enrichment_jobs.decay_ioc_confidence`` applies it to every Indicator and writes a node when any
of its ``AGING_FIELDS`` differs from the stored value. ``node_report_items`` /
``edge_report_items`` are the forward-only report properties of the node and of its
``SOURCED_FROM`` edge. Tests pin every splice.

The time of an evaluation
-------------------------
(2026-10-16) Every evaluation, a write or the job, applies the rule at the database's current time
(``DATABASE_TIME``, the statement clock: one instant per statement, read when it starts), lifted to
the node's ``aging_evaluated_at`` when that is later (``evaluated_at_expr``), and stores that time
with the aging values whenever it writes them. Real time only moves forward, so an evaluation whose
statement starts later evaluates at a later time, whichever DAG run it belongs to: a cleared or
re-run task, a baseline overlapping a scheduled sync and the command line evaluate at the time they
run, and a write of a newer report evaluates that report at the time its statement started. No run
passes a time and no clock is shared between runs.

For one basis, every value of the rule (tier, factor, confidence, ``aging_since``, ``active``,
``retired_at``, ``retired_by``) changes in one direction only as the time grows. The lift keeps a
node from moving backwards where the clocks of two evaluations do not follow their order: two
transactions that overlap (each statement reads the clock when it starts) or a clock set back on
the database server. ``aging_evaluated_at`` is the time at which the node's aging values were last
written (a write, or a job run that changed them); a job run that changes nothing leaves it
unchanged, so a node holds the state of its stored time, which is also the state of every later
time it was evaluated at without a change.

Two evaluations of one node never interleave. The batch and single-item writes set properties of
the node in the clause before the rule, which takes the node's write lock until the write commits,
and read the node for the rule after that clause. The alert path applies the rule in a second
statement of its transaction (``Neo4jClient.create_indicator_from_alert``): in its one statement
the planner reads the basis with the ``MERGE``, before the lock. The job locks each node it is
about to change (``apoc.lock.nodes``) and evaluates it again under the lock. A time a test gives
the job (``decay_ioc_confidence(as_of=...)``) is lifted per node in the same way, so it cannot move
a node backwards either.

One case leaves a node behind the latest evaluation for a while, without moving it backwards. The
job selects the nodes to change without a lock, and a job run that changes none of a node's values
neither locks it nor stores a time on it, so a write whose statement started before that job
evaluated the node, and which commits a newer report after it, evaluates the report at its own
statement's start, earlier than the job's time. The node then holds the state of the new report at
that earlier time until the next write or job evaluates it at its own time. The gap lasts as long
as that write's statement ran, lock waits included (the batch write locks all its rows with the
``MERGE`` before it sets any property).

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

# 2026-10-16: the time an evaluation applies the rule at before the per-node lift: the database's
# current time (the clock of the statement, read when it starts). No run passes a time.
DATABASE_TIME = "datetime()"

# 2026-10-16: the property holding the time at which the node's aging values were last written; an
# evaluation at an older time is lifted to it (``evaluated_at_expr``).
EVALUATED_AT = "aging_evaluated_at"


def evaluation_time(value: Any) -> datetime:
    """A time given to the aging job by a test (``decay_ioc_confidence(as_of=...)``) as an aware UTC
    datetime: a datetime (pendulum's subclass included) or an ISO-8601 string; a naive datetime is
    UTC. Production passes none: the rule runs at the database's current time (``DATABASE_TIME``).
    Either time is lifted to the node's ``aging_evaluated_at`` when that is later
    (``evaluated_at_expr``)."""
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


def evaluated_at_expr(var: str, as_of: str = DATABASE_TIME) -> str:
    """Cypher: the time the rule evaluates the Indicator ``var`` at (2026-10-16), the later of
    ``as_of`` (the database's current time; a test's time in the job) and the node's
    ``aging_evaluated_at`` (``as_of`` when the node has none). An evaluation whose clock is behind
    the node's time is lifted to it, so the node's aging never moves backwards (module docstring)."""
    stored = f"{var}.{EVALUATED_AT}"
    return f"CASE WHEN {stored} > {as_of} THEN {stored} ELSE {as_of} END"


def aging_map(var: str, as_of: str = DATABASE_TIME, policy: Optional[AgingPolicy] = None) -> str:
    """Cypher map of the aging properties of the Indicator ``var`` at ``as_of``, lifted to the node's
    ``aging_evaluated_at`` when that is later (``evaluated_at_expr``). ``as_of`` is a Cypher DateTime
    expression: ``DATABASE_TIME`` (the database's current time) in a write; in the job
    ``enrichment_jobs.AGING_JOB_TIME``, the database's current time unless a test gives a time.

    The single definition of the rule (module docstring); its keys are ``AGING_MAP_KEYS``: the
    ``AGING_FIELDS`` and ``aging_evaluated_at``, the time of this evaluation. A write applies
    it in its own clause (``aging_set_clause``) after the clause that records the report and
    ``source_confidence``, so a newer report reactivates the node in the same write; ``+=``
    evaluates the whole map before it assigns, so every entry reads the lifecycle stored before
    this clause. A node with neither ``last_reported_at`` nor ``first_imported_at`` keeps every
    value (EdgeGuard holds no time for it), ``aging_evaluated_at`` included.
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
        f"[_at IN [{evaluated_at_expr(v, as_of)}] | "
        f"[_basis IN [{basis_expr(v)}] | [_age IN [duration.inDays(_basis, _at).days] | "
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
        f"retired_by: CASE WHEN {keep} THEN {v}.retired_by WHEN _age >= {retire} THEN '{RETIRED_BY_DECAY}' ELSE null END, "
        f"{EVALUATED_AT}: CASE WHEN _age IS NULL THEN {v}.{EVALUATED_AT} ELSE _at END"
        f"}}][0]][0]][0]][0]"
    )


def aging_set_item(var: str, policy: Optional[AgingPolicy] = None) -> str:
    """The ``SET`` item that applies the rule to ``var`` at the database's current time, lifted per
    node (``aging_set_clause`` wraps it)."""
    return f"{var} += {aging_map(var, DATABASE_TIME, policy)}"


def aging_set_clause(var: str, policy: Optional[AgingPolicy] = None) -> str:
    """The ``SET`` clause that applies the rule to the Indicator ``var`` in a write (2026-10-16), at
    the database's current time lifted to the node's ``aging_evaluated_at``; a write passes no time.

    Spliced after the clause holding ``source_confidence_item`` and ``node_report_items``, never
    into it: the rule reads ``last_reported_at``, ``last_reported_basis`` and ``source_confidence``,
    and a later clause sees what an earlier clause wrote, whereas items of one ``SET`` clause would
    rely on the order in which Neo4j applies them."""
    return f"SET {aging_set_item(var, policy)}"


# The aging values the rule sets; the job writes a node when any differs from the stored one.
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

# The keys of ``aging_map``: the aging values and the time of the evaluation, which is written with
# them and never on its own (it is no reason to write a node), so a node's ``aging_evaluated_at`` is
# the time at which its aging values were last written.
AGING_MAP_KEYS: Tuple[str, ...] = AGING_FIELDS + (EVALUATED_AT,)


def changed_predicate(var: str, map_var: str) -> str:
    """Cypher predicate: a value of ``AGING_FIELDS`` in the map ``map_var`` differs from the stored
    one (a null and a value differ; two nulls do not), so the job writes only nodes whose aging
    changes, and every node with a stale aging property (``aging_basis`` among them). A later
    ``aging_evaluated_at`` alone is no change; a node evaluated without one stored (written before
    2026-10-16) is written once, so that every node evaluated holds its time."""
    fields = ", ".join(f"'{f}'" for f in AGING_FIELDS)
    return (
        f"(({var}.{EVALUATED_AT} IS NULL AND {map_var}.{EVALUATED_AT} IS NOT NULL) "
        f"OR any(_k IN [{fields}] WHERE NOT coalesce({var}[_k] = {map_var}[_k], "
        f"{var}[_k] IS NULL AND {map_var}[_k] IS NULL)))"
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
