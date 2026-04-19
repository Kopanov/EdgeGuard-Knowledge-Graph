"""
EdgeGuard — Baseline Configuration (single source of truth)
============================================================

Centralizes the resolution of baseline-mode configuration values that have
been historically defined in 4+ places with subtle drift:

  - ``DEFAULT_BASELINE_DAYS`` was hardcoded as ``730`` in:
      * src/run_pipeline.py:881 (CLI default)
      * src/run_pipeline.py:1104 (inner method default)
      * dags/edgeguard_pipeline.py:1732 (DAG ENV default)
      * dags/edgeguard_pipeline.py:1744 (DAG Variable default)
    plus the CLI's ``--baseline-days`` help text said "365" while the
    actual default was 730 (audit Cross-Checker MED + Devil's Advocate).

  - ``BASELINE_COLLECTION_LIMIT`` had similar sprawl.

This module gives both call sites (CLI + DAG) one resolution function with
documented precedence. Any future change to the default propagates without
hunting for hardcoded strings.

Resolution precedence (highest first):
  1. Explicit kwarg/CLI flag (``--baseline-days N`` or ``baseline_days=N``)
  2. ``dag_run.conf`` override (DAG-only — the operator triggering the DAG
      can override per-run via the JSON conf box)
  3. ``EDGEGUARD_BASELINE_DAYS`` env var
  4. Airflow Variable ``BASELINE_DAYS`` (DAG-only — for persistent
      operator overrides without touching env)
  5. ``DEFAULT_BASELINE_DAYS`` (730)

This precedence is now documented HERE rather than scattered across
DAG/CLI files (audit Cross-Checker MED found the previous docs claimed
"env > Variable" while the actual code did "Variable > env override").
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Defaults — single source of truth
# --------------------------------------------------------------------------- #

#: 2 years of historical data is the recommended baseline window. Audit
#: Cross-Checker confirmed 730 is the value used by both DAG and CLI in
#: practice; the previous CLI ``--baseline-days`` help text saying "365"
#: was wrong. Documented at:
#:   - docs/AIRFLOW_DAGS.md
#:   - docs/BASELINE_SMOKE_TEST.md
DEFAULT_BASELINE_DAYS: int = 730

#: Collection limit defaults to 0 = UNLIMITED. Set to a small number for
#: smoke tests; production baselines should always be 0.
DEFAULT_BASELINE_COLLECTION_LIMIT: int = 0

#: Minimum sane baseline window — anything lower triggers a warning. A
#: 30-day baseline is so close to incremental that the operator probably
#: meant to run an incremental DAG instead.
MIN_REASONABLE_BASELINE_DAYS: int = 30


# --------------------------------------------------------------------------- #
# Resolution functions
# --------------------------------------------------------------------------- #


def resolve_baseline_days(
    *,
    explicit: Optional[int] = None,
    dag_run_conf: Optional[dict] = None,
    airflow_variable_value: Optional[Any] = None,
) -> int:
    """Resolve the effective baseline window in days.

    Precedence (highest first):

      1. ``explicit`` — CLI flag or function kwarg. Takes priority over
         everything else when set.
      2. ``dag_run_conf["baseline_days"]`` — per-run operator override
         from the Airflow trigger UI's JSON conf box.
      3. ``EDGEGUARD_BASELINE_DAYS`` env var.
      4. ``airflow_variable_value`` — caller passes the result of
         ``Variable.get("BASELINE_DAYS", default=None)``. Resolved here
         so this module has zero airflow dependency.
      5. ``DEFAULT_BASELINE_DAYS`` (730).

    Logs a warning if the resolved value is below
    ``MIN_REASONABLE_BASELINE_DAYS`` — operators sometimes mean to trigger
    an incremental run but accidentally trigger the baseline DAG with a
    short window.

    Args:
        explicit: CLI flag value or function kwarg. None means "not set".
        dag_run_conf: ``context["dag_run"].conf`` from an Airflow operator,
            or None for non-DAG callers.
        airflow_variable_value: The value of the ``BASELINE_DAYS`` Airflow
            Variable, or None. Caller must pass — this module doesn't
            import airflow.

    Returns:
        Resolved baseline window in days. Always >= 1 (negative or zero
        values are clamped to ``DEFAULT_BASELINE_DAYS`` with a warning).
    """
    # 1. Explicit
    if explicit is not None:
        days = _coerce_positive_int(explicit, label="explicit")
        if days is not None:
            return _check_warn(days)

    # 2. dag_run.conf override
    if dag_run_conf:
        conf_val = dag_run_conf.get("baseline_days")
        if conf_val is not None:
            days = _coerce_positive_int(conf_val, label="dag_run.conf['baseline_days']")
            if days is not None:
                return _check_warn(days)

    # 3. Env var
    env_val = os.getenv("EDGEGUARD_BASELINE_DAYS")
    if env_val:
        days = _coerce_positive_int(env_val, label="EDGEGUARD_BASELINE_DAYS")
        if days is not None:
            return _check_warn(days)

    # 4. Airflow Variable (caller-provided)
    if airflow_variable_value is not None:
        days = _coerce_positive_int(airflow_variable_value, label="Variable['BASELINE_DAYS']")
        if days is not None:
            return _check_warn(days)

    # 5. Default
    return DEFAULT_BASELINE_DAYS


def resolve_baseline_collection_limit(
    *,
    explicit: Optional[int] = None,
    dag_run_conf: Optional[dict] = None,
    airflow_variable_value: Optional[Any] = None,
) -> int:
    """Resolve the effective per-collector item limit for baseline mode.

    Same precedence shape as ``resolve_baseline_days``. ``0`` means
    UNLIMITED (the production default). Negative values are clamped to 0
    with a warning.

    Args:
        explicit, dag_run_conf, airflow_variable_value: see
            ``resolve_baseline_days``. The conf key here is
            ``"collection_limit"``; the env var is
            ``EDGEGUARD_BASELINE_COLLECTION_LIMIT``.

    Returns:
        Resolved item limit. 0 = unlimited.
    """
    if explicit is not None:
        n = _coerce_nonneg_int(explicit, label="explicit")
        if n is not None:
            return n

    if dag_run_conf:
        conf_val = dag_run_conf.get("collection_limit")
        if conf_val is not None:
            n = _coerce_nonneg_int(conf_val, label="dag_run.conf['collection_limit']")
            if n is not None:
                return n

    env_val = os.getenv("EDGEGUARD_BASELINE_COLLECTION_LIMIT")
    if env_val:
        n = _coerce_nonneg_int(env_val, label="EDGEGUARD_BASELINE_COLLECTION_LIMIT")
        if n is not None:
            return n

    if airflow_variable_value is not None:
        n = _coerce_nonneg_int(airflow_variable_value, label="Variable['BASELINE_COLLECTION_LIMIT']")
        if n is not None:
            return n

    return DEFAULT_BASELINE_COLLECTION_LIMIT


# --------------------------------------------------------------------------- #
# Internal coercion helpers
# --------------------------------------------------------------------------- #


def _coerce_positive_int(value: Any, *, label: str) -> Optional[int]:
    """Coerce ``value`` to a positive int. Returns None if not coercible.

    On a negative or zero value, logs a warning and returns None so the
    caller falls through to the next precedence level (rather than
    returning a nonsense value).
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        logger.warning("baseline_config: %s=%r is not an int — falling through", label, value)
        return None
    if n <= 0:
        logger.warning("baseline_config: %s=%d must be positive — falling through", label, n)
        return None
    return n


def _coerce_nonneg_int(value: Any, *, label: str) -> Optional[int]:
    """Coerce to a non-negative int (0 is allowed and means UNLIMITED)."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        logger.warning("baseline_config: %s=%r is not an int — falling through", label, value)
        return None
    if n < 0:
        logger.warning("baseline_config: %s=%d is negative — clamping to 0 (UNLIMITED)", label, n)
        return 0
    return n


def _check_warn(days: int) -> int:
    """Warn if the resolved window is below the minimum-reasonable threshold."""
    if days < MIN_REASONABLE_BASELINE_DAYS:
        logger.warning(
            "baseline_config: resolved baseline window is %d days, below the "
            "recommended minimum of %d. If you meant to run an incremental "
            "sync, trigger an incremental DAG (medium_freq, daily, low_freq) "
            "instead of the baseline DAG.",
            days,
            MIN_REASONABLE_BASELINE_DAYS,
        )
    return days
