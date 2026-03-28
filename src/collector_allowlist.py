"""
EDGEGUARD_COLLECT_SOURCES — which collectors may run.

This module is intentionally **not** under ``collectors/`` so Airflow can import it at DAG
parse time without loading ``collectors/__init__.py`` (which imports every collector).

``run_collector_with_metrics`` uses :func:`is_collector_enabled_by_allowlist` at task runtime
and lazy-imports ``make_skipped_optional_source`` only when skipping.
"""

from __future__ import annotations

import logging
import os
from typing import FrozenSet, Optional, Set

logger = logging.getLogger(__name__)

COLLECT_SOURCES_CANONICAL: FrozenSet[str] = frozenset(
    {
        "otx",
        "nvd",
        "cisa",
        "mitre",
        "virustotal",
        "virustotal_enrich",
        "abuseipdb",
        "threatfox",
        "urlhaus",
        "cybercure",
        "feodo",
        "sslbl",
    }
)


def collect_sources_allowlist_from_env() -> Optional[FrozenSet[str]]:
    """Parse ``EDGEGUARD_COLLECT_SOURCES``.

    - Unset or whitespace-only → ``None`` (all collectors enabled).
    - ``none``, ``-``, or ``0`` alone (case-insensitive) → empty frozenset (disable all).
    - Otherwise comma-separated canonical names; unknown tokens are logged and ignored.
    - If non-empty but no valid names remain → ``None`` (fail-open) with warning.
    """
    raw = os.getenv("EDGEGUARD_COLLECT_SOURCES", "")
    stripped = str(raw).strip()
    if not stripped:
        return None
    low = stripped.lower()
    if low in ("none", "-", "0"):
        return frozenset()
    parts: Set[str] = set()
    unknown: list[str] = []
    for token in stripped.split(","):
        t = token.strip().lower()
        if not t:
            continue
        if t in COLLECT_SOURCES_CANONICAL:
            parts.add(t)
        else:
            unknown.append(token.strip())
    if unknown:
        logger.warning(
            "EDGEGUARD_COLLECT_SOURCES: ignored unknown collector name(s): %s — use: %s",
            unknown,
            ", ".join(sorted(COLLECT_SOURCES_CANONICAL)),
        )
    if not parts:
        logger.warning("EDGEGUARD_COLLECT_SOURCES had no valid names — treating as unset (all collectors enabled)")
        return None
    return frozenset(parts)


def is_collector_enabled_by_allowlist(
    collector_name: str,
    allowed: Optional[FrozenSet[str]] = None,
) -> bool:
    """True if this collector should run given ``EDGEGUARD_COLLECT_SOURCES``.

    If ``allowed`` is provided (e.g. pre-parsed in a tight loop), it is used instead of
    re-reading the environment on each call.
    """
    if allowed is None:
        allowed = collect_sources_allowlist_from_env()
    if allowed is None:
        return True
    if not allowed:
        return False
    return collector_name.strip().lower() in allowed
