"""Seen dates of an indicator: when it is first and last known to have been reported (2026-10-25).

An indicator's dates live on its ``SOURCED_FROM`` edges, one per source (``docs/TIMESTAMPS.md``):

* ``r.source_reported_first_at`` / ``r.source_reported_last_at``, the source's own first-seen and
  last-seen claims, from the sources on the reliable first-seen allowlist only
  (``source_truthful_timestamps``; OTX is not on it, so an OTX edge has neither);
* ``r.last_reported_at``, the source's latest report of the indicator, on every indicator edge:
  the source's own last-report date capped at the MISP record time, or the MISP record time when
  the source gave none (``indicator_aging``).

Reading the claims alone left every indicator without them undated, and a campaign whose indicators
all came from OTX took EdgeGuard's import time as its first and last seen. The seen dates read
every edge:

* first seen: per edge, the source's first-seen claim, else its latest report; the earliest over the
  edges, and never later than the indicator's ``first_imported_at`` (EdgeGuard has had the indicator
  since then, from a source or an alert, while an edge keeps only the source's latest report, which
  a later report moves past the import); ``first_imported_at`` when no edge dates it.
* last seen: per edge, the source's last-seen claim, else its latest report; the latest over the
  edges; ``last_updated`` only when no edge dates the indicator (one no source reported, such as an
  indicator an alert created).

The indicator's own ``last_reported_at`` is not a fallback: every writer records the same report on
that source's edge (the sync's batch write in the same statement), so it is the latest of its edges'
reports, and an indicator without a dated edge has none.

The campaign build (``enrichment_jobs.build_campaign_nodes``) and the alert enrichment
(``alert_processor``) read the definition from this module, so they cannot use different ones. The
STIX export does not for indicators: their ``x_edgeguard_*_seen_at_source`` properties are the
sources' claims only, and ``valid_from`` without a first-seen claim stays ``first_imported_at``; a
Campaign SDO carries the campaign's dates (``stix_exporter``).

Standard library only; the fragments contain no quotes.
"""

from __future__ import annotations


def edge_first(rel: str) -> str:
    """Cypher: the first-report date the ``SOURCED_FROM`` edge ``rel`` gives: the source's first-seen
    claim, else its latest report."""
    return f"coalesce({rel}.source_reported_first_at, {rel}.last_reported_at)"


def edge_last(rel: str) -> str:
    """Cypher: the last-report date the ``SOURCED_FROM`` edge ``rel`` gives: the source's last-seen
    claim, else its latest report."""
    return f"coalesce({rel}.source_reported_last_at, {rel}.last_reported_at)"


def first_seen(edges_first: str, indicator: str) -> str:
    """Cypher: the first seen date of ``indicator``. ``edges_first`` names a variable that holds the
    earliest ``edge_first`` over its edges (null when no edge dates it); the result is never later
    than the indicator's ``first_imported_at``, which it is when no edge dates it."""
    return (
        f"CASE WHEN {edges_first} IS NULL OR {indicator}.first_imported_at < {edges_first} "
        f"THEN {indicator}.first_imported_at ELSE {edges_first} END"
    )


def last_seen(edges_last: str, indicator: str) -> str:
    """Cypher: the last seen date of ``indicator``. ``edges_last`` names a variable that holds the
    latest ``edge_last`` over its edges; ``last_updated`` when no edge dates the indicator."""
    return f"coalesce({edges_last}, {indicator}.last_updated)"
