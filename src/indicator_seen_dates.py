"""Seen dates of an indicator: when it is first and last known to have been reported (2026-10-25).

An indicator's dates live on its ``SOURCED_FROM`` edges, one per source (``docs/TIMESTAMPS.md``):

* ``r.source_reported_first_at`` / ``r.source_reported_last_at``, the source's own first-seen and
  last-seen claims, from the sources on the reliable first-seen allowlist only
  (``source_truthful_timestamps``; OTX is not on it, so an OTX edge has neither);
* ``r.last_reported_at``, the source's latest report of the indicator, on every indicator edge the
  MISP -> Neo4j sync writes (the one writer of an indicator's ``SOURCED_FROM`` edges; an alert writes
  none): the source's own last-report date capped at the MISP record time, or the MISP record time
  when the source gave none (``indicator_aging``);
* ``r.last_recorded_at``, the MISP record time of the source's latest record, on the same edges.
  The edge does not store which kind of date its report is; a report earlier than the record time
  is the source's own date (the two are equal only when the source's date is the record time
  itself), a report equal to it is the record time.

Reading the claims alone left every indicator without them undated, and a campaign whose indicators
all came from OTX took EdgeGuard's import time as its first and last seen. The seen dates read
every edge:

* first seen: per edge, the source's first-seen claim, else its latest report; the earliest over the
  edges, and never later than the indicator's ``first_imported_at`` (EdgeGuard has had the indicator
  since then, from a source or an alert, while an edge keeps only the source's latest report, which
  a later report moves past the import); ``first_imported_at`` when no edge dates it.
* last seen: per edge, the source's own date (2026-11-02): its last-seen claim, else its latest
  report when that is a date the source gave, else its first-seen claim, else its latest report
  (the MISP record time); the latest over the edges; ``last_updated`` only when no edge dates the
  indicator (one no source reported, such as an indicator an alert created). A feed that sends no
  last-seen date (MalwareBazaar, SSL Blacklist, often ThreatFox) has the MISP record time, the time
  of the push, as the latest report of every item; its first-seen claim dates such an edge instead.

The indicator's own ``last_reported_at`` is not a fallback: every writer records the same report on
that source's edge (the sync's batch write in the same statement), so it is the latest of its edges'
reports, and an indicator without a dated edge has none.

The campaign build (``enrichment_jobs.build_campaign_nodes``) and the alert enrichment
(``alert_processor``) read the definition from this module, so they cannot use different ones. The
campaign build also takes its sample of up to 100 indicators by the per-edge last date
(``sample_date``, 2026-11-02), so the sample and the campaign dates follow one definition. The
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
    """Cypher: the last-report date the ``SOURCED_FROM`` edge ``rel`` gives, by the source's own dates:
    its last-seen claim; else its latest report when that is earlier than the edge's MISP record time
    (then it is a date the source gave); else its first-seen claim; else its latest report (the MISP
    record time, or the report of an edge without a record time). A null comparison (an edge
    without ``last_recorded_at``) passes to the next date."""
    return (
        f"coalesce({rel}.source_reported_last_at, "
        f"CASE WHEN {rel}.last_reported_at < {rel}.last_recorded_at THEN {rel}.last_reported_at END, "
        f"{rel}.source_reported_first_at, {rel}.last_reported_at)"
    )


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


def sample_date(edges_last: str, indicator: str) -> str:
    """Cypher: the date by which the campaign build orders an indicator for its sample, newest first
    (2026-11-02). ``edges_last`` names a variable that holds the latest ``edge_last`` over its edges;
    ``first_imported_at`` when no edge dates the indicator (``last_updated`` moves with every write,
    so it would put each node a sync just rewrote first)."""
    return f"coalesce({edges_last}, {indicator}.first_imported_at)"
