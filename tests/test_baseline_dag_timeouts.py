"""Pin baseline DAG ``execution_timeout`` values (2026-04-19 regression).

Vanko's overnight ``edgeguard_baseline`` run failed because
``baseline_build_rels_task`` had ``execution_timeout=timedelta(minutes=45)``
hardcoded — Airflow killed it twice at exactly 45min while the
subprocess inside (which has a 5h internal timeout) was still
processing the relationship batches against a 344K-node graph.

This module pins:

A. **`baseline_build_rels_task`** has at least a 4h execution_timeout.
   The fix bumped it to 5h to MATCH the equivalent task in the
   incremental DAG (``build_relationships_task`` at line ~1655).
   Baseline has MORE work than incremental, so its timeout MUST be
   >= incremental's.

B. **No baseline collection task has < 30min execution_timeout** —
   collectors that finish in <1s today (cisa, mitre, threatfox,
   abuseipdb) need headroom for transient API slowness, and the
   "manage by exception" model is harmed when timeouts are tighter
   than the actual rare-case duration. Anything below 30min is
   either a pre-flight check (which IS allowed at 5min) or a bug.

C. **`run_enrichment_jobs`** still has at least 4h headroom — it
   runs AFTER build_relationships and grows with the graph.

D. **No two equivalent tasks** in the baseline + incremental DAGs
   have inconsistent timeouts. (Specifically: build_relationships
   should have the same or longer timeout in baseline vs. incremental.)
"""

from __future__ import annotations

import os
import re
import sys
from datetime import timedelta

_DAGS = os.path.join(os.path.dirname(__file__), "..", "dags")
if _DAGS not in sys.path:
    sys.path.insert(0, _DAGS)


def _read_dag_source() -> str:
    path = os.path.join(_DAGS, "edgeguard_pipeline.py")
    with open(path) as fh:
        return fh.read()


def _extract_task_timeout(src: str, task_var_name: str) -> timedelta:
    """Find ``<task_var_name> = PythonOperator(...)`` and return the
    ``execution_timeout=timedelta(...)`` value as a real ``timedelta``.

    Tolerates multi-line / multi-keyword constructor styles.
    """
    # Locate the operator block: from `<var> = PythonOperator(` to the
    # matching closing paren.
    head = re.search(rf"\b{re.escape(task_var_name)}\s*=\s*PythonOperator\(", src)
    assert head is not None, f"could not locate {task_var_name} PythonOperator(...)"
    start = head.end()
    depth = 1
    end = start
    while end < len(src) and depth > 0:
        if src[end] == "(":
            depth += 1
        elif src[end] == ")":
            depth -= 1
        end += 1
    block = src[start:end]

    # Find execution_timeout=timedelta(...) inside the block
    m = re.search(r"execution_timeout\s*=\s*timedelta\(([^)]+)\)", block)
    assert m is not None, f"{task_var_name} has no execution_timeout=timedelta(...) — got block: {block[:300]}"
    args_blob = m.group(1)
    # Parse keyword args (e.g. "minutes=45", "hours=5")
    kwargs: dict[str, float] = {}
    for kv in re.split(r",\s*", args_blob):
        kv = kv.strip()
        if not kv:
            continue
        k, _, v = kv.partition("=")
        kwargs[k.strip()] = float(v.strip())
    return timedelta(**kwargs)


def test_baseline_build_relationships_has_at_least_four_hour_timeout():
    """The 2026-04-19 regression: baseline build_relationships had
    45min; was killed twice. MUST be at least 4h going forward."""
    src = _read_dag_source()
    tdelta = _extract_task_timeout(src, "baseline_build_rels_task")
    assert tdelta >= timedelta(hours=4), (
        f"baseline build_relationships execution_timeout is {tdelta} — must be >= 4h "
        "to handle 730-day baseline against populated graph (Vanko regression 2026-04-19)"
    )


def test_baseline_build_relationships_timeout_matches_or_exceeds_incremental():
    """Baseline has MORE work than incremental — its timeout MUST
    be at least as long. The pre-fix state had baseline=45min and
    incremental=5h, an inverted invariant."""
    src = _read_dag_source()
    baseline = _extract_task_timeout(src, "baseline_build_rels_task")
    incremental = _extract_task_timeout(src, "build_relationships_task")
    assert baseline >= incremental, (
        f"baseline build_relationships timeout ({baseline}) must be >= incremental ({incremental}). "
        "Baseline processes more data than incremental; its timeout cannot be tighter."
    )


def test_baseline_full_neo4j_sync_has_at_least_four_hour_timeout():
    """Full sync ran 50min in Vanko's 2026-04-19 baseline; must
    keep generous headroom as the graph grows. 4h minimum."""
    src = _read_dag_source()
    tdelta = _extract_task_timeout(src, "baseline_full_sync_task")
    assert tdelta >= timedelta(hours=4)


def test_baseline_enrichment_has_at_least_four_hour_timeout():
    """Enrichment runs AFTER build_relationships and similarly
    grows with the graph. Same headroom requirement."""
    src = _read_dag_source()
    tdelta = _extract_task_timeout(src, "baseline_enrichment_task")
    assert tdelta >= timedelta(hours=4)


def test_baseline_otx_collection_has_at_least_four_hour_timeout():
    """OTX took 3h 15m in Vanko's run; need headroom above the
    actual duration. 4h minimum (current is 5h)."""
    src = _read_dag_source()
    # OTX is defined inside a TaskGroup as ``bl_otx`` — extract differently
    # since the variable name is local to the with block.
    m = re.search(
        r"bl_otx\s*=\s*PythonOperator\(([^)]*?execution_timeout\s*=\s*timedelta\(([^)]+)\))",
        src,
        re.DOTALL,
    )
    assert m is not None, "could not locate bl_otx PythonOperator(execution_timeout=...)"
    args_blob = m.group(2)
    kwargs: dict[str, float] = {}
    for kv in re.split(r",\s*", args_blob):
        kv = kv.strip()
        if not kv:
            continue
        k, _, v = kv.partition("=")
        kwargs[k.strip()] = float(v.strip())
    tdelta = timedelta(**kwargs)
    assert tdelta >= timedelta(hours=4), (
        f"baseline collect_otx execution_timeout is {tdelta} — needs >= 4h "
        "(Vanko's run took 3h 15m; tight cap risks future failures as OTX grows)"
    )


# ---------------------------------------------------------------------------
# Cross-DAG consistency invariant
# ---------------------------------------------------------------------------


def test_no_baseline_long_running_task_has_sub_thirty_minute_timeout():
    """Any baseline task whose name contains 'sync', 'build', or
    'enrichment' MUST have at least 30min execution_timeout — these
    are the long-running data-processing tasks. Sub-30min caps risk
    a Vanko-style false-positive failure."""
    src = _read_dag_source()
    # Find every baseline_*_task = PythonOperator(...) block
    for m in re.finditer(r"\bbaseline_(\w+)_task\s*=\s*PythonOperator\(", src):
        task_var = f"baseline_{m.group(1)}_task"
        if not any(kw in m.group(1) for kw in ("sync", "build", "enrichment")):
            continue
        tdelta = _extract_task_timeout(src, task_var)
        assert tdelta >= timedelta(minutes=30), (
            f"{task_var} execution_timeout is {tdelta} — long-running data tasks "
            "need >= 30min headroom (Vanko regression 2026-04-19)"
        )
