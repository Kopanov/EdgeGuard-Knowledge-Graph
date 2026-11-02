#!/usr/bin/env python3
"""
EdgeGuard - collectors into MISP (development tool)

``python src/run_pipeline.py`` runs every enabled collector once, with the incremental limit of
its source (``config.get_effective_limit``), and pushes what it collects to MISP, the single
source of truth. It writes nothing to Neo4j. The graph is built from MISP by the MISP -> Neo4j
sync, the link step and the enrichment jobs: the Airflow DAGs run them, and each also runs on its
own (``src/run_misp_to_neo4j.py``, ``src/build_relationships.py``, ``src/enrichment_jobs.py``;
docs/CLI.md). A baseline runs through the ``edgeguard_baseline`` DAG (docs/AIRFLOW_DAGS.md).

The options of the retired in-process baseline and its Neo4j load (the STIX 2.1 import),
``--baseline``, ``--fresh-baseline``, ``--baseline-days`` and ``--stix-flow``, exit with code 2
before the pipeline lock is taken, anything is wiped or a collector runs. The refusal and ``--help``
need no configuration: ``config``, which requires ``NEO4J_PASSWORD`` and the MISP settings when it is
imported, and the collectors, which import it, are imported only where the pipeline is built and run.
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import inspect
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import requests

# ``config`` and the collectors are imported where the pipeline is built and run (``EdgeGuardPipeline``,
# ``_report_failure_with_metrics``), not here: importing ``config`` requires the Neo4j and MISP settings,
# and ``main`` refuses the retired options and answers ``--help`` without them.


# PR #35 commit 2: surface CLI-path collector failures to Prometheus + Slack
# (Vanko follow-up audit). Wrapped in a thin helper so the four except
# branches below stay readable AND so the call is best-effort: a metric
# emission failure never masks the underlying collector exception.
def _report_failure_with_metrics(source_name: str, exc: BaseException) -> None:
    """Best-effort dashboard-visibility for a CLI-path collector failure.

    Calls ``report_collector_failure`` from ``collector_failure_alerts``
    which:
      - classifies transient vs catastrophic via class-name walk
      - emits Prometheus metrics (collection-status, source-health,
        skip-counter, pipeline-error)
      - sends a Slack alert if EDGEGUARD_ENABLE_SLACK_ALERTS=1

    Wrapped in a try/except so a metrics-server outage or Slack 500
    doesn't break the CLI's own error reporting.
    """
    try:
        from collector_failure_alerts import report_collector_failure

        report_collector_failure(source_name, exc)
    except Exception as report_err:
        logging.getLogger(__name__).warning(
            "[%s] failure-reporting helper raised %s — continuing without dashboard signal",
            source_name,
            type(report_err).__name__,
        )


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# The options of the retired in-process baseline and its Neo4j load. The parser still knows them, so a
# call with one of them is refused with directions (exit 2, before anything runs) instead of argparse's
# "unrecognized arguments".
RETIRED_OPTIONS = ("--baseline", "--fresh-baseline", "--baseline-days", "--stix-flow")
RETIRED_OPTIONS_HELP = "Retired: exits 2 before anything runs; a baseline runs through the edgeguard_baseline DAG."
RETIRED_OPTIONS_MESSAGE = (
    "The in-process baseline and its Neo4j load (the STIX 2.1 import) are retired: run_pipeline.py "
    "runs the collectors into MISP only and writes nothing to Neo4j.\n"
    "A baseline runs through the edgeguard_baseline DAG. On every install, with Docker Compose or without it:\n"
    "  edgeguard fresh-baseline --days N   wipe, then collect (backup gate, typed confirmation)\n"
    "  edgeguard baseline --days N         additive\n"
    "  (both refuse while the Airflow scheduler or metadata database is not healthy or an edgeguard_baseline run is\n"
    "  queued or running; without a running Compose airflow service they trigger through the Airflow REST API;\n"
    '  docs/CLI.md, "Baseline triggers")\n'
    "The raw trigger, without those checks, in the Airflow environment:\n"
    "  airflow dags trigger edgeguard_baseline --conf '{\"baseline_days\": N}'   additive\n"
    '  airflow dags trigger edgeguard_baseline --conf \'{"fresh_baseline": true, "baseline_days": N}\'   wipe, then '
    "collect\n"
    "    (the backup gate runs in the baseline_clean task: EDGEGUARD_LAST_BACKUP_AT goes into the environment of the "
    "Airflow processes; docs/BACKUP.md)\n"
    "For development, the modules the DAGs run build the graph from MISP, each on its own:\n"
    "  python src/run_misp_to_neo4j.py --full\n"
    "  python src/build_relationships.py\n"
    "  python src/enrichment_jobs.py\n"
    '(docs/CLI.md, "Pipeline modules run on their own"; docs/AIRFLOW_DAGS.md)'
)


class EdgeGuardPipeline:
    def __init__(self):
        # Imported here, after ``main`` has refused the retired options: these modules import ``config``.
        from collectors.abuseipdb_collector import AbuseIPDBCollector
        from collectors.cisa_collector import CISACollector
        from collectors.cisa_ics_collector import CISAICSCollector
        from collectors.finance_feed_collector import FeodoCollector, SSLBlacklistCollector
        from collectors.global_feed_collector import MalwareBazaarCollector, ThreatFoxCollector, URLhausCollector
        from collectors.misp_collector import MISPCollector
        from collectors.misp_writer import MISPWriter
        from collectors.mitre_collector import MITRECollector
        from collectors.nvd_collector import NVDCollector
        from collectors.otx_collector import OTXCollector
        from collectors.virustotal_collector import VirusTotalCollector
        from collectors.vt_collector import VTCollector

        # Create shared MISPWriter instance for collectors that push to MISP
        self.misp_writer = MISPWriter()

        self.collectors = {
            "misp": MISPCollector(),
            "otx": OTXCollector(misp_writer=self.misp_writer),
            "nvd": NVDCollector(misp_writer=self.misp_writer),
            "cisa": CISACollector(misp_writer=self.misp_writer),
            # 2026-10: CISA ICS advisories (flag-guarded; collect() skips unless EDGEGUARD_ENABLE_CISA_ICS)
            "cisa_ics": CISAICSCollector(misp_writer=self.misp_writer),
            "mitre": MITRECollector(misp_writer=self.misp_writer),
            "virustotal": VTCollector(misp_writer=self.misp_writer),
            # Legacy/enrichment VT collector (separate from vt_collector.VTCollector; same allowlist name as Airflow)
            "virustotal_enrich": VirusTotalCollector(misp_writer=self.misp_writer),
            # Finance-focused feeds - now with MISPWriter
            "feodo": FeodoCollector(misp_writer=self.misp_writer),
            "sslbl": SSLBlacklistCollector(misp_writer=self.misp_writer),
            # Additional feeds
            "urlhaus": URLhausCollector(misp_writer=self.misp_writer),
            # ThreatFox: free key from https://auth.abuse.ch/ — without it collect() skips (optional).
            "threatfox": ThreatFoxCollector(misp_writer=self.misp_writer),
            # AbuseIPDB requires ABUSEIPDB_API_KEY env var (free tier: 1000 req/day)
            "abuseipdb": AbuseIPDBCollector(misp_writer=self.misp_writer),
            # 2026-10: MalwareBazaar (flag-guarded; collect() skips unless EDGEGUARD_ENABLE_MALWAREBAZAAR)
            "malwarebazaar": MalwareBazaarCollector(misp_writer=self.misp_writer),
        }

    def run(self) -> bool:
        """Run every enabled collector once and push to MISP, under the pipeline lock.

        Returns False when the lock is held by a live process, or when a collector reported failure
        or raised (``_run_pipeline_inner``).
        """
        # ── Pipeline lock: prevent concurrent CLI runs ──
        # NOTE: This lock only protects CLI invocations (python run_pipeline.py).
        # Airflow DAGs use max_active_runs=1 for concurrency control instead.
        import lock_files

        lock_path = lock_files.PIPELINE_LOCK_PATH
        os.makedirs(os.path.dirname(lock_path), exist_ok=True)

        # PR #38 (Bug Hunter Tier S S2): atomic lock acquisition via
        # ``O_CREAT|O_EXCL|O_WRONLY``. The previous TOCTOU pattern —
        # ``os.path.exists(lock_path)`` then ``with open(lock_path, "w")`` —
        # could let two CLI invocations both find no lock and both write
        # their PID, last writer wins. Two pipelines then ran concurrently,
        # racing MISP event creation (the very condition the lock was meant
        # to prevent).
        #
        # ``O_EXCL`` is POSIX-defined as atomic create-or-fail: if the
        # file already exists, ``os.open`` raises ``FileExistsError`` AND
        # does NOT touch the existing file. No window for a racing process
        # to slip in. Stale-lock recovery (the "PID is gone" case) still
        # uses the read-then-unlink-then-retry pattern below — but the
        # final lock acquisition itself is atomic.
        def _read_lock_pid(path: str) -> Optional[int]:
            """Read the PID stored in the pipeline lock file, or None on any error.

            PR-A audit fix (Bug Hunter HIGH H2): used by ``_cleanup_lock``
            to verify the lock still belongs to THIS process before
            unlinking. Mirrors the read-then-compare-pid pattern in
            ``baseline_lock.release_baseline_lock``. Returns None for
            any read or parse error — caller treats None as "don't
            unlink" (safer than treating it as match).
            """
            try:
                with open(path) as fh:
                    return int(fh.read().strip())
            except (OSError, ValueError):
                return None

        def _try_atomic_lock_acquire(path: str) -> bool:
            """Single atomic create-or-fail attempt.

            Returns True iff THIS process now exclusively owns the lock
            file. Returns False on FileExistsError (someone else holds
            it). Returns False on write failure too — the partial sentinel
            is rolled back so a retry can proceed cleanly. Any other
            OSError on the create itself propagates to the caller.

            PR #38 commit X (bugbot MED): added the write-failure
            rollback. Previously a write OSError propagated up
            uncaught while the empty/partial lock file lingered on
            disk → next CLI invocation would see a "live" lock and
            refuse to start, even though the prior process never
            actually held it. Mirrors the baseline_lock.py pattern.
            """
            try:
                # 0o644 — owner rw, others r (matches the previous open(..., "w") default)
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            except FileExistsError:
                return False
            except OSError as exc:
                # PR #38 commit X (bugbot MED): catch the broader OSError too.
                # PermissionError, ENOSPC (disk full), EROFS (read-only fs) etc.
                # would otherwise propagate UNCAUGHT through the caller — the
                # pipeline crashes with a stack trace instead of cleanly
                # refusing to start. Mirrors the baseline_lock.py pattern.
                logger.error(f"Failed to acquire pipeline lock at {path}: {exc}")
                return False
            write_failed = False
            try:
                os.write(fd, str(os.getpid()).encode("ascii"))
            except OSError as exc:
                logger.error(f"Failed to write pipeline-lock PID to {path}: {exc}")
                write_failed = True
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if write_failed:
                # Roll back the partial sentinel so the next attempt isn't blocked.
                try:
                    os.unlink(path)
                except OSError:
                    pass
                return False
            return True

        if not _try_atomic_lock_acquire(lock_path):
            # File exists. Read the PID, decide if it's stale, and possibly retry once.
            try:
                with open(lock_path) as f:
                    old_pid = int(f.read().strip())
            except (ValueError, OSError):
                # Lock file unreadable / malformed.
                #
                # PR #38 commit X (bugbot HIGH): age-gate the auto-recovery
                # to avoid the same TOCTOU race fixed in baseline_lock.py
                # (see ``_is_corrupt_sentinel`` docstring there for the
                # full scenario). Without an age check, Process B could
                # see Process A's mid-write empty file, unlink it, and
                # retry — both processes end up "holding" the lock.
                #
                # Refuse the auto-recovery if the file is fresh (< 5 min);
                # operator must manually delete a fresh lock that's
                # genuinely corrupt.
                _PIPELINE_LOCK_RECOVERY_AGE_SECS = 300
                try:
                    age_secs = time.time() - os.stat(lock_path).st_mtime
                except OSError:
                    age_secs = 0  # treat unstat-able as fresh → refuse
                if age_secs < _PIPELINE_LOCK_RECOVERY_AGE_SECS:
                    logger.error(
                        f"Lock file {lock_path} is unreadable BUT only {age_secs:.0f}s old — "
                        f"refusing to auto-recover (could race a competitor mid-write). "
                        f"Either wait {(_PIPELINE_LOCK_RECOVERY_AGE_SECS - age_secs):.0f}s or "
                        f"manually delete the file if you're sure it's stale."
                    )
                    return False
                logger.warning(
                    f"Lock file {lock_path} unreadable + {age_secs:.0f}s old — treating as stale and removing."
                )
                try:
                    os.unlink(lock_path)
                except OSError:
                    pass
                if not _try_atomic_lock_acquire(lock_path):
                    logger.error("Lost lock-acquisition race after stale-lock cleanup. Aborting.")
                    return False
            else:
                # Check if the process is still alive
                try:
                    os.kill(old_pid, 0)
                    # Process exists (signal 0 succeeded) — could be ours or another user's
                    logger.error(
                        f"Another pipeline process (PID {old_pid}) is still running. "
                        "Aborting to prevent data races. "
                        "If this is stale, delete checkpoints/pipeline.lock and retry."
                    )
                    return False
                except PermissionError:
                    # PID exists but owned by another user — treat as alive (safe side)
                    logger.error(
                        f"Pipeline lock held by PID {old_pid} (different user). "
                        "Aborting. Delete checkpoints/pipeline.lock if stale."
                    )
                    return False
                except ProcessLookupError:
                    logger.info(f"Stale lock file found (PID {old_pid} is gone) — removing.")
                    try:
                        os.unlink(lock_path)
                    except OSError:
                        pass
                    # Single retry; if a competitor grabbed it in the gap, fail loudly.
                    if not _try_atomic_lock_acquire(lock_path):
                        logger.error(
                            "Lost lock-acquisition race after stale-lock cleanup — "
                            "another process grabbed the lock. Aborting."
                        )
                        return False

        import atexit
        import signal

        def _cleanup_lock(*_args):
            # PR-A audit fix (Bug Hunter HIGH H2): only remove the lock file
            # if it still belongs to THIS process. Earlier code did a blind
            # ``os.remove(lock_path)`` — but the stale-PID recovery path
            # (the ``ProcessLookupError`` branch above) lets a competing process
            # unlink-and-re-acquire the same lock. Without the PID check, this
            # process's atexit handler then unlinks the OTHER process's
            # freshly-acquired lock, opening a window where a third invocation
            # can also acquire. Two pipelines run concurrently, racing MISP event
            # creation. Mirrors the release_baseline_lock pattern in
            # src/baseline_lock.py.
            try:
                pid = _read_lock_pid(lock_path)
                if pid is not None and pid == os.getpid():
                    os.remove(lock_path)
                elif pid is not None:
                    logger.warning(
                        "Not removing pipeline lock: sentinel pid=%s != current pid=%s",
                        pid,
                        os.getpid(),
                    )
            except OSError:
                pass

        atexit.register(_cleanup_lock)

        def _sigterm_handler(signum, frame):
            _cleanup_lock()
            sys.exit(1)

        signal.signal(signal.SIGTERM, _sigterm_handler)

        try:
            return self._run_pipeline_inner()
        finally:
            _cleanup_lock()

    def _run_pipeline_inner(self) -> bool:
        """Collection into MISP, separated so the lock is always cleaned up.

        Returns False when a collector reported failure (``success`` False) or raised; a skipped
        optional source (no key, not in ``EDGEGUARD_COLLECT_SOURCES``) is no failure.
        """
        from collector_allowlist import collect_sources_allowlist_from_env, is_collector_enabled_by_allowlist
        from config import get_effective_limit

        logger.info("UPDATE MODE: Collecting latest data into MISP")

        # Generate run ID for reproducibility and traceability
        run_id = str(uuid.uuid4())[:8]

        # Try to get git commit hash for traceability
        git_commit = None
        try:
            import subprocess

            git_commit = (
                subprocess.check_output(
                    ["git", "rev-parse", "--short", "HEAD"],
                    cwd=os.path.dirname(os.path.abspath(__file__)),
                    stderr=subprocess.DEVNULL,
                )
                .decode()
                .strip()
            )
        except Exception:
            pass  # Not a git repo or git not available

        start_time = datetime.now(timezone.utc)
        logger.info("=" * 60)
        logger.info(f"[START] EdgeGuard collection into MISP started (run_id: {run_id})")
        if git_commit:
            logger.info(f"📌 Git commit: {git_commit}")
        logger.info("=" * 60)

        logger.info("\n[FETCH] Collecting from sources and pushing to MISP...")
        total_pushed = 0
        step2_ok: list[str] = []
        step2_skipped: list[tuple[str, str, str]] = []  # (source, reason, reason_class)
        step2_failed: list[tuple[str, str]] = []  # (source, error) — success=False dict
        step2_exceptions: list[tuple[str, str]] = []  # (source, message)

        # Collectors that push to MISP (all except MISP collector itself)
        external_collectors = {k: v for k, v in self.collectors.items() if k != "misp"}

        _allow = collect_sources_allowlist_from_env()
        if _allow is not None:
            logger.info(
                f"   EDGEGUARD_COLLECT_SOURCES allowlist active: "
                f"{sorted(_allow) if _allow else '(none — all external collectors disabled)'}",
            )

        for source_name, collector in external_collectors.items():
            if not is_collector_enabled_by_allowlist(source_name, _allow):
                reason = "Not in EDGEGUARD_COLLECT_SOURCES allowlist"
                rclass = "collector_disabled_by_config"
                logger.warning(f"   [SKIP] {source_name}: {reason} [{rclass}]")
                step2_skipped.append((source_name, reason, rclass))
                continue
            try:
                logger.info(f"\n   Collecting from {source_name}...")
                # The incremental limit of the source, as the scheduled DAGs use it.
                effective_limit = get_effective_limit(source_name)
                logger.info(f"   ℹ️  Limit for {source_name}: {effective_limit if effective_limit else 'unlimited'}")
                # Push to MISP (MISP becomes the single source of truth). The keyword arguments of the
                # scheduled DAGs' collection call: no baseline flag, no baseline window.
                if "push_to_misp" in inspect.signature(collector.collect).parameters:
                    data = collector.collect(limit=effective_limit, push_to_misp=True)
                else:
                    data = collector.collect(limit=effective_limit)

                # Handle both list and dict return types (collectors may return status dict when push_to_misp=True)
                if isinstance(data, dict):
                    logger.debug(f"   ℹ️ {source_name} returned dict with keys: {data.keys()}")
                    if data.get("skipped") is True:
                        reason = str(data.get("skip_reason") or "optional source skipped")
                        rclass = str(data.get("skip_reason_class") or "")
                        extra = f" [{rclass}]" if rclass else ""
                        logger.warning(f"   [SKIP] {source_name}: {reason}{extra}")
                        step2_skipped.append((source_name, reason, rclass))
                        continue
                    if data.get("success") is False:
                        err = data.get("error") or (
                            f"success=false (failed={data.get('failed', 0)}, count={data.get('count', 0)})"
                        )
                        logger.error(f"   [ERR] {source_name}: {err}")
                        step2_failed.append((source_name, str(err)))
                        continue
                    count = int(data.get("count", 0) or 0)
                    logger.info(f"   [OK] {source_name}: {count} items pushed to MISP")
                    total_pushed += count
                    step2_ok.append(source_name)
                else:
                    count = len(data) if data else 0
                    logger.info(f"   [OK] {source_name}: {count} items pushed to MISP")
                    total_pushed += count
                    step2_ok.append(source_name)
            except requests.exceptions.Timeout as e:
                msg = f"Timeout: {e}"
                logger.error(f"   [ERR] {source_name} collector timed out - service may be slow")
                step2_exceptions.append((source_name, msg))
                # PR #35 commit 2: emit Prometheus + Slack visibility
                # so CLI-path failures are dashboard-visible, not just logged.
                _report_failure_with_metrics(source_name, e)
            except requests.exceptions.ConnectionError as e:
                msg = f"ConnectionError: {e}"
                logger.error(f"   [ERR] {source_name} collector failed - connection error (service down?)")
                step2_exceptions.append((source_name, msg))
                _report_failure_with_metrics(source_name, e)
            except ImportError as e:
                msg = f"ImportError: {e}"
                logger.error(f"   [ERR] {source_name} collector failed - missing dependency: {e}")
                step2_exceptions.append((source_name, msg))
                _report_failure_with_metrics(source_name, e)
            except Exception as e:
                msg = f"{type(e).__name__}: {e}"
                logger.error(f"   [ERR] {source_name} collector failed: {msg}")
                step2_exceptions.append((source_name, msg))
                _report_failure_with_metrics(source_name, e)

        logger.info(f"\n[STATS] Total pushed to MISP: {total_pushed} items")
        logger.info("\n[SUMMARY] Collection by source:")
        logger.info(f"   • Succeeded ({len(step2_ok)}): {', '.join(step2_ok) if step2_ok else '—'}")
        if step2_skipped:
            logger.warning(f"   • Skipped optional ({len(step2_skipped)}) — pipeline continues; no data from:")
            for name, reason, rclass in step2_skipped:
                rc = f" [{rclass}]" if rclass else ""
                logger.warning(f"      - {name}:{rc} {reason}")
        else:
            logger.info("   • Skipped optional: none")
        if step2_failed:
            logger.error(f"   • Collector reported failure ({len(step2_failed)}):")
            for name, err in step2_failed:
                logger.error(f"      - {name}: {err}")
        else:
            logger.info("   • Collector reported failure: none")
        if step2_exceptions:
            logger.error(f"   • Raised exception ({len(step2_exceptions)}):")
            for name, err in step2_exceptions:
                logger.error(f"      - {name}: {err}")
        else:
            logger.info("   • Raised exception: none")
        if step2_failed or step2_exceptions:
            logger.warning(
                "[WARN] Collection had failures — MISP may be missing data from those sources; "
                "review logs above and fix keys/connectivity."
            )

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        logger.info(f"\n⏱️  Total time: {elapsed:.1f} seconds")
        logger.info(
            "Nothing was written to Neo4j: the MISP -> Neo4j sync (src/run_misp_to_neo4j.py), "
            "src/build_relationships.py and src/enrichment_jobs.py build the graph from MISP."
        )
        return not (step2_failed or step2_exceptions)


def _retired_options_given(args: argparse.Namespace) -> list[str]:
    """The retired options on the command line, in ``RETIRED_OPTIONS`` order."""
    given = {
        "--baseline": args.baseline,
        "--fresh-baseline": args.fresh_baseline,
        "--baseline-days": args.baseline_days is not None,
        "--stix-flow": args.stix_flow,
    }
    return [option for option in RETIRED_OPTIONS if given[option]]


def main():
    """Main entry point with argument parsing"""
    # No abbreviations: ``--stix`` would otherwise be read as ``--stix-flow``, ``--base`` as ``--baseline``.
    parser = argparse.ArgumentParser(
        description=(
            "EdgeGuard collectors into MISP (development tool): runs every enabled collector once and pushes "
            "to MISP. Writes nothing to Neo4j; a baseline runs through the edgeguard_baseline DAG."
        ),
        allow_abbrev=False,
    )
    retired = parser.add_argument_group("retired options", RETIRED_OPTIONS_HELP)
    retired.add_argument("--baseline", action="store_true", help="the in-process baseline (retired)")
    retired.add_argument("--fresh-baseline", action="store_true", help="the in-process fresh baseline (retired)")
    retired.add_argument("--baseline-days", metavar="N", default=None, help="the in-process baseline window (retired)")
    retired.add_argument("--stix-flow", action="store_true", help="the STIX 2.1 import into Neo4j (retired)")

    args = parser.parse_args()

    refused = _retired_options_given(args)
    if refused:
        # Before the pipeline is built, the lock taken, anything wiped or a collector run.
        print(f"run_pipeline.py: {', '.join(refused)} refused.\n{RETIRED_OPTIONS_MESSAGE}", file=sys.stderr)
        return 2

    pipeline = EdgeGuardPipeline()
    success = pipeline.run()

    if success:
        print("\nCollection into MISP finished.")
    else:
        print("\nCollection into MISP failed or was refused. Check logs.")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
