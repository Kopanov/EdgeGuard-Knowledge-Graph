"""VirusTotal free-tier lookup budget — a small JSON ledger shared across collector runs.

The public VirusTotal API v3 allows **4 lookups per minute** and **500 lookups per
day** on the free tier. The per-minute limit is enforced in-process by
``RateLimiter(requests_per_minute=4)``; the daily quota spans several Airflow task
runs (``edgeguard_medium_freq`` runs every four hours), so it is tracked here in a
ledger file in the shared state directory (``./state`` on the Compose deployment).

Two things are recorded:

* the **daily quota**: lookups used today (UTC) against the configured budget
  (``EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET``, default 400 — headroom below the 500
  that VirusTotal enforces), and whether VirusTotal answered HTTP 429 today;
* the **lookup memory**: which SHA-256 hashes were already looked up and the
  outcome (``ok`` / ``not_found``), so a hash is never looked up twice and a hash
  unknown to VirusTotal is not retried every run. Bounded to the most recent
  :data:`LOOKED_UP_MAX` entries.

Every quota message is prefixed ``[VT-QUOTA]`` so operators can grep the task
logs for it. The ledger never raises into the collector: a corrupt or unwritable
file is logged and the day is treated as fresh — VirusTotal's own HTTP 429 remains
the final guard and marks the day exhausted.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from collectors.collector_utils import state_dir

logger = logging.getLogger(__name__)

QUOTA_LOG_PREFIX = "[VT-QUOTA]"

DAILY_BUDGET_DEFAULT = 400
MAX_LOOKUPS_PER_RUN_DEFAULT = 60
# At 4 lookups a minute a run of 200 takes 50 minutes; the Airflow task is killed after 60.
MAX_LOOKUPS_PER_RUN_CEILING = 200
CANDIDATE_DAYS_DEFAULT = 30
LOOKED_UP_MAX = 20000

# The key check (``source_key_check.py``) spends one lookup in another process, outside the
# collector's in-process rate limiter. Two rules keep every minute inside VirusTotal's 4 lookups:
#   * the check is not sent while a collector run is writing the ledger. A run writes it before
#     its first lookup and then every 10 lookups (150 s at full pace); a run that writes less
#     often than this window is far below 4 lookups a minute, so one more request fits;
#   * a collector run that starts within a minute after a key check waits for the rest of it.
#   * the two processes cannot lock each other out completely, so the collector reads the ledger
#     again when VirusTotal answers HTTP 429: within KEY_CHECK_OVERLAP_SEC of a key check that
#     answer may be the shared per-minute limit, and the day is not marked exhausted.
# The key check writes its time to the ledger before it sends its request, and every write of
# the ledger first takes over what the other process wrote (:meth:`VirusTotalBudget.sync_from_disk`).
COLLECTOR_ACTIVITY_WINDOW_SEC = 300
KEY_CHECK_SPACING_SEC = 60
KEY_CHECK_OVERLAP_SEC = 120
WRITER_COLLECTOR = "collector"
WRITER_KEY_CHECK = "key_check"

_DAILY_BUDGET_ENV = "EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET"
_PER_RUN_ENV = "EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN"
_CANDIDATE_DAYS_ENV = "EDGEGUARD_VIRUSTOTAL_CANDIDATE_DAYS"
_PATH_ENV = "EDGEGUARD_VIRUSTOTAL_BUDGET_PATH"

_LEDGER_FILENAME = "virustotal_daily_budget.json"


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    """Read a non-negative integer knob; an unset, empty or invalid value falls back to *default*."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        logger.warning("%s %s=%r is not an integer — using the default %d", QUOTA_LOG_PREFIX, name, raw, default)
        return default
    if value < minimum:
        logger.warning("%s %s=%d is below %d — using the default %d", QUOTA_LOG_PREFIX, name, value, minimum, default)
        return default
    return value


def daily_budget() -> int:
    """Lookups the collector may spend per UTC day (``EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET``, default 400)."""
    return _env_int(_DAILY_BUDGET_ENV, DAILY_BUDGET_DEFAULT)


def max_lookups_per_run() -> int:
    """Lookups one collector run may spend (``EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN``, default 60).

    Capped at :data:`MAX_LOOKUPS_PER_RUN_CEILING`: a larger run cannot finish inside the task's
    one-hour execution timeout at four lookups a minute and would be killed before it is accounted.
    """
    value = _env_int(_PER_RUN_ENV, MAX_LOOKUPS_PER_RUN_DEFAULT)
    if value > MAX_LOOKUPS_PER_RUN_CEILING:
        logger.warning(
            "%s %s=%d exceeds what one run can finish in its execution timeout — using %d",
            QUOTA_LOG_PREFIX,
            _PER_RUN_ENV,
            value,
            MAX_LOOKUPS_PER_RUN_CEILING,
        )
        return MAX_LOOKUPS_PER_RUN_CEILING
    return value


def candidate_days() -> int:
    """How far back (days) MISP is searched for hashes awaiting enrichment (default 30)."""
    return _env_int(_CANDIDATE_DAYS_ENV, CANDIDATE_DAYS_DEFAULT, minimum=1)


def ledger_path() -> str:
    """Ledger location: ``EDGEGUARD_VIRUSTOTAL_BUDGET_PATH``, else ``<EDGEGUARD_STATE_DIR or <repo>/state>/virustotal_daily_budget.json``.

    The default directory is :func:`collectors.collector_utils.state_dir`, the state-file
    convention of the Airflow DAG (``dags/edgeguard_pipeline.py::get_state_file``), so the
    ledger lands in the ``./state`` bind mount of the Compose deployment and survives
    container restarts.
    """
    override = os.getenv(_PATH_ENV)
    if override and override.strip():
        return override.strip()
    return os.path.join(state_dir(), _LEDGER_FILENAME)


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class VirusTotalBudget:
    """Daily lookup quota and lookup memory for the VirusTotal collector.

    Construct once per collector run; call :meth:`save` at the end of the run (the
    collector also saves after an exhaustion event so the next run sees it even if
    the task is killed afterwards).
    """

    def __init__(self, path: Optional[str] = None, budget: Optional[int] = None):
        self.path = Path(path or ledger_path())
        self.budget = daily_budget() if budget is None else max(0, int(budget))
        self.date = _today()
        self.used = 0
        self.exhausted = False
        self.exhausted_at: Optional[str] = None
        self.exhausted_reason: Optional[str] = None
        self.looked_up: Dict[str, str] = {}
        # As read from the ledger: when it was last written and by whom, and the last key check.
        self.updated_at: Optional[str] = None
        self.updated_by: Optional[str] = None
        self.key_check_at: Optional[str] = None
        self._load()

    # ------------------------------------------------------------------ persistence
    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
            if not isinstance(data, dict):
                raise ValueError("ledger root is not an object")
        except (OSError, ValueError) as exc:
            logger.warning(
                "%s ledger %s unreadable (%s) — starting a fresh day; VirusTotal's HTTP 429 remains the final guard",
                QUOTA_LOG_PREFIX,
                self.path,
                exc,
            )
            return
        looked_up = data.get("looked_up")
        if isinstance(looked_up, dict):
            self.looked_up = {str(k): str(v) for k, v in looked_up.items()}
        if isinstance(data.get("updated_at"), str):
            self.updated_at = data["updated_at"]
            # A ledger written before the key check existed has no writer: it was a collector run.
            self.updated_by = str(data.get("updated_by") or WRITER_COLLECTOR)
        if isinstance(data.get("key_check_at"), str):
            self.key_check_at = data["key_check_at"]
        if data.get("date") != self.date:
            # New UTC day: the quota resets; the lookup memory is kept.
            previous_used = data.get("used", 0)
            logger.info(
                "%s new UTC day %s — daily counter reset (previous day %s: %s lookups used)",
                QUOTA_LOG_PREFIX,
                self.date,
                data.get("date"),
                previous_used,
            )
            return
        try:
            self.used = max(0, int(data.get("used", 0)))
        except (TypeError, ValueError):
            self.used = 0
        self.exhausted = bool(data.get("exhausted", False))
        self.exhausted_at = data.get("exhausted_at")
        self.exhausted_reason = data.get("exhausted_reason")

    def sync_from_disk(self) -> None:
        """Take over what another process wrote to the ledger since this object was loaded.

        The key check and a collector run are different processes. The newest key-check time is
        kept; for the same UTC day the higher counter wins and an exhausted day stays exhausted.
        A missing or unreadable file changes nothing.
        """
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        stamp = data.get("key_check_at")
        if isinstance(stamp, str):
            theirs, ours = self._age(stamp), self.key_check_age()
            if theirs is not None and (ours is None or theirs < ours):
                self.key_check_at = stamp
        if data.get("date") != self.date:
            return
        try:
            self.used = max(self.used, int(data.get("used", 0)))
        except (TypeError, ValueError):
            pass
        if data.get("exhausted") and not self.exhausted:
            self.exhausted = True
            self.exhausted_at = data.get("exhausted_at")
            self.exhausted_reason = data.get("exhausted_reason")

    def save(self, writer: str = WRITER_COLLECTOR) -> None:
        """Write the ledger atomically; failures are logged, never raised."""
        self.sync_from_disk()
        self._trim()
        payload: Dict[str, Any] = {
            "date": self.date,
            "budget": self.budget,
            "used": self.used,
            "exhausted": self.exhausted,
            "exhausted_at": self.exhausted_at,
            "exhausted_reason": self.exhausted_reason,
            "looked_up": self.looked_up,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_by": writer,
            "key_check_at": self.key_check_at,
        }
        tmp = self.path.with_suffix(".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp, "w") as fh:
                json.dump(payload, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            tmp.replace(self.path)
        except OSError as exc:
            logger.warning(
                "%s could not write ledger %s (%s) — the daily counter is not persisted for this run",
                QUOTA_LOG_PREFIX,
                self.path,
                exc,
            )
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def _trim(self) -> None:
        overflow = len(self.looked_up) - LOOKED_UP_MAX
        if overflow > 0:
            for key in list(self.looked_up)[:overflow]:
                del self.looked_up[key]

    # ------------------------------------------------------------------ quota
    @property
    def remaining(self) -> int:
        if self.exhausted:
            return 0
        return max(0, self.budget - self.used)

    def is_exhausted(self) -> bool:
        return self.exhausted or self.remaining <= 0

    def consume(self, n: int = 1) -> None:
        """Count *n* requests that reached VirusTotal (whatever they answered)."""
        self.used += max(0, n)

    def mark_exhausted(self, reason: str) -> None:
        """VirusTotal refused a lookup (HTTP 429): no further lookups today."""
        self.exhausted = True
        self.exhausted_at = datetime.now(timezone.utc).isoformat()
        self.exhausted_reason = reason
        self.used = max(self.used, self.budget)
        logger.warning(
            "%s VirusTotal daily quota exhausted (%s) — no further lookups until 00:00 UTC; the workflow continues",
            QUOTA_LOG_PREFIX,
            reason,
        )

    # ------------------------------------------------------------------ key check coordination
    @staticmethod
    def _age(stamp: Optional[str]) -> Optional[float]:
        """Seconds since a ledger timestamp; None when absent, unreadable or in the future."""
        if not stamp:
            return None
        try:
            then = datetime.fromisoformat(stamp)
        except ValueError:
            return None
        if then.tzinfo is None:
            then = then.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - then).total_seconds()
        return age if age >= 0 else None

    def collector_write_age(self) -> Optional[float]:
        """Seconds since a collector run last wrote the ledger; None when a key check wrote it last."""
        if self.updated_by != WRITER_COLLECTOR:
            return None
        return self._age(self.updated_at)

    def key_check_age(self) -> Optional[float]:
        """Seconds since the last key check spent a lookup; None when there was none."""
        return self._age(self.key_check_at)

    def note_key_check(self) -> None:
        self.key_check_at = datetime.now(timezone.utc).isoformat()

    def seconds_until_key_check_clear(self) -> float:
        """How long a collector run waits so that a recent key check and its own lookups share no minute."""
        age = self.key_check_age()
        return 0.0 if age is None else max(0.0, KEY_CHECK_SPACING_SEC - age)

    # ------------------------------------------------------------------ lookup memory
    def already_looked_up(self, sha256: str) -> bool:
        return sha256.lower() in self.looked_up

    def remember(self, sha256: str, outcome: str) -> None:
        self.looked_up[sha256.lower()] = outcome

    # ------------------------------------------------------------------ reporting
    def summary(self) -> str:
        state = "exhausted" if self.is_exhausted() else f"{self.remaining} remaining"
        return f"{self.used}/{self.budget} lookups used on {self.date} UTC, {state}"
