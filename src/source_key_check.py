#!/usr/bin/env python3
"""Live check of the source API keys: will each keyed source deliver, or be skipped?

A presence check ("the variable is set") cannot answer that. A key the provider does not
accept shows up only inside a run: the collector returns a *skipped* task that Airflow
shows as successful (OTX, VirusTotal, ThreatFox, AbuseIPDB), and a rejected NVD key fails
the NVD task, which in a fresh baseline happens after the stores were wiped. This module
asks each provider once, before a run.

Used by ``edgeguard preflight``, by the first task of the baseline DAG, by
``scripts/preflight_baseline.sh`` and directly::

    python src/source_key_check.py [--json]

Exit code of the command: ``0`` every configured key was accepted (or could not be
judged); ``1`` at least one configured key was rejected and its source will be skipped;
``2`` a key problem that stops a baseline (a rejected NVD key, or a source named in
``EDGEGUARD_BASELINE_REQUIRED_SOURCES`` that cannot deliver).

Rules
-----
* A key value is never logged, returned or written. A detail carries the HTTP status and
  the provider's own short reason, with the key masked should a provider echo it.
* A provider that cannot be reached, that rate-limits the probe, or that answers with an
  unexpected status gives ``unverified``. A network problem is never turned into a verdict
  on the key, and never stops a run.
* Cost per check: OTX and NVD probes are outside any quota. VirusTotal: one file lookup,
  counted in the collector's daily ledger; not sent when that ledger is exhausted, while a
  collector run is in progress, or within 20 seconds of the previous check (the limit is 4
  lookups a minute, shared with the collector).
  AbuseIPDB: one ``check`` request (1,000 a day on the free plan); the ``blacklist``
  endpoint the collector uses (5 a day) is not touched. ThreatFox: one query whose body
  is not downloaded.
* ``EDGEGUARD_SOURCE_KEY_CHECK=false`` disables the requests (air-gapped installations);
  configured keys are then reported as ``unverified``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# Statuses
VALID = "valid"  # the provider accepted the key
REJECTED = "rejected"  # the provider does not accept the key
NOT_SET = "not_set"  # no key configured (or a template placeholder)
UNVERIFIED = "unverified"  # the provider could not be asked, or did not give a verdict
DISABLED = "disabled"  # the source is switched off by EDGEGUARD_COLLECT_SOURCES

LOG_PREFIX = "[SOURCE-KEYS]"
PROBE_TIMEOUT = (5, 20)
# At most three key checks a minute reach VirusTotal (its limit is 4 lookups a minute).
KEY_CHECK_MIN_INTERVAL_SEC = 20

OTX_PROBE_URL = "https://otx.alienvault.com/api/v1/user/me"
NVD_PROBE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# The EICAR test file: known to VirusTotal, harmless, the smallest meaningful lookup.
VIRUSTOTAL_PROBE_URL = (
    "https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
)
THREATFOX_PROBE_URL = "https://threatfox-api.abuse.ch/api/v1/"
ABUSEIPDB_PROBE_URL = "https://api.abuseipdb.com/api/v2/check"

ProbeResult = Tuple[str, str]


def key_check_enabled() -> bool:
    """False when ``EDGEGUARD_SOURCE_KEY_CHECK`` is set to false / 0 / no / off."""
    return os.getenv("EDGEGUARD_SOURCE_KEY_CHECK", "true").strip().lower() not in ("false", "0", "no", "off")


def required_sources() -> FrozenSet[str]:
    """Sources a baseline must not start without (``EDGEGUARD_BASELINE_REQUIRED_SOURCES``, comma-separated)."""
    raw = os.getenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", "")
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def _ssl_verify() -> Any:
    from config import SSL_VERIFY

    return SSL_VERIFY


def _mask(text: str, key: str) -> str:
    """A provider reason, shortened, with the key masked should the provider echo it."""
    cleaned = " ".join(str(text or "").split())
    if key:
        cleaned = cleaned.replace(key, "***")
    return cleaned[:80]


def _json_field(response: requests.Response, *path: str) -> str:
    """A short string field of a JSON answer, or '' (never raises on a non-JSON body)."""
    try:
        node: Any = response.json()
    except ValueError:
        return ""
    for part in path:
        if isinstance(node, list):
            node = node[0] if node else None
        if not isinstance(node, dict):
            return ""
        node = node.get(part)
    return node if isinstance(node, str) else ""


def _verdict(
    response: requests.Response, key: str, reason: str = "", *, rejected: Iterable[int] = (401, 403)
) -> ProbeResult:
    """Map an HTTP answer to a status. Only an explicit refusal of the key is ``rejected``."""
    status = response.status_code
    detail = f"HTTP {status}" + (f" {_mask(reason, key)}" if reason else "")
    if status == 200:
        return VALID, detail
    if status in tuple(rejected):
        return REJECTED, detail
    if status == 429:
        return UNVERIFIED, f"{detail} (rate limit or quota reached; the key itself was not judged)"
    return UNVERIFIED, f"{detail} (unexpected answer; the key was not judged)"


# --------------------------------------------------------------------------- probes
def _probe_otx(key: str) -> ProbeResult:
    response = requests.get(OTX_PROBE_URL, headers={"X-OTX-API-KEY": key}, timeout=PROBE_TIMEOUT, verify=_ssl_verify())
    reason = _json_field(response, "detail") if response.status_code != 200 else ""
    return _verdict(response, key, reason)


def _probe_nvd(key: str) -> ProbeResult:
    """NVD answers a key it does not know with HTTP 404 and the header ``message: Invalid apiKey.``.

    HTTP 403 from NVD is its rate limit, not a verdict on the key.
    """
    response = requests.get(
        NVD_PROBE_URL,
        params={"resultsPerPage": 1},
        headers={"apiKey": key},
        timeout=PROBE_TIMEOUT,
        verify=_ssl_verify(),
        stream=True,
    )
    try:
        message = response.headers.get("message") or ""
        if response.status_code == 404 and "apikey" in message.lower():
            return REJECTED, f"HTTP 404 {_mask(message, key)}"
        return _verdict(response, key, message if response.status_code != 200 else "", rejected=())
    finally:
        response.close()


def _probe_virustotal(key: str) -> ProbeResult:
    """One file lookup, counted in the collector's ledger and kept apart from collector runs.

    The lookup is made in another process than the collector, outside its 4-per-minute rate
    limiter, and VirusTotal answers HTTP 429 for the per-minute limit as well as for the daily
    quota. So the request is not sent while a collector run is writing the ledger, nor within
    :data:`KEY_CHECK_MIN_INTERVAL_SEC` of the previous check, and a 429 on this request is never
    recorded as the end of the collector's day (the collector's own lookups decide that, and the
    collector does not end its day on a 429 that follows a key check within two minutes).
    """
    from collectors.virustotal_budget import COLLECTOR_ACTIVITY_WINDOW_SEC, WRITER_KEY_CHECK, VirusTotalBudget

    budget = VirusTotalBudget()
    if budget.is_exhausted():
        return UNVERIFIED, "the daily VirusTotal lookup budget is used; the key was not probed"
    age = budget.collector_write_age()
    if age is not None and age < COLLECTOR_ACTIVITY_WINDOW_SEC:
        return UNVERIFIED, (
            f"a VirusTotal collector run wrote its ledger {age:.0f} s ago and may be in progress; the key was not "
            "probed, to stay inside the limit of 4 lookups a minute. Run the check again in a few minutes"
        )
    age = budget.key_check_age()
    if age is not None and age < KEY_CHECK_MIN_INTERVAL_SEC:
        return UNVERIFIED, (
            f"the key was checked {age:.0f} s ago; not probed again, to stay inside the limit of 4 lookups a minute"
        )

    # Counted and announced before the request leaves: a collector run that starts, or that is
    # answered 429, during this round trip reads the ledger and finds the check.
    budget.consume(1)
    budget.note_key_check()
    budget.save(writer=WRITER_KEY_CHECK)  # logs and continues when the ledger cannot be written
    response = requests.get(
        VIRUSTOTAL_PROBE_URL, headers={"x-apikey": key}, timeout=PROBE_TIMEOUT, verify=_ssl_verify()
    )
    if response.status_code == 404:
        # "Not found" is an authenticated answer: the key was accepted.
        return VALID, "HTTP 404 (authenticated answer)"
    reason = _json_field(response, "error", "code") if response.status_code != 200 else ""
    return _verdict(response, key, reason)


def _probe_threatfox(key: str) -> ProbeResult:
    """The collector's own query. The status line decides; the body of an accepted query is not downloaded."""
    response = requests.post(
        THREATFOX_PROBE_URL,
        headers={"Auth-Key": key},
        json={"query": "get_iocs", "days": 1},
        timeout=PROBE_TIMEOUT,
        verify=_ssl_verify(),
        stream=True,
    )
    try:
        reason = _json_field(response, "query_status") if response.status_code != 200 else ""
        return _verdict(response, key, reason)
    finally:
        response.close()


def _probe_abuseipdb(key: str) -> ProbeResult:
    response = requests.get(
        ABUSEIPDB_PROBE_URL,
        params={"ipAddress": "1.1.1.1", "maxAgeInDays": "1"},
        headers={"Key": key, "Accept": "application/json"},
        timeout=PROBE_TIMEOUT,
        verify=_ssl_verify(),
    )
    reason = _json_field(response, "errors", "detail") if response.status_code != 200 else ""
    return _verdict(response, key, reason)


# --------------------------------------------------------------------------- configured keys
def _key_otx() -> Tuple[Optional[str], str]:
    from collectors.collector_utils import OTX_API_KEY_PLACEHOLDERS, optional_api_key_effective
    from config import OTX_API_KEY

    return optional_api_key_effective(OTX_API_KEY, OTX_API_KEY_PLACEHOLDERS), "OTX_API_KEY"


def _key_nvd() -> Tuple[Optional[str], str]:
    from config import NVD_API_KEY

    return (NVD_API_KEY or "").strip() or None, "NVD_API_KEY"


def _key_virustotal() -> Tuple[Optional[str], str]:
    from collectors.collector_utils import VIRUSTOTAL_API_KEY_PLACEHOLDERS, optional_api_key_effective
    from config import VIRUSTOTAL_API_KEY

    # config falls back to credentials/api_keys.yaml when the variable is not set: say which one is in use.
    from_file = bool(VIRUSTOTAL_API_KEY) and not os.getenv("VIRUSTOTAL_API_KEY")
    origin = "VIRUSTOTAL_API_KEY in credentials/api_keys.yaml" if from_file else "VIRUSTOTAL_API_KEY"
    return optional_api_key_effective(VIRUSTOTAL_API_KEY, VIRUSTOTAL_API_KEY_PLACEHOLDERS), origin


def _key_threatfox() -> Tuple[Optional[str], str]:
    from collectors.collector_utils import THREATFOX_API_KEY_PLACEHOLDERS, optional_api_key_effective

    return optional_api_key_effective(
        os.getenv("THREATFOX_API_KEY"), THREATFOX_API_KEY_PLACEHOLDERS
    ), "THREATFOX_API_KEY"


def _key_abuseipdb() -> Tuple[Optional[str], str]:
    from collectors.collector_utils import ABUSEIPDB_API_KEY_PLACEHOLDERS, optional_api_key_effective

    return optional_api_key_effective(
        os.getenv("ABUSEIPDB_API_KEY"), ABUSEIPDB_API_KEY_PLACEHOLDERS
    ), "ABUSEIPDB_API_KEY"


@dataclass(frozen=True)
class KeyedSource:
    """A source that authenticates with an API key."""

    name: str  # source name, as used by the DAGs
    collectors: Tuple[str, ...]  # collector names in EDGEGUARD_COLLECT_SOURCES that use this key
    key: Callable[[], Tuple[Optional[str], str]]  # -> (usable key or None, where it is configured)
    probe: Callable[[str], ProbeResult]
    needs_key: bool  # False: the source also answers without a key (NVD, at a lower rate)
    rejected_fails_task: bool  # True: a rejected key fails the collector task instead of skipping it
    get_key_at: str


KEYED_SOURCES: Tuple[KeyedSource, ...] = (
    KeyedSource("otx", ("otx",), _key_otx, _probe_otx, True, False, "https://otx.alienvault.com/api"),
    KeyedSource(
        "nvd", ("nvd",), _key_nvd, _probe_nvd, False, True, "https://nvd.nist.gov/developers/request-an-api-key"
    ),
    KeyedSource(
        "virustotal",
        ("virustotal", "virustotal_enrich"),
        _key_virustotal,
        _probe_virustotal,
        True,
        False,
        "https://www.virustotal.com/gui/my-apikey",
    ),
    KeyedSource("threatfox", ("threatfox",), _key_threatfox, _probe_threatfox, True, False, "https://auth.abuse.ch/"),
    KeyedSource(
        "abuseipdb",
        ("abuseipdb",),
        _key_abuseipdb,
        _probe_abuseipdb,
        True,
        False,
        "https://www.abuseipdb.com/account/api",
    ),
)


# --------------------------------------------------------------------------- result
@dataclass(frozen=True)
class SourceKeyStatus:
    source: str
    configured_in: str
    status: str
    detail: str
    will_collect: Optional[bool]  # None: not known (the key could not be judged)
    task_fails: bool  # the collector task would fail (a rejected NVD key)
    get_key_at: str

    @property
    def is_problem(self) -> bool:
        """A configured key that the provider refuses: always a configuration error."""
        return self.status == REJECTED

    def message(self) -> str:
        if self.status == VALID:
            return f"{self.source}: key accepted by the provider ({self.configured_in}) — the source will be collected"
        if self.status == REJECTED:
            if self.task_fails:
                effect = (
                    "the collector task will FAIL; correct the key, or remove it "
                    "(the source also answers without a key, at a lower rate)"
                )
            else:
                effect = "the source will be SKIPPED"
            return (
                f"{self.source}: key REJECTED by the provider ({self.configured_in}; {self.detail}) — {effect}. "
                f"Key management: {self.get_key_at}"
            )
        if self.status == NOT_SET:
            if self.will_collect:
                return f"{self.source}: no key ({self.configured_in} {self.detail}) — collected without a key, at the lower public rate"
            return (
                f"{self.source}: no key ({self.configured_in} {self.detail}) — the source will be skipped. "
                f"Key: {self.get_key_at}"
            )
        if self.status == DISABLED:
            return f"{self.source}: {self.detail} — key not checked"
        return f"{self.source}: key NOT VERIFIED ({self.configured_in}; {self.detail})"

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _check_one(source: KeyedSource, live: bool) -> SourceKeyStatus:
    from collector_allowlist import is_collector_enabled_by_allowlist

    def result(
        status: str, detail: str, will_collect: Optional[bool], configured_in: str, task_fails: bool = False
    ) -> SourceKeyStatus:
        return SourceKeyStatus(source.name, configured_in, status, detail, will_collect, task_fails, source.get_key_at)

    key, configured_in = source.key()
    if not any(is_collector_enabled_by_allowlist(name) for name in source.collectors):
        return result(DISABLED, "switched off by EDGEGUARD_COLLECT_SOURCES", False, configured_in)
    if not key:
        return result(NOT_SET, "is not set or holds a template placeholder", not source.needs_key, configured_in)
    if not live:
        return result(UNVERIFIED, "the live check is disabled by EDGEGUARD_SOURCE_KEY_CHECK", None, configured_in)
    try:
        status, detail = source.probe(key)
    except requests.exceptions.RequestException as exc:
        return result(UNVERIFIED, f"the provider could not be reached: {type(exc).__name__}", None, configured_in)
    except Exception as exc:  # a defect in a probe must never stop a preflight or a baseline
        logger.warning("%s %s: the key check failed internally (%s)", LOG_PREFIX, source.name, type(exc).__name__)
        return result(UNVERIFIED, f"the check failed internally: {type(exc).__name__}", None, configured_in)
    if status == VALID:
        return result(VALID, detail, True, configured_in)
    if status == REJECTED:
        return result(REJECTED, detail, False, configured_in, task_fails=source.rejected_fails_task)
    return result(UNVERIFIED, detail, None, configured_in)


def check_source_keys(sources: Optional[Iterable[str]] = None) -> List[SourceKeyStatus]:
    """One status per keyed source (all of them, or the named ones), in a fixed order."""
    wanted = {name.strip().lower() for name in sources} if sources is not None else None
    live = key_check_enabled()
    return [_check_one(source, live) for source in KEYED_SOURCES if wanted is None or source.name in wanted]


def baseline_blockers(statuses: Iterable[SourceKeyStatus], required: Optional[Iterable[str]] = None) -> List[str]:
    """Reasons a baseline must not start. Empty for every key state that only skips an optional source.

    * A rejected key whose collector task would fail (NVD): the run fails at that task in any
      case; stopping at the first task spares the wipe of a fresh baseline.
    * A source named in ``EDGEGUARD_BASELINE_REQUIRED_SOURCES`` that is known not to deliver
      (no key, rejected key, switched off). A key that could not be judged does not block.
    """
    needed = required_sources() if required is None else frozenset(name.strip().lower() for name in required)
    blockers: List[str] = []
    for status in statuses:
        if status.status == REJECTED and status.task_fails:
            blockers.append(status.message())
        elif status.source in needed and status.will_collect is False:
            blockers.append(
                f"required source (EDGEGUARD_BASELINE_REQUIRED_SOURCES) cannot deliver — {status.message()}"
            )
    known = {source.name for source in KEYED_SOURCES}
    for name in sorted(needed - known):
        logger.warning(
            "%s EDGEGUARD_BASELINE_REQUIRED_SOURCES names '%s', which is not a keyed source (%s) — ignored",
            LOG_PREFIX,
            name,
            ", ".join(sorted(known)),
        )
    return blockers


def log_report(statuses: Iterable[SourceKeyStatus], log: logging.Logger = logger) -> None:
    """Write one line per source: ERROR for a rejected key, WARNING for a source that will not deliver."""
    for status in statuses:
        if status.status == REJECTED:
            log.error("%s %s", LOG_PREFIX, status.message())
        elif status.status == VALID or (status.status == NOT_SET and status.will_collect):
            log.info("%s %s", LOG_PREFIX, status.message())
        else:
            log.warning("%s %s", LOG_PREFIX, status.message())


def exit_code(statuses: List[SourceKeyStatus]) -> int:
    if baseline_blockers(statuses):
        return 2
    return 1 if any(status.is_problem for status in statuses) else 0


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    statuses = check_source_keys()
    if "--json" in args:
        print(json.dumps([status.as_dict() for status in statuses], indent=2))
    else:
        marks = {VALID: "OK", REJECTED: "REJECTED", NOT_SET: "NO-KEY", UNVERIFIED: "UNKNOWN", DISABLED: "OFF"}
        for status in statuses:
            print(f"{marks[status.status]} {status.message()}")
        for blocker in baseline_blockers(statuses):
            print(f"BLOCKER {blocker}")
    return exit_code(statuses)


if __name__ == "__main__":
    raise SystemExit(main())
