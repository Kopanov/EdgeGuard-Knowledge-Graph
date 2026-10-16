"""Pin: every operator-facing variable of the 2026-10 train reaches the containers.

``docker-compose.yml`` forwards an explicit list of variables through ``x-common-env``;
anything not on the list is silently invisible inside the ``airflow`` container even when
it is set in ``.env``. Found 2026-10-10: the two ICS source flags (and the TLP / alias-merge
levers) were documented in README and ``.env.example`` but never forwarded, so the sources
could not be enabled on the Compose deployment at all.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE = REPO_ROOT / "docker-compose.yml"

# (variable, default that compose must give when .env leaves it unset; None = empty allowed)
FORWARDED = [
    ("EDGEGUARD_ENABLE_MITRE_ICS", "false"),
    ("MITRE_ICS_ATTACK_URL", None),
    ("MITRE_FORCE_REFETCH", None),
    ("EDGEGUARD_MITRE_CONDITIONAL_GET", "true"),
    ("EDGEGUARD_ENABLE_CISA_ICS", "false"),
    ("EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS", "30"),  # int(os.environ.get(...)) — empty would raise
    ("EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN", None),  # _env_int tolerates empty
    ("EDGEGUARD_CISA_ICS_MIN_EXPECTED_ADVISORIES", None),
    ("EDGEGUARD_ENABLE_MALWAREBAZAAR", "false"),  # 2026-10 MalwareBazaar source, flag-guarded
    ("EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN", "500"),  # _env_int; compose carries the code default
    ("EDGEGUARD_THREATFOX_MAX_PER_RUN", "10000"),  # 2026-10 per-run cap sized to the 7-day window
    ("EDGEGUARD_URLHAUS_MAX_PER_RUN", "50000"),  # 2026-10 per-run cap sized to the 30-day csv_recent
    ("EDGEGUARD_FEODO_MAX_PER_RUN", "15000"),  # 2026-10 per-run caps (AbuseIPDB: one request's limit)
    ("EDGEGUARD_SSLBL_MAX_PER_RUN", "20000"),
    ("EDGEGUARD_ABUSEIPDB_MAX_PER_RUN", "10000"),  # one blacklist request per run, free-plan maximum
    ("EDGEGUARD_CISA_INCREMENTAL_DAYS", "30"),  # int(os.environ.get(...))
    ("EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET", "400"),
    ("EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN", "60"),
    ("EDGEGUARD_VIRUSTOTAL_CANDIDATE_DAYS", "30"),
    ("EDGEGUARD_SOURCE_KEY_CHECK", "true"),  # live source key check (source_key_check.py)
    ("EDGEGUARD_BASELINE_REQUIRED_SOURCES", None),  # empty = no keyed source is mandatory
    ("EDGEGUARD_NVD_INCREMENTAL_DAYS", "14"),  # lookback of an NVD incremental run without a cursor
    ("EDGEGUARD_NVD_CURSOR_OVERLAP_SEC", "3600"),  # 2026-10 NVD incremental cursor
    # 2026-10: FIRST EPSS, the post-sync enrichment job (``cve_feed_enrichment``); compose carries
    # the code defaults
    ("EDGEGUARD_ENABLE_EPSS", "true"),
    ("EPSS_URL", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"),
    ("EPSS_MAX_BYTES", "67108864"),
    ("EPSS_DOWNLOAD_DEADLINE_SEC", "300"),
    ("EDGEGUARD_NVD_MAX_PER_RUN", "5000"),
    ("EDGEGUARD_NVD_UPDATE_EXISTING", "true"),
    ("EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE", "true"),  # 2026-10 whole KEV catalogue in baseline mode
    ("EDGEGUARD_NVD_BASELINE_KEV_SWEEP", "true"),  # 2026-10 NVD records of every KEV CVE in baseline mode
    ("EDGEGUARD_NVD_EXTRA_CVE_IDS", None),  # 2026-10 CVE ids fetched by id; empty = none
    ("EDGEGUARD_MISP_DELETE_TIMEOUT_SEC", "900"),  # 2026-10 fresh-baseline wipe: one MISP event delete
    ("EDGEGUARD_OTX_BASELINE_MAX_PAGES", "200"),  # 2026-10 OTX baseline page ceiling (50 pulses per page)
    ("EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES", "25"),
    ("EDGEGUARD_DEFAULT_TLP", "white"),
    ("EDGEGUARD_SYNC_ATTRIBUTE_FILTER", "true"),  # incremental sync writes only changed attributes
    ("EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS", "1"),  # incremental sync window overlap
    ("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "30"),  # 2026-10 last_seen refresh of re-reported indicators
    ("EDGEGUARD_MISP_REFRESH_MAX_PER_RUN", "2000"),
    ("EDGEGUARD_MISP_REFRESH_MAX_SECONDS", "600"),
    # 2026-10-16: indicator aging (src/indicator_aging.py); compose carries the code defaults
    ("EDGEGUARD_AGING_TIER_DAYS", "90,180,365"),
    ("EDGEGUARD_AGING_FACTORS", "0.85,0.70,0.55"),
    ("EDGEGUARD_AGING_RETIRE_DAYS", "730"),
    ("EDGEGUARD_NEO4J_READ_TIMEOUT", "3600"),  # int(os.getenv(...)) — empty would raise
    ("EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE", "true"),
    ("EDGEGUARD_CANONICAL_THREAT_ACTORS", None),  # empty = the reference shipped in src/reference/
    ("EDGEGUARD_ENABLE_MALWARE_TWIN_MERGE", "true"),  # 2026-10 Malware ATT&CK-id twin merge
]


def _common_env() -> dict:
    data = yaml.safe_load(COMPOSE.read_text())
    return data["x-common-env"]


@pytest.mark.parametrize("name, default", FORWARDED, ids=[n for n, _ in FORWARDED])
def test_variable_is_forwarded_with_the_code_default(name, default):
    env = _common_env()
    assert name in env, f"{name} is read by src/ but docker-compose.yml never forwards it into the containers"
    value = str(env[name])
    m = re.fullmatch(r"\$\{" + re.escape(name) + r":-(.*)\}", value)
    assert m, f"{name} must be forwarded as ${{{name}:-<default>}} so .env can override it; got {value!r}"
    if default is None:
        assert m.group(1) == "", f"{name}: compose default must stay empty (code applies its own default)"
    else:
        assert m.group(1) == default, (
            f"{name}: compose default {m.group(1)!r} drifted from the code default {default!r}"
        )


def test_common_env_is_inherited_by_the_airflow_service():
    data = yaml.safe_load(COMPOSE.read_text())
    airflow_env = data["services"]["airflow"]["environment"]
    # YAML merge (<<: *common-env) is resolved by the loader: the flags must be present on the service.
    for name, _ in FORWARDED:
        assert name in airflow_env, f"{name} not visible on the airflow service environment"


def test_sync_min_events_is_forwarded_on_the_airflow_service():
    """``EDGEGUARD_SYNC_MIN_EVENTS`` is read by ``run_misp_to_neo4j.py`` inside the Airflow task.

    It lives next to the other Neo4j-sync knobs on the ``airflow`` service (not in
    ``x-common-env``) and must keep an empty compose default: the code treats empty as the
    default 0 (guard disabled), so ``int("")`` can never be reached.
    """
    data = yaml.safe_load(COMPOSE.read_text())
    airflow_env = data["services"]["airflow"]["environment"]
    name = "EDGEGUARD_SYNC_MIN_EVENTS"
    assert name in airflow_env, (
        f"{name} is read by src/ but docker-compose.yml never forwards it into the airflow container"
    )
    value = str(airflow_env[name])
    m = re.fullmatch(r"\$\{" + re.escape(name) + r":-(.*)\}", value)
    assert m, f"{name} must be forwarded as ${{{name}:-<default>}} so .env can override it; got {value!r}"
    assert m.group(1) == "", f"{name}: compose default must stay empty (code applies its own default 0)"


def test_int_parsed_variables_never_default_to_empty():
    """Guard for the trap the comment in compose describes: set-but-empty + int() = ImportError."""
    env = _common_env()
    for name in (
        "EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS",
        "EDGEGUARD_CISA_INCREMENTAL_DAYS",
        "EDGEGUARD_NVD_INCREMENTAL_DAYS",
    ):
        assert not str(env[name]).endswith(":-}"), f"{name} would be empty inside the container when unset in .env"
