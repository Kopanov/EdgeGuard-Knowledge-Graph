# MISP Backend Tuning for EdgeGuard at Scale

**Audience:** operators deploying or upgrading EdgeGuard against a
MISP backend that will absorb >50,000 attributes per event during
baseline runs (typical for OTX, NVD, ThreatFox at 365–730 day
lookback).

**Why this exists:** during the 2026-04-21 730-day baseline, the
default Docker MISP container hit HTTP 500 errors on most batch pushes
once events crossed ~50K attributes — Apache PHP workers OOMed,
MySQL transactions timed out, and ~11,500 attributes were silently
dropped across the OTX + NVD pushes. EdgeGuard now scales batch
size / throttle adaptively (PR-N4), but the **MISP backend itself
needs the settings below** for the adaptive scaling to actually
help. Adaptive batching alone, against a tiny PHP `memory_limit`,
just fails slower.

The thresholds and settings here are field-tested against the
EdgeGuard 730-day baseline workload (~150K OTX attrs + ~100K NVD
attrs in single events).

---

## TL;DR — Apply these on the MISP container

### `/etc/php/8.x/apache2/php.ini` (and the equivalent `php-fpm` if used)

```ini
; PR-N4 EdgeGuard MISP tuning — large-event batch ingest
memory_limit = 4096M             ; default 512M was OOMing on >50K attr events
max_execution_time = 600         ; default 30s was timing out on bulk inserts
post_max_size = 256M             ; default 8M rejected the JSON payloads
upload_max_filesize = 256M       ; same
max_input_vars = 50000           ; large attribute arrays exceed default 1000
```

### `/etc/mysql/mariadb.conf.d/50-server.cnf` (or equivalent `my.cnf`)

```ini
[mysqld]
# PR-N4 EdgeGuard MISP tuning — large-event batch ingest
innodb_buffer_pool_size = 4G     ; default 128M; aim for ~50% of host RAM
innodb_log_file_size = 512M      ; default 48M; reduces frequent flushes
max_allowed_packet = 256M        ; default 64M; the big payloads hit this
wait_timeout = 600               ; default 28800 is fine; setting explicit
                                 ; for documentation
innodb_flush_log_at_trx_commit = 2  ; faster commits, ACID-on-shutdown only
```

### Apply + verify

```bash
# In your MISP docker compose dir
docker compose restart misp misp-db

# Verify PHP changes
docker compose exec misp php -i | grep -E 'memory_limit|max_execution_time|post_max_size'

# Verify MySQL changes
docker compose exec misp-db mysql -u root -p \
  -e "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('innodb_buffer_pool_size','max_allowed_packet','wait_timeout');"
```

If you can't restart MISP cleanly, the EdgeGuard side will also work
with the env knobs in the next section — they just slow EdgeGuard
down to whatever rate the un-tuned MISP can handle.

---

## EdgeGuard-side env knobs (PR-N4 adaptive scaling)

EdgeGuard's `MISPWriter.push_items` adapts per-event automatically.
The thresholds below are env-tunable — defaults are sane for the MISP
settings above.

| Env var | Default | When to change |
|---|---|---|
| `EDGEGUARD_MISP_PUSH_BATCH_SIZE` | `500` | Hard ceiling; the adaptive logic downscales below this when the target event is large. Lower it (e.g. `200`) only if you're stuck on un-tuned MISP and want to slow down even small events. |
| `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` | `5.0` | Sleep between batches. The adaptive logic widens this to `15s` / `30s` for large/huge events. |
| `EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD` | `50000` | Above this attribute count on the target event, EdgeGuard switches to `batch_size=100, throttle=15s`. Lower if your MISP is undersized. |
| `EDGEGUARD_MISP_HUGE_EVENT_THRESHOLD` | `100000` | Above this, switches to `batch_size=50, throttle=30s`. |
| `EDGEGUARD_MISP_BACKOFF_THRESHOLD` | `3` | Number of consecutive 5xx batch failures before EdgeGuard inserts an extended cooldown. |
| `EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC` | `300.0` | Cooldown duration. 5 min is enough for MISP's PHP to recycle and MySQL to free transaction locks. |
| `EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS` | `true` | Cross-event dedup. Leave on; it prevents pushing duplicates that would just consume MISP cycles. |

### Adaptive scaling tiers (the rule EdgeGuard applies per event)

| Existing event size | batch_size | throttle |
|---|---|---|
| `< 50 000` attrs | configured (default 500) | configured (default 5s) |
| `50 000 – 100 000` | `min(100, configured)` | `max(15s, configured)` |
| `>= 100 000` | `min(50, configured)` | `max(30s, configured)` |

Per-event, not per-collector — so an OTX run pushing into a
small CISA event still uses default batching.

---

## Prometheus metrics PR-N4 added

| Metric | Labels | Meaning |
|---|---|---|
| `edgeguard_misp_push_permanent_failure_total` | `source`, `event_id` | Each increment = one batch (default 500 attrs) lost after `@retry_with_backoff(max_retries=4)` exhausted. **Non-zero rate is the operator signal that backend is undersized.** |
| `edgeguard_misp_push_backoff_triggered_total` | `source` | Each increment = EdgeGuard entered an extended cooldown (default 5 min) after N consecutive 5xx failures. Distinguishes "occasional flap" from "sustained backend overload." |

### Suggested alert rules

```yaml
- alert: EdgeGuardMispBatchPermanentFailure
  expr: sum(rate(edgeguard_misp_push_permanent_failure_total[5m])) > 0
  for: 5m
  annotations:
    summary: "EdgeGuard losing MISP batches permanently"
    description: |
      MISP rejected one or more attribute batches after EdgeGuard's
      retry budget exhausted. Each failure is ~500 attributes lost.
      Check MISP backend RAM / PHP memory_limit / MySQL innodb_buffer_pool_size.
      See docs/MISP_TUNING.md.

- alert: EdgeGuardMispSustainedBackoff
  expr: sum(rate(edgeguard_misp_push_backoff_triggered_total[15m])) > 1
  for: 15m
  annotations:
    summary: "EdgeGuard MISPWriter in extended cooldown >1×/15min"
    description: |
      MISPWriter is hitting consecutive 5xx failures often enough to
      enter the 5-minute cooldown more than once per 15 minutes.
      Backend is sustained-degraded. Tune MISP per docs/MISP_TUNING.md.
```

---

## Symptom → setting cheat-sheet

| What you see | What's wrong | What to change |
|---|---|---|
| HTTP 500 on every batch over a certain size | PHP `memory_limit` or `post_max_size` too small | `memory_limit = 4096M`, `post_max_size = 256M` |
| HTTP 500 with MySQL "Lost connection" or "Lock wait timeout" | InnoDB buffer pool too small for the attribute table | `innodb_buffer_pool_size = 4G`, `innodb_log_file_size = 512M` |
| HTTP 500 with "MySQL has gone away" | `max_allowed_packet` rejecting the JSON | `max_allowed_packet = 256M` |
| HTTP 504 / Apache hangs after ~30s | `max_execution_time` truncating the PHP | `max_execution_time = 600` |
| `Trying to access array offset on value of type null` | MISP attribute payload rejected as too many vars | `max_input_vars = 50000` |
| Push completes but only some attributes saved | MISP silent dedup; expected if `EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS=true` and you're re-running | No action; check `attrs_skipped_existing` in collector stats |
| MISP container restarts mid-push | Apache prefork OOMing the container | Raise the Docker compose `mem_limit` for `misp` AND apply the PHP / MySQL settings above |

---

## Long-term: event sharding (planned, not in PR-N4)

Adaptive batching makes the current single-large-event design SURVIVE
big pushes. The structural fix — **one MISP event capped at ~25K
attributes**, auto-sharded into `EdgeGuard-{source}-{date}-shard-{N}`
— is tracked as a future PR. With shards, no single event ever
crosses the threshold where MISP starts to struggle, and the adaptive
downscaling becomes belt-and-suspenders.

Until shards land, the settings above + PR-N4's adaptive scaling are
the recommended posture.

---

## References

- PR-N4: `src/collectors/misp_writer.py` `push_items` adaptive scaling
- Audit triage: `docs/flow_audits/09_comprehensive_audit.md` (Prod
  Readiness #1, #2, #11)
- On-call report: 2026-04-21 OTX + NVD baseline, ~11,500 attrs lost
- MISP upstream tuning notes:
  https://misp.github.io/MISP/INSTALL.ubuntu2204/#performance-tuning
- PHP `memory_limit`: https://www.php.net/manual/en/ini.core.php
- InnoDB `innodb_buffer_pool_size`:
  https://dev.mysql.com/doc/refman/8.0/en/innodb-buffer-pool-resize.html
